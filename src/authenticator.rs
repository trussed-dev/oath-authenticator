use core::convert::TryInto;

#[cfg(feature = "applet")]
use apdu_dispatch::applet;
use flexiber::{Encodable, EncodableHeapless};
use iso7816::response::{Data, Result, Status};
use serde::{Deserialize, Serialize};
use trussed::{
    client, syscall, try_syscall,
    postcard_deserialize, postcard_serialize,
    types::{Location, ObjectHandle, PathBuf},
};

use crate::{command, Command, oath, state::{CommandState, State}};

/// The TOTP authenticator Trussed® app.
pub struct Authenticator<T> {
    state: State,
    trussed: T,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OathVersion {
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
}

impl Default for OathVersion {
    /// For ykman, 4.2.6 is the first version to support "touch" requirement
    fn default() -> Self {
        // OathVersion { major: 1, minor: 0, patch: 0}
        OathVersion { major: 4, minor: 4, patch: 4}
    }
}

impl flexiber::Encodable for OathVersion {
    fn encoded_length(&self) -> flexiber::Result<flexiber::Length> {
        Ok(3u8.into())
    }
    fn encode(&self, encoder: &mut flexiber::Encoder) -> flexiber::Result<()> {
        let buf = [self.major, self.minor, self.patch];
        buf.as_ref().encode(encoder)
    }
}

// Mar 05 21:43:45 tensor pcscd[2238]: 00000588 APDU: 00 A4 04 00 07 A0 00 00 05 27 21 01
// Mar 05 21:43:45 tensor pcscd[2238]: 00008810 SW:
//      79 03 01 00 00
//      71 08 26 9F 14 54 3A 0E C7 AC
//      90 00

// 61 0F 79 03 01 00 00 71 08 01 02 03 04 01 02 03 04 90 00
#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
pub struct AnswerToSelect {

    #[tlv(simple = "0x79")] // Tag::Version
    version: OathVersion,
    #[tlv(simple = "0x71")] // Tag::Name
    salt: [u8; 8],

    // the following is listed as "locked" and "FIPS mode"
    //
    // NB: Current BER-TLV derive macro has limitation that it
    // wants a tag. It should learn some kind of "suppress-tag-if-none".
    // As we would like to send "nothing" when challeng is None,
    // instead of '74 00', as with the tagged/Option derivation.
    // #[tlv(simple = "0x74")] // Tag::Challenge
    // challenge: Option<[u8; 8]>,
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
pub struct ChallengingAnswerToSelect {

    #[tlv(simple = "0x79")] // Tag::Version
    version: OathVersion,
    #[tlv(simple = "0x71")] // Tag::Name
    salt: [u8; 8],

    // the following is listed as "locked" and "FIPS mode"
    //
    // NB: Current BER-TLV derive macro has limitation that it
    // wants a tag. It should learn some kind of "suppress-tag-if-none".
    // As we would like to send "nothing" when challeng is None,
    // instead of '74 00', as with the tagged/Option derivation.
    #[tlv(simple = "0x74")] // Tag::Challenge
    challenge: [u8; 8],
}

impl AnswerToSelect {
    /// The salt is stable and used in modified form as "device ID" in ykman.
    /// It gets rotated on device reset.
    pub fn new(salt: [u8; 8]) -> Self {
        Self {
            version: Default::default(),
            salt,
            // challenge: None,
        }
    }

    /// This challenge is only added when a password is set on the device.
    ///
    /// It is rotated each time SELECT is called.
    pub fn with_challenge(self, challenge: [u8; 8]) -> ChallengingAnswerToSelect {
        ChallengingAnswerToSelect {
            version: self.version,
            salt: self.salt,
            challenge: challenge,
        }
    }
}

impl<T> Authenticator<T>
where
    T: client::Client + client::HmacSha1 + client::HmacSha256 + client::Sha256,
{
    // const CREDENTIAL_DIRECTORY: &'static str = "cred";
    fn credential_directory() -> PathBuf {
        PathBuf::from("cred")
    }

    pub fn new(trussed: T) -> Self {
        Self {
            state: Default::default(),
            trussed,
        }
    }

    pub fn respond(&mut self, command: &iso7816::Command) -> Result {

        let no_authorization_needed = self.state.persistent(&mut self.trussed, |_, state| !state.password_set());

        // TODO: abstract out this idea to make it usable for all the PIV security indicators

        let client_authorized_before = self.state.runtime.client_authorized;
        self.state.runtime.client_newly_authorized = false;
        if no_authorization_needed {
            self.state.runtime.client_authorized = true;
        }

        debug_now!("inner respond, client_authorized {}", self.state.runtime.client_authorized);
        let result = self.inner_respond(command);

        // we want to clear the authorization flag *except* if it wasn't set before,
        // but was set now.
        // if !(!client_authorized_before && self.state.runtime.client_newly_authorized) {
        // This is equivalent to the simpler formulation that stale authorization gets
        // removed, unless refreshed during this round
        if client_authorized_before || !self.state.runtime.client_newly_authorized {
            self.state.runtime.client_authorized = false;
        }
        if self.state.runtime.client_newly_authorized {
            self.state.runtime.client_authorized = true;
        }

        debug_now!("client_authorized_before {}, client_newly_authorized {}, client_authorized {}",
            client_authorized_before,
            self.state.runtime.client_newly_authorized,
            self.state.runtime.client_authorized,
        );
        result

    }

    fn inner_respond(&mut self, command: &iso7816::Command) -> Result {
        let class = command.class();
        assert!(class.chain().last_or_only());
        assert!(class.secure_messaging().none());
        assert!(class.channel() == Some(0));

        // parse Iso7816Command as PivCommand
        let command: Command = command.try_into()?;
        info_now!("\n====\n{:?}\n====\n", &command);

        if !self.state.runtime.client_authorized {
            match command {
                Command::Select(_) => {}
                Command::Validate(_) => {}
                _ => return Err(Status::ConditionsOfUseNotSatisfied),
            }
        }
        match command {
            Command::Select(select) => self.select(select),
            Command::ListCredentials => self.list_credentials(),
            Command::Register(register) => self.register(register),
            Command::Calculate(calculate) => self.calculate(calculate),
            Command::CalculateAll(calculate_all) => self.calculate_all(calculate_all),
            Command::Delete(delete) => self.delete(delete),
            Command::Reset => self.reset(),
            Command::Validate(validate) => self.validate(validate),
            Command::SetPassword(set_password) => self.set_password(set_password),
            Command::ClearPassword => self.clear_password(),
        }
    }

    pub fn select(&mut self, _select: command::Select<'_>) -> Result {
        self.state.runtime.challenge =
            syscall!(self.trussed.random_bytes(8)).bytes.as_ref().try_into().unwrap();

        let state = self.state.persistent(&mut self.trussed, |_, state| state.clone() );
        let answer_to_select = AnswerToSelect::new(state.salt);

        let data = if state.password_set() {
            answer_to_select.with_challenge(self.state.runtime.challenge).to_heapless_vec()
        } else {
            answer_to_select.to_heapless_vec()
        }.unwrap();

        Ok(Data::from(data))
    }

    fn secret_from_credential_filename<'a>(&mut self, filename: &'a [u8]) -> Option<ObjectHandle> {
        let serialized_credential = try_syscall!(
            self.trussed.read_file(Location::Internal, PathBuf::from(filename))
        )
            .ok()?
            .data;

        let credential: Credential = postcard_deserialize(serialized_credential.as_ref())
            .ok()?;

        Some(credential.secret)
    }

    fn load_credential<'a>(&mut self, label: &'a [u8]) -> Option<Credential<'a>> {
        let filename = self.filename_for_label(label);

        let serialized_credential = try_syscall!(
            self.trussed.read_file(Location::Internal, filename)
        )
            .ok()?
            .data;

        let credential: Credential = postcard_deserialize(serialized_credential.as_ref())
            .ok()?;

        let credential = Credential { label, ..credential };

        Some(credential)
    }

    pub fn reset(&mut self) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let mut maybe_entry = syscall!(self.trussed.read_dir_first(
            Location::Internal,
            Self::credential_directory(),
            None
        )).entry;

        while let Some(ref entry) = maybe_entry {
            let secret = match self.secret_from_credential_filename(entry.path().as_ref().as_bytes()) {
                Some(secret) => secret,
                None => continue,
            };
            if !syscall!(self.trussed.delete(secret)).success {
                debug_now!("could not delete secret {:?}", secret);
            } else {
                debug_now!("deleted secret {:?}", secret);
            }
            if try_syscall!(self.trussed.remove_file(Location::Internal, PathBuf::from(entry.path()))).is_err() {
                debug_now!("could not delete credential with filename {}", entry.path());
            } else {
                debug_now!("deleted credential with filename {}", &PathBuf::from(entry.path()));
            }

            // onwards
            // NB: at this point, the command cache for looping is reset (this should be fixed
            // upstream in Trussed, but...)
            // On the other hand, we already deleted the first credential, so we can just read the
            // first remaining credential.
            maybe_entry = syscall!(self.trussed.read_dir_first(
                Location::Internal,
                Self::credential_directory(),
                None,
            )).entry;
            debug_now!("is there more? {:?}", &maybe_entry);
        }
        Ok(Default::default())
    }

    pub fn delete(&mut self, delete: command::Delete<'_>) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        debug_now!("{:?}", delete);
        // It seems tooling first lists all credentials, so the case of
        // delete being called on a non-existing label hardly occurs.

        // APDU: 00 A4 04 00 07 A0 00 00 05 27 21 01
        // SW: 79 03 01 00 00 71 08 26 9F 14 54 3A 0E C7 AC 90 00
        // APDU: 00 A1 00 00 00
        // SW: 72 13 21 74 6F 74 70 2E 64 61 6E 68 65 72 73 61 6D 2E 63 6F 6D 72 07 21 79 75 62 69 63 6F 90 00

        // APDU: 00 02 00 00 08 71 06 79 75 62 69 63 6F
        // SW: 90 00

        let label = &delete.label;
        if let Some(credential) = self.load_credential(label) {
            if !syscall!(self.trussed.delete(credential.secret)).success {
                debug_now!("could not delete secret {:?}", credential.secret);
            } else {
                debug_now!("deleted secret {:?}", credential.secret);
            }

            let _filename = self.filename_for_label(label);
            if try_syscall!(self.trussed.remove_file(Location::Internal, _filename)).is_err() {
                debug_now!("could not delete credential with filename {}", &self.filename_for_label(label));
            } else {
                debug_now!("deleted credential with filename {}", &self.filename_for_label(label));
            }
        }
        Ok(Default::default())
    }

    /// The YK5 can store a Grande Totale of 32 OATH credentials.
    pub fn list_credentials(&mut self) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        info_now!("recv ListCredentials");
        // return Ok(Default::default());
        // 72 13 21
        //          74 6F 74 70  2E 64 61 6E  68 65 72 73  61 6D 2E 63  6F 6D
        // 72 07 21
        //          79 75 62 69  63 6F
        // 90 00

        let mut maybe_credential = syscall!(self.trussed.read_dir_files_first(
            Location::Internal,
            Self::credential_directory(),
            None
        )).data;

        let mut response = Data::new();
        let mut file_index = 0;
        while let Some(serialized_credential) = maybe_credential {
            info_now!("serialized credential: {}", hex_str!(&serialized_credential));

            // keep track, in case we need continuation
            file_index += 1;
            self.state.runtime.previously = Some(CommandState::ListCredentials(file_index));

            // deserialize
            let credential: Credential = postcard_deserialize(&serialized_credential).unwrap();

            // append data in form:
            // 72
            // len (= 1 + label.len())
            // kind | algorithm
            // label
            response.push(0x72).unwrap();
            response.push((credential.label.len() + 1) as u8).unwrap();
            response.push(oath::combine(credential.kind, credential.algorithm)).unwrap();
            response.extend_from_slice(credential.label).unwrap();

            // check if there's more
            maybe_credential = syscall!(self.trussed.read_dir_files_next()).data;

                // get_data = _encode_extended_apdu(0, self._ins_send_remaining, 0, 0, b"")
            // else:
                // raise TypeError("Invalid ApduFormat set")

            // # Read chained response
            // buf = b""
            // while sw >> 8 == SW1_HAS_MORE_DATA:
                // buf += response
                // response, sw = self.connection.send_and_receive(get_data)

        }

        // ran to completion
        // todo: pack this cleanup in a closure?
        self.state.runtime.previously = None;
        Ok(response)
    }

    pub fn register(&mut self, register: command::Register<'_>) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        info_now!("recv {:?}", &register);

        // 0. ykman does not call delete before register, so we need to speculatively
        // delete the credential (the credential file would be replaced, but we need
        // to delete the secret key).
        self.delete(command::Delete { label: register.credential.label }).ok();

        // 1. Store secret in Trussed
        let raw_key = register.credential.secret;
        let key_handle = syscall!(
            self.trussed.unsafe_inject_shared_key(raw_key, Location::Internal)
        ).key;
        info!("new key handle: {:?}", key_handle);

        // 2. Replace secret in credential with handle
        let credential = Credential::from(&register.credential, key_handle);

        // 3. Generate a filename for the credential
        let filename = self.filename_for_label(&credential.label);

        // 4. Serialize the credential
        let mut buf = [0u8; 256];
        let serialized = postcard_serialize(&credential, &mut buf).unwrap();
        info_now!("storing serialized credential: {}", hex_str!(&serialized));

        // 5. Store it
        syscall!(self.trussed.write_file(
            Location::Internal,
            filename,
            heapless_bytes::Bytes::try_from_slice(serialized).unwrap(),
            None
        ));

        Ok(Default::default())
    }

    fn filename_for_label(&mut self, label: &[u8]) -> trussed::types::PathBuf {
        let label_hash = syscall!(self.trussed.hash_sha256(label))
            .hash;

        // todo: maybe use a counter instead (put it in our persistent state).
        let mut hex_filename = [0u8; 16];
        const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";
        for (i, &value) in label_hash.iter().take(8).enumerate() {
            hex_filename[2*i] = LOOKUP[(value >> 4) as usize];
            hex_filename[2*i + 1] = LOOKUP[(value & 0xF) as usize];
        }

        let filename = PathBuf::from(hex_filename.as_ref());
        let mut path = Self::credential_directory();
        path.push(&filename);
        info_now!("filename: {}", path.as_str_ref_with_trailing_nul());
        path
    }

    // 71 <- Tag::Name
    //    12
    //       74 6F 74 70 2E 64 61 6E 68 65 72 73 61 6D 2E 63 6F 6D
    // 76 <- Tag::TruncatedResponse
    //    05
    //       06 <- digits
    //       75 F9 2B 37 <- dynamically truncated HMAC
    // 71 <- Tag::Name
    //    06
    //       79 75 62 69 63 6F
    // 76 <- Tag::TruncatedResponse
    //    05
    //       06  <- digits
    //       5A D0 A7 CA <- dynamically truncated HMAC
    // 90 00
    pub fn calculate_all(&mut self, calculate_all: command::CalculateAll<'_>) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        let mut maybe_credential = syscall!(self.trussed.read_dir_files_first(
            Location::Internal,
            Self::credential_directory(),
            None
        )).data;

        let mut response = Data::new();
        while let Some(serialized_credential) = maybe_credential {
            info_now!("serialized credential: {}", hex_str!(&serialized_credential));

            // deserialize
            let credential: Credential = postcard_deserialize(&serialized_credential).unwrap();

            // calculate the value
            let truncated_digest = crate::calculate::calculate(
                &mut self.trussed,
                credential.algorithm,
                calculate_all.challenge,
                credential.secret,
            );

            // add to response
            response.push(0x71).unwrap();
            response.push(credential.label.len() as u8).unwrap();
            response.extend_from_slice(credential.label).unwrap();

            response.push(0x76).unwrap();
            response.push(5).unwrap();
            response.push(credential.digits).unwrap();
            response.extend_from_slice(&truncated_digest).unwrap();

            // check if there's more
            maybe_credential = syscall!(self.trussed.read_dir_files_next()).data;
        }

        // ran to completion
        Ok(response)
    }

    pub fn calculate(&mut self, calculate: command::Calculate<'_>) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        info_now!("recv {:?}", &calculate);

        let credential = self.load_credential(&calculate.label).ok_or(Status::NotFound)?;

        let truncated_digest = crate::calculate::calculate(
            &mut self.trussed,
            credential.algorithm,
            calculate.challenge,
            credential.secret,
        );

        let mut response = Data::new();

        response.push(0x71).unwrap();
        response.push(credential.label.len() as u8).unwrap();
        response.extend_from_slice(credential.label).unwrap();

        response.push(0x76).unwrap();
        response.push(credential.digits).unwrap();
        response.extend_from_slice(&truncated_digest).unwrap();

        Ok(response)
    }

    pub fn validate(&mut self, validate: command::Validate<'_>) -> Result {
        let command::Validate { response, challenge } = validate;

        let password_set = self.state.persistent(&mut self.trussed, |_, state| state.password_set());
        debug_now!("pw set: {}", password_set);

        if let Some(key) = self.state.persistent(&mut self.trussed, |_, state| state.authorization_key) {
            debug_now!("key set: {:?}", key);

            // 1. verify what the client sent (rotating challenge)
            let verification = syscall!(self.trussed.sign_hmacsha1(key, &self.state.runtime.challenge)).signature;

            self.state.runtime.challenge =
                syscall!(self.trussed.random_bytes(8)).bytes.as_ref().try_into().unwrap();

            if verification != response {
                return Err(Status::IncorrectDataParameter);
            }

            self.state.runtime.client_newly_authorized = true;

            // 2. calculate our response to their challenge
            let response = syscall!(self.trussed.sign_hmacsha1(key, challenge)).signature;

            let mut data = Data::new();
            data.push(0x75).ok();
            data.push(20).ok();
            data.extend_from_slice(&response).ok();
            debug_now!("validated client! client_newly_authorized = {}", self.state.runtime.client_newly_authorized);
            Ok(data)

        } else {
            Err(Status::ConditionsOfUseNotSatisfied)
        }

        // APDU: 00 A3 00 00 20 (AUTHENTICATE)
        //       75 14
        //             8C E0 33 83 E6 A9 0D 27 8B E7 D2 EF 9E 3B 1F DB F4 5E 91 35
        //       74 08
        //             AF C9 BA 64 22 6D F0 78
        // SW: 75 14
        //             87 BE EB AB 20 F4 C2 FA 24 EA 08 AB D3 4D C1 5B F0 51 DC 85
        //     90 00
        //

        // pub response: &'l [u8; 20],
        // pub challenge: &'l [u8; 8],

    }

    pub fn clear_password(&mut self) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        debug_now!("clearing password/key");
        if let Some(key) = self.state.persistent(&mut self.trussed, |_, state| {
            let existing_key = state.authorization_key;
            state.authorization_key = None;
            existing_key
        }) {
            syscall!(self.trussed.delete(key));
        }
        Ok(Default::default())
    }

    pub fn set_password(&mut self, set_password: command::SetPassword<'_>) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        // when there is no password set:
        // APDU: 00 A4 04 00 07 (SELECT)
        //                      A0 00 00 05 27 21 01
        // SW: 79 03
        //           01 00 00
        //     71 08
        //           26 9F 14 54 3A 0E C7 AC
        //     90 00
        //
        // APDU: 00 03 00 00 33 (SET PASSWORD)
        //       73 11
        //             21 83 93 58 A6 E1 A1 F6 AB 13 46 F6 5E 56 6F 26 8A
        //       74 08
        //             7D CB 79 D5 74 AA 68 6D
        //       75 14
        //             73 CA E7 96 6F 32 A8 49 9E B0 F9 D6 D0 3E AA 06 23 59 C6 F2
        // SW: 90 00

        // when there is a password previously set:
        //
        // APDU: 00 A4 04 00 07 (SELECT)
        //                      A0 00 00 05 27 21 01
        // SW: 79 03
        //           01 00 00
        //     71 08
        //           26 9F 14 54 3A 0E C7 AC
        //     74 08 (SALT, signals password is set)
        //           13 FB E9 67 DF 91 BB 89
        //     7B 01 (ALGORITHM, not sure what for)
        //           21
        //     90 00
        //
        // APDU: 00 A3 00 00 20 (AUTHENTICATE)
        //       75 14
        //             8C E0 33 83 E6 A9 0D 27 8B E7 D2 EF 9E 3B 1F DB F4 5E 91 35
        //       74 08
        //             AF C9 BA 64 22 6D F0 78
        // SW: 75 14
        //             87 BE EB AB 20 F4 C2 FA 24 EA 08 AB D3 4D C1 5B F0 51 DC 85
        //     90 00
        //
        // APDU: 00 03 00 00 33 (SET PASSWORD)
        //       73 11
        //             21 83 93 58 A6 E1 A1 F6 AB 13 46 F6 5E 56 6F 26 8A
        //       74 08
        //             08 7A 1C 76 17 12 C7 9D
        //       75 14
        //             4F B0 29 1A 0E FC 88 46 FA 30 FF A4 C7 1E 51 A5 50 79 9A B8
        // SW: 90 00

        info_now!("entering set password");
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let command::SetPassword { kind, algorithm, key, challenge, response } = set_password;

        info_now!("just checking");
        if kind != oath::Kind::Totp || algorithm != oath::Algorithm::Sha1 {
            return Err(Status::InstructionNotSupportedOrInvalid);
        }

        info_now!("injecting the key");
        let tmp_key = syscall!(self.trussed.unsafe_inject_shared_key(
            key,
            Location::Volatile,
        )).key;

        let verification = syscall!(self.trussed.sign_hmacsha1(tmp_key, challenge)).signature;
        syscall!(self.trussed.delete(tmp_key));

        // not really sure why this is all sent along, I guess some kind of fear of bitrot en-route?
        if verification != response {
            return Err(Status::IncorrectDataParameter);
        }

        // all-right, we have a new password to set
        let key = syscall!(self.trussed.unsafe_inject_shared_key(
            key,
            Location::Internal,
        )).key;

        // self.state::persistent(trussed, |trussed, state| {
        //     state.authorization_key = Some(key);
        // });
        debug_now!("storing password/key");
        self.state.persistent(&mut self.trussed, |_, state| { state.authorization_key = Some(key) } );
        debug_now!("checking it worked:");
        let password_set = self.state.persistent(&mut self.trussed, |_, state| state.password_set());
        debug_now!("pw set: {}", password_set);

        // pub struct SetPassword<'l> {
        //     pub kind: oath::Kind,
        //     pub algorithm: oath::Algorithm,
        //     pub key: &'l [u8],
        //     pub challenge: &'l [u8],
        //     pub response: &'l [u8],
        // }
        Ok(Default::default())
    }

}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credential<'l> {
    pub label: &'l [u8],
    pub kind: oath::Kind,
    pub algorithm: oath::Algorithm,
    pub digits: u8,
    /// What we get here (inspecting the client app) may not be the raw K, but K' in HMAC lingo,
    /// i.e., If secret.len() < block size (64B for Sha1/Sha256, 128B for Sha512),
    /// then it's the hash of the secret.  Otherwise, it's the secret, padded to length
    /// at least 14B with null bytes. This is of no concern to us, as is it does not
    /// change the MAC.
    ///
    /// The 14 is a bit strange: RFC 4226, section 4 says:
    /// "The algorithm MUST use a strong shared secret.  The length of the shared secret MUST be
    /// at least 128 bits.  This document RECOMMENDs a shared secret length of 160 bits."
    ///
    /// Meanwhile, the client app just pads up to 14B :)

    pub secret: trussed::types::ObjectHandle,
    pub touch_required: bool,
    pub counter: Option<u32>,
}

impl<'l> Credential<'l> {
    fn from(credential: &command::Credential<'l>, handle: ObjectHandle) -> Self {
        Self {
            label: credential.label,
            kind: credential.kind,
            algorithm: credential.algorithm,
            digits: credential.digits,
            secret: handle,
            touch_required: credential.touch_required,
            counter: credential.counter,
        }
    }
}


#[cfg(feature = "applet")]
impl<T> applet::Aid for Authenticator<T> {

    fn aid(&self) -> &'static [u8] {
        &crate::YUBICO_OATH_AID
    }

    fn right_truncated_length(&self) -> usize {
        crate::YUBICO_OATH_AID.len()
    }
}


#[cfg(feature = "applet")]
impl<T> applet::Applet for Authenticator<T>
where
    T: client::Client + client::HmacSha1 + client::HmacSha256 + client::Sha256,
{
    fn select(&mut self, apdu: &iso7816::Command) -> applet::Result {
        Ok(applet::Response::Respond(self.respond(apdu).unwrap()))
    }

    fn deselect(&mut self) { /*self.deselect()*/ }

    fn call(&mut self, _type: applet::InterfaceType, apdu: &iso7816::Command) -> applet::Result {
        self.respond(apdu).map(|data| applet::Response::Respond(data))
    }
}
