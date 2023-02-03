use core::convert::TryInto;
use core::marker::PhantomData;
use core::time::Duration;

use flexiber::{Encodable, EncodableHeapless};
use iso7816::{Data, Status};
use trussed::{
    client, syscall, try_syscall,
    types::{Location, PathBuf},
};

use crate::command::VerifyCode;
use crate::credential::Credential;
use crate::encryption_key::EncryptionKeyGetter;
use crate::oath::Kind;
use crate::{
    command, ensure, oath,
    state::{CommandState, State},
    Command,
};

/// The TOTP authenticator Trussed® app.
pub struct Authenticator<T, K> {
    state: State<K>,
    trussed: T,
    encryption_key_getter: PhantomData<K>,
}

use crate::Result;

#[derive(Clone, Copy, Eq, PartialEq)]
struct OathVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl Default for OathVersion {
    /// For ykman, 4.2.6 is the first version to support "touch" requirement
    fn default() -> Self {
        // OathVersion { major: 1, minor: 0, patch: 0}
        OathVersion {
            major: 4,
            minor: 4,
            patch: 4,
        }
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
struct AnswerToSelect {
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
struct ChallengingAnswerToSelect {
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

    #[tlv(simple = "0x7b")] // Tag::Algorithm
    // algorithm: oath::Algorithm,
    algorithm: [u8; 1],
}

impl AnswerToSelect {
    /// The salt is stable and used in modified form as "device ID" in ykman.
    /// It gets rotated on device reset.
    fn new(salt: [u8; 8]) -> Self {
        Self {
            version: Default::default(),
            salt,
            // challenge: None,
        }
    }

    /// This challenge is only added when a password is set on the device.
    ///
    /// It is rotated each time SELECT is called.
    fn with_challenge(self, challenge: [u8; 8]) -> ChallengingAnswerToSelect {
        ChallengingAnswerToSelect {
            version: self.version,
            salt: self.salt,
            challenge,
            // algorithm: oath::Algorithm::Sha1  // TODO set proper algo
            algorithm: [0x01], // TODO set proper algo
        }
    }
}

impl<T, K: EncryptionKeyGetter> Authenticator<T, K>
where
    T: client::Client
        + client::HmacSha1
        + client::HmacSha256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    // const CREDENTIAL_DIRECTORY: &'static str = "cred";
    fn credential_directory() -> PathBuf {
        PathBuf::from("cred")
    }

    pub fn new(trussed: T) -> Self {
        Self {
            state: State::<K>::new(),
            trussed,
            encryption_key_getter: PhantomData,
        }
    }

    pub fn respond<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        let no_authorization_needed = self
            .state
            .with_persistent(&mut self.trussed, |_, state| !state.password_set());

        // TODO: abstract out this idea to make it usable for all the PIV security indicators

        let client_authorized_before = self.state.runtime.client_authorized;
        self.state.runtime.client_newly_authorized = false;
        if no_authorization_needed {
            self.state.runtime.client_authorized = true;
        }

        // debug_now!("inner respond, client_authorized {}", self.state.runtime.client_authorized);
        let result = self.inner_respond(command, reply);

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

        result
    }

    fn inner_respond<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        let class = command.class();
        ensure(
            class.chain().last_or_only(),
            Status::CommandChainingNotSupported,
        )?;
        ensure(
            class.secure_messaging().none(),
            Status::SecureMessagingNotSupported,
        )?;
        ensure(class.channel() == Some(0), Status::ClassNotSupported)?;

        // parse Iso7816Command as PivCommand
        let command: Command = command.try_into()?;
        info_now!("{:?}", &command);

        if !self.state.runtime.client_authorized {
            match command {
                Command::Select(_) => {}
                Command::Validate(_) => {}
                Command::Reset => {}
                Command::VerifyCode(_) => {}
                _ => return Err(Status::ConditionsOfUseNotSatisfied),
            }
        }
        match command {
            Command::Select(select) => self.select(select, reply),
            Command::ListCredentials => self.list_credentials(reply, None),
            Command::Register(register) => self.register(register),
            Command::Calculate(calculate) => self.calculate(calculate, reply),
            // Command::CalculateAll(calculate_all) => self.calculate_all(calculate_all, reply),
            Command::Delete(delete) => self.delete(delete),
            Command::Reset => self.reset(),
            Command::Validate(validate) => self.validate(validate, reply),
            Command::SetPassword(set_password) => self.set_password(set_password),
            Command::ClearPassword => self.clear_password(),
            Command::VerifyCode(verify_code) => self.verify_code(verify_code, reply),
            Command::SendRemaining => self.send_remaining(reply),
            _ => Err(Status::ConditionsOfUseNotSatisfied),
        }
    }

    fn select<const R: usize>(
        &mut self,
        _select: command::Select<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        self.state.runtime.challenge = syscall!(self.trussed.random_bytes(8))
            .bytes
            .as_ref()
            .try_into()
            .unwrap();

        let state = self
            .state
            .with_persistent(&mut self.trussed, |_, state| state.clone());
        let answer_to_select = AnswerToSelect::new(state.salt);

        let data: heapless::Vec<u8, 128> = if state.password_set() {
            answer_to_select
                .with_challenge(self.state.runtime.challenge)
                .to_heapless_vec()
        } else {
            answer_to_select.to_heapless_vec()
        }
        .unwrap();

        reply.extend_from_slice(&data).unwrap();
        Ok(())
    }

    fn load_credential(&mut self, label: &[u8]) -> Option<Credential> {
        let filename = self.filename_for_label(label);

        let credential: Credential = self.state.try_read_file(&mut self.trussed, filename).ok()?;

        if label != credential.label.as_slice() {
            error_now!("Loaded credential label is different than expected. Aborting.");
            return None;
        }

        Some(credential)
    }

    fn reset(&mut self) -> Result {
        self.user_present()?;

        // Well. `ykman oath reset` does not check PIN.
        // If you lost your PIN, you wouldn't be able to reset otherwise.

        debug_now!(":: reset - delete all keys");
        try_syscall!(self.trussed.delete_all(crate::LOCATION))
            .map_err(|_| Status::NotEnoughMemory)?;

        debug_now!(":: reset - delete all files");
        // make sure all other files are removed as well
        // NB: This deletes state.bin too, so it removes a possibly set password and encryption key.
        try_syscall!(self.trussed.remove_dir_all(crate::LOCATION, PathBuf::new()))
            .map_err(|_| Status::NotEnoughMemory)?;

        self.state.runtime.reset();

        debug_now!(":: reset over");
        Ok(())
    }

    fn delete(&mut self, delete: command::Delete<'_>) -> Result {
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
            let _deletion_result_secret = syscall!(self.trussed.delete(credential.secret)).success;
            debug_now!(
                "Deleted secret {:?}, result: {:?}",
                credential.secret,
                _deletion_result_secret
            );

            let _filename = self.filename_for_label(label);
            let _deletion_result =
                try_syscall!(self.trussed.remove_file(crate::LOCATION, _filename));
            debug_now!(
                "Delete credential with filename {}, result: {:?}",
                &self.filename_for_label(label),
                _deletion_result
            );
        }
        Ok(())
    }

    fn try_to_serialize_credential_for_list<const R: usize>(
        credential: &Credential,
        reply: &mut Data<R>,
    ) -> core::result::Result<(), u8> {
        reply.push(0x72)?;
        reply.push((credential.label.len() + 1) as u8)?;
        reply.push(oath::combine(credential.kind, credential.algorithm))?;
        reply.extend_from_slice(&credential.label).map_err(|_| 0)?;
        #[cfg(feature = "devel-ctaphid-bug")]
        if reply.len() > 3072 {
            // Finish early due to the usbd-ctaphid bug, which panics on bigger buffers than this
            // FIXME Remove once fixed
            return Err(1);
        }
        Ok(())
    }

    /// The YK5 can store a Grande Totale of 32 OATH credentials.
    fn list_credentials<const R: usize>(
        &mut self,
        reply: &mut Data<R>,
        file_index: Option<usize>,
    ) -> Result {
        // TODO check if this one conflicts with send remaining
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        // info_now!("recv ListCredentials");
        // return Ok(Default::default());
        // 72 13 21
        //          74 6F 74 70  2E 64 61 6E  68 65 72 73  61 6D 2E 63  6F 6D
        // 72 07 21
        //          79 75 62 69  63 6F
        // 90 00
        let file_index = file_index.unwrap_or(0);

        let mut maybe_credential = {
            // To avoid creating additional buffer for the unfit data
            // we will rewind the state and restart from there accordingly
            let first_file = try_syscall!(self.trussed.read_dir_files_first(
                crate::LOCATION,
                Self::credential_directory(),
                None
            ))
            .map_err(|_| iso7816::Status::UnspecifiedNonpersistentExecutionError)?
            .data;

            // Rewind if needed, otherwise return first file's content
            let file = {
                if file_index > 0 {
                    for _ in 0..file_index - 1 {
                        try_syscall!(self.trussed.read_dir_files_next())
                            .map_err(|_| iso7816::Status::UnspecifiedNonpersistentExecutionError)?;
                    }
                    try_syscall!(self.trussed.read_dir_files_next())
                        .map_err(|_| iso7816::Status::UnspecifiedNonpersistentExecutionError)?
                        .data
                } else {
                    first_file
                }
            };

            let maybe_credential: Option<Credential> = match file {
                None => None,
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
            maybe_credential
        };

        let mut file_index = file_index;
        while let Some(credential) = maybe_credential {
            // Try to serialize, abort if not succeeded
            let current_reply_bytes_count = reply.len();
            let res = Self::try_to_serialize_credential_for_list(&credential, reply);
            if res.is_err() {
                // Revert reply vector to the last good size, removing debris from the failed
                // serialization
                reply.truncate(current_reply_bytes_count);
                return Err(Status::MoreAvailable(0xFF));
            }

            // keep track, in case we need continuation
            file_index += 1;
            self.state.runtime.previously = Some(CommandState::ListCredentials(file_index));

            // check if there's more
            maybe_credential = match syscall!(self.trussed.read_dir_files_next()).data {
                None => None,
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
        }

        // ran to completion
        // todo: pack this cleanup in a closure?
        self.state.runtime.previously = None;
        Ok(())
    }

    fn send_remaining<const R: usize>(&mut self, reply: &mut Data<{ R }>) -> Result {
        let file_index = if let Some(CommandState::ListCredentials(s_file_index)) =
            self.state.runtime.previously
        {
            s_file_index
        } else {
            0
        };

        match self.state.runtime.previously {
            None => Err(Status::ConditionsOfUseNotSatisfied),
            Some(CommandState::ListCredentials(_)) => {
                self.list_credentials(reply, Some(file_index))
            }
        }
    }

    fn register(&mut self, register: command::Register<'_>) -> Result {
        self.user_present()?;

        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        // info_now!("recv {:?}", &register);

        // 0. ykman does not call delete before register, so we need to speculatively
        // delete the credential (the credential file would be replaced, but we need
        // to delete the secret key).
        self.delete(command::Delete {
            label: register.credential.label,
        })
        .ok();

        // 1. Store secret in Trussed
        let raw_key = register.credential.secret;
        let key_handle = try_syscall!(self
            .trussed
            .unsafe_inject_shared_key(raw_key, crate::LOCATION))
        .map_err(|_| Status::NotEnoughMemory)?
        .key;
        // info!("new key handle: {:?}", key_handle);

        // 2. Replace secret in credential with handle
        let credential = Credential::try_from(&register.credential, key_handle)
            .map_err(|_| Status::NotEnoughMemory)?;

        // 3. Generate a filename for the credential
        let filename = self.filename_for_label(&credential.label);

        // 4. Serialize the credential (implicitly) and store it
        let write_res = self
            .state
            .try_write_file(&mut self.trussed, filename, &credential);

        if write_res.is_err() {
            // TODO reuse delete() call
            // 1. Try to delete the key from Trussed, ignore errors
            try_syscall!(self.trussed.delete(credential.secret)).ok();
            // 2. Try to delete the empty file, ignore errors
            let filename = self.filename_for_label(&credential.label);
            try_syscall!(self.trussed.remove_file(crate::LOCATION, filename)).ok();
            // 3. Return the original error
            write_res?
        }

        Ok(())
    }

    fn filename_for_label(&mut self, label: &[u8]) -> trussed::types::PathBuf {
        let label_hash = syscall!(self.trussed.hash_sha256(label)).hash;

        // todo: maybe use a counter instead (put it in our persistent state).
        let mut hex_filename = [0u8; 16];
        const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";
        for (i, &value) in label_hash.iter().take(8).enumerate() {
            hex_filename[2 * i] = LOOKUP[(value >> 4) as usize];
            hex_filename[2 * i + 1] = LOOKUP[(value & 0xF) as usize];
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
    fn calculate_all<const R: usize>(
        &mut self,
        calculate_all: command::CalculateAll<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let maybe_credential_enc = syscall!(self.trussed.read_dir_files_first(
            crate::LOCATION,
            Self::credential_directory(),
            None
        ))
        .data;
        let mut maybe_credential: Option<Credential> = match maybe_credential_enc {
            None => None,
            Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
        };

        while let Some(credential) = maybe_credential {
            // add to response
            reply.push(0x71).unwrap();
            reply.push(credential.label.len() as u8).unwrap();
            reply.extend_from_slice(&credential.label).unwrap();

            // calculate the value
            if credential.kind == oath::Kind::Totp {
                let truncated_digest = crate::calculate::calculate(
                    &mut self.trussed,
                    credential.algorithm,
                    calculate_all.challenge,
                    credential.secret,
                )?;
                reply.push(0x76).unwrap();
                reply.push(5).unwrap();
                reply.push(credential.digits).unwrap();
                reply.extend_from_slice(&truncated_digest).unwrap();
            } else {
                reply.push(0x77).unwrap();
                reply.push(0).unwrap();
            };

            // check if there's more
            maybe_credential = match syscall!(self.trussed.read_dir_files_next()).data {
                None => None,
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
        }

        // ran to completion
        Ok(())
    }

    fn calculate<const R: usize>(
        &mut self,
        calculate: command::Calculate<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        // info_now!("recv {:?}", &calculate);

        let credential = self
            .load_credential(calculate.label)
            .ok_or(Status::NotFound)?;

        if credential.touch_required {
            self.user_present()?;
        }

        let truncated_digest = match credential.kind {
            oath::Kind::Totp => crate::calculate::calculate(
                &mut self.trussed,
                credential.algorithm,
                calculate.challenge,
                credential.secret,
            )?,
            oath::Kind::Hotp => {
                if let Some(counter) = credential.counter {
                    self.calculate_hotp_digest_and_bump_counter(&credential, counter)?
                } else {
                    error_now!("HOTP missing its counter");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
            }
            Kind::HotpReverse => {
                // This credential kind should never be access through calculate()
                return Err(Status::SecurityStatusNotSatisfied);
            }
        };

        // SW: 71 0F 36 30 2F 73 6F 6C 6F 6B 65 79 73 37 5F 36 30 76 05 07 3D 8E 94 CF 90 00
        //
        // correct:
        // SW: 76 05 07 15 F9 B0 1F 90 00
        //
        // incorrect:
        // SW: 76 05 07 60 D2 F2 7C 90 00

        // response.push(0x71).unwrap();
        // response.push(credential.label.len() as u8).unwrap();
        // response.extend_from_slice(credential.label).unwrap();

        reply.push(0x76).unwrap();
        reply.push(5).unwrap();
        reply.push(credential.digits).unwrap();
        reply.extend_from_slice(&truncated_digest).unwrap();
        Ok(())
    }

    fn validate<const R: usize>(
        &mut self,
        validate: command::Validate<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        let command::Validate {
            response,
            challenge,
        } = validate;

        if let Some(key) = self
            .state
            .with_persistent(&mut self.trussed, |_, state| state.authorization_key)
        {
            debug_now!("key set: {:?}", key);

            // 1. verify what the client sent (rotating challenge)
            let verification = try_syscall!(self
                .trussed
                .sign_hmacsha1(key, &self.state.runtime.challenge))
            .map_err(|_| Status::NotEnoughMemory)?
            .signature;

            self.state.runtime.challenge = try_syscall!(self.trussed.random_bytes(8))
                .map_err(|_| Status::NotEnoughMemory)?
                .bytes
                .as_ref()
                .try_into()
                .map_err(|_| Status::NotEnoughMemory)?;

            if verification != response {
                return Err(Status::IncorrectDataParameter);
            }

            self.state.runtime.client_newly_authorized = true;

            // 2. calculate our response to their challenge
            let response = try_syscall!(self.trussed.sign_hmacsha1(key, challenge))
                .map_err(|_| Status::NotEnoughMemory)?
                .signature;

            reply.push(0x75).ok();
            reply.push(20).ok();
            reply.extend_from_slice(&response).ok();
            debug_now!(
                "validated client! client_newly_authorized = {}",
                self.state.runtime.client_newly_authorized
            );
            Ok(())
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

        //  response: &'l [u8; 20],
        //  challenge: &'l [u8; 8],
    }

    fn clear_password(&mut self) -> Result {
        self.user_present()?;

        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        debug_now!("clearing password/key");
        if let Some(key) = self
            .state
            .try_with_persistent_mut(&mut self.trussed, |_, state| {
                let existing_key = state.authorization_key;
                state.authorization_key = None;
                Ok(existing_key)
            })
            .map_err(|_| Status::NotEnoughMemory)?
        {
            syscall!(self.trussed.delete(key));
        }
        Ok(())
    }

    fn set_password(&mut self, set_password: command::SetPassword<'_>) -> Result {
        self.user_present()?;

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

        let command::SetPassword {
            kind,
            algorithm,
            key,
            challenge,
            response,
        } = set_password;

        info_now!("just checking");
        if kind != oath::Kind::Totp || algorithm != oath::Algorithm::Sha1 {
            return Err(Status::InstructionNotSupportedOrInvalid);
        }

        info_now!("injecting the key");
        let tmp_key = try_syscall!(self
            .trussed
            .unsafe_inject_shared_key(key, Location::Volatile,))
        .map_err(|_| Status::NotEnoughMemory)?
        .key;

        let verification = syscall!(self.trussed.sign_hmacsha1(tmp_key, challenge)).signature;
        syscall!(self.trussed.delete(tmp_key));

        // not really sure why this is all sent along, I guess some kind of fear of bitrot en-route?
        if verification != response {
            return Err(Status::IncorrectDataParameter);
        }

        // all-right, we have a new password to set
        let key = try_syscall!(self.trussed.unsafe_inject_shared_key(key, crate::LOCATION,))
            .map_err(|_| Status::NotEnoughMemory)?
            .key;

        debug_now!("storing password/key");
        self.state
            .try_with_persistent_mut(&mut self.trussed, |_, state| {
                state.authorization_key = Some(key);
                Ok(())
            })
            .map_err(|_| Status::NotEnoughMemory)?;

        //  struct SetPassword<'l> {
        //      kind: oath::Kind,
        //      algorithm: oath::Algorithm,
        //      key: &'l [u8],
        //      challenge: &'l [u8],
        //      response: &'l [u8],
        // }
        Ok(())
    }

    /// Verify the HOTP code coming from a PC host, and show visually to user,
    /// that the code is correct or not, with a green or red LED respectively.
    /// Does not need authorization by design.
    ///
    /// https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code
    /// Solution contains a mean to avoid desynchronization between the host's and device's counters. Device calculates up to 9 values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10 subsequent counter positions). In case:
    ///
    /// - no code would match - the on-device counter will not be changed;
    /// - incoming code parsing would fail - the on-device counter will not be changed;
    /// - code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched code-generated HOTP counter and incremented by 1;
    /// - code would match, and the code matches counter without offset - the counter will be incremented by 1.
    ///
    /// Device will stop verifying the HOTP codes in case, when the difference between the host and on-device counters will be greater or equal to 10.
    fn verify_code<const R: usize>(&mut self, args: VerifyCode, reply: &mut Data<{ R }>) -> Result {
        const COUNTER_WINDOW_SIZE: u32 = 9;
        let credential = self.load_credential(args.label).ok_or(Status::NotFound)?;

        if credential.touch_required {
            self.user_present()?;
        }

        let code_in = args.response;

        let current_counter = match credential.kind {
            oath::Kind::HotpReverse => {
                if let Some(counter) = credential.counter {
                    counter
                } else {
                    debug_now!("HOTP missing its counter");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
            }
            _ => return Err(Status::ConditionsOfUseNotSatisfied),
        };
        let mut found = None;
        for offset in 0..=COUNTER_WINDOW_SIZE {
            // Do abort with error on the max value, so these could not be pregenerated,
            // and returned to user after overflow, or the same code used each time
            let counter = current_counter
                .checked_add(offset)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?;
            let code = self
                .calculate_hotp_code_for_counter(&credential, counter)
                .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
            if code == code_in {
                found = Some(counter);
                break;
            }
        }

        let found = match found {
            None => {
                // Failed verification
                self.wink_bad();
                self.delay_on_failure();
                return Err(Status::VerificationFailed);
            }
            Some(val) => val,
        };

        self.bump_counter_for_cred(&credential, found)?;
        self.wink_good();

        // Verification passed
        // Return "No response". Communicate only through error codes.
        reply.push(0x77).unwrap();
        reply.push(0).unwrap();
        Ok(())
    }

    fn calculate_hotp_code_for_counter(
        &mut self,
        credential: &Credential,
        counter: u32,
    ) -> iso7816::Result<u32> {
        let truncated_digest = self.calculate_hotp_digest_for_counter(credential, counter)?;
        let truncated_code = u32::from_be_bytes(truncated_digest);
        let code = (truncated_code & 0x7FFFFFFF)
            % 10u32
                .checked_pow(credential.digits as _)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?;
        debug_now!("Code for ({:?},{}): {}", credential.label, counter, code);
        Ok(code)
    }

    fn calculate_hotp_digest_and_bump_counter(
        &mut self,
        credential: &Credential,
        counter: u32,
    ) -> iso7816::Result<[u8; 4]> {
        let credential = self.bump_counter_for_cred(credential, counter)?;
        let res = self.calculate_hotp_digest_for_counter(&credential, counter)?;
        Ok(res)
    }

    fn bump_counter_for_cred(
        &mut self,
        credential: &Credential,
        counter: u32,
    ) -> Result<Credential> {
        // Do abort with error on the max value, so these could not be pregenerated,
        // and returned to user after overflow, or the same code used each time
        // load-bump counter
        let mut credential = credential.clone();
        credential.counter = Some(
            counter
                .checked_add(1)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?,
        );
        // save credential back, with the updated counter
        let filename = self.filename_for_label(&credential.label);
        self.state
            .try_write_file(&mut self.trussed, filename, &credential)?;

        Ok(credential)
    }

    fn calculate_hotp_digest_for_counter(
        &mut self,
        credential: &Credential,
        counter: u32,
    ) -> Result<[u8; 4]> {
        let counter_long: u64 = counter.into();
        crate::calculate::calculate(
            &mut self.trussed,
            credential.algorithm,
            &counter_long.to_be_bytes(),
            credential.secret,
        )
    }

    fn user_present(&mut self) -> Result {
        use crate::UP_TIMEOUT_MILLISECONDS;
        let result = syscall!(self.trussed.confirm_user_present(UP_TIMEOUT_MILLISECONDS)).result;
        result.map_err(|err| match err {
            trussed::types::consent::Error::TimedOut => Status::SecurityStatusNotSatisfied,
            _ => Status::UnspecifiedPersistentExecutionError,
        })
    }

    fn wink_bad(&mut self) {
        // TODO blink red LED infinite times, highest priority
        syscall!(self.trussed.wink(Duration::from_secs(1000)));
    }

    fn wink_good(&mut self) {
        // TODO blink green LED for 10 seconds, highest priority
        syscall!(self.trussed.wink(Duration::from_secs(10)));
    }

    fn delay_on_failure(&mut self) {

        // TODO block for the time defined in the constant
        // DESIGN allow only a couple of failures per power cycle? Similarly to the FIDO2 PIN
    }
}

impl<T, K> iso7816::App for Authenticator<T, K> {
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new(crate::YUBICO_OATH_AID)
    }
}

#[cfg(feature = "apdu-dispatch")]
impl<T, K: EncryptionKeyGetter, const C: usize, const R: usize> apdu_dispatch::app::App<C, R>
    for Authenticator<T, K>
where
    T: client::Client
        + client::HmacSha1
        + client::HmacSha256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    fn select(&mut self, apdu: &iso7816::Command<C>, reply: &mut Data<R>) -> Result {
        self.respond(apdu, reply)
    }

    fn deselect(&mut self) { /*self.deselect()*/
    }

    fn call(
        &mut self,
        _: iso7816::Interface,
        apdu: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        self.respond(apdu, reply)
    }
}
