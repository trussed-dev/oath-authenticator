use core::convert::{TryFrom, TryInto};

#[cfg(feature = "applet")]
use apdu_dispatch::applet;
use flexiber::{Encodable, EncodableHeapless};
use iso7816::response::{Data, Result, Status};
use serde::{Deserialize, Serialize};
use trussed::{client, syscall, try_syscall, types::{Location, ObjectHandle, PathBuf}};

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

impl AnswerToSelect {
    pub fn new(salt: [u8; 8]) -> Self {
        Self {
            version: Default::default(),
            salt,
            // challenge: None,
        }
    }

    // pub fn with_challenge(self, challenge: [u8; 8]) -> Self {
    //     Self {
    //         version: self.version,
    //         salt: self.salt,
    //         challenge: Some(challenge),
    //     }
    // }
}

impl<T> Authenticator<T>
where
    T: client::Client + client::Sha256 +client::Totp,
{
    pub fn new(trussed: T) -> Self {
        Self {
            state: Default::default(),
            trussed,
        }
    }

    pub fn respond(&mut self, command: &iso7816::Command) -> Result {
        let class = command.class();
        assert!(class.chain().last_or_only());
        assert!(class.secure_messaging().none());
        assert!(class.channel() == Some(0));

        // parse Iso7816Command as PivCommand
        info_now!("before command try_into");
        let command: Command = command.try_into()?;
        info_now!("{:?}", &command);

        match command {
            Command::Select(select) => self.select(select),
            Command::ListCredentials => self.list_credentials(),
            Command::Register(register) => self.register(register),
            Command::Calculate(calculate) => self.calculate(calculate),
            _ => Err(iso7816::Status::FunctionNotSupported),

        }
    }

    fn select(&mut self, select: command::Select<'_>) -> Result {
        let data = AnswerToSelect::new([1,2,3,4,1,2,3,4])
            // .with_challenge([8,7,6,5,4,3,2,1])
            .to_heapless_vec()
            .unwrap();

        Ok(Data::from(data))
    }

    /// The YK5 can store a Grande Total of 32 OATH credentials.
    fn list_credentials(&mut self) -> Result {
        info_now!("recv ListCredentials");
        // return Ok(Default::default());
        // 72 13 21
        //          74 6F 74 70  2E 64 61 6E  68 65 72 73  61 6D 2E 63  6F 6D
        // 72 07 21
        //          79 75 62 69  63 6F
        // 90 00

        let mut maybe_credential = syscall!(self.trussed.read_dir_files_first(
            Location::Internal,
            PathBuf::new(),
            None
        )).data;

        let mut response = Data::new();
        let mut file_index = 0;
        while let Some(serialized_credential) = maybe_credential {
            info_now!("serialized credential: {}", hex_str!(&data));

            // keep track, in case we need continuation
            file_index += 1;
            self.state.runtime.previously = Some(CommandState::ListCredentials(file_index));

            // deserialize
            let credential: Credential = postcard::from_bytes(&serialized_credential).unwrap();

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

    fn register(&mut self, register: command::Register<'_>) -> Result {
        info_now!("recv {:?}", &register);

        // 1. Store secret in Trussed
        let raw_key = register.credential.secret;
        let key_handle = syscall!(
            self.trussed
                .unsafe_inject_totp_key(raw_key, Location::Internal)
        ).key;
        info!("new key handle: {:?}", key_handle);

        // 2. Replace secret in credential with handle
        let credential = Credential::from(&register.credential, key_handle);

        // 3. Generate a filename for the credential
        let filename = self.filename_for_label(&credential.label);

        // 4. Serialize the credential
        let mut buf = [0u8; 256];
        let serialized = postcard::to_slice(&credential, &mut buf).unwrap();
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

        info_now!("filename: {}", core::str::from_utf8(&hex_filename).unwrap());
        hex_filename.as_ref().into()
    }

    fn calculate(&mut self, calculate: command::Calculate<'_>) -> Result {
        info_now!("recv {:?}", &calculate);

        let filename = self.filename_for_label(&calculate.label);

        let serialized_credential = try_syscall!(self.trussed.read_file(
            Location::Internal,
            filename,
        ))
            .map_err(|_| Status::NotFound)?
            .data;

        // let credential: Credential = postcard::from_bytes(serialized_credential.as_ref())
        //     .map_err(|_| anyhow::anyhow!("postcard deserialization error"))?;
        // debug!("found credential: {:?}", &credential);

        // // 2. Calculate OTP
        // let counter = *timestamp / credential.period_seconds;

        // // // TODO: take this out of Trussed again, and implement "by hand" for posterity
        // // let counter_bytes: [u8; 8] = counter.to_be_bytes();
        // // let hmac = syscall!(self.trussed.sign(
        // //     Mechanism::Totp,
        // //     credential.handle,
        // //     &counter_bytes,
        // //     SignatureSerialization::Raw,
        // // )).signature;
        // // debug!("calculated HMAC: {}", hex_str!(&hmac, 4));

        // let otp = syscall!(self.trussed.sign_totp(
        //     &credential.key_handle,
        //     counter,
        // )).signature;

        // try_syscall!(self.trussed.confirm_user_present(5_000))
        //     .map_err(|_| anyhow::anyhow!("Could not obtain confirmation of user presence!"))?;

        // let otp = u64::from_le_bytes(otp[..8].try_into().unwrap());
        todo!();
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
    T: client::Client + client::Sha256 + client::Totp,
{
    fn select(&mut self, apdu: &iso7816::Command) -> applet::Result {
        Ok(applet::Response::Respond(self.respond(apdu).unwrap()))
    }

    fn deselect(&mut self) { /*self.deselect()*/ }

    fn call(&mut self, _type: applet::InterfaceType, apdu: &iso7816::Command) -> applet::Result {
        self.respond(apdu).map(|data| applet::Response::Respond(data))
    }
}
