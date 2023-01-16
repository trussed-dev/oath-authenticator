use core::convert::TryInto;

use iso7816::Status;
use serde::{Deserialize, Serialize};
// use iso7816::response::Result;

use crate::encrypted_container;
use crate::encrypted_container::EncryptedDataContainer;
use trussed::types::Message;
use trussed::{
    postcard_deserialize, postcard_serialize_bytes, syscall, try_syscall,
    types::{KeyId, Location, PathBuf},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State {
    // at startup, trussed is not callable yet.
    // moreover, when worst comes to worst, filesystems are not available
    // persistent: Option<Persistent>,
    pub runtime: Runtime,
    // temporary "state", to be removed again
    // pub hack: Hack,
    // trussed: RefCell<Trussed<S>>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {
    pub salt: [u8; 8],
    /// This is the user's password, passed through PBKDF-HMAC-SHA1.
    /// It is used for authorization using challenge HMAC-SHA1'ing.
    pub authorization_key: Option<KeyId>,
    kek: Option<KeyId>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Runtime {
    /// Not actually used - need to figure out "many credentials" case
    pub previously: Option<CommandState>,
    /// This gets rotated regularly, so someone sniffing on the bus can't replay.
    /// There is a small window between a legitimate client authenticating,
    /// and its next command that needs such authentication.
    pub challenge: [u8; 8],
    /// Gets set after a successful VALIDATE call,
    /// good for use right after (e.g. to set/change/remove password),
    /// and cleared thereafter.
    pub client_authorized: bool,
    /// For book-keeping purposes, set client_authorized / prevents it from being cleared before
    /// returning control to caller of the app
    pub client_newly_authorized: bool,
}

impl Runtime {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl Persistent {
    pub fn password_set(&self) -> bool {
        self.authorization_key.is_some()
    }
    pub fn get_kek<T>(&mut self, trussed: &mut T) -> trussed::error::Result<KeyId>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        Ok(match self.kek {
            None => {
                let r = try_syscall!(trussed.generate_chacha8poly1305_key(Location::Internal))?.key;
                self.kek = Some(r);
                r
            }
            Some(k) => k,
        })
    }
}

impl State {
    const FILENAME: &'static str = "state.bin";

    pub fn try_write_file<T, O>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
        obj: &O,
    ) -> crate::Result
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: Serialize,
    {
        let kek = self
            .get_kek(trussed)
            .map_err(|_| iso7816::Status::UnspecifiedPersistentExecutionError)?;
        let data = EncryptedDataContainer::from_obj(trussed, obj, None, kek)
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
        let data_serialized: Message = data
            .try_into()
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
        debug_now!("Container size: {}", data_serialized.len());
        try_syscall!(trussed.write_file(Location::Internal, filename, data_serialized, None))
            .map_err(|_| iso7816::Status::NotEnoughMemory)?;
        Ok(())
    }

    pub fn get_kek<T>(&mut self, trussed: &mut T) -> trussed::error::Result<KeyId>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        let kek = self.persistent(trussed, |trussed, state| state.get_kek(trussed))?;
        Ok(kek)
    }

    pub fn decrypt_content<T, O>(
        &mut self,
        trussed: &mut T,
        ser_encrypted: Message,
    ) -> encrypted_container::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        for<'a> O: Deserialize<'a>,
    {
        let kek = self
            .get_kek(trussed)
            .map_err(|_| encrypted_container::Error::FailedDecryption)?;

        EncryptedDataContainer::decrypt_from_bytes(trussed, ser_encrypted, kek)
    }

    pub fn try_read_file<T, O>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
    ) -> trussed::error::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: for<'a> Deserialize<'a>,
    {
        let ser_encrypted = try_syscall!(trussed.read_file(Location::Internal, filename))?.data;

        debug_now!("ser_encrypted {:?}", ser_encrypted);

        self.decrypt_content(trussed, ser_encrypted)
            .map_err(|e| e.into())
    }

    pub fn try_persistent<T>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &mut Persistent) -> Result<(), Status>,
    ) -> Result<(), Status>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        let mut state: Persistent =
            try_syscall!(trussed.read_file(Location::Internal, PathBuf::from(Self::FILENAME)))
                .map(|response| postcard_deserialize(&response.data).unwrap())
                .unwrap_or_else(|_| {
                    let salt: [u8; 8] = syscall!(trussed.random_bytes(8))
                        .bytes
                        .as_ref()
                        .try_into()
                        .unwrap();
                    Persistent {
                        salt,
                        authorization_key: None,
                        kek: None,
                    }
                });

        // 2. Let the app read or modify the state
        let result = f(trussed, &mut state);

        // 3. Always write it back
        try_syscall!(trussed.write_file(
            Location::Internal,
            PathBuf::from(Self::FILENAME),
            postcard_serialize_bytes(&state).unwrap(),
            None,
        ))
        .map_err(|_| Status::NotEnoughMemory)?;

        // 4. Return whatever
        result
    }
    pub fn persistent<T, X>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &mut Persistent) -> X,
    ) -> X
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        let mut state: Persistent =
            try_syscall!(trussed.read_file(Location::Internal, PathBuf::from(Self::FILENAME)))
                .map(|response| postcard_deserialize(&response.data).unwrap())
                .unwrap_or_else(|_| {
                    let salt: [u8; 8] = syscall!(trussed.random_bytes(8))
                        .bytes
                        .as_ref()
                        .try_into()
                        .unwrap();
                    Persistent {
                        salt,
                        authorization_key: None,
                        kek: None,
                    }
                });

        // 2. Let the app read or modify the state
        let x = f(trussed, &mut state);

        // 3. Always write it back
        syscall!(trussed.write_file(
            Location::Internal,
            PathBuf::from(Self::FILENAME),
            postcard_serialize_bytes(&state).unwrap(),
            None,
        ));

        x
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandState {
    ListCredentials(usize),
}
