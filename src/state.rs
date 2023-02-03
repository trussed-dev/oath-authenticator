use core::convert::TryInto;
use core::marker::PhantomData;

use iso7816::Status;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::encrypted_container;
use crate::encrypted_container::EncryptedDataContainer;
use crate::encryption_key::EncryptionKeyGetter;
use trussed::types::Message;
use trussed::{
    cbor_deserialize, cbor_serialize_bytes, syscall, try_syscall,
    types::{KeyId, PathBuf},
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct State<K> {
    // at startup, trussed is not callable yet.
    // moreover, when worst comes to worst, filesystems are not available
    // persistent: Option<Persistent>,
    pub runtime: Runtime,
    // temporary "state", to be removed again
    // pub hack: Hack,
    // trussed: RefCell<Trussed<S>>,
    // Count read-write access to the persistence storage. Development only.
    #[cfg(feature = "devel-counters")]
    counter_read_write: u32,
    // Count read-only access to the persistence storage. Development only.
    #[cfg(feature = "devel-counters")]
    counter_read_only: u32,

    _key_getter_marker: PhantomData<K>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {
    pub salt: [u8; 8],
    /// This is the user's password, passed through PBKDF-HMAC-SHA1.
    /// It is used for authorization using challenge HMAC-SHA1'ing.
    pub authorization_key: Option<KeyId>,
    encryption_key: Option<KeyId>,
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

    fn get_or_generate_encryption_key<T>(
        &mut self,
        trussed: &mut T,
    ) -> trussed::error::Result<KeyId>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        Ok(match self.encryption_key {
            None => {
                let r = try_syscall!(trussed.generate_chacha8poly1305_key(crate::LOCATION))?.key;
                self.encryption_key = Some(r);
                r
            }
            Some(k) => k,
        })
    }
}

impl<K: EncryptionKeyGetter> State<K> {
    const FILENAME: &'static str = "state.bin";

    pub fn new() -> Self {
        State {
            runtime: Default::default(),
            #[cfg(feature = "devel-counters")]
            counter_read_write: 0,
            #[cfg(feature = "devel-counters")]
            counter_read_only: 0,
            _key_getter_marker: Default::default(),
        }
    }

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
        let encryption_key = self
            .get_encryption_key_from_state(trussed)
            .map_err(|_| iso7816::Status::UnspecifiedPersistentExecutionError)?;
        let data = EncryptedDataContainer::from_obj(trussed, obj, None, encryption_key)
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
        let data_serialized: Message = data
            .try_into()
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
        debug_now!("Container size: {}", data_serialized.len());
        try_syscall!(trussed.write_file(crate::LOCATION, filename, data_serialized, None))
            .map_err(|_| {
                debug_now!("Failed to write the file");
                iso7816::Status::NotEnoughMemory
            })?;
        Ok(())
    }

    fn get_encryption_key_from_state<T>(&mut self, trussed: &mut T) -> trussed::error::Result<KeyId>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        let encryption_key = K::get_encryption_key();
        return Ok(encryption_key);

        // Try to read it
        let maybe_encryption_key = self.with_persistent(trussed, |_, state| state.encryption_key);

        // Generate encryption key
        let encryption_key = match maybe_encryption_key {
            Some(e) => e,
            None => self.try_with_persistent_mut(trussed, |trussed, state| {
                state.get_or_generate_encryption_key(trussed)
            })?,
        };
        Ok(encryption_key)
    }

    pub fn decrypt_content<T, O>(
        &mut self,
        trussed: &mut T,
        ser_encrypted: Message,
    ) -> encrypted_container::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let encryption_key = self
            .get_encryption_key_from_state(trussed)
            .map_err(|_| encrypted_container::Error::FailedDecryption)?;

        EncryptedDataContainer::decrypt_from_bytes(trussed, ser_encrypted, encryption_key)
    }

    pub fn try_read_file<T, O>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
    ) -> trussed::error::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let ser_encrypted = try_syscall!(trussed.read_file(crate::LOCATION, filename))?.data;

        debug_now!("ser_encrypted {:?}", ser_encrypted);

        self.decrypt_content(trussed, ser_encrypted)
            .map_err(|e| e.into())
    }

    pub fn try_with_persistent_mut<T, X>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &mut Persistent) -> Result<X, trussed::error::Error>,
    ) -> Result<X, trussed::error::Error>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        let mut state: Persistent = Self::get_persistent_or_default(trussed);

        #[cfg(feature = "devel-counters")]
        {
            self.counter_read_write += 1;
            debug_now!("Getting the state RW {}", self.counter_read_write);
        }
        // 2. Let the app read or modify the state
        let x = f(trussed, &mut state);

        // 3. Always write it back
        try_syscall!(trussed.write_file(
            crate::LOCATION,
            PathBuf::from(Self::FILENAME),
            cbor_serialize_bytes(&state).unwrap(),
            None,
        ))?;

        x
    }

    pub fn with_persistent<T, X>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &Persistent) -> X,
    ) -> X
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        let state: Persistent = Self::get_persistent_or_default(trussed);

        #[cfg(feature = "devel-counters")]
        {
            self.counter_read_only += 1;
            debug_now!("Getting the state RO {}", self.counter_read_only);
        }
        // 2. Let the app read the state
        
        f(trussed, &state)
    }

    fn get_persistent_or_default(trussed: &mut impl trussed::Client) -> Persistent {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        // TODO DESIGN discuss, should failed deserialization be reacted on differently
        // TODO handle error from getting the random bytes
        try_syscall!(trussed.read_file(crate::LOCATION, PathBuf::from(Self::FILENAME)))
            .map(|response| cbor_deserialize(&response.data))
            .map(|r| r.unwrap())
            .unwrap_or_else(|_| {
                let salt: [u8; 8] = syscall!(trussed.random_bytes(8))
                    .bytes
                    .as_ref()
                    .try_into()
                    .unwrap();
                Persistent {
                    salt,
                    authorization_key: None,
                    encryption_key: None,
                }
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandState {
    ListCredentials(usize),
}
