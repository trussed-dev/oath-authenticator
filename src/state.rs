use core::convert::TryInto;

use iso7816::Status;
// use iso7816::response::Result;

use trussed::{
    postcard_deserialize, postcard_serialize_bytes,
    syscall, try_syscall,
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
}

impl State {
    const FILENAME: &'static str = "state.bin";

    // pub fn persistent<E, T>(
    //     &mut self,
    //     trussed: &mut T,
    //     f: impl FnOnce(&mut T, &mut Persistent) -> core::result::Result<(), E>
    // )
    //     -> Result<(), E>

    pub fn try_persistent<T>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &mut Persistent) -> Result<(), Status>
    )
        -> Result<(), Status>

    where
        T: trussed::Client,
    {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        let mut state: Persistent = try_syscall!(trussed.read_file(Location::Internal, PathBuf::from(Self::FILENAME)))
            .map(|response| postcard_deserialize(&response.data).unwrap())
            .unwrap_or_else(|_| {
                let salt: [u8; 8] = syscall!(trussed.random_bytes(8)).bytes.as_ref().try_into().unwrap();
                Persistent { salt, authorization_key: None }
            });

        // 2. Let the app read or modify the state
        let result = f(trussed, &mut state);

        // 3. Always write it back
        syscall!(trussed.write_file(
            Location::Internal,
            PathBuf::from(Self::FILENAME),
            postcard_serialize_bytes(&state).unwrap(),
            None,
        ));

        // 4. Return whatever
        result
    }
    pub fn persistent<T, X>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &mut Persistent) -> X
    )
        -> X

    where
        T: trussed::Client,
    {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        let mut state: Persistent = try_syscall!(trussed.read_file(Location::Internal, PathBuf::from(Self::FILENAME)))
            .map(|response| postcard_deserialize(&response.data).unwrap())
            .unwrap_or_else(|_| {
                let salt: [u8; 8] = syscall!(trussed.random_bytes(8)).bytes.as_ref().try_into().unwrap();
                Persistent { salt, authorization_key: None }
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

