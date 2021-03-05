use core::convert::{TryFrom, TryInto};

use iso7816::response::Result;
use trussed::client;

use crate::{Command, state::State};

/// The TOTP authenticator Trussed® app.
pub struct Authenticator<T> {
    state: State,
    trussed: T,
}

impl<T> Authenticator<T>
where
    T: client::Client + client::Ed255 + client::Tdes,
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
        let command: Command = command.try_into()?;

        match command {
            Command::Reset => self.reset(),
            _ => todo!(),

        }

        todo!();
    }

    fn reset(&mut self) {
        todo!();
    }
}


