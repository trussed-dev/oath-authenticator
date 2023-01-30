use crate::Authenticator;
use ctaphid_dispatch::app::{self, Command as HidCommand, Message};
use ctaphid_dispatch::command::VendorCommand;
use iso7816::Status;
use trussed::client;
pub const OTP_CCID: VendorCommand = VendorCommand::H70;

impl<T, K: EncryptionKeyGetter> app::App for Authenticator<T, K>
where
    T: trussed::Client
        + client::HmacSha1
        + client::HmacSha256
        + client::Sha256
        + client::Chacha8Poly1305,
{
    fn commands(&self) -> &'static [HidCommand] {
        &[HidCommand::Vendor(OTP_CCID)]
    }

    fn call(
        &mut self,
        command: HidCommand,
        input_data: &Message,
        response: &mut Message,
    ) -> app::AppResult {
        const MAX_COMMAND_LENGTH: usize = 255;
        match command {
            HidCommand::Vendor(OTP_CCID) => {
                let arr: [u8; 2] = Status::Success.into();
                response.extend(arr);
                let ctap_to_iso7816_command =
                    iso7816::Command::<MAX_COMMAND_LENGTH>::try_from(input_data).map_err(|_e| {
                        response.clear();
                        info_now!("ISO conversion error: {:?}", _e);
                        app::Error::InvalidLength
                    })?;
                let res = self.respond(&ctap_to_iso7816_command, response);

                match res {
                    Ok(_) => return Ok(()),
                    Err(Status::MoreAvailable(b)) => {
                        response[0] = 0x61;
                        response[1] = b;
                        return Ok(());
                    }
                    Err(e) => {
                        info_now!("OTP command execution error: {:?}", e);
                        let arr: [u8; 2] = e.into();
                        response.clear();
                        response.extend(arr);
                    }
                }
            }
            _ => {
                return Err(app::Error::InvalidCommand);
            }
        }
        Ok(())
    }
}
