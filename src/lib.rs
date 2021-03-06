#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate delog;
generate_macros!();

#[macro_use(hex)]
extern crate hex_literal;

pub mod authenticator;
pub use authenticator::Authenticator;
pub mod calculate;
pub mod command;
pub use command::Command;
pub mod oath;
pub mod state;

// https://git.io/JfWuD
pub const YUBICO_RID: [u8; 5] = hex!("A000000 527");
// pub const YUBICO_OTP_PIX: [u8; 3] = hex!("200101");
// pub const YUBICO_OTP_AID: &[u8] = &hex!("A000000527 2001 01");
pub const YUBICO_OATH_AID: &[u8] = &hex!("A000000527 2101");// 01");

// class AID(bytes, Enum):
//     OTP = b'\xa0\x00\x00\x05\x27 \x20\x01'
//     MGR = b'\xa0\x00\x00\x05\x27\x47\x11\x17'
//     OPGP = b'\xd2\x76\x00\x01\x24\x01'
//     OATH = b'\xa0\x00\x00\x05\x27 \x21\x01'
//     PIV = b'\xa0\x00\x00\x03\x08'
//     U2F = b'\xa0\x00\x00\x06\x47\x2f\x00\x01'  # Official
//     U2F_YUBICO = b'\xa0\x00\x00\x05\x27\x10\x02'  # Yubico - No longer used
