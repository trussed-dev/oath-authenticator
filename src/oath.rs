use core::convert::TryFrom;

use serde::{Deserialize, Serialize};


pub const HMAC_MINIMUM_KEY_SIZE: usize = 14;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tag {
    Name = 0x71,
    NameList = 0x72,
    Key = 0x73,
    Challenge = 0x74,
    Response = 0x75,
    /// Tag denots what follows is (digits, dynamically truncated HMAC digest)
    ///
    /// The client then further processes u32::from_be_bytes(truncated-digest)/10**digits.
    TruncatedResponse = 0x76,
    Hotp = 0x77,
    Property = 0x78,
    Version = 0x79,
    InitialMovingFactor = 0x7a,
    Algorithm = 0x7b,
    Touch = 0x7c,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Algorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl TryFrom<u8> for Algorithm {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use Algorithm::*;
        Ok(match byte & 0x0f {
            0x1 => Sha1,
            0x2 => Sha256,
            0x3 => Sha512,
            _ => return Err(Self::Error::IncorrectDataParameter),
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Kind {
    Hotp = 0x10,
    Totp = 0x20,
}

impl TryFrom<u8> for Kind {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Ok(match byte & 0xf0 {
            0x10 => Kind::Hotp,
            0x20 => Kind::Totp,
            _ => return Err(Self::Error::IncorrectDataParameter),
        })
    }
}

pub fn combine(kind: Kind, algorithm: Algorithm) -> u8 {
    kind as u8 | algorithm as u8
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Properties {
    RequireTouch = 0x02,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Instruction {
    Put = 0x01,
    Delete = 0x02,
    SetCode = 0x03,
    Reset = 0x04,
    List = 0xa1,
    Calculate = 0xa2,
    Validate = 0xa3,
    CalculateAll = 0xa4,
    SendRemaining = 0xa5,
}

impl TryFrom<u8> for Instruction {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use Instruction::*;
        Ok(match byte {
            0x01 => Put,
            0x02 => Delete,
            0x03 => SetCode,
            0x04 => Reset,
            0xa1 => List,
            0xa2 => Calculate,
            0xa3 => Validate,
            0xa4 => CalculateAll,
            0xa5 => SendRemaining,
            _ => return Err(Self::Error::InstructionNotSupportedOrInvalid),
        })
    }
}

impl PartialEq<u8> for Instruction {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

// class MASK(IntEnum):
//     ALGO = 0x0f
//     TYPE = 0xf0
