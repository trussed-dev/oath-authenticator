use crate::{command, oath};
use serde::{Deserialize, Serialize};
use trussed::types::{KeyId, ShortData};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialCBOR<'l> {
    #[serde(rename = "L")]
    pub label: ShortData,
    #[serde(rename = "C")]
    pub cred: Credential<'l>,
}

impl<'l> From<Credential<'l>> for CredentialCBOR<'l> {
    fn from(credential: Credential<'l>) -> Self {
        CredentialCBOR {
            label: ShortData::from_slice(credential.label).unwrap(),
            cred: credential,
        }
    }
}

impl<'l> From<&'l CredentialCBOR<'l>> for Credential<'l> {
    fn from(credential: &'l CredentialCBOR<'l>) -> Self {
        Credential {
            label: &credential.label,
            kind: credential.cred.kind,
            algorithm: credential.cred.algorithm,
            digits: credential.cred.digits,
            secret: credential.cred.secret,
            touch_required: credential.cred.touch_required,
            counter: credential.cred.counter,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credential<'l> {
    #[serde(skip)]
    pub label: &'l [u8],
    #[serde(rename = "K")]
    pub kind: oath::Kind,
    #[serde(rename = "A")]
    pub algorithm: oath::Algorithm,
    #[serde(rename = "D")]
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

    #[serde(rename = "S")]
    pub secret: KeyId,
    #[serde(rename = "T")]
    pub touch_required: bool,
    #[serde(rename = "C")]
    pub counter: Option<u32>,
}

impl<'l> Credential<'l> {
    pub fn from(credential: &command::Credential<'l>, key: KeyId) -> Self {
        Self {
            label: credential.label,
            kind: credential.kind,
            algorithm: credential.algorithm,
            digits: credential.digits,
            secret: key,
            touch_required: credential.touch_required,
            counter: credential.counter,
        }
    }
}
