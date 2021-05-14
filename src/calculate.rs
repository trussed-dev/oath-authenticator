use core::convert::TryInto;

use trussed::{client, syscall, types::KeyId};
use crate::oath;

/// The core calculation
///
/// [RFC 4226][rfc-4226] (HOTP) only defines HMAC-SHA1
/// [RFC 6238][rfc-6238] (TOTP) also allows use of HMAC-SHA256 and HMAC-SHA512
///
/// [rfc-4226]: https://tools.ietf.org/html/rfc4226
/// [rfc-6238]: https://tools.ietf.org/html/rfc6238
pub fn calculate<T>(trussed: &mut T, algorithm: oath::Algorithm, challenge: &[u8], key: KeyId)
    -> [u8; 4]
where
    T: client::Client + client::HmacSha1 + client::HmacSha256 + client::Sha256,
{
    use oath::Algorithm::*;
    let truncated = match algorithm {
        Sha1 => {
            let digest = syscall!(trussed.sign_hmacsha1(key, challenge)).signature;
            dynamic_truncation(&digest)
        }
        Sha256 => {
            let digest = syscall!(trussed.sign_hmacsha256(key, challenge)).signature;
            dynamic_truncation(&digest)
        }
        Sha512 => unimplemented!(),
    };

    truncated.to_be_bytes()
}

fn dynamic_truncation(digest: &[u8]) -> u32 {
    // TL;DR: The standard assumes that you use the low 4 bits of the last byte of the hash, regardless of its length. So replace 19 in the original DT definition with 31 for SHA-256 or 63 for SHA-512 and you are good to go.

    // low-order bits of last byte
    let offset_bits = (*digest.last().unwrap() & 0xf) as usize;

    //
    let p = u32::from_be_bytes(digest[offset_bits..][..4].try_into().unwrap());

    // zero highest bit, avoids signed/unsigned "ambiguity"
    p & 0x7fff_ffff
}


// fn hmac_and_truncate(key: &[u8], message: &[u8], digits: u32) -> u64 {
//     use hmac::{Hmac, Mac, NewMac};
//     // let mut hmac = Hmac::<D>::new(GenericArray::from_slice(key));
//     let mut hmac = Hmac::<sha1::Sha1>::new_varkey(key).unwrap();
//     hmac.update(message);
//     let result = hmac.finalize();

//     // output of `.code()` is GenericArray<u8, OutputSize>, again 20B
//     // crypto-mac docs warn: "Be very careful using this method,
//     // since incorrect use of the code material may permit timing attacks
//     // which defeat the security provided by the Mac trait."
//     let hs = result.into_bytes();

//     dynamic_truncation(&hs) % 10_u64.pow(digits)
// }

