use serde::{Deserialize, Serialize};
use trussed::{cbor_deserialize, cbor_serialize, try_syscall};
use trussed::Error::InvalidSerializationFormat;
use trussed::types::{KeyId, Message};
use crate::SERIALIZED_CREDENTIAL_BUFFER_SIZE;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedSerializedCredential{
    #[serde(rename = "D")]
    pub data:  trussed::types::Message,
    #[serde(rename = "T")]
    pub tag: trussed::types::ShortData,
    #[serde(rename = "N")]
    pub nonce: trussed::types::ShortData,
}

// obj -> serialization -> encryption -> serialization -> EncryptedSerializedData
// T -> u8

// EncryptedSerializedData -> deser -> decryption -> deser -> obj
// u8 -> T

impl TryFrom<&[u8]> for EncryptedSerializedCredential {
    type Error = trussed::error::Error;
    //fixme use own errors

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let credential = cbor_deserialize(value)
            .map_err(|_| InvalidSerializationFormat)?;
        Ok(credential)
    }
}

impl TryFrom<EncryptedSerializedCredential> for Message {
    type Error = trussed::error::Error;
    //fixme use own errors

    fn try_from(value: EncryptedSerializedCredential) -> Result<Self, Self::Error> {
        let mut buf = [0u8; SERIALIZED_CREDENTIAL_BUFFER_SIZE];
        let r = cbor_serialize(&value, &mut buf)
            .map_err(|_| trussed::error::Error::InvalidSerializationFormat)
            ?;
        let bytes = Message::from_slice(r).map_err(|_| trussed::error::Error::InvalidSerializationFormat)?;
        Ok(bytes)
    }
}

impl EncryptedSerializedCredential {

    // fn from_buffer<T>(trussed: &mut T, message: &[u8], aead: Option<&[u8]>, key_encryption_key: KeyId) -> trussed::error::Result<EncryptedSerializedCredential>
    //     where T: trussed::Client + trussed::client::Chacha8Poly1305 {
    //     Self::encrypt(trussed, message, aead, key_encryption_key)
    // }

    pub fn from_obj<T,O>(trussed: &mut T, obj: &O, aead: Option<&[u8]>, key_encryption_key: KeyId) -> trussed::error::Result<EncryptedSerializedCredential>
        where T: trussed::Client + trussed::client::Chacha8Poly1305 , O: Serialize{
        let mut buf = [0u8; SERIALIZED_CREDENTIAL_BUFFER_SIZE];
        let message = cbor_serialize(obj, &mut buf).unwrap();
        Self::encrypt_message(trussed, message, aead, key_encryption_key)
    }

    pub fn encrypt_message<T>(trussed: &mut T, message: &[u8], aead: Option<&[u8]>, key_encryption_key: KeyId) -> trussed::error::Result<EncryptedSerializedCredential>
        where T: trussed::Client + trussed::client::Chacha8Poly1305 {

        #[cfg(feature = "no-encrypted-credentials")]
        {
            return Ok(EncryptedSerializedCredential{
                data: Message::from_slice(&message).unwrap(),
                nonce: Default::default(),
                tag: Default::default(),
                // nonce: ShortData::from_slice(&[12u8, 12]).unwrap(),
                // tag: ShortData::from_slice(&[16u8, 16]).unwrap(),
            });
        }


        // nonce is provided internally via internal per-key counter, hence not passed here
        let encryption_results = try_syscall!(
                trussed
                .encrypt_chacha8poly1305(key_encryption_key, message,
                aead.unwrap_or_default(), None)
            ).unwrap();

        let encrypted_serialized_credential = EncryptedSerializedCredential{
            data: Message::from_slice(&encryption_results.ciphertext).unwrap(),
            nonce: encryption_results.nonce,
            tag: encryption_results.tag,
        };
        Ok(encrypted_serialized_credential)
    }


    pub fn decrypt<T, O>(&self, trussed: &mut T, aead: Option<&[u8]>, key_encryption_key: KeyId) -> trussed::error::Result<O>
        where T: trussed::Client + trussed::client::Chacha8Poly1305, O: for <'a> Deserialize<'a>
    {
        let message = self.decrypt_to_serialized(trussed, aead, key_encryption_key)?;
        Ok(cbor_deserialize(&message)
            .map_err(|_| trussed::error::Error::InvalidSerializationFormat)?)
    }

    pub fn decrypt_to_serialized<T>(&self, trussed: &mut T, aead: Option<&[u8]>, key_encryption_key: KeyId) -> trussed::error::Result<Message>
        where T: trussed::Client + trussed::client::Chacha8Poly1305
    {
        let esc = self;

        if esc.data.is_empty() {
            return Err(trussed::Error::InvalidSerializationFormat);
        }

        #[cfg(feature = "no-encrypted-credentials")]
        {
            return Ok(Message::from_slice(&esc.data).unwrap());
        }

        let serialized = try_syscall!(trussed.decrypt_chacha8poly1305(
            key_encryption_key,
            &esc.data,
            aead.unwrap_or_default(),
            &esc.nonce,
            &esc.tag
        ))
            .map_err(|_| trussed::error::Error::InvalidSerializationFormat)?
            .plaintext
            .ok_or(trussed::Error::InvalidSerializationFormat)?;

        Ok(serialized)
    }

}