use serde::{Deserialize, Serialize};
use trussed::types::{KeyId, Message};
use trussed::{cbor_deserialize, cbor_serialize, try_syscall};

/// The buffer size for the serialization operation of a single encrypted+serialized credential
/// The minimum size should be about 256 (the current maximum packet length)
///     + CBOR overhead (field names and map encoding) + encryption overhead (12B nonce + 16B tag)
/// The extra bytes could be used in the future, when operating on the password-extended credentials.
const SERIALIZED_OBJECT_BUFFER_SIZE: usize = 1024;

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    DeserializationToContainerError,
    DeserializationToObjectError,
    ObjectSerializationError,
    ContainerSerializationError,
    SerializationBufferTooSmall,
    FailedEncryption,
    FailedContainerSerialization,
    EmptyContainerData,
    FailedDecryption,
    EmptyDecryptedData,
}

pub type Result<T = ()> = core::result::Result<T, Error>;

impl From<Error> for trussed::error::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::DeserializationToContainerError => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::DeserializationToObjectError => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::ObjectSerializationError => trussed::error::Error::InvalidSerializationFormat,
            Error::ContainerSerializationError => trussed::error::Error::InvalidSerializationFormat,
            Error::SerializationBufferTooSmall => trussed::error::Error::InternalError,
            Error::FailedEncryption => trussed::error::Error::InternalError,
            Error::FailedContainerSerialization => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::EmptyContainerData => trussed::error::Error::WrongMessageLength,
            Error::FailedDecryption => trussed::error::Error::InvalidSerializationFormat,
            Error::EmptyDecryptedData => trussed::error::Error::WrongMessageLength,
        }
    }
}

/// Universal AEAD encrypted data container, using CBOR and Chacha8Poly1305
///
/// Encryption is realized by serializing the object using CBOR, then encrypting it using Chacha8Poly1305,
/// storing related crypto data, namely nonce and tag, and finally serializing the latter,
/// again using CBOR.
///
/// For the plaintext of size 48 bytes, the resulting container size is 87 bytes,
/// including the 28 bytes of cryptographic data overhead, and leaving 11 bytes
/// as the CBOR serialization overhead.
///
/// Decryption operation is done the same way as its counterpart, but backwards.
/// The serialized Encrypted Data Container in bytes is first deserialized, making a EDC instance,
/// and afterwards the decryption operation in Trussed is called, resulting in a original serialized
/// object, which is then deserialized to a proper instance.
///
/// CBOR was chosen as the serialization format due to its simplicity and extensibility.
/// If that is a requirement, more space efficient and faster would be postcard. Be advised however,
/// that it's format changes between major revisions (as expected with semver versioning).
///
/// This type has implemented bidirectional serialization to trussed Message object.
///
/// Showing the processing paths graphically:
/// T -> \[u8\]: object -> CBOR serialization -> EncryptedDataContainer encryption  -> CBOR serialization -> serialized EncryptedDataContainer
///
/// \[u8\] -> T: serialized EncryptedDataContainer -> CBOR deserialization -> EncryptedDataContainer decryption -> CBOR deserialization -> object
///
/// Note: to decrease the CBOR overhead it might be useful to rename the serialized object fields for
/// the serialization purposes. Use the `#[serde(rename = "A")]` attribute.
///
/// Usage example:
/// ```compile_fail
/// let kek = get_kek(trussed)?;
/// let data = EncryptedDataContainer::from_obj(trussed, obj, None, kek)?;
/// let data_serialized: Message = data.try_into()?;
/// ```
/// Future work and extensions:
/// - Generalize over serialization method
/// - Generalize buffer size
/// - Investigate postcard structure extensibility, as a means for smaller overhead for serialization
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedDataContainer {
    #[serde(rename = "D")]
    pub data: trussed::types::Message,
    #[serde(rename = "T")]
    pub tag: trussed::types::ShortData,
    #[serde(rename = "N")]
    pub nonce: trussed::types::ShortData,
}

impl TryFrom<&[u8]> for EncryptedDataContainer {
    type Error = Error;

    /// Create an instance from this serialized Encrypted Data Container
    fn try_from(value: &[u8]) -> Result<Self> {
        let credential =
            cbor_deserialize(value).map_err(|_| Error::DeserializationToContainerError)?;
        Ok(credential)
    }
}

impl TryFrom<EncryptedDataContainer> for Message {
    type Error = Error;

    /// Try to serialize EncryptedDataContainer to Bytes
    fn try_from(value: EncryptedDataContainer) -> Result<Self> {
        let mut buf = [0u8; SERIALIZED_OBJECT_BUFFER_SIZE];
        let r = cbor_serialize(&value, &mut buf).map_err(|_| Error::ObjectSerializationError)?;
        let bytes = Message::from_slice(r).map_err(|_| Error::SerializationBufferTooSmall)?;
        Ok(bytes)
    }
}

impl EncryptedDataContainer {
    /// Decrypt given Bytes and return original object instance
    pub fn decrypt_from_bytes<T, O>(
        trussed: &mut T,
        ser_encrypted: Message,
        key_encryption_key: KeyId,
    ) -> Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        for<'a> O: Deserialize<'a>,
    {
        let deserialized_container: EncryptedDataContainer =
            cbor_deserialize(&ser_encrypted).map_err(|_| Error::DeserializationToContainerError)?;

        deserialized_container.decrypt(trussed, None, key_encryption_key)
    }

    /// Create Encrypted Data Container from the given object
    pub fn from_obj<T, O>(
        trussed: &mut T,
        obj: &O,
        aead: Option<&[u8]>,
        key_encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: Serialize,
    {
        let mut buf = [0u8; SERIALIZED_OBJECT_BUFFER_SIZE];
        let message = cbor_serialize(obj, &mut buf).map_err(|_| Error::ObjectSerializationError)?;
        debug_now!("Plaintext size: {}", message.len());
        Self::encrypt_message(trussed, message, aead, key_encryption_key)
    }

    /// Encrypt given Bytes object, and return an Encrypted Data Container
    pub fn encrypt_message<T>(
        trussed: &mut T,
        message: &[u8],
        aead: Option<&[u8]>,
        key_encryption_key: KeyId,
    ) -> Result<EncryptedDataContainer>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        #[cfg(feature = "no-encrypted-credentials")]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(EncryptedDataContainer {
                data: Message::from_slice(&message).unwrap(),
                nonce: Default::default(),
                tag: Default::default(),
                // nonce: ShortData::from_slice(&[12u8, 12]).unwrap(),
                // tag: ShortData::from_slice(&[16u8, 16]).unwrap(),
            });
        }

        // nonce is provided internally via internal per-key counter, hence not passed here
        let encryption_results = try_syscall!(trussed.encrypt_chacha8poly1305(
            key_encryption_key,
            message,
            aead.unwrap_or_default(),
            None
        ))
        .map_err(|_| Error::FailedEncryption)?;

        let ciphertext = Message::from_slice(&encryption_results.ciphertext)
            .map_err(|_| Error::FailedContainerSerialization)?;

        let encrypted_serialized_credential = EncryptedDataContainer {
            data: ciphertext,
            nonce: encryption_results.nonce,
            tag: encryption_results.tag,
        };
        Ok(encrypted_serialized_credential)
    }

    /// Decrypt the content of this Encrypted Data Instance, and deserialize to the original object
    pub fn decrypt<T, O>(
        &self,
        trussed: &mut T,
        aead: Option<&[u8]>,
        key_encryption_key: KeyId,
    ) -> Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: for<'a> Deserialize<'a>,
    {
        let message = self
            .decrypt_to_serialized(trussed, aead, key_encryption_key)
            .map_err(|_| Error::DeserializationToContainerError)?;
        cbor_deserialize(&message).map_err(|_| Error::DeserializationToObjectError)
    }

    /// Decrypt the content of this Encrypted Data Instance, and return the original serialized object
    pub fn decrypt_to_serialized<T>(
        &self,
        trussed: &mut T,
        aead: Option<&[u8]>,
        key_encryption_key: KeyId,
    ) -> Result<Message>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        if self.data.is_empty() {
            return Err(Error::EmptyContainerData);
        }

        #[cfg(feature = "no-encrypted-credentials")]
        {
            // Skipping error handling, as this feature is only for the debugging purposes
            return Ok(Message::from_slice(&self.data).unwrap());
        }

        let serialized = try_syscall!(trussed.decrypt_chacha8poly1305(
            key_encryption_key,
            &self.data,
            aead.unwrap_or_default(),
            &self.nonce,
            &self.tag
        ))
        .map_err(|_| Error::FailedDecryption)?
        .plaintext
        .ok_or(Error::EmptyDecryptedData)?;

        Ok(serialized)
    }
}
