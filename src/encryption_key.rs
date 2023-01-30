use trussed::types::KeyId;

pub trait EncryptionKeyGetter {
    /// Gets encryption KeyID
    fn get_encryption_key() -> KeyId;

    /// Gets encryption KeyID for the given password
    fn get_encryption_key_for_password(password: &[u8]) -> KeyId;
}
