use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use bincode::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use rand::{TryRng, rngs::SysRng};
use thiserror::Error;

/// The version number of the currently supported serialized Vault envelope.
const CURRENT_VERSION: u8 = 1;
/// The number of bytes in the Argon2 salt.
const SALT_LENGTH: usize = 16;
/// The number of bytes in an AES-GCM nonce.
const NONCE_LENGTH: usize = 12;
/// The number of bytes in the derived AES-256 key.
const KEY_LENGTH: usize = 32;
/// The number of bytes in an AES-GCM authentication tag.
const AUTH_TAG_LENGTH: usize = 16;

/// The versioned serialized container stored on disk.
#[derive(Debug, Encode, Decode)]
struct Envelope {
    /// Identifies the format used by the envelope and its payload.
    version: u8,
    /// The salt used to derive the encryption key from the Master password.
    salt: [u8; SALT_LENGTH],
    /// The fresh nonce used for this encrypted payload.
    nonce: [u8; NONCE_LENGTH],
    /// The authenticated ciphertext containing the serialized payload.
    cipher_text: Vec<u8>,
}

/// The plaintext payload represented by the current empty Vault format.
#[derive(Debug, Encode, Decode)]
struct Payload {
    /// Opaque payload bytes reserved for credential entries in later workflows.
    bytes: Vec<u8>,
}

/// An unlocked Vault held in memory with its derived encryption key.
#[derive(Debug)]
pub struct Vault {
    /// The salt retained for subsequent saves of this Vault.
    salt: [u8; SALT_LENGTH],
    /// The derived AES-256 key; the Master password itself is not retained.
    key: [u8; KEY_LENGTH],
    /// The decrypted payload held by the open session.
    payload: Payload,
}

/// Errors raised while creating, decoding, or unlocking a Vault.
#[derive(Debug, Error)]
pub enum VaultError {
    /// The operating system could not provide cryptographically secure randomness.
    #[error("could not generate vault randomness: {0}")]
    Random(#[source] rand::rngs::SysError),

    /// Argon2 could not derive a key from the supplied Master password and salt.
    #[error("could not derive the vault encryption key: {0}")]
    KeyDerivation(argon2::Error),

    /// The Vault envelope or payload could not be serialized.
    #[error("could not encode the vault: {0}")]
    Encode(#[source] bincode::error::EncodeError),

    /// The serialized Vault envelope is malformed.
    #[error("malformed vault file: {0}")]
    Decode(#[source] bincode::error::DecodeError),

    /// The file uses a Vault format version this application does not support.
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u8),

    /// The envelope does not contain enough bytes for an authenticated ciphertext.
    #[error("malformed vault file: ciphertext is too short")]
    CiphertextTooShort,

    /// The envelope contains an invalid AES-GCM nonce.
    #[error("malformed vault file: invalid nonce")]
    InvalidNonce,

    /// Authentication failed because the password is wrong or the Vault is damaged.
    #[error("incorrect master password or damaged Vault")]
    InvalidMasterPassword,

    /// The decrypted payload is not valid for the current Vault format.
    #[error("malformed vault file: encrypted payload is invalid: {0}")]
    InvalidPayload(#[source] bincode::error::DecodeError),

    /// AES-GCM could not encrypt the serialized payload.
    #[error("could not encrypt the vault")]
    Encryption,

    /// AES-GCM could not be initialized with the derived key.
    #[error("could not initialize AES-256-GCM encryption")]
    CipherInitialization,
}

impl Vault {
    /// Creates a new empty Vault and derives its AES-256 key from the Master password.
    pub fn new(master_password: &str) -> Result<Self, VaultError> {
        let salt = random_bytes::<SALT_LENGTH>()?;
        let key = derive_key(master_password, &salt)?;
        Ok(Self {
            salt,
            key,
            payload: Payload { bytes: Vec::new() },
        })
    }

    /// Decodes and decrypts a persisted Vault with the supplied Master password.
    pub fn unlock(bytes: &[u8], master_password: &str) -> Result<Self, VaultError> {
        let envelope = decode_envelope(bytes)?;
        if envelope.version != CURRENT_VERSION {
            return Err(VaultError::UnsupportedVersion(envelope.version));
        }
        if envelope.cipher_text.len() < AUTH_TAG_LENGTH {
            return Err(VaultError::CiphertextTooShort);
        }

        let key = derive_key(master_password, &envelope.salt)?;
        let cipher = cipher_for(&key)?;
        let nonce =
            Nonce::try_from(envelope.nonce.as_slice()).map_err(|_| VaultError::InvalidNonce)?;
        let plaintext = cipher
            .decrypt(&nonce, envelope.cipher_text.as_ref())
            .map_err(|_| VaultError::InvalidMasterPassword)?;
        let payload = decode_payload(&plaintext)?;

        Ok(Self {
            salt: envelope.salt,
            key,
            payload,
        })
    }

    /// Serializes the Vault into a fresh encrypted envelope with a new nonce.
    pub fn to_bytes(&self) -> Result<Vec<u8>, VaultError> {
        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        let mut rng = SysRng;
        rng.try_fill_bytes(&mut nonce_bytes)
            .map_err(VaultError::Random)?;
        let plaintext =
            encode_to_vec(&self.payload, config::standard()).map_err(VaultError::Encode)?;
        let cipher = cipher_for(&self.key)?;
        let nonce =
            Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| VaultError::InvalidNonce)?;
        let cipher_text = cipher
            .encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| VaultError::Encryption)?;
        let envelope = Envelope {
            version: CURRENT_VERSION,
            salt: self.salt,
            nonce: nonce_bytes,
            cipher_text,
        };
        encode_to_vec(&envelope, config::standard()).map_err(VaultError::Encode)
    }
}

/// Decodes one complete Vault envelope and rejects trailing bytes.
fn decode_envelope(bytes: &[u8]) -> Result<Envelope, VaultError> {
    let (envelope, consumed): (Envelope, usize) =
        decode_from_slice(bytes, config::standard()).map_err(VaultError::Decode)?;
    if consumed != bytes.len() {
        return Err(VaultError::Decode(bincode::error::DecodeError::Other(
            "trailing data after vault envelope",
        )));
    }
    Ok(envelope)
}

/// Decodes one complete decrypted payload and rejects trailing bytes.
fn decode_payload(bytes: &[u8]) -> Result<Payload, VaultError> {
    let (payload, consumed): (Payload, usize) =
        decode_from_slice(bytes, config::standard()).map_err(VaultError::InvalidPayload)?;
    if consumed != bytes.len() {
        return Err(VaultError::InvalidPayload(
            bincode::error::DecodeError::Other("trailing data after vault payload"),
        ));
    }
    Ok(payload)
}

/// Derives the AES-256 key using the accepted Argon2id parameters.
fn derive_key(
    master_password: &str,
    salt: &[u8; SALT_LENGTH],
) -> Result<[u8; KEY_LENGTH], VaultError> {
    let mut key = [0u8; KEY_LENGTH];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default())
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(VaultError::KeyDerivation)?;
    Ok(key)
}

/// Builds an AES-256-GCM cipher from a fixed-size derived key.
fn cipher_for(key: &[u8; KEY_LENGTH]) -> Result<Aes256Gcm, VaultError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::CipherInitialization)
}

/// Fills a fixed-size byte array with operating-system randomness.
fn random_bytes<const LENGTH: usize>() -> Result<[u8; LENGTH], VaultError> {
    let mut bytes = [0u8; LENGTH];
    let mut rng = SysRng;
    rng.try_fill_bytes(&mut bytes).map_err(VaultError::Random)?;
    Ok(bytes)
}
