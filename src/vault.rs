use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::{Algorithm, Argon2, Params, Version};
use bincode::{Decode, Encode, config, decode_from_slice, encode_to_vec};
use rand::{TryRng, rngs::SysRng};
use thiserror::Error;

const CURRENT_VERSION: u8 = 1;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;
const AUTH_TAG_LENGTH: usize = 16;

#[derive(Debug, Encode, Decode)]
struct Envelope {
    version: u8,
    salt: [u8; SALT_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    cipher_text: Vec<u8>,
}

#[derive(Debug, Encode, Decode)]
struct Payload {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct Vault {
    salt: [u8; SALT_LENGTH],
    key: [u8; KEY_LENGTH],
    payload: Payload,
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("could not generate vault randomness: {0}")]
    Random(#[source] rand::rngs::SysError),

    #[error("could not derive the vault encryption key: {0}")]
    KeyDerivation(argon2::Error),

    #[error("could not encode the vault: {0}")]
    Encode(#[source] bincode::error::EncodeError),

    #[error("malformed vault file: {0}")]
    Decode(#[source] bincode::error::DecodeError),

    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u8),

    #[error("malformed vault file: ciphertext is too short")]
    CiphertextTooShort,

    #[error("malformed vault file: invalid nonce")]
    InvalidNonce,

    #[error("incorrect master password or damaged Vault")]
    InvalidMasterPassword,

    #[error("malformed vault file: encrypted payload is invalid: {0}")]
    InvalidPayload(#[source] bincode::error::DecodeError),

    #[error("could not encrypt the vault")]
    Encryption,

    #[error("could not initialize AES-256-GCM encryption")]
    CipherInitialization,
}

impl Vault {
    pub fn new(master_password: &str) -> Result<Self, VaultError> {
        let salt = random_bytes::<SALT_LENGTH>()?;
        let key = derive_key(master_password, &salt)?;
        Ok(Self {
            salt,
            key,
            payload: Payload { bytes: Vec::new() },
        })
    }

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

fn cipher_for(key: &[u8; KEY_LENGTH]) -> Result<Aes256Gcm, VaultError> {
    Aes256Gcm::new_from_slice(key).map_err(|_| VaultError::CipherInitialization)
}

fn random_bytes<const LENGTH: usize>() -> Result<[u8; LENGTH], VaultError> {
    let mut bytes = [0u8; LENGTH];
    let mut rng = SysRng;
    rng.try_fill_bytes(&mut bytes).map_err(VaultError::Random)?;
    Ok(bytes)
}
