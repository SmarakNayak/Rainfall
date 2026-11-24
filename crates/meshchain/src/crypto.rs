//! Keys and signing. Starting with Ed25519 only.
//! With capability for extension

use ed25519_dalek::VerifyingKey;

use crate::{crypto::KeyType::Ed25519, encoding::DecodeError};

#[repr(u8)]
pub enum KeyType {
    Ed25519 = 0,
    // 0xFF reserved for extensions
}

impl KeyType {
    pub fn tag(self) -> u8 {
        self as u8
    }

    pub fn from_tag(tag: u8) -> Result<KeyType, DecodeError> {
        match tag {
            t if t == KeyType::Ed25519 as u8 => Ok(KeyType::Ed25519),
            _ => Err(DecodeError::Unsupported),
        }
    }
}

pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            PublicKey::Ed25519(public_key) => {
                out.push(Ed25519.tag());
                out.extend_from_slice(public_key.as_bytes());
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<(PublicKey, &[u8]), DecodeError> {
        let (&tag, rest) = input.split_first().ok_or(DecodeError::Malformed)?;
        match KeyType::from_tag(tag)? {
            KeyType::Ed25519 => {
                let (key_bytes, rest) = rest
                    .split_first_chunk::<32>()
                    .ok_or(DecodeError::Malformed)?;
                let verifying_key =
                    VerifyingKey::from_bytes(key_bytes).map_err(|_| DecodeError::Malformed)?;
                if verifying_key.is_weak() {
                    return Err(DecodeError::WeakKey);
                }
                Ok((PublicKey::Ed25519(verifying_key), rest))
            }
        }
    }
}

enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
}

pub struct KeyPair {
    pub public_key: PublicKey,
    private_key: PrivateKey,
}

impl KeyPair {
    pub fn generate_keypair(key_type: KeyType) -> Result<Self, getrandom::Error> {
        let key_pair = match key_type {
            KeyType::Ed25519 => {
                let mut key_buffer = [0u8; 32];
                getrandom::fill(&mut key_buffer)?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_buffer);
                let verifying_key = signing_key.verifying_key();
                Ok(KeyPair {
                    private_key: PrivateKey::Ed25519(signing_key),
                    public_key: PublicKey::Ed25519(verifying_key),
                })
            }
        };
        key_pair
    }
}
