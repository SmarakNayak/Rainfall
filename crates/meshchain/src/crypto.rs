//! Keys and signing. Starting with Ed25519 only.
//! With capability for extension

pub enum KeyType {
    Ed25519,
}

pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
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
                    public_key: PublicKey::Ed25519(verifying_key)
                })
            }
        };
        key_pair
    }
}