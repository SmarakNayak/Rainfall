//! Keys and signing. Starting with Ed25519 only.
//! With capability for extension

use ed25519_dalek::VerifyingKey;

use crate::encoding::DecodeError;

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
#[derive(Debug, PartialEq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    pub fn encode(&self, out: &mut Vec<u8>) {
        match self {
            PublicKey::Ed25519(public_key) => {
                out.push(KeyType::Ed25519.tag());
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
                // Reject small-order keys, for which anyone can forge signatures, and
                // keys with a torsion component. With torsion, cofactored and
                // cofactorless verifiers can disagree on the same signature, and one
                // private key has several valid public keys. Requiring torsion-free
                // keys means every client reaches the same verdict.
                if verifying_key.is_weak() || !verifying_key.to_edwards().is_torsion_free() {
                    return Err(DecodeError::BadKey);
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

#[cfg(test)]
mod tests {
    use super::*;

    mod key_type {
        use super::*;
        use borsh::BorshSerialize;

        #[derive(BorshSerialize)]
        #[borsh(use_discriminant = true)]
        enum BorschKeyType {
            Ed25519 = 0,
        }

        #[test]
        fn encode_matches_borsh() {
            let borsh_bytes = borsh::to_vec(&BorschKeyType::Ed25519).unwrap();
            assert_eq!(vec![KeyType::Ed25519.tag()], borsh_bytes);
        }

        #[test]
        fn ed25519_tag_is_zero() {
            assert_eq!(KeyType::Ed25519.tag(), 0);
            assert!(matches!(KeyType::from_tag(0), Ok(KeyType::Ed25519)));
        }

        #[test]
        fn unknown_tags_are_unsupported() {
            for tag in 1..=u8::MAX {
                assert!(
                    matches!(KeyType::from_tag(tag), Err(DecodeError::Unsupported)),
                    "tag {tag}"
                );
            }
        }

        #[test]
        fn reserved_tag_is_unsupported() {
            assert!(matches!(
                KeyType::from_tag(0xFF),
                Err(DecodeError::Unsupported)
            ));
        }
    }

    mod public_key {
        use super::*;
        /// Fixed seed so failures reproduce. A key derived from a seed is always
        /// in the prime-order subgroup, so it passes the strict checks.
        fn test_key() -> PublicKey {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
            PublicKey::Ed25519(signing_key.verifying_key())
        }

        /// The Ed25519 public key for the seed [1; 32].
        const TEST_KEY_BYTES: [u8; 32] = [
            138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9,
            191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92,
        ];

        /// The `PublicKey` layout written as a type Borsh can derive: an enum is a
        /// u8 variant index followed by its fields, and a fixed array has no
        /// length prefix.
        #[derive(borsh::BorshSerialize)]
        enum BorshPublicKey {
            Ed25519([u8; 32]),
        }

        #[test]
        fn encode_matches_borsh() {
            let mut bytes = Vec::new();
            test_key().encode(&mut bytes);
            let borsh_bytes = borsh::to_vec(&BorshPublicKey::Ed25519(TEST_KEY_BYTES)).unwrap();
            assert_eq!(bytes, borsh_bytes);
        }

        #[test]
        fn encode() {
            let mut bytes = Vec::new();
            test_key().encode(&mut bytes);
            let mut expected = vec![0];
            expected.extend_from_slice(&TEST_KEY_BYTES);
            assert_eq!(bytes, expected);
        }

        #[test]
        fn decode() {
            let mut key_bytes = vec![0]; //ed25519 tag is 0
            key_bytes.extend_from_slice(&TEST_KEY_BYTES);
            let Ok((decoded, rest)) = PublicKey::decode(&key_bytes) else {
                panic!("decode failed");
            };
            assert!(rest.is_empty());
            assert_eq!(decoded, test_key());
        }

        #[test]
        fn round_trip() {
            let mut bytes = Vec::new();
            test_key().encode(&mut bytes);

            let Ok((decoded, rest)) = PublicKey::decode(&bytes) else {
                panic!("decode failed");
            };
            assert!(rest.is_empty());

            let mut reencoded = Vec::new();
            decoded.encode(&mut reencoded);
            assert_eq!(reencoded, bytes);
        }
    }
}
