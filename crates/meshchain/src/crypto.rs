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

        /// Tag byte followed by `rest`.
        fn tagged(tag: u8, rest: &[u8]) -> Vec<u8> {
            let mut bytes = vec![tag];
            bytes.extend_from_slice(rest);
            bytes
        }

        /// 32 bytes encoding y = n, with x's sign bit clear.
        fn point_with_y(n: u8) -> [u8; 32] {
            let mut bytes = [0; 32];
            bytes[0] = n;
            bytes
        }

        #[test]
        fn decode_returns_trailing_bytes() {
            let mut bytes = tagged(0, &TEST_KEY_BYTES);
            bytes.push(0xAB);
            let Ok((decoded, rest)) = PublicKey::decode(&bytes) else {
                panic!("decode failed");
            };
            assert_eq!(decoded, test_key());
            assert_eq!(rest, [0xAB]);
        }

        #[test]
        fn truncated_input_is_malformed() {
            for input in [&[][..], &[0], &tagged(0, &TEST_KEY_BYTES[..31])] {
                assert!(
                    matches!(PublicKey::decode(input), Err(DecodeError::Malformed)),
                    "{} bytes",
                    input.len()
                );
            }
        }

        /// Checks that decode passes on from_tag's error rather than turning it
        /// into Malformed. The key_type tests cover every tag value.
        #[test]
        fn unknown_tag_is_unsupported() {
            let input = tagged(1, &TEST_KEY_BYTES);
            assert!(matches!(
                PublicKey::decode(&input),
                Err(DecodeError::Unsupported)
            ));
        }

        /// No x satisfies the curve equation for y = 2.
        #[test]
        fn invalid_point_is_malformed() {
            assert!(matches!(
                PublicKey::decode(&tagged(0, &point_with_y(2))),
                Err(DecodeError::Malformed)
            ));
        }

        /// y = 0 is a point of order 4, and y = 1 is the identity.
        #[test]
        fn small_order_keys_are_bad() {
            for n in [0, 1] {
                assert!(
                    matches!(
                        PublicKey::decode(&tagged(0, &point_with_y(n))),
                        Err(DecodeError::BadKey)
                    ),
                    "y = {n}"
                );
            }
        }

        #[test]
        fn torsion_key_is_bad() {
            // Precondition: a valid point that is not small-order, so this reaches
            // the torsion check rather than is_weak.
            let key = VerifyingKey::from_bytes(&point_with_y(3)).unwrap();
            assert!(!key.is_weak());

            assert!(matches!(
                PublicKey::decode(&tagged(0, &point_with_y(3))),
                Err(DecodeError::BadKey)
            ));
        }

        /// p = 2^255 - 19, little-endian. The values p..p+18 still fit in 255
        /// bits, so they are alternative spellings of y = 0..18. Accepting one
        /// would give a key two encodings, and so two genesis ids.
        #[test]
        fn non_canonical_keys_are_rejected() {
            for sign in [0x00, 0x80] {
                for d in 0..19u8 {
                    let mut key = [0xFF; 32];
                    key[0] = 0xED + d; // p's low byte is 0xED, so this never carries
                    key[31] = 0x7F | sign; // the top bit is x's sign, not part of y
                    assert!(
                        PublicKey::decode(&tagged(0, &key)).is_err(),
                        "y = p + {d}, sign {sign:#x}"
                    );
                }
            }
        }
    }
}
