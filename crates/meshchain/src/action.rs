use crate::encoding::{DecodeError, EncodeError};

#[derive(Debug, PartialEq)]
pub struct Action {
    /// Crypto suite: how to hash and verify. 255 is reserved.
    pub version: u8,
    pub parent: Option<[u8; 32]>,
    pub payload: Vec<u8>,
}

impl Action {
    pub fn new(version: u8, parent: Option<[u8; 32]>, payload: Vec<u8>) -> Self {
        Action {
            version,
            parent,
            payload,
        }
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        // Check before writing anything, so an error leaves `out` untouched.
        // The layout below is version 0's; other versions would need their own.
        if self.version != 0 {
            return Err(EncodeError::Unsupported);
        }
        let len = u32::try_from(self.payload.len()).map_err(|_| EncodeError::TooLarge)?;
        out.push(self.version);
        match self.parent {
            None => out.push(0),
            Some(parent_bytes) => {
                out.push(1);
                out.extend_from_slice(&parent_bytes);
            }
        }
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    pub fn decode(input: &[u8]) -> Result<(Action, &[u8]), DecodeError> {
        let (&version, rest) = input.split_first().ok_or(DecodeError::Malformed)?;
        // The layout after the version byte belongs to the version, so stop
        // before reading anything we might misinterpret.
        if version != 0 {
            return Err(DecodeError::Unsupported);
        }

        let (&parent_tag, rest) = rest.split_first().ok_or(DecodeError::Malformed)?;
        let (parent, rest) = match parent_tag {
            0 => (None, rest),
            1 => {
                let (parent_bytes, rest) = rest
                    .split_first_chunk::<32>()
                    .ok_or(DecodeError::Malformed)?;
                (Some(*parent_bytes), rest)
            }
            _ => return Err(DecodeError::Malformed),
        };

        let (len_bytes, rest) = rest
            .split_first_chunk::<4>()
            .ok_or(DecodeError::Malformed)?;
        let len = u32::from_le_bytes(*len_bytes) as usize;
        // Check the claimed length against the bytes actually present before
        // copying, so a short input can't make us allocate a huge buffer.
        let (payload, rest) = rest.split_at_checked(len).ok_or(DecodeError::Malformed)?;

        let action = Action {
            version,
            parent,
            payload: payload.to_vec(),
        };
        Ok((action, rest))
    }
}

pub struct SignedAction {
    pub action: Action,
    pub signature: [u8; 64],
}

/// The genesis id is the main identifier of a person. It is a hash of
/// their genesis action, which contains their initial public key, so a
/// valid genesis can only be created by a holder of the initial private
/// key. Importantly, that key does not grant control forever: if it's
/// lost or leaked, it can be revoked and replaced by newer keys. The
/// genesis id remains their identifier.
///
/// If the key leaks, attackers may create competing chains under the
/// victim's genesis id. It is up to the victim's friends to recognise
/// which is genuine. They already hold a copy of the original chain and
/// can contact the victim through other channels, so friends are well
/// placed to spot a fake; others rely on their friends' verdict.
pub fn get_genesis_id(genesis: &Action) -> Result<i128, &'static str> {
    if genesis.parent.is_some() {
        return Err("genesis must not have a parent");
    }
    use std::hash::{DefaultHasher, Hasher};

    // Toy hash: not cryptographic, swap for BLAKE3 later.
    let mut h = DefaultHasher::new();
    h.write_u8(genesis.version);
    h.write(&genesis.payload);
    Ok(h.finish() as i128)
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_matches::assert_matches;
    use borsh::BorshSerialize;

    const PARENT: [u8; 32] = [7; 32];

    #[derive(BorshSerialize)]
    struct BorshAction {
        version: u8,
        parent: Option<[u8; 32]>,
        payload: Vec<u8>,
    }

    #[test]
    fn encode_matches_borsh() {
        #[track_caller]
        fn case(action: Action) {
            let mut bytes = Vec::new();
            action.encode(&mut bytes).unwrap();
            let borsh_bytes = borsh::to_vec(&BorshAction {
                version: action.version,
                parent: action.parent,
                payload: action.payload,
            })
            .unwrap();
            assert_eq!(bytes, borsh_bytes);
        }

        // empty payload: length 0, no payload bytes
        case(Action::new(0, None, vec![]));
        // no parent: tag 0, nothing after it
        case(Action::new(0, None, vec![1, 2, 3]));
        // parent: tag 1, then 32 bytes
        case(Action::new(0, Some(PARENT), vec![1, 2, 3]));
        // length over 255: little-endian across two bytes
        case(Action::new(0, None, vec![0; 0x0102]));
        //alternate versions are not tested as not supported in our encoding - but supported in borsh
    }

    #[test]
    fn encoding() {
        #[track_caller]
        fn case(action: Action, expected: &str) {
            let mut bytes = Vec::new();
            action.encode(&mut bytes).unwrap();
            assert_eq!(hex::encode(&bytes), expected);
            assert_eq!(Action::decode(&bytes).unwrap(), (action, &[][..]));
        }

        // empty payload: length 0, no payload bytes
        case(Action::new(0, None, vec![]), "000000000000");
        // no parent: tag 0, nothing after it
        case(Action::new(0, None, vec![1, 2, 3]), "000003000000010203");
        // parent: tag 1, then 32 bytes
        case(
            Action::new(0, Some(PARENT), vec![1, 2, 3]),
            &format!("0001{}03000000010203", "07".repeat(32)),
        );
        // length over 255: little-endian across two bytes
        case(
            Action::new(0, None, vec![0; 0x0102]),
            &format!("000002010000{}", "00".repeat(0x0102)),
        );
    }

    #[test]
    fn unsupported_version() {
        for version in 1..=u8::MAX {
            // A valid tail follows, so this shows decode stops at the version byte.
            assert_matches!(
                Action::decode(&[version, 0, 0, 0, 0, 0]),
                Err(DecodeError::Unsupported)
            );
            assert_matches!(
                Action::new(version, None, vec![]).encode(&mut Vec::new()),
                Err(EncodeError::Unsupported)
            );
        }
    }

    #[test]
    fn failed_encode_leaves_out_untouched() {
        // Start with bytes in `out`, so clearing them would also be caught.
        let mut bytes = vec![0xff];
        Action::new(1, None, vec![]).encode(&mut bytes).unwrap_err();
        assert_eq!(bytes, [0xff]);
    }

    #[test]
    fn too_large_payload() {
        assert_matches!(
            Action::new(0, None, vec![0; u32::MAX as usize + 1]).encode(&mut Vec::new()),
            Err(EncodeError::TooLarge)
        );
    }

    #[test]
    fn encode_appends() {
        let mut bytes = vec![0xff];
        Action::new(0, None, vec![1, 2, 3])
            .encode(&mut bytes)
            .unwrap();
        assert_eq!(hex::encode(&bytes), "ff000003000000010203");
    }

    #[test]
    fn invalid_parent_tag() {
        for tag in 2..=u8::MAX {
            assert_matches!(
                Action::decode(&[0, tag, 0, 0, 0, 0]),
                Err(DecodeError::Malformed)
            );
        }
    }

    #[test]
    fn truncated() {
        #[track_caller]
        fn case(input: &str) {
            assert_matches!(
                Action::decode(&hex::decode(input).unwrap()),
                Err(DecodeError::Malformed)
            );
        }

        // no version
        case("");
        // no parent tag
        case("00");
        // parent one byte short
        case(&format!("0001{}", "07".repeat(31)));
        // parent present, no length
        case(&format!("0001{}", "07".repeat(32)));
        // length cut short (3 of 4 bytes)
        case("0000030000");
        // payload cut short (1 of 3 bytes)
        case("00000300000001");
        // length far past input: rejected, not allocated
        case("0000ffffffff010203");
    }

    #[test]
    fn trailing_bytes_are_returned() {
        let input = hex::decode("000000000000ff").unwrap();
        assert_eq!(
            Action::decode(&input).unwrap(),
            (Action::new(0, None, vec![]), &[0xff][..])
        );
    }
}
