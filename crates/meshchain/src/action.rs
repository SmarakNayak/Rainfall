use crate::encoding::{DecodeError, EncodeError};

pub struct Action {
    /// Crypto suite: how to hash and verify. 255 is reserved.
    pub version: u8,
    pub parent: Option<[u8; 32]>,
    pub payload: Vec<u8>,
}

impl Action {
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
