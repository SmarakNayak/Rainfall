pub struct Action {
    /// Crypto suite: how to hash and verify. 255 is reserved.
    pub version: u8,
    pub parent: Option<[u8; 32]>,
    pub payload: Vec<u8>,
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
