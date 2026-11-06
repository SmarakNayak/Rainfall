/// The hash of a record. Computed from the record, never stored on it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Id(pub [u8; 32]);

/// One entry in a person's log.
///
/// Rule (enforced by validate, not the types): `parent` is `None`
/// if and only if the payload is `Genesis`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// The record this one follows. `None` only for genesis.
    pub parent: Option<Id>,
    pub payload: Payload,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    /// Starts a log. Its hash becomes the account ID.
    /// The nonce stops two new accounts hashing to the same ID;
    /// once records carry a key, the key will do that job.
    Genesis { nonce: u64 },
    /// Application data. Meshchain stores and orders it, never reads it.
    App(Vec<u8>),
}
