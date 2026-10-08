use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use sha2::{Digest, Sha256};
use std::fmt;

/// A record ID: the SHA-256 of the record's contents.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id(pub [u8; 32]);

/// An account is identified by the ID of its genesis record.
pub type AccountId = Id;

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0[..4].iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex = String::deserialize(d)?;
        let invalid = || de::Error::custom("expected 64 lowercase hex digits");
        if hex.len() != 64 {
            return Err(invalid());
        }
        let mut bytes = [0; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            let pair = &hex[2 * i..2 * i + 2];
            if !pair.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                return Err(invalid());
            }
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Id(bytes))
    }
}

/// Names the key that signed a record.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Key(pub String);

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Payload {
    Genesis { name: String },
    Post { text: String },
    Friend { peer: AccountId },
    /// The recovery quorum from this record onwards.
    Policy { members: Vec<AccountId>, threshold: usize },
    /// The author vouches for another account's key change.
    Attest { target: Id },
    /// Signed by a new key; claims the account from `parent` onwards.
    KeyChange,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// `None` only for genesis, whose own ID is the account ID.
    pub account: Option<AccountId>,
    pub parent: Option<Id>,
    pub key: Key,
    pub payload: Payload,
    pub id: Id,
}

impl Record {
    pub fn new(account: Option<AccountId>, parent: Option<Id>, key: Key, payload: Payload) -> Self {
        let mut record = Record { account, parent, key, payload, id: Id([0; 32]) };
        record.id = record.contents_hash();
        record
    }

    pub fn account_id(&self) -> AccountId {
        self.account.unwrap_or(self.id)
    }

    pub fn has_valid_id(&self) -> bool {
        self.id == self.contents_hash()
    }

    // Hashes an unambiguous encoding: fixed-size IDs, length-prefixed strings
    // and lists, and a tag byte per variant.
    fn contents_hash(&self) -> Id {
        let mut h = Sha256::new();
        put_option(&mut h, self.account);
        put_option(&mut h, self.parent);
        put_str(&mut h, &self.key.0);
        match &self.payload {
            Payload::Genesis { name } => {
                h.update([0]);
                put_str(&mut h, name);
            }
            Payload::Post { text } => {
                h.update([1]);
                put_str(&mut h, text);
            }
            Payload::Friend { peer } => {
                h.update([2]);
                h.update(peer.0);
            }
            Payload::Policy { members, threshold } => {
                h.update([3]);
                h.update((members.len() as u64).to_le_bytes());
                members.iter().for_each(|m| h.update(m.0));
                h.update((*threshold as u64).to_le_bytes());
            }
            Payload::Attest { target } => {
                h.update([4]);
                h.update(target.0);
            }
            Payload::KeyChange => h.update([5]),
        }
        Id(h.finalize().into())
    }
}

fn put_option(h: &mut Sha256, id: Option<Id>) {
    match id {
        Some(id) => {
            h.update([1]);
            h.update(id.0);
        }
        None => h.update([0]),
    }
}

fn put_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}
