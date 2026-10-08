//! A barebones mesh-chain client: every account is its own chain of records,
//! and each client decides which branch of an account is current using only
//! the records it holds. No signatures, storage or networking yet.
//!
//! Signing is modelled, not implemented: a record's `key` names the key that
//! signed it, and the model assumes signatures cannot be forged, so only a
//! client holding a key writes records with it. Stealing a key is modelled by
//! copying it.

mod client;
mod record;

pub use client::{Client, Invalid, Resolution, Saved, Status, WriteError};
pub use record::{AccountId, Id, Key, Payload, Record};
