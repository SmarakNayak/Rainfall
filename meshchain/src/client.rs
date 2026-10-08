use crate::record::{AccountId, Id, Key, Payload, Record};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

/// Why a record was rejected. Each check needs only the record and its parent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Invalid {
    GenesisShape,
    MissingParent,
    WrongAccount,
    KeyChangeReusesKey,
    NotControllingKey,
    PolicyMembers,
    PolicyThreshold,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WriteError {
    NoIdentity,
    ParentNotHeld,
    Invalid(Invalid),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Status {
    Unknown,
    Ok,
    /// The controlling key signed more than one continuation of `head`.
    Forked { forks: Vec<Id> },
    /// Accepted key changes branch off equally early; members who backed
    /// every one of them are named.
    Disputed { competing: Vec<Id>, equivocators: Vec<AccountId> },
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Resolution {
    pub status: Status,
    pub head: Option<Id>,
    /// Key changes seen along the way that have not reached their threshold.
    pub pending: Vec<Id>,
}

#[derive(Clone, Debug)]
struct Identity {
    key: Key,
    head: Id,
}

#[derive(Serialize, Deserialize)]
pub struct Saved {
    name: String,
    key_count: u32,
    records: Vec<Record>,
    identities: Vec<SavedIdentity>,
}

#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    account: AccountId,
    key: Key,
    head: Id,
}

fn validate(record: &Record, parent: Option<&Record>) -> Result<(), Invalid> {
    if let Payload::Genesis { .. } = record.payload {
        return match (record.account, record.parent) {
            (None, None) => Ok(()),
            _ => Err(Invalid::GenesisShape),
        };
    }
    let parent = parent.ok_or(Invalid::MissingParent)?;
    if record.account != Some(parent.account_id()) {
        return Err(Invalid::WrongAccount);
    }
    // A key change is signed by the new key; everything else by the parent's key.
    if let Payload::KeyChange = record.payload {
        return if record.key == parent.key { Err(Invalid::KeyChangeReusesKey) } else { Ok(()) };
    }
    if record.key != parent.key {
        return Err(Invalid::NotControllingKey);
    }
    if let Payload::Policy { members, threshold } = &record.payload {
        let distinct: BTreeSet<_> = members.iter().collect();
        if distinct.len() != members.len() || record.account.is_some_and(|a| distinct.contains(&a)) {
            return Err(Invalid::PolicyMembers);
        }
        // A strict majority means two competing recoveries cannot both reach
        // the threshold unless some member attests to both.
        if *threshold * 2 <= members.len() || *threshold > members.len() {
            return Err(Invalid::PolicyThreshold);
        }
    }
    Ok(())
}

pub struct Client {
    name: String,
    key_count: u32,
    records: HashMap<Id, Record>,
    children: HashMap<Id, Vec<Id>>,
    /// Target key change → attest records naming it.
    attests: HashMap<Id, Vec<Id>>,
    /// Missing parent → records waiting for it.
    orphans: HashMap<Id, Vec<Record>>,
    rejected: HashMap<Id, Invalid>,
    /// Accounts this client can write for.
    identities: HashMap<AccountId, Identity>,
}

impl Client {
    pub fn new(name: &str) -> Self {
        Client {
            name: name.to_owned(),
            key_count: 0,
            records: HashMap::new(),
            children: HashMap::new(),
            attests: HashMap::new(),
            orphans: HashMap::new(),
            rejected: HashMap::new(),
            identities: HashMap::new(),
        }
    }

    fn new_key(&mut self) -> Key {
        self.key_count += 1;
        Key(format!("{}/k{}", self.name, self.key_count))
    }

    /// Accepts records in any order; a record whose parent hasn't arrived
    /// waits. Returns the IDs that became part of this client's store, in the
    /// order they were added, including waiting records this unblocked.
    pub fn receive(&mut self, records: impl IntoIterator<Item = Record>) -> Vec<Id> {
        let mut added = Vec::new();
        for record in records {
            self.add(record, &mut added);
        }
        added
    }

    fn add(&mut self, record: Record, added: &mut Vec<Id>) {
        let mut queue = vec![record];
        while let Some(record) = queue.pop() {
            // Check the ID first. A tampered copy claiming a genuine record's
            // ID must not get that ID rejected or take its orphan slot.
            if !record.has_valid_id() || self.records.contains_key(&record.id) || self.rejected.contains_key(&record.id) {
                continue;
            }
            if let Some(parent) = record.parent.filter(|p| !self.records.contains_key(p)) {
                let waiting = self.orphans.entry(parent).or_default();
                if !waiting.iter().any(|r| r.id == record.id) {
                    waiting.push(record);
                }
                continue;
            }
            if let Err(reason) = validate(&record, record.parent.map(|p| &self.records[&p])) {
                self.rejected.insert(record.id, reason);
                continue;
            }
            if let Some(parent) = record.parent {
                self.children.entry(parent).or_default().push(record.id);
            }
            if let Payload::Attest { target } = record.payload {
                self.attests.entry(target).or_default().push(record.id);
            }
            queue.extend(self.orphans.remove(&record.id).unwrap_or_default());
            added.push(record.id);
            self.records.insert(record.id, record);
        }
    }

    /// Everything needed to rebuild this client, for saving to disk.
    pub fn save(&self) -> Saved {
        let mut identities: Vec<SavedIdentity> = self
            .identities
            .iter()
            .map(|(&account, i)| SavedIdentity { account, key: i.key.clone(), head: i.head })
            .collect();
        identities.sort_by_key(|i| i.account);
        let mut records = self.all();
        records.sort_by_key(|r| r.id);
        Saved { name: self.name.clone(), key_count: self.key_count, records, identities }
    }

    /// Rebuilds a client from saved state. Records are validated again, as if
    /// received from a peer.
    pub fn load(saved: Saved) -> Self {
        let mut client = Client::new(&saved.name);
        client.key_count = saved.key_count;
        client.receive(saved.records);
        for i in saved.identities {
            client.identities.insert(i.account, Identity { key: i.key, head: i.head });
        }
        client
    }

    /// Accounts this client can write for.
    pub fn own_accounts(&self) -> Vec<AccountId> {
        let mut accounts: Vec<AccountId> = self.identities.keys().copied().collect();
        accounts.sort();
        accounts
    }

    /// The name an account gave itself in its genesis record.
    pub fn name_of(&self, account: AccountId) -> Option<&str> {
        match &self.records.get(&account)?.payload {
            Payload::Genesis { name } => Some(name),
            _ => None,
        }
    }

    pub fn all(&self) -> Vec<Record> {
        self.records.values().cloned().collect()
    }

    pub fn record(&self, id: Id) -> Option<&Record> {
        self.records.get(&id)
    }

    pub fn rejection(&self, id: Id) -> Option<Invalid> {
        self.rejected.get(&id).copied()
    }

    pub fn orphan_count(&self) -> usize {
        self.orphans.values().map(Vec::len).sum()
    }

    pub fn key_of(&self, account: AccountId) -> Option<&Key> {
        self.identities.get(&account).map(|i| &i.key)
    }

    /// This client's own latest record for an account it writes.
    pub fn head_of(&self, account: AccountId) -> Option<Id> {
        self.identities.get(&account).map(|i| i.head)
    }

    // --- Writing ---------------------------------------------------------

    pub fn create_account(&mut self, name: &str) -> AccountId {
        let key = self.new_key();
        let record = Record::new(None, None, key.clone(), Payload::Genesis { name: name.to_owned() });
        let id = record.id;
        self.receive([record]);
        self.identities.insert(id, Identity { key, head: id });
        id
    }

    pub fn append(&mut self, account: AccountId, payload: Payload) -> Result<Id, WriteError> {
        let identity = self.identities.get(&account).ok_or(WriteError::NoIdentity)?;
        let record = Record::new(Some(account), Some(identity.head), identity.key.clone(), payload);
        let id = self.commit(record)?;
        self.identities.get_mut(&account).expect("identity checked above").head = id;
        Ok(id)
    }

    pub fn post(&mut self, account: AccountId, text: &str) -> Result<Id, WriteError> {
        self.append(account, Payload::Post { text: text.to_owned() })
    }

    pub fn befriend(&mut self, account: AccountId, peer: AccountId) -> Result<Id, WriteError> {
        self.append(account, Payload::Friend { peer })
    }

    pub fn set_policy(&mut self, account: AccountId, members: Vec<AccountId>, threshold: usize) -> Result<Id, WriteError> {
        self.append(account, Payload::Policy { members, threshold })
    }

    pub fn attest(&mut self, account: AccountId, target: Id) -> Result<Id, WriteError> {
        self.append(account, Payload::Attest { target })
    }

    /// A replacement device claims `account` from `parent`, the last record its
    /// owner knows to be legitimate. Anything the old key signed after `parent`
    /// loses if this claim is accepted.
    pub fn recover(&mut self, account: AccountId, parent: Id) -> Result<Id, WriteError> {
        let key = self.new_key();
        let id = self.commit(Record::new(Some(account), Some(parent), key.clone(), Payload::KeyChange))?;
        self.identities.insert(account, Identity { key, head: id });
        Ok(id)
    }

    /// Test helper: model a stolen device by copying an identity's key and head.
    pub fn steal(&mut self, from: &Client, account: AccountId) {
        self.receive(from.all());
        if let Some(identity) = from.identities.get(&account) {
            self.identities.insert(account, identity.clone());
        }
    }

    fn commit(&mut self, record: Record) -> Result<Id, WriteError> {
        let id = record.id;
        self.receive([record]);
        if let Some(reason) = self.rejection(id) {
            return Err(WriteError::Invalid(reason));
        }
        if !self.records.contains_key(&id) {
            return Err(WriteError::ParentNotHeld);
        }
        Ok(id)
    }

    // --- Reading ---------------------------------------------------------

    fn depth(&self, id: Id) -> usize {
        self.ancestry(id).len()
    }

    /// The records from genesis to `id`, inclusive.
    pub fn ancestry(&self, id: Id) -> Vec<&Record> {
        let mut path: Vec<&Record> = std::iter::successors(self.records.get(&id), |r| r.parent.and_then(|p| self.records.get(&p))).collect();
        path.reverse();
        path
    }

    /// The deepest record that is an ancestor of, or equal to, every given record.
    fn common_ancestor(&self, ids: &[Id]) -> Id {
        let paths: Vec<Vec<Id>> = ids.iter().map(|&id| self.ancestry(id).iter().map(|r| r.id).collect()).collect();
        let shared = (0..).take_while(|&i| paths.iter().all(|p| p.get(i).is_some() && p.get(i) == paths[0].get(i))).count();
        paths[0][shared - 1]
    }

    /// Key changes reachable from `id` through records signed by the same key.
    /// Records below an unaccepted key change are signed by a key nobody has
    /// accepted yet, so nothing in that subtree may count, including any
    /// policy it sets for itself.
    fn key_changes_below(&self, id: Id) -> Vec<&Record> {
        let mut found = Vec::new();
        let mut stack: Vec<Id> = self.children.get(&id).cloned().unwrap_or_default();
        while let Some(child) = stack.pop() {
            let record = &self.records[&child];
            if let Payload::KeyChange = record.payload {
                found.push(record);
            } else {
                stack.extend(self.children.get(&child).into_iter().flatten());
            }
        }
        found
    }

    /// The recovery policy in force at a record: the latest one on its ancestry.
    fn policy_at(&self, id: Id) -> Option<(&[AccountId], usize)> {
        self.ancestry(id).into_iter().rev().find_map(|r| match &r.payload {
            Payload::Policy { members, threshold } => Some((members.as_slice(), *threshold)),
            _ => None,
        })
    }

    /// Members of the policy in force at the key change's parent who attested
    /// to it. Any attestation on a member's chain counts, including one written
    /// with a stolen member key: a compromised member is a malicious member,
    /// which the threshold already tolerates.
    fn supporters(&self, key_change: &Record) -> Vec<AccountId> {
        let Some((members, _)) = key_change.parent.and_then(|p| self.policy_at(p)) else { return Vec::new() };
        let attesters: BTreeSet<AccountId> = self.attests.get(&key_change.id).into_iter().flatten().map(|a| self.records[a].account_id()).collect();
        members.iter().copied().filter(|m| attesters.contains(m)).collect()
    }

    fn is_accepted(&self, key_change: &Record) -> bool {
        key_change.parent.and_then(|p| self.policy_at(p)).is_some_and(|(_, threshold)| self.supporters(key_change).len() >= threshold)
    }

    /// Decides the current head of an account from the records this client holds.
    ///
    /// Starting at genesis:
    ///  1. If an accepted key change exists below the current record, jump to
    ///     the one with the shallowest parent. It claims the key was
    ///     compromised from that point, backed by a quorum committed earlier,
    ///     so it overrides any old-key records after it. Equal depths are a
    ///     dispute.
    ///  2. Otherwise follow ordinary children. Two of them means the
    ///     controlling key signed two continuations: a provable fork.
    ///  3. Unaccepted key changes are reported as pending and otherwise ignored.
    pub fn resolve(&self, account: AccountId) -> Resolution {
        let Some(genesis) = self.records.get(&account).filter(|r| matches!(r.payload, Payload::Genesis { .. })) else {
            return Resolution { status: Status::Unknown, head: None, pending: Vec::new() };
        };
        let mut pending = BTreeSet::new();
        let mut current = genesis;
        loop {
            let below = self.key_changes_below(current.id);
            let (accepted, unaccepted): (Vec<&Record>, Vec<&Record>) = below.into_iter().partition(|r| self.is_accepted(r));
            pending.extend(unaccepted.iter().map(|r| r.id));
            let done = |status, head| Resolution { status, head: Some(head), pending: pending.iter().copied().collect() };

            if let Some(shallowest) = accepted.iter().filter_map(|r| r.parent).map(|p| self.depth(p)).min() {
                let mut winners: Vec<&Record> = accepted.into_iter().filter(|r| r.parent.map(|p| self.depth(p)) == Some(shallowest)).collect();
                if winners.len() > 1 {
                    winners.sort_by_key(|r| r.id);
                    let backers: Vec<Vec<AccountId>> = winners.iter().map(|r| self.supporters(r)).collect();
                    let mut equivocators: Vec<AccountId> = backers[0].iter().copied().filter(|m| backers.iter().all(|b| b.contains(m))).collect();
                    equivocators.sort();
                    let parents: Vec<Id> = winners.iter().filter_map(|r| r.parent).collect();
                    let competing = winners.iter().map(|r| r.id).collect();
                    return done(Status::Disputed { competing, equivocators }, self.common_ancestor(&parents));
                }
                current = winners[0];
                continue;
            }

            let mut next: Vec<Id> = self.children.get(&current.id).into_iter().flatten().copied().filter(|c| !matches!(self.records[c].payload, Payload::KeyChange)).collect();
            match next.len() {
                0 => return done(Status::Ok, current.id),
                1 => current = &self.records[&next[0]],
                _ => {
                    next.sort();
                    return done(Status::Forked { forks: next }, current.id);
                }
            }
        }
    }

    /// The resolved history of an account, genesis first.
    pub fn history(&self, account: AccountId) -> Vec<&Record> {
        self.resolve(account).head.map(|h| self.ancestry(h)).unwrap_or_default()
    }
}
