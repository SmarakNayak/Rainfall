use meshchain::{AccountId, Client, Id, Invalid, Payload, Record, Resolution, Status, WriteError};
use std::collections::BTreeSet;

struct Ids {
    alice: AccountId,
    bob: AccountId,
    cat: AccountId,
    dan: AccountId,
    eve: AccountId,
}

struct World {
    alice: Client,
    bob: Client,
    cat: Client,
    dan: Client,
    eve: Client,
    ids: Ids,
}

/// Bob's recovery quorum is Alice, Cat and Dan: any 2 of 3.
fn world() -> World {
    let [mut alice, mut bob, mut cat, mut dan, mut eve] = ["alice", "bob", "cat", "dan", "eve"].map(Client::new);
    let ids = Ids {
        alice: alice.create_account("alice"),
        bob: bob.create_account("bob"),
        cat: cat.create_account("cat"),
        dan: dan.create_account("dan"),
        eve: eve.create_account("eve"),
    };
    bob.befriend(ids.bob, ids.alice).unwrap();
    bob.set_policy(ids.bob, vec![ids.alice, ids.cat, ids.dan], 2).unwrap();
    World { alice, bob, cat, dan, eve, ids }
}

/// Every client receives every other client's records.
fn sync(clients: &mut [&mut Client]) {
    let all: Vec<Record> = clients.iter().flat_map(|c| c.all()).collect();
    for client in clients.iter_mut() {
        client.receive(all.clone());
    }
}

fn shuffled<T: Clone>(items: &[T], mut seed: u64) -> Vec<T> {
    let mut out = items.to_vec();
    for i in (1..out.len()).rev() {
        seed = (seed * 1103515245 + 12345) % (1 << 31);
        out.swap(i, (seed % (i as u64 + 1)) as usize);
    }
    out
}

fn texts(client: &Client, account: AccountId) -> Vec<String> {
    client
        .history(account)
        .into_iter()
        .filter_map(|r| match &r.payload {
            Payload::Post { text } => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn set(ids: &[Id]) -> BTreeSet<Id> {
    ids.iter().copied().collect()
}

#[test]
fn records_arriving_before_their_parents_wait_and_then_apply() {
    let World { mut bob, mut eve, ids, .. } = world();
    for text in ["one", "two", "three"] {
        bob.post(ids.bob, text).unwrap();
    }
    let mut records = bob.all();
    records.sort_by_key(|r| std::cmp::Reverse(bob.ancestry(r.id).len()));
    eve.receive(records);
    assert_eq!(eve.orphan_count(), 0);
    assert_eq!(eve.resolve(ids.bob), bob.resolve(ids.bob));
    assert_eq!(texts(&eve, ids.bob), ["one", "two", "three"]);
}

#[test]
fn a_key_signing_two_continuations_is_a_provable_fork() {
    let World { mut bob, mut eve, ids, .. } = world();
    let mut thief = Client::new("thief");
    thief.steal(&bob, ids.bob);
    let fork_point = bob.head_of(ids.bob).unwrap();
    let a = bob.post(ids.bob, "from bob").unwrap();
    let b = thief.post(ids.bob, "from thief").unwrap();
    eve.receive(bob.all().into_iter().chain(thief.all()));
    let view = eve.resolve(ids.bob);
    assert_eq!(view.head, Some(fork_point));
    let Status::Forked { forks } = view.status else { panic!("expected a fork, got {view:?}") };
    assert_eq!(set(&forks), set(&[a, b]));
}

#[test]
fn a_quorum_backed_recovery_overrides_what_the_thief_signed_afterwards() {
    let World { mut alice, mut bob, mut cat, mut eve, ids, .. } = world();
    bob.post(ids.bob, "before theft").unwrap();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut thief = Client::new("thief");
    thief.steal(&bob, ids.bob);
    thief.post(ids.bob, "thief").unwrap();

    let mut replacement = Client::new("bob-new");
    replacement.receive(bob.all());
    let claim = replacement.recover(ids.bob, last_good).unwrap();

    sync(&mut [&mut alice, &mut cat, &mut eve, &mut thief, &mut replacement]);
    assert_eq!(texts(&eve, ids.bob), ["before theft", "thief"]);
    assert_eq!(eve.resolve(ids.bob).pending, [claim]);

    alice.attest(ids.alice, claim).unwrap();
    sync(&mut [&mut alice, &mut eve]);
    assert_eq!(eve.resolve(ids.bob).pending, [claim], "one attestation is not enough");
    assert_eq!(texts(&eve, ids.bob), ["before theft", "thief"]);

    cat.attest(ids.cat, claim).unwrap();
    replacement.post(ids.bob, "back").unwrap();
    sync(&mut [&mut cat, &mut replacement, &mut eve]);
    let expected = Resolution { status: Status::Ok, head: replacement.head_of(ids.bob), pending: vec![] };
    assert_eq!(eve.resolve(ids.bob), expected);
    assert_eq!(texts(&eve, ids.bob), ["before theft", "back"]);
}

#[test]
fn attestations_from_outside_the_committed_quorum_do_not_count() {
    let World { mut alice, bob, mut eve, ids, .. } = world();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut replacement = Client::new("bob-new");
    replacement.receive(bob.all());
    let claim = replacement.recover(ids.bob, last_good).unwrap();
    alice.attest(ids.alice, claim).unwrap();
    eve.attest(ids.eve, claim).unwrap();
    sync(&mut [&mut alice, &mut replacement, &mut eve]);
    let view = eve.resolve(ids.bob);
    assert_eq!(view.head, Some(last_good));
    assert_eq!(view.pending, [claim]);
}

#[test]
fn a_policy_written_under_an_unaccepted_key_change_gives_it_no_authority() {
    let World { bob, mut eve, ids, .. } = world();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut impostor = Client::new("impostor");
    let sybils = vec![impostor.create_account("s1"), impostor.create_account("s2")];
    impostor.receive(bob.all());
    impostor.recover(ids.bob, last_good).unwrap();
    impostor.set_policy(ids.bob, sybils.clone(), 2).unwrap();
    let second = impostor.recover(ids.bob, impostor.head_of(ids.bob).unwrap()).unwrap();
    for s in sybils {
        impostor.attest(s, second).unwrap();
    }
    eve.receive(impostor.all());
    assert_eq!(eve.resolve(ids.bob).head, Some(last_good));
}

/// Known gap: a thief holding the current key can replace the quorum and then
/// recover to a key of their own. The owner can still win by recovering from a
/// point before the policy change, because the shallowest accepted claim wins.
/// Stopping the thief outright needs a delay or witnesses on policy changes.
#[test]
fn a_thief_who_swaps_the_quorum_loses_to_the_owner_recovering_from_before_the_swap() {
    let World { mut alice, bob, mut cat, mut eve, ids, .. } = world();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut thief = Client::new("thief");
    let sybils = vec![thief.create_account("s1"), thief.create_account("s2")];
    thief.steal(&bob, ids.bob);
    thief.set_policy(ids.bob, sybils.clone(), 2).unwrap();
    let thief_claim = thief.recover(ids.bob, thief.head_of(ids.bob).unwrap()).unwrap();
    for s in sybils {
        thief.attest(s, thief_claim).unwrap();
    }

    eve.receive(thief.all());
    assert_eq!(eve.resolve(ids.bob).head, Some(thief_claim), "gap: the thief wins until the owner acts");

    let mut replacement = Client::new("bob-new");
    replacement.receive(bob.all());
    let owner_claim = replacement.recover(ids.bob, last_good).unwrap();
    alice.attest(ids.alice, owner_claim).unwrap();
    cat.attest(ids.cat, owner_claim).unwrap();
    sync(&mut [&mut alice, &mut cat, &mut replacement, &mut eve]);
    assert_eq!(eve.resolve(ids.bob).head, Some(owner_claim));
}

#[test]
fn a_member_attesting_two_competing_recoveries_produces_a_dispute_that_names_them() {
    let World { mut alice, bob, mut cat, mut dan, mut eve, ids, .. } = world();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut one = Client::new("claimant-1");
    let mut two = Client::new("claimant-2");
    one.receive(bob.all());
    two.receive(bob.all());
    let first = one.recover(ids.bob, last_good).unwrap();
    let second = two.recover(ids.bob, last_good).unwrap();
    alice.attest(ids.alice, first).unwrap();
    cat.attest(ids.cat, first).unwrap();
    cat.attest(ids.cat, second).unwrap();
    dan.attest(ids.dan, second).unwrap();
    sync(&mut [&mut alice, &mut cat, &mut dan, &mut one, &mut two, &mut eve]);
    let view = eve.resolve(ids.bob);
    assert_eq!(view.head, Some(last_good));
    let Status::Disputed { competing, equivocators } = view.status else { panic!("expected a dispute, got {view:?}") };
    assert_eq!(set(&competing), set(&[first, second]));
    assert_eq!(equivocators, [ids.cat]);
}

#[test]
fn every_delivery_order_gives_every_observer_the_same_answer() {
    let World { mut alice, mut bob, mut cat, ids, .. } = world();
    bob.post(ids.bob, "before theft").unwrap();
    let last_good = bob.head_of(ids.bob).unwrap();
    let mut thief = Client::new("thief");
    thief.steal(&bob, ids.bob);
    thief.post(ids.bob, "thief").unwrap();
    let mut replacement = Client::new("bob-new");
    replacement.receive(bob.all());
    let claim = replacement.recover(ids.bob, last_good).unwrap();
    alice.attest(ids.alice, claim).unwrap();
    cat.attest(ids.cat, claim).unwrap();
    replacement.post(ids.bob, "back").unwrap();
    sync(&mut [&mut alice, &mut cat, &mut thief, &mut replacement]);

    let everything = replacement.all();
    let expected = replacement.resolve(ids.bob);
    for seed in 1..=50 {
        let mut observer = Client::new(&format!("observer-{seed}"));
        for record in shuffled(&everything, seed) {
            observer.receive([record]);
        }
        assert_eq!(observer.resolve(ids.bob), expected, "seed {seed}");
    }
}

#[test]
fn policies_must_be_a_strict_majority_of_distinct_other_accounts() {
    let World { mut bob, ids, .. } = world();
    let invalid = |e| Err(WriteError::Invalid(e));
    assert_eq!(bob.set_policy(ids.bob, vec![ids.alice, ids.cat], 1), invalid(Invalid::PolicyThreshold));
    assert_eq!(bob.set_policy(ids.bob, vec![ids.alice, ids.alice], 2), invalid(Invalid::PolicyMembers));
    assert_eq!(bob.set_policy(ids.bob, vec![ids.bob, ids.alice], 2), invalid(Invalid::PolicyMembers));
}

#[test]
fn tampered_and_forged_records_are_rejected() {
    let World { mut bob, mut eve, ids, .. } = world();
    let id = bob.post(ids.bob, "original").unwrap();
    let genuine = bob.record(id).unwrap().clone();
    let tampered = Record { payload: Payload::Post { text: "edited".into() }, ..genuine.clone() };
    let eve_key = eve.key_of(ids.eve).unwrap().clone();
    let forged = Record::new(Some(ids.bob), Some(id), eve_key, Payload::Post { text: "forged".into() });

    eve.receive(bob.all().into_iter().filter(|r| r.id != id).chain([tampered, forged.clone()]));
    assert!(eve.record(id).is_none(), "the tampered copy is dropped");
    assert_eq!(eve.rejection(id), None, "and does not get the genuine id rejected");

    // The genuine record still applies, then the forged child fails against it.
    eve.receive([genuine]);
    assert_eq!(eve.rejection(forged.id), Some(Invalid::NotControllingKey));
    assert_eq!(texts(&eve, ids.bob), ["original"]);
}
