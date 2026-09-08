# Rainfall identity-chain client

A runnable local reference client for Rainfall’s per-person identity histories.
Each observer chooses a continuation using friendship evidence. There is no
mining, global consensus or automatic endorsement-count winner.

## Run

Requires Node.js 22 or newer. There are no third-party dependencies and no install
step. From the repository root on NixOS, enter `nix develop`, then:

```sh
cd apps/chain-client
npm start
```

Open http://127.0.0.1:8787. The client stores its state in `data/state.json`.
Use separate data directories for different phones/observers:

```sh
PORT=8788 RAINFALL_DATA=data/bob npm start
```

The process binds to loopback. Local peer addresses can be entered in the UI.
Peers serve signed records; your private key and local branch selections never
leave through exports or the peer API. Keys are stored **unencrypted** in a
mode-0600 local file under a mode-0700 directory created by the client. This is a
development keystore, not Android Keystore or an encrypted wallet.

## Try the recovery scenario

```sh
npm run demo
```

This generates separate Alice, Bob, Carol, Dave and replacement-phone stores and
prints the commands to launch them. It refuses to overwrite an existing demo.
Bob’s old phone has added an attacker-created friend after the claimed change
time. Alice and Carol endorse Bob’s replacement. Review the two branches in
Alice’s UI: the attacker-created friend is not eligible under the candidate’s
historical friendship boundary. Selecting a branch does not remove its rival.
The demo preloads records for convenience; use the empty-client walkthrough
below to exercise exchange and neighbourhood discovery from scratch.

## Empty-client walkthrough

1. Create Alice and Bob in separate instances. Download each history bundle and
   import it in the other instance. Compare account IDs in person.
2. Publish a friendship offer on both clients. Exchange the bundles again, or
   configure each other’s local peer address and sync. Reciprocal offers establish
   a friendship, including recovery responsibility; one offer is insufficient.
3. Add Carol as Bob’s friend the same way. Alice’s sync discovers Bob’s offers and
   pulls Carol’s history at depth two. Discovery is not an assertion of trust.
4. Open a fresh instance for Bob’s replacement phone and import Bob’s history.
   Copy the last legitimate record hash and specify an effective change time at
   or after that record, and no later than now. Create the replacement branch.
5. Import the replacement bundle into Alice and Carol. After recognising Bob and
   verifying the displayed replacement key in person, each can attest on their
   own chain. Bob’s old private key is not needed.
6. Exchange or sync evidence. Each observer explicitly selects a branch. Peers
   keep their own decisions. A disputed signer’s evidence is labelled accordingly.

Export/import is also the bootstrap and offline transport. Peer sync is pull-only:
for two-way exchange both instances must pull, or exchange files. Sync is manual,
not a background service. No public server is required.

## Protocol implemented

Records use version 1, SHA-256 IDs, Ed25519 signatures and a deterministic,
sorted-key JSON encoding. All allowed payloads contain strings and safe integer
times, avoiding arbitrary-number canonicalisation. Public keys use base64 SPKI;
signatures use base64. Record IDs hash the signed body plus signature.

Every record contains `v`, `account`, `parent`, `time`, `kind`, `key`, `data`,
`signature`, and `id`. `time` is integer Unix milliseconds.

| Kind | Payload | Meaning |
| --- | --- | --- |
| `genesis` | `name` | Origin, with null account and parent; its hash is the account ID |
| `friend` | `peer` account ID | Friendship offer; reciprocal offers establish the relationship |
| `key-change` | `effectiveAt` | New-key-signed candidate continuation of a specific parent |
| `attest` | `target` key-change hash | Signer personally recognises a friend’s replacement key |

Ordinary events must use their parent’s controlling key. Key changes introduce a
different key, signed by that new key. They are structurally valid claims, not
automatic grants of control. Event times are monotonic along each branch;
`parent.time <= effectiveAt <= keyChange.time`.

Imports validate signatures, hashes, account continuity, allowed fields, payloads
and dependencies before committing the whole bundle. Unordered bundles and
duplicates are supported. An invalid bundle does not partially import.

The resolver follows a unique ordinary continuation. It stops at a fork or key
change until the user chooses a branch. Explicit choices are local state, never
remote authority. Conflicts remain visible after selection.

For a candidate key change, eligible affirmers are reciprocal direct friends on
its parent history with both friendship offers dated strictly before
`effectiveAt`. The other party’s offer is checked on the observer’s locally
selected history. Candidate endorsements are shown only from accounts in the
observer’s two-hop neighbourhood. All candidate evidence remains inspectable in
raw records, including excluded claims. Multiple endorsements from one account
do not count as independent people; contradictory endorsements are displayed.

Sync requests complete account histories at depth 0, 1 and 2, following offers
for discovery and reciprocal friendships for expansion. Verification dependencies
may include a more distant genesis or the target of an attestation; this does not
recursively pull every distant account’s full history. Relay replies containing
unrequested, unrelated histories are rejected.

## Scope and unresolved security rules

- This is a standalone identity client, not an SSB integration or the Android BLE
  app. No private-message or social-feed implementation is included.
- There is **no automatic consensus policy**. Attestations are evidence and each
  observer explicitly chooses; inconsistent observers are supported.
- Signed timestamps are claims, not trusted time. Backdated fake friendships and
  disputed friendship snapshots are **not solved**. This implementation must not
  be described as Sybil-proof. No pre-theft electorate can be inferred solely
  from an attacker-controlled clock.
- First-time trust bootstrap, recursively disputed attesters and freshness of
  peer data require further policy design. Conflicting signer histories are
  shown rather than silently counted as authoritative.
- Friendship removal, multi-device account control, confidential friendship
  graphs, encrypted network transport and hardware-backed key storage are not
  implemented. Public bundles reveal names, graph edges and identity events.
- The HTTP transport is deliberately limited to local loopback peers. LAN and
  internet operation need authenticated encrypted transport and peer discovery.
- Bounds: 10,000 stored records, 4 KB per record, 8 MB per exchange, 200 requested
  accounts per sync round, and 20 configured peers. These are development limits,
  not large-network performance claims.
- A directory lock prevents simultaneous writers through the server entry point.
  After an unclean process termination, check the process is gone before removing
  `client.lock`. Disk state is replaced atomically; it is not an encrypted backup.

## Checks

```sh
npm test
```

Tests exercise signatures, atomic import, key replacement, direct-friend-only
attestation, two-hop evidence, late fake friendships, conflicting continuations,
persistence, HTTP access controls and actual local relay sync.

## Local API

`GET /bundle?accounts=<comma-separated account IDs>` serves public signed records.
`GET /state` and `POST /action` require the per-process `x-rainfall-token` supplied
to the local UI. Cross-origin requests and unexpected Host headers are rejected.
Supported actions: `create`, `import`, `friend`, `recover`, `attest`, `select`,
`peers`, `sync`. See `server.js` for the small request shapes.
