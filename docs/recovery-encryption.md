# Rainfall recovery encryption model

Status: proposed design, not implemented. This document specifies how an
account's private data is encrypted, how friends hold pieces of it, how it is
synchronised, and how a person who has lost every device gets it back. It
builds on the identity-chain protocol in
[`apps/chain-client`](../apps/chain-client/README.md). Transport and storage
follow Syncthing's model approximately (§8).

## 1. Goals

1. **Recoverability.** A person who loses all devices, and remembers nothing,
   can restore their data with the help of `t` of the `n` friends they chose.
   The same threshold governs keys and data: any `t` holders together have
   both enough shares and enough of the encrypted data. The backup survives
   as long as no more than `n − t` holders fail, vanish or turn malicious.
2. **Confidentiality against friends.** Fewer than `t` friends, even colluding,
   learn nothing about the data or the keys protecting it.
3. **Confidentiality against storage and infrastructure.** Friends storing
   ciphertext, relays and discovery servers learn nothing beyond sizes, timing
   and who connects to whom.
4. **Integrity.** A recovering device detects a corrupt or malicious share,
   a forged backup, or a rolled-back backup, rather than silently accepting it.
5. **Separation of identity and secrets.** Getting control of the identity back
   (who you are) and getting your data back (what you had) are separate
   mechanisms, gated by the same human act: a friend recognising you.
6. **No server of record.** Relay and discovery servers are allowed, and anyone
   may run them, but they are untrusted infrastructure. No server decides who
   an account belongs to or can read its data.
7. **Tolerates spotty phone connectivity.** Nothing requires two phones to be
   online at the same moment except an in-person ceremony.

### Adversary model

No holder is assumed honest. Any holder may lie, withhold, return garbage,
collude with others, or run a modified app that ignores every rule in this
document. The design therefore guarantees:

- **Confidentiality** while at most `t − 1` holders are malicious. They learn
  nothing, whatever they do.
- **Availability** while at most `n − t` holders are malicious, unreachable or
  have lost their data. The other `t` suffice for both shares and data.
- **Integrity** with any number of malicious holders. Every share, shard,
  index and manifest is checked against a commitment signed by the owner, so
  bad data is detected and the holder that sent it is identified. Malicious
  holders can deny recovery only by being more than `n − t`.

With the strict-majority rule (§5) both bounds are about half: at the default
`n = 5, t = 3`, up to 2 holders may be malicious on either side.

Release rules (recognition, waiting period, veto, rate limit) are enforced only
by **honest** holders' apps. A malicious holder can release its share to anyone
at any time. That is why it takes `t` releases: an attacker controlling `m`
holders still has to deceive `t − m` honest holders in person, each of whom
applies the waiting period and sends recovery alerts.

### Non-goals

- Protecting against `t` or more colluding holders. That is the trust being
  delegated; the design makes it costly and visible, not impossible (see the
  optional passphrase factor in §11).
- Retroactive secrecy after a holder is removed. Removing a friend protects
  data written afterwards, not data that already existed (§7).
- Recovering the old identity signing key. It is never backed up (§2).
- Hiding traffic metadata from relays and discovery servers.

## 2. Key hierarchy

```
  Identity signing key (Ed25519)        per account, per chain branch
    └─ signs chain records, device certificates and backup manifests

  Device key (Ed25519, TLS)             per device, hardware-backed, never exported
    └─ device ID = SHA-256(public key); authenticates sync connections (§8)

  Custody key (X25519)                  per account, published on the chain
    └─ receives share deposits from friends ("I hold this for you")

  Recovery key  RK  (256-bit random)    per epoch; only ever exists as shares
    │                                   or transiently in memory
    └─ HKDF ─┬─ wrap key   WK  ──wraps──▶ Vault key VK
             └─ check value CV           (published in the manifest)

  Vault key  VK  (256-bit random)       per account, synced between own devices
    ├─ HKDF ── index key IK  ── encrypts the backup index
    └─ wraps block-key generations BK_1, BK_2, …

  Block key generation  BK_g            new generation when a holder is removed
    └─ per-block key k_b = HKDF(BK_g, SHA-256(plaintext block))
```

Why the layers:

- **RK is split, VK is not.** Re-sharing RK when holders change only re-wraps
  a 32-byte VK; the backup ciphertext is untouched.
- **VK rotates independently.** Rotating VK does not require collecting shares;
  the new VK is wrapped under the current WK, and only the small index and the
  block-key generation list are re-encrypted.
- **Block-key generations rotate lazily.** A new generation encrypts new or
  changed blocks only; unchanged blocks keep their old generation (§7).

The identity signing key is deliberately excluded from the backup. Recovery
always produces a new identity key through a `key-change` record, so a stolen
phone's key is retired rather than restored next to the thief's copy. The
backup contains what the owner cannot regenerate: VK, the custody private key
(so shares held *for friends* survive), message keys, contacts, local branch
selections and app data.

## 3. Primitives

| Purpose | Primitive |
| --- | --- |
| Signatures | Ed25519 (already used by the chain) |
| Key agreement / public-key encryption | HPKE, RFC 9180: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, `Auth` mode where the sender has a key |
| Block encryption | XChaCha20-Poly1305 with a per-block key derived from the plaintext hash (§8.5) |
| Index encryption | XChaCha20-Poly1305 under IK, random nonce |
| Key derivation | HKDF-SHA256 with domain-separated `info` strings (`rainfall/v1/wrap`, `rainfall/v1/check`, …) |
| Secret sharing | Shamir over GF(2^8), byte-wise on the 32-byte RK, `2 ≤ t ≤ n ≤ 16` |
| Hashing / commitments / block IDs | SHA-256 |
| Transport | TLS 1.3, mutual authentication with self-signed device certificates (Syncthing-style) |
| Optional passphrase | Argon2id (m = 256 MiB, t = 3, p = 1 on phones; tune per device class) |

Use audited implementations (libsodium, or `@noble/*` plus `hpke-js` in
JavaScript). No primitive in this table should be hand-rolled, including Shamir.

On Android, device keys live in the Keystore (StrongBox where present).
Keystore X25519/Ed25519 support depends on API level; where unavailable, keep
the private key encrypted under a non-exportable Keystore AES-GCM key.

## 4. Chain additions

The current chain records are public and permanent, so only public keys and
commitments go on it. New and extended record kinds, signed by the controlling
key like other ordinary events:

| Kind | Payload | Meaning |
| --- | --- | --- |
| `custody-key` | `x25519` public key | Encrypt share deposits for this account to this key. Superseded by a later `custody-key`. |
| `device` | `deviceId`, `revoked` | This device ID speaks for the account (or no longer does). |
| `key-change` (extended) | `effectiveAt`, `recoveryKey`, `deviceId` | `recoveryKey` is an X25519 key generated on the replacement device; released shares are encrypted to it. `deviceId` lets peers accept the replacement device's sync connections. |

Changing `key-change` needs a protocol version bump, since `validate` currently
requires exactly `['effectiveAt']`.

Deposits, manifests, releases and backup data travel off-chain (§8), so the
public chain does not show who holds whose shares or data.

## 5. Setup: depositing shares

The owner picks `n` holders from their reciprocal friends and a threshold `t`.

1. Generate RK and VK if not present; derive `WK = HKDF(RK, "wrap")`,
   `CV = HKDF(RK, "check")`.
2. Split RK into shares `s_1 … s_n` with threshold `t`.
3. Commit to each share:
   `c_i = SHA-256("rainfall/v1/share" ‖ account ‖ epoch ‖ i ‖ s_i)`.
   Each `s_i` is 32 uniformly distributed bytes, so `c_i` leaks nothing.
4. Build and sign the **recovery manifest** with the identity key:

   ```
   { account, epoch, seq, t, n,
     holders: [{ index, account, custodyKey }],
     commitments: [c_1 … c_n],
     cv: CV,
     wrappedVK: AEAD(WK, VK, aad = account ‖ epoch),
     passphrase: null | { salt, argon2Params },
     generations: [{ g, wrappedBK: AEAD(VK, BK_g) }],
     index: { hash, size } }
   ```

   `seq` increases with every manifest; `epoch` increases only on re-sharing.
   `index.hash` is the SHA-256 of the encrypted index (§8.5), so the signed
   manifest commits to the exact backup state.
5. For each holder, send a **deposit** encrypted with HPKE `Auth` mode to the
   holder's `custody-key`, from the owner's device key:

   ```
   HPKE(custodyKey_i, info = "rainfall/v1/deposit",
        aad = account ‖ epoch ‖ i,
        pt  = { s_i, manifest })
   ```

   The holder stores `s_i` sealed under its own device key, keeps the newest
   manifest by `seq`, and includes the deposit in **its own** backup so a
   holder losing a phone doesn't lose your share.

Deposits happen during the in-person BLE ceremony when possible, otherwise via
a sync connection or mailbox (§8), and are acknowledged with a holder-signed
receipt. The owner's app shows how many live receipts it has, and warns when
fewer than `t + 1` holders have been seen recently.

Every share holder also stores one erasure-coded shard of every block (§8.5),
so holding a share and holding data are the same role. Extra full-copy storage,
such as the owner's own home server, is optional and only adds availability.

### Choosing `t` and `n`

Default `n = 5, t = 3`; allow `n` from 3 to 16, and require a strict majority,
`t ≥ ⌊n/2⌋ + 1` (so `n = 3` needs `t = 2`). Each person holds at most one share
regardless of how many devices they own. The UI should explain the trade-off
plainly: higher `t` resists collusion and social engineering; lower `t`
tolerates unreachable friends.

**Holder choice is independent of the chain eligibility rule.** The open
problem of backdated friendships in the identity client does not affect
secrets: an attacker cannot become a holder by forging a friendship date,
because holders are exactly the accounts the owner encrypted shares to.

## 6. Recovery

```
 New device                       Holder (friend)                 Old devices (if any)
 ──────────                       ───────────────                 ────────────────────
 gen identity key, device key,
 recoveryKey; publish key-change ─▶ sees key-change
                                   in-person recognition,
                                   SAS compare over BLE
                                   writes `attest` on own chain
                                   starts release timer ─────────▶ alerted via mailboxes;
                                                                   may veto
                                   timer expires, no veto
 ◀──── release: HPKE(recoveryKey, s_i, manifest)
 collect ≥ t valid shares
 RK → CV check → WK → VK → IK, BK_g
 pull index and shards from the same ≥ t holders (§8.5)
 publish new custody-key, re-share (new epoch)
```

### 6.1 Release conditions

A holder's app releases `s_i` only when all of these hold:

1. **Recognition.** The holder's user confirmed, in person, that the claimant is
   the account owner, comparing a short authentication string derived from the
   `key-change` id and `recoveryKey`. This is the same act that produces an
   `attest` record, and the release is bound to that specific `key-change`.
2. **Waiting period.** At least `D` has passed since the holder first saw the
   key-change (default 72 hours). During it, the holder's app posts an alert to
   the mailboxes of every device the owner's chain lists and of the owner's
   other friends (§8.3).
3. **No unresolved veto.** A `recovery-veto` signed by the pre-change identity
   key and naming the `key-change` id pauses release. Because a thief holding
   an unlocked old phone can also veto, a veto is not final: it raises the wait
   to `D_veto` (default 14 days) and requires recognition to be repeated in
   person after the veto. That keeps a thief from blocking recovery forever
   while giving a legitimate owner time to respond.
4. **Rate limit.** At most one release per account per epoch to distinct
   `recoveryKey`s within `D`. Competing key-changes are shown to the holder as
   a dispute, not answered automatically.

When recognition happens in person, the release can travel over the same BLE
session. Remote recognition (a video call) is allowed only as an explicit,
slower path that uses `D_veto` as its wait, and the release is delivered by
mailbox.

### 6.2 Release message

```
HPKE(recoveryKey, mode = Auth from holder's device key,
     info = "rainfall/v1/release",
     aad  = account ‖ epoch ‖ i ‖ keyChangeId,
     pt   = { s_i, latestManifest, extraStorage })
```

Binding `keyChangeId` in the AAD means a release captured in transit cannot be
replayed to a different claimant. `extraStorage` lists any optional full-copy
storage devices the holder knows of. The holder's own shards follow over the
same connection, or by a faster local link when the release happens in person.

### 6.3 Reconstruction on the new device

1. Verify each manifest's signature against the identity key that controlled
   the chain **before** the `key-change`. Use the valid manifest with the highest
   `seq` among all those received; holders can withhold the newest one but
   cannot forge one.
2. Check each returned share against `c_i` in that manifest. Discard and flag
   any mismatch; a wrong share identifies a faulty or malicious holder.
3. With `≥ t` verified shares, interpolate RK and confirm `HKDF(RK, "check") = CV`.
4. If the manifest has a passphrase factor, derive it now (§11).
5. Unwrap VK and the block-key generations; derive IK.
6. Connect to holders (and any extra storage) as the device named in the
   `key-change` (§8.4). Fetch the encrypted index, check its hash against the
   manifest, decrypt it, then collect `t` shards per block, verifying each
   shard ID, decode and check each block ID. Small, essential files come first
   so the app is usable before media finishes.
7. Immediately: publish a new `custody-key`, start a fresh epoch (new RK, new
   shares) and rotate VK. The old epoch's shares were just exposed to the
   new device and the release channel and should not protect future data.

## 7. Maintenance

| Event | Action |
| --- | --- |
| Data changes | Encrypt new or changed blocks, write a new encrypted index, sign a manifest with `seq + 1`, send each holder its shard of every new block with the index update and manifest. Shares unchanged. |
| Holder added | New epoch: fresh RK, re-wrap VK, deposit new shares to the full set. |
| Holder removed, unreachable, or changes custody key | New epoch as above, plus a new VK and a new block-key generation. Send `custody-revoke` asking former holders to delete old shares. |
| Holder's own identity changes via `key-change` | Treat as removed until the owner re-confirms them in person; then re-deposit. |
| Holder added (data side) | The owner computes the new holder's shard index for every block from plaintext it already has and uploads only that holder's shards; other holders' shards are unchanged. |
| Holder removed (data side) | Nothing to re-encode: its shard index is simply retired. Availability drops by one until a replacement is added. |
| Threshold `t` changed | Every block must be re-encoded with the new `t` and every holder receives new shards. This is the one bulk operation, so the UI discourages changing `t`. |
| Extra full-copy storage added or removed | No key changes: it holds only ciphertext. |
| Own device added | Publish a `device` record; transfer VK, custody private key and current epoch state over the device-pairing channel; no re-sharing needed. |
| Own device lost, another still held | Publish a revoking `device` record and rotate VK; social recovery is not needed. |

Fresh RK on every holder change, rather than re-sharing the same RK, is
required. Otherwise `t` shares from an old epoch, which removed holders still
have, would still reconstruct it.

**No bulk re-encryption.** A holder change touches only key material: a new
RK, a new or re-wrapped VK, a re-encrypted index, and `n` deposits of about
1–2 KB each. After a removal, blocks written from then on use the new
block-key generation; unchanged blocks keep the old one. Re-encrypting
unchanged blocks would buy nothing, because their content predates the removal
and the old quorum could already read it. If an unchanged block is identical to
content written later, it is reused rather than re-encrypted, which reveals to
the old quorum only that the content still exists.

**Epoch overlap.** Deposits need every new holder to be reachable, so a new
epoch becomes active only once at least `t + 1` holders have returned signed
receipts. Until then, holders keep the previous epoch's shares and manifest.
When a removal is the reason for the new epoch, the owner may activate it as
soon as `t` receipts arrive.

Holders periodically (e.g. weekly) answer a liveness challenge. The response
must be impossible to compute without the share itself, otherwise a holder
could keep a small derived value, delete the share and still pass. So at
deposit time the owner draws `m` secret random challenges `x_1 … x_m` (e.g.
`m = 104`, two years of weekly checks) and keeps only the expected answers
`HMAC(s_i, x_j)`, discarding `s_i`. Each check reveals one unused `x_j`; the
holder cannot have precomputed the answer. A new epoch brings new challenges.
For shards the owner needs no stored answers: it can recompute any shard from
its own plaintext, so it challenges with a fresh nonce and random shard IDs and
expects `HMAC(nonce, shards)`. Failing or missed checks count against the
holder; too many triggers a prompt to replace it.

A passed check proves possession at that moment, not willingness to release
later. Nothing can prove the latter, which is why availability rests on the
threshold rather than on any holder's good behaviour.

## 8. Transport and storage (Syncthing-style)

Sync follows Syncthing's architecture: devices identified by certificate
hashes, mutual TLS, local and global discovery, relays as a fallback, and
block-level exchange of an index plus content-addressed blocks. Three things
differ: store-and-forward mailboxes for phones; friends store only ciphertext,
like Syncthing's untrusted, encrypted-only devices; and instead of full copies
on a few peers, data is erasure-coded across all share holders so that
availability follows the same `t`-of-`n` threshold as the keys.

### 8.1 Device identity and connections

- Each device has a long-lived Ed25519 key and a self-signed TLS certificate.
  The **device ID** is the SHA-256 of the public key, displayed in base32 with
  check characters as in Syncthing.
- Connections are TLS 1.3 with mutual authentication. Each side checks that the
  peer's certificate matches an expected device ID; no certificate authority
  is involved.
- A device ID is accepted as speaking for an account when that account's
  accepted chain branch has a `device` record or `key-change` naming it.
- Friends exchange device IDs during the BLE ceremony, so discovery never needs
  to reveal a mapping from account to device.

### 8.2 Discovery

- **Local:** LAN broadcast announcements as in Syncthing, plus BLE when phones
  are nearby.
- **Global:** devices announce `deviceId → [addresses, relay URIs]` to
  discovery servers, authenticated by their TLS certificate; peers look up by
  device ID. Anyone may run a discovery server; clients use several.
  A discovery server learns device IDs, IP addresses and who looks up whom,
  but not accounts or content.

### 8.3 Relays and mailboxes

- **Relays** work like Syncthing relays: when a direct connection fails (the
  common case on mobile carrier NAT), both devices connect out to a relay,
  which pairs them by device ID and forwards TLS bytes it cannot read. Relays
  are untrusted and rate-limited, and anyone may run one.
- **Mailboxes** are an addition Syncthing doesn't need: relays also hold small
  store-and-forward messages for devices that are offline. A message is
  addressed to a device ID, HPKE-encrypted to that device, limited to 64 KiB,
  and expires after 30 days. The recipient authenticates with its device key to
  collect. Messages carry an ID and are idempotent, so posting to several
  relays is safe.
- Everything small travels this way when there is no live connection:
  deposits, receipts, manifests, release requests and releases, vetoes,
  recovery alerts, liveness challenges and chain records.
- Recovery alerts fan out: each holder posts to every device of the owner and
  to the owner's other friends, so an alert reaches the owner through whoever
  comes online first.
- A mailbox only carries ciphertext, but it does see when a device collects
  and how much it receives.

**Wake-ups.** A device may register a **wake endpoint** with its mailboxes.
When a message arrives, the relay sends an empty request to that endpoint,
which means only "check your mailbox". Wake endpoints are an optional,
per-platform adapter, not part of the protocol:

| Client | Wake endpoint |
| --- | --- |
| iOS | Push gateway run by the app publisher, which sends an empty push through Apple's push service. The device's push token is encrypted to the gateway, so relays never see it. |
| Android with Google services | The same gateway, through Firebase Cloud Messaging, or UnifiedPush if the user prefers. |
| Android without Google services | A UnifiedPush endpoint on a server the user chooses, which any relay operator may also run. |
| Desktop, Linux, always-on nodes | None; they keep a connection open to their relays. |

The protocol must never depend on Apple or Google: a client with no wake
endpoint is fully functional and only loses latency. The gateway and the
platform push services learn only that a device was woken, and when. They can
delay or drop wake-ups but cannot read, forge or affect recovery, since
messages wait in the mailbox and recovery alerts fan out to every friend.
The gateway rate-limits wakes per token.

### 8.4 Roles and authorisation

| Peer | Holds | May fetch |
| --- | --- | --- |
| Owner's own devices | Plaintext data, VK, plaintext index | Everything |
| Share holders | Their share, signed manifests, the encrypted index, the shard table, and their own shard of every block | Other holders' shards, to repair a lost shard of their own |
| Optional extra storage (e.g. the owner's home server) | Full encrypted copy | Shards, to keep its copy complete |
| Replacement device during recovery | Nothing yet | Index and shards, once it authenticates with the device ID in a `key-change` for that account |

Holders serve shards to the owner's devices, to other holders of the same
account, and to devices named in any `key-change` they have seen for the
account. Serving ciphertext to a disputed claimant leaks nothing; the
restriction exists to stop third parties using holders as free bandwidth.

**Why erasure coding, not a few full copies.** If full copies sit on a handful
of chosen peers, those few people decide whether the backup survives,
regardless of the threshold. With a `t`-of-`n` code across all `n` holders,
any `t` holders reconstruct the data, the backup is lost only if more than
`n − t` holders lose it, and no holder ever has more than `1/t` of the
ciphertext. Recovery already requires meeting `t` holders, so the shards come
from the same people who release the shares.

### 8.5 Index and blocks

- The backup is a set of files: the app database, key material, and optionally
  media. Each file is split into blocks whose size scales with the file, from
  128 KiB to 16 MiB, as in Syncthing.
- Each block is encrypted with
  `k_b = HKDF(BK_g, info = "rainfall/v1/block" ‖ SHA-256(plaintext))` and a
  zero nonce, which is safe because each key encrypts exactly one plaintext.
  The **block ID** is SHA-256 of the ciphertext.
- Encryption is deterministic within an account and generation, so identical
  blocks deduplicate and unchanged blocks are never re-sent. Holders can see
  that two of your blocks are equal, but nothing about their content;
  different accounts' blocks never match.
- Each encrypted block is split with a Reed–Solomon code over GF(2^8) into `n`
  **shards**, any `t` of which rebuild it; shard `i` goes to holder `i`. Each
  shard is `1/t` of the block's size, so total storage is `n/t` times the
  backup (5/3 ≈ 1.7× at the default), and the **shard ID** is the SHA-256 of
  the shard.
- The **shard table** maps each block ID to its `n` shard IDs. It is not
  secret, and its hash is committed in the signed manifest, so holders and the
  recovering device can verify every shard before decoding.
- The **index** lists files with names, sizes, modification times, and for each
  block its plaintext hash, generation and block ID. It is encrypted under IK
  and small, so every holder keeps a full copy.
- Sync is BEP-like: on connecting, peers exchange which accounts they carry;
  the owner sends `IndexUpdate` (manifest, encrypted index, shard table) and
  each holder's new shards; the holder verifies each against its ID and
  acknowledges with a signed receipt naming the manifest `seq` it now fully
  holds.
- **Repair without the owner.** Coding works on ciphertext, so a holder that
  lost shards can fetch `t` other holders' shards of the same blocks and
  recompute its own, without any key.
- Holders delete shards not referenced by any of the last `K` manifests
  (default 3) after a grace period, so rollbacks during an incident remain
  possible.

### 8.6 Phone constraints

- Small messages go through mailboxes, so they don't depend on both phones
  being online.
- Bulk block transfer runs only on unmetered networks while charging, unless
  the user starts it, and at higher speed when friends meet in person
  (Wi-Fi Direct or Nearby Connections, not BLE).
- On Android, sync runs in short WorkManager windows or a foreground service
  while the app is open; iOS limits it to background processing windows.
  Optional extra storage on an always-on machine makes day-to-day sync easier,
  but survival of the backup never depends on it.
- During recovery the `t` holders are met in person, so their shards can move
  over Wi-Fi Direct or Nearby Connections at that meeting rather than through
  relays.
- The default backup excludes media, keeping it to roughly tens of MB so that
  initial upload and recovery finish over ordinary phone connections. Media
  backup is opt-in.

## 9. Threat analysis

| Threat | Outcome |
| --- | --- |
| Fewer than `t` holders collude | Learn nothing (Shamir information-theoretic secrecy). |
| `t` holders collude | Can decrypt the backup by combining shares outside the app. Inherent in social recovery; mitigated only by the threshold, careful holder choice, and the optional passphrase factor (§11). |
| Attacker social-engineers `t` holders | Must deceive each in person; the waiting period and fanned-out alerts give the real owner a window to veto and warn friends. |
| Phone thief | Has the device but not the identity: recovery rotates the identity key and VK, and friends see the dispute. Device data is protected by Keystore and the lock screen, outside this design. |
| Malicious holder returns a bad share or shard | Detected by the share commitment or shard ID; the holder is identified and recovery proceeds with others. |
| Malicious holder releases early or to an impostor | Gives the attacker one share. Release rules bind only honest holders, so the attacker still needs `t` in total (§1, adversary model). |
| Malicious holder suppresses recovery alerts | Every honest holder sends alerts independently, so silence from some does not stop them. |
| Malicious holder sends fake alerts or vetoes | Alerts must name a `key-change` that exists; vetoes must be signed by the pre-change identity key, which holders don't have. |
| Holder deletes its share but fakes liveness | Not possible: answers need `s_i` itself, against challenges it has not seen (§7). |
| Holder accumulates others' shards through repair | Gets ciphertext only. Repair requests are rate-limited to stop bandwidth abuse. |
| Holder serves a stale manifest | Highest valid `seq` wins; staleness is bounded by how many holders withhold the latest. |
| Forged backup, index or block | Rejected: the manifest is signed by the pre-change identity key, it commits to the index hash, and every block is checked against its ID. |
| Release intercepted | Encrypted to the claimant's `recoveryKey` and bound to its `key-change` id. |
| Malicious relay or mailbox | Sees ciphertext, device IDs, IPs, timing and volume. Can delay or drop messages; posting to several relays limits the damage. Cannot read, forge or replay. |
| Malicious discovery server | Can return wrong addresses, which fail TLS device ID checks, or withhold them; clients query several. Learns lookup patterns. |
| Holders drop or withhold data | Tolerated up to `n − t` holders; detected by liveness challenges, after which the owner replaces them. |
| Backdated friendship | Irrelevant to secret recovery; holders are fixed by deposit, not chain eligibility. Still relevant to which identity branch observers accept. |
| Holder loses their phone | Their deposit is in their own backup and comes back with their recovery. |
| Graph privacy | Holder and storage lists live only in encrypted deposits and manifests, not on the chain. Relays and discovery servers see which device IDs talk. The friend graph itself is already public in this protocol. |

## 10. Choosing what to back up

Default contents: VK, custody private key, chain state and local branch
selections, contacts and friend device IDs, message keys and message history.
Opt-in: media. Never: the identity signing key and device keys.

## 11. Optional passphrase factor

For people who want protection against a colluding quorum and accept the risk
of forgetting a passphrase:

```
RK = HKDF(ikm = S_social ‖ Argon2id(passphrase, salt), info = "rainfall/v1/rk")
```

where `S_social` is what Shamir reconstructs. A quorum alone then has only an
offline guessing attack, slowed by Argon2id; the strength is the passphrase's.
Forgetting the passphrase makes the backup unrecoverable, so the app should
default to off and require a successful recall test before enabling it.

## 12. Implementation plan

1. Protocol v2: `custody-key` and `device` records, `recoveryKey` and
   `deviceId` on `key-change`; tests for field validation and supersession.
2. A `recovery` module in `chain-client` (pure functions): split/combine with
   commitments, manifest build/verify, deposit/release HPKE wrapping, block and
   index encryption. Unit tests with fixed vectors, including bad-share,
   rollback, replay and tampered-block cases.
3. Replace the loopback HTTP peer API with mutual-TLS device connections and a
   BEP-like index/block exchange; then a minimal relay with mailboxes and a
   discovery server, runnable locally for tests.
4. Extend `npm run demo`: Bob deposits to Alice, Carol and Dave (`t = 2`),
   Alice and Carol also store his blocks, Bob loses his phone and recovers with
   Alice and Carol through a relay; tests show Dave's share alone and a
   tampered share both fail.
5. Mobile: Keystore-backed device and custody keys, and deposit/release inside
   the BLE ceremony after it is proven reliable (per the first milestone).

## 13. Open questions

- **Relay and discovery operation.** Who runs the default servers, and how
  clients pick among a community pool.
- **Metadata.** Relays and discovery servers see device-to-device contact
  patterns. Rotating device IDs or onion routing would reduce this, at
  significant cost in complexity.
- **Clock trust.** `D` is measured on each holder's clock; that is acceptable
  for delays but should be stated, since chain timestamps are claims.
- **Holder fatigue.** How often re-sharing prompts are acceptable before people
  ignore them.
- **Storage quotas** between friends, and what happens when a holder refuses
  shards. A holder that refuses storage can't be a holder.
- **Recovery when fewer than `t` holders remain**: none, by design. The app must
  push re-sharing before that point, not after.
