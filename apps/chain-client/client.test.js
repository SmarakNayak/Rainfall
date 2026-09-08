import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, statSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { Client } from './client.js';
import { Ledger, keys, seal } from './protocol.js';
import { serve } from './server.js';

const make = name => { const c = new Client(); c.create(name, 1000); return c; };
const exchange = (...clients) => {
  const records = [...new Map(clients.flatMap(c => [...c.ledger.records]).map(([id, r]) => [id, r])).values()];
  for (const c of clients) c.import(records);
};
const friend = (a, b, time = 2000) => { exchange(a, b); a.befriend(b.state.account, time); b.befriend(a.state.account, time); exchange(a, b); };
function scenario() {
  const bob = make('Bob'), alice = make('Alice'), dave = make('Dave'), carol = make('Carol');
  friend(bob, alice); friend(alice, dave); friend(bob, carol); exchange(bob, alice, dave, carol);
  const replacement = new Client(); replacement.import([...bob.ledger.records.values()]);
  const change = replacement.recover(bob.state.head, 3000, 4000);
  return { bob, alice, dave, carol, replacement, change };
}
test('signed records reject tampering and imports are atomic, unordered and idempotent', () => {
  const a = make('Alice'), b = make('Bob'); friend(a, b);
  const records = [...a.ledger.records.values()].reverse();
  const ledger = new Ledger(records); ledger.import(records);
  assert.equal(ledger.records.size, records.length);
  const bad = structuredClone(records[0]); bad.time++;
  const fresh = new Ledger();
  assert.throws(() => fresh.import([...records.slice(1), bad]), /signature|hash/);
  assert.equal(fresh.records.size, 0);
  assert.throws(() => new Ledger([records[0]]), /dependencies/);
});
test('key change preserves account ID, names explicit time and requires explicit acceptance', () => {
  const { alice, bob, replacement, change } = scenario();
  alice.import([...replacement.ledger.records.values()]);
  assert.equal(change.account, bob.state.account);
  assert.equal(change.data.effectiveAt, 3000);
  assert.equal(alice.resolved(bob.state.account).status, 'pending-key-change');
  assert.notEqual(alice.resolved(bob.state.account).head, change.id);
  alice.select(bob.state.account, change.id);
  assert.equal(alice.resolved(bob.state.account).head, change.id);
});
test('only direct friends affirm; two-hop observers receive evidence', () => {
  const { alice, bob, dave, replacement, change } = scenario();
  exchange(alice, dave, replacement);
  assert.throws(() => dave.attest(change.id, 5000), /direct friend/);
  alice.attest(change.id, 5000); exchange(alice, dave);
  assert.equal(dave.neighbourhood().get(bob.state.account), 2);
  assert.equal(dave.evidence(change).find(e => e.account === alice.state.account).supports, true);
});
test('post-change fake friendships cannot endorse a recovery even with valid signatures', () => {
  const { bob, replacement, change } = scenario();
  const fake = make('Fake'); friend(bob, fake, 3500);
  exchange(fake, replacement);
  assert.throws(() => fake.attest(change.id, 5000), /direct friend/);
  // A malicious client can bypass its UI and sign an attestation. It remains
  // cryptographically valid evidence but is excluded from the eligible electorate.
  fake.append('attest', { target: change.id }, 5000);
  replacement.import([...fake.ledger.records.values()]);
  assert.equal(replacement.evidence(change).some(e => e.account === fake.state.account), false);
});
test('old-key and competing replacement branches remain visible and do not overwrite local choice', () => {
  const { bob, alice, replacement, change } = scenario();
  const fake = make('Fake'); friend(bob, fake, 3500);
  const other = new Client(); other.import([...replacement.ledger.records.values()]);
  const alternative = other.recover(change.parent, 3000, 4500);
  exchange(alice, bob, replacement, other);
  assert.equal(alice.ledger.heads(bob.state.account).length, 3);
  alice.select(bob.state.account, change.id);
  assert.equal(alice.resolved(bob.state.account).head, change.id);
  assert.equal(alice.resolved(bob.state.account).status, 'disputed');
  assert.ok(alice.ledger.records.has(alternative.id));
});
test('wrong account, wrong signer, malformed time and unknown kinds fail validation', () => {
  const a = make('A'), b = make('B'); exchange(a, b);
  const parent = a.state.head;
  const body = { v: 1, account: a.state.account, parent, time: 2000, kind: 'friend', key: b.state.key.publicKey, data: { peer: b.state.account } };
  assert.throws(() => a.import([seal(body, b.state.key)]), /Signing key/);
  const replacement = keys();
  assert.throws(() => a.import([seal({ ...body, kind: 'key-change', key: replacement.publicKey, data: { effectiveAt: 999 } }, replacement)]), /time/);
  assert.throws(() => a.import([seal({ ...body, account: b.state.account }, b.state.key)]), /Wrong account/);
  assert.throws(() => a.import([seal({ ...body, kind: 'unknown', key: a.state.key.publicKey }, a.state.key)]), /Unknown/);
});
test('state persists keys and local selection without including secrets in public exports', () => {
  const dir = mkdtempSync(join(tmpdir(), 'rainfall-'));
  try {
    const c = new Client(dir); c.create('Alice');
    const loaded = new Client(dir);
    assert.equal(loaded.state.key.privateKey, c.state.key.privateKey);
    assert.equal(loaded.resolved(c.state.account).head, c.state.head);
    assert.equal(statSync(join(dir, 'state.json')).mode & 0o777, 0o600);
    assert.ok(!JSON.stringify(c.view()).includes('PRIVATE KEY'));
    assert.ok(!JSON.stringify(c.ledger.bundle([c.state.account])).includes('PRIVATE KEY'));
  } finally { rmSync(dir, { recursive: true }); }
});
test('HTTP client protects local mutations and pulls verified two-hop histories from a relay', async t => {
  const bob = make('Bob'), alice = make('Alice'), carol = make('Carol'), distant = make('Distant');
  friend(bob, alice); friend(alice, carol); friend(carol, distant); exchange(alice, carol, distant);
  // Bob initially knows Alice but not Carol. Alice acts as a relay.
  const server = serve(alice, 0); await once(server, 'listening');
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  bob.state.peers = [base];
  const results = await bob.sync(); assert.ok(results.every(r => r.ok));
  assert.equal(bob.neighbourhood().get(carol.state.account), 2);
  assert.equal(bob.neighbourhood().has(distant.state.account), false);
  // The third-hop genesis can be a dependency of Carol's friend record, but its full chain isn't pulled.
  assert.equal([...bob.ledger.records.values()].filter(r => r.account === distant.state.account).length, 0);
  assert.equal((await fetch(`${base}/state`)).status, 403);
  const html = await (await fetch(base)).text(); const token = html.match(/content="([a-f0-9]{64})"/)[1];
  assert.equal((await fetch(`${base}/state`, { headers: { 'x-rainfall-token': token } })).status, 200);
  assert.equal((await fetch(`${base}/action`, { method: 'POST', headers: { 'x-rainfall-token': token, origin: 'https://evil.example' }, body: '{}' })).status, 403);
  await assert.rejects(() => bob.pull('https://example.com', [alice.state.account]), /loopback/);
});
test('hostile relay cannot inject unrelated account histories', async t => {
  const alice = make('Alice'), fake = make('Unrelated');
  const http = await import('node:http');
  const server = http.createServer((req, res) => res.end(JSON.stringify([...fake.ledger.records.values()]))).listen(0, '127.0.0.1');
  await once(server, 'listening'); t.after(() => { server.closeAllConnections(); server.close(); });
  await assert.rejects(() => alice.pull(`http://127.0.0.1:${server.address().port}`, [alice.state.account]), /unrequested/);
  assert.equal(alice.ledger.records.has(fake.state.account), false);
});
