import { mkdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { Client } from './client.js';

const root = resolve(process.argv[2] ?? 'data/demo');
if (existsSync(root)) throw Error(`Refusing to overwrite an existing demo directory: ${root}`);
mkdirSync(root, { recursive: true, mode: 0o700 });
const names = ['alice', 'bob', 'carol', 'dave', 'replacement'];
const [alice, bob, carol, dave, replacement] = names.map(name => new Client(join(root, name)));
const now = Date.now();
for (const [i, c] of [alice, bob, carol, dave].entries()) c.create(names[i], now - 10000);
const exchange = (...clients) => {
  const records = [...new Map(clients.flatMap(c => [...c.ledger.records])).values()];
  for (const c of clients) c.import(records);
};
function friend(a, b, time) {
  exchange(a, b); a.befriend(b.state.account, time); b.befriend(a.state.account, time); exchange(a, b);
}
friend(alice, bob, now - 9000); friend(bob, carol, now - 8000); friend(alice, dave, now - 7000);
exchange(alice, bob, carol, dave, replacement);
const recovery = replacement.recover(bob.state.head, now - 5000, now - 4000);
const fake = new Client(); fake.create('attacker-created friend', now - 4500);
friend(bob, fake, now - 3000);
exchange(alice, bob, carol, dave, replacement, fake);
alice.attest(recovery.id, now - 2000); carol.attest(recovery.id, now - 1000);
exchange(alice, bob, carol, dave, replacement);
for (const [i, c] of [alice, bob, carol, dave, replacement].entries()) {
  c.state.peers = names.filter((_, j) => i !== j).map(name => `http://127.0.0.1:${8787 + names.indexOf(name)}`);
  c.save();
}
console.log(`Demo created in ${root}\nBob has competing old-phone and replacement branches. Alice and Carol endorse the replacement.\nRun these commands in separate terminals from apps/chain-client:`);
for (const [i, name] of names.entries()) console.log(`PORT=${8787 + i} RAINFALL_DATA=${JSON.stringify(join(root, name))} npm start`);
console.log('Open Alice on port 8787 to review evidence from Bob’s friends and follow a branch locally.');
