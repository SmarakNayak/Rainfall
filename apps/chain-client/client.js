import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Ledger, keys, seal, MAX_RECORDS } from './protocol.js';

export class Client {
  constructor(directory) {
    this.directory = directory;
    const file = directory && join(directory, 'state.json');
    this.state = file && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) :
      { account: null, head: null, key: null, selections: {}, peers: [], records: [] };
    this.ledger = new Ledger(this.state.records);
  }
  save() {
    this.state.records = [...this.ledger.records.values()];
    if (!this.directory) return;
    mkdirSync(this.directory, { recursive: true, mode: 0o700 });
    const file = join(this.directory, 'state.json');
    writeFileSync(`${file}.tmp`, JSON.stringify(this.state), { mode: 0o600 });
    renameSync(`${file}.tmp`, file);
  }
  create(name, time = Date.now()) {
    if (this.state.account) throw Error('This client already has an account');
    const key = keys();
    const r = seal({ v: 1, account: null, parent: null, time, kind: 'genesis', key: key.publicKey, data: { name } }, key);
    this.ledger.import([r]);
    Object.assign(this.state, { account: r.id, head: r.id, key });
    this.state.selections[r.id] = r.id; this.save(); return r;
  }
  append(kind, data, time = Date.now()) {
    const { account, head, key } = this.state;
    if (!account) throw Error('Create or recover an account first');
    const r = seal({ v: 1, account, parent: head, time, kind, key: key.publicKey, data }, key);
    this.ledger.import([r]); this.state.head = r.id;
    this.state.selections[account] = r.id; this.save(); return r;
  }
  recover(parentId, effectiveAt, time = Date.now()) {
    const parent = this.ledger.records.get(parentId);
    if (!parent) throw Error('Import the previous history first');
    if (this.state.account && this.state.account !== (parent.account ?? parent.id)) throw Error('Use a fresh data directory to recover another account');
    const key = keys();
    const r = seal({ v: 1, account: parent.account ?? parent.id, parent: parentId, time,
      kind: 'key-change', key: key.publicKey, data: { effectiveAt } }, key);
    this.ledger.import([r]);
    Object.assign(this.state, { account: r.account, head: r.id, key });
    this.state.selections[r.account] = r.id; this.save(); return r;
  }
  import(records) { this.ledger.import(records); this.save(); }
  // Follow a unique ordinary continuation. Key changes always require local acceptance.
  resolved(account) {
    let head = this.state.selections[account] ?? account;
    if (!this.ledger.records.has(head)) return { head: null, status: 'unknown' };
    while (true) {
      const children = [...this.ledger.records.values()].filter(r => r.parent === head);
      if (children.length !== 1 || children[0].kind === 'key-change') break;
      head = children[0].id;
    }
    const heads = this.ledger.heads(account);
    const selectedPath = new Set(this.ledger.path(head).map(r => r.id));
    const outside = [...this.ledger.records.values()].filter(r => (r.account ?? r.id) === account && !selectedPath.has(r.id));
    return { head, status: outside.length ? (heads.length > 1 ? 'disputed' : 'pending-key-change') : 'accepted' };
  }
  select(account, head) {
    const record = this.ledger.records.get(head);
    if (!record || (record.account ?? record.id) !== account) throw Error('Head does not belong to account');
    if (account === this.state.account && record.key !== this.state.key?.publicKey) throw Error('This phone does not possess that branch key');
    this.state.selections[account] = head;
    if (account === this.state.account) this.state.head = head;
    this.save();
  }
  offers(account, before = Infinity, explicitHead) {
    return this.ledger.path(explicitHead ?? this.resolved(account).head)
      .filter(r => r.kind === 'friend' && r.time < before).map(r => r.data.peer);
  }
  friends(account, before = Infinity, explicitHead) {
    return [...new Set(this.offers(account, before, explicitHead))]
      .filter(peer => this.offers(peer, before).includes(account));
  }
  befriend(peer, time = Date.now()) {
    if (!this.ledger.records.has(peer)) throw Error('Import the friend’s identity first');
    if (this.offers(this.state.account).includes(peer)) throw Error('Friendship offer already exists');
    return this.append('friend', { peer }, time);
  }
  attest(targetId, time = Date.now()) {
    const target = this.ledger.records.get(targetId);
    if (target?.kind !== 'key-change') throw Error('Select a key-change record');
    const eligible = this.friends(target.account, target.data.effectiveAt, target.parent);
    if (!eligible.includes(this.state.account)) throw Error('Only a direct friend established before the claimed change may attest');
    return this.append('attest', { target: targetId }, time);
  }
  neighbourhood() {
    const depth = new Map();
    if (!this.state.account) return depth;
    depth.set(this.state.account, 0);
    let frontier = [this.state.account];
    for (let d = 1; d <= 2; d++) {
      const next = [];
      for (const account of frontier) for (const friend of this.friends(account)) if (!depth.has(friend)) {
        depth.set(friend, d); next.push(friend);
      }
      frontier = next;
    }
    return depth;
  }
  evidence(target) {
    const eligible = this.friends(target.account, target.data.effectiveAt, target.parent);
    const neighbourhood = this.neighbourhood();
    return eligible.filter(account => neighbourhood.has(account)).map(account => {
      const resolved = this.resolved(account);
      const statements = this.ledger.path(resolved.head).filter(r => r.kind === 'attest' &&
        this.ledger.records.get(r.data.target)?.account === target.account);
      return { account, signerStatus: resolved.status, supports: statements.some(r => r.data.target === target.id),
        targets: [...new Set(statements.map(r => r.data.target))] };
    });
  }
  view() {
    const neighbourhood = this.neighbourhood();
    return { account: this.state.account, head: this.state.head, peers: this.state.peers,
      accounts: [...this.ledger.records.values()].filter(r => r.kind === 'genesis').map(r => ({
        id: r.id, name: r.data.name, depth: neighbourhood.get(r.id) ?? null,
        ...this.resolved(r.id), friends: this.friends(r.id),
        heads: this.ledger.heads(r.id).map(h => h.id),
        records: [...this.ledger.records.values()].filter(e => (e.account ?? e.id) === r.id)
          .map(e => ({ ...e, evidence: e.kind === 'key-change' ? this.evidence(e) : undefined })),
      })) };
  }
  async pull(peer, accounts) {
    const url = new URL(peer);
    if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname) || url.username || url.password)
      throw Error('This prototype supports loopback HTTP peers only');
    url.pathname = '/bundle'; url.search = ''; url.hash = '';
    url.searchParams.set('accounts', accounts.join(','));
    const response = await fetch(url, { signal: AbortSignal.timeout(5000), redirect: 'error' });
    if (!response.ok) throw Error(`Peer returned ${response.status}`);
    let size = 0; const chunks = [];
    for await (const chunk of response.body) {
      size += chunk.length;
      if (size > 8 * 1024 * 1024) throw Error('Peer bundle too large');
      chunks.push(chunk);
    }
    const body = JSON.parse(Buffer.concat(chunks).toString());
    if (!Array.isArray(body) || body.length > MAX_RECORDS) throw Error('Invalid peer bundle');
    // A peer cannot smuggle arbitrary unrelated histories in its response.
    const candidate = new Ledger(body);
    const allowed = new Set(candidate.bundle(accounts).map(r => r.id));
    if (body.some(r => !allowed.has(r.id))) throw Error('Peer returned unrequested histories');
    this.import(body);
  }
  async sync() {
    if (!this.state.account) throw Error('Create or recover an account first');
    const results = [];
    // Pull root, candidate neighbours, then their neighbours. One-sided offers are
    // discovery hints only; they become graph edges only after reciprocal records.
    let accounts = [this.state.account];
    for (let depth = 0; depth <= 2; depth++) {
      if (accounts.length > 200) throw Error('Neighbourhood exceeds prototype sync limit');
      for (const peer of this.state.peers) {
        try { await this.pull(peer, accounts); results.push({ peer, depth, ok: true }); }
        catch (error) { results.push({ peer, depth, ok: false, error: error.message }); }
      }
      if (depth === 0) accounts = [...new Set([this.state.account, ...this.offers(this.state.account)])];
      if (depth === 1) accounts = [...new Set([this.state.account, ...this.friends(this.state.account)
        .flatMap(account => [account, ...this.offers(account)])])];
    }
    return results;
  }
}
