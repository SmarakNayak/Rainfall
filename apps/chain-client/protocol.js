import { createHash, generateKeyPairSync, createPublicKey, sign, verify } from 'node:crypto';

export const MAX_RECORDS = 10000;
export function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonical(value[k])}`).join(',')}}`;
}
export const hash = value => createHash('sha256').update(canonical(value)).digest('hex');
export function keys() {
  const pair = generateKeyPairSync('ed25519');
  return { publicKey: pair.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) };
}
function publicKey(value) {
  const key = createPublicKey({ key: Buffer.from(value, 'base64'), type: 'spki', format: 'der' });
  if (key.asymmetricKeyType !== 'ed25519') throw Error('Expected Ed25519 key');
  return key;
}
export function seal(body, key) {
  const signature = sign(null, Buffer.from(canonical(body)), key.privateKey).toString('base64');
  return { ...body, signature, id: hash({ ...body, signature }) };
}
function requireThat(condition, message) { if (!condition) throw Error(message); }
function exact(value, fields) {
  requireThat(value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).sort().join(',') === fields.sort().join(','), 'Unexpected record fields');
}
const digest = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export function validate(record, records) {
  exact(record, ['v', 'account', 'parent', 'time', 'kind', 'key', 'data', 'signature', 'id']);
  const { id, signature, ...body } = record;
  requireThat(record.v === 1 && Number.isSafeInteger(record.time) && record.time >= 0, 'Invalid version or time');
  requireThat(typeof signature === 'string' && signature.length <= 128 && typeof record.key === 'string' && record.key.length <= 128, 'Invalid signature or key');
  requireThat(id === hash({ ...body, signature }) && verify(null, Buffer.from(canonical(body)), publicKey(record.key), Buffer.from(signature, 'base64')), 'Invalid hash or signature');
  const data = record.data;
  if (record.kind === 'genesis') {
    exact(data, ['name']);
    requireThat(record.parent === null && record.account === null && typeof data.name === 'string' && data.name.trim().length > 0 && data.name.length <= 80, 'Invalid genesis');
    return;
  }
  requireThat(digest(record.account) && digest(record.parent), 'Invalid account or parent');
  const parent = records.get(record.parent);
  requireThat(parent, `Missing parent ${record.parent}`);
  requireThat((parent.account ?? parent.id) === record.account && record.time >= parent.time, 'Wrong account or non-monotonic time');
  if (record.kind === 'key-change') {
    exact(data, ['effectiveAt']);
    requireThat(Number.isSafeInteger(data.effectiveAt) && data.effectiveAt >= parent.time && data.effectiveAt <= record.time && record.key !== parent.key, 'Invalid key-change time or key');
    // A new-key signature is only a candidate continuation, never proof of ownership.
    return;
  }
  requireThat(record.key === parent.key, 'Signing key does not control parent');
  if (record.kind === 'friend') {
    exact(data, ['peer']);
    requireThat(digest(data.peer) && data.peer !== record.account && records.get(data.peer)?.kind === 'genesis', 'Invalid friend');
  } else if (record.kind === 'attest') {
    exact(data, ['target']);
    const target = records.get(data.target);
    requireThat(target?.kind === 'key-change' && target.account !== record.account, 'Invalid attestation target');
  } else throw Error('Unknown event kind');
}

export class Ledger {
  constructor(records = []) { this.records = new Map(); this.import(records); }
  import(input) {
    requireThat(Array.isArray(input) && input.length <= MAX_RECORDS, 'Record limit exceeded');
    const next = new Map(this.records);
    const pending = new Map();
    for (const r of input) {
      requireThat(r && typeof r === 'object' && JSON.stringify(r).length <= 4096, 'Oversized or invalid record');
      if (next.has(r.id)) requireThat(canonical(next.get(r.id)) === canonical(r), 'Conflicting record ID');
      else {
        if (pending.has(r.id)) requireThat(canonical(pending.get(r.id)) === canonical(r), 'Conflicting record ID');
        pending.set(r.id, r);
      }
    }
    requireThat(next.size + pending.size <= MAX_RECORDS, 'Local record limit exceeded');
    // Dependency ordering permits unordered bundles, including cross-chain attestations.
    while (pending.size) {
      let progressed = false;
      for (const [id, r] of pending) {
        if (r.parent && !next.has(r.parent)) continue;
        if (r.kind === 'friend' && !next.has(r.data?.peer)) continue;
        if (r.kind === 'attest' && !next.has(r.data?.target)) continue;
        validate(r, next);
        next.set(id, structuredClone(r)); pending.delete(id); progressed = true;
      }
      requireThat(progressed, 'Missing or cyclic record dependencies');
    }
    this.records = next;
  }
  path(head) {
    const result = [];
    for (let r = this.records.get(head); r; r = this.records.get(r.parent)) result.push(r);
    return result.reverse();
  }
  heads(account) {
    const rows = [...this.records.values()].filter(r => (r.account ?? r.id) === account);
    const parents = new Set(rows.map(r => r.parent));
    return rows.filter(r => !parents.has(r.id));
  }
  bundle(accounts) {
    const ids = new Set();
    const stack = [...this.records.values()].filter(r => accounts.includes(r.account ?? r.id)).map(r => r.id);
    while (stack.length) {
      const id = stack.pop();
      if (ids.has(id)) continue;
      const r = this.records.get(id);
      if (!r) continue;
      ids.add(id);
      if (r.parent) stack.push(r.parent);
      // Include verification dependencies, not all of the referenced account's history.
      if (r.kind === 'friend') stack.push(r.data.peer);
      if (r.kind === 'attest') stack.push(r.data.target);
    }
    return [...ids].map(id => this.records.get(id));
  }
}
