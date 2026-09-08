import http from 'node:http';
import { readFileSync, mkdirSync, openSync, closeSync, unlinkSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Client } from './client.js';

export function serve(client, port = 8787) {
  const token = randomBytes(32).toString('hex');
  const files = new Map([['/', ['index.html', 'text/html']], ['/ui.js', ['ui.js', 'text/javascript']], ['/style.css', ['style.css', 'text/css']]]);
  let mutation = Promise.resolve();
  const server = http.createServer(async (req, res) => {
    const reply = (code, value, type = 'application/json') => {
      res.writeHead(code, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" });
      res.end(type === 'application/json' ? JSON.stringify(value) : value);
    };
    try {
      const address = server.address();
      const hosts = [`127.0.0.1:${address.port}`, `localhost:${address.port}`];
      if (!hosts.includes(req.headers.host)) return reply(403, { error: 'Invalid host' });
      const url = new URL(req.url, `http://${req.headers.host}`);
      if (req.headers.origin && req.headers.origin !== url.origin) return reply(403, { error: 'Cross-origin request rejected' });
      if (req.method === 'GET' && files.has(url.pathname)) {
        const [name, type] = files.get(url.pathname);
        return reply(200, readFileSync(new URL(name, import.meta.url), 'utf8').replace('__TOKEN__', token), type);
      }
      // Public signed records only. No keys, local branch choices or peer configuration.
      if (req.method === 'GET' && url.pathname === '/bundle') {
        const accounts = (url.searchParams.get('accounts') ?? '').split(',');
        if (accounts.length > 200 || accounts.some(a => !/^[a-f0-9]{64}$/.test(a))) throw Error('Invalid account list');
        return reply(200, client.ledger.bundle(accounts));
      }
      if (req.headers['x-rainfall-token'] !== token) return reply(403, { error: 'Local access token required' });
      if (req.method === 'GET' && url.pathname === '/state') return reply(200, client.view());
      if (req.method !== 'POST' || url.pathname !== '/action') return reply(404, { error: 'Not found' });
      let size = 0; const chunks = [];
      for await (const chunk of req) {
        size += chunk.length; if (size > 8 * 1024 * 1024) throw Error('Request too large'); chunks.push(chunk);
      }
      const body = JSON.parse(Buffer.concat(chunks).toString());
      const run = async () => {
        switch (body.action) {
          case 'create': return client.create(body.name);
          case 'import': return client.import(body.records);
          case 'friend': return client.befriend(body.peer);
          case 'recover': return client.recover(body.parent, body.effectiveAt);
          case 'attest': return client.attest(body.target);
          case 'select': return client.select(body.account, body.head);
          case 'sync': return client.sync();
          case 'peers': {
            if (!Array.isArray(body.peers) || body.peers.length > 20 || body.peers.some(p => typeof p !== 'string' || p.length > 200)) throw Error('Invalid peers');
            client.state.peers = body.peers; client.save(); return;
          }
          default: throw Error('Unknown action');
        }
      };
      // Serialise mutations across awaited sync requests.
      const task = mutation.then(run); mutation = task.catch(() => {});
      const result = await task;
      reply(200, { result: result ?? null, state: client.view() });
    } catch (error) { reply(400, { error: error.message }); }
  });
  server.requestTimeout = 15000;
  server.listen(port, '127.0.0.1');
  return server;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const directory = resolve(process.env.RAINFALL_DATA ?? 'data');
  mkdirSync(directory, { recursive: true, mode: 0o700 });
  const lock = join(directory, 'client.lock');
  let fd;
  try { fd = openSync(lock, 'wx', 0o600); }
  catch { throw Error(`Data directory is locked: ${directory}. If the previous process crashed, remove client.lock after checking it is no longer running.`); }
  process.on('exit', () => { closeSync(fd); unlinkSync(lock); });
  const port = Number(process.env.PORT ?? 8787);
  const server = serve(new Client(directory), port);
  server.on('error', error => { console.error(error.message); process.exit(1); });
  server.on('listening', () => console.log(`Rainfall: http://127.0.0.1:${server.address().port} · ${directory}`));
  for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => process.exit(0)));
}
