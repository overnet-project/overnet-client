// A loopback-only integration example; no sessions, account database, or private keys.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { verifySignedEvent } from '../src/protocol/auth.ts';
const challenges = new Map<string, { scope: string; expires: number }>();
const server = createServer(async (request, response) => {
  const json = (code: number, value: unknown) => { response.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); response.end(JSON.stringify(value)); };
  try {
    if (request.method === 'GET' && request.url === '/') {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
      response.end(await readFile(new URL('./sign-in.html', import.meta.url))); return;
    }
    if (request.method === 'GET' && request.url === '/client.js') {
      response.writeHead(200, { 'Content-Type': 'text/javascript', 'Cache-Control': 'no-store' });
      response.end(await readFile(new URL('../dist/example.js', import.meta.url))); return;
    }
    const scope = `http://${request.headers.host}/example`;
    if (request.method === 'GET' && request.url === '/challenge') {
      for (const [nonce, data] of challenges) if (data.expires < Date.now()) challenges.delete(nonce);
      if (challenges.size >= 100) { json(429, { error: 'Too many pending challenges' }); return; }
      const challenge = crypto.randomUUID(); challenges.set(challenge, { scope, expires: Date.now() + 120000 });
      json(200, { scope, challenge }); return;
    }
    if (request.method === 'POST' && request.url === '/authenticate') {
      let body = '';
      for await (const chunk of request) { body += String(chunk); if (body.length > 16384) { json(413, {}); return; } }
      const { auth_event: event } = JSON.parse(body);
      if (!verifySignedEvent(event) || event.kind !== 22242) { json(403, {}); return; }
      const tag = (name: string) => event.tags.find((t) => t[0] === name)?.[1];
      const nonce = tag('challenge') ?? '', issued = challenges.get(nonce);
      if (!issued || issued.expires <= Date.now() || issued.scope !== scope || tag('relay') !== scope) { json(403, {}); return; }
      challenges.delete(nonce);
      json(200, { identity: event.pubkey }); return;
    }
    json(404, {});
  } catch { if (!response.headersSent) json(400, { error: 'Invalid request' }); else response.end(); }
});
server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  if (address && typeof address !== 'string') console.log(`Open http://127.0.0.1:${address.port}/ (or http://localhost:${address.port}/ to test another origin).`);
});
