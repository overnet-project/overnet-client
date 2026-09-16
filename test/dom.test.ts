import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { JSDOM } from 'jsdom';

class Port {
  messages: any[] = [];
  listeners: ((message: any) => void)[] = [];
  disconnectListeners: (() => void)[] = [];
  onMessage = { addListener: (fn: (message: any) => void) => { this.listeners.push(fn); } };
  onDisconnect = { addListener: (fn: () => void) => { this.disconnectListeners.push(fn); } };
  closed = false;
  broken = false;
  postMessage(message: unknown) { if (this.broken) throw new Error('Disconnected'); this.messages.push(message); }
  receive(message: unknown) { for (const fn of this.listeners) fn(message); }
  disconnect() { this.closed = true; for (const fn of this.disconnectListeners) fn(); }
  respond(result: unknown) { this.receive({ id: this.messages.at(-1).id, result }); }
}
const tick = async () => { for (let i = 0; i < 4; i++) await new Promise(setImmediate); };
const ports: Port[] = [], tabs: string[] = [];
const api = { runtime: {
  connect: () => { const p = new Port(); ports.push(p); return p; },
  getManifest: () => ({ version: '0.2.0' }), getURL: (path: string) => `moz-extension://test/${path}`,
}, tabs: { create: async ({ url }: { url: string }) => { tabs.push(url); } } };

async function page(file?: string) {
  const html = file ? await readFile(new URL(`../src/extension/${file}/index.html`, import.meta.url), 'utf8') : '<!doctype html>';
  const dom = new JSDOM(html, { url: 'https://app.example/' });
  const w = dom.window;
  const original = new Map<string, PropertyDescriptor | undefined>();
  for (const [key, value] of Object.entries({ browser: api, window: w, document: w.document, location: w.location, Option: w.Option })) {
    original.set(key, Object.getOwnPropertyDescriptor(globalThis, key));
    Object.defineProperty(globalThis, key, { value, configurable: true, writable: true });
  }
  const element = (id: string) => w.document.querySelector<HTMLElement>(id)!;
  const value = (id: string, value: string) => { (element(id) as HTMLInputElement).value = value; };
  const submit = async (id: string) => { element(id).dispatchEvent(new w.Event('submit', { cancelable: true })); await tick(); };
  const close = () => {
    w.dispatchEvent(new w.Event('pagehide')); w.close();
    for (const [key, descriptor] of original) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor); else Reflect.deleteProperty(globalThis, key);
    }
  };
  return { w, element, value, submit, close };
}

test('content binding filters callers, limits requests, and cleans up disconnected documents', async () => {
  const p = await page();
  try {
    const replies: any[] = [];
    p.w.postMessage = (data: unknown) => { replies.push(data); };
    await import('../src/extension/content.ts');
    const send = (data: unknown, origin = p.w.location.origin, source: any = p.w) => p.w.dispatchEvent(new p.w.MessageEvent('message', { data, origin, source }));
    const request = (id = 'one', method = 'authenticate') => ({ type: 'overnet:request', id, method, challenge: { scope: 'scope', challenge: 'nonce' }, approve: true });
    for (const data of [null, [], {}, { ...request(), id: '' }, { ...request(), method: 1 }]) send(data);
    send(request(), 'https://evil.example'); send(request(), p.w.location.origin, null);
    assert.equal(ports.length, 0); assert.equal(replies.length, 0);
    send(request('info', 'provider.info'));
    assert.deepEqual(replies.pop().result, { version: 1, methods: ['authenticate'] });
    send(request('absent', 'cancel')); assert.equal(ports.length, 0);
    send({ ...request(), challenge: 'x'.repeat(16385) }); assert.equal(replies.pop().code, 'protocol.invalid_params');
    const cyclic: any = request(); cyclic.self = cyclic; send(cyclic); assert.equal(replies.pop().code, 'protocol.invalid_params');
    send(request()); const port = ports.at(-1)!;
    assert.deepEqual(Object.keys(port.messages[0]).sort(), ['challenge', 'id', 'method']);
    send(request()); send(request('one', 'provider.info')); assert.equal(port.messages.length, 1); assert.equal(replies.length, 0);
    send(request('two')); assert.equal(replies.pop().code, 'browser.busy');
    port.receive(null); port.receive({ id: 'stranger' }); assert.equal(replies.length, 0);
    port.respond({ auth_event: { id: 'signed' } }); assert.equal(replies.pop().result.auth_event.id, 'signed');
    send(request('two')); assert.equal(ports.at(-1), port);
    send({ ...request('two', 'cancel'), challenge: 'x'.repeat(20000) });
    assert.deepEqual(port.messages.at(-1), { id: 'two', method: 'cancel' });
    assert.equal(replies.length, 0, 'cancel has only the eventual terminal reply');
    port.receive({ id: 'two', error: 'Cancelled', code: 'browser.cancelled' }); assert.equal(replies.pop().code, 'browser.cancelled');
    send(request('three')); port.disconnect(); assert.equal(replies.pop().code, 'browser.unavailable');
    send(request('four')); const replacement = ports.at(-1)!; assert.notEqual(replacement, port);
    port.disconnect(); assert.equal(replies.length, 0, 'stale disconnect cannot cancel replacement');
    replacement.respond({}); replies.pop(); replacement.broken = true;
    send(request('broken')); assert.equal(replies.pop().code, 'browser.unavailable');
    replacement.broken = false; send(request('navigation'));
    p.w.dispatchEvent(new p.w.Event('pagehide')); assert(replacement.closed); assert.equal(replies.length, 0);
    replacement.receive({ id: 'navigation', result: 'late' }); assert.equal(replies.length, 0);
  } finally { p.close(); }
});

test('identity UI handles creation, unlock, backups, locking, errors and connection loss', async () => {
  const p = await page('popup');
  try {
    await import('../src/extension/popup/popup.ts');
    const port = ports.at(-1)!;
    port.receive(null); port.receive({ id: 'unknown' });
    port.respond({ identities: [], policies: [] }); await tick();
    assert(p.element('#existing').hidden); assert.match(p.element('#status').textContent!, /first identity/);
    p.value('#new-password', 'mismatch'); p.value('#confirm-password', 'different'); await p.submit('#create-form');
    assert.match(p.element('#status').textContent!, /do not match/); assert.equal(port.messages.length, 1);
    p.value('#label', '<script>Family</script>'); p.value('#key', 'private import');
    p.value('#import-password', 'old password'); p.value('#new-password', 'passphrase'); p.value('#confirm-password', 'passphrase');
    await p.submit('#create-form'); assert.equal(port.messages.at(-1).method, 'create');
    assert.equal(port.messages.at(-1).params.key, 'private import');
    const identity = { id: 'id', label: '<script>Family</script>', pubkey: 'aa'.repeat(32), unlocked: true };
    const view = { identities: [identity], policies: [] as any[] };
    port.respond(view); await tick();
    assert(!p.element('#existing').hidden); assert(p.element('#unlock-form').hidden);
    assert.equal((p.element('#key') as HTMLInputElement).value, '');
    assert.equal((p.element('#new-password') as HTMLInputElement).value, '');
    assert.equal(p.w.document.querySelectorAll('select script').length, 0);
    p.value('#backup-password', 'backup'); p.value('#backup-confirm', 'wrong'); await p.submit('#backup-form');
    assert.match(p.element('#status').textContent!, /do not match/);
    p.value('#backup-password', 'backup password'); p.value('#backup-confirm', 'backup password'); await p.submit('#backup-form');
    assert.equal(port.messages.at(-1).method, 'backup'); port.respond({ backup: 'ncryptsec-test-backup' }); await tick();
    assert(!p.element('#backup-result').hidden); assert.equal((p.element('#backup-password') as HTMLInputElement).value, '');
    const href = (p.element('#download') as HTMLAnchorElement).href;
    assert.equal(await (await fetch(href)).text(), 'ncryptsec-test-backup\n');
    p.element('#lock').click(); await tick(); identity.unlocked = false; port.respond(view); await tick();
    assert(p.element('#backup-result').hidden); await assert.rejects(fetch(href));
    assert(!p.element('#unlock-form').hidden); assert.match(p.element('#state').textContent!, /Locked/);
    p.value('#password', 'wrong'); await p.submit('#unlock-form'); port.receive({ id: port.messages.at(-1).id, error: 'Wrong passphrase' }); await tick();
    assert.match(p.element('#status').textContent!, /Wrong passphrase/); assert.equal((p.element('#password') as HTMLInputElement).value, '');
    p.value('#password', 'correct'); await p.submit('#unlock-form'); identity.unlocked = true;
    view.policies = [{ identityId: 'id', origin: 'https://chat.example', scope: 'scope', relay: 'wss://relay.example' },
      { identityId: 'id', origin: 'https://other.example', scope: 'scope' }];
    port.respond(view); await tick(); assert.match(p.element('#policies').textContent!, /delegation/);
    p.element('#identity').dispatchEvent(new p.w.Event('change')); assert(!p.element('#backup-section').hidden);
    p.element('#forget').click(); await tick(); port.respond({ ...view, policies: [] }); await tick();
    assert.match(p.element('#policies').textContent!, /No remembered/);
    p.element('#lock').click(); await tick(); port.disconnect(); await tick();
    assert.match(p.element('#status').textContent!, /disconnected/);
    assert([...p.w.document.querySelectorAll('button')].every((button) => !button.disabled));
  } finally { p.close(); }
});

test('approval UI shows the real service and keeps decisions and passwords on its private port', async () => {
  const p = await page('approval');
  try {
    await import('../src/extension/approval/approval.ts'); const port = ports.at(-1)!;
    const message = { identities: [] as any[], policies: [], origin: 'https://chat.example', challenge: { scope: 'irc://test' } as any };
    port.receive(message); assert(p.element('form').hidden);
    p.element('#manage').click(); await tick(); assert.equal(tabs.at(-1), 'moz-extension://test/popup/index.html');
    p.element('#refresh').click(); assert.deepEqual(port.messages.pop(), { refresh: true });
    message.identities = [{ id: 'id', label: 'Family', unlocked: false }, { id: 'other', label: 'Work', unlocked: true }];
    port.receive(message); assert.equal(p.element('#origin').textContent, message.origin);
    assert.equal(p.element('#scope').textContent, 'irc://test'); assert(!p.element('#unlock').hidden);
    p.value('#identity', 'other'); p.element('#identity').dispatchEvent(new p.w.Event('change')); assert(p.element('#unlock').hidden);
    message.challenge = { ...message.challenge, delegate_pubkey: 'aa'.repeat(32), expires_at: 2000000000, relay_url: 'wss://relay.example' };
    port.receive(message); assert.equal((p.element('#identity') as HTMLInputElement).value, 'other');
    assert(!p.element('#delegation').hidden); assert.match(p.element('#remember-text').textContent!, /24 hours/);
    assert.equal(p.element('#relay').textContent, 'wss://relay.example');
    p.value('#identity', 'id'); p.element('#identity').dispatchEvent(new p.w.Event('change'));
    p.value('#password', 'local password'); (p.element('#remember') as HTMLInputElement).checked = true;
    await p.submit('form'); assert.deepEqual(port.messages.pop(), { approve: true, identityId: 'id', password: 'local password', remember: true });
    assert.equal((p.element('#password') as HTMLInputElement).value, ''); assert((p.element('#approve') as HTMLButtonElement).disabled);
    port.receive({ error: 'Could not unlock' }); assert.match(p.element('#status').textContent!, /Could not unlock/);
    assert(!(p.element('#approve') as HTMLButtonElement).disabled);
    p.element('#deny').click(); assert.deepEqual(port.messages.pop(), { approve: false });
    const close = p.w.close.bind(p.w);
    let closed = false; p.w.close = () => { closed = true; }; port.disconnect(); assert(closed); p.w.close = close;
  } finally { p.close(); }
});
