import assert from 'node:assert/strict';
import test from 'node:test';
import { Agent, type State } from '../src/agent/agent.ts';
import { installBridge } from '../src/extension/bridge.ts';
import type { Browser } from '../src/extension/api.ts';
import { verifySignedEvent } from '../src/protocol/auth.ts';

class Emitter {
  listeners: ((...args: any[]) => unknown)[] = [];
  addListener(fn: (...args: any[]) => unknown) { this.listeners.push(fn); }
  emit(...args: unknown[]) { for (const fn of this.listeners) void fn(...args); }
}
class Port {
  onMessage = new Emitter(); onDisconnect = new Emitter(); messages: any[] = []; closed = false;
  sender: browser.runtime.MessageSender;
  name: string;
  constructor(name: string, url: string, frameId = 0) { this.name = name; this.sender = { url, frameId, tab: { id: 1 } as browser.tabs.Tab }; }
  postMessage(message: unknown) { this.messages.push(structuredClone(message)); }
  disconnect() { if (!this.closed) { this.closed = true; this.onDisconnect.emit(); } }
}
const tick = async () => { for (let i = 0; i < 8; i++) await new Promise(setImmediate); };
const challenge = () => ({ scope: 'irc://irc.example/overnet', challenge: 'nonce', relay_url: 'wss://relay.example',
  grant_kind: 14142, delegate_pubkey: 'aa'.repeat(32), session_id: 'session', expires_at: Math.floor(Date.now() / 1000) + 600 });
async function harness(timeout = 120000) {
  let data: State | undefined;
  const agent = await Agent.open({ read: async () => data, write: async (next) => { data = next; } });
  const view = await agent.addIdentity('Test identity', 'test passphrase', '11'.repeat(32));
  const windows: { id: number; url: string }[] = [], ports: Port[] = [];
  const api = { runtime: { onConnect: new Emitter(), getURL: (path: string) => `moz-extension://local/${path}` },
    windows: { onRemoved: new Emitter(), create: async ({ url }: { url: string }) => {
      const w = { id: windows.length + 1, url }; windows.push(w); return w;
    }, remove: async (id: number) => { api.windows.onRemoved.emit(id); } } };
  installBridge(api as unknown as Browser, Promise.resolve(agent), timeout);
  const connect = (name: string, url: string, frameId = 0) => { const p = new Port(name, url, frameId); ports.push(p); api.runtime.onConnect.emit(p); return p; };
  const page = (url = 'https://chat.example/path', frame = 0) => connect('overnet-page', url, frame);
  const request = async (p: Port, id = 'request') => {
    p.onMessage.emit({ id, method: 'authenticate', challenge: challenge(), origin: 'https://forged.example',
      identity_id: 'stolen', program_id: 'admin', approve: true }); await tick();
  };
  const approval = async () => { const p = connect('overnet-approval', windows.at(-1)!.url); await tick(); return p; };
  return { api, agent, id: view.identities[0].id, windows, connect, page, request, approval,
    close: () => { ports.forEach((p) => { p.disconnect(); }); agent.lock(); } };
}

test('only trusted extension controls can authorize; caller flags and forged controls cannot', async () => {
  const b = await harness();
  try {
    const page = b.page(); await b.request(page);
    assert.equal(page.messages.length, 0);
    const forged = b.connect('overnet-approval', `https://chat.example/approval/index.html#${b.windows[0].url.split('#')[1]}`);
    assert(forged.closed);
    const fakeSettings = b.connect('overnet-settings', 'https://chat.example/popup/index.html'); assert(fakeSettings.closed);
    const ui = await b.approval(); assert.equal(ui.messages[0].origin, 'https://chat.example');
    ui.onMessage.emit({ approve: true, identityId: 'stolen' }); await tick(); assert.equal(page.messages.length, 0);
    ui.onMessage.emit({ approve: true, identityId: b.id, remember: false }); await tick();
    assert(verifySignedEvent(page.messages[0].result.auth_event));
    assert.deepEqual(Object.keys(page.messages[0].result).sort(), ['auth_event', 'delegate_event']);
    assert(!JSON.stringify(page.messages).includes('encryptedKey'));
  } finally { b.close(); }
});

test('duplicate IDs, cancellation, navigation, frames and stale approval windows cannot sign', async () => {
  const b = await harness();
  try {
    assert(b.page('https://chat.example', 1).closed);
    const p = b.page(); await b.request(p); const ui = await b.approval();
    await b.request(p); assert.equal(b.windows.length, 1); assert.equal(p.messages.length, 0);
    p.onMessage.emit({ id: 'request', method: 'cancel' }); await tick();
    assert.equal(p.messages[0].code, 'browser.cancelled');
    ui.onMessage.emit({ approve: true, identityId: b.id }); await tick(); assert.equal(p.messages.length, 1);
    await b.request(p, 'next'); const next = await b.approval(); p.disconnect();
    next.onMessage.emit({ approve: true, identityId: b.id }); await tick(); assert.equal(p.messages.length, 1);
    const replacement = b.page(); assert.equal(replacement.messages.length, 0);
  } finally { b.close(); }
});

test('denial and approval in concurrent origins remain isolated', async () => {
  const b = await harness();
  try {
    const a = b.page(), other = b.page('https://other.example');
    await b.request(a); const au = await b.approval();
    await b.request(other); const ou = await b.approval();
    au.onMessage.emit({ approve: false }); await tick();
    assert.equal(a.messages[0].code, 'auth.policy_denied'); assert.equal(other.messages.length, 0);
    ou.onMessage.emit({ approve: true, identityId: b.id, remember: true }); await tick();
    assert(verifySignedEvent(other.messages[0].result.auth_event));
    await b.request(a, 'again'); assert.equal(b.windows.length, 3, 'other origin approval does not cover first');
  } finally { b.close(); }
});

test('timeout and locking invalidate pending approvals', async () => {
  const b = await harness(50);
  try {
    const p = b.page(); await b.request(p); const ui = await b.approval();
    await new Promise((resolve) => setTimeout(resolve, 65));
    assert.equal(p.messages[0].code, 'browser.timeout');
    ui.onMessage.emit({ approve: true, identityId: b.id }); await tick(); assert.equal(p.messages.length, 1);
    await b.request(p, 'lock'); const next = await b.approval();
    const settings = b.connect('overnet-settings', 'moz-extension://local/popup/index.html');
    settings.onMessage.emit({ id: 'lock', method: 'lock' }); await tick();
    assert.equal(p.messages[1].code, 'browser.cancelled');
    next.onMessage.emit({ approve: true, identityId: b.id }); await tick(); assert.equal(p.messages.length, 2);
  } finally { b.close(); }
});

test('unknown methods are errors and website policy administration is unavailable', async () => {
  const b = await harness();
  try {
    const p = b.page();
    for (const method of ['identities.list', 'policies.grant', 'backup', 'sessions.renew', 'signEvent']) {
      p.onMessage.emit({ id: method, method }); await tick();
      assert.equal(p.messages.at(-1).code, 'protocol.unknown_method');
    }
    assert.equal(b.windows.length, 0);
  } finally { b.close(); }
});

test('a delayed timer cannot let expired approval return signed artifacts', async () => {
  const b = await harness(), clock = Date.now;
  try {
    const page = b.page(); await b.request(page); const ui = await b.approval();
    Date.now = () => clock() + 120001;
    ui.onMessage.emit({ approve: true, identityId: b.id, remember: true }); await tick();
    assert.equal(page.messages[0].code, 'browser.timeout');
    assert.equal(page.messages[0].result, undefined);
    assert.deepEqual(b.agent.view().policies, []);
  } finally { Date.now = clock; b.close(); }
});

test('invalid callers, malformed requests, queue limits and closed approval windows fail safely', async () => {
  const b = await harness();
  try {
    assert(b.page('file:///tmp/app').closed);
    assert(b.connect('overnet-settings', 'invalid URL').closed);
    assert(b.connect('unknown', 'moz-extension://local/popup/index.html').closed);
    const p = b.page();
    for (const message of [null, {}, { id: 'request', method: 1 }, { id: '', method: 'authenticate' }]) p.onMessage.emit(message);
    p.onMessage.emit({ id: 'missing', method: 'cancel' }); await tick(); assert.equal(p.messages.length, 0);
    p.onMessage.emit({ id: 'invalid', method: 'authenticate', challenge: {} }); await tick();
    assert.equal(p.messages.at(-1).code, 'protocol.invalid_params');
    await b.request(p); const first = await b.approval();
    assert(b.connect('overnet-approval', b.windows[0].url).closed, 'second UI cannot attach to same request');
    first.onMessage.emit(null); first.onMessage.emit({ refresh: true }); await tick();
    assert.equal(first.messages.length, 2);
    first.onMessage.emit({ approve: true, identityId: '' }); await tick(); assert.equal(p.messages.length, 1);
    await b.request(p, 'busy'); assert.equal(p.messages.at(-1).code, 'browser.busy');
    for (let i = 0; i < 3; i++) await b.request(b.page(`https://site${i}.example`));
    const overflow = b.page('https://overflow.example'); await b.request(overflow);
    assert.equal(overflow.messages[0].code, 'browser.busy'); assert.equal(b.windows.length, 4);
    b.api.windows.onRemoved.emit(b.windows[0].id); await tick(); assert.equal(p.messages.at(-1).code, 'browser.cancelled');
    first.onMessage.emit({ approve: true, identityId: b.id }); await tick(); assert.equal(p.messages.at(-1).result, undefined);
    p.postMessage = () => { throw new Error('Document disappeared'); };
    p.onMessage.emit({ id: 'gone', method: 'unknown' }); await tick();
  } finally { b.close(); }
});

test('locked identities can retry approval and remembered sign-in bypasses the prompt until forgotten', async () => {
  const b = await harness();
  try {
    b.agent.lock(); const p = b.page(); await b.request(p); const ui = await b.approval();
    for (const password of [undefined, 'wrong passphrase']) {
      ui.onMessage.emit({ approve: true, identityId: b.id, password }); await tick();
      assert.equal(ui.messages.at(-1).code, 'auth.backend_unavailable'); assert.equal(p.messages.length, 0);
    }
    ui.onMessage.emit({ approve: true, identityId: b.id, password: 'test passphrase', remember: true }); await tick();
    assert(verifySignedEvent(p.messages[0].result.auth_event));
    await b.request(p, 'remembered'); assert(verifySignedEvent(p.messages[1].result.auth_event)); assert.equal(b.windows.length, 1);
    const other = b.page('https://new.example'); await b.request(other);
    const settings = b.connect('overnet-settings', 'moz-extension://local/popup/index.html');
    settings.onMessage.emit({ id: 'forget', method: 'forget' }); await tick();
    assert.equal(other.messages[0].code, 'browser.cancelled'); assert.deepEqual(b.agent.view().policies, []);
    await b.request(p, 'prompt-again'); assert.equal(b.windows.length, 3);
  } finally { b.close(); }
});

test('cancellation while opening a window and expiration during signing cannot deliver late results', async (t) => {
  const b = await harness();
  try {
    let release!: (value: { id: number; url: string }) => void;
    const create = b.api.windows.create;
    b.api.windows.create = async () => new Promise((resolve) => { release = resolve; });
    const p = b.page(); await b.request(p); p.disconnect(); release({ id: 100, url: 'closed' }); await tick();
    assert.equal(p.messages.length, 0);
    b.api.windows.create = create;
    const next = b.page(); await b.request(next); const ui = await b.approval();
    const now = Date.now();
    t.mock.method(b.agent, 'authorize', async () => {
      t.mock.method(Date, 'now', () => now + 120001);
      return { auth_event: {} };
    });
    ui.onMessage.emit({ approve: true, identityId: b.id }); await tick();
    assert.equal(next.messages[0].code, 'browser.timeout'); assert.equal(next.messages[0].result, undefined);
  } finally { t.mock.restoreAll(); b.close(); }
});
