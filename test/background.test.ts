import assert from 'node:assert/strict';
import test from 'node:test';
import { validateBackup } from '../src/agent/keys.ts';
import { Agent, type State } from '../src/agent/agent.ts';

class Emitter {
  listeners: ((value?: any) => unknown)[] = [];
  addListener(fn: (value?: any) => unknown) { this.listeners.push(fn); }
  async emit(value?: unknown) { await Promise.all(this.listeners.map((fn) => fn(value))); }
}

test('background registers immediately and trusted settings persist encrypted identities across restart', async () => {
  let state: State | undefined;
  let release!: () => void;
  const loading = new Promise<void>((resolve) => { release = resolve; });
  const onConnect = new Emitter();
  const api = {
    runtime: { onConnect, getURL: (path: string) => `moz-extension://local/${path}` },
    windows: { onRemoved: new Emitter() },
    storage: { local: {
      get: async (key: string) => { assert.equal(key, 'overnetAgent'); await loading; return { overnetAgent: state }; },
      set: async (value: { overnetAgent: State }) => { state = structuredClone(value.overnetAgent); },
    } },
  };
  Object.defineProperty(globalThis, 'browser', { value: api, configurable: true });
  try {
    await import('../src/extension/background.ts');
    assert.equal(onConnect.listeners.length, 1, 'listeners must exist while storage is still loading');
    const messages: any[] = [];
    const port = { name: 'overnet-settings', sender: { url: api.runtime.getURL('popup/index.html') },
      onMessage: new Emitter(), postMessage: (message: unknown) => { messages.push(message); } };
    await onConnect.emit(port); release();
    const request = async (method: string, params?: unknown) => {
      await port.onMessage.emit({ id: method, method, params }); return messages.at(-1);
    };
    await port.onMessage.emit(null); await port.onMessage.emit({ id: '', method: 'lock' }); assert.equal(messages.length, 0);
    assert.deepEqual((await request('status')).result, { identities: [], policies: [] });
    assert.equal((await request('signEvent')).code, 'protocol.unknown_method');
    assert.equal((await request('create', { label: 1 })).code, 'protocol.invalid_params');
    const added = await request('create', { label: 'Family', password: 'local test password', key: '33'.repeat(32) });
    assert.equal(added.result.identities.length, 1); const id = added.result.identities[0].id;
    assert(state); validateBackup(state.identities[0].encryptedKey);
    assert(!JSON.stringify(state).includes('local test password')); assert(!JSON.stringify(state).includes('33'.repeat(32)));
    const backup = (await request('backup', { identityId: id, password: 'backup password' })).result.backup;
    validateBackup(backup);
    const locked = await request('lock'); assert.equal(locked.result.identities[0].unlocked, false);
    assert.equal((await request('unlock', { identityId: id, password: 'wrong password' })).code, 'auth.backend_unavailable');
    assert.equal((await request('unlock', { identityId: id, password: 'local test password' })).result.identities[0].unlocked, true);
    assert.deepEqual((await request('forget')).result.policies, []);
    const restored = await request('create', { label: 'Duplicate', password: 'new local password', key: backup, importPassword: 'backup password' });
    assert.equal(restored.code, 'protocol.invalid_params');
    const restarted = await Agent.open({ read: async () => state, write: async () => assert.fail('read-only restart') });
    assert.equal(restarted.view().identities[0].pubkey, added.result.identities[0].pubkey);
    assert.equal(restarted.view().identities[0].unlocked, false);
    await request('lock');
    const browserGlobal = Object.getOwnPropertyDescriptor(globalThis, 'browser')!;
    Reflect.deleteProperty(globalThis, 'browser');
    Object.defineProperty(globalThis, 'chrome', { value: api, configurable: true });
    try { assert.equal((await import(new URL('../src/extension/api.ts?chrome', import.meta.url).href)).api, api); }
    finally { Reflect.deleteProperty(globalThis, 'chrome'); Object.defineProperty(globalThis, 'browser', browserGlobal); }
  } finally { Reflect.deleteProperty(globalThis, 'browser'); }
});
