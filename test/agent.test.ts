import assert from 'node:assert/strict';
import test from 'node:test';
import { Agent, type State, type Store } from '../src/agent/agent.ts';
import { readKey, validateBackup } from '../src/agent/keys.ts';
import { parseChallenge, verifySignedEvent } from '../src/protocol/auth.ts';
import { failure, OvernetError } from '../src/protocol/errors.ts';
import { bech32 } from '@scure/base';

const password = 'local testing passphrase';
const key = '11'.repeat(32);
const origin = 'https://chat.example';
const challenge = () => ({ scope: 'irc://irc.example/overnet', challenge: 'nonce', relay_url: 'wss://relay.example',
  grant_kind: 14142, delegate_pubkey: 'aa'.repeat(32), session_id: 'session', expires_at: Math.floor(Date.now() / 1000) + 600 });
const code = (expected: string) => (e: unknown) => e instanceof OvernetError && e.code === expected;
class MemoryStore implements Store {
  data: unknown;
  fail = false;
  async read() { return structuredClone(this.data); }
  async write(state: State) { if (this.fail) throw new Error('secret backend detail'); this.data = structuredClone(state); }
}
async function setup() {
  const store = new MemoryStore(), agent = await Agent.open(store);
  const view = await agent.addIdentity('Local', password, key);
  return { store, agent, id: view.identities[0].id };
}

test('identity creation, encrypted persistence, lock, and restart preserve the public key', async () => {
  const { agent, store, id } = await setup();
  assert.equal(agent.view().identities[0].pubkey, '4f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa');
  assert(!JSON.stringify(store.data).includes(key)); assert(!JSON.stringify(store.data).includes(password));
  agent.lock();
  await assert.rejects(agent.authorize(origin, challenge(), { identityId: id, remember: false }), code('auth.backend_unavailable'));
  assert.throws(() => agent.unlock(id, 'wrong password'), code('auth.backend_unavailable'));
  agent.unlock(id, password);
  const signed = await agent.authorize(origin, challenge(), { identityId: id, remember: false });
  assert(verifySignedEvent(signed.auth_event)); assert(verifySignedEvent(signed.delegate_event));
  assert.equal(signed.auth_event.pubkey, signed.delegate_event!.pubkey);
  const restarted = await Agent.open(store);
  assert.equal(restarted.view().identities[0].pubkey, agent.view().identities[0].pubkey);
  assert.equal(restarted.view().identities[0].unlocked, false);
  assert.throws(() => restarted.backup(id, password), code('auth.backend_unavailable'));
});

test('backup restores the same identity with a new local passphrase and no approvals', async () => {
  const { agent, id } = await setup();
  await agent.authorize(origin, challenge(), { identityId: id, remember: true });
  const backup = agent.backup(id, 'backup passphrase');
  validateBackup(backup);
  const restored = await Agent.open(new MemoryStore());
  const view = await restored.addIdentity('Restored', 'new local passphrase', backup, 'backup passphrase');
  assert.equal(view.identities[0].pubkey, agent.view().identities[0].pubkey);
  assert.deepEqual(view.policies, []);
  restored.lock(); restored.unlock(view.identities[0].id, 'new local passphrase');
  await assert.rejects(restored.authorize(origin, challenge()), code('auth.approval_required'));
});

test('failed imports, duplicate keys and failed writes do not replace an identity', async () => {
  const { agent, store } = await setup(); const before = structuredClone(store.data);
  for (const invalid of ['0'.repeat(64), 'ff'.repeat(32), 'bad key']) {
    await assert.rejects(agent.addIdentity('Broken', password, invalid));
  }
  await assert.rejects(agent.addIdentity('Duplicate', password, key));
  assert.deepEqual(store.data, before);
  store.fail = true;
  await assert.rejects(agent.addIdentity('Unsaved', password), /Could not save/);
  assert.equal(agent.view().identities.length, 1);
  assert.deepEqual(store.data, before);
});

test('remembered approvals bind identity, profile, origin, scope, action, relay, and lifetime', async () => {
  const { agent, store, id } = await setup();
  const auth = { scope: challenge().scope, challenge: 'auth nonce' };
  await agent.authorize(origin, auth, { identityId: id, remember: true });
  assert((await agent.authorize(origin, auth)).auth_event);
  await assert.rejects(agent.authorize(origin, challenge()), code('auth.approval_required'));
  await agent.authorize(origin, challenge(), { identityId: id, remember: true });
  assert((await agent.authorize(origin, { ...challenge(), session_id: 'new session', challenge: 'new nonce' })).delegate_event);
  for (const [caller, change] of [
    ['https://other.example', {}], ['http://chat.example', {}], ['https://chat.example:444', {}],
    [origin, { scope: 'irc://other.example/overnet' }], [origin, { relay_url: 'wss://other.example' }],
  ] as [string, object][]) await assert.rejects(agent.authorize(caller, { ...challenge(), ...change }), code('auth.approval_required'));
  await assert.rejects(agent.authorize(origin, { ...challenge(), expires_at: Math.floor(Date.now() / 1000) + 86401 }), code('auth.policy_denied'));
  const restarted = await Agent.open(store);
  restarted.unlock(id, password);
  assert((await restarted.authorize(origin, challenge())).delegate_event);
  const other = await Agent.open(new MemoryStore());
  await other.addIdentity('Same user, separate profile', password, key);
  await assert.rejects(other.authorize(origin, challenge()), code('auth.approval_required'));
  await restarted.forgetApprovals();
  await assert.rejects(restarted.authorize(origin, challenge()), code('auth.approval_required'));
});

test('multiple identities require explicit selection when policies are ambiguous', async () => {
  const { agent, id } = await setup();
  const other = await agent.addIdentity('Other', password, '22'.repeat(32));
  await agent.authorize(origin, challenge(), { identityId: id, remember: true });
  await agent.authorize(origin, challenge(), { identityId: other.identities[1].id, remember: true });
  await assert.rejects(agent.authorize(origin, challenge()), code('auth.approval_required'));
});

test('unknown or corrupted persisted state fails closed; supplied public keys are checked at unlock', async () => {
  const { agent, store, id } = await setup();
  const state = store.data as State;
  for (const data of [null, {}, { ...state, version: 99 }, { ...state, policies: [{}] },
    { ...state, identities: [{ ...state.identities[0], encryptedKey: 'corrupt' }] }]) {
    await assert.rejects(Agent.open({ read: async () => data, write: async () => { assert.fail('must not overwrite'); } }), code('auth.backend_unavailable'));
  }
  state.identities[0].pubkey = 'aa'.repeat(32);
  const corrupt = await Agent.open(store);
  assert.throws(() => corrupt.unlock(id, password), code('auth.backend_unavailable'));
  assert.equal(corrupt.view().identities[0].unlocked, false);
  assert.equal(agent.view().identities[0].unlocked, true);
});

test('a pinned service cannot be downgraded to provisional address trust', async () => {
  const { store, id } = await setup();
  (store.data as State).servicePins[challenge().scope] = 'pinned-service-key';
  const pinned = await Agent.open(store); pinned.unlock(id, password);
  await assert.rejects(pinned.authorize(origin, challenge(), { identityId: id, remember: true }), code('auth.service_identity_mismatch'));
  assert.deepEqual(pinned.view().policies, []);
});

test('locking or cancellation during a policy save prevents delivery of signatures', async () => {
  const { store, id } = await setup();
  let release!: () => void;
  const agent = await Agent.open({ read: () => store.read(), write: async (state) => {
    await new Promise<void>((resolve) => { release = resolve; }); await store.write(state);
  } });
  agent.unlock(id, password);
  const pending = agent.authorize(origin, challenge(), { identityId: id, remember: true });
  await new Promise(setImmediate); agent.lock(); release();
  await assert.rejects(pending, code('auth.backend_unavailable'));
  agent.unlock(id, password);
  const controller = new AbortController();
  const cancelled = agent.authorize(origin, challenge(), { identityId: id, remember: true }, controller.signal);
  await new Promise(setImmediate); controller.abort(); release();
  await assert.rejects(cancelled, code('browser.cancelled'));
});

test('malformed delegation and imported KDF work are bounded before cryptographic work', () => {
  for (const field of ['relay_url', 'grant_kind', 'delegate_pubkey', 'session_id', 'expires_at']) {
    const partial: Record<string, unknown> = challenge(); delete partial[field]; assert.throws(() => parseChallenge(partial));
    for (const value of [null, [], {}, '', true]) assert.throws(() => parseChallenge({ ...challenge(), [field]: value }));
  }
  assert.throws(() => parseChallenge({ ...challenge(), grant_kind: '1.4142e4' }));
  assert.throws(() => parseChallenge({ ...challenge(), expires_at: 1 }));
  assert.throws(() => parseChallenge({ scope: 'spoof\nservice', challenge: 'nonce' }));
  assert.equal(parseChallenge({ ...challenge(), origin: 'forged', approved: true }).scope, challenge().scope);
  const bytes = new Uint8Array(91); bytes[0] = 2; bytes[1] = 30;
  const workBomb = bech32.encode('ncryptsec', bech32.toWords(bytes), 500);
  assert.throws(() => validateBackup(workBomb));
  assert.throws(() => readKey(workBomb, password));
  assert.equal(failure(new Error('private key and filesystem details')).error, 'Overnet could not complete this request.');
});

test('invalid identities, callers, policies and trust records cannot widen access', async () => {
  const { agent, store, id } = await setup();
  for (const caller of ['null', 'file:///tmp/app', `${origin}/path`]) {
    await assert.rejects(agent.authorize(caller, challenge()), code('protocol.invalid_params'));
  }
  for (const identityId of ['', 'missing']) {
    await assert.rejects(agent.authorize(origin, challenge(), { identityId, remember: false }), code('auth.identity_required'));
  }
  assert.throws(() => agent.unlock('missing', password), code('auth.identity_required'));
  await assert.rejects(agent.addIdentity(' ', password), code('protocol.invalid_params'));
  await assert.rejects(agent.addIdentity('New', 'short', '22'.repeat(32)), code('protocol.invalid_params'));
  const state = structuredClone(store.data) as State;
  const policy = { id: 'policy', identityId: id, origin, scope: 'scope', maxLifetime: 0 };
  for (const change of [
    { identities: [state.identities[0], state.identities[0]] }, { identities: [{}] },
    { servicePins: { scope: '' } }, { policies: [{ ...policy, identityId: 'absent' }] },
    { policies: [{ ...policy, origin: `${origin}/path` }] }, { policies: [{ ...policy, origin: 'file:///tmp' }] },
    { policies: [{ ...policy, relay: '' }] }, { policies: [{ ...policy, maxLifetime: 1 }] },
    { policies: [{ ...policy, maxLifetime: -1 }] }, { policies: [{ ...policy, maxLifetime: 86401 }] },
    { policies: [{ ...policy, maxLifetime: 1.5 }] }, { policies: [{ ...policy, maxLifetime: '0' }] },
  ]) await assert.rejects(Agent.open({ read: async () => ({ ...state, ...change }), write: async () => assert.fail('must not write') }), code('auth.backend_unavailable'));
  const full = await Agent.open({ read: async () => ({ ...state, identities: Array.from({ length: 32 }, (_, i) => ({ ...state.identities[0], id: `id-${i}` })) }), write: async () => assert.fail('must not write') });
  await assert.rejects(full.addIdentity('Too many', password), code('auth.policy_denied'));
  const pinned = await Agent.open({ read: async () => ({ ...state, servicePins: { [challenge().relay_url]: 'pin' } }), write: async () => assert.fail('must not write') });
  await assert.rejects(pinned.authorize(origin, challenge()), code('auth.service_identity_mismatch'));
  agent.lock();
});
