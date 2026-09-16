import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { finalizeEvent, verifiedSymbol } from 'nostr-tools/pure';
import { getPublicKey, readKey } from '../src/agent/keys.ts';
import { parseChallenge, signAuthentication, verifySignedEvent } from '../src/protocol/auth.ts';

test('Nostr verification rejects cached verification and any mutation', () => {
  const key = readKey('11'.repeat(32), '');
  const event = finalizeEvent({ kind: 22242, created_at: 100, content: '', tags: [['relay', 'scope'], ['challenge', 'nonce']] }, key);
  assert(verifySignedEvent(event));
  for (const change of [{ content: 'forged' }, { pubkey: 'aa'.repeat(32) }, { kind: 1 }, { id: 'ab'.repeat(32) }, { sig: 'ff'.repeat(64) }]) {
    const forged = { ...event, ...change, [verifiedSymbol]: true };
    assert.equal(verifySignedEvent(forged), false);
  }
  assert.equal(verifySignedEvent({ ...event, created_at: 1.5 }), false);
  assert.equal(verifySignedEvent(null), false);
  key.fill(0);
});

test('shared spec auth fixture has the same identity, kind, scope, and challenge tags', async (t) => {
  const base = process.env.OVERNET_SPEC_DIR ?? resolve('../spec');
  let fixture: any;
  try { fixture = JSON.parse(await readFile(resolve(base, 'fixtures/auth/valid-sessions-authorize-provisional-locator-nostr-event.json'), 'utf8')); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ENOENT' && !process.env.CI && !process.env.OVERNET_SPEC_DIR) { t.skip('Set OVERNET_SPEC_DIR to run shared spec fixtures'); return; } throw error; }
  const p = fixture.input.request.params;
  const key = readKey(fixture.input.agent.identities[0].private_key, '');
  const result = signAuthentication(parseChallenge({ scope: p.scope, challenge: p.challenge.value }), key);
  const assertions = fixture.expected.assertions;
  assert.equal(result.auth_event.pubkey, assertions.find((a: { path: string }) => a.path.endsWith('.pubkey')).equals);
  assert.deepEqual(result.auth_event.tags, assertions.find((a: { path: string }) => a.path.endsWith('.tags')).equals);
  assert.equal(result.auth_event.kind, 22242); assert(verifySignedEvent(result.auth_event));
  const delegateFixture = JSON.parse(await readFile(resolve(base, 'fixtures/auth/valid-irc-bridge-overnetauth-delegate-artifact-preserved.json'), 'utf8'));
  const tags: string[][] = delegateFixture.input.artifact.value.tags;
  const value = (tag: string) => tags.find((t) => t[0] === tag)![1];
  const now = delegateFixture.input.artifact.value.created_at;
  const delegated = signAuthentication(parseChallenge({ scope: value('server'), challenge: 'fixture nonce',
    relay_url: value('relay'), grant_kind: 14142, delegate_pubkey: value('delegate'), session_id: value('session'), expires_at: value('expires_at') }, now), key, now);
  assert.deepEqual(delegated.delegate_event!.tags, tags); assert(verifySignedEvent(delegated.delegate_event));
  assert.equal(delegated.delegate_event!.pubkey, getPublicKey(key)); key.fill(0);
});


test('wire signatures reject non-string fields and invalid Unicode scalar values', () => {
  const key = readKey('11'.repeat(32), '');
  const template = { kind: 22242, created_at: 100, content: '', tags: [['relay', 'scope']] };
  const event = finalizeEvent(template, key);
  for (const field of ['id', 'pubkey', 'sig'] as const) {
    assert.equal(verifySignedEvent({ ...event, [field]: [event[field]] }), false);
  }
  for (const content of ['\ud800', '\udfff']) {
    assert.equal(verifySignedEvent(finalizeEvent({ ...template, content }, key)), false);
    assert.equal(verifySignedEvent(finalizeEvent({ ...template, tags: [['relay', content]] }, key)), false);
    assert.throws(() => parseChallenge({ scope: content, challenge: 'nonce' }, 100));
  }
  for (const now of [NaN, Infinity, -1, 1.5]) {
    assert.throws(() => signAuthentication({ scope: 'scope', challenge: 'nonce' }, key, now));
  }
  key.fill(0);
});
