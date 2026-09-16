import assert from 'node:assert/strict';
import test from 'node:test';
import { bech32 } from '@scure/base';
import { nsecEncode, npubEncode } from 'nostr-tools/nip19';
import { readKey, validateBackup } from '../src/agent/keys.ts';

test('key imports accept nsec and reject public keys and unsupported encrypted backup metadata', () => {
  const key = Uint8Array.from({ length: 32 }, () => 0x11);
  assert.deepEqual(readKey(nsecEncode(key), ''), key);
  assert.throws(() => readKey(npubEncode('aa'.repeat(32)), ''), /Could not unlock/);
  const valid = new Uint8Array(91); valid[0] = 2; valid[1] = 16;
  const encode = (data: Uint8Array, prefix = 'ncryptsec') => bech32.encode(prefix, bech32.toWords(data), 1000);
  for (const [index, value] of [[0, 1], [1, 9], [1, 19], [42, 3]]) {
    const bytes = valid.slice(); bytes[index] = value; assert.throws(() => validateBackup(encode(bytes)));
  }
  for (const value of [undefined, 'x'.repeat(501), encode(valid, 'wrong'), encode(valid.slice(1))]) assert.throws(() => validateBackup(value));
  assert.throws(() => readKey(encode(valid), ''), /Could not unlock/);
  key.fill(0);
});
