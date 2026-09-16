import assert from 'node:assert/strict';
import test from 'node:test';
import { OvernetClient, OvernetError } from '../src/web/index.ts';
class Page extends EventTarget {
  location = { origin: 'https://example.test' };
  messages: any[] = [];
  postMessage(message: unknown, origin: string) { assert.equal(origin, this.location.origin); this.messages.push(message); }
  reply(data: unknown, origin = this.location.origin, source: unknown = this) {
    const event = new Event('message'); Object.assign(event, { data, origin, source }); this.dispatchEvent(event);
  }
}

test('SDK correlates requests and ignores wrong source, origin, and ID', async () => {
  const page = new Page(), sdk = new OvernetClient(page as unknown as Window);
  const response = sdk.info(); const id = page.messages[0].id;
  page.reply({ type: 'overnet:response', id, result: { version: 99 } }, 'https://forged.test');
  page.reply({ type: 'overnet:response', id, result: { version: 99 } }, page.location.origin, {});
  page.reply({ type: 'overnet:response', id: 'wrong', result: { version: 99 } });
  const info = { version: 1, methods: ['authenticate'] };
  page.reply({ type: 'overnet:response', id, result: info }); assert.deepEqual(await response, info);
});

test('SDK cancellation and timeout settle once, cancel the operation, and discard late replies', async () => {
  const page = new Page(), sdk = new OvernetClient(page as unknown as Window), controller = new AbortController();
  const response = sdk.authenticate({ scope: 'scope', challenge: 'nonce' }, { signal: controller.signal });
  const id = page.messages[0].id; controller.abort();
  await assert.rejects(response, (e: unknown) => e instanceof OvernetError && e.code === 'browser.cancelled');
  assert.equal(page.messages.at(-1).method, 'cancel'); assert.equal(page.messages.at(-1).id, id);
  page.reply({ type: 'overnet:response', id, result: { auth_event: {} } });
  await assert.rejects(sdk.info({ timeout: 5 }), (e: unknown) => e instanceof OvernetError && e.code === 'browser.timeout');
  assert.equal(page.messages.at(-1).method, 'cancel');
});

test('SDK errors preserve machine codes and malformed results fail', async () => {
  const page = new Page(), sdk = new OvernetClient(page as unknown as Window);
  const failed = sdk.authenticate({});
  page.reply({ type: 'overnet:response', id: page.messages[0].id, code: 'auth.policy_denied', error: 'Declined' });
  await assert.rejects(failed, (e: unknown) => e instanceof OvernetError && e.code === 'auth.policy_denied');
  const malformed = sdk.info();
  page.reply({ type: 'overnet:response', id: page.messages.at(-1).id, result: {} });
  await assert.rejects(malformed, /Invalid Overnet response/);
});

test('SDK handles successful authentication, malformed messages, navigation and unavailable bindings', async () => {
  const page = new Page(), sdk = new OvernetClient(page as unknown as Window);
  for (const timeout of [0, -1, NaN, Infinity, 2147483648]) await assert.rejects(sdk.info({ timeout }), RangeError);
  assert.equal(page.messages.length, 0);
  const success = sdk.authenticate({ scope: 'scope', challenge: 'nonce' });
  page.reply(null); page.reply({ type: 'other' });
  const result = { auth_event: { id: 'service verifies this' } };
  page.reply({ type: 'overnet:response', id: page.messages.at(-1).id, result }); assert.deepEqual(await success, result);
  for (const result of [null, { auth_event: null }, { version: 1, methods: [] }]) {
    const failed = sdk.authenticate({}); page.reply({ type: 'overnet:response', id: page.messages.at(-1).id, result });
    await assert.rejects(failed, /Invalid Overnet response/);
  }
  const legacy = sdk.info(); page.reply({ type: 'overnet:response', id: page.messages.at(-1).id, error: 'Legacy error' });
  await assert.rejects(legacy, (error: unknown) => error instanceof OvernetError && error.code === 'auth.internal_failure');
  const navigation = sdk.authenticate({}); page.dispatchEvent(new Event('pagehide'));
  await assert.rejects(navigation, /cancelled/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(sdk.authenticate({}, { signal: controller.signal }), /cancelled/);
  await assert.rejects(sdk.authenticate({}, { timeout: 1 }), /timed out/);
  page.postMessage = () => { throw new Error('Window unavailable'); };
  await assert.rejects(sdk.info(), (error: unknown) => error instanceof OvernetError && error.code === 'browser.unavailable');
  await assert.rejects(sdk.info({ signal: controller.signal }), /cancelled/);
});
