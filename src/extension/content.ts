import { api } from './api.ts';
import { object, text } from '../protocol/errors.ts';

let port: browser.runtime.Port | undefined;
const pending = new Set<string>();
const reply = (id: string, data: Record<string, unknown>) => {
  window.postMessage({ type: 'overnet:response', id, ...data }, location.origin);
};
function connect(): browser.runtime.Port {
  if (port) return port;
  const connection = api.runtime.connect({ name: 'overnet-page' });
  connection.onMessage.addListener((message: unknown) => {
    if (!object(message) || typeof message.id !== 'string' || !pending.delete(message.id)) return;
    const { id, result, error, code } = message;
    reply(id, typeof error === 'string' ? { error, code } : { result });
  });
  connection.onDisconnect.addListener(() => {
    if (port !== connection) return;
    port = undefined;
    for (const id of pending) reply(id, { code: 'browser.unavailable', error: 'Overnet disconnected. Try signing in again.' });
    pending.clear();
  });
  port = connection;
  return connection;
}
window.addEventListener('message', (event: MessageEvent<unknown>) => {
  const m = event.data;
  if (event.source !== window || event.origin !== location.origin || !object(m) ||
      m.type !== 'overnet:request' || !text(m.id, 128) || typeof m.method !== 'string') return;
  if (m.method !== 'cancel' && pending.has(m.id)) return;
  if (m.method === 'provider.info') {
    reply(m.id, { result: { version: 1, methods: ['authenticate'] } }); return;
  }
  if (m.method === 'cancel' && !pending.has(m.id)) return;
  try {
    if (m.method !== 'cancel' && JSON.stringify(m).length > 16384) throw new Error();
  } catch {
    reply(m.id, { code: 'protocol.invalid_params', error: 'Overnet request is too large or malformed.' }); return;
  }
  if (m.method !== 'cancel') {
    if (pending.size) { reply(m.id, { code: 'browser.busy', error: 'A sign-in request is already pending.' }); return; }
    pending.add(m.id);
  }
  try { connect().postMessage({ id: m.id, method: m.method, ...(m.method === 'cancel' ? {} : { challenge: m.challenge }) }); }
  catch {
    pending.delete(m.id);
    reply(m.id, { code: 'browser.unavailable', error: 'Reload this page after reloading Overnet.' });
  }
});
window.addEventListener('pagehide', () => {
  const old = port; port = undefined; pending.clear(); old?.disconnect();
});
