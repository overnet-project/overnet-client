import type { AuthResult } from '../protocol/auth.ts';
import { object, OvernetError } from '../protocol/errors.ts';
export { OvernetError } from '../protocol/errors.ts';
export type { AuthResult } from '../protocol/auth.ts';
export type ProviderInfo = { version: number; methods: string[] };
export type RequestOptions = { signal?: AbortSignal; timeout?: number };

export class OvernetClient {
  #window: Window;
  constructor(target: Window = window) { this.#window = target; }

  info(options: RequestOptions = {}): Promise<ProviderInfo> {
    return this.#request('provider.info', undefined, { timeout: 2000, ...options });
  }
  authenticate(challenge: unknown, options: RequestOptions = {}): Promise<AuthResult> {
    return this.#request('authenticate', challenge, { timeout: 125000, ...options });
  }
  #request<T>(method: string, challenge: unknown, options: RequestOptions): Promise<T> {
    const w = this.#window, id = crypto.randomUUID();
    const delay = options.timeout ?? 125000;
    if (!Number.isFinite(delay) || delay <= 0 || delay > 2147483647) return Promise.reject(new RangeError('Invalid request timeout'));
    return new Promise((resolve, reject) => {
      let finished = false;
      const post = (method: string) => w.postMessage({ type: 'overnet:request', id, method, challenge }, w.location.origin);
      const finish = (result?: T, error?: Error) => {
        if (finished) return;
        finished = true; clearTimeout(timer);
        w.removeEventListener('message', receive); w.removeEventListener('pagehide', abort);
        options.signal?.removeEventListener('abort', abort);
        if (error) reject(error); else resolve(result as T);
      };
      const cancel = (code: string, message: string) => {
        try { post('cancel'); } catch { /* The document or binding may be gone. */ }
        finish(undefined, new OvernetError(code, message));
      };
      const abort = () => cancel('browser.cancelled', 'Sign-in cancelled.');
      const receive = (event: MessageEvent) => {
        const m = event.data;
        if (event.source !== w || event.origin !== w.location.origin || m?.type !== 'overnet:response' || m.id !== id) return;
        if (typeof m.error === 'string') finish(undefined, new OvernetError(typeof m.code === 'string' ? m.code : 'auth.internal_failure', m.error));
        else if (object(m.result) && (method === 'provider.info'
          ? m.result.version === 1 && Array.isArray(m.result.methods) && m.result.methods.includes('authenticate')
          : object(m.result.auth_event))) finish(m.result as T);
        else finish(undefined, new OvernetError('protocol.invalid_message', 'Invalid Overnet response.'));
      };
      const timer = setTimeout(() => cancel('browser.timeout', method === 'provider.info'
        ? 'Enable the Overnet extension on this website.' : 'Overnet sign-in timed out.'), delay);
      w.addEventListener('message', receive); w.addEventListener('pagehide', abort);
      options.signal?.addEventListener('abort', abort, { once: true });
      if (options.signal?.aborted) abort(); else {
        try { post(method); } catch { finish(undefined, new OvernetError('browser.unavailable', 'Overnet is unavailable.')); }
      }
    });
  }
}
