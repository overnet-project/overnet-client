import { finalizeEvent, verifyEvent, type Event } from "nostr-tools/pure";
import { object, OvernetError, scalarString, text } from "./errors.ts";

export type Challenge = { scope: string; challenge: string; delegation?: {
  relay_url: string; grant_kind: 14142; delegate_pubkey: string; session_id: string; expires_at: number;
} };
export type AuthResult = { auth_event: Event; delegate_event?: Event };
export const maxLifetime = 86400;
const fields = ["relay_url", "grant_kind", "delegate_pubkey", "session_id", "expires_at"];
const integer = (x: unknown) => (typeof x === "number" && Number.isSafeInteger(x)) ||
  (typeof x === "string" && /^[0-9]+$/.test(x) && Number.isSafeInteger(Number(x)));

// Copy only the shared exchange fields. Callers cannot supply event templates.
export function parseChallenge(value: unknown, now = Math.floor(Date.now() / 1000)): Challenge {
  const invalid = () => new OvernetError("protocol.invalid_params", "Invalid or expired service challenge.");
  if (!Number.isSafeInteger(now) || now < 0 || !object(value) || !text(value.scope) || !text(value.challenge, 4096)) throw invalid();
  const result: Challenge = { scope: value.scope, challenge: value.challenge };
  if (fields.some((field) => Object.hasOwn(value, field))) {
    if (!text(value.relay_url) || !text(value.session_id, 512) ||
        typeof value.delegate_pubkey !== "string" || !/^[0-9a-f]{64}$/.test(value.delegate_pubkey) ||
        !integer(value.grant_kind) || Number(value.grant_kind) !== 14142 ||
        !integer(value.expires_at) || Number(value.expires_at) <= now) throw invalid();
    if (Number(value.expires_at) > now + maxLifetime) {
      throw new OvernetError("auth.policy_denied", "Session delegation is limited to 24 hours.");
    }
    result.delegation = { relay_url: value.relay_url, grant_kind: 14142,
      delegate_pubkey: value.delegate_pubkey, session_id: value.session_id, expires_at: Number(value.expires_at) };
  }
  return result;
}

export function signAuthentication(challenge: Challenge, key: Uint8Array,
  now = Math.floor(Date.now() / 1000)): AuthResult {
  // Validate again after waiting for user interaction or storage.
  const c = parseChallenge({ scope: challenge.scope, challenge: challenge.challenge, ...challenge.delegation }, now);
  const auth_event = finalizeEvent({ kind: 22242, created_at: now, content: "",
    tags: [["relay", c.scope], ["challenge", c.challenge]] }, key);
  if (!c.delegation) return { auth_event };
  const d = c.delegation;
  const delegate_event = finalizeEvent({ kind: 14142, created_at: now, content: "", tags: [
    ["relay", d.relay_url], ["server", c.scope], ["delegate", d.delegate_pubkey],
    ["session", d.session_id], ["expires_at", String(d.expires_at)],
  ] }, key);
  return { auth_event, delegate_event };
}

// Never trust nostr-tools' cached verified symbol on a caller-owned object.
export function verifySignedEvent(value: unknown): value is Event {
  try {
    if (!object(value) || typeof value.id !== "string" || !/^[0-9a-f]{64}$/.test(value.id) ||
        typeof value.pubkey !== "string" || !/^[0-9a-f]{64}$/.test(value.pubkey) ||
        typeof value.sig !== "string" || !/^[0-9a-f]{128}$/.test(value.sig) ||
        !Number.isSafeInteger(value.created_at) || Number(value.created_at) < 0 ||
        !Number.isSafeInteger(value.kind) || Number(value.kind) < 0 || Number(value.kind) > 65535 ||
        !scalarString(value.content) || !Array.isArray(value.tags) ||
        !value.tags.every((tag) => Array.isArray(tag) && tag.every(scalarString))) return false;
    return verifyEvent(JSON.parse(JSON.stringify(value)) as Event);
  } catch { return false; }
}
