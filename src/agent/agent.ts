import { type AuthResult, type Challenge, maxLifetime, parseChallenge, signAuthentication } from "../protocol/auth.ts";
import { object, OvernetError, text } from "../protocol/errors.ts";
import { generateSecretKey, getPublicKey, protectKey, readKey, validateBackup } from "./keys.ts";

export type Identity = { id: string; label: string; pubkey: string; encryptedKey: string };
export type Policy = { id: string; identityId: string; origin: string; scope: string; relay?: string; maxLifetime: number };
export type State = { version: 1; profile: string; identities: Identity[]; policies: Policy[]; servicePins: Record<string, string> };
export type AgentView = { identities: { id: string; label: string; pubkey: string; unlocked: boolean }[]; policies: Policy[] };
export interface Store { read(): Promise<unknown>; write(state: State): Promise<void> }
export type Approval = { identityId: string; remember: boolean };
const locked = () => new OvernetError("auth.backend_unavailable", "Unlock your identity in Overnet to continue.");

function validateState(value: unknown): asserts value is State {
  try {
    if (!object(value) || value.version !== 1 || !text(value.profile, 128) ||
        !Array.isArray(value.identities) || value.identities.length > 32 ||
        !Array.isArray(value.policies) || value.policies.length > 256 || !object(value.servicePins)) throw new Error();
    const ids = new Set<string>();
    for (const identity of value.identities) {
      if (!object(identity) || !text(identity.id, 128) || ids.has(identity.id) || !text(identity.label, 80) ||
          typeof identity.pubkey !== "string" || !/^[0-9a-f]{64}$/.test(identity.pubkey)) throw new Error();
      validateBackup(identity.encryptedKey); ids.add(identity.id);
    }
    for (const p of value.policies) {
      if (!object(p) || !text(p.id, 128) || typeof p.identityId !== "string" || !ids.has(p.identityId) ||
          !text(p.origin) || new URL(p.origin).origin !== p.origin || !/^https?:/.test(p.origin) || !text(p.scope) ||
          (p.relay !== undefined && !text(p.relay)) || typeof p.maxLifetime !== "number" ||
          !Number.isSafeInteger(p.maxLifetime) || p.maxLifetime < 0 || p.maxLifetime > maxLifetime ||
          (p.relay === undefined && p.maxLifetime !== 0)) throw new Error();
    }
    if (!Object.entries(value.servicePins).every(([scope, key]) => text(scope) && text(key))) throw new Error();
  } catch { throw new OvernetError("auth.backend_unavailable", "Saved Overnet identity or trust data is unreadable. Restore a backup; existing data has been preserved."); }
}

export class Agent {
  #state: State;
  #store: Store;
  #keys = new Map<string, Uint8Array>();
  #writes: Promise<unknown> = Promise.resolve();
  #generation = 0;

  private constructor(store: Store, state: State) { this.#store = store; this.#state = state; }

  static async open(store: Store): Promise<Agent> {
    let state = await store.read();
    if (state === undefined) state = { version: 1, profile: crypto.randomUUID(), identities: [], policies: [], servicePins: {} };
    validateState(state);
    return new Agent(store, structuredClone(state));
  }

  view(): AgentView {
    return { identities: this.#state.identities.map(({ id, label, pubkey }) => ({ id, label, pubkey, unlocked: this.#keys.has(id) })),
      policies: structuredClone(this.#state.policies) };
  }

  #serial<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.#writes.then(operation);
    this.#writes = result.catch(() => {});
    return result;
  }

  async #save(next: State): Promise<void> {
    validateState(next);
    try { await this.#store.write(structuredClone(next)); }
    catch { throw new OvernetError("auth.backend_unavailable", "Could not save Overnet data. No change has been acknowledged."); }
    this.#state = next;
  }

  addIdentity(label: string, password: string, imported = "", importPassword = password): Promise<AgentView> {
    const generation = this.#generation;
    return this.#serial(async () => {
      if (!text(label.trim(), 80)) throw new OvernetError("protocol.invalid_params", "Choose an identity name (up to 80 characters).");
      if (this.#state.identities.length >= 32) throw new OvernetError("auth.policy_denied", "This profile already has 32 identities.");
      const key = imported.trim() ? readKey(imported.trim(), importPassword) : generateSecretKey();
      try {
        const pubkey = getPublicKey(key);
        if (this.#state.identities.some((i) => i.pubkey === pubkey)) {
          throw new OvernetError("protocol.invalid_params", "That identity is already in this profile.");
        }
        const record: Identity = { id: crypto.randomUUID(), label: label.trim(), pubkey, encryptedKey: protectKey(key, password) };
        await this.#save({ ...this.#state, identities: [...this.#state.identities, record] });
        if (generation === this.#generation) this.#keys.set(record.id, key.slice());
        return this.view();
      } finally { key.fill(0); }
    });
  }

  unlock(id: string, password: string): AgentView {
    const identity = this.#state.identities.find((i) => i.id === id);
    if (!identity) throw new OvernetError("auth.identity_required", "Select an identity.");
    const key = readKey(identity.encryptedKey, password);
    if (getPublicKey(key) !== identity.pubkey) { key.fill(0); throw locked(); }
    this.#keys.get(id)?.fill(0);
    this.#keys.set(id, key);
    return this.view();
  }

  lock(): AgentView {
    this.#generation++;
    for (const key of this.#keys.values()) key.fill(0);
    this.#keys.clear();
    return this.view();
  }

  backup(id: string, password: string): string {
    const key = this.#keys.get(id);
    if (!key) throw locked();
    return protectKey(key, password);
  }

  forgetApprovals(): Promise<AgentView> {
    this.#generation++; // Invalidate signing waiting on a policy write.
    return this.#serial(async () => { await this.#save({ ...this.#state, policies: [] }); return this.view(); });
  }

  #trust(challenge: Challenge): void {
    if (Object.hasOwn(this.#state.servicePins, challenge.scope) ||
        (challenge.delegation && Object.hasOwn(this.#state.servicePins, challenge.delegation.relay_url))) {
      throw new OvernetError("auth.service_identity_mismatch", "This request cannot prove the service identity already pinned in this profile.");
    }
  }

  // Only the trusted host can supply Approval. A website gets no reference to this agent.
  async authorize(origin: string, rawChallenge: unknown, approval?: Approval, signal?: AbortSignal): Promise<AuthResult> {
    if (!/^https?:/.test(origin) || new URL(origin).origin !== origin) {
      throw new OvernetError("protocol.invalid_params", "Invalid caller origin.");
    }
    const generation = this.#generation;
    const check = () => {
      if (signal?.aborted) throw new OvernetError("browser.cancelled", "Sign-in cancelled.");
      if (generation !== this.#generation) throw locked();
    };
    check();
    const challenge = parseChallenge(rawChallenge);
    this.#trust(challenge);
    let id = approval?.identityId;
    if (!approval) {
      const policies = this.#state.policies.filter((p) => p.origin === origin && p.scope === challenge.scope &&
        p.relay === challenge.delegation?.relay_url && (!challenge.delegation ||
          challenge.delegation.expires_at <= Math.floor(Date.now() / 1000) + p.maxLifetime));
      const identities = [...new Set(policies.map((p) => p.identityId))];
      if (identities.length !== 1) throw new OvernetError("auth.approval_required", "Approve this sign-in in Overnet.");
      id = identities[0];
    }
    if (!id || !this.#state.identities.some((i) => i.id === id)) throw new OvernetError("auth.identity_required", "Select an identity.");
    if (!this.#keys.has(id)) throw locked();
    if (approval?.remember) {
      const identityId = id;
      await this.#serial(async () => {
        check(); this.#trust(challenge);
        const policy: Policy = { id: crypto.randomUUID(), identityId, origin, scope: challenge.scope,
          ...(challenge.delegation ? { relay: challenge.delegation.relay_url } : {}),
          maxLifetime: challenge.delegation ? maxLifetime : 0 };
        const policies = this.#state.policies.filter((p) => !(p.identityId === identityId && p.origin === origin &&
          p.scope === challenge.scope && p.relay === policy.relay));
        await this.#save({ ...this.#state, policies: [...policies, policy] });
      });
    }
    check(); this.#trust(challenge);
    const key = this.#keys.get(id);
    if (!key) throw locked();
    return signAuthentication(challenge, key);
  }
}
