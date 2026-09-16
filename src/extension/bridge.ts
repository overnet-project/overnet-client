import type { Agent, Approval } from "../agent/agent.ts";
import { parseChallenge } from "../protocol/auth.ts";
import { failure, object, OvernetError, text } from "../protocol/errors.ts";
import type { Browser } from "./api.ts";

type Port = browser.runtime.Port;
type Request = { token: string; id: string; origin: string; page: Port; challenge: Record<string, unknown>;
  controller: AbortController; deadline: number; timer: ReturnType<typeof setTimeout>; ui?: Port; windowId?: number; signing?: boolean };

export function callerOrigin(sender?: browser.runtime.MessageSender): string {
  if (sender?.frameId !== 0 || !Number.isInteger(sender.tab?.id) || !sender.url) throw new Error("Invalid document");
  const url = new URL(sender.url);
  if (!["https:", "http:"].includes(url.protocol)) throw new Error("Invalid origin");
  return url.origin;
}

export function installBridge(api: Browser, ready: Promise<Agent>, timeout = 120000): void {
  // Keep listener registration synchronous, even while persistent state loads.
  const pending = new Map<string, Request>();
  const approvalURL = api.runtime.getURL("approval/index.html");
  const settingsURL = api.runtime.getURL("popup/index.html");
  const send = (port: Port, message: unknown) => { try { port.postMessage(message); } catch { /* Document is gone. */ } };
  const active = (request: Request): boolean => {
    if (!pending.has(request.token)) return false;
    if (Date.now() >= request.deadline) {
      finish(request, undefined, new OvernetError("browser.timeout", "Sign-in approval expired. Connect again."));
      return false;
    }
    return true;
  };
  const finish = (request: Request, result?: unknown, error?: unknown, deliver = true) => {
    if (!pending.delete(request.token)) return;
    // Timers can be delayed while the browser is suspended or decrypting a key.
    if (result !== undefined && Date.now() >= request.deadline) {
      result = undefined;
      error = new OvernetError("browser.timeout", "Sign-in approval expired. Connect again.");
    }
    clearTimeout(request.timer); request.controller.abort();
    if (deliver) send(request.page, { id: request.id, ...(error ? failure(error) : { result }) });
    request.ui?.disconnect();
    if (request.windowId !== undefined) void api.windows.remove(request.windowId).catch(() => {});
  };
  const cancel = (request: Request, deliver = true) => finish(request, undefined,
    new OvernetError("browser.cancelled", "Sign-in cancelled."), deliver);
  const show = async (request: Request) => {
    const agent = await ready;
    if (active(request) && request.ui) send(request.ui, { origin: request.origin, challenge: request.challenge, ...agent.view() });
  };

  api.windows.onRemoved.addListener((id) => {
    for (const request of pending.values()) if (request.windowId === id) cancel(request);
  });
  api.runtime.onConnect.addListener((port) => {
    if (port.name === "overnet-page") {
      let origin: string;
      try { origin = callerOrigin(port.sender); } catch { port.disconnect(); return; }
      port.onDisconnect.addListener(() => {
        for (const request of pending.values()) if (request.page === port) cancel(request, false);
      });
      port.onMessage.addListener(async (message: unknown) => {
        if (!object(message) || !text(message.id, 128) || typeof message.method !== "string") return;
        const current = [...pending.values()].find((r) => r.page === port);
        if (message.method === "cancel") { if (current?.id === message.id) cancel(current); return; }
        if (current?.id === message.id) return;
        let request: Request | undefined;
        try {
          if (message.method !== "authenticate") throw new OvernetError("protocol.unknown_method", "Unsupported Overnet method.");
          if (current || pending.size >= 4) throw new OvernetError("browser.busy", "A sign-in approval is already pending.");
          const parsed = parseChallenge(message.challenge);
          const challenge = { scope: parsed.scope, challenge: parsed.challenge, ...parsed.delegation };
          const token = crypto.randomUUID();
          request = { token, id: message.id, origin, page: port, challenge, controller: new AbortController(), deadline: Date.now() + timeout,
            timer: setTimeout(() => {
              const r = pending.get(token);
              if (r) finish(r, undefined, new OvernetError("browser.timeout", "Sign-in approval expired. Connect again."));
            }, timeout) };
          pending.set(token, request);
          const agent = await ready;
          if (!active(request)) return;
          try {
            const result = await agent.authorize(origin, challenge, undefined, request.controller.signal);
            finish(request, result); return;
          } catch (error) {
            if (!(error instanceof OvernetError) || !["auth.approval_required", "auth.backend_unavailable"].includes(error.code)) throw error;
          }
          if (!active(request)) return;
          const window = await api.windows.create({ url: `${approvalURL}#${token}`, type: "popup", width: 520, height: 760 });
          if (active(request)) request.windowId = window?.id;
          else if (window?.id !== undefined) void api.windows.remove(window.id).catch(() => {});
        } catch (error) {
          if (request) finish(request, undefined, error);
          else send(port, { id: message.id, ...failure(error) });
        }
      });
      return;
    }

    let url: URL;
    try { url = new URL(port.sender?.url ?? "about:blank"); } catch { port.disconnect(); return; }
    const base = `${url.protocol}//${url.host}${url.pathname}`;
    if (port.name === "overnet-approval") {
      const request = pending.get(url.hash.slice(1));
      if (base !== approvalURL || !request || request.ui) { port.disconnect(); return; }
      request.ui = port;
      port.onDisconnect.addListener(() => cancel(request));
      void show(request).catch((error) => finish(request, undefined, error));
      port.onMessage.addListener(async (message: unknown) => {
        if (!active(request) || !object(message)) return;
        if (message.refresh === true) { await show(request); return; }
        if (message.approve !== true) { finish(request, undefined, new OvernetError("auth.policy_denied", "Sign-in declined.")); return; }
        if (request.signing || !text(message.identityId, 128)) return;
        request.signing = true;
        try {
          const agent = await ready;
          if (!active(request)) return;
          const identity = agent.view().identities.find((i) => i.id === message.identityId);
          if (!identity) throw new OvernetError("auth.identity_required", "Select an identity.");
          if (!identity.unlocked) {
            if (typeof message.password !== "string") throw new OvernetError("auth.backend_unavailable", "Enter your local unlock passphrase.");
            agent.unlock(identity.id, message.password);
          }
          const approval: Approval = { identityId: identity.id, remember: message.remember === true };
          const result = await agent.authorize(request.origin, request.challenge, approval, request.controller.signal);
          finish(request, result);
        } catch (error) {
          if (active(request)) {
            request.signing = false;
            if (error instanceof OvernetError && ["auth.backend_unavailable", "auth.identity_required"].includes(error.code)) send(port, failure(error));
            else finish(request, undefined, error);
          }
        }
      });
      return;
    }

    if (port.name !== "overnet-settings" || base !== settingsURL) { port.disconnect(); return; }
    port.onMessage.addListener(async (message: unknown) => {
      if (!object(message) || !text(message.id, 128) || !text(message.method, 64)) return;
      try {
        const agent = await ready;
        const p = object(message.params) ? message.params : {};
        const string = (name: string) => typeof p[name] === "string" ? p[name] as string : "";
        let result: unknown;
        switch (message.method) {
          case "status": result = agent.view(); break;
          case "create": result = await agent.addIdentity(string("label"), string("password"), string("key"), string("importPassword") || string("password")); break;
          case "unlock": result = agent.unlock(string("identityId"), string("password")); break;
          case "backup": result = { backup: agent.backup(string("identityId"), string("password")) }; break;
          case "lock":
            result = agent.lock();
            for (const request of pending.values()) cancel(request);
            break;
          case "forget":
            for (const request of pending.values()) cancel(request);
            result = await agent.forgetApprovals(); break;
          default: throw new OvernetError("protocol.unknown_method", "Unsupported identity operation.");
        }
        send(port, { id: message.id, result });
      } catch (error) { send(port, { id: message.id, ...failure(error) }); }
    });
  });
  // Attach a rejection handler immediately; requests still receive the failure.
  void ready.catch(() => {});
}
