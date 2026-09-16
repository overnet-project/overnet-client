# Overnet Client

TypeScript client software for Overnet: shared authentication code, a local
identity agent, a browser extension, and a small website SDK. Firefox desktop is
the first tested browser. The extension signs locally and needs no Perl runtime,
native messaging connector, or separately started process.

This repository replaces `browser-extension`. The extension ID and website
message format are preserved, so the existing Kiwi authentication plugin and
IRC server do not need changes.

## Architecture

| Directory | Responsibility |
| --- | --- |
| `src/protocol/` | Shared authentication challenge validation, signed events, and Nostr verification |
| `src/agent/` | Encrypted identities, locking, approval policy, service trust, and authorized signing |
| `src/extension/` | Trusted browser controls, caller identification, local storage, and document lifetime |
| `src/web/` | Website SDK; messaging only, with no agent or cryptography code |
| `manifests/` | Shared manifest and browser-specific overrides |
| `examples/` | Independent sign-in example using the SDK and a verifying local service |

The agent has no browser imports. Its host supplies a store whose writes must
atomically replace and durably save one state object. Only trusted host code may
supply approval decisions. Websites never receive an agent reference, private
keys, identity lists, storage access, or local session handles.

[Nostr Tools](https://github.com/nbd-wtf/nostr-tools) supplies event cryptography
and NIP-49 encryption. Protocol verification rechecks signatures without trusting
a cached verification flag. The current protocol module implements the shared
authentication exchange; it is not yet a complete Overnet core event validator
or relay client. Applications continue to own service connections and behavior.

The language-independent contracts live in the specification repository:

- [Authentication](https://github.com/overnet-project/spec/blob/main/docs/auth.md)
- [Browser binding](https://github.com/overnet-project/spec/blob/main/docs/user-agent.md)
- [IRC binding](https://github.com/overnet-project/spec/blob/main/docs/adapters/irc.md)

## Build and install locally

Development requires Node.js 24 or later. End users only need the built extension.
From the top-level Overnet workspace:

```sh
npm --prefix repos/overnet-client ci
npm --prefix repos/overnet-client run verify
```

In Firefox, open `about:debugging#/runtime/this-firefox`, choose **Load Temporary
Add-on**, and select `repos/overnet-client/dist/extension/firefox/manifest.json`.
If the previous Overnet extension is loaded, remove that temporary installation
first, then load this build. Its identity key remains in the previous Perl agent
until you explicitly import it here.

Open the Overnet toolbar button and add an identity. Leave the import field empty
to create one, or import an existing `nsec`, hexadecimal private key, or encrypted
`ncryptsec` backup. Choose a local unlock passphrase. Create an encrypted backup
and save it before relying on the identity.

Refresh your webchat page, connect, and approve the sign-in. If the identity is
locked, the approval window asks for its local passphrase. Nothing is sent to a
native connector or a password-authentication service.

Temporary add-ons disappear on browser restart. Keep a backup and reload the
build for development; do not rely on temporary-installation storage surviving
removal. Normal Firefox distribution still requires a signed add-on. Signing and
store publication are separate release work. Do not uninstall your only copy of
an identity before saving its backup.

Use `repos/overnet-client`; the old `repos/browser-extension` alias has been removed.
The previous native-connector build remains at `dist/firefox/` for migration;
new builds go to `dist/extension/firefox/` and leave those old files untouched.
The previous generated build is not required by a new clone.

## Identity storage and approvals

The extension stores only NIP-49 encrypted keys, public identity metadata,
remembered policies, and service pins in `browser.storage.local`. It never uses
browser synchronization. Unlocked keys live in agent memory and are cleared on
lock or background termination; a browser restart starts locked. JavaScript does
not guarantee complete erasure of every temporary memory copy.

Backups are standard NIP-49 v2 `ncryptsec` strings protected by their own chosen
passphrase, using scrypt and XChaCha20-Poly1305. New keys and backups use scrypt
`log_n = 16`. Imports accept `log_n` from 10 through 18 and reject higher work
factors before decryption to bound memory and CPU use. Restore validates the key,
re-encrypts it with the new local passphrase, and creates no remembered approvals.
The same public key is retained. Back up each identity separately.

Multiple identities are supported. Remembered access binds one identity, the
actual website origin in this browser profile, the exact service scope, the
requested action, and (for delegation) the exact authority endpoint. The trusted
approval window explicitly offers future delegated sessions of up to 24 hours.
Changed origins, scopes, or authority endpoints require a fresh decision.
**Forget remembered access** prevents future automatic approvals; it does not
revoke grants already issued to a service.

This binding currently uses provisional service address trust. It does not
implement service-identity discovery or silently bypass an existing service pin.
Requests for a pinned service that cannot prove that identity are rejected.
Native IPC uses the separate Perl agent and requires a host that establishes
trusted caller identity. Its unbound daemon socket supports discovery only;
signing and administration require that caller integration.

## Website SDK

The build produces `dist/web.js`, a standalone ES module. Copy it into your web
application and use:

```js
import { OvernetClient } from './overnet-client.js';

const overnet = new OvernetClient();
await overnet.info();
const result = await overnet.authenticate(serviceChallenge, {
  signal: connectionAbortController.signal,
});
// Carry result.auth_event and optional result.delegate_event to your service.
// The service must verify both against its current challenge and session.
```

`authenticate` accepts the shared challenge from the service. Aborting cancels
pending local approval. Finite timeouts handle a missing or restarted extension.
Errors expose `.code` and `.message`. The existing `window.postMessage` contract
is also supported: `provider.info`, `authenticate`, and `cancel`, using the same
`overnet:request` and `overnet:response` envelopes as the original integration.
Messages are public to scripts on that page and are not themselves proof of
identity or extension authenticity.

For a separate application that uses the SDK:

```sh
npm --prefix repos/overnet-client run demo
```

Open the printed loopback URL. Its service verifies the signature, scope, and
single-use challenge. Opening the equivalent `localhost` URL exercises a second
origin and requires separate approval. This is a development example, not a
production service.

## Verification

GitHub Actions runs `npm run verify` on every push and pull request using Node.js
24. The same command runs locally: Biome lint (warnings fail), strict TypeScript
checks, tests with coverage gates, the Firefox build, and Mozilla's `web-ext`
validator (warnings fail). Dependency versions are locked by `npm ci`.

Coverage must reach **95% for lines, statements, functions, and branches** across
all `src/**/*.ts`, including the extension UI, content script, and background
entry point. Files never imported by a test count as uncovered. Generated
bundles, tests, build scripts, and examples are outside this runtime-source gate;
they still receive the applicable lint, type, and build checks. Run
`npm run test:coverage` separately to regenerate the HTML report at
`coverage/index.html` and the LCOV report at `coverage/lcov.info`. CI uploads the
reports as a `coverage` artifact, including when the coverage gate fails.

`npm test` covers real signing, encrypted backup/restore, restart and lock
behavior, persistent policies, origin and service isolation, corrupted storage,
cancellation, trusted UI checks, and SDK errors. DOM tests exercise the actual
extension scripts with jsdom and mocked WebExtension ports; they do not replace
testing in Firefox. Shared auth fixture checks use `../spec` when available, or
an explicit `OVERNET_SPEC_DIR`. They skip only for a local run without a spec
checkout or explicit path. Missing fixtures fail in CI, which checks out a pinned
revision of [the spec](https://github.com/overnet-project/spec) into `.spec/`.
Update that revision in `.github/workflows/ci.yml` when adopting newer fixtures.

The initial implementation was also checked in isolated Firefox profiles:
identity creation, backup, restoration into a fresh profile, lock/unlock, a full
browser restart, and successful SASL authentication and registration with the
unchanged Kiwi plugin on debserver. The SDK example exercised two origins,
denial, remembered access, and a restart that required unlocking the identity.
The test profiles enabled unsigned permanent add-ons for restart testing; no
signing preference was changed in the user's browser.

## License

GNU General Public License, version 3. See [LICENSE](LICENSE).
