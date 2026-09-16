import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { decode } from "nostr-tools/nip19";
import { encrypt, decrypt } from "nostr-tools/nip49";
import { bech32 } from "@scure/base";
import { OvernetError, text } from "../protocol/errors.ts";

export { generateSecretKey, getPublicKey };

export function validateBackup(value: unknown): asserts value is string {
  try {
    if (typeof value !== "string" || value.length > 500) throw new Error();
    const decoded = bech32.decode(value as `${string}1${string}`, 500);
    const bytes = bech32.fromWords(decoded.words);
    // Bound imported KDF work before invoking scrypt; NIP-49 v2 is 91 bytes.
    if (decoded.prefix !== "ncryptsec" || bytes.length !== 91 || bytes[0] !== 2 ||
        bytes[1] < 10 || bytes[1] > 18 || bytes[42] > 2) throw new Error();
  } catch { throw new OvernetError("protocol.invalid_params", "Invalid or unsupported encrypted identity backup."); }
}

export function protectKey(key: Uint8Array, password: unknown): string {
  if (!text(password, 1024) || password.length < 8) {
    throw new OvernetError("protocol.invalid_params", "Use a local passphrase of at least 8 characters.");
  }
  return encrypt(key, password, 16);
}

export function readKey(value: string, password: string): Uint8Array {
  let key: Uint8Array | undefined;
  try {
    if (value.startsWith("ncryptsec1")) {
      validateBackup(value);
      if (!text(password, 1024)) throw new Error();
      key = decrypt(value, password);
    } else if (/^[0-9a-fA-F]{64}$/.test(value)) {
      key = Uint8Array.from(value.match(/../g)!, (byte) => parseInt(byte, 16));
    } else {
      const result = decode(value);
      if (result.type !== "nsec") throw new Error();
      key = result.data;
    }
    getPublicKey(key); // Reject zero, out-of-range, or malformed private keys.
    return key;
  } catch {
    key?.fill(0);
    throw new OvernetError("auth.backend_unavailable", "Could not unlock or import this identity. Check the key and passphrase.");
  }
}
