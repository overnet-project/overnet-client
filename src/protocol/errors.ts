export class OvernetError extends Error {
  readonly code: string;
  constructor(code: string, message: string) { super(message); this.code = code; }
}

export function failure(error: unknown): { code: string; error: string } {
  return error instanceof OvernetError
    ? { code: error.code, error: error.message }
    : { code: "auth.internal_failure", error: "Overnet could not complete this request." };
}

export function scalarString(value: unknown): value is string {
  // In Unicode mode, a valid surrogate pair is matched as its scalar value.
  return typeof value === "string" && !/[\ud800-\udfff]/u.test(value);
}

export function text(value: unknown, max = 2048): value is string {
  return scalarString(value) && value.length > 0 && value.length <= max &&
    // biome-ignore lint/suspicious/noControlCharactersInRegex: Protocol text must reject control characters.
    !/[\u0000-\u001f\u007f]/u.test(value);
}

export function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
