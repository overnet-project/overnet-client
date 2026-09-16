export type Browser = typeof browser;
export const api: Browser = globalThis.browser ?? (globalThis as unknown as { chrome: Browser }).chrome;
