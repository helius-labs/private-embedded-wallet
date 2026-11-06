import { SprEmbeddedWalletError } from "./error.js";

function skipWs(text: string, i: number): number {
  while (i < text.length && /\s/.test(text[i] ?? "")) i += 1;
  return i;
}

function parseString(text: string, start: number): { value: string; next: number } {
  if (text[start] !== '"') throw new SprEmbeddedWalletError("InvalidCanonicalJson");
  let i = start + 1;
  let value = "";
  while (i < text.length) {
    const ch = text[i];
    if (ch === '"') return { value, next: i + 1 };
    if (ch === "\\") {
      const next = text[i + 1];
      const map: Record<string, string> = {
        '"': '"',
        "\\": "\\",
        "/": "/",
        b: "\b",
        f: "\f",
        n: "\n",
        r: "\r",
        t: "\t",
      };
      if (next && map[next] !== undefined) {
        value += map[next];
        i += 2;
        continue;
      }
      if (next === "u") {
        const hex = text.slice(i + 2, i + 6);
        value += String.fromCharCode(Number.parseInt(hex, 16));
        i += 6;
        continue;
      }
      throw new SprEmbeddedWalletError("InvalidCanonicalJson");
    }
    value += ch;
    i += 1;
  }
  throw new SprEmbeddedWalletError("InvalidCanonicalJson");
}

function parseValue(text: string, start: number): { next: number } {
  let i = skipWs(text, start);
  const ch = text[i];
  if (ch === "{") {
    i += 1;
    i = skipWs(text, i);
    const seen = new Set<string>();
    if (text[i] === "}") return { next: i + 1 };
    while (i < text.length) {
      i = skipWs(text, i);
      const key = parseString(text, i);
      if (seen.has(key.value)) throw new SprEmbeddedWalletError("DuplicateJsonField");
      seen.add(key.value);
      i = skipWs(text, key.next);
      if (text[i] !== ":") throw new SprEmbeddedWalletError("InvalidCanonicalJson");
      const nested = parseValue(text, i + 1);
      i = skipWs(text, nested.next);
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "}") return { next: i + 1 };
      throw new SprEmbeddedWalletError("InvalidCanonicalJson");
    }
    throw new SprEmbeddedWalletError("InvalidCanonicalJson");
  }
  if (ch === "[") {
    i += 1;
    i = skipWs(text, i);
    if (text[i] === "]") return { next: i + 1 };
    while (i < text.length) {
      const nested = parseValue(text, i);
      i = skipWs(text, nested.next);
      if (text[i] === ",") {
        i += 1;
        continue;
      }
      if (text[i] === "]") return { next: i + 1 };
      throw new SprEmbeddedWalletError("InvalidCanonicalJson");
    }
    throw new SprEmbeddedWalletError("InvalidCanonicalJson");
  }
  if (ch === '"') return { next: parseString(text, i).next };
  if (ch === "t" || ch === "f" || ch === "n" || ch === "-" || (ch !== undefined && ch >= "0" && ch <= "9")) {
    while (i < text.length && /[0-9eE+.\-truefalsn]/.test(text[i] ?? "")) i += 1;
    return { next: i };
  }
  throw new SprEmbeddedWalletError("InvalidCanonicalJson");
}

/**
 * Parses JSON, rejecting duplicate keys and trailing data. When `exactKeys` is
 * given, the top-level object must carry exactly those keys, mirroring serde's
 * `deny_unknown_fields` plus its required-field checks on the Rust side.
 */
export function parseStrictJson<T>(text: string, exactKeys?: readonly string[]): T {
  const scanned = parseValue(text, 0);
  if (skipWs(text, scanned.next) !== text.length) {
    throw new SprEmbeddedWalletError("InvalidCanonicalJson");
  }
  const value = JSON.parse(text) as T;
  if (exactKeys && value && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value as object);
    for (const key of keys) {
      if (!exactKeys.includes(key)) throw new SprEmbeddedWalletError("UnknownJsonField");
    }
    if (keys.length !== exactKeys.length) throw new SprEmbeddedWalletError("InvalidCanonicalJson");
  }
  return value;
}
