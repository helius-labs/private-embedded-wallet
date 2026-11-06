import { SprEmbeddedWalletError } from "./error.js";

function appendJsonString(out: string[], value: string): void {
  out.push('"');
  for (const ch of value) {
    const code = ch.codePointAt(0) ?? 0;
    if (ch === '"') out.push('\\"');
    else if (ch === "\\") out.push("\\\\");
    else if (ch === "\b") out.push("\\b");
    else if (ch === "\f") out.push("\\f");
    else if (ch === "\n") out.push("\\n");
    else if (ch === "\r") out.push("\\r");
    else if (ch === "\t") out.push("\\t");
    else if (code < 0x20) out.push(`\\u${code.toString(16).padStart(4, "0")}`);
    else out.push(ch);
  }
  out.push('"');
}

function utf16Cmp(a: string, b: string): number {
  const left = [];
  const right = [];
  for (let i = 0; i < a.length; i += 1) left.push(a.charCodeAt(i));
  for (let i = 0; i < b.length; i += 1) right.push(b.charCodeAt(i));
  const n = Math.min(left.length, right.length);
  for (let i = 0; i < n; i += 1) {
    if (left[i] !== right[i]) return (left[i] ?? 0) - (right[i] ?? 0);
  }
  return left.length - right.length;
}

function appendJcs(out: string[], value: unknown): void {
  if (value === null) {
    out.push("null");
    return;
  }
  if (value === true) {
    out.push("true");
    return;
  }
  if (value === false) {
    out.push("false");
    return;
  }
  if (typeof value === "number") {
    if (!Number.isInteger(value) || !Number.isFinite(value)) {
      throw new SprEmbeddedWalletError("InvalidCanonicalJson");
    }
    out.push(String(value));
    return;
  }
  if (typeof value === "string") {
    appendJsonString(out, value);
    return;
  }
  if (Array.isArray(value)) {
    out.push("[");
    value.forEach((item, i) => {
      if (i > 0) out.push(",");
      appendJcs(out, item);
    });
    out.push("]");
    return;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value).sort(utf16Cmp);
    out.push("{");
    keys.forEach((key, i) => {
      if (i > 0) out.push(",");
      appendJsonString(out, key);
      out.push(":");
      appendJcs(out, (value as Record<string, unknown>)[key]);
    });
    out.push("}");
    return;
  }
  throw new SprEmbeddedWalletError("InvalidCanonicalJson");
}

export function canonicalizeJsonValue(value: unknown): string {
  const out: string[] = [];
  appendJcs(out, value);
  return out.join("");
}

export function isRfc8785(input: string): boolean {
  try {
    return canonicalizeJsonValue(JSON.parse(input) as unknown) === input;
  } catch {
    return false;
  }
}
