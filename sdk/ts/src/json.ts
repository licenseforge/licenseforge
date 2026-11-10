// A strict JSON reader for lf1 payloads (spec/license-format.md, claim
// encoding rules). JSON.parse isn't enough: it keeps the last of duplicate
// keys, folds 1.0 into 1, and keeps unpaired surrogate escapes. This reader
// keeps number tokens as text and refuses what the spec refuses.

/** A parsed JSON value: numbers keep their source token. */
export type Value =
  | { kind: "object"; entries: Map<string, Value> }
  | { kind: "array"; items: Value[] }
  | { kind: "string"; value: string }
  | { kind: "number"; token: string }
  | { kind: "bool"; value: boolean }
  | { kind: "null" };

/** The deepest object/array nesting allowed (the top-level object is depth 1). */
export const maxDepth = 32;

export class JSONError extends Error {}

const numberRE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

/**
 * Parses text as exactly one JSON object with nothing but JSON whitespace
 * around it: no duplicate keys in any object, nesting at most maxDepth,
 * no unpaired surrogate escapes, no control characters in strings.
 */
export function parseObject(text: string): Map<string, Value> {
  let i = 0;
  const fail = (msg: string): never => {
    throw new JSONError(`${msg} at offset ${i}`);
  };
  const ws = () => {
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) break;
      i++;
    }
  };
  const hex4 = (at: number): number => {
    const h = text.slice(at, at + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u escape");
    return parseInt(h, 16);
  };
  const str = (): string => {
    i++; // the opening quote
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return out;
      }
      if (c < 0x20) fail("control character in string");
      if (c !== 0x5c) {
        out += text[i];
        i++;
        continue;
      }
      const e = text[i + 1];
      i += 2;
      switch (e) {
        case '"': out += '"'; break;
        case "\\": out += "\\"; break;
        case "/": out += "/"; break;
        case "b": out += "\b"; break;
        case "f": out += "\f"; break;
        case "n": out += "\n"; break;
        case "r": out += "\r"; break;
        case "t": out += "\t"; break;
        case "u": {
          const u = hex4(i);
          i += 4;
          if (u >= 0xdc00 && u <= 0xdfff) fail("unpaired surrogate escape");
          if (u >= 0xd800 && u <= 0xdbff) {
            if (text[i] !== "\\" || text[i + 1] !== "u") fail("unpaired surrogate escape");
            const lo = hex4(i + 2);
            if (lo < 0xdc00 || lo > 0xdfff) fail("unpaired surrogate escape");
            i += 6;
            out += String.fromCharCode(u, lo);
          } else {
            out += String.fromCharCode(u);
          }
          break;
        }
        default:
          fail("bad escape");
      }
    }
  };
  const value = (depth: number): Value => {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      if (depth > maxDepth) fail(`nesting deeper than ${maxDepth}`);
      i++;
      ws();
      if (c === "{") {
        const entries = new Map<string, Value>();
        if (text[i] === "}") {
          i++;
          return { kind: "object", entries };
        }
        for (;;) {
          ws();
          if (text[i] !== '"') fail("expected a key");
          const k = str();
          if (entries.has(k)) fail(`duplicate key ${JSON.stringify(k)}`);
          ws();
          if (text[i] !== ":") fail("expected :");
          i++;
          entries.set(k, value(depth + 1));
          ws();
          if (text[i] === ",") {
            i++;
            continue;
          }
          if (text[i] === "}") {
            i++;
            return { kind: "object", entries };
          }
          fail("expected , or }");
        }
      }
      const items: Value[] = [];
      if (text[i] === "]") {
        i++;
        return { kind: "array", items };
      }
      for (;;) {
        items.push(value(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return { kind: "array", items };
        }
        fail("expected , or ]");
      }
    }
    if (c === '"') return { kind: "string", value: str() };
    for (const [word, v] of [["true", { kind: "bool", value: true }], ["false", { kind: "bool", value: false }], ["null", { kind: "null" }]] as const) {
      if (text.startsWith(word, i)) {
        i += word.length;
        return v;
      }
    }
    numberRE.lastIndex = i;
    const m = numberRE.exec(text);
    if (!m) return fail("unexpected character");
    i += m[0].length;
    return { kind: "number", token: m[0] };
  };
  ws();
  if (text[i] !== "{") fail("expected a JSON object");
  const top = value(1);
  ws();
  if (i !== text.length) fail("trailing data after the object");
  return (top as { kind: "object"; entries: Map<string, Value> }).entries;
}
