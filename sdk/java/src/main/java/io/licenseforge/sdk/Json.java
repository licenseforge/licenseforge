package io.licenseforge.sdk;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict JSON reader for lf1 payloads and key sets (spec/license-format.md,
 * claim encoding rules). Default Jackson or Gson isn't enough: they accept
 * duplicate keys, fold 1.0 into 1 and keep unpaired surrogate escapes. This
 * reader keeps number tokens as text and refuses what the spec refuses.
 */
final class Json {
  /** The deepest object/array nesting allowed (the top-level object is depth 1). */
  static final int MAX_DEPTH = 32;

  /** A parsed value: Map (insertion-ordered), List, String, Num, Boolean, or NULL. */
  static final Object NULL = new Object() {
    @Override
    public String toString() {
      return "null";
    }
  };

  /** A number, kept as its source token. */
  record Num(String token) {}

  static final class JsonException extends Exception {
    private static final long serialVersionUID = 1L;

    JsonException(String msg) {
      super(msg);
    }
  }

  private final String text;
  private int i;

  private Json(String text) {
    this.text = text;
  }

  /** Parses text as exactly one JSON object; see {@link #parseValue}. */
  @SuppressWarnings("unchecked")
  static Map<String, Object> parseObject(String text) throws JsonException {
    Object v = parseValue(text);
    if (!(v instanceof Map)) throw new JsonException("expected a JSON object");
    return (Map<String, Object>) v;
  }

  /**
   * Parses text as exactly one JSON value with nothing but JSON whitespace
   * around it: no duplicate keys in any object, nesting at most MAX_DEPTH,
   * no unpaired surrogate escapes, no control characters in strings.
   */
  static Object parseValue(String text) throws JsonException {
    Json p = new Json(text);
    Object v = p.value(1);
    p.ws();
    if (p.i != text.length()) throw p.fail("trailing data after the value");
    return v;
  }

  private JsonException fail(String msg) {
    return new JsonException(msg + " at offset " + i);
  }

  private char at(int k) {
    return k < text.length() ? text.charAt(k) : '\0';
  }

  private boolean more() {
    return i < text.length();
  }

  private void ws() {
    while (more()) {
      char c = text.charAt(i);
      if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
      i++;
    }
  }

  private int hex4(int k) throws JsonException {
    if (k + 4 > text.length()) throw fail("bad \\u escape");
    int u = 0;
    for (int j = k; j < k + 4; j++) {
      char c = text.charAt(j); // ASCII hex only: Character.digit takes other scripts' digits
      int d = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
      if (d < 0) throw fail("bad \\u escape");
      u = u * 16 + d;
    }
    return u;
  }

  private String str() throws JsonException {
    i++; // the opening quote
    StringBuilder out = new StringBuilder();
    for (;;) {
      if (!more()) throw fail("unterminated string");
      char c = text.charAt(i);
      if (c == '"') {
        i++;
        return out.toString();
      }
      if (c < 0x20) throw fail("control character in string");
      if (c != '\\') {
        // An unpaired surrogate can only come from a Java String built in memory:
        // decoded UTF-8 never has one. Refuse it like an unpaired escape.
        if (Character.isHighSurrogate(c)) {
          if (!Character.isLowSurrogate(at(i + 1))) throw fail("unpaired surrogate");
          out.append(c).append(text.charAt(i + 1));
          i += 2;
          continue;
        }
        if (Character.isLowSurrogate(c)) throw fail("unpaired surrogate");
        out.append(c);
        i++;
        continue;
      }
      char e = at(i + 1);
      i += 2;
      switch (e) {
        case '"' -> out.append('"');
        case '\\' -> out.append('\\');
        case '/' -> out.append('/');
        case 'b' -> out.append('\b');
        case 'f' -> out.append('\f');
        case 'n' -> out.append('\n');
        case 'r' -> out.append('\r');
        case 't' -> out.append('\t');
        case 'u' -> {
          int u = hex4(i);
          i += 4;
          if (u >= 0xdc00 && u <= 0xdfff) throw fail("unpaired surrogate escape");
          if (u >= 0xd800 && u <= 0xdbff) {
            if (at(i) != '\\' || at(i + 1) != 'u') throw fail("unpaired surrogate escape");
            int lo = hex4(i + 2);
            if (lo < 0xdc00 || lo > 0xdfff) throw fail("unpaired surrogate escape");
            i += 6;
            out.append((char) u).append((char) lo);
          } else {
            out.append((char) u);
          }
        }
        default -> throw fail("bad escape");
      }
    }
  }

  private Object value(int depth) throws JsonException {
    ws();
    char c = at(i);
    if (!more()) throw fail("unexpected end");
    if (c == '{' || c == '[') {
      if (depth > MAX_DEPTH) throw fail("nesting deeper than " + MAX_DEPTH);
      i++;
      ws();
      return c == '{' ? object(depth) : array(depth);
    }
    if (c == '"') return str();
    if (text.startsWith("true", i)) {
      i += 4;
      return Boolean.TRUE;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return Boolean.FALSE;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return NULL;
    }
    return number();
  }

  private Map<String, Object> object(int depth) throws JsonException {
    Map<String, Object> entries = new LinkedHashMap<>();
    if (at(i) == '}') {
      i++;
      return Collections.unmodifiableMap(entries);
    }
    for (;;) {
      ws();
      if (!more() || at(i) != '"') throw fail("expected a key");
      String k = str();
      if (entries.containsKey(k)) throw fail("duplicate key");
      ws();
      if (!more() || at(i) != ':') throw fail("expected :");
      i++;
      entries.put(k, value(depth + 1));
      ws();
      if (more() && at(i) == ',') {
        i++;
        continue;
      }
      if (more() && at(i) == '}') {
        i++;
        return Collections.unmodifiableMap(entries);
      }
      throw fail("expected , or }");
    }
  }

  private List<Object> array(int depth) throws JsonException {
    List<Object> items = new ArrayList<>();
    if (at(i) == ']') {
      i++;
      return Collections.unmodifiableList(items);
    }
    for (;;) {
      items.add(value(depth + 1));
      ws();
      if (more() && at(i) == ',') {
        i++;
        continue;
      }
      if (more() && at(i) == ']') {
        i++;
        return Collections.unmodifiableList(items);
      }
      throw fail("expected , or ]");
    }
  }

  /** -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? */
  private Num number() throws JsonException {
    int start = i;
    if (at(i) == '-') i++;
    if (at(i) == '0' && more()) {
      i++;
    } else if (digit(at(i)) && more()) {
      while (more() && digit(at(i))) i++;
    } else {
      throw fail("unexpected character");
    }
    if (more() && at(i) == '.') {
      i++;
      if (!more() || !digit(at(i))) throw fail("bad number");
      while (more() && digit(at(i))) i++;
    }
    if (more() && (at(i) == 'e' || at(i) == 'E')) {
      i++;
      if (more() && (at(i) == '+' || at(i) == '-')) i++;
      if (!more() || !digit(at(i))) throw fail("bad number");
      while (more() && digit(at(i))) i++;
    }
    return new Num(text.substring(start, i));
  }

  private static boolean digit(char c) {
    return c >= '0' && c <= '9';
  }
}
