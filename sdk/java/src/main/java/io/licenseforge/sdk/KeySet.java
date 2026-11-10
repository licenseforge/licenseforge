package io.licenseforge.sdk;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * The trusted key set's JSON form (spec/license-format.md): what the dashboard
 * shows under Settings → Signing keys, and the vectors' "keys".
 */
public final class KeySet {
  private KeySet() {}

  private static final Pattern KID = Pattern.compile("[A-Za-z0-9_:-]{1,128}");

  /** {@link #parse(String)} on UTF-8 bytes (no BOM). */
  public static List<PublicKey> parse(byte[] json) throws LicenseException {
    try {
      return parse(utf8(json));
    } catch (CharacterCodingException e) {
      throw new LicenseException(LicenseException.Code.INVALID_KEY_SET, "not valid UTF-8");
    }
  }

  /**
   * Reads a trusted key set: a non-empty JSON array of objects with exactly
   * "kid", "alg" and "public_key" (case-sensitive, none repeated), string
   * values, kid matching the spec's pattern, public_key canonical base64url.
   * Anything else is INVALID_KEY_SET. As the spec says, keys load as given:
   * an unknown or empty alg, a duplicate kid, a wrong key length or a weak key
   * surface in verify. Messages never echo the file.
   */
  public static List<PublicKey> parse(String json) throws LicenseException {
    Object top;
    try {
      top = Json.parseValue(json); // a BOM isn't JSON whitespace; unpaired surrogates are refused
    } catch (Json.JsonException e) {
      throw bad("not well-formed JSON (or a repeated field)");
    }
    if (!(top instanceof List<?> items)) throw bad("not a JSON array");
    if (items.isEmpty()) throw bad("no keys");
    List<PublicKey> keys = new ArrayList<>(items.size());
    for (int i = 0; i < items.size(); i++) {
      if (!(items.get(i) instanceof Map<?, ?> m)) throw bad("key " + i + ": not an object");
      if (m.size() != 3) throw bad("key " + i + " needs exactly kid, alg and public_key");
      String kid = field(m, "kid", i);
      String alg = field(m, "alg", i);
      String pub = field(m, "public_key", i);
      if (!KID.matcher(kid).matches()) throw bad("key " + i + ": kid isn't 1-128 of [A-Za-z0-9_:-]");
      byte[] key = LicenseFile.b64url(pub);
      if (key == null) throw bad("key " + i + ": public_key isn't canonical base64url without padding");
      keys.add(new PublicKey(kid, alg, key));
    }
    return List.copyOf(keys);
  }

  private static String field(Map<?, ?> m, String name, int i) throws LicenseException {
    Object v = m.get(name);
    if (v == null) throw bad("key " + i + " needs exactly kid, alg and public_key");
    if (!(v instanceof String s)) throw bad("key " + i + ": " + name + " must be a string");
    return s;
  }

  private static LicenseException bad(String msg) {
    return new LicenseException(LicenseException.Code.INVALID_KEY_SET, msg);
  }

  /** Strict UTF-8: invalid bytes are an error; a BOM stays (and is then refused as JSON). */
  static String utf8(byte[] b) throws CharacterCodingException {
    return StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(b))
        .toString();
  }
}
