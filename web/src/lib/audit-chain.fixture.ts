// Test vectors for the audit chain check, from the server's audit.Hash (internal/audit).
// Vectors from the server's audit.Hash (internal/audit), not from this code.
export const ZERO = "0".repeat(64);
export const H1 = "80eb4bb09a6fcc47a920048909d9ce291140f66c23817980b577d5d9dd632f57";
export const H2 = "22a81332267713fa765caf9ba6e320800f4a9572ac78348a8d44a4703828a9d3";
// An escape (backslash u00e9) and escaped quotes, built from char codes so no tool rewrites them: the hash
// covers them as sent, and re-serializing would change them.
export const BS = String.fromCharCode(92);
export const D1 = `{"note":"<a&b> ü ${BS}u00e9 ${BS}"q${BS}"","i":1,"nested":{"x":[1,2]}}`;
export const first = {
  id: "aud_aaaaaaaaaaaaaaaaaaaaaaaaaa", tenant_id: "tnt_bbbbbbbbbbbbbbbbbbbbbbbbbb", seq: 1, occurred_at: "2026-11-05T05:23:00.120000Z",
  actor_type: "user" as const, actor_id: "usr_cccccccccccccccccccccccccc", action: "license.issue",
  object_type: "license", object_id: "lic_dddddddddddddddddddddddddd", outcome: "success" as const,
  source_ip: "203.0.113.7", user_agent: 'Mozilla/5.0 "quoted"', details: JSON.parse(D1) as Record<string, unknown>, prev_hash: ZERO, hash: H1,
};
export const second = {
  id: "aud_eeeeeeeeeeeeeeeeeeeeeeeeee", tenant_id: first.tenant_id, seq: 2, occurred_at: "2026-11-05T05:23:01.120000Z",
  actor_type: "system" as const, actor_id: null, action: "audit.prune", object_type: null, object_id: null, outcome: "failure" as const,
  source_ip: null, user_agent: null, details: {}, prev_hash: H1, hash: H2,
};

