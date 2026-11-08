import { afterEach, describe, expect, it, vi } from "vitest";
import { problemMessage } from "@/i18n";
import { ApiError, api, fieldErrors, queryRetry, setCsrfToken } from "./client";
import { assignableTokenRoles, canManageTokens, createToken, revokeToken, tokensQuery } from "./tokens";
import { QueryClient } from "@tanstack/react-query";

function serve(status: number, body: unknown, type = "application/json") {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () =>
    new Response(typeof body === "string" ? body : JSON.stringify(body), { status, headers: { "Content-Type": type } }),
  );
  vi.stubGlobal("fetch", f);
  return f;
}
const sent = (f: ReturnType<typeof serve>) => f.mock.calls[0]![0];

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrfToken("");
});

const created = {
  id: "tok_1", name: "ci", role: "sdk", all_products: true, product_ids: [], display: "lf_live_abc…",
  created_by: "usr_1", created_at: "2026-11-04T00:00:00Z", expires_at: "2027-02-02T00:00:00Z",
  last_used_at: null, revoked_at: null, token: "lf_live_SECRET",
};

describe("generated client wrapper", () => {
  it("sends the CSRF token and same-origin cookies on unsafe calls", async () => {
    setCsrfToken("csrf-1");
    const f = serve(201, created);
    expect((await createToken("acme", { name: "ci", role: "sdk", all_products: true })).token).toBe("lf_live_SECRET");
    const req = sent(f);
    expect(req.method).toBe("POST");
    expect(req.url).toBe(`${window.location.origin}/api/v1/tenants/acme/api-tokens`);
    expect(req.credentials).toBe("same-origin");
    expect(req.headers.get("X-CSRF-Token")).toBe("csrf-1");
  });

  it("never sends the CSRF token to another origin", async () => {
    setCsrfToken("csrf-1");
    const f = serve(201, created);
    await api.POST("/tenants/{tenant}/api-tokens", {
      baseUrl: "https://evil.example/api/v1",
      params: { path: { tenant: "acme" } },
      body: { name: "ci", role: "sdk", all_products: true },
    });
    expect(sent(f).url).toBe("https://evil.example/api/v1/tenants/acme/api-tokens");
    expect(sent(f).headers.has("X-CSRF-Token")).toBe(false);
  });

  it("sends no CSRF token on reads", async () => {
    setCsrfToken("csrf-1");
    const f = serve(200, { items: [], next_cursor: "c2" });
    const page = await new QueryClient().fetchInfiniteQuery(tokensQuery("acme"));
    expect(page.pages[0]?.next_cursor).toBe("c2");
    expect(sent(f).method).toBe("GET");
    expect(sent(f).credentials).toBe("same-origin");
    expect(sent(f).headers.has("X-CSRF-Token")).toBe(false);
  });

  it("parses problems: status, code and field errors by JSON Pointer", async () => {
    serve(
      422,
      {
        type: "about:blank", title: "Unprocessable Entity", status: 422, code: "validation_failed", request_id: "r1",
        errors: [
          { field: "/name", message: "too long" },
          { field: "/product_ids/0", message: "unknown product" },
          { field: "/a~1b~0c", message: "escaped" },
        ],
      },
      "application/problem+json",
    );
    const err = await createToken("acme", { name: "x", role: "sdk", all_products: false }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 422, code: "validation_failed" });
    expect(fieldErrors(err)).toEqual({ name: "too long", product_ids: "unknown product", "a/b~c": "escaped" });
    expect(problemMessage((err as ApiError).code)).toBe("Some fields need fixing.");
  });

  it("treats a non-problem error as unknown", async () => {
    serve(502, "Bad Gateway", "text/plain");
    const err = await revokeToken("acme", "tok_1").catch((e: unknown) => e);
    expect(err).toMatchObject({ status: 502, code: "unknown" });
    expect(fieldErrors(err)).toEqual({});
    expect(problemMessage("no_such_code")).toBe(problemMessage("unknown"));
  });
});

describe("assignableTokenRoles", () => {
  const all = { all: true, products: [] };
  it("offers the caller's role and below, plus sdk", () => {
    expect(assignableTokenRoles({ role: "owner", scope: all })).toEqual(["owner", "admin", "manager", "support", "viewer", "sdk"]);
    expect(assignableTokenRoles({ role: "admin", scope: all })).toEqual(["admin", "manager", "support", "viewer", "sdk"]);
  });
  it("offers nothing to roles without token:write", () => {
    for (const role of ["manager", "support", "viewer", "sdk"] as const) expect(assignableTokenRoles({ role, scope: all })).toEqual([]);
  });
  it("offers nothing to product-scoped members, owners included", () => {
    for (const role of ["owner", "admin"] as const) {
      const m = { role, scope: { all: false, products: ["prd_1"] } };
      expect(assignableTokenRoles(m)).toEqual([]);
      expect(canManageTokens(m)).toBe(false);
    }
  });
});

describe("queryRetry", () => {
  const problem = (status: number, code: string) => new ApiError(status, "x", { type: "about:blank", title: "x", status, code, request_id: "r" });
  it("never retries a client error: a retry can't fix it and would delay the MFA explanation", () => {
    for (const e of [problem(401, "unauthenticated"), problem(403, "mfa_required"), problem(404, "not_found"), problem(422, "validation_failed")]) {
      expect(queryRetry(0, e)).toBe(false);
    }
  });
  it("retries network failures and 5xx up to three times", () => {
    expect([0, 1, 2, 3].map((n) => queryRetry(n, new TypeError("Failed to fetch")))).toEqual([true, true, true, false]);
    expect(queryRetry(0, problem(503, "internal"))).toBe(true);
  });
});
