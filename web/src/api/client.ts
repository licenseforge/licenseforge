// The one place the dashboard talks HTTP (ADR-0020). Every request goes
// through apiFetch: same-origin cookies only, and the session's CSRF token on
// unsafe methods. /api/v1 calls use the client generated from
// api/openapi.yaml (`npm run gen:api` writes schema.ts); /auth/* (the Go BFF,
// not in the spec) uses request().
import createClient from "openapi-fetch";
import type { components, paths } from "./schema";

export type Problem = components["schemas"]["Problem"];

export class ApiError extends Error {
  readonly status: number;
  readonly problem?: Problem;
  constructor(status: number, message: string, problem?: Problem) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }
  /** The problem's stable code (ADR-0032), or "unknown" for a non-problem answer. */
  get code(): string {
    return this.problem?.code ?? "unknown";
  }
}

// In memory only, never in storage; set when the session loads.
let csrfToken = "";
export function setCsrfToken(token: string) {
  csrfToken = token;
}

const safe = new Set(["GET", "HEAD", "OPTIONS"]);

async function apiFetch(input: Request): Promise<Response> {
  const req = new Request(input, { credentials: "same-origin" });
  // Never send the token to another origin.
  if (!safe.has(req.method) && csrfToken && new URL(req.url).origin === window.location.origin) {
    req.headers.set("X-CSRF-Token", csrfToken);
  }
  return fetch(req);
}

/** A /auth/* call: the Response, or an ApiError for a non-2xx status. */
export async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await apiFetch(new Request(new URL(path, window.location.origin), init));
  if (!res.ok) throw new ApiError(res.status, `${init.method ?? "GET"} ${path}: ${res.status}`);
  return res;
}

export const api = createClient<paths>({ baseUrl: `${window.location.origin}/api/v1`, fetch: apiFetch });

function isProblem(v: unknown): v is Problem {
  return typeof v === "object" && v !== null && typeof (v as Problem).code === "string";
}

/** The data of an openapi-fetch result, or an ApiError carrying its problem. */
export function unwrap<T>(r: { data?: T; error?: unknown; response: Response }): T {
  if (r.data === undefined) throw failure(check(r));
  check(r);
  return r.data;
}

/** The Response of a result without a body (204), or an ApiError carrying its problem. */
export function check(r: { error?: unknown; response: Response }): Response {
  if (!r.response.ok) throw failure(r.response, r.error);
  return r.response;
}

function failure(res: Response, error?: unknown): ApiError {
  const p = isProblem(error) ? error : undefined;
  return new ApiError(res.status, `${res.url}: ${p?.code ?? res.status}`, p);
}

/**
 * The problem's field errors by top-level body field: "/product_ids/0"
 * becomes "product_ids" (RFC 6901 pointers, ~1 and ~0 unescaped).
 */
export function fieldErrors(e: unknown): Record<string, string> {
  const out: Record<string, string> = {};
  if (!(e instanceof ApiError)) return out;
  for (const { field, message } of e.problem?.errors ?? []) {
    const key = (field.split("/")[1] ?? "").replace(/~1/g, "/").replace(/~0/g, "~");
    out[key] ??= message;
  }
  return out;
}

/** A session that ended mid-use (expiry, logout elsewhere) goes to sign in. */
export function onAuthError(e: unknown) {
  if (e instanceof ApiError && e.status === 401) window.location.assign("/login");
}
