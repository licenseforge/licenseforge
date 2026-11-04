import { QueryClient } from "@tanstack/react-query";
import { isRedirect } from "@tanstack/react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { getSession, logout, requireSession } from "./session";

const session = { user: { id: "usr_1", email: "a@example.com", name: "Ada" }, csrf_token: "tok" };

function serve(status: number, body: unknown = {}) {
  const f = vi.fn<(req: Request) => Promise<Response>>(async () => new Response(status === 204 ? null : JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", f);
  return f;
}

const sent = (f: ReturnType<typeof serve>) => f.mock.calls[0]![0];

afterEach(() => vi.unstubAllGlobals());

describe("getSession", () => {
  it("loads the session with same-origin cookies", async () => {
    const f = serve(200, session);
    expect(await getSession()).toEqual(session);
    expect(sent(f).url).toBe(`${window.location.origin}/auth/session`);
    expect(sent(f).credentials).toBe("same-origin");
  });
  it("is null without a session", async () => {
    serve(401);
    expect(await getSession()).toBeNull();
  });
  it("throws on other errors", async () => {
    serve(500);
    await expect(getSession()).rejects.toBeInstanceOf(ApiError);
  });
});

describe("requireSession", () => {
  it("redirects to /login on 401", async () => {
    serve(401);
    const err = await requireSession(new QueryClient()).catch((e: unknown) => e);
    expect(isRedirect(err)).toBe(true);
    expect((err as { options: { to: string } }).options.to).toBe("/login");
  });
  it("returns the session", async () => {
    serve(200, session);
    expect(await requireSession(new QueryClient())).toEqual(session);
  });
});

describe("logout", () => {
  it("posts with the session's CSRF token and same-origin cookies", async () => {
    serve(200, session);
    await getSession(); // remembers the token
    const f = serve(204);
    await logout();
    expect(sent(f).method).toBe("POST");
    expect(sent(f).credentials).toBe("same-origin");
    expect(sent(f).headers.get("X-CSRF-Token")).toBe("tok");
  });
  it("treats 401 as already logged out", async () => {
    serve(401);
    await expect(logout()).resolves.toBeUndefined();
  });
  it("throws on other errors", async () => {
    serve(403);
    await expect(logout()).rejects.toMatchObject({ status: 403 });
  });
});
