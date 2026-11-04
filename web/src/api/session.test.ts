import { QueryClient } from "@tanstack/react-query";
import { isRedirect } from "@tanstack/react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { getAuthConfig, getSession, loginHref, logout, requireSession } from "./session";

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

describe("getAuthConfig", () => {
  it("loads the banner", async () => {
    const cfg = { banner: "Authorized use only.", banner_id: "abc" };
    serve(200, cfg);
    expect(await getAuthConfig()).toEqual(cfg);
  });
  it("is no banner when login is off (404)", async () => {
    serve(404);
    expect(await getAuthConfig()).toEqual({ banner: "", banner_id: "" });
  });
  it("throws on other errors, so the gate stays shut", async () => {
    serve(500);
    await expect(getAuthConfig()).rejects.toMatchObject({ status: 500 });
  });
});

describe("loginHref (banner gate)", () => {
  const withBanner = { banner: "Authorized use only.", banner_id: "a/b+c" };
  it("is disabled until the config loaded", () => {
    expect(loginHref(undefined, true)).toBeNull();
  });
  it("needs agreement when there is a banner", () => {
    expect(loginHref(withBanner, false)).toBeNull();
    expect(loginHref(withBanner, true)).toBe("/auth/login?banner=a%2Fb%2Bc");
  });
  it("goes straight to login without a banner", () => {
    expect(loginHref({ banner: "", banner_id: "" }, false)).toBe("/auth/login");
  });
});
