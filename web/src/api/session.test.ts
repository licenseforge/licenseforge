import { QueryClient } from "@tanstack/react-query";
import { isRedirect } from "@tanstack/react-router";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError } from "./client";
import { getSession, logout, requireSession } from "./session";

const session = { user: { id: "usr_1", email: "a@example.com", name: "Ada" }, csrf_token: "tok" };

function serve(status: number, body: unknown = {}) {
  const f = vi.fn(async () => new Response(status === 204 ? null : JSON.stringify(body), { status }));
  vi.stubGlobal("fetch", f);
  return f;
}

afterEach(() => vi.unstubAllGlobals());

describe("getSession", () => {
  it("loads the session with same-origin cookies", async () => {
    const f = serve(200, session);
    expect(await getSession()).toEqual(session);
    expect(f).toHaveBeenCalledWith("/auth/session", expect.objectContaining({ credentials: "same-origin" }));
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
  it("posts with the CSRF token and same-origin cookies", async () => {
    const f = serve(204);
    await logout("tok");
    expect(f).toHaveBeenCalledWith(
      "/auth/logout",
      expect.objectContaining({ method: "POST", credentials: "same-origin", headers: { "X-CSRF-Token": "tok" } }),
    );
  });
  it("treats 401 as already logged out", async () => {
    serve(401);
    await expect(logout("tok")).resolves.toBeUndefined();
  });
  it("throws on other errors", async () => {
    serve(403);
    await expect(logout("tok")).rejects.toMatchObject({ status: 403 });
  });
});
