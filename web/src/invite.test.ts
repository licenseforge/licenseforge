import { afterEach, expect, it } from "vitest";
import { forgetInviteToken, inviteWaiting, takeInviteToken } from "./invite";

afterEach(() => {
  forgetInviteToken();
  window.history.replaceState(null, "", "/");
});

it("reads the token from the fragment and removes it from the address bar", () => {
  window.history.replaceState(null, "", "/invite#token=abc%2Fdef");
  expect(takeInviteToken()).toBe("abc/def");
  expect(window.location.hash).toBe("");
  expect(window.location.href).not.toContain("abc");
  // kept for the sign-in round trip, until used
  expect(inviteWaiting()).toBe(true);
  expect(takeInviteToken()).toBe("abc/def");
  forgetInviteToken();
  expect(inviteWaiting()).toBe(false);
  expect(takeInviteToken()).toBeNull();
});

it("never reads a token from the query string", () => {
  window.history.replaceState(null, "", "/invite?token=leaky");
  expect(takeInviteToken()).toBeNull();
  expect(inviteWaiting()).toBe(false);
});
