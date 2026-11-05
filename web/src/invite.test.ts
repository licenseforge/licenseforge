import { afterEach, expect, it } from "vitest";
import { forgetInviteToken, inviteWaiting, takeInviteToken } from "./invite";

afterEach(() => forgetInviteToken());

it("reads the token from the fragment and keeps it for the sign-in round trip", () => {
  expect(takeInviteToken("token=abc%2Fdef")).toBe("abc/def");
  expect(inviteWaiting()).toBe(true);
  expect(takeInviteToken("")).toBe("abc/def"); // after sign-in, the fragment is gone
  forgetInviteToken();
  expect(inviteWaiting()).toBe(false);
  expect(takeInviteToken("")).toBeNull();
});

it("accepts a leading # and other fragment parameters", () => {
  expect(takeInviteToken("#x=1&token=t1")).toBe("t1");
});

it("returns null for a malformed fragment, keeping nothing", () => {
  expect(takeInviteToken("token=%E0%A4%A")).toBeNull();
  expect(inviteWaiting()).toBe(false);
});
