// The invite link carries its token in the URL fragment (#token=…), which
// browsers never send to a server, so it stays out of access logs and
// Referer headers. It is read here, removed from the address bar, and kept
// in this tab's sessionStorage only until it is used, so it survives the
// sign-in round trip (whose callback always returns to /).
const key = "lf-invite";

/** The invite token from the fragment (then removed from the URL), else the one kept across sign-in. */
export function takeInviteToken(): string | null {
  const m = /^#(?:.*&)?token=([^&]+)/.exec(window.location.hash);
  if (m?.[1]) {
    const token = decodeURIComponent(m[1]);
    window.history.replaceState(null, "", window.location.pathname);
    try {
      sessionStorage.setItem(key, token);
    } catch {
      // not kept: the user signs in and opens the link again
    }
    return token;
  }
  try {
    return sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

export function forgetInviteToken() {
  try {
    sessionStorage.removeItem(key);
  } catch {
    // nothing kept
  }
}

/** Whether a sign-in interrupted an invitation (the index route sends the user back to it). */
export function inviteWaiting(): boolean {
  try {
    return sessionStorage.getItem(key) !== null;
  } catch {
    return false;
  }
}
