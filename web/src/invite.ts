// The invite link carries its token in the URL fragment (#token=…), which
// browsers never send to a server, so it stays out of access logs and
// Referer headers. It is read here (the page then removes it from the
// address bar through the router) and kept in this tab's sessionStorage only
// until it is used, so it survives the sign-in round trip (whose callback
// always returns to /).
const key = "lf-invite";

/**
 * The invite token from hash (the fragment without "#"), else the one kept
 * across sign-in. A malformed fragment gives null.
 */
export function takeInviteToken(hash: string): string | null {
  const m = /^(?:.*&)?token=([^&]+)/.exec(hash.replace(/^#/, ""));
  if (m?.[1]) {
    let token: string;
    try {
      token = decodeURIComponent(m[1]);
    } catch {
      return null; // a broken link, e.g. a cut-off escape
    }
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
