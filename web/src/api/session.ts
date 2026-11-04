import { queryOptions, type QueryClient } from "@tanstack/react-query";
import { redirect } from "@tanstack/react-router";
import { ApiError, request } from "./client";

// Served by the Go BFF (internal/weblogin), not the public API, so these
// types are written by hand rather than generated.
export type User = { id: string; email: string; name: string };
export type Session = { user: User; csrf_token: string };

/** The signed-in session, or null when there is none (401). */
export async function getSession(): Promise<Session | null> {
  try {
    return (await (await request("/auth/session")).json()) as Session;
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return null;
    throw e;
  }
}

export const sessionQuery = queryOptions({ queryKey: ["session"], queryFn: getSession, staleTime: 60_000 });

/** For a route's beforeLoad: the session, or a redirect to /login. */
export async function requireSession(qc: QueryClient): Promise<Session> {
  const s = await qc.ensureQueryData(sessionQuery);
  if (!s) throw redirect({ to: "/login" });
  return s;
}

/** Ends the session. A 401 means it already ended, which is fine. */
export async function logout(csrfToken: string): Promise<void> {
  try {
    await request("/auth/logout", { method: "POST", headers: { "X-CSRF-Token": csrfToken } });
  } catch (e) {
    if (e instanceof ApiError && e.status === 401) return;
    throw e;
  }
}
