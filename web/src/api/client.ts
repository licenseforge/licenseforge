// The one place the dashboard talks HTTP. A client generated from
// api/openapi.yaml replaces request() for /api/ calls; it must keep these
// rules: same-origin cookies only, and an ApiError with the status on failure.

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const res = await fetch(path, { ...init, credentials: "same-origin" });
  if (!res.ok) throw new ApiError(res.status, `${init.method ?? "GET"} ${path}: ${res.status}`);
  return res;
}
