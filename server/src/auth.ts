import type { Env } from "./types";

function encoder() {
  return new TextEncoder();
}

export async function timingSafeEqualString(
  left: string,
  right: string
): Promise<boolean> {
  const leftBytes = encoder().encode(left);
  const rightBytes = encoder().encode(right);

  if (leftBytes.byteLength !== rightBytes.byteLength) {
    return false;
  }

  return crypto.subtle.timingSafeEqual(leftBytes, rightBytes);
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) {
    return null;
  }

  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1]?.trim() || null;
}

export async function requireIngestAuth(
  request: Request,
  env: Env
): Promise<Response | null> {
  const expected = env.INGEST_API_KEY;
  if (!expected) {
    // Local/dev convenience: allow when secret is unset.
    if (env.ENVIRONMENT === "development") {
      return null;
    }

    return jsonError(503, "INGEST_API_KEY is not configured");
  }

  const provided = bearerToken(request);
  if (!provided || !(await timingSafeEqualString(provided, expected))) {
    return jsonError(401, "Invalid ingest credentials");
  }

  return null;
}

export async function requireStudioAuth(
  request: Request,
  env: Env
): Promise<Response | null> {
  const expected = env.STUDIO_API_KEY;
  if (!expected) {
    if (env.ENVIRONMENT === "development") {
      return null;
    }

    return jsonError(503, "STUDIO_API_KEY is not configured");
  }

  const provided = bearerToken(request);
  if (!provided || !(await timingSafeEqualString(provided, expected))) {
    return jsonError(401, "Invalid studio credentials");
  }

  return null;
}

export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

export function jsonError(status: number, error: string): Response {
  return json({ ok: false, error }, status);
}
