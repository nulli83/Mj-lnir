import { json, jsonError, requireIngestAuth, requireStudioAuth } from "./auth";
import { buildDecision } from "./decide";
import { defaultPolicy, loadPolicy, savePolicy } from "./policy";
import type {
  DecisionRecord,
  Env,
  GamePolicy,
  IngestRequest,
  SessionRecord,
  SessionStartRequest,
  StudioWebhookPayload,
} from "./types";

function corsHeaders(request: Request): HeadersInit {
  const origin = request.headers.get("origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
  };
}

function withCors(response: Response, request: Request): Response {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(request))) {
    headers.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

async function readJson<T>(request: Request): Promise<T | null> {
  try {
    return (await request.json()) as T;
  } catch {
    return null;
  }
}

async function maybeWebhook(
  env: Env,
  policy: GamePolicy,
  decision: DecisionRecord,
  ctx: ExecutionContext
): Promise<void> {
  if (!policy.webhook_url || decision.action === "observe") {
    return;
  }

  const payload: StudioWebhookPayload = {
    type: "decision",
    decision,
  };

  ctx.waitUntil(
    fetch(policy.webhook_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    }).catch(() => undefined)
  );
}

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    if (request.method === "OPTIONS") {
      return withCors(new Response(null, { status: 204 }), request);
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";

    try {
      if (request.method === "GET" && path === "/health") {
        return withCors(
          json({
            ok: true,
            service: "mjolnir-server",
            environment: env.ENVIRONMENT,
          }),
          request
        );
      }

      if (request.method === "POST" && path === "/v1/sessions") {
        const authError = await requireIngestAuth(request, env);
        if (authError) {
          return withCors(authError, request);
        }

        const body = await readJson<SessionStartRequest>(request);
        if (!body?.game_id || !body?.player_id) {
          return withCors(
            jsonError(400, "game_id and player_id are required"),
            request
          );
        }

        const now = Date.now();
        const session: SessionRecord = {
          session_id: crypto.randomUUID(),
          game_id: body.game_id,
          player_id: body.player_id,
          client_version: body.client_version || "unknown",
          machine_fingerprint: body.machine_fingerprint || "",
          target_process: body.target_process || "",
          created_at: now,
          last_seen_at: now,
          peak_risk: 0,
          finding_count: 0,
        };

        await env.MJOLNIR_KV.put(
          `session:${session.session_id}`,
          JSON.stringify(session),
          { expirationTtl: 60 * 60 * 24 }
        );

        const policy = await loadPolicy(env, session.game_id);

        return withCors(
          json({
            ok: true,
            session_id: session.session_id,
            policy: {
              observe_only_default: policy.observe_only_default,
              kick_threshold: policy.kick_threshold,
              ban_threshold: policy.ban_threshold,
              require_evidence_window: policy.require_evidence_window,
              known_bad_hashes: policy.known_bad_hashes,
            },
          }),
          request
        );
      }

      if (request.method === "POST" && path === "/v1/ingest") {
        const authError = await requireIngestAuth(request, env);
        if (authError) {
          return withCors(authError, request);
        }

        const body = await readJson<IngestRequest>(request);
        if (
          !body?.session_id ||
          !body?.game_id ||
          !Array.isArray(body.events)
        ) {
          return withCors(
            jsonError(400, "session_id, game_id, and events[] are required"),
            request
          );
        }

        if (body.events.length > 200) {
          return withCors(
            jsonError(413, "events batch too large (max 200)"),
            request
          );
        }

        const sessionRaw = await env.MJOLNIR_KV.get(
          `session:${body.session_id}`
        );
        if (!sessionRaw) {
          return withCors(jsonError(404, "unknown session_id"), request);
        }

        const session = JSON.parse(sessionRaw) as SessionRecord;
        if (session.game_id !== body.game_id) {
          return withCors(jsonError(403, "session/game mismatch"), request);
        }

        const policy = await loadPolicy(env, body.game_id);
        const decision = buildDecision(session, body.events, policy);

        session.last_seen_at = Date.now();
        session.peak_risk = decision.peak_risk;
        session.finding_count = decision.finding_count;

        await env.MJOLNIR_KV.put(
          `session:${session.session_id}`,
          JSON.stringify(session),
          { expirationTtl: 60 * 60 * 24 }
        );

        await env.MJOLNIR_KV.put(
          `decision:${session.session_id}`,
          JSON.stringify(decision),
          { expirationTtl: 60 * 60 * 24 * 7 }
        );

        // Keep a short recent evidence trail for studio review.
        await env.MJOLNIR_KV.put(
          `evidence:${session.session_id}:${decision.decided_at}`,
          JSON.stringify({
            session_id: session.session_id,
            received_at: decision.decided_at,
            events: body.events.slice(0, 50),
          }),
          { expirationTtl: 60 * 60 * 24 * 3 }
        );

        await maybeWebhook(env, policy, decision, ctx);

        return withCors(
          json({
            ok: true,
            decision,
          }),
          request
        );
      }

      if (request.method === "GET" && path.startsWith("/v1/decisions/")) {
        const authError = await requireStudioAuth(request, env);
        if (authError) {
          return withCors(authError, request);
        }

        const sessionId = path.slice("/v1/decisions/".length);
        if (!sessionId) {
          return withCors(jsonError(400, "session_id required"), request);
        }

        const raw = await env.MJOLNIR_KV.get(`decision:${sessionId}`);
        if (!raw) {
          return withCors(jsonError(404, "no decision yet"), request);
        }

        return withCors(
          json({
            ok: true,
            decision: JSON.parse(raw) as DecisionRecord,
          }),
          request
        );
      }

      if (request.method === "GET" && path.startsWith("/v1/policy/")) {
        const authError = await requireStudioAuth(request, env);
        if (authError) {
          return withCors(authError, request);
        }

        const gameId = decodeURIComponent(path.slice("/v1/policy/".length));
        if (!gameId) {
          return withCors(jsonError(400, "game_id required"), request);
        }

        const policy = await loadPolicy(env, gameId);
        return withCors(json({ ok: true, policy }), request);
      }

      if (request.method === "PUT" && path.startsWith("/v1/policy/")) {
        const authError = await requireStudioAuth(request, env);
        if (authError) {
          return withCors(authError, request);
        }

        const gameId = decodeURIComponent(path.slice("/v1/policy/".length));
        const body = await readJson<Partial<GamePolicy>>(request);
        if (!gameId || !body) {
          return withCors(jsonError(400, "invalid policy payload"), request);
        }

        const current = await loadPolicy(env, gameId);
        const next: GamePolicy = {
          ...current,
          ...body,
          game_id: gameId,
          kick_threshold: Number(
            body.kick_threshold ?? current.kick_threshold
          ),
          ban_threshold: Number(body.ban_threshold ?? current.ban_threshold),
          known_bad_hashes: Array.isArray(body.known_bad_hashes)
            ? body.known_bad_hashes
            : current.known_bad_hashes,
        };

        if (next.kick_threshold >= next.ban_threshold) {
          return withCors(
            jsonError(400, "kick_threshold must be lower than ban_threshold"),
            request
          );
        }

        await savePolicy(env, next);
        return withCors(json({ ok: true, policy: next }), request);
      }

      if (request.method === "GET" && path === "/v1/games/demo/policy") {
        return withCors(
          json({ ok: true, policy: defaultPolicy("demo", env) }),
          request
        );
      }

      return withCors(jsonError(404, "not found"), request);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "internal server error";
      return withCors(jsonError(500, message), request);
    }
  },
} satisfies ExportedHandler<Env>;
