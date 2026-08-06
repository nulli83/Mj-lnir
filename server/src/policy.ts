import type { Env, GamePolicy } from "./types";

export function defaultPolicy(gameId: string, env: Env): GamePolicy {
  return {
    game_id: gameId,
    observe_only_default: true,
    kick_threshold: Number(env.DEFAULT_KICK_THRESHOLD || 70),
    ban_threshold: Number(env.DEFAULT_BAN_THRESHOLD || 90),
    require_evidence_window: true,
    known_bad_hashes: [],
    updated_at: Date.now(),
  };
}

export async function loadPolicy(
  env: Env,
  gameId: string
): Promise<GamePolicy> {
  const raw = await env.MJOLNIR_KV.get(`policy:${gameId}`);
  if (!raw) {
    return defaultPolicy(gameId, env);
  }

  try {
    return { ...defaultPolicy(gameId, env), ...JSON.parse(raw) };
  } catch {
    return defaultPolicy(gameId, env);
  }
}

export async function savePolicy(
  env: Env,
  policy: GamePolicy
): Promise<void> {
  policy.updated_at = Date.now();
  await env.MJOLNIR_KV.put(
    `policy:${policy.game_id}`,
    JSON.stringify(policy)
  );
}
