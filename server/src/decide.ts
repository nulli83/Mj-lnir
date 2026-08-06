import type {
  DecisionAction,
  DecisionRecord,
  FindingEvent,
  GamePolicy,
  SessionRecord,
} from "./types";

export function scoreEvents(events: FindingEvent[]): {
  peak: number;
  average: number;
  categories: string[];
} {
  if (events.length === 0) {
    return { peak: 0, average: 0, categories: [] };
  }

  let sum = 0;
  let peak = 0;
  const categories = new Set<string>();

  for (const event of events) {
    const risk = Math.max(0, Number(event.risk_score) || 0);
    sum += risk;
    peak = Math.max(peak, risk);
    if (event.category) {
      categories.add(event.category);
    }
  }

  return {
    peak,
    average: Math.round(sum / events.length),
    categories: [...categories].sort(),
  };
}

export function decideAction(
  peak: number,
  average: number,
  policy: GamePolicy,
  categories: string[]
): { action: DecisionAction; reason: string } {
  const criticalCategories = categories.filter((category) =>
    ["INJECTION", "MANUAL_MAP", "INLINE_HOOK", "HOOK", "IMAGE"].includes(
      category
    )
  );

  if (peak >= policy.ban_threshold) {
    return {
      action: "ban",
      reason: `Peak risk ${peak} reached ban threshold ${policy.ban_threshold}`,
    };
  }

  if (
    peak >= policy.kick_threshold &&
    (average >= Math.floor(policy.kick_threshold * 0.7) ||
      criticalCategories.length > 0)
  ) {
    return {
      action: "kick",
      reason: `Peak risk ${peak} / avg ${average} reached kick threshold ${policy.kick_threshold}`,
    };
  }

  if (criticalCategories.length >= 2 && peak >= 55) {
    return {
      action: "challenge",
      reason: `Multiple critical vectors (${criticalCategories.join(", ")}) warrant a live challenge`,
    };
  }

  return {
    action: "observe",
    reason: "Evidence below enforcement thresholds",
  };
}

export function buildDecision(
  session: SessionRecord,
  events: FindingEvent[],
  policy: GamePolicy
): DecisionRecord {
  const scored = scoreEvents(events);
  const peak = Math.max(session.peak_risk, scored.peak);
  const { action, reason } = decideAction(
    peak,
    scored.average,
    policy,
    scored.categories
  );

  return {
    session_id: session.session_id,
    game_id: session.game_id,
    player_id: session.player_id,
    action,
    reason,
    peak_risk: peak,
    average_risk: scored.average,
    finding_count: session.finding_count + events.length,
    decided_at: Date.now(),
    categories: scored.categories,
  };
}
