import { describe, expect, it } from "vitest";
import { buildDecision, decideAction, scoreEvents } from "./decide";
import type { GamePolicy, SessionRecord } from "./types";

const policy: GamePolicy = {
  game_id: "demo",
  observe_only_default: true,
  kick_threshold: 70,
  ban_threshold: 90,
  require_evidence_window: true,
  known_bad_hashes: [],
  updated_at: 0,
};

describe("scoreEvents", () => {
  it("computes peak and average", () => {
    const scored = scoreEvents([
      {
        level: "HIGH",
        category: "INJECTION",
        details: "x",
        pid: 1,
        risk_score: 80,
      },
      {
        level: "MEDIUM",
        category: "MODULE",
        details: "y",
        pid: 1,
        risk_score: 40,
      },
    ]);

    expect(scored.peak).toBe(80);
    expect(scored.average).toBe(60);
    expect(scored.categories).toEqual(["INJECTION", "MODULE"]);
  });
});

describe("decideAction", () => {
  it("bans on peak threshold", () => {
    expect(decideAction(95, 40, policy, ["MODULE"]).action).toBe("ban");
  });

  it("kicks on sustained threshold", () => {
    expect(decideAction(75, 55, policy, ["HANDLE"]).action).toBe("kick");
  });

  it("challenges multi-critical medium risk", () => {
    expect(
      decideAction(60, 40, policy, ["INJECTION", "INLINE_HOOK"]).action
    ).toBe("challenge");
  });

  it("observes below thresholds", () => {
    expect(decideAction(30, 20, policy, ["OVERLAY"]).action).toBe("observe");
  });
});

describe("buildDecision", () => {
  it("rolls session peak forward", () => {
    const session: SessionRecord = {
      session_id: "s1",
      game_id: "demo",
      player_id: "p1",
      client_version: "1.0",
      machine_fingerprint: "",
      target_process: "game.exe",
      created_at: 1,
      last_seen_at: 1,
      peak_risk: 88,
      finding_count: 2,
    };

    const decision = buildDecision(
      session,
      [
        {
          level: "HIGH",
          category: "HOOK",
          details: "iat",
          pid: 9,
          risk_score: 50,
        },
      ],
      policy
    );

    expect(decision.peak_risk).toBe(88);
    expect(decision.finding_count).toBe(3);
    expect(decision.action).toBe("kick");
  });
});
