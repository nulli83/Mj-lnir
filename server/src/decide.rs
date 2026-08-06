use crate::types::{
    DecisionAction, DecisionRecord, FindingEvent, GamePolicy, SessionRecord,
};

pub struct Score {
    pub peak: i32,
    pub average: i32,
    pub categories: Vec<String>,
}

pub fn score_events(events: &[FindingEvent]) -> Score {
    if events.is_empty() {
        return Score {
            peak: 0,
            average: 0,
            categories: Vec::new(),
        };
    }

    let mut sum = 0i64;
    let mut peak = 0i32;
    let mut categories = Vec::new();

    for event in events {
        let risk = event.risk_score.max(0);
        sum += i64::from(risk);
        peak = peak.max(risk);
        if !event.category.is_empty() && !categories.contains(&event.category) {
            categories.push(event.category.clone());
        }
    }

    categories.sort();

    Score {
        peak,
        average: (sum / events.len() as i64) as i32,
        categories,
    }
}

pub fn action_rank(action: &DecisionAction) -> u8 {
    match action {
        DecisionAction::Observe => 0,
        DecisionAction::Challenge => 1,
        DecisionAction::Kick => 2,
        DecisionAction::Ban => 3,
    }
}

pub fn decide_action(
    peak: i32,
    average: i32,
    policy: &GamePolicy,
    categories: &[String],
) -> (DecisionAction, String) {
    if policy.observe_only_default {
        return (
            DecisionAction::Observe,
            "Policy observe_only_default=true; enforcement suppressed".into(),
        );
    }

    let critical: Vec<&str> = categories
        .iter()
        .map(String::as_str)
        .filter(|category| {
            matches!(
                *category,
                "INJECTION" | "MANUAL_MAP" | "INLINE_HOOK" | "HOOK" | "IMAGE"
            )
        })
        .collect();

    if peak >= policy.ban_threshold {
        return (
            DecisionAction::Ban,
            format!(
                "Peak risk {peak} reached ban threshold {}",
                policy.ban_threshold
            ),
        );
    }

    if peak >= policy.kick_threshold
        && (average >= (policy.kick_threshold as f64 * 0.7).floor() as i32
            || !critical.is_empty())
    {
        return (
            DecisionAction::Kick,
            format!(
                "Peak risk {peak} / avg {average} reached kick threshold {}",
                policy.kick_threshold
            ),
        );
    }

    if critical.len() >= 2 && peak >= 55 {
        return (
            DecisionAction::Challenge,
            format!(
                "Multiple critical vectors ({}) warrant a live challenge",
                critical.join(", ")
            ),
        );
    }

    (
        DecisionAction::Observe,
        "Evidence below enforcement thresholds".into(),
    )
}

pub fn build_decision(
    session: &SessionRecord,
    events: &[FindingEvent],
    policy: &GamePolicy,
    previous: Option<&DecisionRecord>,
) -> DecisionRecord {
    let scored = score_events(events);
    let peak = session.peak_risk.max(scored.peak);
    let (mut action, mut reason) =
        decide_action(peak, scored.average, policy, &scored.categories);

    let mut categories = scored.categories;
    if let Some(previous) = previous {
        if action_rank(&previous.action) > action_rank(&action) {
            action = previous.action.clone();
            reason = format!(
                "Retained stronger prior decision ({:?}): {}",
                previous.action, previous.reason
            );
        }

        for category in &previous.categories {
            if !categories.contains(category) {
                categories.push(category.clone());
            }
        }
        categories.sort();
    }

    DecisionRecord {
        session_id: session.session_id.clone(),
        game_id: session.game_id.clone(),
        player_id: session.player_id.clone(),
        action,
        reason,
        peak_risk: peak,
        average_risk: scored.average.max(previous.map(|p| p.average_risk).unwrap_or(0)),
        finding_count: session.finding_count + events.len() as u64,
        decided_at: chrono::Utc::now().timestamp_millis(),
        categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(observe_only: bool) -> GamePolicy {
        GamePolicy {
            game_id: "demo".into(),
            observe_only_default: observe_only,
            kick_threshold: 70,
            ban_threshold: 90,
            require_evidence_window: true,
            known_bad_hashes: Vec::new(),
            webhook_url: None,
            updated_at: 0,
        }
    }

    fn event(category: &str, risk: i32) -> FindingEvent {
        FindingEvent {
            v: 1,
            ts: 1,
            n: 1,
            level: "HIGH".into(),
            category: category.into(),
            details: "x".into(),
            pid: 1,
            risk_score: risk,
            mac: None,
        }
    }

    #[test]
    fn scores_peak_and_average() {
        let scored = score_events(&[event("INJECTION", 80), event("MODULE", 40)]);
        assert_eq!(scored.peak, 80);
        assert_eq!(scored.average, 60);
        assert_eq!(scored.categories, vec!["INJECTION", "MODULE"]);
    }

    #[test]
    fn bans_on_peak() {
        let (action, _) = decide_action(95, 40, &policy(false), &["MODULE".into()]);
        assert_eq!(action, DecisionAction::Ban);
    }

    #[test]
    fn kicks_on_sustained() {
        let (action, _) = decide_action(75, 55, &policy(false), &["HANDLE".into()]);
        assert_eq!(action, DecisionAction::Kick);
    }

    #[test]
    fn challenges_multi_critical() {
        let (action, _) = decide_action(
            60,
            40,
            &policy(false),
            &["INJECTION".into(), "INLINE_HOOK".into()],
        );
        assert_eq!(action, DecisionAction::Challenge);
    }

    #[test]
    fn observes_below_threshold() {
        let (action, _) = decide_action(30, 20, &policy(false), &["OVERLAY".into()]);
        assert_eq!(action, DecisionAction::Observe);
    }

    #[test]
    fn observe_only_suppresses_enforcement() {
        let (action, _) = decide_action(95, 90, &policy(true), &["INJECTION".into()]);
        assert_eq!(action, DecisionAction::Observe);
    }

    #[test]
    fn retains_stronger_prior_decision() {
        let session = SessionRecord {
            session_id: "s1".into(),
            game_id: "demo".into(),
            player_id: "p1".into(),
            client_version: "1.0".into(),
            machine_fingerprint: String::new(),
            target_process: "game.exe".into(),
            created_at: 1,
            last_seen_at: 1,
            peak_risk: 95,
            finding_count: 2,
        };

        let previous = DecisionRecord {
            session_id: "s1".into(),
            game_id: "demo".into(),
            player_id: "p1".into(),
            action: DecisionAction::Ban,
            reason: "prior ban".into(),
            peak_risk: 95,
            average_risk: 95,
            finding_count: 2,
            decided_at: 1,
            categories: vec!["INJECTION".into()],
        };

        let decision = build_decision(
            &session,
            &[event("OVERLAY", 10)],
            &policy(false),
            Some(&previous),
        );
        assert_eq!(decision.action, DecisionAction::Ban);
        assert_eq!(decision.peak_risk, 95);
    }

    #[test]
    fn rolls_session_peak_forward() {
        let session = SessionRecord {
            session_id: "s1".into(),
            game_id: "demo".into(),
            player_id: "p1".into(),
            client_version: "1.0".into(),
            machine_fingerprint: String::new(),
            target_process: "game.exe".into(),
            created_at: 1,
            last_seen_at: 1,
            peak_risk: 88,
            finding_count: 2,
        };

        let decision = build_decision(&session, &[event("HOOK", 50)], &policy(false), None);
        assert_eq!(decision.peak_risk, 88);
        assert_eq!(decision.finding_count, 3);
        assert_eq!(decision.action, DecisionAction::Kick);
    }
}
