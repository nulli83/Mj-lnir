use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DecisionAction {
    Observe,
    Kick,
    Ban,
    Challenge,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingEvent {
    #[serde(default)]
    pub v: u32,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub n: u64,
    pub level: String,
    pub category: String,
    pub details: String,
    pub pid: u32,
    #[serde(default)]
    pub risk_score: i32,
    #[serde(default)]
    pub mac: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SessionStartRequest {
    pub game_id: String,
    pub player_id: String,
    #[serde(default)]
    pub client_version: Option<String>,
    #[serde(default)]
    pub machine_fingerprint: Option<String>,
    #[serde(default)]
    pub target_process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub game_id: String,
    pub player_id: String,
    pub client_version: String,
    pub machine_fingerprint: String,
    pub target_process: String,
    pub created_at: i64,
    pub last_seen_at: i64,
    pub peak_risk: i32,
    pub finding_count: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IngestRequest {
    pub session_id: String,
    pub game_id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub player_id: Option<String>,
    pub events: Vec<FindingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub session_id: String,
    pub game_id: String,
    pub player_id: String,
    pub action: DecisionAction,
    pub reason: String,
    pub peak_risk: i32,
    pub average_risk: i32,
    pub finding_count: u64,
    pub decided_at: i64,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GamePolicy {
    pub game_id: String,
    pub observe_only_default: bool,
    pub kick_threshold: i32,
    pub ban_threshold: i32,
    pub require_evidence_window: bool,
    pub known_bad_hashes: Vec<String>,
    #[serde(default)]
    pub webhook_url: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StudioWebhookPayload {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub decision: DecisionRecord,
}
