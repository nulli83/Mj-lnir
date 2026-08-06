export interface Env {
  MJOLNIR_KV: KVNamespace;
  ENVIRONMENT: string;
  DEFAULT_KICK_THRESHOLD: string;
  DEFAULT_BAN_THRESHOLD: string;
  /** Client ingest key — set via `wrangler secret put INGEST_API_KEY` */
  INGEST_API_KEY?: string;
  /** Studio / game-server key — set via `wrangler secret put STUDIO_API_KEY` */
  STUDIO_API_KEY?: string;
}

export type DecisionAction = "observe" | "kick" | "ban" | "challenge";

export interface FindingEvent {
  v?: number;
  ts?: number;
  n?: number;
  level: string;
  category: string;
  details: string;
  pid: number;
  risk_score: number;
  mac?: string;
}

export interface SessionStartRequest {
  game_id: string;
  player_id: string;
  client_version?: string;
  machine_fingerprint?: string;
  target_process?: string;
}

export interface SessionRecord {
  session_id: string;
  game_id: string;
  player_id: string;
  client_version: string;
  machine_fingerprint: string;
  target_process: string;
  created_at: number;
  last_seen_at: number;
  peak_risk: number;
  finding_count: number;
}

export interface IngestRequest {
  session_id: string;
  game_id: string;
  player_id?: string;
  events: FindingEvent[];
}

export interface DecisionRecord {
  session_id: string;
  game_id: string;
  player_id: string;
  action: DecisionAction;
  reason: string;
  peak_risk: number;
  average_risk: number;
  finding_count: number;
  decided_at: number;
  categories: string[];
}

export interface GamePolicy {
  game_id: string;
  observe_only_default: boolean;
  kick_threshold: number;
  ban_threshold: number;
  require_evidence_window: boolean;
  known_bad_hashes: string[];
  webhook_url?: string;
  updated_at: number;
}

export interface StudioWebhookPayload {
  type: "decision";
  decision: DecisionRecord;
}
