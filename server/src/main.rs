mod auth;
mod decide;
mod store;
mod types;

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{require_ingest, require_studio};
use crate::decide::build_decision;
use crate::store::Store;
use crate::types::{
    DecisionAction, GamePolicy, IngestRequest, SessionRecord, SessionStartRequest,
    StudioWebhookPayload,
};

pub struct AppState {
    pub store: Store,
    pub ingest_api_key: Option<String>,
    pub studio_api_key: Option<String>,
    pub allow_open_auth: bool,
    pub default_kick_threshold: i32,
    pub default_ban_threshold: i32,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn env_opt(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn default_policy(state: &AppState, game_id: &str) -> GamePolicy {
    GamePolicy {
        game_id: game_id.to_string(),
        observe_only_default: true,
        kick_threshold: state.default_kick_threshold,
        ban_threshold: state.default_ban_threshold,
        require_evidence_window: true,
        known_bad_hashes: Vec::new(),
        webhook_url: None,
        updated_at: now_ms(),
    }
}

fn load_policy(state: &AppState, game_id: &str) -> GamePolicy {
    state
        .store
        .get_policy(game_id)
        .unwrap_or_else(|| default_policy(state, game_id))
}

async fn maybe_webhook(policy: &GamePolicy, decision: &types::DecisionRecord) {
    if decision.action == DecisionAction::Observe {
        return;
    }

    let Some(url) = policy.webhook_url.as_ref() else {
        return;
    };

    if !(url.starts_with("https://") || url.starts_with("http://127.0.0.1") || url.starts_with("http://localhost")) {
        warn!("webhook url rejected (must be https or localhost): {url}");
        return;
    }

    let payload = StudioWebhookPayload {
        kind: "decision",
        decision: decision.clone(),
    };

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            warn!("webhook client init failed: {error}");
            return;
        }
    };

    if let Err(error) = client.post(url).json(&payload).send().await {
        warn!("webhook delivery failed: {error}");
    }
}

async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "service": "mjolnir-server",
        "version": env!("CARGO_PKG_VERSION"),
        "auth_open": state.allow_open_auth
            && state.ingest_api_key.is_none()
            && state.studio_api_key.is_none(),
    }))
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<SessionStartRequest>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    require_ingest(&state, &headers)?;

    if body.game_id.trim().is_empty() || body.player_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "game_id and player_id are required"})),
        ));
    }

    let now = now_ms();
    let session = SessionRecord {
        session_id: Uuid::new_v4().to_string(),
        game_id: body.game_id,
        player_id: body.player_id,
        client_version: body.client_version.unwrap_or_else(|| "unknown".into()),
        machine_fingerprint: body.machine_fingerprint.unwrap_or_default(),
        target_process: body.target_process.unwrap_or_default(),
        created_at: now,
        last_seen_at: now,
        peak_risk: 0,
        finding_count: 0,
    };

    state.store.put_session(&session).map_err(store_error)?;
    let policy = load_policy(&state, &session.game_id);

    Ok((
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "session_id": session.session_id,
            "policy": {
                "observe_only_default": policy.observe_only_default,
                "kick_threshold": policy.kick_threshold,
                "ban_threshold": policy.ban_threshold,
                "require_evidence_window": policy.require_evidence_window,
                "known_bad_hashes": policy.known_bad_hashes,
            }
        })),
    ))
}

async fn ingest(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<IngestRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_ingest(&state, &headers)?;

    if body.session_id.trim().is_empty() || body.game_id.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "session_id, game_id, and events[] are required"})),
        ));
    }

    if body.events.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "events must be a non-empty array"})),
        ));
    }

    if body.events.len() > 200 {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(json!({"ok": false, "error": "events batch too large (max 200)"})),
        ));
    }

    let mut session = state
        .store
        .get_session(&body.session_id)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(json!({"ok": false, "error": "unknown session_id"})),
            )
        })?;

    if session.game_id != body.game_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"ok": false, "error": "session/game mismatch"})),
        ));
    }

    let policy = load_policy(&state, &body.game_id);
    let previous = state.store.get_decision(&body.session_id);
    let decision = build_decision(
        &session,
        &body.events,
        &policy,
        previous.as_ref(),
    );

    session.last_seen_at = now_ms();
    session.peak_risk = decision.peak_risk;
    session.finding_count = decision.finding_count;

    state.store.put_session(&session).map_err(store_error)?;
    state.store.put_decision(&decision).map_err(store_error)?;

    let evidence_key = format!("{}-{}", session.session_id, decision.decided_at);
    let evidence = json!({
        "session_id": session.session_id,
        "received_at": decision.decided_at,
        "events": body.events.iter().take(50).collect::<Vec<_>>(),
    });
    state
        .store
        .put_evidence(&evidence_key, &evidence)
        .map_err(store_error)?;

    maybe_webhook(&policy, &decision).await;

    Ok(Json(json!({
        "ok": true,
        "decision": decision
    })))
}

async fn get_decision(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_studio(&state, &headers)?;

    let decision = state.store.get_decision(&session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "no decision yet"})),
        )
    })?;

    Ok(Json(json!({ "ok": true, "decision": decision })))
}

async fn get_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(game_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_studio(&state, &headers)?;
    let policy = load_policy(&state, &game_id);
    Ok(Json(json!({ "ok": true, "policy": policy })))
}

#[derive(Debug, Deserialize)]
struct PolicyUpdate {
    observe_only_default: Option<bool>,
    kick_threshold: Option<i32>,
    ban_threshold: Option<i32>,
    require_evidence_window: Option<bool>,
    known_bad_hashes: Option<Vec<String>>,
    webhook_url: Option<String>,
}

async fn put_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(game_id): Path<String>,
    Json(body): Json<PolicyUpdate>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_studio(&state, &headers)?;

    let mut policy = load_policy(&state, &game_id);
    if let Some(value) = body.observe_only_default {
        policy.observe_only_default = value;
    }
    if let Some(value) = body.kick_threshold {
        policy.kick_threshold = value;
    }
    if let Some(value) = body.ban_threshold {
        policy.ban_threshold = value;
    }
    if let Some(value) = body.require_evidence_window {
        policy.require_evidence_window = value;
    }
    if let Some(value) = body.known_bad_hashes {
        policy.known_bad_hashes = value;
    }
    if let Some(value) = body.webhook_url {
        policy.webhook_url = if value.is_empty() {
            None
        } else {
            Some(value)
        };
    }

    if policy.kick_threshold >= policy.ban_threshold {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": "kick_threshold must be lower than ban_threshold"
            })),
        ));
    }

    policy.updated_at = now_ms();
    state.store.put_policy(&policy).map_err(store_error)?;

    Ok(Json(json!({ "ok": true, "policy": policy })))
}

async fn issue_challenge(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    require_studio(&state, &headers)?;

    let session = state.store.get_session(&session_id).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(json!({"ok": false, "error": "unknown session_id"})),
        )
    })?;

    let nonce = Uuid::new_v4().to_string();
    let issued_at = now_ms();
    let expires_at = issued_at + 60_000;

    let challenge = json!({
        "session_id": session.session_id,
        "game_id": session.game_id,
        "player_id": session.player_id,
        "nonce": nonce,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "instructions": [
            "Client must echo nonce in next ingest batch details or a future /v1/challenge-response",
            "Use for live presence / anti-replay of offline bots"
        ]
    });

    state
        .store
        .put_evidence(
            &format!("challenge-{}-{}", session.session_id, issued_at),
            &challenge,
        )
        .map_err(store_error)?;

    Ok(Json(json!({ "ok": true, "challenge": challenge })))
}

fn store_error(error: store::StoreError) -> (StatusCode, Json<Value>) {
    match error {
        store::StoreError::InvalidKey => (
            StatusCode::BAD_REQUEST,
            Json(json!({"ok": false, "error": "invalid id/key"})),
        ),
        _ => {
            warn!("storage error: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"ok": false, "error": "storage error"})),
            )
        }
    }
}

fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/sessions", post(create_session))
        .route("/v1/ingest", post(ingest))
        .route("/v1/challenges/{session_id}", post(issue_challenge))
        .route("/v1/decisions/{session_id}", get(get_decision))
        .route("/v1/policy/{game_id}", get(get_policy).put(put_policy))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mjolnir_server=info,tower_http=info".into()),
        )
        .init();

    let bind = env_opt("MJOLNIR_BIND").unwrap_or_else(|| "0.0.0.0:8787".into());
    let data_dir = PathBuf::from(env_opt("MJOLNIR_DATA_DIR").unwrap_or_else(|| "data".into()));
    let environment = env_opt("MJOLNIR_ENV")
        .unwrap_or_else(|| "development".into())
        .to_ascii_lowercase();
    let is_production = matches!(environment.as_str(), "production" | "prod");

    let ingest_api_key = env_opt("MJOLNIR_INGEST_API_KEY").or_else(|| env_opt("INGEST_API_KEY"));
    let studio_api_key = env_opt("MJOLNIR_STUDIO_API_KEY").or_else(|| env_opt("STUDIO_API_KEY"));

    if is_production && (ingest_api_key.is_none() || studio_api_key.is_none()) {
        return Err(
            "MJOLNIR_ENV=production requires MJOLNIR_INGEST_API_KEY and MJOLNIR_STUDIO_API_KEY"
                .into(),
        );
    }

    let state = Arc::new(AppState {
        store: Store::open(&data_dir)?,
        ingest_api_key,
        studio_api_key,
        allow_open_auth: !is_production,
        default_kick_threshold: env_opt("DEFAULT_KICK_THRESHOLD")
            .and_then(|value| value.parse().ok())
            .unwrap_or(70),
        default_ban_threshold: env_opt("DEFAULT_BAN_THRESHOLD")
            .and_then(|value| value.parse().ok())
            .unwrap_or(90),
    });

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    info!(
        "Mjölnir server v{} listening on http://{bind} (data={})",
        env!("CARGO_PKG_VERSION"),
        data_dir.display()
    );

    axum::serve(listener, app(state)).await?;
    Ok(())
}
