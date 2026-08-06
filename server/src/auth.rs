use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};

use crate::AppState;

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .map(str::trim)
}

fn timing_eq(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn check_key(
    state: &AppState,
    headers: &HeaderMap,
    expected: Option<&str>,
    missing_label: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    match expected {
        None if state.allow_open_auth => Ok(()),
        None => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "ok": false,
                "error": format!("{missing_label} is not configured")
            })),
        )),
        Some(expected) => {
            let provided = bearer_token(headers).unwrap_or_default();
            if timing_eq(provided, expected) {
                Ok(())
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "ok": false,
                        "error": "Invalid credentials"
                    })),
                ))
            }
        }
    }
}

pub fn require_ingest(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<Value>)> {
    check_key(
        state,
        headers,
        state.ingest_api_key.as_deref(),
        "INGEST_API_KEY",
    )
}

pub fn require_studio(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<Value>)> {
    check_key(
        state,
        headers,
        state.studio_api_key.as_deref(),
        "STUDIO_API_KEY",
    )
}
