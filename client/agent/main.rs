use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::env;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::sync::Mutex;
use tokio::time::sleep;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityPayload {
    #[serde(default = "default_version")]
    v: u32,
    #[serde(default)]
    ts: i64,
    #[serde(default)]
    n: u64,
    level: String,
    category: String,
    details: String,
    pid: u32,
    #[serde(default)]
    risk_score: i32,
    #[serde(default)]
    mac: Option<String>,
}

fn default_version() -> u32 {
    0
}

#[derive(Debug, Clone)]
struct ServerConfig {
    base_url: String,
    ingest_key: String,
    game_id: String,
    player_id: String,
    target_process: String,
    client_version: String,
}

impl ServerConfig {
    fn from_env() -> Option<Self> {
        let base_url = env::var("MJOLNIR_SERVER_URL")
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())?;

        let ingest_key = env::var("MJOLNIR_INGEST_API_KEY")
            .or_else(|_| env::var("MJOLNIR_INGEST_KEY"))
            .or_else(|_| env::var("INGEST_API_KEY"))
            .unwrap_or_default();

        Some(Self {
            base_url,
            ingest_key,
            game_id: env::var("MJOLNIR_GAME_ID").unwrap_or_else(|_| "demo".into()),
            player_id: env::var("MJOLNIR_PLAYER_ID")
                .unwrap_or_else(|_| format!("player-{}", std::process::id())),
            target_process: env::var("MJOLNIR_TARGET_PROCESS")
                .unwrap_or_else(|_| "game.exe".into()),
            client_version: env!("CARGO_PKG_VERSION").into(),
        })
    }
}

struct ServerBridge {
    config: ServerConfig,
    http: reqwest::Client,
    session_id: Option<String>,
    queue: VecDeque<SecurityPayload>,
}

impl ServerBridge {
    fn new(config: ServerConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .expect("http client"),
            session_id: None,
            queue: VecDeque::new(),
        }
    }

    fn enqueue(&mut self, payload: SecurityPayload) {
        self.queue.push_back(payload);
        while self.queue.len() > 200 {
            self.queue.pop_front();
        }
    }

    async fn ensure_session(&mut self) -> Result<(), String> {
        if self.session_id.is_some() {
            return Ok(());
        }

        let mut request = self
            .http
            .post(format!("{}/v1/sessions", self.config.base_url))
            .json(&serde_json::json!({
                "game_id": self.config.game_id,
                "player_id": self.config.player_id,
                "client_version": self.config.client_version,
                "target_process": self.config.target_process,
            }));

        if !self.config.ingest_key.is_empty() {
            request = request.bearer_auth(&self.config.ingest_key);
        }

        let response = request
            .send()
            .await
            .map_err(|error| format!("session start failed: {error}"))?;

        if !response.status().is_success() {
            return Err(format!(
                "session start HTTP {}",
                response.status().as_u16()
            ));
        }

        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|error| format!("session parse failed: {error}"))?;

        let session_id = body
            .get("session_id")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "session_id missing in response".to_string())?
            .to_string();

        println!("[+] Server session established: {session_id}");
        if let Some(policy) = body.get("policy") {
            println!("[*] Server policy: {policy}");
        }

        self.session_id = Some(session_id);
        Ok(())
    }

    fn requeue(&mut self, events: Vec<SecurityPayload>) {
        for event in events.into_iter().rev() {
            self.queue.push_front(event);
        }
        while self.queue.len() > 200 {
            self.queue.pop_back();
        }
    }

    async fn flush(&mut self) -> Result<(), String> {
        if self.queue.is_empty() {
            return Ok(());
        }

        if let Err(error) = self.ensure_session().await {
            return Err(error);
        }

        let session_id = self
            .session_id
            .clone()
            .ok_or_else(|| "missing session".to_string())?;

        let events: Vec<SecurityPayload> = self.queue.drain(..).collect();
        let count = events.len();

        let mut request = self
            .http
            .post(format!("{}/v1/ingest", self.config.base_url))
            .json(&serde_json::json!({
                "session_id": session_id,
                "game_id": self.config.game_id,
                "player_id": self.config.player_id,
                "events": &events,
            }));

        if !self.config.ingest_key.is_empty() {
            request = request.bearer_auth(&self.config.ingest_key);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                self.requeue(events);
                return Err(format!("ingest failed: {error}"));
            }
        };

        let status = response.status();
        if !status.is_success() {
            let should_drop_session = status.as_u16() == 404;
            self.requeue(events);
            if should_drop_session {
                self.session_id = None;
            }
            return Err(format!("ingest HTTP {}", status.as_u16()));
        }

        let body: serde_json::Value = match response.json().await {
            Ok(body) => body,
            Err(error) => {
                self.requeue(events);
                return Err(format!("ingest parse failed: {error}"));
            }
        };

        if let Some(decision) = body.get("decision") {
            let action = decision
                .get("action")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let reason = decision
                .get("reason")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            println!("[*] Server decision ({count} events): {action} — {reason}");
        }

        Ok(())
    }
}

struct AuthState {
    secret: Option<String>,
    last_nonce: u64,
    seen_nonces: HashSet<u64>,
    max_skew_secs: i64,
}

impl AuthState {
    fn from_env() -> Self {
        let secret = env::var("MJOLNIR_IPC_SECRET")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());

        Self {
            secret,
            last_nonce: 0,
            seen_nonces: HashSet::new(),
            max_skew_secs: 60,
        }
    }

    fn verify(&mut self, payload: &SecurityPayload) -> Result<(), String> {
        let Some(secret) = &self.secret else {
            return Ok(());
        };

        let Some(mac_hex) = payload.mac.as_ref() else {
            return Err("missing mac on authenticated IPC channel".into());
        };

        if payload.v != 1 {
            return Err(format!("unsupported IPC version {}", payload.v));
        }

        if payload.ts <= 0 {
            return Err("missing or invalid timestamp".into());
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        if (now - payload.ts).abs() > self.max_skew_secs {
            return Err(format!(
                "timestamp outside allowed skew (ts={}, now={})",
                payload.ts, now
            ));
        }

        if payload.n == 0 {
            return Err("missing nonce".into());
        }

        if payload.n <= self.last_nonce || self.seen_nonces.contains(&payload.n) {
            return Err(format!("replayed or stale nonce {}", payload.n));
        }

        let canonical = format!(
            "1|{}|{}|{}|{}|{}|{}|{}",
            payload.ts,
            payload.n,
            payload.level,
            payload.category,
            payload.details,
            payload.pid,
            payload.risk_score
        );

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|_| "invalid HMAC secret".to_string())?;
        mac.update(canonical.as_bytes());

        let expected = mac.finalize().into_bytes();
        let provided =
            hex::decode(mac_hex).map_err(|_| "mac is not valid hex".to_string())?;

        if expected.as_slice() != provided.as_slice() {
            return Err("HMAC verification failed".into());
        }

        self.last_nonce = payload.n;
        self.seen_nonces.insert(payload.n);

        if self.seen_nonces.len() > 4096 {
            let watermark = self.last_nonce.saturating_sub(2048);
            self.seen_nonces.retain(|nonce| *nonce > watermark);
            self.seen_nonces.insert(payload.n);
        }

        Ok(())
    }
}

fn print_banner(auth_enabled: bool, server_enabled: bool) {
    println!("============================================================");
    println!(" Mjölnir Client Agent v{}", env!("CARGO_PKG_VERSION"));
    println!(" Local IPC: \\\\.\\pipe\\mjolnir_ipc");
    println!(
        " IPC HMAC: {}",
        if auth_enabled {
            "required"
        } else {
            "optional/off"
        }
    );
    println!(
        " Server forward: {}",
        if server_enabled { "enabled" } else { "off" }
    );
    println!("============================================================");
}

fn summarize(payload: &SecurityPayload) {
    println!(
        "[{}] [{}] [PID {}] [Risk {}] {}",
        payload.level, payload.category, payload.pid, payload.risk_score, payload.details
    );
}

async fn drain_frames(
    pending: &mut String,
    auth: &mut AuthState,
    bridge: &Option<Arc<Mutex<ServerBridge>>>,
) {
    while let Some(index) = pending.find('\n') {
        let line = pending[..index].trim().to_string();
        pending.drain(..=index);

        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<SecurityPayload>(&line) {
            Ok(payload) => match auth.verify(&payload) {
                Ok(()) => {
                    summarize(&payload);
                    if let Some(bridge) = bridge {
                        let mut guard = bridge.lock().await;
                        guard.enqueue(payload);
                    }
                }
                Err(error) => {
                    eprintln!("[!] Rejected telemetry frame: {error} | {line}");
                }
            },
            Err(error) => {
                eprintln!("[!] Invalid telemetry frame: {error} | {line}");
            }
        }
    }
}

async fn serve_pipe_session(
    auth: &mut AuthState,
    bridge: Option<Arc<Mutex<ServerBridge>>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pipe_path = r"\\.\pipe\mjolnir_ipc";
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_path)?;

    println!("[*] Named pipe ready. Waiting for C++ core...");
    server.connect().await?;
    println!("[+] C++ security core connected.");

    let mut stream = server;
    let mut buffer = vec![0u8; 8192];
    let mut pending = String::new();
    let mut last_flush = tokio::time::Instant::now();
    let mut flush_tick = tokio::time::interval(Duration::from_secs(1));
    flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            result = stream.read(&mut buffer) => {
                match result {
                    Ok(0) => {
                        println!("[-] C++ core disconnected.");
                        break;
                    }
                    Ok(n) => {
                        pending.push_str(&String::from_utf8_lossy(&buffer[..n]));
                        drain_frames(&mut pending, auth, &bridge).await;

                        if pending.len() > 64 * 1024 {
                            eprintln!("[!] Discarding oversized incomplete telemetry frame.");
                            pending.clear();
                        }
                    }
                    Err(error) => {
                        eprintln!("[ERROR] Pipe read failed: {error}");
                        break;
                    }
                }
            }
            _ = flush_tick.tick() => {
                if last_flush.elapsed() < Duration::from_secs(5) {
                    continue;
                }

                if let Some(bridge) = &bridge {
                    let mut guard = bridge.lock().await;
                    if let Err(error) = guard.flush().await {
                        eprintln!("[!] Server flush failed: {error}");
                    }
                }
                last_flush = tokio::time::Instant::now();
            }
        }
    }

    if let Some(bridge) = bridge {
        let mut guard = bridge.lock().await;
        if let Err(error) = guard.flush().await {
            eprintln!("[!] Final server flush failed: {error}");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut auth = AuthState::from_env();
    let server_config = ServerConfig::from_env();
    let bridge = server_config.map(|config| Arc::new(Mutex::new(ServerBridge::new(config))));

    print_banner(auth.secret.is_some(), bridge.is_some());

    if let Some(bridge) = &bridge {
        let mut guard = bridge.lock().await;
        if let Err(error) = guard.ensure_session().await {
            eprintln!("[!] Could not open server session yet: {error}");
        }
    }

    loop {
        if let Err(error) = serve_pipe_session(&mut auth, bridge.clone()).await {
            eprintln!("[ERROR] Pipe session failed: {error}");
        }

        println!("[*] Restarting pipe listener in 1s...");
        sleep(Duration::from_secs(1)).await;
    }
}
