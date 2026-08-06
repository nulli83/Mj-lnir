use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
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
        let provided = hex::decode(mac_hex)
            .map_err(|_| "mac is not valid hex".to_string())?;

        if expected.as_slice() != provided.as_slice() {
            return Err("HMAC verification failed".into());
        }

        self.last_nonce = payload.n;
        self.seen_nonces.insert(payload.n);

        if self.seen_nonces.len() > 4096 {
            self.seen_nonces.clear();
            self.seen_nonces.insert(payload.n);
        }

        Ok(())
    }
}

fn print_banner(auth_enabled: bool) {
    println!("============================================================");
    println!(" Mjölnir Orchestrator v1.2.0");
    println!(" Awaiting C++ security core on \\\\.\\pipe\\mjolnir_ipc");
    println!(
        " IPC HMAC: {}",
        if auth_enabled { "required" } else { "optional/off" }
    );
    println!("============================================================");
}

fn summarize(payload: &SecurityPayload) {
    println!(
        "[{}] [{}] [PID {}] [Risk {}] {}",
        payload.level, payload.category, payload.pid, payload.risk_score, payload.details
    );
}

fn drain_frames(pending: &mut String, auth: &mut AuthState) {
    while let Some(index) = pending.find('\n') {
        let line = pending[..index].trim().to_string();
        pending.drain(..=index);

        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<SecurityPayload>(&line) {
            Ok(payload) => match auth.verify(&payload) {
                Ok(()) => summarize(&payload),
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pipe_path = r"\\.\pipe\mjolnir_ipc";
    let server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(pipe_path)?;

    println!("[*] Named pipe ready. Waiting for C++ core...");
    server.connect().await?;
    println!("[+] C++ security core connected.");

    auth.last_nonce = 0;
    auth.seen_nonces.clear();

    let mut stream = server;
    let mut buffer = vec![0u8; 8192];
    let mut pending = String::new();

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                println!("[-] C++ core disconnected.");
                break;
            }
            Ok(n) => {
                pending.push_str(&String::from_utf8_lossy(&buffer[..n]));
                drain_frames(&mut pending, auth);

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

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut auth = AuthState::from_env();
    print_banner(auth.secret.is_some());

    loop {
        if let Err(error) = serve_pipe_session(&mut auth).await {
            eprintln!("[ERROR] Pipe session failed: {error}");
        }

        println!("[*] Restarting pipe listener in 1s...");
        sleep(Duration::from_secs(1)).await;
    }
}
