use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::Manager;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Debug, Clone)]
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
        }
    }

    fn verify(&mut self, payload: &SecurityPayload) -> bool {
        let Some(secret) = &self.secret else {
            return true;
        };

        let Some(mac_hex) = payload.mac.as_ref() else {
            return false;
        };

        if payload.v != 1 || payload.ts <= 0 || payload.n == 0 {
            return false;
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        if (now - payload.ts).abs() > 60 {
            return false;
        }

        if payload.n <= self.last_nonce || self.seen_nonces.contains(&payload.n) {
            return false;
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

        let Ok(mut mac) = HmacSha256::new_from_slice(secret.as_bytes()) else {
            return false;
        };
        mac.update(canonical.as_bytes());

        let expected = mac.finalize().into_bytes();
        let Ok(provided) = hex::decode(mac_hex) else {
            return false;
        };

        if expected.as_slice() != provided.as_slice() {
            return false;
        }

        self.last_nonce = payload.n;
        self.seen_nonces.insert(payload.n);
        if self.seen_nonces.len() > 4096 {
            self.seen_nonces.clear();
            self.seen_nonces.insert(payload.n);
        }

        true
    }
}

#[tauri::command]
fn get_daemon_status() -> String {
    "Mjölnir Security Daemon - Active & Monitoring".into()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let handle = app.handle().clone();

            tauri::async_runtime::spawn(async move {
                let pipe_path = r"\\.\pipe\mjolnir_ipc";
                let mut auth = AuthState::from_env();

                loop {
                    let server = match ServerOptions::new().create(pipe_path) {
                        Ok(server) => server,
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            continue;
                        }
                    };

                    if server.connect().await.is_err() {
                        continue;
                    }

                    auth.last_nonce = 0;
                    auth.seen_nonces.clear();

                    let mut stream = server;
                    let mut buffer = vec![0u8; 8192];
                    let mut pending = String::new();

                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) => break,
                            Ok(n) => {
                                pending.push_str(&String::from_utf8_lossy(&buffer[..n]));

                                while let Some(index) = pending.find('\n') {
                                    let line = pending[..index].trim().to_string();
                                    pending.drain(..=index);

                                    if line.is_empty() {
                                        continue;
                                    }

                                    if let Ok(payload) =
                                        serde_json::from_str::<SecurityPayload>(&line)
                                    {
                                        if auth.verify(&payload) {
                                            let _ = handle.emit("security-alert", payload);
                                        }
                                    }
                                }

                                if pending.len() > 64 * 1024 {
                                    pending.clear();
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_daemon_status])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
