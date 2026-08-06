use tauri::Manager;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SecurityPayload {
    level: String,
    category: String,
    details: String,
    pid: u32,
    #[serde(default)]
    risk_score: i32,
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
                                        let _ = handle.emit("security-alert", payload);
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
