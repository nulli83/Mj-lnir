use tauri::Manager;
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::io::AsyncReadExt;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct SecurityPayload {
    level: String,
    category: String,
    details: String,
    pid: u32,
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
            
            // Spawn background task to listen for the C++ Core via Named Pipes
            tauri::async_runtime::spawn(async move {
                let pipe_path = r"\\.\pipe\mjolnir_ipc";
                loop {
                    if let Ok(server) = ServerOptions::new().create(pipe_path) {
                        if server.connect().await.is_ok() {
                            let mut stream = server;
                            let mut buffer = vec![0u8; 2048];
                            
                            loop {
                                match stream.read(&mut buffer).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        if let Ok(payload) = serde_json::from_slice::<SecurityPayload>(&buffer[..n]) {
                                            // Push telemetry packet live to the Web UI frontend
                                            let _ = handle.emit("security-alert", payload);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![get_daemon_status])
        .run(tauri::generate_context())
        .expect("error while running tauri application");
}
