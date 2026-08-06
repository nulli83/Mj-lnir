use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::windows::named_pipe::ServerOptions;
use tokio::time::sleep;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityPayload {
    level: String,
    category: String,
    details: String,
    pid: u32,
    #[serde(default)]
    risk_score: i32,
}

fn print_banner() {
    println!("============================================================");
    println!(" Mjölnir Orchestrator v1.1.0");
    println!(" Awaiting C++ security core on \\\\.\\pipe\\mjolnir_ipc");
    println!("============================================================");
}

fn summarize(payload: &SecurityPayload) {
    println!(
        "[{}] [{}] [PID {}] [Risk {}] {}",
        payload.level,
        payload.category,
        payload.pid,
        payload.risk_score,
        payload.details
    );
}

fn drain_frames(pending: &mut String) {
    while let Some(index) = pending.find('\n') {
        let line = pending[..index].trim().to_string();
        pending.drain(..=index);

        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<SecurityPayload>(&line) {
            Ok(payload) => summarize(&payload),
            Err(error) => {
                eprintln!("[!] Invalid telemetry frame: {error} | {line}");
            }
        }
    }
}

async fn serve_pipe_session() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => {
                println!("[-] C++ core disconnected.");
                break;
            }
            Ok(n) => {
                pending.push_str(&String::from_utf8_lossy(&buffer[..n]));
                drain_frames(&mut pending);

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
    print_banner();

    loop {
        if let Err(error) = serve_pipe_session().await {
            eprintln!("[ERROR] Pipe session failed: {error}");
        }

        println!("[*] Restarting pipe listener in 1s...");
        sleep(Duration::from_secs(1)).await;
    }
}
