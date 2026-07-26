use tokio::net::windows::named_pipe::ServerOptions;
use tokio::io::AsyncReadExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Mjölnir Rust Orchestrator initialized. Awaiting C++ Core IPC stream...");

    let pipe_path = r"\\.\pipe\mjolnir_ipc";

    loop {
        // Create the named pipe server instance
        let server = ServerOptions::new()
            .create(pipe_path)?;

        // Wait for the C++ core to connect asynchronously
        server.connect().await?;
        println!("[+] C++ Security Core connected via Named Pipe.");

        // Spawn an async worker task to read incoming telemetry
        tokio::spawn(async move {
            let mut stream = server;
            let mut buffer = vec![0u8; 1024];

            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => {
                        println!("[-] C++ Core disconnected.");
                        break;
                    }
                    Ok(n) => {
                        let message = String::from_utf8_lossy(&buffer[..n]);
                        println!("[TELEMETRY RECEIVED] {}", message);
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Pipe read failed: {}", e);
                        break;
                    }
                }
            }
        });
    }
}
