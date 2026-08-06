# Mjölnir Client

This is what **end users / players** install. It runs on the game machine, collects evidence, and (optionally) forwards it to the studio server.

## Components

| Piece | Path | Role |
| --- | --- | --- |
| **Core** | `core/` | C++ security scanner (`mjolnir_core.exe` + watchdog) |
| **Agent** | `agent/` | Rust process that owns the local named pipe and forwards telemetry |
| **UI** | `ui/` | Optional Tauri dashboard |

```
game.exe
   ^
   | audited locally
mjolnir_core.exe  --pipe-->  mjolnir_agent  --HTTPS-->  mjolnir-server
```

Local enforcement (terminate process) can still happen on-box. **Bans, kicks, and account actions must be decided server-side** by the game studio using `/v1/decisions` or webhooks.

## Build (Windows)

### Core

```bat
cd client\core
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

### Agent

```bat
cd client\agent
cargo run --release
```

Start the agent first, then the core.

## Environment

| Variable | Purpose |
| --- | --- |
| `MJOLNIR_IPC_SECRET` | Shared HMAC secret with the C++ core |
| `MJOLNIR_SERVER_URL` | Studio control-plane URL (enables forward) |
| `MJOLNIR_INGEST_API_KEY` | Bearer token for `/v1/sessions` + `/v1/ingest` (alias: `MJOLNIR_INGEST_KEY`) |
| `MJOLNIR_GAME_ID` | Game identifier issued by the studio |
| `MJOLNIR_PLAYER_ID` | Player / account id from the game launcher |
| `MJOLNIR_TARGET_PROCESS` | Optional target process name hint |

Without `MJOLNIR_SERVER_URL`, the agent stays local-only (console + optional UI).
