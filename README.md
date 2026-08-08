# Mjölnir

**Mjölnir** is a Windows-focused anti-cheat stack with a clear split:

* **Client** — installed on player machines (C++ scanner + Rust agent)
* **Server** — self-hosted control plane for game studios (Rust)

Local detection gathers evidence. **Account actions (kick/ban) belong on the server**, owned by the people who ship the game.

When the hammer falls, cheaters get logged — and when the studio enables enforcement, stopped.

## Architecture

```
                    PLAYER MACHINE (client)
 ┌──────────────────────────────────────────────────────────┐
 │  game.exe  <--- audited by ---  mjolnir_core.exe (C++)   │
 │                                      |                   │
 │                                      | named pipe        │
 │                                      v                   │
 │                            mjolnir_agent (Rust)          │
 └──────────────────────────────|───────────────────────────┘
                                | HTTP(S) /v1/ingest
                                v
                    STUDIO CONTROL PLANE (server)
                      mjolnir_server (self-hosted Rust)
                                |
                    /v1/decisions + optional webhook
                                v
                         game backend / ban systems
```

| Side | Who uses it | Responsibility |
| --- | --- | --- |
| `client/` | Players / launcher install | Detect, protect itself, local observe/enforce, forward evidence |
| `server/` | Game developers | Policy, session scoring, kick/ban decisions, webhooks |
| `shared/` | Both | Protocol / trust notes |

## Repository layout

```
client/
  core/       # C++ security core + watchdog + whitelist.json
  agent/      # Rust IPC intake + optional server forwarder
  ui/         # optional Tauri dashboard
server/       # self-hosted Rust control plane
shared/       # cross-cutting protocol docs
```

## Client detection vectors (summary)

Modules, overlays, handles, debugger, integrity, RWX regions, threads, provenance, IAT/inline/EAT hooks, ntdll syscall-stub integrity, ETW/trace patches, manual-map, process hollowing/remap, writable image code caves, weakened mitigations (DEP/ASLR/CFG), instrumentation callbacks / ThreadHideFromDebugger, image integrity, artifacts, services, baselines, lifetime, injection heuristics, dangerous privileges, suspicious named pipes, autorun persistence, suspicious listening ports, evidence-gated local enforce, twin watchdog, self-protect, timing, process watch, optional HMAC IPC.

Default local mode is **observe-only** (`client/core/whitelist.json`).

## Quick start

### Client (Windows)

```bat
cd client\agent
cargo run --release

cd client\core
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Optional server forward from the agent:

```bat
set MJOLNIR_SERVER_URL=http://your-server:8787
set MJOLNIR_INGEST_API_KEY=ingest-secret
set MJOLNIR_GAME_ID=my-game
set MJOLNIR_PLAYER_ID=user-42
```

### Server (Linux / Windows / macOS)

```bash
cd server
cargo test
cargo run --release
```

Defaults to `http://0.0.0.0:8787`. Set `MJOLNIR_INGEST_API_KEY` and `MJOLNIR_STUDIO_API_KEY` before production.

See `client/README.md` and `server/README.md` for auth and policy details.

## Trust model (important)

The client runs on a hostile machine. Evidence is valuable for ranking and investigation, but studios should combine it with their own game-server signals before permanent bans. Details: `shared/protocol.md`.

## Status

v1.12.0 — writable-image, persistence, ports, ETW patch scanners + challenge-response.

See [`CHANGELOG.md`](CHANGELOG.md) for full history.
