# Changelog

All notable changes to **Mjölnir** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for release tags described below.

## [Unreleased]

### Added

- Linux `systemd --user` install + login auto-update scripts (`scripts/`, `server/systemd/`) — pending merge of PR #6

## [1.9.1] - 2026-08-06

### Fixed

- Client agent no longer drops ingest events when a server flush fails (batch is requeued)
- Agent accepts `MJOLNIR_INGEST_API_KEY` (and legacy `MJOLNIR_INGEST_KEY` / `INGEST_API_KEY`)
- Server honors `observe_only_default` (suppresses kick/ban while true)
- Stronger prior decisions (`ban`/`kick`) are retained instead of being overwritten by weaker batches
- Policy/storage keys sanitized to block path traversal
- Evidence settle window no longer keeps attach-time peaks for enforce
- Injection thread boost only applies to already-suspicious module births
- Empty ingest batches rejected; webhook timeout + https/localhost restriction
- Production mode requires both API keys (`production` / `prod`)
- HMAC sign failure no longer sends unsigned IPC frames
- Agent flush timer runs even when the named pipe is quiet

## [1.9.0] - 2026-08-06

### Added

- Clear **client / server** split:
  - `client/core` — C++ security scanner + watchdog
  - `client/agent` — Rust IPC intake + optional server forwarder
  - `client/ui` — optional Tauri dashboard
  - `server/` — self-hosted Rust control plane for game studios
  - `shared/protocol.md` — trust model and wire formats
- Studio API: `/v1/sessions`, `/v1/ingest`, `/v1/decisions/:id`, `/v1/policy/:game_id`, `/health`
- JSON file persistence under `server/data/`
- Bearer auth for ingest and studio keys

### Changed

- Removed Cloudflare Worker / wrangler stack; server is a native Rust binary (`mjolnir_server`)
- Repository layout moved off `frontend/` into `client/` + `server/`

## [1.8.0] - 2026-08-06

### Added

- Evidence-gated local enforcement (sliding window: settle, samples, peak, average/sustained)
- Injection heuristics on baseline module birth (temp paths, random names, thread correlation)
- Optional HMAC-SHA256 IPC (`v` / `ts` / `n` / `mac`) between C++ core and Rust agent
- Config knobs in `whitelist.json` for evidence, injection, and `ipc_hmac_secret`

## [1.7.0] - 2026-08-06

### Added

- Persistent baselines per game build hash (`baselines/`)
- Region / handle lifetime tracking (birth + W→X escalation)
- Twin watchdog process (`mjolnir_watchdog.exe`) for mutual restart
- Self-protect mitigations and in-process watchdog
- Lifetime tracker priming to reduce first-cycle false positives

## [1.6.0] - 2026-08

### Added

- Image integrity (disk vs memory `.text` / PE header)
- Artifact scanner (known cheat mutexes / debugger windows)
- Windows service scanner for suspicious/vulnerable drivers

## [1.5.0] - 2026-08

### Added

- Inline hook scanner (prologue trampolines)
- Manual-map scanner (PE headers in private executable memory)
- Risky device / driver path checks

## [1.4.0] - 2026-08

### Added

- IAT hook scanning for critical APIs
- Local timing anomaly detection (QPC vs tick)
- Optional enforce mode (terminate target / watched tools)

## [1.3.0] - 2026-08

### Fixed

- Handle-table enumeration bug (`SystemExtendedHandleInformation`)

### Changed

- Hardened multi-vector detection pipeline wiring

## [1.0.0] - 2026-08

### Added

- Initial Windows usermode core: modules, overlays, handles, debugger, integrity, RWX regions, threads, provenance, process watch
- Hot-reloadable `whitelist.json` policy
- Named-pipe telemetry to Rust orchestrator + JSONL alerts
- Observe-only default mode

---

[Unreleased]: https://github.com/nulli83/Mj-lnir/compare/main...HEAD
[1.9.1]: https://github.com/nulli83/Mj-lnir/commits/main
