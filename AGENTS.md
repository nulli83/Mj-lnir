# AGENTS.md

## Cursor Cloud specific instructions

Mjölnir is a self-hosted, Windows-focused anti-cheat monorepo:

- `server/` — Rust (`axum`) control-plane HTTP API. **This is the only component that builds and runs on the Linux cloud VM.**
- `client/core/` — C++/CMake security scanner. **Windows-only** (`CMakeLists.txt` hard-fails on non-Windows).
- `client/agent/` and `client/ui/` — Rust, use Windows named pipes / Tauri. **Do not build or run on Linux.**

So all cloud-agent lint/test/build/run work targets `server/` only.

### Toolchain caveat (important)

The committed `server/Cargo.lock` pins transitive deps (e.g. `cpufeatures`) that require Rust `edition2024`. The VM's baseline `rustc` (1.83) is too old and fails with `feature 'edition2024' is required`. The startup update script installs and defaults to the latest `stable` toolchain (1.85+), which fixes this. If you ever see the `edition2024` error, run `rustup default stable`.

Always build/test with `--locked` to respect the committed lockfile.

### Server commands (run from `server/`)

Standard commands are documented in `server/README.md`. Quick reference:

- Build: `cargo build --locked`
- Test: `cargo test --locked` (unit tests live in `src/decide.rs`)
- Lint: `cargo clippy --locked`
- Run (dev): `cargo run --locked` — binds `0.0.0.0:8787` (override with `MJOLNIR_BIND`), persists JSON to `server/data/` (git-ignored).

### Running / testing notes

- In `development` (default `MJOLNIR_ENV`), auth is open when API keys are unset, but the `Authorization: Bearer ...` header can still be sent freely. `production` requires `MJOLNIR_INGEST_API_KEY` and `MJOLNIR_STUDIO_API_KEY`.
- Ingest events use the `FindingEvent` schema (`src/types.rs`): `level`, `category`, `details`, `pid`, `risk_score` — not `kind`/`severity`/`risk`. Malformed bodies get a plain-text 4xx (not JSON).
- Enforcement is suppressed while a game's policy has `observe_only_default: true` (the default). To see `kick`/`ban` decisions, first `PUT /v1/policy/:game_id` with `observe_only_default: false`.
- No external database or services are needed; persistence is plain JSON files under `MJOLNIR_DATA_DIR` (default `server/data/`).
