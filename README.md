# Mjölnir

**Mjölnir** is a Windows-focused anti-cheat stack built in **C++** and **Rust**.
The C++ core performs low-level process inspection. The Rust orchestrator streams telemetry over named pipes to operators and optional UI surfaces.

When the hammer falls, cheaters get logged — and in enforce mode, stopped.

## Architecture

```
game.exe  <--- audited by ---  mjolnir_core.exe (C++)
                                      |
                                      |  named pipe: \\.\pipe\mjolnir_ipc
                                      v
                            mjolnir_orchestrator (Rust)
                                      |
                                      v
                         dashboard / SIEM / operators
```

* **C++ Core:** module audits, overlay detection, external handle scanning, debugger checks, Authenticode/SHA-256 integrity, RWX region scanning, risk scoring, JSONL alerts.
* **Rust Orchestrator:** async named-pipe telemetry intake, reconnect loops, structured event printing, Tauri dashboard feed.

## Active Detection Vectors

| Vector | What it catches |
| --- | --- |
| Module whitelist + path scoring | Injected DLLs, temp/download loads |
| Integrity (Authenticode + SHA-256, cached) | Unsigned / untrusted / known-bad binaries |
| Overlay scanner | Click-through ESP / external overlays |
| Handle scanner (extended handle table) | Cheat tools holding `VM_WRITE` / `CREATE_THREAD` |
| Debugger detector | Remote debuggers, debug ports, hardware BPs |
| Memory regions | Private RWX / shellcode-style mappings |
| Thread scanner | Threads whose start address is outside modules |
| Provenance checks | Unexpected parent process / install path |
| Hook scanner (IAT) | Critical API imports redirected outside exporter / into private RX |
| Inline hook scanner | JMP/trampoline patches on critical API prologues |
| Manual-map scanner | PE headers inside private executable memory |
| Device/driver scanner | Known vulnerable/cheat kernel devices and drivers |
| Timing anomaly | QPC vs tick divergence suggesting single-stepping |
| Process watchlist | Cheat Engine, x64dbg, IDA, remote-access tools |

Default mode is **observe-only** (`settings.observe_only = true` in `whitelist.json`).
Set `observe_only` to `false` to enable enforcement: if `highest_risk >= enforce_risk_threshold`, the target process is terminated.

Target acquisition uses `target.process_name` and optional `target.window_title`.

## Project Layout

```
frontend/src/
  windows/           # C++ security core
    main.cpp         # daemon loop
    engine.hpp       # scan orchestration
    memory.hpp       # process/memory helpers
    modules.hpp      # DLL enumeration + risk
    overlay.hpp      # suspicious overlay detection
    handles.hpp      # external handle enumeration
    debugger.hpp     # debugger / HWBP checks
    integrity.hpp    # Authenticode + SHA-256 (cached)
    regions.hpp      # RWX memory region scan
    threads.hpp      # start-address module checks
    process.hpp      # parent + install-path provenance
    hooks.hpp        # critical IAT hook checks
    timing.hpp       # QPC/tick anomaly checks
    enforce.hpp      # optional terminate-on-threshold
    alert.hpp        # alert bus + JSONL logging
    ipc.hpp          # named-pipe client
    config.*         # hot-reloadable whitelist.json
    whitelist.json   # policy / allowlists / weights
  main.rs            # Rust orchestrator
  src-tauri/         # optional Tauri dashboard
```

## Build (Windows)

### C++ core

```bat
cd frontend\src\windows
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Requires Visual Studio / MSVC and network access the first time (FetchContent pulls `nlohmann/json`).

### Rust orchestrator

```bat
cd frontend\src
cargo run --release
```

Start the Rust orchestrator first so the named pipe exists, then launch `mjolnir_core.exe`.

## Configuration

Edit `frontend/src/windows/whitelist.json`:

* `target.process_name` — process to protect
* `whitelisted_modules` / `whitelisted_processes`
* `allowed_overlay_processes`
* `trusted_publishers` / `trusted_hashes`
* `monitor_only_processes` — tooling that should raise alerts when present
* `risk_weights` — tune scoring per vector
* `settings.observe_only` — keep `true` while tuning
* `settings.scan_interval_ms` — scan cadence
* Hot reload: save the file and the core reloads automatically

## Telemetry

Alerts are:

1. printed to console
2. appended to `log/mjolnir.jsonl`
3. streamed over IPC as newline-delimited JSON:

```json
{"level":"HIGH","category":"MODULE","details":"...","pid":1234,"risk_score":65}
```

## System Requirements

* Windows 10/11 x64 for the security core
* Administrator privileges recommended for full handle enumeration
* Linux host is fine for editing; Windows is required to compile/run the C++ core

## Status

v1.3.0 — adds critical IAT hook scanning, timing anomaly checks, and optional
enforce mode (`observe_only=false` + `enforce_risk_threshold`).
