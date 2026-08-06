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
| Image integrity | Disk vs memory `.text` hook-like patches / wiped MZ headers |
| Artifact scanner | Known cheat mutexes and debugger window titles/classes |
| Service scanner | Suspicious/vulnerable drivers installed as services |
| Session/persistent baseline | Module birth + `.text` CRC; saved per game-hash under `baselines/` |
| Lifetime tracking | Region birth / W→X escalation and mid-session handle appearance |
| Injection heuristics | New modules from temp/random names correlated with out-of-module threads |
| Evidence window | Delayed enforce on sustained peak/average risk (cuts one-cycle false kills) |
| Twin watchdog | Sibling `mjolnir_watchdog.exe` restarts a dead/frozen core |
| Self-protect | Process mitigations, self-hash, handles-to-AC, in-process watchdog |
| Device/driver scanner | Known vulnerable/cheat kernel devices and drivers |
| Timing anomaly | QPC vs tick divergence suggesting single-stepping |
| Process watchlist | Cheat Engine, x64dbg, IDA, remote-access tools |
| HMAC IPC | Optional `MJOLNIR_IPC_SECRET` / `ipc_hmac_secret` signs frames (nonce + ts) |

Default mode is **observe-only** (`settings.observe_only = true` in `whitelist.json`).
Set `observe_only` to `false` to enable enforcement. With `enable_evidence_window=true` (default),
termination requires sustained evidence across a sliding window (settle cycles + min samples + peak + average/sustained high),
not a single noisy scan cycle. Disable the window only for debugging.
With `enforce_terminate_watched_tools=true`, known cheat/debug tools are also terminated.

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
    inline_hooks.hpp # prologue trampoline checks
    manual_map.hpp   # PE images in private RX memory
    image_integrity.hpp # disk vs memory code patches
    artifacts.hpp    # cheat mutexes / debugger windows
    services.hpp     # suspicious Windows services
    baseline.hpp     # session + persistent module/code baselines
    lifetime.hpp     # region/handle birth & escalation tracking
    injection.hpp    # module-birth injection heuristics
    evidence.hpp     # sliding-window enforce gate
    self_protect.hpp # AC process hardening + in-process watchdog
    twin_watchdog.hpp / watchdog_main.cpp  # sibling restarter
    devices.hpp      # risky kernel devices/drivers
    timing.hpp       # QPC/tick anomaly checks
    enforce.hpp      # optional terminate-on-threshold
    alert.hpp        # alert bus + JSONL logging
    ipc.hpp          # named-pipe client (optional HMAC-SHA256)
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
{"v":1,"ts":1710000000,"n":12,"level":"HIGH","category":"INJECTION","details":"...","pid":1234,"risk_score":85,"mac":"..."}
```

Set the same secret on both sides for authenticated telemetry:

* environment: `MJOLNIR_IPC_SECRET`
* or `settings.ipc_hmac_secret` in `whitelist.json` (env wins)

When the secret is set, the orchestrator rejects missing/invalid MAC, stale timestamps, and replayed nonces.

## System Requirements

* Windows 10/11 x64 for the security core
* Administrator privileges recommended for full handle enumeration
* Linux host is fine for editing; Windows is required to compile/run the C++ core

## Status

v1.8.0 — evidence-gated enforcement, injection heuristics on module birth,
and optional HMAC-SHA256 IPC (nonce + timestamp) between core and orchestrator.
