# Changelog

All notable changes to **Mjölnir** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Linux `systemd --user` install + login auto-update scripts (PR #6, if not yet merged)

## [1.13.0] - 2026-08-08

### Added

- **Exception/VEH scanner** — compares `KiUserExceptionDispatcher`, `RtlDispatchException`, VEH/APC dispatcher prologues remote vs local
- **Hosts scanner** — flags game/AC domain redirects in the system hosts file
- **Token scanner** — elevated / High-System integrity / impersonation tokens on the target
- **Connection scanner** — established TCP to suspicious remote ports from the game process
- Persistence coverage extended with **AppInit_DLLs** and **IFEO Debugger** redirects
- Agent live challenge loop: `GET /v1/challenges/:session_id` + automatic `POST /v1/challenge-response`
- Critical categories: `EXCEPTION_DISPATCH`, `HOSTS`, `TOKEN`

### Config

- `enable_exception_dispatch_scan`, `enable_hosts_scan`, `enable_token_scan`, `enable_connection_scan`
- Weights: `exception_dispatch`, `hosts_tamper`, `suspicious_token`, `suspicious_connection`

## [1.12.0] - 2026-08-08

### Added

- **Writable image scanner** — MEM_IMAGE regions that are writable+executable (code caves)
- **Persistence scanner** — HKCU/HKLM Run/RunOnce entries matching cheat/debug tooling
- **Port scanner** — listening TCP ports commonly used by remote/cheat tools
- **ETW patch scanner** — patched `EtwEventWrite` / `NtTraceEvent` prologues
- Server `POST /v1/challenge-response` to verify studio-issued challenge nonces
- Critical categories: `WRITABLE_IMAGE`, `ETW`, `PERSISTENCE`

## [1.11.0] - 2026-08-08

### Added

- **Syscall stub scanner** — critical ntdll Nt* prologues remote vs local (JMP/trampoline / missing syscall pattern)
- **Hollowing scanner** — MEM_PRIVATE primary image, private entry point, PEB ImagePathName vs OS path
- **Mitigation scanner** — DEP/ASLR/CFG weakened, dynamic-code remote downgrade
- **Stealth scanner** — ProcessInstrumentationCallback + ThreadHideFromDebugger
- Server `POST /v1/challenges/:session_id` — studio-issued live challenge nonce
- Server treats `SYSCALL_STUB`, `HOLLOWING`, `STEALTH` as critical categories

### Config

- `enable_syscall_stub_scan`, `enable_hollowing_scan`, `enable_mitigation_scan`, `enable_stealth_scan`
- Weights: `syscall_stub`, `hollowing`, `mitigation`, `stealth`

## [1.10.0] - 2026-08-08

### Added

- **Privilege scanner** — flags non-whitelisted processes with SeDebugPrivilege / SeLoadDriverPrivilege / SeTcbPrivilege
- **EAT hook scanner** — compares critical ntdll/kernel32/kernelbase export RVAs in the target vs local exports
- **Named pipe scanner** — detects pipes matching known cheat/debug tooling patterns
- Server scoring treats `EAT_HOOK`, `PRIVILEGE`, and `PIPE` as critical categories
- Server `known_bad_hashes` now boosts peak risk and can force `ban` when a hash appears in event details

### Config

- `enable_privilege_scan`, `enable_eat_hook_scan`, `enable_pipe_scan`
- Risk weights: `dangerous_privilege`, `eat_hook`, `suspicious_pipe`

## [1.9.1] - 2026-08-06

### Fixed

- Ingest queue loss, ingest API key env mismatch, observe_only enforcement, sticky decisions, path traversal, evidence settle, injection FP, empty batches, webhook timeout, HMAC unsigned frames

## [1.9.0] - 2026-08-06

### Added

- Client/server split and self-hosted Rust control plane

## [1.8.0] - 2026-08-06

### Added

- Evidence-gated enforce, injection heuristics, HMAC IPC

## [1.7.0] - 2026-08-06

### Added

- Persistent baselines, lifetime tracking, twin watchdog, self-protect
