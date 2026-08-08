# Changelog

All notable changes to **Mjölnir** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Linux `systemd --user` install + login auto-update scripts (PR #6, if not yet merged)

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
