# Mjölnir client ↔ server protocol

## Trust model

| Layer | Trust |
| --- | --- |
| C++ core → Rust agent (named pipe) | Optional HMAC-SHA256 (`MJOLNIR_IPC_SECRET`) |
| Client agent → server | Bearer `MJOLNIR_INGEST_API_KEY` over HTTP(S) |
| Game backend → server | Bearer `MJOLNIR_STUDIO_API_KEY` over HTTP(S) |

The client can be compromised. Treat ingest evidence as **untrusted input**: useful for ranking and investigation, never as sole proof without server-side game signals (reports, replay, economy anomalies, etc.).

## Local IPC frame (core → agent)

```json
{
  "v": 1,
  "ts": 1710000000,
  "n": 12,
  "level": "HIGH",
  "category": "INJECTION",
  "details": "...",
  "pid": 1234,
  "risk_score": 85,
  "mac": "optional-hmac-hex"
}
```

Canonical MAC string:

```
1|{ts}|{n}|{level}|{category}|{details}|{pid}|{risk_score}
```

## Ingest batch (agent → server)

`POST /v1/ingest`

```json
{
  "session_id": "uuid",
  "game_id": "my-game",
  "player_id": "user-42",
  "events": [ /* SecurityPayload[] */ ]
}
```

## Decision (server → studio)

```json
{
  "session_id": "uuid",
  "game_id": "my-game",
  "player_id": "user-42",
  "action": "observe|challenge|kick|ban",
  "reason": "...",
  "peak_risk": 85,
  "average_risk": 61,
  "finding_count": 14,
  "decided_at": 1710000123456,
  "categories": ["INJECTION", "HOOK"]
}
```

Game servers should:

1. Map `player_id` to their account system
2. Apply `kick` / `ban` in their own authority path
3. Prefer webhook + poll for redundancy
