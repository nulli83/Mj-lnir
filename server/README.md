# Mjölnir Server (control plane)

This is what **game studios** run. It is the source of truth for policy and enforcement decisions.

Implemented as a **Cloudflare Worker** with KV storage.

## Responsibilities

* Accept authenticated evidence from client agents
* Keep per-player sessions
* Score batches into `observe` / `challenge` / `kick` / `ban`
* Expose decisions for the game backend to poll
* Push optional webhooks when action != observe
* Store per-game policy (thresholds, known-bad hashes, webhook URL)

The server does **not** scan Windows processes. Detection stays on the client.

## API

| Method | Path | Auth | Who |
| --- | --- | --- | --- |
| `GET` | `/health` | none | ops |
| `POST` | `/v1/sessions` | ingest | client agent |
| `POST` | `/v1/ingest` | ingest | client agent |
| `GET` | `/v1/decisions/:session_id` | studio | game backend |
| `GET` | `/v1/policy/:game_id` | studio | studio tools |
| `PUT` | `/v1/policy/:game_id` | studio | studio tools |

### Example: start session (client)

```bash
curl -X POST "$MJOLNIR_SERVER_URL/v1/sessions" \
  -H "Authorization: Bearer $INGEST_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"game_id":"my-game","player_id":"user-42","client_version":"1.3.0"}'
```

### Example: poll decision (game server)

```bash
curl "$MJOLNIR_SERVER_URL/v1/decisions/$SESSION_ID" \
  -H "Authorization: Bearer $STUDIO_API_KEY"
```

### Example: set policy

```bash
curl -X PUT "$MJOLNIR_SERVER_URL/v1/policy/my-game" \
  -H "Authorization: Bearer $STUDIO_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "kick_threshold": 70,
    "ban_threshold": 90,
    "observe_only_default": false,
    "webhook_url": "https://game.example/internal/mjolnir-webhook",
    "known_bad_hashes": []
  }'
```

## Deploy

```bash
cd server
npm install
npx wrangler kv namespace create mjolnir-kv
# put the returned id into wrangler.jsonc
npx wrangler secret put INGEST_API_KEY
npx wrangler secret put STUDIO_API_KEY
npm run deploy
```

Local:

```bash
npm run dev
npm test
```

In development, auth is open when secrets are unset. Production requires both secrets.
