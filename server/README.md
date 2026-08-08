# Mjölnir Server (self-hosted)

Own control-plane API for **game studios**. No Cloudflare dependency.

Runs as a Rust binary (`mjolnir_server`) with JSON file persistence under `data/`.

## Responsibilities

* Accept authenticated evidence from client agents
* Keep per-player sessions
* Score batches into `observe` / `challenge` / `kick` / `ban`
* Expose decisions for the game backend to poll
* Optional webhooks when action != observe
* Store per-game policy (thresholds, known-bad hashes, webhook URL)

Detection stays on the client. This server only decides.

## API

| Method | Path | Auth | Who |
| --- | --- | --- | --- |
| `GET` | `/health` | none | ops |
| `POST` | `/v1/sessions` | ingest | client agent |
| `POST` | `/v1/ingest` | ingest | client agent |
| `POST` | `/v1/challenges/:session_id` | studio | game backend (live nonce) |
| `POST` | `/v1/challenge-response` | ingest | client agent (echo nonce) |
| `GET` | `/v1/decisions/:session_id` | studio | game backend |
| `GET` | `/v1/policy/:game_id` | studio | studio tools |
| `PUT` | `/v1/policy/:game_id` | studio | studio tools |

## Run

```bash
cd server
cargo run --release
```

Default bind: `http://0.0.0.0:8787`

### Environment

| Variable | Purpose |
| --- | --- |
| `MJOLNIR_BIND` | Listen address (default `0.0.0.0:8787`) |
| `MJOLNIR_DATA_DIR` | Persistence directory (default `data`) |
| `MJOLNIR_ENV` | `development` (open auth if keys unset) or `production` |
| `MJOLNIR_INGEST_API_KEY` | Bearer key for client agents |
| `MJOLNIR_STUDIO_API_KEY` | Bearer key for game backends |
| `DEFAULT_KICK_THRESHOLD` | Default `70` |
| `DEFAULT_BAN_THRESHOLD` | Default `90` |

In `production`, both API keys are required.

### Example

```bash
export MJOLNIR_INGEST_API_KEY=ingest-secret
export MJOLNIR_STUDIO_API_KEY=studio-secret
cargo run --release

# client session
curl -X POST http://127.0.0.1:8787/v1/sessions \
  -H "Authorization: Bearer ingest-secret" \
  -H "Content-Type: application/json" \
  -d '{"game_id":"my-game","player_id":"user-42"}'

# studio decision poll
curl http://127.0.0.1:8787/v1/decisions/$SESSION_ID \
  -H "Authorization: Bearer studio-secret"
```

## Tests

```bash
cargo test
```

## Client forward

Point the player agent at this host:

```bat
set MJOLNIR_SERVER_URL=http://your-server:8787
set MJOLNIR_INGEST_API_KEY=ingest-secret
set MJOLNIR_GAME_ID=my-game
set MJOLNIR_PLAYER_ID=user-42
```

## Linux local service (systemd --user)

On your Linux machine, install so the server starts at login and optionally auto-updates from `main`:

```bash
git clone https://github.com/nulli83/Mj-lnir.git
cd Mj-lnir
./scripts/install-linux-service.sh
```

This installs:

* `~/.config/systemd/user/mjolnir-update.service` — `git pull` + `cargo build --release` on login
* `~/.config/systemd/user/mjolnir-server.service` — runs `mjolnir_server`
* `~/.config/mjolnir/server.env` — edit API keys here
* binary at `~/.local/share/mjolnir/bin/mjolnir_server`

Useful commands:

```bash
curl http://127.0.0.1:8787/health
systemctl --user status mjolnir-server.service
journalctl --user -u mjolnir-server.service -f
~/.local/share/mjolnir/bin/mjolnir-update.sh
```

Server only (no auto-update on login):

```bash
./scripts/install-linux-service.sh --no-auto-update
```
