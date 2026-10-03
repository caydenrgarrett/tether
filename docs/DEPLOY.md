# Deploying tether

## The rule that matters

**Agents get a URL and a token. Nothing else.** The machine or container that
runs your agents must not be able to read the drive, `.tether/` or the audit
key. Everything below exists to make that true.

## Docker (recommended)

```bash
cp .env.example .env            # set TETHER_ADMIN_PASSWORD
docker compose up -d tether agent-api
open http://localhost:8700      # sign in as the admin from .env
```

What runs:

| Service | Can reach | Exposed |
|---|---|---|
| `tether` (review app) | drive + key volumes | `127.0.0.1:8700` only |
| `agent-api` | drive + key volumes | internal `agents` network only |
| your agents | `agent-api` only | nothing; the network has no internet egress |

Give an agent a workspace and a token:

```bash
docker compose exec tether tether create --agent agent:reporter \
  --task "Weekly summary" --read 'data/**' --write 'reports/**'
docker compose exec tether tether token ws_...
TETHER_TOKEN=tth_... docker compose --profile agent run --rm agent   # the example agent
```

For your own agent, attach its container to the `agents` network and pass
`TETHER_URL=http://agent-api:8701` and `TETHER_TOKEN`. MCP agents can use
`tether mcp --url http://agent-api:8701 --token tth_...`.

To put files in the drive, copy them into the `drive` volume (for example
`docker compose cp ./myfiles/. tether:/data/drive/`). tether snapshots
out-of-band changes before every fork, merge and rollback.

## HTTPS

Either terminate TLS at a proxy (see `docker/Caddyfile`) and run
`tether serve --host 0.0.0.0 --allowed-host review.example.com --secure-cookies`,
or serve it directly with `--tls-cert cert.pem --tls-key key.pem`. The agent
API takes the same `--tls-cert` and `--tls-key` flags.

## People

```bash
tether user add alice --role reviewer     # viewer | reviewer | admin
tether user role alice admin
tether user passwd alice
tether user remove alice
```

Adding the first user switches the review app from local mode to team mode,
where everyone signs in. The app refuses to listen beyond localhost until a
user exists.

| Role | Can |
|---|---|
| viewer | see workspaces, diffs, history and the audit log |
| reviewer | + approve and discard workspaces |
| admin | + roll back versions |

## Alerts and audit export

```bash
tether notify add https://hooks.slack.com/services/... --event flag --event submit
tether notify add https://siem.example.com/hook --format json   # signed with HMAC-SHA256
tether notify test

tether log --format cef --since 1200 >> /var/log/tether.cef    # ship to your SIEM
```

## Protect the audit trail

- Keep the HMAC key off the drive: `TETHER_AUDIT_KEY_FILE=/keys/audit.key`
  (the Docker setup already does this).
- Anchor the head hash somewhere agents can't write, on a schedule:
  `tether verify | tail -1 >> /secure/anchors.log`. Later,
  `tether verify --expect-head <hash>` proves nothing was cut off the end.

## Backups

Back up the drive volume (it contains `.tether/`) and the key volume
separately. A restore without the key still has every file and version, but
the audit log can no longer be verified.
