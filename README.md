# tether

Versioned, sandboxed, forkable file workspaces for AI agents, with per-agent
permissions and a tamper-evident audit log of everything an agent reads or changes.

Instead of pointing an agent at real files, you give it a **workspace**:

1. **Fork on start.** The agent gets a copy-on-write fork of the latest version. The originals are untouched.
2. **Scoped access.** Each agent and task gets its own policy, for example read-only on `contracts/**`, read-write on `reports/**`, nothing else. Files it can't read don't appear in its listings at all.
3. **Everything is logged.** Every read, write, delete, and denied attempt goes into an append-only, hash-chained, HMAC-signed log.
4. **Review before merge.** A human sees the diff. Approving it applies the changes to the real files as a new version. Rejecting it discards the fork.
5. **Rollback.** Every state is a version, and any version can be restored. A rollback is recorded as a new version, so history is never erased.
6. **Guardrails.** Writes containing credentials are blocked, read and write budgets are enforced, and violations flag the workspace so it can't be merged without someone signing off.

It ships as a Python library, a CLI, an MCP server, an HTTP API for agents and a review web app with team sign-in. There are no dependencies outside the standard library.

**Docs:** [Deploying](docs/DEPLOY.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md) · [Roadmap](docs/ROADMAP.md) · [Design](docs/DESIGN.md) · [Demo script](docs/DEMO.md) · [Interview guide](docs/INTERVIEWS.md)

## Quick start

Requires Python 3.10+ on Linux or macOS.

```bash
pip install git+https://github.com/caydenrgarrett/tether   # or, from a checkout: pip install -e .
python examples/demo.py     # the full scenario below, end to end
python -m unittest discover -s tests -t .
```

```bash
cd company-drive
tether init

# Give an agent a workspace
WS=$(tether create --agent agent:summarizer --task "summarize contracts" \
       --read 'contracts/**' --write 'reports/**' --max-reads 500)

# The agent works through the API (or these commands)
tether files $WS                              # only what it may read
tether cat   $WS contracts/acme.txt
echo "..." | tether put $WS reports/summary.md
tether cat   $WS finance/payroll.csv          # denied, and logged

# A human reviews it
tether diff  $WS
tether merge $WS --reviewer user:bob          # or: tether discard $WS --reason "..."

# Afterwards
tether history
tether rollback 0
tether log --workspace $WS
tether log --denied
tether verify                                 # exits 1 if the log was tampered with
tether serve                                  # the review web app
tether gc                                     # delete blobs nothing refers to
```

From Python, which is how an agent harness would use it:

```python
from tether import Repo, AccessDenied

repo = Repo.find("company-drive")
ws = repo.create_workspace(
    agent="agent:summarizer",
    task="summarize contracts",
    policy={
        "rules": [
            {"path": "contracts/**", "access": "read"},
            {"path": "reports/**",   "access": "write"},
        ],
        "guardrails": {"block_secrets": True, "max_reads": 500},
    },
)

# Expose these as the agent's file tools:
ws.list("contracts/")
ws.read_text("contracts/acme.txt")
ws.write("reports/summary.md", "...")

print(ws.render_diff())
repo.merge(ws.id, reviewer="user:bob")
```

## Run it in Docker

The isolated setup: agents get only an API URL and a token, on a network with no access to the files, the audit key or the internet.

```bash
cp .env.example .env              # set the first admin's password
docker compose up -d tether agent-api
open http://localhost:8700        # sign in
```

See [docs/DEPLOY.md](docs/DEPLOY.md) for HTTPS, users, alerts and backups.

## Connecting agents

There are three ways to connect an agent. Pick whichever fits how it runs.

### 1. MCP: Claude Code, Claude Desktop and other MCP clients

```bash
WS=$(tether create --agent agent:claude --task "summarize contracts" --read 'contracts/**' --write 'reports/**')
claude mcp add tether -- tether --root /path/to/drive mcp --workspace $WS
```

Or put it in any MCP client config:

```json
{"mcpServers": {"tether": {"command": "tether", "args": ["--root", "/path/to/drive", "mcp", "--workspace", "ws_..."]}}}
```

The agent gets seven tools: `list_files`, `read_file`, `write_file`, `delete_file`, `show_changes`, `workspace_info` and `submit_for_review`. Every call goes through the workspace's policy, guardrails and audit log. A denied call comes back to the agent as a tool error, so it knows to stop rather than retry. The server also tells the agent to ignore instructions it finds inside file contents.

For the strongest isolation, turn off the agent's own file and shell tools so these are its only access. With Claude Code that means `--disallowedTools "Bash,Read,Write,Edit,Glob,Grep"`.

### 2. HTTP API: agents in containers or on other machines

```bash
tether agent-api --port 8701           # add --host 0.0.0.0 behind a TLS proxy
tether token $WS                        # prints tth_..., shown once
```

| Method | Path | |
|---|---|---|
| `GET` | `/v1/workspace` | workspace info and policy |
| `GET` | `/v1/files?prefix=P` | files the agent may read |
| `GET` / `PUT` / `DELETE` | `/v1/files/<path>` | read, write (raw body), delete |
| `GET` | `/v1/changes` | changed files and a unified diff |
| `POST` | `/v1/submit` | `{"note": "..."}`. Done; merges at once if auto-approve allows. |

Every request needs `Authorization: Bearer tth_...`. A token is bound to exactly one workspace. Only its SHA-256 hash is stored. It's revoked automatically when the workspace is merged or discarded, and `tether revoke $WS` revokes it earlier. Requests with a bad token get a 401 and are logged. The agent never sees the real files or `.tether/`.

To run an MCP agent against a remote API, use `tether mcp --url https://host:8701 --token tth_...`.

### 3. Python

```python
from tether.client import Client           # remote, over HTTP
ws = Client("http://127.0.0.1:8701", token)

# or, in-process:  ws = Repo.find("drive").workspace("ws_...")

ws.list("contracts/"); ws.read_text("contracts/acme.txt")
ws.write("reports/summary.md", "...")
ws.submit("summary ready")   # {"status": "merged", ...} or {"status": "awaiting_review", "reason": ...}
```

`Client` and `Workspace` have the same methods, so agent code doesn't change between local and remote.

## Auto-approve

Some changes are low-risk enough that a person shouldn't have to click approve. A policy can say which ones:

```json
"auto_approve": {"paths": ["reports/**"], "max_changes": 5, "allow_deletes": false}
```

```bash
tether create --agent agent:reporter --read 'data/**' --write 'reports/**' \
              --auto-approve 'reports/**' --auto-max-changes 5
```

When the agent submits, tether merges it right away as `policy:auto-approve` if all of these hold:

- every changed file is under one of the `paths`
- the number of changed files is within `max_changes`
- there are no deletes, unless `allow_deletes` is set
- the workspace has no guardrail flags
- nothing conflicts with edits made to the real files since the fork

If any check fails, the workspace waits for a human, and the reason is returned to the agent and written to the audit log. **A forked sub-agent can't grant itself auto-approval**, because every policy in the fork chain must allow the change.

## Review app

```bash
tether serve                       # http://localhost:8700, reviewing as $TETHER_USER
python examples/review_demo.py     # seeds a sample drive with agent workspaces, then serves it
```

The web app is the reviewer's side of the product:

- **Review.** It lists every agent workspace, with flagged ones selected first. For each one you see its unified diff, guardrail flags, denied attempts, access policy (including inherited layers for forks), and everything the agent did. **Approve & merge** stays disabled until you confirm you've reviewed any flags. **Discard** takes an optional reason, which goes into the audit log.
- **History.** Every version of the real files, showing who approved what. You can restore any version.
- **Activity.** The full audit log, with a filter for denied actions only. The header badge re-verifies the log's hash chain every 15 seconds.
- **Search.** Press ⌘K (or `/`) to jump to any workspace, agent or page.

The design follows `docs/DESIGN.md`. It bundles the Geist typeface (SIL Open Font License, in `tether/static/fonts/`), so it works offline and makes no third-party requests.

The app runs as one reviewer identity and listens on 127.0.0.1 only. Since it can change real files:

- Requests with an unexpected `Host` header are rejected, which blocks DNS rebinding.
- Every state-changing request needs a per-process token that only the served page has, which blocks cross-site requests.
- The page sends a strict Content-Security-Policy.
- Content from agents, such as diffs, paths, and reasons, is treated as untrusted. It's always rendered as text, never as HTML, because it can carry prompt-injection payloads.

## Teams, alerts and audit export

```bash
tether user add alice --role reviewer        # viewer | reviewer | admin; turns on sign-in
tether serve --tls-cert cert.pem --tls-key key.pem --host 0.0.0.0 --allowed-host review.example.com

tether notify add https://hooks.slack.com/services/...   # flags, submissions, merges, failed sign-ins
tether log --format cef --since 1200                     # or jsonl, for your SIEM
```

- **Roles are enforced on the server.** Viewers can only look, reviewers can approve and discard, and admins can also roll back.
- **Sessions are protected:**
  - HttpOnly, SameSite=Strict cookies, each with its own CSRF token
  - five failed sign-ins lock that account and address for 15 minutes
  - every sign-in is audited
- **Never exposed without sign-in.** The app refuses to listen beyond localhost until at least one user exists.
- **Webhooks:**
  - Slack messages escape agent-supplied text, so an agent can't @-mention your channel.
  - JSON webhooks are signed with HMAC-SHA256 in `X-Tether-Signature`.

## Policies

Access is **deny by default**, and the **last matching rule wins**, so you can grant broadly and then carve out exceptions:

```json
{
  "rules": [
    {"path": "**",           "access": "read"},
    {"path": "secrets/**",   "access": "none"},
    {"path": "**/*.env",     "access": "none"},
    {"path": "reports/**",   "access": "write"}
  ],
  "guardrails": {
    "block_secrets": true,
    "block_secret_reads": false,
    "max_reads": 500,
    "max_writes": 100,
    "max_file_bytes": 10485760
  }
}
```

Access levels are `none`, `read`, and `write` (which includes read). In globs, `*` and `?` don't cross `/`, and `**` matches any depth. Pass a policy file with `tether create --policy policy.json`, or build one from `--read`, `--write`, and `--deny` flags.

**Forks narrow access and never widen it.** `tether fork WS --agent agent:helper ...` (or `repo.fork_workspace`) creates a child workspace for a sub-agent. The child's access to any path is the minimum across every policy in its chain, so a sub-agent can't get access its parent didn't have.

## Guardrails and flags

| Guardrail | What happens |
|---|---|
| `block_secrets` (on by default) | A write containing a private key, AWS, GitHub, Anthropic, OpenAI, Slack, Stripe, or Google key, or a `password=...`-style assignment, is refused. |
| `block_secret_reads` | A read of a file containing credentials is refused. |
| `max_reads`, `max_writes` | Operations past the budget are refused. |
| `max_file_bytes` | Oversized writes are refused. |
| Path escapes | `../`, absolute paths, and `.tether/` are refused. |

Each of these refusals also **flags** the workspace, because they look like an agent going off-script, for example after a prompt injection. A flagged workspace can't be merged until a reviewer passes `--allow-flagged`, and that override is itself logged. Plain policy denials are logged without flagging.

## Merge safety

- **No self-approval.** The reviewer must be a different identity from the agent.
- **Line-level merging.** If someone edited a text file on disk after the fork and the agent also changed it, edits to different parts of the file are merged line by line, the way git does. Overlapping edits, binary files and edit-versus-delete are refused as conflicts, with the paths listed. Edits to different files always merge.
- **Out-of-band edits are preserved.** The directory is snapshotted before every fork, merge, and rollback, so direct human edits become versions and are never silently overwritten.
- **No writing through symlinks.** A merge will not follow a symlink out of the tracked directory.

## Audit log

`.tether/audit.log` holds one JSON line per event:

```json
{"seq":7,"ts":"2026-10-02T23:59:01.123456+00:00","action":"read","actor":"agent:summarizer",
 "workspace":"ws_4227a05ecfc4","path":"finance/payroll.csv","outcome":"denied",
 "reason":"policy grants 'none', needs 'read'","severity":"warning",
 "prev":"<hash of entry 6>","hash":"<HMAC-SHA256 of this entry>"}
```

Allowed reads record the SHA-256 of exactly what the agent saw. Writes record the before and after hashes, so any change can be traced to its content.

`tether verify` recomputes the chain and reports any entry that was edited, reordered, or deleted. Cutting entries off the end leaves a chain that is still valid internally. To catch that, record `tether verify`'s head hash somewhere the agent can't write, such as a ticket, an external log service, or a signed commit, and later run `tether verify --expect-head <hash>`.

## Architecture

```
company-drive/                 the real files (agents never touch these directly)
└── .tether/
    ├── objects/ab/cdef…       content-addressed blobs (SHA-256), read-only, verified on read
    ├── versions/00000003.json version = manifest {path: sha256} + who/why/approved_by
    ├── workspaces/ws_….json   fork state: agent, policy chain, manifest, counters, flags, status
    ├── audit.log              hash-chained, HMAC-signed JSONL
    ├── audit.key              HMAC key (prototype only; see below)
    └── lock                   flock for repository-wide operations
```

- **Copy-on-write.** A workspace is a dict of path to content hash. Forking copies that dict and no file data. A write stores one new blob and repoints one entry.
- **Versions.** Each version is a full manifest. Diffs, merges, and rollbacks are manifest comparisons, and only changed files are written to disk.
- **Entry points.** The Python library, CLI, MCP server and HTTP API all call the same `Workspace` methods, so a policy is enforced identically everywhere.
- **Enforcement point.** Every agent operation goes through `Workspace`. It normalizes the path, evaluates the policy chain, applies guardrails, performs the operation, and writes the audit entry. Denials are logged before the error is raised.

## Deployment notes

- **Isolate agents from the files.** Run `tether agent-api` as a dedicated OS user that owns the drive and `.tether/`. Run agents somewhere else, such as a container, another user or another machine, with only the URL and a token. The API is then the only path to the files.
- **Keep the audit key away from agents.** Set `TETHER_AUDIT_KEY_FILE` to a path outside the drive that only the tether user can read. In production, keep it in a KMS or a separate signing service.
- **Anchor the audit head.** Copy `tether verify`'s head hash somewhere agents can't write, on a schedule, so a truncated log can be detected.
- **Garbage collection.** `tether gc` deletes stored content that nothing points to any more, typically drafts an agent overwrote before finishing. Their hashes stay in the audit log, but the bytes don't, so skip `gc` if you need to keep every intermediate draft for forensics.

## Known limitations

- **The sandbox is the API, not the OS.** In-process use, MCP over stdio and the CLI run with your own filesystem permissions. Hard isolation needs the HTTP API with agents running as a different user or in a container, as described under deployment notes.
- **No mounted drive.** There's no FUSE mount or WebDAV yet; agents use the API or the CLI.
- **Sessions live in memory.** Restarting the review app signs everyone out, and it runs as a single process.
- **Single-machine storage.** Concurrency comes from `flock`, and storage is a local directory instead of S3 or Postgres.
- **Regex secret scanning.** It will miss some credentials and flag some false positives.
- **Whole files in memory.** Reads and writes hold a file in memory, and the agent API caps bodies at 64 MB by default. It isn't built for multi-GB media yet.
- **No SSO.** Accounts are local to each tether install. See the [roadmap](docs/ROADMAP.md).

## Customer discovery

The interview script is in [docs/INTERVIEWS.md](docs/INTERVIEWS.md), and the five-minute demo is in [docs/DEMO.md](docs/DEMO.md).
