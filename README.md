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

This is the step-1 prototype: a Python library plus CLI with no dependencies outside the standard library, and no FUSE or mounted drive yet.

## Quick start

Requires Python 3.10+ on Linux or macOS.

```bash
pip install -e .            # or run with: python -m tether ...
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

## Review app

```bash
tether serve                       # http://localhost:8700, reviewing as $TETHER_USER
python examples/review_demo.py     # seeds a sample drive with agent workspaces, then serves it
```

The web app is the reviewer's side of the product:

- **Review.** It lists every agent workspace, with flagged ones selected first. For each one you see its unified diff, guardrail flags, denied attempts, access policy (including inherited layers for forks), and everything the agent did. **Approve & merge** stays disabled until you confirm you've reviewed any flags. **Discard** takes an optional reason, which goes into the audit log.
- **History.** Every version of the real files, showing who approved what. You can restore any version.
- **Activity.** The full audit log, with a filter for denied actions only. The header badge re-verifies the log's hash chain every 15 seconds.

The app runs as one reviewer identity and listens on 127.0.0.1 only. Since it can change real files:

- Requests with an unexpected `Host` header are rejected, which blocks DNS rebinding.
- Every state-changing request needs a per-process token that only the served page has, which blocks cross-site requests.
- The page sends a strict Content-Security-Policy.
- Content from agents, such as diffs, paths, and reasons, is treated as untrusted. It's always rendered as text, never as HTML, because it can carry prompt-injection payloads.

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
- **Conflict detection.** If someone edited a file on disk after the fork and the agent also changed it, the merge is refused and lists the paths. Edits that don't overlap merge cleanly.
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
- **Enforcement point.** Every agent operation goes through `Workspace`. It normalizes the path, evaluates the policy chain, applies guardrails, performs the operation, and writes the audit entry. Denials are logged before the error is raised.

## Known limitations of the prototype

- **The agent runs with your filesystem permissions.** The sandbox is the API, not the OS. That's fine when the harness only gives the agent the workspace tools, but not if the agent has a shell on the same machine. Next steps are to run the service as a separate user or behind an HTTP API, and to move `audit.key` into a KMS or a separate log service.
- **No mounted drive.** There's no FUSE mount or WebDAV yet; agents use the API or the CLI.
- **One reviewer, one machine.** The review app has no logins or roles yet; it acts as whoever started it.
- **Single-machine storage.** Concurrency comes from `flock`, and storage is a local directory instead of S3 or Postgres.
- **Regex secret scanning.** It will miss some credentials and flag some false positives.
- **Simple merge model.** Conflicts are detected per file, with no line-level three-way merge.

## Interview questions this prototype should help answer

- What would you need to see before letting an agent edit real company files?
- When an agent did something wrong, how did you find out, and how long did it take to undo?
- Who should approve agent changes: a person, a policy, or nobody below some risk level?
- Would you run this as a library in your agent harness, a hosted API, or a mounted drive?
