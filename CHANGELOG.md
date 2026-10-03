# Changelog

## 0.2.0

- **Team mode for the review app.** Accounts with viewer, reviewer and admin
  roles; scrypt password hashes; HttpOnly SameSite=Strict sessions with CSRF
  tokens; lockout after repeated failed sign-ins; every sign-in audited.
- **HTTPS** on both servers (`--tls-cert`, `--tls-key`), `--allowed-host` for
  reverse proxies, Secure cookies and HSTS under TLS.
- **Line-level merging.** Agent and human edits to different parts of the same
  text file merge instead of conflicting.
- **Notifications.** `tether notify` sends Slack messages or signed JSON
  webhooks on flags, submissions, merges, discards, rollbacks and failed
  sign-ins.
- **SIEM export.** `tether log --format cef|jsonl --since SEQ`.
- **Docker deployment** with agents isolated on an internal network that has no
  access to the files, the audit key or the internet.
- Redesigned review app with a command palette, plus a landing page.

## 0.1.0

- Copy-on-write workspaces, per-agent policies, guardrails, signed audit log,
  review and merge, versions and rollback.
- Agent tokens, HTTP API, Python client, MCP server, submit and auto-approve.
