# Security policy

tether is a security product, so we treat reports about it seriously.

## Reporting a vulnerability

Please don't open a public issue. Use GitHub's private vulnerability reporting
("Report a vulnerability" under the repository's Security tab). Include what
you found, how to reproduce it and what an attacker could do with it.

We aim to acknowledge reports within 3 business days and to ship a fix or
mitigation for confirmed high-severity issues within 30 days. We're happy to
credit you in the changelog.

## In scope

- Anything that lets an agent read, write or list a file its policy doesn't allow
- Escaping a workspace (path traversal, symlinks, the merge or rollback path)
- Forging, editing or silently deleting audit-log entries
- Bypassing sign-in, roles, CSRF or Host checks in the review app
- Using or forging agent tokens beyond their one workspace
- Getting a merge past a guardrail flag or a policy's auto-approve limits

## Known limits (not vulnerabilities)

These are documented trade-offs, listed in the README:

- In-process use, MCP over stdio and the CLI run with the caller's filesystem
  permissions. Hard isolation needs the HTTP API with agents in a separate
  container or OS user (see `docs/DEPLOY.md`).
- Truncating the tail of the audit log is only detected if you anchor the head
  hash elsewhere.
- Credential detection is pattern-based.
