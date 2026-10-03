# Roadmap

What's built is in the CHANGELOG. This is what comes next, ordered by what
customer interviews are most likely to ask for. Re-order it after the
interviews.

## Next

- **Hosted tether.** A managed review app and agent API with sign-in, so teams
  don't run servers. Per-organisation storage and keys.
- **Single sign-on.** Google and Microsoft sign-in, SCIM user provisioning.
- **Approval rules.** Require two approvers for some paths. Route approvals to
  code owners per folder. Approve from Slack.
- **Content-aware guardrails.** Classify files (PII, financial, legal) and
  write policies against labels, not just paths. Block reads of PII by default.

## Later

- **Mounted drive.** Expose a workspace as a filesystem (FUSE or WebDAV) for
  agents and tools that only speak files.
- **Cloud storage backends.** S3, Google Drive, SharePoint and Box as the
  source of truth, with tether as the governed layer in front.
- **Large files.** Streaming reads and writes, chunked storage and
  deduplication for multi-GB media.
- **Compliance reports.** Exportable evidence for SOC 2 and ISO 27001 audits
  ("every change to finance files in Q3, with approver").
- **External audit anchoring.** Publish log heads to a transparency log or
  object-lock storage automatically.

## Known gaps today

See "Known limitations" in the README.
