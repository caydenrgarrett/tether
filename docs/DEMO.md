# Five-minute demo

Run it from a laptop. Practise it twice.

## Setup (before the call)

```bash
python examples/review_demo.py ./demo-drive     # seeds sample agents, opens localhost:8700
```

Keep the landing page open in another tab.

## Script

**0:00 – The problem (30 s).** "Companies are starting to let AI agents touch
real files. When an agent goes wrong, from a bug or an instruction hidden in a
document, nobody can say what it read, what it changed or how to undo it."

**0:30 – The inbox (30 s).** Open the review app. "Every agent task gets its
own sandboxed copy of the files. Nothing it does touches the real files until
someone approves it. Here are three agents waiting on me."

**1:00 – The prompt injection (90 s).** Select `contract-summarizer`.

- Point at the red flag: "A contract had a hidden instruction to copy the
  payroll file into the report."
- Scroll to Activity: "It tried to read payroll and was blocked, because its
  policy only allows contracts. Then it tried to write a credential into the
  report, and that was blocked and flagged."
- Point at Approve: "I can't merge until I confirm I've reviewed the flag.
  Everything I do is in the same signed log."

**2:30 – The diff and the policy (45 s).** Scroll up to Changes and Access.
"Here's exactly what it changed. Here's what it was allowed to see: contracts
read-only, reports writable, nothing else."

**3:15 – Approve and roll back (45 s).** Tick the box and click Approve. Go to
History and click Restore on the previous version. "Every state of the files
is a version. Undo is one click, and the undo is recorded too."

**4:00 – Audit log (30 s).** Open Audit log and filter to Denied. "Every
entry is signed and chained to the one before it. If someone edits or deletes
an entry, the badge at the top turns red."

**4:30 – How it plugs in (30 s).** "It works with Claude Code and any MCP
agent in one command, or over an HTTP API for agents in containers. In Docker,
the agent can't even see the files or reach the internet."

**5:00 – Ask.** "What would stop you from using this next week?"
