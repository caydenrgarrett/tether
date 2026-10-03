# Customer interview guide

**Goal:** find out whether people who run agents feel enough pain about file
access to change how they work, and who would pay. You're learning, not
selling. Show the product only in the last ten minutes, if at all.

**Who to talk to (aim for 15–20):**

- Engineers who run agents against real files or data at work (coding agents
  count, but look for non-code files: docs, spreadsheets, contracts, tickets)
- Security, IT or compliance people at companies starting to allow agents
- Founders of small AI-agent startups whose customers ask about safety
- Ops or finance leads whose teams use agents on shared drives

Where to find them: your CySA+ and school network, LinkedIn searches for
"AI agents" + "security", agent-builder Discords and Slack communities, local
AI meetups, and people who post about MCP servers.

## Before the call

- 30 minutes, video if possible. Ask permission to take notes.
- Write down the one thing you most want to learn from this person.

## Script

**1. Context (5 min)**

- What do you do, and where do AI agents show up in your work today?
- Which agents, and what can they touch? Files, drives, repos, databases, SaaS apps?
- Who decided what they're allowed to access? How?

**2. The last bad moment (10 min).** Stories beat opinions. Dig into one.

- Tell me about the last time an agent did something you didn't expect with a file or data.
- What happened? How did you find out? How long did it take?
- How did you work out what it had touched? How did you undo it?
- What did it cost you: time, trust, a customer, an incident ticket?
- If it hasn't happened: what's stopping you from giving agents more access today?

**3. Current workaround (5 min)**

- What do you do today to keep agents safe? (Separate folders, git, copies, manual review, nothing?)
- What's annoying about that?
- Have you looked for a tool for this? What did you find, and why didn't you use it?

**4. Priorities (5 min).** Ask them to rank these, don't pitch them.

- Seeing exactly what an agent read and changed
- Undoing an agent's changes
- Limiting what an agent can see in the first place
- Approving changes before they land
- Proving to someone else (security, an auditor, a customer) what happened

**5. Buying (3 min)**

- If this were solved, who at your company would care most? Who signs off on tools like this?
- Have you paid for anything in this space? How much?

**6. Optional demo (5–10 min).** Only if they've described the pain. Follow
`docs/DEMO.md`, then ask "What would stop you from using this next week?"

**Close.** "Who else should I talk to about this?" Ask for two intros.

## Don't

- Don't ask "would you use this?" Everyone says yes.
- Don't explain the product before you've heard their story.
- Don't argue with an answer. Write it down.

## After each call (5 min)

Fill one row in a sheet:

| Name | Role | Company size | Agents used | Last bad moment (1 line) | Pain 1–5 | Top priority | Current workaround | Who pays | Wants a follow-up? | Intros |
|---|---|---|---|---|---|---|---|---|---|---|

## What a "yes, keep going" looks like after 15 calls

- At least 5 people describe a specific incident without being prompted, and rate the pain 4 or 5.
- The same top priority shows up in most of those 5.
- At least 3 ask to try it, or ask when they can.
- At least one says who would pay and roughly how much.

If you don't see this, change the angle (a different buyer, a different
priority) before writing more code.
