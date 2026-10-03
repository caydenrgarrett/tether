"""Command-line interface.

    tether init [DIR]
    tether create --agent NAME [--read GLOB] [--write GLOB] [--deny GLOB] [--policy FILE] [--task TEXT]
    tether fork WS --agent NAME [...same policy flags]
    tether ls
    tether show WS
    tether files WS [PREFIX]          # what the agent can see
    tether cat WS PATH                # read as the agent
    tether put WS PATH [FILE]         # write as the agent (stdin if FILE omitted)
    tether rm WS PATH                 # delete as the agent
    tether diff WS
    tether merge WS [--reviewer NAME] [--allow-flagged]
    tether discard WS [--reason TEXT]
    tether history
    tether rollback VERSION
    tether log [--workspace WS] [--agent NAME] [--denied] [--json]
    tether verify [--expect-head HASH]
    tether serve [--port N] [--reviewer NAME]   # review web app

  Connecting agents:
    tether token WS                   # issue a bearer token for one workspace
    tether revoke WS                  # revoke all of its tokens
    tether agent-api [--host H] [--port N]
    tether mcp --workspace WS         # MCP server over stdio (or --url/--token for remote)
    tether submit WS [--note TEXT]    # agent is done; auto-merges if policy allows

  Maintenance:
    tether gc                         # delete unreferenced blobs
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys

from . import __version__
from .policy import Policy
from .workspace import Repo, TetherError, default_actor


def _repo(args) -> Repo:
    return Repo.find(args.root or os.environ.get("TETHER_ROOT"))


def _policy(args) -> Policy:
    if args.policy:
        with open(args.policy) as f:
            d = json.load(f)
    else:
        d = {"rules": [], "guardrails": {}}
    rules = d.setdefault("rules", [])
    for flag, access in (("read", "read"), ("write", "write"), ("deny", "none")):
        rules.extend({"path": g, "access": access} for g in getattr(args, flag) or [])
    g = d.setdefault("guardrails", {})
    if args.max_reads is not None:
        g["max_reads"] = args.max_reads
    if args.max_writes is not None:
        g["max_writes"] = args.max_writes
    if args.block_secret_reads:
        g["block_secret_reads"] = True
    if args.auto_approve:
        d["auto_approve"] = {"paths": args.auto_approve, "max_changes": args.auto_max_changes,
                             "allow_deletes": args.auto_allow_deletes}
    if not rules:
        raise TetherError("policy grants nothing; pass --read/--write globs or --policy FILE")
    return Policy.from_dict(d)


def _add_policy_flags(p):
    p.add_argument("--agent", required=True, help="agent identity recorded in the audit log")
    p.add_argument("--task", help="what the agent is doing (recorded in the audit log)")
    p.add_argument("--policy", help="JSON policy file")
    p.add_argument("--read", action="append", metavar="GLOB", help="grant read access (repeatable)")
    p.add_argument("--write", action="append", metavar="GLOB", help="grant read-write access (repeatable)")
    p.add_argument("--deny", action="append", metavar="GLOB", help="revoke access (repeatable, applied last)")
    p.add_argument("--max-reads", type=int)
    p.add_argument("--max-writes", type=int)
    p.add_argument("--block-secret-reads", action="store_true")
    p.add_argument("--auto-approve", action="append", metavar="GLOB",
                   help="merge on submit without review if every change is under these paths (repeatable)")
    p.add_argument("--auto-max-changes", type=int, help="auto-approve at most this many changed files")
    p.add_argument("--auto-allow-deletes", action="store_true", help="let auto-approve include deletes")


def _fmt_entry(e: dict) -> str:
    parts = [f"#{e['seq']}", e["ts"][:19].replace("T", " "), e["actor"], e["action"]]
    for key in ("workspace", "path", "version", "outcome"):
        if key in e:
            parts.append(f"{key}={e[key]}")
    if "reason" in e:
        parts.append(f"reason={e['reason']!r}")
    return "  ".join(str(p) for p in parts)


def cmd_init(args):
    repo = Repo.init(args.dir, actor=args.actor)
    print(f"initialized tether repository in {repo.root} (v{repo.head()}, "
          f"{len(repo.version(repo.head())['manifest'])} files)")


def cmd_create(args):
    ws = _repo(args).create_workspace(args.agent, _policy(args), task=args.task, actor=args.actor)
    print(ws.id)


def cmd_fork(args):
    ws = _repo(args).fork_workspace(args.workspace, args.agent, _policy(args), task=args.task, actor=args.actor)
    print(ws.id)


def cmd_ls(args):
    rows = [ws.state for ws in _repo(args).workspaces()]
    if not rows:
        print("no workspaces")
    for st in rows:
        flags = f"  flags={len(st['flags'])}" if st["flags"] else ""
        print(f"{st['id']}  {st['status']:<9}  agent={st['agent']}  base=v{st['base_version']}  "
              f"reads={st['counters']['reads']} writes={st['counters']['writes']}{flags}"
              + (f"  task={st['task']!r}" if st.get("task") else ""))


def cmd_show(args):
    st = dict(_repo(args).workspace(args.workspace).state)
    st["files"] = len(st.pop("manifest"))
    st["tokens"] = len(st.pop("token_hashes", []))
    print(json.dumps(st, indent=2))


def cmd_files(args):
    for p in _repo(args).workspace(args.workspace).list(args.prefix):
        print(p)


def cmd_cat(args):
    data = _repo(args).workspace(args.workspace).read(args.path)
    sys.stdout.buffer.write(data)


def cmd_put(args):
    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    else:
        data = sys.stdin.buffer.read()
    _repo(args).workspace(args.workspace).write(args.path, data)


def cmd_rm(args):
    _repo(args).workspace(args.workspace).delete(args.path)


def cmd_diff(args):
    ws = _repo(args).workspace(args.workspace)
    for f in ws.flags:
        print(f"!! flagged: {f['action']} {f.get('path') or ''}: {f['reason']}")
    text = ws.render_diff()
    print(text if text else "no changes")


def cmd_merge(args):
    n = _repo(args).merge(args.workspace, reviewer=args.reviewer or args.actor or default_actor(),
                          allow_flagged=args.allow_flagged)
    print(f"merged {args.workspace} as v{n}")


def cmd_discard(args):
    _repo(args).discard(args.workspace, actor=args.actor, reason=args.reason)
    print(f"discarded {args.workspace}")


def cmd_history(args):
    for v in _repo(args).history():
        extra = f"  approved_by={v['approved_by']}" if "approved_by" in v else ""
        print(f"v{v['version']}  {v['ts'][:19].replace('T', ' ')}  {v['actor']}  {v['message']}"
              f"  ({len(v['manifest'])} files){extra}")


def cmd_rollback(args):
    n = _repo(args).rollback(args.version, actor=args.actor)
    print(f"restored v{args.version} as v{n}")


def cmd_log(args):
    from .notify import to_cef

    entries = _repo(args).audit.entries(workspace=args.workspace, actor=args.agent)
    if args.denied:
        entries = [e for e in entries if e.get("outcome") == "denied"]
    if args.since is not None:
        entries = [e for e in entries if e["seq"] > args.since]
    fmt = "jsonl" if args.json else args.format
    for e in entries:
        if fmt == "jsonl":
            print(json.dumps(e, sort_keys=True))
        elif fmt == "cef":
            print(to_cef(e, __version__))
        else:
            print(_fmt_entry(e))


def cmd_notify(args):
    from .notify import Notifier

    repo = _repo(args)
    n = Notifier(repo.meta)
    if args.notify_cmd == "add":
        hook = n.add(args.url, args.event, args.format)
        repo.audit.append("notify_add", args.actor or default_actor(), url=args.url, events=hook["events"])
        print(f"added webhook {hook['id']} ({hook['format']}) for: {', '.join(hook['events'])}")
        if hook["format"] == "json":
            print(f"signing secret (verify X-Tether-Signature with it): {hook['secret']}")
    elif args.notify_cmd == "remove":
        n.remove(args.id)
        repo.audit.append("notify_remove", args.actor or default_actor(), webhook=args.id)
        print(f"removed webhook {args.id}")
    elif args.notify_cmd == "list":
        hooks = n.hooks()
        if not hooks:
            print("no webhooks")
        for h in hooks:
            print(f"{h['id']}  {h['format']:<5}  {h['url']}  [{', '.join(h['events'])}]")
    elif args.notify_cmd == "test":
        sample = {"seq": 0, "ts": "", "action": "submit", "actor": "agent:test", "workspace": "ws_000000000000",
                  "note": "Test notification from tether."}
        if not n.hooks():
            raise TetherError("no webhooks configured")
        n.dispatch(sample, wait=True)
        print("sent a test 'submit' event to every webhook that listens for it")


def cmd_verify(args):
    result = _repo(args).audit.verify(expect_head=args.expect_head)
    for p in result.problems:
        print(f"FAIL {p}")
    print(f"{'ok' if result.ok else 'TAMPERED'}: {result.entries} entries, head {result.head}")
    return 0 if result.ok else 1


def cmd_serve(args):
    from .server import make_server

    repo = _repo(args)
    reviewer = args.reviewer or args.actor or default_actor()
    server = make_server(str(repo.root), reviewer, host=args.host, port=args.port, allowed_hosts=args.allowed_host,
                         certfile=args.tls_cert, keyfile=args.tls_key,
                         secure_cookies=True if args.secure_cookies else None)
    host, port = server.server_address[:2]
    scheme = "https" if args.tls_cert else "http"
    print(f"tether review app for {repo.root}")
    print("team mode: everyone signs in" if server.team else f"local mode: reviewing as {reviewer}")
    print(f"open {scheme}://{'localhost' if host == '127.0.0.1' else host}:{port}/  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cmd_token(args):
    print(_repo(args).issue_token(args.workspace, actor=args.actor))


def cmd_revoke(args):
    n = _repo(args).revoke_tokens(args.workspace, actor=args.actor)
    print(f"revoked {n} token(s) for {args.workspace}")


def cmd_submit(args):
    r = _repo(args).workspace(args.workspace).submit(args.note)
    if r["status"] == "merged":
        print(f"auto-approved and merged as v{r['version']}")
    else:
        print(f"submitted for review ({r['reason']})")


def cmd_agent_api(args):
    from .agent_api import make_server

    repo = _repo(args)
    server = make_server(str(repo.root), host=args.host, port=args.port, max_body=args.max_body_mb * 1024 * 1024,
                         certfile=args.tls_cert, keyfile=args.tls_key)
    host, port = server.server_address[:2]
    scheme = "https" if args.tls_cert else "http"
    print(f"tether agent API for {repo.root} on {scheme}://{host}:{port}/v1  (ctrl-c to stop)")
    if host not in ("127.0.0.1", "localhost", "::1") and not args.tls_cert:
        print("warning: listening beyond localhost; put TLS in front of this", file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def cmd_mcp(args):
    from .mcp import MCPServer

    if args.workspace:
        backend = _repo(args).workspace(args.workspace)
    else:
        from .client import Client

        backend = Client(args.url, args.token)
    MCPServer(backend).serve()


def cmd_gc(args):
    r = _repo(args).gc(actor=args.actor)
    print(f"removed {r['removed']} unreferenced blob(s), freed {r['bytes']} bytes")


def _read_password(args) -> str:
    if args.password_stdin:
        return sys.stdin.readline().rstrip("\n")
    first = getpass.getpass("Password (12+ characters): ")
    if getpass.getpass("Repeat password: ") != first:
        raise TetherError("passwords don't match")
    return first


def cmd_user(args):
    from .users import UserStore

    repo = _repo(args)
    users = UserStore(repo.meta)
    actor = args.actor or default_actor()
    if args.user_cmd == "list":
        rows = users.list()
        if not rows:
            print("no users (the review app runs in local mode)")
        for u in rows:
            print(f"{u['name']:<24} {u['role']:<9} added {u['created'][:10]}")
        return
    if args.user_cmd == "add":
        users.add(args.name, _read_password(args), args.role)
        repo.audit.append("user_add", actor, user=args.name, role=args.role)
        print(f"added {args.name} ({args.role}); the review app now requires sign-in")
    elif args.user_cmd == "passwd":
        users.set_password(args.name, _read_password(args))
        repo.audit.append("user_passwd", actor, user=args.name)
        print(f"password changed for {args.name}")
    elif args.user_cmd == "role":
        users.set_role(args.name, args.role)
        repo.audit.append("user_role", actor, user=args.name, role=args.role)
        print(f"{args.name} is now {args.role}")
    elif args.user_cmd == "remove":
        users.remove(args.name)
        repo.audit.append("user_remove", actor, user=args.name)
        print(f"removed {args.name}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="tether", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"tether {__version__}")
    parser.add_argument("--root", help="repository directory (default: search upward, or $TETHER_ROOT)")
    parser.add_argument("--actor", help="who is running this command (default: $TETHER_USER or your username)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="start tracking a directory")
    p.add_argument("dir", nargs="?", default=".")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("create", help="fork the latest version into a workspace for an agent")
    _add_policy_flags(p)
    p.set_defaults(func=cmd_create)

    p = sub.add_parser("fork", help="fork an existing workspace (access is narrowed, never widened)")
    p.add_argument("workspace")
    _add_policy_flags(p)
    p.set_defaults(func=cmd_fork)

    sub.add_parser("ls", help="list workspaces").set_defaults(func=cmd_ls)

    p = sub.add_parser("show", help="show a workspace's state and policy")
    p.add_argument("workspace")
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("files", help="list files visible to the agent")
    p.add_argument("workspace")
    p.add_argument("prefix", nargs="?", default="")
    p.set_defaults(func=cmd_files)

    p = sub.add_parser("cat", help="read a file as the agent")
    p.add_argument("workspace")
    p.add_argument("path")
    p.set_defaults(func=cmd_cat)

    p = sub.add_parser("put", help="write a file as the agent")
    p.add_argument("workspace")
    p.add_argument("path")
    p.add_argument("file", nargs="?")
    p.set_defaults(func=cmd_put)

    p = sub.add_parser("rm", help="delete a file as the agent")
    p.add_argument("workspace")
    p.add_argument("path")
    p.set_defaults(func=cmd_rm)

    p = sub.add_parser("diff", help="review what the agent changed")
    p.add_argument("workspace")
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser("merge", help="approve and apply a workspace's changes")
    p.add_argument("workspace")
    p.add_argument("--reviewer")
    p.add_argument("--allow-flagged", action="store_true", help="merge even though guardrails flagged it")
    p.set_defaults(func=cmd_merge)

    p = sub.add_parser("discard", help="reject a workspace")
    p.add_argument("workspace")
    p.add_argument("--reason")
    p.set_defaults(func=cmd_discard)

    sub.add_parser("history", help="list versions").set_defaults(func=cmd_history)

    p = sub.add_parser("rollback", help="restore an earlier version")
    p.add_argument("version", type=int)
    p.set_defaults(func=cmd_rollback)

    p = sub.add_parser("log", help="show the audit log")
    p.add_argument("--workspace")
    p.add_argument("--agent")
    p.add_argument("--denied", action="store_true", help="only denied actions")
    p.add_argument("--json", action="store_true", help="same as --format jsonl")
    p.add_argument("--format", choices=["text", "jsonl", "cef"], default="text",
                   help="jsonl or cef (ArcSight Common Event Format) to feed a SIEM")
    p.add_argument("--since", type=int, metavar="SEQ", help="only entries after this sequence number")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("notify", help="send Slack or webhook alerts on flags, submissions and merges")
    ns = p.add_subparsers(dest="notify_cmd", required=True)
    q = ns.add_parser("add", help="add a webhook (Slack incoming-webhook URL or any HTTPS endpoint)")
    q.add_argument("url")
    q.add_argument("--event", action="append", choices=["flag", "submit", "merge", "discard", "rollback", "login_failed"],
                   help="only these events (repeatable; default: all)")
    q.add_argument("--format", choices=["slack", "json"], default="slack")
    q = ns.add_parser("remove", help="remove a webhook")
    q.add_argument("id")
    ns.add_parser("list", help="list webhooks")
    ns.add_parser("test", help="send a test event")
    p.set_defaults(func=cmd_notify)

    p = sub.add_parser("verify", help="check the audit log for tampering")
    p.add_argument("--expect-head", help="head hash recorded earlier, to detect truncation")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("token", help="issue a bearer token for an agent's workspace (shown once)")
    p.add_argument("workspace")
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("revoke", help="revoke all tokens for a workspace")
    p.add_argument("workspace")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("submit", help="mark a workspace done (as the agent); auto-merges if policy allows")
    p.add_argument("workspace")
    p.add_argument("--note")
    p.set_defaults(func=cmd_submit)

    p = sub.add_parser("agent-api", help="serve the token-authenticated HTTP API for agents")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8701)
    p.add_argument("--max-body-mb", type=int, default=64)
    p.add_argument("--tls-cert", help="PEM certificate to serve HTTPS")
    p.add_argument("--tls-key", help="PEM private key for --tls-cert")
    p.set_defaults(func=cmd_agent_api)

    p = sub.add_parser("mcp", help="run an MCP server over stdio for one workspace")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--workspace", help="local workspace id")
    g.add_argument("--url", help="agent API base URL (token from --token or $TETHER_TOKEN)")
    p.add_argument("--token")
    p.set_defaults(func=cmd_mcp)

    sub.add_parser("gc", help="delete blobs nothing refers to").set_defaults(func=cmd_gc)

    p = sub.add_parser("serve", help="open the review web app")
    p.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    p.add_argument("--port", type=int, default=8700)
    p.add_argument("--reviewer", help="identity for approvals in local mode (default: --actor)")
    p.add_argument("--allowed-host", action="append", metavar="HOST[:PORT]",
                   help="public hostname the app is reached at, e.g. behind a reverse proxy (repeatable)")
    p.add_argument("--tls-cert", help="PEM certificate to serve HTTPS")
    p.add_argument("--tls-key", help="PEM private key for --tls-cert")
    p.add_argument("--secure-cookies", action="store_true", help="mark cookies Secure (when TLS ends at a proxy)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("user", help="manage review-app accounts (adding one turns on sign-in)")
    us = p.add_subparsers(dest="user_cmd", required=True)
    q = us.add_parser("add", help="add a user")
    q.add_argument("name")
    q.add_argument("--role", choices=["viewer", "reviewer", "admin"], default="reviewer")
    q.add_argument("--password-stdin", action="store_true", help="read the password from stdin")
    q = us.add_parser("passwd", help="change a user's password")
    q.add_argument("name")
    q.add_argument("--password-stdin", action="store_true")
    q = us.add_parser("role", help="change a user's role")
    q.add_argument("name")
    q.add_argument("role", choices=["viewer", "reviewer", "admin"])
    q = us.add_parser("remove", help="remove a user")
    q.add_argument("name")
    us.add_parser("list", help="list users")
    p.set_defaults(func=cmd_user)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args) or 0
    except (TetherError, PermissionError, FileNotFoundError, ValueError) as e:
        print(f"tether: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
