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
"""

from __future__ import annotations

import argparse
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
    entries = _repo(args).audit.entries(workspace=args.workspace, actor=args.agent)
    if args.denied:
        entries = [e for e in entries if e.get("outcome") == "denied"]
    for e in entries:
        print(json.dumps(e, sort_keys=True) if args.json else _fmt_entry(e))


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
    server = make_server(str(repo.root), reviewer, host=args.host, port=args.port)
    host, port = server.server_address[:2]
    print(f"tether review app for {repo.root}")
    print(f"reviewing as {reviewer}")
    print(f"open http://{'localhost' if host == '127.0.0.1' else host}:{port}/  (ctrl-c to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


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
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_log)

    p = sub.add_parser("verify", help="check the audit log for tampering")
    p.add_argument("--expect-head", help="head hash recorded earlier, to detect truncation")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("serve", help="open the review web app")
    p.add_argument("--host", default="127.0.0.1", help="interface to bind (default: localhost only)")
    p.add_argument("--port", type=int, default=8700)
    p.add_argument("--reviewer", help="identity recorded for approvals (default: --actor)")
    p.set_defaults(func=cmd_serve)
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
