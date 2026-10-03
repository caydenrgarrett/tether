"""A minimal remote agent: it only knows TETHER_URL and TETHER_TOKEN.

It lists what it may read, writes a summary and submits it for review.
Swap the body for your real agent loop (or point an MCP client at
`tether mcp --url $TETHER_URL --token $TETHER_TOKEN`).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tether import AccessDenied  # noqa: E402
from tether.client import Client  # noqa: E402

ws = Client()  # reads TETHER_URL and TETHER_TOKEN
info = ws.info()
print(f"agent {info['agent']} working on: {info.get('task') or 'no task'}")
files = ws.list()
print(f"can see {len(files)} file(s)")
lines = [f"- {p} ({len(ws.read(p))} bytes)" for p in files[:50]]
try:
    ws.write("out/inventory.md", "# Inventory\n\n" + "\n".join(lines) + "\n")
except AccessDenied as e:
    print(f"write refused: {e}")
print(ws.submit(f"Listed {len(files)} files."))
