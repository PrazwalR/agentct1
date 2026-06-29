"""Bridge to the TypeScript agentctl engine via the `agentctl eval` JSON command.

Keeps a single decision engine (the TS core) instead of reimplementing policy,
behavioral, and intent logic in Python. Requires Node.js and the built CLI.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def _node_bin() -> str:
    return os.environ.get("NODE_BIN") or shutil.which("node") or "node"


def _cli_path() -> str:
    """Locate packages/cli/dist/cli.js (override with AGENTCTL_CLI)."""
    override = os.environ.get("AGENTCTL_CLI")
    if override:
        return override
    here = Path(__file__).resolve()
    # packages/python/agentctl/_bridge.py -> repo root is parents[3]
    return str(here.parents[3] / "packages" / "cli" / "dist" / "cli.js")


def evaluate_via_bridge(policy: dict, request: dict) -> dict:
    """Run the TS engine's evaluate() for one payment, returning the decision dict."""
    payload = json.dumps({"policy": policy, "request": request})
    proc = subprocess.run(
        [_node_bin(), _cli_path(), "eval"],
        input=payload,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"agentctl eval failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout.strip())
