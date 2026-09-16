#!/usr/bin/env python3
"""Block Wizard execute calls unless HOL Guard explicitly allows them."""

import json
import shutil
import subprocess
import sys
from typing import Any

_TIMEOUT_SECONDS = 10
_ALLOWED = {"allow", "benign"}


def block(reason: str) -> int:
    print(f"HOL Guard blocked tool call: {reason}", file=sys.stderr)
    return 2


def evaluate(payload: dict[str, Any]) -> int:
    if payload.get("event") != "pre_tool_use" or payload.get("tool_name") != "execute":
        return 0

    args = payload.get("args")
    if not isinstance(args, dict):
        return block("missing execute arguments")
    command = args.get("command")
    if not isinstance(command, str) or not command.strip():
        return block("missing command")

    executable = shutil.which("hol-guard")
    if not executable:
        return block("hol-guard is not installed")

    try:
        result = subprocess.run(
            [executable, "command", "test", command, "--json"],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode != 0:
            return block("Guard evaluation failed")
        verdict = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, ValueError):
        return block("Guard evaluation failed")

    if not isinstance(verdict, dict):
        return block("Guard returned malformed output")
    decision = str(verdict.get("decision", "")).lower()
    if decision in _ALLOWED:
        return 0
    return block(f"decision was {decision or 'unknown'}")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            return block("hook payload was not an object")
        return evaluate(payload)
    except Exception:
        return block("unexpected hook failure")


if __name__ == "__main__":
    raise SystemExit(main())
