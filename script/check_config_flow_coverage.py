"""Enforce full config-flow line and branch coverage in the unified suite."""

import json
import sys
from pathlib import Path


def main() -> int:
    """Check the measured flow module, failing closed if it was not measured."""
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json")
    report = json.loads(path.read_text())
    matches = [
        value
        for name, value in report["files"].items()
        if name.replace("\\", "/").endswith("custom_components/gecko/config_flow.py")
    ]
    if len(matches) != 1:
        print("Config flow was not uniquely identified in the coverage report")
        return 1
    summary = matches[0]["summary"]
    if not summary["num_statements"] or not summary["num_branches"]:
        print("Config flow line and branch measurement is required")
        return 1
    missing_lines = matches[0]["missing_lines"]
    missing_branches = matches[0].get("missing_branches", [])
    if missing_lines or missing_branches:
        print(
            f"Uncovered config-flow lines: {missing_lines}; branches: {missing_branches}"
        )
        return 1
    print("Config flow: 100% line and branch coverage")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
