"""Keep the completed HA entity coverage work from regressing."""

import json
import sys
from pathlib import Path

MODULES = {
    "entity",
    "fan",
    "light",
    "climate",
    "select",
    "sensor",
    "binary_sensor",
    "diagnostics",
}
FULL_COVERAGE = {"entity", "fan", "light", "climate", "select", "diagnostics"}


def check(report: dict) -> list[str]:
    """Require each module, branch measurement, and its coverage target."""
    errors = []
    if report.get("meta", {}).get("branch_coverage") is not True:
        return ["Branch coverage measurement is required"]
    for module in sorted(MODULES):
        suffix = f"custom_components/gecko/{module}.py"
        matches = [
            value
            for name, value in report.get("files", {}).items()
            if name.replace("\\", "/").endswith(suffix)
        ]
        if len(matches) != 1:
            errors.append(f"{module}: module was not uniquely measured")
            continue
        value = matches[0]
        summary = value["summary"]
        if (
            not summary["num_statements"]
            or not summary.get("num_branches")
            or "missing_branches" not in value
        ):
            errors.append(f"{module}: statement and branch measurement is required")
        elif module in FULL_COVERAGE:
            if value["missing_lines"] or value.get("missing_branches"):
                errors.append(
                    f"{module}: full statement and branch coverage is required"
                )
        elif summary["percent_covered"] <= 95:
            errors.append(
                f"{module}: combined statement/branch coverage must exceed 95%"
            )
    return errors


def main() -> int:
    """Validate a coverage.py JSON report produced by the complete suite."""
    report = json.loads(
        Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json").read_text()
    )
    if errors := check(report):
        print("\n".join(errors))
        return 1
    print(
        "Entity coverage: every module above 95%; all control platforms and diagnostics at 100%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
