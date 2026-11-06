"""Guard non-entity HA modules at measured floors while pursuing Silver.

These floors are regression protection, not a quality-tier claim. Existing flow
and entity gates impose stronger requirements on the completed modules.
"""

import json
from pathlib import Path
import sys

BASELINE = Path(__file__).with_name("integration_coverage_baseline.json")


def check(report, baseline=None):
    baseline = baseline if baseline is not None else json.loads(BASELINE.read_text())
    errors = []
    if report.get("meta", {}).get("branch_coverage") is not True:
        return ["Branch measurement is required"]
    files = {
        name.replace("\\", "/"): value
        for name, value in report.get("files", {}).items()
    }
    for module, floor in baseline.items():
        matches = [
            value
            for name, value in files.items()
            if name.endswith(f"custom_components/gecko/{module}.py")
        ]
        if len(matches) != 1:
            errors.append(f"{module}: must be uniquely measured")
            continue
        summary = matches[0]["summary"]
        if "num_branches" not in summary or "covered_branches" not in summary:
            errors.append(f"{module}: branch counts are required")
            continue
        statements = summary["num_statements"]
        branches = summary.get("num_branches", 0)
        line_percent = 100 * summary["covered_lines"] / statements if statements else 0
        branch_percent = (
            100 * summary.get("covered_branches", 0) / branches if branches else 100
        )
        if line_percent < floor["statements"] or branch_percent < floor["branches"]:
            errors.append(
                f"{module}: {line_percent:.1f}% statements / {branch_percent:.1f}% branches below {floor}"
            )
    measured = {
        name.rsplit("/", 1)[-1][:-3]
        for name in files
        if "custom_components/gecko/" in name
        and "/" not in name.split("custom_components/gecko/", 1)[1]
    }
    # Every top-level HA module must be accounted for in this or a stronger gate.
    stronger = {
        "config_flow",
        "entity",
        "fan",
        "light",
        "climate",
        "select",
        "sensor",
        "binary_sensor",
        "diagnostics",
    }
    source = Path(__file__).resolve().parents[1] / "custom_components/gecko"
    expected = {path.stem for path in source.glob("*.py")}
    for module in sorted(expected - set(baseline) - stronger):
        errors.append(f"{module}: add an explicit coverage target")
    for module in sorted(expected - measured):
        errors.append(f"{module}: absent from coverage report")
    return errors


def main():
    report = json.loads(
        Path(sys.argv[1] if len(sys.argv) > 1 else "coverage.json").read_text()
    )
    errors = check(report)
    if errors:
        print("\n".join(errors))
        return 1
    print(
        "Integration coverage baseline preserved; Silver still requires >95% per module"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
