"""Coverage guards must fail closed rather than accepting missing measurements."""

from copy import deepcopy
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "integration_gate",
    Path(__file__).parents[1] / "script/check_integration_coverage.py",
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def test_baseline_rejects_missing_measurement_and_unmeasured_branches():
    assert gate.check({"meta": {}}, {}) == ["Branch measurement is required"]
    errors = gate.check(
        {"meta": {"branch_coverage": True}, "files": {}},
        {"api": {"statements": 80, "branches": 60}},
    )
    assert "api: must be uniquely measured" in errors
    assert "api: absent from coverage report" in errors


def test_baseline_detects_line_and_branch_regressions():
    baseline = {"api": {"statements": 80, "branches": 60}}
    report = {
        "meta": {"branch_coverage": True},
        "files": {
            "custom_components/gecko/api.py": {
                "summary": {
                    "num_statements": 10,
                    "covered_lines": 8,
                    "num_branches": 10,
                    "covered_branches": 6,
                }
            }
        },
    }
    assert not any(error.startswith("api:") for error in gate.check(report, baseline))
    for key in ("covered_lines", "covered_branches"):
        bad = deepcopy(report)
        bad["files"]["custom_components/gecko/api.py"]["summary"][key] -= 1
        assert any(error.startswith("api:") for error in gate.check(bad, baseline))


def test_missing_branch_counts_are_rejected():
    report = {
        "meta": {"branch_coverage": True},
        "files": {
            "custom_components/gecko/api.py": {
                "summary": {"num_statements": 10, "covered_lines": 10}
            }
        },
    }
    assert "api: branch counts are required" in gate.check(
        report, {"api": {"statements": 80, "branches": 60}}
    )
