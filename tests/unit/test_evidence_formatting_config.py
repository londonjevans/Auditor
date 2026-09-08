"""Automatic source checks must not rewrite external operator evidence."""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_external_evidence_exclusion_is_exact_and_keeps_owned_source_in_scope() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text())
    ruff = configuration["tool"]["ruff"]
    exclusions = ruff["extend-exclude"]
    assert set(exclusions) == {
        "config/public_model_lineage/sources/**",
        "docs/remediation/v3/operator_captures/**",
        "docs/remediation/v3/operator_results.md",
    }
    assert len(exclusions) == 3
    assert "exclude" not in ruff, "retain the formatter's built-in exclusions"
    for owned_path in (
        "src/mmaudit/models/owned.py",
        "tests/unit/test_owned.py",
        "scripts/validate_governance_state.py",
        "docs/remediation/v3/owned.py",
        "docs/owned/operator_results.md",
        "README.md",
    ):
        assert not any(fnmatch.fnmatchcase(owned_path, pattern) for pattern in exclusions)
