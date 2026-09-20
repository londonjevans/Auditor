"""Original-file scaling observations cannot manufacture work, credit or timing success."""

from pathlib import Path

import pytest

from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.scheduler_scaling_support import load_scaling_cases, measure_original_tree
from tests.unit import test_truncation_recovery_journal as projection_support


def test_original_small_tree_measurement_preserves_records_custody_and_no_credit(
    tmp_path: Path,
) -> None:
    original_projection = projection_support._projection
    result = measure_original_tree(load_scaling_cases()[0], tmp_path, samples=1, profile=False)
    assert projection_support._projection is original_projection
    assert result["provisional_findings"] == 1
    assert result["case"]["children"] == 2
    assert result["request_limit"] == 33
    assert result["original_file_count"] > 0 and result["original_file_bytes"] > 0
    assert result["accounted_child_cost_usd"] == "0.10"
    assert result["original_files_unchanged"]
    assert result["original_costs_and_request_ordinals_unchanged"]
    assert result["new_resume_dispatches"] == result["provider_calls"] == 0
    assert result["promotion_or_completion_credit"] is False
    assert result["runtime_optimization_applied"] is result["throughput_claim"] is False
    assert set(result["phases"]) == {
        "journal_evidence",
        "public_artifact",
        "provisional_export",
        "original_resume",
        "resumed_export",
    }
    assert all(len(phase["samples"]) == 1 for phase in result["phases"].values())
    # Invariant: an existing original measurement may not be silently replaced or rerun.
    with pytest.raises(FileExistsError):
        measure_original_tree(load_scaling_cases()[0], tmp_path, samples=1, profile=False)
