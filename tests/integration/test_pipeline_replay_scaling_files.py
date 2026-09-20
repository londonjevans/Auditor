"""The measurement must use full original pipeline ownership, never a reconstructed substitute."""

from pathlib import Path

import pytest

from tests.integration import test_unresolved_recovery_tree_pipeline as original_test
from tests.pipeline_replay_scaling_support import measure_original_pipeline_replay
from tests.unresolved_recovery_tree_support import tree_scenarios


@pytest.mark.asyncio
async def test_full_pipeline_measurement_preserves_original_cost_files_roles_and_no_credit(
    tmp_path: Path,
) -> None:
    case = next(case for case in tree_scenarios() if case.name == "generic-limited")
    original_run = vars(original_test)["_run"]
    result = await measure_original_pipeline_replay(case, tmp_path, samples=1, profile=False)
    assert vars(original_test)["_run"] is original_run
    assert result["case"]["expected_children"] == 4
    assert len(result["fresh_pipeline"]["samples"]) == 1
    assert len(result["full_original_resume"]["samples"]) == 1
    assert "separate_profile" not in result["full_original_resume"]
    assert result["original_regression_assertions_passed"]
    assert result["original_files_costs_findings_roles_unchanged"]
    assert result["verification_outside_timing"]
    assert result["original_file_count"] > 0 and result["original_file_bytes"] > 0
    assert result["real_provider_calls"] == result["new_resume_dispatches"] == 0
    assert result["promotion_or_completion_credit"] is False
    assert result["runtime_optimization_applied"] is result["throughput_claim"] is False
    with pytest.raises(FileExistsError):
        await measure_original_pipeline_replay(case, tmp_path, samples=1, profile=False)
