"""Original private plan writer and CLI stage one trial without external actions."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.models.candidate_plan_ancestry import (
    resolve_verified_candidate_selection_plan_ancestry,
    validate_candidate_selection_plan_reactivation,
    write_candidate_selection_plan_reactivation,
)
from mmaudit.models.candidate_selection import load_candidate_selection_plan
from tests.integration.test_operator_reservation_transport import local_only as local_only
from tests.unit.test_candidate_plan_endpoint_trial import ROOT, _trial


def test_original_private_writer_reopens_exact_trial_and_never_changes_active_plan(
    tmp_path: Path,
) -> None:
    active = ROOT / "config/models.selection-plan.json"
    original = active.read_bytes()
    trial = _trial()
    output = tmp_path / "trial.json"
    assert (
        write_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), path=output, successor=trial
        )
        == trial
    )
    assert output.stat().st_mode & 0o777 == 0o600
    reopened = load_candidate_selection_plan(output)
    assert (
        validate_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), successor=reopened
        )
        == trial
    )
    retained = output.read_bytes()
    with pytest.raises(ValueError):
        write_candidate_selection_plan_reactivation(
            resolve_verified_candidate_selection_plan_ancestry(), path=output, successor=trial
        )
    assert output.read_bytes() == retained and active.read_bytes() == original


@pytest.mark.parametrize("endpoint", ("fireworks", "sail-research/fp4", "phala"))
def test_original_cli_emits_only_current_trial_without_provider_secret_or_process(
    tmp_path: Path, endpoint: str
) -> None:
    active = ROOT / "config/models.selection-plan.json"
    before = active.read_bytes()
    output = tmp_path / "trial.json"
    result = CliRunner().invoke(
        app,
        [
            "models",
            "emit-selection-plan-reactivation",
            "--candidate",
            "deepseek/deepseek-v4-pro-0813=" + endpoint,
            "--candidate-endpoint-trial",
            "--output",
            str(output),
            "--no-color",
        ],
    )
    if endpoint == "fireworks":
        assert result.exit_code == 0, result.output
        assert "schema-v1.12" in result.output
        assert "adoption prohibited" in result.output and "plan was not adopted" in result.output
        assert load_candidate_selection_plan(output) == _trial()
        assert output.stat().st_mode & 0o777 == 0o600
    else:
        assert result.exit_code != 0
        assert not output.exists()
    assert active.read_bytes() == before
