"""Real frozen-truth resolution cannot promote synthetic local runner declarations."""

import socket
import subprocess
from decimal import Decimal
from pathlib import Path

import pytest

from mmaudit.models.authenticated_calibration import (
    AuthenticatedCalibrationCandidateInputs,
    observe_authenticated_model_calibration,
)
from mmaudit.models.authenticated_runner import (
    VerifiedCrossLineageRunnerCustody,
    _require_closed_cross_lineage_ledger_interval,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.unit import test_authenticated_runner_durable_bundle as fixtures


@pytest.mark.parametrize("kind", ["missing", "serialized", "unregistered"])
def test_live_frozen_truth_does_not_authorize_non_live_synthetic_runner(monkeypatch, kind):
    def forbidden(*_args, **_kwargs):
        pytest.fail("provider-free custody integration attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    inputs = fixtures._v11_inputs()
    capability = (
        None
        if kind == "missing"
        else {}
        if kind == "serialized"
        else object.__new__(VerifiedCrossLineageRunnerCustody)
    )
    selected = (inputs.evidence.runs[0].candidate_model_id,)
    with pytest.raises(ValueError, match=r"runner custody is absent|runner custody.*required"):
        observe_authenticated_model_calibration(
            selected_model_ids=selected,
            benchmark_suite=inputs.live.suite,
            ground_truth=inputs.live.ground_truth,
            inputs=(
                AuthenticatedCalibrationCandidateInputs(
                    runner_custody=capability,
                    runner_evidence=inputs.evidence,
                    runs=inputs.live.runs,
                ),
            ),
        )


def test_shared_ledger_advance_requires_a_distinct_campaign_custody_handoff(tmp_path: Path):
    """Actual local closure is snapshot-exact, not a reusable historical-prefix proof."""

    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-costs.json", cap_usd=Decimal("250"))
    first_open = begin_cross_lineage_ledger_interval(ledger)
    first_reservation = ledger.reserve("synthetic-first", Decimal("1"))
    ledger.reconcile(first_reservation, Decimal("1"))
    first = close_cross_lineage_ledger_interval(
        first_open, expected_request_ids=("synthetic-first",)
    )
    assert _require_closed_cross_lineage_ledger_interval(first).evidence.final_spent_usd == "1"
    second_open = begin_cross_lineage_ledger_interval(ledger)
    second_reservation = ledger.reserve("synthetic-second", Decimal("1"))
    ledger.reconcile(second_reservation, Decimal("1"))
    second = close_cross_lineage_ledger_interval(
        second_open, expected_request_ids=("synthetic-second",)
    )
    assert _require_closed_cross_lineage_ledger_interval(second).evidence.final_spent_usd == "2"
    with pytest.raises(ValueError, match="ledger changed after closure"):
        _require_closed_cross_lineage_ledger_interval(first)
