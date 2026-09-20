"""Provider-free native refusal, original local source replay and ledger preservation."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

import mmaudit.models.authenticated_runner as runner
import mmaudit.orchestration.authenticated_calibration_accounting as accounting
from mmaudit.models.authenticated_calibration import (
    AuthenticatedCalibrationCandidateInputs,
    observe_authenticated_model_calibration,
)
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit.test_retained_runner_custody import RetainedRunnerHarness, retain
from tests.unit.test_retained_runner_custody import retained_runner as retained_runner


def test_native_retention_does_not_promote_an_isolated_registration(
    retained_runner: RetainedRunnerHarness, forbid_network_and_secrets: list[str]
) -> None:
    subject = retained_runner
    raw = subject.ledger.path.read_bytes()
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        runner.retain_verified_cross_lineage_runner_custody(
            subject.original,
            evidence=subject.evidence,
            accounting=subject.owner,
        )
    assert (
        accounting.observe_calibration_ledger_accounting(subject.owner).retained_interval_count == 0
    )
    assert subject.ledger.path.read_bytes() == raw
    assert forbid_network_and_secrets == []


def test_native_calibration_refuses_isolated_retained_runner_custody(
    retained_runner: RetainedRunnerHarness, forbid_network_and_secrets: list[str]
) -> None:
    subject = retained_runner
    successor, runs = retain(subject)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        observe_authenticated_model_calibration(
            selected_model_ids=(subject.evidence.runs[0].candidate_model_id,),
            benchmark_suite=subject.live.suite,
            ground_truth=subject.live.ground_truth,
            inputs=(AuthenticatedCalibrationCandidateInputs(successor, subject.evidence, runs),),
        )
    assert forbid_network_and_secrets == []


@pytest.mark.parametrize("mutation", ("remove", "reprice", "retimestamp"))
def test_retained_runner_refuses_changed_original_ledger_history(
    retained_runner: RetainedRunnerHarness, forbid_network_and_secrets: list[str], mutation: str
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    original = subject.ledger.path.read_text()
    payload = json.loads(original)
    request_id = next(iter(payload["entries"]))
    entry = payload["entries"][request_id]
    if mutation == "remove":
        payload["entries"].pop(request_id)
    elif mutation == "reprice":
        entry["actual_cost_usd"] = entry["accounted_cost_usd"] = "0"
    else:
        entry["updated_at"] = "2099-01-01T00:00:00+00:00"
    subject.ledger.path.write_text(json.dumps(payload))
    try:
        with pytest.raises(ValueError, match="custody is unavailable"):
            subject.require(successor, evidence=subject.evidence)
    finally:
        # Restoring the synthetic ledger permits normal fixture disposal only.
        subject.ledger.path.write_text(original)
    assert forbid_network_and_secrets == []


def test_retention_keeps_genuine_frozen_source_custody_required(
    retained_runner: RetainedRunnerHarness, forbid_network_and_secrets: list[str]
) -> None:
    subject = retained_runner
    successor, _runs = retain(subject)
    lease = subject.registry.snapshot(successor)
    capability = object.__new__(type(lease.state.ground_truth_capability))
    subject.registry.replace_state(
        successor, lease, replace(lease.state, ground_truth_capability=capability)
    )
    with pytest.raises(ValueError, match="ground-truth capability"):
        subject.require(successor, evidence=subject.evidence)
    assert forbid_network_and_secrets == []
