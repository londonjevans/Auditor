"""Real local closure checks inside explicit nonauthorizing lifecycle stand-ins."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.authenticated_runner_openrouter as adapter
from mmaudit.models.authenticated_calibration import (
    AuthenticatedCalibrationCandidateInputs,
    observe_authenticated_model_calibration,
)
from mmaudit.models.authenticated_runner import (
    _require_closed_cross_lineage_ledger_interval,
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
)
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from tests.integration.test_operator_reservation_boundary import (
    forbid_network_and_secrets as forbid_network_and_secrets,
)
from tests.unit import test_authenticated_runner_durable_bundle as durable_fixtures
from tests.unit import test_authenticated_runner_openrouter as adapter_fixtures
from tests.unit.test_authenticated_runner_consumption_scope import (
    ScopeState,
    _assert_disposed,
)
from tests.unit.test_authenticated_runner_consumption_scope import (
    scope_state as scope_state,
)


@pytest.fixture
def native_inputs(forbid_network_and_secrets: list[str]) -> Any:
    """Keep the legacy fixture's asyncio.run calls off pytest's loop-policy thread."""

    assert forbid_network_and_secrets == []
    with ThreadPoolExecutor(max_workers=1) as executor:
        return executor.submit(durable_fixtures._v11_inputs).result(timeout=30)


@pytest.mark.asyncio
async def test_real_runner_verifier_never_yields_an_unregistered_capability(
    native_inputs: Any,
    monkeypatch: pytest.MonkeyPatch,
    forbid_network_and_secrets: list[str],
) -> None:
    inputs = native_inputs
    execution = replace(adapter_fixtures._completed_execution(), runner_evidence=inputs.evidence)
    # Only the execution/input-loading boundary is a stand-in. Runner verification
    # and revocation are the original production callables, with no issued lease.
    adapter_fixtures._install_completed_runner(monkeypatch, execution)
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-no-provider-key"})
    with pytest.raises(ValueError, match=r"absent|mismatched|revoked"):
        async with adapter.authenticated_openrouter_runner_scope(
            launch=adapter_fixtures._structural_launch(), operator_secrets=secrets
        ):
            pytest.fail("serialized evidence recreated live runner custody")
    assert secrets.cleared
    assert forbid_network_and_secrets == []


@pytest.mark.asyncio
@pytest.mark.parametrize("later", ("none", "known", "reserved", "unknown"))
async def test_scope_cannot_turn_snapshot_exact_closure_into_historical_prefix_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    scope_state: ScopeState,
    forbid_network_and_secrets: list[str],
    later: str,
) -> None:
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic.json", cap_usd=Decimal("250"))
    opened = begin_cross_lineage_ledger_interval(ledger)
    prior = ledger.reserve("synthetic-prior", Decimal("1"))
    ledger.reconcile(prior, Decimal("0.5"))
    closed = close_cross_lineage_ledger_interval(opened, expected_request_ids=(prior.request_id,))
    original_entry = ledger.snapshot().entries[0]
    original_require = adapter._TRUSTED_REQUIRE_RUNNER_CUSTODY
    original_revoke = adapter._TRUSTED_REVOKE_RUNNER_CUSTODY
    state = scope_state

    def require(capability: Any, *, evidence: Any) -> Any:
        # The runner lease is explicitly synthetic; its prerequisite below uses
        # the actual immutable local closure capability and real ledger reads.
        if not state.revoked:
            _require_closed_cross_lineage_ledger_interval(closed)
        return original_require(capability, evidence=evidence)

    adapter_fixtures._install_lifecycle_doubles(
        monkeypatch, require=require, revoke=original_revoke
    )
    retained: list[bytes] = []

    async def consume() -> None:
        async with adapter.authenticated_openrouter_runner_scope(
            launch=adapter_fixtures._structural_launch(), operator_secrets=state.secrets
        ):
            assert _require_closed_cross_lineage_ledger_interval(closed)
            if later != "none":
                pending = ledger.reserve("synthetic-later", Decimal("1"))
                if later == "known":
                    ledger.reconcile(pending, Decimal("0.5"))
                elif later == "unknown":
                    ledger.commit_for_transport(pending)
                    ledger.reconcile(pending, None)
            retained.append(ledger.path.read_bytes())

    if later == "none":
        await consume()
    else:
        expected = (
            "not a terminal non-overrun 250 USD ledger"
            if later == "reserved"
            else "ledger changed after closure"
        )
        with pytest.raises(ValueError, match=expected):
            await consume()
    assert ledger.path.read_bytes() == retained[0]
    assert original_entry in ledger.snapshot().entries
    if later != "none":
        entry = next(
            item for item in ledger.snapshot().entries if item.request_id != prior.request_id
        )
        assert (
            entry.status
            is {
                "known": CostEntryStatus.RECONCILED,
                "reserved": CostEntryStatus.RESERVED,
                "unknown": CostEntryStatus.UNCERTAIN_ACCOUNTED,
            }[later]
        )
    _assert_disposed(state)
    assert forbid_network_and_secrets == []


@pytest.mark.asyncio
async def test_scoped_lifecycle_stand_in_cannot_issue_native_calibration_verification(
    native_inputs: Any, scope_state: ScopeState, forbid_network_and_secrets: list[str]
) -> None:
    inputs = native_inputs
    state = scope_state
    async with adapter.authenticated_openrouter_runner_scope(
        launch=adapter_fixtures._structural_launch(), operator_secrets=state.secrets
    ) as execution:
        with pytest.raises(ValueError):
            observe_authenticated_model_calibration(
                selected_model_ids=(inputs.evidence.runs[0].candidate_model_id,),
                benchmark_suite=inputs.live.suite,
                ground_truth=inputs.live.ground_truth,
                inputs=(
                    AuthenticatedCalibrationCandidateInputs(
                        runner_custody=execution.runner_capability,
                        runner_evidence=inputs.evidence,
                        runs=inputs.live.runs,
                    ),
                ),
            )
    _assert_disposed(state)
    assert forbid_network_and_secrets == []
