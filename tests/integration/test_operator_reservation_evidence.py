"""Local cost-consumer composition; MOCK requests never prove REAL smoke admission."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    _entry_sha256,
    _snapshot_sha256,
)
from mmaudit.models.authenticated_runner_smoke import (
    AuthenticatedRunnerSmokeCostPlan,
    AuthenticatedRunnerSmokeRunEvidence,
    _require_operator_cost_ledger_join,
    _require_usage_preview_join,
)
from mmaudit.models.openrouter import require_operator_cost_preview_usage
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import CandidateModel
from mmaudit.models.route_cost_reservations import (
    ExactRouteCostReservation,
    RouteCostReservationPolicy,
)
from mmaudit.models.route_runtime_evidence import (
    _RuntimeSourceItem,
    _schema_proof_is_valid,
    _token_detail_proof_is_valid,
    _validate_source_item,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, cost_entry_sha256
from mmaudit.orchestration.manifest import canonical_sha256
from tests.integration.test_operator_reservation_transport import (
    _client_for_inputs,
    _complete_reserved,
)
from tests.integration.test_operator_reservation_transport import (
    local_only as local_only,
)
from tests.unit.test_openrouter import _completion_response
from tests.unit.test_openrouter_operator_reservations import _reservation_inputs
from tests.unit.test_openrouter_request_cost_preview import _preview


def _reseal(payload: dict[str, Any], field: str) -> None:
    payload[field] = canonical_sha256(
        {key: value for key, value in payload.items() if key != field}
    )


@pytest.fixture
async def billed_request(config_factory: Any, tmp_path: Path) -> tuple[Any, ...]:
    inputs = _reservation_inputs(config_factory, tmp_path)
    preview = _preview(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "cost-evidence.json", cap_usd=Decimal("250"))
    initial = ledger.snapshot()
    bodies: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(request.content.decode())
        return _completion_response(
            '{"answer":"synthetic cost observation"}',
            selected_model="alpha/atlas-secure-20260727",
            provider="Approved Provider",
            reasoning_tokens=6,
        )

    client, http_client, _usage = _client_for_inputs(inputs, ledger, handler)
    try:
        result = await _complete_reserved(client, preview)
    finally:
        await client.close()
        await http_client.aclose()
    final = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal("250")).snapshot()
    entry = final.entries[0]
    assert len(bodies) == 1
    assert _entry_sha256(entry) == cost_entry_sha256(entry)
    interval = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256=canonical_sha256({"synthetic": str(ledger.path)}),
        initial_snapshot_sha256=_snapshot_sha256(initial),
        final_snapshot_sha256=_snapshot_sha256(final),
        initial_spent_usd="0",
        interval_spent_usd="0.01",
        final_spent_usd="0.01",
        entries=(
            AuthenticatedCrossLineageLedgerEntryEvidence(
                request_id=entry.request_id,
                entry_sha256=_entry_sha256(entry),
                reserved_usd=preview.maximum_cost_usd_per_attempt_exact,
                actual_cost_usd="0.01",
            ),
        ),
    )
    return result.usage_record, preview, interval, bodies[0]


def test_mock_request_preview_and_exact_closed_bill_compose_without_credit(
    billed_request: tuple[Any, ...],
) -> None:
    """Invariant: replay joins actual per-request reserve and bill without REAL promotion."""

    usage, preview, interval, _body = billed_request
    attempts = _require_usage_preview_join(usage, preview)
    assert len(attempts) == 1
    _require_operator_cost_ledger_join(attempts, interval)
    assert usage.execution_evidence is ExecutionEvidenceKind.MOCK
    assert not preview.authorizes_dispatch and not preview.grants_completion_credit
    assert attempts[0].actual_billed_cost_usd_exact == "0.01"
    assert not attempts[0].reservation.policy.provider_enforced_total_ceiling


def test_current_cost_mode_keeps_native_token_proofs_without_promoting_mock_execution(
    billed_request: tuple[Any, ...],
) -> None:
    """Isolate pure proof checks; partial test subjects cannot form an admitted bundle."""

    usage, preview, _interval, _body = billed_request
    item = _RuntimeSourceItem(
        run=AuthenticatedRunnerSmokeRunEvidence.model_construct(),
        model=CandidateModel.model_construct(
            selection_plan_sha256=preview.operator_cost_reservation.selection_plan_sha256,
            route_predicate_profile_sha256=preview.route_predicate_profile_sha256,
            exact_route_constraint_sha256=preview.operator_cost_reservation.route_constraint_sha256,
            route_predicate_report_sha256="1" * 64,
            output_capability_sha256=preview.output_capability_sha256,
            structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        ),
        plan=AuthenticatedRunnerSmokeCostPlan.model_construct(request_preview=preview),
        usage=usage,
        proof_kind="PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
    )
    assert _token_detail_proof_is_valid(item)
    assert _schema_proof_is_valid(item)
    with pytest.raises(ValueError, match="route-bound REAL success"):
        _validate_source_item(item)


@pytest.mark.parametrize(
    "field",
    (
        "selection_plan_sha256",
        "route_predicate_profile_sha256",
        "route_constraint_sha256",
        "policy",
        "pricing",
    ),
)
def test_coherent_reservation_retargeting_does_not_consume_the_original_preview(
    billed_request: tuple[Any, ...], field: str
) -> None:
    """Invariant: self-consistent evidence cannot replace the caller's selected contract."""

    usage, preview, _interval, body = billed_request
    payload = usage.model_dump(mode="json")
    attempt = payload["routing"]["operator_cost_attempts"][0]
    reservation = attempt["reservation"]
    if field == "policy":
        reservation["policy"] = RouteCostReservationPolicy.build(
            ledger_ceiling_usd_exact="249"
        ).model_dump(mode="json")
    elif field == "pricing":
        current = ExactRouteCostReservation.model_validate_json(json.dumps(reservation))
        pricing = {item.component.value: item.unit_price for item in current.exact_pricing}
        pricing["input_cache_write"] = "0.0000019"
        changed = ExactRouteCostReservation.build(
            policy=current.policy,
            selection_plan_sha256=current.selection_plan_sha256,
            route_predicate_profile_sha256=current.route_predicate_profile_sha256,
            route_constraint_sha256=current.route_constraint_sha256,
            endpoint_snapshot_sha256=current.endpoint_snapshot_sha256,
            request_material=json.dumps(json.loads(body), sort_keys=True, separators=(",", ":")),
            request_token_plan=current.request_token_plan,
            pricing=pricing,
        )
        reservation = changed.model_dump(mode="json")
    else:
        reservation[field] = "f" * 64
    _reseal(reservation, "reservation_sha256")
    attempt["reservation"] = reservation
    _reseal(attempt, "evidence_sha256")
    payload["routing"]["operator_cost_attempt_sha256s"] = [attempt["evidence_sha256"]]
    changed_usage = UsageRecord.model_validate_json(json.dumps(payload))
    with pytest.raises(ValueError, match="complete reservation custody"):
        require_operator_cost_preview_usage(changed_usage, preview)


@pytest.mark.parametrize(
    "field",
    (
        "operator_cost_request_material_projection_sha256",
        "operator_cost_bound_projection_sha256",
        "request_cost_preview_sha256",
    ),
)
@pytest.mark.parametrize("omit", (False, True))
def test_missing_or_different_actual_request_projection_is_not_preview_evidence(
    billed_request: tuple[Any, ...], field: str, omit: bool
) -> None:
    usage, preview, _interval, _body = billed_request
    routing = dict(usage.routing)
    if omit:
        routing.pop(field)
    else:
        routing[field] = "f" * 64
    changed_usage = usage.model_copy(update={"routing": routing})
    with pytest.raises(ValueError, match="exact request projection"):
        require_operator_cost_preview_usage(changed_usage, preview)


def test_erasing_all_cost_attempts_cannot_downgrade_operator_preview_consumption(
    billed_request: tuple[Any, ...],
) -> None:
    usage, preview, _interval, _body = billed_request
    routing = dict(usage.routing)
    for field in (
        "operator_cost_attempts",
        "operator_cost_attempt_sha256s",
        "cost_enforcement_basis",
    ):
        routing.pop(field)
    with pytest.raises(ValueError, match="exact request projection"):
        require_operator_cost_preview_usage(usage.model_copy(update={"routing": routing}), preview)


@pytest.mark.parametrize("field", ("entry_sha256", "request_id", "reserved_usd", "actual_cost_usd"))
def test_different_closed_entry_cannot_reconcile_a_retained_actual_bill(
    billed_request: tuple[Any, ...], field: str
) -> None:
    usage, preview, interval, _body = billed_request
    attempts = _require_usage_preview_join(usage, preview)
    payload = interval.model_dump(mode="json")
    payload["entries"][0][field] = {
        "entry_sha256": "f" * 64,
        "request_id": "different-local-request",
        "reserved_usd": "1",
        "actual_cost_usd": "0.02",
    }[field]
    if field == "actual_cost_usd":
        payload.update(interval_spent_usd="0.02", final_spent_usd="0.02")
    changed = AuthenticatedCrossLineageLedgerIntervalEvidence.model_validate_json(
        json.dumps(payload)
    )
    with pytest.raises(ValueError, match="exact closed ledger entry"):
        _require_operator_cost_ledger_join(attempts, changed)
