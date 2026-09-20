"""Owned-client admission with synthetic inputs and a mandatory pre-network stop.

No completion or provider-origin evidence is produced. Discovery and the prior
authentication flag are explicit synthetic antecedents, not observations of a
provider. Real transport identities remain untouched; local billing/response
composition is tested separately on MOCK.
"""

from __future__ import annotations

import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.openrouter as openrouter_module
import mmaudit.operator_secrets as secrets_module
from mmaudit.benchmark.models import (
    MODEL_BENCHMARK_SCHEMA_NAME,
    ModelBenchmarkResponse,
    blinded_model_benchmark_request,
    model_benchmark_system_prompt,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterError,
    preview_openrouter_structured_request_cost,
    trusted_openrouter_execution_evidence,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.privacy_provenance import (
    prove_pinned_noncrediting_smoke_model_benchmark_source,
)
from tests.unit.test_openrouter import _MODEL_BENCHMARK_SMOKE_CORPUS
from tests.unit.test_openrouter_operator_reservations import _reservation_inputs


@pytest.fixture(autouse=True)
def forbid_network_and_secrets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    reached: list[str] = []
    active = True

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        reached.append("prohibited external access")
        raise AssertionError("owned-client admission must stop before network or secret access")

    def audit(event: str, arguments: tuple[Any, ...]) -> None:
        if active and (
            event in {"socket.connect", "socket.getaddrinfo", "socket.sendto", "subprocess.Popen"}
            or (event == "socket.__new__" and arguments[1] in {socket.AF_INET, socket.AF_INET6})
        ):
            forbidden()

    # Audit events stop egress without changing the socket class also exported by
    # SSL. All HTTPX/HTTPcore/TLS dispatch surfaces must remain pristine.
    sys.addaudithook(audit)
    monkeypatch.setattr(secrets_module, "load_operator_secrets", forbidden)
    try:
        yield reached
    finally:
        active = False


class _StopBeforeNetwork(Exception):
    """Test-only terminal stop, never a simulated provider response."""


@dataclass(slots=True)
class _StopObserver:
    client: OpenRouterClient
    ledger: AtomicCostLedger
    expected_request_id: str
    expected_reserve: Decimal
    reached: bool = False

    def request_ready(self, **_values: Any) -> None:
        return None

    def request_dispatched(self, *, logical_request_id: str) -> None:
        assert logical_request_id == self.expected_request_id
        assert openrouter_module._openrouter_client_callables_are_pristine()
        assert trusted_openrouter_execution_evidence(self.client) is ExecutionEvidenceKind.REAL
        reservation = self.client.budget._issued[logical_request_id]
        assert reservation.persistent is not None
        assert reservation.endpoint_cost_bound is not None
        contract = reservation.endpoint_cost_bound.operator_reservation
        assert contract is not None
        assert contract.request_token_plan.request_id == logical_request_id
        assert Decimal(contract.reserved_cost_usd_exact) == self.expected_reserve
        assert contract.policy.provider_enforced_total_ceiling is False
        assert self.ledger.active_reservation(logical_request_id) == reservation.persistent
        snapshot = self.ledger.snapshot()
        assert len(snapshot.entries) == 1
        assert snapshot.entries[0].status is CostEntryStatus.RESERVED
        assert snapshot.spent_usd == 0
        assert snapshot.active_reserved_usd == self.expected_reserve
        self.reached = True
        raise _StopBeforeNetwork


@pytest.mark.asyncio
@pytest.mark.parametrize("run_kind", ("primary", "replay"))
@pytest.mark.parametrize("authenticated", (False, True))
async def test_owned_smoke_admits_exact_operator_reservation_before_local_stop(
    config_factory: Any,
    tmp_path: Path,
    forbid_network_and_secrets: list[str],
    run_kind: str,
    authenticated: bool,
) -> None:
    """Invariant: real-client admission reserves exactly but cannot send or mint a bill."""

    inputs = _reservation_inputs(config_factory, tmp_path)
    config = inputs["config"]
    config = config.model_copy(
        update={
            "privacy": config.privacy.model_copy(
                update={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK, "require_zdr": True}
            )
        }
    )
    smoke = load_authenticated_runner_smoke_corpus_bundle(_MODEL_BENCHMARK_SMOKE_CORPUS)
    now = datetime.now(UTC).replace(microsecond=0)
    source = prove_pinned_noncrediting_smoke_model_benchmark_source(smoke, now=now)
    logical_id = f"authrunner.smoke.r1.candidate.{run_kind}:{smoke.bundle_sha256}"
    shape = {
        "role": "model_benchmark",
        "system_prompt": model_benchmark_system_prompt(),
        "user_prompt": blinded_model_benchmark_request(smoke.case),
        "response_model": ModelBenchmarkResponse,
        "schema_name": MODEL_BENCHMARK_SCHEMA_NAME,
        "logical_request_id": logical_id,
    }
    preview = preview_openrouter_structured_request_cost(
        execution=config.execution,
        privacy=config.privacy,
        token_budgets=config.token_budgets,
        provider_policy=inputs["policy"],
        reasoning_policy=inputs["reasoning_policy"],
        discovery_manifest=inputs["manifest"],
        discovery_evidence=inputs["evidence"],
        **shape,
    )
    assert preview.schema_version == "1.4"
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal(250))
    budget = BudgetManager(
        total_usd=config.execution.budget_usd,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=config.execution.conservative_usd_per_million_tokens,
        max_requests_per_agent=config.execution.max_requests_per_agent,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    usage = UsageLedger()
    privacy = resolve_effective_privacy_policy(
        profile=config.privacy.profile,
        require_zdr=True,
        consent_observation=None,
        source_sha256=smoke.source_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=source,
        configured_model_ids=(inputs["evidence"].exact_model_id,),
        configured_provider_endpoints=inputs["policy"].configured_endpoints,
        requested_budget_usd=Decimal(250),
        now=now,
    )
    client = OpenRouterClient(
        api_key="synthetic-never-dispatched-test-key",
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        provider_policy=inputs["policy"],
        reasoning_policy=inputs["reasoning_policy"],
        token_budgets=config.token_budgets,
        candidate_revocation_route_constraint=inputs[
            "evidence"
        ].endpoint_snapshot.exact_route_constraint,
        effective_privacy_policy=privacy,
        source_provenance_observation=source,
    )
    observer = _StopObserver(
        client, ledger, logical_id, Decimal(preview.maximum_cost_usd_per_attempt_exact)
    )
    try:
        # Model only the pre-existing upstream authentication result. No validator,
        # callable identity, transport receipt or runtime-origin issuer is replaced.
        client._authentication_validated = authenticated
        client.register_certification_model_discovery(
            evidence=inputs["evidence"], manifest=inputs["manifest"]
        )
        client.bind_request_lifecycle_observer(observer)
        assert trusted_openrouter_execution_evidence(client) is ExecutionEvidenceKind.REAL
        with pytest.raises((_StopBeforeNetwork, OpenRouterError)) as stopped:
            await client.complete_with_evidence(
                models=[inputs["evidence"].exact_model_id],
                expected_request_cost_preview=preview,
                **shape,
            )
    finally:
        await client.close()
    assert forbid_network_and_secrets == []
    reopened = AtomicCostLedger.open_existing(ledger.path, cap_usd=Decimal(250))
    snapshot = reopened.snapshot()
    assert snapshot.spent_usd == snapshot.active_reserved_usd == 0
    if not authenticated:
        assert not observer.reached
        assert "requires an authenticated owned provider client" in str(stopped.value)
        assert snapshot.entries == ()
        return
    assert observer.reached, f"refused before the intended boundary: {stopped.value}"
    assert len(snapshot.entries) == 1
    assert snapshot.entries[0].status is CostEntryStatus.RELEASED
    assert snapshot.entries[0].actual_cost_usd is None
    assert all(record.status != "success" for record in usage.records)
    assert all(record.openrouter_generation_id is None for record in usage.records)
