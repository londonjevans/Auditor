"""Complete synthetic cost replay, without provider execution or runtime-origin credit.

Four sealed MOCK requests produce real local reservations and bills. Only an
explicit test-fixture projection supplies the structural REAL identity/generation
antecedents needed to exercise serialized smoke/runtime validators. That projection
does not acquire the production transport receipts or runner custody.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.models.route_runtime_evidence as runtime_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationWireResponse,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
    build_cross_lineage_adjudication_response,
    cross_lineage_adjudication_system_prompt,
    prepare_noncrediting_cross_lineage_adjudication_smoke,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkCaseResult,
    NoncreditingModelBenchmarkSmokeReport,
    authenticated_runner_smoke_model_benchmark_request_descriptor,
    load_model_benchmark_corpus,
)
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    _snapshot_sha256,
)
from mmaudit.models.authenticated_runner_smoke import (
    AuthenticatedRunnerSmokeEvidenceBundle,
    authenticated_runner_smoke_evidence_bytes,
    build_authenticated_runner_smoke_cost_plan,
    revalidate_authenticated_runner_smoke_evidence_bytes,
    seal_authenticated_runner_smoke_evidence_bundle,
    seal_authenticated_runner_smoke_run_evidence,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.generation_evidence import (
    _reconcile_noncrediting_smoke_generation_evidence_structural,
)
from mmaudit.models.identity import OpenRouterIdentityBindingResult, seal_bound_openrouter_identity
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    preview_openrouter_structured_request_cost,
    require_operator_cost_preview_usage,
    validate_openrouter_generation_payload,
)
from mmaudit.models.public_lineage_authority import resolve_verified_public_model_lineage
from mmaudit.models.route_admission import require_authenticated_runner_three_route_admission
from mmaudit.models.route_constraints import RouteConstraintPurpose
from mmaudit.models.route_runtime_evidence import (
    build_route_runtime_evidence_artifact,
    verify_route_runtime_evidence,
)
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import (
    UsageLedger,
    _has_authrunner_owned_real_usage_origin,
    is_creditable_usage_record,
    structurally_noncrediting_unknown_token_smoke_usage_error,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, cost_entry_sha256
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacySourceClassification, resolve_effective_privacy_policy
from mmaudit.repository.privacy_provenance import (
    prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source,
    prove_pinned_noncrediting_smoke_model_benchmark_source,
)
from tests.identity_fixtures import bind_synthetic_usage_identity, reattest_synthetic_real_usage
from tests.integration.test_operator_reservation_transport import local_only as local_only
from tests.unit import test_authenticated_runner_smoke_runtime as smoke_fixtures
from tests.unit import test_route_runtime_evidence as runtime_fixtures
from tests.unit.test_openrouter import _completion_response, _generation_payload


def _rebind(model: Any, hash_field: str, **changes: Any) -> Any:
    payload = {**model.model_dump(mode="json", exclude={hash_field}), **changes}
    return type(model).model_validate_json(
        json.dumps({**payload, hash_field: canonical_sha256(payload)})
    )


@pytest.fixture
def runtime_antecedents(
    config_factory: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Any, ...]:
    # Fresh synthetic metadata, not refreshed provider discovery. Keep expiry
    # validation active when binding the actual local request's frozen snapshot.
    monkeypatch.setattr(
        smoke_fixtures.candidate_fixtures,
        "_NOW",
        datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=2),
    )
    return runtime_fixtures._launch_bound_native_smoke_bundle(
        monkeypatch, tmp_path, config_factory, operator_reservation=True
    )


@pytest.fixture
async def reserved_runtime(
    config_factory: Any, tmp_path: Path, runtime_antecedents: tuple[Any, ...]
) -> tuple[Any, ...]:
    source_bundle, subjects, routes = runtime_antecedents
    smoke = load_authenticated_runner_smoke_corpus_bundle(smoke_fixtures.SMOKE_CORPUS_PATH)
    suite = load_model_benchmark_corpus(smoke_fixtures.CORPUS_PATH)
    config = smoke_fixtures._smoke_config(config_factory)
    reasoning = build_reasoning_policy(config)
    ledger = AtomicCostLedger.initialize(tmp_path / "four-local-bills.json", cap_usd=Decimal(250))
    initial = ledger.snapshot()
    budget = BudgetManager(
        total_usd=250,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=config.execution.conservative_usd_per_million_tokens,
        max_requests_per_agent=config.execution.max_requests_per_agent,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
        global_input_token_budget=config.token_budgets.global_input_token_budget,
        global_output_token_budget=config.token_budgets.global_output_token_budget,
    )
    mock_usages: list[UsageRecord] = []

    async def complete(
        *, model: Any, route: Any, shape: dict[str, Any], source: Any, response: Any
    ) -> tuple[Any, Any, Any]:
        _, manifest, evidence = route
        policy = OpenRouterProviderPolicy(
            only=(model.approved_provider_endpoint,), certification=True
        )
        preview = preview_openrouter_structured_request_cost(
            execution=config.execution,
            privacy=config.privacy,
            token_budgets=config.token_budgets,
            provider_policy=policy,
            reasoning_policy=reasoning,
            discovery_manifest=manifest,
            discovery_evidence=evidence[0],
            **shape,
        )
        assert preview.schema_version == "1.4"
        generation_id = f"synthetic-{len(mock_usages)}"

        def handler(_request: httpx.Request) -> httpx.Response:
            value = _completion_response(
                response.model_dump_json(),
                model=model.exact_model_id,
                selected_model=model.canonical_model_slug,
                provider=model.approved_provider_name,
                reasoning_tokens=6,
            ).json()
            value["id"] = generation_id
            return httpx.Response(200, headers={"X-Generation-Id": generation_id}, json=value)

        privacy = resolve_effective_privacy_policy(
            profile=config.privacy.profile,
            require_zdr=True,
            consent_observation=None,
            source_sha256=source.evidence.source_sha256,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_provenance_observation=source,
            configured_model_ids=(model.exact_model_id,),
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            requested_budget_usd=Decimal(250),
            now=source.evidence.observed_at,
        )
        client = OpenRouterClient(
            api_key="synthetic-mock-only-cost-replay",
            base_url="https://fake.test/api/v1/",
            test_only_mock_handler=handler,
            execution=config.execution,
            privacy=config.privacy,
            budget=budget,
            usage=UsageLedger(),
            token_budgets=config.token_budgets,
            provider_policy=policy,
            reasoning_policy=reasoning,
            candidate_revocation_route_constraint=evidence[
                0
            ].endpoint_snapshot.exact_route_constraint,
            effective_privacy_policy=privacy,
            source_provenance_observation=source,
        )
        try:
            client.register_certification_model_discovery(evidence=evidence[0], manifest=manifest)
            snapshot = client.registered_model_identity_snapshot(model.exact_model_id)
            result = await client.complete_with_evidence(
                models=[model.exact_model_id], expected_request_cost_preview=preview, **shape
            )
        finally:
            await client.close()
        actual = result.usage_record
        assert actual.execution_evidence is ExecutionEvidenceKind.MOCK
        assert not _has_authrunner_owned_real_usage_origin(actual)
        mock_usages.append(actual)
        require_operator_cost_preview_usage(actual, preview)
        # Explicit structural antecedent, not a claim about the actual MOCK call.
        usage = bind_synthetic_usage_identity(
            UsageRecord.model_validate(
                {**actual.model_dump(mode="json"), "execution_evidence": ExecutionEvidenceKind.REAL}
            )
        )
        synthetic_binding = OpenRouterIdentityBindingResult.model_validate(
            usage.routing["identity_binding"]
        )
        assert snapshot is not None and synthetic_binding.generation is not None
        binding = seal_bound_openrouter_identity(
            snapshot=snapshot,
            request=synthetic_binding.request,
            generation=synthetic_binding.generation,
            evaluated_at=synthetic_binding.evaluated_at,
        )
        usage = reattest_synthetic_real_usage(
            UsageRecord.model_validate(
                {
                    **usage.model_dump(mode="json"),
                    "routing": {
                        **usage.routing,
                        "identity_snapshot_sha256": snapshot.snapshot_sha256,
                        "identity_binding": binding.model_dump(mode="json"),
                        "identity_binding_sha256": binding.binding_sha256,
                    },
                }
            )
        )
        assert not _has_authrunner_owned_real_usage_origin(usage)
        assert structurally_noncrediting_unknown_token_smoke_usage_error(usage) is None
        assert usage.started_at is not None and usage.ended_at is not None
        raw_generation = _generation_payload(
            generation_id=generation_id,
            model=model.canonical_model_slug,
            provider_name=model.approved_provider_name,
            reasoning_tokens=6,
        )
        raw_generation["data"]["created_at"] = usage.started_at.isoformat()
        raw_generation["data"]["request_id"] = usage.request_id
        generation = validate_openrouter_generation_payload(
            raw_generation,
            requested_generation_id=generation_id,
            retrieved_at=usage.ended_at + timedelta(seconds=1),
            execution_evidence=ExecutionEvidenceKind.REAL,
        )
        generation = _reconcile_noncrediting_smoke_generation_evidence_structural(
            generation,
            usage_record=usage,
            expected_exact_model=model.exact_model_id,
            expected_canonical_model=model.canonical_model_slug,
            expected_catalog_identity_binding_sha256=usage.routing[
                "catalog_identity_binding_sha256"
            ],
            expected_discovery_evidence_sha256=model.discovery_evidence_sha256,
            expected_provider_name=model.approved_provider_name,
        )
        return usage, preview, generation

    candidates = []
    for old_run in source_bundle.runs:
        descriptor = authenticated_runner_smoke_model_benchmark_request_descriptor(
            smoke_run_index=1,
            run_kind=old_run.run_kind.value,
            selection_sha256=smoke.bundle_sha256,
            case=smoke.case,
            target=old_run.candidate_report.target,
        )
        shape = {
            "role": descriptor.request_role,
            "system_prompt": descriptor.system_prompt,
            "user_prompt": descriptor.user_prompt,
            "response_model": descriptor.response_model,
            "schema_name": descriptor.schema_name,
            "logical_request_id": descriptor.logical_request_id,
        }
        source = prove_pinned_noncrediting_smoke_model_benchmark_source(
            smoke, now=datetime.now(UTC).replace(microsecond=0)
        )
        usage, preview, generation = await complete(
            model=old_run.candidate,
            route=routes[0],
            shape=shape,
            source=source,
            response=old_run.candidate_report.result.normalized_response,
        )
        result = ModelBenchmarkCaseResult.model_validate(
            {
                **old_run.candidate_report.result.model_dump(mode="json"),
                "usage_record": usage.model_dump(mode="json"),
                "generation_evidence": generation.model_dump(mode="json"),
            }
        )
        report: NoncreditingModelBenchmarkSmokeReport = _rebind(
            old_run.candidate_report, "report_sha256", result=result.model_dump(mode="json")
        )
        candidates.append((old_run, report, preview, generation))

    runs = []
    for index, (old_run, report, candidate_preview, candidate_generation) in enumerate(candidates):
        prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
            public_lineage_capability=resolve_verified_public_model_lineage(),
            suite=suite,
            selected_case=smoke.case,
            selected_ground_truth=smoke.ground_truth_case,
            selection_sha256=smoke.bundle_sha256,
            candidate_report=report,
            judge=old_run.judge,
            run_kind=old_run.run_kind,
        )
        request = prepared.requests[0]
        response = build_cross_lineage_adjudication_response(
            request=request,
            dimension_outcomes=request.expected_dimension_outcomes,
            disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
            rationale="Synthetic local cost-consumer composition, no provider observation.",
        )
        wire = CrossLineageAdjudicationWireResponse.model_validate(
            {
                "dimension_outcomes": tuple(
                    {"dimension": outcome.dimension, "passed": outcome.passed}
                    for outcome in response.dimension_outcomes
                ),
                "disposition": response.disposition,
                "rationale": response.rationale,
            }
        )
        source = prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source(
            smoke, report.result, prepared, now=datetime.now(UTC).replace(microsecond=0)
        )
        usage, judge_preview, judge_generation = await complete(
            model=old_run.judge,
            route=routes[index + 1],
            source=source,
            response=wire,
            shape={
                "role": "model_benchmark",
                "system_prompt": cross_lineage_adjudication_system_prompt(),
                "user_prompt": request.provider_visible_user_prompt,
                "response_model": CrossLineageAdjudicationWireResponse,
                "schema_name": CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
                "logical_request_id": (
                    f"authrunner.smoke.r1.judge.{old_run.run_kind.value.lower()}:"
                    f"{request.request_sha256}"
                ),
            },
        )
        adjudication = build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=(
                build_cross_lineage_adjudication_case_result(
                    request=request,
                    response=response,
                    usage_record=usage,
                    generation_evidence=judge_generation,
                ),
            ),
        )
        plans = tuple(
            build_authenticated_runner_smoke_cost_plan(
                smoke_run_index=1,
                run_kind=old_run.run_kind,
                stage=stage,
                case_id=smoke.case.case_id,
                selection_sha256=smoke.bundle_sha256,
                request_preview=preview,
            )
            for stage, preview in (("CANDIDATE", candidate_preview), ("JUDGE", judge_preview))
        )
        runs.append(
            seal_authenticated_runner_smoke_run_evidence(
                smoke_run_index=1,
                run_kind=old_run.run_kind,
                candidate=old_run.candidate,
                judge=old_run.judge,
                candidate_cost_plan=plans[0],
                candidate_report=report,
                candidate_generation_refetch=candidate_generation,
                prepared_adjudication=prepared,
                judge_cost_plan=plans[1],
                adjudication_report=adjudication,
                judge_generation_refetch=judge_generation,
            )
        )
    final = ledger.snapshot()
    interval = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256=canonical_sha256({"synthetic-local-ledger": str(ledger.path)}),
        initial_snapshot_sha256=_snapshot_sha256(initial),
        final_snapshot_sha256=_snapshot_sha256(final),
        initial_spent_usd="0",
        interval_spent_usd="0.04",
        final_spent_usd="0.04",
        entries=tuple(
            AuthenticatedCrossLineageLedgerEntryEvidence(
                request_id=entry.request_id,
                entry_sha256=cost_entry_sha256(entry),
                reserved_usd=str(entry.reserved_usd),
                actual_cost_usd="0.01",
            )
            for entry in sorted(final.entries, key=lambda entry: entry.request_id)
        ),
    )
    values = source_bundle.model_dump(
        mode="python",
        exclude={
            "bundle_sha256",
            "runs",
            "closed_ledger_evidence",
            "execution_sequence_request_ids",
        },
    )
    bundle = seal_authenticated_runner_smoke_evidence_bundle(
        **values,
        runs=tuple(runs),
        closed_ledger_evidence=interval,
        execution_sequence_request_ids=tuple(usage.request_id for usage in mock_usages),
    )
    return bundle, subjects, routes, tuple(mock_usages)


def test_complete_synthetic_cost_bundle_replays_through_all_three_runtime_routes(
    reserved_runtime: tuple[Any, ...],
) -> None:
    """Invariant: all four exact bills join without granting runtime/provider authority."""

    bundle, subjects, routes, mock_usages = reserved_runtime
    assert type(bundle) is AuthenticatedRunnerSmokeEvidenceBundle
    replayed = revalidate_authenticated_runner_smoke_evidence_bytes(
        authenticated_runner_smoke_evidence_bytes(bundle)
    )
    policy = runtime_fixtures._policy(maximum_age_days=30)
    artifact = build_route_runtime_evidence_artifact(
        smoke_bundle=replayed, qualification_policy=policy
    )
    capability = verify_route_runtime_evidence(artifact, policy)
    reports = require_authenticated_runner_three_route_admission(
        candidate=routes[0],
        primary_judge=routes[1],
        replay_judge=routes[2],
        purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
        runtime_evidence=capability,
        qualification_policy=policy,
        runtime_required_output_tokens=subjects[0][4].runtime_required_output_tokens,
    )
    assert len(reports) == 3
    assert len(mock_usages) == len(bundle.closed_ledger_evidence.entries) == 4
    assert all(usage.execution_evidence is ExecutionEvidenceKind.MOCK for usage in mock_usages)
    assert all(not is_creditable_usage_record(usage, require_real=True) for usage in mock_usages)
    assert not bundle.provider_call_authorized and not bundle.runner_custody_authorized
    assert not bundle.model_qualification_authorized and not bundle.release_authorized


def test_runtime_cost_join_refuses_each_registry_axis_for_every_usage(
    reserved_runtime: tuple[Any, ...],
) -> None:
    """Invariant: an intact reservation cannot be attached to another registry binding."""

    bundle = reserved_runtime[0]
    for run in bundle.runs:
        for model, plan, usage, proof in (
            (
                run.candidate,
                run.candidate_cost_plan,
                run.candidate_report.result.usage_record,
                "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
            ),
            (
                run.judge,
                run.judge_cost_plan,
                run.adjudication_report.cases[0].usage_record,
                "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            ),
        ):
            item = runtime_module._RuntimeSourceItem(run, model, plan, usage, proof)
            runtime_module._validate_source_item(item)
            for axis in (
                "selection_plan_sha256",
                "route_predicate_profile_sha256",
                "exact_route_constraint_sha256",
            ):
                changed = type(model).model_validate_json(
                    json.dumps(
                        {
                            **model.model_dump(mode="json"),
                            axis: canonical_sha256(
                                {"synthetic_changed_axis": axis, "original": getattr(model, axis)}
                            ),
                        }
                    )
                )
                item = runtime_module._RuntimeSourceItem(run, changed, plan, usage, proof)
                with pytest.raises(ValueError, match=r"exact route preview|exact registry custody"):
                    runtime_module._validate_source_item(item)
