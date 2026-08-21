from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import mmaudit.benchmark.cross_lineage_adjudication as adjudication_module
import mmaudit.models.authenticated_runner_smoke as smoke_evidence_module
import mmaudit.orchestration.authenticated_runner_smoke_openrouter as smoke_runtime_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationRunKind,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_response,
    prepare_noncrediting_cross_lineage_adjudication_smoke,
)
from mmaudit.benchmark.models import load_model_benchmark_corpus
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner_smoke import (
    AuthenticatedRunnerSmokeEvidenceBundle,
    AuthenticatedRunnerSmokeRunEvidence,
    build_authenticated_runner_smoke_cost_plan,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.generation_evidence import OpenRouterGenerationEvidence
from mmaudit.models.public_lineage_authority import (
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateModel,
    LineageReviewStatus,
    seal_operator_lineage_review,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import UsageLedger
from mmaudit.operator_secrets import OPENROUTER_API_KEY_NAME, OperatorSecrets
from mmaudit.orchestration.authenticated_runner_smoke_openrouter import (
    AuthenticatedRunnerSmokeOpenRouterError,
    AuthenticatedRunnerSmokeOpenRouterLaunch,
    AuthenticatedRunnerSmokePreflightInventory,
    AuthenticatedRunnerSmokeRunPlan,
    _require_exact_smoke_callback_ledger_delta,
    _require_three_distinct_roots,
    execute_authenticated_runner_smoke_openrouter,
    preflight_authenticated_runner_smoke_openrouter_launch,
)
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacyProfile
from tests.identity_fixtures import bind_synthetic_usage_identity, rebind_synthetic_token_plan
from tests.unit.test_authenticated_runner_cost_plan import _preview, _replace_preview
from tests.unit.test_authenticated_runner_durable_bundle import (
    _cost_preview_for_usage,
    _usage_with_cost_preview,
)
from tests.unit.test_authenticated_runner_execution import _config
from tests.unit.test_authenticated_runner_smoke_benchmark import (
    JUDGE_ID,
    SELECTION_SHA256,
    _judge,
    _smoke_report,
)
from tests.unit.test_cross_lineage_adjudication import _judge_usage_and_generation
from tests.unit.test_model_benchmark_portfolio import (
    _as_structural_real,
    _candidate_registry,
    _report,
)

ROOT = Path(__file__).parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
SMOKE_CORPUS_PATH = ROOT / "benchmarks" / "model_corpus_smoke"
NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

CANDIDATE_ID = "deepseek/deepseek-v4-pro-0813"
PRIMARY_JUDGE_ID = "minimax/minimax-m3"
REPLAY_JUDGE_ID = "moonshotai/kimi-k3"
_TOKEN_ROUTING_FIELDS = (
    "request_token_plan",
    "request_token_plan_sha256",
    "atomic_token_reservation",
    "atomic_token_reservation_sha256",
    "atomic_token_reservations",
    "atomic_token_reservation_sha256s",
)


def _snapshot(*, entries: tuple[CostEntry, ...], spent: Decimal) -> CostLedgerSnapshot:
    return CostLedgerSnapshot(
        cap_usd=Decimal("250"),
        spent_usd=spent,
        active_reserved_usd=Decimal(0),
        remaining_usd=Decimal("250") - spent,
        over_cap=False,
        has_reservation_overrun=False,
        entries=entries,
    )


def _approved_candidate(model_id: str) -> CandidateModel:
    capability = resolve_verified_public_model_lineage()
    lineage = require_verified_public_model_lineage(capability, model_id)
    base = _candidate_registry((model_id,)).candidates[0]
    review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(model_id,),
        rationale="Synthetic unit binding to the compiled public-lineage projection.",
        root_lineage=lineage.root_lineage,
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256=lineage.bundle_sha256,
    )
    return CandidateModel.model_validate(
        {
            **base.model_dump(mode="python"),
            "root_lineage": lineage.root_lineage,
            "lineage_review": review,
        },
        strict=True,
    )


def _smoke_config(
    config_factory: Callable[..., AuditConfig],
    *,
    retries: int = 1,
) -> AuditConfig:
    return config_factory(
        execution={
            "budget_usd": 250.0,
            "max_model_retries": retries,
            "max_requests_per_agent": 192,
        },
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK},
        models={
            "provider_policy": {"allow_fallbacks": False},
            "reasoning": {"effort": "high", "reserved_tokens": 4_096},
        },
    )


def _candidate_smoke_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    selection_sha256: str,
    case_id: str,
    index: int,
    prompt_price: str = "0.001",
) -> Any:
    preview = _preview(
        index,
        logical_request_id=(
            f"authrunner.smoke.r1.candidate.{run_kind.value.casefold()}:{selection_sha256}"
        ),
        maximum_attempts=2,
        prompt_price=prompt_price,
    )
    return build_authenticated_runner_smoke_cost_plan(
        run_kind=run_kind,
        stage="CANDIDATE",
        case_id=case_id,
        selection_sha256=selection_sha256,
        request_preview=preview,
    )


def _judge_smoke_plan(
    *,
    run_kind: CrossLineageAdjudicationRunKind,
    selection_sha256: str,
    case_id: str,
    request_sha256: str,
    index: int,
) -> Any:
    preview = _preview(
        index,
        logical_request_id=(
            f"authrunner.smoke.r1.judge.{run_kind.value.casefold()}:{request_sha256}"
        ),
        maximum_attempts=2,
    )
    return build_authenticated_runner_smoke_cost_plan(
        run_kind=run_kind,
        stage="JUDGE",
        case_id=case_id,
        selection_sha256=selection_sha256,
        request_preview=preview,
    )


def _discovery_stub(label: str) -> SimpleNamespace:
    return SimpleNamespace(
        discovery_evidence_sha256=canonical_sha256({"discovery": label}),
        require_compatible_reasoning_profile=lambda _control: None,
    )


def _launch(
    *,
    config: AuditConfig,
    tmp_path: Path,
    candidate_tripwires: tuple[Decimal, Decimal] = (Decimal("1"), Decimal("1")),
    judge_tripwires: tuple[Decimal, Decimal] = (Decimal("1"), Decimal("1")),
) -> AuthenticatedRunnerSmokeOpenRouterLaunch:
    tmp_path.chmod(0o700)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "smoke-runtime-ledger.json",
        cap_usd=Decimal("250"),
    )
    budget = BudgetManager(
        total_usd=250.0,
        max_output_tokens=config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(config.execution.conservative_usd_per_million_tokens),
        max_requests_per_agent=192,
        atomic_ledger=ledger,
        require_endpoint_cost_bound=True,
    )
    candidate_manifest = SimpleNamespace(
        manifest_sha256=canonical_sha256({"manifest": "candidate"})
    )
    primary_manifest = SimpleNamespace(manifest_sha256=canonical_sha256({"manifest": "primary"}))
    replay_manifest = SimpleNamespace(manifest_sha256=canonical_sha256({"manifest": "replay"}))
    candidate_evidence = _discovery_stub("candidate")
    primary_evidence = _discovery_stub("primary")
    replay_evidence = _discovery_stub("replay")
    run_plans = (
        AuthenticatedRunnerSmokeRunPlan(
            run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
            judge_discovery_manifest=cast(Any, primary_manifest),
            judge_discovery_evidence=cast(Any, (primary_evidence,)),
            judge_registry=_candidate_registry((PRIMARY_JUDGE_ID,)),
            candidate_cost_tripwire_usd_per_attempt=candidate_tripwires[0],
            judge_cost_tripwire_usd_per_attempt=judge_tripwires[0],
        ),
        AuthenticatedRunnerSmokeRunPlan(
            run_kind=CrossLineageAdjudicationRunKind.REPLAY,
            judge_discovery_manifest=cast(Any, replay_manifest),
            judge_discovery_evidence=cast(Any, (replay_evidence,)),
            judge_registry=_candidate_registry((REPLAY_JUDGE_ID,)),
            candidate_cost_tripwire_usd_per_attempt=candidate_tripwires[1],
            judge_cost_tripwire_usd_per_attempt=judge_tripwires[1],
        ),
    )
    return AuthenticatedRunnerSmokeOpenRouterLaunch(
        config=config,
        explicitly_allow_synthetic_egress=True,
        public_lineage_capability=resolve_verified_public_model_lineage(),
        benchmark_suite=load_model_benchmark_corpus(CORPUS_PATH),
        smoke_corpus=load_authenticated_runner_smoke_corpus_bundle(SMOKE_CORPUS_PATH),
        candidate_discovery_manifest=cast(Any, candidate_manifest),
        candidate_discovery_evidence=cast(Any, (candidate_evidence,)),
        candidate_registry=_candidate_registry((CANDIDATE_ID,)),
        budget=budget,
        usage=UsageLedger(),
        run_plans=run_plans,
    )


def _fake_bundle_validator_subject() -> tuple[
    SimpleNamespace,
    list[SimpleNamespace],
    list[SimpleNamespace],
    list[SimpleNamespace],
]:
    config_fields = {
        "execution_config_sha256": "1" * 64,
        "privacy_config_sha256": "2" * 64,
        "token_budget_config_sha256": "3" * 64,
        "reasoning_policy_sha256": "4" * 64,
        "reasoning_policy_role_binding_sha256": "5" * 64,
        "reasoning_profile_sha256": "6" * 64,
    }
    previews = [
        SimpleNamespace(logical_request_id=f"smoke-request-{index}", **config_fields)
        for index in range(4)
    ]
    plans = [
        SimpleNamespace(
            request_preview=previews[index],
            maximum_attempts=2,
            maximum_cost_usd_per_attempt_exact="1",
            case_id="case-df79ea132113b863",
            selection_sha256=("721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"),
        )
        for index in range(4)
    ]
    usages = [
        SimpleNamespace(
            request_id=f"smoke-request-{index}",
            openrouter_generation_id=f"generation-{index}",
            request_body_sha256=canonical_sha256({"body": index}),
            attempts=1,
            accounted_cost_usd_exact="0.1",
        )
        for index in range(4)
    ]
    candidate = SimpleNamespace(exact_model_id=CANDIDATE_ID)
    primary = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        run_sha256="7" * 64,
        candidate=candidate,
        judge=SimpleNamespace(exact_model_id=PRIMARY_JUDGE_ID),
        candidate_cost_plan=plans[0],
        judge_cost_plan=plans[1],
        candidate_report=SimpleNamespace(result=SimpleNamespace(usage_record=usages[0])),
        adjudication_report=SimpleNamespace(cases=(SimpleNamespace(usage_record=usages[1]),)),
    )
    replay = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.REPLAY,
        run_sha256="8" * 64,
        candidate=candidate,
        judge=SimpleNamespace(exact_model_id=REPLAY_JUDGE_ID),
        candidate_cost_plan=plans[2],
        judge_cost_plan=plans[3],
        candidate_report=SimpleNamespace(result=SimpleNamespace(usage_record=usages[2])),
        adjudication_report=SimpleNamespace(cases=(SimpleNamespace(usage_record=usages[3]),)),
    )
    entries = [
        SimpleNamespace(
            request_id=usage.request_id,
            reserved_usd="1",
            actual_cost_usd="0.1",
        )
        for usage in usages
    ]
    bundle = SimpleNamespace(
        runs=(primary, replay),
        selected_case_id="case-df79ea132113b863",
        smoke_corpus_bundle_sha256=(
            "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
        ),
        maximum_provider_attempt_count=8,
        execution_sequence_request_ids=(
            usages[0].request_id,
            usages[2].request_id,
            usages[1].request_id,
            usages[3].request_id,
        ),
        closed_ledger_evidence=SimpleNamespace(entries=tuple(entries)),
        bundle_sha256="9" * 64,
        model_dump=lambda **_kwargs: {"synthetic": "bundle"},
    )
    return bundle, previews, usages, entries


def _validate_fake_bundle(
    monkeypatch: pytest.MonkeyPatch,
    bundle: SimpleNamespace,
) -> object:
    monkeypatch.setattr(smoke_evidence_module, "_require_usage_preview_join", lambda *_a: None)
    monkeypatch.setattr(
        smoke_evidence_module,
        "_canonical_sha256",
        lambda _value: bundle.bundle_sha256,
    )
    validator = cast(
        Callable[[Any], object],
        AuthenticatedRunnerSmokeEvidenceBundle.protocol_is_exact_and_self_bound,
    )
    return validator(bundle)


def _fake_run_validator_subject() -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    candidate = _approved_candidate(CANDIDATE_ID)
    judge = _approved_candidate(PRIMARY_JUDGE_ID)
    request_sha256 = "a" * 64
    candidate_usage = SimpleNamespace(
        request_id="candidate-request",
        routing={
            "privacy_profile": "SYNTHETIC_BENCHMARK",
            "privacy_source_classification": "SYNTHETIC_COMMITTED",
            "privacy_source_sha256": smoke_evidence_module._SMOKE_SOURCE_SHA256,
            "privacy_source_proof_kind": ("PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"),
        },
    )
    judge_usage = SimpleNamespace(request_id=f"authrunner.smoke.r1.judge.primary:{request_sha256}")
    embedded_candidate = SimpleNamespace(retrieved_at=NOW)
    embedded_judge = SimpleNamespace(retrieved_at=NOW)
    candidate_report = SimpleNamespace(
        run_kind="PRIMARY",
        selection_sha256="b" * 64,
        report_sha256="c" * 64,
        corpus_sha256=smoke_evidence_module._PARENT_CORPUS_SHA256,
        ground_truth_sha256=smoke_evidence_module._PARENT_GROUND_TRUTH_SHA256,
        selected_case_sha256=smoke_evidence_module._SMOKE_CORPUS_CASE_SHA256,
        selected_ground_truth_sha256=(smoke_evidence_module._SMOKE_GROUND_TRUTH_CASE_SHA256),
        result=SimpleNamespace(
            case_id="case-df79ea132113b863",
            usage_record=candidate_usage,
            generation_evidence=embedded_candidate,
        ),
        target=SimpleNamespace(
            model_id=candidate.exact_model_id,
            root_lineage=candidate.root_lineage,
        ),
    )
    candidate_plan = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        stage="CANDIDATE",
        selection_sha256="b" * 64,
        case_id="case-df79ea132113b863",
        request_preview=SimpleNamespace(
            logical_request_id=candidate_usage.request_id,
            exact_model_id=candidate.exact_model_id,
        ),
    )
    prepared = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        candidate_report_sha256=candidate_report.report_sha256,
        prepared_run_sha256="d" * 64,
        corpus_sha256=smoke_evidence_module._PARENT_CORPUS_SHA256,
        ground_truth_sha256=smoke_evidence_module._PARENT_GROUND_TRUTH_SHA256,
        case_ids=("case-df79ea132113b863",),
        requests=(
            SimpleNamespace(
                request_sha256=request_sha256,
                corpus_case_sha256=smoke_evidence_module._SMOKE_CORPUS_CASE_SHA256,
                ground_truth_case_sha256=(smoke_evidence_module._SMOKE_GROUND_TRUTH_CASE_SHA256),
            ),
        ),
        target=SimpleNamespace(
            candidate_model_id=candidate.exact_model_id,
            candidate_root_lineage=candidate.root_lineage,
            judge_model_id=judge.exact_model_id,
            judge_root_lineage=judge.root_lineage,
        ),
    )
    judge_plan = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        stage="JUDGE",
        selection_sha256=candidate_plan.selection_sha256,
        case_id=candidate_plan.case_id,
        request_preview=SimpleNamespace(
            logical_request_id=judge_usage.request_id,
            exact_model_id=judge.exact_model_id,
        ),
    )
    adjudication_report = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        prepared_run_sha256=prepared.prepared_run_sha256,
        candidate_report_sha256=candidate_report.report_sha256,
        cases=(
            SimpleNamespace(
                usage_record=judge_usage,
                generation_evidence=embedded_judge,
            ),
        ),
    )
    run = SimpleNamespace(
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
        candidate=candidate,
        judge=judge,
        candidate_cost_plan=candidate_plan,
        candidate_report=candidate_report,
        candidate_generation_refetch=SimpleNamespace(retrieved_at=NOW + timedelta(seconds=1)),
        prepared_adjudication=prepared,
        judge_cost_plan=judge_plan,
        adjudication_report=adjudication_report,
        judge_generation_refetch=SimpleNamespace(retrieved_at=NOW + timedelta(seconds=1)),
        run_sha256="e" * 64,
        model_dump=lambda **_kwargs: {"synthetic": "run"},
    )
    return run, prepared, candidate_report


def _validate_fake_run(monkeypatch: pytest.MonkeyPatch, run: SimpleNamespace) -> object:
    monkeypatch.setattr(
        smoke_evidence_module, "_require_generation_refetch", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        smoke_evidence_module,
        "_canonical_sha256",
        lambda _value: run.run_sha256,
    )
    validator = cast(
        Callable[[Any], object],
        AuthenticatedRunnerSmokeRunEvidence.run_is_exact_and_self_bound,
    )
    return validator(run)


def _usage_with_request_id(usage: UsageRecord, request_id: str) -> UsageRecord:
    payload = usage.model_dump(mode="python")
    payload["request_id"] = request_id
    routing = dict(payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    payload["routing"] = routing
    return bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )


class _StopAfterJudges(RuntimeError):
    pass


def _install_execution_order_harness(
    monkeypatch: pytest.MonkeyPatch,
    launch: AuthenticatedRunnerSmokeOpenRouterLaunch,
    *,
    fail_second_candidate_delta: bool,
) -> tuple[list[str], OperatorSecrets]:
    smoke = launch.smoke_corpus
    candidate_plans = tuple(
        _candidate_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            index=index,
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    )
    inventory = AuthenticatedRunnerSmokePreflightInventory(
        run_count=2,
        case_count=1,
        logical_request_count=4,
        maximum_attempts_per_logical_request=2,
        maximum_provider_attempt_count=8,
        generation_refetch_count=4,
        effective_config_sha256=launch.config.stable_hash(),
        initial_spent_usd=Decimal(0),
        operator_interval_tripwire_usd=Decimal("8"),
        operator_final_spent_tripwire_usd=Decimal("8"),
        candidate_cost_plans=cast(Any, candidate_plans),
        candidate_derived_interval_cost_cap_usd=Decimal("0.1"),
        candidate_derived_final_spent_cap_usd=Decimal("0.1"),
    )
    source = _as_structural_real(_report(launch.benchmark_suite, CANDIDATE_ID))
    base_usages = tuple(item.usage_record for item in source.results[0].cases[:4])
    assert all(item is not None for item in base_usages)
    request_sha256s = ("a" * 64, "b" * 64)
    candidate_usages = tuple(
        _usage_with_request_id(
            cast(UsageRecord, base_usages[index]), plan.request_preview.logical_request_id
        )
        for index, plan in enumerate(candidate_plans)
    )
    judge_plans = tuple(
        _judge_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            request_sha256=request_sha256s[index],
            index=index + 2,
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    )
    judge_usages = tuple(
        _usage_with_request_id(
            cast(UsageRecord, base_usages[index + 2]),
            plan.request_preview.logical_request_id,
        )
        for index, plan in enumerate(judge_plans)
    )
    events: list[str] = []

    class _FakeAdapter:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def candidate(self, *, plan: Any, cost_plan: Any) -> tuple[Any, Any]:
            index = 0 if plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
            events.append(f"C:{plan.run_kind.value}")
            assert cost_plan == candidate_plans[index]
            usage = candidate_usages[index]
            launch.usage.add(usage)
            report = SimpleNamespace(
                report_sha256=canonical_sha256({"candidate": index}),
                result=SimpleNamespace(usage_record=usage),
            )
            return report, SimpleNamespace(retrieved_at=NOW)

        async def prepare_judges(self, prepared: tuple[Any, ...]) -> None:
            events.append("PREPARE:PRIMARY,REPLAY")
            assert tuple(item.plan.run_kind for item in prepared) == (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )

        async def judge(self, *, prepared: Any, cost_plan: Any) -> tuple[Any, Any]:
            index = 0 if prepared.plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
            events.append(f"J:{prepared.plan.run_kind.value}")
            assert cost_plan == judge_plans[index]
            usage = judge_usages[index]
            launch.usage.add(usage)
            report = SimpleNamespace(cases=(SimpleNamespace(usage_record=usage),))
            return report, SimpleNamespace(retrieved_at=NOW)

        async def close(self) -> None:
            events.append("ADAPTER:CLOSE")

    async def adopt(**_kwargs: object) -> None:
        return None

    def prepare(**kwargs: object) -> SimpleNamespace:
        kind = cast(CrossLineageAdjudicationRunKind, kwargs["run_kind"])
        index = 0 if kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
        return SimpleNamespace(
            run_kind=kind,
            requests=(SimpleNamespace(request_sha256=request_sha256s[index]),),
        )

    def judge_plan(*, prepared: Any, **_kwargs: object) -> Any:
        index = 0 if prepared.plan.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1
        events.append(f"PLAN:{prepared.plan.run_kind.value}")
        return judge_plans[index]

    candidate_delta_count = 0

    def exact_delta(*, label: str, **_kwargs: object) -> None:
        nonlocal candidate_delta_count
        if label == "candidate":
            candidate_delta_count += 1
            if fail_second_candidate_delta and candidate_delta_count == 2:
                raise AuthenticatedRunnerSmokeOpenRouterError(
                    "synthetic second-candidate ledger anomaly"
                )

    def aggregate(**_kwargs: object) -> None:
        events.append("ADMIT:BOTH")

    def seal_run(**kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            candidate_report=kwargs["candidate_report"],
            adjudication_report=kwargs["adjudication_report"],
        )

    def stop_after_judges(*_args: object, **_kwargs: object) -> None:
        raise _StopAfterJudges

    monkeypatch.setattr(
        smoke_runtime_module,
        "preflight_authenticated_runner_smoke_openrouter_launch",
        lambda _launch: inventory,
    )
    monkeypatch.setattr(smoke_runtime_module, "_adopt_ledger_baseline", adopt)
    monkeypatch.setattr(
        smoke_runtime_module, "begin_cross_lineage_ledger_interval", lambda _l: object()
    )
    monkeypatch.setattr(smoke_runtime_module, "_SmokeOpenRouterAdapter", _FakeAdapter)
    monkeypatch.setattr(
        smoke_runtime_module,
        "prepare_noncrediting_cross_lineage_adjudication_smoke",
        prepare,
    )
    monkeypatch.setattr(smoke_runtime_module, "_judge_cost_plan", judge_plan)
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_exact_smoke_callback_ledger_delta",
        exact_delta,
    )
    monkeypatch.setattr(smoke_runtime_module, "_require_aggregate_judge_admission", aggregate)
    monkeypatch.setattr(
        smoke_runtime_module, "seal_authenticated_runner_smoke_run_evidence", seal_run
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "close_cross_lineage_ledger_interval",
        stop_after_judges,
    )
    secrets = OperatorSecrets({OPENROUTER_API_KEY_NAME: "synthetic-provider-free-order-test"})
    return events, secrets


def test_smoke_callback_ledger_delta_requires_usage_cost_equality() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, "deepseek/deepseek-v4-pro-0813"))
    usage = report.results[0].cases[0].usage_record
    assert usage is not None
    assert usage.accounted_cost_usd_exact is not None
    assert usage.attempts == 1
    actual = Decimal(usage.accounted_cost_usd_exact)
    entry = CostEntry(
        request_id=usage.request_id,
        reservation_id="synthetic-reservation",
        status=CostEntryStatus.RECONCILED,
        reserved_usd=Decimal("1"),
        actual_cost_usd=actual,
        accounted_cost_usd=actual,
        release_reason=None,
        created_at=NOW,
        updated_at=NOW,
    )
    before = _snapshot(entries=(), spent=Decimal(0))
    after = _snapshot(entries=(entry,), spent=actual)

    _require_exact_smoke_callback_ledger_delta(
        before=before,
        after=after,
        records=(usage,),
        label="candidate",
    )

    drift = Decimal("0.000001")
    mismatched_entry = CostEntry(
        **{
            **entry.__dict__,
            "actual_cost_usd": actual + drift,
            "accounted_cost_usd": actual + drift,
        }
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="ledger delta is not exact",
    ):
        _require_exact_smoke_callback_ledger_delta(
            before=before,
            after=_snapshot(entries=(mismatched_entry,), spent=actual + drift),
            records=(usage,),
            label="candidate",
        )


def test_smoke_preflight_lineage_requires_exact_documentary_roots() -> None:
    capability = resolve_verified_public_model_lineage()
    candidate = _approved_candidate("deepseek/deepseek-v4-pro-0813")
    primary = _approved_candidate("minimax/minimax-m3")
    replay = _approved_candidate("moonshotai/kimi-k3")

    _require_three_distinct_roots(
        capability,
        candidate=candidate,
        judges=(primary, replay),
    )

    wrong_review = seal_operator_lineage_review(
        status=LineageReviewStatus.APPROVED,
        reviewed_model_ids=(primary.exact_model_id,),
        rationale="Synthetic negative with a wrong but internally consistent root.",
        root_lineage=f"sha256:{'f' * 64}",
        reviewed_by="synthetic-unit-reviewer",
        reviewed_at=NOW,
        evidence_sha256="f" * 64,
    )
    wrong_primary = CandidateModel.model_validate(
        {
            **primary.model_dump(mode="python"),
            "root_lineage": wrong_review.root_lineage,
            "lineage_review": wrong_review,
        },
        strict=True,
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="projection",
    ):
        _require_three_distinct_roots(
            capability,
            candidate=candidate,
            judges=(wrong_primary, replay),
        )


def test_callback_ledger_delta_rejects_equal_aggregate_with_wrong_per_usage_costs() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, CANDIDATE_ID))
    first = report.results[0].cases[0].usage_record
    second = report.results[0].cases[1].usage_record
    assert first is not None
    assert second is not None
    first = first.model_copy(
        update={
            "accounted_cost_usd": 0.01,
            "accounted_cost_usd_exact": "0.01",
            "attempts": 1,
        }
    )
    second = second.model_copy(
        update={
            "accounted_cost_usd": 0.02,
            "accounted_cost_usd_exact": "0.02",
            "attempts": 1,
        }
    )
    wrong_entries = tuple(
        CostEntry(
            request_id=usage.request_id,
            reservation_id=f"reservation-{index}",
            status=CostEntryStatus.RECONCILED,
            reserved_usd=Decimal("1"),
            actual_cost_usd=Decimal("0.015"),
            accounted_cost_usd=Decimal("0.015"),
            release_reason=None,
            created_at=NOW,
            updated_at=NOW,
        )
        for index, usage in enumerate((first, second))
    )
    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="ledger delta is not exact",
    ):
        _require_exact_smoke_callback_ledger_delta(
            before=_snapshot(entries=(), spent=Decimal(0)),
            after=_snapshot(entries=wrong_entries, spent=Decimal("0.03")),
            records=(first, second),
            label="aggregate",
        )

    exact_entries = tuple(
        CostEntry(
            **{
                **entry.__dict__,
                "actual_cost_usd": Decimal(usage.accounted_cost_usd_exact or "0"),
                "accounted_cost_usd": Decimal(usage.accounted_cost_usd_exact or "0"),
            }
        )
        for entry, usage in zip(wrong_entries, (first, second), strict=True)
    )
    _require_exact_smoke_callback_ledger_delta(
        before=_snapshot(entries=(), spent=Decimal(0)),
        after=_snapshot(entries=exact_entries, spent=Decimal("0.03")),
        records=(first, second),
        label="aggregate",
    )


def test_usage_preview_join_binds_full_token_reasoning_discovery_and_output_projection() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _as_structural_real(_report(suite, CANDIDATE_ID))
    usage = report.results[0].cases[0].usage_record
    assert usage is not None
    preview = _cost_preview_for_usage(usage, index=0)
    bound = _usage_with_cost_preview(usage, preview)

    smoke_evidence_module._require_usage_preview_join(bound, preview)

    drifted = _replace_preview(
        preview,
        output_capability_sha256="f" * 64,
    )
    with pytest.raises(ValueError, match="exact cost preview"):
        smoke_evidence_module._require_usage_preview_join(bound, drifted)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "retries", (0, 2)
)
def test_preflight_rejects_any_retry_policy_other_than_one_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
    retries: int,
) -> None:
    launch = _launch(config=_smoke_config(config_factory, retries=retries), tmp_path=tmp_path)
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_singleton_registry",
        lambda **kwargs: kwargs["registry"].candidates[0],
    )
    monkeypatch.setattr(
        smoke_runtime_module, "_require_three_distinct_roots", lambda *_a, **_k: None
    )

    def must_not_derive_cost(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("retry inventory must reject before cost derivation")

    monkeypatch.setattr(smoke_runtime_module, "_candidate_cost_plan", must_not_derive_cost)

    with pytest.raises(
        AuthenticatedRunnerSmokeOpenRouterError,
        match="retry inventory",
    ):
        preflight_authenticated_runner_smoke_openrouter_launch(launch)


def test_preflight_operator_tripwire_sums_unequal_candidate_and_judge_roles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(
        config=_smoke_config(config_factory),
        tmp_path=tmp_path,
        candidate_tripwires=(Decimal("1"), Decimal("2")),
        judge_tripwires=(Decimal("3"), Decimal("5")),
    )
    smoke = launch.smoke_corpus
    plans = {
        kind: _candidate_smoke_plan(
            run_kind=kind,
            selection_sha256=smoke.bundle_sha256,
            case_id=smoke.case.case_id,
            index=index,
            prompt_price="0.001" if index == 0 else "0.002",
        )
        for index, kind in enumerate(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            )
        )
    }
    monkeypatch.setattr(
        smoke_runtime_module,
        "_require_singleton_registry",
        lambda **kwargs: kwargs["registry"].candidates[0],
    )
    monkeypatch.setattr(
        smoke_runtime_module, "_require_three_distinct_roots", lambda *_a, **_k: None
    )
    monkeypatch.setattr(
        smoke_runtime_module,
        "_candidate_cost_plan",
        lambda **kwargs: plans[kwargs["run_kind"]],
    )

    inventory = preflight_authenticated_runner_smoke_openrouter_launch(launch)

    assert inventory.operator_interval_tripwire_usd == Decimal("22")
    assert inventory.operator_final_spent_tripwire_usd == Decimal("22")
    assert inventory.candidate_derived_interval_cost_cap_usd == sum(
        (Decimal(plan.maximum_cost_usd_all_attempts_exact) for plan in plans.values()),
        start=Decimal(0),
    )


def test_execution_orders_both_candidates_then_both_judge_preparations_and_judges(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_config(config_factory), tmp_path=tmp_path)
    events, secrets = _install_execution_order_harness(
        monkeypatch,
        launch,
        fail_second_candidate_delta=False,
    )
    try:
        with pytest.raises(_StopAfterJudges):
            asyncio.run(
                execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=secrets,
                )
            )
    finally:
        secrets.clear()

    assert events == [
        "C:PRIMARY",
        "C:REPLAY",
        "PREPARE:PRIMARY,REPLAY",
        "PLAN:PRIMARY",
        "PLAN:REPLAY",
        "ADMIT:BOTH",
        "J:PRIMARY",
        "J:REPLAY",
        "ADAPTER:CLOSE",
    ]


def test_execution_never_prepares_or_dispatches_judge_after_candidate_ledger_anomaly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Callable[..., AuditConfig],
) -> None:
    launch = _launch(config=_config(config_factory), tmp_path=tmp_path)
    events, secrets = _install_execution_order_harness(
        monkeypatch,
        launch,
        fail_second_candidate_delta=True,
    )
    try:
        with pytest.raises(
            AuthenticatedRunnerSmokeOpenRouterError,
            match="ledger anomaly",
        ):
            asyncio.run(
                execute_authenticated_runner_smoke_openrouter(
                    launch=launch,
                    operator_secrets=secrets,
                )
            )
    finally:
        secrets.clear()

    assert events == ["C:PRIMARY", "C:REPLAY", "ADAPTER:CLOSE"]


def test_smoke_judge_namespace_requires_its_disjoint_smoke_proof_kind() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    report = _smoke_report(suite)
    judge = _judge(JUDGE_ID)
    case = suite.cases[0]
    truth = suite.ground_truth_case(case.case_id)
    prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
        public_lineage_capability=resolve_verified_public_model_lineage(),
        suite=suite,
        selected_case=case,
        selected_ground_truth=truth,
        selection_sha256=SELECTION_SHA256,
        candidate_report=report,
        judge=judge,
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
    )
    request = prepared.requests[0]
    response = build_cross_lineage_adjudication_response(
        request=request,
        dimension_outcomes=request.expected_dimension_outcomes,
        disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
        rationale="Synthetic smoke namespace and proof-kind regression.",
    )
    usage, generation = _judge_usage_and_generation(
        case_index=0,
        request=request,
        response=response,
        judge=judge,
    )
    smoke_request_id = adjudication_module._cross_lineage_adjudication_smoke_logical_request_id(
        request
    )
    release_request_id = adjudication_module._cross_lineage_adjudication_logical_request_id(request)
    assert smoke_request_id != release_request_id
    payload = usage.model_dump(mode="python")
    payload["request_id"] = smoke_request_id
    routing = dict(payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing["privacy_source_proof_kind"] = "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"
    payload["routing"] = routing
    smoke_usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )
    generation_payload = generation.model_dump(mode="json", exclude={"evidence_sha256"})
    generation_payload["request_id"] = smoke_request_id
    smoke_generation = OpenRouterGenerationEvidence.model_validate(
        {
            **generation_payload,
            "evidence_sha256": canonical_sha256(generation_payload),
        }
    )

    result = build_cross_lineage_adjudication_case_result(
        request=request,
        response=response,
        usage_record=smoke_usage,
        generation_evidence=smoke_generation,
    )
    assert result.usage_record.request_id == smoke_request_id

    wrong_payload = smoke_usage.model_dump(mode="python")
    wrong_routing = dict(wrong_payload["routing"])
    for field in _TOKEN_ROUTING_FIELDS:
        wrong_routing.pop(field, None)
    wrong_routing["privacy_source_proof_kind"] = "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
    wrong_payload["routing"] = wrong_routing
    wrong_usage = bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(wrong_payload))
    )
    with pytest.raises(ValueError, match="privacy custody"):
        build_cross_lineage_adjudication_case_result(
            request=request,
            response=response,
            usage_record=wrong_usage,
            generation_evidence=smoke_generation,
        )


def test_bundle_rejects_mixed_common_preview_config_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, previews, _usages, _entries = _fake_bundle_validator_subject()
    assert _validate_fake_bundle(monkeypatch, bundle) is bundle

    previews[3].execution_config_sha256 = "f" * 64
    with pytest.raises(ValueError, match="maximum-attempt inventory"):
        _validate_fake_bundle(monkeypatch, bundle)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "field", ("openrouter_generation_id", "request_body_sha256")
)
def test_bundle_rejects_four_way_generation_or_request_body_reuse(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    bundle, _previews, usages, _entries = _fake_bundle_validator_subject()
    setattr(usages[3], field, getattr(usages[0], field))

    with pytest.raises(ValueError, match="reuses provider request evidence"):
        _validate_fake_bundle(monkeypatch, bundle)


def test_bundle_ledger_cost_must_equal_each_usage_not_only_the_total(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle, _previews, _usages, entries = _fake_bundle_validator_subject()
    entries[0].actual_cost_usd = "0.15"
    entries[1].actual_cost_usd = "0.05"

    with pytest.raises(ValueError, match="cost differs from provider usage"):
        _validate_fake_bundle(monkeypatch, bundle)


def test_run_requires_monotonic_generation_refetch_timestamps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    assert _validate_fake_run(monkeypatch, run) is run

    run.judge_generation_refetch.retrieved_at = NOW - timedelta(seconds=1)
    with pytest.raises(ValueError, match="refetch is not fresh"):
        _validate_fake_run(monkeypatch, run)


def test_run_requires_exact_judge_request_suffix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, _prepared, _candidate_report = _fake_run_validator_subject()
    run.judge_cost_plan.request_preview.logical_request_id = (
        f"authrunner.smoke.r1.judge.primary:{'f' * 64}"
    )

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)


@pytest.mark.parametrize(  # type: ignore[untyped-decorator]
    "join", ("candidate_report", "prepared_candidate")
)
def test_run_requires_documentary_lineage_root_joins(
    monkeypatch: pytest.MonkeyPatch,
    join: str,
) -> None:
    run, prepared, candidate_report = _fake_run_validator_subject()
    if join == "candidate_report":
        candidate_report.target.root_lineage = f"sha256:{'f' * 64}"
    else:
        prepared.target.candidate_root_lineage = f"sha256:{'f' * 64}"

    with pytest.raises(ValueError, match="differs from its exact pair"):
        _validate_fake_run(monkeypatch, run)
