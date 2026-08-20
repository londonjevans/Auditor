from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.authenticated_runner_execution as authenticated_runner_execution_module
import mmaudit.models.generation_evidence as generation_evidence_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationRunKind,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_response,
)
from mmaudit.benchmark.model_portfolio import CandidateBenchmarkCampaignJournal
from mmaudit.benchmark.models import ModelBenchmarkReport, ModelBenchmarkSuite, ModelBenchmarkTarget
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerError
from mmaudit.models.authenticated_runner_execution import (
    AuthenticatedRunnerExecutionError,
    AuthenticatedRunnerExecutionResult,
    AuthenticatedRunnerGenerationSubject,
    AuthenticatedRunnerRunPlan,
    execute_authenticated_cross_lineage_runner,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkExecutionResult,
    CandidateBenchmarkRunState,
    candidate_cost_ledger_snapshot,
)
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
)
from mmaudit.models.ground_truth_authority import (
    VerifiedFrozenGroundTruth,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.public_lineage_authority import (
    VerifiedPublicModelLineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateRegistry,
    QualificationDimensionThreshold,
    QualificationPolicy,
    seal_qualification_policy,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    BudgetManager,
    EndpointRequestCostBound,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.privacy import PrivacyProfile
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    rebind_synthetic_token_plan,
)
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit import test_model_benchmark as benchmark_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
PROVENANCE_PATH = ROOT / "benchmarks" / "model_corpus" / "provenance.json"
CANDIDATE_ID = "deepseek/deepseek-v3.2-exp"
PRIMARY_JUDGE_ID = "google/gemma-4-26b-a4b-it"
REPLAY_JUDGE_ID = "meta-llama/llama-4-maverick"


def _config(config_factory: Callable[..., AuditConfig]) -> AuditConfig:
    return config_factory(
        execution={
            "budget_usd": 250.0,
            "max_model_retries": 1,
            "max_requests_per_agent": 192,
        },
        privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK},
        models={
            "provider_policy": {"allow_fallbacks": False},
            "reasoning": {"effort": "high", "reserved_tokens": 4_096},
        },
    )


@dataclass(slots=True)
class _FakeGenerationExecutor:
    evidence_by_generation_id: dict[str, OpenRouterGenerationEvidence]
    calls: list[
        tuple[
            CrossLineageAdjudicationRunKind,
            AuthenticatedRunnerGenerationSubject,
            tuple[str, ...],
        ]
    ]

    @classmethod
    def from_candidate_reports(
        cls,
        reports: tuple[ModelBenchmarkReport, ...],
    ) -> _FakeGenerationExecutor:
        evidence = {
            case.generation_evidence.generation_id: case.generation_evidence
            for report in reports
            for case in report.results[0].cases
            if case.generation_evidence is not None
        }
        return cls(evidence_by_generation_id=evidence, calls=[])

    def register_judge_results(
        self,
        results: tuple[CrossLineageAdjudicationCaseResult, ...],
    ) -> None:
        for result in results:
            self.evidence_by_generation_id[result.generation_evidence.generation_id] = (
                result.generation_evidence
            )

    async def __call__(
        self,
        *,
        run_kind: CrossLineageAdjudicationRunKind,
        subject: AuthenticatedRunnerGenerationSubject,
        requests: tuple[GenerationVerificationRequest, ...],
    ) -> TrustedGenerationVerification:
        self.calls.append(
            (
                run_kind,
                subject,
                tuple(request.usage_record.request_id for request in requests),
            )
        )
        attestations = tuple(
            self.evidence_by_generation_id[str(request.usage_record.openrouter_generation_id)]
            for request in requests
        )
        return generation_evidence_module._issue_trusted_generation_verification(
            requests=requests,
            attestations=attestations,
            verification_started_at=min(item.retrieved_at for item in attestations),
        )


@dataclass(slots=True)
class _FakeCandidateExecutor:
    reports_by_kind: dict[CrossLineageAdjudicationRunKind, ModelBenchmarkReport]
    calls: list[CrossLineageAdjudicationRunKind]
    fault: str | None = None

    async def __call__(
        self,
        *,
        run_kind: CrossLineageAdjudicationRunKind,
        config: AuditConfig,
        discovery_manifest: OpenRouterModelDiscoveryRunManifest,
        discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
        candidate_registry: CandidateRegistry,
        benchmark_suite: ModelBenchmarkSuite,
        budget: BudgetManager,
        usage: UsageLedger,
        evidence_sink: CandidateBenchmarkCampaignJournal,
        qualification_policy: QualificationPolicy,
    ) -> CandidateBenchmarkExecutionResult:
        del config, discovery_evidence, qualification_policy
        self.calls.append(run_kind)
        if self.fault == "budget_over_cap":
            candidate = candidate_registry.candidates[0]
            request_material = "{}"
            endpoint_bound = EndpointRequestCostBound.from_endpoint_pricing(
                exact_model_id=candidate.exact_model_id,
                provider_endpoint=candidate.approved_provider_endpoint,
                request_material=request_material,
                pricing={
                    "completion": "0",
                    "prompt": "0",
                    "request": "0.01",
                },
                maximum_units={
                    "completion": budget.max_output_tokens,
                    "prompt": len(request_material.encode("utf-8")),
                    "request": 1,
                },
            )
            await budget.reserve(
                "runner-cost-ceiling-probe",
                "model_benchmark",
                request_material,
                endpoint_cost_bound=endpoint_bound,
                exact_model_id=candidate.exact_model_id,
            )
            raise AssertionError("over-cap reservation must reject before provider dispatch")
        stored_report = self.reports_by_kind[run_kind]
        report = stored_report.model_copy(
            update={
                "results": [
                    result.model_copy(
                        update={
                            "cases": [
                                case.model_copy(
                                    update={
                                        "usage_record": (
                                            reattest_synthetic_real_usage(case.usage_record)
                                            if case.usage_record is not None
                                            else None
                                        )
                                    }
                                )
                                for case in result.cases
                            ]
                        }
                    )
                    for result in stored_report.results
                ]
            }
        )
        records = tuple(
            case.usage_record for case in report.results[0].cases if case.usage_record is not None
        )
        assert budget.atomic_ledger is not None
        before = candidate_cost_ledger_snapshot(budget.atomic_ledger.snapshot())
        for record in records:
            cost = Decimal(str(record.accounted_cost_usd))
            reservation = budget.atomic_ledger.reserve(record.request_id, cost)
            budget.atomic_ledger.reconcile(reservation, cost)
            usage.add(record)
        after = candidate_cost_ledger_snapshot(budget.atomic_ledger.snapshot())
        diagnostic = CandidateBenchmarkDiagnostic(
            exact_model_id=candidate_registry.candidates[0].exact_model_id,
            approved_provider_endpoint=(
                candidate_registry.candidates[0].approved_provider_endpoint
            ),
            endpoint_snapshot_sha256=(candidate_registry.candidates[0].endpoint_snapshot_sha256),
            report_sha256=report.report_sha256,
            execution_evidence=report.execution_evidence,
            state=CandidateBenchmarkRunState.COMPLETE,
            failure_stage=None,
            reasoning_suppressed=False,
            corpus_cases=len(benchmark_suite.cases),
            requests_observed=len(records),
            logical_request_count=len(records),
            provider_attempt_count=sum(record.attempts for record in records),
            retry_count=sum(record.attempts - 1 for record in records),
            successful_request_count=len(records),
            failed_request_count=0,
            unresolved_cost_count=0,
            observed_usage_sha256=canonical_sha256(
                [record.model_dump(mode="json") for record in records]
            ),
            cost_ledger_before=before,
            cost_ledger_after=after,
            successful_cases=len(records),
            failed_cases=0,
            error_kinds=(),
        )
        evidence_sink.persist_candidate(
            candidate=candidate_registry.candidates[0],
            report=report,
            diagnostic=diagnostic,
            observed_usage=records,
            ledger_before=before,
            ledger_after=after,
        )
        if self.fault == "extra_active" and run_kind is CrossLineageAdjudicationRunKind.PRIMARY:
            budget.atomic_ledger.reserve("unexpected-candidate-attempt", Decimal("0.01"))
        return CandidateBenchmarkExecutionResult(
            candidate_registry_sha256=candidate_registry.registry_sha256,
            discovery_manifest_sha256=discovery_manifest.manifest_sha256,
            benchmark_corpus_sha256=benchmark_suite.corpus_sha256,
            benchmark_ground_truth_sha256=benchmark_suite.ground_truth_sha256,
            reports=(report,),
            diagnostics=(diagnostic,),
        )


@dataclass(slots=True)
class _FakeJudgeExecutor:
    public_lineage: VerifiedPublicModelLineage
    suite: ModelBenchmarkSuite
    reports_by_kind: dict[CrossLineageAdjudicationRunKind, ModelBenchmarkReport]
    generation_executor: _FakeGenerationExecutor
    judges_by_kind: dict[CrossLineageAdjudicationRunKind, CandidateModel]
    fault: str | None = None
    calls: list[CrossLineageAdjudicationRunKind] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []

    async def __call__(
        self,
        *,
        config: AuditConfig,
        prepared: CrossLineageAdjudicationPreparedRun,
        judge: CandidateModel,
        budget: BudgetManager,
        usage: UsageLedger,
    ) -> tuple[CrossLineageAdjudicationCaseResult, ...]:
        del config
        assert self.calls is not None
        self.calls.append(prepared.run_kind)
        report_judge = judge
        if self.fault == "swapped_route" and prepared.run_kind is (
            CrossLineageAdjudicationRunKind.PRIMARY
        ):
            report_judge = self.judges_by_kind[CrossLineageAdjudicationRunKind.REPLAY]
        request_offset = (
            0 if prepared.run_kind is CrossLineageAdjudicationRunKind.PRIMARY else 1_000
        )
        report_cases: list[CrossLineageAdjudicationCaseResult] = []
        for index, request in enumerate(prepared.requests):
            response = build_cross_lineage_adjudication_response(
                request=request,
                dimension_outcomes=request.expected_dimension_outcomes,
                disposition=CrossLineageAdjudicationDisposition.CONFIRMED,
                rationale="Synthetic structural adjudication fixture.",
            )
            record, generation = runner_fixtures._judge_usage_and_generation(
                case_index=request_offset + index,
                request=request,
                response=response,
                judge=report_judge,
            )
            report_cases.append(
                build_cross_lineage_adjudication_case_result(
                    request=request,
                    response=response,
                    usage_record=record,
                    generation_evidence=generation,
                )
            )
        report = runner_fixtures.build_cross_lineage_adjudication_report(
            prepared=prepared,
            results=report_cases,
        )
        assert budget.atomic_ledger is not None
        for index, result in enumerate(report.cases):
            record = result.usage_record
            cost = Decimal(str(record.accounted_cost_usd))
            if self.fault == "partial" and index == 0:
                budget.atomic_ledger.reserve(record.request_id, cost)
            elif self.fault == "missing" and index == 0:
                pass
            elif self.fault == "noncontiguous" and index == 0:
                reservation = budget.atomic_ledger.reserve(
                    f"{record.request_id}:attempt:2",
                    cost,
                )
                budget.atomic_ledger.reconcile(reservation, cost)
            else:
                reservation = budget.atomic_ledger.reserve(record.request_id, cost)
                budget.atomic_ledger.reconcile(reservation, cost)
            usage.add(record)
        if self.fault == "extra" and prepared.run_kind is CrossLineageAdjudicationRunKind.REPLAY:
            reservation = budget.atomic_ledger.reserve("unexpected-runner-attempt", Decimal("0.01"))
            budget.atomic_ledger.reconcile(reservation, Decimal("0.01"))
        self.generation_executor.register_judge_results(report.cases)
        return report.cases


@dataclass(frozen=True, slots=True)
class _Harness:
    config: AuditConfig
    public_lineage: VerifiedPublicModelLineage
    ground_truth: VerifiedFrozenGroundTruth
    suite: ModelBenchmarkSuite
    discovery_manifest: OpenRouterModelDiscoveryRunManifest
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...]
    registry: CandidateRegistry
    policy: QualificationPolicy
    budget: BudgetManager
    usage: UsageLedger
    plans: tuple[AuthenticatedRunnerRunPlan, ...]
    candidate_executor: _FakeCandidateExecutor
    judge_executor: _FakeJudgeExecutor
    generation_executor: _FakeGenerationExecutor


async def _candidate_reports(candidate: CandidateModel) -> tuple[ModelBenchmarkReport, ...]:
    primary = qualification_fixtures._as_real_report(
        await qualification_fixtures._mock_report(
            target=ModelBenchmarkTarget(model_id=CANDIDATE_ID)
        ),
        candidate=candidate,
    )
    replay = qualification_fixtures._as_real_report(
        await qualification_fixtures._mock_report(
            target=ModelBenchmarkTarget(
                model_id=CANDIDATE_ID,
                request_role="model_benchmark:falsifier:verifier",
            )
        ),
        candidate=candidate,
    )
    payload = replay.model_dump(mode="json")
    result = payload["results"][0]
    result["target"]["request_role"] = "model_benchmark"
    for case in result["cases"]:
        usage_payload = dict(case["usage_record"])
        usage_payload["role"] = "model_benchmark"
        routing = dict(usage_payload["routing"])
        for key in (
            "request_token_plan",
            "request_token_plan_sha256",
            "atomic_token_reservation",
            "atomic_token_reservation_sha256",
            "atomic_token_reservations",
            "atomic_token_reservation_sha256s",
        ):
            routing.pop(key, None)
        usage_payload["routing"] = routing
        usage = bind_synthetic_usage_identity(
            rebind_synthetic_token_plan(UsageRecord.model_validate(usage_payload))
        )
        case["usage_record"] = usage.model_dump(mode="json")
        case["generation_evidence"] = benchmark_fixtures._forged_real_generation_evidence(
            usage
        ).model_dump(mode="json")
    return primary, runner_fixtures._reseal_report(payload)


async def _harness(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    *,
    candidate_fault: str | None = None,
    judge_fault: str | None = None,
) -> _Harness:
    tmp_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp_path.chmod(0o700)
    config = _config(config_factory)
    discovery_manifest, discovery_evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / "inputs",
        config=config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=CANDIDATE_ID,
                provider_endpoint="candidate-provider/fp8",
                provider_name="Candidate Provider",
            ),
        ),
    )
    suite = runner_fixtures.load_model_benchmark_corpus(CORPUS_PATH)
    public_lineage = resolve_verified_public_model_lineage()
    ground_truth = resolve_verified_frozen_ground_truth(
        provenance=load_frozen_ground_truth_provenance(PROVENANCE_PATH),
        benchmark_suite=suite,
    )
    reports = await _candidate_reports(registry.candidates[0])
    reports_by_kind = {
        CrossLineageAdjudicationRunKind.PRIMARY: reports[0],
        CrossLineageAdjudicationRunKind.REPLAY: reports[1],
    }
    generation_executor = _FakeGenerationExecutor.from_candidate_reports(reports)
    candidate_executor = _FakeCandidateExecutor(
        reports_by_kind=reports_by_kind,
        calls=[],
        fault=candidate_fault,
    )
    judge_discoveries = tuple(
        candidate_fixtures._discovery_and_registry(
            tmp_path=tmp_path / f"judge-input-{index}",
            config=config,
            specs=(
                candidate_fixtures._CandidateSpec(
                    model_id=model_id,
                    provider_endpoint=f"provider-judge-{index}",
                    provider_name=f"Synthetic Judge {index}",
                ),
            ),
        )
        for index, model_id in enumerate(
            (PRIMARY_JUDGE_ID, REPLAY_JUDGE_ID),
            start=1,
        )
    )
    judges_by_kind = {
        run_kind: judge_registry.candidates[0]
        for run_kind, (_manifest, _evidence, judge_registry) in zip(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            ),
            judge_discoveries,
            strict=True,
        )
    }
    judge_executor = _FakeJudgeExecutor(
        public_lineage=public_lineage,
        suite=suite,
        reports_by_kind=reports_by_kind,
        generation_executor=generation_executor,
        judges_by_kind=judges_by_kind,
        fault=judge_fault,
    )
    plans = tuple(
        AuthenticatedRunnerRunPlan(
            run_kind=run_kind,
            campaign_path=tmp_path / f"campaign-{run_kind.value.lower()}",
            portfolio_path=tmp_path / f"portfolio-{run_kind.value.lower()}",
            judge_discovery_manifest=judge_manifest,
            judge_discovery_evidence=judge_evidence,
            judge_registry=judge_registry,
            candidate_declared_cost_cap_usd_per_attempt=Decimal("0.01"),
            judge_declared_cost_cap_usd_per_attempt=Decimal("0.01"),
        )
        for run_kind, (judge_manifest, judge_evidence, judge_registry) in zip(
            (
                CrossLineageAdjudicationRunKind.PRIMARY,
                CrossLineageAdjudicationRunKind.REPLAY,
            ),
            judge_discoveries,
            strict=True,
        )
    )
    return _Harness(
        config=config,
        public_lineage=public_lineage,
        ground_truth=ground_truth,
        suite=suite,
        discovery_manifest=discovery_manifest,
        discovery_evidence=discovery_evidence,
        registry=registry,
        policy=qualification_fixtures._policy(),
        budget=candidate_fixtures._budget(tmp_path / "ledger", config),
        usage=UsageLedger(),
        plans=plans,
        candidate_executor=candidate_executor,
        judge_executor=judge_executor,
        generation_executor=generation_executor,
    )


async def _execute(
    harness: _Harness,
    *,
    explicitly_allow_synthetic_egress: bool = True,
) -> AuthenticatedRunnerExecutionResult:
    return await execute_authenticated_cross_lineage_runner(
        config=harness.config,
        explicitly_allow_synthetic_egress=explicitly_allow_synthetic_egress,
        public_lineage_capability=harness.public_lineage,
        ground_truth_capability=harness.ground_truth,
        benchmark_suite=harness.suite,
        discovery_manifest=harness.discovery_manifest,
        discovery_evidence=harness.discovery_evidence,
        candidate_registry=harness.registry,
        qualification_policy=harness.policy,
        budget=harness.budget,
        usage=harness.usage,
        run_plans=harness.plans,
        candidate_executor=harness.candidate_executor,
        judge_executor=harness.judge_executor,
        generation_executor=harness.generation_executor,
    )


async def _assert_preflight_rejection(
    harness: _Harness,
    *,
    expected: str,
) -> None:
    with pytest.raises(AuthenticatedRunnerExecutionError) as caught:
        await _execute(harness)

    assert str(caught.value) == expected
    assert harness.candidate_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_fake_full_orchestration_cannot_issue_runner_custody(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)

    with pytest.raises(
        AuthenticatedCrossLineageRunnerError,
        match="usage lacks owned REAL transport origin",
    ):
        await _execute(harness)

    assert harness.budget.atomic_ledger is not None
    snapshot = harness.budget.atomic_ledger.snapshot()
    assert snapshot.spent_usd == Decimal("0.96")
    assert len(snapshot.entries) == 96
    assert harness.candidate_executor.calls == [
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    ]
    assert harness.judge_executor.calls == harness.candidate_executor.calls
    assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
        AuthenticatedRunnerGenerationSubject.JUDGE,
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
        AuthenticatedRunnerGenerationSubject.JUDGE,
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["missing", "extra", "partial", "noncontiguous"])
async def test_rejects_inexact_or_nonterminal_ledger_intervals(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    fault: str,
) -> None:
    harness = await _harness(tmp_path, config_factory, judge_fault=fault)

    with pytest.raises(ValueError, match="ledger"):
        await _execute(harness)

    if fault == "extra":
        assert harness.candidate_executor.calls == [
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        ]
        assert harness.judge_executor.calls == harness.candidate_executor.calls
        assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.JUDGE,
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
        ]
    else:
        assert harness.candidate_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
        assert harness.judge_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
        assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
            AuthenticatedRunnerGenerationSubject.CANDIDATE
        ]


@pytest.mark.asyncio
async def test_nonterminal_primary_candidate_ledger_stops_generation_and_judging(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory, candidate_fault="extra_active")

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="PRIMARY candidate callback ledger delta",
    ):
        await _execute(harness)

    assert harness.candidate_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    snapshot = harness.budget.atomic_ledger.snapshot()
    assert snapshot.active_reserved_usd == Decimal("0.01")
    assert len(snapshot.entries) == 25


@pytest.mark.asyncio
async def test_rejects_swapped_judge_route_before_generation_credit(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory, judge_fault="swapped_route")

    with pytest.raises(ValueError, match="exact judge route"):
        await _execute(harness)

    assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
        AuthenticatedRunnerGenerationSubject.CANDIDATE
    ]


@pytest.mark.asyncio
async def test_preflight_rejects_plan_order_and_cost_cap_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    reversed_harness = await _harness(tmp_path / "order", config_factory)
    reversed_harness = replace(reversed_harness, plans=tuple(reversed(reversed_harness.plans)))
    with pytest.raises(AuthenticatedRunnerExecutionError, match="PRIMARY then REPLAY"):
        await _execute(reversed_harness)
    assert reversed_harness.candidate_executor.calls == []

    cap_harness = await _harness(tmp_path / "cap", config_factory)
    excessive_plans = tuple(
        replace(
            plan,
            candidate_declared_cost_cap_usd_per_attempt=Decimal("2"),
            judge_declared_cost_cap_usd_per_attempt=Decimal("2"),
        )
        for plan in cap_harness.plans
    )
    cap_harness = replace(cap_harness, plans=excessive_plans)
    with pytest.raises(AuthenticatedRunnerExecutionError, match="strictly below 250 USD"):
        await _execute(cap_harness)
    assert cap_harness.candidate_executor.calls == []


@pytest.mark.asyncio
async def test_declared_candidate_attempt_cap_rejects_before_ledger_reservation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory, candidate_fault="budget_over_cap")
    plans = tuple(
        replace(
            plan,
            candidate_declared_cost_cap_usd_per_attempt=Decimal("0.0001"),
        )
        for plan in harness.plans
    )
    harness = replace(harness, plans=plans)

    with pytest.raises(BudgetExhaustedError, match="active per-request cost ceiling"):
        await _execute(harness)

    assert harness.candidate_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_preflight_identifies_strict_zdr_profile_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)
    payload: dict[str, Any] = harness.config.model_dump(mode="json")
    payload["privacy"]["profile"] = PrivacyProfile.STRICT_ZDR.value
    changed = replace(harness, config=AuditConfig.model_validate(payload))

    await _assert_preflight_rejection(
        changed,
        expected=("runner privacy profile is STRICT_ZDR; expected SYNTHETIC_BENCHMARK"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("privacy_update", "expected"),
    [
        (
            {"require_zdr": False},
            "runner SYNTHETIC_BENCHMARK policy requires require_zdr=true",
        ),
        (
            {"maximum_model_retention": "temporary"},
            ("runner SYNTHETIC_BENCHMARK policy requires maximum_model_retention=zero"),
        ),
        (
            {"store_raw_responses": True},
            ("runner SYNTHETIC_BENCHMARK policy refuses raw prompt or response storage"),
        ),
    ],
)
async def test_preflight_identifies_zdr_and_retention_control_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    privacy_update: dict[str, object],
    expected: str,
) -> None:
    harness = await _harness(tmp_path, config_factory)
    changed_privacy = harness.config.privacy.model_copy(update=privacy_update)
    changed = replace(
        harness,
        config=harness.config.model_copy(update={"privacy": changed_privacy}),
    )

    await _assert_preflight_rejection(changed, expected=expected)


@pytest.mark.asyncio
async def test_preflight_identifies_fallback_policy_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)
    payload: dict[str, Any] = harness.config.model_dump(mode="json")
    payload["models"]["provider_policy"]["allow_fallbacks"] = True
    changed = replace(harness, config=AuditConfig.model_validate(payload))

    await _assert_preflight_rejection(
        changed,
        expected="runner provider fallback is enabled; no fallback is allowed",
    )


@pytest.mark.asyncio
async def test_preflight_sanitizes_local_egress_allowlist_failure_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = await _harness(tmp_path, config_factory)

    def reject_egress(**_kwargs: object) -> None:
        raise ValueError("untrusted dynamic rejection detail")

    monkeypatch.setattr(
        authenticated_runner_execution_module,
        "validate_candidate_benchmark_egress",
        reject_egress,
    )

    await _assert_preflight_rejection(
        harness,
        expected="runner frozen corpus is outside the synthetic-source egress allowlist",
    )


@pytest.mark.asyncio
async def test_programmatic_egress_denial_stops_before_callback_or_ledger_mutation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="explicit synthetic-source egress authorization",
    ):
        await _execute(harness, explicitly_allow_synthetic_egress=False)

    assert harness.candidate_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_preflight_identifies_policy_capacity_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)
    thresholds = tuple(
        QualificationDimensionThreshold(
            dimension=threshold.dimension,
            minimum_cases=(25 if index == 0 else threshold.minimum_cases),
            minimum_score=threshold.minimum_score,
        )
        for index, threshold in enumerate(harness.policy.thresholds)
    )
    policy = seal_qualification_policy(
        created_at=harness.policy.created_at,
        thresholds=thresholds,
        tier_a_minimum_overall_score=harness.policy.tier_a_minimum_overall_score,
        maximum_validity_days=harness.policy.maximum_validity_days,
        maximum_benchmark_evidence_age_days=(harness.policy.maximum_benchmark_evidence_age_days),
    )

    await _assert_preflight_rejection(
        replace(harness, policy=policy),
        expected="runner qualification policy exceeds frozen-corpus case capacity",
    )


@pytest.mark.asyncio
async def test_preflight_identifies_frozen_ground_truth_failure_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory)
    absent_authority: VerifiedFrozenGroundTruth = object.__new__(VerifiedFrozenGroundTruth)

    await _assert_preflight_rejection(
        replace(harness, ground_truth=absent_authority),
        expected="runner frozen ground-truth capability does not bind the exact suite",
    )


@pytest.mark.asyncio
async def test_preflight_identifies_each_budget_control_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config_harness = await _harness(tmp_path / "config", config_factory)
    changed_execution = config_harness.config.execution.model_copy(update={"budget_usd": 249.0})
    await _assert_preflight_rejection(
        replace(
            config_harness,
            config=config_harness.config.model_copy(update={"execution": changed_execution}),
        ),
        expected="runner configured execution budget must equal 250 USD",
    )

    manager_harness = await _harness(tmp_path / "manager", config_factory)
    manager_harness.budget.total_usd = 249.0
    await _assert_preflight_rejection(
        manager_harness,
        expected="runner shared budget manager total must equal 250 USD",
    )

    endpoint_harness = await _harness(tmp_path / "endpoint", config_factory)
    endpoint_harness.budget.require_endpoint_cost_bound = False
    await _assert_preflight_rejection(
        endpoint_harness,
        expected="runner shared budget must require endpoint cost binding",
    )

    ledger_harness = await _harness(tmp_path / "ledger", config_factory)
    wrong_ledger_parent = tmp_path / "wrong-ledger"
    wrong_ledger_parent.mkdir(mode=0o700)
    wrong_ledger = AtomicCostLedger.initialize(
        wrong_ledger_parent / "cost-ledger.json",
        cap_usd=Decimal("249"),
    )
    wrong_budget = BudgetManager(
        total_usd=250.0,
        max_output_tokens=ledger_harness.config.execution.max_output_tokens_per_request,
        conservative_usd_per_million_tokens=(
            ledger_harness.config.execution.conservative_usd_per_million_tokens
        ),
        max_requests_per_agent=ledger_harness.config.execution.max_requests_per_agent,
        atomic_ledger=wrong_ledger,
        require_endpoint_cost_bound=True,
    )
    await _assert_preflight_rejection(
        replace(ledger_harness, budget=wrong_budget),
        expected="runner atomic cost ledger cap must equal 250 USD",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["collision", "linked_parent", "unsafe_parent"])
async def test_preflight_rejects_unsafe_output_custody_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    fault: str,
) -> None:
    harness = await _harness(tmp_path / fault, config_factory)
    first = harness.plans[0]
    if fault == "collision":
        first.portfolio_path.mkdir(mode=0o700)
    elif fault == "linked_parent":
        real_parent = tmp_path / "linked-real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        first = replace(first, portfolio_path=linked_parent / "portfolio")
    else:
        unsafe_parent = tmp_path / "unsafe-parent"
        unsafe_parent.mkdir(mode=0o755)
        unsafe_parent.chmod(0o755)
        first = replace(first, portfolio_path=unsafe_parent / "portfolio")
    harness = replace(harness, plans=(first, harness.plans[1]))

    with pytest.raises(AuthenticatedRunnerExecutionError, match=r"output|fresh|linked"):
        await _execute(harness)

    assert harness.candidate_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()
