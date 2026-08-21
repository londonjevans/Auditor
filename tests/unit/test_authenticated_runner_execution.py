from __future__ import annotations

import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import mmaudit.models.authenticated_runner_execution as authenticated_runner_execution_module
import mmaudit.models.generation_evidence as generation_evidence_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationDisposition,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationRunKind,
    adjudication_generation_verification_requests,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_response,
)
from mmaudit.benchmark.model_portfolio import (
    CandidateBenchmarkCampaignJournal,
)
from mmaudit.benchmark.models import (
    ModelBenchmarkCaseResult,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
)
from mmaudit.config import AuditConfig
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageRunnerError,
    VerifiedCrossLineageRunnerCustody,
)
from mmaudit.models.authenticated_runner_cost_plan import (
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
)
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
from mmaudit.models.endpoint_snapshots import EndpointSnapshotValidationError
from mmaudit.models.generation_evidence import (
    GenerationEvidenceValidationError,
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
)
from mmaudit.models.ground_truth_authority import (
    VerifiedFrozenGroundTruth,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
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
from mmaudit.models.qualification_workflow import (
    candidate_generation_verification_requests,
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
    rebind_synthetic_token_plan,
)
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit import test_candidate_benchmark as candidate_fixtures
from tests.unit import test_model_benchmark as benchmark_fixtures
from tests.unit import test_qualification_workflow as qualification_fixtures

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
PROVENANCE_PATH = ROOT / "benchmarks" / "model_corpus" / "provenance.json"
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


def _usage_bound_to_preview(
    record: UsageRecord,
    preview: OpenRouterStructuredRequestCostPreview,
) -> UsageRecord:
    payload = record.model_dump(mode="python")
    payload["request_id"] = preview.logical_request_id
    routing = dict(record.routing)
    for field in _TOKEN_ROUTING_FIELDS:
        routing.pop(field, None)
    routing.update(
        {
            "request_cost_preview_sha256": preview.preview_sha256,
            "request_cost_preview_maximum_cost_usd_per_attempt_exact": (
                preview.maximum_cost_usd_per_attempt_exact
            ),
            "request_cost_preview_maximum_cost_usd_all_attempts_exact": (
                preview.maximum_cost_usd_all_attempts_exact
            ),
        }
    )
    payload["routing"] = routing
    return bind_synthetic_usage_identity(
        rebind_synthetic_token_plan(UsageRecord.model_validate(payload))
    )


def _candidate_case_bound_to_preview(
    *,
    case: ModelBenchmarkCaseResult,
    preview: OpenRouterStructuredRequestCostPreview,
) -> ModelBenchmarkCaseResult:
    assert case.usage_record is not None
    usage_record = _usage_bound_to_preview(case.usage_record, preview)
    return case.model_copy(
        update={
            "usage_record": usage_record,
            "generation_evidence": benchmark_fixtures._forged_real_generation_evidence(
                usage_record
            ),
        }
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
    atomic_ledger: AtomicCostLedger | None = None
    usage: UsageLedger | None = None
    fault: tuple[AuthenticatedRunnerGenerationSubject, str] | None = None
    issued_capabilities: (
        list[tuple[TrustedGenerationVerification, tuple[GenerationVerificationRequest, ...]]] | None
    ) = None

    @classmethod
    def from_candidate_reports(
        cls,
        reports: tuple[ModelBenchmarkReport, ...],
        *,
        atomic_ledger: AtomicCostLedger | None = None,
        usage: UsageLedger | None = None,
        fault: tuple[AuthenticatedRunnerGenerationSubject, str] | None = None,
    ) -> _FakeGenerationExecutor:
        evidence = {
            case.generation_evidence.generation_id: case.generation_evidence
            for report in reports
            for case in report.results[0].cases
            if case.generation_evidence is not None
        }
        return cls(
            evidence_by_generation_id=evidence,
            calls=[],
            atomic_ledger=atomic_ledger,
            usage=usage,
            fault=fault,
            issued_capabilities=[],
        )

    def register_judge_results(
        self,
        results: tuple[CrossLineageAdjudicationCaseResult, ...],
    ) -> None:
        for result in results:
            self.evidence_by_generation_id[result.generation_evidence.generation_id] = (
                result.generation_evidence
            )

    def register_candidate_report(self, report: ModelBenchmarkReport) -> None:
        for result in report.results:
            for case in result.cases:
                if case.generation_evidence is not None:
                    self.evidence_by_generation_id[case.generation_evidence.generation_id] = (
                        case.generation_evidence
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
        if self.fault is not None and self.fault[0] is subject:
            mutation = self.fault[1]
            if mutation == "usage":
                assert self.usage is not None
                self.usage.add(requests[0].usage_record)
            else:
                assert mutation == "ledger"
                assert self.atomic_ledger is not None
                mutation_id = (
                    f"generation-{subject.value.lower()}-{run_kind.value.lower()}-mutation"
                )
                reservation = self.atomic_ledger.reserve(mutation_id, Decimal("0.01"))
                self.atomic_ledger.reconcile(reservation, Decimal("0.01"))
        capability = generation_evidence_module._issue_trusted_generation_verification(
            requests=requests,
            attestations=attestations,
            verification_started_at=min(item.retrieved_at for item in attestations),
        )
        assert self.issued_capabilities is not None
        self.issued_capabilities.append((capability, requests))
        return capability


@dataclass(slots=True)
class _FakeCandidateExecutor:
    reports_by_kind: dict[CrossLineageAdjudicationRunKind, ModelBenchmarkReport]
    generation_executor: _FakeGenerationExecutor
    calls: list[CrossLineageAdjudicationRunKind]
    request_cost_plans: list[AuthenticatedRunnerStagedCostPlan]
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
        request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    ) -> CandidateBenchmarkExecutionResult:
        del config, discovery_evidence, qualification_policy
        self.calls.append(run_kind)
        self.request_cost_plans.append(request_cost_plan)
        assert request_cost_plan.run_kind is run_kind
        assert request_cost_plan.stage is AuthenticatedRunnerCostPlanStage.CANDIDATE
        assert len(request_cost_plan.request_previews) == len(benchmark_suite.cases)
        if self.fault == "budget_over_cap":
            candidate = candidate_registry.candidates[0]
            preview = request_cost_plan.request_previews[0]
            request_material = "{}"
            endpoint_bound = EndpointRequestCostBound.from_endpoint_pricing(
                exact_model_id=candidate.exact_model_id,
                provider_endpoint=candidate.approved_provider_endpoint,
                request_material=request_material,
                pricing={
                    "completion": "0",
                    "prompt": "0",
                    "request": "2",
                },
                maximum_units={
                    "completion": preview.requested_completion_tokens,
                    "prompt": preview.prompt_byte_upper_bound_tokens,
                    "request": 1,
                },
            )
            await budget.reserve(
                "runner-cost-ceiling-probe",
                "model_benchmark",
                request_material,
                endpoint_cost_bound=endpoint_bound,
                exact_model_id=candidate.exact_model_id,
                planned_prompt_tokens=preview.prompt_byte_upper_bound_tokens,
                planned_visible_output_tokens=preview.reserved_output_tokens,
                planned_reasoning_tokens=preview.reserved_reasoning_tokens,
                planned_completion_tokens=preview.requested_completion_tokens,
                request_token_plan_sha256=preview.request_token_plan_projection_sha256,
            )
            raise AssertionError("over-cap reservation must reject before provider dispatch")
        stored_report = self.reports_by_kind[run_kind]
        provisional_report = stored_report.model_copy(
            update={
                "results": [
                    result.model_copy(
                        update={
                            "cases": [
                                _candidate_case_bound_to_preview(
                                    case=case,
                                    preview=request_cost_plan.request_previews[index],
                                )
                                for index, case in enumerate(result.cases)
                            ]
                        }
                    )
                    for result in stored_report.results
                ]
            }
        )
        sealed_report = runner_fixtures._reseal_report(provisional_report.model_dump(mode="json"))
        report = sealed_report.model_copy(update={"results": provisional_report.results})
        self.generation_executor.register_candidate_report(report)
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
class _FakeJudgeRoutePreparationExecutor:
    calls: list[
        tuple[
            tuple[CrossLineageAdjudicationRunKind, ...],
            tuple[str, ...],
            tuple[str, ...],
        ]
    ]

    async def __call__(
        self,
        *,
        config: AuditConfig,
        prepared_runs: tuple[CrossLineageAdjudicationPreparedRun, ...],
        judges: tuple[CandidateModel, ...],
    ) -> None:
        del config
        assert tuple(item.run_kind for item in prepared_runs) == (
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        )
        assert tuple(item.target.judge_model_id for item in prepared_runs) == tuple(
            judge.exact_model_id for judge in judges
        )
        self.calls.append(
            (
                tuple(item.run_kind for item in prepared_runs),
                tuple(judge.exact_model_id for judge in judges),
                tuple(item.prepared_run_sha256 for item in prepared_runs),
            )
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
    request_cost_plans: list[AuthenticatedRunnerStagedCostPlan] | None = None

    def __post_init__(self) -> None:
        if self.calls is None:
            self.calls = []
        if self.request_cost_plans is None:
            self.request_cost_plans = []

    async def __call__(
        self,
        *,
        config: AuditConfig,
        prepared: CrossLineageAdjudicationPreparedRun,
        judge: CandidateModel,
        budget: BudgetManager,
        usage: UsageLedger,
        request_cost_plan: AuthenticatedRunnerStagedCostPlan,
    ) -> tuple[CrossLineageAdjudicationCaseResult, ...]:
        del config
        assert self.calls is not None
        assert self.request_cost_plans is not None
        self.calls.append(prepared.run_kind)
        self.request_cost_plans.append(request_cost_plan)
        assert request_cost_plan.run_kind is prepared.run_kind
        assert request_cost_plan.stage is AuthenticatedRunnerCostPlanStage.JUDGE
        assert len(request_cost_plan.request_previews) == len(prepared.requests)
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
            record = _usage_bound_to_preview(
                record,
                request_cost_plan.request_previews[index],
            )
            generation = benchmark_fixtures._forged_real_generation_evidence(record)
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
    judge_route_preparation_executor: _FakeJudgeRoutePreparationExecutor
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
        for key in _TOKEN_ROUTING_FIELDS:
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
    generation_fault: tuple[AuthenticatedRunnerGenerationSubject, str] | None = None,
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
                native_structured_output_parameter="structured_outputs",
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
    budget = candidate_fixtures._budget(tmp_path / "ledger", config)
    usage = UsageLedger()
    generation_executor = _FakeGenerationExecutor.from_candidate_reports(
        reports,
        atomic_ledger=budget.atomic_ledger,
        usage=usage,
        fault=generation_fault,
    )
    candidate_executor = _FakeCandidateExecutor(
        reports_by_kind=reports_by_kind,
        generation_executor=generation_executor,
        calls=[],
        request_cost_plans=[],
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
                    native_structured_output_parameter="structured_outputs",
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
    judge_route_preparation_executor = _FakeJudgeRoutePreparationExecutor(calls=[])
    plans = tuple(
        AuthenticatedRunnerRunPlan(
            run_kind=run_kind,
            campaign_path=tmp_path / f"campaign-{run_kind.value.lower()}",
            portfolio_path=tmp_path / f"portfolio-{run_kind.value.lower()}",
            judge_discovery_manifest=judge_manifest,
            judge_discovery_evidence=judge_evidence,
            judge_registry=judge_registry,
            candidate_declared_cost_cap_usd_per_attempt=Decimal("1"),
            judge_declared_cost_cap_usd_per_attempt=Decimal("1"),
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
        budget=budget,
        usage=usage,
        plans=plans,
        candidate_executor=candidate_executor,
        judge_route_preparation_executor=judge_route_preparation_executor,
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
        judge_route_preparation_executor=harness.judge_route_preparation_executor,
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
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


def _assert_exact_preview_bindings(harness: _Harness) -> None:
    judge_plans = harness.judge_executor.request_cost_plans
    assert judge_plans is not None
    plans = (
        *harness.candidate_executor.request_cost_plans,
        *judge_plans,
    )
    assert len(plans) == 4
    records = tuple(harness.usage.records)
    assert len(records) == 96
    for offset, plan in enumerate(plans):
        plan_records = records[offset * 24 : (offset + 1) * 24]
        assert tuple(record.request_id for record in plan_records) == tuple(
            preview.logical_request_id for preview in plan.request_previews
        )
        for record, preview in zip(plan_records, plan.request_previews, strict=True):
            assert record.routing["request_cost_preview_sha256"] == preview.preview_sha256
            assert (
                record.routing["request_cost_preview_maximum_cost_usd_per_attempt_exact"]
                == preview.maximum_cost_usd_per_attempt_exact
            )
            assert (
                record.routing["request_cost_preview_maximum_cost_usd_all_attempts_exact"]
                == preview.maximum_cost_usd_all_attempts_exact
            )
            assert record.accounted_cost_usd_exact is not None
            assert Decimal(record.accounted_cost_usd_exact) <= Decimal(
                preview.maximum_cost_usd_per_attempt_exact
            )


@pytest.mark.asyncio
async def test_public_executor_captures_impl_and_child_custody_factory(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = await _harness(tmp_path, config_factory)
    invocations: list[str] = []

    async def forged_impl(**_kwargs: object) -> AuthenticatedRunnerExecutionResult:
        invocations.append("impl")
        raise AssertionError("retargeted runner implementation was invoked")

    def forged_factory() -> object:
        invocations.append("factory")
        raise AssertionError("retargeted child-custody factory was invoked")

    def forged_result_factory(**_kwargs: object) -> AuthenticatedRunnerExecutionResult:
        invocations.append("result")
        raise AssertionError("retargeted execution-result factory was invoked")

    monkeypatch.setattr(
        authenticated_runner_execution_module,
        "_execute_authenticated_cross_lineage_runner_impl",
        forged_impl,
    )
    monkeypatch.setattr(
        authenticated_runner_execution_module,
        "_new_runner_child_capability_custody",
        forged_factory,
    )
    monkeypatch.setattr(
        authenticated_runner_execution_module,
        "_new_authenticated_runner_execution_result",
        forged_result_factory,
    )

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="explicit synthetic-source egress authorization",
    ):
        await _execute(harness, explicitly_allow_synthetic_egress=False)

    assert invocations == []
    assert harness.candidate_executor.calls == []
    assert harness.generation_executor.calls == []


def test_execution_result_factory_captures_original_dataclass_initializer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = cast(
        Callable[..., AuthenticatedRunnerExecutionResult],
        cast(Any, authenticated_runner_execution_module)._new_authenticated_runner_execution_result,
    )
    forged_calls: list[str] = []

    def forged_init(self: object, **_kwargs: object) -> None:
        forged_calls.append(type(self).__name__)

    monkeypatch.setattr(AuthenticatedRunnerExecutionResult, "__init__", forged_init)
    inventory = cast(Any, object())
    interval = cast(Any, object())
    capability = cast(Any, object())
    evidence = cast(Any, object())
    projection = cast(Any, object())

    result = factory(
        inventory=inventory,
        runs=(),
        closed_ledger_interval=interval,
        runner_capability=capability,
        runner_evidence=evidence,
        runner_projection=projection,
    )

    assert type(result) is AuthenticatedRunnerExecutionResult
    assert result.inventory is inventory
    assert result.closed_ledger_interval is interval
    assert result.runner_capability is capability
    assert result.runner_evidence is evidence
    assert result.runner_projection is projection
    assert forged_calls == []


def test_execution_result_factory_rejects_slot_descriptor_retarget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = cast(
        Callable[..., AuthenticatedRunnerExecutionResult],
        cast(Any, authenticated_runner_execution_module)._new_authenticated_runner_execution_result,
    )
    sink_calls: list[str] = []

    class SinkDescriptor:
        def __get__(self, _instance: object, _owner: object) -> object:
            sink_calls.append("get")
            return object()

        def __set__(self, _instance: object, _value: object) -> None:
            sink_calls.append("set")

    monkeypatch.setattr(
        AuthenticatedRunnerExecutionResult,
        "runner_capability",
        SinkDescriptor(),
    )

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="execution result custody descriptors changed",
    ):
        factory(
            inventory=cast(Any, object()),
            runs=(),
            closed_ledger_interval=cast(Any, object()),
            runner_capability=cast(Any, object()),
            runner_evidence=cast(Any, object()),
            runner_projection=cast(Any, object()),
        )

    assert sink_calls == []


def test_execution_result_factory_rejects_split_getattribute_descriptor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = cast(
        Callable[..., AuthenticatedRunnerExecutionResult],
        cast(Any, authenticated_runner_execution_module)._new_authenticated_runner_execution_result,
    )
    descriptor_calls: list[str] = []
    trusted_getattribute = AuthenticatedRunnerExecutionResult.__getattribute__

    class SplitDescriptor:
        def __get__(self, instance: object | None, _owner: object) -> object:
            descriptor_calls.append("class" if instance is None else "instance")
            if instance is None:
                return trusted_getattribute
            return lambda _name: object()

    monkeypatch.setattr(
        AuthenticatedRunnerExecutionResult,
        "__getattribute__",
        SplitDescriptor(),
    )

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="execution result custody descriptors changed",
    ):
        factory(
            inventory=cast(Any, object()),
            runs=(),
            closed_ledger_interval=cast(Any, object()),
            runner_capability=cast(Any, object()),
            runner_evidence=cast(Any, object()),
            runner_projection=cast(Any, object()),
        )

    assert descriptor_calls == []


def test_child_custody_falls_back_when_adopted_parent_is_unregistered() -> None:
    inputs = cast(Callable[[], Any], runner_fixtures.live_inputs.__wrapped__)()
    (
        retain_campaign,
        retain_generation,
        adopt_parent,
        _release,
        revoke,
    ) = cast(Any, authenticated_runner_execution_module)._new_runner_child_capability_custody()
    registry = runner_fixtures._candidate_registry((runner_fixtures.CANDIDATE_ID,))

    for run in inputs.runs:
        retain_campaign(run.candidate_campaign_verification)
        retain_generation(run.candidate_generation_verification)
        retain_generation(run.judge_generation_verification)
    adopt_parent(object.__new__(VerifiedCrossLineageRunnerCustody))
    _release()

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match="runner live capability cleanup was incomplete",
    ):
        revoke()

    for run in inputs.runs:
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            run.candidate_campaign_verification.require_for(
                portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
                reports=run.candidate_campaign_reports,
                policy_sha256=run.candidate_campaign_policy_sha256,
                effective_config_sha256=run.candidate_campaign_effective_config_sha256,
            )
        candidate_request = candidate_generation_verification_requests(
            registry=registry,
            benchmark_reports=(run.candidate_report,),
        )[0]
        judge_request = adjudication_generation_verification_requests(
            report=run.adjudication_report,
            judge=run.judge,
        )[0]
        for capability, request in (
            (run.candidate_generation_verification, candidate_request),
            (run.judge_generation_verification, judge_request),
        ):
            with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
                capability.attestation_for(
                    benchmark_report_sha256=request.benchmark_report_sha256,
                    case_id=request.case_id,
                    exact_model_id=request.exact_model_id,
                    canonical_model_id=request.canonical_model_id,
                    catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                    discovery_evidence_sha256=request.discovery_evidence_sha256,
                    usage_record=request.usage_record,
                    expected_provider_name=request.expected_provider_name,
                )


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
    assert {entry.request_id for entry in snapshot.entries} == {
        record.request_id for record in harness.usage.records
    }
    assert all(
        entry.reserved_usd == entry.accounted_cost_usd == entry.actual_cost_usd == Decimal("0.01")
        for entry in snapshot.entries
    )
    _assert_exact_preview_bindings(harness)
    assert harness.candidate_executor.calls == [
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    ]
    assert len(harness.judge_route_preparation_executor.calls) == 1
    assert harness.judge_executor.calls == harness.candidate_executor.calls
    assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
        AuthenticatedRunnerGenerationSubject.JUDGE,
        AuthenticatedRunnerGenerationSubject.JUDGE,
    ]
    assert harness.generation_executor.issued_capabilities is not None
    assert len(harness.generation_executor.issued_capabilities) == 4
    for generation_capability, requests in harness.generation_executor.issued_capabilities:
        request = requests[0]
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
            generation_capability.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )


class _HandoffTraceInterruption(BaseException):
    pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handoff",
    ("campaign", "candidate_generation", "judge_generation"),
)
async def test_traceback_recovered_child_capability_is_revoked_during_handoff(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    handoff: str,
) -> None:
    harness = await _harness(tmp_path / handoff, config_factory)
    recovered: list[tuple[object, object]] = []
    implementation_code = cast(
        Any, authenticated_runner_execution_module
    )._execute_authenticated_cross_lineage_runner_impl.__code__

    def interrupt(frame: Any, event: str, _arg: object) -> object:
        if frame.f_code is implementation_code and event == "line":
            local = frame.f_locals
            capability_name = {
                "campaign": "campaign_verification",
                "candidate_generation": "candidate_generation",
                "judge_generation": "judge_generation",
            }[handoff]
            retained_name = {
                "campaign": "campaign_retained",
                "candidate_generation": "candidate_generation_retained",
                "judge_generation": "judge_generation_retained",
            }[handoff]
            capability = local.get(capability_name)
            if capability is not None and local.get(retained_name) is False:
                if handoff == "campaign":
                    binding: object = (
                        local["portfolio"],
                        local["candidate_result"].reports,
                        local["qualification_policy"].policy_sha256,
                        local["effective_config_sha256"],
                    )
                else:
                    requests_name = (
                        "candidate_generation_requests"
                        if handoff == "candidate_generation"
                        else "judge_generation_requests"
                    )
                    binding = local[requests_name][0]
                recovered.append((capability, binding))
                raise _HandoffTraceInterruption(handoff)
        return interrupt

    sys.settrace(interrupt)
    try:
        with pytest.raises(_HandoffTraceInterruption, match=handoff):
            await _execute(harness)
    finally:
        sys.settrace(None)

    assert len(recovered) == 1
    capability, binding = recovered[0]
    if handoff == "campaign":
        portfolio, reports, policy_sha256, effective_config_sha256 = cast(Any, binding)
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            cast(Any, capability).require_for(
                portfolio_sha256=portfolio.portfolio_sha256,
                reports=reports,
                policy_sha256=policy_sha256,
                effective_config_sha256=effective_config_sha256,
            )
    else:
        request = cast(Any, binding)
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
            cast(Any, capability).attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )


@pytest.mark.asyncio
async def test_traceback_recovered_parent_and_children_are_revoked_during_handoff(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path / "parent", config_factory)
    implementation = cast(
        Any,
        authenticated_runner_execution_module,
    )._execute_authenticated_cross_lineage_runner_impl
    implementation_code = implementation.__code__
    parent_live: set[int] = set()
    recovered_parent: list[tuple[VerifiedCrossLineageRunnerCustody, object]] = []
    campaign_bindings: list[tuple[object, object, tuple[Any, ...], str, str]] = []
    original_campaign_issue = cast(
        Any,
        authenticated_runner_execution_module,
    ).issue_trusted_candidate_benchmark_campaign_verification

    def issue_campaign(**kwargs: Any) -> object:
        capability = original_campaign_issue(**kwargs)
        campaign = kwargs["campaign"]
        campaign_bindings.append(
            (
                capability,
                kwargs["portfolio"],
                kwargs["reports"],
                campaign.manifest.qualification_policy_sha256,
                campaign.manifest.effective_config_sha256,
            )
        )
        return capability

    def issue_parent(**kwargs: Any) -> tuple[VerifiedCrossLineageRunnerCustody, object]:
        capability = object.__new__(VerifiedCrossLineageRunnerCustody)
        parent_live.add(id(capability))
        runs = tuple(kwargs["runs"])
        records = tuple(
            record
            for run in runs
            for record in (
                *(
                    case.usage_record
                    for case in run.candidate_report.results[0].cases
                    if case.usage_record is not None
                ),
                *(case.usage_record for case in run.adjudication_report.cases),
            )
        )
        projection = SimpleNamespace(
            ledger_request_ids=tuple(
                sorted(
                    cast(Any, authenticated_runner_execution_module)._attempt_request_ids(records)
                )
            ),
            runs=tuple(
                SimpleNamespace(
                    adjudication_report_sha256=run.adjudication_report.report_sha256,
                )
                for run in runs
            ),
        )
        return capability, SimpleNamespace(projection=projection)

    def require_parent(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: Any,
    ) -> object:
        if id(capability) not in parent_live:
            raise AuthenticatedRunnerExecutionError("parent capability is revoked")
        return evidence.projection

    def revoke_parent(capability: VerifiedCrossLineageRunnerCustody) -> None:
        try:
            parent_live.remove(id(capability))
        except KeyError:
            raise AuthenticatedRunnerExecutionError("parent capability is revoked") from None

    (
        retain_campaign,
        retain_generation,
        adopt_parent,
        _release,
        revoke_children,
    ) = cast(Any, authenticated_runner_execution_module)._new_runner_child_capability_custody()

    def interrupt(frame: Any, event: str, _arg: object) -> object:
        if frame.f_code is implementation_code and event == "line":
            capability = frame.f_locals.get("runner_capability")
            evidence = frame.f_locals.get("runner_evidence")
            if capability is not None and frame.f_locals.get("parent_adopted") is False:
                recovered_parent.append((capability, evidence))
                raise _HandoffTraceInterruption("parent")
        return interrupt

    sys.settrace(interrupt)
    try:
        with pytest.raises(_HandoffTraceInterruption, match="parent"):
            try:
                await implementation(
                    config=harness.config,
                    explicitly_allow_synthetic_egress=True,
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
                    judge_route_preparation_executor=(harness.judge_route_preparation_executor),
                    judge_executor=harness.judge_executor,
                    generation_executor=harness.generation_executor,
                    issue_campaign_capability=issue_campaign,
                    revoke_campaign_capability=cast(
                        Any,
                        authenticated_runner_execution_module,
                    ).revoke_trusted_candidate_benchmark_campaign_verification,
                    issue_runner_custody=issue_parent,
                    require_runner_custody=require_parent,
                    revoke_runner_custody=revoke_parent,
                    revoke_generation_capability=cast(
                        Any,
                        authenticated_runner_execution_module,
                    ).revoke_trusted_generation_verification,
                    build_execution_result=cast(
                        Any,
                        authenticated_runner_execution_module,
                    )._new_authenticated_runner_execution_result,
                    retain_campaign_capability=retain_campaign,
                    retain_generation_capability=retain_generation,
                    adopt_parent_capability=adopt_parent,
                )
            except BaseException:
                revoke_children()
                raise
    finally:
        sys.settrace(None)

    assert len(recovered_parent) == 1
    capability, evidence = recovered_parent[0]
    with pytest.raises(AuthenticatedRunnerExecutionError, match="parent capability is revoked"):
        require_parent(capability, evidence=evidence)
    assert len(campaign_bindings) == 2
    for campaign, portfolio, reports, policy_sha256, effective_config_sha256 in campaign_bindings:
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            cast(Any, campaign).require_for(
                portfolio_sha256=portfolio.portfolio_sha256,
                reports=reports,
                policy_sha256=policy_sha256,
                effective_config_sha256=effective_config_sha256,
            )
    assert harness.generation_executor.issued_capabilities is not None
    assert len(harness.generation_executor.issued_capabilities) == 4
    for generation, requests in harness.generation_executor.issued_capabilities:
        request = requests[0]
        with pytest.raises(GenerationEvidenceValidationError, match="not trusted"):
            generation.attestation_for(
                benchmark_report_sha256=request.benchmark_report_sha256,
                case_id=request.case_id,
                exact_model_id=request.exact_model_id,
                canonical_model_id=request.canonical_model_id,
                catalog_identity_binding_sha256=request.catalog_identity_binding_sha256,
                discovery_evidence_sha256=request.discovery_evidence_sha256,
                usage_record=request.usage_record,
                expected_provider_name=request.expected_provider_name,
            )


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

    assert len(harness.judge_route_preparation_executor.calls) == 1
    if fault == "extra":
        assert harness.candidate_executor.calls == [
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        ]
        assert harness.judge_executor.calls == harness.candidate_executor.calls
        assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.JUDGE,
        ]
    else:
        assert harness.candidate_executor.calls == [
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        ]
        assert harness.judge_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
        assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
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
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    snapshot = harness.budget.atomic_ledger.snapshot()
    assert snapshot.active_reserved_usd == Decimal("0.01")
    assert len(snapshot.entries) == 25


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("subject", "mutation"),
    [
        (AuthenticatedRunnerGenerationSubject.CANDIDATE, "usage"),
        (AuthenticatedRunnerGenerationSubject.CANDIDATE, "ledger"),
        (AuthenticatedRunnerGenerationSubject.JUDGE, "usage"),
        (AuthenticatedRunnerGenerationSubject.JUDGE, "ledger"),
    ],
)
async def test_generation_refetch_cannot_mutate_usage_or_cost_before_next_paid_callback(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    subject: AuthenticatedRunnerGenerationSubject,
    mutation: str,
) -> None:
    harness = await _harness(
        tmp_path,
        config_factory,
        generation_fault=(subject, mutation),
    )

    with pytest.raises(
        AuthenticatedRunnerExecutionError,
        match=f"PRIMARY {subject.value.lower()} generation re-fetch changed cost custody",
    ):
        await _execute(harness)

    candidate_stage = subject is AuthenticatedRunnerGenerationSubject.CANDIDATE
    expected_candidate_calls = [
        CrossLineageAdjudicationRunKind.PRIMARY,
        *([] if candidate_stage else [CrossLineageAdjudicationRunKind.REPLAY]),
    ]
    assert harness.candidate_executor.calls == expected_candidate_calls
    assert len(harness.judge_route_preparation_executor.calls) == (0 if candidate_stage else 1)
    assert harness.judge_executor.calls == (
        [] if candidate_stage else [CrossLineageAdjudicationRunKind.PRIMARY]
    )
    assert [item[1] for item in harness.generation_executor.calls] == (
        [AuthenticatedRunnerGenerationSubject.CANDIDATE]
        if candidate_stage
        else [
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.CANDIDATE,
            AuthenticatedRunnerGenerationSubject.JUDGE,
        ]
    )

    candidate_plans = harness.candidate_executor.request_cost_plans
    judge_plans = harness.judge_executor.request_cost_plans
    assert judge_plans is not None
    paid_plans = candidate_plans[:1] if candidate_stage else [*candidate_plans, *judge_plans[:1]]
    paid_request_ids = {
        preview.logical_request_id for plan in paid_plans for preview in plan.request_previews
    }
    mutation_id = f"generation-{subject.value.lower()}-primary-mutation"
    expected_ledger_ids = paid_request_ids | ({mutation_id} if mutation == "ledger" else set())
    assert harness.budget.atomic_ledger is not None
    snapshot = harness.budget.atomic_ledger.snapshot()
    assert {entry.request_id for entry in snapshot.entries} == expected_ledger_ids
    expected_entry_count = (24 if candidate_stage else 72) + (mutation == "ledger")
    assert len(snapshot.entries) == expected_entry_count
    assert snapshot.active_reserved_usd == Decimal(0)
    assert snapshot.spent_usd == Decimal(expected_entry_count) * Decimal("0.01")
    assert len(harness.usage.records) == (24 if candidate_stage else 72) + (mutation == "usage")


@pytest.mark.asyncio
async def test_rejects_swapped_judge_route_before_generation_credit(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory, judge_fault="swapped_route")

    with pytest.raises(ValueError, match="exact judge route"):
        await _execute(harness)

    assert len(harness.judge_route_preparation_executor.calls) == 1
    assert [subject for _kind, subject, _ids in harness.generation_executor.calls] == [
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
        AuthenticatedRunnerGenerationSubject.CANDIDATE,
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
    assert reversed_harness.judge_route_preparation_executor.calls == []

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
    assert cap_harness.judge_route_preparation_executor.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("role_index", [-1, 0, 1])
async def test_preflight_rejects_non_native_structured_output_for_every_runner_role(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    role_index: int,
) -> None:
    harness = await _harness(tmp_path / "native", config_factory)
    model = harness.registry.candidates[0] if role_index == -1 else harness.plans[role_index].judge
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / f"loose-{role_index}",
        config=harness.config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model.exact_model_id,
                provider_endpoint=model.approved_provider_endpoint,
                provider_name=model.approved_provider_name,
                canonical_model_id=model.canonical_model_slug,
            ),
        ),
    )
    if role_index == -1:
        harness = replace(
            harness,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            registry=registry,
        )
        expected = "candidate route lacks required native structured_outputs"
    else:
        plans = list(harness.plans)
        plans[role_index] = replace(
            plans[role_index],
            judge_discovery_manifest=manifest,
            judge_discovery_evidence=evidence,
            judge_registry=registry,
        )
        harness = replace(harness, plans=tuple(plans))
        expected = "judge route lacks required native structured_outputs"
    assert harness.budget.atomic_ledger is not None
    before = harness.budget.atomic_ledger.snapshot()

    with pytest.raises(AuthenticatedRunnerExecutionError, match=expected):
        await _execute(harness)

    assert harness.candidate_executor.calls == []
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger.snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("role_index", [-1, 0, 1])
async def test_preflight_rejects_context_fallback_completion_limit_for_every_runner_role(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    role_index: int,
) -> None:
    harness = await _harness(tmp_path / "completion-capacity", config_factory)
    model = harness.registry.candidates[0] if role_index == -1 else harness.plans[role_index].judge
    manifest, evidence, registry = candidate_fixtures._discovery_and_registry(
        tmp_path=tmp_path / f"context-fallback-{role_index}",
        config=harness.config,
        specs=(
            candidate_fixtures._CandidateSpec(
                model_id=model.exact_model_id,
                provider_endpoint=model.approved_provider_endpoint,
                provider_name=model.approved_provider_name,
                canonical_model_id=model.canonical_model_slug,
                native_structured_output_parameter="structured_outputs",
                endpoint_completion_limit_published=False,
            ),
        ),
    )
    if role_index == -1:
        harness = replace(
            harness,
            discovery_manifest=manifest,
            discovery_evidence=evidence,
            registry=registry,
        )
        expected = "candidate route lacks an explicit metadata completion limit"
    else:
        plans = list(harness.plans)
        plans[role_index] = replace(
            plans[role_index],
            judge_discovery_manifest=manifest,
            judge_discovery_evidence=evidence,
            judge_registry=registry,
        )
        harness = replace(harness, plans=tuple(plans))
        expected = "judge route lacks an explicit metadata completion limit"
    assert evidence[0].endpoint_snapshot.endpoints[0].max_completion_tokens_source == (
        "context_limit"
    )
    assert harness.budget.atomic_ledger is not None
    before = harness.budget.atomic_ledger.snapshot()

    with pytest.raises(AuthenticatedRunnerExecutionError, match=expected):
        await _execute(harness)

    assert harness.candidate_executor.calls == []
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger.snapshot() == before
    assert all(
        not path.exists()
        for plan in harness.plans
        for path in (plan.campaign_path, plan.portfolio_path)
    )


@pytest.mark.asyncio
async def test_preflight_preserves_sanitized_reasoning_incompatibility_category(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = await _harness(tmp_path, config_factory)

    def incompatible_reasoning(**_kwargs: object) -> AuthenticatedRunnerStagedCostPlan:
        raise EndpointSnapshotValidationError("SENSITIVE_SENTINEL")

    monkeypatch.setattr(
        authenticated_runner_execution_module,
        "_candidate_staged_cost_plan",
        incompatible_reasoning,
    )

    with pytest.raises(AuthenticatedRunnerExecutionError) as caught:
        await _execute(harness)

    assert str(caught.value) == (
        "runner candidate reasoning profile is incompatible with frozen launch evidence"
    )
    assert caught.value.__cause__ is None
    assert "SENSITIVE_SENTINEL" not in "".join(traceback.format_exception(caught.value))
    assert harness.candidate_executor.calls == []
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("judge_index", [0, 1])
async def test_preflight_rejects_either_incompatible_judge_reasoning_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
    judge_index: int,
) -> None:
    harness = await _harness(tmp_path, config_factory)
    incompatible_model = harness.plans[judge_index].judge.exact_model_id
    original = OpenRouterModelDiscoveryEvidence.require_compatible_reasoning_profile

    def require_compatible_reasoning_profile(
        self: OpenRouterModelDiscoveryEvidence,
        profile: Any,
    ) -> None:
        if self.exact_model_id == incompatible_model:
            raise EndpointSnapshotValidationError("SENSITIVE_SENTINEL")
        original(self, profile)

    monkeypatch.setattr(
        OpenRouterModelDiscoveryEvidence,
        "require_compatible_reasoning_profile",
        require_compatible_reasoning_profile,
    )

    with pytest.raises(AuthenticatedRunnerExecutionError) as caught:
        await _execute(harness)

    assert str(caught.value) == (
        "runner judge reasoning profile is incompatible with frozen launch evidence"
    )
    assert caught.value.__cause__ is None
    assert "SENSITIVE_SENTINEL" not in "".join(traceback.format_exception(caught.value))
    assert harness.candidate_executor.calls == []
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.judge_executor.calls == []
    assert harness.generation_executor.calls == []
    assert harness.usage.records == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()


@pytest.mark.asyncio
async def test_declared_candidate_attempt_cap_rejects_before_ledger_reservation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await _harness(tmp_path, config_factory, candidate_fault="budget_over_cap")

    with pytest.raises(BudgetExhaustedError, match="active per-request cost ceiling"):
        await _execute(harness)

    assert harness.candidate_executor.calls == [CrossLineageAdjudicationRunKind.PRIMARY]
    assert harness.judge_route_preparation_executor.calls == []
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
    assert harness.judge_route_preparation_executor.calls == []
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

    output_harness = await _harness(tmp_path / "output", config_factory)
    output_harness.budget.max_output_tokens += 1
    await _assert_preflight_rejection(
        output_harness,
        expected="runner shared budget maximum output tokens differ from configuration",
    )

    rate_harness = await _harness(tmp_path / "rate", config_factory)
    rate_harness.budget.conservative_rate += 1.0
    await _assert_preflight_rejection(
        rate_harness,
        expected="runner shared budget conservative rate differs from configuration",
    )

    request_harness = await _harness(tmp_path / "request", config_factory)
    request_harness.budget.max_requests_per_agent += 1
    await _assert_preflight_rejection(
        request_harness,
        expected="runner shared budget request cap differs from configuration",
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
        global_input_token_budget=(ledger_harness.config.token_budgets.global_input_token_budget),
        global_output_token_budget=(ledger_harness.config.token_budgets.global_output_token_budget),
        per_model_usd_caps={
            model: str(cap)
            for model, cap in ledger_harness.config.token_budgets.per_model_cost_budget_usd.items()
        },
        per_role_usd_caps={
            role: str(cap)
            for role, cap in ledger_harness.config.token_budgets.per_role_cost_budget_usd.items()
        },
    )
    await _assert_preflight_rejection(
        replace(ledger_harness, budget=wrong_budget),
        expected="runner atomic cost ledger cap must equal 250 USD",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "expected"),
    (
        (
            "global_input_token_budget",
            "runner shared budget global input token budget differs from configuration",
        ),
        (
            "global_output_token_budget",
            "runner shared budget global output token budget differs from configuration",
        ),
    ),
)
async def test_preflight_rejects_aggregate_token_budget_drift_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    field: str,
    expected: str,
) -> None:
    harness = await _harness(tmp_path / field, config_factory)
    configured = getattr(harness.config.token_budgets, field)
    setattr(harness.budget, field, configured + 1)

    await _assert_preflight_rejection(harness, expected=expected)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("per_model_usd_caps", {CANDIDATE_ID: Decimal("1")}),
        ("per_role_usd_caps", {"model_benchmark": Decimal("1")}),
    ),
)
async def test_preflight_rejects_scoped_cost_budget_drift_before_dispatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    field: str,
    value: dict[str, Decimal],
) -> None:
    harness = await _harness(tmp_path / field, config_factory)
    setattr(harness.budget, field, value)

    await _assert_preflight_rejection(
        harness,
        expected="runner shared budget scoped cost budgets differ from configuration",
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
    assert harness.judge_route_preparation_executor.calls == []
    assert harness.budget.atomic_ledger is not None
    assert harness.budget.atomic_ledger.snapshot().entries == ()
