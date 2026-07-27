"""Fail-closed benchmark execution for one frozen OpenRouter candidate set."""

from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Protocol

from pydantic import Field, field_validator, model_validator

from mmaudit.benchmark.models import (
    ModelBenchmarkProviderResult,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    OpenRouterModelBenchmarkProvider,
    run_model_benchmark,
)
from mmaudit.config import AuditConfig
from mmaudit.models.discovery import (
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.identifiers import (
    EXACT_MODEL_ID_PATTERN,
    require_exact_openrouter_model_id,
)
from mmaudit.models.openrouter import (
    OpenRouterClient,
    OpenRouterProviderPolicy,
    OpenRouterReasoning,
)
from mmaudit.models.qualification import (
    CandidateModel,
    CandidateRegistry,
    QualificationPolicy,
    validate_candidate_registry_discovery,
)
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel, UsageRecord
from mmaudit.models.usage import UsageLedger
from mmaudit.orchestration.budgets import BudgetManager
from mmaudit.orchestration.cost_ledger import (
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.manifest import canonical_sha256

_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_ERROR_KIND_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,99}$"
_DECIMAL_PATTERN = r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"


class CandidateCostLedgerSnapshot(StrictModel):
    """Secret-free, self-hashed projection of one atomic cost-ledger snapshot."""

    cap_usd: str = Field(pattern=_DECIMAL_PATTERN)
    spent_usd: str = Field(pattern=_DECIMAL_PATTERN)
    active_reserved_usd: str = Field(pattern=_DECIMAL_PATTERN)
    remaining_usd: str = Field(pattern=_DECIMAL_PATTERN)
    over_cap: bool
    has_reservation_overrun: bool
    entry_count: int = Field(ge=0)
    reserved_count: int = Field(ge=0)
    reconciled_count: int = Field(ge=0)
    released_count: int = Field(ge=0)
    uncertain_accounted_count: int = Field(ge=0)
    reservation_overrun_count: int = Field(ge=0)
    entries_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("cap_usd", "spent_usd", "active_reserved_usd", "remaining_usd")
    @classmethod
    def monetary_values_are_canonical(cls, value: str) -> str:
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("cost-ledger snapshot values must be canonical decimals") from exc
        if not parsed.is_finite() or parsed < 0 or _canonical_decimal(parsed) != value:
            raise ValueError("cost-ledger snapshot values must be canonical nonnegative decimals")
        return value

    @model_validator(mode="after")
    def counts_and_hash_are_consistent(self) -> CandidateCostLedgerSnapshot:
        status_total = (
            self.reserved_count
            + self.reconciled_count
            + self.released_count
            + self.uncertain_accounted_count
            + self.reservation_overrun_count
        )
        if status_total != self.entry_count:
            raise ValueError("cost-ledger snapshot status counts are inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"snapshot_sha256"}))
        if self.snapshot_sha256 != expected:
            raise ValueError("cost-ledger snapshot hash is inconsistent")
        return self


def candidate_cost_ledger_snapshot(
    snapshot: CostLedgerSnapshot,
) -> CandidateCostLedgerSnapshot:
    """Normalize one validated in-memory ledger snapshot without persisting paths."""

    entries = tuple(
        {
            "request_id": entry.request_id,
            "reservation_id": entry.reservation_id,
            "status": entry.status.value,
            "reserved_usd": _canonical_decimal(entry.reserved_usd),
            "actual_cost_usd": (
                None if entry.actual_cost_usd is None else _canonical_decimal(entry.actual_cost_usd)
            ),
            "accounted_cost_usd": _canonical_decimal(entry.accounted_cost_usd),
            "release_reason": (
                None if entry.release_reason is None else entry.release_reason.value
            ),
            "created_at": entry.created_at.isoformat(),
            "updated_at": entry.updated_at.isoformat(),
        }
        for entry in sorted(snapshot.entries, key=lambda item: item.request_id)
    )
    counts = {
        status: sum(entry.status is status for entry in snapshot.entries)
        for status in CostEntryStatus
    }
    payload = {
        "cap_usd": _canonical_decimal(snapshot.cap_usd),
        "spent_usd": _canonical_decimal(snapshot.spent_usd),
        "active_reserved_usd": _canonical_decimal(snapshot.active_reserved_usd),
        "remaining_usd": _canonical_decimal(snapshot.remaining_usd),
        "over_cap": snapshot.over_cap,
        "has_reservation_overrun": snapshot.has_reservation_overrun,
        "entry_count": len(snapshot.entries),
        "reserved_count": counts[CostEntryStatus.RESERVED],
        "reconciled_count": counts[CostEntryStatus.RECONCILED],
        "released_count": counts[CostEntryStatus.RELEASED],
        "uncertain_accounted_count": counts[CostEntryStatus.UNCERTAIN_ACCOUNTED],
        "reservation_overrun_count": counts[CostEntryStatus.RESERVATION_OVERRUN],
        "entries_sha256": canonical_sha256(entries),
    }
    return CandidateCostLedgerSnapshot.model_validate(
        {
            **payload,
            "snapshot_sha256": canonical_sha256(payload),
        }
    )


class CandidateBenchmarkFailureStage(StrEnum):
    """Sanitized candidate-local stage that prevented a complete benchmark."""

    CLIENT_INITIALIZATION = "client_initialization"
    AUTHENTICATION = "authentication"
    ENDPOINT_REGISTRATION = "endpoint_registration"
    BENCHMARK_EXECUTION = "benchmark_execution"


class CandidateBenchmarkRunState(StrEnum):
    COMPLETE = "complete"
    COMPLETE_WITH_FAILURES = "complete_with_failures"
    UNVERIFIED_FAILURE = "unverified_failure"


class CandidateBenchmarkDiagnostic(StrictModel):
    """Non-secret execution summary for exactly one candidate report."""

    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    approved_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    endpoint_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_evidence: ExecutionEvidenceKind
    state: CandidateBenchmarkRunState
    failure_stage: CandidateBenchmarkFailureStage | None = None
    reasoning_suppressed: bool
    corpus_cases: int = Field(ge=1)
    requests_observed: int = Field(ge=0)
    logical_request_count: int = Field(default=0, ge=0)
    provider_attempt_count: int = Field(default=0, ge=0)
    retry_count: int = Field(default=0, ge=0)
    successful_request_count: int = Field(default=0, ge=0)
    failed_request_count: int = Field(default=0, ge=0)
    unresolved_cost_count: int = Field(default=0, ge=0)
    observed_usage_sha256: str = Field(
        default=canonical_sha256([]),
        pattern=r"^[0-9a-f]{64}$",
    )
    cost_ledger_before: CandidateCostLedgerSnapshot | None = None
    cost_ledger_after: CandidateCostLedgerSnapshot | None = None
    successful_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    error_kinds: tuple[str, ...] = Field(max_length=100)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def counts_and_state_are_consistent(self) -> CandidateBenchmarkDiagnostic:
        if self.successful_cases + self.failed_cases != self.corpus_cases:
            raise ValueError("candidate benchmark diagnostic case counts are inconsistent")
        if self.requests_observed > self.corpus_cases:
            raise ValueError("candidate benchmark diagnostic request count is invalid")
        if (
            self.logical_request_count != self.requests_observed
            or self.successful_request_count + self.failed_request_count != self.requests_observed
            or self.provider_attempt_count != self.requests_observed + self.retry_count
            or self.unresolved_cost_count > self.provider_attempt_count
        ):
            raise ValueError("candidate benchmark request accounting is inconsistent")
        if (self.cost_ledger_before is None) != (self.cost_ledger_after is None):
            raise ValueError("candidate benchmark ledger snapshots must be present together")
        if self.error_kinds != tuple(sorted(set(self.error_kinds))) or any(
            not re.fullmatch(_ERROR_KIND_PATTERN, value) for value in self.error_kinds
        ):
            raise ValueError("candidate benchmark diagnostic error kinds are invalid")
        if self.state is CandidateBenchmarkRunState.COMPLETE and (
            self.failed_cases or self.failure_stage is not None
        ):
            raise ValueError("complete candidate benchmark cannot retain failures")
        if self.state is CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES and (
            not self.failed_cases or self.failure_stage is not None
        ):
            raise ValueError("provider case failures cannot claim a setup failure stage")
        if self.state is CandidateBenchmarkRunState.UNVERIFIED_FAILURE and (
            self.failure_stage is None
            or self.execution_evidence is not ExecutionEvidenceKind.UNVERIFIED
        ):
            raise ValueError("candidate failure provenance is inconsistent")
        return self


class CandidateBenchmarkEvidenceSink(Protocol):
    """Durable exact-prefix sink used before advancing to another candidate."""

    @property
    def reports(self) -> tuple[ModelBenchmarkReport, ...]: ...

    @property
    def diagnostics(self) -> tuple[CandidateBenchmarkDiagnostic, ...]: ...

    @property
    def qualification_policy_sha256(self) -> str: ...

    def validate_candidate_start(
        self,
        *,
        candidate: CandidateModel,
        ledger_before: CandidateCostLedgerSnapshot,
    ) -> None: ...

    def persist_candidate(
        self,
        *,
        candidate: CandidateModel,
        report: ModelBenchmarkReport,
        diagnostic: CandidateBenchmarkDiagnostic,
        observed_usage: tuple[UsageRecord, ...],
        ledger_before: CandidateCostLedgerSnapshot,
        ledger_after: CandidateCostLedgerSnapshot,
    ) -> None: ...


class CandidateBenchmarkExecutionResult(StrictModel):
    """Exact sorted one-model reports and their non-secret run diagnostics."""

    candidate_registry_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovery_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    benchmark_corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    benchmark_ground_truth_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reports: tuple[ModelBenchmarkReport, ...] = Field(min_length=1, max_length=128)
    diagnostics: tuple[CandidateBenchmarkDiagnostic, ...] = Field(
        min_length=1,
        max_length=128,
    )

    @model_validator(mode="after")
    def exact_report_set_is_consistent(self) -> CandidateBenchmarkExecutionResult:
        report_ids: list[str] = []
        for report in self.reports:
            if len(report.results) != 1:
                raise ValueError("candidate benchmark outputs must be one-model reports")
            result = report.results[0]
            report_ids.append(result.target.model_id)
            if (
                report.corpus_sha256 != self.benchmark_corpus_sha256
                or report.ground_truth_sha256 != self.benchmark_ground_truth_sha256
            ):
                raise ValueError("candidate benchmark report changed its benchmark suite")
        diagnostic_ids = [item.exact_model_id for item in self.diagnostics]
        if report_ids != sorted(set(report_ids)) or diagnostic_ids != report_ids:
            raise ValueError("candidate benchmark reports and diagnostics require an exact set")
        if any(
            diagnostic.report_sha256 != report.report_sha256
            or diagnostic.execution_evidence is not report.execution_evidence
            for diagnostic, report in zip(self.diagnostics, self.reports, strict=True)
        ):
            raise ValueError("candidate benchmark diagnostics are not report-bound")
        return self


class CandidateBenchmarkClientFactory(Protocol):
    """Injectable construction boundary; production uses the concrete client."""

    def __call__(
        self,
        *,
        api_key: str,
        config: AuditConfig,
        budget: BudgetManager,
        usage: UsageLedger,
        candidate: CandidateModel,
        provider_policy: OpenRouterProviderPolicy,
        reasoning: OpenRouterReasoning | None,
    ) -> OpenRouterClient: ...


class CandidateBenchmarkUnavailableError(ValueError):
    """Content-free provider error used to preserve a failed candidate denominator."""


class _UnverifiedCandidateFailureProvider:
    async def evaluate(
        self,
        *,
        target: ModelBenchmarkTarget,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelBenchmarkProviderResult:
        del target, system_prompt, user_prompt
        raise CandidateBenchmarkUnavailableError("candidate benchmark execution was unavailable")


async def run_candidate_registry_benchmarks(
    *,
    config: AuditConfig,
    discovery_manifest: OpenRouterModelDiscoveryRunManifest,
    discovery_evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    candidate_registry: CandidateRegistry,
    benchmark_suite: ModelBenchmarkSuite,
    budget: BudgetManager,
    usage: UsageLedger,
    operator_api_key: str,
    explicitly_allow_synthetic_egress: bool,
    client_factory: CandidateBenchmarkClientFactory | None = None,
    evidence_sink: CandidateBenchmarkEvidenceSink | None = None,
    qualification_policy: QualificationPolicy | None = None,
) -> CandidateBenchmarkExecutionResult:
    """Benchmark every exact frozen candidate while preserving failed denominators."""

    config = AuditConfig.model_validate(config.model_dump(mode="json"))
    discovery_manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        discovery_manifest.model_dump(mode="json")
    )
    discovery_evidence = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="json"))
        for item in discovery_evidence
    )
    candidate_registry = CandidateRegistry.model_validate(
        candidate_registry.model_dump(mode="json")
    )
    benchmark_suite = ModelBenchmarkSuite.model_validate(benchmark_suite.model_dump(mode="json"))
    if not isinstance(budget, BudgetManager) or budget.atomic_ledger is None:
        raise ValueError("candidate benchmarks require a shared durable atomic cost ledger")
    if not budget.require_endpoint_cost_bound:
        raise ValueError("candidate benchmarks require endpoint-bound cost controls")
    if not isinstance(usage, UsageLedger):
        raise ValueError("candidate benchmarks require a shared usage ledger")
    if not isinstance(operator_api_key, str) or not operator_api_key:
        raise ValueError("candidate benchmarks require an in-memory operator credential")
    validate_candidate_benchmark_egress(
        config=config,
        benchmark_suite=benchmark_suite,
        explicitly_allowed=explicitly_allow_synthetic_egress,
    )
    if evidence_sink is not None:
        if qualification_policy is None:
            raise ValueError("durable candidate campaigns require a qualification policy")
        validate_candidate_benchmark_policy_capacity(
            benchmark_suite=benchmark_suite,
            qualification_policy=qualification_policy,
        )
        if evidence_sink.qualification_policy_sha256 != qualification_policy.policy_sha256:
            raise ValueError("candidate campaign qualification policy binding differs")

    validate_candidate_registry_discovery(
        registry=candidate_registry,
        run_manifest=discovery_manifest,
        evidence=discovery_evidence,
    )
    if client_factory is None and evidence_sink is None:
        raise ValueError("real candidate benchmarks require a durable campaign evidence sink")
    evidence_by_model = {item.exact_model_id: item for item in discovery_evidence}
    factory = client_factory or _build_concrete_client
    reports = list(evidence_sink.reports if evidence_sink is not None else ())
    diagnostics = list(evidence_sink.diagnostics if evidence_sink is not None else ())
    candidate_ids = tuple(candidate.exact_model_id for candidate in candidate_registry.candidates)
    persisted_ids = tuple(report.results[0].target.model_id for report in reports)
    if (
        persisted_ids != candidate_ids[: len(persisted_ids)]
        or tuple(item.exact_model_id for item in diagnostics) != persisted_ids
    ):
        raise ValueError("candidate benchmark journal is not an exact candidate prefix")
    try:
        for candidate in candidate_registry.candidates[len(reports) :]:
            usage_start = len(usage.records)
            assert budget.atomic_ledger is not None
            raw_ledger_before = budget.atomic_ledger.snapshot()
            ledger_before = candidate_cost_ledger_snapshot(raw_ledger_before)
            if evidence_sink is not None:
                evidence_sink.validate_candidate_start(
                    candidate=candidate,
                    ledger_before=ledger_before,
                )
            target = ModelBenchmarkTarget(
                model_id=candidate.exact_model_id,
                root_lineage=candidate.root_lineage,
            )
            reasoning, reasoning_suppressed = _candidate_reasoning(config, candidate)
            report, failure_stage, _requests_observed = await _execute_candidate(
                config=config,
                benchmark_suite=benchmark_suite,
                budget=budget,
                usage=usage,
                candidate=candidate,
                target=target,
                endpoint_evidence=evidence_by_model[candidate.exact_model_id],
                operator_api_key=operator_api_key,
                reasoning=reasoning,
                factory=factory,
            )
            observed_usage = tuple(usage.records[usage_start:])
            raw_ledger_after = budget.atomic_ledger.snapshot()
            ledger_after = candidate_cost_ledger_snapshot(raw_ledger_after)
            _require_exact_candidate_usage_binding(
                report=report,
                observed_records=observed_usage,
                failure_stage=failure_stage,
            )
            diagnostic = _candidate_diagnostic(
                candidate=candidate,
                report=report,
                reasoning_suppressed=reasoning_suppressed,
                failure_stage=failure_stage,
                observed_usage=observed_usage,
                ledger_before=ledger_before,
                ledger_after=ledger_after,
                raw_ledger_before=raw_ledger_before,
                raw_ledger_after=raw_ledger_after,
            )
            if evidence_sink is not None:
                evidence_sink.persist_candidate(
                    candidate=candidate,
                    report=report,
                    diagnostic=diagnostic,
                    observed_usage=observed_usage,
                    ledger_before=ledger_before,
                    ledger_after=ledger_after,
                )
            reports.append(report)
            diagnostics.append(diagnostic)
    finally:
        operator_api_key = ""

    return CandidateBenchmarkExecutionResult(
        candidate_registry_sha256=candidate_registry.registry_sha256,
        discovery_manifest_sha256=discovery_manifest.manifest_sha256,
        benchmark_corpus_sha256=benchmark_suite.corpus_sha256,
        benchmark_ground_truth_sha256=benchmark_suite.ground_truth_sha256,
        reports=tuple(reports),
        diagnostics=tuple(diagnostics),
    )


def _build_concrete_client(
    *,
    api_key: str,
    config: AuditConfig,
    budget: BudgetManager,
    usage: UsageLedger,
    candidate: CandidateModel,
    provider_policy: OpenRouterProviderPolicy,
    reasoning: OpenRouterReasoning | None,
) -> OpenRouterClient:
    del candidate
    return OpenRouterClient(
        api_key=api_key,
        execution=config.execution,
        privacy=config.privacy,
        budget=budget,
        usage=usage,
        provider_policy=provider_policy,
        reasoning=reasoning,
    )


async def _execute_candidate(
    *,
    config: AuditConfig,
    benchmark_suite: ModelBenchmarkSuite,
    budget: BudgetManager,
    usage: UsageLedger,
    candidate: CandidateModel,
    target: ModelBenchmarkTarget,
    endpoint_evidence: OpenRouterModelDiscoveryEvidence,
    operator_api_key: str,
    reasoning: OpenRouterReasoning | None,
    factory: CandidateBenchmarkClientFactory,
) -> tuple[ModelBenchmarkReport, CandidateBenchmarkFailureStage | None, int]:
    before_usage = len(usage.records)
    client: OpenRouterClient | None = None
    try:
        provider_policy = OpenRouterProviderPolicy(
            certification=True,
            only=(candidate.approved_provider_endpoint,),
            allow_fallbacks=False,
        )
        try:
            created_client = factory(
                api_key=operator_api_key,
                config=config,
                budget=budget,
                usage=usage,
                candidate=candidate,
                provider_policy=provider_policy,
                reasoning=reasoning,
            )
            if type(created_client) is not OpenRouterClient:
                raise TypeError("candidate benchmark client is not the concrete client")
            client = created_client
        except Exception:
            return (
                await _unverified_failure_report(
                    benchmark_suite=benchmark_suite,
                    target=target,
                ),
                CandidateBenchmarkFailureStage.CLIENT_INITIALIZATION,
                len(usage.records) - before_usage,
            )
        try:
            await client.validate_authentication()
        except Exception:
            return (
                await _unverified_failure_report(
                    benchmark_suite=benchmark_suite,
                    target=target,
                ),
                CandidateBenchmarkFailureStage.AUTHENTICATION,
                len(usage.records) - before_usage,
            )
        try:
            endpoint_payload = await client.get_model_endpoint_metadata(candidate.exact_model_id)
            zdr_payload = await client.list_zdr_endpoints()
            current_endpoint_evidence = validate_openrouter_endpoint_snapshot(
                exact_model_id=candidate.exact_model_id,
                configured_provider_endpoints=(candidate.approved_provider_endpoint,),
                provider_policy_mode="only",
                endpoint_payload=endpoint_payload,
                require_zdr=True,
                zdr_payload=zdr_payload,
                reasoning_requested=False,
            )
            if current_endpoint_evidence != endpoint_evidence.endpoint_snapshot:
                raise ValueError("current endpoint metadata differs from frozen discovery evidence")
            if reasoning is not None and "reasoning" not in (
                current_endpoint_evidence.endpoints[0].supported_parameters
            ):
                raise ValueError("current endpoint does not support requested reasoning")
            client.register_certification_endpoint_snapshot(evidence=current_endpoint_evidence)
        except Exception:
            return (
                await _unverified_failure_report(
                    benchmark_suite=benchmark_suite,
                    target=target,
                ),
                CandidateBenchmarkFailureStage.ENDPOINT_REGISTRATION,
                len(usage.records) - before_usage,
            )
        try:
            return (
                await run_model_benchmark(
                    corpus=benchmark_suite,
                    targets=[target],
                    provider=OpenRouterModelBenchmarkProvider(client),
                ),
                None,
                len(usage.records) - before_usage,
            )
        except Exception:
            return (
                await _unverified_failure_report(
                    benchmark_suite=benchmark_suite,
                    target=target,
                ),
                CandidateBenchmarkFailureStage.BENCHMARK_EXECUTION,
                len(usage.records) - before_usage,
            )
    finally:
        if client is not None:
            try:
                client.clear_credentials()
            finally:
                await client.close()


def _require_exact_candidate_usage_binding(
    *,
    report: ModelBenchmarkReport,
    observed_records: tuple[UsageRecord, ...],
    failure_stage: CandidateBenchmarkFailureStage | None,
) -> None:
    report_records = tuple(
        case.usage_record
        for result in report.results
        for case in result.cases
        if case.usage_record is not None
    )
    if failure_stage is None and report_records != observed_records:
        raise ValueError("candidate benchmark produced request usage not bound to its exact report")
    if failure_stage is not None and any(
        record not in observed_records for record in report_records
    ):
        raise ValueError("failed candidate report contains unobserved request usage")


def _candidate_reasoning(
    config: AuditConfig,
    candidate: CandidateModel,
) -> tuple[OpenRouterReasoning | None, bool]:
    configured = config.models.reasoning
    requested = (
        configured.effort is not None or configured.max_tokens is not None or configured.exclude
    )
    if not candidate.reasoning_supported:
        return None, requested
    if not requested:
        return None, False
    return (
        OpenRouterReasoning(
            effort=configured.effort,
            max_tokens=configured.max_tokens,
            exclude=configured.exclude,
        ),
        False,
    )


def validate_candidate_benchmark_egress(
    *,
    config: AuditConfig,
    benchmark_suite: ModelBenchmarkSuite,
    explicitly_allowed: bool,
) -> None:
    """Permit measurement before lineage approval without weakening privacy controls."""

    if not explicitly_allowed:
        raise ValueError("candidate benchmarks require explicit synthetic-source egress approval")
    if not config.privacy.require_zdr:
        raise ValueError("candidate benchmarks require zero-data-retention routing")
    if config.privacy.store_raw_prompts or config.privacy.store_raw_responses:
        raise ValueError("candidate benchmarks refuse raw prompt or response storage")
    if config.privacy.maximum_model_retention != "zero":
        raise ValueError("candidate benchmarks require zero-retention model routing")
    if any(not case.source_path.startswith("synthetic/") for case in benchmark_suite.corpus.cases):
        raise ValueError("candidate benchmarks only permit the versioned synthetic corpus")


def validate_candidate_benchmark_policy_capacity(
    *,
    benchmark_suite: ModelBenchmarkSuite,
    qualification_policy: QualificationPolicy,
) -> None:
    """Fail before spend when the frozen corpus cannot realize a policy denominator."""

    suite = ModelBenchmarkSuite.model_validate(benchmark_suite.model_dump(mode="json"))
    policy = QualificationPolicy.model_validate(qualification_policy.model_dump(mode="json"))
    semantic_counts = {
        dimension: sum(dimension in case.dimensions for case in suite.ground_truth.cases)
        for dimension in {item.dimension for item in policy.thresholds}
    }
    for threshold in policy.thresholds:
        realized = (
            len(suite.corpus.cases)
            if threshold.dimension.value == "structured_output_compliance"
            else semantic_counts[threshold.dimension]
        )
        if realized < threshold.minimum_cases:
            raise ValueError(
                "candidate benchmark corpus underfills qualification policy dimension "
                f"{threshold.dimension.value}: {realized} < {threshold.minimum_cases}"
            )


async def _unverified_failure_report(
    *,
    benchmark_suite: ModelBenchmarkSuite,
    target: ModelBenchmarkTarget,
) -> ModelBenchmarkReport:
    return await run_model_benchmark(
        corpus=benchmark_suite,
        targets=[target],
        provider=_UnverifiedCandidateFailureProvider(),
    )


def _candidate_diagnostic(
    *,
    candidate: CandidateModel,
    report: ModelBenchmarkReport,
    reasoning_suppressed: bool,
    failure_stage: CandidateBenchmarkFailureStage | None,
    observed_usage: tuple[UsageRecord, ...],
    ledger_before: CandidateCostLedgerSnapshot,
    ledger_after: CandidateCostLedgerSnapshot,
    raw_ledger_before: CostLedgerSnapshot,
    raw_ledger_after: CostLedgerSnapshot,
) -> CandidateBenchmarkDiagnostic:
    result = report.results[0]
    failed_cases = sum(case.error_kind is not None for case in result.cases)
    error_kinds = tuple(
        sorted({case.error_kind for case in result.cases if case.error_kind is not None})
    )
    if failure_stage is not None:
        state = CandidateBenchmarkRunState.UNVERIFIED_FAILURE
    elif failed_cases:
        state = CandidateBenchmarkRunState.COMPLETE_WITH_FAILURES
    else:
        state = CandidateBenchmarkRunState.COMPLETE
    requests_observed = len(observed_usage)
    provider_attempt_count = sum(item.attempts for item in observed_usage)
    successful_request_count = sum(item.status == "success" for item in observed_usage)
    before_request_ids = {entry.request_id for entry in raw_ledger_before.entries}
    new_entries = tuple(
        entry for entry in raw_ledger_after.entries if entry.request_id not in before_request_ids
    )
    unresolved_cost_count = sum(
        entry.status in {CostEntryStatus.RESERVED, CostEntryStatus.UNCERTAIN_ACCOUNTED}
        for entry in new_entries
    )
    return CandidateBenchmarkDiagnostic(
        exact_model_id=candidate.exact_model_id,
        approved_provider_endpoint=candidate.approved_provider_endpoint,
        endpoint_snapshot_sha256=candidate.endpoint_snapshot_sha256,
        report_sha256=report.report_sha256,
        execution_evidence=report.execution_evidence,
        state=state,
        failure_stage=failure_stage,
        reasoning_suppressed=reasoning_suppressed,
        corpus_cases=len(result.cases),
        requests_observed=requests_observed,
        logical_request_count=requests_observed,
        provider_attempt_count=provider_attempt_count,
        retry_count=provider_attempt_count - requests_observed,
        successful_request_count=successful_request_count,
        failed_request_count=requests_observed - successful_request_count,
        unresolved_cost_count=unresolved_cost_count,
        observed_usage_sha256=canonical_sha256(
            [item.model_dump(mode="json") for item in observed_usage]
        ),
        cost_ledger_before=ledger_before,
        cost_ledger_after=ledger_after,
        successful_cases=len(result.cases) - failed_cases,
        failed_cases=failed_cases,
        error_kinds=error_kinds,
    )


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered if rendered not in {"", "-0"} else "0"
