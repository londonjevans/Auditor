"""Atomic exact-set storage for private model benchmark reports.

This module performs no provider access and makes no qualification decision. It
binds normalized benchmark reports to one frozen candidate registry and preserves
their existing execution-evidence labels without promoting mixed or unverified
sets.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Literal, Never, SupportsIndex

from pydantic import Field, field_validator, model_validator

from mmaudit.benchmark.models import (
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    verify_model_benchmark_report_structure,
)
from mmaudit.models.candidate_benchmark import (
    CandidateBenchmarkDiagnostic,
    CandidateBenchmarkRunState,
    CandidateCostLedgerSnapshot,
    CandidateReasoningProfileBenchmarkExecutionResult,
    CandidateReasoningProfileBenchmarkPlan,
    CandidateReasoningProfileBenchmarkRoute,
    CandidateReasoningProfileBenchmarkRun,
    candidate_cost_ledger_snapshot,
)
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.qualification import CandidateModel, CandidateRegistry
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel, UsageRecord
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_DECIMAL_PATTERN = r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"
_REPORT_FILENAME_PATTERN = r"^model-report-[0-9a-f]{64}\.json$"
_PORTFOLIO_MANIFEST_NAME = "model-benchmark-portfolio.json"
_CAMPAIGN_MANIFEST_NAME = "candidate-benchmark-campaign.json"
_CAMPAIGN_ENTRY_FILENAME_PATTERN = r"^candidate-[0-9]{3}-[0-9a-f]{64}\.json$"
_REASONING_CAMPAIGN_MANIFEST_NAME = "reasoning-profile-benchmark-campaign.json"
_REASONING_CAMPAIGN_ENTRY_FILENAME_PATTERN = r"^reasoning-route-[0-9]{4}-[0-9a-f]{64}\.json$"
_MAX_CANDIDATES = 128
_MAX_REPORT_BYTES = 50_000_000
_MAX_MANIFEST_BYTES = 5_000_000
_PRIVATE_DIRECTORY_MODE = 0o700
_PRIVATE_FILE_MODE = 0o600


class TrustedCandidateBenchmarkCampaignVerification:
    """Opaque proof that one fresh complete campaign retains live response provenance."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedCandidateBenchmarkCampaignVerification:
        del cls
        raise TypeError("trusted campaign verification cannot be constructed directly")

    def __init__(
        self,
        *_args: object,
        **_kwargs: object,
    ) -> None:
        del self, _args, _kwargs

    def require_for(
        self,
        *,
        portfolio_sha256: str,
        reports: tuple[ModelBenchmarkReport, ...],
        policy_sha256: str,
        effective_config_sha256: str,
    ) -> None:
        """Reject reuse for any portfolio, report content, policy, or config drift."""

        _require_trusted_campaign_capability(
            self,
            portfolio_sha256=portfolio_sha256,
            reports=reports,
            policy_sha256=policy_sha256,
            effective_config_sha256=effective_config_sha256,
        )

    def __copy__(self) -> None:
        raise TypeError("trusted campaign verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("trusted campaign verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted campaign verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted campaign verification cannot be serialized")


def _build_campaign_runtime_authority() -> tuple[
    Callable[..., CandidateBenchmarkCampaignJournal],
    Callable[..., TrustedCandidateBenchmarkCampaignVerification],
    Callable[
        [
            TrustedCandidateBenchmarkCampaignVerification,
            str,
            tuple[ModelBenchmarkReport, ...],
            str,
            str,
        ],
        None,
    ],
]:
    """Create process-local journal and capability registries hidden from data models."""

    @dataclass(frozen=True, slots=True)
    class TrustedCampaignCapabilityState:
        portfolio_sha256: str
        journal_sha256: str
        policy_sha256: str
        effective_config_sha256: str
        cost_ledger_path_sha256: str
        report_content_bindings: tuple[tuple[str, str], ...]

    journal_registry: dict[
        int,
        tuple[weakref.ReferenceType[object], list[str]],
    ] = {}
    capability_registry: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedCandidateBenchmarkCampaignVerification],
            TrustedCampaignCapabilityState,
        ],
    ] = {}
    lock = threading.RLock()

    def register_fresh_journal(journal: object) -> Callable[[int, str], None]:
        key = id(journal)

        def discard(reference: weakref.ReferenceType[object]) -> None:
            with lock:
                current = journal_registry.get(key)
                if current is not None and current[0] is reference:
                    journal_registry.pop(key, None)

        reference = weakref.ref(journal, discard)
        with lock:
            journal_registry[key] = (reference, [])

        def record_live_binding(expected_prior_count: int, binding: str) -> None:
            with lock:
                registered = journal_registry.get(key)
                if registered is None:
                    return
                registered_reference, bindings = registered
                if registered_reference() is not journal or len(bindings) != expected_prior_count:
                    journal_registry.pop(key, None)
                    raise ValueError("fresh campaign runtime authority became inconsistent")
                bindings.append(binding)

        return record_live_binding

    def live_bindings(journal: object) -> tuple[str, ...] | None:
        with lock:
            registered = journal_registry.get(id(journal))
            if registered is None or registered[0]() is not journal:
                return None
            return tuple(registered[1])

    def create_campaign(
        path: Path,
        *,
        candidate_registry: CandidateRegistry,
        corpus: ModelBenchmarkSuite,
        effective_config_sha256: str,
        qualification_policy_sha256: str,
        cost_ledger: AtomicCostLedger,
    ) -> CandidateBenchmarkCampaignJournal:
        journal = _create_candidate_benchmark_campaign_unregistered(
            path,
            candidate_registry=candidate_registry,
            corpus=corpus,
            effective_config_sha256=effective_config_sha256,
            qualification_policy_sha256=qualification_policy_sha256,
            cost_ledger=cost_ledger,
        )
        journal._attach_live_binding_recorder(register_fresh_journal(journal))
        return journal

    def issue_capability(
        *,
        campaign: CandidateBenchmarkCampaignJournal,
        portfolio: ModelBenchmarkPortfolio,
        reports: tuple[ModelBenchmarkReport, ...],
    ) -> TrustedCandidateBenchmarkCampaignVerification:
        if type(campaign) is not CandidateBenchmarkCampaignJournal:
            raise ValueError("trusted campaign verification requires the original campaign")
        campaign.require_complete()
        validated_reports = tuple(
            ModelBenchmarkReport.model_validate(report.model_dump(mode="json"))
            for report in reports
        )
        verify_model_benchmark_portfolio_campaign(
            campaign.path,
            portfolio=portfolio,
            reports=validated_reports,
            candidate_registry=campaign._candidate_registry,
            corpus=campaign._corpus,
            effective_config_sha256=campaign.manifest.effective_config_sha256,
            qualification_policy_sha256=campaign.manifest.qualification_policy_sha256,
            cost_ledger=campaign._cost_ledger,
        )
        expected_bindings = tuple(
            binding for _model_id, binding in _report_content_bindings(validated_reports)
        )
        current_live_bindings = live_bindings(campaign)
        if current_live_bindings is None or current_live_bindings != expected_bindings:
            raise ValueError(
                "trusted campaign verification requires every original runtime-attested report"
            )
        capability = object.__new__(TrustedCandidateBenchmarkCampaignVerification)
        state = TrustedCampaignCapabilityState(
            portfolio_sha256=portfolio.portfolio_sha256,
            journal_sha256=campaign.journal_sha256,
            policy_sha256=campaign.manifest.qualification_policy_sha256,
            effective_config_sha256=campaign.manifest.effective_config_sha256,
            cost_ledger_path_sha256=campaign.manifest.cost_ledger_path_sha256,
            report_content_bindings=_report_content_bindings(validated_reports),
        )
        key = id(capability)

        def discard(
            reference: weakref.ReferenceType[TrustedCandidateBenchmarkCampaignVerification],
        ) -> None:
            with lock:
                current = capability_registry.get(key)
                if current is not None and current[0] is reference:
                    capability_registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            capability_registry[key] = (reference, state)
        return capability

    def require_capability(
        capability: TrustedCandidateBenchmarkCampaignVerification,
        portfolio_sha256: str,
        reports: tuple[ModelBenchmarkReport, ...],
        policy_sha256: str,
        effective_config_sha256: str,
    ) -> None:
        with lock:
            registered = capability_registry.get(id(capability))
        state = registered[1] if registered is not None and registered[0]() is capability else None
        if (
            type(capability) is not TrustedCandidateBenchmarkCampaignVerification
            or state is None
            or state.portfolio_sha256 != portfolio_sha256
            or state.policy_sha256 != policy_sha256
            or state.effective_config_sha256 != effective_config_sha256
            or not state.cost_ledger_path_sha256
            or not state.journal_sha256
            or state.report_content_bindings != _report_content_bindings(reports)
        ):
            raise ValueError("trusted campaign verification does not bind qualification inputs")

    return (
        create_campaign,
        issue_capability,
        require_capability,
    )


(
    create_candidate_benchmark_campaign,
    issue_trusted_candidate_benchmark_campaign_verification,
    _require_trusted_campaign_capability_positional,
) = _build_campaign_runtime_authority()


def _require_trusted_campaign_capability(
    capability: TrustedCandidateBenchmarkCampaignVerification,
    *,
    portfolio_sha256: str,
    reports: tuple[ModelBenchmarkReport, ...],
    policy_sha256: str,
    effective_config_sha256: str,
) -> None:
    _require_trusted_campaign_capability_positional(
        capability,
        portfolio_sha256,
        reports,
        policy_sha256,
        effective_config_sha256,
    )


class TrustedCandidateReasoningProfileCampaignVerification:
    """Opaque same-process authority over supplemental parsed response content."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> TrustedCandidateReasoningProfileCampaignVerification:
        del cls
        raise TypeError("trusted reasoning-profile campaign verification is opaque")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def require_for(
        self,
        *,
        plan_sha256: str,
        reports: tuple[ModelBenchmarkReport, ...],
        policy_sha256: str,
        effective_config_sha256: str,
    ) -> None:
        _require_trusted_reasoning_campaign_capability_positional(
            self,
            plan_sha256,
            reports,
            policy_sha256,
            effective_config_sha256,
        )

    def __copy__(self) -> None:
        raise TypeError("trusted reasoning-profile campaign verification cannot be copied")

    def __deepcopy__(self, _memo: object) -> None:
        raise TypeError("trusted reasoning-profile campaign verification cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("trusted reasoning-profile campaign verification cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("trusted reasoning-profile campaign verification cannot be serialized")


def _build_reasoning_campaign_runtime_authority() -> tuple[
    Callable[..., CandidateReasoningProfileBenchmarkCampaignJournal],
    Callable[..., TrustedCandidateReasoningProfileCampaignVerification],
    Callable[
        [
            TrustedCandidateReasoningProfileCampaignVerification,
            str,
            tuple[ModelBenchmarkReport, ...],
            str,
            str,
        ],
        None,
    ],
]:
    """Hide live supplemental content bindings in closure-owned weak registries."""

    @dataclass(frozen=True, slots=True)
    class TrustedReasoningCampaignState:
        plan_sha256: str
        journal_sha256: str
        policy_sha256: str
        effective_config_sha256: str
        report_content_bindings: tuple[tuple[str, str], ...]

    journals: dict[int, tuple[weakref.ReferenceType[object], list[str]]] = {}
    capabilities: dict[
        int,
        tuple[
            weakref.ReferenceType[TrustedCandidateReasoningProfileCampaignVerification],
            TrustedReasoningCampaignState,
        ],
    ] = {}
    lock = threading.RLock()

    def register(journal: object) -> Callable[[int, str], None]:
        key = id(journal)

        def discard(reference: weakref.ReferenceType[object]) -> None:
            with lock:
                current = journals.get(key)
                if current is not None and current[0] is reference:
                    journals.pop(key, None)

        reference = weakref.ref(journal, discard)
        with lock:
            journals[key] = (reference, [])

        def record(expected_prior_count: int, binding: str) -> None:
            with lock:
                current = journals.get(key)
                if current is None or current[0]() is not journal:
                    raise ValueError("reasoning-profile campaign authority is unavailable")
                if len(current[1]) != expected_prior_count:
                    journals.pop(key, None)
                    raise ValueError("reasoning-profile campaign authority became inconsistent")
                current[1].append(binding)

        return record

    def create(
        path: Path,
        *,
        plan: CandidateReasoningProfileBenchmarkPlan,
        candidate_registry: CandidateRegistry,
        corpus: ModelBenchmarkSuite,
        effective_config_sha256: str,
        qualification_policy_sha256: str,
        cost_ledger: AtomicCostLedger,
    ) -> CandidateReasoningProfileBenchmarkCampaignJournal:
        journal = _create_candidate_reasoning_profile_campaign_unregistered(
            path,
            plan=plan,
            candidate_registry=candidate_registry,
            corpus=corpus,
            effective_config_sha256=effective_config_sha256,
            qualification_policy_sha256=qualification_policy_sha256,
            cost_ledger=cost_ledger,
        )
        journal._attach_live_binding_recorder(register(journal))
        return journal

    def issue(
        *,
        campaign: CandidateReasoningProfileBenchmarkCampaignJournal,
        execution: CandidateReasoningProfileBenchmarkExecutionResult,
    ) -> TrustedCandidateReasoningProfileCampaignVerification:
        if type(campaign) is not CandidateReasoningProfileBenchmarkCampaignJournal:
            raise ValueError("trusted reasoning-profile authority requires the original campaign")
        campaign.require_complete()
        validated = CandidateReasoningProfileBenchmarkExecutionResult.model_validate(
            execution.model_dump(mode="json")
        )
        if validated.plan_sha256 != campaign.plan_sha256 or validated.runs != campaign.runs:
            raise ValueError("reasoning-profile execution differs from its live journal")
        with lock:
            registered = journals.get(id(campaign))
            live = (
                tuple(registered[1])
                if registered is not None and registered[0]() is campaign
                else None
            )
        verify_candidate_reasoning_profile_benchmark_campaign(
            campaign.path,
            execution=validated,
            plan=campaign.manifest.plan,
            candidate_registry=campaign._candidate_registry,
            corpus=campaign._corpus,
            effective_config_sha256=campaign.manifest.effective_config_sha256,
            qualification_policy_sha256=campaign.manifest.qualification_policy_sha256,
            cost_ledger=campaign._cost_ledger,
        )
        expected = tuple(
            binding for _model_id, binding in _report_content_bindings(validated.reports)
        )
        if live != expected:
            raise ValueError(
                "trusted reasoning-profile verification requires every original live report"
            )
        capability = object.__new__(TrustedCandidateReasoningProfileCampaignVerification)
        state = TrustedReasoningCampaignState(
            plan_sha256=campaign.plan_sha256,
            journal_sha256=campaign.journal_sha256,
            policy_sha256=campaign.manifest.qualification_policy_sha256,
            effective_config_sha256=campaign.manifest.effective_config_sha256,
            report_content_bindings=_report_content_bindings(validated.reports),
        )
        key = id(capability)

        def discard_capability(
            reference: weakref.ReferenceType[TrustedCandidateReasoningProfileCampaignVerification],
        ) -> None:
            with lock:
                current = capabilities.get(key)
                if current is not None and current[0] is reference:
                    capabilities.pop(key, None)

        reference = weakref.ref(capability, discard_capability)
        with lock:
            capabilities[key] = (reference, state)
        return capability

    def require(
        capability: TrustedCandidateReasoningProfileCampaignVerification,
        plan_sha256: str,
        reports: tuple[ModelBenchmarkReport, ...],
        policy_sha256: str,
        effective_config_sha256: str,
    ) -> None:
        with lock:
            registered = capabilities.get(id(capability))
        state = registered[1] if registered is not None and registered[0]() is capability else None
        if (
            type(capability) is not TrustedCandidateReasoningProfileCampaignVerification
            or state is None
            or state.plan_sha256 != plan_sha256
            or state.policy_sha256 != policy_sha256
            or state.effective_config_sha256 != effective_config_sha256
            or not state.journal_sha256
            or state.report_content_bindings != _report_content_bindings(reports)
        ):
            raise ValueError(
                "trusted reasoning-profile verification does not bind qualification inputs"
            )

    return create, issue, require


(
    create_candidate_reasoning_profile_benchmark_campaign,
    issue_trusted_candidate_reasoning_profile_campaign_verification,
    _require_trusted_reasoning_campaign_capability_positional,
) = _build_reasoning_campaign_runtime_authority()


class ModelBenchmarkPortfolioUsage(StrictModel):
    """Exact aggregate of the UsageRecords retained by all bound reports."""

    report_count: int = Field(ge=1, le=_MAX_CANDIDATES)
    usage_record_count: int = Field(ge=0)
    logical_request_count: int = Field(ge=0)
    provider_attempt_count: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    successful_request_count: int = Field(ge=0)
    failed_request_count: int = Field(ge=0)
    unresolved_cost_count: int = Field(ge=0)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    reported_cost_record_count: int = Field(ge=0)
    reported_cost_usd: str = Field(max_length=100, pattern=_DECIMAL_PATTERN)
    accounted_cost_usd: str = Field(max_length=100, pattern=_DECIMAL_PATTERN)
    latency_record_count: int = Field(ge=0)
    total_latency_ms: int = Field(ge=0)
    maximum_latency_ms: int | None = Field(default=None, ge=0)

    @field_validator("reported_cost_usd", "accounted_cost_usd")
    @classmethod
    def costs_are_canonical_nonnegative_decimals(cls, value: str) -> str:
        try:
            parsed = Decimal(value)
        except InvalidOperation as exc:
            raise ValueError("portfolio costs must be canonical decimals") from exc
        if not parsed.is_finite() or parsed < 0 or _canonical_decimal(parsed) != value:
            raise ValueError("portfolio costs must be canonical nonnegative decimals")
        return value

    @model_validator(mode="after")
    def optional_aggregate_counts_are_consistent(self) -> ModelBenchmarkPortfolioUsage:
        if (
            self.reported_cost_record_count > self.usage_record_count
            or self.latency_record_count > self.usage_record_count
        ):
            raise ValueError("portfolio optional aggregate counts exceed usage records")
        if (
            self.logical_request_count != self.usage_record_count
            or self.provider_attempt_count != self.logical_request_count + self.retry_count
            or self.successful_request_count + self.failed_request_count
            != self.logical_request_count
            or self.unresolved_cost_count > self.provider_attempt_count
        ):
            raise ValueError("portfolio provider-request accounting is inconsistent")
        if (self.maximum_latency_ms is None) != (self.latency_record_count == 0):
            raise ValueError("portfolio maximum latency presence is inconsistent")
        if self.latency_record_count == 0 and self.total_latency_ms != 0:
            raise ValueError("portfolio latency total requires observed latency records")
        if self.usage_record_count == 0 and (
            self.prompt_tokens != 0
            or self.logical_request_count != 0
            or self.provider_attempt_count != 0
            or self.retry_count != 0
            or self.successful_request_count != 0
            or self.failed_request_count != 0
            or self.unresolved_cost_count != 0
            or self.completion_tokens != 0
            or self.total_tokens != 0
            or self.reported_cost_record_count != 0
            or self.reported_cost_usd != "0"
            or self.accounted_cost_usd != "0"
            or self.latency_record_count != 0
            or self.total_latency_ms != 0
            or self.maximum_latency_ms is not None
        ):
            raise ValueError("zero-usage portfolio aggregates must remain zero")
        return self


class ModelBenchmarkReportArtifact(StrictModel):
    """One exact on-disk report binding."""

    exact_model_id: str = Field(min_length=3, max_length=300)
    filename: str = Field(pattern=_REPORT_FILENAME_PATTERN)
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    report_sha256: str = Field(pattern=_SHA256_PATTERN)
    execution_evidence: ExecutionEvidenceKind

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def filename_is_model_bound(self) -> ModelBenchmarkReportArtifact:
        if self.filename != _report_filename(self.exact_model_id):
            raise ValueError("benchmark report filename is not bound to its exact model")
        return self


class ModelBenchmarkPortfolioPayload(StrictModel):
    """Exact candidate/report-set manifest without a qualification claim."""

    schema_version: Literal["1.0"] = "1.0"
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_run_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_model_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    corpus_name: str = Field(min_length=1, max_length=500)
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    started_at: datetime | None
    ended_at: datetime | None
    usage: ModelBenchmarkPortfolioUsage
    execution_evidence: ExecutionEvidenceKind
    report_artifacts: tuple[ModelBenchmarkReportArtifact, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    diagnostics: tuple[CandidateBenchmarkDiagnostic, ...] = Field(
        default_factory=tuple,
        max_length=_MAX_CANDIDATES,
    )
    observed_usage_records: tuple[UsageRecord, ...] = Field(
        default_factory=tuple,
        max_length=10_000,
    )
    campaign_journal_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    initial_cost_ledger_snapshot: CandidateCostLedgerSnapshot | None = None
    cost_ledger_snapshot: CandidateCostLedgerSnapshot | None = None

    @field_validator("candidate_model_ids")
    @classmethod
    def candidate_ids_are_exact_sorted_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        for model_id in value:
            require_exact_openrouter_model_id(model_id)
        if value != tuple(sorted(set(value))):
            raise ValueError("portfolio candidate models must be unique and sorted")
        return value

    @field_validator("started_at", "ended_at")
    @classmethod
    def timestamps_are_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("portfolio timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def exact_set_aggregates_and_evidence_are_consistent(
        self,
    ) -> ModelBenchmarkPortfolioPayload:
        if (self.started_at is None) != (self.ended_at is None):
            raise ValueError("portfolio runtime timestamps must be present together")
        if self.usage.usage_record_count == 0 and self.started_at is not None:
            raise ValueError("zero-usage portfolio cannot claim runtime timestamps")
        if self.usage.usage_record_count > 0 and self.started_at is None:
            raise ValueError("portfolio usage records require runtime timestamps")
        if (
            self.started_at is not None
            and self.ended_at is not None
            and self.ended_at < self.started_at
        ):
            raise ValueError("portfolio end timestamp precedes its start")
        if self.candidate_set_sha256 != canonical_sha256(list(self.candidate_model_ids)):
            raise ValueError("portfolio candidate-set hash is inconsistent")
        artifact_ids = tuple(item.exact_model_id for item in self.report_artifacts)
        if artifact_ids != self.candidate_model_ids:
            raise ValueError("portfolio reports do not exactly cover the candidate set")
        filenames = tuple(item.filename for item in self.report_artifacts)
        if len(filenames) != len(set(filenames)):
            raise ValueError("portfolio report filenames must be unique")
        if self.usage.report_count != len(self.report_artifacts):
            raise ValueError("portfolio report count is inconsistent")
        if self.diagnostics:
            diagnostic_ids = tuple(item.exact_model_id for item in self.diagnostics)
            if diagnostic_ids != self.candidate_model_ids:
                raise ValueError("portfolio diagnostics do not exactly cover the candidate set")
            if any(
                diagnostic.report_sha256 != artifact.report_sha256
                or diagnostic.execution_evidence is not artifact.execution_evidence
                for diagnostic, artifact in zip(
                    self.diagnostics,
                    self.report_artifacts,
                    strict=True,
                )
            ):
                raise ValueError("portfolio diagnostics are not bound to report artifacts")
            if (
                sum(item.requests_observed for item in self.diagnostics)
                != self.usage.usage_record_count
            ):
                raise ValueError("portfolio diagnostics disagree with retained request usage")
        if self.campaign_journal_sha256 is not None and (
            self.qualification_policy_sha256 is None
            or self.initial_cost_ledger_snapshot is None
            or self.cost_ledger_snapshot is None
        ):
            raise ValueError("journal-bound portfolio requires policy and cost-ledger snapshots")
        if len(self.observed_usage_records) != self.usage.usage_record_count:
            raise ValueError("portfolio retained usage count is inconsistent")
        if (self.initial_cost_ledger_snapshot is None) != (self.cost_ledger_snapshot is None):
            raise ValueError("portfolio cost-ledger snapshots must be present together")
        if self.initial_cost_ledger_snapshot is not None and self.cost_ledger_snapshot is not None:
            spent_delta = Decimal(self.cost_ledger_snapshot.spent_usd) - Decimal(
                self.initial_cost_ledger_snapshot.spent_usd
            )
            unresolved_delta = (
                self.cost_ledger_snapshot.reserved_count
                + self.cost_ledger_snapshot.uncertain_accounted_count
                - self.initial_cost_ledger_snapshot.reserved_count
                - self.initial_cost_ledger_snapshot.uncertain_accounted_count
            )
            if (
                spent_delta != Decimal(self.usage.accounted_cost_usd)
                or unresolved_delta != self.usage.unresolved_cost_count
            ):
                raise ValueError("portfolio usage disagrees with its cost-ledger snapshots")
        expected_evidence = _combined_execution_evidence(
            tuple(item.execution_evidence for item in self.report_artifacts)
        )
        if self.execution_evidence is not expected_evidence:
            raise ValueError("portfolio execution evidence promotes or misstates its reports")
        return self


class ModelBenchmarkPortfolio(ModelBenchmarkPortfolioPayload):
    portfolio_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def portfolio_hash_matches(self) -> ModelBenchmarkPortfolio:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"portfolio_sha256"}))
        if self.portfolio_sha256 != expected:
            raise ValueError("model benchmark portfolio hash is inconsistent")
        return self


class CandidateBenchmarkCampaignManifestPayload(StrictModel):
    """Immutable bindings created before any candidate provider work."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_run_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_model_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CANDIDATES,
    )
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    cost_ledger_path_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_cost_ledger_snapshot: CandidateCostLedgerSnapshot

    @field_validator("created_at")
    @classmethod
    def created_at_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("candidate campaign creation time must be UTC")
        return value

    @field_validator("candidate_model_ids")
    @classmethod
    def candidate_ids_are_exact_sorted_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        for model_id in value:
            require_exact_openrouter_model_id(model_id)
        if value != tuple(sorted(set(value))):
            raise ValueError("candidate campaign models must be unique and sorted")
        return value


class CandidateBenchmarkCampaignManifest(CandidateBenchmarkCampaignManifestPayload):
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def manifest_hash_matches(self) -> CandidateBenchmarkCampaignManifest:
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"campaign_manifest_sha256"})
        )
        if self.campaign_manifest_sha256 != expected:
            raise ValueError("candidate campaign manifest hash is inconsistent")
        return self


class CandidateBenchmarkCampaignEntryPayload(StrictModel):
    """One atomic candidate report, diagnostic, usage, and ledger transition."""

    schema_version: Literal["1.0"] = "1.0"
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_index: int = Field(ge=0, lt=_MAX_CANDIDATES)
    exact_model_id: str
    report: ModelBenchmarkReport
    diagnostic: CandidateBenchmarkDiagnostic
    observed_usage: tuple[UsageRecord, ...] = Field(max_length=1_000)
    ledger_before: CandidateCostLedgerSnapshot
    ledger_after: CandidateCostLedgerSnapshot

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @model_validator(mode="after")
    def evidence_is_exactly_bound(self) -> CandidateBenchmarkCampaignEntryPayload:
        if (
            len(self.report.results) != 1
            or self.report.results[0].target.model_id != self.exact_model_id
            or self.diagnostic.exact_model_id != self.exact_model_id
            or self.diagnostic.report_sha256 != self.report.report_sha256
            or self.diagnostic.observed_usage_sha256
            != canonical_sha256([item.model_dump(mode="json") for item in self.observed_usage])
            or self.diagnostic.cost_ledger_before != self.ledger_before
            or self.diagnostic.cost_ledger_after != self.ledger_after
        ):
            raise ValueError("candidate campaign entry evidence bindings are inconsistent")
        if any(item.requested_model != self.exact_model_id for item in self.observed_usage):
            raise ValueError("candidate campaign usage belongs to a different exact model")
        request_ids = tuple(item.request_id for item in self.observed_usage)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("candidate campaign entry replays a logical request ID")
        report_usage = tuple(
            case.usage_record
            for result in self.report.results
            for case in result.cases
            if case.usage_record is not None
        )
        report_usage_projection = _usage_records_public_projection(report_usage)
        observed_usage_projection = _usage_records_public_projection(self.observed_usage)
        if self.diagnostic.state is not CandidateBenchmarkRunState.UNVERIFIED_FAILURE:
            if report_usage_projection != observed_usage_projection:
                raise ValueError("completed candidate report omits observed request usage")
        elif any(item not in observed_usage_projection for item in report_usage_projection):
            raise ValueError("failed candidate report contains unobserved request usage")
        if (
            self.diagnostic.requests_observed != len(self.observed_usage)
            or self.diagnostic.provider_attempt_count
            != sum(item.attempts for item in self.observed_usage)
            or self.diagnostic.retry_count != sum(item.attempts - 1 for item in self.observed_usage)
            or self.diagnostic.successful_request_count
            != sum(item.status == "success" for item in self.observed_usage)
        ):
            raise ValueError("candidate campaign diagnostic request accounting is inconsistent")
        ledger_cost_delta = Decimal(self.ledger_after.spent_usd) - Decimal(
            self.ledger_before.spent_usd
        )
        observed_accounted_cost = sum(
            (Decimal(str(item.accounted_cost_usd)) for item in self.observed_usage),
            Decimal(0),
        )
        unresolved_before = (
            self.ledger_before.reserved_count + self.ledger_before.uncertain_accounted_count
        )
        unresolved_after = (
            self.ledger_after.reserved_count + self.ledger_after.uncertain_accounted_count
        )
        if (
            self.ledger_after.entry_count < self.ledger_before.entry_count
            or ledger_cost_delta < 0
            or ledger_cost_delta != observed_accounted_cost
            or unresolved_after - unresolved_before != self.diagnostic.unresolved_cost_count
        ):
            raise ValueError("candidate campaign usage and ledger accounting disagree")
        return self


class CandidateBenchmarkCampaignEntry(CandidateBenchmarkCampaignEntryPayload):
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def entry_hash_matches(self) -> CandidateBenchmarkCampaignEntry:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"entry_sha256"}))
        if self.entry_sha256 != expected:
            raise ValueError("candidate campaign entry hash is inconsistent")
        return self


class CandidateBenchmarkCampaignJournal:
    """Validated private append-only exact-prefix candidate campaign."""

    def __init__(
        self,
        *,
        path: Path,
        manifest: CandidateBenchmarkCampaignManifest,
        entries: tuple[CandidateBenchmarkCampaignEntry, ...],
        candidate_registry: CandidateRegistry,
        corpus: ModelBenchmarkSuite,
        cost_ledger: AtomicCostLedger,
    ) -> None:
        self.path = path
        self.manifest = manifest
        self._entries = list(entries)
        self._candidate_registry = candidate_registry
        self._corpus = corpus
        self._cost_ledger = cost_ledger
        self._live_binding_recorder: Callable[[int, str], None] | None = None

    def _attach_live_binding_recorder(
        self,
        recorder: Callable[[int, str], None],
    ) -> None:
        if self._live_binding_recorder is not None:
            raise ValueError("candidate campaign runtime authority is already attached")
        self._live_binding_recorder = recorder

    @property
    def reports(self) -> tuple[ModelBenchmarkReport, ...]:
        return tuple(item.report for item in self._entries)

    @property
    def diagnostics(self) -> tuple[CandidateBenchmarkDiagnostic, ...]:
        return tuple(item.diagnostic for item in self._entries)

    @property
    def observed_usage(self) -> tuple[UsageRecord, ...]:
        return tuple(record for item in self._entries for record in item.observed_usage)

    @property
    def qualification_policy_sha256(self) -> str:
        return self.manifest.qualification_policy_sha256

    @property
    def final_cost_ledger_snapshot(self) -> CandidateCostLedgerSnapshot:
        if self._entries:
            return self._entries[-1].ledger_after
        return self.manifest.initial_cost_ledger_snapshot

    @property
    def journal_sha256(self) -> str:
        return canonical_sha256(
            {
                "campaign_manifest_sha256": self.manifest.campaign_manifest_sha256,
                "entry_sha256": [item.entry_sha256 for item in self._entries],
            }
        )

    def persist_candidate(
        self,
        *,
        candidate: CandidateModel,
        report: ModelBenchmarkReport,
        diagnostic: CandidateBenchmarkDiagnostic,
        observed_usage: tuple[UsageRecord, ...],
        ledger_before: CandidateCostLedgerSnapshot,
        ledger_after: CandidateCostLedgerSnapshot,
    ) -> None:
        """Atomically append one exact next candidate entry and fsync it."""

        index = len(self._entries)
        if index >= len(self._candidate_registry.candidates):
            raise ValueError("candidate campaign already contains its exact candidate set")
        expected_candidate = self._candidate_registry.candidates[index]
        if candidate != expected_candidate:
            raise ValueError("candidate campaign append is not the exact next candidate")
        if ledger_before != self.final_cost_ledger_snapshot:
            raise ValueError("candidate campaign cost-ledger transition is discontinuous")
        prior_request_ids = {
            record.request_id for entry in self._entries for record in entry.observed_usage
        }
        prior_generation_ids = {
            record.openrouter_generation_id
            for entry in self._entries
            for record in entry.observed_usage
            if record.openrouter_generation_id is not None
        }
        if any(record.request_id in prior_request_ids for record in observed_usage) or any(
            record.openrouter_generation_id in prior_generation_ids
            for record in observed_usage
            if record.openrouter_generation_id is not None
        ):
            raise ValueError("candidate campaign replays request or generation evidence")
        current = candidate_cost_ledger_snapshot(self._cost_ledger.snapshot())
        if current != ledger_after:
            raise ValueError("candidate campaign cost-ledger snapshot is not current")
        live_content_binding = _live_report_content_binding(
            report=report,
            observed_usage=observed_usage,
        )
        payload = CandidateBenchmarkCampaignEntryPayload(
            campaign_manifest_sha256=self.manifest.campaign_manifest_sha256,
            candidate_index=index,
            exact_model_id=candidate.exact_model_id,
            report=report,
            diagnostic=diagnostic,
            observed_usage=observed_usage,
            ledger_before=ledger_before,
            ledger_after=ledger_after,
        )
        serialized = payload.model_dump(mode="json")
        entry = CandidateBenchmarkCampaignEntry.model_validate(
            {
                **serialized,
                "entry_sha256": canonical_sha256(serialized),
            }
        )
        filename = _campaign_entry_filename(index, candidate.exact_model_id)
        _atomic_write_private_bytes(
            self.path / filename,
            stable_json(entry).encode("utf-8"),
            maximum=_MAX_REPORT_BYTES,
        )
        loaded = _load_campaign_entry(self.path / filename)
        if loaded != entry:
            raise ValueError("candidate campaign entry changed during persistence")
        self._entries.append(loaded)
        if self._live_binding_recorder is not None:
            self._live_binding_recorder(index, live_content_binding)

    def validate_candidate_start(
        self,
        *,
        candidate: CandidateModel,
        ledger_before: CandidateCostLedgerSnapshot,
    ) -> None:
        """Reject stale journal/ledger state before any next provider request."""

        index = len(self._entries)
        if (
            index >= len(self._candidate_registry.candidates)
            or candidate != self._candidate_registry.candidates[index]
            or ledger_before != self.final_cost_ledger_snapshot
            or candidate_cost_ledger_snapshot(self._cost_ledger.snapshot()) != ledger_before
        ):
            raise ValueError("candidate campaign is not ready for the exact next provider work")

    def require_complete(self) -> None:
        if len(self._entries) != len(self._candidate_registry.candidates):
            raise ValueError("candidate campaign does not have exact-set report coverage")


class CandidateReasoningProfileBenchmarkCampaignManifestPayload(StrictModel):
    """Immutable supplemental route, corpus, config, policy, and ledger bindings."""

    schema_version: Literal["1.0"] = "1.0"
    created_at: datetime
    candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    discovery_run_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    qualification_policy_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    plan: CandidateReasoningProfileBenchmarkPlan
    cost_ledger_path_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_cost_ledger_snapshot: CandidateCostLedgerSnapshot

    @field_validator("created_at")
    @classmethod
    def reasoning_campaign_time_is_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("reasoning-profile campaign creation time must be UTC")
        return value


class CandidateReasoningProfileBenchmarkCampaignManifest(
    CandidateReasoningProfileBenchmarkCampaignManifestPayload
):
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def reasoning_manifest_hash_matches(
        self,
    ) -> CandidateReasoningProfileBenchmarkCampaignManifest:
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"campaign_manifest_sha256"})
        )
        if self.campaign_manifest_sha256 != expected:
            raise ValueError("reasoning-profile campaign manifest hash is inconsistent")
        return self


class CandidateReasoningProfileBenchmarkCampaignEntryPayload(StrictModel):
    """One durable supplemental route outcome and exact ledger transition."""

    schema_version: Literal["1.0"] = "1.0"
    campaign_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    route_index: int = Field(ge=0, lt=4_096)
    route: CandidateReasoningProfileBenchmarkRoute
    report: ModelBenchmarkReport
    diagnostic: CandidateBenchmarkDiagnostic
    observed_usage: tuple[UsageRecord, ...] = Field(max_length=1_000)
    ledger_before: CandidateCostLedgerSnapshot
    ledger_after: CandidateCostLedgerSnapshot

    @model_validator(mode="after")
    def reasoning_entry_is_exactly_bound(
        self,
    ) -> CandidateReasoningProfileBenchmarkCampaignEntryPayload:
        outcome = CandidateReasoningProfileBenchmarkRun(
            route=self.route,
            report=self.report,
            diagnostic=self.diagnostic,
        )
        del outcome
        if (
            self.diagnostic.observed_usage_sha256
            != canonical_sha256([item.model_dump(mode="json") for item in self.observed_usage])
            or self.diagnostic.cost_ledger_before != self.ledger_before
            or self.diagnostic.cost_ledger_after != self.ledger_after
            or any(
                item.requested_model != self.route.exact_model_id
                or item.role != self.route.request_role
                for item in self.observed_usage
            )
        ):
            raise ValueError("reasoning-profile campaign entry bindings are inconsistent")
        request_ids = tuple(item.request_id for item in self.observed_usage)
        if len(request_ids) != len(set(request_ids)):
            raise ValueError("reasoning-profile campaign entry replays a request ID")
        report_usage = tuple(
            case.usage_record
            for result in self.report.results
            for case in result.cases
            if case.usage_record is not None
        )
        report_projection = _usage_records_public_projection(report_usage)
        observed_projection = _usage_records_public_projection(self.observed_usage)
        if self.diagnostic.state is not CandidateBenchmarkRunState.UNVERIFIED_FAILURE:
            if report_projection != observed_projection:
                raise ValueError("completed reasoning-profile report omits observed usage")
        elif any(item not in observed_projection for item in report_projection):
            raise ValueError("failed reasoning-profile report contains unobserved usage")
        ledger_delta = Decimal(self.ledger_after.spent_usd) - Decimal(self.ledger_before.spent_usd)
        observed_cost = sum(
            (Decimal(str(item.accounted_cost_usd)) for item in self.observed_usage),
            Decimal(0),
        )
        unresolved_before = (
            self.ledger_before.reserved_count + self.ledger_before.uncertain_accounted_count
        )
        unresolved_after = (
            self.ledger_after.reserved_count + self.ledger_after.uncertain_accounted_count
        )
        if (
            self.ledger_after.entry_count < self.ledger_before.entry_count
            or ledger_delta < 0
            or ledger_delta != observed_cost
            or unresolved_after - unresolved_before != self.diagnostic.unresolved_cost_count
        ):
            raise ValueError("reasoning-profile campaign usage and ledger disagree")
        return self


class CandidateReasoningProfileBenchmarkCampaignEntry(
    CandidateReasoningProfileBenchmarkCampaignEntryPayload
):
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def reasoning_entry_hash_matches(
        self,
    ) -> CandidateReasoningProfileBenchmarkCampaignEntry:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"entry_sha256"}))
        if self.entry_sha256 != expected:
            raise ValueError("reasoning-profile campaign entry hash is inconsistent")
        return self


class CandidateReasoningProfileBenchmarkCampaignJournal:
    """Private append-only supplemental campaign with optional live authority."""

    def __init__(
        self,
        *,
        path: Path,
        manifest: CandidateReasoningProfileBenchmarkCampaignManifest,
        entries: tuple[CandidateReasoningProfileBenchmarkCampaignEntry, ...],
        candidate_registry: CandidateRegistry,
        corpus: ModelBenchmarkSuite,
        cost_ledger: AtomicCostLedger,
    ) -> None:
        self.path = path
        self.manifest = manifest
        self._entries = list(entries)
        self._candidate_registry = candidate_registry
        self._corpus = corpus
        self._cost_ledger = cost_ledger
        self._live_binding_recorder: Callable[[int, str], None] | None = None

    def _attach_live_binding_recorder(self, recorder: Callable[[int, str], None]) -> None:
        if self._live_binding_recorder is not None:
            raise ValueError("reasoning-profile campaign runtime authority is already attached")
        self._live_binding_recorder = recorder

    @property
    def plan_sha256(self) -> str:
        return self.manifest.plan.plan_sha256

    @property
    def runs(self) -> tuple[CandidateReasoningProfileBenchmarkRun, ...]:
        return tuple(
            CandidateReasoningProfileBenchmarkRun(
                route=item.route,
                report=item.report,
                diagnostic=item.diagnostic,
            )
            for item in self._entries
        )

    @property
    def final_cost_ledger_snapshot(self) -> CandidateCostLedgerSnapshot:
        return (
            self._entries[-1].ledger_after
            if self._entries
            else self.manifest.initial_cost_ledger_snapshot
        )

    @property
    def journal_sha256(self) -> str:
        return canonical_sha256(
            {
                "campaign_manifest_sha256": self.manifest.campaign_manifest_sha256,
                "entry_sha256": [item.entry_sha256 for item in self._entries],
            }
        )

    def require_live_authority(self) -> None:
        """Reject reloaded journals before supplemental provider work can begin."""

        if self._live_binding_recorder is None:
            raise ValueError("reasoning-profile campaign lacks live runtime authority")

    def validate_route_start(
        self,
        *,
        route: CandidateReasoningProfileBenchmarkRoute,
        ledger_before: CandidateCostLedgerSnapshot,
    ) -> None:
        index = len(self._entries)
        if (
            self._live_binding_recorder is None
            or index >= len(self.manifest.plan.routes)
            or route != self.manifest.plan.routes[index]
            or ledger_before != self.final_cost_ledger_snapshot
            or candidate_cost_ledger_snapshot(self._cost_ledger.snapshot()) != ledger_before
        ):
            raise ValueError("reasoning-profile campaign is not ready for the next route")

    def persist_route(
        self,
        *,
        route: CandidateReasoningProfileBenchmarkRoute,
        report: ModelBenchmarkReport,
        diagnostic: CandidateBenchmarkDiagnostic,
        observed_usage: tuple[UsageRecord, ...],
        ledger_before: CandidateCostLedgerSnapshot,
        ledger_after: CandidateCostLedgerSnapshot,
    ) -> None:
        index = len(self._entries)
        if (
            self._live_binding_recorder is None
            or index >= len(self.manifest.plan.routes)
            or route != self.manifest.plan.routes[index]
            or ledger_before != self.final_cost_ledger_snapshot
        ):
            raise ValueError("reasoning-profile campaign append is not the exact next route")
        prior_request_ids = {
            item.request_id for entry in self._entries for item in entry.observed_usage
        }
        prior_generation_ids = {
            item.openrouter_generation_id
            for entry in self._entries
            for item in entry.observed_usage
            if item.openrouter_generation_id is not None
        }
        if any(item.request_id in prior_request_ids for item in observed_usage) or any(
            item.openrouter_generation_id in prior_generation_ids
            for item in observed_usage
            if item.openrouter_generation_id is not None
        ):
            raise ValueError("reasoning-profile campaign replays request or generation evidence")
        if candidate_cost_ledger_snapshot(self._cost_ledger.snapshot()) != ledger_after:
            raise ValueError("reasoning-profile campaign ledger snapshot is not current")
        live_binding = _live_report_content_binding(
            report=report,
            observed_usage=observed_usage,
        )
        payload = CandidateReasoningProfileBenchmarkCampaignEntryPayload(
            campaign_manifest_sha256=self.manifest.campaign_manifest_sha256,
            route_index=index,
            route=route,
            report=report,
            diagnostic=diagnostic,
            observed_usage=observed_usage,
            ledger_before=ledger_before,
            ledger_after=ledger_after,
        )
        serialized = payload.model_dump(mode="json")
        entry = CandidateReasoningProfileBenchmarkCampaignEntry.model_validate(
            {**serialized, "entry_sha256": canonical_sha256(serialized)}
        )
        filename = _reasoning_campaign_entry_filename(index, route)
        _atomic_write_private_bytes(
            self.path / filename,
            stable_json(entry).encode("utf-8"),
            maximum=_MAX_REPORT_BYTES,
        )
        loaded = _load_reasoning_campaign_entry(self.path / filename)
        if loaded != entry:
            raise ValueError("reasoning-profile campaign entry changed during persistence")
        self._entries.append(loaded)
        if self._live_binding_recorder is not None:
            self._live_binding_recorder(index, live_binding)

    def require_complete(self) -> None:
        if len(self._entries) != len(self.manifest.plan.routes):
            raise ValueError("reasoning-profile campaign lacks exact route coverage")


def _create_candidate_reasoning_profile_campaign_unregistered(
    path: Path,
    *,
    plan: CandidateReasoningProfileBenchmarkPlan,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> CandidateReasoningProfileBenchmarkCampaignJournal:
    """Create a fresh private supplemental journal before any provider work."""

    frozen_plan = CandidateReasoningProfileBenchmarkPlan.model_validate(
        plan.model_dump(mode="json")
    )
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    if not re.fullmatch(_SHA256_PATTERN, effective_config_sha256):
        raise ValueError("reasoning-profile campaign effective-config hash is invalid")
    if not re.fullmatch(_SHA256_PATTERN, qualification_policy_sha256):
        raise ValueError("reasoning-profile campaign qualification-policy hash is invalid")
    if not isinstance(cost_ledger, AtomicCostLedger):
        raise ValueError("reasoning-profile campaign requires an atomic cost ledger")
    candidate_ids = {item.exact_model_id for item in registry.candidates}
    if any(route.exact_model_id not in candidate_ids for route in frozen_plan.routes):
        raise ValueError("reasoning-profile plan names a model outside the candidate registry")

    absolute = Path(os.path.abspath(path))
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise ValueError("reasoning-profile campaign journal destination must be fresh")
    _reject_linked_components(absolute.parent)
    absolute.parent.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
    _reject_linked_components(absolute.parent)
    payload = CandidateReasoningProfileBenchmarkCampaignManifestPayload(
        created_at=datetime.now(UTC),
        candidate_registry_sha256=registry.registry_sha256,
        discovery_run_manifest_sha256=registry.discovery_run_sha256,
        corpus_sha256=suite.corpus_sha256,
        ground_truth_sha256=suite.ground_truth_sha256,
        qualification_policy_sha256=qualification_policy_sha256,
        effective_config_sha256=effective_config_sha256,
        plan=frozen_plan,
        cost_ledger_path_sha256=_cost_ledger_path_sha256(cost_ledger),
        initial_cost_ledger_snapshot=candidate_cost_ledger_snapshot(cost_ledger.snapshot()),
    )
    serialized = payload.model_dump(mode="json")
    manifest = CandidateReasoningProfileBenchmarkCampaignManifest.model_validate(
        {
            **serialized,
            "campaign_manifest_sha256": canonical_sha256(serialized),
        }
    )
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{absolute.name}.",
            suffix=".reasoning-campaign.tmp",
            dir=absolute.parent,
        )
    )
    os.chmod(temporary, _PRIVATE_DIRECTORY_MODE)
    published = False
    try:
        _write_private_bytes(
            temporary / _REASONING_CAMPAIGN_MANIFEST_NAME,
            stable_json(manifest).encode("utf-8"),
            maximum=_MAX_MANIFEST_BYTES,
        )
        _fsync_directory(temporary)
        if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
            raise ValueError("reasoning-profile campaign journal destination was reused")
        os.rename(temporary, absolute)
        published = True
        _fsync_directory(absolute.parent)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
    return CandidateReasoningProfileBenchmarkCampaignJournal(
        path=absolute,
        manifest=manifest,
        entries=(),
        candidate_registry=registry,
        corpus=suite,
        cost_ledger=cost_ledger,
    )


def resume_candidate_reasoning_profile_benchmark_campaign(
    path: Path,
    *,
    plan: CandidateReasoningProfileBenchmarkPlan,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> CandidateReasoningProfileBenchmarkCampaignJournal:
    """Resume exact structural evidence without restoring live response authority."""

    frozen_plan = CandidateReasoningProfileBenchmarkPlan.model_validate(
        plan.model_dump(mode="json")
    )
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    absolute = Path(os.path.abspath(path))
    _require_private_directory(absolute, label="reasoning-profile campaign journal")
    manifest_raw = _read_private_file(
        absolute / _REASONING_CAMPAIGN_MANIFEST_NAME,
        maximum=_MAX_MANIFEST_BYTES,
    )
    manifest = _parse_model(
        manifest_raw,
        CandidateReasoningProfileBenchmarkCampaignManifest,
    )
    if manifest_raw != stable_json(manifest).encode("utf-8"):
        raise ValueError("reasoning-profile campaign manifest is not canonical")
    if (
        manifest.candidate_registry_sha256 != registry.registry_sha256
        or manifest.discovery_run_manifest_sha256 != registry.discovery_run_sha256
        or manifest.corpus_sha256 != suite.corpus_sha256
        or manifest.ground_truth_sha256 != suite.ground_truth_sha256
        or manifest.qualification_policy_sha256 != qualification_policy_sha256
        or manifest.effective_config_sha256 != effective_config_sha256
        or manifest.plan != frozen_plan
        or manifest.cost_ledger_path_sha256 != _cost_ledger_path_sha256(cost_ledger)
    ):
        raise ValueError("reasoning-profile campaign resume bindings do not match")

    entries: list[CandidateReasoningProfileBenchmarkCampaignEntry] = []
    expected_names = {_REASONING_CAMPAIGN_MANIFEST_NAME}
    missing_seen = False
    for index, route in enumerate(frozen_plan.routes):
        filename = _reasoning_campaign_entry_filename(index, route)
        entry_path = absolute / filename
        if not entry_path.exists():
            missing_seen = True
            continue
        if missing_seen:
            raise ValueError("reasoning-profile campaign entries are not a contiguous prefix")
        entry = _load_reasoning_campaign_entry(entry_path)
        if (
            entry.campaign_manifest_sha256 != manifest.campaign_manifest_sha256
            or entry.route_index != index
            or entry.route != route
        ):
            raise ValueError("reasoning-profile campaign entry differs from its frozen route")
        if entries:
            if entry.ledger_before != entries[-1].ledger_after:
                raise ValueError("reasoning-profile campaign ledger transitions are discontinuous")
        elif entry.ledger_before != manifest.initial_cost_ledger_snapshot:
            raise ValueError("reasoning-profile first ledger transition is inconsistent")
        verify_model_benchmark_report_structure(entry.report, corpus=suite)
        entries.append(entry)
        expected_names.add(filename)
    if {item.name for item in absolute.iterdir()} != expected_names:
        raise ValueError("reasoning-profile campaign contains unmanifested artifacts")
    request_ids = tuple(record.request_id for entry in entries for record in entry.observed_usage)
    generation_ids = tuple(
        record.openrouter_generation_id
        for entry in entries
        for record in entry.observed_usage
        if record.openrouter_generation_id is not None
    )
    if len(request_ids) != len(set(request_ids)) or len(generation_ids) != len(set(generation_ids)):
        raise ValueError("reasoning-profile campaign replays request or generation evidence")
    expected_current = (
        entries[-1].ledger_after if entries else manifest.initial_cost_ledger_snapshot
    )
    if candidate_cost_ledger_snapshot(cost_ledger.snapshot()) != expected_current:
        raise ValueError("reasoning-profile campaign cost ledger changed outside its journal")
    return CandidateReasoningProfileBenchmarkCampaignJournal(
        path=absolute,
        manifest=manifest,
        entries=tuple(entries),
        candidate_registry=registry,
        corpus=suite,
        cost_ledger=cost_ledger,
    )


def verify_candidate_reasoning_profile_benchmark_campaign(
    path: Path,
    *,
    execution: CandidateReasoningProfileBenchmarkExecutionResult,
    plan: CandidateReasoningProfileBenchmarkPlan,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> None:
    """Verify persisted supplemental evidence without minting same-process authority."""

    journal = resume_candidate_reasoning_profile_benchmark_campaign(
        path,
        plan=plan,
        candidate_registry=candidate_registry,
        corpus=corpus,
        effective_config_sha256=effective_config_sha256,
        qualification_policy_sha256=qualification_policy_sha256,
        cost_ledger=cost_ledger,
    )
    journal.require_complete()
    validated = CandidateReasoningProfileBenchmarkExecutionResult.model_validate(
        execution.model_dump(mode="json")
    )
    if validated.plan_sha256 != journal.plan_sha256 or validated.runs != journal.runs:
        raise ValueError("reasoning-profile execution differs from its campaign journal")


def _create_candidate_benchmark_campaign_unregistered(
    path: Path,
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> CandidateBenchmarkCampaignJournal:
    """Create one explicitly selected fresh private journal before provider work."""

    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    if not re.fullmatch(_SHA256_PATTERN, effective_config_sha256):
        raise ValueError("candidate campaign effective-config hash is invalid")
    if not re.fullmatch(_SHA256_PATTERN, qualification_policy_sha256):
        raise ValueError("candidate campaign qualification-policy hash is invalid")
    if not isinstance(cost_ledger, AtomicCostLedger):
        raise ValueError("candidate campaign requires an atomic cost ledger")
    absolute = Path(os.path.abspath(path))
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise ValueError("candidate campaign journal destination must be fresh")
    _reject_linked_components(absolute.parent)
    absolute.parent.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
    _reject_linked_components(absolute.parent)
    created_at = datetime.now(UTC)
    payload = CandidateBenchmarkCampaignManifestPayload(
        created_at=created_at,
        candidate_registry_sha256=registry.registry_sha256,
        discovery_run_manifest_sha256=registry.discovery_run_sha256,
        candidate_model_ids=tuple(item.exact_model_id for item in registry.candidates),
        corpus_sha256=suite.corpus_sha256,
        ground_truth_sha256=suite.ground_truth_sha256,
        qualification_policy_sha256=qualification_policy_sha256,
        effective_config_sha256=effective_config_sha256,
        cost_ledger_path_sha256=_cost_ledger_path_sha256(cost_ledger),
        initial_cost_ledger_snapshot=candidate_cost_ledger_snapshot(cost_ledger.snapshot()),
    )
    serialized = payload.model_dump(mode="json")
    manifest = CandidateBenchmarkCampaignManifest.model_validate(
        {
            **serialized,
            "campaign_manifest_sha256": canonical_sha256(serialized),
        }
    )
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{absolute.name}.",
            suffix=".campaign.tmp",
            dir=absolute.parent,
        )
    )
    os.chmod(temporary, _PRIVATE_DIRECTORY_MODE)
    published = False
    try:
        _write_private_bytes(
            temporary / _CAMPAIGN_MANIFEST_NAME,
            stable_json(manifest).encode("utf-8"),
            maximum=_MAX_MANIFEST_BYTES,
        )
        _fsync_directory(temporary)
        if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
            raise ValueError("candidate campaign journal destination was reused")
        os.rename(temporary, absolute)
        published = True
        _fsync_directory(absolute.parent)
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)
    journal = CandidateBenchmarkCampaignJournal(
        path=absolute,
        manifest=manifest,
        entries=(),
        candidate_registry=registry,
        corpus=suite,
        cost_ledger=cost_ledger,
    )
    return journal


def resume_candidate_benchmark_campaign(
    path: Path,
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> CandidateBenchmarkCampaignJournal:
    """Explicitly resume one exact bound journal; never create or reuse implicitly."""

    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    absolute = Path(os.path.abspath(path))
    _require_private_directory(absolute, label="candidate campaign journal")
    manifest_raw = _read_private_file(
        absolute / _CAMPAIGN_MANIFEST_NAME,
        maximum=_MAX_MANIFEST_BYTES,
    )
    manifest = _parse_model(manifest_raw, CandidateBenchmarkCampaignManifest)
    if manifest_raw != stable_json(manifest).encode("utf-8"):
        raise ValueError("candidate campaign manifest is not canonical")
    expected_ids = tuple(item.exact_model_id for item in registry.candidates)
    if (
        manifest.candidate_registry_sha256 != registry.registry_sha256
        or manifest.discovery_run_manifest_sha256 != registry.discovery_run_sha256
        or manifest.candidate_model_ids != expected_ids
        or manifest.corpus_sha256 != suite.corpus_sha256
        or manifest.ground_truth_sha256 != suite.ground_truth_sha256
        or manifest.qualification_policy_sha256 != qualification_policy_sha256
        or manifest.effective_config_sha256 != effective_config_sha256
        or manifest.cost_ledger_path_sha256 != _cost_ledger_path_sha256(cost_ledger)
    ):
        raise ValueError("candidate campaign resume bindings do not match")

    entries: list[CandidateBenchmarkCampaignEntry] = []
    expected_names = {_CAMPAIGN_MANIFEST_NAME}
    missing_seen = False
    for index, model_id in enumerate(expected_ids):
        filename = _campaign_entry_filename(index, model_id)
        entry_path = absolute / filename
        if not entry_path.exists():
            missing_seen = True
            continue
        if missing_seen:
            raise ValueError("candidate campaign entries are not a contiguous exact prefix")
        entry = _load_campaign_entry(entry_path)
        if (
            entry.campaign_manifest_sha256 != manifest.campaign_manifest_sha256
            or entry.candidate_index != index
            or entry.exact_model_id != model_id
        ):
            raise ValueError("candidate campaign entry differs from its frozen position")
        if entries:
            if entry.ledger_before != entries[-1].ledger_after:
                raise ValueError("candidate campaign ledger transitions are discontinuous")
        elif entry.ledger_before != manifest.initial_cost_ledger_snapshot:
            raise ValueError("candidate campaign first ledger transition is inconsistent")
        verify_model_benchmark_report_structure(entry.report, corpus=suite)
        entries.append(entry)
        expected_names.add(filename)
    observed_names = {item.name for item in absolute.iterdir()}
    if observed_names != expected_names:
        raise ValueError("candidate campaign contains stale or unmanifested artifacts")
    request_ids = tuple(record.request_id for entry in entries for record in entry.observed_usage)
    generation_ids = tuple(
        record.openrouter_generation_id
        for entry in entries
        for record in entry.observed_usage
        if record.openrouter_generation_id is not None
    )
    if len(request_ids) != len(set(request_ids)) or len(generation_ids) != len(set(generation_ids)):
        raise ValueError("candidate campaign replays request or generation evidence")
    expected_current = (
        entries[-1].ledger_after if entries else manifest.initial_cost_ledger_snapshot
    )
    if candidate_cost_ledger_snapshot(cost_ledger.snapshot()) != expected_current:
        raise ValueError("candidate campaign cost ledger changed outside its journal")
    return CandidateBenchmarkCampaignJournal(
        path=absolute,
        manifest=manifest,
        entries=tuple(entries),
        candidate_registry=registry,
        corpus=suite,
        cost_ledger=cost_ledger,
    )


def verify_model_benchmark_portfolio_campaign(
    path: Path,
    *,
    portfolio: ModelBenchmarkPortfolio,
    reports: tuple[ModelBenchmarkReport, ...],
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    effective_config_sha256: str,
    qualification_policy_sha256: str,
    cost_ledger: AtomicCostLedger,
) -> None:
    """Structurally validate persisted campaign evidence without minting live trust."""

    campaign = resume_candidate_benchmark_campaign(
        path,
        candidate_registry=candidate_registry,
        corpus=corpus,
        effective_config_sha256=effective_config_sha256,
        qualification_policy_sha256=qualification_policy_sha256,
        cost_ledger=cost_ledger,
    )
    campaign.require_complete()
    validated_portfolio = ModelBenchmarkPortfolio.model_validate(portfolio.model_dump(mode="json"))
    validated_reports = tuple(
        ModelBenchmarkReport.model_validate(report.model_dump(mode="json")) for report in reports
    )
    if (
        _reports_public_projection(campaign.reports)
        != _reports_public_projection(validated_reports)
        or campaign.diagnostics != validated_portfolio.diagnostics
        or _usage_records_public_projection(campaign.observed_usage)
        != _usage_records_public_projection(validated_portfolio.observed_usage_records)
        or campaign.journal_sha256 != validated_portfolio.campaign_journal_sha256
        or campaign.manifest.qualification_policy_sha256
        != validated_portfolio.qualification_policy_sha256
        or campaign.manifest.initial_cost_ledger_snapshot
        != validated_portfolio.initial_cost_ledger_snapshot
        or campaign.final_cost_ledger_snapshot != validated_portfolio.cost_ledger_snapshot
    ):
        raise ValueError("benchmark portfolio differs from its actual campaign journal")


def seal_model_benchmark_portfolio_from_campaign(
    path: Path,
    *,
    campaign: CandidateBenchmarkCampaignJournal,
) -> ModelBenchmarkPortfolio:
    """Seal only a complete, freshly revalidated exact journal set."""

    campaign.require_complete()
    reloaded = resume_candidate_benchmark_campaign(
        campaign.path,
        candidate_registry=campaign._candidate_registry,
        corpus=campaign._corpus,
        effective_config_sha256=campaign.manifest.effective_config_sha256,
        qualification_policy_sha256=campaign.manifest.qualification_policy_sha256,
        cost_ledger=campaign._cost_ledger,
    )
    reloaded.require_complete()
    return write_model_benchmark_portfolio(
        path,
        candidate_registry=reloaded._candidate_registry,
        corpus=reloaded._corpus,
        reports=reloaded.reports,
        diagnostics=reloaded.diagnostics,
        observed_usage=reloaded.observed_usage,
        campaign_journal_sha256=reloaded.journal_sha256,
        qualification_policy_sha256=reloaded.manifest.qualification_policy_sha256,
        initial_cost_ledger_snapshot=reloaded.manifest.initial_cost_ledger_snapshot,
        cost_ledger_snapshot=reloaded.final_cost_ledger_snapshot,
    )


def write_model_benchmark_portfolio(
    path: Path,
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    reports: tuple[ModelBenchmarkReport, ...],
    diagnostics: tuple[CandidateBenchmarkDiagnostic, ...] = (),
    observed_usage: tuple[UsageRecord, ...] | None = None,
    campaign_journal_sha256: str | None = None,
    qualification_policy_sha256: str | None = None,
    initial_cost_ledger_snapshot: CandidateCostLedgerSnapshot | None = None,
    cost_ledger_snapshot: CandidateCostLedgerSnapshot | None = None,
) -> ModelBenchmarkPortfolio:
    """Atomically publish a fresh private exact-set report directory."""

    registry, suite, ordered_reports = _validate_report_set(
        candidate_registry=candidate_registry,
        corpus=corpus,
        reports=reports,
    )
    retained_usage = (
        _report_usage_records(ordered_reports)
        if observed_usage is None
        else tuple(
            UsageRecord.model_validate(item.model_dump(mode="json")) for item in observed_usage
        )
    )
    validated_diagnostics = _validate_diagnostics(
        reports=ordered_reports,
        diagnostics=diagnostics,
        observed_usage=retained_usage,
    )
    absolute = Path(os.path.abspath(path))
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise ValueError("model benchmark portfolio destination must be fresh")
    _reject_linked_components(absolute.parent)
    absolute.parent.mkdir(parents=True, exist_ok=True, mode=_PRIVATE_DIRECTORY_MODE)
    _reject_linked_components(absolute.parent)
    temporary = Path(
        tempfile.mkdtemp(
            prefix=f".{absolute.name}.",
            suffix=".tmp",
            dir=absolute.parent,
        )
    )
    os.chmod(temporary, _PRIVATE_DIRECTORY_MODE)
    published = False
    try:
        bindings: list[ModelBenchmarkReportArtifact] = []
        for report in ordered_reports:
            model_id = report.results[0].target.model_id
            filename = _report_filename(model_id)
            serialized = stable_json(report).encode("utf-8")
            if len(serialized) > _MAX_REPORT_BYTES:
                raise ValueError("model benchmark report exceeds the portfolio bound")
            destination = temporary / filename
            _write_private_bytes(destination, serialized, maximum=_MAX_REPORT_BYTES)
            written = _read_private_file(destination, maximum=_MAX_REPORT_BYTES)
            if written != serialized:
                raise ValueError("model benchmark report changed during portfolio staging")
            bindings.append(
                ModelBenchmarkReportArtifact(
                    exact_model_id=model_id,
                    filename=filename,
                    artifact_sha256=hashlib.sha256(written).hexdigest(),
                    report_sha256=report.report_sha256,
                    execution_evidence=report.execution_evidence,
                )
            )
        portfolio = _seal_portfolio(
            candidate_registry=registry,
            corpus=suite,
            reports=ordered_reports,
            report_artifacts=tuple(bindings),
            diagnostics=validated_diagnostics,
            observed_usage=retained_usage,
            campaign_journal_sha256=campaign_journal_sha256,
            qualification_policy_sha256=qualification_policy_sha256,
            initial_cost_ledger_snapshot=initial_cost_ledger_snapshot,
            cost_ledger_snapshot=cost_ledger_snapshot,
        )
        manifest_bytes = stable_json(portfolio).encode("utf-8")
        _write_private_bytes(
            temporary / _PORTFOLIO_MANIFEST_NAME,
            manifest_bytes,
            maximum=_MAX_MANIFEST_BYTES,
        )
        expected_names = {
            _PORTFOLIO_MANIFEST_NAME,
            *(item.filename for item in bindings),
        }
        if {item.name for item in temporary.iterdir()} != expected_names:
            raise ValueError("model benchmark portfolio staging contains unexpected artifacts")
        _fsync_directory(temporary)
        if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
            raise ValueError("model benchmark portfolio destination was reused")
        os.rename(temporary, absolute)
        published = True
        _fsync_directory(absolute.parent)
        return portfolio
    finally:
        if not published:
            shutil.rmtree(temporary, ignore_errors=True)


def load_model_benchmark_portfolio(
    path: Path,
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
) -> tuple[ModelBenchmarkPortfolio, tuple[ModelBenchmarkReport, ...]]:
    """Load and independently reconcile one complete private portfolio directory."""

    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    absolute = Path(os.path.abspath(path))
    _reject_linked_components(absolute)
    try:
        directory_metadata = os.lstat(absolute)
    except OSError as exc:
        raise ValueError("model benchmark portfolio directory is unavailable") from exc
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise ValueError("model benchmark portfolio must be a private regular directory")

    manifest_raw = _read_private_file(
        absolute / _PORTFOLIO_MANIFEST_NAME,
        maximum=_MAX_MANIFEST_BYTES,
    )
    portfolio = _parse_model(manifest_raw, ModelBenchmarkPortfolio)
    if manifest_raw != stable_json(portfolio).encode("utf-8"):
        raise ValueError("model benchmark portfolio manifest is not canonical")
    _validate_portfolio_bindings(
        portfolio=portfolio,
        candidate_registry=registry,
        corpus=suite,
    )

    expected_names = {
        _PORTFOLIO_MANIFEST_NAME,
        *(item.filename for item in portfolio.report_artifacts),
    }
    observed_names = {item.name for item in absolute.iterdir()}
    if observed_names != expected_names:
        raise ValueError("model benchmark portfolio contains stale or unmanifested artifacts")

    reports: list[ModelBenchmarkReport] = []
    for binding in portfolio.report_artifacts:
        report_raw = _read_private_file(
            absolute / binding.filename,
            maximum=_MAX_REPORT_BYTES,
        )
        if hashlib.sha256(report_raw).hexdigest() != binding.artifact_sha256:
            raise ValueError("model benchmark report byte hash differs from its manifest")
        report = _parse_model(report_raw, ModelBenchmarkReport)
        if report_raw != stable_json(report).encode("utf-8"):
            raise ValueError("model benchmark report artifact is not canonical")
        if (
            len(report.results) != 1
            or report.results[0].target.model_id != binding.exact_model_id
            or report.report_sha256 != binding.report_sha256
            or report.execution_evidence is not binding.execution_evidence
        ):
            raise ValueError("model benchmark report differs from its artifact binding")
        verify_model_benchmark_report_structure(report, corpus=suite)
        reports.append(report)

    ordered_reports = tuple(reports)
    expected = _seal_portfolio(
        candidate_registry=registry,
        corpus=suite,
        reports=ordered_reports,
        report_artifacts=portfolio.report_artifacts,
        diagnostics=portfolio.diagnostics,
        observed_usage=portfolio.observed_usage_records,
        campaign_journal_sha256=portfolio.campaign_journal_sha256,
        qualification_policy_sha256=portfolio.qualification_policy_sha256,
        initial_cost_ledger_snapshot=portfolio.initial_cost_ledger_snapshot,
        cost_ledger_snapshot=portfolio.cost_ledger_snapshot,
    )
    if portfolio != expected:
        raise ValueError("model benchmark portfolio aggregates differ from report evidence")
    return portfolio, ordered_reports


def _validate_report_set(
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[CandidateRegistry, ModelBenchmarkSuite, tuple[ModelBenchmarkReport, ...]]:
    registry = CandidateRegistry.model_validate(candidate_registry.model_dump(mode="json"))
    suite = ModelBenchmarkSuite.model_validate(corpus.model_dump(mode="json"))
    if not reports:
        raise ValueError("model benchmark portfolio requires one report per candidate")
    validated: list[ModelBenchmarkReport] = []
    for report in reports:
        checked = ModelBenchmarkReport.model_validate(report.model_dump(mode="json"))
        if len(checked.results) != 1:
            raise ValueError("portfolio reports must each contain exactly one model")
        verify_model_benchmark_report_structure(checked, corpus=suite)
        validated.append(checked)
    ordered = tuple(sorted(validated, key=lambda item: item.results[0].target.model_id))
    report_ids = tuple(item.results[0].target.model_id for item in ordered)
    if len(report_ids) != len(set(report_ids)):
        raise ValueError("portfolio reports contain duplicate exact models")
    candidate_ids = tuple(candidate.exact_model_id for candidate in registry.candidates)
    if report_ids != candidate_ids:
        raise ValueError("portfolio reports do not exactly cover the candidate registry")
    _aggregate_usage(
        _report_usage_records(ordered),
        report_count=len(ordered),
        unresolved_cost_count=0,
    )
    return registry, suite, ordered


def _validate_portfolio_bindings(
    *,
    portfolio: ModelBenchmarkPortfolio,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
) -> None:
    candidate_ids = tuple(candidate.exact_model_id for candidate in candidate_registry.candidates)
    if (
        portfolio.candidate_registry_sha256 != candidate_registry.registry_sha256
        or portfolio.discovery_run_manifest_sha256 != candidate_registry.discovery_run_sha256
        or portfolio.candidate_model_ids != candidate_ids
        or portfolio.corpus_name != corpus.name
        or portfolio.corpus_sha256 != corpus.corpus_sha256
        or portfolio.ground_truth_sha256 != corpus.ground_truth_sha256
    ):
        raise ValueError(
            "model benchmark portfolio is not bound to the supplied registry and corpus"
        )


def _seal_portfolio(
    *,
    candidate_registry: CandidateRegistry,
    corpus: ModelBenchmarkSuite,
    reports: tuple[ModelBenchmarkReport, ...],
    report_artifacts: tuple[ModelBenchmarkReportArtifact, ...],
    diagnostics: tuple[CandidateBenchmarkDiagnostic, ...],
    observed_usage: tuple[UsageRecord, ...],
    campaign_journal_sha256: str | None,
    qualification_policy_sha256: str | None,
    initial_cost_ledger_snapshot: CandidateCostLedgerSnapshot | None,
    cost_ledger_snapshot: CandidateCostLedgerSnapshot | None,
) -> ModelBenchmarkPortfolio:
    candidate_ids = tuple(candidate.exact_model_id for candidate in candidate_registry.candidates)
    report_ids = tuple(report.results[0].target.model_id for report in reports)
    artifact_ids = tuple(item.exact_model_id for item in report_artifacts)
    if report_ids != candidate_ids or artifact_ids != candidate_ids:
        raise ValueError("portfolio sealing requires exact candidate report coverage")
    report_usage = _report_usage_records(reports)
    if any(record not in observed_usage for record in report_usage):
        raise ValueError("portfolio reports contain usage absent from retained campaign evidence")
    if not diagnostics and report_usage != observed_usage:
        raise ValueError("portfolio without diagnostics cannot retain orphan request usage")
    unresolved_cost_count = sum(item.unresolved_cost_count for item in diagnostics)
    usage, started_at, ended_at = _aggregate_usage(
        observed_usage,
        report_count=len(reports),
        unresolved_cost_count=unresolved_cost_count,
    )
    if started_at is not None and started_at < candidate_registry.created_at:
        raise ValueError("model benchmark portfolio predates its candidate registry")
    payload = ModelBenchmarkPortfolioPayload(
        candidate_registry_sha256=candidate_registry.registry_sha256,
        candidate_set_sha256=canonical_sha256(list(candidate_ids)),
        discovery_run_manifest_sha256=candidate_registry.discovery_run_sha256,
        candidate_model_ids=candidate_ids,
        corpus_name=corpus.name,
        corpus_sha256=corpus.corpus_sha256,
        ground_truth_sha256=corpus.ground_truth_sha256,
        qualification_policy_sha256=qualification_policy_sha256,
        started_at=started_at,
        ended_at=ended_at,
        usage=usage,
        execution_evidence=_combined_execution_evidence(
            tuple(report.execution_evidence for report in reports)
        ),
        report_artifacts=report_artifacts,
        diagnostics=diagnostics,
        observed_usage_records=observed_usage,
        campaign_journal_sha256=campaign_journal_sha256,
        initial_cost_ledger_snapshot=initial_cost_ledger_snapshot,
        cost_ledger_snapshot=cost_ledger_snapshot,
    )
    serialized = payload.model_dump(mode="json")
    return ModelBenchmarkPortfolio.model_validate(
        {
            **serialized,
            "portfolio_sha256": canonical_sha256(serialized),
        }
    )


def _validate_diagnostics(
    *,
    reports: tuple[ModelBenchmarkReport, ...],
    diagnostics: tuple[CandidateBenchmarkDiagnostic, ...],
    observed_usage: tuple[UsageRecord, ...],
) -> tuple[CandidateBenchmarkDiagnostic, ...]:
    validated = tuple(
        CandidateBenchmarkDiagnostic.model_validate(item.model_dump(mode="json"))
        for item in diagnostics
    )
    if not validated:
        return ()
    report_ids = tuple(report.results[0].target.model_id for report in reports)
    if tuple(item.exact_model_id for item in validated) != report_ids:
        raise ValueError("portfolio diagnostics do not exactly cover the report set")
    for report, diagnostic in zip(reports, validated, strict=True):
        model_usage = tuple(
            item for item in observed_usage if item.requested_model == diagnostic.exact_model_id
        )
        if (
            diagnostic.report_sha256 != report.report_sha256
            or diagnostic.execution_evidence is not report.execution_evidence
            or diagnostic.requests_observed != len(model_usage)
            or diagnostic.observed_usage_sha256
            != canonical_sha256([item.model_dump(mode="json") for item in model_usage])
        ):
            raise ValueError("portfolio diagnostic differs from its exact report evidence")
    return validated


def _aggregate_usage(
    records: tuple[UsageRecord, ...],
    *,
    report_count: int,
    unresolved_cost_count: int,
) -> tuple[ModelBenchmarkPortfolioUsage, datetime | None, datetime | None]:
    if not records:
        return (
            ModelBenchmarkPortfolioUsage(
                report_count=report_count,
                usage_record_count=0,
                logical_request_count=0,
                provider_attempt_count=0,
                retry_count=0,
                successful_request_count=0,
                failed_request_count=0,
                unresolved_cost_count=0,
                prompt_tokens=0,
                completion_tokens=0,
                total_tokens=0,
                reported_cost_record_count=0,
                reported_cost_usd="0",
                accounted_cost_usd="0",
                latency_record_count=0,
                total_latency_ms=0,
                maximum_latency_ms=None,
            ),
            None,
            None,
        )
    request_ids = tuple(record.request_id for record in records)
    if len(request_ids) != len(set(request_ids)):
        raise ValueError("model benchmark portfolio replays a request ID")
    generation_ids = tuple(
        record.openrouter_generation_id
        for record in records
        if record.openrouter_generation_id is not None
    )
    if len(generation_ids) != len(set(generation_ids)):
        raise ValueError("model benchmark portfolio replays a generation ID")

    reported_costs = tuple(
        Decimal(str(record.reported_cost_usd))
        for record in records
        if record.reported_cost_usd is not None
    )
    accounted_costs = tuple(Decimal(str(record.accounted_cost_usd)) for record in records)
    latencies = tuple(record.latency_ms for record in records if record.latency_ms is not None)
    started_at = min(_record_start(record) for record in records)
    ended_at = max(_record_end(record) for record in records)
    usage = ModelBenchmarkPortfolioUsage(
        report_count=report_count,
        usage_record_count=len(records),
        logical_request_count=len(records),
        provider_attempt_count=sum(record.attempts for record in records),
        retry_count=sum(record.attempts - 1 for record in records),
        successful_request_count=sum(record.status == "success" for record in records),
        failed_request_count=sum(record.status != "success" for record in records),
        unresolved_cost_count=unresolved_cost_count,
        prompt_tokens=sum(record.prompt_tokens for record in records),
        completion_tokens=sum(record.completion_tokens for record in records),
        total_tokens=sum(record.total_tokens for record in records),
        reported_cost_record_count=len(reported_costs),
        reported_cost_usd=_canonical_decimal(sum(reported_costs, Decimal(0))),
        accounted_cost_usd=_canonical_decimal(sum(accounted_costs, Decimal(0))),
        latency_record_count=len(latencies),
        total_latency_ms=sum(latencies),
        maximum_latency_ms=max(latencies) if latencies else None,
    )
    return usage, started_at, ended_at


def _record_start(record: UsageRecord) -> datetime:
    return _as_utc(record.started_at or record.timestamp)


def _record_end(record: UsageRecord) -> datetime:
    return _as_utc(record.ended_at or record.timestamp)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("model benchmark UsageRecord timestamps must be timezone-aware")
    return value.astimezone(UTC)


def _combined_execution_evidence(
    values: tuple[ExecutionEvidenceKind, ...],
) -> ExecutionEvidenceKind:
    if not values:
        return ExecutionEvidenceKind.UNVERIFIED
    unique = set(values)
    if len(unique) != 1:
        return ExecutionEvidenceKind.UNVERIFIED
    return next(iter(unique))


def _report_filename(model_id: str) -> str:
    return f"model-report-{hashlib.sha256(model_id.encode()).hexdigest()}.json"


def _campaign_entry_filename(index: int, model_id: str) -> str:
    return f"candidate-{index:03d}-{hashlib.sha256(model_id.encode()).hexdigest()}.json"


def _reasoning_campaign_entry_filename(
    index: int,
    route: CandidateReasoningProfileBenchmarkRoute,
) -> str:
    identity = f"{route.exact_model_id}\0{route.request_role}".encode()
    return f"reasoning-route-{index:04d}-{hashlib.sha256(identity).hexdigest()}.json"


def _report_usage_records(
    reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[UsageRecord, ...]:
    return tuple(
        case.usage_record
        for report in reports
        for result in report.results
        for case in result.cases
        if case.usage_record is not None
    )


def _usage_records_public_projection(
    records: tuple[UsageRecord, ...],
) -> tuple[str, ...]:
    """Project records onto their canonical public fields, excluding private provenance."""

    return tuple(canonical_sha256(record.model_dump(mode="json")) for record in records)


def _reports_public_projection(
    reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[str, ...]:
    """Return the canonical serialized content identity of each ordered report."""

    return tuple(canonical_sha256(report.model_dump(mode="json")) for report in reports)


def _report_content_bindings(
    reports: tuple[ModelBenchmarkReport, ...],
) -> tuple[tuple[str, str], ...]:
    """Bind each exact model ID to all canonical serialized report content."""

    bindings: list[tuple[str, str]] = []
    for report in reports:
        if len(report.results) != 1:
            raise ValueError("trusted campaign reports must each contain one exact model")
        bindings.append(
            (
                report.results[0].target.model_id,
                canonical_sha256(report.model_dump(mode="json")),
            )
        )
    return tuple(bindings)


def _live_report_content_binding(
    *,
    report: ModelBenchmarkReport,
    observed_usage: tuple[UsageRecord, ...],
) -> str:
    """Validate original REAL response provenance before caching a report binding."""

    report_usage = _report_usage_records((report,))
    observed_projection = _usage_records_public_projection(observed_usage)
    report_projection = _usage_records_public_projection(report_usage)
    if any(binding not in observed_projection for binding in report_projection):
        raise ValueError("candidate report contains usage absent from its live execution")
    for record in report_usage:
        if record.execution_evidence is ExecutionEvidenceKind.REAL and not (
            is_creditable_usage_record(
                record,
                require_real=True,
                require_certification=True,
            )
        ):
            raise ValueError(
                "REAL candidate report content lacks owned runtime execution provenance"
            )
    return canonical_sha256(report.model_dump(mode="json"))


def _cost_ledger_path_sha256(cost_ledger: AtomicCostLedger) -> str:
    resolved = cost_ledger.path.resolve(strict=True)
    return hashlib.sha256(os.fsencode(resolved)).hexdigest()


def _load_campaign_entry(path: Path) -> CandidateBenchmarkCampaignEntry:
    raw = _read_private_file(path, maximum=_MAX_REPORT_BYTES)
    entry = _parse_model(raw, CandidateBenchmarkCampaignEntry)
    if raw != stable_json(entry).encode("utf-8"):
        raise ValueError("candidate campaign entry is not canonical")
    return entry


def _load_reasoning_campaign_entry(
    path: Path,
) -> CandidateReasoningProfileBenchmarkCampaignEntry:
    if re.fullmatch(_REASONING_CAMPAIGN_ENTRY_FILENAME_PATTERN, path.name) is None:
        raise ValueError("reasoning-profile campaign entry filename is invalid")
    raw = _read_private_file(path, maximum=_MAX_REPORT_BYTES)
    entry = _parse_model(raw, CandidateReasoningProfileBenchmarkCampaignEntry)
    if raw != stable_json(entry).encode("utf-8"):
        raise ValueError("reasoning-profile campaign entry is not canonical")
    return entry


def _require_private_directory(path: Path, *, label: str) -> None:
    _reject_linked_components(path)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ValueError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise ValueError(f"{label} must be a private regular directory")


def _atomic_write_private_bytes(path: Path, value: bytes, *, maximum: int) -> None:
    if path.exists() or path.is_symlink() or path.is_junction():
        raise ValueError("candidate campaign entry destination already exists")
    _require_private_directory(path.parent, label="candidate campaign journal")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed writing candidate campaign entry")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    published = False
    try:
        if path.exists() or path.is_symlink() or path.is_junction():
            raise ValueError("candidate campaign entry destination was reused")
        os.rename(temporary, path)
        published = True
        _fsync_directory(path.parent)
    finally:
        if not published:
            temporary.unlink(missing_ok=True)


def _canonical_decimal(value: Decimal) -> str:
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered if rendered not in {"", "-0"} else "0"


def _write_private_bytes(path: Path, value: bytes, *, maximum: int) -> None:
    if not value or len(value) > maximum:
        raise ValueError("model benchmark portfolio artifact bytes are invalid")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, _PRIVATE_FILE_MODE)
    try:
        os.fchmod(descriptor, _PRIVATE_FILE_MODE)
        view = memoryview(value)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("failed writing model benchmark portfolio artifact")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_file(path: Path, *, maximum: int) -> bytes:
    _reject_linked_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("model benchmark portfolio artifact is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != _PRIVATE_FILE_MODE
            or not 0 < metadata.st_size <= maximum
        ):
            raise ValueError(
                "model benchmark portfolio artifact must be private, bounded, and unshared"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_nlink,
            stat.S_IMODE(metadata.st_mode),
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_nlink,
            stat.S_IMODE(after.st_mode),
        )
        if len(raw) != metadata.st_size or identity != after_identity:
            raise ValueError("model benchmark portfolio artifact changed while being read")
        return raw
    finally:
        os.close(descriptor)


def _parse_model[ModelT: StrictModel](raw: bytes, model_type: type[ModelT]) -> ModelT:
    try:
        payload = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("model benchmark portfolio artifact is not strict JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("model benchmark portfolio artifact must contain one object")
    return model_type.model_validate(payload)


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_linked_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    for candidate in (absolute, *absolute.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("model benchmark portfolio path may not traverse links")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
