"""Provider-free custody for authenticated cross-lineage benchmark execution.

Durable models in this module are evidence only.  Runtime authority is retained in
opaque, PID-local capabilities whose live inputs are replayed on every use.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import weakref
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal, localcontext
from itertools import islice
from typing import Any, Literal, Never, SupportsIndex, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

import mmaudit.benchmark.cross_lineage_adjudication as _adjudication_module
import mmaudit.benchmark.model_portfolio as _model_portfolio_module
import mmaudit.benchmark.models as _benchmark_models_module
import mmaudit.models.generation_evidence as _generation_evidence_module
import mmaudit.models.ground_truth_authority as _ground_truth_module
import mmaudit.models.public_lineage_authority as _public_lineage_module
import mmaudit.models.usage as _usage_module
import mmaudit.orchestration.cost_ledger as _cost_ledger_module
import mmaudit.orchestration.manifest as _manifest_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    prepare_cross_lineage_adjudication,
)
from mmaudit.benchmark.model_portfolio import (
    ModelBenchmarkPortfolio,
    TrustedCandidateBenchmarkCampaignVerification,
)
from mmaudit.benchmark.models import ModelBenchmarkReport, ModelBenchmarkSuite
from mmaudit.models.generation_evidence import (
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    _has_authrunner_generation_origin,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruth,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.models.public_lineage_authority import (
    VerifiedIndependentPublicModelLineageProjection,
    VerifiedPublicModelLineage,
    require_independent_public_model_lineage,
)
from mmaudit.models.qualification import CandidateModel
from mmaudit.models.schemas import ExecutionEvidenceKind, StrictModel, UsageRecord
from mmaudit.models.usage import _has_authrunner_owned_real_usage_origin
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    CostEntry,
    CostEntryStatus,
    CostLedgerSnapshot,
)
from mmaudit.orchestration.manifest import canonical_sha256

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REQUEST_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DECIMAL_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_RUNNER_LEDGER_CAP_USD = Decimal("250")
_MAX_INTERVAL_REQUEST_IDS = 100_000
_MAX_CAMPAIGN_REPORTS = 128
_MAX_RUNS = 16
_MAX_CASES = 10_000
_MAX_ATTEMPTS_PER_REQUEST = 32


class AuthenticatedCrossLineageRunnerError(ValueError):
    """Authenticated runner evidence or live custody is invalid."""


class _StrictFrozenEvidence(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class OpenCrossLineageLedgerInterval:
    """Opaque PID-local start marker for one exact atomic-ledger interval."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> OpenCrossLineageLedgerInterval:
        del cls
        raise TypeError("open cross-lineage ledger interval cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("open cross-lineage ledger interval cannot be serialized")


class ClosedCrossLineageLedgerInterval:
    """Opaque PID-local proof of one exact reconciled append-only interval."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> ClosedCrossLineageLedgerInterval:
        del cls
        raise TypeError("closed cross-lineage ledger interval cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("closed cross-lineage ledger interval cannot be serialized")


class AuthenticatedCrossLineageLedgerEntryEvidence(_StrictFrozenEvidence):
    """Durable, non-authorizing binding for one known-cost interval entry."""

    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    reserved_usd: str | None = Field(
        default=None,
        pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$",
    )
    actual_cost_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

    @field_validator("reserved_usd", "actual_cost_usd")
    @classmethod
    def cost_is_canonical(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if _decimal_text(_parse_decimal(value, label="ledger entry cost")) != value:
            raise ValueError("ledger entry cost is not canonical")
        return value


class AuthenticatedCrossLineageLedgerIntervalEvidence(_StrictFrozenEvidence):
    """Durable evidence for a closed interval; it cannot recreate live custody."""

    ledger_identity_sha256: str = Field(pattern=_SHA256_PATTERN)
    initial_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    final_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    cap_usd: Literal["250"] = "250"
    initial_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    interval_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    final_spent_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
    entries: tuple[AuthenticatedCrossLineageLedgerEntryEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_INTERVAL_REQUEST_IDS,
    )

    @model_validator(mode="after")
    def interval_is_exact(self) -> AuthenticatedCrossLineageLedgerIntervalEvidence:
        request_ids = tuple(item.request_id for item in self.entries)
        if request_ids != tuple(sorted(set(request_ids))):
            raise ValueError("cross-lineage ledger entries must be unique and sorted")
        initial = _parse_decimal(self.initial_spent_usd, label="initial ledger spend")
        interval = _parse_decimal(self.interval_spent_usd, label="interval ledger spend")
        final = _parse_decimal(self.final_spent_usd, label="final ledger spend")
        if any(
            _decimal_text(value) != text
            for value, text in (
                (initial, self.initial_spent_usd),
                (interval, self.interval_spent_usd),
                (final, self.final_spent_usd),
            )
        ):
            raise ValueError("cross-lineage ledger spend is not canonical")
        with localcontext() as context:
            context.prec = 64
            entry_total = sum(
                (
                    _parse_decimal(item.actual_cost_usd, label="interval entry cost")
                    for item in self.entries
                ),
                start=Decimal(0),
            )
        if any(
            item.reserved_usd is not None
            and _parse_decimal(item.actual_cost_usd, label="ledger entry actual cost")
            > _parse_decimal(item.reserved_usd, label="ledger entry reserved cost")
            for item in self.entries
        ):
            raise ValueError("cross-lineage ledger actual cost exceeds its reservation")
        if interval != entry_total or final != initial + interval:
            raise ValueError("cross-lineage ledger interval spend is inconsistent")
        if final >= _RUNNER_LEDGER_CAP_USD:
            raise ValueError("cross-lineage ledger final spend must remain below 250 USD")
        return self


class AuthenticatedCrossLineageCaseExecutionEvidence(_StrictFrozenEvidence):
    """Exact non-secret identity and cost joins for one authenticated model response."""

    case_id: str = Field(pattern=r"^case-[0-9a-f]{16}$")
    request_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    attempt_count: int = Field(ge=1, le=_MAX_ATTEMPTS_PER_REQUEST)
    attempt_request_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_ATTEMPTS_PER_REQUEST,
    )
    generation_id: str = Field(min_length=1, max_length=500)
    request_body_sha256: str = Field(pattern=_SHA256_PATTERN)
    validated_response_sha256: str = Field(pattern=_SHA256_PATTERN)
    generation_attestation_sha256: str = Field(pattern=_SHA256_PATTERN)
    accounted_cost_usd: str = Field(pattern=r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")

    @model_validator(mode="after")
    def execution_identities_are_exact(self) -> AuthenticatedCrossLineageCaseExecutionEvidence:
        expected_attempts = tuple(
            self.request_id if index == 1 else f"{self.request_id}:attempt:{index}"
            for index in range(1, self.attempt_count + 1)
        )
        if self.attempt_request_ids != expected_attempts:
            raise ValueError("case attempt request IDs are inconsistent")
        accounted = _parse_decimal(self.accounted_cost_usd, label="case accounted cost")
        if _decimal_text(accounted) != self.accounted_cost_usd:
            raise ValueError("case accounted cost is not canonical")
        return self


class AuthenticatedCrossLineageRunnerRunEvidence(_StrictFrozenEvidence):
    """Durable non-authorizing joins for one candidate/judge execution pair."""

    run_kind: CrossLineageAdjudicationRunKind
    candidate_model_id: str = Field(min_length=3, max_length=300)
    candidate_root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    judge_model_id: str = Field(min_length=3, max_length=300)
    judge_root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    candidate_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_portfolio_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_campaign_report_sha256s: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_CAMPAIGN_REPORTS,
    )
    prepared_run_sha256: str = Field(pattern=_SHA256_PATTERN)
    adjudication_report_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_cases: tuple[AuthenticatedCrossLineageCaseExecutionEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_CASES,
    )
    judge_cases: tuple[AuthenticatedCrossLineageCaseExecutionEvidence, ...] = Field(
        min_length=1,
        max_length=_MAX_CASES,
    )

    @model_validator(mode="after")
    def run_has_exact_independent_case_coverage(self) -> AuthenticatedCrossLineageRunnerRunEvidence:
        if (
            self.candidate_model_id == self.judge_model_id
            or self.candidate_root_lineage == self.judge_root_lineage
        ):
            raise ValueError("authenticated runner evidence requires independent roots")
        campaign_hashes = self.candidate_campaign_report_sha256s
        if campaign_hashes != tuple(sorted(set(campaign_hashes))):
            raise ValueError("candidate campaign report hashes must be unique and sorted")
        if self.candidate_report_sha256 not in campaign_hashes:
            raise ValueError("candidate campaign omits the adjudicated candidate report")
        candidate_case_ids = tuple(item.case_id for item in self.candidate_cases)
        judge_case_ids = tuple(item.case_id for item in self.judge_cases)
        if (
            candidate_case_ids != tuple(sorted(set(candidate_case_ids)))
            or judge_case_ids != candidate_case_ids
        ):
            raise ValueError("candidate and judge cases require exact sorted coverage")
        return self


class AuthenticatedCrossLineageRunnerEvidence(_StrictFrozenEvidence):
    """Serializable runner evidence that deliberately grants no runtime authority."""

    schema_version: Literal["1.0"] = "1.0"
    objective_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_ground_truth_provenance_sha256: str = Field(pattern=_SHA256_PATTERN)
    frozen_source_revision: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_case_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    public_lineage_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    public_lineage_manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    case_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_CASES)
    runs: tuple[AuthenticatedCrossLineageRunnerRunEvidence, ...] = Field(
        min_length=2,
        max_length=_MAX_RUNS,
    )
    ledger_interval: AuthenticatedCrossLineageLedgerIntervalEvidence
    serialized_authority: Literal[False] = False
    lineage_identity_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    generation_verification_authorized: Literal[False] = False
    adjudication_credit_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    benchmark_authorized: Literal[False] = False
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "serialized_authority",
        "lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_custody_authorized",
        "generation_verification_authorized",
        "adjudication_credit_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "benchmark_authorized",
        mode="before",
    )
    @classmethod
    def durable_authority_is_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("durable authenticated runner authority must be literal false")
        return value

    @model_validator(mode="after")
    def exact_sets_and_hash_are_consistent(self) -> AuthenticatedCrossLineageRunnerEvidence:
        if self.case_ids != tuple(sorted(set(self.case_ids))):
            raise ValueError("authenticated runner case IDs must be unique and sorted")
        kinds = tuple(item.run_kind for item in self.runs)
        if (
            kinds.count(CrossLineageAdjudicationRunKind.PRIMARY) != 1
            or kinds.count(CrossLineageAdjudicationRunKind.REPLAY) != len(kinds) - 1
        ):
            raise ValueError("authenticated runner requires one PRIMARY and at least one REPLAY")
        expected_order = tuple(
            sorted(
                self.runs,
                key=lambda item: (
                    item.run_kind is CrossLineageAdjudicationRunKind.REPLAY,
                    item.judge_model_id,
                    item.adjudication_report_sha256,
                ),
            )
        )
        if self.runs != expected_order:
            raise ValueError("authenticated runner runs are not canonical")
        candidate_ids = {item.candidate_model_id for item in self.runs}
        candidate_roots = {item.candidate_root_lineage for item in self.runs}
        judge_ids = tuple(item.judge_model_id for item in self.runs)
        judge_roots = tuple(item.judge_root_lineage for item in self.runs)
        if (
            len(candidate_ids) != 1
            or len(candidate_roots) != 1
            or len(set(judge_ids)) != len(judge_ids)
            or len(set(judge_roots)) != len(judge_roots)
            or any(
                tuple(case.case_id for case in item.candidate_cases) != self.case_ids
                for item in self.runs
            )
        ):
            raise ValueError("authenticated runner model roots or case coverage are inconsistent")
        all_cases = tuple(
            case
            for item in self.runs
            for cases in (item.candidate_cases, item.judge_cases)
            for case in cases
        )
        for identities, label in (
            ((item.request_id for item in all_cases), "request IDs"),
            ((item.generation_id for item in all_cases), "generation IDs"),
            ((item.request_body_sha256 for item in all_cases), "request-body hashes"),
        ):
            values = tuple(identities)
            if len(values) != len(set(values)):
                raise ValueError(f"authenticated runner reuses {label}")
        expected_hash = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected_hash:
            raise ValueError("authenticated runner evidence hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class CrossLineageRunnerRunCustody:
    """Live capabilities and durable reports retained for one exact runner pass."""

    run_kind: CrossLineageAdjudicationRunKind
    candidate_report: ModelBenchmarkReport
    candidate_campaign_verification: TrustedCandidateBenchmarkCampaignVerification
    candidate_portfolio: ModelBenchmarkPortfolio
    candidate_campaign_reports: tuple[ModelBenchmarkReport, ...]
    candidate_campaign_policy_sha256: str
    candidate_campaign_effective_config_sha256: str
    candidate_generation_verification: TrustedGenerationVerification
    judge: CandidateModel
    prepared_adjudication: CrossLineageAdjudicationPreparedRun
    adjudication_report: CrossLineageAdjudicationReport
    judge_generation_verification: TrustedGenerationVerification


@dataclass(frozen=True, slots=True)
class VerifiedCrossLineageRunnerRunProjection:
    """Fresh identity-only projection for one reverified runner pass."""

    run_kind: CrossLineageAdjudicationRunKind
    candidate_model_id: str
    candidate_root_lineage: str
    judge_model_id: str
    judge_root_lineage: str
    candidate_report_sha256: str
    candidate_portfolio_sha256: str
    prepared_run_sha256: str
    adjudication_report_sha256: str
    case_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedCrossLineageRunnerProjection:
    """Fresh PID-local projection after every retained authority has replayed."""

    evidence_sha256: str
    objective_sha256: str
    frozen_ground_truth_provenance_sha256: str
    frozen_source_revision: str
    benchmark_corpus_sha256: str
    benchmark_ground_truth_sha256: str
    ground_truth_case_binding_set_sha256: str
    public_lineage_bundle_sha256: str
    public_lineage_manifest_file_sha256: str
    ledger_initial_snapshot_sha256: str
    ledger_final_snapshot_sha256: str
    ledger_final_spent_usd: str
    ledger_request_ids: tuple[str, ...]
    runs: tuple[VerifiedCrossLineageRunnerRunProjection, ...]
    serialized_authority: Literal[False]
    lineage_identity_authorized: Literal[False]
    runner_custody_authorized: Literal[True]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    generation_verification_authorized: Literal[False]
    adjudication_credit_authorized: Literal[False]
    model_qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    benchmark_authorized: Literal[False]


class VerifiedCrossLineageRunnerCustody:
    """Opaque non-serializable PID-local authenticated runner custody."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedCrossLineageRunnerCustody:
        del cls
        raise TypeError("verified cross-lineage runner custody cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified cross-lineage runner custody cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified cross-lineage runner custody cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified cross-lineage runner custody cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified cross-lineage runner custody cannot be serialized")


@dataclass(frozen=True, slots=True)
class _PidLocalLeaseSnapshot[LeaseStateT]:
    """Exact hidden registry entry observed before a potentially long replay."""

    process_id: int
    state: LeaseStateT
    nonce: object


class _PidLocalOneWayLeaseRegistry[LeaseCapabilityT, LeaseStateT]:
    """One-way PID-local lease storage that never creates an authority object."""

    __slots__ = ("_capability_type", "_entries", "_getpid", "_lock")

    def __init__(
        self,
        *,
        capability_type: type[LeaseCapabilityT],
        getpid: Callable[[], int],
    ) -> None:
        self._capability_type = capability_type
        self._getpid = getpid
        self._entries: dict[
            int,
            tuple[
                weakref.ReferenceType[LeaseCapabilityT],
                int,
                LeaseStateT,
                object,
            ],
        ] = {}
        self._lock = threading.RLock()

    def register(self, capability: LeaseCapabilityT, state: LeaseStateT) -> None:
        """Register one exact newly issued capability in the current PID."""

        if type(capability) is not self._capability_type:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent, mismatched, or revoked"
            )
        key = id(capability)

        def discard(reference: weakref.ReferenceType[LeaseCapabilityT]) -> None:
            with self._lock:
                current = self._entries.get(key)
                if current is not None and current[0] is reference:
                    self._entries.pop(key, None)

        try:
            reference = weakref.ref(capability, discard)
        except TypeError:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent, mismatched, or revoked"
            ) from None
        entry = (reference, self._getpid(), state, object())
        with self._lock:
            current = self._entries.get(key)
            if current is not None and current[0]() is capability:
                raise AuthenticatedCrossLineageRunnerError(
                    "verified cross-lineage runner custody is already registered"
                )
            self._entries[key] = entry

    def snapshot(
        self,
        capability: LeaseCapabilityT,
    ) -> _PidLocalLeaseSnapshot[LeaseStateT]:
        """Return the exact current lease entry or reject absent and forked custody."""

        if type(capability) is not self._capability_type:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent, mismatched, or revoked"
            )
        with self._lock:
            entry = self._entries.get(id(capability))
        if entry is None or entry[0]() is not capability:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent, mismatched, or revoked"
            )
        if entry[1] != self._getpid():
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody belongs to another process"
            )
        return _PidLocalLeaseSnapshot(
            process_id=entry[1],
            state=entry[2],
            nonce=entry[3],
        )

    def recheck(
        self,
        capability: LeaseCapabilityT,
        snapshot: _PidLocalLeaseSnapshot[LeaseStateT],
    ) -> None:
        """Reject a lease removed or replaced while its retained evidence replayed."""

        if type(capability) is not self._capability_type:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody changed or was revoked during replay"
            )
        with self._lock:
            entry = self._entries.get(id(capability))
        if (
            type(snapshot) is not _PidLocalLeaseSnapshot
            or entry is None
            or entry[0]() is not capability
            or entry[1] != self._getpid()
            or entry[1] != snapshot.process_id
            or entry[2] is not snapshot.state
            or entry[3] is not snapshot.nonce
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody changed or was revoked during replay"
            )

    def revoke(self, capability: LeaseCapabilityT) -> None:
        """Remove one exact current-PID lease permanently and return no evidence."""

        if type(capability) is not self._capability_type:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent, mismatched, or revoked"
            )
        key = id(capability)
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry[0]() is not capability:
                raise AuthenticatedCrossLineageRunnerError(
                    "verified cross-lineage runner custody is absent, mismatched, or revoked"
                )
            if entry[1] != self._getpid():
                raise AuthenticatedCrossLineageRunnerError(
                    "verified cross-lineage runner custody belongs to another process"
                )
            removed = self._entries.pop(key)
        if removed is not entry:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody changed during revocation"
            )


@dataclass(frozen=True, slots=True)
class _ClosedLedgerIntervalView:
    capability: ClosedCrossLineageLedgerInterval
    ledger: AtomicCostLedger
    ledger_identity_sha256: str
    initial_snapshot: CostLedgerSnapshot
    final_snapshot: CostLedgerSnapshot
    new_entries: tuple[CostEntry, ...]
    evidence: AuthenticatedCrossLineageLedgerIntervalEvidence


def _parse_decimal(value: str, *, label: str) -> Decimal:
    if type(value) is not str or _DECIMAL_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    parsed = Decimal(value)
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{label} is invalid")
    return parsed


def _decimal_text(value: Decimal) -> str:
    if type(value) is not Decimal or not value.is_finite() or value < 0:
        raise ValueError("money value is invalid")
    if value == 0:
        return "0"
    rendered = format(value, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


def _entry_material(entry: CostEntry) -> dict[str, object]:
    return {
        "request_id": entry.request_id,
        "reservation_id": entry.reservation_id,
        "status": entry.status.value,
        "reserved_usd": _decimal_text(entry.reserved_usd),
        "actual_cost_usd": (
            None if entry.actual_cost_usd is None else _decimal_text(entry.actual_cost_usd)
        ),
        "accounted_cost_usd": _decimal_text(entry.accounted_cost_usd),
        "release_reason": None if entry.release_reason is None else entry.release_reason.value,
        "created_at": entry.created_at.isoformat(),
        "updated_at": entry.updated_at.isoformat(),
    }


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _entry_sha256(entry: CostEntry) -> str:
    return _canonical_sha256(_entry_material(entry))


def _snapshot_sha256(snapshot: CostLedgerSnapshot) -> str:
    return _canonical_sha256(
        {
            "cap_usd": _decimal_text(snapshot.cap_usd),
            "spent_usd": _decimal_text(snapshot.spent_usd),
            "active_reserved_usd": _decimal_text(snapshot.active_reserved_usd),
            "entries": [_entry_material(item) for item in snapshot.entries],
        }
    )


def _build_cross_lineage_ledger_interval_authority() -> tuple[
    Callable[[AtomicCostLedger], OpenCrossLineageLedgerInterval],
    Callable[..., ClosedCrossLineageLedgerInterval],
    Callable[[ClosedCrossLineageLedgerInterval], _ClosedLedgerIntervalView],
    Callable[[ClosedCrossLineageLedgerInterval], _ClosedLedgerIntervalView],
    Callable[[], None],
]:
    """Build hidden registries for exact process-local ledger interval custody."""

    @dataclass(frozen=True, slots=True)
    class OpenState:
        process_id: int
        ledger: AtomicCostLedger
        ledger_identity_sha256: str
        initial_snapshot: CostLedgerSnapshot

    @dataclass(slots=True)
    class ClosedState:
        process_id: int
        view: _ClosedLedgerIntervalView
        claimed: bool = False

    open_registry: weakref.WeakKeyDictionary[OpenCrossLineageLedgerInterval, OpenState] = (
        weakref.WeakKeyDictionary()
    )
    closed_registry: weakref.WeakKeyDictionary[ClosedCrossLineageLedgerInterval, ClosedState] = (
        weakref.WeakKeyDictionary()
    )
    lock = threading.RLock()
    namespace = globals()
    trusted_self_module = sys.modules[__name__]
    trusted_cost_ledger_module = _cost_ledger_module
    trusted_sys_module = sys
    trusted_os_module = os
    trusted_json_module = json
    trusted_hashlib_module = hashlib
    trusted_getpid = os.getpid
    trusted_os_functions = {
        name: getattr(os, name) for name in ("close", "fdopen", "fstat", "geteuid", "open")
    }
    trusted_json_dumps = json.dumps
    trusted_json_load = json.load
    trusted_sha256 = hashlib.sha256
    trusted_snapshot = AtomicCostLedger.snapshot
    trusted_identity_getter = cast(property, AtomicCostLedger.identity_sha256).fget
    assert trusted_identity_getter is not None
    trusted_cost_ledger_callables = {
        name: getattr(trusted_cost_ledger_module, name)
        for name in (
            "_open_lock_file",
            "_open_regular_private_file",
            "_require_exact_lock_path",
            "_snapshot",
            "_unique_object",
            "_validate_state",
        )
    }

    def ledger_descriptor_surface() -> tuple[tuple[str, object], ...]:
        return tuple(
            sorted(
                (
                    (name, descriptor)
                    for name, descriptor in vars(AtomicCostLedger).items()
                    if callable(descriptor)
                    or isinstance(descriptor, (classmethod, staticmethod, property))
                ),
                key=lambda item: item[0],
            )
        )

    trusted_ledger_descriptor_surface = ledger_descriptor_surface()
    trusted_objects = {
        "AtomicCostLedger": AtomicCostLedger,
        "CostEntry": CostEntry,
        "CostEntryStatus": CostEntryStatus,
        "CostLedgerSnapshot": CostLedgerSnapshot,
        "OpenCrossLineageLedgerInterval": OpenCrossLineageLedgerInterval,
        "ClosedCrossLineageLedgerInterval": ClosedCrossLineageLedgerInterval,
        "AuthenticatedCrossLineageLedgerEntryEvidence": (
            AuthenticatedCrossLineageLedgerEntryEvidence
        ),
        "AuthenticatedCrossLineageLedgerIntervalEvidence": (
            AuthenticatedCrossLineageLedgerIntervalEvidence
        ),
        "_canonical_sha256": _canonical_sha256,
        "_decimal_text": _decimal_text,
        "_entry_material": _entry_material,
        "_entry_sha256": _entry_sha256,
        "_snapshot_sha256": _snapshot_sha256,
    }
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        if (
            namespace.get("sys") is not trusted_sys_module
            or namespace.get("os") is not trusted_os_module
            or namespace.get("json") is not trusted_json_module
            or namespace.get("hashlib") is not trusted_hashlib_module
            or namespace.get("_cost_ledger_module") is not trusted_cost_ledger_module
            or trusted_sys_module.modules.get(__name__) is not trusted_self_module
            or trusted_sys_module.modules.get(trusted_cost_ledger_module.__name__)
            is not trusted_cost_ledger_module
            or any(namespace.get(name) is not value for name, value in trusted_objects.items())
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
            or trusted_cost_ledger_module.AtomicCostLedger is not AtomicCostLedger
            or trusted_cost_ledger_module.CostEntry is not CostEntry
            or trusted_cost_ledger_module.CostEntryStatus is not CostEntryStatus
            or trusted_cost_ledger_module.CostLedgerSnapshot is not CostLedgerSnapshot
            or any(
                getattr(trusted_cost_ledger_module, name) is not value
                for name, value in trusted_cost_ledger_callables.items()
            )
            or ledger_descriptor_surface() != trusted_ledger_descriptor_surface
            or AtomicCostLedger.snapshot is not trusted_snapshot
            or cast(property, AtomicCostLedger.identity_sha256).fget is not trusted_identity_getter
            or os.getpid is not trusted_getpid
            or any(getattr(os, name) is not value for name, value in trusted_os_functions.items())
            or json.dumps is not trusted_json_dumps
            or json.load is not trusted_json_load
            or hashlib.sha256 is not trusted_sha256
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner ledger verifier runtime is not pristine"
            )

    def require_clean_snapshot(snapshot: CostLedgerSnapshot, *, final: bool) -> None:
        if (
            type(snapshot) is not CostLedgerSnapshot
            or snapshot.cap_usd != _RUNNER_LEDGER_CAP_USD
            or snapshot.active_reserved_usd != 0
            or snapshot.over_cap
            or snapshot.has_reservation_overrun
            or any(
                item.status
                in {
                    CostEntryStatus.RESERVED,
                    CostEntryStatus.RESERVATION_OVERRUN,
                }
                for item in snapshot.entries
            )
            or (final and snapshot.spent_usd >= _RUNNER_LEDGER_CAP_USD)
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger is not a terminal non-overrun 250 USD ledger"
            )

    def current_view(state: ClosedState) -> _ClosedLedgerIntervalView:
        if state.process_id != trusted_getpid():
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval belongs to another process"
            )
        view = state.view
        if (
            type(view.ledger) is not AtomicCostLedger
            or trusted_identity_getter(view.ledger) != view.ledger_identity_sha256
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger identity changed"
            )
        current = trusted_snapshot(view.ledger)
        require_clean_snapshot(current, final=True)
        if current != view.final_snapshot:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger changed after closure"
            )
        return view

    def begin(ledger: AtomicCostLedger) -> OpenCrossLineageLedgerInterval:
        require_pristine()
        if type(ledger) is not AtomicCostLedger:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval requires the exact atomic ledger type"
            )
        identity = trusted_identity_getter(ledger)
        initial = trusted_snapshot(ledger)
        require_clean_snapshot(initial, final=False)
        capability = object.__new__(OpenCrossLineageLedgerInterval)
        with lock:
            open_registry[capability] = OpenState(
                process_id=trusted_getpid(),
                ledger=ledger,
                ledger_identity_sha256=identity,
                initial_snapshot=initial,
            )
        require_pristine()
        return capability

    def close(
        interval: OpenCrossLineageLedgerInterval,
        *,
        expected_request_ids: Iterable[str],
    ) -> ClosedCrossLineageLedgerInterval:
        require_pristine()
        if type(interval) is not OpenCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "open cross-lineage ledger interval authority is absent"
            )
        bounded = tuple(islice(iter(expected_request_ids), _MAX_INTERVAL_REQUEST_IDS + 1))
        require_pristine()
        if not bounded or len(bounded) > _MAX_INTERVAL_REQUEST_IDS:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request set is empty or exceeds its bound"
            )
        if any(
            type(item) is not str or _REQUEST_ID_PATTERN.fullmatch(item) is None for item in bounded
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request ID is invalid"
            )
        expected = tuple(sorted(bounded))
        if len(expected) != len(set(expected)):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger expected request IDs are not unique"
            )
        with lock:
            state = open_registry.get(interval)
        if state is None or state.process_id != trusted_getpid():
            raise AuthenticatedCrossLineageRunnerError(
                "open cross-lineage ledger interval authority is absent"
            )
        ledger = state.ledger
        if trusted_identity_getter(ledger) != state.ledger_identity_sha256:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger identity changed during the interval"
            )
        final = trusted_snapshot(ledger)
        require_clean_snapshot(final, final=True)
        initial_by_id = {item.request_id: item for item in state.initial_snapshot.entries}
        final_by_id = {item.request_id: item for item in final.entries}
        if any(final_by_id.get(request_id) != entry for request_id, entry in initial_by_id.items()):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger changed an entry that preceded the interval"
            )
        new_request_ids = tuple(sorted(set(final_by_id) - set(initial_by_id)))
        if new_request_ids != expected:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval differs from the exact expected request set"
            )
        new_entries = tuple(final_by_id[item] for item in new_request_ids)
        if any(
            item.status is not CostEntryStatus.RECONCILED
            or item.actual_cost_usd is None
            or item.accounted_cost_usd != item.actual_cost_usd
            or item.actual_cost_usd > item.reserved_usd
            for item in new_entries
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval contains non-reconciled or unknown cost"
            )
        with localcontext() as context:
            context.prec = 64
            interval_spent = final.spent_usd - state.initial_snapshot.spent_usd
            entry_spent = sum(
                (cast(Decimal, item.actual_cost_usd) for item in new_entries),
                start=Decimal(0),
            )
        if interval_spent < 0 or interval_spent != entry_spent:
            raise AuthenticatedCrossLineageRunnerError(
                "cross-lineage ledger interval spend is inconsistent"
            )
        entry_evidence = tuple(
            AuthenticatedCrossLineageLedgerEntryEvidence(
                request_id=item.request_id,
                entry_sha256=_entry_sha256(item),
                reserved_usd=_decimal_text(item.reserved_usd),
                actual_cost_usd=_decimal_text(cast(Decimal, item.actual_cost_usd)),
            )
            for item in new_entries
        )
        evidence = AuthenticatedCrossLineageLedgerIntervalEvidence(
            ledger_identity_sha256=state.ledger_identity_sha256,
            initial_snapshot_sha256=_snapshot_sha256(state.initial_snapshot),
            final_snapshot_sha256=_snapshot_sha256(final),
            cap_usd="250",
            initial_spent_usd=_decimal_text(state.initial_snapshot.spent_usd),
            interval_spent_usd=_decimal_text(interval_spent),
            final_spent_usd=_decimal_text(final.spent_usd),
            entries=entry_evidence,
        )
        capability = object.__new__(ClosedCrossLineageLedgerInterval)
        view = _ClosedLedgerIntervalView(
            capability=capability,
            ledger=ledger,
            ledger_identity_sha256=state.ledger_identity_sha256,
            initial_snapshot=state.initial_snapshot,
            final_snapshot=final,
            new_entries=new_entries,
            evidence=evidence,
        )
        with lock:
            current = open_registry.get(interval)
            if current is not state:
                raise AuthenticatedCrossLineageRunnerError(
                    "open cross-lineage ledger interval changed during closure"
                )
            del open_registry[interval]
            closed_registry[capability] = ClosedState(
                process_id=trusted_getpid(),
                view=view,
            )
        require_pristine()
        return capability

    def require_closed(
        capability: ClosedCrossLineageLedgerInterval,
    ) -> _ClosedLedgerIntervalView:
        require_pristine()
        if type(capability) is not ClosedCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        with lock:
            state = closed_registry.get(capability)
        if state is None:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        result = current_view(state)
        require_pristine()
        return result

    def claim_closed(
        capability: ClosedCrossLineageLedgerInterval,
    ) -> _ClosedLedgerIntervalView:
        require_pristine()
        if type(capability) is not ClosedCrossLineageLedgerInterval:
            raise AuthenticatedCrossLineageRunnerError(
                "closed cross-lineage ledger interval authority is absent"
            )
        with lock:
            state = closed_registry.get(capability)
            if state is None:
                raise AuthenticatedCrossLineageRunnerError(
                    "closed cross-lineage ledger interval authority is absent"
                )
            if state.claimed:
                raise AuthenticatedCrossLineageRunnerError(
                    "closed cross-lineage ledger interval was already claimed"
                )
            result = current_view(state)
            state.claimed = True
        require_pristine()
        return result

    public_bindings.update(
        {
            "begin_cross_lineage_ledger_interval": begin,
            "close_cross_lineage_ledger_interval": close,
        }
    )
    return begin, close, require_closed, claim_closed, require_pristine


(
    begin_cross_lineage_ledger_interval,
    close_cross_lineage_ledger_interval,
    _require_closed_cross_lineage_ledger_interval,
    _claim_closed_cross_lineage_ledger_interval,
    _require_pristine_cross_lineage_ledger_runtime,
) = _build_cross_lineage_ledger_interval_authority()
del _build_cross_lineage_ledger_interval_authority


def _build_authenticated_cross_lineage_runner_authority() -> tuple[
    Callable[
        ...,
        tuple[VerifiedCrossLineageRunnerCustody, AuthenticatedCrossLineageRunnerEvidence],
    ],
    Callable[..., VerifiedCrossLineageRunnerProjection],
    Callable[[VerifiedCrossLineageRunnerCustody], None],
]:
    """Capture every live verifier and retain custody outside durable evidence."""

    @dataclass(frozen=True, slots=True)
    class RunnerState:
        process_id: int
        public_lineage_capability: VerifiedPublicModelLineage
        ground_truth_capability: VerifiedFrozenGroundTruth
        benchmark_suite: ModelBenchmarkSuite
        runs: tuple[CrossLineageRunnerRunCustody, ...]
        closed_ledger_interval: ClosedCrossLineageLedgerInterval
        evidence: AuthenticatedCrossLineageRunnerEvidence

    namespace = globals()
    trusted_self_module = sys.modules[__name__]
    trusted_sys_module = sys
    trusted_adjudication_module = _adjudication_module
    trusted_model_portfolio_module = _model_portfolio_module
    trusted_benchmark_models_module = _benchmark_models_module
    trusted_generation_evidence_module = _generation_evidence_module
    trusted_ground_truth_module = _ground_truth_module
    trusted_public_lineage_module = _public_lineage_module
    trusted_usage_module = _usage_module
    trusted_manifest_module = _manifest_module
    trusted_modules = {
        "_adjudication_module": trusted_adjudication_module,
        "_model_portfolio_module": trusted_model_portfolio_module,
        "_benchmark_models_module": trusted_benchmark_models_module,
        "_generation_evidence_module": trusted_generation_evidence_module,
        "_ground_truth_module": trusted_ground_truth_module,
        "_public_lineage_module": trusted_public_lineage_module,
        "_usage_module": trusted_usage_module,
        "_manifest_module": trusted_manifest_module,
    }
    trusted_getpid = os.getpid
    registry: _PidLocalOneWayLeaseRegistry[
        VerifiedCrossLineageRunnerCustody,
        RunnerState,
    ] = _PidLocalOneWayLeaseRegistry(
        capability_type=VerifiedCrossLineageRunnerCustody,
        getpid=trusted_getpid,
    )
    trusted_lease_register = _PidLocalOneWayLeaseRegistry.register
    trusted_lease_snapshot = _PidLocalOneWayLeaseRegistry.snapshot
    trusted_lease_recheck = _PidLocalOneWayLeaseRegistry.recheck
    trusted_lease_revoke = _PidLocalOneWayLeaseRegistry.revoke
    trusted_model_dump = BaseModel.model_dump
    trusted_dump_json = BaseModel.model_dump_json
    trusted_model_construct = cast(Any, BaseModel.model_construct).__func__
    trusted_validate_json = cast(Any, BaseModel.model_validate_json).__func__
    trusted_require_ledger = _require_closed_cross_lineage_ledger_interval
    trusted_claim_ledger = _claim_closed_cross_lineage_ledger_interval
    trusted_ledger_pristine = _require_pristine_cross_lineage_ledger_runtime
    trusted_require_independent = require_independent_public_model_lineage
    trusted_prepare_adjudication = prepare_cross_lineage_adjudication
    trusted_case_result_getattribute = CrossLineageAdjudicationCaseResult.__getattribute__
    trusted_ground_require = VerifiedFrozenGroundTruth.require_for
    trusted_campaign_require = TrustedCandidateBenchmarkCampaignVerification.require_for
    trusted_generation_attestation = TrustedGenerationVerification.attestation_for
    trusted_generation_origin = _has_authrunner_generation_origin
    trusted_usage_origin = _has_authrunner_owned_real_usage_origin
    trusted_types = {
        "BaseModel": BaseModel,
        "AuthenticatedCrossLineageRunnerError": AuthenticatedCrossLineageRunnerError,
        "AuthenticatedCrossLineageRunnerEvidence": AuthenticatedCrossLineageRunnerEvidence,
        "CrossLineageRunnerRunCustody": CrossLineageRunnerRunCustody,
        "_PidLocalLeaseSnapshot": _PidLocalLeaseSnapshot,
        "_PidLocalOneWayLeaseRegistry": _PidLocalOneWayLeaseRegistry,
        "VerifiedCrossLineageRunnerCustody": VerifiedCrossLineageRunnerCustody,
        "VerifiedCrossLineageRunnerProjection": VerifiedCrossLineageRunnerProjection,
        "VerifiedCrossLineageRunnerRunProjection": VerifiedCrossLineageRunnerRunProjection,
        "VerifiedPublicModelLineage": VerifiedPublicModelLineage,
        "VerifiedIndependentPublicModelLineageProjection": (
            VerifiedIndependentPublicModelLineageProjection
        ),
        "VerifiedFrozenGroundTruth": VerifiedFrozenGroundTruth,
        "VerifiedFrozenGroundTruthProjection": VerifiedFrozenGroundTruthProjection,
        "ModelBenchmarkSuite": ModelBenchmarkSuite,
        "ModelBenchmarkReport": ModelBenchmarkReport,
        "ModelBenchmarkPortfolio": ModelBenchmarkPortfolio,
        "CandidateModel": CandidateModel,
        "CrossLineageAdjudicationCaseResult": CrossLineageAdjudicationCaseResult,
        "CrossLineageAdjudicationPreparedRun": CrossLineageAdjudicationPreparedRun,
        "CrossLineageAdjudicationReport": CrossLineageAdjudicationReport,
        "CrossLineageAdjudicationRunKind": CrossLineageAdjudicationRunKind,
        "TrustedCandidateBenchmarkCampaignVerification": (
            TrustedCandidateBenchmarkCampaignVerification
        ),
        "TrustedGenerationVerification": TrustedGenerationVerification,
        "OpenRouterGenerationEvidence": OpenRouterGenerationEvidence,
        "UsageRecord": UsageRecord,
        "ExecutionEvidenceKind": ExecutionEvidenceKind,
    }
    trusted_functions = {
        "require_independent_public_model_lineage": trusted_require_independent,
        "prepare_cross_lineage_adjudication": trusted_prepare_adjudication,
        "canonical_sha256": canonical_sha256,
        "_require_closed_cross_lineage_ledger_interval": trusted_require_ledger,
        "_claim_closed_cross_lineage_ledger_interval": trusted_claim_ledger,
        "_require_pristine_cross_lineage_ledger_runtime": trusted_ledger_pristine,
        "_has_authrunner_generation_origin": trusted_generation_origin,
        "_has_authrunner_owned_real_usage_origin": trusted_usage_origin,
    }
    trusted_adjudication_callables = {
        name: getattr(trusted_adjudication_module, name)
        for name in (
            "_case_result_hash_payload",
            "_reconcile_generation_evidence_structural",
            "_report_hash_payload",
            "_usage_output_mode",
            "_usage_record_sha256",
            "canonical_sha256",
            "cross_lineage_adjudication_validated_response_sha256",
            "structured_output_prompt_sha256",
        )
    }
    trusted_campaign_callables = {
        name: getattr(trusted_model_portfolio_module, name)
        for name in (
            "_report_content_bindings",
            "_require_trusted_campaign_capability",
            "_require_trusted_campaign_capability_positional",
            "canonical_sha256",
        )
    }
    trusted_benchmark_callables = {
        name: getattr(trusted_benchmark_models_module, name)
        for name in (
            "_case_execution_evidence",
            "_dimension_scores",
            "_is_structurally_creditable_usage_record",
            "_model_execution_evidence",
            "_validated_response_sha256",
            "canonical_sha256",
        )
    }
    trusted_generation_callables = {
        name: getattr(trusted_generation_evidence_module, name)
        for name in (
            "_reconcile_generation_evidence_structural",
            "_trusted_generation_binding_for",
            "_usage_record_sha256",
            "_validated_usage_copy_preserving_owned_attestation",
            "_has_authrunner_generation_origin",
        )
    }
    trusted_usage_callables = {
        "_has_authrunner_owned_real_usage_origin": trusted_usage_origin,
    }
    trusted_ground_callable = trusted_ground_truth_module._require_verified_frozen_ground_truth
    trusted_manifest_json = cast(Any, trusted_manifest_module).json
    trusted_manifest_hashlib = cast(Any, trusted_manifest_module).hashlib
    trusted_benchmark_hashlib = cast(Any, trusted_benchmark_models_module).hashlib
    public_bindings: dict[str, object] = {}

    def require_pristine() -> None:
        trusted_ledger_pristine()
        if (
            namespace.get("sys") is not trusted_sys_module
            or any(namespace.get(name) is not module for name, module in trusted_modules.items())
            or trusted_sys_module.modules.get(__name__) is not trusted_self_module
            or any(
                trusted_sys_module.modules.get(module.__name__) is not module
                for module in trusted_modules.values()
            )
            or any(namespace.get(name) is not value for name, value in trusted_types.items())
            or any(namespace.get(name) is not value for name, value in trusted_functions.items())
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
            or _PidLocalOneWayLeaseRegistry.register is not trusted_lease_register
            or _PidLocalOneWayLeaseRegistry.snapshot is not trusted_lease_snapshot
            or _PidLocalOneWayLeaseRegistry.recheck is not trusted_lease_recheck
            or _PidLocalOneWayLeaseRegistry.revoke is not trusted_lease_revoke
            or trusted_public_lineage_module.VerifiedPublicModelLineage
            is not VerifiedPublicModelLineage
            or trusted_public_lineage_module.VerifiedIndependentPublicModelLineageProjection
            is not VerifiedIndependentPublicModelLineageProjection
            or trusted_public_lineage_module.require_independent_public_model_lineage
            is not trusted_require_independent
            or trusted_ground_truth_module.VerifiedFrozenGroundTruth
            is not VerifiedFrozenGroundTruth
            or VerifiedFrozenGroundTruth.require_for is not trusted_ground_require
            or trusted_ground_truth_module._require_verified_frozen_ground_truth
            is not trusted_ground_callable
            or trusted_model_portfolio_module.TrustedCandidateBenchmarkCampaignVerification
            is not TrustedCandidateBenchmarkCampaignVerification
            or TrustedCandidateBenchmarkCampaignVerification.require_for
            is not trusted_campaign_require
            or trusted_generation_evidence_module.TrustedGenerationVerification
            is not TrustedGenerationVerification
            or TrustedGenerationVerification.attestation_for is not trusted_generation_attestation
            or trusted_adjudication_module.CrossLineageAdjudicationReport
            is not CrossLineageAdjudicationReport
            or trusted_adjudication_module.CrossLineageAdjudicationCaseResult
            is not CrossLineageAdjudicationCaseResult
            or CrossLineageAdjudicationCaseResult.__getattribute__
            is not trusted_case_result_getattribute
            or trusted_adjudication_module.CrossLineageAdjudicationPreparedRun
            is not CrossLineageAdjudicationPreparedRun
            or trusted_adjudication_module.CrossLineageAdjudicationRunKind
            is not CrossLineageAdjudicationRunKind
            or trusted_adjudication_module.prepare_cross_lineage_adjudication
            is not trusted_prepare_adjudication
            or trusted_benchmark_models_module.ModelBenchmarkReport is not ModelBenchmarkReport
            or trusted_benchmark_models_module.ModelBenchmarkSuite is not ModelBenchmarkSuite
            or trusted_model_portfolio_module.ModelBenchmarkPortfolio is not ModelBenchmarkPortfolio
            or trusted_generation_evidence_module.OpenRouterGenerationEvidence
            is not OpenRouterGenerationEvidence
            or trusted_manifest_module.canonical_sha256 is not canonical_sha256
            or cast(Any, trusted_manifest_module).json is not trusted_manifest_json
            or trusted_manifest_json is not json
            or cast(Any, trusted_manifest_module).hashlib is not trusted_manifest_hashlib
            or trusted_manifest_hashlib is not hashlib
            or cast(Any, trusted_benchmark_models_module).hashlib is not trusted_benchmark_hashlib
            or trusted_benchmark_hashlib is not hashlib
            or any(
                getattr(trusted_adjudication_module, name) is not value
                for name, value in trusted_adjudication_callables.items()
            )
            or any(
                getattr(trusted_model_portfolio_module, name) is not value
                for name, value in trusted_campaign_callables.items()
            )
            or any(
                getattr(trusted_benchmark_models_module, name) is not value
                for name, value in trusted_benchmark_callables.items()
            )
            or any(
                getattr(trusted_generation_evidence_module, name) is not value
                for name, value in trusted_generation_callables.items()
            )
            or any(
                getattr(trusted_usage_module, name) is not value
                for name, value in trusted_usage_callables.items()
            )
            or os.getpid is not trusted_getpid
            or BaseModel.model_dump is not trusted_model_dump
            or BaseModel.model_dump_json is not trusted_dump_json
            or cast(Any, BaseModel.model_construct).__func__ is not trusted_model_construct
            or cast(Any, BaseModel.model_validate_json).__func__ is not trusted_validate_json
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated cross-lineage runner verifier runtime is not pristine"
            )

    def validated_model[T: BaseModel](value: object, expected_type: type[T], *, label: str) -> T:
        if type(value) is not expected_type:
            raise AuthenticatedCrossLineageRunnerError(f"{label} has the wrong exact type")
        try:
            raw = trusted_dump_json(cast(BaseModel, value))
            # These models are already strict.  Pydantic's JSON mode must still decode
            # canonical RFC 3339 datetimes before strict field validation runs.
            result = trusted_validate_json(expected_type, raw)
        except (TypeError, ValueError, ValidationError):
            raise AuthenticatedCrossLineageRunnerError(f"{label} is structurally invalid") from None
        if result != value:
            raise AuthenticatedCrossLineageRunnerError(f"{label} changed during validation")
        return cast(T, result)

    def bounded_campaign_reports(
        value: object,
    ) -> tuple[ModelBenchmarkReport, ...]:
        if type(value) is not tuple:
            raise AuthenticatedCrossLineageRunnerError(
                "candidate campaign reports must be an exact tuple"
            )
        reports = tuple(islice(cast(tuple[object, ...], value), _MAX_CAMPAIGN_REPORTS + 1))
        require_pristine()
        if not reports or len(reports) > _MAX_CAMPAIGN_REPORTS or len(reports) != len(value):
            raise AuthenticatedCrossLineageRunnerError(
                "candidate campaign report inventory is empty or exceeds its bound"
            )
        return tuple(
            validated_model(item, ModelBenchmarkReport, label="candidate campaign report")
            for item in reports
        )

    def require_generation_origin(
        capability: TrustedGenerationVerification,
        atomic_ledger: AtomicCostLedger,
    ) -> None:
        """Require one exact fresh REAL OpenRouter refetch capability."""

        require_pristine()
        try:
            trusted = trusted_generation_origin(capability, atomic_ledger=atomic_ledger)
        except (AttributeError, TypeError, ValueError):
            trusted = False
        require_pristine()
        if not trusted:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner generation capability lacks owned REAL refetch origin"
            )

    def require_usage_origin(record: UsageRecord, atomic_ledger: AtomicCostLedger) -> None:
        """Require one exact bound-success REAL OpenRouter usage object."""

        require_pristine()
        try:
            trusted = trusted_usage_origin(record, atomic_ledger=atomic_ledger)
        except (AttributeError, TypeError, ValueError):
            trusted = False
        require_pristine()
        if not trusted:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner usage lacks owned REAL transport origin"
            )

    def preflight_runs(
        values: Iterable[CrossLineageRunnerRunCustody],
    ) -> tuple[CrossLineageRunnerRunCustody, ...]:
        bounded = tuple(islice(iter(values), _MAX_RUNS + 1))
        require_pristine()
        if len(bounded) < 2 or len(bounded) > _MAX_RUNS:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner requires between two and sixteen bounded runs"
            )
        for run in bounded:
            if type(run) is not CrossLineageRunnerRunCustody:
                raise AuthenticatedCrossLineageRunnerError(
                    "authenticated runner run custody has the wrong exact type"
                )
            if type(run.run_kind) is not CrossLineageAdjudicationRunKind:
                raise AuthenticatedCrossLineageRunnerError(
                    "authenticated runner run kind has the wrong exact type"
                )
            validated_model(run.candidate_report, ModelBenchmarkReport, label="candidate report")
            validated_model(
                run.candidate_portfolio,
                ModelBenchmarkPortfolio,
                label="candidate portfolio",
            )
            bounded_campaign_reports(run.candidate_campaign_reports)
            validated_model(
                run.adjudication_report,
                CrossLineageAdjudicationReport,
                label="adjudication report",
            )
            validated_model(
                run.judge,
                CandidateModel,
                label="adjudication judge",
            )
            validated_model(
                run.prepared_adjudication,
                CrossLineageAdjudicationPreparedRun,
                label="prepared adjudication",
            )
            if (
                type(run.candidate_campaign_verification)
                is not TrustedCandidateBenchmarkCampaignVerification
                or type(run.candidate_generation_verification) is not TrustedGenerationVerification
                or type(run.judge_generation_verification) is not TrustedGenerationVerification
                or re.fullmatch(_SHA256_PATTERN, run.candidate_campaign_policy_sha256) is None
                or re.fullmatch(
                    _SHA256_PATTERN,
                    run.candidate_campaign_effective_config_sha256,
                )
                is None
            ):
                raise AuthenticatedCrossLineageRunnerError(
                    "authenticated runner live capability or campaign binding is invalid"
                )
        kinds = tuple(item.run_kind for item in bounded)
        if (
            kinds.count(CrossLineageAdjudicationRunKind.PRIMARY) != 1
            or kinds.count(CrossLineageAdjudicationRunKind.REPLAY) != len(kinds) - 1
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner requires exactly one PRIMARY and at least one REPLAY"
            )
        candidate_report_hashes = tuple(item.candidate_report.report_sha256 for item in bounded)
        portfolio_hashes = tuple(item.candidate_portfolio.portfolio_sha256 for item in bounded)
        adjudication_hashes = tuple(item.adjudication_report.report_sha256 for item in bounded)
        campaign_capabilities = tuple(id(item.candidate_campaign_verification) for item in bounded)
        generation_capabilities = tuple(
            capability
            for item in bounded
            for capability in (
                item.candidate_generation_verification,
                item.judge_generation_verification,
            )
        )
        if (
            len(set(candidate_report_hashes)) != len(bounded)
            or len(set(portfolio_hashes)) != len(bounded)
            or len(set(adjudication_hashes)) != len(bounded)
            or len(set(campaign_capabilities)) != len(bounded)
            or len({id(item) for item in generation_capabilities}) != len(generation_capabilities)
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner runs must retain separate reports and live capabilities"
            )
        return tuple(
            sorted(
                bounded,
                key=lambda item: (
                    item.run_kind is CrossLineageAdjudicationRunKind.REPLAY,
                    item.adjudication_report.target.judge_model_id,
                    item.adjudication_report.report_sha256,
                ),
            )
        )

    def required_routing_text(record: UsageRecord, key: str) -> str:
        value = record.routing.get(key)
        if type(value) is not str or not value:
            raise AuthenticatedCrossLineageRunnerError(
                f"authenticated runner usage lacks exact {key} routing"
            )
        return value

    def case_execution_evidence(
        *,
        case_id: str,
        usage: UsageRecord,
        validated_response_sha256: str,
        attestation: OpenRouterGenerationEvidence,
    ) -> AuthenticatedCrossLineageCaseExecutionEvidence:
        generation_id = usage.openrouter_generation_id
        request_body_sha256 = usage.request_body_sha256
        accounted = usage.accounted_cost_usd_exact
        if (
            usage.execution_evidence is not ExecutionEvidenceKind.REAL
            or type(generation_id) is not str
            or not generation_id
            or type(request_body_sha256) is not str
            or re.fullmatch(_SHA256_PATTERN, request_body_sha256) is None
            or type(validated_response_sha256) is not str
            or re.fullmatch(_SHA256_PATTERN, validated_response_sha256) is None
            or type(accounted) is not str
            or usage.attempts > _MAX_ATTEMPTS_PER_REQUEST
            or type(attestation) is not OpenRouterGenerationEvidence
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner case execution evidence is incomplete"
            )
        attempt_ids = tuple(
            usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
            for index in range(1, usage.attempts + 1)
        )
        return AuthenticatedCrossLineageCaseExecutionEvidence(
            case_id=case_id,
            request_id=usage.request_id,
            attempt_count=usage.attempts,
            attempt_request_ids=attempt_ids,
            generation_id=generation_id,
            request_body_sha256=request_body_sha256,
            validated_response_sha256=validated_response_sha256,
            generation_attestation_sha256=attestation.evidence_sha256,
            accounted_cost_usd=_decimal_text(
                _parse_decimal(accounted, label="usage accounted cost")
            ),
        )

    def require_generation_attestation(
        capability: TrustedGenerationVerification,
        *,
        atomic_ledger: AtomicCostLedger,
        report_sha256: str,
        case_id: str,
        exact_model_id: str,
        canonical_model_id: str,
        catalog_identity_binding_sha256: str,
        discovery_evidence_sha256: str,
        usage_record: UsageRecord,
        expected_provider_name: str,
    ) -> OpenRouterGenerationEvidence:
        require_generation_origin(capability, atomic_ledger)
        require_pristine()
        try:
            result = trusted_generation_attestation(
                capability,
                benchmark_report_sha256=report_sha256,
                case_id=case_id,
                exact_model_id=exact_model_id,
                canonical_model_id=canonical_model_id,
                catalog_identity_binding_sha256=catalog_identity_binding_sha256,
                discovery_evidence_sha256=discovery_evidence_sha256,
                usage_record=usage_record,
                expected_provider_name=expected_provider_name,
            )
        except (AttributeError, TypeError, ValueError):
            raise AuthenticatedCrossLineageRunnerError(
                "generation verification capability does not bind an exact runner case"
            ) from None
        require_pristine()
        if type(result) is not OpenRouterGenerationEvidence:
            raise AuthenticatedCrossLineageRunnerError(
                "generation verification returned an invalid attestation type"
            )
        return result

    def replay_ground_truth(
        capability: VerifiedFrozenGroundTruth,
        suite: ModelBenchmarkSuite,
    ) -> VerifiedFrozenGroundTruthProjection:
        if type(capability) is not VerifiedFrozenGroundTruth:
            raise AuthenticatedCrossLineageRunnerError(
                "frozen ground-truth capability has the wrong exact type"
            )
        require_pristine()
        try:
            projection = trusted_ground_require(
                capability,
                objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
                provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
                source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
                benchmark_corpus_sha256=suite.corpus_sha256,
                benchmark_ground_truth_sha256=suite.ground_truth_sha256,
            )
        except (AttributeError, TypeError, ValueError):
            raise AuthenticatedCrossLineageRunnerError(
                "frozen ground-truth capability does not bind the runner suite"
            ) from None
        require_pristine()
        if type(projection) is not VerifiedFrozenGroundTruthProjection:
            raise AuthenticatedCrossLineageRunnerError(
                "frozen ground-truth replay returned an invalid projection type"
            )
        return projection

    def replay_run(
        *,
        public_lineage_capability: VerifiedPublicModelLineage,
        suite: ModelBenchmarkSuite,
        run: CrossLineageRunnerRunCustody,
        atomic_ledger: AtomicCostLedger,
    ) -> AuthenticatedCrossLineageRunnerRunEvidence:
        candidate_report = run.candidate_report
        candidate_result = (
            candidate_report.results[0] if len(candidate_report.results) == 1 else None
        )
        adjudication = run.adjudication_report
        prepared = run.prepared_adjudication
        target = adjudication.target
        if candidate_result is None:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner candidate report must contain one exact result"
            )
        candidate_model_id = candidate_result.target.model_id
        if type(public_lineage_capability) is not VerifiedPublicModelLineage:
            raise AuthenticatedCrossLineageRunnerError(
                "public lineage capability has the wrong exact type"
            )
        require_pristine()
        try:
            rebuilt_prepared = trusted_prepare_adjudication(
                public_lineage_capability=public_lineage_capability,
                suite=suite,
                candidate_report=candidate_report,
                judge=run.judge,
                run_kind=run.run_kind,
            )
        except (AttributeError, TypeError, ValueError):
            raise AuthenticatedCrossLineageRunnerError(
                "prepared adjudication cannot be rebuilt from frozen authority"
            ) from None
        require_pristine()
        if (
            type(rebuilt_prepared) is not CrossLineageAdjudicationPreparedRun
            or trusted_dump_json(rebuilt_prepared) != trusted_dump_json(prepared)
            or adjudication.prepared_run_sha256 != prepared.prepared_run_sha256
            or trusted_dump_json(adjudication.target) != trusted_dump_json(prepared.target)
            or adjudication.case_ids != prepared.case_ids
            or adjudication.candidate_report_sha256 != prepared.candidate_report_sha256
            or tuple(item.request for item in adjudication.cases) != prepared.requests
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "prepared adjudication differs from frozen truth or retained report"
            )
        require_pristine()
        try:
            independence = trusted_require_independent(
                public_lineage_capability,
                candidate_model_id,
                target.judge_model_id,
            )
        except (AttributeError, TypeError, ValueError):
            raise AuthenticatedCrossLineageRunnerError(
                "public lineage capability does not prove the runner pair independent"
            ) from None
        require_pristine()
        if (
            type(independence) is not VerifiedIndependentPublicModelLineageProjection
            or independence.left_exact_model_id != candidate_model_id
            or independence.right_exact_model_id != target.judge_model_id
            or independence.independent is not True
            or independence.left_root_lineage == independence.right_root_lineage
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "public lineage replay returned an invalid independence projection"
            )
        case_ids = tuple(item.case_id for item in suite.cases)
        if (
            run.run_kind is not adjudication.run_kind
            or candidate_report.execution_evidence is not ExecutionEvidenceKind.REAL
            or candidate_result.execution_evidence is not ExecutionEvidenceKind.REAL
            or candidate_report.corpus_name != suite.name
            or candidate_report.corpus_sha256 != suite.corpus_sha256
            or candidate_report.ground_truth_sha256 != suite.ground_truth_sha256
            or tuple(candidate_report.case_ids) != case_ids
            or tuple(item.case_id for item in candidate_result.cases) != case_ids
            or adjudication.corpus_name != suite.name
            or adjudication.corpus_sha256 != suite.corpus_sha256
            or adjudication.ground_truth_sha256 != suite.ground_truth_sha256
            or adjudication.case_ids != case_ids
            or adjudication.candidate_report_sha256 != candidate_report.report_sha256
            or target.candidate_model_id != candidate_model_id
            or target.candidate_root_lineage != independence.left_root_lineage
            or target.judge_root_lineage != independence.right_root_lineage
            or target.public_lineage_bundle_sha256 != independence.bundle_sha256
            or target.public_lineage_manifest_file_sha256 != independence.manifest_file_sha256
            or (
                candidate_result.target.root_lineage is not None
                and candidate_result.target.root_lineage != independence.left_root_lineage
            )
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "runner reports differ from the frozen suite or fresh public roots"
            )
        campaign_reports = bounded_campaign_reports(run.candidate_campaign_reports)
        campaign_report_hashes = tuple(sorted(item.report_sha256 for item in campaign_reports))
        if (
            len(set(campaign_report_hashes)) != len(campaign_report_hashes)
            or candidate_report.report_sha256 not in campaign_report_hashes
            or run.candidate_portfolio.corpus_name != suite.name
            or run.candidate_portfolio.corpus_sha256 != suite.corpus_sha256
            or run.candidate_portfolio.ground_truth_sha256 != suite.ground_truth_sha256
            or run.candidate_portfolio.execution_evidence is not ExecutionEvidenceKind.REAL
            or run.candidate_portfolio.qualification_policy_sha256
            != run.candidate_campaign_policy_sha256
            or run.candidate_portfolio.campaign_journal_sha256 is None
            or run.candidate_portfolio.initial_cost_ledger_snapshot is None
            or run.candidate_portfolio.cost_ledger_snapshot is None
            or not any(
                item.exact_model_id == candidate_model_id
                and item.report_sha256 == candidate_report.report_sha256
                and item.execution_evidence is ExecutionEvidenceKind.REAL
                for item in run.candidate_portfolio.report_artifacts
            )
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "candidate portfolio does not bind the exact REAL candidate report"
            )
        require_pristine()
        try:
            trusted_campaign_require(
                run.candidate_campaign_verification,
                portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
                reports=run.candidate_campaign_reports,
                policy_sha256=run.candidate_campaign_policy_sha256,
                effective_config_sha256=run.candidate_campaign_effective_config_sha256,
            )
        except (AttributeError, TypeError, ValueError):
            raise AuthenticatedCrossLineageRunnerError(
                "candidate campaign capability does not bind the runner report"
            ) from None
        require_pristine()
        candidate_cases_raw = tuple(islice(iter(candidate_result.cases), _MAX_CASES + 1))
        judge_cases_raw = tuple(islice(iter(adjudication.cases), _MAX_CASES + 1))
        require_pristine()
        if (
            len(candidate_cases_raw) != len(case_ids)
            or len(judge_cases_raw) != len(case_ids)
            or len(candidate_cases_raw) > _MAX_CASES
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner case inventory differs from the frozen suite"
            )
        candidate_cases: list[AuthenticatedCrossLineageCaseExecutionEvidence] = []
        judge_cases: list[AuthenticatedCrossLineageCaseExecutionEvidence] = []
        for expected_case_id, candidate_case, judge_case in zip(
            case_ids,
            candidate_cases_raw,
            judge_cases_raw,
            strict=True,
        ):
            candidate_usage = candidate_case.usage_record
            candidate_generation = candidate_case.generation_evidence
            if (
                candidate_case.case_id != expected_case_id
                or candidate_case.error_kind is not None
                or candidate_case.execution_evidence is not ExecutionEvidenceKind.REAL
                or type(candidate_usage) is not UsageRecord
                or type(candidate_generation) is not OpenRouterGenerationEvidence
                or candidate_case.validated_response_sha256 is None
                or judge_case.case_id != expected_case_id
                or type(judge_case.usage_record) is not UsageRecord
                or type(judge_case.generation_evidence) is not OpenRouterGenerationEvidence
                or judge_case.request.candidate_report_sha256 != candidate_report.report_sha256
                or judge_case.request.candidate_case_result_sha256
                != canonical_sha256(candidate_case.model_dump(mode="json"))
                or judge_case.request.candidate_validated_response_sha256
                != candidate_case.validated_response_sha256
                or judge_case.request.candidate_request_body_sha256
                != candidate_usage.request_body_sha256
                or judge_case.request.candidate_usage_record_sha256
                != canonical_sha256(candidate_usage.model_dump(mode="json"))
                or judge_case.request.candidate_generation_evidence_sha256
                != candidate_generation.evidence_sha256
            ):
                raise AuthenticatedCrossLineageRunnerError(
                    "adjudication case does not bind the exact candidate response"
                )
            require_usage_origin(candidate_usage, atomic_ledger)
            require_usage_origin(judge_case.usage_record, atomic_ledger)
            candidate_attestation = require_generation_attestation(
                run.candidate_generation_verification,
                atomic_ledger=atomic_ledger,
                report_sha256=candidate_report.report_sha256,
                case_id=expected_case_id,
                exact_model_id=candidate_model_id,
                canonical_model_id=required_routing_text(candidate_usage, "canonical_model"),
                catalog_identity_binding_sha256=required_routing_text(
                    candidate_usage,
                    "catalog_identity_binding_sha256",
                ),
                discovery_evidence_sha256=required_routing_text(
                    candidate_usage,
                    "discovery_evidence_sha256",
                ),
                usage_record=candidate_usage,
                expected_provider_name=required_routing_text(
                    candidate_usage,
                    "selected_provider_name",
                ),
            )
            judge_attestation = require_generation_attestation(
                run.judge_generation_verification,
                atomic_ledger=atomic_ledger,
                report_sha256=adjudication.report_sha256,
                case_id=expected_case_id,
                exact_model_id=target.judge_model_id,
                canonical_model_id=target.judge_canonical_model_id,
                catalog_identity_binding_sha256=target.judge_catalog_identity_binding_sha256,
                discovery_evidence_sha256=target.judge_discovery_evidence_sha256,
                usage_record=judge_case.usage_record,
                expected_provider_name=target.judge_provider_name,
            )
            if (
                candidate_attestation != candidate_generation
                or judge_attestation != judge_case.generation_evidence
            ):
                raise AuthenticatedCrossLineageRunnerError(
                    "live generation verification differs from embedded case evidence"
                )
            candidate_cases.append(
                case_execution_evidence(
                    case_id=expected_case_id,
                    usage=candidate_usage,
                    validated_response_sha256=candidate_case.validated_response_sha256,
                    attestation=candidate_attestation,
                )
            )
            judge_cases.append(
                case_execution_evidence(
                    case_id=expected_case_id,
                    usage=judge_case.usage_record,
                    validated_response_sha256=judge_case.judge_validated_response_sha256,
                    attestation=judge_attestation,
                )
            )
        return AuthenticatedCrossLineageRunnerRunEvidence(
            run_kind=run.run_kind,
            candidate_model_id=candidate_model_id,
            candidate_root_lineage=independence.left_root_lineage,
            judge_model_id=target.judge_model_id,
            judge_root_lineage=independence.right_root_lineage,
            candidate_report_sha256=candidate_report.report_sha256,
            candidate_portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
            candidate_campaign_report_sha256s=campaign_report_hashes,
            prepared_run_sha256=adjudication.prepared_run_sha256,
            adjudication_report_sha256=adjudication.report_sha256,
            candidate_cases=tuple(candidate_cases),
            judge_cases=tuple(judge_cases),
        )

    def build_evidence(
        *,
        public_lineage_capability: VerifiedPublicModelLineage,
        ground_truth_capability: VerifiedFrozenGroundTruth,
        suite: ModelBenchmarkSuite,
        runs: tuple[CrossLineageRunnerRunCustody, ...],
        ledger_view: _ClosedLedgerIntervalView,
    ) -> AuthenticatedCrossLineageRunnerEvidence:
        fresh_runs = preflight_runs(runs)
        if fresh_runs != runs:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner retained run ordering or structure drifted"
            )
        runs = fresh_runs
        validated_suite = validated_model(suite, ModelBenchmarkSuite, label="benchmark suite")
        ground_truth = replay_ground_truth(ground_truth_capability, validated_suite)
        case_ids = tuple(item.case_id for item in validated_suite.cases)
        if ground_truth.case_count != len(case_ids):
            raise AuthenticatedCrossLineageRunnerError(
                "frozen ground-truth capability has different case coverage"
            )
        run_evidence = tuple(
            replay_run(
                public_lineage_capability=public_lineage_capability,
                suite=validated_suite,
                run=run,
                atomic_ledger=ledger_view.ledger,
            )
            for run in runs
        )
        bundle_hashes = {
            run.adjudication_report.target.public_lineage_bundle_sha256 for run in runs
        }
        manifest_hashes = {
            run.adjudication_report.target.public_lineage_manifest_file_sha256 for run in runs
        }
        if len(bundle_hashes) != 1 or len(manifest_hashes) != 1:
            raise AuthenticatedCrossLineageRunnerError(
                "runner runs do not share one fresh public-lineage evidence bundle"
            )
        all_cases = tuple(
            case
            for run in run_evidence
            for cases in (run.candidate_cases, run.judge_cases)
            for case in cases
        )
        attempt_ids = tuple(
            attempt_id for case in all_cases for attempt_id in case.attempt_request_ids
        )
        if len(attempt_ids) != len(set(attempt_ids)):
            raise AuthenticatedCrossLineageRunnerError(
                "runner usage produces colliding provider-attempt request IDs"
            )
        ledger_by_id = {item.request_id: item for item in ledger_view.new_entries}
        if tuple(sorted(attempt_ids)) != tuple(sorted(ledger_by_id)):
            raise AuthenticatedCrossLineageRunnerError(
                "closed ledger interval differs from every exact runner attempt"
            )
        for case in all_cases:
            with localcontext() as context:
                context.prec = 64
                actual = sum(
                    (
                        cast(Decimal, ledger_by_id[request_id].actual_cost_usd)
                        for request_id in case.attempt_request_ids
                    ),
                    start=Decimal(0),
                )
            if actual != _parse_decimal(case.accounted_cost_usd, label="case accounted cost"):
                raise AuthenticatedCrossLineageRunnerError(
                    "runner usage cost differs from its reconciled ledger attempts"
                )
        provisional = AuthenticatedCrossLineageRunnerEvidence.model_construct(
            schema_version="1.0",
            objective_sha256=ground_truth.objective_sha256,
            frozen_ground_truth_provenance_sha256=ground_truth.provenance_sha256,
            frozen_source_revision=ground_truth.source_revision,
            benchmark_corpus_sha256=ground_truth.benchmark_corpus_sha256,
            benchmark_ground_truth_sha256=ground_truth.benchmark_ground_truth_sha256,
            ground_truth_case_binding_set_sha256=ground_truth.case_binding_set_sha256,
            public_lineage_bundle_sha256=next(iter(bundle_hashes)),
            public_lineage_manifest_file_sha256=next(iter(manifest_hashes)),
            case_ids=case_ids,
            runs=run_evidence,
            ledger_interval=ledger_view.evidence,
            serialized_authority=False,
            lineage_identity_authorized=False,
            provider_call_authorized=False,
            source_egress_authorized=False,
            runner_custody_authorized=False,
            generation_verification_authorized=False,
            adjudication_credit_authorized=False,
            model_qualification_authorized=False,
            production_selection_authorized=False,
            seal_publication_authorized=False,
            release_authorized=False,
            benchmark_authorized=False,
            evidence_sha256="0" * 64,
        )
        evidence_hash = _canonical_sha256(
            provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        )
        return AuthenticatedCrossLineageRunnerEvidence(
            **provisional.model_dump(mode="python", exclude={"evidence_sha256"}),
            evidence_sha256=evidence_hash,
        )

    def projection(
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> VerifiedCrossLineageRunnerProjection:
        return VerifiedCrossLineageRunnerProjection(
            evidence_sha256=evidence.evidence_sha256,
            objective_sha256=evidence.objective_sha256,
            frozen_ground_truth_provenance_sha256=(evidence.frozen_ground_truth_provenance_sha256),
            frozen_source_revision=evidence.frozen_source_revision,
            benchmark_corpus_sha256=evidence.benchmark_corpus_sha256,
            benchmark_ground_truth_sha256=evidence.benchmark_ground_truth_sha256,
            ground_truth_case_binding_set_sha256=(evidence.ground_truth_case_binding_set_sha256),
            public_lineage_bundle_sha256=evidence.public_lineage_bundle_sha256,
            public_lineage_manifest_file_sha256=(evidence.public_lineage_manifest_file_sha256),
            ledger_initial_snapshot_sha256=(evidence.ledger_interval.initial_snapshot_sha256),
            ledger_final_snapshot_sha256=evidence.ledger_interval.final_snapshot_sha256,
            ledger_final_spent_usd=evidence.ledger_interval.final_spent_usd,
            ledger_request_ids=tuple(item.request_id for item in evidence.ledger_interval.entries),
            runs=tuple(
                VerifiedCrossLineageRunnerRunProjection(
                    run_kind=item.run_kind,
                    candidate_model_id=item.candidate_model_id,
                    candidate_root_lineage=item.candidate_root_lineage,
                    judge_model_id=item.judge_model_id,
                    judge_root_lineage=item.judge_root_lineage,
                    candidate_report_sha256=item.candidate_report_sha256,
                    candidate_portfolio_sha256=item.candidate_portfolio_sha256,
                    prepared_run_sha256=item.prepared_run_sha256,
                    adjudication_report_sha256=item.adjudication_report_sha256,
                    case_ids=tuple(case.case_id for case in item.candidate_cases),
                )
                for item in evidence.runs
            ),
            serialized_authority=False,
            lineage_identity_authorized=False,
            runner_custody_authorized=True,
            provider_call_authorized=False,
            source_egress_authorized=False,
            generation_verification_authorized=False,
            adjudication_credit_authorized=False,
            model_qualification_authorized=False,
            production_selection_authorized=False,
            seal_publication_authorized=False,
            release_authorized=False,
            benchmark_authorized=False,
        )

    def issue(
        *,
        public_lineage_capability: VerifiedPublicModelLineage,
        ground_truth_capability: VerifiedFrozenGroundTruth,
        benchmark_suite: ModelBenchmarkSuite,
        runs: Iterable[CrossLineageRunnerRunCustody],
        closed_ledger_interval: ClosedCrossLineageLedgerInterval,
    ) -> tuple[VerifiedCrossLineageRunnerCustody, AuthenticatedCrossLineageRunnerEvidence]:
        require_pristine()
        retained_runs = preflight_runs(runs)
        ledger_view = trusted_require_ledger(closed_ledger_interval)
        evidence = build_evidence(
            public_lineage_capability=public_lineage_capability,
            ground_truth_capability=ground_truth_capability,
            suite=benchmark_suite,
            runs=retained_runs,
            ledger_view=ledger_view,
        )
        claimed = trusted_claim_ledger(closed_ledger_interval)
        if claimed != ledger_view:
            raise AuthenticatedCrossLineageRunnerError(
                "closed ledger interval changed while runner custody issued"
            )
        capability = object.__new__(VerifiedCrossLineageRunnerCustody)
        state = RunnerState(
            process_id=trusted_getpid(),
            public_lineage_capability=public_lineage_capability,
            ground_truth_capability=ground_truth_capability,
            benchmark_suite=benchmark_suite,
            runs=retained_runs,
            closed_ledger_interval=closed_ledger_interval,
            evidence=evidence,
        )
        trusted_lease_register(registry, capability, state)
        require_pristine()
        return capability, evidence

    def require(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> VerifiedCrossLineageRunnerProjection:
        require_pristine()
        if type(capability) is not VerifiedCrossLineageRunnerCustody:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent or mismatched"
            )
        if type(evidence) is not AuthenticatedCrossLineageRunnerEvidence:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner evidence has the wrong exact type"
            )
        current_evidence = validated_model(
            evidence,
            AuthenticatedCrossLineageRunnerEvidence,
            label="authenticated runner evidence",
        )
        lease_snapshot = trusted_lease_snapshot(registry, capability)
        state = lease_snapshot.state
        if state.process_id != trusted_getpid() or current_evidence != state.evidence:
            raise AuthenticatedCrossLineageRunnerError(
                "verified cross-lineage runner custody is absent or mismatched"
            )
        ledger_view = trusted_require_ledger(state.closed_ledger_interval)
        replayed = build_evidence(
            public_lineage_capability=state.public_lineage_capability,
            ground_truth_capability=state.ground_truth_capability,
            suite=state.benchmark_suite,
            runs=state.runs,
            ledger_view=ledger_view,
        )
        if replayed != state.evidence or replayed != current_evidence:
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner live evidence drifted after issuance"
            )
        result = projection(replayed)
        trusted_lease_recheck(registry, capability, lease_snapshot)
        require_pristine()
        return result

    def revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        """Permanently invalidate one exact current-PID runner lease."""

        # Disposal is fail-safe: a mutated public binding must be reported, but it
        # must not keep an already-issued lease alive.  The captured registry
        # descriptor validates the exact capability and PID before removing it.
        trusted_lease_revoke(registry, capability)
        require_pristine()

    public_bindings.update(
        {
            "issue_verified_cross_lineage_runner_custody": issue,
            "require_verified_cross_lineage_runner_custody": require,
            "revoke_verified_cross_lineage_runner_custody": revoke,
        }
    )
    return issue, require, revoke


(
    issue_verified_cross_lineage_runner_custody,
    require_verified_cross_lineage_runner_custody,
    revoke_verified_cross_lineage_runner_custody,
) = _build_authenticated_cross_lineage_runner_authority()
del _build_authenticated_cross_lineage_runner_authority


__all__ = [
    "AuthenticatedCrossLineageCaseExecutionEvidence",
    "AuthenticatedCrossLineageLedgerEntryEvidence",
    "AuthenticatedCrossLineageLedgerIntervalEvidence",
    "AuthenticatedCrossLineageRunnerError",
    "AuthenticatedCrossLineageRunnerEvidence",
    "AuthenticatedCrossLineageRunnerRunEvidence",
    "ClosedCrossLineageLedgerInterval",
    "CrossLineageRunnerRunCustody",
    "OpenCrossLineageLedgerInterval",
    "VerifiedCrossLineageRunnerCustody",
    "VerifiedCrossLineageRunnerProjection",
    "VerifiedCrossLineageRunnerRunProjection",
    "begin_cross_lineage_ledger_interval",
    "close_cross_lineage_ledger_interval",
    "issue_verified_cross_lineage_runner_custody",
    "require_verified_cross_lineage_runner_custody",
    "revoke_verified_cross_lineage_runner_custody",
]
