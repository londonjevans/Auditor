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
from dataclasses import dataclass, replace
from decimal import Decimal, localcontext
from itertools import islice
from typing import Any, Literal, Never, SupportsIndex, cast

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

import mmaudit.benchmark.cross_lineage_adjudication as _adjudication_module
import mmaudit.benchmark.model_portfolio as _model_portfolio_module
import mmaudit.benchmark.models as _benchmark_models_module
import mmaudit.models.authenticated_runner_ledger as _ledger_authority_module
import mmaudit.models.generation_evidence as _generation_evidence_module
import mmaudit.models.ground_truth_authority as _ground_truth_module
import mmaudit.models.public_lineage_authority as _public_lineage_module
import mmaudit.models.usage as _usage_module
import mmaudit.orchestration.authenticated_calibration_accounting as _calibration_accounting_module
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
    revoke_trusted_candidate_benchmark_campaign_verification,
    transfer_trusted_candidate_benchmark_campaign_verification,
)
from mmaudit.benchmark.models import ModelBenchmarkReport, ModelBenchmarkSuite
from mmaudit.models.authenticated_runner_ledger import (
    _DECIMAL_PATTERN as _DECIMAL_PATTERN,
)
from mmaudit.models.authenticated_runner_ledger import (
    _MAX_INTERVAL_REQUEST_IDS as _MAX_INTERVAL_REQUEST_IDS,
)
from mmaudit.models.authenticated_runner_ledger import (
    _REQUEST_ID_PATTERN as _REQUEST_ID_PATTERN,
)
from mmaudit.models.authenticated_runner_ledger import (
    _RUNNER_LEDGER_CAP_USD as _RUNNER_LEDGER_CAP_USD,
)
from mmaudit.models.authenticated_runner_ledger import (
    _SHA256_PATTERN as _SHA256_PATTERN,
)
from mmaudit.models.authenticated_runner_ledger import (
    AuthenticatedCrossLineageLedgerEntryEvidence as AuthenticatedCrossLineageLedgerEntryEvidence,
)
from mmaudit.models.authenticated_runner_ledger import (
    AuthenticatedCrossLineageLedgerIntervalEvidence as AuthenticatedCrossLineageLedgerIntervalEvidence,
)
from mmaudit.models.authenticated_runner_ledger import (
    AuthenticatedCrossLineageRunnerError as AuthenticatedCrossLineageRunnerError,
)
from mmaudit.models.authenticated_runner_ledger import (
    ClosedCrossLineageLedgerInterval as ClosedCrossLineageLedgerInterval,
)
from mmaudit.models.authenticated_runner_ledger import (
    OpenCrossLineageLedgerInterval as OpenCrossLineageLedgerInterval,
)
from mmaudit.models.authenticated_runner_ledger import (
    _canonical_sha256 as _canonical_sha256,
)
from mmaudit.models.authenticated_runner_ledger import (
    _claim_closed_cross_lineage_ledger_interval as _claim_closed_cross_lineage_ledger_interval,
)
from mmaudit.models.authenticated_runner_ledger import (
    _ClosedLedgerIntervalView as _ClosedLedgerIntervalView,
)
from mmaudit.models.authenticated_runner_ledger import (
    _decimal_text as _decimal_text,
)
from mmaudit.models.authenticated_runner_ledger import (
    _entry_material as _entry_material,
)
from mmaudit.models.authenticated_runner_ledger import (
    _entry_sha256 as _entry_sha256,
)
from mmaudit.models.authenticated_runner_ledger import (
    _parse_decimal as _parse_decimal,
)
from mmaudit.models.authenticated_runner_ledger import (
    _require_closed_cross_lineage_ledger_interval as _require_closed_cross_lineage_ledger_interval,
)
from mmaudit.models.authenticated_runner_ledger import (
    _require_pristine_cross_lineage_ledger_runtime as _require_pristine_cross_lineage_ledger_runtime,
)
from mmaudit.models.authenticated_runner_ledger import (
    _snapshot_sha256 as _snapshot_sha256,
)
from mmaudit.models.authenticated_runner_ledger import (
    _StrictFrozenEvidence as _StrictFrozenEvidence,
)
from mmaudit.models.authenticated_runner_ledger import (
    begin_cross_lineage_ledger_interval as begin_cross_lineage_ledger_interval,
)
from mmaudit.models.authenticated_runner_ledger import (
    close_cross_lineage_ledger_interval as close_cross_lineage_ledger_interval,
)
from mmaudit.models.generation_evidence import (
    GenerationVerificationRequest,
    OpenRouterGenerationEvidence,
    TrustedGenerationVerification,
    _has_authrunner_generation_origin,
    revoke_trusted_generation_verification,
    transfer_trusted_generation_verification,
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
from mmaudit.models.schemas import ExecutionEvidenceKind, UsageRecord
from mmaudit.models.usage import _has_authrunner_owned_real_usage_origin
from mmaudit.orchestration.authenticated_calibration_accounting import (
    CalibrationLedgerAccounting,
    CalibrationLedgerPrefixProjection,
    RetainedCalibrationLedgerPrefix,
    require_calibration_ledger_prefix,
    retain_calibration_ledger_interval,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    cost_ledger_snapshot_sha256,
)
from mmaudit.orchestration.manifest import canonical_sha256

_MAX_CAMPAIGN_REPORTS = 128
_MAX_RUNS = 16
_MAX_CASES = 10_000
_MAX_ATTEMPTS_PER_REQUEST = 32


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

    schema_version: Literal["1.0", "1.1"] = "1.0"
    effective_config_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
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
        if (self.schema_version == "1.0") != (self.effective_config_sha256 is None):
            raise ValueError(
                "authenticated runner evidence version and effective config custody differ"
            )
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
    effective_config_sha256: str | None
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

    def replace_state(
        self,
        capability: LeaseCapabilityT,
        snapshot: _PidLocalLeaseSnapshot[LeaseStateT],
        state: LeaseStateT,
    ) -> _PidLocalLeaseSnapshot[LeaseStateT]:
        """Atomically change one live lease's state; stale or revoked leases stay invalid."""

        with self._lock:
            self.recheck(capability, snapshot)
            entry = self._entries[id(capability)]
            nonce = object()
            self._entries[id(capability)] = (entry[0], entry[1], state, nonce)
            return _PidLocalLeaseSnapshot(process_id=entry[1], state=state, nonce=nonce)

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


def _build_runner_child_capability_inventory_revoker() -> Callable[..., None]:
    """Capture fail-safe invalidation for retained campaign and generation leases."""

    trusted_campaign_type = TrustedCandidateBenchmarkCampaignVerification
    trusted_generation_type = TrustedGenerationVerification
    trusted_campaign_revoke = revoke_trusted_candidate_benchmark_campaign_verification
    trusted_generation_revoke = revoke_trusted_generation_verification
    trusted_max_runs = _MAX_RUNS

    def revoke(
        *,
        campaigns: tuple[TrustedCandidateBenchmarkCampaignVerification, ...],
        generations: tuple[TrustedGenerationVerification, ...],
        expected_campaign_count: int | None,
    ) -> None:
        campaign_inventory_valid = type(campaigns) is tuple and all(
            type(item) is trusted_campaign_type for item in campaigns
        )
        generation_inventory_valid = type(generations) is tuple and all(
            type(item) is trusted_generation_type for item in generations
        )
        unique_campaigns = tuple({id(item): item for item in campaigns}.values())
        unique_generations = tuple({id(item): item for item in generations}.values())
        inventory_valid = (
            campaign_inventory_valid
            and generation_inventory_valid
            and len(unique_campaigns) == len(campaigns)
            and len(unique_generations) == len(generations)
            and (
                expected_campaign_count is None
                or (
                    type(expected_campaign_count) is int
                    and 2 <= expected_campaign_count <= trusted_max_runs
                    and len(campaigns) == expected_campaign_count
                    and len(generations) == expected_campaign_count * 2
                )
            )
        )
        failure: BaseException | None = (
            None
            if inventory_valid
            else AuthenticatedCrossLineageRunnerError(
                "authenticated runner child capability inventory is invalid"
            )
        )
        for campaign in unique_campaigns:
            if type(campaign) is not trusted_campaign_type:
                continue
            try:
                trusted_campaign_revoke(campaign)
            except BaseException as exc:
                if failure is None:
                    failure = exc
        for generation in unique_generations:
            if type(generation) is not trusted_generation_type:
                continue
            try:
                trusted_generation_revoke(generation)
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            if not isinstance(failure, Exception):
                raise failure
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner child capability revocation was incomplete"
            ) from None

    return revoke


_revoke_runner_child_capability_inventory = _build_runner_child_capability_inventory_revoker()
del _build_runner_child_capability_inventory_revoker


def _build_authenticated_cross_lineage_runner_authority() -> tuple[
    Callable[
        ...,
        tuple[VerifiedCrossLineageRunnerCustody, AuthenticatedCrossLineageRunnerEvidence],
    ],
    Callable[..., VerifiedCrossLineageRunnerProjection],
    Callable[[VerifiedCrossLineageRunnerCustody], None],
    Callable[
        ...,
        tuple[VerifiedCrossLineageRunnerCustody, tuple[CrossLineageRunnerRunCustody, ...]],
    ],
    Callable[
        ...,
        tuple[VerifiedCrossLineageRunnerCustody, tuple[CrossLineageRunnerRunCustody, ...]],
    ],
]:
    """Capture every live verifier and retain custody outside durable evidence."""

    @dataclass(frozen=True, slots=True)
    class RunnerState:
        process_id: int
        run_count: int
        public_lineage_capability: VerifiedPublicModelLineage
        ground_truth_capability: VerifiedFrozenGroundTruth
        benchmark_suite: ModelBenchmarkSuite
        runs: tuple[CrossLineageRunnerRunCustody, ...]
        campaign_capabilities: tuple[TrustedCandidateBenchmarkCampaignVerification, ...]
        generation_capabilities: tuple[TrustedGenerationVerification, ...]
        closed_ledger_interval: ClosedCrossLineageLedgerInterval
        evidence: AuthenticatedCrossLineageRunnerEvidence
        retained_ledger_prefix: RetainedCalibrationLedgerPrefix | None = None
        retained_ledger_view: _ClosedLedgerIntervalView | None = None

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
        "_ledger_authority_module": _ledger_authority_module,
        "_calibration_accounting_module": _calibration_accounting_module,
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
    trusted_max_runs = _MAX_RUNS
    trusted_runner_capability_type = VerifiedCrossLineageRunnerCustody
    trusted_object_new = object.__new__
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
    trusted_lease_replace = _PidLocalOneWayLeaseRegistry.replace_state
    trusted_model_dump = BaseModel.model_dump
    trusted_dump_json = BaseModel.model_dump_json
    trusted_model_construct = cast(Any, BaseModel.model_construct).__func__
    trusted_validate_json = cast(Any, BaseModel.model_validate_json).__func__
    trusted_require_ledger = _require_closed_cross_lineage_ledger_interval
    trusted_claim_ledger = _claim_closed_cross_lineage_ledger_interval
    trusted_ledger_pristine = _require_pristine_cross_lineage_ledger_runtime
    trusted_require_prefix = require_calibration_ledger_prefix
    trusted_retain_interval = retain_calibration_ledger_interval
    trusted_snapshot_hash = cost_ledger_snapshot_sha256
    # Relocating the ledger implementation must not unguard aliases still used
    # by original runner validators and consumers.
    trusted_ledger_exports = {
        name: getattr(_ledger_authority_module, name)
        for name in (
            "AuthenticatedCrossLineageRunnerError",
            "AuthenticatedCrossLineageLedgerEntryEvidence",
            "AuthenticatedCrossLineageLedgerIntervalEvidence",
            "ClosedCrossLineageLedgerInterval",
            "OpenCrossLineageLedgerInterval",
            "_ClosedLedgerIntervalView",
            "_StrictFrozenEvidence",
            "_parse_decimal",
            "_decimal_text",
            "_canonical_sha256",
            "_entry_material",
            "_entry_sha256",
            "_snapshot_sha256",
            "begin_cross_lineage_ledger_interval",
            "close_cross_lineage_ledger_interval",
        )
    }
    trusted_require_independent = require_independent_public_model_lineage
    trusted_prepare_adjudication = prepare_cross_lineage_adjudication
    trusted_case_result_getattribute = CrossLineageAdjudicationCaseResult.__getattribute__
    trusted_ground_require = VerifiedFrozenGroundTruth.require_for
    trusted_campaign_require = TrustedCandidateBenchmarkCampaignVerification.require_for
    trusted_campaign_revoke = revoke_trusted_candidate_benchmark_campaign_verification
    trusted_generation_attestation = TrustedGenerationVerification.attestation_for
    trusted_generation_origin = _has_authrunner_generation_origin
    trusted_generation_revoke = revoke_trusted_generation_verification
    trusted_child_inventory_revoke = _revoke_runner_child_capability_inventory
    trusted_run_getattribute = CrossLineageRunnerRunCustody.__getattribute__
    trusted_run_child_descriptors = {
        name: vars(CrossLineageRunnerRunCustody)[name]
        for name in (
            "candidate_campaign_verification",
            "candidate_generation_verification",
            "judge_generation_verification",
        )
    }

    def run_child_capability(run: CrossLineageRunnerRunCustody, name: str) -> object:
        return cast(Any, trusted_run_child_descriptors[name]).__get__(
            run,
            CrossLineageRunnerRunCustody,
        )

    trusted_usage_origin = _has_authrunner_owned_real_usage_origin
    trusted_types = {
        "CalibrationLedgerAccounting": CalibrationLedgerAccounting,
        "CalibrationLedgerPrefixProjection": CalibrationLedgerPrefixProjection,
        "RetainedCalibrationLedgerPrefix": RetainedCalibrationLedgerPrefix,
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
        "require_calibration_ledger_prefix": trusted_require_prefix,
        "retain_calibration_ledger_interval": trusted_retain_interval,
        "cost_ledger_snapshot_sha256": trusted_snapshot_hash,
        "require_independent_public_model_lineage": trusted_require_independent,
        "prepare_cross_lineage_adjudication": trusted_prepare_adjudication,
        "canonical_sha256": canonical_sha256,
        "_require_closed_cross_lineage_ledger_interval": trusted_require_ledger,
        "_claim_closed_cross_lineage_ledger_interval": trusted_claim_ledger,
        "_require_pristine_cross_lineage_ledger_runtime": trusted_ledger_pristine,
        "_has_authrunner_generation_origin": trusted_generation_origin,
        "_has_authrunner_owned_real_usage_origin": trusted_usage_origin,
        "revoke_trusted_candidate_benchmark_campaign_verification": (trusted_campaign_revoke),
        "revoke_trusted_generation_verification": trusted_generation_revoke,
        "_revoke_runner_child_capability_inventory": trusted_child_inventory_revoke,
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
            "revoke_trusted_candidate_benchmark_campaign_verification",
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
            "_recheck_trusted_generation_capability",
            "_snapshot_trusted_generation_capability",
            "_trusted_generation_binding_for",
            "_usage_record_sha256",
            "_validated_usage_copy_preserving_owned_attestation",
            "_has_authrunner_generation_origin",
            "revoke_trusted_generation_verification",
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
    retention_function_states = tuple(
        (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
        )
        for function in (
            trusted_require_prefix,
            trusted_retain_interval,
            trusted_snapshot_hash,
            trusted_lease_replace,
            CalibrationLedgerPrefixProjection.__init__,
        )
    )

    def require_pristine() -> None:
        trusted_ledger_pristine()
        if (
            namespace.get("sys") is not trusted_sys_module
            or namespace.get("_MAX_RUNS") != trusted_max_runs
            or any(namespace.get(name) is not module for name, module in trusted_modules.items())
            or trusted_sys_module.modules.get(__name__) is not trusted_self_module
            or any(
                trusted_sys_module.modules.get(module.__name__) is not module
                for module in trusted_modules.values()
            )
            or any(namespace.get(name) is not value for name, value in trusted_types.items())
            or any(namespace.get(name) is not value for name, value in trusted_functions.items())
            or any(namespace.get(name) is not value for name, value in public_bindings.items())
            or any(
                namespace.get(name) is not value
                or getattr(_ledger_authority_module, name) is not value
                for name, value in trusted_ledger_exports.items()
            )
            or _calibration_accounting_module.CalibrationLedgerAccounting
            is not CalibrationLedgerAccounting
            or _calibration_accounting_module.RetainedCalibrationLedgerPrefix
            is not RetainedCalibrationLedgerPrefix
            or _calibration_accounting_module.CalibrationLedgerPrefixProjection
            is not CalibrationLedgerPrefixProjection
            or _calibration_accounting_module.require_calibration_ledger_prefix
            is not trusted_require_prefix
            or _calibration_accounting_module.retain_calibration_ledger_interval
            is not trusted_retain_interval
            or any(
                function.__code__ is not code
                or function.__defaults__ is not defaults
                or function.__kwdefaults__ is not kwdefaults
                or tuple(sorted((function.__kwdefaults__ or {}).items())) != keyword_items
                for function, code, defaults, kwdefaults, keyword_items in retention_function_states
            )
            or _PidLocalOneWayLeaseRegistry.register is not trusted_lease_register
            or _PidLocalOneWayLeaseRegistry.snapshot is not trusted_lease_snapshot
            or _PidLocalOneWayLeaseRegistry.recheck is not trusted_lease_recheck
            or _PidLocalOneWayLeaseRegistry.revoke is not trusted_lease_revoke
            or _PidLocalOneWayLeaseRegistry.replace_state is not trusted_lease_replace
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
            or CrossLineageRunnerRunCustody.__getattribute__ is not trusted_run_getattribute
            or any(
                vars(CrossLineageRunnerRunCustody).get(name) is not descriptor
                for name, descriptor in trusted_run_child_descriptors.items()
            )
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
        bounded = tuple(islice(iter(values), trusted_max_runs + 1))
        require_pristine()
        if len(bounded) < 2 or len(bounded) > trusted_max_runs:
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
                type(run_child_capability(run, "candidate_campaign_verification"))
                is not TrustedCandidateBenchmarkCampaignVerification
                or type(run_child_capability(run, "candidate_generation_verification"))
                is not TrustedGenerationVerification
                or type(run_child_capability(run, "judge_generation_verification"))
                is not TrustedGenerationVerification
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
        campaign_capabilities = tuple(
            id(run_child_capability(item, "candidate_campaign_verification")) for item in bounded
        )
        generation_capabilities = tuple(
            capability
            for item in bounded
            for capability in (
                run_child_capability(item, "candidate_generation_verification"),
                run_child_capability(item, "judge_generation_verification"),
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
                cast(
                    TrustedCandidateBenchmarkCampaignVerification,
                    run_child_capability(run, "candidate_campaign_verification"),
                ),
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
                cast(
                    TrustedGenerationVerification,
                    run_child_capability(run, "candidate_generation_verification"),
                ),
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
                cast(
                    TrustedGenerationVerification,
                    run_child_capability(run, "judge_generation_verification"),
                ),
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
        effective_config_hashes = {run.candidate_campaign_effective_config_sha256 for run in runs}
        if len(effective_config_hashes) != 1:
            raise AuthenticatedCrossLineageRunnerError(
                "runner runs do not share one effective configuration"
            )
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
            schema_version="1.1",
            effective_config_sha256=next(iter(effective_config_hashes)),
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
            effective_config_sha256=evidence.effective_config_sha256,
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
        campaign_capabilities = tuple(
            cast(
                TrustedCandidateBenchmarkCampaignVerification,
                run_child_capability(run, "candidate_campaign_verification"),
            )
            for run in retained_runs
        )
        generation_capabilities = tuple(
            cast(TrustedGenerationVerification, child_capability)
            for run in retained_runs
            for child_capability in (
                run_child_capability(run, "candidate_generation_verification"),
                run_child_capability(run, "judge_generation_verification"),
            )
        )
        if (
            len(campaign_capabilities) != len(retained_runs)
            or len(generation_capabilities) != len(retained_runs) * 2
            or len({id(item) for item in campaign_capabilities}) != len(campaign_capabilities)
            or len({id(item) for item in generation_capabilities}) != len(generation_capabilities)
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner child capability inventory is invalid"
            )
        require_pristine()
        claimed = trusted_claim_ledger(closed_ledger_interval)
        if claimed != ledger_view:
            raise AuthenticatedCrossLineageRunnerError(
                "closed ledger interval changed while runner custody issued"
            )
        capability = trusted_object_new(trusted_runner_capability_type)
        state = RunnerState(
            process_id=trusted_getpid(),
            run_count=len(retained_runs),
            public_lineage_capability=public_lineage_capability,
            ground_truth_capability=ground_truth_capability,
            benchmark_suite=benchmark_suite,
            runs=retained_runs,
            campaign_capabilities=campaign_capabilities,
            generation_capabilities=generation_capabilities,
            closed_ledger_interval=closed_ledger_interval,
            evidence=evidence,
        )
        registered = False
        try:
            trusted_lease_register(registry, capability, state)
            registered = True
            require_pristine()
        except BaseException as original:
            cleanup_failure: BaseException | None = None
            try:
                trusted_lease_revoke(registry, capability)
            except AuthenticatedCrossLineageRunnerError as exc:
                if registered:
                    cleanup_failure = exc
            except BaseException as exc:
                cleanup_failure = exc
            try:
                trusted_child_inventory_revoke(
                    campaigns=state.campaign_capabilities,
                    generations=state.generation_capabilities,
                    expected_campaign_count=state.run_count,
                )
            except BaseException as exc:
                if cleanup_failure is None:
                    cleanup_failure = exc
            if cleanup_failure is not None:
                if not isinstance(cleanup_failure, Exception):
                    raise cleanup_failure from None
                raise AuthenticatedCrossLineageRunnerError(
                    "authenticated runner issuance cleanup was incomplete"
                ) from None
            raise original
        return capability, evidence

    def ledger_view_for(state: RunnerState) -> _ClosedLedgerIntervalView:
        """Replay exact closure or its originally captured, currently owned cost prefix."""

        prefix = state.retained_ledger_prefix
        view = state.retained_ledger_view
        if prefix is None and view is None:
            return trusted_require_ledger(state.closed_ledger_interval)
        if (
            type(prefix) is not RetainedCalibrationLedgerPrefix
            or type(view) is not _ClosedLedgerIntervalView
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "retained runner ledger custody is incomplete"
            )
        require_pristine()
        try:
            current = trusted_require_prefix(prefix)
        except (TypeError, ValueError) as exc:
            raise AuthenticatedCrossLineageRunnerError(
                "retained runner ledger custody is unavailable"
            ) from exc
        if type(current) is not CalibrationLedgerPrefixProjection:
            raise AuthenticatedCrossLineageRunnerError("retained runner cost projection is invalid")
        if current.current_accounting.blockers:
            raise AuthenticatedCrossLineageRunnerError(
                "retained runner ledger has unassigned or unsafe work"
            )
        with localcontext() as context:
            context.prec = 64
            spent = view.final_snapshot.spent_usd - view.initial_snapshot.spent_usd
        final_entries = {entry.request_id: entry for entry in view.final_snapshot.entries}
        if (
            view.capability is not state.closed_ledger_interval
            or view.evidence != state.evidence.ledger_interval
            or view.ledger_identity_sha256 != current.current_accounting.ledger_identity_sha256
            or trusted_snapshot_hash(view.initial_snapshot) != current.initial_snapshot_sha256
            or trusted_snapshot_hash(view.final_snapshot) != current.final_snapshot_sha256
            or tuple(entry.request_id for entry in view.new_entries) != current.interval_request_ids
            or tuple(final_entries.get(request_id) for request_id in current.interval_request_ids)
            != view.new_entries
            or spent != current.interval_spent_usd
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "retained runner prefix differs from its original closed ledger"
            )
        require_pristine()
        return view

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
        ledger_view = ledger_view_for(state)
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
        if state.retained_ledger_prefix is not None and ledger_view_for(state) != ledger_view:
            raise AuthenticatedCrossLineageRunnerError(
                "retained runner ledger changed during replay"
            )
        trusted_lease_recheck(registry, capability, lease_snapshot)
        require_pristine()
        return result

    def revoke(capability: VerifiedCrossLineageRunnerCustody) -> None:
        """Permanently invalidate one runner lease and every retained child lease."""

        # Disposal is fail-safe: a mutated public binding must be reported, but it
        # must not keep an already-issued lease alive.  Snapshot the exact retained
        # runs, remove the parent first, then attempt every unique child revocation
        # even when an earlier child reports a failure.
        lease_snapshot = trusted_lease_snapshot(registry, capability)
        state = lease_snapshot.state
        failure: BaseException | None = None
        try:
            trusted_lease_revoke(registry, capability)
        except BaseException as exc:
            failure = exc
        try:
            trusted_child_inventory_revoke(
                campaigns=state.campaign_capabilities,
                generations=state.generation_capabilities,
                expected_campaign_count=state.run_count,
            )
        except BaseException as exc:
            if failure is None:
                failure = exc
        try:
            require_pristine()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if failure is not None:
            if not isinstance(failure, Exception):
                raise failure
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner child capability revocation was incomplete"
            ) from None

    # Transfer preserves its source's ledger lifetime. Only explicit retention
    # below binds a fully verified source to original-prefix accounting custody.
    transfer_pid = trusted_getpid()
    transfer_campaign = transfer_trusted_candidate_benchmark_campaign_verification
    transfer_generation = transfer_trusted_generation_verification
    transfer_replace = replace
    request_type = GenerationVerificationRequest
    transfer_objects = {
        "replace": transfer_replace,
        "GenerationVerificationRequest": request_type,
        "transfer_trusted_candidate_benchmark_campaign_verification": transfer_campaign,
        "transfer_trusted_generation_verification": transfer_generation,
    }
    transfer_functions = (
        transfer_campaign,
        transfer_generation,
        transfer_replace,
        CrossLineageRunnerRunCustody.__init__,
        RunnerState.__init__,
        request_type.__init__,
        require,
        revoke,
    )
    transfer_function_states = tuple(
        (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
        )
        for function in transfer_functions
    )

    def require_transfer_pristine() -> None:
        require_pristine()
        if (
            trusted_getpid() != transfer_pid
            or any(namespace.get(name) is not value for name, value in transfer_objects.items())
            or trusted_model_portfolio_module.transfer_trusted_candidate_benchmark_campaign_verification
            is not transfer_campaign
            or trusted_generation_evidence_module.transfer_trusted_generation_verification
            is not transfer_generation
            or trusted_generation_evidence_module.GenerationVerificationRequest is not request_type
            or CrossLineageRunnerRunCustody.__init__ is not transfer_functions[3]
            or RunnerState.__init__ is not transfer_functions[4]
            or request_type.__init__ is not transfer_functions[5]
            or any(
                function.__code__ is not code
                or function.__defaults__ is not defaults
                or function.__kwdefaults__ is not kwdefaults
                or tuple(sorted((function.__kwdefaults__ or {}).items())) != keyword_items
                for function, code, defaults, kwdefaults, keyword_items in transfer_function_states
            )
        ):
            raise AuthenticatedCrossLineageRunnerError(
                "authenticated runner custody transfer runtime is not pristine"
            )

    def generation_transfer_requests(
        run: CrossLineageRunnerRunCustody,
        *,
        candidate: bool,
    ) -> tuple[GenerationVerificationRequest, ...]:
        report = run.candidate_report if candidate else run.adjudication_report
        cases = (
            run.candidate_report.results[0].cases if candidate else run.adjudication_report.cases
        )
        if not 1 <= len(cases) <= 512:
            raise AuthenticatedCrossLineageRunnerError(
                "runner transfer exceeds the original generation proof bound"
            )
        requests: list[GenerationVerificationRequest] = []
        for case in cases:
            usage = case.usage_record
            if type(usage) is not UsageRecord:
                raise AuthenticatedCrossLineageRunnerError("runner transfer lacks original usage")
            target = run.adjudication_report.target
            requests.append(
                request_type(
                    benchmark_report_sha256=report.report_sha256,
                    case_id=case.case_id,
                    exact_model_id=(
                        run.candidate_report.results[0].target.model_id
                        if candidate
                        else target.judge_model_id
                    ),
                    canonical_model_id=(
                        required_routing_text(usage, "canonical_model")
                        if candidate
                        else target.judge_canonical_model_id
                    ),
                    catalog_identity_binding_sha256=(
                        required_routing_text(usage, "catalog_identity_binding_sha256")
                        if candidate
                        else target.judge_catalog_identity_binding_sha256
                    ),
                    discovery_evidence_sha256=(
                        required_routing_text(usage, "discovery_evidence_sha256")
                        if candidate
                        else target.judge_discovery_evidence_sha256
                    ),
                    expected_provider_name=(
                        required_routing_text(usage, "selected_provider_name")
                        if candidate
                        else target.judge_provider_name
                    ),
                    usage_record=usage,
                )
            )
        return tuple(requests)

    def transfer(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
    ) -> tuple[VerifiedCrossLineageRunnerCustody, tuple[CrossLineageRunnerRunCustody, ...]]:
        """Consume one runner and all children; publish only a fully replayed successor.

        This moves ownership, not freshness or the source's ledger lifetime. Original adapter
        scopes must not use it until they implement an authenticated handoff.
        A failed transaction never revives consumed custody or drops liabilities.
        """

        require_transfer_pristine()
        original_projection = require(capability, evidence=evidence)
        lease = trusted_lease_snapshot(registry, capability)
        state = lease.state
        requests = tuple(
            (
                generation_transfer_requests(run, candidate=True),
                generation_transfer_requests(run, candidate=False),
            )
            for run in state.runs
        )
        campaigns = list(state.campaign_capabilities)
        generations = list(state.generation_capabilities)
        require_transfer_pristine()
        trusted_lease_recheck(registry, capability, lease)
        # Only one caller can remove the source. No child move begins before it
        # succeeds; concurrent readers recheck this same one-way lease afterward.
        trusted_lease_revoke(registry, capability)
        successor: VerifiedCrossLineageRunnerCustody | None = None
        registered = False
        try:
            moved_runs: list[CrossLineageRunnerRunCustody] = []
            for index, run in enumerate(state.runs):
                require_transfer_pristine()
                campaigns[index] = transfer_campaign(
                    campaigns[index],
                    portfolio_sha256=run.candidate_portfolio.portfolio_sha256,
                    reports=run.candidate_campaign_reports,
                    policy_sha256=run.candidate_campaign_policy_sha256,
                    effective_config_sha256=run.candidate_campaign_effective_config_sha256,
                )
                for offset, exact_requests in enumerate(requests[index]):
                    child = index * 2 + offset
                    generations[child] = transfer_generation(
                        generations[child], requests=exact_requests
                    )
                moved_runs.append(
                    transfer_replace(
                        run,
                        candidate_campaign_verification=campaigns[index],
                        candidate_generation_verification=generations[index * 2],
                        judge_generation_verification=generations[index * 2 + 1],
                    )
                )
            retained = tuple(moved_runs)
            moved_state = transfer_replace(
                state,
                runs=retained,
                campaign_capabilities=tuple(campaigns),
                generation_capabilities=tuple(generations),
            )
            require_transfer_pristine()
            successor = trusted_object_new(trusted_runner_capability_type)
            registered = True
            trusted_lease_register(registry, successor, moved_state)
            successor_lease = trusted_lease_snapshot(registry, successor)
            if require(successor, evidence=evidence) != original_projection:
                raise AuthenticatedCrossLineageRunnerError(
                    "runner successor differs from its original verified projection"
                )
            require_transfer_pristine()
            trusted_lease_recheck(registry, successor, successor_lease)
        except BaseException as original:
            failure: BaseException | None = None
            if registered and successor is not None:
                try:
                    trusted_lease_revoke(registry, successor)
                except BaseException as exc:
                    failure = exc
            try:
                trusted_child_inventory_revoke(
                    campaigns=tuple(campaigns),
                    generations=tuple(generations),
                    expected_campaign_count=state.run_count,
                )
            except BaseException as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                if not isinstance(failure, Exception):
                    raise failure from None
                raise AuthenticatedCrossLineageRunnerError(
                    "authenticated runner transfer cleanup was incomplete"
                ) from original
            raise
        return successor, retained

    def retain(
        capability: VerifiedCrossLineageRunnerCustody,
        *,
        evidence: AuthenticatedCrossLineageRunnerEvidence,
        accounting: CalibrationLedgerAccounting,
    ) -> tuple[VerifiedCrossLineageRunnerCustody, tuple[CrossLineageRunnerRunCustody, ...]]:
        """Move verified custody into one originally captured ledger prefix, never data alone.

        Retention records real cost history before movement. A failed move does
        not erase that accounting fact or imply a completed candidate campaign.
        The accounting owner must remain live through every native consumption.
        """

        require_transfer_pristine()
        original = require(capability, evidence=evidence)
        lease = trusted_lease_snapshot(registry, capability)
        state = lease.state
        if state.retained_ledger_prefix is not None or state.retained_ledger_view is not None:
            raise AuthenticatedCrossLineageRunnerError("runner ledger custody is already retained")
        view = trusted_require_ledger(state.closed_ledger_interval)
        prefix = trusted_retain_interval(accounting, interval=state.closed_ledger_interval)
        require_transfer_pristine()
        trusted_lease_recheck(registry, capability, lease)
        successor, runs = transfer(capability, evidence=evidence)
        try:
            moved = trusted_lease_snapshot(registry, successor)
            retained_state = transfer_replace(
                moved.state, retained_ledger_prefix=prefix, retained_ledger_view=view
            )
            retained_lease = trusted_lease_replace(registry, successor, moved, retained_state)
            if require(successor, evidence=evidence) != original:
                raise AuthenticatedCrossLineageRunnerError(
                    "retained runner differs from its original verified projection"
                )
            require_transfer_pristine()
            trusted_lease_recheck(registry, successor, retained_lease)
        except BaseException as original_failure:
            failure: BaseException | None = None
            try:
                trusted_lease_revoke(registry, successor)
            except BaseException as exc:
                failure = exc
            try:
                trusted_child_inventory_revoke(
                    campaigns=tuple(
                        cast(
                            TrustedCandidateBenchmarkCampaignVerification,
                            run_child_capability(run, "candidate_campaign_verification"),
                        )
                        for run in runs
                    ),
                    generations=tuple(
                        cast(TrustedGenerationVerification, run_child_capability(run, name))
                        for run in runs
                        for name in (
                            "candidate_generation_verification",
                            "judge_generation_verification",
                        )
                    ),
                    expected_campaign_count=state.run_count,
                )
            except BaseException as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                if not isinstance(failure, Exception):
                    raise failure from None
                raise AuthenticatedCrossLineageRunnerError(
                    "retained runner cleanup was incomplete"
                ) from original_failure
            raise
        return successor, runs

    public_bindings.update(
        {
            "issue_verified_cross_lineage_runner_custody": issue,
            "require_verified_cross_lineage_runner_custody": require,
            "revoke_verified_cross_lineage_runner_custody": revoke,
            "transfer_verified_cross_lineage_runner_custody": transfer,
            "retain_verified_cross_lineage_runner_custody": retain,
        }
    )
    return issue, require, revoke, transfer, retain


(
    issue_verified_cross_lineage_runner_custody,
    require_verified_cross_lineage_runner_custody,
    revoke_verified_cross_lineage_runner_custody,
    transfer_verified_cross_lineage_runner_custody,
    retain_verified_cross_lineage_runner_custody,
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
    "retain_verified_cross_lineage_runner_custody",
    "revoke_verified_cross_lineage_runner_custody",
    "transfer_verified_cross_lineage_runner_custody",
]
