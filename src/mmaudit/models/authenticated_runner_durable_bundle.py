"""Strict, nonauthorizing durable bundle for authenticated runner evidence.

The bundle retains only typed evidence that can be replayed offline.  It cannot
recreate the PID-local runner capability, provider clients, credentials, secret
holders, or an authenticated execution result.  A valid bundle proves only that
its serialized objects and hashes are mutually consistent.
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from collections.abc import Mapping, Sequence
from decimal import Decimal, localcontext
from pathlib import Path
from typing import Annotated, Any, Final, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mmaudit.artifact_limits import MAX_JSON_ARTIFACT_BYTES
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationPreparedRun,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
)
from mmaudit.benchmark.models import ModelBenchmarkReport
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    AuthenticatedCrossLineageRunnerEvidence,
    AuthenticatedCrossLineageRunnerRunEvidence,
)
from mmaudit.models.authenticated_runner_cost_plan import (
    AuthenticatedRunnerCostPlanStage,
    AuthenticatedRunnerStagedCostPlan,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
    EvidenceSealLineageRole,
    EvidenceSealRunKind,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.models.token_planning import RequestTokenPlan
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence
from mmaudit.reporting.json_report import stable_json_bytes

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_REJECTION_KIND_PATTERN = r"^[A-Za-z][A-Za-z0-9_]{0,99}$"
_SAFE_ROUTING_KEY = re.compile(r"[a-z][a-z0-9_]{0,127}\Z")
_FORBIDDEN_ROUTING_KEY = re.compile(
    r"api_?key|api_?token|^(?!privacy_authorization\Z).*authorization(?:_?header)?|"
    r"bearer_?token|"
    r"(?:access|refresh|session|auth|authentication|oauth|id|csrf)_?token|"
    r"client_?secret|secret|credential|mnemonic|password|private_?key|"
    r"(?:session|auth|access|secret)_?key|cookie|session_?id|"
    r"(?:private|raw|repository)_?"
    r"(?:source|context)|source_?(?:code|content|text)|context_?"
    r"(?:package|payload|request_?evidence)$|provider_?visible|registry|"
    r"runner_?(?:authority|capability|custody)"
)
_DISALLOWED_ROUTING_KEYS = frozenset(
    {
        "api_key",
        "api_token",
        "authorization",
        "authorization_header",
        "bearer_token",
        "client_secret",
        "context",
        "context_package",
        "context_request_evidence",
        "credential",
        "credentials",
        "mnemonic",
        "opaque_capability",
        "password",
        "private_capability",
        "private_context",
        "private_key",
        "private_source",
        "private_source_code",
        "raw_private_source",
        "raw_source",
        "registry",
        "registry_state",
        "repository_context",
        "repository_source",
        "runner_authority",
        "runner_capability",
        "runner_custody",
        "secret",
        "secrets",
        "source",
        "source_code",
        "source_content",
        "source_text",
        "system_prompt",
        "token",
        "user_prompt",
        "verified_capability",
        "wallet_material",
        "provider_visible_payload",
        "provider_visible_prompt",
        "provider_visible_user_prompt",
    }
)
_MAX_ROUTING_DEPTH = 32
_MAX_ROUTING_NODES = 100_000
_MAX_ROUTING_STRING = 1_000_000
_MAX_ROUTING_LIST = 10_000
_MAX_ROUTING_PROPERTIES = 256
_MAX_SIGNED_INTEGER = 2**63 - 1
_MAX_SAFE_FLOAT = 1e18

AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT: Final[int] = 24
AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT: Final[int] = 2
AUTHENTICATED_RUNNER_DURABLE_MAX_ATTEMPTS: Final[int] = 32
AUTHENTICATED_RUNNER_DURABLE_ROUTING_KEYS: Final[tuple[str, ...]] = tuple(
    sorted(
        {
            "accepted_model_aliases",
            "atomic_request_limit_reservation",
            "atomic_request_limit_reservation_sha256",
            "atomic_request_limit_reservation_sha256s",
            "atomic_request_limit_reservations",
            "atomic_token_reservation",
            "atomic_token_reservation_sha256",
            "atomic_token_reservation_sha256s",
            "atomic_token_reservations",
            "audit_model_refresh_pricing_attempt",
            "audit_model_refresh_pricing_attempt_sha256",
            "audit_model_refresh_pricing_attempt_sha256s",
            "audit_model_refresh_pricing_attempts",
            "benchmark_report_sha256",
            "cached_tokens",
            "canonical_model",
            "catalog_identity_binding_sha256",
            "catalog_snapshot_sha256",
            "certification_request",
            "configured_provider_only",
            "configured_provider_order",
            "data_collection",
            "discovery_evidence_sha256",
            "discovery_provenance_sha256",
            "effective_privacy_policy_sha256",
            "endpoint_pricing_sha256",
            "endpoint_snapshot_sha256",
            "finish_reason",
            "generation_id",
            "host_model_fallback_used",
            "identity_binding",
            "identity_binding_sha256",
            "identity_binding_status",
            "identity_model_author",
            "identity_snapshot_expires_at",
            "identity_snapshot_sha256",
            "identity_strength",
            "latency_ms",
            "model_metadata_snapshot_sha256",
            "native_finish_reason",
            "output_capability_sha256",
            "privacy_authorization",
            "privacy_consent_expires_at",
            "privacy_consent_file_sha256",
            "privacy_consent_sha256",
            "privacy_endpoint_policy_class",
            "privacy_profile",
            "privacy_source_classification",
            "privacy_source_proof_kind",
            "privacy_source_provenance_sha256",
            "privacy_source_sha256",
            "production_selection_sha256",
            "provider",
            "provider_fallback_used",
            "provider_fallbacks_allowed",
            "provider_policy_sha256",
            "provisional_identity_strength",
            "qualification_artifact_sha256",
            "qualification_expires_at",
            "qualification_result_sha256",
            "qualification_verification_sha256",
            "qualification_verified_at",
            "qualified_canonical_model_slug",
            "qualified_endpoint_snapshot_sha256",
            "qualified_exact_model_id",
            "qualified_model_metadata_snapshot_sha256",
            "qualified_output_capability_sha256",
            "qualified_pricing_snapshot_sha256",
            "qualified_provider_endpoint",
            "qualified_provider_name",
            "qualified_reasoning_binding_sha256",
            "qualified_roles",
            "qualified_root_lineage",
            "qualified_structured_output_mode",
            "reasoning_tokens",
            "repair_evidence",
            "repair_request",
            "repair_used",
            "request_ended_at",
            "request_cost_preview_maximum_cost_usd_all_attempts_exact",
            "request_cost_preview_maximum_cost_usd_per_attempt_exact",
            "request_cost_preview_sha256",
            "request_started_at",
            "request_token_plan",
            "request_token_plan_sha256",
            "requested_model",
            "response_provider_identity",
            "router_attempt",
            "router_attempt_count",
            "router_attempts_observed",
            "router_metadata_sha256",
            "router_pipeline",
            "router_strategy",
            "schema_sha256",
            "selected_model",
            "selected_provider_endpoint",
            "selected_provider_identity",
            "selected_provider_name",
            "selection_verification_sha256",
            "structured_output",
            "structured_output_capability_sha256",
            "structured_output_mode",
            "structured_output_original_response_sha256",
            "structured_output_protocol_sha256",
            "structured_output_reasoning_request_sha256",
            "structured_output_request_body_sha256",
            "structured_output_request_shape_sha256",
            "structured_output_require_parameters",
            "structured_output_required_provider_parameters",
            "structured_output_response_format",
            "structured_output_supported_modes",
            "structured_output_validated_response_sha256",
            "validation_status",
            "zdr_requested",
        }
    )
)


class AuthenticatedRunnerDurableBundleError(ValueError):
    """Durable AUTHRUNNER objects are absent, unsafe, or not exactly joined."""


class _StrictFrozenEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        revalidate_instances="always",
    )


class AuthenticatedRunnerDurableRunEvidence(_StrictFrozenEvidence):
    """One ordered prepared request inventory and its completed judge report."""

    schema_version: Literal["1.0", "1.1"] = "1.0"
    run_kind: CrossLineageAdjudicationRunKind
    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan | None = None
    judge_cost_plan: AuthenticatedRunnerStagedCostPlan | None = None
    candidate_report: ModelBenchmarkReport
    prepared_run: CrossLineageAdjudicationPreparedRun
    adjudication_report: CrossLineageAdjudicationReport
    runner_run_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    run_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def prepared_and_report_evidence_is_exact(self) -> Self:
        candidate_report = _revalidate_model(
            self.candidate_report,
            ModelBenchmarkReport,
            label="candidate benchmark report",
        )
        prepared = _revalidate_model(
            self.prepared_run,
            CrossLineageAdjudicationPreparedRun,
            label="prepared adjudication",
        )
        report = _revalidate_model(
            self.adjudication_report,
            CrossLineageAdjudicationReport,
            label="adjudication report",
        )
        candidate_cost_plan = self.candidate_cost_plan
        judge_cost_plan = self.judge_cost_plan
        if self.schema_version == "1.0":
            if candidate_cost_plan is not None or judge_cost_plan is not None:
                raise ValueError("durable AUTHRUNNER v1.0 cannot carry staged cost plans")
        elif candidate_cost_plan is None or judge_cost_plan is None:
            raise ValueError("durable AUTHRUNNER v1.1 requires both staged cost plans")
        else:
            candidate_cost_plan = _revalidate_model(
                candidate_cost_plan,
                AuthenticatedRunnerStagedCostPlan,
                label="candidate staged cost plan",
            )
            judge_cost_plan = _revalidate_model(
                judge_cost_plan,
                AuthenticatedRunnerStagedCostPlan,
                label="judge staged cost plan",
            )
        if (
            prepared.run_kind is not self.run_kind
            or report.run_kind is not self.run_kind
            or report.target != prepared.target
            or report.prepared_run_sha256 != prepared.prepared_run_sha256
            or report.corpus_name != prepared.corpus_name
            or report.corpus_sha256 != prepared.corpus_sha256
            or report.ground_truth_sha256 != prepared.ground_truth_sha256
            or report.candidate_report_sha256 != prepared.candidate_report_sha256
            or candidate_report.report_sha256 != prepared.candidate_report_sha256
            or report.case_ids != prepared.case_ids
            or tuple(item.request for item in report.cases) != prepared.requests
        ):
            raise ValueError("durable adjudication report differs from its prepared run")
        _require_safe_candidate_report_routing(candidate_report)
        _require_safe_report_routing(report)
        if candidate_cost_plan is not None and judge_cost_plan is not None:
            if (
                candidate_cost_plan.run_kind is not self.run_kind
                or candidate_cost_plan.stage is not AuthenticatedRunnerCostPlanStage.CANDIDATE
                or judge_cost_plan.run_kind is not self.run_kind
                or judge_cost_plan.stage is not AuthenticatedRunnerCostPlanStage.JUDGE
            ):
                raise ValueError("durable staged cost plan differs from its run kind")
            _require_exact_cost_plan_report_join(
                candidate_cost_plan=candidate_cost_plan,
                judge_cost_plan=judge_cost_plan,
                candidate_report=candidate_report,
                adjudication_report=report,
            )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"run_bundle_sha256"}))
        if self.run_bundle_sha256 != expected:
            raise ValueError("durable AUTHRUNNER run-bundle hash is inconsistent")
        return self


class AuthenticatedRunnerAuthsealComplete(_StrictFrozenEvidence):
    """Bounded AUTHSEAL comparison inputs; they do not issue authority."""

    status: Literal["COMPLETE"] = "COMPLETE"
    collision_map: EvidenceSealCollisionMap
    decision_projections: tuple[EvidenceSealDecisionProjection, ...] = Field(
        min_length=2,
        max_length=2,
    )
    decision_projection_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    comparison_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        return _literal_false(value, label="AUTHSEAL comparison authority")

    @model_validator(mode="after")
    def comparison_is_ordered_and_self_hashed(self) -> Self:
        collision_map = _revalidate_model(
            self.collision_map,
            EvidenceSealCollisionMap,
            label="AUTHSEAL collision map",
        )
        projections = tuple(
            _revalidate_model(
                item,
                EvidenceSealDecisionProjection,
                label="AUTHSEAL decision projection",
            )
            for item in self.decision_projections
        )
        if tuple(item.run_kind for item in projections) != (
            EvidenceSealRunKind.PRIMARY,
            EvidenceSealRunKind.REPLAY,
        ):
            raise ValueError("AUTHSEAL decisions require exact PRIMARY then REPLAY order")
        if any(item.same_root for item in collision_map.pairs):
            raise ValueError("AUTHSEAL comparison contains a same-root judge")
        expected_set = canonical_sha256([item.model_dump(mode="json") for item in projections])
        if self.decision_projection_set_sha256 != expected_set:
            raise ValueError("AUTHSEAL decision-projection set hash is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"comparison_sha256"}))
        if self.comparison_sha256 != expected:
            raise ValueError("AUTHSEAL comparison hash is inconsistent")
        return self


class AuthenticatedRunnerAuthsealRejected(_StrictFrozenEvidence):
    """Type-only comparison failure with no provider or exception content."""

    status: Literal["REJECTED"] = "REJECTED"
    rejection_kind: str = Field(pattern=_REJECTION_KIND_PATTERN, max_length=100)
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    comparison_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def authority_is_literal_false(cls, value: object) -> object:
        return _literal_false(value, label="AUTHSEAL rejection authority")

    @model_validator(mode="after")
    def rejection_is_type_only_and_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"comparison_sha256"}))
        if self.comparison_sha256 != expected:
            raise ValueError("AUTHSEAL rejection hash is inconsistent")
        return self


AuthenticatedRunnerAuthsealComparison = Annotated[
    AuthenticatedRunnerAuthsealComplete | AuthenticatedRunnerAuthsealRejected,
    Field(discriminator="status"),
]


class AuthenticatedRunnerDurableEvidenceBundle(_StrictFrozenEvidence):
    """Complete offline AUTHRUNNER evidence that grants no serialized authority."""

    schema_version: Literal["1.0", "1.1"] = "1.0"
    runner_evidence: AuthenticatedCrossLineageRunnerEvidence
    runner_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    closed_ledger_evidence: AuthenticatedCrossLineageLedgerIntervalEvidence
    closed_ledger_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    runs: tuple[AuthenticatedRunnerDurableRunEvidence, ...] = Field(
        min_length=2,
        max_length=2,
    )
    authseal_comparison: AuthenticatedRunnerAuthsealComparison
    serialized_authority: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    runner_custody_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    benchmark_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    seal_publication_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "serialized_authority",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_custody_authorized",
        "authority_issuance_authorized",
        "benchmark_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        mode="before",
    )
    @classmethod
    def durable_authority_is_literal_false(cls, value: object) -> object:
        return _literal_false(value, label="durable AUTHRUNNER bundle authority")

    @model_validator(mode="after")
    def retained_evidence_is_exactly_joined(self) -> Self:
        evidence = _revalidate_model(
            self.runner_evidence,
            AuthenticatedCrossLineageRunnerEvidence,
            label="authenticated runner evidence",
        )
        ledger = _revalidate_model(
            self.closed_ledger_evidence,
            AuthenticatedCrossLineageLedgerIntervalEvidence,
            label="closed runner ledger evidence",
        )
        if (
            evidence.evidence_sha256 != self.runner_evidence_sha256
            or ledger != evidence.ledger_interval
            or canonical_sha256(ledger.model_dump(mode="json"))
            != self.closed_ledger_evidence_sha256
        ):
            raise ValueError("durable bundle differs from runner or closed-ledger evidence")
        if tuple(item.run_kind for item in self.runs) != (
            CrossLineageAdjudicationRunKind.PRIMARY,
            CrossLineageAdjudicationRunKind.REPLAY,
        ):
            raise ValueError("durable bundle requires exact PRIMARY then REPLAY order")
        expected_run_version = self.schema_version
        if any(item.schema_version != expected_run_version for item in self.runs):
            raise ValueError("durable bundle and run schema versions differ")
        _require_frozen_protocol_shape(evidence)
        for retained, run in zip(self.runs, evidence.runs, strict=True):
            _require_exact_run_join(retained=retained, run=run, evidence=evidence)
        _require_exact_ledger_join(evidence=evidence, ledger=ledger)
        if self.schema_version == "1.1":
            _require_exact_cost_plan_ledger_join(retained_runs=self.runs, ledger=ledger)
        _require_exact_authseal_join(
            comparison=self.authseal_comparison,
            evidence=evidence,
            retained_runs=self.runs,
        )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected:
            raise ValueError("durable AUTHRUNNER bundle hash is inconsistent")
        return self


def build_authenticated_runner_durable_bundle(
    *,
    runner_evidence: AuthenticatedCrossLineageRunnerEvidence,
    candidate_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...],
    judge_cost_plans: tuple[AuthenticatedRunnerStagedCostPlan, ...],
    candidate_reports: tuple[ModelBenchmarkReport, ...],
    prepared_runs: tuple[CrossLineageAdjudicationPreparedRun, ...],
    adjudication_reports: tuple[CrossLineageAdjudicationReport, ...],
    authseal_collision_map: EvidenceSealCollisionMap | None,
    authseal_decision_projections: tuple[EvidenceSealDecisionProjection, ...],
    authseal_rejection_kind: str | None,
) -> AuthenticatedRunnerDurableEvidenceBundle:
    """Build one exact two-run durable evidence bundle without runtime authority."""

    if (
        type(candidate_cost_plans) is not tuple
        or type(judge_cost_plans) is not tuple
        or type(candidate_reports) is not tuple
        or type(prepared_runs) is not tuple
        or type(adjudication_reports) is not tuple
    ):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER inputs must be exact ordered tuples"
        )
    if (
        len(candidate_cost_plans) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        or len(judge_cost_plans) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        or len(candidate_reports) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        or len(prepared_runs) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        or len(adjudication_reports) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
    ):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER requires exactly two retained runs"
        )
    try:
        evidence = _revalidate_model(
            runner_evidence,
            AuthenticatedCrossLineageRunnerEvidence,
            label="authenticated runner evidence",
        )
        _require_frozen_protocol_shape(evidence)
        retained_runs = tuple(
            _build_run_evidence(
                candidate_cost_plan=candidate_cost_plan,
                judge_cost_plan=judge_cost_plan,
                candidate_report=candidate_report,
                prepared=prepared,
                report=report,
                runner_run=runner_run,
            )
            for candidate_cost_plan, judge_cost_plan, candidate_report, prepared, report, runner_run in zip(
                candidate_cost_plans,
                judge_cost_plans,
                candidate_reports,
                prepared_runs,
                adjudication_reports,
                evidence.runs,
                strict=True,
            )
        )
        comparison = _build_authseal_comparison(
            collision_map=authseal_collision_map,
            decisions=authseal_decision_projections,
            rejection_kind=authseal_rejection_kind,
        )
        ledger = evidence.ledger_interval
        payload: dict[str, Any] = {
            "schema_version": "1.1",
            "runner_evidence": evidence,
            "runner_evidence_sha256": evidence.evidence_sha256,
            "closed_ledger_evidence": ledger,
            "closed_ledger_evidence_sha256": canonical_sha256(ledger.model_dump(mode="json")),
            "runs": retained_runs,
            "authseal_comparison": comparison,
            "serialized_authority": False,
            "provider_call_authorized": False,
            "source_egress_authorized": False,
            "runner_custody_authorized": False,
            "authority_issuance_authorized": False,
            "benchmark_authorized": False,
            "model_qualification_authorized": False,
            "production_selection_authorized": False,
            "seal_publication_authorized": False,
            "release_authorized": False,
        }
        bundle = AuthenticatedRunnerDurableEvidenceBundle(
            **payload,
            bundle_sha256=canonical_sha256(_json_payload(payload)),
        )
        authenticated_runner_durable_bundle_bytes(bundle)
    except AuthenticatedRunnerDurableBundleError:
        raise
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER bundle is invalid"
        ) from None
    return bundle


def authenticated_runner_durable_bundle_bytes(
    bundle: AuthenticatedRunnerDurableEvidenceBundle,
) -> bytes:
    """Return the sole canonical bounded UTF-8 representation of a bundle."""

    validated = _revalidate_model(
        bundle,
        AuthenticatedRunnerDurableEvidenceBundle,
        label="durable AUTHRUNNER bundle",
    )
    raw = stable_json_bytes(validated)
    if not raw or len(raw) > MAX_JSON_ARTIFACT_BYTES:
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER bundle exceeds its byte ceiling"
        )
    return raw


def revalidate_authenticated_runner_durable_bundle(
    raw: bytes,
) -> AuthenticatedRunnerDurableEvidenceBundle:
    """Strictly replay one canonical bounded bundle from untrusted bytes."""

    if type(raw) is not bytes or not raw or len(raw) > MAX_JSON_ARTIFACT_BYTES:
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER bytes are absent, non-exact, or over the byte ceiling"
        )
    try:
        # JSON timestamps are necessarily strings; the model-level strict contracts and
        # canonical byte equality below still reject every coercive alternate encoding.
        bundle = AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(raw)
    except (TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER bytes do not validate"
        ) from None
    if type(bundle) is not AuthenticatedRunnerDurableEvidenceBundle:
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER parser returned the wrong exact type"
        )
    if authenticated_runner_durable_bundle_bytes(bundle) != raw:
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER bytes are not canonically serialized"
        )
    return bundle


def load_authenticated_runner_durable_bundle(
    path: Path,
) -> AuthenticatedRunnerDurableEvidenceBundle:
    """Safely load one canonical private bundle without recreating runtime authority."""

    if not isinstance(path, Path) or not path.is_absolute() or not path.name:
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER path must be one absolute private file"
        )
    absolute = Path(os.path.abspath(path))
    try:
        parent_before = absolute.parent.lstat()
        file_before = absolute.lstat()
        if (
            not stat.S_ISDIR(parent_before.st_mode)
            or stat.S_IMODE(parent_before.st_mode) != 0o700
            or parent_before.st_uid != os.geteuid()
            or not stat.S_ISREG(file_before.st_mode)
            or stat.S_IMODE(file_before.st_mode) != 0o600
            or file_before.st_uid != os.geteuid()
            or file_before.st_nlink != 1
            or not 0 < file_before.st_size <= MAX_JSON_ARTIFACT_BYTES
        ):
            raise AuthenticatedRunnerDurableBundleError(
                "durable AUTHRUNNER file must be owned, private, regular, and unshared"
            )
        observation = read_json_evidence(
            evidence_root=absolute.parent,
            relative_path=absolute.name,
            max_bytes=MAX_JSON_ARTIFACT_BYTES,
        )
        parent_after = absolute.parent.lstat()
        file_after = absolute.lstat()
    except AuthenticatedRunnerDurableBundleError:
        raise
    except (OSError, ValueError):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER file is absent, unsafe, or changed"
        ) from None
    if (
        _file_identity(parent_before) != _file_identity(parent_after)
        or _file_identity(file_before) != _file_identity(file_after)
        or observation.binding.path != absolute.name
        or observation.binding.size != file_before.st_size
    ):
        raise AuthenticatedRunnerDurableBundleError(
            "durable AUTHRUNNER file changed during observation"
        )
    return revalidate_authenticated_runner_durable_bundle(observation.content)


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _build_run_evidence(
    *,
    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan | None,
    judge_cost_plan: AuthenticatedRunnerStagedCostPlan | None,
    candidate_report: ModelBenchmarkReport,
    prepared: CrossLineageAdjudicationPreparedRun,
    report: CrossLineageAdjudicationReport,
    runner_run: AuthenticatedCrossLineageRunnerRunEvidence,
) -> AuthenticatedRunnerDurableRunEvidence:
    if (candidate_cost_plan is None) != (judge_cost_plan is None):
        raise AuthenticatedRunnerDurableBundleError(
            "durable run requires both staged cost plans together"
        )
    if candidate_cost_plan is not None and judge_cost_plan is not None:
        candidate_cost_plan = _revalidate_model(
            candidate_cost_plan,
            AuthenticatedRunnerStagedCostPlan,
            label="candidate staged cost plan",
        )
        judge_cost_plan = _revalidate_model(
            judge_cost_plan,
            AuthenticatedRunnerStagedCostPlan,
            label="judge staged cost plan",
        )
    candidate_report = _revalidate_model(
        candidate_report,
        ModelBenchmarkReport,
        label="candidate benchmark report",
    )
    prepared = _revalidate_model(
        prepared,
        CrossLineageAdjudicationPreparedRun,
        label="prepared adjudication",
    )
    report = _revalidate_model(
        report,
        CrossLineageAdjudicationReport,
        label="adjudication report",
    )
    # Check flexible provider-routing evidence before a Pydantic error could render
    # an offending value into a caller-visible exception string.
    _require_safe_candidate_report_routing(candidate_report)
    _require_safe_report_routing(report)
    runner_run = _revalidate_model(
        runner_run,
        AuthenticatedCrossLineageRunnerRunEvidence,
        label="runner run evidence",
    )
    payload: dict[str, Any] = {
        "schema_version": "1.1" if candidate_cost_plan is not None else "1.0",
        "run_kind": prepared.run_kind,
        "candidate_cost_plan": candidate_cost_plan,
        "judge_cost_plan": judge_cost_plan,
        "candidate_report": candidate_report,
        "prepared_run": prepared,
        "adjudication_report": report,
        "runner_run_evidence_sha256": canonical_sha256(runner_run.model_dump(mode="json")),
    }
    return AuthenticatedRunnerDurableRunEvidence(
        **payload,
        run_bundle_sha256=canonical_sha256(_json_payload(payload)),
    )


def _build_authseal_comparison(
    *,
    collision_map: EvidenceSealCollisionMap | None,
    decisions: tuple[EvidenceSealDecisionProjection, ...],
    rejection_kind: str | None,
) -> AuthenticatedRunnerAuthsealComparison:
    if type(decisions) is not tuple:
        raise AuthenticatedRunnerDurableBundleError(
            "AUTHSEAL decision projections must be an exact tuple"
        )
    if rejection_kind is None:
        if type(collision_map) is not EvidenceSealCollisionMap or len(decisions) != 2:
            raise AuthenticatedRunnerDurableBundleError(
                "complete AUTHSEAL comparison requires a collision map and two decisions"
            )
        exact_collision = _revalidate_model(
            collision_map,
            EvidenceSealCollisionMap,
            label="AUTHSEAL collision map",
        )
        exact_decisions = tuple(
            _revalidate_model(
                item,
                EvidenceSealDecisionProjection,
                label="AUTHSEAL decision projection",
            )
            for item in decisions
        )
        payload: dict[str, Any] = {
            "status": "COMPLETE",
            "collision_map": exact_collision,
            "decision_projections": exact_decisions,
            "decision_projection_set_sha256": canonical_sha256(
                [item.model_dump(mode="json") for item in exact_decisions]
            ),
            "authority_issuance_authorized": False,
            "model_qualification_authorized": False,
            "production_selection_authorized": False,
            "seal_publication_authorized": False,
            "release_authorized": False,
        }
        return AuthenticatedRunnerAuthsealComplete(
            **payload,
            comparison_sha256=canonical_sha256(_json_payload(payload)),
        )
    if (
        type(rejection_kind) is not str
        or re.fullmatch(_REJECTION_KIND_PATTERN, rejection_kind) is None
        or collision_map is not None
        or decisions != ()
    ):
        raise AuthenticatedRunnerDurableBundleError(
            "AUTHSEAL rejection must contain only one bounded exception type"
        )
    rejected_payload: dict[str, Any] = {
        "status": "REJECTED",
        "rejection_kind": rejection_kind,
        "authority_issuance_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "seal_publication_authorized": False,
        "release_authorized": False,
    }
    return AuthenticatedRunnerAuthsealRejected(
        **rejected_payload,
        comparison_sha256=canonical_sha256(_json_payload(rejected_payload)),
    )


def _require_exact_run_join(
    *,
    retained: AuthenticatedRunnerDurableRunEvidence,
    run: AuthenticatedCrossLineageRunnerRunEvidence,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> None:
    candidate_report = retained.candidate_report
    prepared = retained.prepared_run
    report = retained.adjudication_report
    target = prepared.target
    if (
        retained.run_kind is not run.run_kind
        or retained.runner_run_evidence_sha256 != canonical_sha256(run.model_dump(mode="json"))
        or candidate_report.report_sha256 != run.candidate_report_sha256
        or prepared.prepared_run_sha256 != run.prepared_run_sha256
        or report.report_sha256 != run.adjudication_report_sha256
        or prepared.candidate_report_sha256 != run.candidate_report_sha256
        or target.candidate_model_id != run.candidate_model_id
        or target.candidate_root_lineage != run.candidate_root_lineage
        or target.judge_model_id != run.judge_model_id
        or target.judge_root_lineage != run.judge_root_lineage
        or target.public_lineage_bundle_sha256 != evidence.public_lineage_bundle_sha256
        or target.public_lineage_manifest_file_sha256
        != evidence.public_lineage_manifest_file_sha256
        or prepared.corpus_sha256 != evidence.benchmark_corpus_sha256
        or prepared.ground_truth_sha256 != evidence.benchmark_ground_truth_sha256
        or prepared.case_ids != evidence.case_ids
        or candidate_report.corpus_sha256 != evidence.benchmark_corpus_sha256
        or candidate_report.ground_truth_sha256 != evidence.benchmark_ground_truth_sha256
        or tuple(candidate_report.case_ids) != evidence.case_ids
        or len(candidate_report.results) != 1
    ):
        raise ValueError("retained adjudication differs from authenticated runner run hashes")
    candidate_result = candidate_report.results[0]
    if (
        candidate_report.execution_evidence is not ExecutionEvidenceKind.REAL
        or candidate_result.execution_evidence is not ExecutionEvidenceKind.REAL
        or candidate_result.target.model_id != run.candidate_model_id
        or candidate_result.target.root_lineage not in (None, run.candidate_root_lineage)
        or len(candidate_result.cases) != len(prepared.requests)
        or len(run.candidate_cases) != len(prepared.requests)
        or len(run.judge_cases) != len(report.cases)
    ):
        raise ValueError("retained adjudication case coverage differs from runner evidence")
    for report_case, request, candidate in zip(
        candidate_result.cases,
        prepared.requests,
        run.candidate_cases,
        strict=True,
    ):
        usage = report_case.usage_record
        generation = report_case.generation_evidence
        if usage is None or generation is None or report_case.validated_response_sha256 is None:
            raise ValueError("retained candidate report lacks exact REAL case evidence")
        expected_attempt_ids = tuple(
            usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
            for index in range(1, usage.attempts + 1)
        )
        if (
            request.case_id != candidate.case_id
            or report_case.case_id != candidate.case_id
            or request.candidate_case_result_sha256
            != canonical_sha256(report_case.model_dump(mode="json"))
            or request.candidate_usage_record_sha256
            != canonical_sha256(usage.model_dump(mode="json"))
            or request.candidate_request_body_sha256 != candidate.request_body_sha256
            or usage.request_body_sha256 != candidate.request_body_sha256
            or request.candidate_validated_response_sha256 != candidate.validated_response_sha256
            or report_case.validated_response_sha256 != candidate.validated_response_sha256
            or request.candidate_generation_evidence_sha256
            != candidate.generation_attestation_sha256
            or generation.evidence_sha256 != candidate.generation_attestation_sha256
            or generation.generation_id != candidate.generation_id
            or usage.request_id != candidate.request_id
            or usage.attempts != candidate.attempt_count
            or expected_attempt_ids != candidate.attempt_request_ids
            or usage.accounted_cost_usd_exact != candidate.accounted_cost_usd
        ):
            raise ValueError("prepared candidate case differs from runner execution evidence")
    for case, judge in zip(report.cases, run.judge_cases, strict=True):
        usage = case.usage_record
        expected_attempt_ids = tuple(
            usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
            for index in range(1, usage.attempts + 1)
        )
        if (
            case.case_id != judge.case_id
            or usage.request_id != judge.request_id
            or usage.attempts != judge.attempt_count
            or expected_attempt_ids != judge.attempt_request_ids
            or case.generation_evidence.generation_id != judge.generation_id
            or case.judge_request_body_sha256 != judge.request_body_sha256
            or case.judge_validated_response_sha256 != judge.validated_response_sha256
            or case.generation_evidence.evidence_sha256 != judge.generation_attestation_sha256
            or usage.accounted_cost_usd_exact != judge.accounted_cost_usd
        ):
            raise ValueError("retained judge case differs from runner execution evidence")


def _require_exact_cost_plan_report_join(
    *,
    candidate_cost_plan: AuthenticatedRunnerStagedCostPlan,
    judge_cost_plan: AuthenticatedRunnerStagedCostPlan,
    candidate_report: ModelBenchmarkReport,
    adjudication_report: CrossLineageAdjudicationReport,
) -> None:
    if len(candidate_report.results) != 1:
        raise ValueError("candidate cost plan lacks one exact report result")
    candidate_cases = candidate_report.results[0].cases
    judge_cases = adjudication_report.cases
    if (
        candidate_cost_plan.case_ids != tuple(item.case_id for item in candidate_cases)
        or judge_cost_plan.case_ids != tuple(item.case_id for item in judge_cases)
        or len(candidate_cost_plan.request_previews) != len(candidate_cases)
        or len(judge_cost_plan.request_previews) != len(judge_cases)
    ):
        raise ValueError("staged cost plans differ from durable report case coverage")
    for plan, usages in (
        (
            candidate_cost_plan,
            tuple(item.usage_record for item in candidate_cases),
        ),
        (
            judge_cost_plan,
            tuple(item.usage_record for item in judge_cases),
        ),
    ):
        if any(usage is None for usage in usages):
            raise ValueError("staged cost plan lacks one exact durable usage record")
        for preview, maybe_usage in zip(plan.request_previews, usages, strict=True):
            if maybe_usage is None:
                raise ValueError("staged cost plan lacks one exact durable usage record")
            usage = maybe_usage
            accounted = usage.accounted_cost_usd_exact
            token_plan = _durable_request_token_plan(usage.routing)
            reasoning_plan = token_plan.reasoning_plan
            if (
                usage.request_id != preview.logical_request_id
                or usage.role != preview.role
                or usage.requested_model != preview.exact_model_id
                or tuple(usage.configured_provider_endpoints) != (preview.provider_endpoint,)
                or usage.actual_provider_endpoint != preview.provider_endpoint
                or usage.prompt_sha256 != preview.prompt_sha256
                or usage.user_prompt_sha256 != preview.user_prompt_sha256
                or usage.schema_sha256 != preview.response_schema_sha256
                or not 1 <= usage.attempts <= preview.maximum_attempts
                or usage.routing.get("selected_provider_endpoint") != preview.provider_endpoint
                or usage.routing.get("discovery_evidence_sha256")
                != preview.discovery_evidence_sha256
                or usage.routing.get("discovery_provenance_sha256")
                != preview.discovery_provenance_sha256
                or usage.routing.get("catalog_snapshot_sha256") != preview.catalog_snapshot_sha256
                or usage.routing.get("catalog_identity_binding_sha256")
                != preview.catalog_identity_binding_sha256
                or usage.routing.get("model_metadata_snapshot_sha256")
                != preview.model_metadata_snapshot_sha256
                or usage.routing.get("identity_snapshot_sha256")
                != preview.model_identity_snapshot_sha256
                or usage.routing.get("endpoint_snapshot_sha256")
                != preview.endpoint_policy_snapshot_sha256
                or usage.routing.get("endpoint_pricing_sha256") != preview.endpoint_pricing_sha256
                or usage.routing.get("output_capability_sha256") != preview.output_capability_sha256
                or usage.routing.get("structured_output_mode")
                != preview.structured_output_mode.value
                or usage.routing.get("structured_output_request_shape_sha256")
                != preview.output_request_shape_sha256
                or canonical_sha256(
                    usage.routing.get("structured_output_required_provider_parameters")
                )
                != preview.required_provider_parameters_sha256
                or usage.routing.get("structured_output_protocol_sha256")
                != preview.strict_output_protocol_sha256
                or usage.routing.get("structured_output_reasoning_request_sha256")
                != preview.reasoning_request_sha256
                or usage.routing.get("request_cost_preview_sha256") != preview.preview_sha256
                or usage.routing.get("request_cost_preview_maximum_cost_usd_per_attempt_exact")
                != preview.maximum_cost_usd_per_attempt_exact
                or usage.routing.get("request_cost_preview_maximum_cost_usd_all_attempts_exact")
                != preview.maximum_cost_usd_all_attempts_exact
                or accounted is None
                or token_plan.request_id != preview.logical_request_id
                or token_plan.role != preview.role
                or token_plan.prompt_byte_upper_bound_tokens
                != preview.prompt_byte_upper_bound_tokens
                or token_plan.requested_completion_tokens != preview.requested_completion_tokens
                or token_plan.reserved_output_tokens != preview.reserved_output_tokens
                or token_plan.reserved_reasoning_tokens != preview.reserved_reasoning_tokens
                or reasoning_plan is None
                or reasoning_plan.evidence_sha256 != preview.reasoning_plan_sha256
                or reasoning_plan.policy_artifact_sha256 != preview.reasoning_policy_sha256
                or reasoning_plan.policy_role_binding_sha256
                != preview.reasoning_policy_role_binding_sha256
                or reasoning_plan.control_profile.profile_sha256 != preview.reasoning_profile_sha256
                or reasoning_plan.endpoint_capability_sha256 != preview.reasoning_capability_sha256
                or reasoning_plan.qualification_binding_sha256
                != preview.reasoning_qualification_sha256
                or Decimal(accounted)
                > Decimal(preview.maximum_cost_usd_per_attempt_exact) * Decimal(usage.attempts)
            ):
                raise ValueError("durable usage differs from its enforced request-cost preview")


def _durable_request_token_plan(routing: Mapping[str, Any]) -> RequestTokenPlan:
    raw = routing.get("request_token_plan")
    if not isinstance(raw, Mapping):
        raise ValueError("durable usage lacks its exact request token plan")
    try:
        plan = RequestTokenPlan.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
        )
    except (TypeError, ValueError, ValidationError):
        raise ValueError("durable usage request token plan is invalid") from None
    if routing.get("request_token_plan_sha256") != plan.plan_sha256:
        raise ValueError("durable usage request token plan hash is inconsistent")
    return plan


def _require_exact_cost_plan_ledger_join(
    *,
    retained_runs: tuple[AuthenticatedRunnerDurableRunEvidence, ...],
    ledger: AuthenticatedCrossLineageLedgerIntervalEvidence,
) -> None:
    entries = {item.request_id: item for item in ledger.entries}
    for retained in retained_runs:
        candidate_plan = retained.candidate_cost_plan
        judge_plan = retained.judge_cost_plan
        if candidate_plan is None or judge_plan is None:
            raise ValueError("current durable AUTHRUNNER bundle lacks staged cost plans")
        candidate_cases = retained.candidate_report.results[0].cases
        judge_cases = retained.adjudication_report.cases
        for plan, usages in (
            (candidate_plan, tuple(item.usage_record for item in candidate_cases)),
            (judge_plan, tuple(item.usage_record for item in judge_cases)),
        ):
            for preview, usage in zip(plan.request_previews, usages, strict=True):
                if usage is None:
                    raise ValueError("staged cost-plan ledger join lacks durable usage")
                expected_reservation = preview.maximum_cost_usd_per_attempt_exact
                attempt_ids = tuple(
                    usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
                    for index in range(1, usage.attempts + 1)
                )
                if any(
                    (entry := entries.get(request_id)) is None
                    or entry.reserved_usd != expected_reservation
                    or Decimal(entry.actual_cost_usd) > Decimal(expected_reservation)
                    for request_id in attempt_ids
                ):
                    raise ValueError(
                        "durable ledger reservation differs from its enforced request-cost preview"
                    )


def _require_frozen_protocol_shape(evidence: AuthenticatedCrossLineageRunnerEvidence) -> None:
    if (
        len(evidence.runs) != AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        or len(evidence.case_ids) != AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT
        or any(
            len(run.candidate_cases) != AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT
            or len(run.judge_cases) != AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT
            for run in evidence.runs
        )
        or not (
            AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT * AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT * 2
            <= len(evidence.ledger_interval.entries)
            <= AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
            * AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT
            * 2
            * AUTHENTICATED_RUNNER_DURABLE_MAX_ATTEMPTS
        )
    ):
        raise AuthenticatedRunnerDurableBundleError(
            "durable bundle differs from the frozen two-run 24-case protocol"
        )


def _require_exact_ledger_join(
    *,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
    ledger: AuthenticatedCrossLineageLedgerIntervalEvidence,
) -> None:
    cases = tuple(
        case
        for run in evidence.runs
        for inventory in (run.candidate_cases, run.judge_cases)
        for case in inventory
    )
    attempt_ids = tuple(attempt_id for case in cases for attempt_id in case.attempt_request_ids)
    if len(attempt_ids) != len(set(attempt_ids)):
        raise ValueError("durable runner evidence reuses a ledger attempt identity")
    entries_by_id = {item.request_id: item for item in ledger.entries}
    if tuple(sorted(attempt_ids)) != tuple(entries_by_id):
        raise ValueError("closed ledger differs from the exact durable runner attempts")
    for case in cases:
        with localcontext() as context:
            context.prec = 160
            observed = sum(
                (Decimal(entries_by_id[item].actual_cost_usd) for item in case.attempt_request_ids),
                start=Decimal(0),
            )
        if observed != Decimal(case.accounted_cost_usd):
            raise ValueError("closed ledger cost differs from durable runner case evidence")


def _require_exact_authseal_join(
    *,
    comparison: AuthenticatedRunnerAuthsealComparison,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
    retained_runs: tuple[AuthenticatedRunnerDurableRunEvidence, ...],
) -> None:
    if type(comparison) is AuthenticatedRunnerAuthsealRejected:
        return
    if type(comparison) is not AuthenticatedRunnerAuthsealComplete:
        raise ValueError("AUTHSEAL comparison has the wrong exact type")
    candidate_identities = {
        (item.candidate_model_id, item.candidate_root_lineage) for item in evidence.runs
    }
    if len(candidate_identities) != 1:
        raise ValueError("runner evidence has inconsistent AUTHSEAL candidate lineage")
    candidate_identity = next(iter(candidate_identities))
    collision = comparison.collision_map
    if (
        collision.candidate.role is not EvidenceSealLineageRole.CANDIDATE
        or (collision.candidate.exact_model_id, collision.candidate.root_lineage)
        != candidate_identity
    ):
        raise ValueError("AUTHSEAL collision map differs from the runner candidate")
    expected_judges = tuple(
        sorted((item.judge_model_id, item.judge_root_lineage) for item in evidence.runs)
    )
    observed_judges = tuple((item.exact_model_id, item.root_lineage) for item in collision.judges)
    if observed_judges != expected_judges:
        raise ValueError("AUTHSEAL collision map differs from runner judges")
    for projection, run, retained in zip(
        comparison.decision_projections,
        evidence.runs,
        retained_runs,
        strict=True,
    ):
        if (
            projection.run_kind.value != run.run_kind.value
            or projection.benchmark_report_sha256 != run.candidate_report_sha256
            or projection.benchmark_corpus_sha256 != evidence.benchmark_corpus_sha256
            or projection.benchmark_ground_truth_sha256 != evidence.benchmark_ground_truth_sha256
            or projection.ground_truth_provenance_sha256
            != evidence.frozen_ground_truth_provenance_sha256
            or (projection.candidate.exact_model_id, projection.candidate.root_lineage)
            != candidate_identity
            or projection.runner.role is not EvidenceSealLineageRole.JUDGE
            or (projection.runner.exact_model_id, projection.runner.root_lineage)
            != (run.judge_model_id, run.judge_root_lineage)
            or len(projection.case_outcome_sha256s) != len(evidence.case_ids)
        ):
            raise ValueError("AUTHSEAL decision projection differs from its runner run")
        _require_decision_matches_candidate_report(
            projection=projection,
            report=retained.candidate_report,
        )


def _require_decision_matches_candidate_report(
    *,
    projection: EvidenceSealDecisionProjection,
    report: ModelBenchmarkReport,
) -> None:
    if (
        report.execution_evidence is not ExecutionEvidenceKind.REAL
        or len(report.results) != 1
        or report.results[0].target.model_id != projection.candidate.exact_model_id
        or report.results[0].target.root_lineage not in (None, projection.candidate.root_lineage)
    ):
        raise ValueError("AUTHSEAL decision lacks its exact REAL candidate report")
    result = report.results[0]
    case_hashes = tuple(
        canonical_sha256(
            {
                "case_id": item.case_id,
                "validated_response_sha256": item.validated_response_sha256,
                "observed_classification": (
                    item.observed_classification.value
                    if item.observed_classification is not None
                    else None
                ),
                "observed_locations": [
                    value.model_dump(mode="json") for value in item.observed_locations
                ],
                "observed_invariant_kind": (
                    item.observed_invariant_kind.value
                    if item.observed_invariant_kind is not None
                    else None
                ),
                "dimensions": [value.model_dump(mode="json") for value in item.dimensions],
                "error_kind": item.error_kind,
            }
        )
        for item in result.cases
    )
    case_dimension_outcomes = tuple(
        {
            "case_id": case.case_id,
            "dimension": dimension.dimension.value,
            "passed": dimension.passed,
        }
        for case in result.cases
        for dimension in case.dimensions
    )
    case_dimension_hash = canonical_sha256(case_dimension_outcomes)
    dimension_hashes = tuple(
        canonical_sha256(item.model_dump(mode="json")) for item in result.dimensions
    )
    with localcontext() as context:
        context.prec = 160
        projected_score = Decimal(str(result.overall_score)) * Decimal(1_000_000)
    if projected_score != projected_score.to_integral_value():
        raise ValueError("candidate benchmark score is not exactly representable in micros")
    overall_micros = int(projected_score)
    deterministic_output = canonical_sha256(
        {
            "candidate_model_id": projection.candidate.exact_model_id,
            "candidate_root_lineage": projection.candidate.root_lineage,
            "benchmark_corpus_sha256": report.corpus_sha256,
            "benchmark_ground_truth_sha256": report.ground_truth_sha256,
            "case_outcome_sha256s": list(case_hashes),
            "case_dimension_outcome_set_sha256": case_dimension_hash,
            "dimension_score_sha256s": list(dimension_hashes),
            "overall_score_micros": overall_micros,
            "execution_evidence": report.execution_evidence.value,
        }
    )
    if (
        projection.case_outcome_sha256s != case_hashes
        or projection.case_dimension_outcome_set_sha256 != case_dimension_hash
        or projection.dimension_score_sha256s != dimension_hashes
        or projection.overall_score_micros != overall_micros
        or projection.execution_evidence != report.execution_evidence.value
        or projection.deterministic_output_sha256 != deterministic_output
    ):
        raise ValueError("AUTHSEAL decision differs from retained candidate scoring evidence")


def _require_safe_report_routing(report: CrossLineageAdjudicationReport) -> None:
    for case in report.cases:
        _require_safe_routing_value(case.usage_record.routing)


def _require_safe_candidate_report_routing(report: ModelBenchmarkReport) -> None:
    for result in report.results:
        for case in result.cases:
            if case.usage_record is None:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable candidate report lacks typed routing evidence"
                )
            _require_safe_routing_value(case.usage_record.routing)


def _require_safe_routing_value(value: object) -> None:
    if type(value) is not dict:
        raise AuthenticatedRunnerDurableBundleError(
            "durable routing contains a non-protocol top-level field"
        )
    for key in value:
        if type(key) is not str or _routing_key_is_sensitive(key):
            raise AuthenticatedRunnerDurableBundleError(
                "durable routing contains a sensitive field name"
            )
        if key not in AUTHENTICATED_RUNNER_DURABLE_ROUTING_KEYS:
            raise AuthenticatedRunnerDurableBundleError(
                "durable routing contains a non-protocol top-level field"
            )
    remaining: list[tuple[object, int]] = [(value, 0)]
    observed_nodes = 0
    while remaining:
        current, depth = remaining.pop()
        observed_nodes += 1
        if observed_nodes > _MAX_ROUTING_NODES or depth > _MAX_ROUTING_DEPTH:
            raise AuthenticatedRunnerDurableBundleError(
                "durable routing evidence exceeds its structural bounds"
            )
        if current is None or type(current) is bool:
            continue
        if type(current) is int:
            if not -_MAX_SIGNED_INTEGER - 1 <= current <= _MAX_SIGNED_INTEGER:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable routing integer exceeds its bound"
                )
            continue
        if type(current) is float:
            if not math.isfinite(current) or abs(current) > _MAX_SAFE_FLOAT:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable routing number exceeds its bound"
                )
            continue
        if type(current) is str:
            if len(current) > _MAX_ROUTING_STRING:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable routing string exceeds its bound"
                )
            continue
        if type(current) is list:
            if len(current) > _MAX_ROUTING_LIST:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable routing list exceeds its bound"
                )
            remaining.extend((item, depth + 1) for item in current)
            continue
        if type(current) is dict:
            if len(current) > _MAX_ROUTING_PROPERTIES:
                raise AuthenticatedRunnerDurableBundleError(
                    "durable routing object exceeds its bound"
                )
            for key, child in current.items():
                if type(key) is not str or _routing_key_is_sensitive(key):
                    raise AuthenticatedRunnerDurableBundleError(
                        "durable routing contains a sensitive field name"
                    )
                remaining.append((child, depth + 1))
            continue
        raise AuthenticatedRunnerDurableBundleError("durable routing contains a non-JSON value")


def _routing_key_is_sensitive(key: str) -> bool:
    return (
        _SAFE_ROUTING_KEY.fullmatch(key) is None
        or key in _DISALLOWED_ROUTING_KEYS
        or _FORBIDDEN_ROUTING_KEY.search(key) is not None
        or ("capability" in key and not key.endswith("_capability_sha256"))
    )


def _revalidate_model[ModelT: BaseModel](
    value: object,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT:
    if type(value) is not model:
        raise AuthenticatedRunnerDurableBundleError(f"{label} has the wrong exact type")
    try:
        raw = json.dumps(
            value.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        validated = model.model_validate_json(raw)
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise AuthenticatedRunnerDurableBundleError(f"{label} does not revalidate") from None
    if type(validated) is not model:
        raise AuthenticatedRunnerDurableBundleError(f"{label} revalidated to the wrong type")
    return validated


def _literal_false(value: object, *, label: str) -> object:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label} must be literal false")
    return value


def _json_payload(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: item.model_dump(mode="json") if isinstance(item, BaseModel) else _json_value(item)
        for key, item in value.items()
    }


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_value(item) for item in value]
    return value


__all__ = [
    "AuthenticatedRunnerAuthsealComparison",
    "AuthenticatedRunnerAuthsealComplete",
    "AuthenticatedRunnerAuthsealRejected",
    "AuthenticatedRunnerDurableBundleError",
    "AuthenticatedRunnerDurableEvidenceBundle",
    "AuthenticatedRunnerDurableRunEvidence",
    "authenticated_runner_durable_bundle_bytes",
    "build_authenticated_runner_durable_bundle",
    "load_authenticated_runner_durable_bundle",
    "revalidate_authenticated_runner_durable_bundle",
]
