"""Auditable contract for the maximum-assurance profile.

The profile name is never treated as proof that a deep audit occurred.  This
module converts actual engine results into explicit, machine-readable clauses.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, SupportsIndex

from mmaudit.agents.specialists import canonical_specialist_role, completed_specialist_roles
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
)
from mmaudit.config import AuditConfig, model_family, model_lineage_index
from mmaudit.constants import (
    ALL_SPECIALIST_ROLES,
    CANDIDATE_DEPENDENT_SPECIALIST_ROLES,
    CANDIDATE_INDEPENDENT_SPECIALIST_ROLES,
    SPECIALIST_AUXILIARY_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.policy_selection import (
    AuditModelRoutingEvidence,
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
)
from mmaudit.models.qualification import (
    VerifiedProductionQualification,
    VerifiedTierAModelQualification,
    usage_matches_verified_reasoning_qualification_route,
)
from mmaudit.models.reasoning import (
    ReasoningPolicyError,
    resolve_reasoning_request_role,
)
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshEvidence,
    AuditModelRefreshPricingEvidence,
    AuditModelRefreshPricingRouteEvidence,
    AuditModelRefreshRouteEvidence,
    VerifiedAuditModelRefreshGuard,
    VerifiedAuditModelRefreshPricingAuthority,
)
from mmaudit.models.scheduler import (
    SchedulerArtifact,
    SchedulerAuditModelRefreshBinding,
    SchedulerAuditModelRefreshPricingBinding,
    SchedulerAuditModelSelectionBinding,
    SchedulerBindings,
    SchedulerCampaignStatus,
    SchedulerCostLedgerBaseline,
    SchedulerModelRequestEvidence,
    SchedulerScope,
    SchedulerShardInventory,
    SchedulerTerminalStatus,
    SchedulerTruncationRecoveryModelRequestEvidence,
    SchedulerTruncationRecoveryPromotionDisposition,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditScope,
    AuditScopeAssessment,
    CandidateReproductionResolution,
    CompilationStatus,
    ContextPackage,
    ContextRequestEvidence,
    EconomicSimulationPlan,
    ExecutionEvidenceKind,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantSuite,
    KnownIssueTaxonomyCoverage,
    LanguageCapabilityAssessment,
    LanguageCapabilityProfile,
    LanguageCapabilityStatus,
    MaximumAssuranceAssessment,
    MaximumAssuranceRequirement,
    MaximumAssuranceStatus,
    ModelReviewCoverage,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewStatus,
    RepositoryCodeExecutionState,
    RepositorySuiteInventoryKind,
    RepositorySuiteInventoryPhase,
    RepositoryTestExecutionStatus,
    RepositoryTestKind,
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    ScannerRun,
    ScannerStatus,
    ScopeEvidenceStatus,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphKind,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    SpecialistExecutionRecord,
    UsageRecord,
    audit_model_refresh_guard_capability_projection_sha256,
    validate_audit_model_refresh_pricing_usage_custody,
)
from mmaudit.models.usage import (
    candidate_falsifier_role_prefix,
    is_accountable_usage_record,
    is_creditable_usage_record,
    is_recovery_accountable_usage_record,
    is_recovery_creditable_usage_record,
    source_backed_whole_protocol_context,
    usage_requires_audit_policy_evidence,
)
from mmaudit.orchestration.replay import (
    OfflineReplay,
    OfflineReplayStatus,
    ReplayComponentKind,
    ReplayComponentStatus,
)
from mmaudit.solidity.economics import plan_economic_simulations
from mmaudit.traceability import (
    ImplementationStatus,
    MaximumAssuranceTraceability,
)

if TYPE_CHECKING:
    from mmaudit.orchestration.truncation_recovery_evidence import (
        VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage,
        VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverageProjection,
        VerifiedPromotedTruncationRecoverySurfaceCoverage,
        VerifiedPromotedTruncationRecoverySurfaceCoverageProjection,
    )

FULL_SEMANTIC_GRAPHS: frozenset[SolidityGraphKind] = frozenset(
    {
        SolidityGraphKind.INHERITANCE,
        SolidityGraphKind.MODIFIER,
        SolidityGraphKind.INTERNAL_CALL,
        SolidityGraphKind.EXTERNAL_CALL,
        SolidityGraphKind.LOW_LEVEL_CALL,
        SolidityGraphKind.DELEGATECALL,
        SolidityGraphKind.CONTRACT_CREATION,
        SolidityGraphKind.STATE_READ,
        SolidityGraphKind.STATE_WRITE,
        SolidityGraphKind.STATE_DEPENDENCY,
        SolidityGraphKind.ASSET_FLOW,
        SolidityGraphKind.PRIVILEGE,
        SolidityGraphKind.PROXY,
        SolidityGraphKind.STORAGE_LAYOUT,
        SolidityGraphKind.UPGRADE_COMPATIBILITY,
        SolidityGraphKind.INITIALIZER,
        SolidityGraphKind.ORACLE_DEPENDENCY,
        SolidityGraphKind.EVENT_STATE,
        SolidityGraphKind.SIGNATURE_REPLAY,
        SolidityGraphKind.REENTRANCY,
        SolidityGraphKind.SENSITIVE_REACHABILITY,
    }
)

CERTIFIED_PROPERTY_ENGINES: frozenset[str] = frozenset({"echidna", "medusa", "halmos"})
CERTIFIED_FORMAL_PROOF_ENGINES: frozenset[str] = frozenset(
    {"certora", "kontrol", "solc-smtchecker"}
)
CERTIFIED_ISOLATION_BACKENDS: frozenset[str] = frozenset({"bubblewrap", "sandbox-exec"})
CERTIFIED_ENSEMBLE_MIN_EXACT_MODELS = 8
CERTIFIED_ENSEMBLE_MIN_ROOT_LINEAGES = 6
CERTIFIED_ENSEMBLE_MIN_SPECIALIST_RESPONSIBILITIES = 24
CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES = 4
CERTIFIED_ENSEMBLE_MIN_CRITICAL_SURFACE_LINEAGES = 3
CERTIFIED_ENSEMBLE_MIN_FALSIFIER_LINEAGES = 2
if (
    len(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)
    != CERTIFIED_ENSEMBLE_MIN_SPECIALIST_RESPONSIBILITIES
):
    raise RuntimeError(
        "certified specialist minimum must equal the frozen candidate-independent portfolio"
    )

_PROVIDER_SESSION_PROVENANCE_ISSUER = object()


@dataclass(frozen=True, slots=True, init=False)
class ProviderSessionProvenance:
    """Bound one audit's model usage to its provider-client execution class."""

    _issuer: object
    execution_evidence: ExecutionEvidenceKind
    pipeline_owned: bool
    trusted_concrete_client: bool
    usage_evidence_consistent: bool

    def __new__(cls, issuer: object | None = None) -> ProviderSessionProvenance:
        if issuer is not _PROVIDER_SESSION_PROVENANCE_ISSUER:
            raise TypeError(
                "provider session provenance can only be issued by the pipeline boundary"
            )
        return object.__new__(cls)

    def __init__(self, issuer: object | None = None) -> None:
        del issuer

    @property
    def permits_real_model_credit(self) -> bool:
        """Return whether this session may contribute REAL model evidence."""

        return (
            self._issuer is _PROVIDER_SESSION_PROVENANCE_ISSUER
            and self.execution_evidence is ExecutionEvidenceKind.REAL
            and self.pipeline_owned
            and self.trusted_concrete_client
            and self.usage_evidence_consistent
        )

    def __reduce__(self) -> Never:
        raise TypeError("provider session provenance cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("provider session provenance cannot be serialized")


def _issue_provider_session_provenance(
    *,
    execution_evidence: ExecutionEvidenceKind,
    pipeline_owned: bool,
    trusted_concrete_client: bool,
    usage_evidence_consistent: bool,
) -> ProviderSessionProvenance:
    """Issue one in-memory capability from facts derived at the pipeline boundary."""

    if type(execution_evidence) is not ExecutionEvidenceKind:
        raise TypeError("provider session execution evidence has an invalid type")
    capability = ProviderSessionProvenance(_PROVIDER_SESSION_PROVENANCE_ISSUER)
    object.__setattr__(capability, "_issuer", _PROVIDER_SESSION_PROVENANCE_ISSUER)
    object.__setattr__(capability, "execution_evidence", execution_evidence)
    object.__setattr__(capability, "pipeline_owned", pipeline_owned)
    object.__setattr__(capability, "trusted_concrete_client", trusted_concrete_client)
    object.__setattr__(
        capability,
        "usage_evidence_consistent",
        usage_evidence_consistent,
    )
    return capability


@dataclass(frozen=True)
class AssuranceRuntime:
    """Only deterministic execution facts used to evaluate the contract."""

    repository_execution_sha256: str | None = None
    projects: list[SolidityProjectMetadata] = field(default_factory=list)
    compilations: list[SolidityCompilationResult] = field(default_factory=list)
    index: SoliditySymbolIndex | None = None
    graphs: SolidityGraphSet | None = None
    scanners: list[ScannerRun] = field(default_factory=list)
    invariants: InvariantSuite | None = None
    expected_invariant_harnesses: set[tuple[str, str, str]] = field(default_factory=set)
    invariant_executions: list[InvariantExecutionResult] = field(default_factory=list)
    economic_simulations: list[EconomicSimulationPlan] = field(default_factory=list)
    formal_runs: list[FormalToolRun] = field(default_factory=list)
    property_corpus_sha256: str | None = None
    property_corpus_property_ids: set[str] = field(default_factory=set)
    property_corpus_property_hashes: dict[str, str] = field(default_factory=dict)
    reproduction_results: list[ReproductionResult] = field(default_factory=list)
    reproduction_resolutions: list[CandidateReproductionResolution] = field(default_factory=list)
    eligible_high_critical_ids: set[str] = field(default_factory=set)
    feasible_high_critical_ids: set[str] = field(default_factory=set)
    documented_infeasible_ids: set[str] = field(default_factory=set)
    model_roles_completed: set[str] = field(default_factory=set)
    specialist_roles_completed: set[str] = field(default_factory=set)
    auxiliary_roles_completed: set[str] = field(default_factory=set)
    specialist_execution_records: list[SpecialistExecutionRecord] = field(default_factory=list)
    verifier_completed: bool = False
    falsifier_completed: bool = False
    candidate_falsifier_request_ids: dict[str, set[str]] = field(default_factory=dict)
    judge_completed: bool = False
    coverage: SolidityCoverage | None = None
    model_review_coverage: ModelReviewCoverage | None = None
    taxonomy_coverage: KnownIssueTaxonomyCoverage | None = None
    model_surface_review_artifacts: list[ModelSurfaceReviewArtifact] = field(default_factory=list)
    promoted_truncation_recovery_surface_coverages: list[
        VerifiedPromotedTruncationRecoverySurfaceCoverage
    ] = field(default_factory=list)
    promoted_recursive_recovery_surface_coverages: list[
        VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage
    ] = field(default_factory=list)
    model_usage: list[UsageRecord] = field(default_factory=list)
    provider_session: ProviderSessionProvenance | None = None
    production_qualification: VerifiedProductionQualification | None = None
    audit_model_selection_evidence: AuditModelSelectionEvidenceBundle | None = None
    verified_audit_model_selection: VerifiedAuditModelSelection | None = None
    audit_model_refresh_evidence: AuditModelRefreshEvidence | None = None
    audit_model_refresh_guard: VerifiedAuditModelRefreshGuard | None = None
    audit_model_refresh_pricing_evidence: AuditModelRefreshPricingEvidence | None = None
    audit_model_refresh_pricing_authority: VerifiedAuditModelRefreshPricingAuthority | None = None
    language_capability: LanguageCapabilityAssessment | None = None
    scope_assessment: AuditScopeAssessment | None = None
    benchmark_verification: BenchmarkCertificateVerification | None = None
    benchmark_repository_git_commit: str | None = None
    offline_replay: OfflineReplay | None = None
    replay_run_id: str | None = None
    replay_manifest_sha256: str | None = None
    replay_verification_sha256: str | None = None
    isolation_available: bool = False
    scanner_only: bool = False
    artifacts: set[str] = field(default_factory=set)
    traceability: MaximumAssuranceTraceability | None = None
    scheduler_artifact: SchedulerArtifact | None = None
    expected_scheduler_bindings: SchedulerBindings | None = None
    expected_scheduler_analysis_input_sha256: str | None = None
    expected_scheduler_shard_inventory: SchedulerShardInventory | None = None
    expected_scheduler_cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None


@dataclass(frozen=True, slots=True)
class _CurrentAuditModelSelection:
    """Independently revalidated policy selection used only for assurance comparison."""

    evidence_bundle: AuditModelSelectionEvidenceBundle
    capability: VerifiedAuditModelSelection
    binding: SchedulerAuditModelSelectionBinding
    selected_model_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CurrentAuditModelRefresh:
    """Current durable refresh comparison joined to independent live selections.

    This projection deliberately excludes the opaque refresh guard and grants no routing,
    provider-access, promotion, or pricing authority.
    """

    evidence: AuditModelRefreshEvidence
    binding: SchedulerAuditModelRefreshBinding
    audit_model_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class _CurrentAuditModelRefreshPricing:
    """Current live pricing authority plus its non-authorizing scheduler projection."""

    evidence: AuditModelRefreshPricingEvidence
    authority: VerifiedAuditModelRefreshPricingAuthority
    binding: SchedulerAuditModelRefreshPricingBinding
    audit_model_ids: frozenset[str]


def _routing_evidence_matches_audit_selection(
    evidence: AuditModelRoutingEvidence,
    binding: SchedulerAuditModelSelectionBinding,
) -> bool:
    try:
        route = binding.route_for(evidence.route.exact_model_id)
    except ValueError:
        return False
    return (
        evidence.audit_model_selection_bundle_sha256 == binding.audit_model_selection_bundle_sha256
        and evidence.audit_selection_sha256 == binding.audit_selection_sha256
        and evidence.selected_model_set_sha256 == binding.selected_model_set_sha256
        and evidence.audit_scope_sha256 == binding.audit_scope_sha256
        and evidence.source_sha256 == binding.source_sha256
        and evidence.audit_context_sha256 == binding.audit_context_sha256
        and evidence.client_constraints_sha256 == binding.client_constraints_sha256
        and evidence.intended_use.value == binding.intended_use
        and evidence.technical_production_selection_sha256
        == binding.technical_production_selection_sha256
        and evidence.technical_qualification_capability_sha256
        == binding.technical_qualification_capability_sha256
        and evidence.policy_artifact_sha256 == binding.policy_artifact_sha256
        and evidence.policy_evaluation_sha256 == binding.policy_evaluation_sha256
        and evidence.policy_authority_receipt_sha256 == binding.policy_authority_receipt_sha256
        and evidence.policy_authority_statement_sha256 == binding.policy_authority_statement_sha256
        and evidence.policy_authority_envelope_sha256 == binding.policy_authority_envelope_sha256
        and evidence.policy_authority_trust_anchor_sha256
        == binding.policy_authority_trust_anchor_sha256
        and evidence.policy_source_observation_sha256 == binding.policy_source_observation_sha256
        and evidence.policy_source_commitment_set_sha256
        == binding.policy_source_commitment_set_sha256
        and evidence.expires_at == binding.selection_expires_at
        and evidence.route.provider_name == route.provider_name
        and evidence.route.provider_endpoint == route.provider_endpoint
        and evidence.route.route_sha256 == route.policy_route_sha256
        and evidence.selected_model_sha256 == route.selected_model_sha256
    )


def _current_audit_model_selection(
    evidence_bundle: AuditModelSelectionEvidenceBundle | None,
    capability: VerifiedAuditModelSelection | None,
    technical_qualification: VerifiedProductionQualification | None,
) -> _CurrentAuditModelSelection | None:
    """Return a current opaque authority joined to the exact durable policy bundle."""

    if (
        type(evidence_bundle) is not AuditModelSelectionEvidenceBundle
        or type(capability) is not VerifiedAuditModelSelection
        or type(technical_qualification) is not VerifiedProductionQualification
    ):
        return None
    try:
        bundle = AuditModelSelectionEvidenceBundle.model_validate_json(
            evidence_bundle.model_dump_json(),
            strict=True,
        )
        selection = bundle.selection
        now = datetime.now(UTC).replace(microsecond=0)
        technical_qualification.require_current(now=now)
        if (
            selection.technical_qualification_capability_sha256
            != technical_qualification.capability_sha256
            or selection.technical_qualification_artifact_sha256
            != technical_qualification.artifact_sha256
            or selection.technical_qualification_verification_sha256
            != technical_qualification.qualification_verification_sha256
            or selection.technical_production_selection_sha256
            != technical_qualification.production_selection_sha256
            or selection.technical_selection_verification_sha256
            != technical_qualification.selection_verification_sha256
            or selection.technical_production_effective_config_sha256
            != technical_qualification.production_effective_config_sha256
            or selection.technical_candidate_registry_sha256
            != technical_qualification.candidate_registry_sha256
            or selection.technical_qualification_policy_sha256
            != technical_qualification.policy_sha256
            or selection.technical_release_observation_sha256
            != technical_qualification.release_observation_sha256
        ):
            return None
        capability.require_current(
            now=now,
            expected_audit_scope_sha256=selection.audit_scope_sha256,
            expected_source_sha256=selection.source_sha256,
            expected_audit_context_sha256=selection.audit_context_sha256,
            expected_client_constraints_sha256=selection.client_constraints_sha256,
        )
        binding = SchedulerAuditModelSelectionBinding.from_evidence_bundle(bundle)
        selected_ids = frozenset(selection.selected_model_ids)
        if (
            selected_ids != frozenset(model.exact_model_id for model in capability.models)
            or selected_ids != frozenset(binding.selected_model_ids)
            or selection.expires_at <= now
        ):
            return None
        capability_by_id = {model.exact_model_id: model for model in capability.models}
        if any(
            capability_by_id[model.exact_model_id].root_lineage != model.root_lineage
            or capability_by_id[model.exact_model_id].approved_provider_name
            != model.approved_provider_name
            or capability_by_id[model.exact_model_id].approved_provider_endpoint
            != model.approved_provider_endpoint
            for model in selection.models
        ):
            return None
        routing = capability.routing_evidence(
            binding.selected_model_ids[0],
            now=now,
            expected_audit_scope_sha256=selection.audit_scope_sha256,
            expected_source_sha256=selection.source_sha256,
            expected_audit_context_sha256=selection.audit_context_sha256,
            expected_client_constraints_sha256=selection.client_constraints_sha256,
        )
        if not _routing_evidence_matches_audit_selection(routing, binding):
            return None
    except (TypeError, ValueError):
        return None
    return _CurrentAuditModelSelection(
        evidence_bundle=bundle,
        capability=capability,
        binding=binding,
        selected_model_ids=selected_ids,
    )


def _usage_audit_routing_evidence(record: UsageRecord) -> AuditModelRoutingEvidence | None:
    raw = record.routing.get("audit_model_routing_evidence")
    if not isinstance(raw, dict):
        return None
    try:
        evidence = AuditModelRoutingEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError):
        return None
    if evidence.model_dump(mode="json") != raw:
        return None
    metadata = dict(evidence.request_metadata())
    routing_sha256 = metadata.pop("routing_evidence_sha256")
    if record.routing.get("audit_policy_routing_evidence_sha256") != routing_sha256 or any(
        record.routing.get(key) != value for key, value in metadata.items()
    ):
        return None
    return evidence


def _usage_matches_audit_model_selection(
    record: UsageRecord,
    selection: _CurrentAuditModelSelection | None,
) -> bool:
    if selection is None or not usage_requires_audit_policy_evidence(record):
        return False
    evidence = _usage_audit_routing_evidence(record)
    if evidence is None or not _routing_evidence_matches_audit_selection(
        evidence,
        selection.binding,
    ):
        return False
    try:
        route = selection.binding.route_for(record.requested_model)
    except ValueError:
        return False
    return (
        evidence.route.exact_model_id == record.requested_model
        and record.provider == route.provider_name
        and record.actual_provider_endpoint == route.provider_endpoint
        and record.started_at is not None
        and record.ended_at is not None
        and record.started_at >= selection.capability.selected_at
        and record.started_at < selection.binding.selection_expires_at
        and record.ended_at >= record.started_at
    )


def _current_audit_model_refresh(
    evidence: AuditModelRefreshEvidence | None,
    guard: VerifiedAuditModelRefreshGuard | None,
    technical_qualification: VerifiedProductionQualification | None,
    audit_selection: _CurrentAuditModelSelection | None,
) -> _CurrentAuditModelRefresh | None:
    """Return current comparison custody joined to independently live selections."""

    if (
        type(evidence) is not AuditModelRefreshEvidence
        or type(guard) is not VerifiedAuditModelRefreshGuard
        or type(technical_qualification) is not VerifiedProductionQualification
        or audit_selection is None
    ):
        return None
    try:
        canonical = AuditModelRefreshEvidence.model_validate_json(
            evidence.model_dump_json(),
            strict=True,
        )
        now = datetime.now(UTC).replace(microsecond=0)
        technical_qualification.require_current(now=now)
        audit_selection.capability.require_current(
            now=now,
            expected_audit_scope_sha256=canonical.audit_scope_sha256,
            expected_source_sha256=canonical.source_sha256,
            expected_audit_context_sha256=canonical.audit_context_sha256,
            expected_client_constraints_sha256=canonical.client_constraints_sha256,
        )
        guard.require_current(
            now=now,
            expected_workflow_status_sha256=canonical.expected_workflow_status_sha256,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection.capability,
            expected_audit_scope_sha256=canonical.audit_scope_sha256,
            expected_source_sha256=canonical.source_sha256,
            expected_audit_context_sha256=canonical.audit_context_sha256,
            expected_client_constraints_sha256=canonical.client_constraints_sha256,
        )
        binding = SchedulerAuditModelRefreshBinding.from_evidence(canonical)
    except (AttributeError, TypeError, ValueError):
        return None
    technical_by_id = {model.exact_model_id: model for model in technical_qualification.models}
    refresh_by_id = {route.exact_model_id: route for route in canonical.routes}
    if (
        canonical != evidence
        or now < canonical.verified_at
        or now >= canonical.expires_at
        or guard.evidence_sha256 != canonical.evidence_sha256
        or guard.capability_sha256 != binding.guard_capability_sha256
        or canonical.expected_workflow_status_sha256 != canonical.workflow_status_sha256
        or canonical.technical_qualification_capability_sha256
        != technical_qualification.capability_sha256
        or canonical.technical_production_selection_sha256
        != technical_qualification.production_selection_sha256
        or canonical.technical_candidate_registry_sha256
        != technical_qualification.candidate_registry_sha256
        or canonical.technical_qualification_expires_at != technical_qualification.expires_at
        or canonical.audit_selection_capability_sha256
        != audit_selection.capability.capability_sha256
        or canonical.audit_selection_sha256 != audit_selection.binding.audit_selection_sha256
        or canonical.audit_selection_expires_at != audit_selection.binding.selection_expires_at
        or canonical.audit_scope_sha256 != audit_selection.binding.audit_scope_sha256
        or canonical.source_sha256 != audit_selection.binding.source_sha256
        or canonical.audit_context_sha256 != audit_selection.binding.audit_context_sha256
        or canonical.client_constraints_sha256 != audit_selection.binding.client_constraints_sha256
        or canonical.technical_model_ids != tuple(technical_by_id)
        or canonical.audit_model_ids != audit_selection.binding.selected_model_ids
        or tuple(refresh_by_id) != canonical.technical_model_ids
    ):
        return None
    for route in canonical.routes:
        qualified = technical_by_id.get(route.exact_model_id)
        if qualified is None or (
            route.canonical_model_slug != qualified.canonical_model_slug
            or route.root_lineage != qualified.root_lineage
            or route.approved_provider_endpoint != qualified.approved_provider_endpoint
            or route.approved_provider_name != qualified.approved_provider_name
            or route.endpoint_snapshot_sha256 != qualified.endpoint_snapshot_sha256
            or route.output_capability_sha256 != qualified.output_capability_sha256
            or route.model_metadata_snapshot_sha256 != qualified.model_metadata_snapshot_sha256
            or route.qualified_pricing_snapshot_sha256 != qualified.pricing_snapshot_sha256
            or route.structured_output_mode is not qualified.structured_output_mode
            or route.approved_roles != qualified.approved_roles
            or route.benchmark_report_sha256 != qualified.benchmark_report_sha256
            or route.qualification_expires_at != qualified.expires_at
            or route.audit_selected != (route.exact_model_id in audit_selection.selected_model_ids)
            or route.runtime_authorized
        ):
            return None
    return _CurrentAuditModelRefresh(
        evidence=canonical,
        binding=binding,
        audit_model_ids=frozenset(canonical.audit_model_ids),
    )


def _usage_matches_audit_model_refresh(
    record: UsageRecord,
    refresh: _CurrentAuditModelRefresh | None,
) -> bool:
    """Match one detached REAL usage record to exact current refresh custody."""

    if refresh is None or record.execution_evidence is not ExecutionEvidenceKind.REAL:
        return False
    raw = record.routing.get("audit_model_refresh_route_evidence")
    if not isinstance(raw, dict):
        return False
    try:
        route = AuditModelRefreshRouteEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError):
        return False
    retained = tuple(
        item
        for item in refresh.evidence.routes
        if item.exact_model_id == record.requested_model and item.audit_selected
    )
    started_at = record.started_at or record.timestamp
    ended_at = record.ended_at
    return (
        route.model_dump(mode="json") == raw
        and len(retained) == 1
        and route == retained[0]
        and route.exact_model_id in refresh.audit_model_ids
        and route.exact_model_id == record.requested_model
        and record.routing.get("audit_model_refresh_evidence_sha256")
        == refresh.evidence.evidence_sha256
        and record.routing.get("audit_model_refresh_workflow_status_sha256")
        == refresh.evidence.workflow_status_sha256
        and record.routing.get("audit_model_refresh_snapshot_sha256")
        == refresh.evidence.snapshot_sha256
        and record.routing.get("audit_model_refresh_route_evidence_sha256")
        == route.route_evidence_sha256
        and record.routing.get("audit_model_refresh_technical_route_set_sha256")
        == refresh.evidence.technical_route_set_sha256
        and record.routing.get("audit_model_refresh_audit_route_set_sha256")
        == refresh.evidence.audit_route_set_sha256
        and record.routing.get("audit_model_refresh_expires_at")
        == refresh.evidence.expires_at.isoformat()
        and record.routing.get("audit_model_refresh_guard_capability_sha256")
        == audit_model_refresh_guard_capability_projection_sha256(refresh.evidence)
        and not route.runtime_authorized
        and started_at >= refresh.evidence.verified_at
        and started_at < refresh.evidence.expires_at
        and started_at < route.qualification_expires_at
        and ended_at is not None
        and ended_at >= started_at
    )


def _current_audit_model_refresh_pricing(
    evidence: AuditModelRefreshPricingEvidence | None,
    authority: VerifiedAuditModelRefreshPricingAuthority | None,
    technical_qualification: VerifiedProductionQualification | None,
    audit_selection: _CurrentAuditModelSelection | None,
    audit_refresh: _CurrentAuditModelRefresh | None,
    refresh_guard: VerifiedAuditModelRefreshGuard | None,
) -> _CurrentAuditModelRefreshPricing | None:
    """Return current pricing custody only while every live authority remains exact."""

    if (
        type(evidence) is not AuditModelRefreshPricingEvidence
        or type(authority) is not VerifiedAuditModelRefreshPricingAuthority
        or type(technical_qualification) is not VerifiedProductionQualification
        or audit_selection is None
        or audit_refresh is None
        or type(refresh_guard) is not VerifiedAuditModelRefreshGuard
    ):
        return None
    try:
        canonical = AuditModelRefreshPricingEvidence.model_validate_json(
            evidence.model_dump_json(),
            strict=True,
        )
        now = datetime.now(UTC).replace(microsecond=0)
        authority.require_current(
            now=now,
            expected_workflow_status_sha256=canonical.expected_workflow_status_sha256,
            refresh_evidence=audit_refresh.evidence,
            refresh_guard=refresh_guard,
            technical_qualification=technical_qualification,
            audit_selection=audit_selection.capability,
            expected_audit_scope_sha256=canonical.audit_scope_sha256,
            expected_source_sha256=canonical.source_sha256,
            expected_audit_context_sha256=canonical.audit_context_sha256,
            expected_client_constraints_sha256=canonical.client_constraints_sha256,
        )
        binding = SchedulerAuditModelRefreshPricingBinding.from_evidence(canonical)
    except (AttributeError, TypeError, ValueError):
        return None
    refresh_routes = {route.exact_model_id: route for route in audit_refresh.evidence.routes}
    if (
        canonical != evidence
        or now < canonical.verified_at
        or now >= canonical.expires_at
        or canonical.refresh_evidence_sha256 != audit_refresh.evidence.evidence_sha256
        or canonical.refresh_guard_capability_sha256 != refresh_guard.capability_sha256
        or canonical.technical_qualification_capability_sha256
        != technical_qualification.capability_sha256
        or canonical.technical_production_selection_sha256
        != technical_qualification.production_selection_sha256
        or canonical.audit_selection_capability_sha256
        != audit_selection.capability.capability_sha256
        or canonical.audit_selection_sha256 != audit_selection.binding.audit_selection_sha256
        or canonical.audit_scope_sha256 != audit_selection.binding.audit_scope_sha256
        or canonical.source_sha256 != audit_selection.binding.source_sha256
        or canonical.audit_context_sha256 != audit_selection.binding.audit_context_sha256
        or canonical.client_constraints_sha256 != audit_selection.binding.client_constraints_sha256
        or canonical.audit_model_ids != audit_selection.binding.selected_model_ids
        or authority.capability_sha256 != binding.pricing_authority_capability_sha256
        or authority.pricing_evidence_sha256 != canonical.evidence_sha256
    ):
        return None
    if any(
        (refresh_route := refresh_routes.get(route.exact_model_id)) is None
        or route.refresh_route_evidence_sha256 != refresh_route.route_evidence_sha256
        or route.audit_selected != refresh_route.audit_selected
        or route.pricing_use_authorized
        or route.provider_access_authorized
        or route.model_selection_authorized
        for route in canonical.routes
    ):
        return None
    return _CurrentAuditModelRefreshPricing(
        evidence=canonical,
        authority=authority,
        binding=binding,
        audit_model_ids=frozenset(canonical.audit_model_ids),
    )


def _usage_matches_audit_model_refresh_pricing(
    record: UsageRecord,
    pricing: _CurrentAuditModelRefreshPricing | None,
    selection: _CurrentAuditModelSelection | None,
    refresh: _CurrentAuditModelRefresh | None,
) -> bool:
    """Match one REAL usage record to exact current prices and attempt bounds."""

    if (
        pricing is None
        or selection is None
        or refresh is None
        or record.execution_evidence is not ExecutionEvidenceKind.REAL
    ):
        return False
    try:
        validate_audit_model_refresh_pricing_usage_custody(
            audit_model_refresh_pricing_evidence=pricing.evidence,
            audit_model_refresh_evidence=refresh.evidence,
            audit_model_selection=selection.evidence_bundle.selection,
            usage=(record,),
        )
        raw = record.routing.get("audit_model_refresh_pricing_route_evidence")
        if not isinstance(raw, dict):
            return False
        route = AuditModelRefreshPricingRouteEvidence.model_validate_json(
            json.dumps(
                raw,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ),
            strict=True,
        )
    except (TypeError, ValueError):
        return False
    retained = tuple(
        item
        for item in pricing.evidence.routes
        if item.exact_model_id == record.requested_model and item.audit_selected
    )
    return (
        len(retained) == 1
        and route == retained[0]
        and route.exact_model_id in pricing.audit_model_ids
        and record.routing.get("endpoint_pricing_sha256") == route.current_pricing_sha256
        and record.routing.get("qualified_pricing_snapshot_sha256")
        == route.qualified_pricing_snapshot_sha256
    )


def _scheduler_assurance_errors(
    config: AuditConfig,
    runtime: AssuranceRuntime,
    audit_selection: _CurrentAuditModelSelection | None,
    audit_refresh: _CurrentAuditModelRefresh | None,
    audit_refresh_pricing: _CurrentAuditModelRefreshPricing | None,
) -> tuple[str, ...]:
    """Return fail-closed scheduler binding and real-provider evidence defects."""

    artifact = runtime.scheduler_artifact
    expected_bindings = runtime.expected_scheduler_bindings
    expected_analysis_input_sha256 = runtime.expected_scheduler_analysis_input_sha256
    expected_inventory = runtime.expected_scheduler_shard_inventory
    expected_cost_baseline = runtime.expected_scheduler_cost_ledger_baseline
    if artifact is None:
        return ("seven-pass scheduler evidence was not produced",)
    try:
        artifact = SchedulerArtifact.model_validate(artifact.model_dump(mode="python"))
    except ValueError:
        return ("seven-pass scheduler evidence is structurally invalid",)
    errors: list[str] = []
    if audit_selection is None:
        errors.append("current audit policy-selected model authority was not supplied")
    if audit_refresh is None:
        errors.append("current veto-only model-refresh custody was not supplied")
    if audit_refresh_pricing is None:
        errors.append("current bounded model-refresh pricing custody was not supplied")
    if artifact.summary.status is not SchedulerCampaignStatus.COMPLETE:
        errors.append(f"seven-pass scheduler did not complete: {artifact.summary.status.value}")
    if expected_bindings is None:
        errors.append("trusted runtime scheduler bindings were not supplied")
    if expected_analysis_input_sha256 is None:
        errors.append("trusted runtime scheduler analysis-input binding was not supplied")
    if expected_inventory is None:
        errors.append("trusted runtime scheduler shard inventory was not supplied")
    if expected_cost_baseline is None:
        errors.append("trusted runtime scheduler cost-ledger baseline was not supplied")
    if (
        expected_bindings is not None
        and expected_analysis_input_sha256 is not None
        and expected_bindings.analysis_input_sha256 != expected_analysis_input_sha256
    ):
        errors.append(
            "scheduler bindings differ from the trusted pre-scheduler analysis-input digest"
        )
    manifest = artifact.summary.manifest
    if expected_bindings is not None and manifest.bindings != expected_bindings:
        errors.append("scheduler artifact bindings differ from trusted runtime bindings")
    if expected_inventory is not None and manifest.shard_inventory != expected_inventory:
        errors.append("scheduler artifact shard inventory differs from trusted runtime inventory")
    if audit_selection is not None and (
        manifest.bindings.audit_model_selection != audit_selection.binding
        or expected_bindings is None
        or expected_bindings.audit_model_selection != audit_selection.binding
    ):
        errors.append("scheduler audit-selection binding differs from current policy authority")
    if audit_refresh is not None and (
        manifest.bindings.audit_model_refresh != audit_refresh.binding
        or expected_bindings is None
        or expected_bindings.audit_model_refresh != audit_refresh.binding
    ):
        errors.append("scheduler model-refresh binding differs from current refresh custody")
    if audit_refresh_pricing is not None and (
        manifest.bindings.audit_model_refresh_pricing != audit_refresh_pricing.binding
        or expected_bindings is None
        or expected_bindings.audit_model_refresh_pricing != audit_refresh_pricing.binding
    ):
        errors.append("scheduler pricing binding differs from current pricing authority")
    if manifest.cost_ledger_baseline != expected_cost_baseline:
        errors.append(
            "scheduler artifact cost-ledger baseline differs from trusted runtime baseline"
        )
    privacy_custody = manifest.privacy_evidence_custody
    if privacy_custody is None:
        errors.append("scheduler artifact lacks exact pre-dispatch privacy custody")
    elif (
        expected_bindings is not None
        and expected_bindings.privacy_evidence_custody_sha256 != privacy_custody.custody_sha256
    ):
        errors.append("scheduler privacy custody differs from trusted runtime bindings")
    if expected_inventory is not None and expected_analysis_input_sha256 is not None:
        from mmaudit.orchestration.scheduler_runtime import build_scheduler_bindings

        try:
            derived_bindings = build_scheduler_bindings(
                config=config,
                shard_inventory=expected_inventory,
                qualification=runtime.production_qualification,
                analysis_input_sha256=expected_analysis_input_sha256,
                cost_ledger_baseline=expected_cost_baseline,
                privacy_evidence_custody=privacy_custody,
                audit_model_selection_evidence=(
                    audit_selection.evidence_bundle if audit_selection is not None else None
                ),
                audit_model_refresh_evidence=(
                    audit_refresh.evidence if audit_refresh is not None else None
                ),
                audit_model_refresh_pricing_evidence=(
                    audit_refresh_pricing.evidence if audit_refresh_pricing is not None else None
                ),
            )
        except ValueError:
            errors.append("trusted runtime scheduler analysis-input binding is invalid")
            derived_bindings = None
        if expected_bindings != derived_bindings:
            errors.append(
                "trusted runtime scheduler bindings differ from current configuration, "
                "qualification, prompt, schema, tool, or source evidence"
            )

    requests = {item.logical_request_id: item for item in artifact.model_requests}
    recovery_requests = {item.logical_request_id: item for item in artifact.recovery_model_requests}
    all_requests: dict[
        str,
        SchedulerModelRequestEvidence | SchedulerTruncationRecoveryModelRequestEvidence,
    ] = {**requests, **recovery_requests}
    if (
        not requests
        or len(requests) != len(artifact.model_requests)
        or len(recovery_requests) != len(artifact.recovery_model_requests)
        or len(all_requests) != len(requests) + len(recovery_requests)
    ):
        errors.append("scheduler artifact lacks a unique substantive model-request inventory")
        return tuple(errors)
    usages = {item.request_id: item for item in runtime.model_usage}
    if len(usages) != len(runtime.model_usage):
        errors.append("runtime provider usage contains duplicate request identities")
        return tuple(errors)
    if set(usages) != set(all_requests):
        errors.append("runtime provider usage differs from the scheduler request inventory")
        return tuple(errors)
    surface_artifacts: dict[str, ModelSurfaceReviewArtifact] = {}
    duplicate_surface_artifact = False
    for runtime_artifact in runtime.model_surface_review_artifacts:
        try:
            sealed_artifact = ModelSurfaceReviewArtifact.model_validate(
                runtime_artifact.model_dump(mode="python")
            )
        except ValueError:
            errors.append("runtime model-surface evidence contains an invalid artifact")
            continue
        if sealed_artifact.request_id in surface_artifacts:
            duplicate_surface_artifact = True
        surface_artifacts[sealed_artifact.request_id] = sealed_artifact

    from mmaudit.orchestration.scheduler import (
        require_verified_promoted_recursive_truncation_recovery_surface_coverage,
    )
    from mmaudit.orchestration.truncation_recovery_evidence import (
        TruncationRecoveryEvidenceError,
    )

    recursive_bindings = tuple(
        binding
        for pass_result in artifact.summary.pass_results
        for binding in pass_result.recovery_promotion_bindings
        if binding.schema_version == "1.1"
    )
    recursive_projections: list[
        VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverageProjection
    ] = []
    if len(runtime.promoted_recursive_recovery_surface_coverages) > 32:
        errors.append("live recursive recovery promotions exceed their compiled bound")
    else:
        for capability in runtime.promoted_recursive_recovery_surface_coverages:
            try:
                recursive_projections.append(
                    require_verified_promoted_recursive_truncation_recovery_surface_coverage(
                        capability
                    )
                )
            except (TypeError, TruncationRecoveryEvidenceError):
                errors.append("live recursive recovery promotion custody is invalid")
    recursive_binding_ids = tuple(binding.promotion_entry_sha256 for binding in recursive_bindings)
    recursive_projection_ids = tuple(
        projection.promotion_entry_sha256 for projection in recursive_projections
    )
    if (
        len(recursive_binding_ids) != len(set(recursive_binding_ids))
        or len(recursive_projection_ids) != len(set(recursive_projection_ids))
        or set(recursive_binding_ids) != set(recursive_projection_ids)
    ):
        errors.append(
            "public recursive recovery promotions differ from exact live promotion custody"
        )

    recursive_parent_custody: dict[str, tuple[UsageRecord, ContextPackage]] = {}
    recursive_bridge_custody: dict[str, tuple[UsageRecord, ContextPackage]] = {}
    recursive_leaf_custody: dict[str, tuple[UsageRecord, ContextPackage]] = {}
    seen_recursive_artifacts: set[str] = set()
    for projection in recursive_projections:
        matching_bindings = tuple(
            binding
            for binding in recursive_bindings
            if binding.promotion_entry_sha256 == projection.promotion_entry_sha256
        )
        if len(matching_bindings) != 1:
            continue
        binding = matching_bindings[0]
        promoted_artifact = projection.artifact
        promotion_requests = tuple(
            request
            for request in artifact.recovery_model_requests
            if request.promotion_entry_sha256 == projection.promotion_entry_sha256
        )
        bridge_requests = tuple(
            request
            for request in promotion_requests
            if request.promotion_disposition
            is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
        )
        leaf_requests = tuple(
            sorted(
                (
                    request
                    for request in promotion_requests
                    if request.promotion_disposition
                    is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                ),
                key=lambda request: request.global_request_ordinal or 0,
            )
        )
        parent_requests = tuple(
            request
            for request in artifact.model_requests
            if request.task_id == binding.parent_task_id
        )
        projected_usage = (
            projection.parent_usage_record,
            projection.bridge_usage_record,
            *projection.leaf_usage_records,
        )
        exact_tree = (
            binding.parent_task_id == promoted_artifact.parent_task_id
            and binding.recovered_output_artifact_sha256
            == projection.recovered_output_artifact_sha256
            and binding.direct_child_result_sha256s == projection.direct_child_result_sha256s
            and binding.nested_family_id == projection.nested_family_id
            and binding.nested_family_root_sha256 == projection.nested_family_root_sha256
            and binding.nested_recovery_plan_sha256 == projection.nested_recovery_plan_sha256
            and binding.nested_family_closure_id == projection.nested_family_closure_id
            and binding.nested_family_closure_sha256 == projection.nested_family_closure_sha256
            and binding.nested_child_result_sha256s == projection.nested_child_result_sha256s
            and binding.superseded_bridge_result_sha256
            == projection.superseded_bridge_result_sha256
            and binding.promoted_leaf_result_sha256s == projection.promoted_leaf_result_sha256s
            and len(parent_requests) == 1
            and parent_requests[0].logical_request_id == projection.parent_usage_record.request_id
            and len(promotion_requests) == 4
            and len(bridge_requests) == 1
            and len(leaf_requests) == 3
            and bridge_requests[0].child_result_entry_sha256
            == projection.superseded_bridge_result_sha256
            and bridge_requests[0].terminal_status is SchedulerTerminalStatus.TRUNCATED
            and bridge_requests[0].recovery_family_id == projection.family_id
            and bridge_requests[0].family_root_sha256 == projection.family_root_sha256
            and bridge_requests[0].recovery_plan_sha256
            == promoted_artifact.recovery_plan.plan_sha256
            and bridge_requests[0].family_closure_id == projection.family_closure_id
            and bridge_requests[0].family_closure_sha256 == projection.family_closure_sha256
            and tuple(request.child_result_entry_sha256 for request in leaf_requests)
            == projection.promoted_leaf_result_sha256s
            and all(
                request.terminal_status is SchedulerTerminalStatus.SUCCEEDED
                for request in leaf_requests
            )
            and len(projected_usage) == 5
            and len({usage.request_id for usage in projected_usage}) == 5
            and len(projection.leaf_contexts) == 3
            and len(promoted_artifact.children) == 3
            and promoted_artifact.artifact_sha256 not in seen_recursive_artifacts
            and leaf_requests[0].recovery_family_id == projection.family_id
            and leaf_requests[0].family_root_sha256 == projection.family_root_sha256
            and leaf_requests[0].recovery_plan_sha256 == promoted_artifact.recovery_plan.plan_sha256
            and leaf_requests[0].family_closure_id == projection.family_closure_id
            and leaf_requests[0].family_closure_sha256 == projection.family_closure_sha256
            and all(
                request.recovery_family_id == projection.nested_family_id
                and request.family_root_sha256 == projection.nested_family_root_sha256
                and request.recovery_plan_sha256 == projection.nested_recovery_plan_sha256
                and request.family_closure_id == projection.nested_family_closure_id
                and request.family_closure_sha256 == projection.nested_family_closure_sha256
                for request in leaf_requests[1:]
            )
        )
        if not exact_tree:
            errors.append("recursive recovery promotion differs from its exact public tree")
            continue
        seen_recursive_artifacts.add(promoted_artifact.artifact_sha256)
        bridge_request = bridge_requests[0]
        exact_live_tree = (
            usages.get(projection.parent_usage_record.request_id) is projection.parent_usage_record
            and usages.get(projection.bridge_usage_record.request_id)
            is projection.bridge_usage_record
            and promoted_artifact.parent.usage_record == projection.parent_usage_record
            and promoted_artifact.bridge.usage_record == projection.bridge_usage_record
            and bridge_request.logical_request_id == projection.bridge_usage_record.request_id
            and bridge_request.output_artifact_sha256 is None
            and bridge_request.logical_request_id not in surface_artifacts
        )
        leaf_custody_items: list[tuple[str, UsageRecord, ContextPackage]] = []
        for child, leaf_usage, leaf_context, leaf_request in zip(
            promoted_artifact.children,
            projection.leaf_usage_records,
            projection.leaf_contexts,
            leaf_requests,
            strict=True,
        ):
            if (
                usages.get(leaf_usage.request_id) is not leaf_usage
                or child.usage_record != leaf_usage
                or leaf_request.logical_request_id != leaf_usage.request_id
                or surface_artifacts.get(leaf_usage.request_id) != child.surface_artifact
            ):
                exact_live_tree = False
            leaf_custody_items.append((leaf_usage.request_id, leaf_usage, leaf_context))
        if not exact_live_tree:
            errors.append("recursive recovery promotion differs from exact live usage custody")
            continue
        parent_request = parent_requests[0]
        if (
            not _promoted_recovery_context_matches_request(
                context=projection.parent_context,
                usage=projection.parent_usage_record,
                request=parent_request,
                allow_missing_request_binding=True,
            )
            or not _promoted_recovery_context_matches_request(
                context=projection.bridge_context,
                usage=projection.bridge_usage_record,
                request=bridge_request,
            )
            or any(
                not _promoted_recovery_context_matches_request(
                    context=leaf_context,
                    usage=leaf_usage,
                    request=leaf_request,
                )
                for leaf_usage, leaf_context, leaf_request in zip(
                    projection.leaf_usage_records,
                    projection.leaf_contexts,
                    leaf_requests,
                    strict=True,
                )
            )
        ):
            errors.append("recursive recovery promotion differs from exact live context custody")
            continue
        recursive_parent_custody[parent_request.logical_request_id] = (
            projection.parent_usage_record,
            projection.parent_context,
        )
        recursive_bridge_custody[bridge_request.logical_request_id] = (
            projection.bridge_usage_record,
            projection.bridge_context,
        )
        for leaf_request_id, leaf_usage, leaf_context in leaf_custody_items:
            recursive_leaf_custody[leaf_request_id] = (leaf_usage, leaf_context)
    scheduler_surface_requests = {
        request_id
        for request_id, request in requests.items()
        if request.model_surface_review_request_count > 0
    }
    scheduler_surface_requests.update(
        request_id
        for request_id, request in recovery_requests.items()
        if request.promotion_entry_sha256 is not None and request.output_artifact_sha256 is not None
    )
    if duplicate_surface_artifact or set(surface_artifacts) != scheduler_surface_requests:
        errors.append("runtime model-surface artifacts differ from scheduler request custody")
    specialist_outcomes: dict[str, SpecialistAcceptedOutcome] = {}
    specialist_outcome_duplicate = False
    for execution_record in runtime.specialist_execution_records:
        try:
            sealed_record = SpecialistExecutionRecord.model_validate(
                execution_record.model_dump(mode="python")
            )
        except ValueError:
            errors.append("scheduler specialist outcome evidence contains an invalid record")
            continue
        for outcome in sealed_record.accepted_outcomes:
            if outcome.request_id in specialist_outcomes:
                specialist_outcome_duplicate = True
            specialist_outcomes[outcome.request_id] = outcome
    promoted_parent_task_ids = {
        binding.parent_task_id
        for pass_result in artifact.summary.pass_results
        for binding in pass_result.recovery_promotion_bindings
    }
    scheduler_specialist_requests = {
        request_id: role
        for request_id, request in requests.items()
        if request.task_id not in promoted_parent_task_ids
        if (role := canonical_specialist_role(request.role)) is not None
    }
    promoted_recovery_specialist_requests = {
        request_id: role
        for request_id, request in recovery_requests.items()
        if request.promotion_entry_sha256 is not None
        and (role := canonical_specialist_role(request.role)) is not None
    }
    if set(scheduler_specialist_requests) & set(promoted_recovery_specialist_requests):
        errors.append("scheduler specialist request identity is ambiguous")
    scheduler_specialist_requests.update(promoted_recovery_specialist_requests)
    if specialist_outcome_duplicate or set(specialist_outcomes) != set(
        scheduler_specialist_requests
    ):
        errors.append("scheduler specialist requests differ from exact host-accepted outcomes")
    expected_source_descriptors = (
        {
            source.source_descriptor_sha256
            for shard in expected_inventory.shards
            for source in shard.sources
        }
        if expected_inventory is not None
        else set()
    )
    global_scope_sha256 = SchedulerScope.global_scope().scope_sha256
    production_qualification = _current_production_qualification(runtime.production_qualification)
    for request_id, request in sorted(all_requests.items()):
        usage = usages[request_id]
        routed_lineage = usage.routing.get("qualified_root_lineage")
        if isinstance(request, SchedulerTruncationRecoveryModelRequestEvidence):
            if request.promotion_entry_sha256 is None:
                errors.append(f"scheduler recovery request {request_id} lacks a guarded promotion")
                continue
            if (
                request.promotion_disposition
                is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
            ):
                bridge_custody = recursive_bridge_custody.get(request_id)
                if bridge_custody is None or bridge_custody[0] is not usage:
                    errors.append(
                        f"scheduler recursive bridge {request_id} lacks exact live promotion "
                        "custody"
                    )
                    continue
                if (
                    request.schema_version != "1.2"
                    or request.terminal_status is not SchedulerTerminalStatus.TRUNCATED
                    or request.runtime_completion_evidence_sha256 is not None
                    or request.validated_response_sha256 is not None
                    or request.normalization_evidence_sha256 is not None
                    or request.output_artifact_sha256 is not None
                    or request.specialist_accepted_outcome_sha256 is not None
                ):
                    errors.append(
                        f"scheduler recursive bridge {request_id} claimed successful review custody"
                    )
                    continue
                if not is_recovery_accountable_usage_record(
                    usage,
                    request_limit_scope=request.request_limit_scope,
                    request_limit_count_before=request.request_limit_count_before,
                    require_real=True,
                ):
                    errors.append(
                        f"scheduler recursive bridge {request_id} lacks real accountable usage"
                    )
                    continue
                if not _usage_matches_real_model_route(
                    usage,
                    config,
                    production_qualification,
                    runtime.provider_session,
                    audit_selection,
                    audit_refresh,
                    audit_refresh_pricing,
                    recovery_request_limit_scope=request.request_limit_scope,
                    recovery_request_limit_count_before=request.request_limit_count_before,
                ):
                    errors.append(
                        f"scheduler recursive bridge {request_id} lacks current qualified "
                        "accounting route"
                    )
                    continue
                if (
                    usage.role != request.role
                    or usage.requested_model != request.requested_model
                    or usage.prompt_sha256 != request.provider_prompt_sha256
                    or usage.user_prompt_sha256 != request.user_prompt_sha256
                    or usage.schema_sha256 != request.response_schema_sha256
                    or request.usage_record_sha256
                    != scheduler_canonical_sha256(usage.model_dump(mode="json"))
                    or request.provider_response_sha256 != usage.response_sha256
                    or usage.fallback_used
                    or usage.substitution_detected
                    or routed_lineage != request.root_lineage
                    or not _promoted_recovery_context_matches_request(
                        context=bridge_custody[1],
                        usage=usage,
                        request=request,
                    )
                ):
                    errors.append(
                        f"scheduler recursive bridge {request_id} differs from exact provider "
                        "accounting evidence"
                    )
                continue
            if request.promotion_disposition is not None and (
                request.promotion_disposition
                is not SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                or request_id not in recursive_leaf_custody
            ):
                errors.append(
                    f"scheduler recursive leaf {request_id} lacks exact live promotion custody"
                )
                continue
            if request.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                errors.append(f"scheduler recovery request {request_id} did not succeed")
                continue
            if not is_recovery_creditable_usage_record(
                usage,
                request_limit_scope=request.request_limit_scope,
                request_limit_count_before=request.request_limit_count_before,
                require_real=True,
            ):
                errors.append(
                    f"scheduler recovery request {request_id} lacks real creditable usage"
                )
                continue
            if not _is_real_model_usage(
                usage,
                config,
                production_qualification,
                runtime.provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=request.request_limit_scope,
                recovery_request_limit_count_before=request.request_limit_count_before,
            ):
                errors.append(
                    f"scheduler recovery request {request_id} lacks current qualified "
                    "certification-grade provider evidence"
                )
                continue
            if audit_selection is None:
                errors.append(
                    f"scheduler recovery request {request_id} lacks audit policy authority"
                )
                continue
            policy_binding = audit_selection.binding
            if (
                request.audit_policy_selection_binding_sha256 != policy_binding.binding_sha256
                or request.audit_model_selection_bundle_sha256
                != policy_binding.audit_model_selection_bundle_sha256
                or request.audit_selection_sha256 != policy_binding.audit_selection_sha256
                or request.audit_selected_model_set_sha256
                != policy_binding.selected_model_set_sha256
                or request.audit_scope_sha256 != policy_binding.audit_scope_sha256
                or request.audit_source_sha256 != policy_binding.source_sha256
                or request.audit_selection_expires_at != policy_binding.selection_expires_at
                or request.audit_policy_routing_evidence_sha256
                != usage.routing.get("audit_policy_routing_evidence_sha256")
            ):
                errors.append(
                    f"scheduler recovery request {request_id} differs from audit policy selection"
                )
                continue
            assert production_qualification is not None
            try:
                qualified_model = production_qualification.model_for(
                    usage.requested_model,
                    now=datetime.now(UTC).replace(microsecond=0),
                )
            except ValueError:
                errors.append(
                    f"scheduler recovery request {request_id} lacks a current qualified model"
                )
                continue
            raw_context = usage.routing.get("context_request_evidence")
            try:
                context_evidence = ContextRequestEvidence.model_validate(raw_context)
            except ValueError:
                errors.append(
                    f"scheduler recovery request {request_id} lacks exact context evidence"
                )
                continue
            surface_artifact = surface_artifacts.get(request_id)
            if (
                surface_artifact is None
                or surface_artifact.request_id != request.logical_request_id
                or surface_artifact.review_role != request.role
                or surface_artifact.artifact_sha256 != request.output_artifact_sha256
                or surface_artifact.rendered_context_sha256 != context_evidence.rendered_sha256
                or surface_artifact.prompt_sha256 != request.provider_prompt_sha256
                or surface_artifact.response_sha256 != request.provider_response_sha256
                or surface_artifact.validated_response_sha256 != request.validated_response_sha256
                or surface_artifact.response_schema_sha256 != request.response_schema_sha256
            ):
                errors.append(
                    f"scheduler recovery request {request_id} differs from exact runtime "
                    "model-surface artifact"
                )
                continue
            specialist_role = scheduler_specialist_requests.get(request_id)
            accepted_outcome = specialist_outcomes.get(request_id)
            if specialist_role is not None:
                if (
                    accepted_outcome is None
                    or accepted_outcome.outcome_kind
                    is not SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
                    or accepted_outcome.specialist_role != specialist_role
                    or accepted_outcome.request_role != request.role
                    or accepted_outcome.validated_response_sha256
                    != request.validated_response_sha256
                    or accepted_outcome.context_request_evidence_sha256
                    != request.context_request_evidence_sha256
                    or accepted_outcome.requested_surface_count != len(surface_artifact.records)
                    or accepted_outcome.surface_review_artifact_sha256
                    != surface_artifact.artifact_sha256
                    or request.specialist_accepted_outcome_sha256
                    != accepted_outcome.evidence_sha256
                ):
                    errors.append(
                        f"scheduler recovery specialist request {request_id} differs from its "
                        "exact host-accepted outcome"
                    )
                    continue
            elif request.specialist_accepted_outcome_sha256 is not None:
                errors.append(
                    f"non-specialist scheduler recovery request {request_id} claims a "
                    "specialist outcome"
                )
                continue
            if (
                usage.role != request.role
                or usage.requested_model != request.requested_model
                or usage.prompt_sha256 != request.provider_prompt_sha256
                or usage.user_prompt_sha256 != request.user_prompt_sha256
                or usage.schema_sha256 != request.response_schema_sha256
                or request.usage_record_sha256
                != scheduler_canonical_sha256(usage.model_dump(mode="json"))
                or request.context_request_evidence_sha256 != context_evidence.evidence_sha256
                or request.provider_response_sha256 != usage.response_sha256
                or request.validated_response_sha256 != usage.validated_response_sha256
                or context_evidence.request_id != request.logical_request_id
                or context_evidence.request_role != request.role
                or usage.routing.get("context_request_evidence_sha256")
                != context_evidence.evidence_sha256
                or usage.fallback_used
                or usage.substitution_detected
                or routed_lineage != request.root_lineage
                or request.root_lineage != qualified_model.root_lineage
            ):
                errors.append(
                    f"scheduler recovery request {request_id} differs from exact provider evidence"
                )
            continue

        specialist_role = scheduler_specialist_requests.get(request_id)
        if specialist_role is not None:
            accepted_outcome = specialist_outcomes.get(request_id)
            if accepted_outcome is None:
                errors.append(
                    f"scheduler specialist request {request_id} lacks a host-accepted outcome"
                )
                continue
            if accepted_outcome.outcome_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW and (
                accepted_outcome.requested_surface_count
                != request.model_surface_review_request_count
                or accepted_outcome.surface_review_artifact_sha256
                != request.model_surface_review_artifact_sha256
            ):
                errors.append(
                    f"scheduler specialist request {request_id} differs from its exact "
                    "model-surface custody"
                )
                continue
            if (
                accepted_outcome.specialist_role != specialist_role
                or accepted_outcome.request_role != request.role
                or accepted_outcome.validated_response_sha256 != request.validated_response_sha256
                or accepted_outcome.context_request_evidence_sha256
                != request.context_request_evidence_sha256
                or request.specialist_accepted_outcome_sha256 != accepted_outcome.evidence_sha256
            ):
                errors.append(
                    f"scheduler specialist request {request_id} differs from its exact "
                    "host-accepted outcome"
                )
                continue
        elif request.specialist_accepted_outcome_sha256 is not None:
            errors.append(
                f"non-specialist scheduler request {request_id} claims a specialist outcome"
            )
            continue
        if request.task_id in promoted_parent_task_ids:
            if request.terminal_status is not SchedulerTerminalStatus.TRUNCATED:
                errors.append(
                    f"promoted scheduler parent {request_id} did not retain its truncation"
                )
            recursive_parent = recursive_parent_custody.get(request_id)
            if recursive_parent is not None and (
                recursive_parent[0] is not usage
                or not is_accountable_usage_record(usage, require_real=True)
                or not _usage_matches_real_model_route(
                    usage,
                    config,
                    production_qualification,
                    runtime.provider_session,
                    audit_selection,
                    audit_refresh,
                    audit_refresh_pricing,
                    recovery_request_limit_scope=None,
                    recovery_request_limit_count_before=None,
                )
                or not _promoted_recovery_context_matches_request(
                    context=recursive_parent[1],
                    usage=usage,
                    request=request,
                    allow_missing_request_binding=True,
                )
            ):
                errors.append(
                    f"promoted recursive scheduler parent {request_id} lacks exact live "
                    "accounting custody"
                )
            continue
        if request.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
            errors.append(f"scheduler model request {request_id} did not succeed")
            continue
        if not is_creditable_usage_record(usage, require_real=True):
            errors.append(f"scheduler model request {request_id} lacks real creditable usage")
            continue
        if not _is_real_model_usage(
            usage,
            config,
            production_qualification,
            runtime.provider_session,
            audit_selection,
            audit_refresh,
            audit_refresh_pricing,
        ):
            errors.append(
                f"scheduler model request {request_id} lacks current qualified "
                "certification-grade provider evidence"
            )
            continue
        if audit_selection is None:
            errors.append(f"scheduler model request {request_id} lacks audit policy authority")
            continue
        policy_binding = audit_selection.binding
        if (
            request.audit_policy_selection_binding_sha256 != policy_binding.binding_sha256
            or request.audit_model_selection_bundle_sha256
            != policy_binding.audit_model_selection_bundle_sha256
            or request.audit_selection_sha256 != policy_binding.audit_selection_sha256
            or request.audit_selected_model_set_sha256 != policy_binding.selected_model_set_sha256
            or request.audit_scope_sha256 != policy_binding.audit_scope_sha256
            or request.audit_source_sha256 != policy_binding.source_sha256
            or request.audit_selection_expires_at != policy_binding.selection_expires_at
            or request.audit_policy_routing_evidence_sha256
            != usage.routing.get("audit_policy_routing_evidence_sha256")
        ):
            errors.append(
                f"scheduler model request {request_id} differs from audit policy selection"
            )
            continue
        assert production_qualification is not None
        try:
            qualified_model = production_qualification.model_for(
                usage.requested_model,
                now=datetime.now(UTC).replace(microsecond=0),
            )
        except ValueError:
            errors.append(f"scheduler model request {request_id} lacks a current qualified model")
            continue
        if source_backed_whole_protocol_context(usage) is not None and (
            request.scope_sha256 != global_scope_sha256
            or set(request.delivered_source_descriptor_sha256s) != expected_source_descriptors
        ):
            errors.append(
                f"scheduler model request {request_id} lacks exact global "
                "whole-protocol source delivery"
            )
            continue
        raw_context = usage.routing.get("context_request_evidence")
        try:
            context_evidence = ContextRequestEvidence.model_validate(raw_context)
        except ValueError:
            errors.append(f"scheduler model request {request_id} lacks exact context evidence")
            continue
        surface_artifact = surface_artifacts.get(request_id)
        if request.model_surface_review_request_count > 0:
            if surface_artifact is None:
                errors.append(
                    f"scheduler model request {request_id} lacks its runtime model-surface artifact"
                )
                continue
            if (
                surface_artifact.request_id != request.logical_request_id
                or surface_artifact.review_role != request.role
                or len(surface_artifact.requested_surface_ids)
                != request.model_surface_review_request_count
                or surface_artifact.requested_surface_manifest_sha256
                != request.model_surface_review_request_manifest_sha256
                or surface_artifact.artifact_sha256 != request.model_surface_review_artifact_sha256
                or surface_artifact.rendered_context_sha256 != context_evidence.rendered_sha256
                or surface_artifact.prompt_sha256 != request.provider_prompt_sha256
                or surface_artifact.response_sha256 != request.provider_response_sha256
                or surface_artifact.validated_response_sha256 != request.validated_response_sha256
                or surface_artifact.response_schema_sha256 != request.response_schema_sha256
            ):
                errors.append(
                    f"scheduler model request {request_id} differs from exact runtime "
                    "model-surface artifact"
                )
                continue
        elif surface_artifact is not None:
            errors.append(
                f"scheduler model request {request_id} claims an unplanned runtime "
                "model-surface artifact"
            )
            continue
        if (
            usage.role != request.role
            or usage.requested_model != request.requested_model
            or usage.returned_model != request.requested_model
            or usage.actual_model != request.requested_model
            or usage.prompt_sha256 != request.provider_prompt_sha256
            or usage.user_prompt_sha256 != request.user_prompt_sha256
            or usage.schema_sha256 != request.response_schema_sha256
            or usage.validated_response_sha256 != request.terminal_evidence_sha256
            or request.usage_record_sha256
            != scheduler_canonical_sha256(usage.model_dump(mode="json"))
            or request.context_request_evidence_sha256 != context_evidence.evidence_sha256
            or request.provider_response_sha256 != usage.response_sha256
            or request.validated_response_sha256 != usage.validated_response_sha256
            or context_evidence.request_id != request.logical_request_id
            or context_evidence.request_role != request.role
            or usage.routing.get("context_request_evidence_sha256")
            != context_evidence.evidence_sha256
            or usage.fallback_used
            or usage.substitution_detected
            or routed_lineage != request.root_lineage
            or request.root_lineage != qualified_model.root_lineage
        ):
            errors.append(
                f"scheduler model request {request_id} differs from exact provider evidence"
            )
    return tuple(errors)


def _specialist_execution_errors(
    runtime: AssuranceRuntime,
) -> tuple[set[str], tuple[str, ...]]:
    """Derive completed specialist roles only from host-validated execution records."""

    records: list[SpecialistExecutionRecord] = []
    errors: list[str] = []
    for record in runtime.specialist_execution_records:
        try:
            records.append(
                SpecialistExecutionRecord.model_validate(record.model_dump(mode="python"))
            )
        except ValueError:
            errors.append("specialist execution evidence contains an invalid record")
    role_counts = Counter(record.role for record in records)
    expected_roles = set(ALL_SPECIALIST_ROLES)
    if set(role_counts) != expected_roles or any(count != 1 for count in role_counts.values()):
        errors.append("specialist execution evidence differs from the exact role inventory")
    derived = completed_specialist_roles(records)
    derived_investigators = derived & set(SPECIALIST_INVESTIGATOR_ROLES)
    derived_auxiliary = derived & set(SPECIALIST_AUXILIARY_ROLES)
    if runtime.specialist_roles_completed != derived_investigators:
        errors.append("declared investigator completion differs from accepted outcomes")
    if runtime.auxiliary_roles_completed != derived_auxiliary:
        errors.append("declared auxiliary completion differs from accepted outcomes")
    return derived, tuple(errors)


class MaximumAssuranceContract:
    """Evaluate whether the promised maximum-assurance engines actually ran."""

    version = "1.0"

    def __init__(
        self,
        config: AuditConfig,
        *,
        require: bool | None = None,
        allow_downgrade: bool | None = None,
    ) -> None:
        self.config = config
        self.requested = config.profile is AuditProfile.MAXIMUM_ASSURANCE
        self.required = config.maximum_assurance.require if require is None else require
        self.allow_downgrade = (
            config.maximum_assurance.allow_downgrade if allow_downgrade is None else allow_downgrade
        )

    def configuration_requirements(
        self,
        *,
        isolation_available: bool,
        scanner_only: bool,
    ) -> list[MaximumAssuranceRequirement]:
        """Return requirements that can be checked before model or target execution."""

        if not self.requested and not self.required:
            return []
        configured_roles = self._configured_specialist_roles()
        configured_families = self._configured_families()
        missing_roles = set(ALL_SPECIALIST_ROLES) - configured_roles
        return [
            _requirement(
                "maximum_assurance_profile",
                self.requested,
                (
                    "maximum-assurance profile selected"
                    if self.requested
                    else "--require-maximum-assurance requires --profile maximum-assurance"
                ),
                state=(
                    AnalysisState.DETERMINISTIC if self.requested else AnalysisState.NOT_ANALYZED
                ),
            ),
            _requirement(
                "solidity_evm_capability_profile",
                self.config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM,
                (
                    "solidity-evm capability profile selected"
                    if self.config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
                    else (
                        "generic-source-review cannot satisfy the Solidity/EVM "
                        "maximum-assurance contract"
                    )
                ),
            ),
            _requirement(
                "full_pipeline_mode",
                not scanner_only,
                (
                    "full multi-agent pipeline requested"
                    if not scanner_only
                    else "scanner-only mode cannot satisfy maximum-assurance"
                ),
            ),
            _requirement(
                "model_family_diversity",
                len(configured_families) >= self.config.maximum_assurance.minimum_model_families,
                (
                    f"{len(configured_families)} distinct configured model families; "
                    f"{self.config.maximum_assurance.minimum_model_families} required"
                ),
            ),
            _requirement(
                "specialist_agent_configuration",
                len(configured_roles) >= self.config.maximum_assurance.minimum_specialist_agents,
                (
                    f"{len(configured_roles)} specialist roles configured; "
                    f"{self.config.maximum_assurance.minimum_specialist_agents} required"
                ),
            ),
            _requirement(
                "specialist_role_coverage",
                not missing_roles,
                (
                    "all required specialist responsibilities are configured"
                    if not missing_roles
                    else "missing specialist responsibilities: " + ", ".join(sorted(missing_roles))
                ),
            ),
            _requirement(
                "hardened_dynamic_isolation",
                isolation_available,
                (
                    "hardened disposable-workspace execution backend available"
                    if isolation_available
                    else "no supported hardened dynamic-execution backend is available"
                ),
            ),
        ]

    def evaluate(self, runtime: AssuranceRuntime) -> MaximumAssuranceAssessment:
        """Evaluate every contract clause from actual run evidence."""

        if not self.requested and not self.required:
            return MaximumAssuranceAssessment(
                contract_version="1.1",
                requested=False,
                required=False,
                downgrade_allowed=self.allow_downgrade,
                downgraded=False,
                status=MaximumAssuranceStatus.NOT_REQUESTED,
            )

        requirements = self.configuration_requirements(
            isolation_available=runtime.isolation_available,
            scanner_only=runtime.scanner_only,
        )
        requirements.extend(self._traceability_requirements(runtime))
        requirements.extend(self._runtime_requirements(runtime))
        failed = [item for item in requirements if item.required and not item.passed]
        if not failed:
            status = MaximumAssuranceStatus.COMPLETE
            downgraded = False
        elif self.allow_downgrade:
            status = MaximumAssuranceStatus.DOWNGRADED
            downgraded = True
        elif any(item.state is AnalysisState.ATTEMPTED_FAILED for item in failed):
            status = MaximumAssuranceStatus.INCONCLUSIVE
            downgraded = False
        else:
            status = MaximumAssuranceStatus.FAILED
            downgraded = False
        return MaximumAssuranceAssessment(
            contract_version="1.1",
            requested=self.requested,
            required=self.required,
            downgrade_allowed=self.allow_downgrade,
            downgraded=downgraded,
            status=status,
            requirements=requirements,
            downgrade_reasons=[item.detail for item in failed] if downgraded else [],
        )

    def _traceability_requirements(
        self,
        runtime: AssuranceRuntime,
    ) -> list[MaximumAssuranceRequirement]:
        matrix = runtime.traceability
        if matrix is None:
            return [
                _requirement(
                    "requirements_traceability",
                    False,
                    "maximum-assurance traceability matrix was not supplied to the contract",
                    artifacts=_present(
                        runtime.artifacts,
                        "maximum_assurance_traceability.json",
                    ),
                )
            ]
        requirements = [
            _requirement(
                "requirements_traceability",
                True,
                (
                    f"traceability schema {matrix.schema_version} evaluated at "
                    f"{matrix.last_verified_commit}"
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "maximum_assurance_traceability.json",
                ),
            )
        ]
        for item in matrix.requirements:
            if not item.required_for_complete:
                continue
            implemented = item.implementation_status is ImplementationStatus.IMPLEMENTED
            requirements.append(
                _requirement(
                    f"traceability:{item.requirement_id.lower()}",
                    implemented,
                    (
                        f"{item.requirement_id} is implemented"
                        if implemented
                        else (
                            f"{item.requirement_id} is "
                            f"{item.implementation_status.value}: {item.downgrade_reason}"
                        )
                    ),
                    artifacts=[
                        artifact
                        for artifact in item.runtime_artifacts
                        if artifact in runtime.artifacts
                    ],
                )
            )
        return requirements

    def _runtime_requirements(
        self,
        runtime: AssuranceRuntime,
    ) -> list[MaximumAssuranceRequirement]:
        expected_compilations = Counter(
            (project.project_root, project.project_type.value) for project in runtime.projects
        )
        observed_compilations = Counter(
            (result.project_root, result.framework.value) for result in runtime.compilations
        )
        compilation_attempted = any(
            result.status
            not in {
                CompilationStatus.SKIPPED,
                CompilationStatus.UNAVAILABLE,
            }
            for result in runtime.compilations
        )
        compilation_inventory_complete = bool(expected_compilations) and (
            observed_compilations == expected_compilations
        )
        compilation_succeeded = compilation_inventory_complete and all(
            result.status is CompilationStatus.SUCCESS
            and result.ast_available
            and bool(result.contracts_compiled)
            for result in runtime.compilations
        )
        compilation_state = (
            AnalysisState.DETERMINISTIC
            if compilation_succeeded
            else (
                AnalysisState.ATTEMPTED_FAILED
                if compilation_attempted
                else AnalysisState.NOT_ANALYZED
            )
        )
        missing_compilations = list((expected_compilations - observed_compilations).elements())
        unexpected_compilations = list((observed_compilations - expected_compilations).elements())
        incomplete_compilations = [
            f"{result.project_root} ({result.framework.value}): {result.status.value}"
            + (
                "; compiler AST unavailable"
                if result.status is CompilationStatus.SUCCESS and not result.ast_available
                else ""
            )
            + (
                "; no compiled contracts"
                if result.status is CompilationStatus.SUCCESS and not result.contracts_compiled
                else ""
            )
            for result in runtime.compilations
            if result.status is not CompilationStatus.SUCCESS
            or not result.ast_available
            or not result.contracts_compiled
        ]
        indexed_projects = (
            Counter(
                (project.project_root, project.project_type.value)
                for project in runtime.index.projects
            )
            if runtime.index is not None
            else Counter()
        )
        ast_backed = (
            runtime.index is not None
            and indexed_projects == expected_compilations
            and bool(runtime.index.ast_sources)
            and not runtime.index.fallback_sources
        )
        index_state = (
            AnalysisState.DETERMINISTIC
            if ast_backed
            else (
                AnalysisState.FALLBACK_PARSER
                if runtime.index is not None and runtime.index.fallback_sources
                else AnalysisState.NOT_ANALYZED
            )
        )
        analyzed_graphs = set(runtime.graphs.analyzed_graphs) if runtime.graphs else set()
        missing_graphs = sorted(graph.value for graph in FULL_SEMANTIC_GRAPHS - analyzed_graphs)
        omitted_graphs = sorted(
            omission.graph.value
            for omission in (runtime.graphs.edge_omissions if runtime.graphs else ())
        )
        omitted_graph_facts = sorted(
            f"{omission.fact_kind.value}={omission.omitted_count}"
            for omission in (runtime.graphs.fact_omissions if runtime.graphs else ())
        )
        graph_generation_complete = bool(
            runtime.graphs is not None
            and runtime.graphs.generation_complete
            and not runtime.graphs.edge_omissions
            and not runtime.graphs.fact_omissions
        )
        semantic_graphs_complete = not missing_graphs and graph_generation_complete
        semantic_graph_failure_details = [
            *(
                ["missing graph transformations: " + ", ".join(missing_graphs)]
                if missing_graphs
                else []
            ),
            *(
                ["semantic graph generation is incomplete"]
                if runtime.graphs is not None and not runtime.graphs.generation_complete
                else []
            ),
            *(["typed graph omissions: " + ", ".join(omitted_graphs)] if omitted_graphs else []),
            *(
                ["typed graph-fact omissions: " + ", ".join(omitted_graph_facts)]
                if omitted_graph_facts
                else []
            ),
        ]
        real_scanners = [run for run in runtime.scanners if _is_real_scanner_run(run)]
        slither_records = [run for run in runtime.scanners if run.scanner == "slither"]
        real_slither = (
            slither_records[0]
            if (
                len(slither_records) == 1
                and _is_real_slither_run(slither_records[0])
                and _scanner_matches_trust_pin(
                    slither_records[0],
                    version=self.config.scanners.slither.version,
                    sha256=self.config.scanners.slither.sha256,
                )
            )
            else None
        )
        foundry_records = [run for run in runtime.scanners if run.scanner == "foundry_fork"]
        real_foundry_portfolio = (
            foundry_records[0]
            if (
                len(foundry_records) == 1
                and is_qualifying_real_foundry_portfolio(
                    foundry_records[0],
                    self.config,
                    expected_repository_sha256=runtime.repository_execution_sha256,
                )
                and _scanner_matches_trust_pin(
                    foundry_records[0],
                    version=self.config.scanners.foundry_fork.version,
                    sha256=self.config.scanners.foundry_fork.sha256,
                )
            )
            else None
        )
        invariant_count = (
            len(runtime.invariants.invariants) if runtime.invariants is not None else 0
        )
        invariant_attempts = [
            result
            for result in runtime.invariant_executions
            if result.status is not InvariantExecutionStatus.NOT_ATTEMPTED
        ]
        invariant_completed = [
            result
            for result in runtime.invariant_executions
            if result.status
            in {
                InvariantExecutionStatus.PASSED,
                InvariantExecutionStatus.COUNTEREXAMPLE,
            }
        ]
        real_invariant_executions = [
            result
            for result in runtime.invariant_executions
            if _is_real_invariant_execution(result, self.config)
        ]
        expected_harnesses = {
            (invariant_id, harness_name): harness_sha256
            for invariant_id, harness_name, harness_sha256 in runtime.expected_invariant_harnesses
        }
        observed_harness_counts = Counter(
            (result.invariant_id, result.harness_name) for result in runtime.invariant_executions
        )
        observed_harnesses = {
            (result.invariant_id, result.harness_name): result.harness_spec_sha256
            for result in runtime.invariant_executions
        }
        executable_invariant_ids = {
            invariant.id
            for invariant in (
                runtime.invariants.invariants if runtime.invariants is not None else []
            )
            if invariant.executable
        }
        invariant_inventory_bound = (
            bool(expected_harnesses)
            and all(count == 1 for count in observed_harness_counts.values())
            and set(observed_harnesses) == set(expected_harnesses)
            and observed_harnesses == expected_harnesses
            and executable_invariant_ids == {invariant_id for invariant_id, _ in expected_harnesses}
            and runtime.invariants is not None
            and runtime.invariants.executable_count == len(executable_invariant_ids)
        )
        planned_economic = {
            plan.kind
            for plan in runtime.economic_simulations
            if plan.applicable and plan.execution_required
        }
        typed_economic = {
            plan.kind
            for plan in runtime.economic_simulations
            if plan.applicable and plan.execution_required and plan.typed_harness_available
        }
        executed_economic = {
            result.economic_template
            for result in invariant_completed
            if result.economic_template is not None
        }
        missing_economic = planned_economic - executed_economic
        untyped_economic = planned_economic - typed_economic
        expected_economic_plans = plan_economic_simulations(runtime.invariants, runtime.graphs)

        def economic_plan_identity(plan: EconomicSimulationPlan) -> tuple[object, ...]:
            return (
                plan.kind,
                plan.applicable,
                tuple(plan.invariant_ids),
                plan.typed_harness_available,
                plan.execution_required,
                plan.required_transaction_ordering,
            )

        economic_plan_inventory_bound = sorted(
            (economic_plan_identity(plan) for plan in runtime.economic_simulations),
            key=repr,
        ) == sorted(
            (economic_plan_identity(plan) for plan in expected_economic_plans),
            key=repr,
        )
        attempted_ids = {
            result.candidate_id for result in runtime.reproduction_results if result.attempts > 0
        }
        resolution_counts = Counter(
            resolution.candidate_id for resolution in runtime.reproduction_resolutions
        )
        duplicate_resolutions = {
            candidate_id for candidate_id, count in resolution_counts.items() if count != 1
        }
        bound_reproduction_refs: dict[str, set[str]] = {}
        for result in runtime.reproduction_results:
            if (
                result.state
                in {
                    ReproductionState.REPRODUCED,
                    ReproductionState.REPRODUCED_AND_MINIMIZED,
                }
                and result.attempts > 0
                and result.successful_attempts == result.attempts
                and result.integrity is not None
                and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            ):
                bound_reproduction_refs.setdefault(result.candidate_id, set()).add(
                    f"reproduction:{result.integrity.integrity_sha256}"
                )
        qualifying_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.REPRODUCED
            and bool(resolution.evidence_refs)
            and set(resolution.evidence_refs)
            <= bound_reproduction_refs.get(resolution.candidate_id, set())
            and resolution.candidate_id not in duplicate_resolutions
        }
        unbound_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.REPRODUCED
            and resolution.candidate_id not in qualifying_resolution_ids
        }
        inconclusive_resolution_ids = {
            resolution.candidate_id
            for resolution in runtime.reproduction_resolutions
            if resolution.kind is ReproductionResolutionKind.INCONCLUSIVE
        }
        missing_reproduction = (
            (runtime.feasible_high_critical_ids - qualifying_resolution_ids)
            | (runtime.feasible_high_critical_ids & duplicate_resolutions)
            | (runtime.feasible_high_critical_ids & unbound_resolution_ids)
        )
        undocumented_impossible = (
            runtime.eligible_high_critical_ids
            - runtime.feasible_high_critical_ids
            - runtime.documented_infeasible_ids
        )
        formal_records_by_name: dict[str, list[FormalToolRun]] = {}
        for run in runtime.formal_runs:
            formal_records_by_name.setdefault(run.tool, []).append(run)
        real_property_engines = {
            tool: records[0]
            for tool, records in formal_records_by_name.items()
            if (
                len(records) == 1
                and _is_real_property_engine_run(records[0])
                and _formal_run_matches_config_pin(records[0], self.config)
                and _formal_run_matches_expected_corpus(records[0], runtime)
            )
        }
        real_formal_proofs = {
            tool: records[0]
            for tool, records in formal_records_by_name.items()
            if tool in CERTIFIED_FORMAL_PROOF_ENGINES
            and len(records) == 1
            and _is_real_formal_proof_run(records[0])
            and _formal_run_matches_config_pin(records[0], self.config)
            and _formal_run_matches_expected_corpus(records[0], runtime)
        }
        expected_replay_components = _expected_replay_components(runtime, expected_harnesses)
        expected_replay_kinds = {kind for kind, _identifier in expected_replay_components}
        offline_replay_qualified = offline_replay_is_qualifying(
            runtime.offline_replay,
            expected_run_id=runtime.replay_run_id,
            expected_manifest_sha256=runtime.replay_manifest_sha256,
            expected_verification_sha256=runtime.replay_verification_sha256,
            expected_applicable_kinds=expected_replay_kinds,
            expected_components=expected_replay_components,
        )
        production_qualification = _current_production_qualification(
            runtime.production_qualification
        )
        audit_selection = _current_audit_model_selection(
            runtime.audit_model_selection_evidence,
            runtime.verified_audit_model_selection,
            production_qualification,
        )
        audit_refresh = _current_audit_model_refresh(
            runtime.audit_model_refresh_evidence,
            runtime.audit_model_refresh_guard,
            production_qualification,
            audit_selection,
        )
        audit_refresh_pricing = _current_audit_model_refresh_pricing(
            runtime.audit_model_refresh_pricing_evidence,
            runtime.audit_model_refresh_pricing_authority,
            production_qualification,
            audit_selection,
            audit_refresh,
            runtime.audit_model_refresh_guard,
        )
        real_provider_session = _real_provider_session_is_qualifying(runtime.provider_session)
        promoted_recovery_coordinates = _promoted_recovery_request_coordinates(
            runtime.scheduler_artifact
        )
        real_model_records = [
            record
            for record in runtime.model_usage
            if _is_real_model_usage(
                record,
                self.config,
                production_qualification,
                runtime.provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=(
                    promoted_recovery_coordinates.get(record.request_id, (None, None))[0]
                ),
                recovery_request_limit_count_before=(
                    promoted_recovery_coordinates.get(record.request_id, (None, None))[1]
                ),
            )
        ]
        real_model_roles = {record.role for record in real_model_records}
        qualified_selection_model_ids = (
            set(audit_selection.selected_model_ids) if audit_selection is not None else set()
        )
        executed_qualified_model_ids = {record.requested_model for record in real_model_records}
        qualified_selection_execution_complete = bool(qualified_selection_model_ids) and (
            executed_qualified_model_ids == qualified_selection_model_ids
        )
        model_coverage_backed_by_real_usage = _model_coverage_is_backed_by_real_usage(
            runtime.model_review_coverage,
            runtime.model_usage,
            runtime.model_surface_review_artifacts,
            runtime.promoted_truncation_recovery_surface_coverages,
            runtime.promoted_recursive_recovery_surface_coverages,
            self.config,
            production_qualification,
            runtime.provider_session,
            audit_selection,
            audit_refresh,
            audit_refresh_pricing,
            scheduler_artifact=runtime.scheduler_artifact,
            recovery_request_limit_coordinates=promoted_recovery_coordinates,
        )
        if runtime.model_review_coverage is None:
            model_coverage_detail = "per-surface model review coverage was not produced"
        elif not model_coverage_backed_by_real_usage:
            model_coverage_detail = (
                "model surface credits are not backed by matching certification-grade "
                "technical qualification, audit-policy selection, and current model-refresh "
                "custody for real-provider usage"
            )
        elif runtime.model_review_coverage.critical.denominator == 0:
            model_coverage_detail = (
                "critical-surface denominator is zero; maximum assurance requires "
                "a non-empty critical-surface inventory"
            )
        else:
            model_coverage_detail = (
                f"{runtime.model_review_coverage.critical.numerator}/"
                f"{runtime.model_review_coverage.critical.denominator} critical "
                "surface(s) received independent technical-qualified, policy-selected "
                "registered-lineage review"
            )
        qualified_candidate_falsifier_lineages = {
            candidate_id: _real_model_usage_lineages(
                [
                    record
                    for record in real_model_records
                    if record.role.startswith(candidate_falsifier_role_prefix(candidate_id) + ":")
                    and record.request_id
                    in runtime.candidate_falsifier_request_ids.get(candidate_id, set())
                ],
                production_qualification,
            )
            for candidate_id in sorted(runtime.eligible_high_critical_ids)
        }
        falsifier_lineage_minimum = min(
            (len(lineages) for lineages in qualified_candidate_falsifier_lineages.values()),
            default=0,
        )
        candidate_falsifier_complete = bool(runtime.eligible_high_critical_ids) and all(
            len(lineages) >= CERTIFIED_ENSEMBLE_MIN_FALSIFIER_LINEAGES
            for lineages in qualified_candidate_falsifier_lineages.values()
        )
        real_specialist_roles = {
            role
            for request_role in real_model_roles
            if (role := canonical_specialist_role(request_role)) is not None
        }
        completed_specialist_evidence, specialist_execution_errors = _specialist_execution_errors(
            runtime
        )
        specialist_execution_bound = not specialist_execution_errors
        accepted_real_specialist_roles = completed_specialist_evidence & real_specialist_roles
        required_candidate_independent_roles = set(CANDIDATE_INDEPENDENT_SPECIALIST_ROLES)
        accepted_real_candidate_independent_roles = (
            accepted_real_specialist_roles & required_candidate_independent_roles
        )
        missing_candidate_independent_roles = (
            required_candidate_independent_roles - accepted_real_candidate_independent_roles
        )
        accepted_real_candidate_dependent_roles = accepted_real_specialist_roles & set(
            CANDIDATE_DEPENDENT_SPECIALIST_ROLES
        )
        executed_root_lineages = _real_model_usage_lineages(
            real_model_records,
            production_qualification,
        )
        whole_protocol_root_lineages = _real_model_usage_lineages(
            [
                record
                for record in real_model_records
                if source_backed_whole_protocol_context(record) is not None
            ],
            production_qualification,
        )
        critical_surface_lineages = (
            {
                surface.surface_id: set(surface.root_lineages)
                for surface in runtime.model_review_coverage.surfaces
                if surface.critical
            }
            if model_coverage_backed_by_real_usage and runtime.model_review_coverage is not None
            else {}
        )
        critical_surface_lineage_minimum = min(
            (len(lineages) for lineages in critical_surface_lineages.values()),
            default=0,
        )
        critical_surface_ensemble_complete = bool(critical_surface_lineages) and all(
            len(lineages) >= CERTIFIED_ENSEMBLE_MIN_CRITICAL_SURFACE_LINEAGES
            for lineages in critical_surface_lineages.values()
        )
        certified_ensemble_complete = (
            len(executed_qualified_model_ids) >= CERTIFIED_ENSEMBLE_MIN_EXACT_MODELS
            and qualified_selection_execution_complete
            and len(executed_root_lineages) >= CERTIFIED_ENSEMBLE_MIN_ROOT_LINEAGES
            and specialist_execution_bound
            and not missing_candidate_independent_roles
            and len(whole_protocol_root_lineages) >= CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES
            and critical_surface_ensemble_complete
            and (candidate_falsifier_complete or not runtime.eligible_high_critical_ids)
        )
        certified_falsifier_detail = (
            "N/A (no high/critical candidates)"
            if not runtime.eligible_high_critical_ids
            else (
                f"minimum={falsifier_lineage_minimum}/"
                f"{CERTIFIED_ENSEMBLE_MIN_FALSIFIER_LINEAGES} across "
                f"{len(runtime.eligible_high_critical_ids)} candidate(s)"
            )
        )
        certified_ensemble_detail = (
            f"exact models={len(executed_qualified_model_ids)}/"
            f"{CERTIFIED_ENSEMBLE_MIN_EXACT_MODELS}; "
            f"selected executed={len(executed_qualified_model_ids)}/"
            f"{len(qualified_selection_model_ids)}; "
            f"root lineages={len(executed_root_lineages)}/"
            f"{CERTIFIED_ENSEMBLE_MIN_ROOT_LINEAGES}; "
            "candidate-independent specialist responsibilities="
            f"{len(accepted_real_candidate_independent_roles)}/"
            f"{CERTIFIED_ENSEMBLE_MIN_SPECIALIST_RESPONSIBILITIES}; "
            "candidate-dependent specialist extras="
            f"{len(accepted_real_candidate_dependent_roles)}/"
            f"{len(CANDIDATE_DEPENDENT_SPECIALIST_ROLES)}; "
            "missing candidate-independent roles="
            f"{','.join(sorted(missing_candidate_independent_roles)) or 'none'}; "
            f"whole-protocol lineages={len(whole_protocol_root_lineages)}/"
            f"{CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES}; "
            f"critical surfaces={len(critical_surface_lineages)} with minimum "
            f"lineages={critical_surface_lineage_minimum}/"
            f"{CERTIFIED_ENSEMBLE_MIN_CRITICAL_SURFACE_LINEAGES}; "
            f"candidate falsifier lineages={certified_falsifier_detail}"
        )
        benchmark_required = (
            self.requested
            or self.config.maximum_assurance.benchmark_gate
            or self.config.maximum_assurance.ci_mode
        )
        benchmark_qualified = (
            runtime.benchmark_verification is not None
            and runtime.benchmark_verification.status is CertificateVerificationStatus.CURRENT
            and runtime.benchmark_repository_git_commit is not None
            and runtime.benchmark_verification.observed_repository_git_commit
            == runtime.benchmark_repository_git_commit
            and runtime.benchmark_verification.origin is CertificateVerificationOrigin.FILE_BACKED
            and runtime.benchmark_verification.file_backed_evidence is not None
            and runtime.benchmark_verification.file_backed_evidence.benchmark_profile
            is AuditProfile.MAXIMUM_ASSURANCE
            and runtime.benchmark_verification.file_backed_evidence.benchmark_reports_loaded > 0
            and "benchmark-certificate-verification.json" in runtime.artifacts
        )
        base_roles = {
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
        }
        completed_specialists = (
            completed_specialist_evidence
            & set(SPECIALIST_INVESTIGATOR_ROLES)
            & real_specialist_roles
        )
        completed_auxiliary = (
            completed_specialist_evidence & set(SPECIALIST_AUXILIARY_ROLES) & real_specialist_roles
        )
        missing_investigators = set(SPECIALIST_INVESTIGATOR_ROLES) - completed_specialists
        scheduler_errors = _scheduler_assurance_errors(
            self.config,
            runtime,
            audit_selection,
            audit_refresh,
            audit_refresh_pricing,
        )
        scheduler_complete = not scheduler_errors
        language_capability_complete = (
            runtime.language_capability is not None
            and runtime.language_capability.requested_profile
            is LanguageCapabilityProfile.SOLIDITY_EVM
            and runtime.language_capability.achieved_profile
            is LanguageCapabilityProfile.SOLIDITY_EVM
            and runtime.language_capability.status is LanguageCapabilityStatus.MATCHED
            and runtime.language_capability.evm_portfolio_applicable
            and runtime.language_capability.evm_maximum_assurance_eligible
            and not runtime.language_capability.blocking_discovery_omissions
            and "language-capability.json" in runtime.artifacts
        )
        clauses = [
            _requirement(
                "seven_pass_scheduler",
                scheduler_complete,
                (
                    "all seven ordered scheduler passes completed with exact runtime bindings "
                    "and real provider evidence"
                    if scheduler_complete
                    else "; ".join(scheduler_errors)
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if scheduler_complete
                    else (
                        AnalysisState.NOT_ANALYZED
                        if runtime.scheduler_artifact is None
                        else AnalysisState.ATTEMPTED_FAILED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scheduler-state.json"),
            ),
            _requirement(
                "solidity_evm_language_capability",
                language_capability_complete,
                (
                    "source-bound Solidity/EVM language capability matched and was serialized"
                    if language_capability_complete
                    else (
                        "source-bound Solidity/EVM language capability was not achieved"
                        if runtime.language_capability is None
                        else (
                            "matched Solidity/EVM language capability artifact was not serialized"
                            if runtime.language_capability.status
                            is LanguageCapabilityStatus.MATCHED
                            and runtime.language_capability.evm_maximum_assurance_eligible
                            and "language-capability.json" not in runtime.artifacts
                            else (
                                "language capability discovery retained blocking omissions: "
                                + ", ".join(
                                    runtime.language_capability.blocking_discovery_omissions
                                )
                                if runtime.language_capability.blocking_discovery_omissions
                                else (
                                    f"requested={runtime.language_capability.requested_profile.value}; "
                                    f"status={runtime.language_capability.status.value}; "
                                    "maximum-assurance-eligible="
                                    f"{runtime.language_capability.evm_maximum_assurance_eligible}"
                                )
                            )
                        )
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if language_capability_complete
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.language_capability is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "language-capability.json"),
            ),
            _requirement(
                "full_protocol_scope",
                runtime.scope_assessment is not None
                and runtime.scope_assessment.requested is AuditScope.FULL_PROTOCOL
                and runtime.scope_assessment.complete,
                (
                    f"requested={runtime.scope_assessment.requested.value}; "
                    f"achieved="
                    f"{runtime.scope_assessment.achieved.value if runtime.scope_assessment.achieved else 'none'}"
                    if runtime.scope_assessment is not None
                    else "audit-scope assessment was not produced"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if runtime.scope_assessment is not None and runtime.scope_assessment.complete
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.scope_assessment is not None
                        and any(
                            item.required and item.status is ScopeEvidenceStatus.OMITTED
                            for item in runtime.scope_assessment.components
                        )
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scope-assessment.json"),
            ),
            _requirement(
                "solidity_project_detection",
                bool(runtime.projects),
                (
                    f"{len(runtime.projects)} Solidity project(s) detected"
                    if runtime.projects
                    else "no Solidity project was detected"
                ),
                artifacts=_present(runtime.artifacts, "solidity-projects.json"),
            ),
            _requirement(
                "compilation",
                compilation_succeeded,
                (
                    "all detected projects compiled successfully with compiler AST output"
                    if compilation_succeeded
                    else _compilation_failure_detail(
                        missing=missing_compilations,
                        unexpected=unexpected_compilations,
                        incomplete=incomplete_compilations,
                        attempted=compilation_attempted,
                    )
                ),
                state=compilation_state,
                artifacts=_present(runtime.artifacts, "solidity-compilation.json"),
            ),
            _requirement(
                "ast_backed_index",
                ast_backed,
                (
                    f"{len(runtime.index.ast_sources)} source file(s) indexed from compiler AST"
                    if ast_backed and runtime.index
                    else (
                        "compiler AST index is incomplete, project-mismatched, or includes "
                        "fallback-parsed sources"
                    )
                ),
                state=index_state,
                artifacts=_present(runtime.artifacts, "solidity-index.json"),
            ),
            _requirement(
                "full_semantic_graphs",
                semantic_graphs_complete,
                (
                    "all required semantic graph transformations completed"
                    if semantic_graphs_complete
                    else "; ".join(semantic_graph_failure_details)
                ),
                artifacts=_present(runtime.artifacts, "solidity-graphs.json"),
            ),
            _requirement(
                "deterministic_scanners",
                bool(real_scanners),
                (
                    f"{len(real_scanners)} real isolated deterministic scanner(s) completed"
                    if real_scanners
                    else "no scanner produced qualifying real isolated execution evidence"
                ),
                state=(
                    AnalysisState.SCANNER_SUPPORTED
                    if real_scanners
                    else AnalysisState.ATTEMPTED_FAILED
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "slither_execution",
                real_slither is not None,
                (
                    "one exact real isolated Slither execution completed"
                    if real_slither is not None
                    else (
                        f"{len(slither_records)} Slither record(s) exist but exact qualifying "
                        "real execution evidence is absent or ambiguous"
                    )
                ),
                state=(
                    AnalysisState.SCANNER_SUPPORTED
                    if real_slither is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if slither_records
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "foundry_unit_property_invariant_execution",
                real_foundry_portfolio is not None,
                (
                    "one exact real isolated Foundry suite observed non-empty conclusive unit, "
                    "property/fuzz, and invariant campaigns"
                    if real_foundry_portfolio is not None
                    else (
                        f"{len(foundry_records)} Foundry suite record(s) exist but exact "
                        "qualifying observed execution evidence is absent or ambiguous"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_foundry_portfolio is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if foundry_records
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "scanner-results.json"),
            ),
            _requirement(
                "specialist_execution_evidence",
                specialist_execution_bound,
                (
                    "specialist responsibilities are derived from exact host-accepted outcomes"
                    if specialist_execution_bound
                    else "; ".join(specialist_execution_errors)
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if runtime.specialist_execution_records
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "multi_agent_review",
                specialist_execution_bound
                and base_roles <= real_model_roles
                and len(completed_specialists)
                >= self.config.maximum_assurance.minimum_specialist_agents
                and not missing_investigators,
                (
                    f"{len(completed_specialists)} real-provider specialist role(s) completed; "
                    f"{self.config.maximum_assurance.minimum_specialist_agents} required; "
                    f"missing investigators={','.join(sorted(missing_investigators)) or 'none'}"
                ),
                state=(
                    AnalysisState.MODEL_ONLY if real_model_records else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "critical_model_surface_review",
                bool(real_model_records)
                and runtime.model_review_coverage is not None
                and runtime.model_review_coverage.applicable
                and runtime.model_review_coverage.critical.denominator > 0
                and runtime.model_review_coverage.critical_gate_passed
                and model_coverage_backed_by_real_usage,
                model_coverage_detail,
                state=(
                    AnalysisState.MODEL_ONLY
                    if real_model_records
                    and runtime.model_review_coverage is not None
                    and runtime.model_review_coverage.applicable
                    and runtime.model_review_coverage.critical.denominator > 0
                    and model_coverage_backed_by_real_usage
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "model-review-coverage.json"),
            ),
            _requirement(
                "known_issue_taxonomy_critical_disposition",
                runtime.taxonomy_coverage is not None
                and runtime.taxonomy_coverage.critical_gate_passed,
                (
                    f"{runtime.taxonomy_coverage.critical.numerator}/"
                    f"{runtime.taxonomy_coverage.critical.denominator} applicable critical "
                    "known-issue classes received explicit credited review; critical gaps="
                    f"{','.join(runtime.taxonomy_coverage.critical_gap_ids) or 'none'}"
                    if runtime.taxonomy_coverage is not None
                    else "known-issue taxonomy coverage was not produced"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if runtime.taxonomy_coverage is not None
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=(
                    _present(runtime.artifacts, "known-issue-taxonomy-coverage.json")
                    + _present(runtime.artifacts, "known-issue-taxonomy.json")
                ),
            ),
            _requirement(
                "certified_model_ensemble",
                certified_ensemble_complete,
                certified_ensemble_detail,
                state=(
                    AnalysisState.MODEL_ONLY if real_model_records else AnalysisState.NOT_ANALYZED
                ),
                artifacts=sorted(
                    _present(runtime.artifacts, "specialist-execution.json")
                    + _present(runtime.artifacts, "model-review-coverage.json")
                    + _present(
                        runtime.artifacts,
                        "model-qualification-runtime.json",
                    )
                ),
            ),
            _requirement(
                "invariant_discovery",
                runtime.invariants is not None and invariant_count > 0,
                f"{invariant_count} source-linked invariant(s) discovered",
                artifacts=_present(runtime.artifacts, "solidity-invariants.json"),
            ),
            _requirement(
                "independent_invariant_review",
                "invariant_review" in completed_auxiliary,
                (
                    "dedicated real-provider non-finding invariant-review role completed"
                    if "invariant_review" in completed_auxiliary
                    else "dedicated real-provider invariant-review role did not complete"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if "invariant_review" in completed_auxiliary
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "invariant-review.json"),
            ),
            _requirement(
                "stateful_invariant_execution",
                invariant_inventory_bound
                and bool(runtime.invariant_executions)
                and len(real_invariant_executions) == len(runtime.invariant_executions),
                (
                    (
                        f"{len(real_invariant_executions)}/{len(expected_harnesses)} "
                        "expected typed stateful invariant harness(es) completed with real "
                        "isolated, replayed campaign evidence"
                    )
                    if invariant_inventory_bound
                    else "stateful invariant results do not exactly match the sealed "
                    "executable harness inventory"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if invariant_inventory_bound
                    and runtime.invariant_executions
                    and len(real_invariant_executions) == len(runtime.invariant_executions)
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if invariant_attempts
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "invariant-execution-results.json"),
            ),
            _requirement(
                "protocol_economic_simulation",
                economic_plan_inventory_bound and not missing_economic,
                (
                    f"{len(executed_economic & planned_economic)}/"
                    f"{len(planned_economic)} applicable economic template(s) executed"
                    + (
                        f"; {len(untyped_economic)} selected template(s) lack deterministic "
                        "typed harness support"
                        if untyped_economic
                        else ""
                    )
                    if planned_economic
                    else (
                        "no protocol-specific economic simulation was applicable"
                        if economic_plan_inventory_bound
                        else "economic simulation plan does not match deterministic applicability"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if economic_plan_inventory_bound and not missing_economic
                    else (
                        AnalysisState.NOT_ANALYZED
                        if untyped_economic
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if executed_economic
                            else AnalysisState.NOT_ANALYZED
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "economic-simulation-plan.json"),
            ),
            _requirement(
                "critical_high_reproduction",
                not missing_reproduction and not undocumented_impossible,
                (
                    f"{len(qualifying_resolution_ids & runtime.feasible_high_critical_ids)}/"
                    f"{len(runtime.feasible_high_critical_ids)} feasible high/critical "
                    "candidate(s) received qualifying terminal resolutions"
                    + (
                        f"; {len(missing_reproduction)} feasible candidate(s) remain unresolved"
                        if missing_reproduction
                        else ""
                    )
                    + (
                        f"; {len(inconclusive_resolution_ids & runtime.feasible_high_critical_ids)} "
                        "feasible candidate(s) are explicitly inconclusive"
                        if inconclusive_resolution_ids & runtime.feasible_high_critical_ids
                        else ""
                    )
                    + (
                        f"; {len(duplicate_resolutions)} candidate(s) have ambiguous resolutions"
                        if duplicate_resolutions
                        else ""
                    )
                    + (
                        f"; {len(unbound_resolution_ids)} reproduced resolution(s) are not "
                        "bound to qualifying raw runtime evidence"
                        if unbound_resolution_ids
                        else ""
                    )
                    + (
                        f"; {len(undocumented_impossible)} infeasible candidate(s) lacked a reason"
                        if undocumented_impossible
                        else ""
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if not runtime.feasible_high_critical_ids and not undocumented_impossible
                    else (
                        AnalysisState.REPRODUCED
                        if not missing_reproduction and not undocumented_impossible
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if attempted_ids or runtime.reproduction_resolutions
                            else AnalysisState.NOT_ANALYZED
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "reproduction-results.json"),
            ),
            _requirement(
                "independent_verifier",
                runtime.verifier_completed
                and ("verifier" in real_model_roles or not runtime.eligible_high_critical_ids),
                (
                    "independent real-provider verifier completed"
                    if (
                        runtime.verifier_completed
                        and (
                            "verifier" in real_model_roles or not runtime.eligible_high_critical_ids
                        )
                    )
                    else "independent real-provider verifier did not complete"
                ),
            ),
            _requirement(
                "independent_falsifier",
                (runtime.falsifier_completed and candidate_falsifier_complete)
                or not runtime.eligible_high_critical_ids,
                (
                    "two independent candidate-falsifier lineages completed for every "
                    "eligible high/critical candidate"
                    if (runtime.falsifier_completed and candidate_falsifier_complete)
                    else (
                        "no eligible high/critical candidate required falsification"
                        if not runtime.eligible_high_critical_ids
                        else (
                            f"minimum {falsifier_lineage_minimum} independent "
                            "candidate-falsifier lineage(s) per candidate are backed by "
                            "certification-grade real-provider usage; 2 required "
                            f"for each of {len(runtime.eligible_high_critical_ids)} candidate(s)"
                        )
                    )
                ),
                artifacts=_present(runtime.artifacts, "cross-examination.json"),
            ),
            _requirement(
                "independent_test_synthesis",
                (
                    {"test_generation", "exploit_reproduction_planner"} <= completed_auxiliary
                    or not runtime.eligible_high_critical_ids
                ),
                (
                    "independent test-generation and exploit-planning roles completed"
                    if {
                        "test_generation",
                        "exploit_reproduction_planner",
                    }
                    <= completed_auxiliary
                    else (
                        "no eligible high/critical candidate required test synthesis"
                        if not runtime.eligible_high_critical_ids
                        else "one or more independent test-synthesis roles did not complete"
                    )
                ),
            ),
            _requirement(
                "evidence_capped_judge",
                runtime.judge_completed
                and ("judge" in real_model_roles or not runtime.eligible_high_critical_ids),
                (
                    "evidence-capped real-provider judge completed"
                    if (
                        runtime.judge_completed
                        and ("judge" in real_model_roles or not runtime.eligible_high_critical_ids)
                    )
                    else "evidence-capped real-provider judge did not complete"
                ),
            ),
            _requirement(
                "report_quality_review",
                "report_quality" in completed_auxiliary,
                (
                    "independent real-provider report-quality review completed"
                    if "report_quality" in completed_auxiliary
                    else "independent real-provider report-quality review did not complete"
                ),
            ),
            _requirement(
                "coverage_report",
                runtime.coverage is not None,
                (
                    "coverage artifact generated"
                    if runtime.coverage is not None
                    else "coverage artifact missing"
                ),
                artifacts=_present(runtime.artifacts, "solidity-coverage.json"),
            ),
            _requirement(
                "formal_adapter_inventory",
                bool(real_property_engines or real_formal_proofs),
                (
                    f"{len(real_property_engines) + len(real_formal_proofs)} qualifying real "
                    "formal/property engine result(s) recorded"
                    if real_property_engines or real_formal_proofs
                    else "formal/property adapter layer produced no qualifying real execution"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_property_engines or real_formal_proofs
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.formal_runs
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "formal-results.json"),
            ),
            _requirement(
                "formal_proof_engine",
                bool(real_formal_proofs),
                (
                    "real isolated formal proof engine(s) completed: "
                    + ", ".join(sorted(real_formal_proofs))
                    if real_formal_proofs
                    else (
                        "no Certora, Kontrol, or Solidity SMTChecker record contained "
                        "qualifying real isolated execution evidence"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_formal_proofs
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.formal_runs
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_formal_artifacts(list(real_formal_proofs.values())),
            ),
            _requirement(
                "isolated_replay_execution",
                offline_replay_qualified,
                (
                    f"{len(runtime.offline_replay.components)} sealed scanner, saved-test, and "
                    "counterexample replay component(s) matched under real isolation"
                    if offline_replay_qualified and runtime.offline_replay is not None
                    else "no qualifying manifest-bound real offline replay was supplied"
                ),
                state=(
                    AnalysisState.REPRODUCED
                    if offline_replay_qualified
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.offline_replay is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "offline-replay.json"),
            ),
            _requirement(
                "production_model_qualification",
                production_qualification is not None,
                (
                    f"{len(production_qualification.models)} exact Tier A model(s) across "
                    f"{len({model.root_lineage for model in production_qualification.models})} "
                    "independently reviewed root lineage(s) are bound to current real "
                    "technical benchmark evidence"
                    if production_qualification is not None
                    else (
                        "no current verified production qualification capability was supplied; "
                        "configured quality hash text is not runtime evidence"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if production_qualification is not None
                    else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "model-qualification-runtime.json",
                ),
            ),
            _requirement(
                "audit_model_refresh_custody",
                audit_refresh is not None,
                (
                    "current veto-only refresh evidence is exact-joined to the independently "
                    "verified technical and audit selections"
                    if audit_refresh is not None
                    else (
                        "no current exact model-refresh custody matched the independently "
                        "verified technical selection, audit selection, scheduler binding, and "
                        "usage routes"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if audit_refresh is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.audit_model_refresh_evidence is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "audit-model-refresh-evidence.json",
                ),
            ),
            _requirement(
                "audit_model_refresh_pricing_custody",
                audit_refresh_pricing is not None,
                (
                    "current bounded pricing evidence is exact-joined to refresh, technical, "
                    "audit-selection, scheduler, and per-attempt cost custody"
                    if audit_refresh_pricing is not None
                    else (
                        "no current bounded pricing authority matched refresh, technical, "
                        "audit-selection, scheduler, and per-attempt cost custody"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if audit_refresh_pricing is not None
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.audit_model_refresh_pricing_evidence is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "audit-model-refresh-pricing-evidence.json",
                ),
            ),
            _requirement(
                "real_provider_session_provenance",
                real_provider_session,
                (
                    "model usage is bound to the pipeline-owned concrete REAL provider session"
                    if real_provider_session
                    else (
                        "no pipeline-owned concrete REAL provider session with "
                        "execution-consistent usage was supplied"
                    )
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if real_provider_session
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.model_usage
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "qualified_model_selection_execution",
                qualified_selection_execution_complete,
                (
                    f"{len(executed_qualified_model_ids)}/"
                    f"{len(qualified_selection_model_ids)} exact audit-policy-selected "
                    "Tier A model(s) have successful policy- and refresh-bound real-provider usage"
                    if qualified_selection_model_ids
                    else "no current audit policy-selected model authority was available"
                ),
                state=(
                    AnalysisState.MODEL_ONLY
                    if qualified_selection_execution_complete
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if real_model_records
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=sorted(
                    _present(runtime.artifacts, "model-qualification-runtime.json")
                    + _present(runtime.artifacts, "audit-model-selection-evidence.json")
                ),
            ),
            _requirement(
                "real_model_execution",
                bool(real_model_records),
                (
                    f"{len(real_model_records)} policy-selected, refresh-bound real-provider "
                    "model request(s) completed"
                    if real_model_records
                    else "no audit-policy-selected real-provider model request completed"
                ),
                state=(
                    AnalysisState.MODEL_ONLY if real_model_records else AnalysisState.NOT_ANALYZED
                ),
                artifacts=_present(runtime.artifacts, "specialist-execution.json"),
            ),
            _requirement(
                "certified_execution_isolation",
                real_slither is not None
                and real_foundry_portfolio is not None
                and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                and bool(real_formal_proofs)
                and invariant_inventory_bound
                and len(real_invariant_executions) == len(expected_harnesses)
                and offline_replay_qualified,
                (
                    "every mandatory scanner, property, proof, invariant, and replay "
                    "portfolio member has real hardened-isolation evidence"
                    if (
                        real_slither is not None
                        and real_foundry_portfolio is not None
                        and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                        and bool(real_formal_proofs)
                        and invariant_inventory_bound
                        and len(real_invariant_executions) == len(expected_harnesses)
                        and offline_replay_qualified
                    )
                    else "one or more mandatory portfolio members lacks real hardened-isolation "
                    "execution evidence"
                ),
                state=(
                    AnalysisState.DETERMINISTIC
                    if (
                        real_slither is not None
                        and real_foundry_portfolio is not None
                        and set(real_property_engines) >= CERTIFIED_PROPERTY_ENGINES
                        and bool(real_formal_proofs)
                        and invariant_inventory_bound
                        and len(real_invariant_executions) == len(expected_harnesses)
                        and offline_replay_qualified
                    )
                    else AnalysisState.ATTEMPTED_FAILED
                ),
            ),
            _requirement(
                "benchmark_regression_gate",
                benchmark_qualified,
                (
                    "file-backed benchmark certificate "
                    f"{runtime.benchmark_verification.certificate_sha256} is current"
                    if benchmark_qualified and runtime.benchmark_verification is not None
                    else (
                        "benchmark certificate is stale"
                        if runtime.benchmark_verification is not None
                        and runtime.benchmark_verification.status
                        is CertificateVerificationStatus.STALE
                        else (
                            "benchmark verification was not loaded from a sealed "
                            "maximum-assurance certificate and complete non-empty "
                            "passed-report files"
                            if runtime.benchmark_verification is not None
                            else "benchmark gate was not requested"
                        )
                    )
                ),
                required=benchmark_required,
                state=(
                    AnalysisState.DETERMINISTIC
                    if benchmark_qualified
                    else (
                        AnalysisState.ATTEMPTED_FAILED
                        if runtime.benchmark_verification is not None
                        else AnalysisState.NOT_ANALYZED
                    )
                ),
                artifacts=_present(
                    runtime.artifacts,
                    "benchmark-certificate-verification.json",
                ),
            ),
        ]
        for tool in self.config.formal.required_tools:
            records = formal_records_by_name.get(tool, [])
            required_run = records[0] if len(records) == 1 else None
            qualifies = (
                required_run is not None
                and (
                    _is_real_property_engine_run(required_run)
                    if tool in CERTIFIED_PROPERTY_ENGINES
                    else (
                        _is_real_formal_proof_run(required_run)
                        if tool in CERTIFIED_FORMAL_PROOF_ENGINES
                        else _is_real_formal_run(required_run)
                    )
                )
                and _formal_run_matches_config_pin(required_run, self.config)
                and (
                    tool not in (CERTIFIED_PROPERTY_ENGINES | CERTIFIED_FORMAL_PROOF_ENGINES)
                    or _formal_run_matches_expected_corpus(required_run, runtime)
                )
            )
            clauses.append(
                _requirement(
                    f"required_formal_tool:{tool}",
                    qualifies,
                    (
                        f"{tool} completed with qualifying real isolated non-empty evidence"
                        if qualifies
                        else (
                            f"{tool} emitted {len(records)} ambiguous or non-qualifying "
                            "run record(s)"
                            if records
                            else f"{tool} did not produce a run record"
                        )
                    ),
                    state=(
                        AnalysisState.DETERMINISTIC
                        if qualifies
                        else (
                            AnalysisState.ATTEMPTED_FAILED
                            if records
                            else AnalysisState.NOT_ANALYZED
                        )
                    ),
                    artifacts=(
                        _formal_artifacts([required_run]) if required_run is not None else []
                    ),
                )
            )
        return clauses

    def _configured_families(self) -> set[str]:
        values: Iterable[str]
        specialists = getattr(self.config.models, "specialists", {})
        values = [
            self.config.models.role(role).primary
            for role in (
                "threat_model",
                "source_audit",
                "business_logic",
                "configuration",
                "verifier",
                "judge",
            )
        ]
        if isinstance(specialists, dict):
            values = [*values, *(slot.primary for slot in specialists.values())]
        return {model_family(identifier) for identifier in values}

    def _configured_specialist_roles(self) -> set[str]:
        specialists = getattr(self.config.models, "specialists", {})
        return set(specialists) if isinstance(specialists, dict) else set()


def _requirement(
    engine: str,
    passed: bool,
    detail: str,
    *,
    required: bool = True,
    state: AnalysisState | None = None,
    artifacts: list[str] | None = None,
) -> MaximumAssuranceRequirement:
    return MaximumAssuranceRequirement(
        engine=engine,
        required=required,
        passed=passed,
        blocking=required and not passed,
        state=state or (AnalysisState.DETERMINISTIC if passed else AnalysisState.NOT_ANALYZED),
        detail=detail,
        artifacts=artifacts or [],
    )


def _is_sha256(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _positive_integer(value: int | None) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _positive_integer_at_least(value: int | None, minimum: int) -> bool:
    return _positive_integer(value) and value is not None and value >= minimum


def _formal_execution_observation_matches(run: FormalToolRun) -> bool:
    return (
        _is_sha256(run.execution_observation_sha256)
        and run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    )


def _is_real_scanner_run(run: ScannerRun) -> bool:
    return (
        run.status is ScannerStatus.SUCCESS
        and run.execution_evidence is ExecutionEvidenceKind.REAL
        and bool(run.version)
        and _is_sha256(run.executable_sha256)
        and bool(run.command)
        and bool(run.raw_output_path)
        and _is_sha256(run.raw_output_sha256)
        and run.raw_output_bytes > 0
        and run.process_exit_code is not None
        and run.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
        and _is_sha256(run.isolation_attestation_sha256)
        and run.finished_at >= run.started_at
    )


def _scanner_execution_observation_matches(run: ScannerRun) -> bool:
    return (
        _is_sha256(run.execution_observation_sha256) and run.execution_observation_sha256_is_valid()
    )


def is_qualifying_real_scanner_run(run: ScannerRun) -> bool:
    """Return whether a scanner has strict REAL, isolated, machine-validated evidence."""

    return (
        _is_real_scanner_run(run)
        and run.machine_output_validated
        and _scanner_execution_observation_matches(run)
    )


def _is_real_slither_run(run: ScannerRun) -> bool:
    return (
        run.scanner == "slither"
        and is_qualifying_real_scanner_run(run)
        and run.process_exit_code == 0
    )


def _scanner_matches_trust_pin(
    run: ScannerRun,
    *,
    version: str | None,
    sha256: str | None,
) -> bool:
    return (
        version is not None
        and sha256 is not None
        and run.executable_sha256 == sha256
        and run.version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(version)}(?![0-9.])",
            run.version,
        )
        is not None
    )


def _formal_run_matches_config_pin(run: FormalToolRun, config: AuditConfig) -> bool:
    formal = config.formal
    pins: dict[str, tuple[str | None, str | None]] = {
        "echidna": (formal.echidna_version, formal.echidna_sha256),
        "medusa": (formal.medusa_version, formal.medusa_sha256),
        "halmos": (formal.halmos_version, formal.halmos_sha256),
        "kontrol": (formal.kontrol_version, formal.kontrol_sha256),
        "certora": (
            formal.certora.cli_version if formal.certora.enabled else None,
            formal.certora.cli_sha256 if formal.certora.enabled else None,
        ),
    }
    expected = pins.get(run.tool)
    if expected is None:
        return False
    version, sha256 = expected
    if (
        version is None
        or sha256 is None
        or run.executable_sha256 != sha256
        or run.version is None
        or re.search(
            rf"(?<![0-9.]){re.escape(version)}(?![0-9.])",
            run.version,
        )
        is None
    ):
        return False
    if run.tool != "halmos":
        return True
    return (
        formal.halmos_solver_version is not None
        and formal.halmos_solver_sha256 is not None
        and len(run.dependencies) == 1
        and run.dependencies[0].name == "z3"
        and run.dependencies[0].executable_sha256 == formal.halmos_solver_sha256
        and run.dependencies[0].version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(formal.halmos_solver_version)}(?![0-9.])",
            run.dependencies[0].version,
        )
        is not None
    )


def is_qualifying_real_foundry_portfolio(
    run: ScannerRun,
    config: AuditConfig,
    *,
    expected_repository_sha256: str | None,
) -> bool:
    try:
        run = ScannerRun.model_validate(run.model_dump(mode="json"))
    except (TypeError, ValueError):
        return False
    summary = run.foundry_summary
    selection = run.repository_suite_selection
    inventory = run.repository_suite_inventory
    post_inventory = run.repository_suite_post_inventory
    execution_policy = run.repository_suite_execution_policy
    executions = run.repository_test_executions
    expected_total_timeout = min(
        config.execution.scanner_timeout_seconds,
        config.smart_contracts.max_fork_probe_seconds,
        config.smart_contracts.repository_suite.total_timeout_seconds,
    )
    expected_per_test_timeout = min(
        expected_total_timeout,
        config.smart_contracts.repository_suite.per_test_timeout_seconds,
    )
    classified_statuses = {
        RepositoryTestExecutionStatus.PASSED,
        RepositoryTestExecutionStatus.FAILED,
        RepositoryTestExecutionStatus.REVERTED,
        RepositoryTestExecutionStatus.ASSERTION_FAILED,
    }
    if (
        run.scanner != "foundry_fork"
        or not _is_real_scanner_run(run)
        or summary is None
        or selection is None
        or inventory is None
        or post_inventory is None
        or execution_policy is None
        or not executions
        or not _is_sha256(expected_repository_sha256)
        or selection.inventory_kind is not RepositorySuiteInventoryKind.ISOLATED_FOUNDRY_BUILD_INFO
        or selection.profile != config.smart_contracts.repository_suite.profile
        or selection.repository_sha256 != expected_repository_sha256
        or selection.inventory_sha256 != inventory.normalized_inventory_sha256
        or inventory.phase is not RepositorySuiteInventoryPhase.PRE_EXECUTION
        or post_inventory.phase is not RepositorySuiteInventoryPhase.POST_EXECUTION
        or inventory.execution_evidence is not ExecutionEvidenceKind.REAL
        or post_inventory.execution_evidence is not ExecutionEvidenceKind.REAL
        or inventory.inventory_sha256 != inventory.expected_inventory_sha256()
        or post_inventory.inventory_sha256 != post_inventory.expected_inventory_sha256()
        or inventory.repository_sha256 != selection.repository_sha256
        or post_inventory.repository_sha256 != selection.repository_sha256
        or inventory.configuration_sha256 != selection.configuration_sha256
        or post_inventory.configuration_sha256 != selection.configuration_sha256
        or inventory.tool_version != run.version
        or post_inventory.tool_version != run.version
        or inventory.tool_sha256 != run.executable_sha256
        or post_inventory.tool_sha256 != run.executable_sha256
        or inventory.compiler_version != execution_policy.compiler_version
        or post_inventory.compiler_version != execution_policy.compiler_version
        or inventory.compiler_sha256 != execution_policy.compiler_sha256
        or post_inventory.compiler_sha256 != execution_policy.compiler_sha256
        or inventory.isolation_backend != run.isolation_backend
        or post_inventory.isolation_backend != run.isolation_backend
        or inventory.isolation_attestation_sha256 != run.isolation_attestation_sha256
        or post_inventory.isolation_attestation_sha256 != run.isolation_attestation_sha256
        or inventory.execution_evidence is not run.execution_evidence
        or post_inventory.execution_evidence is not run.execution_evidence
        or inventory.repository_code_execution is not run.repository_code_execution
        or post_inventory.repository_code_execution is not run.repository_code_execution
        or inventory.normalized_inventory_sha256 != post_inventory.normalized_inventory_sha256
        or inventory.inventory_record_count != post_inventory.inventory_record_count
        or tuple(
            (
                project.project_root,
                project.build_info_bundle_sha256,
                project.normalized_build_info_bundle_sha256,
                project.parser_inventory_sha256,
                project.normalized_inventory_sha256,
            )
            for project in inventory.projects
        )
        != tuple(
            (
                project.project_root,
                project.build_info_bundle_sha256,
                project.normalized_build_info_bundle_sha256,
                project.parser_inventory_sha256,
                project.normalized_inventory_sha256,
            )
            for project in post_inventory.projects
        )
        or selection.configuration_sha256 != config.smart_contracts.repository_suite.stable_hash()
        or selection.selection_sha256 != selection.expected_selection_sha256()
        or not _scanner_matches_trust_pin(
            run,
            version=config.scanners.foundry_fork.version,
            sha256=config.scanners.foundry_fork.sha256,
        )
        or config.reproduction.expected_chain_id is None
        or config.reproduction.pinned_block_number is None
        or execution_policy.policy_sha256 != execution_policy.expected_policy_sha256()
        or execution_policy.selection_sha256 != selection.selection_sha256
        or execution_policy.selection_configuration_sha256 != selection.configuration_sha256
        or execution_policy.chain_id != config.reproduction.expected_chain_id
        or execution_policy.block_number != config.reproduction.pinned_block_number
        or execution_policy.tool_version != run.version
        or execution_policy.tool_sha256 != run.executable_sha256
        or config.smart_contracts.solc_version is None
        or config.smart_contracts.solc_sha256 is None
        or execution_policy.compiler_sha256 != config.smart_contracts.solc_sha256
        or re.search(
            rf"(?<![0-9.]){re.escape(config.smart_contracts.solc_version)}(?![0-9.])",
            execution_policy.compiler_version,
        )
        is None
        or execution_policy.isolation_backend != run.isolation_backend
        or execution_policy.isolation_attestation_sha256 != run.isolation_attestation_sha256
        or execution_policy.fuzz_seed != config.smart_contracts.repository_suite.fuzz_seed
        or execution_policy.fuzz_runs != config.smart_contracts.foundry_fuzz_runs
        or execution_policy.invariant_runs != config.smart_contracts.foundry_invariant_runs
        or execution_policy.per_test_timeout_seconds != expected_per_test_timeout
        or execution_policy.total_timeout_seconds != expected_total_timeout
        or run.duration_seconds > execution_policy.total_timeout_seconds
        or execution_policy.max_output_bytes_per_test
        != config.smart_contracts.repository_suite.max_output_bytes_per_test
        or execution_policy.max_total_output_bytes
        != config.smart_contracts.repository_suite.max_total_output_bytes
    ):
        return False
    inventory_records = {
        record.record_sha256: record for project in inventory.projects for record in project.records
    }
    post_inventory_records = {
        record.record_sha256: record
        for project in post_inventory.projects
        for record in project.records
    }
    selected_by_hash = {descriptor.descriptor_sha256: descriptor for descriptor in selection.tests}
    executions_by_descriptor = {execution.descriptor_sha256: execution for execution in executions}
    if (
        len(inventory_records) != inventory.inventory_record_count
        or inventory_records != post_inventory_records
        or len(selected_by_hash) != selection.selected_test_count
        or set(executions_by_descriptor) != set(selected_by_hash)
        or len(executions_by_descriptor) != len(executions)
        or any(
            descriptor.inventory_sha256 != inventory.normalized_inventory_sha256
            or descriptor.inventory_record_sha256 not in inventory_records
            for descriptor in selection.tests
        )
    ):
        return False
    observed_tests = summary.unit_tests + summary.fuzz_tests + summary.invariant_tests
    return (
        run.process_exit_code in {0, 1}
        and run.machine_output_validated
        and _scanner_execution_observation_matches(run)
        and summary.unit_tests > 0
        and summary.fuzz_tests > 0
        and summary.invariant_tests > 0
        and summary.passed_tests + summary.failed_tests == observed_tests
        and summary.skipped_tests == 0
        and summary.fuzz_cases >= execution_policy.fuzz_runs
        and summary.invariant_runs >= execution_policy.invariant_runs
        and summary.invariant_calls > 0
        and len(executions) == selection.selected_test_count
        and all(
            execution.status in classified_statuses
            and execution.execution_evidence is ExecutionEvidenceKind.REAL
            and execution.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
            and execution.machine_output_validated
            and execution.duration_seconds <= execution_policy.per_test_timeout_seconds
            and execution.chain_id == config.reproduction.expected_chain_id
            and execution.block_number == config.reproduction.pinned_block_number
            and execution.block_hash is not None
            and re.fullmatch(r"0x[0-9a-f]{64}", execution.block_hash) is not None
            and execution.fuzz_seed == config.smart_contracts.repository_suite.fuzz_seed
            and execution.compiler_sha256 == config.smart_contracts.solc_sha256
            and config.smart_contracts.solc_version is not None
            and execution.compiler_version is not None
            and re.search(
                rf"(?<![0-9.]){re.escape(config.smart_contracts.solc_version)}(?![0-9.])",
                execution.compiler_version,
            )
            is not None
            and execution.execution_sha256 == execution.expected_execution_sha256()
            and _is_sha256(execution.command_sha256)
            and _is_sha256(execution.output_sha256)
            and _is_sha256(execution.machine_result_sha256)
            and execution.execution_policy_sha256 == execution_policy.policy_sha256
            and execution.selection_sha256 == selection.selection_sha256
            and execution.inventory_sha256 == inventory.inventory_sha256
            and execution.post_inventory_sha256 == post_inventory.inventory_sha256
            and execution.inventory_record_sha256
            == selected_by_hash[execution.descriptor_sha256].inventory_record_sha256
            and execution.canonical_key
            == selected_by_hash[execution.descriptor_sha256].canonical_key
            and (
                execution.test_kind is not RepositoryTestKind.FUZZ
                or execution.fuzz_cases >= execution_policy.fuzz_runs
            )
            and (
                execution.test_kind is not RepositoryTestKind.INVARIANT
                or execution.invariant_runs >= execution_policy.invariant_runs
            )
            for execution in executions
        )
    )


def _is_real_formal_run(run: FormalToolRun) -> bool:
    indexed_sources = run.coverage.get("indexed_sources")
    return (
        run.status is FormalToolStatus.SUCCESS
        and run.execution_evidence is ExecutionEvidenceKind.REAL
        and bool(run.version)
        and _is_sha256(run.executable_sha256)
        and bool(run.command)
        and run.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
        and _is_sha256(run.isolation_attestation_sha256)
        and bool(run.stdout_path)
        and bool(run.stderr_path)
        and (
            run.process_exit_code == 0
            or (
                run.tool in (CERTIFIED_PROPERTY_ENGINES | {"kontrol"})
                and run.process_exit_code == 1
            )
        )
        and _is_sha256(run.stdout_sha256)
        and _is_sha256(run.stderr_sha256)
        and (run.result_sha256 is None or _is_sha256(run.result_sha256))
        and run.stdout_bytes + run.stderr_bytes + run.result_bytes > 0
        and run.machine_output_validated
        and _formal_execution_observation_matches(run)
        and isinstance(indexed_sources, int)
        and not isinstance(indexed_sources, bool)
        and indexed_sources > 0
    )


def is_structurally_qualifying_real_formal_run(run: FormalToolRun) -> bool:
    """Return whether retained formal evidence satisfies the REAL execution contract."""

    return _is_real_formal_run(run)


def _is_real_property_engine_run(run: FormalToolRun) -> bool:
    configured_campaign = run.configured_campaign
    observed_campaign = run.observed_campaign
    conclusive_evidence = [
        evidence
        for evidence in run.evidence
        if (
            evidence.tool == run.tool
            and evidence.status is FormalToolStatus.SUCCESS
            and evidence.result_kind
            in {
                FormalResultKind.NONE,
                FormalResultKind.COUNTEREXAMPLE,
            }
        )
    ]
    conclusive_property_ids = {evidence.property_id for evidence in conclusive_evidence}
    return (
        run.tool in CERTIFIED_PROPERTY_ENGINES
        and _is_real_formal_run(run)
        and _is_sha256(run.property_corpus_hash)
        and run.translated_properties > 0
        and len(run.executed_property_ids) == run.translated_properties
        and run.observed_property_ids == run.executed_property_ids
        and conclusive_property_ids == set(run.executed_property_ids)
        and len(conclusive_evidence) == len(run.executed_property_ids)
        and len(run.evidence) == len(conclusive_evidence)
        and configured_campaign is not None
        and observed_campaign is not None
        and (
            (
                run.tool in {"echidna", "medusa"}
                and _positive_integer_at_least(
                    observed_campaign.runs,
                    configured_campaign.runs,
                )
                and _positive_integer_at_least(
                    observed_campaign.calls,
                    configured_campaign.runs,
                )
                and _positive_integer_at_least(
                    observed_campaign.depth,
                    configured_campaign.depth,
                )
            )
            or (
                run.tool == "halmos"
                and _positive_integer(observed_campaign.paths)
                and (
                    observed_campaign.depth is None
                    or _positive_integer_at_least(
                        observed_campaign.depth,
                        configured_campaign.depth,
                    )
                )
            )
        )
        and (
            run.tool != "halmos"
            or (
                len(run.dependencies) == 1
                and run.dependencies[0].name == "z3"
                and bool(run.dependencies[0].version)
                and _is_sha256(run.dependencies[0].executable_sha256)
            )
        )
    )


def _formal_run_matches_expected_corpus(
    run: FormalToolRun,
    runtime: AssuranceRuntime,
) -> bool:
    """Require every mandatory property engine to execute the same sealed corpus."""

    return (
        _is_sha256(runtime.property_corpus_sha256)
        and bool(runtime.property_corpus_property_ids)
        and run.property_corpus_hash == runtime.property_corpus_sha256
        and set(run.property_corpus_property_ids) == runtime.property_corpus_property_ids
        and set(run.executed_property_ids) == runtime.property_corpus_property_ids
        and set(run.observed_property_ids) == runtime.property_corpus_property_ids
        and run.translated_properties == len(runtime.property_corpus_property_ids)
        and {binding.corpus_property_id for binding in run.translated_property_bindings}
        == runtime.property_corpus_property_ids
        and runtime.property_corpus_property_hashes
        == {
            binding.corpus_property_id: binding.property_hash
            for binding in run.translated_property_bindings
        }
    )


def _is_real_formal_proof_run(run: FormalToolRun) -> bool:
    qualifying_results = [
        evidence
        for evidence in run.evidence
        if (
            evidence.tool == run.tool
            and evidence.status is FormalToolStatus.SUCCESS
            and evidence.result_kind in {FormalResultKind.PROOF, FormalResultKind.COUNTEREXAMPLE}
            and bool(evidence.property_id)
            and bool(evidence.artifact_paths)
        )
    ]
    return (
        run.tool in CERTIFIED_FORMAL_PROOF_ENGINES
        and _is_real_formal_run(run)
        and bool(qualifying_results)
        and run.translated_properties > 0
        and run.observed_property_ids == run.executed_property_ids
        and {result.property_id for result in qualifying_results} == set(run.executed_property_ids)
        and len(qualifying_results) == run.translated_properties
        and len(run.evidence) == len(qualifying_results)
        and (
            run.tool != "certora"
            or (bool(run.specification_artifacts) and bool(run.vacuity_artifacts))
        )
    )


def is_structurally_qualifying_real_invariant_execution(
    result: InvariantExecutionResult,
) -> bool:
    """Validate self-contained REAL invariant execution evidence without configuration pins."""

    completed = {
        InvariantExecutionStatus.PASSED,
        InvariantExecutionStatus.COUNTEREXAMPLE,
    }
    coverage = result.campaign_coverage
    return (
        result.status in completed
        and result.execution_evidence is ExecutionEvidenceKind.REAL
        and _is_sha256(result.executable_sha256)
        and _is_sha256(result.source_sha256)
        and result.compiler_version is not None
        and _is_sha256(result.compiler_sha256)
        and _is_sha256(result.isolation_attestation_sha256)
        and _is_sha256(result.execution_observation_sha256)
        and result.execution_observation_sha256 == result.expected_execution_observation_sha256()
        and bool(result.command)
        and result.runs > 0
        and result.depth > 0
        and result.attempts >= 2
        and result.successful_attempts == result.attempts
        and result.replay_confirmed
        and len(result.attempt_evidence) == result.attempts
        and all(
            attempt.fresh_workspace
            and attempt.status is result.status
            and attempt.source_sha256 == result.source_sha256
            and _is_sha256(attempt.stdout_sha256)
            and _is_sha256(attempt.stderr_sha256)
            and bool(attempt.stdout_path)
            and bool(attempt.stderr_path)
            and attempt.process_exit_code in {0, 1}
            and attempt.machine_output_validated
            and attempt.campaign_runs > 0
            and attempt.campaign_calls > 0
            for attempt in result.attempt_evidence
        )
        and coverage is not None
        and coverage.attempts_consistent
        and coverage.sequence_depth_bound == result.depth
        and coverage.observed_campaign_runs > 0
        and coverage.observed_campaign_calls > 0
        and bool(coverage.declared_action_functions)
        and bool(coverage.observed_action_functions)
        and set(coverage.observed_action_functions) == set(coverage.declared_action_functions)
        and bool(coverage.declared_state_properties)
        and bool(coverage.observed_state_properties)
        and set(coverage.observed_state_properties) == set(coverage.declared_state_properties)
        and (
            result.status is InvariantExecutionStatus.PASSED
            or bool(coverage.observed_sequence_lengths)
        )
        and bool(result.stdout_path)
        and bool(result.stderr_path)
        and result.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
    )


def _is_real_invariant_execution(
    result: InvariantExecutionResult,
    config: AuditConfig,
) -> bool:
    return (
        is_structurally_qualifying_real_invariant_execution(result)
        and result.executable_sha256 == config.scanners.foundry_fork.sha256
        and config.smart_contracts.solc_version is not None
        and config.smart_contracts.solc_sha256 is not None
        and result.compiler_version is not None
        and re.search(
            rf"(?<![0-9.]){re.escape(config.smart_contracts.solc_version)}(?![0-9.])",
            result.compiler_version,
        )
        is not None
        and result.compiler_sha256 == config.smart_contracts.solc_sha256
    )


def is_structurally_qualifying_real_reproduction(result: ReproductionResult) -> bool:
    """Validate a retained isolated replay as substantive REAL reproduction evidence."""

    positive_states = {
        ReproductionState.REPRODUCED,
        ReproductionState.REPRODUCED_AND_MINIMIZED,
    }
    completed_states = {*positive_states, ReproductionState.NOT_REPRODUCED}
    if result.state not in completed_states:
        return False
    expected_attempt_state = (
        ReproductionState.REPRODUCED
        if result.state in positive_states
        else ReproductionState.NOT_REPRODUCED
    )
    expected_successful_attempts = result.attempts if result.state in positive_states else 0
    integrity = result.integrity
    return (
        result.execution_evidence is ExecutionEvidenceKind.REAL
        and _is_sha256(result.executable_sha256)
        and _is_sha256(result.specification_sha256)
        and _is_sha256(result.generated_test_sha256)
        and bool(result.generated_test_path)
        and bool(result.regression_test_path)
        and bool(result.command)
        and result.attempts > 0
        and result.successful_attempts == expected_successful_attempts
        and len(result.attempt_evidence) == result.attempts
        and bool(result.stdout_path)
        and bool(result.stderr_path)
        and result.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
        and _is_sha256(result.isolation_attestation_sha256)
        and _is_sha256(result.repository_sha256)
        and integrity is not None
        and integrity.status is ReproductionIntegrityStatus.VERIFIED
        and integrity.repository_sha256 == result.repository_sha256
        and bool(integrity.targets)
        and bool(integrity.reachability)
        and integrity.settlement.verified_attempts == result.attempts
        and all(check.passed for check in integrity.checks)
        and all(
            attempt.attempt == index
            and attempt.state is expected_attempt_state
            and attempt.fresh_workspace
            and attempt.repository_sha256 == result.repository_sha256
            and attempt.generated_test_sha256 == result.generated_test_sha256
            and _is_sha256(attempt.stdout_sha256)
            and _is_sha256(attempt.stderr_sha256)
            for index, attempt in enumerate(result.attempt_evidence, start=1)
        )
    )


def offline_replay_is_qualifying(
    replay: OfflineReplay | None,
    *,
    expected_run_id: str | None,
    expected_manifest_sha256: str | None,
    expected_verification_sha256: str | None,
    expected_applicable_kinds: set[ReplayComponentKind],
    expected_components: set[tuple[ReplayComponentKind, str]],
) -> bool:
    if (
        replay is None
        or expected_run_id is None
        or expected_manifest_sha256 is None
        or expected_verification_sha256 is None
        or not expected_applicable_kinds
        or not expected_components
    ):
        return False
    observed_component_counts = Counter(
        (component.kind, component.identifier) for component in replay.components
    )
    observed_kinds = {
        component.kind
        for component in replay.components
        if (
            component.status is ReplayComponentStatus.MATCHED
            and component.executed
            and component.execution_evidence is ExecutionEvidenceKind.REAL
            and component.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
            and _is_sha256(component.isolation_attestation_sha256)
        )
    }
    return (
        replay.status is OfflineReplayStatus.REPLAYED
        and replay.run_id == expected_run_id
        and replay.manifest_sha256 == expected_manifest_sha256
        and replay.run_verification_sha256 == expected_verification_sha256
        and set(replay.applicable_kinds) == expected_applicable_kinds
        and set(observed_component_counts) == expected_components
        and all(count == 1 for count in observed_component_counts.values())
        and not replay.missing_kinds
        and bool(replay.components)
        and observed_kinds == set(replay.applicable_kinds)
        and all(
            component.status is ReplayComponentStatus.MATCHED
            and component.executed
            and component.execution_evidence is ExecutionEvidenceKind.REAL
            and component.isolation_backend in CERTIFIED_ISOLATION_BACKENDS
            and _is_sha256(component.isolation_attestation_sha256)
            for component in replay.components
        )
    )


def _expected_replay_components(
    runtime: AssuranceRuntime,
    expected_harnesses: dict[tuple[str, str], str],
) -> set[tuple[ReplayComponentKind, str]]:
    """Derive exact replay member obligations from runtime evidence."""

    expected = {(ReplayComponentKind.SCANNER, run.scanner) for run in runtime.scanners}
    results = {
        (result.invariant_id, result.harness_name): result
        for result in runtime.invariant_executions
    }
    for identity in expected_harnesses:
        result = results.get(identity)
        kind = (
            ReplayComponentKind.COUNTEREXAMPLE
            if result is not None and result.status is InvariantExecutionStatus.COUNTEREXAMPLE
            else ReplayComponentKind.SAVED_TEST
        )
        expected.add((kind, f"{identity[0]}/{identity[1]}"))
    expected.update(
        (
            ReplayComponentKind.SAVED_TEST,
            f"{result.candidate_id}/{result.test_name}",
        )
        for result in runtime.reproduction_results
    )
    return expected


def _current_production_qualification(
    qualification: VerifiedProductionQualification | None,
) -> VerifiedProductionQualification | None:
    if type(qualification) is not VerifiedProductionQualification:
        return None
    try:
        return qualification.require_current(
            now=datetime.now(UTC).replace(microsecond=0),
        )
    except ValueError:
        return None


def _promoted_recovery_request_coordinates(
    artifact: SchedulerArtifact | None,
) -> dict[str, tuple[str, int]]:
    """Project only promoted child request-limit coordinates from validated scheduler state."""

    if artifact is None:
        return {}
    try:
        validated = SchedulerArtifact.model_validate(artifact.model_dump(mode="python"))
    except ValueError:
        return {}
    return {
        request.logical_request_id: (
            request.request_limit_scope,
            request.request_limit_count_before,
        )
        for request in validated.recovery_model_requests
        if request.promotion_entry_sha256 is not None
        and request.promotion_disposition
        is not SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
    }


def _promoted_recovery_context_matches_request(
    *,
    context: ContextPackage,
    usage: UsageRecord,
    request: SchedulerModelRequestEvidence | SchedulerTruncationRecoveryModelRequestEvidence,
    allow_missing_request_binding: bool = False,
) -> bool:
    """Bind one live capability context to its public request and usage routing."""

    from mmaudit.orchestration.context import render_context, revalidate_context_package
    from mmaudit.orchestration.model_review_evidence import (
        model_surface_context_source_custody,
    )

    if type(context) is not ContextPackage:
        return False
    try:
        validated = revalidate_context_package(context)
        rendered = render_context(validated)
        requested_surface_manifest_sha256, source_location_proof_sha256s = (
            model_surface_context_source_custody(validated)
        )
        expected = ContextRequestEvidence.build(
            request_id=request.logical_request_id,
            request_role=request.role,
            context_role=validated.role,
            byte_budget=validated.byte_budget,
            declared_bytes_used=validated.bytes_used,
            rendered_bytes=len(rendered.encode()),
            source_bytes=validated.delivered_source_bytes(),
            configured_maximum_source_tokens_per_request=(
                validated.configured_maximum_source_tokens_per_request
            ),
            effective_source_byte_ceiling=validated.effective_source_byte_ceiling,
            rendered_sha256=hashlib.sha256(rendered.encode()).hexdigest(),
            requested_surface_manifest_sha256=requested_surface_manifest_sha256,
            source_location_proof_sha256s=source_location_proof_sha256s,
            retrieval_policy=validated.solidity_retrieval_policy,
            retrieval_corpus_sha256=validated.solidity_retrieval_corpus_sha256,
            retrieval_transcript=validated.solidity_retrieval_transcript,
        )
        routed = ContextRequestEvidence.model_validate(
            usage.routing.get("context_request_evidence")
        )
    except (TypeError, ValueError):
        return False
    return (
        validated == context
        and routed == expected
        and (
            request.context_request_evidence_sha256 == expected.evidence_sha256
            or (allow_missing_request_binding and request.context_request_evidence_sha256 is None)
        )
        and usage.routing.get("context_request_evidence_sha256") == expected.evidence_sha256
    )


def _real_provider_session_is_qualifying(
    provider_session: ProviderSessionProvenance | None,
) -> bool:
    if type(provider_session) is not ProviderSessionProvenance:
        return False
    try:
        return provider_session.permits_real_model_credit
    except AttributeError:
        return False


def _is_real_model_usage(
    record: UsageRecord,
    config: AuditConfig,
    qualification: VerifiedProductionQualification | None,
    provider_session: ProviderSessionProvenance | None,
    audit_selection: _CurrentAuditModelSelection | None = None,
    audit_refresh: _CurrentAuditModelRefresh | None = None,
    audit_refresh_pricing: _CurrentAuditModelRefreshPricing | None = None,
    *,
    recovery_request_limit_scope: str | None = None,
    recovery_request_limit_count_before: int | None = None,
) -> bool:
    recovery_coordinates_present = (
        recovery_request_limit_scope is not None,
        recovery_request_limit_count_before is not None,
    )
    if recovery_coordinates_present[0] != recovery_coordinates_present[1]:
        return False
    usage_is_creditable = (
        is_recovery_creditable_usage_record(
            record,
            request_limit_scope=recovery_request_limit_scope,
            request_limit_count_before=recovery_request_limit_count_before,
            require_real=True,
            require_certification=True,
        )
        if recovery_request_limit_scope is not None
        and recovery_request_limit_count_before is not None
        else is_creditable_usage_record(
            record,
            require_real=True,
            require_certification=True,
        )
    )
    return usage_is_creditable and _usage_matches_real_model_route(
        record,
        config,
        qualification,
        provider_session,
        audit_selection,
        audit_refresh,
        audit_refresh_pricing,
        recovery_request_limit_scope=recovery_request_limit_scope,
        recovery_request_limit_count_before=recovery_request_limit_count_before,
    )


def _usage_matches_real_model_route(
    record: UsageRecord,
    config: AuditConfig,
    qualification: VerifiedProductionQualification | None,
    provider_session: ProviderSessionProvenance | None,
    audit_selection: _CurrentAuditModelSelection | None,
    audit_refresh: _CurrentAuditModelRefresh | None,
    audit_refresh_pricing: _CurrentAuditModelRefreshPricing | None,
    *,
    recovery_request_limit_scope: str | None,
    recovery_request_limit_count_before: int | None,
) -> bool:
    """Join one live usage route without independently deciding response credit."""

    if (
        qualification is None
        or not _real_provider_session_is_qualifying(provider_session)
        or not _usage_matches_audit_model_selection(record, audit_selection)
        or not _usage_matches_audit_model_refresh(record, audit_refresh)
        or not _usage_matches_audit_model_refresh_pricing(
            record,
            audit_refresh_pricing,
            audit_selection,
            audit_refresh,
        )
    ):
        return False
    try:
        role_resolution = resolve_reasoning_request_role(record.role)
    except ReasoningPolicyError:
        return False
    whole_protocol_context = source_backed_whole_protocol_context(record)
    whole_protocol_review = role_resolution.mapping_kind == "whole_protocol_indexed"
    if whole_protocol_review and whole_protocol_context is None:
        return False
    if not whole_protocol_review and whole_protocol_context is not None:
        return False
    role = role_resolution.qualification_role
    if whole_protocol_review:
        configured_models = {model.exact_model_id for model in qualification.models}
    else:
        try:
            configured_role = config.models.role(role)
        except (KeyError, TypeError):
            return False
        configured_models = {configured_role.primary, *configured_role.fallbacks}
    if record.role.startswith(
        (
            "candidate_falsifier:",
            "specialist:falsifier:cross_exam_",
        )
    ):
        for supporting_role in ("verifier", "judge"):
            role_config = config.models.role(supporting_role)
            configured_models.update({role_config.primary, *role_config.fallbacks})
    try:
        qualified_model = qualification.model_for(
            record.requested_model,
            now=datetime.now(UTC).replace(microsecond=0),
        )
    except ValueError:
        return False
    routing = record.routing
    return (
        record.requested_model in configured_models
        and record.returned_model
        in {
            qualified_model.exact_model_id,
            qualified_model.canonical_model_slug,
        }
        and record.actual_model
        in {
            qualified_model.exact_model_id,
            qualified_model.canonical_model_slug,
        }
        and record.actual_provider_endpoint == qualified_model.approved_provider_endpoint
        and routing.get("selected_model") == record.actual_model
        and routing.get("canonical_model") == qualified_model.canonical_model_slug
        and routing.get("selected_provider_endpoint") == qualified_model.approved_provider_endpoint
        and routing.get("selected_provider_name") == qualified_model.approved_provider_name
        and routing.get("model_metadata_snapshot_sha256")
        == qualified_model.model_metadata_snapshot_sha256
        and _qualified_usage_role(role, qualified_model)
        and routing.get("qualified_exact_model_id") == qualified_model.exact_model_id
        and routing.get("qualified_canonical_model_slug") == qualified_model.canonical_model_slug
        and routing.get("qualified_root_lineage") == qualified_model.root_lineage
        and routing.get("qualified_provider_endpoint") == qualified_model.approved_provider_endpoint
        and routing.get("qualified_provider_name") == qualified_model.approved_provider_name
        and routing.get("qualified_endpoint_snapshot_sha256")
        == qualified_model.endpoint_snapshot_sha256
        and routing.get("qualified_model_metadata_snapshot_sha256")
        == qualified_model.model_metadata_snapshot_sha256
        and routing.get("qualified_pricing_snapshot_sha256")
        == qualified_model.pricing_snapshot_sha256
        and routing.get("qualified_roles") == list(qualified_model.approved_roles)
        and routing.get("qualification_verified_at") == qualification.verified_at.isoformat()
        and routing.get("qualification_expires_at") == qualified_model.expires_at.isoformat()
        and routing.get("qualification_artifact_sha256") == qualification.artifact_sha256
        and routing.get("qualification_verification_sha256")
        == qualification.qualification_verification_sha256
        and routing.get("production_selection_sha256") == qualification.production_selection_sha256
        and routing.get("selection_verification_sha256")
        == qualification.selection_verification_sha256
        and routing.get("qualification_result_sha256")
        == qualified_model.qualification_result_sha256
        and usage_matches_verified_reasoning_qualification_route(
            record=record,
            production_qualification=qualification,
            now=datetime.now(UTC).replace(microsecond=0),
            recovery_request_limit_scope=recovery_request_limit_scope,
            recovery_request_limit_count_before=recovery_request_limit_count_before,
        )
    )


def _qualified_usage_role(
    role: str,
    model: VerifiedTierAModelQualification,
) -> bool:
    return role in model.approved_roles


def _real_model_usage_lineages(
    records: Iterable[UsageRecord],
    qualification: VerifiedProductionQualification | None,
) -> set[str]:
    if qualification is None:
        return set()
    lineages: set[str] = set()
    now = datetime.now(UTC).replace(microsecond=0)
    for record in records:
        try:
            lineages.add(
                qualification.model_for(
                    record.requested_model,
                    now=now,
                ).root_lineage
            )
        except ValueError:
            continue
    return lineages


def _model_coverage_is_backed_by_real_usage(
    coverage: ModelReviewCoverage | None,
    records: list[UsageRecord],
    artifacts: list[ModelSurfaceReviewArtifact],
    promoted_surface_coverages: list[VerifiedPromotedTruncationRecoverySurfaceCoverage],
    promoted_recursive_surface_coverages: list[
        VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverage
    ],
    config: AuditConfig,
    qualification: VerifiedProductionQualification | None,
    provider_session: ProviderSessionProvenance | None,
    audit_selection: _CurrentAuditModelSelection | None,
    audit_refresh: _CurrentAuditModelRefresh | None,
    audit_refresh_pricing: _CurrentAuditModelRefreshPricing | None,
    *,
    scheduler_artifact: SchedulerArtifact | None,
    recovery_request_limit_coordinates: dict[str, tuple[str, int]] | None = None,
) -> bool:
    if coverage is None:
        return False

    from mmaudit.orchestration.scheduler import (
        require_verified_promoted_recursive_truncation_recovery_surface_coverage,
        require_verified_promoted_truncation_recovery_surface_coverage,
    )
    from mmaudit.orchestration.truncation_recovery_evidence import (
        TruncationRecoveryEvidenceError,
    )

    usage_by_request: dict[str, list[UsageRecord]] = {}
    for record in records:
        usage_by_request.setdefault(record.request_id, []).append(record)
    artifacts_by_request: dict[str, list[ModelSurfaceReviewArtifact]] = {}
    for artifact in artifacts:
        artifacts_by_request.setdefault(artifact.request_id, []).append(artifact)

    if len(promoted_surface_coverages) + len(promoted_recursive_surface_coverages) > 32:
        return False
    validated_scheduler_artifact: SchedulerArtifact | None = None
    if scheduler_artifact is not None:
        if type(scheduler_artifact) is not SchedulerArtifact:
            return False
        try:
            validated_scheduler_artifact = SchedulerArtifact.model_validate_json(
                scheduler_artifact.model_dump_json(),
                strict=True,
            )
        except (AttributeError, TypeError, ValueError):
            return False
    public_promotion_bindings = (
        tuple(
            binding
            for pass_result in validated_scheduler_artifact.summary.pass_results
            for binding in pass_result.recovery_promotion_bindings
        )
        if validated_scheduler_artifact is not None
        else ()
    )
    public_promotion_entry_sha256s = tuple(
        binding.promotion_entry_sha256 for binding in public_promotion_bindings
    )
    if len(public_promotion_entry_sha256s) != len(set(public_promotion_entry_sha256s)):
        return False
    composite_by_artifact_sha256: dict[
        str,
        VerifiedPromotedTruncationRecoverySurfaceCoverageProjection
        | VerifiedPromotedRecursiveTruncationRecoverySurfaceCoverageProjection,
    ] = {}
    promoted_parent_partitions: dict[str, set[tuple[str, str]]] = {}
    promoted_child_partitions: dict[str, set[tuple[str, str]]] = {}
    seen_promotion_entries: set[str] = set()
    for capability in promoted_surface_coverages:
        try:
            projection = require_verified_promoted_truncation_recovery_surface_coverage(capability)
        except (TypeError, TruncationRecoveryEvidenceError):
            return False
        promoted_artifact = projection.artifact
        if (
            projection.promotion_entry_sha256 in seen_promotion_entries
            or promoted_artifact.artifact_sha256 in composite_by_artifact_sha256
            or promoted_artifact.artifact_sha256 in {item.artifact_sha256 for item in artifacts}
        ):
            return False
        seen_promotion_entries.add(projection.promotion_entry_sha256)
        matching_bindings = tuple(
            binding
            for binding in public_promotion_bindings
            if binding.promotion_entry_sha256 == projection.promotion_entry_sha256
        )
        if len(matching_bindings) != 1:
            return False
        binding = matching_bindings[0]
        if (
            binding.schema_version != "1.0"
            or binding.parent_task_id != promoted_artifact.parent_task_id
            or binding.recovered_output_artifact_sha256
            != projection.recovered_output_artifact_sha256
            or binding.direct_child_result_sha256s != projection.child_result_entry_sha256s
        ):
            return False
        parent_usage_matches = usage_by_request.get(promoted_artifact.parent_logical_request_id, [])
        if (
            len(parent_usage_matches) != 1
            or parent_usage_matches[0] is not projection.parent_usage_record
            or promoted_artifact.parent.usage_record != projection.parent_usage_record
            or not is_accountable_usage_record(parent_usage_matches[0], require_real=True)
            or parent_usage_matches[0].routing.get("certification_request") is not True
            or not _usage_matches_real_model_route(
                parent_usage_matches[0],
                config,
                qualification,
                provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=None,
                recovery_request_limit_count_before=None,
            )
        ):
            return False
        recovery_requests = tuple(
            request
            for request in (
                validated_scheduler_artifact.recovery_model_requests
                if validated_scheduler_artifact is not None
                else ()
            )
            if request.promotion_entry_sha256 == projection.promotion_entry_sha256
        )
        if (
            len(recovery_requests) != len(promoted_artifact.children)
            or len(projection.child_usage_records) != len(promoted_artifact.children)
            or {request.child_result_entry_sha256 for request in recovery_requests}
            != set(projection.child_result_entry_sha256s)
            or {request.logical_request_id for request in recovery_requests}
            != {child.usage_record.request_id for child in promoted_artifact.children}
        ):
            return False
        recovery_requests_by_id = {
            request.logical_request_id: request for request in recovery_requests
        }
        for child, live_child_usage, expected_child_result_sha256 in zip(
            promoted_artifact.children,
            projection.child_usage_records,
            projection.child_result_entry_sha256s,
            strict=True,
        ):
            matching_child_usage = usage_by_request.get(live_child_usage.request_id, [])
            matching_child_artifacts = artifacts_by_request.get(live_child_usage.request_id, [])
            request = recovery_requests_by_id.get(live_child_usage.request_id)
            if (
                len(matching_child_usage) != 1
                or matching_child_usage[0] is not live_child_usage
                or child.usage_record != live_child_usage
                or len(matching_child_artifacts) != 1
                or matching_child_artifacts[0] != child.surface_artifact
                or request is None
                or request.child_result_entry_sha256 != expected_child_result_sha256
                or not _is_real_model_usage(
                    matching_child_usage[0],
                    config,
                    qualification,
                    provider_session,
                    audit_selection,
                    audit_refresh,
                    audit_refresh_pricing,
                    recovery_request_limit_scope=request.request_limit_scope,
                    recovery_request_limit_count_before=request.request_limit_count_before,
                )
            ):
                return False
        parent_surface_ids = {
            origin.surface_id for origin in promoted_artifact.origins if origin.provisional
        }
        projected_parent_surface_ids = {
            review.surface_id for review in promoted_artifact.parent.projection.surface_reviews
        }
        child_partition = {
            (child.surface_artifact.artifact_sha256, record.surface_id)
            for child in promoted_artifact.children
            for record in child.surface_artifact.records
        }
        child_surface_ids = {surface_id for _, surface_id in child_partition}
        request_surface_ids = {request.surface_id for request in promoted_artifact.requests}
        if (
            not child_partition
            or parent_surface_ids != projected_parent_surface_ids
            or parent_surface_ids & child_surface_ids
            or parent_surface_ids | child_surface_ids != request_surface_ids
            or len(parent_surface_ids) + len(child_partition) != len(request_surface_ids)
        ):
            return False
        promoted_parent_partitions[promoted_artifact.artifact_sha256] = {
            (promoted_artifact.artifact_sha256, surface_id) for surface_id in parent_surface_ids
        }
        promoted_child_partitions[promoted_artifact.artifact_sha256] = child_partition
        composite_by_artifact_sha256[promoted_artifact.artifact_sha256] = projection

    for recursive_capability in promoted_recursive_surface_coverages:
        try:
            recursive_projection = (
                require_verified_promoted_recursive_truncation_recovery_surface_coverage(
                    recursive_capability
                )
            )
        except (TypeError, TruncationRecoveryEvidenceError):
            return False
        recursive_artifact = recursive_projection.artifact
        if (
            recursive_projection.promotion_entry_sha256 in seen_promotion_entries
            or recursive_artifact.artifact_sha256 in composite_by_artifact_sha256
            or recursive_artifact.artifact_sha256 in {item.artifact_sha256 for item in artifacts}
        ):
            return False
        seen_promotion_entries.add(recursive_projection.promotion_entry_sha256)
        matching_bindings = tuple(
            binding
            for binding in public_promotion_bindings
            if binding.promotion_entry_sha256 == recursive_projection.promotion_entry_sha256
        )
        if len(matching_bindings) != 1:
            return False
        binding = matching_bindings[0]
        if (
            binding.schema_version != "1.1"
            or binding.parent_task_id != recursive_artifact.parent_task_id
            or binding.recovered_output_artifact_sha256
            != recursive_projection.recovered_output_artifact_sha256
            or binding.direct_child_result_sha256s
            != recursive_projection.direct_child_result_sha256s
            or binding.nested_family_id != recursive_projection.nested_family_id
            or binding.nested_family_root_sha256 != recursive_projection.nested_family_root_sha256
            or binding.nested_recovery_plan_sha256
            != recursive_projection.nested_recovery_plan_sha256
            or binding.nested_family_closure_id != recursive_projection.nested_family_closure_id
            or binding.nested_family_closure_sha256
            != recursive_projection.nested_family_closure_sha256
            or binding.nested_child_result_sha256s
            != recursive_projection.nested_child_result_sha256s
            or binding.superseded_bridge_result_sha256
            != recursive_projection.superseded_bridge_result_sha256
            or binding.promoted_leaf_result_sha256s
            != recursive_projection.promoted_leaf_result_sha256s
        ):
            return False

        parent_usage_matches = usage_by_request.get(
            recursive_artifact.parent_logical_request_id,
            [],
        )
        parent_requests = tuple(
            request
            for request in (
                validated_scheduler_artifact.model_requests
                if validated_scheduler_artifact is not None
                else ()
            )
            if request.task_id == binding.parent_task_id
        )
        if (
            len(parent_usage_matches) != 1
            or parent_usage_matches[0] is not recursive_projection.parent_usage_record
            or recursive_artifact.parent.usage_record != recursive_projection.parent_usage_record
            or len(parent_requests) != 1
            or parent_requests[0].logical_request_id
            != recursive_projection.parent_usage_record.request_id
            or not is_accountable_usage_record(parent_usage_matches[0], require_real=True)
            or parent_usage_matches[0].routing.get("certification_request") is not True
            or not _usage_matches_real_model_route(
                parent_usage_matches[0],
                config,
                qualification,
                provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=None,
                recovery_request_limit_count_before=None,
            )
            or not _promoted_recovery_context_matches_request(
                context=recursive_projection.parent_context,
                usage=parent_usage_matches[0],
                request=parent_requests[0],
                allow_missing_request_binding=True,
            )
        ):
            return False

        recovery_requests = tuple(
            request
            for request in (
                validated_scheduler_artifact.recovery_model_requests
                if validated_scheduler_artifact is not None
                else ()
            )
            if request.promotion_entry_sha256 == recursive_projection.promotion_entry_sha256
        )
        bridge_requests = tuple(
            request
            for request in recovery_requests
            if request.promotion_disposition
            is SchedulerTruncationRecoveryPromotionDisposition.SUPERSEDED_TRUNCATED_BRIDGE
        )
        leaf_requests = tuple(
            sorted(
                (
                    request
                    for request in recovery_requests
                    if request.promotion_disposition
                    is SchedulerTruncationRecoveryPromotionDisposition.SUCCESSFUL_LEAF
                ),
                key=lambda request: request.global_request_ordinal or 0,
            )
        )
        if (
            len(recovery_requests) != 4
            or len(bridge_requests) != 1
            or len(leaf_requests) != 3
            or bridge_requests[0].child_result_entry_sha256
            != recursive_projection.superseded_bridge_result_sha256
            or bridge_requests[0].terminal_status is not SchedulerTerminalStatus.TRUNCATED
            or bridge_requests[0].recovery_family_id != recursive_projection.family_id
            or bridge_requests[0].family_root_sha256 != recursive_projection.family_root_sha256
            or bridge_requests[0].recovery_plan_sha256
            != recursive_artifact.recovery_plan.plan_sha256
            or bridge_requests[0].family_closure_id != recursive_projection.family_closure_id
            or bridge_requests[0].family_closure_sha256
            != recursive_projection.family_closure_sha256
            or tuple(request.child_result_entry_sha256 for request in leaf_requests)
            != recursive_projection.promoted_leaf_result_sha256s
            or any(
                request.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
                for request in leaf_requests
            )
            or {request.child_result_entry_sha256 for request in recovery_requests}
            != {
                *recursive_projection.direct_child_result_sha256s,
                *recursive_projection.nested_child_result_sha256s,
            }
            or leaf_requests[0].recovery_family_id != recursive_projection.family_id
            or leaf_requests[0].family_root_sha256 != recursive_projection.family_root_sha256
            or leaf_requests[0].recovery_plan_sha256 != recursive_artifact.recovery_plan.plan_sha256
            or leaf_requests[0].family_closure_id != recursive_projection.family_closure_id
            or leaf_requests[0].family_closure_sha256 != recursive_projection.family_closure_sha256
            or any(
                request.recovery_family_id != recursive_projection.nested_family_id
                or request.family_root_sha256 != recursive_projection.nested_family_root_sha256
                or request.recovery_plan_sha256 != recursive_projection.nested_recovery_plan_sha256
                or request.family_closure_id != recursive_projection.nested_family_closure_id
                or request.family_closure_sha256
                != recursive_projection.nested_family_closure_sha256
                for request in leaf_requests[1:]
            )
        ):
            return False

        bridge_request = bridge_requests[0]
        bridge_usage_matches = usage_by_request.get(
            recursive_projection.bridge_usage_record.request_id,
            [],
        )
        if (
            len(bridge_usage_matches) != 1
            or bridge_usage_matches[0] is not recursive_projection.bridge_usage_record
            or recursive_artifact.bridge.usage_record != recursive_projection.bridge_usage_record
            or bridge_request.logical_request_id
            != recursive_projection.bridge_usage_record.request_id
            or artifacts_by_request.get(bridge_request.logical_request_id)
            or not is_recovery_accountable_usage_record(
                recursive_projection.bridge_usage_record,
                request_limit_scope=bridge_request.request_limit_scope,
                request_limit_count_before=bridge_request.request_limit_count_before,
                require_real=True,
            )
            or not _usage_matches_real_model_route(
                recursive_projection.bridge_usage_record,
                config,
                qualification,
                provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=bridge_request.request_limit_scope,
                recovery_request_limit_count_before=bridge_request.request_limit_count_before,
            )
            or not _promoted_recovery_context_matches_request(
                context=recursive_projection.bridge_context,
                usage=recursive_projection.bridge_usage_record,
                request=bridge_request,
            )
        ):
            return False

        if (
            len(recursive_projection.leaf_usage_records) != 3
            or len(recursive_projection.leaf_contexts) != 3
            or len(recursive_artifact.children) != 3
        ):
            return False
        for child, live_leaf_usage, leaf_context, request in zip(
            recursive_artifact.children,
            recursive_projection.leaf_usage_records,
            recursive_projection.leaf_contexts,
            leaf_requests,
            strict=True,
        ):
            matching_leaf_usage = usage_by_request.get(live_leaf_usage.request_id, [])
            matching_leaf_artifacts = artifacts_by_request.get(live_leaf_usage.request_id, [])
            if (
                len(matching_leaf_usage) != 1
                or matching_leaf_usage[0] is not live_leaf_usage
                or child.usage_record != live_leaf_usage
                or request.logical_request_id != live_leaf_usage.request_id
                or len(matching_leaf_artifacts) != 1
                or matching_leaf_artifacts[0] != child.surface_artifact
                or not _is_real_model_usage(
                    live_leaf_usage,
                    config,
                    qualification,
                    provider_session,
                    audit_selection,
                    audit_refresh,
                    audit_refresh_pricing,
                    recovery_request_limit_scope=request.request_limit_scope,
                    recovery_request_limit_count_before=request.request_limit_count_before,
                )
                or not _promoted_recovery_context_matches_request(
                    context=leaf_context,
                    usage=live_leaf_usage,
                    request=request,
                )
            ):
                return False
        parent_surface_ids = {
            origin.surface_id for origin in recursive_artifact.origins if origin.provisional
        }
        projected_parent_surface_ids = {
            review.surface_id for review in recursive_artifact.parent.projection.surface_reviews
        }
        leaf_partition = {
            (child.surface_artifact.artifact_sha256, record.surface_id)
            for child in recursive_artifact.children
            for record in child.surface_artifact.records
        }
        leaf_surface_ids = {surface_id for _, surface_id in leaf_partition}
        request_surface_ids = {request.surface_id for request in recursive_artifact.requests}
        if (
            not leaf_partition
            or parent_surface_ids != projected_parent_surface_ids
            or parent_surface_ids & leaf_surface_ids
            or parent_surface_ids | leaf_surface_ids != request_surface_ids
            or len(parent_surface_ids) + len(leaf_partition) != len(request_surface_ids)
        ):
            return False
        promoted_parent_partitions[recursive_artifact.artifact_sha256] = {
            (recursive_artifact.artifact_sha256, surface_id) for surface_id in parent_surface_ids
        }
        promoted_child_partitions[recursive_artifact.artifact_sha256] = leaf_partition
        composite_by_artifact_sha256[recursive_artifact.artifact_sha256] = recursive_projection
    if seen_promotion_entries != set(public_promotion_entry_sha256s):
        return False

    lineage_by_model = model_lineage_index(config)
    credited_reference_count = 0
    credited_composite_artifact_surfaces: set[tuple[str, str]] = set()
    credited_ordinary_artifact_surfaces: set[tuple[str, str]] = set()
    for surface in coverage.surfaces:
        credited_references = [
            reference for reference in surface.evidence_references if reference.credited
        ]
        if (
            surface.reviewed != bool(credited_references)
            or surface.reviewer_roles
            != sorted({reference.review_role for reference in credited_references})
            or surface.root_lineages
            != sorted(
                {
                    reference.root_lineage
                    for reference in credited_references
                    if reference.root_lineage is not None
                }
            )
        ):
            return False
        credited_reference_count += len(credited_references)
        for reference in credited_references:
            promoted_projection = composite_by_artifact_sha256.get(reference.artifact_sha256)
            if promoted_projection is not None:
                composite_artifact = promoted_projection.artifact
                usage = promoted_projection.parent_usage_record
                matching_origins = tuple(
                    origin
                    for origin in composite_artifact.origins
                    if origin.surface_id == reference.surface_id and origin.provisional
                )
                promoted_records = tuple(
                    record
                    for record in composite_artifact.records
                    if record.surface_id == reference.surface_id
                )
                try:
                    qualified_model = (
                        qualification.model_for(
                            usage.requested_model,
                            now=datetime.now(UTC).replace(microsecond=0),
                        )
                        if qualification is not None
                        else None
                    )
                except ValueError:
                    return False
                lineage = lineage_by_model.get(usage.requested_model.lower())
                if (
                    len(matching_origins) != 1
                    or len(promoted_records) != 1
                    or qualified_model is None
                    or lineage is None
                    or reference.surface_id != surface.surface_id
                    or reference.status
                    not in {
                        ModelSurfaceReviewStatus.CANDIDATE,
                        ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                    }
                    or reference.request_id != usage.request_id
                    or reference.requested_model != usage.requested_model
                    or reference.model != usage.actual_model
                    or reference.review_role != usage.role
                    or reference.review_role != promoted_records[0].review_role
                    or reference.status is not promoted_records[0].status
                    or reference.root_lineage != qualified_model.root_lineage
                    or lineage.root_lineage != qualified_model.root_lineage
                    or lineage.root_lineage not in config.privacy.approved_model_lineages
                    or matching_origins[0].request_id != usage.request_id
                ):
                    return False
                credited_composite_artifact_surfaces.add(
                    (reference.artifact_sha256, reference.surface_id)
                )
                continue
            matching_usage = usage_by_request.get(reference.request_id, [])
            if len(matching_usage) != 1:
                return False
            usage = matching_usage[0]
            recovery_coordinates = (recovery_request_limit_coordinates or {}).get(usage.request_id)
            if not _is_real_model_usage(
                usage,
                config,
                qualification,
                provider_session,
                audit_selection,
                audit_refresh,
                audit_refresh_pricing,
                recovery_request_limit_scope=(
                    recovery_coordinates[0] if recovery_coordinates is not None else None
                ),
                recovery_request_limit_count_before=(
                    recovery_coordinates[1] if recovery_coordinates is not None else None
                ),
            ):
                return False

            matching_artifacts = artifacts_by_request.get(reference.request_id, [])
            if len(matching_artifacts) != 1:
                return False
            ordinary_artifact = matching_artifacts[0]
            if ordinary_artifact.artifact_sha256 != reference.artifact_sha256:
                return False
            try:
                sealed_artifact = ModelSurfaceReviewArtifact.model_validate(
                    ordinary_artifact.model_dump(mode="json")
                )
            except ValueError:
                return False

            ordinary_records = [
                record
                for record in sealed_artifact.records
                if record.surface_id == reference.surface_id
            ]
            if len(ordinary_records) != 1:
                return False
            review_record = ordinary_records[0]
            try:
                qualified_model = (
                    qualification.model_for(
                        usage.requested_model,
                        now=datetime.now(UTC).replace(microsecond=0),
                    )
                    if qualification is not None
                    else None
                )
            except ValueError:
                return False
            lineage = lineage_by_model.get(usage.requested_model.lower())
            if lineage is None or qualified_model is None:
                return False
            if lineage.root_lineage not in config.privacy.approved_model_lineages:
                return False
            if (
                reference.surface_id != surface.surface_id
                or reference.status
                not in {
                    ModelSurfaceReviewStatus.CANDIDATE,
                    ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
                }
                or reference.status is not review_record.status
                or reference.review_role != usage.role
                or reference.review_role != sealed_artifact.review_role
                or reference.review_role != review_record.review_role
                or reference.requested_model != usage.requested_model
                or reference.model != usage.actual_model
                or reference.root_lineage != qualified_model.root_lineage
                or lineage.root_lineage != qualified_model.root_lineage
                or sealed_artifact.request_id != usage.request_id
                or reference.surface_id not in sealed_artifact.requested_surface_ids
                or sealed_artifact.prompt_sha256 != usage.prompt_sha256
                or sealed_artifact.response_sha256 != usage.response_sha256
                or sealed_artifact.validated_response_sha256 != usage.validated_response_sha256
                or sealed_artifact.response_schema_sha256 != usage.schema_sha256
            ):
                return False
            credited_ordinary_artifact_surfaces.add(
                (ordinary_artifact.artifact_sha256, reference.surface_id)
            )
    consumed_composite_artifact_sha256s = {
        artifact_sha256
        for artifact_sha256, child_partition in promoted_child_partitions.items()
        if child_partition <= credited_ordinary_artifact_surfaces
        and promoted_parent_partitions[artifact_sha256] <= credited_composite_artifact_surfaces
    }
    return credited_reference_count > 0 and consumed_composite_artifact_sha256s == set(
        composite_by_artifact_sha256
    )


def _compilation_failure_detail(
    *,
    missing: list[tuple[str, str]],
    unexpected: list[tuple[str, str]],
    incomplete: list[str],
    attempted: bool,
) -> str:
    issues: list[str] = []
    if missing:
        issues.append(
            "missing project results: "
            + ", ".join(f"{root} ({framework})" for root, framework in sorted(missing))
        )
    if unexpected:
        issues.append(
            "unexpected project results: "
            + ", ".join(f"{root} ({framework})" for root, framework in sorted(unexpected))
        )
    if incomplete:
        issues.append("non-qualifying results: " + ", ".join(sorted(incomplete)))
    if issues:
        return "; ".join(issues)
    return (
        "compilation did not produce qualifying project evidence"
        if attempted
        else ("compilation was not attempted")
    )


def _present(artifacts: set[str], filename: str) -> list[str]:
    return [filename] if filename in artifacts else []


def _formal_artifacts(runs: list[FormalToolRun]) -> list[str]:
    return sorted(
        {
            artifact
            for run in runs
            for evidence in run.evidence
            for artifact in evidence.artifact_paths
        }
    )
