"""End-to-end read-only audit pipeline with partial-result preservation."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import time
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any, Literal, cast

from mmaudit.agents.base import (
    AgentRequestProtocol,
    FindingReviewResult,
    WholeProtocolReviewAgent,
)
from mmaudit.agents.business_logic import BusinessLogicAgent
from mmaudit.agents.configuration import ConfigurationAgent
from mmaudit.agents.invariant_review import InvariantReviewAgent
from mmaudit.agents.judge import JudgeAgent
from mmaudit.agents.reproduction import ExploitTestPlannerAgent, FalsifierAgent
from mmaudit.agents.source_audit import SourceAuditAgent
from mmaudit.agents.specialists import (
    ReportQualityAgent,
    SpecialistFindingAgent,
    build_specialist_execution_records,
    canonical_specialist_role,
    completed_specialist_roles,
    specialist_context_budget,
)
from mmaudit.agents.threat_model import ThreatModelAgent
from mmaudit.agents.verifier import (
    CandidateCrossExaminerAgent,
    CandidateFalsifierAgent,
    PreparedCandidateCrossExaminationInput,
    VerifierAgent,
    normalize_cross_examination_response,
    select_candidate_falsifier_models,
    select_validation_falsifier_models,
)
from mmaudit.agents.verifier import (
    insufficient_verifications as _insufficient_verifications,
)
from mmaudit.benchmark.certificate import (
    BenchmarkCertificateVerification,
    CertificateVerificationOrigin,
    CertificateVerificationStatus,
)
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
    configured_model_ids,
    model_lineage_index,
    validate_model_independence,
)
from mmaudit.constants import (
    ANALYSIS_ROLES,
    AUDIT_REPORT_SCHEMA_VERSION,
    REPORT_SCHEMA_VERSION,
    SEVERITY_ORDER,
    SPECIALIST_AUXILIARY_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
    ExitCode,
)
from mmaudit.isolation.dependencies import (
    DependencyPreparationRun,
    prepare_dependencies,
)
from mmaudit.logging import JsonLineHandler, RedactingFilter
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    openrouter_catalog_canonical_slug,
    validate_openrouter_model_discovery,
)
from mmaudit.models.endpoint_snapshots import (
    EndpointSnapshotValidationError,
    validate_openrouter_endpoint_snapshot,
)
from mmaudit.models.openrouter import (
    OpenRouterAuthenticationError,
    OpenRouterClient,
    OpenRouterError,
    OpenRouterPrivacyError,
    OpenRouterQualificationRoutingEvidence,
    OpenRouterQualifiedReasoningRoutingBinding,
    OpenRouterSchemaError,
    trusted_openrouter_execution_evidence,
)
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.registry import (
    ModelRegistry,
    ProductionQualificationValidation,
    extract_zdr_model_ids,
)
from mmaudit.models.runtime import (
    build_openrouter_runtime_controls,
    production_model_qualification_required,
)
from mmaudit.models.scheduler import (
    SchedulerAbsenceReason,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCandidateWorkset,
    SchedulerCostLedgerBaseline,
    SchedulerEvidencePayloadBinding,
    SchedulerPassKind,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerPrivacyEvidenceCustody,
    SchedulerRetainedJournalReference,
    SchedulerScope,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerShardKind,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
    scheduler_response_schema_sha256,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    AuditScopeAssessment,
    CandidateCrossExaminationDecision,
    CandidateCrossExaminationResponse,
    CandidateFinding,
    CandidateOriginKind,
    CandidateReproductionResolution,
    CandidateReviewBatch,
    CompilationStatus,
    ContextPackage,
    ContextRequestEvidence,
    DependencyPreparationStatus,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    Evidence,
    ExecutionEvidenceKind,
    FalsificationBatch,
    FalsificationVerdict,
    Finding,
    FindingOriginKind,
    FindingStatus,
    FormalToolRun,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantReviewBatch,
    InvariantReviewResult,
    InvariantSuite,
    JudgeDecision,
    JudgeDecisionBatch,
    Location,
    LocationValidation,
    MaximumAssuranceAssessment,
    MinimumAnalysisFloor,
    ModelReviewCoverage,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRequest,
    ModelVote,
    PriorAuditComparison,
    PropertyCorpus,
    QualityGateResult,
    ReportQualityReview,
    RepositoryDifferentialRunStatus,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ReproductionIntegrityStatus,
    ReproductionResolutionKind,
    ReproductionResult,
    ReproductionState,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphEdge,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SolidityProjectType,
    SoliditySymbolIndex,
    SpecialistAcceptedOutcome,
    SpecialistAcceptedOutcomeKind,
    ThreatModel,
    TransactionOrderingCapability,
    UsageRecord,
    VerificationBatch,
    VerificationDecision,
    VerificationVerdict,
)
from mmaudit.models.sharding import (
    SolidityShardInventory,
    SolidityShardOverlapKind,
    SolidityShardPolicy,
    SolidityShardReportBinding,
    SolidityShardsArtifact,
)
from mmaudit.models.usage import (
    UsageLedger,
    candidate_falsifier_role,
    is_creditable_usage_record,
)
from mmaudit.orchestration.assurance import (
    CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES,
    AssuranceRuntime,
    MaximumAssuranceContract,
    ProviderSessionProvenance,
    _issue_provider_session_provenance,
    is_qualifying_real_foundry_portfolio,
)
from mmaudit.orchestration.budgets import BudgetExhaustedError, BudgetManager
from mmaudit.orchestration.candidate_enrichment import (
    attach_formal_counterexamples as _attach_formal_counterexamples,
)
from mmaudit.orchestration.ci import (
    CI_STATE_FILENAME,
    CIJobStatus,
    CIRepositorySuiteStatus,
    CIRunState,
    LoadedCIBaseline,
    build_ci_evidence_from_report,
    build_ci_repository_suite_evidence,
    build_ci_run_state,
    ci_producer_sha256,
    deterministic_ci_coverage_metrics,
    deterministic_ci_policy_sha256,
)
from mmaudit.orchestration.consensus import (
    HOST_EXECUTION_ANALYSIS_LINK_SOURCE,
    CandidateGroup,
    enforce_critical_evidence_cap,
    group_candidates,
    merge_group,
    preliminary_status,
)
from mmaudit.orchestration.context import (
    ContextBoundaryError,
    ContextBudgetError,
    ContextBuilder,
    context_hash_index,
    context_json_escape_overhead_tokens,
    render_context,
    revalidate_context_package,
)
from mmaudit.orchestration.context_manifest import (
    ContextManifest,
    ContextPreflightRequestEvidence,
    build_context_manifest,
    context_manifest_report_binding,
    write_context_manifest,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.execution_candidates import (
    ExecutionCandidateBuildResult,
    build_invariant_execution_candidates,
)
from mmaudit.orchestration.manifest import (
    SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME,
    ManifestFileBinding,
    build_run_evidence_manifest,
    canonical_sha256,
    open_manifest_bound_json_artifacts,
    open_pre_manifest_json_artifacts,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.model_coverage import (
    build_model_review_coverage,
    build_model_surface_requests,
    build_semantic_shard_source_review_request,
    model_review_critical_surface_gate,
    model_review_edge_subject_id,
    model_surface_assignment_feasibility_gate,
    plan_model_surface_review_assignments,
)
from mmaudit.orchestration.model_review_evidence import build_source_file_review_request
from mmaudit.orchestration.prior_audit import (
    build_prior_audit_comparison,
    prior_audit_quality_gate,
    withhold_prior_audit_from_discovery,
)
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    audit_quality_status_for_run_status,
    minimum_analysis_floor_quality_gate,
)
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    open_scheduler_privacy_evidence_custody,
)
from mmaudit.orchestration.scheduler_runtime import (
    PipelineScheduler,
    build_scheduler_analysis_input_inventory,
    build_scheduler_bindings,
    build_scheduler_cost_ledger_baseline,
    build_scheduler_shard_inventory,
)
from mmaudit.orchestration.scope import (
    assess_audit_scope,
    filter_discovery_for_scope,
    scope_quality_gate,
)
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    PrivacyRetentionConsentObservation,
    PrivacySourceClassification,
    TrustedPrivacyAuthorization,
    resolve_effective_privacy_policy,
    resolve_trusted_privacy_authorization,
    validate_trusted_privacy_authorization,
)
from mmaudit.reporting.bundle import (
    RunCostLedgerEvidence,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
    build_run_cost_ledger_evidence,
    source_symbol_is_present,
)
from mmaudit.reporting.client import (
    bind_active_finding_source_locations,
    build_client_source_excerpts,
    render_client_markdown,
)
from mmaudit.reporting.json_report import stable_json, write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import report_status_metadata
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import (
    DiscoveryResult,
    discover_repository,
    safe_repository_root,
)
from mmaudit.repository.ignore import IgnoreMatcher, normalize_relative_path, safe_ignore_file
from mmaudit.repository.locations import validate_candidate, validate_location
from mmaudit.repository.mapping import build_repository_map
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceEvidence,
    PrivacySourceProvenanceObservation,
    prove_privacy_source_classification,
    validate_privacy_source_provenance_observation,
)
from mmaudit.repository.redaction import SecretSafetyError
from mmaudit.repository.workspace import audited_workspace_exclusion_root
from mmaudit.scanners.base import ScannerSourceIntegrityError, scanner_workspace_sha256
from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
from mmaudit.scanners.fork_matrix import (
    ForkMatrixDependencies,
    RepositoryForkMatrixRunner,
    repository_fork_matrix_timeout_budget_seconds,
)
from mmaudit.scanners.projection import project_scanner_finding
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.runtime_evidence import (
    validated_scanner_run_location_annotation_preserving_runtime_authority,
)
from mmaudit.solidity.compile import compile_solidity_projects
from mmaudit.solidity.coverage import (
    build_solidity_coverage,
    with_invariant_review_coverage,
    with_model_review_coverage,
    with_runtime_coverage,
)
from mmaudit.solidity.economics import plan_economic_simulations
from mmaudit.solidity.formal import FormalRunner, compare_dynamic_engine_outcomes
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.invariant_review import validate_invariant_review
from mmaudit.solidity.invariant_templates import generate_invariant_harnesses
from mmaudit.solidity.invariants import discover_invariants
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.properties import build_property_corpus
from mmaudit.solidity.reproduction import (
    ForkReproductionRunner,
    translate_foundry_test,
)
from mmaudit.solidity.reproduction_integrity import verify_reproduction_integrity
from mmaudit.solidity.sharding import (
    build_solidity_shard_inventory,
    solidity_graph_edge_id,
    verify_solidity_shard_inventory,
)
from mmaudit.traceability import (
    build_traceability_matrix,
    validate_traceability_evidence,
    write_traceability_artifact,
)


def _exact_completed_usage(
    usage_records: list[UsageRecord],
    completion_usage: UsageRecord,
    *,
    expected_role: str,
) -> UsageRecord:
    """Join one host-validated result to exactly one immutable ledger request."""

    try:
        normalized = UsageRecord.model_validate(completion_usage.model_dump(mode="python"))
    except ValueError as exc:
        raise OpenRouterSchemaError(
            "validated agent result carried invalid completion evidence"
        ) from exc
    matches = [record for record in usage_records if record.request_id == normalized.request_id]
    if len(matches) != 1:
        raise OpenRouterSchemaError(
            "validated agent result did not join exactly one provider usage record"
        )
    selected = matches[0]
    if (
        selected.model_dump(mode="json") != normalized.model_dump(mode="json")
        or selected.role != expected_role
        or normalized.role != expected_role
        or not is_creditable_usage_record(selected)
    ):
        raise OpenRouterSchemaError(
            "validated agent result differed from its exact completed provider request"
        )
    return selected


def _bound_context_request_evidence(
    usage_record: UsageRecord,
    context: ContextPackage,
) -> tuple[ContextPackage, ContextRequestEvidence]:
    """Revalidate one exact request/context binding from detached evidence."""

    try:
        sealed_context = revalidate_context_package(context)
    except ContextBoundaryError as exc:
        raise OpenRouterSchemaError(
            "validated agent context failed detached boundary validation"
        ) from exc
    raw_evidence = usage_record.routing.get("context_request_evidence")
    if not isinstance(raw_evidence, dict):
        raise OpenRouterSchemaError("validated agent result lacks typed request/context evidence")
    try:
        evidence = ContextRequestEvidence.model_validate(raw_evidence)
    except ValueError as exc:
        raise OpenRouterSchemaError(
            "validated agent request/context evidence failed validation"
        ) from exc
    rendered_sha256 = hashlib.sha256(render_context(sealed_context).encode("utf-8")).hexdigest()
    source_bytes = sum(len(excerpt.content.encode("utf-8")) for excerpt in sealed_context.excerpts)
    if (
        evidence.request_id != usage_record.request_id
        or evidence.request_role != usage_record.role
        or evidence.context_role != sealed_context.role
        or evidence.declared_bytes_used != sealed_context.bytes_used
        or evidence.byte_budget != sealed_context.byte_budget
        or evidence.rendered_sha256 != rendered_sha256
        or evidence.source_bytes != source_bytes
        or evidence.configured_maximum_source_tokens_per_request
        != sealed_context.configured_maximum_source_tokens_per_request
        or evidence.effective_source_byte_ceiling != sealed_context.effective_source_byte_ceiling
        or usage_record.routing.get("context_request_evidence_sha256") != evidence.evidence_sha256
    ):
        raise OpenRouterSchemaError(
            "validated agent request/context evidence differed from its exact package"
        )
    return sealed_context, evidence


def _validated_finding_result(
    result: FindingReviewResult,
    *,
    expected_role: str,
    usage_records: list[UsageRecord],
) -> tuple[ContextPackage, UsageRecord]:
    """Bind a candidate batch to its exact completed request and source package."""

    usage_record = _exact_completed_usage(
        usage_records,
        result.completion_usage,
        expected_role=expected_role,
    )
    context, context_evidence = _bound_context_request_evidence(
        usage_record,
        result.surface_review_context,
    )
    # ContextRequestEvidence has already validated the closed request-role to
    # context-role relationship. Indexed whole-protocol requests deliberately
    # share the frozen ``whole_protocol_review`` context role.
    if usage_record.user_prompt_sha256 != context_evidence.rendered_sha256:
        raise OpenRouterSchemaError(
            "candidate review completion was not bound to its exact source context"
        )
    if any(
        finding.origin_kind is not CandidateOriginKind.MODEL_REVIEW
        or finding.execution_provenance is not None
        for finding in result.findings
    ):
        raise OpenRouterSchemaError(
            "model review attempted to claim host-owned deterministic execution origin"
        )
    if any(
        evidence.source == HOST_EXECUTION_ANALYSIS_LINK_SOURCE
        for finding in result.findings
        for evidence in finding.evidence
    ):
        raise OpenRouterSchemaError(
            "model review attempted to claim a host-owned execution analysis link"
        )
    artifact = result.surface_review_artifact
    if artifact is None:
        if context.requested_model_surfaces:
            raise OpenRouterSchemaError("candidate review omitted required surface-review evidence")
    else:
        try:
            artifact = ModelSurfaceReviewArtifact.model_validate(artifact.model_dump(mode="python"))
        except ValueError as exc:
            raise OpenRouterSchemaError(
                "candidate review carried invalid surface-review evidence"
            ) from exc
        try:
            artifact.require_exact_requested_surface_manifest(context.requested_model_surfaces)
        except ValueError as exc:
            raise OpenRouterSchemaError(
                "candidate review artifact differed from its requested surface manifest"
            ) from exc
        if (
            artifact.request_id != usage_record.request_id
            or artifact.review_role != expected_role
            or artifact.prompt_sha256 != usage_record.prompt_sha256
            or artifact.rendered_context_sha256 != context_evidence.rendered_sha256
            or artifact.rendered_context_sha256 != usage_record.user_prompt_sha256
            or artifact.response_sha256 != usage_record.response_sha256
            or artifact.validated_response_sha256 != usage_record.validated_response_sha256
            or artifact.response_schema_sha256 != usage_record.schema_sha256
        ):
            raise OpenRouterSchemaError(
                "candidate review artifact differed from its exact provider evidence"
            )
    return context, usage_record


def _register_candidate_origin_packages(
    origin_packages: dict[str, ContextPackage],
    *,
    candidate_ids: list[str],
    context: ContextPackage,
) -> None:
    """Register each candidate exactly once against one detached source package."""

    if len(candidate_ids) != len(set(candidate_ids)) or any(
        candidate_id in origin_packages for candidate_id in candidate_ids
    ):
        raise OpenRouterSchemaError(
            "candidate review returned a duplicate or conflicting candidate ID"
        )
    sealed = revalidate_context_package(context)
    for candidate_id in candidate_ids:
        origin_packages[candidate_id] = sealed


def _candidate_origin_context_hashes(
    origin_packages: dict[str, ContextPackage],
    candidate_id: str,
) -> dict[tuple[str, int, int], str]:
    """Return only the source hashes delivered to the candidate's originating request."""

    context = origin_packages.get(candidate_id)
    return context_hash_index([context]) if context is not None else {}


def _candidate_origin_source_hashes(
    origin_packages: dict[str, ContextPackage],
    candidate: CandidateFinding,
) -> dict[tuple[str, int, int], str]:
    """Return only source hashes from the candidate's host-attested origin."""

    if candidate.origin_kind is CandidateOriginKind.DETERMINISTIC_EXECUTION:
        provenance = candidate.execution_provenance
        if provenance is None:
            return {}
        return {
            (location.path, location.start_line, location.end_line): location.content_hash
            for location in provenance.source_locations
            if location.content_hash is not None
        }
    return _candidate_origin_context_hashes(origin_packages, candidate.candidate_id)


@dataclass(frozen=True)
class PipelineResult:
    report: AuditReport
    run_dir: Path
    exit_code: ExitCode
    ci_state: CIRunState | None = None

    def exit_for_findings(self, fail_on: Severity | None) -> ExitCode:
        if self.exit_code is not ExitCode.SUCCESS or fail_on is None:
            return self.exit_code
        threshold = SEVERITY_ORDER[fail_on.value]
        if any(
            finding.status is not FindingStatus.REJECTED
            and SEVERITY_ORDER[finding.severity.value] >= threshold
            for finding in self.report.findings
        ):
            return ExitCode.FINDINGS
        return ExitCode.SUCCESS

    def exit_for_ci(self, fail_on: Severity | None) -> ExitCode:
        """Apply CI evidence gates without weakening ordinary audit exits."""

        if self.exit_code is not ExitCode.SUCCESS:
            return self.exit_code
        if self.ci_state is None:
            return ExitCode.INCOMPLETE
        if self.ci_state.job_status in {
            CIJobStatus.ANALYSIS_FAILED,
            CIJobStatus.COVERAGE_REGRESSION,
        }:
            return ExitCode.INCOMPLETE
        return self.exit_for_findings(fail_on)


def _repository_source_scope_sha256(repository_map: RepositoryMap) -> str:
    """Bind consent to the exact discovered source inventory used by the run manifest."""

    payload = [
        {
            "path": item.path,
            "sha256": item.sha256,
            "size": item.size,
        }
        for item in sorted(repository_map.files, key=lambda candidate: candidate.path)
    ]
    return canonical_sha256(payload)


def _scheduler_response_schema_sha256(response_model: type[Any]) -> str:
    """Return the exact structured-output schema commitment used by the scheduler."""

    return scheduler_response_schema_sha256(response_model)


def _scheduler_root_lineage(config: AuditConfig, model_id: str) -> str:
    """Resolve one exact configured model to its operator-reviewed root lineage."""

    lineage = model_lineage_index(config).get(model_id.lower())
    if lineage is None:
        raise ValueError(f"scheduled model lacks immutable root lineage: {model_id}")
    return lineage.root_lineage


def _whole_protocol_review_models(
    config: AuditConfig,
    qualification: VerifiedProductionQualification | None,
) -> tuple[tuple[str, str], ...]:
    """Select four exact independently qualified whole-protocol reviewers."""

    if config.profile is not AuditProfile.MAXIMUM_ASSURANCE:
        return ()
    if qualification is None:
        raise ValueError("maximum assurance lacks production model qualification")
    qualification.require_current(now=datetime.now(UTC).replace(microsecond=0))
    configured = set(configured_model_ids(config, include_fallbacks=True))
    selected: list[tuple[str, str]] = []
    selected_lineages: set[str] = set()
    for model in sorted(qualification.models, key=lambda item: item.exact_model_id):
        if (
            model.exact_model_id not in configured
            or "whole_protocol_review" not in model.approved_roles
            or model.root_lineage in selected_lineages
        ):
            continue
        selected.append((model.exact_model_id, model.root_lineage))
        selected_lineages.add(model.root_lineage)
        if len(selected) == CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES:
            break
    if len(selected) != CERTIFIED_ENSEMBLE_MIN_WHOLE_PROTOCOL_LINEAGES:
        raise ValueError(
            "maximum assurance lacks four independently qualified whole-protocol reviewers"
        )
    return tuple(selected)


def _scheduler_primary_only_config(config: AuditConfig) -> AuditConfig:
    """Disable unsealed model fallback routes for scheduler-bound agent calls."""

    models = config.models
    core_roles = (
        "threat_model",
        "source_audit",
        "business_logic",
        "configuration",
        "verifier",
        "judge",
    )
    updates: dict[str, Any] = {
        role: models.role(role).model_copy(update={"fallbacks": []}) for role in core_roles
    }
    updates["specialists"] = {
        role: configured.model_copy(update={"fallbacks": []})
        for role, configured in models.specialists.items()
    }
    exact_models = models.model_copy(update=updates)
    return config.model_copy(update={"models": exact_models})


def _candidate_source_paths(candidate: CandidateFinding) -> frozenset[str]:
    """Return every source path explicitly cited by one typed candidate."""

    paths = {location.path for location in candidate.locations}
    if candidate.source is not None:
        paths.add(candidate.source.path)
    if candidate.sink is not None:
        paths.add(candidate.sink.path)
    return frozenset(paths)


def _candidate_payload_sha256s(
    candidates: Sequence[CandidateFinding],
) -> dict[str, str]:
    """Hash every canonical normalized candidate payload, not only its stable ID."""

    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("candidate payload hashing requires unique candidate IDs")
    return {
        candidate.candidate_id: scheduler_canonical_sha256(candidate.model_dump(mode="json"))
        for candidate in sorted(candidates, key=lambda item: item.candidate_id)
    }


def _bind_terminal_finding_source_ranges(
    findings: list[Finding],
    *,
    source_contents: dict[str, str],
    label: str,
) -> list[Finding]:
    """Bind terminal findings before pass seven seals their exact public payloads."""

    bound: list[Finding] = []
    for finding in findings:
        if not finding.location_validation.valid:
            raise ValueError(f"{label} finding lacks valid source-location evidence: {finding.id}")
        if not finding.locations:
            raise ValueError(f"{label} finding lacks a source location: {finding.id}")
        bound_locations: list[Location] = []
        for location in finding.locations:
            try:
                content = source_contents[location.path]
            except KeyError:
                raise ValueError(
                    f"source content is unavailable for cited path: {location.path}"
                ) from None
            lines = content.splitlines(keepends=True)
            if (
                location.start_line < 1
                or location.end_line < location.start_line
                or location.end_line > len(lines)
            ):
                raise ValueError(f"source line range is outside the audited file: {location.path}")
            selected = "".join(lines[location.start_line - 1 : location.end_line])
            observed_range_hash = line_range_hash(
                content,
                location.start_line,
                location.end_line,
            )
            if location.content_hash is not None and location.content_hash != observed_range_hash:
                raise ValueError(
                    f"source range hash differs from the final finding: {location.path}"
                )
            if location.symbol is not None and not source_symbol_is_present(
                location.symbol,
                selected,
            ):
                raise ValueError(
                    f"source symbol is absent from the final cited range: {location.path}"
                )
            bound_locations.append(
                location.model_copy(update={"content_hash": observed_range_hash})
            )
        bound.append(finding.model_copy(update={"locations": bound_locations}))
    return bound


def _finding_reduction_activation_input(
    candidates: list[CandidateFinding],
    *,
    blind_candidate_ids: set[str],
    execution_candidate_ids: set[str],
) -> dict[str, Any]:
    """Build the exact pass-three input after all candidate evidence is finalized."""

    return {
        "blind_candidate_ids": sorted(blind_candidate_ids),
        "execution_candidate_ids": sorted(execution_candidate_ids),
        "candidate_payload_sha256s": _candidate_payload_sha256s(candidates),
    }


def _deterministic_candidate_validation(
    root: Path,
    candidate: CandidateFinding,
    *,
    context_hashes: dict[tuple[str, int, int], str],
) -> LocationValidation:
    """Retain validation substance without embedding wall-clock replay drift."""

    validation = validate_candidate(root, candidate, context_hashes=context_hashes)
    return validation.model_copy(update={"validated_at": None})


def _require_candidate_workset_payloads(
    workset: SchedulerCandidateWorkset,
    candidates: list[CandidateFinding],
) -> None:
    """Reject same-ID/different-payload drift before downstream model activation."""

    actual = _candidate_payload_sha256s(candidates)
    expected = {
        binding.candidate_id: binding.candidate_payload_sha256
        for binding in workset.candidate_payload_bindings
    }
    if actual != expected:
        raise ValueError("downstream candidate payloads differ from the pass-four workset")


def _semantic_shard_context_paths(
    inventory: SolidityShardInventory | None,
    *,
    shard_id: str,
    primary_paths: set[str],
) -> set[str]:
    """Expand one blind shard context by its exact typed overlap and boundaries."""

    if inventory is None:
        return set(primary_paths)
    shards = {item.shard_id: item for item in inventory.shards}
    if shard_id not in shards:
        return set(primary_paths)
    related_ids = {shard_id}
    for boundary in inventory.boundaries:
        if boundary.source_shard_id == shard_id:
            related_ids.add(boundary.target_shard_id)
        elif boundary.target_shard_id == shard_id:
            related_ids.add(boundary.source_shard_id)
    for overlap in inventory.overlaps:
        if overlap.primary_shard_id == shard_id:
            related_ids.add(overlap.consumer_shard_id)
        elif overlap.consumer_shard_id == shard_id:
            related_ids.add(overlap.primary_shard_id)
    return set(primary_paths) | {
        shards[related_id].source_path for related_id in sorted(related_ids) if related_id in shards
    }


def _source_audit_shard_surface_requests(
    *,
    shard: SchedulerShardDescriptor,
    discovery: DiscoveryResult,
    solidity_index: SoliditySymbolIndex | None,
    assigned: list[ModelSurfaceReviewRequest],
    solidity_requests: list[ModelSurfaceReviewRequest],
) -> list[ModelSurfaceReviewRequest]:
    """Require one explicit substantive review surface for every scoped source file."""

    scoped_paths = {source.path for source in shard.sources}
    selected = {
        request.surface_id: request
        for request in assigned
        if not request.allowed_locations
        or {location.path for location in request.allowed_locations} <= scoped_paths
    }
    discovered_by_path = {item.relative_path: item for item in discovery.files}
    for source in shard.sources:
        item = discovered_by_path.get(source.path)
        if item is None or item.sha256 != source.sha256 or item.size != source.size:
            raise ValueError("source-audit shard differs from the discovered source inventory")
        # Every blind source review carries one path-cited whole-file disposition.
        # Symbol-only Solidity records remain useful, but cannot by themselves prove
        # substantive review of the exact source bytes bound into this shard.
        request = build_source_file_review_request(
            path=item.relative_path,
            size=item.size,
            lines=item.lines,
            sha256=item.sha256,
        )
        selected[request.surface_id] = request
        if shard.kind is SchedulerShardKind.SOLIDITY_SEMANTIC:
            semantic_requests = sorted(
                (
                    surface
                    for surface in solidity_requests
                    if surface.kind is not ModelReviewSurfaceKind.SOURCE_FILE
                    and surface.allowed_locations
                    and {location.path for location in surface.allowed_locations} <= {source.path}
                ),
                key=lambda surface: surface.surface_id,
            )
            if semantic_requests:
                semantic_request = semantic_requests[0]
            else:
                if solidity_index is None:
                    raise ValueError(
                        "source-audit semantic shard lacks a typed Solidity source surface"
                    )
                semantic_request = build_semantic_shard_source_review_request(
                    index=solidity_index,
                    source_path=item.relative_path,
                    source_content=item.content,
                    source_sha256=item.sha256,
                )
            selected[semantic_request.surface_id] = semantic_request
    if shard.kind is SchedulerShardKind.SOLIDITY_SEMANTIC and not any(
        request.kind is not ModelReviewSurfaceKind.SOURCE_FILE
        and request.allowed_locations
        and {location.path for location in request.allowed_locations} <= scoped_paths
        for request in selected.values()
    ):
        raise ValueError("source-audit semantic shard lacks a typed Solidity source surface")
    return sorted(selected.values(), key=lambda request: request.surface_id)


def _blind_shard_surface_requests(
    *,
    shard: SchedulerShardDescriptor,
    discovery: DiscoveryResult,
    assigned: list[ModelSurfaceReviewRequest],
) -> list[ModelSurfaceReviewRequest]:
    """Bind every blind task to a disposition of its declared primary shard sources.

    Fine-grained assignments may legitimately cite semantic neighbours included in the
    context.  They cannot, however, replace all review custody for the shard named by the
    scheduler task.  Add a whole-file disposition only for a primary source that has no
    assigned location of its own.
    """

    discovered_by_path = {item.relative_path: item for item in discovery.files}
    selected = {request.surface_id: request for request in assigned}
    for source in shard.sources:
        item = discovered_by_path.get(source.path)
        if item is None or item.sha256 != source.sha256 or item.size != source.size:
            raise ValueError("blind-review shard differs from the discovered source inventory")
        if not any(
            any(location.path == source.path for location in request.allowed_locations)
            for request in selected.values()
        ):
            request = build_source_file_review_request(
                path=item.relative_path,
                size=item.size,
                lines=item.lines,
                sha256=item.sha256,
            )
            selected[request.surface_id] = request
    if not selected:
        raise ValueError("scheduled blind review lacks an explicit source-file surface")
    return sorted(selected.values(), key=lambda request: request.surface_id)


def _whole_protocol_surface_requests(
    *,
    discovery: DiscoveryResult,
) -> list[ModelSurfaceReviewRequest]:
    """Require one exact whole-file disposition for every audited source path.

    Whole-protocol reviewers receive every trusted source file. Requiring the
    full fine-grained surface catalogue again would duplicate shard-review
    metadata and can crowd the actual source out of the bounded request.
    """

    selected: dict[str, ModelSurfaceReviewRequest] = {}
    for item in discovery.files:
        request = build_source_file_review_request(
            path=item.relative_path,
            size=item.size,
            lines=item.lines,
            sha256=item.sha256,
        )
        selected[request.surface_id] = request
    return sorted(selected.values(), key=lambda request: request.surface_id)


def _cross_shard_boundary_surface_requests(
    inventory: SolidityShardInventory | None,
    graphs: SolidityGraphSet | None,
    index: SoliditySymbolIndex | None,
) -> dict[str, ModelSurfaceReviewRequest]:
    """Build one exact review surface for every typed cross-shard graph boundary."""

    if inventory is None or not inventory.boundaries:
        return {}
    if graphs is None or index is None:
        raise ValueError("cross-shard boundaries require typed graph and symbol evidence")
    edges_by_id = {solidity_graph_edge_id(edge): edge for edge in graphs.edges}
    entities_by_id = {entity.id: entity for entity in index.entities}
    requests: dict[str, ModelSurfaceReviewRequest] = {}
    for boundary in inventory.boundaries:
        edge = edges_by_id.get(boundary.graph_edge_id)
        if edge is None:
            raise ValueError("cross-shard boundary lacks its exact normalized graph edge")
        source = entities_by_id.get(edge.source_id)
        subject_id = model_review_edge_subject_id(edge)
        allowed_symbols = tuple(
            sorted(
                {
                    value
                    for value in (
                        source.signature if source is not None else None,
                        source.name if source is not None else None,
                    )
                    if value
                }
            )
        )
        request = ModelSurfaceReviewRequest(
            surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                ModelReviewSurfaceKind.CALL,
                subject_id,
            ),
            kind=ModelReviewSurfaceKind.CALL,
            subject_id=subject_id,
            contract=(
                source.contract_name if source is not None and source.contract_name else "protocol"
            ),
            function_or_state_surface=f"{edge.source_id} -> {edge.label}"[:500],
            critical=True,
            allowed_locations=(
                Location(
                    path=edge.path,
                    start_line=edge.start_line,
                    end_line=edge.end_line,
                    symbol=None,
                    content_hash=edge.source_hash,
                ),
            ),
            allowed_symbols=allowed_symbols,
            invariant_considered=(
                "Cross-shard calls must preserve authorization, state, asset, and "
                "accounting integrity across the exact graph boundary."
            ),
        )
        requests[boundary.boundary_id] = request
    return requests


def _cross_shard_overlap_surface_requests(
    inventory: SolidityShardInventory | None,
    graphs: SolidityGraphSet | None,
    index: SoliditySymbolIndex | None,
) -> dict[str, ModelSurfaceReviewRequest]:
    """Bind every semantic overlap to one exact reachable graph-edge review surface."""

    if inventory is None or not inventory.overlaps:
        return {}
    if graphs is None or index is None:
        raise ValueError("cross-shard overlaps require typed graph and symbol evidence")
    edges_by_id = {solidity_graph_edge_id(edge): edge for edge in graphs.edges}
    entities_by_id = {entity.id: entity for entity in index.entities}
    paths_by_shard = {shard.shard_id: shard.source_path for shard in inventory.shards}
    requests: dict[str, ModelSurfaceReviewRequest] = {}
    for overlap in inventory.overlaps:
        relevant_paths = {
            paths_by_shard[overlap.primary_shard_id],
            paths_by_shard[overlap.consumer_shard_id],
        }
        edge_candidates: tuple[SolidityGraphEdge, ...]
        if overlap.resource_kind is SolidityShardOverlapKind.GRAPH_EDGE:
            edge = edges_by_id.get(overlap.resource_id)
            edge_candidates = () if edge is None else (edge,)
        else:
            edge_candidates = tuple(
                edge
                for _edge_id, edge in sorted(edges_by_id.items())
                if overlap.resource_id in {edge.source_id, edge.target_id}
                and edge.path in relevant_paths
            )
        if not edge_candidates:
            raise ValueError("cross-shard overlap lacks an exact reachable graph edge")
        edge = edge_candidates[0]
        source = entities_by_id.get(edge.source_id)
        subject_id = model_review_edge_subject_id(edge)
        allowed_symbols = tuple(
            sorted(
                {
                    value
                    for value in (
                        source.signature if source is not None else None,
                        source.name if source is not None else None,
                        edge.source_id,
                    )
                    if value
                }
            )
        )
        requests[overlap.overlap_id] = ModelSurfaceReviewRequest(
            surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                ModelReviewSurfaceKind.CALL,
                subject_id,
            ),
            kind=ModelReviewSurfaceKind.CALL,
            subject_id=subject_id,
            contract=(
                source.contract_name if source is not None and source.contract_name else "protocol"
            ),
            function_or_state_surface=(
                f"semantic overlap {overlap.overlap_id}: {edge.source_id} -> {edge.label}"
            )[:500],
            critical=True,
            allowed_locations=(
                Location(
                    path=edge.path,
                    start_line=edge.start_line,
                    end_line=edge.end_line,
                    symbol=None,
                    content_hash=edge.source_hash,
                ),
            ),
            allowed_symbols=allowed_symbols,
            invariant_considered=(
                "Cross-shard semantic overlap must preserve authorization, state, asset, and "
                "accounting integrity across both exact source scopes."
            ),
        )
    return requests


def _build_deterministic_finding_reduction(
    candidates: list[CandidateFinding],
    validations: dict[str, LocationValidation],
    *,
    blind_candidate_ids: set[str],
    execution_candidate_ids: set[str],
) -> dict[str, Any]:
    """Group the exact candidate inventory without granting host-generated authority."""

    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)):
        raise ValueError("finding reduction requires unique candidate IDs")
    if set(candidate_ids) != blind_candidate_ids | execution_candidate_ids:
        raise ValueError("finding reduction input differs from the frozen candidate inventory")
    if blind_candidate_ids & execution_candidate_ids:
        raise ValueError("blind and execution candidate inventories must be disjoint")
    if set(validations) != set(candidate_ids):
        raise ValueError("finding reduction requires one validation per candidate")

    groups = group_candidates(candidates)
    group_records = []
    for group in groups:
        member_ids = tuple(candidate.candidate_id for candidate in group.candidates)
        group_records.append(
            {
                "group_id": group.group_id,
                "candidate_ids": list(member_ids),
                "canonical_candidate_id": member_ids[0],
                "valid_candidate_ids": [
                    candidate_id for candidate_id in member_ids if validations[candidate_id].valid
                ],
                "invalid_candidate_ids": [
                    candidate_id
                    for candidate_id in member_ids
                    if not validations[candidate_id].valid
                ],
            }
        )
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": "mmaudit.deterministic-finding-reduction.v1",
        "blind_candidate_ids": sorted(blind_candidate_ids),
        "execution_candidate_ids": sorted(execution_candidate_ids),
        "candidate_ids": sorted(candidate_ids),
        "candidate_payload_sha256s": _candidate_payload_sha256s(candidates),
        "candidate_records": [
            {
                "candidate_id": candidate.candidate_id,
                "candidate_sha256": scheduler_canonical_sha256(candidate.model_dump(mode="json")),
                "location_validation": {
                    "valid": validations[candidate.candidate_id].valid,
                    "content_hash": validations[candidate.candidate_id].content_hash,
                    "errors": list(validations[candidate.candidate_id].errors),
                },
            }
            for candidate in sorted(candidates, key=lambda item: item.candidate_id)
        ],
        "groups": group_records,
        "canonical_candidate_ids": sorted(
            record["canonical_candidate_id"] for record in group_records
        ),
    }
    return {**body, "reduction_sha256": scheduler_canonical_sha256(body)}


def _validate_deterministic_finding_reduction(
    reduction: dict[str, Any],
    *,
    expected_candidate_ids: set[str],
) -> None:
    """Reject metadata-only or incomplete finding-reduction output."""

    required = {
        "schema_version",
        "algorithm",
        "blind_candidate_ids",
        "execution_candidate_ids",
        "candidate_ids",
        "candidate_records",
        "candidate_payload_sha256s",
        "groups",
        "canonical_candidate_ids",
        "reduction_sha256",
    }
    if set(reduction) != required:
        raise ValueError("finding reduction output is not the exact typed projection")
    if reduction["schema_version"] != "1.0" or reduction["algorithm"] != (
        "mmaudit.deterministic-finding-reduction.v1"
    ):
        raise ValueError("finding reduction output uses an unsupported contract")
    candidate_ids = reduction["candidate_ids"]
    if candidate_ids != sorted(expected_candidate_ids):
        raise ValueError("finding reduction output omits or adds candidates")
    records = reduction["candidate_records"]
    record_ids = (
        [
            str(record["candidate_id"])
            for record in records
            if isinstance(record, dict) and isinstance(record.get("candidate_id"), str)
        ]
        if isinstance(records, list)
        else []
    )
    if sorted(record_ids) != sorted(expected_candidate_ids) or len(record_ids) != len(
        expected_candidate_ids
    ):
        raise ValueError("finding reduction output lacks exact candidate records")
    payload_hashes = reduction["candidate_payload_sha256s"]
    if (
        not isinstance(payload_hashes, dict)
        or set(payload_hashes) != expected_candidate_ids
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in payload_hashes.values()
        )
    ):
        raise ValueError("finding reduction output lacks exact candidate payload hashes")
    groups = reduction["groups"]
    if not isinstance(groups, list):
        raise ValueError("finding reduction output lacks typed groups")
    grouped_ids = [
        candidate_id
        for group in groups
        if isinstance(group, dict)
        for candidate_id in group.get("candidate_ids", [])
    ]
    if sorted(grouped_ids) != sorted(expected_candidate_ids) or len(grouped_ids) != len(
        expected_candidate_ids
    ):
        raise ValueError("finding reduction groups do not partition the candidate inventory")
    canonical_ids = [
        value
        for group in groups
        if isinstance(group, dict)
        if isinstance((value := group.get("canonical_candidate_id")), str)
    ]
    if len(canonical_ids) != len(groups):
        raise ValueError("finding reduction groups lack canonical candidates")
    if reduction["canonical_candidate_ids"] != sorted(canonical_ids):
        raise ValueError("finding reduction canonical representatives are inconsistent")
    body = {key: value for key, value in reduction.items() if key != "reduction_sha256"}
    if reduction["reduction_sha256"] != scheduler_canonical_sha256(body):
        raise ValueError("finding reduction output hash is inconsistent")


def _cross_shard_relationship_descriptors(
    inventory: SolidityShardInventory | None,
) -> list[dict[str, Any]]:
    """Return the canonical trusted semantic-relationship projection."""

    if inventory is None:
        return []
    paths_by_shard = {shard.shard_id: shard.source_path for shard in inventory.shards}
    relationships = [
        {
            "relationship_id": boundary.boundary_id,
            "relationship_kind": "graph_boundary",
            "source_shard_id": boundary.source_shard_id,
            "target_shard_id": boundary.target_shard_id,
            "source_path": paths_by_shard[boundary.source_shard_id],
            "target_path": paths_by_shard[boundary.target_shard_id],
            "resource_id": boundary.graph_edge_id,
            "relationship_sha256": boundary.boundary_sha256,
        }
        for boundary in inventory.boundaries
    ]
    relationships.extend(
        {
            "relationship_id": overlap.overlap_id,
            "relationship_kind": "semantic_overlap",
            "source_shard_id": overlap.primary_shard_id,
            "target_shard_id": overlap.consumer_shard_id,
            "source_path": paths_by_shard[overlap.primary_shard_id],
            "target_path": paths_by_shard[overlap.consumer_shard_id],
            "resource_id": overlap.resource_id,
            "relationship_sha256": overlap.overlap_sha256,
        }
        for overlap in inventory.overlaps
    )
    relationships.sort(key=lambda item: item["relationship_id"])
    return relationships


def _build_cross_shard_integration(
    inventory: SolidityShardInventory | None,
    candidates: list[CandidateFinding],
    validations: dict[str, LocationValidation],
    *,
    shard_ids: tuple[str, ...],
    invariant_review: InvariantReviewResult | None,
    boundary_surface_requests: dict[str, ModelSurfaceReviewRequest],
    boundary_review_artifacts: dict[str, ModelSurfaceReviewArtifact],
    boundary_candidate_ids: dict[str, set[str]],
    overlap_surface_requests: dict[str, ModelSurfaceReviewRequest],
    overlap_review_artifacts: dict[str, ModelSurfaceReviewArtifact],
    overlap_candidate_ids: dict[str, set[str]],
) -> dict[str, Any]:
    """Evaluate candidates against every exact semantic boundary and overlap."""

    candidate_ids = [candidate.candidate_id for candidate in candidates]
    if len(candidate_ids) != len(set(candidate_ids)) or set(validations) != set(candidate_ids):
        raise ValueError("cross-shard integration requires an exact validated candidate inventory")
    candidate_paths = {
        candidate.candidate_id: _candidate_source_paths(candidate) for candidate in candidates
    }
    boundary_ids = (
        {boundary.boundary_id for boundary in inventory.boundaries}
        if inventory is not None
        else set()
    )
    overlap_ids = (
        {overlap.overlap_id for overlap in inventory.overlaps} if inventory is not None else set()
    )
    if (
        set(boundary_surface_requests) != boundary_ids
        or set(boundary_review_artifacts) != boundary_ids
        or set(boundary_candidate_ids) != boundary_ids
    ):
        raise ValueError("cross-shard integration lacks exact boundary review evidence")
    if (
        set(overlap_surface_requests) != overlap_ids
        or set(overlap_review_artifacts) != overlap_ids
        or set(overlap_candidate_ids) != overlap_ids
    ):
        raise ValueError("cross-shard integration lacks exact overlap review evidence")
    relationship_review_records: dict[str, Any] = {}
    relationship_requests = {**boundary_surface_requests, **overlap_surface_requests}
    relationship_artifacts = {**boundary_review_artifacts, **overlap_review_artifacts}
    relationship_candidate_ids = {**boundary_candidate_ids, **overlap_candidate_ids}
    if len(relationship_requests) != len(boundary_ids | overlap_ids):
        raise ValueError("cross-shard relationship review identities collide")
    for relationship_id in sorted(boundary_ids | overlap_ids):
        request = relationship_requests[relationship_id]
        artifact = relationship_artifacts[relationship_id]
        artifact.require_exact_requested_surface_manifest((request,))
        if len(artifact.records) != 1 or artifact.records[0].status.value not in {
            "CANDIDATE",
            "REVIEWED_NO_ISSUE",
        }:
            raise ValueError("cross-shard boundary review was not substantively completed")
        if not relationship_candidate_ids[relationship_id] <= set(candidate_ids):
            raise ValueError("cross-shard relationship review references an unknown candidate")
        if (artifact.records[0].status.value == "CANDIDATE") != bool(
            relationship_candidate_ids[relationship_id]
        ):
            raise ValueError(
                "cross-shard relationship disposition differs from its candidate output"
            )
        relationship_review_records[relationship_id] = artifact.records[0]
    relationships = _cross_shard_relationship_descriptors(inventory)
    decisions = []
    for relationship in relationships:
        boundary_paths = {relationship["source_path"], relationship["target_path"]}
        linked_ids = sorted(
            {
                candidate_id
                for candidate_id, paths in candidate_paths.items()
                if boundary_paths <= paths
            }
            | (relationship_candidate_ids[relationship["relationship_id"]])
        )
        relationship_id = relationship["relationship_id"]
        record = relationship_review_records[relationship_id]
        decision = {
            "relationship_id": relationship_id,
            "linked_candidate_ids": linked_ids,
            "status": record.status.value,
            "surface_id": record.surface_id,
            "review_artifact_sha256": relationship_artifacts[relationship_id].artifact_sha256,
        }
        decisions.append(decision)
    if inventory is None:
        status = "NOT_APPLICABLE_NO_SEMANTIC_INVENTORY"
    elif not relationships:
        status = "REVIEWED_NO_CROSS_SHARD_RELATIONSHIPS"
    else:
        status = "EVALUATED"
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "algorithm": "mmaudit.cross-shard-integration.v1",
        "status": status,
        "semantic_inventory_sha256": inventory.inventory_sha256 if inventory is not None else None,
        "candidate_ids": sorted(candidate_ids),
        "candidate_payload_sha256s": _candidate_payload_sha256s(candidates),
        "shard_ids": sorted(shard_ids),
        "semantic_relationship_ids": [
            relationship["relationship_id"] for relationship in relationships
        ],
        "boundary_review_artifact_sha256s": sorted(
            artifact.artifact_sha256 for artifact in relationship_artifacts.values()
        ),
        "invariant_review_present": invariant_review is not None,
        "high_critical_candidate_ids": sorted(
            candidate.candidate_id
            for candidate in candidates
            if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
        ),
        "validation_candidate_ids": sorted(
            candidate_id for candidate_id, validation in validations.items() if validation.valid
        ),
        "relationships": relationships,
        "decisions": decisions,
        "invariant_review_decision_ids": sorted(
            decision.invariant_id
            for decision in (invariant_review.decisions if invariant_review is not None else [])
        ),
    }
    return {**body, "integration_sha256": scheduler_canonical_sha256(body)}


def _validate_cross_shard_integration(
    integration: dict[str, Any],
    *,
    expected_candidate_ids: set[str],
    expected_relationship_ids: set[str],
) -> None:
    """Reject no-op metadata echoes as cross-shard integration evidence."""

    required = {
        "schema_version",
        "algorithm",
        "status",
        "semantic_inventory_sha256",
        "candidate_ids",
        "candidate_payload_sha256s",
        "shard_ids",
        "semantic_relationship_ids",
        "boundary_review_artifact_sha256s",
        "invariant_review_present",
        "high_critical_candidate_ids",
        "validation_candidate_ids",
        "relationships",
        "decisions",
        "invariant_review_decision_ids",
        "integration_sha256",
    }
    if set(integration) != required:
        raise ValueError("cross-shard integration output is not the exact typed projection")
    if integration["schema_version"] != "1.0" or integration["algorithm"] != (
        "mmaudit.cross-shard-integration.v1"
    ):
        raise ValueError("cross-shard integration output uses an unsupported contract")
    if integration["candidate_ids"] != sorted(expected_candidate_ids):
        raise ValueError("cross-shard integration output omits or adds candidates")
    payload_hashes = integration["candidate_payload_sha256s"]
    if (
        not isinstance(payload_hashes, dict)
        or set(payload_hashes) != expected_candidate_ids
        or any(
            not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None
            for value in payload_hashes.values()
        )
    ):
        raise ValueError("cross-shard integration lacks exact candidate payload hashes")
    relationships = integration["relationships"]
    decisions = integration["decisions"]
    if not isinstance(relationships, list) or not isinstance(decisions, list):
        raise ValueError("cross-shard integration output lacks relationship decisions")
    relationship_ids = [
        str(item["relationship_id"])
        for item in relationships
        if isinstance(item, dict) and isinstance(item.get("relationship_id"), str)
    ]
    decision_ids = [
        str(item["relationship_id"])
        for item in decisions
        if isinstance(item, dict) and isinstance(item.get("relationship_id"), str)
    ]
    if (
        sorted(relationship_ids) != sorted(expected_relationship_ids)
        or sorted(decision_ids) != sorted(expected_relationship_ids)
        or len(relationship_ids) != len(expected_relationship_ids)
        or len(decision_ids) != len(expected_relationship_ids)
    ):
        raise ValueError("cross-shard integration did not evaluate every exact relationship")
    if integration["semantic_relationship_ids"] != relationship_ids:
        raise ValueError("cross-shard integration relationship projection is inconsistent")
    expected_artifact_sha256s = sorted(
        str(item["review_artifact_sha256"])
        for item in decisions
        if isinstance(item, dict) and isinstance(item.get("review_artifact_sha256"), str)
    )
    if integration["boundary_review_artifact_sha256s"] != expected_artifact_sha256s:
        raise ValueError("cross-shard integration artifact projection is inconsistent")
    body = {key: value for key, value in integration.items() if key != "integration_sha256"}
    if integration["integration_sha256"] != scheduler_canonical_sha256(body):
        raise ValueError("cross-shard integration output hash is inconsistent")


def _require_exact_model_decision_inventory(
    *,
    expected_ids: set[str],
    observed_ids: list[str],
    label: str,
) -> None:
    """Fail closed when a scheduled model omits, duplicates, or adds a decision."""

    observed_set = set(observed_ids)
    missing = expected_ids - observed_set
    unknown = observed_set - expected_ids
    duplicate_count = len(observed_ids) - len(observed_set)
    if missing or unknown or duplicate_count:
        raise OpenRouterSchemaError(
            f"{label} returned an incomplete decision inventory "
            f"(missing={len(missing)}, unknown={len(unknown)}, "
            f"duplicates={duplicate_count})"
        )


class AuditPipeline:
    """Coordinates trusted scanners and constrained model roles."""

    def __init__(
        self,
        config: AuditConfig,
        *,
        repo: Path,
        output: Path,
        file_config: AuditConfig | None = None,
        environment_overrides: AuditConfigOverrides | None = None,
        cli_overrides: AuditConfigOverrides | None = None,
        scanner_runner: ScannerRunner | None = None,
        client: OpenRouterClient | None = None,
        cost_ledger: AtomicCostLedger | None = None,
        api_key: str | None = None,
        logger: logging.Logger | None = None,
        reproduction_runner: ForkReproductionRunner | None = None,
        invariant_runner: FoundryInvariantRunner | None = None,
        formal_runner: FormalRunner | None = None,
        production_qualification: VerifiedProductionQualification | None = None,
        privacy_consent_observation: PrivacyRetentionConsentObservation | None = None,
        privacy_source_classification: PrivacySourceClassification = (
            PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
        ),
        repository_fork_matrix_runner: RepositoryForkMatrixRunner | None = None,
    ) -> None:
        self.config = config.effective()
        self.file_config = file_config or self.config
        self.environment_overrides = environment_overrides or AuditConfigOverrides()
        self.cli_overrides = cli_overrides or AuditConfigOverrides()
        reconstructed = self.cli_overrides.apply(self.environment_overrides.apply(self.file_config))
        if canonical_audit_config_json(reconstructed) != canonical_audit_config_json(self.config):
            raise ValueError(
                "pipeline configuration does not match its recorded override provenance"
            )
        self.repo_input = safe_repository_root(repo)
        self.output = resolve_safe_output_root(output)
        self.client = client
        self.cost_ledger = cost_ledger
        self.api_key = api_key or ""
        self.production_qualification = production_qualification
        self.privacy_consent_observation = privacy_consent_observation
        self.privacy_source_classification = privacy_source_classification
        self.privacy_source_provenance_observation: PrivacySourceProvenanceObservation | None = None
        self.privacy_source_provenance: PrivacySourceProvenanceEvidence | None = None
        self.effective_privacy_policy: EffectivePrivacyPolicyEvidence | None = None
        self.privacy_authorization: TrustedPrivacyAuthorization | None = None
        self.privacy_source_sha256: str | None = None
        self.logger = logger or logging.getLogger("mmaudit.pipeline")
        self.reproduction_runner = reproduction_runner or ForkReproductionRunner(
            self.config.reproduction,
            self.config.smart_contracts,
        )
        self.scanner_runner = scanner_runner or ScannerRunner(
            self.config,
            backend=self.reproduction_runner.backend,
        )
        shared_backend = getattr(self.reproduction_runner, "backend", None)
        if invariant_runner is None:
            configured_invariant_runner = FoundryInvariantRunner(
                self.config.reproduction,
                self.config.smart_contracts,
                backend=shared_backend,
            )
            configured_invariant_runner.backend = shared_backend
            self.invariant_runner = configured_invariant_runner
        else:
            self.invariant_runner = invariant_runner
        if formal_runner is None:
            configured_formal_runner = FormalRunner(
                self.config.formal,
                backend=shared_backend,
            )
            configured_formal_runner.backend = shared_backend
            self.formal_runner = configured_formal_runner
        else:
            self.formal_runner = formal_runner
        self.repository_fork_matrix_runner = (
            RepositoryForkMatrixRunner(
                self.config.smart_contracts,
                self.config.reproduction,
                dependencies=ForkMatrixDependencies(
                    clean_state_provider=TrustedCleanAnvilLauncher(),
                ),
            )
            if repository_fork_matrix_runner is None
            else repository_fork_matrix_runner
        )
        self._owns_client = False
        self._active_scheduler: PipelineScheduler | None = None

    def clear_credentials(self) -> None:
        """Drop operator credentials retained by pipeline/provider objects."""

        self.api_key = ""
        if self.client is not None:
            self.client.clear_credentials()
        self.privacy_authorization = None
        self.privacy_consent_observation = None
        self.privacy_source_provenance_observation = None

    def _effective_cost_ledger(self) -> AtomicCostLedger | None:
        """Resolve one atomic-ledger authority and reject split custody."""

        client_ledger = self.client.budget.atomic_ledger if self.client is not None else None
        configured_ledger = self.cost_ledger
        if client_ledger is not None and configured_ledger is not None:
            if client_ledger.identity_sha256 != configured_ledger.identity_sha256:
                raise ValueError("pipeline and provider client use different cost ledgers")
            return client_ledger
        if self.client is not None:
            if configured_ledger is not None:
                raise ValueError("provider client does not use the configured cost ledger")
            return client_ledger
        return configured_ledger

    def _planned_model_execution_evidence(self) -> ExecutionEvidenceKind:
        """Return the fail-closed evidence class for the pending provider path."""

        if self.client is None:
            return ExecutionEvidenceKind.REAL
        return trusted_openrouter_execution_evidence(self.client)

    async def run(
        self,
        *,
        resume_run_dir: Path | None = None,
        scanner_only: bool = False,
        allow_code_egress: bool = False,
        skip_codeql: bool = False,
        changed_since: str | None = None,
        severity_threshold: Severity = Severity.INFORMATIONAL,
        fail_on: Severity | None = None,
        refresh_models: bool = False,
        allow_fork_probing: bool = False,
        require_maximum_assurance: bool | None = None,
        allow_maximum_assurance_downgrade: bool | None = None,
        benchmark_verification: BenchmarkCertificateVerification | None = None,
        benchmark_repository_git_commit: str | None = None,
        ci_mode: bool = False,
        ci_baseline: LoadedCIBaseline | None = None,
    ) -> PipelineResult:
        """Execute one audit and always clear provider credentials afterward."""

        try:
            return await self._run_with_provider(
                resume_run_dir=resume_run_dir,
                scanner_only=scanner_only,
                allow_code_egress=allow_code_egress,
                skip_codeql=skip_codeql,
                changed_since=changed_since,
                severity_threshold=severity_threshold,
                fail_on=fail_on,
                refresh_models=refresh_models,
                allow_fork_probing=allow_fork_probing,
                require_maximum_assurance=require_maximum_assurance,
                allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
                benchmark_verification=benchmark_verification,
                benchmark_repository_git_commit=benchmark_repository_git_commit,
                ci_mode=ci_mode,
                ci_baseline=ci_baseline,
            )
        finally:
            scheduler = self._active_scheduler
            if scheduler is not None:
                if self.client is not None:
                    with contextlib.suppress(OpenRouterError):
                        self.client.unbind_request_lifecycle_observer(scheduler)
                scheduler.close()
                self._active_scheduler = None
            self.api_key = ""
            if self.client is not None:
                if self._owns_client:
                    await self.client.close()
                else:
                    self.client.clear_credentials()
            self.privacy_authorization = None
            self.privacy_consent_observation = None
            self.privacy_source_provenance_observation = None

    async def _run_with_provider(
        self,
        *,
        resume_run_dir: Path | None = None,
        scanner_only: bool = False,
        allow_code_egress: bool = False,
        skip_codeql: bool = False,
        changed_since: str | None = None,
        severity_threshold: Severity = Severity.INFORMATIONAL,
        fail_on: Severity | None = None,
        refresh_models: bool = False,
        allow_fork_probing: bool = False,
        require_maximum_assurance: bool | None = None,
        allow_maximum_assurance_downgrade: bool | None = None,
        benchmark_verification: BenchmarkCertificateVerification | None = None,
        benchmark_repository_git_commit: str | None = None,
        ci_mode: bool = False,
        ci_baseline: LoadedCIBaseline | None = None,
    ) -> PipelineResult:
        # A pipeline object may be reused for a later scanner-only run.  Derived
        # privacy state is run-local and must never survive that boundary.
        self.privacy_source_provenance = None
        self.privacy_source_provenance_observation = None
        self.effective_privacy_policy = None
        self.privacy_authorization = None
        self.privacy_source_sha256 = None
        run_options = AuditRunOptions(
            scanner_only=scanner_only,
            allow_code_egress=allow_code_egress,
            skip_codeql=skip_codeql,
            changed_since=changed_since,
            severity_threshold=severity_threshold,
            fail_on=fail_on,
            refresh_models=refresh_models,
            allow_fork_probing=allow_fork_probing,
            require_maximum_assurance=require_maximum_assurance,
            allow_maximum_assurance_downgrade=allow_maximum_assurance_downgrade,
            benchmark_repository_git_commit=benchmark_repository_git_commit,
            privacy_source_classification=self.privacy_source_classification,
            retention_consent_file_sha256=(
                self.privacy_consent_observation.file_sha256
                if self.privacy_consent_observation is not None
                else None
            ),
        )
        resume_scheduler_journal = (
            _resolve_scheduler_resume_journal(self.output, resume_run_dir)
            if resume_run_dir is not None
            else None
        )
        if resume_scheduler_journal is not None and scanner_only:
            raise ValueError("scheduler resume is unavailable for scanner-only execution")
        if ci_mode and (
            not scanner_only
            or allow_code_egress
            or refresh_models
            or self.client is not None
            or self.cost_ledger is not None
            or self.api_key
        ):
            raise ValueError("CI mode is provider-free scanner-only execution")
        if ci_baseline is not None and not ci_mode:
            raise ValueError("CI baseline evidence is accepted only in CI mode")
        ci_producer_digest = ci_producer_sha256() if ci_mode else None
        ci_policy_digest = (
            deterministic_ci_policy_sha256(self.config, run_options) if ci_mode else None
        )
        if not scanner_only and self.client is not None and self.client.usage.records:
            raise ValueError("provider audits require a fresh empty client usage ledger")
        if not scanner_only and self.client is not None and self.client.context_preflight.records:
            raise ValueError("provider audits require a fresh empty context preflight ledger")
        planned_model_execution_evidence = self._planned_model_execution_evidence()
        if (
            not scanner_only
            and self.client is not None
            and planned_model_execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        ):
            raise ValueError("provider audits reject unverified injected clients")
        if (
            not scanner_only
            and self.client is not None
            and planned_model_execution_evidence is ExecutionEvidenceKind.REAL
            and (not self._owns_client or type(self.client) is not OpenRouterClient)
        ):
            raise ValueError("injected provider clients cannot establish REAL execution provenance")
        effective_cost_ledger = self._effective_cost_ledger()
        if not scanner_only and effective_cost_ledger is None:
            raise ValueError("provider audits require an explicit existing cumulative cost ledger")
        benchmark_required = (
            self.config.maximum_assurance.benchmark_gate or self.config.maximum_assurance.ci_mode
        )
        downgrade_allowed = (
            self.config.maximum_assurance.allow_downgrade
            if allow_maximum_assurance_downgrade is None
            else allow_maximum_assurance_downgrade
        )
        if (
            benchmark_required
            and (
                benchmark_verification is None
                or benchmark_repository_git_commit is None
                or (
                    benchmark_verification is not None
                    and benchmark_verification.observed_repository_git_commit
                    != benchmark_repository_git_commit
                )
                or benchmark_verification.status is not CertificateVerificationStatus.CURRENT
                or benchmark_verification.origin is not CertificateVerificationOrigin.FILE_BACKED
                or benchmark_verification.file_backed_evidence is None
                or (
                    self.config.profile is AuditProfile.MAXIMUM_ASSURANCE
                    and benchmark_verification.file_backed_evidence.benchmark_profile
                    is not AuditProfile.MAXIMUM_ASSURANCE
                )
            )
            and not downgrade_allowed
        ):
            raise ValueError("configured benchmark gate requires current certificate verification")
        run_started_at = datetime.now(UTC)
        run_started_monotonic = time.monotonic()
        time_to_first_candidate_seconds: float | None = None
        try:
            output_relative_to_repo = self.output.resolve().relative_to(
                self.repo_input.resolve(strict=True)
            )
        except ValueError:
            output_relative_to_repo = None
        if output_relative_to_repo is not None and not output_relative_to_repo.parts:
            raise ValueError("output directory cannot be the repository root")
        allow_custom_repository_exclusion = False
        if (
            output_relative_to_repo is not None
            and audited_workspace_exclusion_root(output_relative_to_repo) is None
            and not self.output.exists()
        ):
            self.output.mkdir(parents=True, exist_ok=False, mode=0o700)
            try:
                self.output.resolve(strict=True).relative_to(self.repo_input.resolve(strict=True))
            except (OSError, ValueError) as exc:
                raise ValueError(
                    "custom in-repository output escaped its audited repository"
                ) from exc
            allow_custom_repository_exclusion = True
        run_id, run_dir = self._create_run_dir()
        if benchmark_verification is not None:
            write_json(
                run_dir / "benchmark-certificate-verification.json",
                benchmark_verification,
            )
        log_handler = JsonLineHandler(run_dir / "logs" / "events.jsonl")
        log_handler.addFilter(RedactingFilter())
        if self.logger.level == logging.NOTSET:
            self.logger.setLevel(logging.INFO)
        self.logger.addHandler(log_handler)
        incomplete: list[str] = []
        terminal_code = ExitCode.SUCCESS
        budget_halted = False
        candidates: list[CandidateFinding] = []
        pass_four_candidates: list[CandidateFinding] = []
        pass_four_candidate_projection_frozen = False
        candidate_origin_packages: dict[str, ContextPackage] = {}
        pending_execution_candidates: list[CandidateFinding] = []
        execution_candidates_integrated = False
        formal_counterexamples_attached = False
        execution_candidate_build = ExecutionCandidateBuildResult(
            candidates=(),
            dispositions=(),
            rejected_counterexample_count=0,
            limitations=(),
        )
        verifications = VerificationBatch(decisions=[])
        decisions: dict[str, VerificationDecision] = {}
        cross_examinations: list[CandidateCrossExaminationDecision] = []
        final_findings: list[Finding] = []
        rejected_findings: list[Finding] = []
        filtered_findings: list[Finding] = []
        post_judge_execution_severity_candidates: dict[str, CandidateFinding] = {}
        scanner_runs = []
        threat_model: ThreatModel | None = None
        threat_location_rejections: list[str] = []
        context_withheld_files = 0
        solidity_projects: list[SolidityProjectMetadata] = []
        scope_assessment: AuditScopeAssessment | None = None
        prior_audit_comparison: PriorAuditComparison | None = None
        prior_material_withheld_from_discovery = False
        solidity_compilations: list[SolidityCompilationResult] = []
        dependency_preparation = DependencyPreparationRun(
            results=[],
            sboms=[],
            prepared_roots={},
        )
        solidity_index: SoliditySymbolIndex | None = None
        solidity_graphs: SolidityGraphSet | None = None
        solidity_shards: SolidityShardInventory | None = None
        solidity_shard_binding: SolidityShardReportBinding | None = None
        solidity_invariants: InvariantSuite | None = None
        invariant_review_batch: InvariantReviewBatch | None = None
        invariant_review: InvariantReviewResult | None = None
        invariant_executions: list[InvariantExecutionResult] = []
        invariant_harnesses: list[FoundryInvariantHarnessSpec] = []
        invariant_harness_limitations: list[str] = []
        property_corpus: PropertyCorpus = build_property_corpus(None, None, [])
        economic_simulations: list[EconomicSimulationPlan] = []
        formal_runs: list[FormalToolRun] = []
        solidity_coverage: SolidityCoverage | None = None
        repository_suite_differential: RepositorySuiteDifferentialRun | None = None
        model_review_coverage: ModelReviewCoverage | None = None
        provider_session: ProviderSessionProvenance | None = None
        model_surface_review_artifacts: list[ModelSurfaceReviewArtifact] = []
        model_surface_review_contexts: dict[str, list[ContextPackage]] = {}
        model_surface_review_assignments: dict[str, list[ModelSurfaceReviewRequest]] = {}
        generated_tests: list[GeneratedFoundryTestSpec] = []
        reproductions: list[ReproductionResult] = []
        reproduction_resolutions: list[CandidateReproductionResolution] = []
        falsifications = FalsificationBatch(decisions=[])
        eligible_for_reproduction: list[CandidateFinding] = []
        quality_gates: list[QualityGateResult] = []
        maximum_assurance: MaximumAssuranceAssessment | None = None
        report_quality_review: ReportQualityReview | None = None
        scheduler_artifact: SchedulerArtifact | None = None
        scheduler_analysis_input_sha256: str | None = None
        scheduler_bindings: SchedulerBindings | None = None
        scheduler_cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None
        scheduler_privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None
        scheduler_inventory: SchedulerShardInventory | None = None
        scheduler_report_binding: dict[str, Any] | None = None
        scheduler_halted = False
        candidate_groups_count = 0
        validations: dict[str, LocationValidation] = {}
        discovery: DiscoveryResult
        repository_execution_sha256: str | None = None
        repository_execution_exclusion_root: Path | None = None
        scanner_source_exclusion_root = (
            self.output.resolve(strict=True)
            if output_relative_to_repo is not None
            else self.repo_input.resolve(strict=True) / ".mmaudit"
        )
        scanner_source_sha256: str | None = None
        assurance_contract = MaximumAssuranceContract(
            self.config,
            require=require_maximum_assurance,
            allow_downgrade=allow_maximum_assurance_downgrade,
        )
        isolation_available = bool(
            getattr(self.reproduction_runner, "isolation_available", False)
            and getattr(self.invariant_runner, "isolation_available", False)
            and getattr(self.formal_runner, "isolation_available", False)
        )
        preflight_requirements = assurance_contract.configuration_requirements(
            isolation_available=isolation_available,
            scanner_only=scanner_only,
        )
        preflight_blocked = (
            any(
                requirement.required and not requirement.passed
                for requirement in preflight_requirements
            )
            and not assurance_contract.allow_downgrade
        )
        if preflight_blocked:
            incomplete.extend(
                f"maximum-assurance preflight failed: {requirement.engine}: {requirement.detail}"
                for requirement in preflight_requirements
                if requirement.required and not requirement.passed
            )
            terminal_code = ExitCode.CONFIGURATION

        ignore_path = safe_ignore_file(
            self.repo_input,
            self.config.repository.ignore_file,
        )
        matcher = IgnoreMatcher.from_file(ignore_path)
        if output_relative_to_repo is not None:
            matcher.rules.append("/" + output_relative_to_repo.as_posix().rstrip("/") + "/")
        if self.config.prior_audit.path is not None:
            matcher.rules.append("/" + normalize_relative_path(self.config.prior_audit.path))
        if self.config.dependency_preparation.offline_snapshot_path is not None:
            snapshot_parent = PurePosixPath(
                normalize_relative_path(self.config.dependency_preparation.offline_snapshot_path)
            ).parent
            matcher.rules.append("/" + snapshot_parent.as_posix().rstrip("/") + "/")
        repository_suite_identity_required = bool(
            self.config.scanners.foundry_fork.enabled
            and self.config.smart_contracts.enabled
            and self.config.smart_contracts.repository_suite.foundry_include_paths
            and self.config.smart_contracts.repository_suite.foundry_include_tests
        )
        if repository_suite_identity_required:
            repository_execution_exclusion_root = scanner_source_exclusion_root
            try:
                repository_execution_sha256 = scanner_workspace_sha256(
                    self.repo_input,
                    repository_execution_exclusion_root,
                    allow_custom_private_exclusion=allow_custom_repository_exclusion,
                )
            except (OSError, ValueError) as exc:
                incomplete.append(
                    "repository execution source identity could not be frozen before discovery: "
                    f"{type(exc).__name__}"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
        unfiltered_discovery = discover_repository(
            self.repo_input,
            self.config.repository,
            matcher,
            changed_since=changed_since,
        )
        if repository_execution_sha256 is not None:
            try:
                post_discovery_repository_sha256 = scanner_workspace_sha256(
                    self.repo_input,
                    repository_execution_exclusion_root,
                    allow_custom_private_exclusion=allow_custom_repository_exclusion,
                )
            except (OSError, ValueError) as exc:
                incomplete.append(
                    "repository execution source identity could not be revalidated after "
                    f"discovery: {type(exc).__name__}"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            else:
                if post_discovery_repository_sha256 != repository_execution_sha256:
                    incomplete.append("repository execution source changed during discovery")
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
        (
            unfiltered_discovery,
            prior_material_withheld_from_discovery,
        ) = withhold_prior_audit_from_discovery(
            unfiltered_discovery,
            self.config.prior_audit.path,
        )
        scope_projects = discover_solidity_projects(
            unfiltered_discovery,
            self.config.smart_contracts,
        )
        discovery = filter_discovery_for_scope(
            unfiltered_discovery,
            scope_projects,
            self.config.scope.mode,
        )
        solidity_source_contents_by_path = {
            item.relative_path: item.content
            for item in discovery.files
            if item.language == "Solidity"
        }
        audited_scanner_paths = tuple(item.relative_path for item in discovery.files)
        scanner_source_inventory_valid = True
        try:
            scanner_source_sha256 = scanner_workspace_sha256(
                discovery.root,
                scanner_source_exclusion_root,
                audited_relative_paths=audited_scanner_paths,
                allow_custom_private_exclusion=allow_custom_repository_exclusion,
            )
            if (
                repository_execution_sha256 is not None
                and scanner_source_sha256 != repository_execution_sha256
            ):
                raise ValueError(
                    "audited scanner source inventory differs from the frozen repository identity"
                )
        except (OSError, ValueError) as exc:
            scanner_source_inventory_valid = False
            incomplete.append(
                "audited source inventory is incompatible with scanner execution workspaces: "
                f"{type(exc).__name__}"
            )
            if terminal_code is ExitCode.SUCCESS:
                terminal_code = ExitCode.INCOMPLETE
        repository_map = build_repository_map(discovery, changed_since=changed_since)
        write_json(run_dir / "repository-map.json", repository_map)
        self.privacy_source_sha256 = _repository_source_scope_sha256(repository_map)
        if not scanner_only:
            configured_privacy_models = tuple(
                sorted(set(configured_model_ids(self.config, include_fallbacks=True)))
            )
            configured_privacy_endpoints = tuple(
                sorted(
                    set(self.config.models.provider_policy.only)
                    | set(self.config.models.provider_policy.order)
                )
            )
            privacy_now = datetime.now(UTC).replace(microsecond=0)
            try:
                self.privacy_source_provenance_observation = prove_privacy_source_classification(
                    discovery,
                    requested_classification=self.privacy_source_classification,
                    source_sha256=self.privacy_source_sha256,
                    now=privacy_now,
                )
                self.privacy_source_provenance = validate_privacy_source_provenance_observation(
                    self.privacy_source_provenance_observation,
                    source_sha256=self.privacy_source_sha256,
                    source_classification=self.privacy_source_classification,
                )
                write_json(
                    run_dir / "privacy-source-provenance.json",
                    self.privacy_source_provenance,
                )
                if self.config.privacy.require_zdr:
                    self.effective_privacy_policy = resolve_effective_privacy_policy(
                        profile=self.config.privacy.profile,
                        require_zdr=True,
                        consent_observation=self.privacy_consent_observation,
                        source_sha256=self.privacy_source_sha256,
                        source_classification=self.privacy_source_classification,
                        source_provenance_observation=(self.privacy_source_provenance_observation),
                        configured_model_ids=configured_privacy_models,
                        configured_provider_endpoints=configured_privacy_endpoints,
                        requested_budget_usd=Decimal(str(self.config.execution.budget_usd)),
                        now=privacy_now,
                    )
                else:
                    self.privacy_authorization = resolve_trusted_privacy_authorization(
                        profile=self.config.privacy.profile,
                        require_zdr=False,
                        consent_observation=self.privacy_consent_observation,
                        source_sha256=self.privacy_source_sha256,
                        source_classification=self.privacy_source_classification,
                        source_provenance_observation=(self.privacy_source_provenance_observation),
                        configured_model_ids=configured_privacy_models,
                        configured_provider_endpoints=configured_privacy_endpoints,
                        requested_budget_usd=Decimal(str(self.config.execution.budget_usd)),
                        now=privacy_now,
                    )
                    self.effective_privacy_policy = validate_trusted_privacy_authorization(
                        self.privacy_authorization,
                        evidence_sha256=self.privacy_authorization.evidence.evidence_sha256,
                        source_sha256=self.privacy_source_sha256,
                        source_classification=self.privacy_source_classification,
                        source_provenance_sha256=(self.privacy_source_provenance.evidence_sha256),
                        configured_model_ids=configured_privacy_models,
                        configured_provider_endpoints=configured_privacy_endpoints,
                        requested_budget_usd=Decimal(str(self.config.execution.budget_usd)),
                        now=privacy_now,
                    )
                if resume_scheduler_journal is not None:
                    if not self.config.privacy.require_zdr:
                        raise OpenRouterPrivacyError(
                            "scheduler resume requires ZDR-bound retained privacy evidence"
                        )
                    if (
                        self.privacy_source_provenance is None
                        or self.effective_privacy_policy is None
                    ):
                        raise OpenRouterPrivacyError(
                            "scheduler resume lacks current privacy evidence"
                        )
                    (
                        self.privacy_source_provenance,
                        self.effective_privacy_policy,
                    ) = _load_exact_resume_privacy_evidence(
                        resume_scheduler_journal,
                        current_provenance=self.privacy_source_provenance,
                        current_policy=self.effective_privacy_policy,
                    )
                    write_json(
                        run_dir / "privacy-source-provenance.json",
                        self.privacy_source_provenance,
                    )
                if (
                    self.client is not None
                    and self.effective_privacy_policy is not None
                    and self.client.effective_privacy_policy is None
                ):
                    self.client.bind_effective_privacy_context(
                        effective_privacy_policy=self.effective_privacy_policy,
                        privacy_authorization=self.privacy_authorization,
                    )
                elif (
                    self.client is not None
                    and self.client.effective_privacy_policy != self.effective_privacy_policy
                ):
                    raise OpenRouterPrivacyError(
                        "injected provider client binds different effective privacy evidence"
                    )
                write_json(
                    run_dir / "privacy-policy.json",
                    self.effective_privacy_policy,
                )
                if self.privacy_source_provenance is None or self.effective_privacy_policy is None:
                    raise OpenRouterPrivacyError(
                        "scheduler privacy custody lacks complete typed evidence"
                    )
                scheduler_privacy_evidence_custody = _build_scheduler_privacy_evidence_custody(
                    run_dir,
                    provenance=self.privacy_source_provenance,
                    policy=self.effective_privacy_policy,
                )
            except (ValueError, OpenRouterPrivacyError) as exc:
                incomplete.append(f"privacy authorization failed: {exc}")
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.PRIVACY_REFUSAL
                if self.effective_privacy_policy is not None:
                    write_json(
                        run_dir / "privacy-policy.json",
                        self.effective_privacy_policy,
                    )

        try:
            solidity_projects = discover_solidity_projects(
                discovery,
                self.config.smart_contracts,
            )
            dependency_preparation = prepare_dependencies(
                discovery.root,
                solidity_projects,
                self.config.dependency_preparation,
                run_dir / "private" / "dependency-preparation",
            )
            dependency_failures = [
                result
                for result in dependency_preparation.results
                if result.status
                in {
                    DependencyPreparationStatus.REJECTED,
                    DependencyPreparationStatus.FAILED,
                }
            ]
            if self.config.dependency_preparation.required and dependency_failures:
                incomplete.extend(
                    "required dependency preparation failed: "
                    f"{result.project_root}: {result.status.value}"
                    for result in dependency_failures
                )
                terminal_code = ExitCode.INCOMPLETE
            compilation_config = (
                self.config.smart_contracts.model_copy(update={"compile": False})
                if preflight_blocked
                else self.config.smart_contracts
            )
            dependency_arguments: dict[str, Any] = {}
            if self.config.dependency_preparation.enabled:
                snapshot_path = self.config.dependency_preparation.offline_snapshot_path
                assert snapshot_path is not None
                snapshot_parent_relative = PurePosixPath(
                    normalize_relative_path(snapshot_path)
                ).parent.as_posix()
                dependency_arguments = {
                    "prepared_dependencies": dependency_preparation.prepared_roots,
                    "require_prepared_dependencies": True,
                    "excluded_repository_paths": (snapshot_parent_relative,),
                }
            compilation_run = compile_solidity_projects(
                discovery.root,
                solidity_projects,
                compilation_config,
                run_dir / "private" / "solidity-compile",
                backend=getattr(self.reproduction_runner, "backend", None),
                **dependency_arguments,
            )
            solidity_compilations = compilation_run.results
            index_build = build_solidity_index(
                discovery,
                solidity_projects,
                compilation_run.artifact_roots,
            )
            solidity_index = index_build.index
            solidity_graphs = build_solidity_graphs(discovery, index_build)
            if any(item.language == "Solidity" for item in discovery.files):
                shard_policy = SolidityShardPolicy.build()
                solidity_shards = build_solidity_shard_inventory(
                    discovery,
                    solidity_index,
                    solidity_graphs,
                    policy=shard_policy,
                )
                solidity_shard_binding = SolidityShardReportBinding.from_inventory(solidity_shards)
                verify_solidity_shard_inventory(
                    discovery=discovery,
                    index=solidity_index,
                    graphs=solidity_graphs,
                    inventory=solidity_shards,
                    expected_policy=shard_policy,
                    report_binding=solidity_shard_binding,
                )
            solidity_invariants = discover_invariants(
                discovery,
                solidity_index,
                solidity_graphs,
                self.config.invariants,
            )
            economic_simulations = plan_economic_simulations(
                solidity_invariants,
                solidity_graphs,
            )
            invariant_harnesses = list(self.config.invariants.harnesses)
            if self.config.invariants.generate_foundry_templates:
                generated = generate_invariant_harnesses(
                    solidity_invariants,
                    solidity_index,
                    targets=self.config.reproduction.targets,
                    economic_plans=economic_simulations,
                    runs=self.config.smart_contracts.foundry_invariant_runs,
                    depth=64,
                    local_deployments=self.config.invariants.local_deployments,
                )
                invariant_harness_limitations = generated.limitations
                configured_keys = {
                    (harness.invariant_id, harness.name) for harness in invariant_harnesses
                }
                invariant_harnesses.extend(
                    harness
                    for harness in generated.harnesses
                    if (harness.invariant_id, harness.name) not in configured_keys
                )
            executable_ids = {harness.invariant_id for harness in invariant_harnesses}
            solidity_invariants = solidity_invariants.model_copy(
                update={
                    "invariants": [
                        invariant.model_copy(update={"executable": invariant.id in executable_ids})
                        for invariant in solidity_invariants.invariants
                    ],
                    "executable_count": len(executable_ids),
                    "warnings": [
                        *solidity_invariants.warnings,
                        *invariant_harness_limitations[:100],
                    ],
                }
            )
            property_corpus = build_property_corpus(
                solidity_invariants,
                solidity_index,
                invariant_harnesses,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            incomplete.append(
                f"Solidity deterministic analysis failed safely: {type(exc).__name__}"
            )
            if terminal_code is ExitCode.SUCCESS:
                terminal_code = ExitCode.INCOMPLETE
            solidity_compilations = [
                result
                for result in solidity_compilations
                if result.status is not CompilationStatus.SUCCESS
            ]
        scope_assessment = assess_audit_scope(
            discovery,
            solidity_projects,
            self.config.scope,
            include_docs=self.config.repository.include_docs,
            include_tests=self.config.repository.include_tests,
        )
        write_json(
            run_dir / "scope-assessment.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "assessment": scope_assessment.model_dump(mode="json"),
            },
        )
        scope_preflight_gate = scope_quality_gate(scope_assessment)
        if (
            scope_preflight_gate.required
            and not scope_preflight_gate.passed
            and terminal_code is ExitCode.SUCCESS
        ):
            if (
                self.config.profile is AuditProfile.MAXIMUM_ASSURANCE
                and assurance_contract.allow_downgrade
            ):
                incomplete.append(
                    "maximum-assurance preflight downgrade: "
                    f"{scope_preflight_gate.gate}: {scope_preflight_gate.detail}"
                )
            else:
                incomplete.append(
                    "quality gate failed before provider spend: "
                    f"{scope_preflight_gate.gate}: {scope_preflight_gate.detail}"
                )
                terminal_code = ExitCode.INCOMPLETE
        if (
            self.config.formal.enabled
            and not preflight_blocked
            and solidity_index is not None
            and solidity_invariants is not None
        ):
            try:
                formal_runs = await asyncio.to_thread(
                    self.formal_runner.run,
                    repository_root=discovery.root,
                    projects=solidity_projects,
                    index=solidity_index,
                    invariants=solidity_invariants,
                    private_dir=run_dir / "private" / "formal",
                    property_corpus=property_corpus,
                )
            except (OSError, ValueError, RuntimeError) as exc:
                incomplete.append(f"formal adapter layer failed safely: {type(exc).__name__}")
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
        write_json(
            run_dir / "dependency-preparation.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "enabled": self.config.dependency_preparation.enabled,
                "required": self.config.dependency_preparation.required,
                "results": [
                    result.model_dump(mode="json") for result in dependency_preparation.results
                ],
            },
        )
        write_json(
            run_dir / "dependency-sbom.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "documents": [
                    sbom.model_dump(mode="json", by_alias=True)
                    for sbom in dependency_preparation.sboms
                ],
            },
        )
        write_json(
            run_dir / "solidity-projects.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "projects": [project.model_dump(mode="json") for project in solidity_projects],
            },
        )
        write_json(
            run_dir / "solidity-compilation.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "results": [result.model_dump(mode="json") for result in solidity_compilations],
            },
        )
        write_json(
            run_dir / "solidity-index.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "index": solidity_index.model_dump(mode="json") if solidity_index else None,
            },
        )
        write_json(
            run_dir / "solidity-graphs.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "graphs": solidity_graphs.model_dump(mode="json") if solidity_graphs else None,
            },
        )
        write_json(
            run_dir / "solidity-shards.json",
            SolidityShardsArtifact(inventory=solidity_shards),
        )
        write_json(
            run_dir / "solidity-invariants.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "invariants": (
                    solidity_invariants.model_dump(mode="json") if solidity_invariants else None
                ),
            },
        )
        write_json(
            run_dir / "economic-simulation-plan.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "templates": [plan.model_dump(mode="json") for plan in economic_simulations],
            },
        )
        write_json(
            run_dir / "invariant-harness-plan.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "harnesses": [harness.model_dump(mode="json") for harness in invariant_harnesses],
                "limitations": invariant_harness_limitations,
            },
        )
        write_json(
            run_dir / "property-corpus.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "corpus": property_corpus.model_dump(mode="json"),
            },
        )
        self.logger.info("Running deterministic scanners", extra={"run_id": run_id})
        if not preflight_blocked and scanner_source_inventory_valid:
            assert scanner_source_sha256 is not None
            try:
                scanner_runs = await self.scanner_runner.run_all(
                    discovery.root,
                    run_dir / "private" / "scanner-output",
                    audited_relative_paths=audited_scanner_paths,
                    skip_codeql=skip_codeql,
                    allow_fork_probing=allow_fork_probing,
                    projects=solidity_projects,
                    expected_repository_sha256=scanner_source_sha256,
                    repository_exclusion_root=scanner_source_exclusion_root,
                    allow_custom_repository_exclusion=allow_custom_repository_exclusion,
                )
            except ScannerSourceIntegrityError:
                scanner_source_inventory_valid = False
                incomplete.append(
                    "audited source identity could not be preserved through scanner execution"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
        if (
            scanner_source_inventory_valid
            and self.config.smart_contracts.repository_suite.fork_matrix_states
        ):
            repository_suite_differential = await self._execute_repository_fork_matrix(
                repository_root=discovery.root,
                private_root=run_dir / "private" / "repository-fork-matrix",
                projects=solidity_projects,
                repository_sha256=repository_execution_sha256,
                repository_exclusion_root=repository_execution_exclusion_root,
                scanner_runs=scanner_runs,
            )
            if repository_suite_differential.status is not RepositoryDifferentialRunStatus.COMPLETE:
                detail = (
                    "configured repository suite differential did not complete: "
                    f"{repository_suite_differential.status.value}"
                )
                if repository_suite_differential.limitations:
                    detail += f": {repository_suite_differential.limitations[0]}"
                incomplete.append(detail)
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
        if scanner_source_sha256 is not None:
            try:
                post_scanner_repository_sha256 = scanner_workspace_sha256(
                    discovery.root,
                    scanner_source_exclusion_root,
                    audited_relative_paths=audited_scanner_paths,
                    allow_custom_private_exclusion=allow_custom_repository_exclusion,
                )
            except (OSError, ValueError) as exc:
                incomplete.append(
                    "audited source identity could not be revalidated after "
                    f"scanner execution: {type(exc).__name__}"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            else:
                if post_scanner_repository_sha256 != scanner_source_sha256:
                    incomplete.append(
                        "audited source changed during scanner execution or "
                        "repository differential execution"
                    )
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
        scanner_runs = [_annotate_scanner_locations(discovery.root, run) for run in scanner_runs]
        all_scanner_findings = [finding for run in scanner_runs for finding in run.findings]
        allowed_scanner_paths = {discovered.relative_path for discovered in discovery.files}
        scanner_findings = _scanner_findings_for_context(
            discovery.root,
            all_scanner_findings,
            allowed_scanner_paths,
        )
        write_json(
            run_dir / "scanner-results.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "runs": [run.model_dump(mode="json") for run in scanner_runs],
            },
        )
        required_scanner_failures = (
            [] if preflight_blocked else self.scanner_runner.required_failures(scanner_runs)
        )
        if required_scanner_failures:
            incomplete.extend(required_scanner_failures)
            terminal_code = ExitCode.SCANNER_FAILURE
        solidity_coverage = build_solidity_coverage(
            discovery=discovery,
            projects=solidity_projects,
            compilations=solidity_compilations,
            index=solidity_index,
            graphs=solidity_graphs,
            scanner_runs=scanner_runs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            formal_runs=formal_runs,
            expected_repository_sha256=repository_execution_sha256,
        )
        write_json(
            run_dir / "solidity-coverage.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "coverage": solidity_coverage.model_dump(mode="json"),
            },
        )

        fork_acknowledged = self.config.smart_contracts.allow_fork_probing or allow_fork_probing
        invariant_executions = await self._execute_invariant_harnesses(
            discovery=discovery,
            projects=solidity_projects,
            index=solidity_index,
            suite=solidity_invariants,
            economic_simulations=economic_simulations,
            harnesses=invariant_harnesses,
            run_dir=run_dir,
            fork_acknowledged=fork_acknowledged,
        )
        write_json(
            run_dir / "invariant-execution-results.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "harnesses": [harness.model_dump(mode="json") for harness in invariant_harnesses],
                "results": [result.model_dump(mode="json") for result in invariant_executions],
            },
        )
        execution_candidate_build = build_invariant_execution_candidates(
            repository_root=discovery.root,
            invariant_suite=solidity_invariants,
            harnesses=invariant_harnesses,
            property_corpus=property_corpus,
            executions=invariant_executions,
        )
        pending_execution_candidates = list(execution_candidate_build.candidates)
        if pending_execution_candidates and time_to_first_candidate_seconds is None:
            time_to_first_candidate_seconds = time.monotonic() - run_started_monotonic
        if execution_candidate_build.rejected_counterexample_count:
            incomplete.extend(
                f"execution-origin evidence rejected: {limitation}"
                for limitation in execution_candidate_build.limitations
            )
            if terminal_code is ExitCode.SUCCESS:
                terminal_code = ExitCode.INCOMPLETE
        if invariant_executions:
            solidity_coverage = build_solidity_coverage(
                discovery=discovery,
                projects=solidity_projects,
                compilations=solidity_compilations,
                index=solidity_index,
                graphs=solidity_graphs,
                scanner_runs=scanner_runs,
                invariants=solidity_invariants,
                invariant_executions=invariant_executions,
                economic_simulations=economic_simulations,
                formal_runs=formal_runs,
                expected_repository_sha256=repository_execution_sha256,
            )
            write_json(
                run_dir / "solidity-coverage.json",
                {
                    "schema_version": REPORT_SCHEMA_VERSION,
                    "coverage": solidity_coverage.model_dump(mode="json"),
                },
            )
        if (
            solidity_projects
            and not scanner_only
            and self.config.reproduction.required_for_solidity
            and not fork_acknowledged
            and terminal_code is ExitCode.SUCCESS
        ):
            incomplete.append(
                "Solidity audits require candidate-specific local fork reproduction; "
                "pass --allow-fork after configuring a loopback fork RPC"
            )
            terminal_code = ExitCode.PRIVACY_REFUSAL

        if not scanner_only and terminal_code is ExitCode.SUCCESS:
            egress_enabled = self.config.privacy.allow_code_egress or allow_code_egress
            if not egress_enabled:
                incomplete.append(
                    "source-code egress was not acknowledged; set privacy.allow_code_egress "
                    "or pass --allow-code-egress"
                )
                terminal_code = ExitCode.PRIVACY_REFUSAL
            else:
                model_errors = validate_model_independence(self.config)
                if model_errors:
                    incomplete.extend(model_errors)
                    terminal_code = ExitCode.CONFIGURATION
                elif not self.api_key and self.client is None:
                    incomplete.append("operator OpenRouter credential is unavailable")
                    terminal_code = ExitCode.MODEL_FAILURE

        if scanner_only:
            scanner_report_findings = _scanner_findings_for_report(
                discovery.root,
                all_scanner_findings,
            )
            for finding in scanner_report_findings:
                if finding.status is FindingStatus.REJECTED:
                    rejected_findings.append(finding)
                elif (
                    SEVERITY_ORDER[finding.severity.value]
                    >= SEVERITY_ORDER[severity_threshold.value]
                ):
                    final_findings.append(finding)
                else:
                    filtered_findings.append(finding)
        model_qualification_required = production_model_qualification_required(
            self.config,
            execution_evidence=self._planned_model_execution_evidence(),
        )
        qualification_preflight: ProductionQualificationValidation | None = None
        if not scanner_only:
            qualification_preflight = self._write_model_qualification_runtime(
                run_dir,
                required=model_qualification_required,
            )
            if qualification_preflight.required and not qualification_preflight.valid:
                incomplete.append("; ".join(qualification_preflight.errors))
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.MODEL_FAILURE
        usage = (
            UsageLedger()
            if scanner_only
            else (self.client.usage if self.client is not None else UsageLedger())
        )
        budget = (
            self.client.budget
            if self.client is not None and not scanner_only
            else BudgetManager(
                total_usd=self.config.execution.budget_usd,
                max_output_tokens=self.config.execution.max_output_tokens_per_request,
                conservative_usd_per_million_tokens=(
                    self.config.execution.conservative_usd_per_million_tokens
                ),
                max_requests_per_agent=self.config.execution.max_requests_per_agent,
                atomic_ledger=None if scanner_only else effective_cost_ledger,
                require_endpoint_cost_bound=not scanner_only,
                global_input_token_budget=(
                    None if scanner_only else self.config.token_budgets.global_input_token_budget
                ),
                global_output_token_budget=(
                    None if scanner_only else self.config.token_budgets.global_output_token_budget
                ),
                per_model_usd_caps={
                    model: str(cap)
                    for model, cap in self.config.token_budgets.per_model_cost_budget_usd.items()
                },
                per_role_usd_caps={
                    role: str(cap)
                    for role, cap in self.config.token_budgets.per_role_cost_budget_usd.items()
                },
            )
        )
        model_surface_requests = build_model_surface_requests(
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        minimum_critical_surface_lineages = (
            3 if self.config.profile is AuditProfile.MAXIMUM_ASSURANCE else 1
        )
        model_surface_review_assignments = plan_model_surface_review_assignments(
            self.config,
            model_surface_requests,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            minimum_critical_root_lineages=minimum_critical_surface_lineages,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        model_surface_assignment_gate = model_surface_assignment_feasibility_gate(
            self.config,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            requests=model_surface_requests,
            assignments=model_surface_review_assignments,
            required=bool(solidity_projects) and not scanner_only,
            minimum_critical_root_lineages=minimum_critical_surface_lineages,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        lower_profile_surface_gate = model_surface_assignment_feasibility_gate(
            self.config,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            requests=model_surface_requests,
            assignments=model_surface_review_assignments,
            required=bool(solidity_projects) and not scanner_only,
            minimum_critical_root_lineages=1,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        surface_downgrade_authorized = (
            self.config.profile is AuditProfile.MAXIMUM_ASSURANCE
            and assurance_contract.allow_downgrade
            and lower_profile_surface_gate.passed
        )
        model_spend_preflight_blocked = (
            model_surface_assignment_gate.required
            and not model_surface_assignment_gate.passed
            and not surface_downgrade_authorized
        )
        if model_surface_assignment_gate.required and not model_surface_assignment_gate.passed:
            if surface_downgrade_authorized:
                incomplete.append(
                    "maximum-assurance preflight downgrade: "
                    f"{model_surface_assignment_gate.gate}: "
                    f"{model_surface_assignment_gate.detail}"
                )
            else:
                incomplete.append(
                    "quality gate failed before provider spend: "
                    f"{model_surface_assignment_gate.gate}: "
                    f"{model_surface_assignment_gate.detail}"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE

        context_builder: ContextBuilder | None = None
        if (
            not scanner_only
            and terminal_code is ExitCode.SUCCESS
            and not model_spend_preflight_blocked
        ):
            if self.client is None:
                controls = build_openrouter_runtime_controls(
                    self.config,
                    certification=model_qualification_required,
                    require_single_model_per_role=model_qualification_required,
                    effective_privacy_policy=self.effective_privacy_policy,
                    privacy_authorization=self.privacy_authorization,
                )
                self.client = OpenRouterClient(
                    api_key=self.api_key or "",
                    execution=self.config.execution,
                    privacy=self.config.privacy,
                    budget=budget,
                    usage=usage,
                    run_dir=run_dir / "private",
                    logger=self.logger,
                    provider_policy=controls.provider_policy,
                    reasoning_policy=controls.reasoning_policy,
                    qualification_routing=_openrouter_qualification_routing(
                        self.production_qualification
                    ),
                    production_qualification=self.production_qualification,
                    token_budgets=self.config.token_budgets,
                    effective_privacy_policy=self.effective_privacy_policy,
                    privacy_authorization=self.privacy_authorization,
                )
                self._owns_client = True
                self.api_key = ""
            try:
                if resume_scheduler_journal is None:
                    await self._validate_models(
                        run_dir,
                        refresh=refresh_models,
                        source_egress_requested=True,
                        qualification_preflight=qualification_preflight,
                    )
                context_builder = ContextBuilder(
                    discovery=discovery,
                    repository_map=repository_map,
                    repository_config=self.config.repository,
                    privacy=self.config.privacy,
                    scanner_findings=scanner_findings,
                    scanner_secret_paths=_scanner_secret_paths(
                        all_scanner_findings,
                        allowed_scanner_paths,
                    ),
                    solidity_projects=solidity_projects,
                    solidity_compilations=solidity_compilations,
                    solidity_index=solidity_index,
                    solidity_graphs=solidity_graphs,
                    solidity_invariants=solidity_invariants,
                    invariant_executions=invariant_executions,
                    economic_simulations=economic_simulations,
                    formal_runs=formal_runs,
                    solidity_coverage=solidity_coverage,
                    maximum_source_tokens_per_request=(
                        self.config.token_budgets.maximum_source_tokens_per_request
                    ),
                )
                context_withheld_files = len(repository_map.files) - len(
                    context_builder.repository_map.files
                )
                scheduler_inventory = build_scheduler_shard_inventory(
                    repository_map,
                    solidity_shards,
                )
                scheduler_analysis_input = build_scheduler_analysis_input_inventory(
                    run_options=run_options,
                    discovery=discovery,
                    repository_map=repository_map,
                    repository_execution_sha256=repository_execution_sha256,
                    scanner_source_sha256=scanner_source_sha256,
                    dependency_preparation=dependency_preparation,
                    scope_assessment=scope_assessment,
                    projects=solidity_projects,
                    compilations=solidity_compilations,
                    index=solidity_index,
                    graphs=solidity_graphs,
                    semantic_shards=solidity_shards,
                    invariants=solidity_invariants,
                    invariant_harnesses=invariant_harnesses,
                    invariant_executions=invariant_executions,
                    property_corpus=property_corpus,
                    economic_simulations=economic_simulations,
                    formal_runs=formal_runs,
                    scanner_runs=scanner_runs,
                    repository_suite_differential=repository_suite_differential,
                    solidity_coverage=solidity_coverage,
                    execution_candidate_build=execution_candidate_build,
                    model_surface_requests=model_surface_requests,
                    model_surface_review_assignments=model_surface_review_assignments,
                    disposable_roots=(run_dir / "private",),
                    audited_exclusion_roots=(
                        (scanner_source_exclusion_root,)
                        if output_relative_to_repo is not None
                        else ()
                    ),
                )
                scheduler_analysis_input_sha256 = scheduler_analysis_input.analysis_input_sha256
                atomic_ledger = self._effective_cost_ledger()
                scheduler_cost_ledger_baseline = None
                if resume_scheduler_journal is None and atomic_ledger is not None:
                    scheduler_cost_ledger_baseline = build_scheduler_cost_ledger_baseline(
                        atomic_ledger
                    )
                scheduler_bindings = build_scheduler_bindings(
                    config=self.config,
                    shard_inventory=scheduler_inventory,
                    qualification=self.production_qualification,
                    analysis_input_sha256=scheduler_analysis_input_sha256,
                    cost_ledger_baseline=scheduler_cost_ledger_baseline,
                    privacy_evidence_custody=scheduler_privacy_evidence_custody,
                )
                if resume_scheduler_journal is None:
                    if scheduler_privacy_evidence_custody is None:
                        raise ValueError(
                            "scheduler creation requires exact pre-dispatch privacy custody"
                        )
                    scheduler = PipelineScheduler.create(
                        run_dir / "private" / "scheduler-journal",
                        bindings=scheduler_bindings,
                        analysis_input_inventory=scheduler_analysis_input,
                        shard_inventory=scheduler_inventory,
                        cost_ledger_baseline=scheduler_cost_ledger_baseline,
                        privacy_evidence_custody=scheduler_privacy_evidence_custody,
                    )
                    self._active_scheduler = scheduler
                else:
                    if atomic_ledger is None:
                        raise ValueError(
                            "scheduler resume requires the exact persistent cost ledger"
                        )
                    scheduler = PipelineScheduler.resume(
                        resume_scheduler_journal,
                        bindings=scheduler_bindings,
                        analysis_input_inventory=scheduler_analysis_input,
                        shard_inventory=scheduler_inventory,
                        cost_ledger_baseline=None,
                        atomic_ledger=atomic_ledger,
                    )
                    self._active_scheduler = scheduler
                    await self._validate_models(
                        run_dir,
                        refresh=refresh_models,
                        source_egress_requested=True,
                        qualification_preflight=qualification_preflight,
                    )
                    recovered_usage, recovery_scope = (
                        scheduler.journal.claim_restorable_usage_for_budget_recovery(
                            atomic_ledger=atomic_ledger
                        )
                    )
                    await budget.restore_recovered_usage(
                        recovered_usage,
                        recovery_scope=recovery_scope,
                    )
                    for record in recovered_usage:
                        usage.add(record)
                    scheduler_cost_ledger_baseline = scheduler.manifest.cost_ledger_baseline
                    scheduler_bindings = scheduler.manifest.bindings
                self.client.bind_request_lifecycle_observer(scheduler)
            except SecretSafetyError as exc:
                incomplete.append(str(exc))
                terminal_code = ExitCode.PRIVACY_REFUSAL
            except BudgetExhaustedError as exc:
                incomplete.append(str(exc))
                terminal_code = ExitCode.INCOMPLETE
                budget_halted = True
            except OpenRouterAuthenticationError as exc:
                incomplete.append(str(exc))
                terminal_code = ExitCode.MODEL_FAILURE
            except OpenRouterError as exc:
                incomplete.append(str(exc))
                terminal_code = ExitCode.MODEL_FAILURE
            except (OSError, ValueError) as exc:
                incomplete.append(
                    f"seven-pass scheduler preflight failed: {type(exc).__name__}: {exc}"
                )
                terminal_code = ExitCode.INCOMPLETE

        packages: list[ContextPackage] = []
        accepted_specialist_outcomes: list[SpecialistAcceptedOutcome] = []
        scheduler_agent_config = _scheduler_primary_only_config(self.config)
        if (
            context_builder is not None
            and self.client is not None
            and self._active_scheduler is not None
        ):
            client = self.client
            scheduler = self._active_scheduler
            semaphore = asyncio.Semaphore(self.config.execution.concurrency)

            async def bounded_call(coroutine: Any) -> Any:
                async with semaphore:
                    return await coroutine

            def accept_specialist_outcome(
                *,
                completion_usage: UsageRecord,
                validated_context: ContextPackage,
                specialist_role: str,
                request_role: str,
                outcome_kind: SpecialistAcceptedOutcomeKind,
                requested_surface_count: int = 0,
                surface_artifact: ModelSurfaceReviewArtifact | None = None,
            ) -> SpecialistAcceptedOutcome:
                """Record one role result only after all host-side validation returned."""

                record = _exact_completed_usage(
                    usage.records,
                    completion_usage,
                    expected_role=request_role,
                )
                sealed_context, context_evidence = _bound_context_request_evidence(
                    record,
                    validated_context,
                )
                if record.validated_response_sha256 is None:
                    raise OpenRouterSchemaError(
                        "accepted specialist workflow lacks bound response/context evidence"
                    )
                if surface_artifact is not None:
                    try:
                        surface_artifact = ModelSurfaceReviewArtifact.model_validate(
                            surface_artifact.model_dump(mode="python")
                        )
                    except ValueError as exc:
                        raise OpenRouterSchemaError(
                            "accepted specialist surface artifact failed validation"
                        ) from exc
                    try:
                        surface_artifact.require_exact_requested_surface_manifest(
                            sealed_context.requested_model_surfaces
                        )
                    except ValueError as exc:
                        raise OpenRouterSchemaError(
                            "accepted specialist surface artifact differed from its "
                            "requested surface manifest"
                        ) from exc
                    if (
                        surface_artifact.request_id != record.request_id
                        or surface_artifact.review_role != request_role
                        or surface_artifact.prompt_sha256 != record.prompt_sha256
                        or surface_artifact.response_sha256 != record.response_sha256
                        or surface_artifact.validated_response_sha256
                        != record.validated_response_sha256
                        or surface_artifact.response_schema_sha256 != record.schema_sha256
                        or surface_artifact.rendered_context_sha256
                        != context_evidence.rendered_sha256
                        or surface_artifact.rendered_context_sha256 != record.user_prompt_sha256
                        or requested_surface_count != len(sealed_context.requested_model_surfaces)
                    ):
                        raise OpenRouterSchemaError(
                            "accepted specialist surface artifact differs from its request"
                        )
                accepted = SpecialistAcceptedOutcome.build(
                    request_id=record.request_id,
                    specialist_role=specialist_role,
                    request_role=request_role,
                    outcome_kind=outcome_kind,
                    validated_response_sha256=record.validated_response_sha256,
                    context_request_evidence_sha256=context_evidence.evidence_sha256,
                    requested_surface_count=requested_surface_count,
                    surface_review_artifact_sha256=(
                        surface_artifact.artifact_sha256 if surface_artifact is not None else None
                    ),
                )
                accepted_specialist_outcomes.append(accepted)
                return accepted

            def register_finding_result(
                result: FindingReviewResult,
                *,
                expected_role: str,
            ) -> tuple[ContextPackage, UsageRecord]:
                """Bind every candidate ID to exactly one accepted request package."""

                sealed_context, completion_usage = _validated_finding_result(
                    result,
                    expected_role=expected_role,
                    usage_records=usage.records,
                )
                result_ids = [candidate.candidate_id for candidate in result.findings]
                _register_candidate_origin_packages(
                    candidate_origin_packages,
                    candidate_ids=result_ids,
                    context=sealed_context,
                )
                return sealed_context, completion_usage

            def context_models(role: str) -> tuple[str, ...]:
                configured_role = role
                if role.startswith("specialist:"):
                    configured_role = role.split(":", 1)[1]
                role_config = self.config.models.role(configured_role)
                return (role_config.primary, *role_config.fallbacks)

            def build_context(
                role: str,
                *,
                preview_models: tuple[str, ...] | None = None,
                context_role: str | None = None,
                **kwargs: Any,
            ) -> ContextPackage | None:
                nonlocal terminal_code, budget_halted
                try:
                    configured_budget = kwargs.pop("requested_budget", None)
                    workflow_byte_upper_bound_tokens = kwargs.pop(
                        "workflow_byte_upper_bound_tokens",
                        None,
                    )
                    workflow_prompt = kwargs.pop("workflow_prompt", None)
                    models = preview_models if preview_models is not None else context_models(role)

                    def endpoint_budget(*, context_escape_overhead: int = 0) -> int:
                        return client.context_package_byte_budget(
                            models,
                            role=role,
                            workflow_byte_upper_bound_tokens=(workflow_byte_upper_bound_tokens),
                            workflow_prompt=workflow_prompt,
                            context_json_escape_overhead_tokens=(context_escape_overhead),
                        )

                    initial_endpoint_budget = endpoint_budget()
                    requested_budget = (
                        initial_endpoint_budget
                        if configured_budget is None
                        else min(configured_budget, initial_endpoint_budget)
                    )
                    attempted_budgets: set[int] = set()
                    for _attempt in range(8):
                        if requested_budget in attempted_budgets:
                            raise ContextBudgetError(
                                f"context preview for role {role} did not converge"
                            )
                        attempted_budgets.add(requested_budget)
                        package = context_builder.build(
                            context_role or role,
                            requested_budget=requested_budget,
                            **kwargs,
                        )
                        escaped_endpoint_budget = endpoint_budget(
                            context_escape_overhead=(context_json_escape_overhead_tokens(package))
                        )
                        validated_budget = (
                            escaped_endpoint_budget
                            if configured_budget is None
                            else min(configured_budget, escaped_endpoint_budget)
                        )
                        if requested_budget <= validated_budget:
                            return package
                        requested_budget = min(
                            requested_budget - 1,
                            validated_budget,
                        )
                        if requested_budget <= 0:
                            raise ContextBudgetError(
                                f"context preview for role {role} leaves no package capacity"
                            )
                    raise ContextBudgetError(
                        f"context preview for role {role} did not converge within eight passes"
                    )
                except ContextBudgetError as exc:
                    incomplete.append(f"{role}: {exc}")
                    terminal_code = ExitCode.INCOMPLETE
                    budget_halted = True
                    return None
                except OpenRouterError as exc:
                    incomplete.append(f"{role}: {exc}")
                    terminal_code = ExitCode.MODEL_FAILURE
                    budget_halted = True
                    return None

            def build_specialist_context(
                role: str,
                *,
                preview_models: tuple[str, ...] | None = None,
                request_model_surface_reviews: bool = False,
                **kwargs: Any,
            ) -> ContextPackage | None:
                return build_context(
                    f"specialist:{role}",
                    preview_models=preview_models,
                    requested_budget=specialist_context_budget(
                        role,
                        total_context_bytes=(self.config.repository.max_total_context_bytes),
                        maximum_source_tokens_per_request=(
                            self.config.token_budgets.maximum_source_tokens_per_request
                        ),
                    ),
                    request_model_surface_reviews=request_model_surface_reviews,
                    **kwargs,
                )

            def check_accounted_budget() -> None:
                nonlocal terminal_code, budget_halted
                if budget.spent_usd + 1e-12 < budget.total_usd:
                    return
                if not budget_halted:
                    incomplete.append(
                        "accounted model cost reached the hard run budget; "
                        "no additional requests were scheduled"
                    )
                budget_halted = True
                terminal_code = ExitCode.INCOMPLETE

            def scheduled_model_task(
                *,
                pass_kind: SchedulerPassKind,
                scope: SchedulerScope,
                task_key: str,
                request_role: str,
                request_protocol: AgentRequestProtocol,
                configured_role: str | None = None,
                model_id: str | None = None,
                root_lineage: str | None = None,
                candidate_ids: set[str] | None = None,
            ) -> SchedulerTaskPlan:
                selected_model = model_id
                if selected_model is None:
                    if configured_role is None:
                        raise ValueError("scheduled model task lacks a configured role")
                    selected_model = self.config.models.role(configured_role).primary
                selected_lineage = root_lineage or _scheduler_root_lineage(
                    self.config,
                    selected_model,
                )
                request_hashes = client.preview_structured_request_hashes(
                    role=request_role,
                    model=selected_model,
                    system_prompt=request_protocol.system_prompt,
                    user_prompt="",
                    response_model=request_protocol.response_model,
                    schema_name=request_protocol.schema_name,
                )
                response_schema_sha256 = _scheduler_response_schema_sha256(
                    request_protocol.response_model
                )
                if request_hashes.schema_sha256 != response_schema_sha256:
                    raise ValueError("scheduled request protocol schema hash is inconsistent")
                return scheduler.model_task(
                    pass_kind=pass_kind,
                    scope=scope,
                    task_key=task_key,
                    role=request_role,
                    requested_model=selected_model,
                    root_lineage=selected_lineage,
                    system_prompt_sha256=request_hashes.system_prompt_sha256,
                    response_schema_sha256=response_schema_sha256,
                    candidate_ids=tuple(sorted(candidate_ids or ())),
                )

            def conclude_scheduler_result(result: SchedulerPassResult) -> SchedulerPassStatus:
                nonlocal terminal_code, budget_halted, scheduler_halted
                if result.status is not SchedulerPassStatus.COMPLETE:
                    reason = (
                        "seven-pass scheduler stopped after "
                        f"{result.plan.pass_kind.value}: {result.status.value}"
                    )
                    if reason not in incomplete:
                        incomplete.append(reason)
                    scheduler_halted = True
                    budget_halted = True
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.MODEL_FAILURE
                return result.status

            def conclude_scheduler_pass() -> SchedulerPassStatus:
                return conclude_scheduler_result(scheduler.seal_pass_result())

            def completed_usage_for_task(task: SchedulerTaskPlan) -> UsageRecord:
                """Recover one exact completed request without promoting serialized evidence."""

                matches = tuple(
                    record
                    for record in usage.records
                    if record.request_id == task.logical_request_id
                )
                if len(matches) != 1:
                    raise ValueError("resumed scheduler task lacks one exact restored usage record")
                return _exact_completed_usage(
                    usage.records,
                    matches[0],
                    expected_role=task.role,
                )

            def completed_finding_review(
                pass_result: SchedulerPassResult,
                task: SchedulerTaskPlan,
                agent: Any,
                context: ContextPackage,
            ) -> FindingReviewResult:
                result = scheduler.completed_result_for_task(pass_result, task)
                if result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                    raise OpenRouterSchemaError(
                        "completed candidate review lacks a successful scheduler result"
                    )
                raw_response = scheduler.completed_output_for_task(
                    pass_result,
                    task,
                    CandidateReviewBatch,
                )
                completed_review = cast(
                    FindingReviewResult,
                    agent.bind_completed_review(
                        context,
                        raw_response=raw_response,
                        completion_usage=completed_usage_for_task(task),
                    ),
                )
                retained_outputs = tuple(
                    output for output in scheduler.journal.outputs if output.task_id == task.task_id
                )
                if len(retained_outputs) != 1 or retained_outputs[
                    0
                ].accepted_candidate_payload_sha256s != _candidate_payload_sha256s(
                    completed_review.findings
                ):
                    raise OpenRouterSchemaError(
                        "resumed candidate review differs from its host-accepted projection"
                    )
                return completed_review

            def completed_finding_review_or_terminal(
                pass_result: SchedulerPassResult,
                task: SchedulerTaskPlan,
                agent: Any,
                context: ContextPackage,
            ) -> FindingReviewResult | SchedulerTaskResult:
                result = scheduler.completed_result_for_task(pass_result, task)
                if result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
                    return result
                return completed_finding_review(pass_result, task, agent, context)

            def require_completed_specialist_outcome(
                task: SchedulerTaskPlan,
                expected: SpecialistAcceptedOutcome | None,
                *,
                surface_requests: tuple[ModelSurfaceReviewRequest, ...] = (),
                surface_artifact: ModelSurfaceReviewArtifact | None = None,
            ) -> None:
                outputs = tuple(
                    output for output in scheduler.journal.outputs if output.task_id == task.task_id
                )
                if (
                    len(outputs) != 1
                    or outputs[0].specialist_accepted_outcome != expected
                    or outputs[0].model_surface_review_requests != surface_requests
                    or outputs[0].model_surface_review_artifact != surface_artifact
                ):
                    raise OpenRouterSchemaError(
                        "resumed specialist outcome differs from its exact retained output"
                    )

            async def completed_value(value: Any) -> Any:
                return value

            threat_agent = ThreatModelAgent(scheduler_agent_config, self.client)
            threat_task = scheduled_model_task(
                pass_kind=SchedulerPassKind.ORIENTATION,
                scope=SchedulerScope.global_scope(),
                task_key="threat-model",
                request_role="threat_model",
                configured_role="threat_model",
                request_protocol=threat_agent.request_protocol,
            )
            completed_orientation = scheduler.completed_pass_result(
                SchedulerPassKind.ORIENTATION,
                (threat_task,),
            )
            active_orientation_result: SchedulerTaskResult | None = None
            if completed_orientation is None:
                scheduler.prepare_pass(SchedulerPassKind.ORIENTATION, (threat_task,))
                active_orientation_result = scheduler.result_for_task(threat_task)
            threat_context = build_context("threat_model")
            retained_orientation_result = (
                scheduler.completed_result_for_task(completed_orientation, threat_task)
                if completed_orientation is not None
                else active_orientation_result
            )
            if (
                retained_orientation_result is not None
                and retained_orientation_result.terminal_status
                is not SchedulerTerminalStatus.SUCCEEDED
            ):
                incomplete.append(
                    "threat_model: resumed scheduler task retained terminal status "
                    f"{retained_orientation_result.terminal_status.value}"
                )
            elif threat_context is not None:
                packages.append(threat_context)
                try:
                    if completed_orientation is not None:
                        raw_threat_model = scheduler.completed_output_for_task(
                            completed_orientation,
                            threat_task,
                            ThreatModel,
                        )
                    elif active_orientation_result is not None:
                        raw_threat_model = scheduler.output_for_task(
                            threat_task,
                            ThreatModel,
                        )
                    else:
                        self.logger.info("Running threat-model role", extra={"run_id": run_id})
                        raw_threat_model = await bounded_call(
                            threat_agent.run(
                                threat_context,
                                logical_request_id=threat_task.logical_request_id,
                            )
                        )
                    threat_model, threat_location_rejections = _validated_threat_model(
                        discovery.root,
                        raw_threat_model,
                        context_hashes=context_hash_index([threat_context]),
                    )
                    if completed_orientation is None and active_orientation_result is None:
                        scheduler.record_model_success(
                            threat_task,
                            output_value=raw_threat_model,
                            usage_records=usage.records,
                        )
                except BudgetExhaustedError as exc:
                    scheduler.record_failure(threat_task, exc, usage_records=usage.records)
                    incomplete.append(f"threat_model: {exc}")
                    terminal_code = ExitCode.INCOMPLETE
                    budget_halted = True
                except OpenRouterError as exc:
                    scheduler.record_failure(threat_task, exc, usage_records=usage.records)
                    incomplete.append(f"threat_model: {exc}")
                    terminal_code = ExitCode.MODEL_FAILURE
            else:
                scheduler.record_failure(
                    threat_task,
                    ContextBudgetError("threat-model context was not produced"),
                )
            if completed_orientation is None:
                conclude_scheduler_pass()
            else:
                conclude_scheduler_result(completed_orientation)
            check_accounted_budget()

            specialist_roles = (
                [
                    role
                    for role in SPECIALIST_INVESTIGATOR_ROLES
                    if role in self.config.models.specialists
                ]
                if self.config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
                else []
            )
            blind_specs: list[
                tuple[
                    str,
                    str,
                    type[Any] | None,
                    SchedulerShardDescriptor,
                    SchedulerTaskPlan,
                ]
            ] = []
            whole_protocol_specs: list[
                tuple[
                    str,
                    str,
                    WholeProtocolReviewAgent,
                    SchedulerTaskPlan,
                ]
            ] = []
            if not scheduler_halted:
                for shard in scheduler.manifest.shard_inventory.shards:
                    scope = SchedulerScope.single_shard(shard.shard_id)
                    for role, agent_class in (
                        ("source_audit", SourceAuditAgent),
                        ("business_logic", BusinessLogicAgent),
                        ("configuration", ConfigurationAgent),
                    ):
                        blind_specs.append(
                            (
                                role,
                                role,
                                agent_class,
                                shard,
                                scheduled_model_task(
                                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                                    scope=scope,
                                    task_key=f"{role}-{shard.shard_id}",
                                    request_role=role,
                                    configured_role=role,
                                    request_protocol=agent_class(
                                        scheduler_agent_config,
                                        self.client,
                                    ).request_protocol,
                                ),
                            )
                        )
                    for role in specialist_roles:
                        blind_specs.append(
                            (
                                f"specialist:{role}",
                                role,
                                None,
                                shard,
                                scheduled_model_task(
                                    pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                                    scope=scope,
                                    task_key=f"specialist-{role}-{shard.shard_id}",
                                    request_role=f"specialist:{role}",
                                    configured_role=role,
                                    request_protocol=SpecialistFindingAgent(
                                        scheduler_agent_config,
                                        self.client,
                                        role,
                                    ).request_protocol,
                                ),
                            )
                        )
                for review_index, (model_id, root_lineage) in enumerate(
                    _whole_protocol_review_models(
                        self.config,
                        self.production_qualification,
                    )
                ):
                    whole_agent = WholeProtocolReviewAgent(
                        scheduler_agent_config,
                        self.client,
                        review_index=review_index,
                        exact_model_id=model_id,
                    )
                    request_role = whole_agent.role
                    whole_protocol_specs.append(
                        (
                            request_role,
                            model_id,
                            whole_agent,
                            scheduled_model_task(
                                pass_kind=SchedulerPassKind.BLIND_SHARD_REVIEW,
                                scope=SchedulerScope.global_scope(),
                                task_key=f"whole-protocol-review-{review_index}",
                                request_role=request_role,
                                request_protocol=whole_agent.request_protocol,
                                model_id=model_id,
                                root_lineage=root_lineage,
                            ),
                        )
                    )
                blind_plan_tasks = (
                    *(spec[4] for spec in blind_specs),
                    *(spec[3] for spec in whole_protocol_specs),
                )
                completed_blind_review = scheduler.completed_pass_result(
                    SchedulerPassKind.BLIND_SHARD_REVIEW,
                    blind_plan_tasks,
                )
                if completed_blind_review is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.BLIND_SHARD_REVIEW,
                        blind_plan_tasks,
                    )

                blind_contexts: list[
                    tuple[
                        str,
                        str,
                        type[Any] | None,
                        SchedulerTaskPlan,
                        ContextPackage,
                    ]
                ] = []
                whole_protocol_contexts: list[
                    tuple[
                        str,
                        WholeProtocolReviewAgent,
                        SchedulerTaskPlan,
                        ContextPackage,
                    ]
                ] = []
                for (
                    request_role,
                    configured_role,
                    blind_agent_type,
                    shard,
                    scheduler_task,
                ) in blind_specs:
                    scoped_source_paths = {source.path for source in shard.sources}
                    allowed_paths = (
                        scoped_source_paths
                        if request_role == "source_audit"
                        else _semantic_shard_context_paths(
                            solidity_shards,
                            shard_id=shard.shard_id,
                            primary_paths=scoped_source_paths,
                        )
                    )
                    assigned_surfaces = [
                        surface
                        for surface in model_surface_review_assignments.get(request_role, [])
                        if not surface.allowed_locations
                        or {location.path for location in surface.allowed_locations}
                        <= allowed_paths
                    ]
                    if request_role == "source_audit":
                        try:
                            assigned_surfaces = _source_audit_shard_surface_requests(
                                shard=shard,
                                discovery=discovery,
                                solidity_index=solidity_index,
                                assigned=assigned_surfaces,
                                solidity_requests=model_surface_requests,
                            )
                        except ValueError as exc:
                            incomplete.append(f"source_audit: {exc}")
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                            break
                    else:
                        try:
                            assigned_surfaces = _blind_shard_surface_requests(
                                shard=shard,
                                discovery=discovery,
                                assigned=assigned_surfaces,
                            )
                        except ValueError as exc:
                            incomplete.append(f"{request_role}: {exc}")
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                            break
                    if request_role.startswith("specialist:"):
                        package = build_specialist_context(
                            configured_role,
                            threat_model=threat_model,
                            requested_model_surfaces=assigned_surfaces,
                            allowed_source_paths=allowed_paths,
                        )
                    else:
                        package = build_context(
                            request_role,
                            threat_model=threat_model,
                            requested_model_surfaces=assigned_surfaces,
                            allowed_source_paths=allowed_paths,
                        )
                    if package is None:
                        break
                    blind_contexts.append(
                        (
                            request_role,
                            configured_role,
                            blind_agent_type,
                            scheduler_task,
                            package,
                        )
                    )

                if len(blind_contexts) == len(blind_specs):
                    whole_protocol_paths = {
                        source.path
                        for shard in scheduler.manifest.shard_inventory.shards
                        for source in shard.sources
                    }
                    whole_protocol_surfaces = _whole_protocol_surface_requests(
                        discovery=discovery,
                    )
                    for (
                        request_role,
                        model_id,
                        whole_protocol_agent,
                        scheduler_task,
                    ) in whole_protocol_specs:
                        package = build_context(
                            request_role,
                            preview_models=(model_id,),
                            context_role="whole_protocol_review",
                            threat_model=threat_model,
                            requested_model_surfaces=whole_protocol_surfaces,
                            allowed_source_paths=whole_protocol_paths,
                        )
                        if package is None:
                            break
                        whole_protocol_contexts.append(
                            (request_role, whole_protocol_agent, scheduler_task, package)
                        )

                if len(blind_contexts) != len(blind_specs) or len(whole_protocol_contexts) != len(
                    whole_protocol_specs
                ):
                    blind_failure = ContextBudgetError(
                        "blind shard contexts were not frozen as one complete plan"
                    )
                    for (
                        _request_role,
                        _configured_role,
                        _agent_type,
                        _shard,
                        task_plan,
                    ) in blind_specs:
                        scheduler.record_failure(task_plan, blind_failure)
                    for _request_role, _model_id, _agent, task_plan in whole_protocol_specs:
                        scheduler.record_failure(task_plan, blind_failure)
                else:
                    # The complete pass plan and every shard-scoped context are
                    # frozen before any investigator task is allowed to run.
                    blind_tasks: list[
                        tuple[
                            str,
                            str,
                            SchedulerTaskPlan,
                            ContextPackage,
                            asyncio.Task[Any],
                        ]
                    ] = []
                    for (
                        request_role,
                        configured_role,
                        blind_agent_type,
                        scheduler_task,
                        blind_package,
                    ) in blind_contexts:
                        packages.append(blind_package)
                        blind_agent = (
                            SpecialistFindingAgent(
                                scheduler_agent_config,
                                self.client,
                                configured_role,
                            )
                            if blind_agent_type is None
                            else blind_agent_type(scheduler_agent_config, self.client)
                        )
                        recovered_review = (
                            completed_finding_review_or_terminal(
                                completed_blind_review,
                                scheduler_task,
                                blind_agent,
                                blind_package,
                            )
                            if completed_blind_review is not None
                            else None
                        )
                        blind_tasks.append(
                            (
                                request_role,
                                configured_role,
                                scheduler_task,
                                blind_package,
                                asyncio.create_task(
                                    (
                                        completed_value(recovered_review)
                                        if recovered_review is not None
                                        else bounded_call(
                                            blind_agent.run(
                                                blind_package,
                                                logical_request_id=(
                                                    scheduler_task.logical_request_id
                                                ),
                                            )
                                        )
                                    ),
                                    name=f"model:{request_role}:{scheduler_task.task_key}",
                                ),
                            )
                        )
                    for (
                        request_role,
                        whole_protocol_agent,
                        scheduler_task,
                        whole_protocol_package,
                    ) in whole_protocol_contexts:
                        packages.append(whole_protocol_package)
                        recovered_review = (
                            completed_finding_review_or_terminal(
                                completed_blind_review,
                                scheduler_task,
                                whole_protocol_agent,
                                whole_protocol_package,
                            )
                            if completed_blind_review is not None
                            else None
                        )
                        blind_tasks.append(
                            (
                                request_role,
                                "whole_protocol_review",
                                scheduler_task,
                                whole_protocol_package,
                                asyncio.create_task(
                                    (
                                        completed_value(recovered_review)
                                        if recovered_review is not None
                                        else bounded_call(
                                            whole_protocol_agent.run(
                                                whole_protocol_package,
                                                logical_request_id=(
                                                    scheduler_task.logical_request_id
                                                ),
                                            )
                                        )
                                    ),
                                    name=f"model:{request_role}:{scheduler_task.task_key}",
                                ),
                            )
                        )
                    for (
                        request_role,
                        configured_role,
                        scheduler_task,
                        _package,
                        task,
                    ) in blind_tasks:
                        try:
                            batch = await task
                            if isinstance(batch, SchedulerTaskResult):
                                incomplete.append(
                                    f"{request_role}: retained scheduler terminal "
                                    f"{batch.terminal_status.value}"
                                )
                                if terminal_code is ExitCode.SUCCESS:
                                    terminal_code = ExitCode.MODEL_FAILURE
                                budget_halted = True
                                continue
                            sealed_context, completion_usage = register_finding_result(
                                batch,
                                expected_role=request_role,
                            )
                            specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None
                            if request_role.startswith("specialist:"):
                                specialist_accepted_outcome = accept_specialist_outcome(
                                    completion_usage=completion_usage,
                                    validated_context=sealed_context,
                                    specialist_role=configured_role,
                                    request_role=request_role,
                                    outcome_kind=(SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW),
                                    requested_surface_count=len(
                                        batch.surface_review_context.requested_model_surfaces
                                    ),
                                    surface_artifact=batch.surface_review_artifact,
                                )
                            candidates.extend(batch.findings)
                            if batch.surface_review_artifact is not None:
                                artifact = batch.surface_review_artifact
                                model_surface_review_artifacts.append(artifact)
                                model_surface_review_contexts.setdefault(
                                    artifact.request_id,
                                    [],
                                ).append(sealed_context)
                            if completed_blind_review is None:
                                scheduler.record_model_success(
                                    scheduler_task,
                                    output_value=batch.raw_response,
                                    usage_records=usage.records,
                                    specialist_accepted_outcome=specialist_accepted_outcome,
                                    accepted_candidates=batch.findings,
                                    model_surface_review_requests=(
                                        sealed_context.requested_model_surfaces
                                    ),
                                    model_surface_review_artifact=(batch.surface_review_artifact),
                                )
                            else:
                                require_completed_specialist_outcome(
                                    scheduler_task,
                                    specialist_accepted_outcome,
                                    surface_requests=tuple(sealed_context.requested_model_surfaces),
                                    surface_artifact=batch.surface_review_artifact,
                                )
                            if batch.findings and time_to_first_candidate_seconds is None:
                                time_to_first_candidate_seconds = (
                                    time.monotonic() - run_started_monotonic
                                )
                        except BudgetExhaustedError as exc:
                            scheduler.record_failure(
                                scheduler_task,
                                exc,
                                usage_records=usage.records,
                            )
                            incomplete.append(f"{request_role}: {exc}")
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                        except OpenRouterError as exc:
                            scheduler.record_failure(
                                scheduler_task,
                                exc,
                                usage_records=usage.records,
                            )
                            incomplete.append(f"{request_role}: {exc}")
                            if terminal_code is ExitCode.SUCCESS:
                                terminal_code = ExitCode.MODEL_FAILURE
                if completed_blind_review is None:
                    conclude_scheduler_pass()
                else:
                    conclude_scheduler_result(completed_blind_review)
                check_accounted_budget()

            blind_candidate_ids = {candidate.candidate_id for candidate in candidates}
            if not scheduler_halted:
                reduction_task = scheduler.host_task(
                    pass_kind=SchedulerPassKind.FINDING_REDUCTION,
                    scope=SchedulerScope.global_scope(),
                    task_key="finding-reduction",
                    role="host:finding_reducer",
                )
                completed_reduction = scheduler.completed_pass_result(
                    SchedulerPassKind.FINDING_REDUCTION,
                    (reduction_task,),
                )
                if completed_reduction is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.FINDING_REDUCTION,
                        (reduction_task,),
                    )
                if pending_execution_candidates:
                    candidates.extend(pending_execution_candidates)
                    execution_candidates_integrated = True
                candidates = _attach_formal_counterexamples(candidates, formal_runs)
                formal_counterexamples_attached = True
                execution_candidate_ids = {
                    candidate.candidate_id for candidate in pending_execution_candidates
                }
                reduction_input = _finding_reduction_activation_input(
                    candidates,
                    blind_candidate_ids=blind_candidate_ids,
                    execution_candidate_ids=execution_candidate_ids,
                )
                if completed_reduction is None:
                    scheduler.activate_host(reduction_task, input_value=reduction_input)
                validations = {
                    candidate.candidate_id: _deterministic_candidate_validation(
                        discovery.root,
                        candidate,
                        context_hashes=_candidate_origin_source_hashes(
                            candidate_origin_packages,
                            candidate,
                        ),
                    )
                    for candidate in candidates
                }
                try:
                    reduction_output = _build_deterministic_finding_reduction(
                        candidates,
                        validations,
                        blind_candidate_ids=blind_candidate_ids,
                        execution_candidate_ids=execution_candidate_ids,
                    )
                    _validate_deterministic_finding_reduction(
                        reduction_output,
                        expected_candidate_ids={candidate.candidate_id for candidate in candidates},
                    )
                    if completed_reduction is None:
                        scheduler.record_host_success(
                            reduction_task,
                            output_value=reduction_output,
                        )
                    else:
                        completed_reduction_result = scheduler.completed_result_for_task(
                            completed_reduction,
                            reduction_task,
                        )
                        if (
                            completed_reduction_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                            or scheduler.journal.load_output(reduction_task.task_id)
                            != reduction_output
                        ):
                            raise ValueError(
                                "resumed finding reduction differs from its exact retained output"
                            )
                except ValueError as exc:
                    scheduler.record_failure(reduction_task, exc)
                    incomplete.append(f"deterministic finding reduction failed: {exc}")
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
                if completed_reduction is None:
                    conclude_scheduler_pass()
                else:
                    conclude_scheduler_result(completed_reduction)

            integration_host_task: SchedulerTaskPlan | None = None
            integration_scheduler_result: SchedulerTaskResult | None = None
            invariant_scheduler_task: SchedulerTaskPlan | None = None
            invariant_scheduler_result: SchedulerTaskResult | None = None
            boundary_review_tasks: dict[str, SchedulerTaskPlan] = {}
            boundary_review_results: dict[str, SchedulerTaskResult] = {}
            boundary_review_artifacts: dict[str, ModelSurfaceReviewArtifact] = {}
            boundary_candidate_ids: dict[str, set[str]] = {}
            overlap_review_tasks: dict[str, SchedulerTaskPlan] = {}
            overlap_review_results: dict[str, SchedulerTaskResult] = {}
            overlap_review_artifacts: dict[str, ModelSurfaceReviewArtifact] = {}
            overlap_candidate_ids: dict[str, set[str]] = {}
            boundary_setup_error: ValueError | None = None
            try:
                boundary_surface_requests = _cross_shard_boundary_surface_requests(
                    solidity_shards,
                    solidity_graphs,
                    solidity_index,
                )
                overlap_surface_requests = _cross_shard_overlap_surface_requests(
                    solidity_shards,
                    solidity_graphs,
                    solidity_index,
                )
            except ValueError as exc:
                boundary_surface_requests = {}
                overlap_surface_requests = {}
                boundary_setup_error = exc
            if not scheduler_halted:
                integration_host_task = scheduler.host_task(
                    pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                    scope=SchedulerScope.global_scope(),
                    task_key="cross-shard-integration",
                    role="host:cross_shard_integrator",
                )
                integration_tasks: list[SchedulerTaskPlan] = [integration_host_task]
                if solidity_shards is not None:
                    for boundary in solidity_shards.boundaries:
                        request = boundary_surface_requests.get(boundary.boundary_id)
                        if request is None:
                            continue
                        boundary_review_tasks[boundary.boundary_id] = scheduled_model_task(
                            pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                            scope=SchedulerScope.shard_set(
                                (boundary.source_shard_id, boundary.target_shard_id)
                            ),
                            task_key=f"boundary-review-{boundary.boundary_id}",
                            request_role="business_logic",
                            configured_role="business_logic",
                            request_protocol=BusinessLogicAgent(
                                scheduler_agent_config,
                                self.client,
                            ).request_protocol,
                            candidate_ids={request.surface_id},
                        )
                    integration_tasks.extend(boundary_review_tasks.values())
                    for overlap in solidity_shards.overlaps:
                        request = overlap_surface_requests.get(overlap.overlap_id)
                        if request is None:
                            continue
                        overlap_review_tasks[overlap.overlap_id] = scheduled_model_task(
                            pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                            scope=SchedulerScope.shard_set(
                                (overlap.primary_shard_id, overlap.consumer_shard_id)
                            ),
                            task_key=f"overlap-review-{overlap.overlap_id}",
                            request_role="business_logic",
                            configured_role="business_logic",
                            request_protocol=BusinessLogicAgent(
                                scheduler_agent_config,
                                self.client,
                            ).request_protocol,
                            candidate_ids={request.surface_id},
                        )
                    integration_tasks.extend(overlap_review_tasks.values())
                if (
                    self.config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
                    and "invariant_review" in self.config.models.specialists
                ):
                    invariant_scheduler_task = scheduled_model_task(
                        pass_kind=SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                        scope=SchedulerScope.global_scope(),
                        task_key="invariant-review",
                        request_role="specialist:invariant_review",
                        configured_role="invariant_review",
                        request_protocol=InvariantReviewAgent(
                            scheduler_agent_config,
                            self.client,
                        ).request_protocol,
                    )
                    integration_tasks.append(invariant_scheduler_task)
                completed_integration = scheduler.completed_pass_result(
                    SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                    integration_tasks,
                )
                if completed_integration is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.CROSS_SHARD_INTEGRATION,
                        integration_tasks,
                    )

            relationship_review_tasks = {
                **boundary_review_tasks,
                **overlap_review_tasks,
            }
            relationship_surface_requests = {
                **boundary_surface_requests,
                **overlap_surface_requests,
            }
            relationship_review_results: dict[str, SchedulerTaskResult] = {
                **boundary_review_results,
                **overlap_review_results,
            }
            relationship_review_artifacts: dict[str, ModelSurfaceReviewArtifact] = {
                **boundary_review_artifacts,
                **overlap_review_artifacts,
            }
            relationship_candidate_ids: dict[str, set[str]] = {
                **boundary_candidate_ids,
                **overlap_candidate_ids,
            }
            if not scheduler_halted and not budget_halted and relationship_review_tasks:
                assert solidity_shards is not None
                paths_by_shard = {
                    shard.shard_id: shard.source_path for shard in solidity_shards.shards
                }
                contexts: dict[str, ContextPackage] = {}
                relationship_scopes = {
                    boundary.boundary_id: (
                        boundary.source_shard_id,
                        boundary.target_shard_id,
                    )
                    for boundary in solidity_shards.boundaries
                } | {
                    overlap.overlap_id: (
                        overlap.primary_shard_id,
                        overlap.consumer_shard_id,
                    )
                    for overlap in solidity_shards.overlaps
                }
                for relationship_id, shard_ids in sorted(relationship_scopes.items()):
                    relationship_scheduler_task = relationship_review_tasks.get(relationship_id)
                    if relationship_scheduler_task is None:
                        continue
                    allowed_paths = {
                        paths_by_shard[shard_ids[0]],
                        paths_by_shard[shard_ids[1]],
                    }
                    relationship_context = build_context(
                        "business_logic",
                        threat_model=threat_model,
                        requested_model_surfaces=(relationship_surface_requests[relationship_id],),
                        allowed_source_paths=allowed_paths,
                    )
                    if relationship_context is None:
                        if completed_integration is None:
                            relationship_review_results[relationship_id] = scheduler.record_failure(
                                relationship_scheduler_task,
                                ContextBudgetError("cross-shard boundary context was not produced"),
                            )
                        else:
                            raise OpenRouterSchemaError(
                                "resumed cross-shard boundary context was not reproduced"
                            )
                    else:
                        packages.append(relationship_context)
                        contexts[relationship_id] = relationship_context
                for relationship_id, relationship_context in sorted(contexts.items()):
                    scheduler_task = relationship_review_tasks[relationship_id]
                    try:
                        relationship_agent = BusinessLogicAgent(
                            scheduler_agent_config,
                            self.client,
                        )
                        batch = (
                            completed_finding_review(
                                completed_integration,
                                scheduler_task,
                                relationship_agent,
                                relationship_context,
                            )
                            if completed_integration is not None
                            else await bounded_call(
                                relationship_agent.run(
                                    relationship_context,
                                    logical_request_id=scheduler_task.logical_request_id,
                                )
                            )
                        )
                        sealed_context, _completion_usage = _validated_finding_result(
                            batch,
                            expected_role="business_logic",
                            usage_records=usage.records,
                        )
                        existing_candidates = {
                            candidate.candidate_id: candidate for candidate in candidates
                        }
                        new_boundary_findings: list[CandidateFinding] = []
                        for candidate_finding in batch.findings:
                            existing = existing_candidates.get(candidate_finding.candidate_id)
                            if existing is not None:
                                if existing != candidate_finding:
                                    raise OpenRouterSchemaError(
                                        "cross-shard review reused a candidate ID for "
                                        "different normalized evidence"
                                    )
                                continue
                            new_boundary_findings.append(candidate_finding)
                        _register_candidate_origin_packages(
                            candidate_origin_packages,
                            candidate_ids=[
                                finding.candidate_id for finding in new_boundary_findings
                            ],
                            context=sealed_context,
                        )
                        candidates.extend(new_boundary_findings)
                        relationship_candidate_ids[relationship_id] = {
                            candidate.candidate_id for candidate in batch.findings
                        }
                        artifact = batch.surface_review_artifact
                        if artifact is None:
                            raise OpenRouterSchemaError(
                                "cross-shard boundary review omitted its surface artifact"
                            )
                        relationship_review_artifacts[relationship_id] = artifact
                        model_surface_review_artifacts.append(artifact)
                        model_surface_review_contexts.setdefault(
                            artifact.request_id,
                            [],
                        ).append(sealed_context)
                        relationship_review_results[relationship_id] = (
                            scheduler.completed_result_for_task(
                                completed_integration,
                                scheduler_task,
                            )
                            if completed_integration is not None
                            else scheduler.record_model_success(
                                scheduler_task,
                                output_value=batch.raw_response,
                                usage_records=usage.records,
                                accepted_candidates=batch.findings,
                                model_surface_review_requests=(
                                    sealed_context.requested_model_surfaces
                                ),
                                model_surface_review_artifact=batch.surface_review_artifact,
                            )
                        )
                        if completed_integration is not None:
                            require_completed_specialist_outcome(
                                scheduler_task,
                                None,
                                surface_requests=tuple(sealed_context.requested_model_surfaces),
                                surface_artifact=batch.surface_review_artifact,
                            )
                    except (BudgetExhaustedError, OpenRouterError) as exc:
                        relationship_review_results[relationship_id] = scheduler.record_failure(
                            scheduler_task,
                            exc,
                            usage_records=usage.records,
                        )
                        incomplete.append(
                            f"cross-shard relationship review {relationship_id}: {exc}"
                        )
                        if isinstance(exc, BudgetExhaustedError):
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                        elif terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                check_accounted_budget()

            boundary_review_results = {
                relationship_id: relationship_review_results[relationship_id]
                for relationship_id in boundary_review_tasks
                if relationship_id in relationship_review_results
            }
            overlap_review_results = {
                relationship_id: relationship_review_results[relationship_id]
                for relationship_id in overlap_review_tasks
                if relationship_id in relationship_review_results
            }
            boundary_review_artifacts = {
                relationship_id: relationship_review_artifacts[relationship_id]
                for relationship_id in boundary_review_tasks
                if relationship_id in relationship_review_artifacts
            }
            overlap_review_artifacts = {
                relationship_id: relationship_review_artifacts[relationship_id]
                for relationship_id in overlap_review_tasks
                if relationship_id in relationship_review_artifacts
            }
            boundary_candidate_ids = {
                relationship_id: relationship_candidate_ids[relationship_id]
                for relationship_id in boundary_review_tasks
                if relationship_id in relationship_candidate_ids
            }
            overlap_candidate_ids = {
                relationship_id: relationship_candidate_ids[relationship_id]
                for relationship_id in overlap_review_tasks
                if relationship_id in relationship_candidate_ids
            }

            if (
                not scheduler_halted
                and not budget_halted
                and self.config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
                and "invariant_review" in self.config.models.specialists
            ):
                assert invariant_scheduler_task is not None
                invariant_context = build_specialist_context(
                    "invariant_review",
                    threat_model=threat_model,
                )
                if invariant_context is not None:
                    packages.append(invariant_context)
                    try:
                        if completed_integration is not None:
                            completed_invariant_result = scheduler.completed_result_for_task(
                                completed_integration,
                                invariant_scheduler_task,
                            )
                            if (
                                completed_invariant_result.terminal_status
                                is not SchedulerTerminalStatus.SUCCEEDED
                            ):
                                raise OpenRouterSchemaError(
                                    "completed invariant review lacks a successful result"
                                )
                            invariant_review_batch = scheduler.completed_output_for_task(
                                completed_integration,
                                invariant_scheduler_task,
                                InvariantReviewBatch,
                            )
                            invariant_completion_usage = completed_usage_for_task(
                                invariant_scheduler_task
                            )
                        else:
                            invariant_result = await bounded_call(
                                InvariantReviewAgent(
                                    scheduler_agent_config,
                                    self.client,
                                ).run_with_evidence(
                                    invariant_context,
                                    logical_request_id=(
                                        invariant_scheduler_task.logical_request_id
                                    ),
                                )
                            )
                            invariant_review_batch = invariant_result.value
                            invariant_completion_usage = invariant_result.completion_usage
                        invariant_review = validate_invariant_review(
                            discovery.root,
                            invariant_review_batch,
                            index=solidity_index,
                            context_hashes=context_hash_index([invariant_context]),
                        )
                        invariant_accepted_outcome = accept_specialist_outcome(
                            completion_usage=invariant_completion_usage,
                            validated_context=invariant_context,
                            specialist_role="invariant_review",
                            request_role="specialist:invariant_review",
                            outcome_kind=SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW,
                        )
                        if completed_integration is None:
                            invariant_scheduler_result = scheduler.record_model_success(
                                invariant_scheduler_task,
                                output_value=invariant_result.raw_response,
                                usage_records=usage.records,
                                specialist_accepted_outcome=invariant_accepted_outcome,
                            )
                        else:
                            require_completed_specialist_outcome(
                                invariant_scheduler_task,
                                invariant_accepted_outcome,
                            )
                            invariant_scheduler_result = completed_invariant_result
                    except BudgetExhaustedError as exc:
                        invariant_scheduler_result = scheduler.record_failure(
                            invariant_scheduler_task,
                            exc,
                            usage_records=usage.records,
                        )
                        incomplete.append(f"specialist:invariant_review: {exc}")
                        terminal_code = ExitCode.INCOMPLETE
                        budget_halted = True
                    except OpenRouterError as exc:
                        invariant_scheduler_result = scheduler.record_failure(
                            invariant_scheduler_task,
                            exc,
                            usage_records=usage.records,
                        )
                        incomplete.append(f"specialist:invariant_review: {exc}")
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                else:
                    invariant_scheduler_result = scheduler.record_failure(
                        invariant_scheduler_task,
                        ContextBudgetError("invariant-review context was not produced"),
                    )
                check_accounted_budget()

            if not scheduler_halted:
                assert integration_host_task is not None
                for boundary_id, scheduler_task in boundary_review_tasks.items():
                    if boundary_id not in boundary_review_results:
                        boundary_review_results[boundary_id] = scheduler.record_failure(
                            scheduler_task,
                            RuntimeError("scheduled cross-shard boundary review did not execute"),
                        )
                for overlap_id, scheduler_task in overlap_review_tasks.items():
                    if overlap_id not in overlap_review_results:
                        overlap_review_results[overlap_id] = scheduler.record_failure(
                            scheduler_task,
                            RuntimeError("scheduled cross-shard overlap review did not execute"),
                        )
                if invariant_scheduler_task is not None and invariant_scheduler_result is None:
                    invariant_scheduler_result = scheduler.record_failure(
                        invariant_scheduler_task,
                        RuntimeError("scheduled invariant review did not execute"),
                    )
                upstream_integration_results = (
                    tuple(boundary_review_results.values())
                    + tuple(overlap_review_results.values())
                    + (
                        (invariant_scheduler_result,)
                        if invariant_scheduler_result is not None
                        else ()
                    )
                )
                validations = {
                    candidate.candidate_id: _deterministic_candidate_validation(
                        discovery.root,
                        candidate,
                        context_hashes=_candidate_origin_source_hashes(
                            candidate_origin_packages,
                            candidate,
                        ),
                    )
                    for candidate in candidates
                }
                expected_relationship_ids = (
                    {boundary.boundary_id for boundary in solidity_shards.boundaries}
                    | {overlap.overlap_id for overlap in solidity_shards.overlaps}
                    if solidity_shards is not None
                    else set()
                )
                semantic_relationships = _cross_shard_relationship_descriptors(solidity_shards)
                integration_input = {
                    "semantic_inventory_sha256": (
                        solidity_shards.inventory_sha256 if solidity_shards is not None else None
                    ),
                    "candidate_ids": sorted(candidate.candidate_id for candidate in candidates),
                    "candidate_payload_sha256s": _candidate_payload_sha256s(candidates),
                    "high_critical_candidate_ids": sorted(
                        candidate.candidate_id
                        for candidate in candidates
                        if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
                    ),
                    "validation_candidate_ids": sorted(
                        candidate_id
                        for candidate_id, validation in validations.items()
                        if validation.valid
                    ),
                    "shard_ids": list(scheduler.manifest.shard_ids),
                    "semantic_relationship_ids": sorted(expected_relationship_ids),
                    "semantic_relationships": semantic_relationships,
                    "boundary_review_artifact_sha256s": sorted(
                        artifact.artifact_sha256
                        for artifact in (
                            *boundary_review_artifacts.values(),
                            *overlap_review_artifacts.values(),
                        )
                    ),
                    "invariant_review_present": invariant_review is not None,
                }
                if completed_integration is None:
                    scheduler.activate_host(
                        integration_host_task,
                        input_value=integration_input,
                        upstream_results=upstream_integration_results,
                    )
                try:
                    integration_output = _build_cross_shard_integration(
                        solidity_shards,
                        candidates,
                        validations,
                        shard_ids=scheduler.manifest.shard_ids,
                        invariant_review=invariant_review,
                        boundary_surface_requests=boundary_surface_requests,
                        boundary_review_artifacts=boundary_review_artifacts,
                        boundary_candidate_ids=boundary_candidate_ids,
                        overlap_surface_requests=overlap_surface_requests,
                        overlap_review_artifacts=overlap_review_artifacts,
                        overlap_candidate_ids=overlap_candidate_ids,
                    )
                    _validate_cross_shard_integration(
                        integration_output,
                        expected_candidate_ids={candidate.candidate_id for candidate in candidates},
                        expected_relationship_ids=expected_relationship_ids,
                    )
                    if completed_integration is None:
                        integration_scheduler_result = scheduler.record_host_success(
                            integration_host_task,
                            output_value=integration_output,
                        )
                    else:
                        integration_scheduler_result = scheduler.completed_result_for_task(
                            completed_integration,
                            integration_host_task,
                        )
                        if (
                            integration_scheduler_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                            or scheduler.journal.load_output(integration_host_task.task_id)
                            != integration_output
                        ):
                            raise ValueError(
                                "resumed cross-shard integration differs from its retained output"
                            )
                except ValueError as exc:
                    integration_scheduler_result = scheduler.record_failure(
                        integration_host_task,
                        exc,
                    )
                    failure_detail = boundary_setup_error or exc
                    incomplete.append(f"cross-shard integration failed: {failure_detail}")
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
                if completed_integration is None:
                    conclude_scheduler_pass()
                else:
                    conclude_scheduler_result(completed_integration)
                if (
                    integration_scheduler_result is not None
                    and integration_scheduler_result.terminal_status.value == "SUCCEEDED"
                ):
                    pass_four_candidates = [
                        CandidateFinding.model_validate(candidate.model_dump(mode="python"))
                        for candidate in candidates
                    ]
                    pass_four_candidate_projection_frozen = True

            if pending_execution_candidates and not execution_candidates_integrated:
                candidates.extend(pending_execution_candidates)
                execution_candidates_integrated = True
            validations = {
                candidate.candidate_id: _deterministic_candidate_validation(
                    discovery.root,
                    candidate,
                    context_hashes=_candidate_origin_source_hashes(
                        candidate_origin_packages,
                        candidate,
                    ),
                )
                for candidate in candidates
            }
            preferred_paths = {
                location.path for candidate in candidates for location in candidate.locations
            }
            if not formal_counterexamples_attached:
                candidates = _attach_formal_counterexamples(candidates, formal_runs)
                formal_counterexamples_attached = True
            cross_examination_candidates = [
                candidate
                for candidate in candidates
                if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
            ]
            pre_judgment_high_critical_ids = {
                candidate.candidate_id for candidate in cross_examination_candidates
            }
            cross_examination_required = bool(cross_examination_candidates)
            reviewer_models: list[tuple[str, str]] = []
            cross_scheduler_tasks: dict[tuple[str, int], SchedulerTaskPlan] = {}
            completed_cross_examination: SchedulerPassResult | None = None
            cross_candidate_workset = (
                scheduler.candidate_workset(SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION)
                if not scheduler_halted
                else None
            )
            if cross_candidate_workset is not None:
                try:
                    _require_candidate_workset_payloads(
                        cross_candidate_workset,
                        pass_four_candidates,
                    )
                except ValueError as exc:
                    incomplete.append(str(exc))
                    scheduler_halted = True
                    budget_halted = True
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
            if (
                cross_candidate_workset is not None
                and set(cross_candidate_workset.selected_candidate_ids)
                != pre_judgment_high_critical_ids
            ):
                incomplete.append(
                    "pass-five candidate inventory differs from the exact pass-four output"
                )
                scheduler_halted = True
                budget_halted = True
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            if (
                not scheduler_halted
                and cross_candidate_workset is not None
                and not cross_candidate_workset.selected_candidate_ids
            ):
                absence = scheduler.conditional_absence(
                    reason=SchedulerAbsenceReason.NO_HIGH_CRITICAL_CANDIDATES,
                    candidate_workset=cross_candidate_workset,
                )
                empty_task = scheduler.empty_task(
                    pass_kind=SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                    scope=SchedulerScope.global_scope(),
                    task_key="no-high-critical-candidates",
                    role="host:conditional_absence",
                    reason=absence.reason.value,
                )
                completed_cross_examination = scheduler.completed_pass_result(
                    SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                    (empty_task,),
                    candidate_workset=cross_candidate_workset,
                    conditional_absence=absence,
                )
                if completed_cross_examination is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                        (empty_task,),
                        candidate_workset=cross_candidate_workset,
                        conditional_absence=absence,
                    )
                assert integration_scheduler_result is not None
                if completed_cross_examination is None:
                    scheduler.activate_host(
                        empty_task,
                        input_value={"absence_sha256": absence.absence_sha256},
                        upstream_results=(integration_scheduler_result,),
                    )
                    scheduler.record_empty(empty_task)
                    conclude_scheduler_pass()
                else:
                    completed_empty = scheduler.completed_result_for_task(
                        completed_cross_examination,
                        empty_task,
                    )
                    if (
                        completed_empty.terminal_status
                        is not SchedulerTerminalStatus.EXPLICIT_EMPTY
                    ):
                        raise ValueError(
                            "resumed cross-examination absence lacks explicit-empty evidence"
                        )
                    conclude_scheduler_result(completed_cross_examination)
            elif not scheduler_halted:
                assert cross_candidate_workset is not None
                reviewer_models = select_candidate_falsifier_models(self.config)
                if len(reviewer_models) != 2:
                    incomplete.append(
                        "candidate cross-examination requires two registered models "
                        "from distinct immutable root lineages"
                    )
                    scheduler_halted = True
                    budget_halted = True
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.CONFIGURATION
                else:
                    for candidate in cross_examination_candidates:
                        candidate_key = scheduler_canonical_sha256(
                            {"candidate_id": candidate.candidate_id}
                        )[:24]
                        for reviewer_index, (model_id, root_lineage) in enumerate(
                            reviewer_models,
                            start=1,
                        ):
                            request_role = candidate_falsifier_role(
                                candidate.candidate_id,
                                reviewer_index,
                            )
                            cross_scheduler_tasks[(candidate.candidate_id, reviewer_index)] = (
                                scheduled_model_task(
                                    pass_kind=(SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION),
                                    scope=SchedulerScope.global_scope(),
                                    task_key=f"cross-exam-{candidate_key}-{reviewer_index}",
                                    request_role=request_role,
                                    model_id=model_id,
                                    root_lineage=root_lineage,
                                    request_protocol=CandidateCrossExaminerAgent(
                                        scheduler_agent_config,
                                        self.client,
                                        reviewer_index=reviewer_index,
                                        model_id=model_id,
                                        root_lineage=root_lineage,
                                    ).request_protocol,
                                    candidate_ids={candidate.candidate_id},
                                )
                            )
                    completed_cross_examination = scheduler.completed_pass_result(
                        SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                        cross_scheduler_tasks.values(),
                        candidate_workset=cross_candidate_workset,
                    )
                    if completed_cross_examination is None:
                        scheduler.prepare_pass(
                            SchedulerPassKind.ADVERSARIAL_CROSS_EXAMINATION,
                            cross_scheduler_tasks.values(),
                            candidate_workset=cross_candidate_workset,
                        )

            if (
                cross_examination_required
                and not budget_halted
                and not scheduler_halted
                and len(reviewer_models) == 2
            ):
                if len(reviewer_models) != 2:
                    raise AssertionError("cross-examination portfolio changed after sealing")
                else:
                    reviewer_model_ids = tuple(
                        model_id for model_id, _root_lineage in reviewer_models
                    )
                    prepared_cross_examinations: dict[
                        str,
                        tuple[PreparedCandidateCrossExaminationInput, ContextPackage],
                    ] = {}
                    for candidate in cross_examination_candidates:
                        prepared_cross_examination = CandidateCrossExaminerAgent.prepare_input(
                            [candidate]
                        )
                        candidate_context = build_context(
                            "candidate_cross_examination",
                            preview_models=reviewer_model_ids,
                            requested_budget=specialist_context_budget(
                                "falsifier",
                                total_context_bytes=(
                                    self.config.repository.max_total_context_bytes
                                ),
                                maximum_source_tokens_per_request=(
                                    self.config.token_budgets.maximum_source_tokens_per_request
                                ),
                            ),
                            workflow_byte_upper_bound_tokens=(
                                prepared_cross_examination.workflow_byte_upper_bound_tokens
                            ),
                            workflow_prompt=prepared_cross_examination.workflow_prompt,
                            threat_model=threat_model,
                            preferred_paths=preferred_paths,
                        )
                        if candidate_context is None:
                            break
                        packages.append(candidate_context)
                        prepared_cross_examinations[candidate.candidate_id] = (
                            prepared_cross_examination,
                            candidate_context,
                        )
                    if len(prepared_cross_examinations) == len(cross_examination_candidates):
                        cross_examiner_tasks = []
                        for reviewer_index, (model_id, root_lineage) in enumerate(
                            reviewer_models,
                            start=1,
                        ):
                            for candidate in cross_examination_candidates:
                                scheduler_task = cross_scheduler_tasks[
                                    (candidate.candidate_id, reviewer_index)
                                ]
                                prepared_input, restored_candidate_context = (
                                    prepared_cross_examinations[candidate.candidate_id]
                                )
                                cross_agent = CandidateCrossExaminerAgent(
                                    scheduler_agent_config,
                                    self.client,
                                    reviewer_index=reviewer_index,
                                    model_id=model_id,
                                    root_lineage=root_lineage,
                                )
                                if completed_cross_examination is not None:
                                    completed_cross_result = scheduler.completed_result_for_task(
                                        completed_cross_examination,
                                        scheduler_task,
                                    )
                                    if (
                                        completed_cross_result.terminal_status
                                        is not SchedulerTerminalStatus.SUCCEEDED
                                    ):
                                        raise OpenRouterSchemaError(
                                            "completed cross-examination lacks a successful result"
                                        )
                                    raw_cross_response = scheduler.completed_output_for_task(
                                        completed_cross_examination,
                                        scheduler_task,
                                        CandidateCrossExaminationResponse,
                                    )
                                    cross_usage = completed_usage_for_task(scheduler_task)
                                    _bound_context_request_evidence(
                                        cross_usage,
                                        restored_candidate_context,
                                    )
                                    restored_decisions = normalize_cross_examination_response(
                                        raw_cross_response,
                                        candidate_ids=dict(prepared_input.candidate_ids),
                                        request_id=cross_usage.request_id,
                                        reviewer_index=reviewer_index,
                                        requested_model=model_id,
                                        returned_model=cross_usage.returned_model,
                                        root_lineage=root_lineage,
                                    )
                                    pending_call = completed_value(
                                        (restored_decisions, raw_cross_response)
                                    )
                                else:

                                    async def run_cross_examination(
                                        *,
                                        agent: CandidateCrossExaminerAgent = cross_agent,
                                        selected_candidate: CandidateFinding = candidate,
                                        context: ContextPackage = restored_candidate_context,
                                        workflow: PreparedCandidateCrossExaminationInput = (
                                            prepared_input
                                        ),
                                        logical_request_id: str = (
                                            scheduler_task.logical_request_id
                                        ),
                                    ) -> tuple[
                                        list[CandidateCrossExaminationDecision],
                                        CandidateCrossExaminationResponse,
                                    ]:
                                        observed = await bounded_call(
                                            agent.run_with_evidence(
                                                [selected_candidate],
                                                context,
                                                prepared_input=workflow,
                                                logical_request_id=logical_request_id,
                                            )
                                        )
                                        return observed.value, observed.raw_response

                                    pending_call = run_cross_examination()
                                cross_examiner_tasks.append(
                                    (
                                        reviewer_index,
                                        candidate.candidate_id,
                                        root_lineage,
                                        scheduler_task,
                                        asyncio.create_task(
                                            pending_call,
                                            name=f"model:{
                                                candidate_falsifier_role(
                                                    candidate.candidate_id,
                                                    reviewer_index,
                                                )
                                            }",
                                        ),
                                    )
                                )
                        for (
                            reviewer_index,
                            candidate_id,
                            _root_lineage,
                            scheduler_task,
                            task,
                        ) in cross_examiner_tasks:
                            try:
                                decisions_for_candidate, raw_cross_response = await task
                                cross_examinations.extend(decisions_for_candidate)
                                if completed_cross_examination is None:
                                    scheduler.record_model_success(
                                        scheduler_task,
                                        output_value=raw_cross_response,
                                        usage_records=usage.records,
                                    )
                            except BudgetExhaustedError as exc:
                                scheduler.record_failure(
                                    scheduler_task,
                                    exc,
                                    usage_records=usage.records,
                                )
                                incomplete.append(
                                    f"candidate_falsifier:{candidate_id}:{reviewer_index}: {exc}"
                                )
                                terminal_code = ExitCode.INCOMPLETE
                                budget_halted = True
                            except OpenRouterError as exc:
                                scheduler.record_failure(
                                    scheduler_task,
                                    exc,
                                    usage_records=usage.records,
                                )
                                incomplete.append(
                                    f"candidate_falsifier:{candidate_id}:{reviewer_index}: {exc}"
                                )
                                if terminal_code is ExitCode.SUCCESS:
                                    terminal_code = ExitCode.MODEL_FAILURE
                        expected_cross_examinations = 2 * len(cross_examination_candidates)
                        if len(cross_examinations) != expected_cross_examinations or any(
                            len(
                                candidate_decisions := [
                                    decision
                                    for decision in cross_examinations
                                    if decision.candidate_id == candidate.candidate_id
                                ]
                            )
                            != 2
                            or len({decision.root_lineage for decision in candidate_decisions}) != 2
                            or {decision.reviewer_index for decision in candidate_decisions}
                            != {1, 2}
                            or len({decision.request_id for decision in candidate_decisions}) != 2
                            for candidate in cross_examination_candidates
                        ):
                            incomplete.append(
                                "candidate cross-examination did not complete two "
                                "independent lineage reviews per high/critical candidate"
                            )
                            if terminal_code is ExitCode.SUCCESS:
                                terminal_code = ExitCode.MODEL_FAILURE
                        candidates = _attach_cross_examination_votes(
                            candidates,
                            cross_examinations,
                        )
                    else:
                        context_failure = ContextBudgetError(
                            "cross-examination contexts were not frozen completely"
                        )
                        for scheduler_task in cross_scheduler_tasks.values():
                            scheduler.record_failure(scheduler_task, context_failure)
                check_accounted_budget()
                if completed_cross_examination is None:
                    conclude_scheduler_pass()
                else:
                    conclude_scheduler_result(completed_cross_examination)
            # Cross-examination is intentionally completed before the independent
            # verifier receives candidate material. This preserves the scheduler's
            # blind adversarial pass boundary and keeps validation in pass six.
            verifier_scheduler_task: SchedulerTaskPlan | None = None
            candidate_falsifier_scheduler_tasks: dict[int, SchedulerTaskPlan] = {}
            planner_scheduler_tasks: dict[str, SchedulerTaskPlan] = {}
            falsifier_scheduler_task: SchedulerTaskPlan | None = None
            reproduction_host_task: SchedulerTaskPlan | None = None
            pass_six_results: list[SchedulerTaskResult] = []
            completed_pass_six: SchedulerPassResult | None = None
            validation_candidate_workset = (
                scheduler.candidate_workset(
                    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
                )
                if not scheduler_halted
                else None
            )
            if validation_candidate_workset is not None:
                try:
                    _require_candidate_workset_payloads(
                        validation_candidate_workset,
                        pass_four_candidates,
                    )
                except ValueError as exc:
                    incomplete.append(str(exc))
                    scheduler_halted = True
                    budget_halted = True
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
            validation_candidate_ids = (
                set(validation_candidate_workset.selected_candidate_ids)
                if validation_candidate_workset is not None
                else set()
            )
            validation_candidates = [
                candidate
                for candidate in candidates
                if candidate.candidate_id in validation_candidate_ids
            ]
            if (
                validation_candidate_workset is not None
                and {
                    candidate.candidate_id
                    for candidate in candidates
                    if validations.get(candidate.candidate_id) is not None
                    and validations[candidate.candidate_id].valid
                }
                != validation_candidate_ids
            ):
                incomplete.append(
                    "pass-six candidate inventory differs from the exact pass-four output"
                )
                scheduler_halted = True
                budget_halted = True
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            planned_reproduction_candidates = [
                candidate
                for candidate in validation_candidates
                if candidate.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
                and validations.get(candidate.candidate_id) is not None
                and validations[candidate.candidate_id].valid
                and _project_for_candidate(candidate, solidity_projects) is not None
            ][: self.config.reproduction.max_candidates]
            configured_planners_for_schedule = [
                role
                for role in ("test_generation", "exploit_reproduction_planner")
                if role in self.config.models.specialists
            ]
            validation_falsifier_models = (
                select_validation_falsifier_models(self.config)
                if validation_candidates and not scheduler_halted
                else []
            )
            if validation_candidates and len(validation_falsifier_models) != 2:
                incomplete.append(
                    "candidate validation requires two independent falsifier lineages "
                    "that are also independent of verifier"
                )
                scheduler_halted = True
                budget_halted = True
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.CONFIGURATION
            if (
                not scheduler_halted
                and validation_candidate_workset is not None
                and not validation_candidate_workset.selected_candidate_ids
            ):
                absence = scheduler.conditional_absence(
                    reason=SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES,
                    candidate_workset=validation_candidate_workset,
                )
                empty_task = scheduler.empty_task(
                    pass_kind=(SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION),
                    scope=SchedulerScope.global_scope(),
                    task_key="no-validation-candidates",
                    role="host:conditional_absence",
                    reason=absence.reason.value,
                )
                completed_pass_six = scheduler.completed_pass_result(
                    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                    (empty_task,),
                    candidate_workset=validation_candidate_workset,
                    conditional_absence=absence,
                )
                if completed_pass_six is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                        (empty_task,),
                        candidate_workset=validation_candidate_workset,
                        conditional_absence=absence,
                    )
                assert integration_scheduler_result is not None
                if completed_pass_six is None:
                    scheduler.activate_host(
                        empty_task,
                        input_value={"absence_sha256": absence.absence_sha256},
                        upstream_results=(integration_scheduler_result,),
                    )
                    scheduler.record_empty(empty_task)
                    conclude_scheduler_pass()
                else:
                    completed_empty = scheduler.completed_result_for_task(
                        completed_pass_six,
                        empty_task,
                    )
                    if (
                        completed_empty.terminal_status
                        is not SchedulerTerminalStatus.EXPLICIT_EMPTY
                    ):
                        raise ValueError("resumed validation absence lacks explicit-empty evidence")
                    conclude_scheduler_result(completed_pass_six)
            elif not scheduler_halted:
                assert validation_candidate_workset is not None
                assert len(validation_falsifier_models) == 2
                verifier_scheduler_task = scheduled_model_task(
                    pass_kind=(SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION),
                    scope=SchedulerScope.global_scope(),
                    task_key="independent-verifier",
                    request_role="verifier",
                    configured_role="verifier",
                    request_protocol=VerifierAgent(
                        scheduler_agent_config,
                        self.client,
                    ).request_protocol,
                    candidate_ids=validation_candidate_ids,
                )
                for falsifier_index, (
                    validation_falsifier_model,
                    validation_falsifier_lineage,
                ) in enumerate(validation_falsifier_models, start=1):
                    candidate_falsifier_scheduler_tasks[falsifier_index] = scheduled_model_task(
                        pass_kind=(SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION),
                        scope=SchedulerScope.global_scope(),
                        task_key=f"candidate-falsifier-{falsifier_index}",
                        request_role="candidate_falsifier",
                        model_id=validation_falsifier_model,
                        root_lineage=validation_falsifier_lineage,
                        request_protocol=CandidateFalsifierAgent(
                            scheduler_agent_config,
                            self.client,
                            model_id=validation_falsifier_model,
                        ).request_protocol,
                        candidate_ids=validation_candidate_ids,
                    )
                validation_tasks: list[SchedulerTaskPlan] = [
                    verifier_scheduler_task,
                    *candidate_falsifier_scheduler_tasks.values(),
                ]
                if (
                    planned_reproduction_candidates
                    and self.config.reproduction.enabled
                    and fork_acknowledged
                ):
                    if configured_planners_for_schedule:
                        for planner_role in configured_planners_for_schedule:
                            request_role = f"specialist:{planner_role}:exploit_test"
                            planner_scheduler_tasks[planner_role] = scheduled_model_task(
                                pass_kind=(
                                    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
                                ),
                                scope=SchedulerScope.global_scope(),
                                task_key=f"planner-{planner_role}",
                                request_role=request_role,
                                configured_role=planner_role,
                                request_protocol=ExploitTestPlannerAgent(
                                    scheduler_agent_config,
                                    self.client,
                                    investigator_role="ensemble",
                                    planner_role=planner_role,
                                ).request_protocol,
                                candidate_ids={
                                    candidate.candidate_id
                                    for candidate in planned_reproduction_candidates
                                },
                            )
                    else:
                        for candidate_role in sorted(
                            {
                                candidate.role or "source_audit"
                                for candidate in planned_reproduction_candidates
                            }
                        ):
                            configured_role = candidate_role.removeprefix("specialist:")
                            planner_scheduler_tasks[candidate_role] = scheduled_model_task(
                                pass_kind=(
                                    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
                                ),
                                scope=SchedulerScope.global_scope(),
                                task_key=(
                                    "planner-"
                                    + scheduler_canonical_sha256(
                                        {"candidate_role": candidate_role}
                                    )[:24]
                                ),
                                request_role=f"specialist:{configured_role}:exploit_test",
                                configured_role=configured_role,
                                request_protocol=ExploitTestPlannerAgent(
                                    scheduler_agent_config,
                                    self.client,
                                    investigator_role=candidate_role,
                                ).request_protocol,
                                candidate_ids={
                                    candidate.candidate_id
                                    for candidate in planned_reproduction_candidates
                                    if (candidate.role or "source_audit") == candidate_role
                                },
                            )
                    validation_tasks.extend(planner_scheduler_tasks.values())
                    falsifier_configured_role = (
                        "falsifier" if "falsifier" in self.config.models.specialists else "verifier"
                    )
                    falsifier_scheduler_task = scheduled_model_task(
                        pass_kind=(SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION),
                        scope=SchedulerScope.global_scope(),
                        task_key="independent-falsifier",
                        request_role=(
                            "specialist:falsifier"
                            if falsifier_configured_role == "falsifier"
                            else "falsifier"
                        ),
                        configured_role=falsifier_configured_role,
                        request_protocol=FalsifierAgent(
                            scheduler_agent_config,
                            self.client,
                        ).request_protocol,
                        candidate_ids={
                            candidate.candidate_id for candidate in planned_reproduction_candidates
                        },
                    )
                    validation_tasks.append(falsifier_scheduler_task)
                reproduction_host_task = scheduler.host_task(
                    pass_kind=(SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION),
                    scope=SchedulerScope.global_scope(),
                    task_key="deterministic-reproduction",
                    role="host:reproduction",
                )
                validation_tasks.append(reproduction_host_task)
                completed_pass_six = scheduler.completed_pass_result(
                    SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                    validation_tasks,
                    candidate_workset=validation_candidate_workset,
                )
                if completed_pass_six is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION,
                        validation_tasks,
                        candidate_workset=validation_candidate_workset,
                    )
            verifier_context = None
            candidate_falsifier_contexts: dict[int, ContextPackage] = {}
            verifier_agent = VerifierAgent(scheduler_agent_config, self.client)
            prepared_verification_input = verifier_agent.prepare_input(validation_candidates)
            candidate_falsifier_agents = {
                falsifier_index: CandidateFalsifierAgent(
                    scheduler_agent_config,
                    self.client,
                    model_id=model_id,
                )
                for falsifier_index, (model_id, _lineage) in enumerate(
                    validation_falsifier_models,
                    start=1,
                )
            }
            prepared_candidate_falsification_input = verifier_agent.prepare_input(
                validation_candidates
            )
            if validation_candidates and not budget_halted and not scheduler_halted:
                assert verifier_scheduler_task is not None
                assert len(candidate_falsifier_scheduler_tasks) == 2
                assert len(candidate_falsifier_agents) == 2
                verifier_context = build_context(
                    "verifier",
                    workflow_byte_upper_bound_tokens=(
                        prepared_verification_input.workflow_byte_upper_bound_tokens
                    ),
                    workflow_prompt=prepared_verification_input.workflow_prompt,
                    threat_model=threat_model,
                    preferred_paths=preferred_paths,
                )
                if verifier_context is not None:
                    packages.append(verifier_context)
                for falsifier_index, candidate_falsifier_agent in sorted(
                    candidate_falsifier_agents.items()
                ):
                    candidate_falsifier_context = build_context(
                        "candidate_falsifier",
                        preview_models=(candidate_falsifier_agent.model_id,),
                        workflow_byte_upper_bound_tokens=(
                            prepared_candidate_falsification_input.workflow_byte_upper_bound_tokens
                        ),
                        workflow_prompt=(prepared_candidate_falsification_input.workflow_prompt),
                        threat_model=threat_model,
                        preferred_paths=preferred_paths,
                    )
                    if candidate_falsifier_context is not None:
                        packages.append(candidate_falsifier_context)
                        candidate_falsifier_contexts[falsifier_index] = candidate_falsifier_context
            if (
                validation_candidates
                and verifier_context is not None
                and not budget_halted
                and not scheduler_halted
            ):
                assert verifier_scheduler_task is not None
                try:
                    if completed_pass_six is not None:
                        completed_verifier_result = scheduler.completed_result_for_task(
                            completed_pass_six,
                            verifier_scheduler_task,
                        )
                        if (
                            completed_verifier_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                        ):
                            raise OpenRouterSchemaError(
                                "completed verifier task lacks a successful result"
                            )
                        verifier_usage = completed_usage_for_task(verifier_scheduler_task)
                        _bound_context_request_evidence(verifier_usage, verifier_context)
                        verifier_result = verifier_agent.bind_completed_review(
                            validation_candidates,
                            verifier_context,
                            raw_response=scheduler.completed_output_for_task(
                                completed_pass_six,
                                verifier_scheduler_task,
                                VerificationBatch,
                            ),
                            completion_usage=verifier_usage,
                            prepared_input=prepared_verification_input,
                        )
                    else:
                        self.logger.info(
                            "Running independent verifier",
                            extra={"run_id": run_id},
                        )
                        verifier_result = await bounded_call(
                            verifier_agent.run_with_evidence(
                                validation_candidates,
                                verifier_context,
                                prepared_input=prepared_verification_input,
                                logical_request_id=verifier_scheduler_task.logical_request_id,
                            )
                        )
                    verifications = verifier_result.value
                    omitted_verifications = [
                        decision.candidate_id
                        for decision in verifications.decisions
                        if decision.rationale == "Verifier omitted this submitted candidate"
                    ]
                    _require_exact_model_decision_inventory(
                        expected_ids=validation_candidate_ids,
                        observed_ids=[
                            decision.candidate_id
                            for decision in verifications.decisions
                            if decision.candidate_id not in omitted_verifications
                        ],
                        label="verifier",
                    )
                    pass_six_results.append(
                        completed_verifier_result
                        if completed_pass_six is not None
                        else scheduler.record_model_success(
                            verifier_scheduler_task,
                            output_value=verifier_result.raw_response,
                            usage_records=usage.records,
                        )
                    )
                except (BudgetExhaustedError, OpenRouterError) as exc:
                    pass_six_results.append(
                        scheduler.record_failure(
                            verifier_scheduler_task,
                            exc,
                            usage_records=usage.records,
                        )
                    )
                    incomplete.append(f"verifier: {exc}")
                    if isinstance(exc, BudgetExhaustedError):
                        budget_halted = True
                    terminal_code = (
                        ExitCode.INCOMPLETE
                        if isinstance(exc, BudgetExhaustedError)
                        else ExitCode.MODEL_FAILURE
                    )
                    verifications = _insufficient_verifications(validation_candidates)
            elif validation_candidates:
                verifications = _insufficient_verifications(validation_candidates)
                if verifier_scheduler_task is not None and not scheduler_halted:
                    pass_six_results.append(
                        scheduler.record_failure(
                            verifier_scheduler_task,
                            ContextBudgetError("verifier context was not produced"),
                        )
                    )
            candidate_falsifier_vote_batches: list[tuple[VerificationBatch, UsageRecord, int]] = []
            for falsifier_index, candidate_falsifier_agent in sorted(
                candidate_falsifier_agents.items()
            ):
                scheduler_task = candidate_falsifier_scheduler_tasks[falsifier_index]
                candidate_falsifier_context = candidate_falsifier_contexts.get(falsifier_index)
                if (
                    validation_candidates
                    and candidate_falsifier_context is not None
                    and not budget_halted
                    and not scheduler_halted
                ):
                    try:
                        if completed_pass_six is not None:
                            completed_candidate_falsifier_result = (
                                scheduler.completed_result_for_task(
                                    completed_pass_six,
                                    scheduler_task,
                                )
                            )
                            if (
                                completed_candidate_falsifier_result.terminal_status
                                is not SchedulerTerminalStatus.SUCCEEDED
                            ):
                                raise OpenRouterSchemaError(
                                    "completed candidate falsifier lacks a successful result"
                                )
                            candidate_falsifier_usage = completed_usage_for_task(scheduler_task)
                            _bound_context_request_evidence(
                                candidate_falsifier_usage,
                                candidate_falsifier_context,
                            )
                            candidate_falsifier_result = (
                                candidate_falsifier_agent.bind_completed_review(
                                    validation_candidates,
                                    candidate_falsifier_context,
                                    raw_response=scheduler.completed_output_for_task(
                                        completed_pass_six,
                                        scheduler_task,
                                        VerificationBatch,
                                    ),
                                    completion_usage=candidate_falsifier_usage,
                                    prepared_input=prepared_candidate_falsification_input,
                                )
                            )
                        else:
                            candidate_falsifier_result = await bounded_call(
                                candidate_falsifier_agent.run_with_evidence(
                                    validation_candidates,
                                    candidate_falsifier_context,
                                    prepared_input=prepared_candidate_falsification_input,
                                    logical_request_id=scheduler_task.logical_request_id,
                                )
                            )
                        candidate_falsifier_verifications = candidate_falsifier_result.value
                        omitted_falsifications = [
                            decision.candidate_id
                            for decision in candidate_falsifier_verifications.decisions
                            if decision.rationale == "Verifier omitted this submitted candidate"
                        ]
                        _require_exact_model_decision_inventory(
                            expected_ids=validation_candidate_ids,
                            observed_ids=[
                                decision.candidate_id
                                for decision in candidate_falsifier_verifications.decisions
                                if decision.candidate_id not in omitted_falsifications
                            ],
                            label=f"candidate falsifier {falsifier_index}",
                        )
                        pass_six_results.append(
                            completed_candidate_falsifier_result
                            if completed_pass_six is not None
                            else scheduler.record_model_success(
                                scheduler_task,
                                output_value=candidate_falsifier_result.raw_response,
                                usage_records=usage.records,
                            )
                        )
                        candidate_falsifier_vote_batches.append(
                            (
                                candidate_falsifier_verifications,
                                candidate_falsifier_result.completion_usage,
                                falsifier_index,
                            )
                        )
                    except (BudgetExhaustedError, OpenRouterError) as exc:
                        pass_six_results.append(
                            scheduler.record_failure(
                                scheduler_task,
                                exc,
                                usage_records=usage.records,
                            )
                        )
                        incomplete.append(f"candidate_falsifier:{falsifier_index}: {exc}")
                        if isinstance(exc, BudgetExhaustedError):
                            budget_halted = True
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = (
                                ExitCode.INCOMPLETE
                                if isinstance(exc, BudgetExhaustedError)
                                else ExitCode.MODEL_FAILURE
                            )
                elif validation_candidates and not scheduler_halted:
                    pass_six_results.append(
                        scheduler.record_failure(
                            scheduler_task,
                            ContextBudgetError("candidate falsifier context was not produced"),
                        )
                    )
            check_accounted_budget()
            decisions = {decision.candidate_id: decision for decision in verifications.decisions}
            candidates = _attach_verifier_votes(
                candidates,
                decisions,
                self.client,
            )
            for (
                falsifier_batch,
                falsifier_usage,
                falsifier_index,
            ) in candidate_falsifier_vote_batches:
                candidates = _attach_verifier_votes(
                    candidates,
                    {decision.candidate_id: decision for decision in falsifier_batch.decisions},
                    self.client,
                    role=f"candidate_falsifier:{falsifier_index}",
                    usage_record=falsifier_usage,
                )
            verifier_task_result = next(
                (
                    result
                    for result in pass_six_results
                    if verifier_scheduler_task is not None
                    and result.task_id == verifier_scheduler_task.task_id
                ),
                None,
            )
            candidate_falsifier_task_results = tuple(
                result
                for task in candidate_falsifier_scheduler_tasks.values()
                for result in pass_six_results
                if result.task_id == task.task_id
            )
            validation_upstream_results = tuple(
                result
                for result in (
                    verifier_task_result,
                    *candidate_falsifier_task_results,
                )
                if result is not None
            )
            if len(validation_upstream_results) == 3:
                for planner_task in planner_scheduler_tasks.values():
                    scheduler.set_upstream_results(
                        planner_task,
                        validation_upstream_results,
                    )
            eligible_for_reproduction = _eligible_reproduction_candidates(
                candidates,
                decisions,
                validations,
                limit=self.config.reproduction.max_candidates,
            )
            if (
                solidity_projects
                and planned_reproduction_candidates
                and verifier_context is not None
                and fork_acknowledged
                and self.config.reproduction.enabled
                and not budget_halted
                and not scheduler_halted
            ):
                planner_tasks: list[
                    tuple[
                        str,
                        str | None,
                        SchedulerTaskPlan,
                        ContextPackage,
                        asyncio.Task[Any],
                    ]
                ]
                planner_tasks = []
                if configured_planners_for_schedule:
                    for planner_role in configured_planners_for_schedule:
                        planner = ExploitTestPlannerAgent(
                            scheduler_agent_config,
                            self.client,
                            investigator_role="ensemble",
                            planner_role=planner_role,
                        )
                        prepared_planner_input = planner.prepare_input(
                            planned_reproduction_candidates
                        )
                        planner_context = build_specialist_context(
                            planner_role,
                            workflow_byte_upper_bound_tokens=(
                                prepared_planner_input.workflow_byte_upper_bound_tokens
                            ),
                            workflow_prompt=prepared_planner_input.workflow_prompt,
                            threat_model=threat_model,
                            preferred_paths=preferred_paths,
                        )
                        if planner_context is None:
                            break
                        packages.append(planner_context)
                        planner_tasks.append(
                            (
                                planner_role,
                                planner_role,
                                planner_scheduler_tasks[planner_role],
                                planner_context,
                                asyncio.create_task(
                                    bounded_call(
                                        planner.run_with_evidence(
                                            planned_reproduction_candidates,
                                            planner_context,
                                            prepared_input=prepared_planner_input,
                                            logical_request_id=planner_scheduler_tasks[
                                                planner_role
                                            ].logical_request_id,
                                        )
                                    ),
                                    name=f"model:{planner_role}:exploit_test",
                                ),
                            )
                        )
                else:
                    by_role: dict[str, list[CandidateFinding]] = {}
                    for candidate in planned_reproduction_candidates:
                        # Execution-origin candidates deliberately have no originating
                        # model role. A later planner may analyze them under the
                        # ordinary source-audit role without acquiring authority over
                        # their host-derived identity, location, or provenance.
                        planning_role = candidate.role or "source_audit"
                        by_role.setdefault(planning_role, []).append(candidate)
                    for role, role_candidates in sorted(by_role.items()):
                        planner = ExploitTestPlannerAgent(
                            scheduler_agent_config,
                            self.client,
                            investigator_role=role,
                        )
                        prepared_planner_input = planner.prepare_input(role_candidates)
                        configured_role = role.removeprefix("specialist:")
                        if role.startswith("specialist:"):
                            planner_context = build_specialist_context(
                                configured_role,
                                workflow_byte_upper_bound_tokens=(
                                    prepared_planner_input.workflow_byte_upper_bound_tokens
                                ),
                                workflow_prompt=prepared_planner_input.workflow_prompt,
                                threat_model=threat_model,
                                preferred_paths=preferred_paths,
                            )
                        else:
                            planner_context = build_context(
                                configured_role,
                                workflow_byte_upper_bound_tokens=(
                                    prepared_planner_input.workflow_byte_upper_bound_tokens
                                ),
                                workflow_prompt=prepared_planner_input.workflow_prompt,
                                threat_model=threat_model,
                                preferred_paths=preferred_paths,
                            )
                        if planner_context is None:
                            break
                        packages.append(planner_context)
                        planner_tasks.append(
                            (
                                role,
                                None,
                                planner_scheduler_tasks[role],
                                planner_context,
                                asyncio.create_task(
                                    bounded_call(
                                        planner.run_with_evidence(
                                            role_candidates,
                                            planner_context,
                                            prepared_input=prepared_planner_input,
                                            logical_request_id=planner_scheduler_tasks[
                                                role
                                            ].logical_request_id,
                                        )
                                    ),
                                    name=f"model:{role}:exploit_test",
                                ),
                            )
                        )
                scheduled_planner_ids = {task.task_id for task in planner_scheduler_tasks.values()}
                built_planner_ids = {item[2].task_id for item in planner_tasks}
                for missing_task in planner_scheduler_tasks.values():
                    if missing_task.task_id not in built_planner_ids:
                        pass_six_results.append(
                            scheduler.record_failure(
                                missing_task,
                                ContextBudgetError("planner context was not produced"),
                            )
                        )
                if built_planner_ids - scheduled_planner_ids:
                    raise ValueError("planner execution escaped its sealed scheduler plan")
                for (
                    planner_label,
                    specialist_role,
                    scheduler_task,
                    planner_context,
                    task,
                ) in planner_tasks:
                    try:
                        planner_result = await task
                        if planner_result is None:
                            raise OpenRouterSchemaError(
                                "scheduled planner returned no completion evidence"
                            )
                        batch = planner_result.value
                        planner_accepted_outcome: SpecialistAcceptedOutcome | None = None
                        if specialist_role is not None:
                            planner_accepted_outcome = accept_specialist_outcome(
                                completion_usage=planner_result.completion_usage,
                                validated_context=planner_context,
                                specialist_role=specialist_role,
                                request_role=f"specialist:{specialist_role}:exploit_test",
                                outcome_kind=(SpecialistAcceptedOutcomeKind.TEST_GENERATION),
                            )
                        generated_tests.extend(batch.tests)
                        pass_six_results.append(
                            scheduler.record_model_success(
                                scheduler_task,
                                output_value=planner_result.raw_response,
                                usage_records=usage.records,
                                specialist_accepted_outcome=planner_accepted_outcome,
                            )
                        )
                    except BudgetExhaustedError as exc:
                        pass_six_results.append(
                            scheduler.record_failure(
                                scheduler_task,
                                exc,
                                usage_records=usage.records,
                            )
                        )
                        incomplete.append(f"{planner_label}:exploit_test: {exc}")
                        terminal_code = ExitCode.INCOMPLETE
                        budget_halted = True
                    except OpenRouterError as exc:
                        pass_six_results.append(
                            scheduler.record_failure(
                                scheduler_task,
                                exc,
                                usage_records=usage.records,
                            )
                        )
                        incomplete.append(f"{planner_label}:exploit_test: {exc}")
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                generated_tests = _unique_generated_tests(generated_tests)[
                    : self.config.reproduction.max_total_tests
                ]
                planned_candidates_by_id = {
                    candidate.candidate_id: candidate
                    for candidate in planned_reproduction_candidates
                }
                eligible_candidate_ids = {
                    candidate.candidate_id for candidate in eligible_for_reproduction
                }
                for specification in generated_tests:
                    selected_candidate = planned_candidates_by_id.get(specification.candidate_id)
                    if selected_candidate is None:
                        raise ValueError(
                            "generated reproduction specification escaped its sealed "
                            "candidate inventory"
                        )
                    if specification.candidate_id not in eligible_candidate_ids:
                        reproductions.append(
                            _not_attempted_reproduction(
                                selected_candidate,
                                specification,
                                "candidate did not remain eligible after independent "
                                "verification; deterministic reproduction was not executed",
                            )
                        )
                        continue
                    project = _project_for_candidate(selected_candidate, solidity_projects)
                    if project is None:
                        reproductions.append(
                            _unsupported_reproduction(
                                selected_candidate,
                                specification,
                                "candidate location is not inside a detected Foundry project",
                            )
                        )
                        continue
                    reproduction = await asyncio.to_thread(
                        self.reproduction_runner.run,
                        repository_root=discovery.root,
                        project=project,
                        candidate=selected_candidate,
                        specification=specification,
                        private_dir=run_dir / "private" / "reproduction",
                    )
                    expected_chain_id = (
                        specification.expected_chain_id
                        if specification.expected_chain_id is not None
                        else self.config.reproduction.expected_chain_id
                    )
                    try:
                        expected_test_sha256 = hashlib.sha256(
                            translate_foundry_test(
                                specification,
                                targets=self.config.reproduction.targets,
                                expected_chain_id=expected_chain_id,
                            ).encode()
                        ).hexdigest()
                    except ValueError:
                        expected_test_sha256 = "0" * 64
                    reproductions.append(
                        verify_reproduction_integrity(
                            repository_root=discovery.root,
                            project=project,
                            candidate=selected_candidate,
                            specification=specification,
                            result=reproduction,
                            index=solidity_index,
                            targets=self.config.reproduction.targets,
                            expected_generated_test_sha256=expected_test_sha256,
                        )
                    )
                if falsifier_scheduler_task is not None and not budget_halted:
                    scheduler.set_upstream_results(
                        falsifier_scheduler_task,
                        pass_six_results,
                    )
                    falsifier_agent = FalsifierAgent(scheduler_agent_config, self.client)
                    prepared_falsifier_input = falsifier_agent.prepare_input(
                        candidates=planned_reproduction_candidates,
                        tests=generated_tests,
                        results=reproductions,
                    )
                    if "falsifier" in self.config.models.specialists:
                        falsifier_context = build_specialist_context(
                            "falsifier",
                            workflow_byte_upper_bound_tokens=(
                                prepared_falsifier_input.workflow_byte_upper_bound_tokens
                            ),
                            workflow_prompt=prepared_falsifier_input.workflow_prompt,
                            threat_model=threat_model,
                            preferred_paths=preferred_paths,
                        )
                    else:
                        falsifier_context = build_context(
                            "verifier",
                            workflow_byte_upper_bound_tokens=(
                                prepared_falsifier_input.workflow_byte_upper_bound_tokens
                            ),
                            workflow_prompt=prepared_falsifier_input.workflow_prompt,
                            threat_model=threat_model,
                            preferred_paths=preferred_paths,
                        )
                    if falsifier_context is not None:
                        packages.append(falsifier_context)
                    if falsifier_context is not None and not budget_halted:
                        try:
                            falsifier_result = await bounded_call(
                                falsifier_agent.run_with_evidence(
                                    candidates=planned_reproduction_candidates,
                                    tests=generated_tests,
                                    results=reproductions,
                                    context=falsifier_context,
                                    prepared_input=prepared_falsifier_input,
                                    logical_request_id=(
                                        falsifier_scheduler_task.logical_request_id
                                    ),
                                )
                            )
                            falsifier_accepted_outcome: SpecialistAcceptedOutcome | None = None
                            if "falsifier" in self.config.models.specialists:
                                falsifier_accepted_outcome = accept_specialist_outcome(
                                    completion_usage=falsifier_result.completion_usage,
                                    validated_context=falsifier_context,
                                    specialist_role="falsifier",
                                    request_role="specialist:falsifier",
                                    outcome_kind=(SpecialistAcceptedOutcomeKind.FALSIFICATION),
                                )
                            falsifications = falsifier_result.value
                            pass_six_results.append(
                                scheduler.record_model_success(
                                    falsifier_scheduler_task,
                                    output_value=falsifier_result.raw_response,
                                    usage_records=usage.records,
                                    specialist_accepted_outcome=falsifier_accepted_outcome,
                                )
                            )
                        except BudgetExhaustedError as exc:
                            pass_six_results.append(
                                scheduler.record_failure(
                                    falsifier_scheduler_task,
                                    exc,
                                    usage_records=usage.records,
                                )
                            )
                            incomplete.append(f"falsifier: {exc}")
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                        except OpenRouterError as exc:
                            pass_six_results.append(
                                scheduler.record_failure(
                                    falsifier_scheduler_task,
                                    exc,
                                    usage_records=usage.records,
                                )
                            )
                            incomplete.append(f"falsifier: {exc}")
                            if terminal_code is ExitCode.SUCCESS:
                                terminal_code = ExitCode.MODEL_FAILURE
                    elif falsifier_context is None:
                        pass_six_results.append(
                            scheduler.record_failure(
                                falsifier_scheduler_task,
                                ContextBudgetError("falsifier context was not produced"),
                            )
                        )
                candidates, decisions = _apply_reproduction_results(
                    candidates,
                    decisions,
                    reproductions,
                    falsifications,
                )
                check_accounted_budget()
            if solidity_projects and eligible_for_reproduction:
                attempted_ids = {
                    result.candidate_id for result in reproductions if result.attempts > 0
                }
                missing_attempts = {
                    candidate.candidate_id for candidate in eligible_for_reproduction
                } - attempted_ids
                if missing_attempts and self.config.quality_gates.require_candidate_reproduction:
                    incomplete.append(
                        f"candidate-specific fork reproduction was not executed for "
                        f"{len(missing_attempts)} eligible Solidity candidate(s)"
                    )
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
            if not scheduler_halted and reproduction_host_task is not None:
                planned_model_tasks = [
                    task
                    for task in (
                        verifier_scheduler_task,
                        *candidate_falsifier_scheduler_tasks.values(),
                        *planner_scheduler_tasks.values(),
                        falsifier_scheduler_task,
                    )
                    if task is not None
                ]
                terminal_task_ids = {result.task_id for result in pass_six_results}
                for planned_task in planned_model_tasks:
                    if planned_task.task_id in terminal_task_ids:
                        continue
                    pass_six_results.append(
                        scheduler.record_failure(
                            planned_task,
                            RuntimeError(
                                "scheduled validation, planning, or falsification did not execute"
                            ),
                        )
                    )
                if not any(
                    result.task_id == reproduction_host_task.task_id for result in pass_six_results
                ):
                    scheduled_reproduction_candidate_ids = list(
                        _scheduled_reproduction_candidate_ids(
                            planned_task
                            for planned_task in (
                                *planner_scheduler_tasks.values(),
                                falsifier_scheduler_task,
                            )
                            if planned_task is not None
                        )
                    )
                    reproduction_summary = {
                        "eligible_candidate_ids": scheduled_reproduction_candidate_ids,
                        "generated_test_ids": sorted(
                            f"{test.candidate_id}:{test.name}" for test in generated_tests
                        ),
                        "reproduction_result_ids": sorted(
                            f"{result.candidate_id}:{result.test_name}" for result in reproductions
                        ),
                        "falsification_decisions": len(falsifications.decisions),
                    }
                    if completed_pass_six is None:
                        scheduler.activate_host(
                            reproduction_host_task,
                            input_value=reproduction_summary,
                            upstream_results=pass_six_results,
                        )
                        try:
                            reproduction_result = scheduler.record_host_success(
                                reproduction_host_task,
                                output_value=reproduction_summary,
                            )
                        except ValueError as exc:
                            reproduction_result = scheduler.record_failure(
                                reproduction_host_task,
                                exc,
                            )
                            incomplete.append(
                                "deterministic reproduction host output did not cover its "
                                "exact scheduled candidate inventory"
                            )
                            if terminal_code is ExitCode.SUCCESS:
                                terminal_code = ExitCode.INCOMPLETE
                    else:
                        reproduction_result = scheduler.completed_result_for_task(
                            completed_pass_six,
                            reproduction_host_task,
                        )
                        if (
                            reproduction_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                            or scheduler.journal.load_output(reproduction_host_task.task_id)
                            != reproduction_summary
                        ):
                            raise ValueError(
                                "resumed reproduction summary differs from retained output"
                            )
                    pass_six_results.append(reproduction_result)
                if completed_pass_six is None:
                    conclude_scheduler_pass()
                else:
                    conclude_scheduler_result(completed_pass_six)
            groups = group_candidates(candidates)
            candidate_groups_count = len(groups)
            group_payloads = [
                _group_payload(group, decisions, validations, scanner_findings) for group in groups
            ]
            judgment_host_task: SchedulerTaskPlan | None = None
            judge_scheduler_task: SchedulerTaskPlan | None = None
            report_quality_scheduler_task: SchedulerTaskPlan | None = None
            pass_seven_results: list[SchedulerTaskResult] = []
            completed_pass_seven: SchedulerPassResult | None = None
            if not scheduler_halted:
                judgment_host_task = scheduler.host_task(
                    pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                    scope=SchedulerScope.global_scope(),
                    task_key="host-evidence-cap",
                    role="host:evidence_cap_judgment",
                )
                judgment_tasks: list[SchedulerTaskPlan] = [judgment_host_task]
                if groups:
                    judge_scheduler_task = scheduled_model_task(
                        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                        scope=SchedulerScope.global_scope(),
                        task_key="final-judge",
                        request_role="judge",
                        configured_role="judge",
                        request_protocol=JudgeAgent(
                            scheduler_agent_config,
                            self.client,
                        ).request_protocol,
                        candidate_ids={group.group_id for group in groups},
                    )
                    judgment_tasks.append(judge_scheduler_task)
                if "report_quality" in self.config.models.specialists:
                    report_quality_scheduler_task = scheduled_model_task(
                        pass_kind=SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                        scope=SchedulerScope.global_scope(),
                        task_key="report-quality",
                        request_role="specialist:report_quality",
                        configured_role="report_quality",
                        request_protocol=ReportQualityAgent(
                            scheduler_agent_config,
                            self.client,
                        ).request_protocol,
                    )
                    judgment_tasks.append(report_quality_scheduler_task)
                completed_pass_seven = scheduler.completed_pass_result(
                    SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                    judgment_tasks,
                )
                if completed_pass_seven is None:
                    scheduler.prepare_pass(
                        SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT,
                        judgment_tasks,
                    )
            judge_context = None
            judge_agent = JudgeAgent(scheduler_agent_config, self.client)
            prepared_judgment_input = judge_agent.prepare_input(
                groups=group_payloads,
                threat_model=threat_model,
            )
            if groups and not budget_halted and not scheduler_halted:
                judge_context = build_context(
                    "judge",
                    workflow_byte_upper_bound_tokens=(
                        prepared_judgment_input.workflow_byte_upper_bound_tokens
                    ),
                    workflow_prompt=prepared_judgment_input.workflow_prompt,
                    threat_model=threat_model,
                    preferred_paths=preferred_paths,
                )
                if judge_context is not None:
                    packages.append(judge_context)
            judge_decisions: dict[str, JudgeDecision] = {}
            if groups and judge_context is not None:
                assert judge_scheduler_task is not None
                try:
                    if completed_pass_seven is not None:
                        completed_judge_result = scheduler.completed_result_for_task(
                            completed_pass_seven,
                            judge_scheduler_task,
                        )
                        if (
                            completed_judge_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                        ):
                            raise OpenRouterSchemaError(
                                "completed judge task lacks a successful result"
                            )
                        judge_usage = completed_usage_for_task(judge_scheduler_task)
                        _bound_context_request_evidence(judge_usage, judge_context)
                        judgment = scheduler.completed_output_for_task(
                            completed_pass_seven,
                            judge_scheduler_task,
                            JudgeDecisionBatch,
                        )
                    else:
                        self.logger.info("Running final judge", extra={"run_id": run_id})
                        judgment = await bounded_call(
                            judge_agent.run(
                                groups=group_payloads,
                                context=judge_context,
                                threat_model=threat_model,
                                prepared_input=prepared_judgment_input,
                                logical_request_id=judge_scheduler_task.logical_request_id,
                            )
                        )
                    returned_group_ids = [decision.group_id for decision in judgment.decisions]
                    expected_group_ids = {group.group_id for group in groups}
                    _require_exact_model_decision_inventory(
                        expected_ids=expected_group_ids,
                        observed_ids=returned_group_ids,
                        label="judge",
                    )
                    judge_decisions = {
                        decision.group_id: decision for decision in judgment.decisions
                    }
                    pass_seven_results.append(
                        completed_judge_result
                        if completed_pass_seven is not None
                        else scheduler.record_model_success(
                            judge_scheduler_task,
                            output_value=judgment,
                            usage_records=usage.records,
                        )
                    )
                except (BudgetExhaustedError, OpenRouterError) as exc:
                    pass_seven_results.append(
                        scheduler.record_failure(
                            judge_scheduler_task,
                            exc,
                            usage_records=usage.records,
                        )
                    )
                    incomplete.append(f"judge: {exc}")
                    if isinstance(exc, BudgetExhaustedError):
                        budget_halted = True
                    terminal_code = (
                        ExitCode.INCOMPLETE
                        if isinstance(exc, BudgetExhaustedError)
                        else ExitCode.MODEL_FAILURE
                    )
            elif groups and judge_scheduler_task is not None and not scheduler_halted:
                pass_seven_results.append(
                    scheduler.record_failure(
                        judge_scheduler_task,
                        ContextBudgetError("judge context was not produced"),
                    )
                )
            check_accounted_budget()
            # Revalidate after the last model call so stale line references cannot
            # survive a repository change during a long audit.
            validations = {
                candidate.candidate_id: _deterministic_candidate_validation(
                    discovery.root,
                    candidate,
                    context_hashes=_candidate_origin_source_hashes(
                        candidate_origin_packages,
                        candidate,
                    ),
                )
                for candidate in candidates
            }
            for group in groups:
                finding = merge_group(
                    group,
                    decisions=decisions,
                    validations=validations,
                    scanner_findings=scanner_findings,
                    judge=judge_decisions.get(group.group_id),
                )
                finding = enforce_critical_evidence_cap(
                    finding,
                    require_formal_or_reproduction=(
                        self.config.maximum_assurance.require_formal_or_reproduction_for_confirmed_critical
                    ),
                )
                (
                    finding,
                    post_judge_accounting_candidates,
                    post_judge_limitation,
                ) = _enforce_post_judge_execution_severity_accounting(
                    group=group,
                    finding=finding,
                    judge=judge_decisions.get(group.group_id),
                    pre_judgment_high_critical_ids=pre_judgment_high_critical_ids,
                )
                if post_judge_limitation is not None:
                    incomplete.append(post_judge_limitation)
                    post_judge_execution_severity_candidates.update(
                        {
                            candidate.candidate_id: candidate
                            for candidate in post_judge_accounting_candidates
                        }
                    )
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.INCOMPLETE
                judge_vote = _judge_vote(
                    judge_decisions.get(group.group_id),
                    self.client,
                )
                if judge_vote is not None:
                    finding = finding.model_copy(
                        update={"model_votes": [*finding.model_votes, judge_vote]}
                    )
                if finding.status is FindingStatus.REJECTED:
                    rejected_findings.append(finding)
                elif (
                    finding.origin_kind is FindingOriginKind.DETERMINISTIC_EXECUTION
                    or SEVERITY_ORDER[finding.severity.value]
                    >= SEVERITY_ORDER[severity_threshold.value]
                ):
                    final_findings.append(finding)
                else:
                    filtered_findings.append(finding)

            if not scheduler_halted:
                assert judgment_host_task is not None
                if not pass_four_candidate_projection_frozen:
                    raise ValueError(
                        "evidence-cap judgment lacks the frozen pass-four candidate projection"
                    )
                if pending_execution_candidates and not execution_candidates_integrated:
                    raise ValueError(
                        "evidence-cap judgment cannot precede deterministic candidate integration"
                    )
                terminal_source_contents = {
                    item.relative_path: item.content for item in discovery.files
                }
                final_findings = _bind_terminal_finding_source_ranges(
                    final_findings,
                    source_contents=terminal_source_contents,
                    label="active",
                )
                filtered_findings = _bind_terminal_finding_source_ranges(
                    filtered_findings,
                    source_contents=terminal_source_contents,
                    label="reporting-filtered",
                )
                terminal_findings = [
                    *(("REPORTED_ACTIVE", finding) for finding in final_findings),
                    *(("REPORTED_REJECTED", finding) for finding in rejected_findings),
                    *(("FILTERED_BELOW_THRESHOLD", finding) for finding in filtered_findings),
                ]
                terminal_findings_by_group: dict[str, tuple[str, Finding]] = {}
                for disposition, finding in terminal_findings:
                    if finding.group_id is None or finding.group_id in terminal_findings_by_group:
                        raise ValueError(
                            "evidence-cap judgment requires one terminal finding per group"
                        )
                    terminal_findings_by_group[finding.group_id] = (disposition, finding)
                if set(terminal_findings_by_group) != {group.group_id for group in groups}:
                    raise ValueError(
                        "evidence-cap judgment terminal findings differ from reduced groups"
                    )

                def evidence_payload_binding(
                    *,
                    kind: Literal[
                        "judge",
                        "verification",
                        "cross_examination",
                        "falsification",
                        "reproduction",
                        "reproduction_resolution",
                    ],
                    subject_id: str,
                    payload: Any,
                ) -> dict[str, str]:
                    return SchedulerEvidencePayloadBinding.build(
                        kind=kind,
                        subject_id=subject_id,
                        payload=payload,
                    ).model_dump(mode="json")

                judgment_reproduction_resolutions = _build_candidate_reproduction_resolutions(
                    candidates=candidates,
                    results=reproductions,
                    forced_candidate_ids=set(post_judge_execution_severity_candidates),
                )
                terminal_finding_records = [
                    {
                        "group_id": group.group_id,
                        "candidate_ids": sorted(
                            candidate.candidate_id for candidate in group.candidates
                        ),
                        "finding_id": terminal_findings_by_group[group.group_id][1].id,
                        "finding_payload_sha256": scheduler_canonical_sha256(
                            terminal_findings_by_group[group.group_id][1].model_dump(mode="json")
                        ),
                        "state": terminal_findings_by_group[group.group_id][0],
                        "finding_status": (
                            terminal_findings_by_group[group.group_id][1].status.value
                        ),
                        "finding_severity": (
                            terminal_findings_by_group[group.group_id][1].severity.value
                        ),
                        "finding_origin_kind": (
                            terminal_findings_by_group[group.group_id][1].origin_kind.value
                        ),
                    }
                    for group in sorted(groups, key=lambda item: item.group_id)
                ]
                judgment_body: dict[str, Any] = {
                    "schema_version": "2.0",
                    "algorithm": "mmaudit.evidence-cap-terminal-authority.v2",
                    "severity_threshold": severity_threshold.value,
                    "group_ids": sorted(group.group_id for group in groups),
                    "judge_decision_ids": sorted(judge_decisions),
                    "candidate_ids": sorted(
                        candidate.candidate_id for candidate in pass_four_candidates
                    ),
                    "candidate_payload_sha256s": _candidate_payload_sha256s(pass_four_candidates),
                    "candidate_grouping_sha256": scheduler_canonical_sha256(
                        [
                            {
                                "group_id": record["group_id"],
                                "candidate_ids": record["candidate_ids"],
                            }
                            for record in terminal_finding_records
                        ]
                    ),
                    "terminal_findings": terminal_finding_records,
                    "final_finding_ids": sorted(finding.id for finding in final_findings),
                    "rejected_finding_ids": sorted(finding.id for finding in rejected_findings),
                    "filtered_finding_ids": sorted(finding.id for finding in filtered_findings),
                    "final_finding_payload_sha256s": {
                        finding.id: scheduler_canonical_sha256(finding.model_dump(mode="json"))
                        for finding in sorted(final_findings, key=lambda item: item.id)
                    },
                    "rejected_finding_payload_sha256s": {
                        finding.id: scheduler_canonical_sha256(finding.model_dump(mode="json"))
                        for finding in sorted(rejected_findings, key=lambda item: item.id)
                    },
                    "filtered_finding_payload_sha256s": {
                        finding.id: scheduler_canonical_sha256(finding.model_dump(mode="json"))
                        for finding in sorted(filtered_findings, key=lambda item: item.id)
                    },
                    "judge_decisions": sorted(
                        (
                            evidence_payload_binding(
                                kind="judge",
                                subject_id=decision.group_id,
                                payload=decision,
                            )
                            for decision in judge_decisions.values()
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                    "verification_decisions": sorted(
                        (
                            evidence_payload_binding(
                                kind="verification",
                                subject_id=decision.candidate_id,
                                payload=decision,
                            )
                            for decision in verifications.decisions
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                    "cross_examination_decisions": sorted(
                        (
                            evidence_payload_binding(
                                kind="cross_examination",
                                subject_id=decision.candidate_id,
                                payload=decision,
                            )
                            for decision in cross_examinations
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                    "falsification_decisions": sorted(
                        (
                            evidence_payload_binding(
                                kind="falsification",
                                subject_id=decision.candidate_id,
                                payload=decision,
                            )
                            for decision in falsifications.decisions
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                    "reproduction_results": sorted(
                        (
                            evidence_payload_binding(
                                kind="reproduction",
                                subject_id=result.candidate_id,
                                payload=result,
                            )
                            for result in reproductions
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                    "reproduction_resolutions": sorted(
                        (
                            evidence_payload_binding(
                                kind="reproduction_resolution",
                                subject_id=resolution.candidate_id,
                                payload=resolution,
                            )
                            for resolution in judgment_reproduction_resolutions
                        ),
                        key=lambda item: (item["subject_id"], item["record_id"]),
                    ),
                }
                judgment_summary = {
                    **judgment_body,
                    "judgment_sha256": scheduler_canonical_sha256(judgment_body),
                }
                if completed_pass_seven is None:
                    scheduler.activate_host(
                        judgment_host_task,
                        input_value=judgment_summary,
                        upstream_results=pass_seven_results,
                    )
                    if any(
                        result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
                        for result in pass_seven_results
                    ):
                        judgment_result = scheduler.record_failure(
                            judgment_host_task,
                            RuntimeError(
                                "evidence-cap judgment depends on an incomplete scheduled result"
                            ),
                        )
                    else:
                        judgment_result = scheduler.record_host_success(
                            judgment_host_task,
                            output_value=judgment_summary,
                        )
                else:
                    judgment_result = scheduler.completed_result_for_task(
                        completed_pass_seven,
                        judgment_host_task,
                    )
                    if (
                        judgment_result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED
                        or scheduler.journal.load_output(judgment_host_task.task_id)
                        != judgment_summary
                    ):
                        raise ValueError(
                            "resumed evidence-cap judgment differs from retained output"
                        )
                pass_seven_results.append(judgment_result)

        if pending_execution_candidates and not execution_candidates_integrated:
            candidates.extend(pending_execution_candidates)
            validations.update(
                {
                    candidate.candidate_id: _deterministic_candidate_validation(
                        discovery.root,
                        candidate,
                        context_hashes=_candidate_origin_source_hashes(
                            candidate_origin_packages,
                            candidate,
                        ),
                    )
                    for candidate in pending_execution_candidates
                }
            )
            execution_groups = group_candidates(pending_execution_candidates)
            candidate_groups_count += len(execution_groups)
            for group in execution_groups:
                finding = merge_group(
                    group,
                    decisions={},
                    validations=validations,
                    scanner_findings=scanner_findings,
                    judge=None,
                )
                finding = enforce_critical_evidence_cap(
                    finding,
                    require_formal_or_reproduction=(
                        self.config.maximum_assurance.require_formal_or_reproduction_for_confirmed_critical
                    ),
                )
                if finding.status is FindingStatus.REJECTED:
                    rejected_findings.append(finding)
                else:
                    final_findings.append(finding)

        assurance_high_critical_candidates_by_id = {
            candidate.candidate_id: candidate
            for candidate in candidates
            if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
            and (validation := validations.get(candidate.candidate_id)) is not None
            and validation.valid
        }
        assurance_high_critical_candidates_by_id.update(
            {
                candidate_id: candidate
                for candidate_id, candidate in post_judge_execution_severity_candidates.items()
                if (validation := validations.get(candidate_id)) is not None and validation.valid
            }
        )
        assurance_high_critical_candidates = sorted(
            assurance_high_critical_candidates_by_id.values(),
            key=lambda candidate: candidate.candidate_id,
        )
        runtime_eligible_candidates_by_id = {
            candidate.candidate_id: candidate for candidate in eligible_for_reproduction
        }
        runtime_eligible_candidates_by_id.update(post_judge_execution_severity_candidates)
        runtime_eligible_candidates = sorted(
            runtime_eligible_candidates_by_id.values(),
            key=lambda candidate: candidate.candidate_id,
        )
        reproduction_resolutions = _build_candidate_reproduction_resolutions(
            candidates=candidates,
            results=reproductions,
            forced_candidate_ids=set(post_judge_execution_severity_candidates),
        )
        unchanged = _repository_unchanged(discovery)
        if not unchanged:
            incomplete.append("audited source changed during the run")
            terminal_code = ExitCode.SCANNER_FAILURE
        if solidity_coverage is not None:
            solidity_coverage = with_invariant_review_coverage(
                solidity_coverage,
                invariant_review,
            )
            solidity_coverage = _record_reproduction_attempts(
                solidity_coverage,
                reproductions,
            )
        private_model_review_path = run_dir / "private" / "model-review-artifacts.json"
        write_json(
            private_model_review_path,
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "artifacts": [
                    artifact.model_dump(mode="json")
                    for artifact in sorted(
                        model_surface_review_artifacts,
                        key=lambda item: item.request_id,
                    )
                ],
            },
        )
        private_model_review_path.chmod(0o600)
        provider_session = _provider_session_provenance(
            client=self.client,
            pipeline_owned=self._owns_client,
            usage_records=usage.records,
        )
        model_credit_usage = (
            usage.records
            if provider_session is None or provider_session.usage_evidence_consistent
            else []
        )
        model_review_coverage = build_model_review_coverage(
            self.config,
            usage_records=model_credit_usage,
            review_artifacts=model_surface_review_artifacts,
            review_contexts_by_request=model_surface_review_contexts,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        if solidity_coverage is not None:
            solidity_coverage = with_model_review_coverage(
                solidity_coverage,
                solidity_index,
                model_review_coverage,
                solidity_graphs,
            )
        quality_gates = _evaluate_quality_gates(
            config=self.config,
            solidity_projects=solidity_projects,
            compilations=solidity_compilations,
            scanner_runs=scanner_runs,
            coverage=solidity_coverage,
            model_review_coverage=model_review_coverage,
            scope_assessment=scope_assessment,
            prior_audit_comparison=prior_audit_comparison,
            invariant_executions=invariant_executions,
            eligible_candidates=runtime_eligible_candidates,
            reproductions=reproductions,
            usage_roles={
                record.role
                for record in usage.records
                if is_creditable_usage_record(record)
                and (
                    not record.role.startswith("specialist:")
                    or record.request_id
                    in {outcome.request_id for outcome in accepted_specialist_outcomes}
                )
            },
            scanner_only=scanner_only,
            model_surface_assignment_gate=model_surface_assignment_gate,
            repository_execution_sha256=repository_execution_sha256,
        )
        if (
            not scanner_only
            and context_builder is not None
            and self.client is not None
            and "report_quality" in self.config.models.specialists
            and not budget_halted
            and not scheduler_halted
        ):
            assert report_quality_scheduler_task is not None
            evidence_cap_result = next(
                result
                for result in pass_seven_results
                if judgment_host_task is not None and result.task_id == judgment_host_task.task_id
            )
            if completed_pass_seven is None:
                scheduler.set_upstream_results(
                    report_quality_scheduler_task,
                    (evidence_cap_result,),
                )
            try:
                report_quality_agent = ReportQualityAgent(
                    scheduler_agent_config,
                    self.client,
                )
                prepared_report_quality_input = report_quality_agent.prepare_input(
                    findings=final_findings,
                    rejected_count=len(rejected_findings),
                    coverage=solidity_coverage,
                    quality_gates=quality_gates,
                    incomplete_reasons=incomplete,
                )
                report_quality_context = build_specialist_context(
                    "report_quality",
                    workflow_byte_upper_bound_tokens=(
                        prepared_report_quality_input.workflow_byte_upper_bound_tokens
                    ),
                    workflow_prompt=prepared_report_quality_input.workflow_prompt,
                    threat_model=threat_model,
                    preferred_paths={
                        location.path
                        for finding in [*final_findings, *rejected_findings]
                        for location in finding.locations
                    },
                )
                if report_quality_context is not None:
                    packages.append(report_quality_context)
                    if completed_pass_seven is not None:
                        completed_report_quality_result = scheduler.completed_result_for_task(
                            completed_pass_seven,
                            report_quality_scheduler_task,
                        )
                        if (
                            completed_report_quality_result.terminal_status
                            is not SchedulerTerminalStatus.SUCCEEDED
                        ):
                            raise OpenRouterSchemaError(
                                "completed report-quality task lacks a successful result"
                            )
                        report_quality_usage = completed_usage_for_task(
                            report_quality_scheduler_task
                        )
                        _bound_context_request_evidence(
                            report_quality_usage,
                            report_quality_context,
                        )
                        report_quality_review = scheduler.completed_output_for_task(
                            completed_pass_seven,
                            report_quality_scheduler_task,
                            ReportQualityReview,
                        )
                    else:
                        report_quality_result = await report_quality_agent.run_with_evidence(
                            findings=final_findings,
                            rejected_count=len(rejected_findings),
                            coverage=solidity_coverage,
                            quality_gates=quality_gates,
                            incomplete_reasons=incomplete,
                            context=report_quality_context,
                            prepared_input=prepared_report_quality_input,
                            logical_request_id=(report_quality_scheduler_task.logical_request_id),
                        )
                        report_quality_usage = report_quality_result.completion_usage
                        report_quality_review = report_quality_result.value
                    report_quality_accepted_outcome = accept_specialist_outcome(
                        completion_usage=report_quality_usage,
                        validated_context=report_quality_context,
                        specialist_role="report_quality",
                        request_role="specialist:report_quality",
                        outcome_kind=SpecialistAcceptedOutcomeKind.REPORT_QUALITY,
                    )
                    if completed_pass_seven is None:
                        pass_seven_results.append(
                            scheduler.record_model_success(
                                report_quality_scheduler_task,
                                output_value=report_quality_result.raw_response,
                                usage_records=usage.records,
                                specialist_accepted_outcome=(report_quality_accepted_outcome),
                            )
                        )
                    else:
                        require_completed_specialist_outcome(
                            report_quality_scheduler_task,
                            report_quality_accepted_outcome,
                        )
                        pass_seven_results.append(completed_report_quality_result)
            except ContextBudgetError as exc:
                pass_seven_results.append(
                    scheduler.record_failure(
                        report_quality_scheduler_task,
                        exc,
                        usage_records=usage.records,
                    )
                )
                incomplete.append(f"report_quality: {exc}")
                budget_halted = True
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            except BudgetExhaustedError as exc:
                pass_seven_results.append(
                    scheduler.record_failure(
                        report_quality_scheduler_task,
                        exc,
                        usage_records=usage.records,
                    )
                )
                incomplete.append(f"report_quality: {exc}")
                budget_halted = True
                terminal_code = ExitCode.INCOMPLETE
            except OpenRouterError as exc:
                pass_seven_results.append(
                    scheduler.record_failure(
                        report_quality_scheduler_task,
                        exc,
                        usage_records=usage.records,
                    )
                )
                incomplete.append(f"report_quality: {exc}")
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.MODEL_FAILURE
        if (
            self._active_scheduler is not None
            and not scheduler_halted
            and judgment_host_task is not None
        ):
            if report_quality_scheduler_task is not None and not any(
                result.task_id == report_quality_scheduler_task.task_id
                for result in pass_seven_results
            ):
                pass_seven_results.append(
                    scheduler.record_failure(
                        report_quality_scheduler_task,
                        RuntimeError("scheduled report-quality review did not execute"),
                    )
                )
            if completed_pass_seven is None:
                conclude_scheduler_pass()
            else:
                conclude_scheduler_result(completed_pass_seven)
        terminal_source_contents = {item.relative_path: item.content for item in discovery.files}
        final_findings = _bind_terminal_finding_source_ranges(
            final_findings,
            source_contents=terminal_source_contents,
            label="active",
        )
        filtered_findings = _bind_terminal_finding_source_ranges(
            filtered_findings,
            source_contents=terminal_source_contents,
            label="reporting-filtered",
        )
        public_candidate_projection = [
            CandidateFinding.model_validate(candidate.model_dump(mode="python"))
            for candidate in (
                pass_four_candidates if pass_four_candidate_projection_frozen else candidates
            )
        ]
        if self._active_scheduler is not None:
            scheduler.seal_terminal_report_authority(
                severity_threshold=severity_threshold,
                candidates=public_candidate_projection,
                final_findings=final_findings,
                rejected_findings=rejected_findings,
                filtered_findings=filtered_findings,
                report_quality_review=report_quality_review,
                verification_decisions=verifications.decisions,
                cross_examination_decisions=cross_examinations,
                falsification_decisions=falsifications.decisions,
                reproduction_results=reproductions,
                reproduction_resolutions=reproduction_resolutions,
            )
            scheduler_artifact = scheduler.artifact()
            scheduler_report_binding = scheduler.report_binding().model_dump(mode="json")
            if resume_scheduler_journal is not None:
                retained_reference = SchedulerRetainedJournalReference.from_artifact(
                    owner_run_id=resume_scheduler_journal.parent.parent.name,
                    consumer_run_id=run_id,
                    artifact=scheduler_artifact,
                )
                write_json(
                    run_dir / "private" / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME,
                    retained_reference,
                )
        retained_scheduler_usage_ids = (
            {
                record.request_id
                for record in self._active_scheduler.journal.restorable_usage_records
            }
            if self._active_scheduler is not None
            else set()
        )
        observed_usage_ids = {record.request_id for record in usage.records}
        successful_scheduler_review_ids = (
            {
                record.request_id
                for record in self._active_scheduler.journal.restorable_review_usage_records
            }
            if self._active_scheduler is not None
            else observed_usage_ids
        )
        structurally_successful_scheduler_review_ids = (
            {
                record.request_id
                for record in (
                    self._active_scheduler.journal.structurally_successful_review_usage_records
                )
            }
            if self._active_scheduler is not None
            else observed_usage_ids
        )
        scheduler_usage_accounting_consistent = self._active_scheduler is None or (
            observed_usage_ids == retained_scheduler_usage_ids
            and successful_scheduler_review_ids <= retained_scheduler_usage_ids
            and structurally_successful_scheduler_review_ids <= retained_scheduler_usage_ids
        )
        if not scheduler_usage_accounting_consistent:
            incomplete.append(
                "provider usage differs from exact retained scheduler accounting evidence"
            )
            terminal_code = ExitCode.MODEL_FAILURE
        provider_session = _provider_session_provenance(
            client=self.client,
            pipeline_owned=self._owns_client,
            usage_records=usage.records,
        )
        model_credit_usage = (
            [
                record
                for record in usage.records
                if record.request_id in successful_scheduler_review_ids
                and is_creditable_usage_record(record, require_real=True)
            ]
            if (
                scheduler_usage_accounting_consistent
                and (provider_session is None or provider_session.usage_evidence_consistent)
            )
            else []
        )
        model_review_accounting_usage = (
            [
                record
                for record in usage.records
                if record.request_id in structurally_successful_scheduler_review_ids
            ]
            if (
                scheduler_usage_accounting_consistent
                and (provider_session is None or provider_session.usage_evidence_consistent)
            )
            else []
        )
        if provider_session is not None and not provider_session.usage_evidence_consistent:
            mismatch_reason = (
                "provider usage execution evidence differs from the established session"
            )
            if mismatch_reason not in incomplete:
                incomplete.append(mismatch_reason)
            terminal_code = ExitCode.MODEL_FAILURE
        model_review_coverage = build_model_review_coverage(
            self.config,
            usage_records=model_review_accounting_usage,
            review_artifacts=model_surface_review_artifacts,
            review_contexts_by_request=model_surface_review_contexts,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
            audited_suite_coverage=solidity_coverage.audited_suite_coverage,
            source_contents_by_path=solidity_source_contents_by_path,
        )
        if solidity_coverage is not None:
            solidity_coverage = with_model_review_coverage(
                solidity_coverage,
                solidity_index,
                model_review_coverage,
                solidity_graphs,
            )
        specialist_execution_records = build_specialist_execution_records(
            self.config,
            usage_records=(list(usage.records) if scheduler_usage_accounting_consistent else []),
            contexts=packages,
            accepted_outcomes=tuple(
                outcome
                for outcome in accepted_specialist_outcomes
                if scheduler_usage_accounting_consistent
                and outcome.request_id in structurally_successful_scheduler_review_ids
            ),
            structurally_successful_request_ids=(
                {
                    record.request_id
                    for record in usage.records
                    if record.request_id in structurally_successful_scheduler_review_ids
                    and canonical_specialist_role(record.role) is not None
                }
                if scheduler_usage_accounting_consistent
                else set()
            ),
        )
        write_json(
            run_dir / "specialist-execution.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "records": [
                    record.model_dump(mode="json") for record in specialist_execution_records
                ],
            },
        )
        raw_successful_usage_roles = {
            record.role for record in model_credit_usage if is_creditable_usage_record(record)
        }
        successful_specialist_roles = completed_specialist_roles(specialist_execution_records)
        successful_usage_roles = {
            request_role
            for request_role in raw_successful_usage_roles
            if (
                (
                    (specialist_role := canonical_specialist_role(request_role)) is None
                    and not request_role.startswith("specialist:")
                )
                or specialist_role in successful_specialist_roles
            )
        }
        if solidity_coverage is not None:
            high_critical_candidate_ids = {
                candidate.candidate_id for candidate in assurance_high_critical_candidates
            }
            configured_model_roles = {
                "threat_model",
                "source_audit",
                "business_logic",
                "configuration",
                *{
                    f"specialist:{role}"
                    for role in self.config.models.specialists
                    if role in SPECIALIST_INVESTIGATOR_ROLES
                    or role in {"invariant_review", "report_quality"}
                },
            }
            if candidates:
                configured_model_roles.add("verifier")
            if candidate_groups_count:
                configured_model_roles.add("judge")
            if runtime_eligible_candidates:
                configured_model_roles.update(
                    {
                        "specialist:test_generation",
                        "specialist:exploit_reproduction_planner",
                    }
                    & {f"specialist:{role}" for role in self.config.models.specialists}
                )
            if high_critical_candidate_ids and "falsifier" in self.config.models.specialists:
                configured_model_roles.add("specialist:falsifier")
            completed_configured_roles = {
                expected
                for expected in configured_model_roles
                if any(
                    actual == expected
                    or actual.startswith(f"{expected}:")
                    or (expected == "specialist:falsifier" and actual == "falsifier")
                    for actual in successful_usage_roles
                )
            }
            solidity_coverage = with_runtime_coverage(
                solidity_coverage,
                eligible_candidate_ids={
                    candidate.candidate_id for candidate in runtime_eligible_candidates
                },
                attempted_candidate_ids={
                    result.candidate_id for result in reproductions if result.attempts > 0
                },
                economic_plans=economic_simulations,
                invariant_executions=invariant_executions,
                formal_runs=formal_runs,
                expected_model_roles=len(configured_model_roles),
                completed_model_roles=len(completed_configured_roles),
            )
        prior_audit_comparison = build_prior_audit_comparison(
            repository_root=discovery.root,
            config=self.config.prior_audit,
            discovery=discovery,
            candidates=candidates,
            candidate_validations=validations,
            findings=[*final_findings, *rejected_findings],
            model_request_count_before_load=len(usage.records),
            prior_material_withheld_from_discovery=(prior_material_withheld_from_discovery),
        )
        write_json(
            run_dir / "prior-audit-comparison.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "comparison": prior_audit_comparison.model_dump(mode="json"),
            },
        )
        quality_gates = _evaluate_quality_gates(
            config=self.config,
            solidity_projects=solidity_projects,
            compilations=solidity_compilations,
            scanner_runs=scanner_runs,
            coverage=solidity_coverage,
            model_review_coverage=model_review_coverage,
            scope_assessment=scope_assessment,
            prior_audit_comparison=prior_audit_comparison,
            invariant_executions=invariant_executions,
            eligible_candidates=runtime_eligible_candidates,
            reproductions=reproductions,
            usage_roles=successful_usage_roles,
            scanner_only=scanner_only,
            model_surface_assignment_gate=model_surface_assignment_gate,
            repository_execution_sha256=repository_execution_sha256,
        )
        high_critical = {candidate.candidate_id for candidate in assurance_high_critical_candidates}
        feasible_high_critical = {
            candidate.candidate_id
            for candidate in assurance_high_critical_candidates
            if candidate.candidate_id in high_critical
            and _project_for_candidate(candidate, solidity_projects) is not None
            and fork_acknowledged
            and isolation_available
        }
        documented_infeasible = {
            result.candidate_id
            for result in reproductions
            if result.candidate_id in high_critical
            and result.attempts == 0
            and bool(result.limitations)
        }
        artifact_names = {path.name for path in run_dir.iterdir() if path.is_file()} | {
            "scanner-results.json",
            "solidity-coverage.json",
            "solidity-invariants.json",
            "invariant-review.json",
            "invariant-harness-plan.json",
            "property-corpus.json",
            "invariant-execution-results.json",
            "economic-simulation-plan.json",
            "formal-results.json",
            "reproduction-results.json",
            "execution-origin-dispositions.json",
            "cross-examination.json",
            "specialist-execution.json",
            "model-review-coverage.json",
            "scope-assessment.json",
            "prior-audit-comparison.json",
            "maximum_assurance_traceability.json",
            "run-evidence-manifest.json",
            *({"scheduler-state.json"} if scheduler_artifact is not None else set()),
        }
        traceability = build_traceability_matrix(repository_map.git_commit)
        maximum_assurance = assurance_contract.evaluate(
            AssuranceRuntime(
                repository_execution_sha256=repository_execution_sha256,
                projects=solidity_projects,
                compilations=solidity_compilations,
                index=solidity_index,
                graphs=solidity_graphs,
                scanners=scanner_runs,
                invariants=solidity_invariants,
                expected_invariant_harnesses={
                    (
                        harness.invariant_id,
                        harness.name,
                        harness.specification_sha256(),
                    )
                    for harness in invariant_harnesses
                },
                invariant_executions=invariant_executions,
                economic_simulations=economic_simulations,
                formal_runs=formal_runs,
                property_corpus_sha256=property_corpus.corpus_hash,
                property_corpus_property_ids={
                    property_spec.id for property_spec in property_corpus.properties
                },
                property_corpus_property_hashes={
                    property_spec.id: property_spec.property_hash
                    for property_spec in property_corpus.properties
                },
                reproduction_results=reproductions,
                reproduction_resolutions=reproduction_resolutions,
                eligible_high_critical_ids=high_critical,
                feasible_high_critical_ids=feasible_high_critical,
                documented_infeasible_ids=documented_infeasible,
                model_roles_completed=successful_usage_roles,
                specialist_roles_completed=(
                    successful_specialist_roles & set(SPECIALIST_INVESTIGATOR_ROLES)
                ),
                auxiliary_roles_completed=(
                    successful_specialist_roles & set(SPECIALIST_AUXILIARY_ROLES)
                ),
                specialist_execution_records=specialist_execution_records,
                verifier_completed=("verifier" in successful_usage_roles or not candidates),
                falsifier_completed=(
                    "falsifier" in successful_specialist_roles or not high_critical
                ),
                candidate_falsifier_request_ids={
                    candidate_id: {
                        decision.request_id
                        for decision in cross_examinations
                        if decision.candidate_id == candidate_id
                    }
                    for candidate_id in sorted(high_critical)
                },
                judge_completed=("judge" in successful_usage_roles or candidate_groups_count == 0),
                coverage=solidity_coverage,
                model_review_coverage=model_review_coverage,
                model_surface_review_artifacts=model_surface_review_artifacts,
                model_usage=usage.records,
                provider_session=provider_session,
                production_qualification=self.production_qualification,
                scope_assessment=scope_assessment,
                benchmark_verification=benchmark_verification,
                benchmark_repository_git_commit=benchmark_repository_git_commit,
                isolation_available=isolation_available,
                scanner_only=scanner_only,
                artifacts=artifact_names,
                traceability=traceability,
                scheduler_artifact=scheduler_artifact,
                expected_scheduler_bindings=scheduler_bindings,
                expected_scheduler_analysis_input_sha256=(scheduler_analysis_input_sha256),
                expected_scheduler_cost_ledger_baseline=scheduler_cost_ledger_baseline,
                expected_scheduler_shard_inventory=scheduler_inventory,
            )
        )
        if maximum_assurance.downgraded:
            incomplete.extend(
                f"maximum-assurance downgraded: {reason}"
                for reason in maximum_assurance.downgrade_reasons
                if f"maximum-assurance downgraded: {reason}" not in incomplete
            )
        elif (
            maximum_assurance.status.value in {"FAILED", "INCONCLUSIVE"}
            and terminal_code is ExitCode.SUCCESS
        ):
            incomplete.extend(
                f"maximum-assurance contract failed: {requirement.engine}: {requirement.detail}"
                for requirement in maximum_assurance.requirements
                if requirement.required and not requirement.passed
            )
            terminal_code = ExitCode.INCOMPLETE

        if ci_mode:
            ci_suite = build_ci_repository_suite_evidence(
                projects=solidity_projects,
                scanner_runs=scanner_runs,
            )
            ci_execution_failures: list[str] = []
            if scanner_source_sha256 is None:
                ci_execution_failures.append(
                    "CI scanner workspace identity could not be established"
                )
            if ci_suite.status is CIRepositorySuiteStatus.FAILED:
                ci_execution_failures.extend(
                    f"CI repository suite failed: {failure}" for failure in ci_suite.failures
                )
            for failure in ci_execution_failures:
                if failure not in incomplete:
                    incomplete.append(failure)
            if ci_execution_failures and terminal_code is ExitCode.SUCCESS:
                terminal_code = ExitCode.INCOMPLETE

        failed_required_pre_floor = [
            gate for gate in quality_gates if gate.required and not gate.passed
        ]
        maximum_downgrade_authorized = (
            self.config.profile is AuditProfile.MAXIMUM_ASSURANCE
            and assurance_contract.allow_downgrade
            and maximum_assurance.downgraded
        )
        if (
            failed_required_pre_floor
            and terminal_code is ExitCode.SUCCESS
            and not maximum_downgrade_authorized
        ):
            incomplete.extend(
                f"quality gate failed: {gate.gate}: {gate.detail}"
                for gate in failed_required_pre_floor
            )
            terminal_code = ExitCode.INCOMPLETE

        explicit_downgrade_reason: str | None = None
        if scanner_only:
            explicit_downgrade_reason = "operator selected scanner-only reduced analysis"
        elif maximum_downgrade_authorized:
            explicit_downgrade_reason = "operator pre-authorized maximum-assurance downgrade"
        surface_analysis_feasible = (
            not solidity_projects
            or scanner_only
            or model_surface_assignment_gate.passed
            or (maximum_downgrade_authorized and lower_profile_surface_gate.passed)
        )
        model_review_applicable = not scanner_only
        minimum_analysis_floor = assess_minimum_analysis_floor(
            repository=repository_map,
            compilations=solidity_compilations,
            scanner_runs=scanner_runs,
            usage=model_credit_usage,
            required_model_roles=(ANALYSIS_ROLES if model_review_applicable else ()),
            coverage_metrics=(
                deterministic_ci_coverage_metrics(solidity_coverage.quality_metrics)
                if ci_mode and solidity_coverage is not None
                else (solidity_coverage.quality_metrics if solidity_coverage is not None else {})
            ),
            solidity_applicable=bool(solidity_projects),
            static_analysis_applicable=bool(solidity_projects) or scanner_only,
            model_review_applicable=model_review_applicable,
            scanner_only=scanner_only,
            explicit_downgrade_reason=explicit_downgrade_reason,
            surface_analysis_feasible=surface_analysis_feasible,
            surface_feasibility_reasons=(
                () if surface_analysis_feasible else (model_surface_assignment_gate.detail,)
            ),
            orchestration_failures=(() if terminal_code is ExitCode.SUCCESS else tuple(incomplete)),
        )
        minimum_floor_gate = minimum_analysis_floor_quality_gate(minimum_analysis_floor)
        quality_gates = [*quality_gates, minimum_floor_gate]
        if minimum_analysis_floor.run_status in {
            AuditRunStatus.INCOMPLETE,
            AuditRunStatus.FAILED,
        }:
            floor_reason = (
                f"quality gate failed: minimum_analysis_floor: {minimum_floor_gate.detail}"
            )
            if floor_reason not in incomplete:
                incomplete.append(floor_reason)
            if terminal_code is ExitCode.SUCCESS:
                terminal_code = ExitCode.INCOMPLETE
        elif minimum_analysis_floor.run_status is AuditRunStatus.DEGRADED:
            degraded_reason = (
                f"run degraded by explicit operator authorization: {explicit_downgrade_reason}"
            )
            if degraded_reason not in incomplete:
                incomplete.append(degraded_reason)
        quality_status = audit_quality_status_for_run_status(minimum_analysis_floor.run_status)
        context_manifest = build_context_manifest(
            run_id=run_id,
            usage_records=usage.records,
            preflight_records=(
                self.client.context_preflight.records
                if self.client is not None and not scanner_only
                else ()
            ),
        )
        ci_metadata: dict[str, Any] | None = None
        if ci_mode:
            assert ci_producer_digest is not None
            assert ci_policy_digest is not None
            ci_metadata = {
                "schema_version": "1.0",
                "enabled": True,
                "scanner_workspace_sha256": scanner_source_sha256,
                "producer_sha256": ci_producer_digest,
                "deterministic_policy_sha256": ci_policy_digest,
                "baseline_state_sha256": (
                    ci_baseline.state.state_sha256 if ci_baseline is not None else None
                ),
                "baseline_manifest_sha256": (
                    ci_baseline.manifest.manifest_sha256 if ci_baseline is not None else None
                ),
            }
        audited_source_contents = {item.relative_path: item.content for item in discovery.files}
        cost_ledger_evidence: RunCostLedgerEvidence | None = None
        if scheduler_cost_ledger_baseline is not None:
            if scheduler_artifact is None:
                raise ValueError("scheduler cost baseline lacks its campaign artifact")
            if effective_cost_ledger is None:
                raise ValueError("scheduler cost baseline lacks its live terminal ledger")
            cost_ledger_evidence = build_run_cost_ledger_evidence(
                baseline=scheduler_cost_ledger_baseline,
                final_snapshot=effective_cost_ledger.snapshot(),
                campaign_logical_request_ids=tuple(
                    item.logical_request_id for item in scheduler_artifact.model_requests
                ),
                usage_records=usage.records,
            )
        exact_accounted_cost = (
            Decimal(cost_ledger_evidence.run_accounted_cost_usd_exact)
            if cost_ledger_evidence is not None
            else sum(
                (
                    Decimal(record.accounted_cost_usd_exact)
                    if record.accounted_cost_usd_exact is not None
                    else Decimal(str(record.accounted_cost_usd))
                    for record in usage.records
                ),
                start=Decimal(0),
            )
        )
        exact_accounted_cost_text = format(exact_accounted_cost, "f")
        if "." in exact_accounted_cost_text:
            exact_accounted_cost_text = exact_accounted_cost_text.rstrip("0").rstrip(".")
        exact_accounted_cost_text = exact_accounted_cost_text or "0"
        report = self._build_report(
            run_id=run_id,
            generated_at=datetime.now(UTC),
            run_started_at=run_started_at,
            duration_seconds=time.monotonic() - run_started_monotonic,
            time_to_first_candidate_seconds=time_to_first_candidate_seconds,
            completed=minimum_analysis_floor.run_status is AuditRunStatus.COMPLETE,
            incomplete=incomplete,
            run_options=run_options,
            repository_map=repository_map,
            scanner_runs=scanner_runs,
            repository_suite_differential=repository_suite_differential,
            usage=usage,
            findings=final_findings,
            rejected=rejected_findings,
            filtered=filtered_findings,
            scanner_only=scanner_only,
            code_egress_enabled=(
                not scanner_only and (self.config.privacy.allow_code_egress or allow_code_egress)
            ),
            severity_threshold=severity_threshold,
            threat_model=threat_model,
            threat_location_rejections=threat_location_rejections,
            context_withheld_files=context_withheld_files,
            allow_fork_probing=allow_fork_probing,
            solidity_projects=solidity_projects,
            solidity_compilations=solidity_compilations,
            dependency_preparation=dependency_preparation,
            solidity_index=solidity_index,
            solidity_graphs=solidity_graphs,
            solidity_shard_binding=solidity_shard_binding,
            solidity_invariants=solidity_invariants,
            property_corpus=property_corpus,
            invariant_review=invariant_review,
            invariant_executions=invariant_executions,
            execution_candidate_build=execution_candidate_build,
            economic_simulations=economic_simulations,
            formal_runs=formal_runs,
            solidity_coverage=solidity_coverage,
            model_review_coverage=model_review_coverage,
            scope_assessment=scope_assessment,
            prior_audit_comparison=prior_audit_comparison,
            generated_tests=generated_tests,
            reproductions=reproductions,
            verifications=verifications,
            cross_examinations=cross_examinations,
            falsifications=falsifications,
            quality_gates=quality_gates,
            quality_status=quality_status,
            run_status=minimum_analysis_floor.run_status,
            minimum_analysis_floor=minimum_analysis_floor,
            maximum_assurance=maximum_assurance,
            report_quality_review=report_quality_review,
            context_manifest=context_manifest,
            ci_metadata=ci_metadata,
            scheduler_report_binding=scheduler_report_binding,
            accounted_cost_usd_exact=exact_accounted_cost_text,
        )
        report = bind_active_finding_source_locations(report, audited_source_contents)
        ci_state: CIRunState | None = None
        if ci_mode:
            assert ci_producer_digest is not None
            ci_evidence = build_ci_evidence_from_report(
                report=report,
                config=self.config,
                run_options=run_options,
                scanner_workspace_sha256=scanner_source_sha256,
                projects=solidity_projects,
                producer_sha256=ci_producer_digest,
            )
            ci_state = build_ci_run_state(
                ci_evidence,
                baseline=(ci_baseline.state if ci_baseline is not None else None),
                baseline_manifest_sha256=(
                    ci_baseline.manifest.manifest_sha256 if ci_baseline is not None else None
                ),
            )
            report_metadata = dict(report.metadata)
            report_ci_metadata = dict(report_metadata["ci"])
            comparison = ci_state.comparison
            report_ci_metadata.update(
                {
                    "job_status": ci_state.job_status.value,
                    "analysis_failures": list(ci_state.analysis_failures),
                    "new_findings": (
                        len(comparison.new_finding_ids)
                        if comparison is not None
                        else len(ci_state.evidence.findings)
                    ),
                    "unchanged_findings": (
                        len(comparison.unchanged_finding_ids) if comparison is not None else 0
                    ),
                    "resolved_findings": (
                        len(comparison.resolved_finding_ids) if comparison is not None else 0
                    ),
                    "coverage_regressions": (
                        len(comparison.coverage_regressions) if comparison is not None else 0
                    ),
                    "whole_run_reuse_eligible": (
                        comparison.whole_run_reuse_eligible if comparison is not None else False
                    ),
                    "historical_evidence_use": "comparison_only_after_current_execution",
                }
            )
            report_metadata["ci"] = report_ci_metadata
            report = AuditReport.model_validate(
                {
                    **report.model_dump(mode="python"),
                    "metadata": report_metadata,
                }
            )
        log_handler.flush()
        self._write_artifacts(
            run_dir=run_dir,
            report=report,
            source_contents=audited_source_contents,
            candidate_projection=public_candidate_projection,
            verifications=verifications,
            cross_examinations=cross_examinations,
            threat_model=threat_model,
            threat_location_rejections=threat_location_rejections,
            solidity_index=solidity_index,
            solidity_graphs=solidity_graphs,
            solidity_invariants=solidity_invariants,
            invariant_review=invariant_review,
            invariant_executions=invariant_executions,
            formal_runs=formal_runs,
            solidity_coverage=solidity_coverage,
            model_review_coverage=model_review_coverage,
            scope_assessment=scope_assessment,
            prior_audit_comparison=prior_audit_comparison,
            generated_tests=generated_tests,
            reproductions=reproductions,
            reproduction_resolutions=reproduction_resolutions,
            falsifications=falsifications,
            run_options=run_options,
            context_manifest=context_manifest,
            ci_state=ci_state,
            scheduler_artifact=scheduler_artifact,
            scheduler_runtime_journal=(
                self._active_scheduler.journal if self._active_scheduler is not None else None
            ),
            cost_ledger=effective_cost_ledger,
            cost_ledger_evidence=cost_ledger_evidence,
        )
        self.logger.removeHandler(log_handler)
        log_handler.close()
        return PipelineResult(
            report=report,
            run_dir=run_dir,
            exit_code=terminal_code,
            ci_state=ci_state,
        )

    async def _execute_invariant_harnesses(
        self,
        *,
        discovery: DiscoveryResult,
        projects: list[SolidityProjectMetadata],
        index: SoliditySymbolIndex | None,
        suite: InvariantSuite | None,
        economic_simulations: list[EconomicSimulationPlan],
        harnesses: list[FoundryInvariantHarnessSpec],
        run_dir: Path,
        fork_acknowledged: bool,
    ) -> list[InvariantExecutionResult]:
        """Validate configured harness bindings before any isolated execution."""

        if not harnesses:
            return []
        invariants = {
            invariant.id: invariant for invariant in (suite.invariants if suite is not None else [])
        }
        indexed_names = {entity.name for entity in index.entities} if index is not None else set()
        results: list[InvariantExecutionResult] = []
        for harness in harnesses:
            invariant = invariants.get(harness.invariant_id)
            error = _invariant_harness_validation_error(
                harness,
                invariant_exists=invariant is not None,
                indexed_names=indexed_names,
                targets=set(self.config.reproduction.targets),
                planned_economic_templates={
                    plan.kind: plan.required_transaction_ordering
                    for plan in economic_simulations
                    if plan.applicable
                },
            )
            project = (
                _project_for_path(invariant.locations[0].path, projects)
                if invariant is not None and invariant.locations
                else None
            )
            if error is None and project is None:
                error = "invariant evidence is not inside a detected Foundry project"
            base = {
                "invariant_id": harness.invariant_id,
                "harness_name": harness.name,
                "harness_spec_sha256": harness.specification_sha256(),
                "runs": harness.runs,
                "depth": harness.depth,
                "seed": harness.seed,
                "economic_template": harness.economic_template,
                "required_transaction_ordering": harness.required_transaction_ordering,
            }
            if error is not None:
                results.append(
                    InvariantExecutionResult(
                        **base,
                        status=InvariantExecutionStatus.GENERATION_FAILED,
                        limitations=[error],
                    )
                )
            elif not self.config.invariants.execute_generated:
                results.append(
                    InvariantExecutionResult(
                        **base,
                        status=InvariantExecutionStatus.NOT_ATTEMPTED,
                        limitations=["generated invariant execution is disabled by configuration"],
                    )
                )
            elif not fork_acknowledged and not harness.local_deployments:
                results.append(
                    InvariantExecutionResult(
                        **base,
                        status=InvariantExecutionStatus.ENVIRONMENT_BLOCKED,
                        limitations=[
                            "typed invariant execution requires explicit local-fork acknowledgement"
                        ],
                    )
                )
            else:
                assert project is not None
                results.append(
                    await asyncio.to_thread(
                        self.invariant_runner.run,
                        repository_root=discovery.root,
                        project=project,
                        specification=harness,
                        private_dir=run_dir / "private" / "invariants",
                    )
                )
        return results

    def _write_model_qualification_runtime(
        self,
        run_dir: Path,
        *,
        required: bool,
    ) -> ProductionQualificationValidation:
        """Persist deterministic qualification evidence before any provider transport."""

        cache_dir = _safe_output_directory(self.output, "cache")
        registry = ModelRegistry(cache_dir / "openrouter-models.json")
        validation = registry.validate_production_qualification(
            self.config,
            self.production_qualification,
            required=required,
            now=datetime.now(UTC).replace(microsecond=0),
        )
        write_json(
            run_dir / "model-qualification-runtime.json",
            validation.as_dict(),
        )
        return validation

    async def _validate_models(
        self,
        run_dir: Path,
        *,
        refresh: bool,
        source_egress_requested: bool,
        qualification_preflight: ProductionQualificationValidation | None = None,
    ) -> None:
        assert self.client is not None
        cache_dir = _safe_output_directory(self.output, "cache")
        registry = ModelRegistry(cache_dir / "openrouter-models.json")
        provider_policy = self.client.provider_policy
        qualification_required = production_model_qualification_required(
            self.config,
            execution_evidence=self._planned_model_execution_evidence(),
        )
        qualification_validation = (
            qualification_preflight
            if qualification_preflight is not None
            else self._write_model_qualification_runtime(
                run_dir,
                required=qualification_required,
            )
        )
        if not qualification_validation.valid:
            raise OpenRouterError("; ".join(qualification_validation.errors))
        qualification_now = qualification_validation.observed_at
        if source_egress_requested and self.effective_privacy_policy is None:
            raise OpenRouterError("source egress lacks resolved effective privacy evidence")
        if source_egress_requested and not provider_policy.configured_endpoints:
            raise OpenRouterError("source egress requires an explicit provider endpoint allowlist")
        real_provider_client = (
            trusted_openrouter_execution_evidence(self.client) is ExecutionEvidenceKind.REAL
        )
        models_payload: dict[str, Any] | None = None
        models = None if refresh or real_provider_client else registry.load_cache()
        if real_provider_client:
            await self.client.validate_authentication()
            models_payload = await self.client.get_certification_model_metadata()
            raw_models = models_payload.get("data")
            if not isinstance(raw_models, list):
                raise OpenRouterError("certification model metadata omitted the model catalog")
            models = list(raw_models)
            registry.save_cache(models)
        elif models is None:
            models = await self.client.list_models()
            registry.save_cache(models)
        assert models is not None
        zdr_ids: set[str] | None = None
        zdr_payload: dict[str, Any] | None = None
        if self.config.privacy.require_zdr or real_provider_client:
            zdr_payload = await self.client.list_zdr_endpoints()
            zdr_ids = extract_zdr_model_ids(zdr_payload)
            if self.config.privacy.require_zdr and not zdr_ids:
                raise OpenRouterError(
                    "ZDR endpoint eligibility could not be verified; refusing code egress"
                )
        errors = registry.validate(
            self.config,
            models,
            zdr_model_ids=zdr_ids,
            source_egress_requested=source_egress_requested,
            production_qualification=self.production_qualification,
            require_verified_qualification=qualification_required,
            qualification_now=qualification_now,
        )
        if errors:
            raise OpenRouterError("; ".join(errors))
        endpoint_snapshots = []
        single_model_payloads: dict[str, dict[str, Any]] = {}
        endpoint_payloads: dict[str, dict[str, Any]] = {}
        discovery_payloads = []
        approved_endpoint_by_model: dict[str, str] = {}
        qualified_models = (
            {model.exact_model_id: model for model in self.production_qualification.models}
            if self.production_qualification is not None
            else {}
        )
        if provider_policy.configured_endpoints:
            for model_id in sorted(set(configured_model_ids(self.config, include_fallbacks=True))):
                qualified_model = qualified_models.get(model_id)
                if qualification_required and qualified_model is None:
                    raise OpenRouterError(
                        f"exact model lacks current production qualification: {model_id}"
                    )
                configured_endpoints = (
                    (qualified_model.approved_provider_endpoint,)
                    if qualified_model is not None
                    else provider_policy.configured_endpoints
                )
                if real_provider_client and len(configured_endpoints) != 1:
                    raise OpenRouterError(
                        "identity-bound real execution requires one exact provider endpoint "
                        f"per model: {model_id}"
                    )
                policy_mode: Literal["only", "order"] = (
                    "only" if qualified_model is not None or provider_policy.only else "order"
                )
                single_model_payload: dict[str, Any] | None = None
                if real_provider_client:
                    assert models_payload is not None
                    openrouter_catalog_canonical_slug(
                        exact_model_id=model_id,
                        models_payload=models_payload,
                    )
                    single_model_payload = await self.client.get_model_metadata(model_id)
                    single_model_payloads[model_id] = single_model_payload
                endpoint_payload = await self.client.get_model_endpoint_metadata(model_id)
                endpoint_payloads[model_id] = endpoint_payload
                try:
                    snapshot = validate_openrouter_endpoint_snapshot(
                        exact_model_id=model_id,
                        configured_provider_endpoints=configured_endpoints,
                        provider_policy_mode=policy_mode,
                        endpoint_payload=endpoint_payload,
                        require_zdr=self.config.privacy.require_zdr,
                        zdr_payload=zdr_payload,
                        reasoning_requested=False,
                        structured_output_required=False,
                    )
                except EndpointSnapshotValidationError as exc:
                    raise OpenRouterError(
                        f"exact provider endpoint validation failed for {model_id}: {exc}"
                    ) from None
                endpoint_snapshots.append(snapshot)
                if real_provider_client:
                    assert models_payload is not None
                    assert single_model_payload is not None
                    approved_endpoint_by_model[model_id] = configured_endpoints[0]
                    discovery_payloads.append(
                        validate_openrouter_model_discovery(
                            exact_model_id=model_id,
                            models_payload=models_payload,
                            single_model_payload=single_model_payload,
                            endpoint_snapshot=snapshot,
                            effective_privacy_policy=self.effective_privacy_policy,
                        )
                    )
                else:
                    self.client.register_endpoint_snapshot(evidence=snapshot)
        if real_provider_client:
            assert models_payload is not None
            assert zdr_payload is not None
            _provenance, discovery_evidence = self.client.seal_real_model_discovery_run(
                run_id=uuid.uuid4().hex,
                retrieved_at=datetime.now(UTC).replace(microsecond=0),
                models_payload=models_payload,
                zdr_payload=zdr_payload,
                single_model_payloads=single_model_payloads,
                endpoint_payloads=endpoint_payloads,
                candidate_routes=tuple(
                    DiscoveryCandidateRoute(
                        exact_model_id=model_id,
                        approved_provider_endpoint=approved_endpoint_by_model[model_id],
                    )
                    for model_id in sorted(approved_endpoint_by_model)
                ),
                payloads=tuple(sorted(discovery_payloads, key=lambda item: item.exact_model_id)),
            )
            for evidence in discovery_evidence:
                self.client.register_model_discovery(evidence=evidence)
        write_json(
            run_dir / "model-validation.json",
            {
                "validated_at": datetime.now(UTC).isoformat(),
                "configured_models": _configured_models(self.config),
                "model_lineages": [
                    lineage.model_dump(mode="json") for lineage in self.config.models.registry
                ],
                "zdr_required": self.config.privacy.require_zdr,
                "effective_privacy_policy": (
                    self.effective_privacy_policy.model_dump(mode="json")
                    if self.effective_privacy_policy is not None
                    else None
                ),
                "endpoint_snapshots": [
                    snapshot.model_dump(mode="json") for snapshot in endpoint_snapshots
                ],
                "production_qualification": qualification_validation.as_dict(),
                "source_egress_policy": {
                    "requested": source_egress_requested,
                    "maximum_retention": self.config.privacy.maximum_model_retention,
                    "approved_root_lineages": list(self.config.privacy.approved_model_lineages),
                },
            },
        )

    def _create_run_dir(self) -> tuple[str, Path]:
        timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        suffix = uuid.uuid4().hex[:8]
        run_id = f"{timestamp}-{suffix}"
        runs_root = _safe_output_directory(self.output, "runs")
        run_dir = runs_root / run_id
        run_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        (run_dir / "logs").mkdir(mode=0o700)
        (run_dir / "private").mkdir(mode=0o700)
        return run_id, run_dir

    async def _execute_repository_fork_matrix(
        self,
        *,
        repository_root: Path,
        private_root: Path,
        projects: list[SolidityProjectMetadata],
        repository_sha256: str | None,
        repository_exclusion_root: Path | None,
        scanner_runs: list[ScannerRun],
    ) -> RepositorySuiteDifferentialRun:
        """Run a configured matrix separately from the qualifying scanner portfolio."""

        suite = self.config.smart_contracts.repository_suite

        def failed(detail: str) -> RepositorySuiteDifferentialRun:
            return RepositorySuiteDifferentialRun.sealed(
                status=RepositoryDifferentialRunStatus.FAILED,
                configuration_sha256=suite.stable_hash(),
                requested_state_ids=tuple(state.state_id for state in suite.fork_matrix_states),
                required_repetitions=suite.fork_matrix_repetitions,
                matrix=None,
                limitations=(detail,),
            )

        if repository_sha256 is None or repository_exclusion_root is None:
            return failed("The repository execution identity was unavailable.")
        baseline_runs = [run for run in scanner_runs if run.scanner == "foundry_fork"]
        if len(baseline_runs) != 1:
            return failed("Exactly one qualifying baseline Foundry run was not available.")
        backend = getattr(self.scanner_runner, "backend", None)
        if backend is None:
            backend = getattr(self.reproduction_runner, "backend", None)
        if backend is None:
            return failed("The configured hardened isolation backend was unavailable.")
        try:
            timeout_budget_seconds = repository_fork_matrix_timeout_budget_seconds(suite)
            absolute_deadline = time.monotonic() + timeout_budget_seconds
            observed = await asyncio.to_thread(
                self.repository_fork_matrix_runner.run,
                repository_root,
                private_root,
                projects=projects,
                repository_sha256=repository_sha256,
                repository_exclusion_root=repository_exclusion_root,
                backend=backend,
                baseline_run=baseline_runs[0],
                absolute_deadline=absolute_deadline,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return failed(
                f"The configured repository suite differential failed safely: {type(exc).__name__}."
            )
        if observed is None:
            return failed("The configured repository suite differential emitted no result.")
        if (
            observed.configuration_sha256 != suite.stable_hash()
            or observed.requested_state_ids
            != tuple(state.state_id for state in suite.fork_matrix_states)
            or observed.required_repetitions != suite.fork_matrix_repetitions
        ):
            return failed(
                "The repository suite differential result differed from its effective "
                "configuration."
            )
        return observed

    def _build_report(
        self,
        *,
        run_id: str,
        generated_at: datetime,
        run_started_at: datetime,
        duration_seconds: float,
        time_to_first_candidate_seconds: float | None,
        completed: bool,
        incomplete: list[str],
        run_options: AuditRunOptions,
        repository_map: Any,
        scanner_runs: list[ScannerRun],
        repository_suite_differential: RepositorySuiteDifferentialRun | None,
        usage: UsageLedger,
        findings: list[Finding],
        rejected: list[Finding],
        filtered: list[Finding],
        scanner_only: bool,
        code_egress_enabled: bool,
        severity_threshold: Severity,
        threat_model: ThreatModel | None,
        threat_location_rejections: list[str],
        context_withheld_files: int,
        allow_fork_probing: bool,
        solidity_projects: list[SolidityProjectMetadata],
        solidity_compilations: list[SolidityCompilationResult],
        dependency_preparation: DependencyPreparationRun,
        solidity_index: SoliditySymbolIndex | None,
        solidity_graphs: SolidityGraphSet | None,
        solidity_shard_binding: SolidityShardReportBinding | None,
        solidity_invariants: InvariantSuite | None,
        property_corpus: PropertyCorpus,
        invariant_review: InvariantReviewResult | None,
        invariant_executions: list[InvariantExecutionResult],
        execution_candidate_build: ExecutionCandidateBuildResult,
        economic_simulations: list[EconomicSimulationPlan],
        formal_runs: list[FormalToolRun],
        solidity_coverage: SolidityCoverage | None,
        model_review_coverage: ModelReviewCoverage,
        scope_assessment: AuditScopeAssessment,
        prior_audit_comparison: PriorAuditComparison,
        generated_tests: list[GeneratedFoundryTestSpec],
        reproductions: list[ReproductionResult],
        verifications: VerificationBatch,
        cross_examinations: list[CandidateCrossExaminationDecision],
        falsifications: FalsificationBatch,
        quality_gates: list[QualityGateResult],
        quality_status: AuditQualityStatus,
        run_status: AuditRunStatus,
        minimum_analysis_floor: MinimumAnalysisFloor,
        maximum_assurance: MaximumAssuranceAssessment,
        report_quality_review: ReportQualityReview | None,
        context_manifest: ContextManifest,
        ci_metadata: dict[str, Any] | None,
        scheduler_report_binding: dict[str, Any] | None,
        accounted_cost_usd_exact: str,
    ) -> AuditReport:
        fork_probing_enabled = self.config.smart_contracts.enabled and (
            self.config.smart_contracts.allow_fork_probing or allow_fork_probing
        )
        fork_rpc_privacy = (
            RepositoryForkRpcPrivacyEvidence.from_differential(repository_suite_differential)
            if repository_suite_differential is not None
            else None
        )
        return AuditReport(
            schema_version=AUDIT_REPORT_SCHEMA_VERSION,
            run_id=run_id,
            generated_at=generated_at,
            completed=completed,
            incomplete_reasons=incomplete,
            repository=repository_map,
            configuration_hash=self.config.stable_hash(),
            model_configuration_hash=self.config.model_hash(),
            privacy={
                **self.config.privacy.model_dump(mode="json"),
                "code_egress_enabled": code_egress_enabled,
                "effective_policy": (
                    self.effective_privacy_policy.model_dump(mode="json")
                    if self.effective_privacy_policy is not None
                    else None
                ),
                "source_provenance": (
                    self.privacy_source_provenance.model_dump(mode="json")
                    if self.privacy_source_provenance is not None
                    else None
                ),
                **(
                    {"fork_rpc_egress": fork_rpc_privacy.model_dump(mode="json")}
                    if fork_rpc_privacy is not None
                    else {}
                ),
            },
            scanner_runs=scanner_runs,
            repository_suite_differential=repository_suite_differential,
            usage=sorted(usage.records, key=lambda record: record.request_id),
            budget_usd=self.config.execution.budget_usd,
            accounted_cost_usd=float(Decimal(accounted_cost_usd_exact)),
            accounted_cost_usd_exact=accounted_cost_usd_exact,
            findings=findings,
            rejected_findings=rejected,
            filtered_findings=filtered,
            audit_profile=self.config.profile,
            quality_status=quality_status,
            run_status=run_status,
            minimum_analysis_floor=minimum_analysis_floor,
            quality_gates=quality_gates,
            scope_assessment=scope_assessment,
            prior_audit_comparison=prior_audit_comparison,
            maximum_assurance=maximum_assurance,
            verification_decisions=verifications.decisions,
            cross_examination_decisions=cross_examinations,
            falsification_decisions=falsifications.decisions,
            reproductions=reproductions,
            invariants=solidity_invariants,
            invariant_review=invariant_review,
            invariant_executions=invariant_executions,
            execution_origin_dispositions=list(execution_candidate_build.dispositions),
            economic_simulations=economic_simulations,
            formal_runs=formal_runs,
            solidity_coverage=solidity_coverage,
            model_review_coverage=model_review_coverage,
            report_quality_review=report_quality_review,
            metadata={
                "tool_version": "0.1.0",
                "run_started_at": run_started_at.isoformat(),
                "duration_seconds": duration_seconds,
                "time_to_first_candidate_seconds": time_to_first_candidate_seconds,
                "python": platform.python_version(),
                "platform": platform.system(),
                "scanner_only": scanner_only,
                "run_options": run_options.model_dump(mode="json"),
                "configuration_provenance": {
                    "file_config_sha256": self.file_config.stable_hash(),
                    "environment_overrides_sha256": self.environment_overrides.stable_hash(),
                    "cli_overrides_sha256": self.cli_overrides.stable_hash(),
                    "run_options_sha256": run_options.stable_hash(),
                },
                "scope": scope_assessment.model_dump(mode="json"),
                "prior_audit": {
                    "configured": prior_audit_comparison.configured,
                    "required": prior_audit_comparison.required,
                    "loaded": prior_audit_comparison.loaded,
                    "findings_compared": len(prior_audit_comparison.items),
                    "blind_discovery_completed_before_load": (
                        prior_audit_comparison.blind_discovery_completed_before_load
                    ),
                },
                "severity_threshold": severity_threshold.value,
                "configured_models": _configured_models(self.config),
                "configured_fallbacks": {
                    role: list(self.config.models.role(role).fallbacks)
                    for role in [
                        "threat_model",
                        "source_audit",
                        "business_logic",
                        "configuration",
                        "verifier",
                        "judge",
                        *sorted(self.config.models.specialists),
                    ]
                },
                "threat_model_generated": threat_model is not None,
                "threat_model_location_rejections": len(threat_location_rejections),
                "context_files_withheld_by_secret_safeguards": context_withheld_files,
                "context_manifest": context_manifest_report_binding(context_manifest).model_dump(
                    mode="json"
                ),
                "context_preflight_records": [
                    request.model_dump(mode="json")
                    for request in context_manifest.requests
                    if isinstance(request, ContextPreflightRequestEvidence)
                ],
                **(
                    {"scheduler": scheduler_report_binding}
                    if scheduler_report_binding is not None
                    else {}
                ),
                "raw_material_stored": (
                    self.config.privacy.store_raw_prompts or self.config.privacy.store_raw_responses
                ),
                **({"ci": ci_metadata} if ci_metadata is not None else {}),
                "smart_contracts": {
                    "detected": bool(solidity_projects),
                    "enabled": self.config.smart_contracts.enabled,
                    "compile_enabled": self.config.smart_contracts.compile,
                    "allow_network": self.config.smart_contracts.allow_network,
                    "fork_only": self.config.smart_contracts.fork_only,
                    "fork_probing_enabled": fork_probing_enabled,
                    "fork_rpc_url_env": self.config.smart_contracts.fork_rpc_url_env,
                    "fork_rpc_url_present": bool(
                        os.environ.get(self.config.smart_contracts.fork_rpc_url_env)
                    ),
                    "require_local_fork_rpc": self.config.smart_contracts.require_local_fork_rpc,
                    "foundry_match_path": self.config.smart_contracts.foundry_match_path,
                    "foundry_match_test": self.config.smart_contracts.foundry_match_test,
                    "foundry_fuzz_runs": self.config.smart_contracts.foundry_fuzz_runs,
                    "foundry_invariant_runs": self.config.smart_contracts.foundry_invariant_runs,
                },
                "dependency_preparation": {
                    "enabled": self.config.dependency_preparation.enabled,
                    "required": self.config.dependency_preparation.required,
                    "results": [
                        result.model_dump(mode="json") for result in dependency_preparation.results
                    ],
                    "sbom_documents": len(dependency_preparation.sboms),
                },
                "solidity": {
                    "projects": [project.model_dump(mode="json") for project in solidity_projects],
                    "compilation": [
                        result.model_dump(mode="json") for result in solidity_compilations
                    ],
                    "index_summary": {
                        "entities": len(solidity_index.entities) if solidity_index else 0,
                        "ast_sources": len(solidity_index.ast_sources) if solidity_index else 0,
                        "fallback_sources": len(solidity_index.fallback_sources)
                        if solidity_index
                        else 0,
                    },
                    "graph_summary": {
                        "edges": len(solidity_graphs.edges) if solidity_graphs else 0,
                        "warnings": len(solidity_graphs.warnings) if solidity_graphs else 0,
                    },
                    "shard_summary": (
                        solidity_shard_binding.model_dump(mode="json")
                        if solidity_shard_binding is not None
                        else None
                    ),
                    "invariant_summary": {
                        "discovered": (
                            len(solidity_invariants.invariants) if solidity_invariants else 0
                        ),
                        "executable": (len(invariant_executions)),
                        "executed": sum(
                            result.status
                            in {
                                InvariantExecutionStatus.PASSED,
                                InvariantExecutionStatus.COUNTEREXAMPLE,
                            }
                            for result in invariant_executions
                        ),
                        "protocol_profiles": (
                            solidity_invariants.protocol_profiles if solidity_invariants else []
                        ),
                        "model_review_proposals": (
                            len(invariant_review.accepted_proposals)
                            if invariant_review is not None
                            else 0
                        ),
                        "model_review_rejections": (
                            len(invariant_review.rejected_proposals)
                            if invariant_review is not None
                            else 0
                        ),
                    },
                    "property_corpus_summary": {
                        "properties": len(property_corpus.properties),
                        "limitations": len(property_corpus.limitations),
                        "corpus_hash": property_corpus.corpus_hash,
                    },
                    "execution_origin_summary": {
                        "originated_candidates": len(execution_candidate_build.candidates),
                        "rejected_counterexamples": (
                            execution_candidate_build.rejected_counterexample_count
                        ),
                        "limitations": list(execution_candidate_build.limitations),
                    },
                    "economic_simulation_summary": {
                        "planned": len(economic_simulations),
                        "executed": len(
                            {
                                result.economic_template
                                for result in invariant_executions
                                if result.economic_template is not None
                                and result.status
                                in {
                                    InvariantExecutionStatus.PASSED,
                                    InvariantExecutionStatus.COUNTEREXAMPLE,
                                }
                            }
                        ),
                        "replayed": len(
                            {
                                result.economic_template
                                for result in invariant_executions
                                if result.economic_template is not None and result.replay_confirmed
                            }
                        ),
                        "counterexamples_minimized": sum(
                            result.economic_template is not None
                            and result.minimization_evidence is not None
                            and result.minimization_evidence.proven_minimal
                            for result in invariant_executions
                        ),
                        "by_template": {
                            kind.value: evidence.model_dump(mode="json")
                            for kind, evidence in (
                                solidity_coverage.economic_template_execution.items()
                                if solidity_coverage is not None
                                else []
                            )
                        },
                    },
                    "formal_summary": {
                        "runs": len(formal_runs),
                        "statuses": {run.tool: run.status.value for run in formal_runs},
                    },
                    "coverage": solidity_coverage.model_dump(mode="json")
                    if solidity_coverage
                    else None,
                    "model_review_coverage_summary": {
                        "surfaces": model_review_coverage.overall.denominator,
                        "reviewed": model_review_coverage.overall.numerator,
                        "critical_surfaces": model_review_coverage.critical.denominator,
                        "critical_reviewed": model_review_coverage.critical.numerator,
                        "critical_gate_passed": (model_review_coverage.critical_gate_passed),
                    },
                    "generated_test_specifications": len(generated_tests),
                    "reproduction_results": len(reproductions),
                    "cross_examination_decisions": len(cross_examinations),
                    "falsification_decisions": len(falsifications.decisions),
                },
            },
        )

    def _write_artifacts(
        self,
        *,
        run_dir: Path,
        report: AuditReport,
        source_contents: dict[str, str],
        candidate_projection: list[CandidateFinding],
        verifications: VerificationBatch,
        cross_examinations: list[CandidateCrossExaminationDecision],
        threat_model: ThreatModel | None,
        threat_location_rejections: list[str],
        solidity_index: SoliditySymbolIndex | None,
        solidity_graphs: SolidityGraphSet | None,
        solidity_invariants: InvariantSuite | None,
        invariant_review: InvariantReviewResult | None,
        invariant_executions: list[InvariantExecutionResult],
        formal_runs: list[FormalToolRun],
        solidity_coverage: SolidityCoverage | None,
        model_review_coverage: ModelReviewCoverage,
        scope_assessment: AuditScopeAssessment,
        prior_audit_comparison: PriorAuditComparison,
        generated_tests: list[GeneratedFoundryTestSpec],
        reproductions: list[ReproductionResult],
        reproduction_resolutions: list[CandidateReproductionResolution],
        falsifications: FalsificationBatch,
        run_options: AuditRunOptions,
        context_manifest: ContextManifest,
        ci_state: CIRunState | None,
        scheduler_artifact: SchedulerArtifact | None,
        scheduler_runtime_journal: SchedulerJournal | None,
        cost_ledger: AtomicCostLedger | None,
        cost_ledger_evidence: RunCostLedgerEvidence | None,
    ) -> None:
        status_metadata = report_status_metadata(report)
        if scheduler_artifact is not None:
            write_json(run_dir / "scheduler-state.json", scheduler_artifact)
        write_context_manifest(
            run_dir / "context-manifest.json",
            context_manifest,
        )
        write_json(
            run_dir / "metadata.json",
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "generated_at": report.generated_at.isoformat(),
                **status_metadata,
                "minimum_analysis_floor": (
                    report.minimum_analysis_floor.model_dump(mode="json")
                    if report.minimum_analysis_floor is not None
                    else None
                ),
                "configuration_hash": report.configuration_hash,
                "model_configuration_hash": report.model_configuration_hash,
                "privacy": report.privacy,
                "repository_suite_differential": (
                    report.repository_suite_differential.model_dump(mode="json")
                    if report.repository_suite_differential is not None
                    else None
                ),
                "metadata": report.metadata,
            },
        )
        if report.repository_suite_differential is not None:
            write_json(
                run_dir / "repository-suite-differential.json",
                report.repository_suite_differential,
            )
            write_json(
                run_dir / "privacy-fork-rpc-egress.json",
                report.privacy["fork_rpc_egress"],
            )
        write_json(
            run_dir / "candidate-findings.json",
            {
                "schema_version": "1.1",
                "findings": [
                    candidate.model_dump(mode="json") for candidate in candidate_projection
                ],
            },
        )
        write_json(
            run_dir / "execution-origin-dispositions.json",
            {
                "schema_version": "1.0",
                "dispositions": [
                    disposition.model_dump(mode="json")
                    for disposition in report.execution_origin_dispositions
                ],
            },
        )
        write_json(
            run_dir / "verification-results.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "decisions": [
                    decision.model_dump(mode="json") for decision in verifications.decisions
                ],
                "threat_model": (threat_model.model_dump(mode="json") if threat_model else None),
                "threat_model_location_rejections": threat_location_rejections,
            },
        )
        write_json(
            run_dir / "cross-examination.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "decisions": [decision.model_dump(mode="json") for decision in cross_examinations],
            },
        )
        write_json(
            run_dir / "solidity-index.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "index": solidity_index.model_dump(mode="json") if solidity_index else None,
            },
        )
        write_json(
            run_dir / "solidity-graphs.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "graphs": solidity_graphs.model_dump(mode="json") if solidity_graphs else None,
            },
        )
        write_json(
            run_dir / "solidity-coverage.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "coverage": solidity_coverage.model_dump(mode="json")
                if solidity_coverage
                else None,
            },
        )
        write_json(
            run_dir / "model-review-coverage.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "coverage": model_review_coverage.model_dump(mode="json"),
            },
        )
        write_json(
            run_dir / "scope-assessment.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "assessment": scope_assessment.model_dump(mode="json"),
            },
        )
        write_json(
            run_dir / "prior-audit-comparison.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "comparison": prior_audit_comparison.model_dump(mode="json"),
            },
        )
        write_json(
            run_dir / "solidity-invariants.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "invariants": (
                    solidity_invariants.model_dump(mode="json") if solidity_invariants else None
                ),
            },
        )
        write_json(
            run_dir / "invariant-review.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "review": (
                    invariant_review.model_dump(mode="json")
                    if invariant_review is not None
                    else None
                ),
            },
        )
        write_json(
            run_dir / "formal-results.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "runs": [run.model_dump(mode="json") for run in formal_runs],
                "dynamic_engine_comparisons": [
                    comparison.model_dump(mode="json")
                    for comparison in compare_dynamic_engine_outcomes(formal_runs)
                ],
            },
        )
        write_json(
            run_dir / "reproduction-results.json",
            {
                "schema_version": REPORT_SCHEMA_VERSION,
                "test_specifications": [
                    specification.model_dump(mode="json") for specification in generated_tests
                ],
                "results": [reproduction.model_dump(mode="json") for reproduction in reproductions],
                "candidate_resolutions": [
                    resolution.model_dump(mode="json") for resolution in reproduction_resolutions
                ],
                "falsification_decisions": [
                    decision.model_dump(mode="json") for decision in falsifications.decisions
                ],
            },
        )
        source_excerpts = build_client_source_excerpts(report, source_contents)
        findings_artifact = build_findings_artifact(
            report,
            candidates=candidate_projection,
            reproduction_resolutions=reproduction_resolutions,
            source_excerpts=source_excerpts,
        )
        write_json(run_dir / "final-findings.json", report)
        write_json(run_dir / "findings.json", findings_artifact)
        write_json(run_dir / "coverage.json", build_coverage_artifact(report))
        write_json(
            run_dir / "model-execution.json",
            build_model_execution_artifact(
                report,
                cost_ledger_evidence=cost_ledger_evidence,
                persistent_ledger_configured=cost_ledger is not None,
            ),
        )
        (run_dir / "client-report.md").write_text(
            render_client_markdown(
                report,
                source_contents,
                candidates=candidate_projection,
                reproduction_resolutions=reproduction_resolutions,
            ),
            encoding="utf-8",
        )
        (run_dir / "forensic-report.md").write_text(
            render_forensic_markdown(report, findings_artifact=findings_artifact),
            encoding="utf-8",
        )
        (run_dir / "audit-report.md").write_text(
            render_markdown(report, findings_artifact=findings_artifact),
            encoding="utf-8",
        )
        write_json(
            run_dir / "audit-results.sarif",
            generate_report_sarif(report, findings_artifact=findings_artifact),
        )
        if ci_state is not None:
            write_json(run_dir / CI_STATE_FILENAME, ci_state)
        traceability = build_traceability_matrix(report.repository.git_commit)
        runtime_artifacts = {path.name for path in run_dir.iterdir() if path.is_file()} | {
            "maximum_assurance_traceability.json",
            "run-evidence-manifest.json",
        }
        validate_traceability_evidence(
            traceability,
            repository_root=None,
            runtime_artifacts=runtime_artifacts,
        )
        write_traceability_artifact(
            run_dir / "maximum_assurance_traceability.json",
            traceability,
        )
        manifest = build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=self.config,
            file_config=self.file_config,
            environment_overrides=self.environment_overrides,
            cli_overrides=self.cli_overrides,
            run_options=run_options,
            production_qualification=(
                self.production_qualification if not run_options.scanner_only else None
            ),
            scheduler_runtime_journal=scheduler_runtime_journal,
        )
        write_run_evidence_manifest(
            run_dir / "run-evidence-manifest.json",
            manifest,
        )
        validate_manifest_artifacts(
            manifest,
            run_dir,
            scheduler_runtime_journal=scheduler_runtime_journal,
        )
        latest = _safe_output_directory(self.output, "latest")
        for filename in (
            "metadata.json",
            "repository-map.json",
            "privacy-source-provenance.json",
            "privacy-policy.json",
            "privacy-fork-rpc-egress.json",
            "scanner-results.json",
            "repository-suite-differential.json",
            "candidate-findings.json",
            "execution-origin-dispositions.json",
            "verification-results.json",
            "final-findings.json",
            "findings.json",
            "client-report.md",
            "forensic-report.md",
            "audit-report.md",
            "audit-results.sarif",
            "coverage.json",
            "model-execution.json",
            "solidity-projects.json",
            "dependency-preparation.json",
            "dependency-sbom.json",
            "solidity-compilation.json",
            "solidity-index.json",
            "solidity-graphs.json",
            "solidity-shards.json",
            "solidity-invariants.json",
            "invariant-review.json",
            "invariant-harness-plan.json",
            "property-corpus.json",
            "invariant-execution-results.json",
            "economic-simulation-plan.json",
            "formal-results.json",
            "solidity-coverage.json",
            "model-review-coverage.json",
            "context-manifest.json",
            "model-qualification-runtime.json",
            "scheduler-state.json",
            "scope-assessment.json",
            "prior-audit-comparison.json",
            "reproduction-results.json",
            CI_STATE_FILENAME,
            "maximum_assurance_traceability.json",
            "run-evidence-manifest.json",
        ):
            source = run_dir / filename
            destination = latest / filename
            if destination.is_symlink():
                raise ValueError(f"refusing symlinked latest report destination: {filename}")
            if destination.exists():
                if not destination.is_file():
                    raise ValueError(f"refusing non-file latest report destination: {filename}")
                destination.unlink()
            if source.exists():
                shutil.copy2(source, destination)


def _safe_output_directory(base: Path, name: str) -> Path:
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidate = base / name
    if candidate.is_symlink():
        raise ValueError(f"refusing symlinked output directory: {candidate}")
    candidate.mkdir(parents=False, exist_ok=True, mode=0o700)
    try:
        candidate.resolve(strict=True).relative_to(base.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ValueError("output directory escaped its configured root") from exc
    return candidate


def _resolve_scheduler_resume_journal(output: Path, run_dir: Path) -> Path:
    """Resolve one explicitly named prior run without consulting mutable aliases."""

    if run_dir.name == "latest":
        raise ValueError("scheduler resume refuses the mutable latest alias")
    runs_root = output / "runs"
    if (
        not runs_root.exists()
        or runs_root.is_symlink()
        or runs_root.is_junction()
        or not runs_root.is_dir()
    ):
        raise ValueError("scheduler resume requires an existing private runs directory")
    candidate = Path(os.path.abspath(run_dir))
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise ValueError(f"scheduler resume refuses symlinked path component: {current}")
    try:
        resolved_runs = runs_root.resolve(strict=True)
        resolved_run = candidate.resolve(strict=True)
    except OSError as exc:
        raise ValueError("scheduler resume run directory is unavailable") from exc
    if resolved_run.parent != resolved_runs or not resolved_run.is_dir():
        raise ValueError("scheduler resume requires one exact direct child of the runs directory")
    private_dir = resolved_run / "private"
    if private_dir.is_symlink() or private_dir.is_junction() or not private_dir.is_dir():
        raise ValueError("scheduler resume private directory is unavailable or unsafe")
    journal = private_dir / "scheduler-journal"
    if journal.is_symlink() or journal.is_junction() or not journal.is_dir():
        raise ValueError("scheduler resume journal is unavailable or unsafe")
    try:
        resolved_private = private_dir.resolve(strict=True)
        resolved_journal = journal.resolve(strict=True)
    except OSError as exc:
        raise ValueError("scheduler resume journal is unavailable or unsafe") from exc
    if (
        resolved_private != resolved_run / "private"
        or resolved_journal != resolved_private / "scheduler-journal"
        or resolved_journal.parent != resolved_private
    ):
        raise ValueError("scheduler resume journal escaped its exact prior run")
    return resolved_journal


def _scheduler_privacy_file_bindings(
    custody: SchedulerPrivacyEvidenceCustody,
) -> tuple[ManifestFileBinding, ManifestFileBinding]:
    return (
        ManifestFileBinding(
            path=custody.source_provenance_path,
            sha256=custody.source_provenance_artifact_sha256,
            size=custody.source_provenance_size,
        ),
        ManifestFileBinding(
            path=custody.effective_policy_path,
            sha256=custody.effective_policy_artifact_sha256,
            size=custody.effective_policy_size,
        ),
    )


def _build_scheduler_privacy_evidence_custody(
    run_dir: Path,
    *,
    provenance: PrivacySourceProvenanceEvidence,
    policy: EffectivePrivacyPolicyEvidence,
) -> SchedulerPrivacyEvidenceCustody:
    """Seal exact emitted privacy bytes before any scheduler model task exists."""

    if (
        provenance.source_sha256 != policy.source_sha256
        or policy.source_provenance_sha256 != provenance.evidence_sha256
    ):
        raise OpenRouterPrivacyError("scheduler privacy evidence source binding is inconsistent")
    provenance_bytes = stable_json(provenance).encode("utf-8")
    policy_bytes = stable_json(policy).encode("utf-8")
    custody = SchedulerPrivacyEvidenceCustody.build(
        source_sha256=provenance.source_sha256,
        source_provenance_size=len(provenance_bytes),
        source_provenance_artifact_sha256=hashlib.sha256(provenance_bytes).hexdigest(),
        source_provenance_evidence_sha256=provenance.evidence_sha256,
        effective_policy_size=len(policy_bytes),
        effective_policy_artifact_sha256=hashlib.sha256(policy_bytes).hexdigest(),
        effective_policy_evidence_sha256=policy.evidence_sha256,
        policy_source_provenance_sha256=policy.source_provenance_sha256,
    )
    names = (custody.source_provenance_path, custody.effective_policy_path)
    with open_pre_manifest_json_artifacts(
        run_dir,
        names,
        expected_bindings=_scheduler_privacy_file_bindings(custody),
        max_bytes=1_048_576,
    ) as payloads:
        observed_provenance = PrivacySourceProvenanceEvidence.model_validate(
            payloads[custody.source_provenance_path]
        )
        observed_policy = EffectivePrivacyPolicyEvidence.model_validate(
            payloads[custody.effective_policy_path]
        )
        if observed_provenance != provenance or observed_policy != policy:
            raise OpenRouterPrivacyError(
                "scheduler privacy custody differs from emitted typed evidence"
            )
    return custody


def _load_exact_resume_privacy_evidence(
    scheduler_journal: Path,
    *,
    current_provenance: PrivacySourceProvenanceEvidence,
    current_policy: EffectivePrivacyPolicyEvidence,
) -> tuple[PrivacySourceProvenanceEvidence, EffectivePrivacyPolicyEvidence]:
    """Reuse the exact prior privacy binding after semantic revalidation.

    Usage records are bound to the original provenance hash.  A later observation
    time must not invalidate an otherwise exact resume, while any security- or
    routing-relevant privacy drift must fail before provider execution.
    """

    prior_run = scheduler_journal.parent.parent
    try:
        with open_scheduler_privacy_evidence_custody(scheduler_journal) as custody:
            names = (custody.source_provenance_path, custody.effective_policy_path)
            bindings = _scheduler_privacy_file_bindings(custody)
            final_manifest_path = prior_run / "run-evidence-manifest.json"
            try:
                final_manifest_path.lstat()
            except FileNotFoundError:
                final_manifest_present = False
            except OSError as exc:
                raise ValueError("scheduler resume final-manifest state is unavailable") from exc
            else:
                final_manifest_present = True
            artifacts = (
                open_manifest_bound_json_artifacts(
                    prior_run,
                    names,
                    required_bindings=bindings,
                    max_bytes=1_048_576,
                )
                if final_manifest_present
                else open_pre_manifest_json_artifacts(
                    prior_run,
                    names,
                    expected_bindings=bindings,
                    max_bytes=1_048_576,
                )
            )
            with artifacts as payloads:
                retained_provenance = PrivacySourceProvenanceEvidence.model_validate(
                    payloads[custody.source_provenance_path]
                )
                retained_policy = EffectivePrivacyPolicyEvidence.model_validate(
                    payloads[custody.effective_policy_path]
                )
                if (
                    retained_provenance.source_sha256 != custody.source_sha256
                    or retained_policy.source_sha256 != custody.source_sha256
                    or retained_provenance.evidence_sha256
                    != custody.source_provenance_evidence_sha256
                    or retained_policy.evidence_sha256 != custody.effective_policy_evidence_sha256
                    or retained_policy.source_provenance_sha256
                    != custody.policy_source_provenance_sha256
                ):
                    raise OpenRouterPrivacyError(
                        "scheduler resume privacy evidence differs from pre-dispatch custody"
                    )
                retained_provenance_projection = retained_provenance.model_dump(
                    mode="json",
                    exclude={"observed_at", "evidence_sha256"},
                )
                current_provenance_projection = current_provenance.model_dump(
                    mode="json",
                    exclude={"observed_at", "evidence_sha256"},
                )
                retained_policy_projection = retained_policy.model_dump(
                    mode="json",
                    exclude={"source_provenance_sha256", "evidence_sha256"},
                )
                current_policy_projection = current_policy.model_dump(
                    mode="json",
                    exclude={"source_provenance_sha256", "evidence_sha256"},
                )
                if (
                    retained_provenance.observed_at > current_provenance.observed_at
                    or retained_provenance_projection != current_provenance_projection
                    or retained_policy_projection != current_policy_projection
                    or retained_policy.source_provenance_sha256
                    != retained_provenance.evidence_sha256
                    or current_policy.source_provenance_sha256 != current_provenance.evidence_sha256
                ):
                    raise OpenRouterPrivacyError(
                        "scheduler resume privacy evidence differs from the current source and "
                        "routing policy"
                    )
                return retained_provenance, retained_policy
    except OpenRouterPrivacyError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise OpenRouterPrivacyError(
            "scheduler resume privacy artifacts failed manifest-bound validation"
        ) from exc


def resolve_safe_output_root(path: Path) -> Path:
    """Resolve an output root only after rejecting existing symlink components."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise ValueError(f"refusing symlinked output path component: {current}")
    return absolute.resolve()


def _configured_models(config: AuditConfig) -> dict[str, str]:
    return {
        role: config.models.role(role).primary
        for role in (
            "threat_model",
            "source_audit",
            "business_logic",
            "configuration",
            "verifier",
            "judge",
            *sorted(config.models.specialists),
        )
    }


def _provider_session_provenance(
    *,
    client: OpenRouterClient | None,
    pipeline_owned: bool,
    usage_records: list[UsageRecord],
) -> ProviderSessionProvenance | None:
    """Bind all provider usage to the one client session that produced it."""

    if client is None:
        if not usage_records:
            return None
        return _issue_provider_session_provenance(
            execution_evidence=ExecutionEvidenceKind.UNVERIFIED,
            pipeline_owned=False,
            trusted_concrete_client=False,
            usage_evidence_consistent=False,
        )
    session_evidence = trusted_openrouter_execution_evidence(client)
    return _issue_provider_session_provenance(
        execution_evidence=session_evidence,
        pipeline_owned=pipeline_owned,
        trusted_concrete_client=type(client) is OpenRouterClient,
        usage_evidence_consistent=all(
            record.execution_evidence is session_evidence for record in usage_records
        ),
    )


def _openrouter_qualification_routing(
    qualification: VerifiedProductionQualification | None,
) -> tuple[OpenRouterQualificationRoutingEvidence, ...]:
    if qualification is None:
        return ()
    checked_at = datetime.now(UTC).replace(microsecond=0)
    qualification.require_current(now=checked_at)
    return tuple(
        OpenRouterQualificationRoutingEvidence(
            exact_model_id=model.exact_model_id,
            canonical_model_slug=model.canonical_model_slug,
            root_lineage=model.root_lineage,
            approved_provider_endpoint=model.approved_provider_endpoint,
            approved_provider_name=model.approved_provider_name,
            endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
            output_capability_sha256=model.output_capability_sha256,
            structured_output_mode=model.structured_output_mode,
            model_metadata_snapshot_sha256=model.model_metadata_snapshot_sha256,
            pricing_snapshot_sha256=model.pricing_snapshot_sha256,
            approved_roles=model.approved_roles,
            verified_at=qualification.verified_at,
            expires_at=model.expires_at,
            qualification_artifact_sha256=qualification.artifact_sha256,
            qualification_verification_sha256=(qualification.qualification_verification_sha256),
            production_selection_sha256=qualification.production_selection_sha256,
            selection_verification_sha256=qualification.selection_verification_sha256,
            qualification_result_sha256=model.qualification_result_sha256,
            benchmark_report_sha256=model.benchmark_report_sha256,
            reasoning_bindings=tuple(
                OpenRouterQualifiedReasoningRoutingBinding(
                    exact_model_id=binding.exact_model_id,
                    approved_provider_endpoint=binding.approved_provider_endpoint,
                    approved_provider_name=binding.approved_provider_name,
                    qualified_role=binding.qualified_role,
                    configured_policy_role=binding.configured_policy_role,
                    control_profile=binding.control_profile,
                    control_profile_sha256=binding.control_profile_sha256,
                    reasoning_policy_artifact_sha256=(binding.reasoning_policy_artifact_sha256),
                    reasoning_policy_role_binding_sha256=(
                        binding.reasoning_policy_role_binding_sha256
                    ),
                    endpoint_reasoning_capability_sha256=(
                        binding.endpoint_reasoning_capability_sha256
                    ),
                    reasoning_benchmark_report_sha256=(binding.reasoning_benchmark_report_sha256),
                    reasoning_benchmark_verification_sha256=(
                        binding.reasoning_benchmark_verification_sha256
                    ),
                    reasoning_benchmark_fresh_evidence_sha256=(
                        binding.reasoning_benchmark_fresh_evidence_sha256
                    ),
                    qualification_report_sha256=binding.qualification_report_sha256,
                    qualification_result_sha256=binding.qualification_result_sha256,
                    qualification_verification_sha256=(binding.qualification_verification_sha256),
                    binding_sha256=binding.binding_sha256,
                )
                for binding in model.reasoning_bindings
            ),
        )
        for model in qualification.models
    )


def _validated_threat_model(
    root: Path,
    threat_model: ThreatModel,
    *,
    context_hashes: dict[tuple[str, int, int], str],
) -> tuple[ThreatModel, list[str]]:
    """Remove invalid boundary citations while retaining deterministic reasons."""

    boundaries = []
    rejections: list[str] = []
    for boundary in threat_model.trust_boundaries:
        valid_locations = []
        for location in boundary.locations:
            validation = validate_location(
                root,
                location,
                context_hashes=context_hashes,
            )
            if validation.valid:
                valid_locations.append(location)
            else:
                reasons = "; ".join(validation.errors) or "invalid location"
                rejections.append(
                    f"{boundary.name}: {location.path}:{location.start_line}-"
                    f"{location.end_line}: {reasons}"
                )
        boundaries.append(boundary.model_copy(update={"locations": valid_locations}))
    return threat_model.model_copy(update={"trust_boundaries": boundaries}), rejections


def _annotate_scanner_locations(root: Path, run: ScannerRun) -> ScannerRun:
    """Record deterministic validation without suppressing local-only evidence."""

    return validated_scanner_run_location_annotation_preserving_runtime_authority(
        root,
        run,
    )


def _scanner_findings_for_context(
    root: Path,
    scanner_findings: list[ScannerFinding],
    allowed_paths: set[str],
) -> list[ScannerFinding]:
    """Select only valid, discovery-approved scanner references for model egress."""

    selected: list[ScannerFinding] = []
    for finding in scanner_findings:
        locations = [
            location
            for location in finding.locations
            if location.path in allowed_paths and validate_location(root, location).valid
        ]
        if locations:
            selected.append(finding.model_copy(update={"locations": locations}))
    return selected


def _scanner_secret_paths(
    scanner_findings: list[ScannerFinding],
    allowed_paths: set[str],
) -> set[str]:
    return {
        location.path
        for finding in scanner_findings
        if finding.scanner == "gitleaks" or finding.metadata.get("class") == "secret"
        for location in finding.locations
        if location.path in allowed_paths
    }


def _scanner_findings_for_report(
    root: Path,
    scanner_findings: list[ScannerFinding],
) -> list[Finding]:
    """Represent scanner-only results as hypotheses with validated locations."""

    findings: list[Finding] = []
    for scanner in scanner_findings:
        validation_results = [validate_location(root, location) for location in scanner.locations]
        findings.append(
            project_scanner_finding(
                scanner,
                validation_results,
                validated_at=datetime.now(UTC),
            )
        )
    return findings


def _attach_verifier_votes(
    candidates: list[CandidateFinding],
    decisions: dict[str, VerificationDecision],
    client: OpenRouterClient,
    *,
    role: str = "verifier",
    usage_record: UsageRecord | None = None,
) -> list[CandidateFinding]:
    usage = usage_record or next(
        (
            record
            for record in reversed(client.usage.records)
            if record.role == role and is_creditable_usage_record(record)
        ),
        None,
    )
    if usage is None:
        return candidates
    result: list[CandidateFinding] = []
    for candidate in candidates:
        decision = decisions.get(candidate.candidate_id)
        if decision is None:
            result.append(candidate)
            continue
        vote = ModelVote(
            role=role,
            requested_model=usage.requested_model,
            returned_model=usage.returned_model,
            family=usage.model_family,
            verdict=decision.verdict.value,
            rationale=decision.rationale,
        )
        result.append(candidate.model_copy(update={"model_votes": [*candidate.model_votes, vote]}))
    return result


def _attach_cross_examination_votes(
    candidates: list[CandidateFinding],
    cross_examinations: list[CandidateCrossExaminationDecision],
) -> list[CandidateFinding]:
    """Retain every independent supporting, disputing, or inconclusive vote."""

    by_candidate: dict[str, list[CandidateCrossExaminationDecision]] = {}
    for decision in cross_examinations:
        by_candidate.setdefault(decision.candidate_id, []).append(decision)
    result: list[CandidateFinding] = []
    for candidate in candidates:
        decisions = sorted(
            by_candidate.get(candidate.candidate_id, []),
            key=lambda item: item.reviewer_index,
        )
        votes = [
            ModelVote(
                role=f"specialist:falsifier:{decision.reviewer_index}",
                requested_model=decision.requested_model,
                returned_model=decision.returned_model,
                family=decision.root_lineage,
                verdict=decision.verdict.value,
                rationale=decision.rationale,
            )
            for decision in decisions
        ]
        result.append(
            candidate.model_copy(update={"model_votes": [*candidate.model_votes, *votes]})
        )
    return result


def _judge_vote(
    decision: JudgeDecision | None,
    client: OpenRouterClient,
) -> ModelVote | None:
    if decision is None:
        return None
    usage = next(
        (
            record
            for record in reversed(client.usage.records)
            if record.role == "judge" and is_creditable_usage_record(record)
        ),
        None,
    )
    if usage is None:
        return None
    return ModelVote(
        role="judge",
        requested_model=usage.requested_model,
        returned_model=usage.returned_model,
        family=usage.model_family,
        verdict=decision.status.value,
        rationale=decision.rationale,
    )


def _eligible_reproduction_candidates(
    candidates: list[CandidateFinding],
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    *,
    limit: int,
) -> list[CandidateFinding]:
    eligible = [
        candidate
        for candidate in candidates
        if candidate.severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL}
        and any(location.path.endswith(".sol") for location in candidate.locations)
        and (validation := validations.get(candidate.candidate_id)) is not None
        and validation.valid
        and (decision := decisions.get(candidate.candidate_id)) is not None
        and decision.verdict in {VerificationVerdict.VERIFIED, VerificationVerdict.PLAUSIBLE}
    ]
    return sorted(
        eligible,
        key=lambda candidate: (
            -SEVERITY_ORDER[candidate.severity.value],
            -candidate.confidence,
            candidate.candidate_id,
        ),
    )[:limit]


def _scheduled_reproduction_candidate_ids(
    tasks: Iterable[SchedulerTaskPlan],
) -> tuple[str, ...]:
    """Return the exact candidate inventory committed by reproduction model tasks."""

    return tuple(
        sorted(
            {
                candidate_id
                for task in tasks
                if task.task_kind is SchedulerTaskKind.MODEL_REQUEST
                and (
                    task.role.endswith(":exploit_test")
                    or task.role in {"falsifier", "specialist:falsifier"}
                )
                for candidate_id in task.candidate_ids
            }
        )
    )


def _project_for_candidate(
    candidate: CandidateFinding,
    projects: list[SolidityProjectMetadata],
) -> SolidityProjectMetadata | None:
    return _project_for_path(candidate.locations[0].path, projects)


def _project_for_path(
    path: str,
    projects: list[SolidityProjectMetadata],
) -> SolidityProjectMetadata | None:
    matches = [
        project
        for project in projects
        if project.project_type in {SolidityProjectType.FOUNDRY, SolidityProjectType.MIXED}
        and (
            project.project_root == "."
            or path == project.project_root
            or path.startswith(project.project_root.rstrip("/") + "/")
        )
    ]
    return max(matches, key=lambda project: len(project.project_root), default=None)


def _invariant_harness_validation_error(
    harness: FoundryInvariantHarnessSpec,
    *,
    invariant_exists: bool,
    indexed_names: set[str],
    targets: set[str],
    planned_economic_templates: dict[
        EconomicSimulationKind,
        TransactionOrderingCapability,
    ],
) -> str | None:
    if not invariant_exists:
        return "harness invariant_id does not match a source-linked inferred invariant"
    if (
        harness.economic_template is not None
        and harness.economic_template not in planned_economic_templates
    ):
        return "harness economic_template was not selected from deterministic protocol facts"
    if (
        harness.economic_template is not None
        and harness.required_transaction_ordering
        is not planned_economic_templates[harness.economic_template]
    ):
        return "harness transaction-ordering requirement differs from the deterministic plan"
    referenced_targets = {
        *(setup.target for setup in harness.setup_calls),
        *(seed.token for seed in harness.token_balance_seeds),
        *(action.target for action in harness.actions),
        *(property_spec.left.target for property_spec in harness.properties),
        *(
            property_spec.right.target
            for property_spec in harness.properties
            if property_spec.right is not None
        ),
    }
    unknown_targets = referenced_targets - targets
    if unknown_targets:
        return "harness referenced unconfigured target aliases: " + ", ".join(
            sorted(unknown_targets)
        )
    referenced_functions = {
        *(setup.function_signature.split("(", 1)[0] for setup in harness.setup_calls),
        *(action.function_signature.split("(", 1)[0] for action in harness.actions),
        *(
            property_spec.left.function_signature.split("(", 1)[0]
            for property_spec in harness.properties
        ),
        *(
            property_spec.right.function_signature.split("(", 1)[0]
            for property_spec in harness.properties
            if property_spec.right is not None
        ),
    }
    unknown_functions = referenced_functions - indexed_names
    if unknown_functions:
        return "harness referenced functions absent from the validated source index: " + ", ".join(
            sorted(unknown_functions)
        )
    return None


def _unsupported_reproduction(
    candidate: CandidateFinding,
    specification: GeneratedFoundryTestSpec,
    limitation: str,
) -> ReproductionResult:
    payload = json.dumps(
        specification.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return ReproductionResult(
        candidate_id=candidate.candidate_id,
        test_name=specification.name,
        state=ReproductionState.ENVIRONMENT_BLOCKED,
        specification_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        assumptions=specification.assumptions,
        required_block_number=specification.required_block_number,
        expected_chain_id=specification.expected_chain_id,
        financial_settlement=specification.financial_settlement,
        limitations=[limitation],
    )


def _not_attempted_reproduction(
    candidate: CandidateFinding,
    specification: GeneratedFoundryTestSpec,
    limitation: str,
) -> ReproductionResult:
    """Retain exact test custody when independent verification closes execution."""

    payload = json.dumps(
        specification.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    return ReproductionResult(
        candidate_id=candidate.candidate_id,
        test_name=specification.name,
        state=ReproductionState.NOT_ATTEMPTED,
        specification_sha256=hashlib.sha256(payload.encode()).hexdigest(),
        assumptions=specification.assumptions,
        required_block_number=specification.required_block_number,
        expected_chain_id=specification.expected_chain_id,
        financial_settlement=specification.financial_settlement,
        limitations=[limitation],
    )


def _unique_generated_tests(
    specifications: list[GeneratedFoundryTestSpec],
) -> list[GeneratedFoundryTestSpec]:
    """Deduplicate independent planners without obscuring their provenance."""

    result: list[GeneratedFoundryTestSpec] = []
    seen: set[tuple[str, str]] = set()
    for specification in specifications:
        key = (specification.candidate_id, specification.name)
        if key in seen:
            continue
        seen.add(key)
        result.append(specification)
    return result


def _apply_reproduction_results(
    candidates: list[CandidateFinding],
    decisions: dict[str, VerificationDecision],
    results: list[ReproductionResult],
    falsifications: FalsificationBatch,
) -> tuple[list[CandidateFinding], dict[str, VerificationDecision]]:
    falsification_by_test = {
        (decision.candidate_id, decision.test_name): decision
        for decision in falsifications.decisions
    }
    evidence_by_candidate: dict[str, list[Evidence]] = {}
    updated_decisions = dict(decisions)
    for result in results:
        falsification = falsification_by_test.get((result.candidate_id, result.test_name))
        if (
            result.state
            in {
                ReproductionState.REPRODUCED,
                ReproductionState.REPRODUCED_AND_MINIMIZED,
            }
            and result.integrity is not None
            and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            and falsification is not None
            and falsification.verdict is FalsificationVerdict.ACCEPTED
            and falsification.test_matches_claim
            and falsification.assumptions_validated
        ):
            evidence_by_candidate.setdefault(result.candidate_id, []).append(
                Evidence(
                    type="reproduction",
                    source="mmaudit-local-fork-reproduction",
                    rule_id=result.state.value,
                    description=(
                        f"Typed Foundry fork test {result.test_name} passed "
                        f"{result.successful_attempts}/{result.attempts} bounded attempts "
                        "and survived independent falsification"
                    ),
                    fingerprint=result.generated_test_sha256 or result.specification_sha256,
                )
            )
        if (
            result.state is ReproductionState.NOT_REPRODUCED
            and result.integrity is not None
            and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
            and falsification is not None
            and falsification.verdict is FalsificationVerdict.FALSIFIED
            and falsification.test_matches_claim
            and falsification.assumptions_validated
            and (decision := updated_decisions.get(result.candidate_id)) is not None
        ):
            updated_decisions[result.candidate_id] = decision.model_copy(
                update={
                    "verdict": VerificationVerdict.REJECTED,
                    "rationale": (
                        f"{decision.rationale}; complete local fork test disproved the claim: "
                        f"{falsification.rationale}"
                    ),
                    "confidence": min(decision.confidence, 0.2),
                }
            )
    return (
        [
            candidate.model_copy(
                update={
                    "evidence": [
                        *candidate.evidence,
                        *evidence_by_candidate.get(candidate.candidate_id, []),
                    ]
                }
            )
            for candidate in candidates
        ],
        updated_decisions,
    )


def _enforce_post_judge_execution_severity_accounting(
    *,
    group: CandidateGroup,
    finding: Finding,
    judge: JudgeDecision | None,
    pre_judgment_high_critical_ids: set[str],
) -> tuple[Finding, tuple[CandidateFinding, ...], str | None]:
    """Fail closed when judgment first raises an execution observation to high impact.

    The judge may assess impact severity, but it runs after candidate cross-examination
    and reproduction planning. A newly high/critical execution-origin finding therefore
    cannot retain an accepted status or disappear from downstream assurance denominators.
    """

    if (
        judge is None
        or finding.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION
        or finding.status is FindingStatus.REJECTED
        or finding.severity not in {Severity.HIGH, Severity.CRITICAL}
    ):
        return finding, (), None

    # Preserve the exact candidate artifact (including its pre-judgment severity).
    # The final finding owns the judge's impact assessment; downstream gates use
    # the provenance-derived candidate ID as an additional required denominator.
    accounting_candidates = tuple(
        candidate
        for candidate in group.execution_candidates
        if candidate.candidate_id not in pre_judgment_high_critical_ids
    )
    if not accounting_candidates:
        return finding, (), None

    candidate_ids = ", ".join(candidate.candidate_id for candidate in accounting_candidates)
    limitation = (
        f"execution-origin group {group.group_id} received {finding.severity.value} impact "
        "severity only after the pre-judgment high/critical phases; provenance-bound "
        f"candidate(s) {candidate_ids} did not receive candidate-specific cross-examination "
        "or reproduction planning, so the finding requires manual review and the run is "
        "incomplete"
    )
    accepted_statuses = {
        FindingStatus.CONFIRMED,
        FindingStatus.STRONGLY_SUPPORTED,
        FindingStatus.HIGH_CONFIDENCE,
        FindingStatus.PLAUSIBLE,
    }
    status = FindingStatus.NEEDS_REVIEW if finding.status in accepted_statuses else finding.status
    return (
        finding.model_copy(
            update={
                "status": status,
                "disagreement": (
                    f"{finding.disagreement}; {limitation}" if finding.disagreement else limitation
                ),
            }
        ),
        accounting_candidates,
        limitation,
    )


def _build_candidate_reproduction_resolutions(
    *,
    candidates: list[CandidateFinding],
    results: list[ReproductionResult],
    forced_candidate_ids: set[str] | None = None,
) -> list[CandidateReproductionResolution]:
    """Derive one fail-closed terminal resolution per high/critical obligation.

    Forced IDs retain their exact emitted candidate payload while a post-judgment
    impact assessment introduces the high/critical assurance obligation.
    """

    forced_candidate_ids = forced_candidate_ids or set()
    results_by_candidate: dict[str, list[ReproductionResult]] = {}
    for result in results:
        results_by_candidate.setdefault(result.candidate_id, []).append(result)
    resolutions: list[CandidateReproductionResolution] = []
    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        if (
            candidate.severity not in {Severity.HIGH, Severity.CRITICAL}
            and candidate.candidate_id not in forced_candidate_ids
        ):
            continue
        candidate_results = results_by_candidate.get(candidate.candidate_id, [])
        reproduced_refs: set[str] = set()
        for result in candidate_results:
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
                reproduced_refs.add(f"reproduction:{result.integrity.integrity_sha256}")
        if reproduced_refs:
            resolutions.append(
                CandidateReproductionResolution(
                    candidate_id=candidate.candidate_id,
                    kind=ReproductionResolutionKind.REPRODUCED,
                    evidence_refs=sorted(reproduced_refs),
                    detail="verified deterministic reproduction resolved candidate",
                )
            )
            continue

        attempted_states = sorted(
            {result.state.value for result in candidate_results if result.attempts > 0}
        )
        resolutions.append(
            CandidateReproductionResolution(
                candidate_id=candidate.candidate_id,
                kind=ReproductionResolutionKind.INCONCLUSIVE,
                evidence_refs=[],
                detail=(
                    "attempted reproduction did not produce a qualifying terminal outcome: "
                    + ", ".join(attempted_states)
                    if attempted_states
                    else "no qualifying integrity-bound deterministic reproduction evidence"
                ),
            )
        )
    return resolutions


def _record_reproduction_attempts(
    coverage: SolidityCoverage,
    reproductions: list[ReproductionResult],
) -> SolidityCoverage:
    """Record candidate replay activity without replacing repository-suite evidence."""

    payload = coverage.model_dump(mode="python")
    payload["reproduction_attempts"] = sum(1 for result in reproductions if result.attempts > 0)
    return SolidityCoverage.model_validate(payload)


def _evaluate_quality_gates(
    *,
    config: AuditConfig,
    solidity_projects: list[SolidityProjectMetadata],
    compilations: list[SolidityCompilationResult],
    scanner_runs: list[ScannerRun],
    coverage: SolidityCoverage | None,
    model_review_coverage: ModelReviewCoverage | None,
    scope_assessment: AuditScopeAssessment | None,
    prior_audit_comparison: PriorAuditComparison | None,
    invariant_executions: list[InvariantExecutionResult],
    eligible_candidates: list[CandidateFinding],
    reproductions: list[ReproductionResult],
    usage_roles: set[str],
    scanner_only: bool,
    model_surface_assignment_gate: QualityGateResult,
    repository_execution_sha256: str | None,
) -> list[QualityGateResult]:
    base_gates = [
        scope_quality_gate(scope_assessment),
        model_surface_assignment_gate,
    ]
    if prior_audit_comparison is not None:
        base_gates.append(prior_audit_quality_gate(prior_audit_comparison, config.prior_audit))
    if not solidity_projects or scanner_only:
        return base_gates
    runs = {run.scanner: run for run in scanner_runs}
    compilation_passed = bool(compilations) and all(
        result.status is CompilationStatus.SUCCESS for result in compilations
    )
    slither = runs.get("slither")
    baseline = runs.get("foundry_fork")
    attempted_candidates = {result.candidate_id for result in reproductions if result.attempts > 0}
    eligible_candidate_ids = {candidate.candidate_id for candidate in eligible_candidates}
    integrity_verified_ids = {
        result.candidate_id
        for result in reproductions
        if result.integrity is not None
        and result.integrity.status is ReproductionIntegrityStatus.VERIFIED
    }
    reproduction_integrity_passed = eligible_candidate_ids <= integrity_verified_ids
    fork_executed = bool(attempted_candidates) or (
        baseline is not None
        and is_qualifying_real_foundry_portfolio(
            baseline,
            config,
            expected_repository_sha256=repository_execution_sha256,
        )
    )
    required_roles = {
        "threat_model",
        "source_audit",
        "business_logic",
        "configuration",
        "verifier",
        "judge",
    }
    maximum = config.profile is AuditProfile.MAXIMUM_ASSURANCE
    completed_invariants = [
        result
        for result in invariant_executions
        if result.status
        in {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
    ]
    metric_gates = [
        _coverage_quality_gate(
            coverage,
            metric_name="solidity_files_indexed",
            gate="solidity_index_coverage",
            threshold=config.quality_gates.min_indexed_contract_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="compiler_contracts_indexed",
            gate="compiler_contract_index_coverage",
            threshold=config.quality_gates.min_indexed_contract_fraction,
            required=maximum,
            empty_is_pass=False,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="candidate_reproduction_tested",
            gate="candidate_reproduction_coverage",
            threshold=config.quality_gates.min_reproduction_attempt_fraction,
            required=config.quality_gates.require_candidate_reproduction,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="public_external_entry_points_reviewed",
            gate="public_external_entry_point_review_coverage",
            threshold=config.quality_gates.min_reviewed_entry_point_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="privileged_entry_points_reviewed",
            gate="privileged_entry_point_review_coverage",
            threshold=config.quality_gates.min_reviewed_privileged_entry_point_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="state_writing_functions_reviewed",
            gate="state_writing_function_review_coverage",
            threshold=config.quality_gates.min_reviewed_state_writing_function_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="high_value_paths_reviewed",
            gate="high_value_path_review_coverage",
            threshold=config.quality_gates.min_reviewed_high_value_path_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="external_calls_classified",
            gate="external_call_classification_coverage",
            threshold=config.quality_gates.min_classified_external_call_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="asset_flows_classified",
            gate="asset_flow_classification_coverage",
            threshold=config.quality_gates.min_classified_asset_flow_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="storage_variables_modelled",
            gate="storage_layout_coverage",
            threshold=config.quality_gates.min_modelled_storage_variable_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="invariants_executed",
            gate="invariant_execution_coverage",
            threshold=config.quality_gates.min_invariant_execution_fraction,
            required=maximum,
            empty_is_pass=False,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="scanner_completion",
            gate="deterministic_scanner_completion",
            threshold=config.quality_gates.min_scanner_completion_fraction,
            required=maximum,
            empty_is_pass=False,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="model_role_completion",
            gate="configured_model_role_completion",
            threshold=config.quality_gates.min_model_role_completion_fraction,
            required=maximum and config.quality_gates.require_all_model_roles,
            empty_is_pass=False,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="economic_templates_executed",
            gate="economic_template_execution_coverage",
            threshold=config.quality_gates.min_economic_template_execution_fraction,
            required=maximum,
        ),
        _coverage_quality_gate(
            coverage,
            metric_name="dependency_resolution",
            gate="dependency_resolution_coverage",
            threshold=config.quality_gates.min_dependency_resolution_fraction,
            required=maximum,
        ),
    ]
    return [
        *base_gates,
        QualityGateResult(
            gate="compilation",
            required=config.quality_gates.require_compilation,
            passed=compilation_passed,
            detail=(
                "all detected Solidity projects compiled"
                if compilation_passed
                else "one or more projects were skipped, unavailable, failed, or timed out"
            ),
        ),
        QualityGateResult(
            gate="slither",
            required=config.quality_gates.require_slither,
            passed=slither is not None and slither.status is ScannerStatus.SUCCESS,
            detail=(f"status={slither.status.value}" if slither is not None else "no Slither run"),
        ),
        QualityGateResult(
            gate="local_fork_execution",
            required=config.reproduction.required_for_solidity
            or config.quality_gates.require_fork_baseline,
            passed=fork_executed,
            detail=(
                "a bounded local-fork test stage executed"
                if fork_executed
                else "no existing or candidate-specific fork test executed"
            ),
        ),
        QualityGateResult(
            gate="reproduction_integrity",
            required=config.quality_gates.require_candidate_reproduction or maximum,
            passed=reproduction_integrity_passed,
            detail=(
                "every eligible candidate has deterministic verified reproduction integrity"
                if reproduction_integrity_passed
                else "missing verified reproduction integrity for candidate(s): "
                + ", ".join(sorted(eligible_candidate_ids - integrity_verified_ids))
            ),
            state=(
                AnalysisState.DETERMINISTIC
                if reproduction_integrity_passed
                else (
                    AnalysisState.ATTEMPTED_FAILED
                    if attempted_candidates
                    else AnalysisState.NOT_ANALYZED
                )
            ),
            artifacts=["reproduction-results.json"],
        ),
        QualityGateResult(
            gate="required_model_roles",
            required=False,
            passed=required_roles <= usage_roles,
            detail=(
                "all base model roles completed"
                if required_roles <= usage_roles
                else "missing roles: " + ", ".join(sorted(required_roles - usage_roles))
            ),
        ),
        QualityGateResult(
            gate="stateful_invariants",
            required=maximum,
            passed=bool(completed_invariants),
            detail=(
                f"{len(completed_invariants)}/{len(invariant_executions)} "
                "typed stateful invariant harness(es) completed"
                if invariant_executions
                else "no validated typed stateful invariant harness was configured"
            ),
        ),
        model_review_critical_surface_gate(
            model_review_coverage,
            required=maximum,
        ),
        *metric_gates,
    ]


def _coverage_quality_gate(
    coverage: SolidityCoverage | None,
    *,
    metric_name: str,
    gate: str,
    threshold: float,
    required: bool,
    empty_is_pass: bool = True,
) -> QualityGateResult:
    """Evaluate one explicit numerator/denominator without inventing coverage."""

    metric = coverage.quality_metrics.get(metric_name) if coverage is not None else None
    if metric is None:
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=False,
            detail=f"{metric_name} coverage was not produced",
            state=AnalysisState.NOT_ANALYZED,
        )
    if metric.denominator == 0:
        evidenced_not_applicable = bool(metric.not_applicable_evidence)
        return QualityGateResult(
            gate=gate,
            required=required,
            passed=empty_is_pass and evidenced_not_applicable,
            detail=(
                f"{metric_name}: evidenced not applicable (0/0); "
                f"{metric.not_applicable_evidence[0]}"
                if evidenced_not_applicable
                else f"{metric_name}: empty denominator has failure evidence; "
                f"failures={len(metric.failures)}"
            ),
            state=metric.state,
        )
    fraction = metric.numerator / metric.denominator
    denominator_integrity_failed = metric.numerator == metric.denominator and bool(metric.failures)
    return QualityGateResult(
        gate=gate,
        required=required,
        passed=fraction >= threshold and not denominator_integrity_failed,
        detail=(
            f"{metric_name}: {metric.numerator}/{metric.denominator} "
            f"({fraction:.1%}); required {threshold:.1%}; "
            f"population={metric.population}; exclusions={len(metric.exclusions)}; "
            f"failures={len(metric.failures)}; confidence={metric.confidence:.2f}; "
            f"provenance={','.join(item.value for item in metric.provenance)}; "
            f"denominator_integrity_failed={denominator_integrity_failed}"
        ),
        state=metric.state,
    )


def _group_payload(
    group: CandidateGroup,
    decisions: dict[str, VerificationDecision],
    validations: dict[str, LocationValidation],
    scanner_findings: list[ScannerFinding],
) -> dict[str, Any]:
    return {
        "group_id": group.group_id,
        "consensus_status_cap": preliminary_status(
            group, decisions, validations, scanner_findings
        ).value,
        "candidates": [candidate.model_dump(mode="json") for candidate in group.candidates],
        "verifier_decisions": [
            decisions[candidate.candidate_id].model_dump(mode="json")
            for candidate in group.candidates
            if candidate.candidate_id in decisions
        ],
        "location_validation": {
            candidate.candidate_id: validations[candidate.candidate_id].model_dump(mode="json")
            for candidate in group.candidates
            if candidate.candidate_id in validations
        },
        "scanner_evidence": [finding.model_dump(mode="json") for finding in scanner_findings][:200],
    }


def _repository_unchanged(discovery: DiscoveryResult) -> bool:
    for item in discovery.files:
        try:
            if item.absolute_path.stat().st_nlink > 1:
                return False
            current = hashlib.sha256(item.absolute_path.read_bytes()).hexdigest()
        except OSError:
            return False
        if current != item.sha256:
            return False
    return True
