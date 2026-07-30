"""End-to-end read-only audit pipeline with partial-result preservation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import shutil
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from mmaudit.agents.base import FindingReviewResult
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
    PreparedCandidateCrossExaminationInput,
    VerifierAgent,
    select_candidate_falsifier_models,
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
    OpenRouterSchemaError,
)
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.registry import (
    ModelRegistry,
    ProductionQualificationValidation,
    extract_zdr_model_ids,
)
from mmaudit.models.runtime import (
    build_openrouter_runtime_controls,
    maximum_assurance_model_certification_required,
)
from mmaudit.models.schemas import (
    AnalysisState,
    AuditProfile,
    AuditQualityStatus,
    AuditReport,
    AuditRunStatus,
    AuditScopeAssessment,
    CandidateCrossExaminationDecision,
    CandidateFinding,
    CandidateOriginKind,
    CandidateReproductionResolution,
    CompilationStatus,
    ContextPackage,
    ContextRequestEvidence,
    DependencyPreparationStatus,
    EconomicSimulationKind,
    EconomicSimulationPlan,
    Evidence,
    EvidenceStrength,
    ExecutionEvidenceKind,
    FalsificationBatch,
    FalsificationVerdict,
    Finding,
    FindingOriginKind,
    FindingStatus,
    FormalResultKind,
    FormalToolRun,
    FoundryInvariantHarnessSpec,
    GeneratedFoundryTestSpec,
    InvariantExecutionResult,
    InvariantExecutionStatus,
    InvariantReviewBatch,
    InvariantReviewResult,
    InvariantSuite,
    JudgeDecision,
    Location,
    LocationValidation,
    MaximumAssuranceAssessment,
    MinimumAnalysisFloor,
    ModelReviewCoverage,
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
    VerificationTest,
    VerificationVerdict,
)
from mmaudit.models.usage import (
    UsageLedger,
    candidate_falsifier_role,
    is_creditable_usage_record,
)
from mmaudit.orchestration.assurance import (
    AssuranceRuntime,
    MaximumAssuranceContract,
    ProviderSessionProvenance,
    _issue_provider_session_provenance,
    is_qualifying_real_foundry_portfolio,
)
from mmaudit.orchestration.budgets import BudgetExhaustedError, BudgetManager
from mmaudit.orchestration.consensus import (
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
    build_run_evidence_manifest,
    canonical_sha256,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.model_coverage import (
    build_model_review_coverage,
    build_model_surface_requests,
    model_review_critical_surface_gate,
    model_surface_assignment_feasibility_gate,
    plan_model_surface_review_assignments,
)
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
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
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
from mmaudit.scanners.base import scanner_workspace_sha256
from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
from mmaudit.scanners.fork_matrix import (
    ForkMatrixDependencies,
    RepositoryForkMatrixRunner,
    repository_fork_matrix_timeout_budget_seconds,
)
from mmaudit.scanners.runner import ScannerRunner
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
    if (
        context.role != expected_role
        or usage_record.user_prompt_sha256 != context_evidence.rendered_sha256
    ):
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

    def clear_credentials(self) -> None:
        """Drop operator credentials retained by pipeline/provider objects."""

        self.api_key = ""
        if self.client is not None:
            self.client.clear_credentials()
        self.privacy_authorization = None
        self.privacy_consent_observation = None
        self.privacy_source_provenance_observation = None

    async def run(
        self,
        *,
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
    ) -> PipelineResult:
        """Execute one audit and always clear provider credentials afterward."""

        try:
            return await self._run_with_provider(
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
            )
        finally:
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
        if not scanner_only and self.client is None and self.cost_ledger is None:
            raise ValueError("provider audits require an explicit existing cumulative cost ledger")
        if not scanner_only and self.client is not None and self.client.usage.records:
            raise ValueError("provider audits require a fresh empty client usage ledger")
        if not scanner_only and self.client is not None and self.client.context_preflight.records:
            raise ValueError("provider audits require a fresh empty context preflight ledger")
        if (
            not scanner_only
            and self.client is not None
            and self.client.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        ):
            raise ValueError("provider audits reject unverified injected clients")
        if (
            not scanner_only
            and self.client is not None
            and self.client.execution_evidence is ExecutionEvidenceKind.REAL
            and (not self._owns_client or type(self.client) is not OpenRouterClient)
        ):
            raise ValueError("injected provider clients cannot establish REAL execution provenance")
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
        candidate_origin_packages: dict[str, ContextPackage] = {}
        pending_execution_candidates: list[CandidateFinding] = []
        execution_candidates_integrated = False
        execution_candidate_build = ExecutionCandidateBuildResult(
            candidates=(),
            rejected_counterexample_count=0,
            limitations=(),
        )
        verifications = VerificationBatch(decisions=[])
        decisions: dict[str, VerificationDecision] = {}
        cross_examinations: list[CandidateCrossExaminationDecision] = []
        final_findings: list[Finding] = []
        rejected_findings: list[Finding] = []
        scanner_runs: list[ScannerRun] = []
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
        candidate_groups_count = 0
        validations: dict[str, LocationValidation] = {}
        discovery: DiscoveryResult
        repository_execution_sha256: str | None = None
        repository_execution_exclusion_root: Path | None = None
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
            repository_execution_exclusion_root = (
                self.output.resolve(strict=True)
                if output_relative_to_repo is not None
                else self.repo_input.resolve(strict=True) / ".mmaudit"
            )
            try:
                repository_execution_sha256 = scanner_workspace_sha256(
                    self.repo_input,
                    repository_execution_exclusion_root,
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
            except (ValueError, OpenRouterPrivacyError) as exc:
                incomplete.append(f"privacy authorization failed: {exc}")
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.PRIVACY_REFUSAL

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
        scanner_runs = (
            []
            if preflight_blocked
            else await self.scanner_runner.run_all(
                discovery.root,
                run_dir / "private" / "scanner-output",
                skip_codeql=skip_codeql,
                allow_fork_probing=allow_fork_probing,
                projects=solidity_projects,
                expected_repository_sha256=repository_execution_sha256,
                repository_exclusion_root=repository_execution_exclusion_root,
            )
        )
        if self.config.smart_contracts.repository_suite.fork_matrix_states:
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
        if repository_execution_sha256 is not None:
            try:
                post_scanner_repository_sha256 = scanner_workspace_sha256(
                    discovery.root,
                    repository_execution_exclusion_root,
                )
            except (OSError, ValueError) as exc:
                incomplete.append(
                    "repository execution source identity could not be revalidated after "
                    f"scanner execution: {type(exc).__name__}"
                )
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            else:
                if post_scanner_repository_sha256 != repository_execution_sha256:
                    incomplete.append(
                        "repository execution source changed during scanner execution or "
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
        real_counterexamples = sum(
            result.status is InvariantExecutionStatus.COUNTEREXAMPLE
            and result.execution_evidence is ExecutionEvidenceKind.REAL
            for result in invariant_executions
        )
        if execution_candidate_build.rejected_counterexample_count and real_counterexamples:
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
        model_certification_required = maximum_assurance_model_certification_required(self.config)
        qualification_preflight: ProductionQualificationValidation | None = None
        if not scanner_only:
            qualification_preflight = self._write_model_qualification_runtime(
                run_dir,
                required=model_certification_required,
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
                atomic_ledger=None if scanner_only else self.cost_ledger,
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
        )
        minimum_critical_surface_lineages = (
            3 if self.config.profile is AuditProfile.MAXIMUM_ASSURANCE else 1
        )
        model_surface_review_assignments = plan_model_surface_review_assignments(
            self.config,
            model_surface_requests,
            minimum_critical_root_lineages=minimum_critical_surface_lineages,
        )
        model_surface_assignment_gate = model_surface_assignment_feasibility_gate(
            self.config,
            index=solidity_index,
            requests=model_surface_requests,
            assignments=model_surface_review_assignments,
            required=bool(solidity_projects) and not scanner_only,
            minimum_critical_root_lineages=minimum_critical_surface_lineages,
        )
        lower_profile_surface_gate = model_surface_assignment_feasibility_gate(
            self.config,
            index=solidity_index,
            requests=model_surface_requests,
            assignments=model_surface_review_assignments,
            required=bool(solidity_projects) and not scanner_only,
            minimum_critical_root_lineages=1,
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
                    certification=model_certification_required,
                    require_single_model_per_role=model_certification_required,
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
                    reasoning=controls.reasoning,
                    qualification_routing=_openrouter_qualification_routing(
                        self.production_qualification
                    ),
                    token_budgets=self.config.token_budgets,
                    effective_privacy_policy=self.effective_privacy_policy,
                    privacy_authorization=self.privacy_authorization,
                )
                self._owns_client = True
                self.api_key = ""
            try:
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

        packages: list[ContextPackage] = []
        accepted_specialist_outcomes: list[SpecialistAcceptedOutcome] = []
        if context_builder is not None and self.client is not None:
            client = self.client
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
            ) -> None:
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
                accepted_specialist_outcomes.append(
                    SpecialistAcceptedOutcome.build(
                        request_id=record.request_id,
                        specialist_role=specialist_role,
                        request_role=request_role,
                        outcome_kind=outcome_kind,
                        validated_response_sha256=record.validated_response_sha256,
                        context_request_evidence_sha256=context_evidence.evidence_sha256,
                        requested_surface_count=requested_surface_count,
                        surface_review_artifact_sha256=(
                            surface_artifact.artifact_sha256
                            if surface_artifact is not None
                            else None
                        ),
                    )
                )

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
                            role,
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

            threat_context = build_context("threat_model")
            if threat_context is not None:
                packages.append(threat_context)
                try:
                    self.logger.info("Running threat-model role", extra={"run_id": run_id})
                    threat_model = await bounded_call(
                        ThreatModelAgent(self.config, self.client).run(threat_context)
                    )
                    threat_model, threat_location_rejections = _validated_threat_model(
                        discovery.root,
                        threat_model,
                        context_hashes=context_hash_index([threat_context]),
                    )
                except BudgetExhaustedError as exc:
                    incomplete.append(f"threat_model: {exc}")
                    terminal_code = ExitCode.INCOMPLETE
                    budget_halted = True
                except OpenRouterError as exc:
                    incomplete.append(f"threat_model: {exc}")
                    terminal_code = ExitCode.MODEL_FAILURE
            check_accounted_budget()

            agent_specs = (
                ()
                if budget_halted
                else (
                    ("source_audit", SourceAuditAgent),
                    ("business_logic", BusinessLogicAgent),
                    ("configuration", ConfigurationAgent),
                )
            )
            tasks: list[tuple[str, asyncio.Task[Any]]] = []
            for role, agent_type in agent_specs:
                package = build_context(
                    role,
                    threat_model=threat_model,
                    requested_model_surfaces=model_surface_review_assignments.get(
                        role,
                        [],
                    ),
                )
                if package is None:
                    break
                packages.append(package)
                agent = agent_type(self.config, self.client)
                tasks.append(
                    (
                        role,
                        asyncio.create_task(
                            bounded_call(agent.run(package)),
                            name=f"model:{role}",
                        ),
                    )
                )
            specialist_roles = (
                [
                    role
                    for role in SPECIALIST_INVESTIGATOR_ROLES
                    if role in self.config.models.specialists
                ]
                if self.config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
                else []
            )
            blind_specialist_contexts: list[tuple[str, Any]] = []
            if not budget_halted:
                # Context construction is synchronous. Freeze every investigator's
                # first-pass package before yielding to any investigator task, so
                # no model-produced candidate can enter a peer discovery context.
                for role in specialist_roles:
                    package = build_specialist_context(
                        role,
                        threat_model=threat_model,
                        requested_model_surfaces=model_surface_review_assignments.get(
                            f"specialist:{role}",
                            [],
                        ),
                    )
                    if package is None:
                        break
                    blind_specialist_contexts.append((role, package))
            for role, task in tasks:
                try:
                    batch = await task
                    sealed_context, _completion_usage = register_finding_result(
                        batch,
                        expected_role=role,
                    )
                    candidates.extend(batch.findings)
                    if batch.surface_review_artifact is not None:
                        artifact = batch.surface_review_artifact
                        model_surface_review_artifacts.append(artifact)
                        model_surface_review_contexts.setdefault(
                            artifact.request_id,
                            [],
                        ).append(sealed_context)
                    if batch.findings and time_to_first_candidate_seconds is None:
                        time_to_first_candidate_seconds = time.monotonic() - run_started_monotonic
                except BudgetExhaustedError as exc:
                    incomplete.append(f"{role}: {exc}")
                    terminal_code = ExitCode.INCOMPLETE
                    budget_halted = True
                except OpenRouterError as exc:
                    incomplete.append(f"{role}: {exc}")
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.MODEL_FAILURE
            check_accounted_budget()

            specialist_tasks: list[tuple[str, asyncio.Task[Any]]] = []
            if not budget_halted:
                for role, package in blind_specialist_contexts:
                    packages.append(package)
                    specialist_tasks.append(
                        (
                            role,
                            asyncio.create_task(
                                bounded_call(
                                    SpecialistFindingAgent(
                                        self.config,
                                        self.client,
                                        role,
                                    ).run(package)
                                ),
                                name=f"model:specialist:{role}",
                            ),
                        )
                    )
            for role, task in specialist_tasks:
                try:
                    batch = await task
                    sealed_context, completion_usage = register_finding_result(
                        batch,
                        expected_role=f"specialist:{role}",
                    )
                    accept_specialist_outcome(
                        completion_usage=completion_usage,
                        validated_context=sealed_context,
                        specialist_role=role,
                        request_role=f"specialist:{role}",
                        outcome_kind=SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW,
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
                    if batch.findings and time_to_first_candidate_seconds is None:
                        time_to_first_candidate_seconds = time.monotonic() - run_started_monotonic
                except BudgetExhaustedError as exc:
                    incomplete.append(f"specialist:{role}: {exc}")
                    terminal_code = ExitCode.INCOMPLETE
                    budget_halted = True
                except OpenRouterError as exc:
                    incomplete.append(f"specialist:{role}: {exc}")
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.MODEL_FAILURE
            check_accounted_budget()

            if (
                not budget_halted
                and self.config.profile in {AuditProfile.DEEP, AuditProfile.MAXIMUM_ASSURANCE}
                and "invariant_review" in self.config.models.specialists
            ):
                invariant_context = build_specialist_context(
                    "invariant_review",
                    threat_model=threat_model,
                )
                if invariant_context is not None:
                    packages.append(invariant_context)
                    try:
                        invariant_result = await bounded_call(
                            InvariantReviewAgent(
                                self.config,
                                self.client,
                            ).run_with_evidence(invariant_context)
                        )
                        invariant_review_batch = invariant_result.value
                        invariant_review = validate_invariant_review(
                            discovery.root,
                            invariant_review_batch,
                            index=solidity_index,
                            context_hashes=context_hash_index([invariant_context]),
                        )
                        accept_specialist_outcome(
                            completion_usage=invariant_result.completion_usage,
                            validated_context=invariant_context,
                            specialist_role="invariant_review",
                            request_role="specialist:invariant_review",
                            outcome_kind=SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW,
                        )
                    except BudgetExhaustedError as exc:
                        incomplete.append(f"specialist:invariant_review: {exc}")
                        terminal_code = ExitCode.INCOMPLETE
                        budget_halted = True
                    except OpenRouterError as exc:
                        incomplete.append(f"specialist:invariant_review: {exc}")
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                check_accounted_budget()

            if pending_execution_candidates:
                candidates.extend(pending_execution_candidates)
                execution_candidates_integrated = True
            validations = {
                candidate.candidate_id: validate_candidate(
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
            verifier_context = None
            verifier_agent = VerifierAgent(self.config, self.client)
            prepared_verification_input = verifier_agent.prepare_input(candidates)
            if candidates and not budget_halted:
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
            if candidates and verifier_context is not None:
                try:
                    self.logger.info(
                        "Running independent verifier",
                        extra={"run_id": run_id},
                    )
                    verifications = await bounded_call(
                        verifier_agent.run(
                            candidates,
                            verifier_context,
                            prepared_input=prepared_verification_input,
                        )
                    )
                    omitted_verifications = [
                        decision.candidate_id
                        for decision in verifications.decisions
                        if decision.rationale == "Verifier omitted this submitted candidate"
                    ]
                    if omitted_verifications:
                        incomplete.append(
                            f"verifier omitted {len(omitted_verifications)} submitted candidate(s)"
                        )
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                except (BudgetExhaustedError, OpenRouterError) as exc:
                    incomplete.append(f"verifier: {exc}")
                    if isinstance(exc, BudgetExhaustedError):
                        budget_halted = True
                    terminal_code = (
                        ExitCode.INCOMPLETE
                        if isinstance(exc, BudgetExhaustedError)
                        else ExitCode.MODEL_FAILURE
                    )
                    verifications = _insufficient_verifications(candidates)
            elif candidates:
                verifications = _insufficient_verifications(candidates)
            check_accounted_budget()
            decisions = {decision.candidate_id: decision for decision in verifications.decisions}
            candidates = _attach_verifier_votes(
                candidates,
                decisions,
                self.client,
            )
            candidates = _attach_formal_counterexamples(candidates, formal_runs)
            cross_examination_candidates = [
                candidate
                for candidate in candidates
                if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
            ]
            cross_examination_required = bool(cross_examination_candidates) and (
                "falsifier" in self.config.models.specialists
                or self.config.profile is AuditProfile.MAXIMUM_ASSURANCE
            )
            if cross_examination_required and not budget_halted:
                reviewer_models = select_candidate_falsifier_models(self.config)
                if len(reviewer_models) != 2:
                    incomplete.append(
                        "candidate cross-examination requires two registered models "
                        "from distinct immutable root lineages"
                    )
                    if terminal_code is ExitCode.SUCCESS:
                        terminal_code = ExitCode.CONFIGURATION
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
                        cross_examiner_tasks = [
                            (
                                reviewer_index,
                                candidate.candidate_id,
                                root_lineage,
                                asyncio.create_task(
                                    bounded_call(
                                        CandidateCrossExaminerAgent(
                                            self.config,
                                            self.client,
                                            reviewer_index=reviewer_index,
                                            model_id=model_id,
                                            root_lineage=root_lineage,
                                        ).run(
                                            [candidate],
                                            prepared_cross_examinations[candidate.candidate_id][1],
                                            prepared_input=prepared_cross_examinations[
                                                candidate.candidate_id
                                            ][0],
                                        )
                                    ),
                                    name=f"model:{
                                        candidate_falsifier_role(
                                            candidate.candidate_id,
                                            reviewer_index,
                                        )
                                    }",
                                ),
                            )
                            for reviewer_index, (model_id, root_lineage) in enumerate(
                                reviewer_models,
                                start=1,
                            )
                            for candidate in cross_examination_candidates
                        ]
                        for (
                            reviewer_index,
                            candidate_id,
                            _root_lineage,
                            task,
                        ) in cross_examiner_tasks:
                            try:
                                cross_examinations.extend(await task)
                            except BudgetExhaustedError as exc:
                                incomplete.append(
                                    f"candidate_falsifier:{candidate_id}:{reviewer_index}: {exc}"
                                )
                                terminal_code = ExitCode.INCOMPLETE
                                budget_halted = True
                            except OpenRouterError as exc:
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
                check_accounted_budget()
            eligible_for_reproduction = _eligible_reproduction_candidates(
                candidates,
                decisions,
                validations,
                limit=self.config.reproduction.max_candidates,
            )
            if (
                solidity_projects
                and eligible_for_reproduction
                and verifier_context is not None
                and fork_acknowledged
                and self.config.reproduction.enabled
                and not budget_halted
            ):
                planner_tasks: list[tuple[str, str | None, ContextPackage, asyncio.Task[Any]]] = []
                configured_planners = [
                    role
                    for role in ("test_generation", "exploit_reproduction_planner")
                    if role in self.config.models.specialists
                ]
                if configured_planners:
                    for planner_role in configured_planners:
                        planner = ExploitTestPlannerAgent(
                            self.config,
                            self.client,
                            investigator_role="ensemble",
                            planner_role=planner_role,
                        )
                        prepared_planner_input = planner.prepare_input(eligible_for_reproduction)
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
                                planner_context,
                                asyncio.create_task(
                                    bounded_call(
                                        planner.run_with_evidence(
                                            eligible_for_reproduction,
                                            planner_context,
                                            prepared_input=prepared_planner_input,
                                        )
                                    ),
                                    name=f"model:{planner_role}:exploit_test",
                                ),
                            )
                        )
                else:
                    by_role: dict[str, list[CandidateFinding]] = {}
                    for candidate in eligible_for_reproduction:
                        # Execution-origin candidates deliberately have no originating
                        # model role. A later planner may analyze them under the
                        # ordinary source-audit role without acquiring authority over
                        # their host-derived identity, location, or provenance.
                        planning_role = candidate.role or "source_audit"
                        by_role.setdefault(planning_role, []).append(candidate)
                    for role, role_candidates in sorted(by_role.items()):
                        planner = ExploitTestPlannerAgent(
                            self.config,
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
                                planner_context,
                                asyncio.create_task(
                                    bounded_call(
                                        planner.run_with_evidence(
                                            role_candidates,
                                            planner_context,
                                            prepared_input=prepared_planner_input,
                                        )
                                    ),
                                    name=f"model:{role}:exploit_test",
                                ),
                            )
                        )
                for planner_label, specialist_role, planner_context, task in planner_tasks:
                    try:
                        planner_result = await task
                        if planner_result is None:
                            raise OpenRouterSchemaError(
                                "scheduled planner returned no completion evidence"
                            )
                        batch = planner_result.value
                        if specialist_role is not None:
                            accept_specialist_outcome(
                                completion_usage=planner_result.completion_usage,
                                validated_context=planner_context,
                                specialist_role=specialist_role,
                                request_role=f"specialist:{specialist_role}:exploit_test",
                                outcome_kind=(SpecialistAcceptedOutcomeKind.TEST_GENERATION),
                            )
                        generated_tests.extend(batch.tests)
                    except BudgetExhaustedError as exc:
                        incomplete.append(f"{planner_label}:exploit_test: {exc}")
                        terminal_code = ExitCode.INCOMPLETE
                        budget_halted = True
                    except OpenRouterError as exc:
                        incomplete.append(f"{planner_label}:exploit_test: {exc}")
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                generated_tests = _unique_generated_tests(generated_tests)[
                    : self.config.reproduction.max_total_tests
                ]
                candidates_by_id = {
                    candidate.candidate_id: candidate for candidate in eligible_for_reproduction
                }
                for specification in generated_tests:
                    selected_candidate = candidates_by_id.get(specification.candidate_id)
                    if selected_candidate is None:
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
                if generated_tests and reproductions and not budget_halted:
                    falsifier_agent = FalsifierAgent(self.config, self.client)
                    prepared_falsifier_input = falsifier_agent.prepare_input(
                        candidates=eligible_for_reproduction,
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
                                    candidates=eligible_for_reproduction,
                                    tests=generated_tests,
                                    results=reproductions,
                                    context=falsifier_context,
                                    prepared_input=prepared_falsifier_input,
                                )
                            )
                            if "falsifier" in self.config.models.specialists:
                                accept_specialist_outcome(
                                    completion_usage=falsifier_result.completion_usage,
                                    validated_context=falsifier_context,
                                    specialist_role="falsifier",
                                    request_role="specialist:falsifier",
                                    outcome_kind=(SpecialistAcceptedOutcomeKind.FALSIFICATION),
                                )
                            falsifications = falsifier_result.value
                        except BudgetExhaustedError as exc:
                            incomplete.append(f"falsifier: {exc}")
                            terminal_code = ExitCode.INCOMPLETE
                            budget_halted = True
                        except OpenRouterError as exc:
                            incomplete.append(f"falsifier: {exc}")
                            if terminal_code is ExitCode.SUCCESS:
                                terminal_code = ExitCode.MODEL_FAILURE
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
            groups = group_candidates(candidates)
            candidate_groups_count = len(groups)
            group_payloads = [
                _group_payload(group, decisions, validations, scanner_findings) for group in groups
            ]
            judge_context = None
            judge_agent = JudgeAgent(self.config, self.client)
            prepared_judgment_input = judge_agent.prepare_input(
                groups=group_payloads,
                threat_model=threat_model,
            )
            if groups and not budget_halted:
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
                try:
                    self.logger.info("Running final judge", extra={"run_id": run_id})
                    judgment = await bounded_call(
                        judge_agent.run(
                            groups=group_payloads,
                            context=judge_context,
                            threat_model=threat_model,
                            prepared_input=prepared_judgment_input,
                        )
                    )
                    returned_group_ids = [decision.group_id for decision in judgment.decisions]
                    expected_group_ids = {group.group_id for group in groups}
                    missing_group_ids = expected_group_ids - set(returned_group_ids)
                    duplicate_group_count = len(returned_group_ids) - len(set(returned_group_ids))
                    if missing_group_ids or duplicate_group_count:
                        incomplete.append(
                            "judge returned an incomplete group decision set "
                            f"(missing={len(missing_group_ids)}, "
                            f"duplicates={duplicate_group_count})"
                        )
                        if terminal_code is ExitCode.SUCCESS:
                            terminal_code = ExitCode.MODEL_FAILURE
                    judge_decisions = {
                        decision.group_id: decision for decision in judgment.decisions
                    }
                except (BudgetExhaustedError, OpenRouterError) as exc:
                    incomplete.append(f"judge: {exc}")
                    if isinstance(exc, BudgetExhaustedError):
                        budget_halted = True
                    terminal_code = (
                        ExitCode.INCOMPLETE
                        if isinstance(exc, BudgetExhaustedError)
                        else ExitCode.MODEL_FAILURE
                    )
            check_accounted_budget()
            # Revalidate after the last model call so stale line references cannot
            # survive a repository change during a long audit.
            validations = {
                candidate.candidate_id: validate_candidate(
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

        if pending_execution_candidates and not execution_candidates_integrated:
            candidates.extend(pending_execution_candidates)
            validations.update(
                {
                    candidate.candidate_id: validate_candidate(
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

        assurance_high_critical_candidates = [
            candidate
            for candidate in candidates
            if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
            and (validation := validations.get(candidate.candidate_id)) is not None
            and validation.valid
        ]
        reproduction_resolutions = _build_candidate_reproduction_resolutions(
            candidates=assurance_high_critical_candidates,
            results=reproductions,
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
            solidity_coverage = solidity_coverage.model_copy(
                update={
                    "tests_executed": sum(result.attempts for result in reproductions),
                    "tests_failed": sum(
                        1
                        for result in reproductions
                        if result.state
                        not in {
                            ReproductionState.REPRODUCED,
                            ReproductionState.REPRODUCED_AND_MINIMIZED,
                        }
                    ),
                    "reproduction_attempts": sum(
                        1 for result in reproductions if result.attempts > 0
                    ),
                }
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
            eligible_candidates=eligible_for_reproduction,
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
        ):
            try:
                report_quality_agent = ReportQualityAgent(
                    self.config,
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
                    report_quality_result = await report_quality_agent.run_with_evidence(
                        findings=final_findings,
                        rejected_count=len(rejected_findings),
                        coverage=solidity_coverage,
                        quality_gates=quality_gates,
                        incomplete_reasons=incomplete,
                        context=report_quality_context,
                        prepared_input=prepared_report_quality_input,
                    )
                    accept_specialist_outcome(
                        completion_usage=report_quality_result.completion_usage,
                        validated_context=report_quality_context,
                        specialist_role="report_quality",
                        request_role="specialist:report_quality",
                        outcome_kind=SpecialistAcceptedOutcomeKind.REPORT_QUALITY,
                    )
                    report_quality_review = report_quality_result.value
            except ContextBudgetError as exc:
                incomplete.append(f"report_quality: {exc}")
                budget_halted = True
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.INCOMPLETE
            except BudgetExhaustedError as exc:
                incomplete.append(f"report_quality: {exc}")
                budget_halted = True
                terminal_code = ExitCode.INCOMPLETE
            except OpenRouterError as exc:
                incomplete.append(f"report_quality: {exc}")
                if terminal_code is ExitCode.SUCCESS:
                    terminal_code = ExitCode.MODEL_FAILURE
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
        if provider_session is not None and not provider_session.usage_evidence_consistent:
            mismatch_reason = (
                "provider usage execution evidence differs from the established session"
            )
            if mismatch_reason not in incomplete:
                incomplete.append(mismatch_reason)
            terminal_code = ExitCode.MODEL_FAILURE
        model_review_coverage = build_model_review_coverage(
            self.config,
            usage_records=model_credit_usage,
            review_artifacts=model_surface_review_artifacts,
            review_contexts_by_request=model_surface_review_contexts,
            index=solidity_index,
            graphs=solidity_graphs,
            invariants=solidity_invariants,
            economic_simulations=economic_simulations,
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
            usage_records=model_credit_usage,
            contexts=packages,
            accepted_outcomes=tuple(
                outcome
                for outcome in accepted_specialist_outcomes
                if outcome.request_id in {record.request_id for record in model_credit_usage}
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
                candidate.candidate_id
                for candidate in eligible_for_reproduction
                if candidate.severity in {Severity.HIGH, Severity.CRITICAL}
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
            if eligible_for_reproduction:
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
                    candidate.candidate_id for candidate in eligible_for_reproduction
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
            eligible_candidates=eligible_for_reproduction,
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
            "cross-examination.json",
            "specialist-execution.json",
            "model-review-coverage.json",
            "scope-assessment.json",
            "prior-audit-comparison.json",
            "maximum_assurance_traceability.json",
            "run-evidence-manifest.json",
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
                solidity_coverage.quality_metrics if solidity_coverage is not None else {}
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
        )
        log_handler.flush()
        self._write_artifacts(
            run_dir=run_dir,
            report=report,
            candidates=candidates,
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
        )
        self.logger.removeHandler(log_handler)
        log_handler.close()
        return PipelineResult(report=report, run_dir=run_dir, exit_code=terminal_code)

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
        qualification_required = maximum_assurance_model_certification_required(self.config)
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
            type(self.client) is OpenRouterClient
            and self.client.execution_evidence is ExecutionEvidenceKind.REAL
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
            usage=usage.records,
            budget_usd=self.config.execution.budget_usd,
            accounted_cost_usd=usage.accounted_cost_usd,
            findings=findings,
            rejected_findings=rejected,
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
                "raw_material_stored": (
                    self.config.privacy.store_raw_prompts or self.config.privacy.store_raw_responses
                ),
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
        candidates: list[CandidateFinding],
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
    ) -> None:
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
                "completed": report.completed,
                "quality_status": report.quality_status.value,
                "run_status": (report.run_status.value if report.run_status is not None else None),
                "minimum_analysis_floor": (
                    report.minimum_analysis_floor.model_dump(mode="json")
                    if report.minimum_analysis_floor is not None
                    else None
                ),
                "incomplete_reasons": report.incomplete_reasons,
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
                "findings": [candidate.model_dump(mode="json") for candidate in candidates],
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
        write_json(run_dir / "final-findings.json", report)
        (run_dir / "audit-report.md").write_text(render_markdown(report), encoding="utf-8")
        write_json(
            run_dir / "audit-results.sarif",
            generate_sarif(
                report.findings,
                maximum_assurance=report.maximum_assurance,
                run_status=report.run_status,
                quality_status=report.quality_status,
                completed=report.completed,
                incomplete_reasons=report.incomplete_reasons,
            ),
        )
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
        )
        write_run_evidence_manifest(
            run_dir / "run-evidence-manifest.json",
            manifest,
        )
        validate_manifest_artifacts(manifest, run_dir)
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
            "verification-results.json",
            "final-findings.json",
            "audit-report.md",
            "audit-results.sarif",
            "solidity-projects.json",
            "dependency-preparation.json",
            "dependency-sbom.json",
            "solidity-compilation.json",
            "solidity-index.json",
            "solidity-graphs.json",
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
            "scope-assessment.json",
            "prior-audit-comparison.json",
            "reproduction-results.json",
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
    session_evidence = client.execution_evidence
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

    findings: list[ScannerFinding] = []
    for finding in run.findings:
        locations = [
            location
            for location in finding.locations
            if location.path != ".git" and not location.path.startswith(".git/")
        ]
        if not locations:
            continue
        validations = [
            validate_location(root, location).model_dump(mode="json") for location in locations
        ]
        findings.append(
            finding.model_copy(
                update={
                    "locations": locations,
                    "metadata": {
                        **finding.metadata,
                        "location_validation": validations,
                    },
                }
            )
        )
    updated = run.model_copy(
        update={
            "findings": findings,
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **updated.model_dump(mode="json"),
            "execution_observation_sha256": updated.expected_execution_observation_sha256(),
        }
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
        errors = [error for result in validation_results for error in result.errors]
        valid_locations = [
            location
            for location, result in zip(scanner.locations, validation_results, strict=True)
            if result.valid
        ]
        hashes = [
            result.content_hash
            for result in validation_results
            if result.valid and result.content_hash
        ]
        aggregate_hash = (
            hashlib.sha256("".join(sorted(hashes)).encode()).hexdigest() if hashes else None
        )
        status = FindingStatus.NEEDS_REVIEW if valid_locations else FindingStatus.REJECTED
        findings.append(
            Finding(
                id=_scanner_stable_finding_id(
                    scanner,
                    valid_locations or scanner.locations,
                ),
                group_id=f"scanner-{scanner.fingerprint[:16]}",
                origin_kind=FindingOriginKind.STATIC_ANALYZER,
                title=scanner.title,
                status=status,
                severity=scanner.severity,
                confidence=0.8 if valid_locations else 0.0,
                cwe=scanner.cwe,
                owasp=[],
                summary=scanner.message,
                impact=(
                    "The scanner matched a potentially security-relevant pattern; "
                    "reachability and concrete impact require local review."
                ),
                preconditions=["The scanner rule applies to a reachable application path"],
                locations=valid_locations or scanner.locations,
                attack_path=[
                    f"{scanner.scanner} matched rule {scanner.rule_id}",
                    "A maintainer confirms attacker reachability and impact locally",
                ],
                evidence=[
                    Evidence(
                        type="scanner",
                        source=scanner.scanner,
                        rule_id=scanner.rule_id,
                        description=scanner.message,
                        fingerprint=scanner.fingerprint,
                    )
                ],
                false_positive_conditions=[
                    "The matched path is unreachable or protected by a control the scanner cannot model"
                ],
                recommendation=(
                    "Review the cited location and the scanner rule guidance, then apply "
                    "the narrowest remediation supported by local verification."
                ),
                verification_test=VerificationTest(
                    description=(
                        "Reproduce the scanner condition against a synthetic local fixture "
                        "without contacting external systems"
                    )
                ),
                location_validation=LocationValidation(
                    valid=bool(valid_locations),
                    content_hash=aggregate_hash,
                    errors=errors,
                    validated_at=datetime.now(UTC),
                ),
                disagreement=(
                    "Scanner-only output has not been accepted by the independent verifier."
                ),
                contributing_candidate_ids=[scanner.fingerprint],
                evidence_strength=(
                    scanner.evidence_strength
                    if status is not FindingStatus.REJECTED
                    else EvidenceStrength.NONE
                ),
            )
        )
    return findings


def _scanner_stable_finding_id(
    scanner: ScannerFinding,
    locations: list[Location],
) -> str:
    primary = sorted(
        locations,
        key=lambda location: (
            location.path,
            location.start_line,
            location.end_line,
            location.symbol or "",
        ),
    )[0]
    vulnerability_class = (
        sorted(value.upper() for value in scanner.cwe)[0]
        if scanner.cwe
        else f"{scanner.scanner}:{scanner.rule_id}"
    )
    payload = "\0".join(
        (
            vulnerability_class,
            primary.path,
            str(primary.start_line),
            primary.symbol or "",
        )
    )
    return f"MMA-{hashlib.sha256(payload.encode()).hexdigest()[:12].upper()}"


def _attach_verifier_votes(
    candidates: list[CandidateFinding],
    decisions: dict[str, VerificationDecision],
    client: OpenRouterClient,
) -> list[CandidateFinding]:
    usage = next(
        (
            record
            for record in reversed(client.usage.records)
            if record.role == "verifier" and is_creditable_usage_record(record)
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
            role="verifier",
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


def _attach_formal_counterexamples(
    candidates: list[CandidateFinding],
    formal_runs: list[FormalToolRun],
) -> list[CandidateFinding]:
    """Attach only source-overlapping formal counterexamples to candidates.

    A proof about an unrelated property is deliberately not used to suppress a
    finding. Counterexamples without a validated indexed location also remain
    run-level evidence rather than candidate evidence.
    """

    result: list[CandidateFinding] = []
    for candidate in candidates:
        evidence = list(candidate.evidence)
        for run in formal_runs:
            for formal in run.evidence:
                if (
                    formal.result_kind is not FormalResultKind.COUNTEREXAMPLE
                    or not formal.locations
                    or not any(
                        candidate_location.path == formal_location.path
                        and candidate_location.start_line <= formal_location.end_line
                        and formal_location.start_line <= candidate_location.end_line
                        for candidate_location in candidate.locations
                        for formal_location in formal.locations
                    )
                ):
                    continue
                fingerprint = hashlib.sha256(
                    json.dumps(
                        {
                            "tool": formal.tool,
                            "property": formal.property_id,
                            "counterexample": formal.counterexample,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()
                evidence.append(
                    Evidence(
                        type="formal",
                        source=formal.tool,
                        rule_id=FormalResultKind.COUNTEREXAMPLE.value,
                        description=(
                            f"Source-overlapping formal counterexample for "
                            f"{formal.property_id}: {formal.property_description}"
                        ),
                        fingerprint=fingerprint,
                    )
                )
        result.append(candidate.model_copy(update={"evidence": _deduplicate_evidence(evidence)}))
    return result


def _deduplicate_evidence(evidence: list[Evidence]) -> list[Evidence]:
    by_key: dict[tuple[str, str, str | None, str | None], Evidence] = {}
    for item in evidence:
        by_key[(item.type, item.source, item.rule_id, item.fingerprint)] = item
    return list(by_key.values())


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


def _insufficient_verifications(
    candidates: list[CandidateFinding],
) -> VerificationBatch:
    return VerificationBatch(
        decisions=[
            VerificationDecision(
                candidate_id=candidate.candidate_id,
                verdict=VerificationVerdict.INSUFFICIENT_CONTEXT,
                rationale="Verifier was unavailable",
                source_to_sink="Not established",
                reachability="Not established",
                authentication="Unknown",
                privilege_requirements="Unknown",
                environmental_assumptions=[],
                guards_and_controls=[],
                false_positive_conditions=candidate.false_positive_conditions,
                safe_verification_test=VerificationTest(
                    description="Review the cited code locally in a disposable fixture"
                ),
                confidence=0,
            )
            for candidate in candidates
        ]
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


def _build_candidate_reproduction_resolutions(
    *,
    candidates: list[CandidateFinding],
    results: list[ReproductionResult],
) -> list[CandidateReproductionResolution]:
    """Derive one fail-closed terminal resolution per high/critical candidate."""

    results_by_candidate: dict[str, list[ReproductionResult]] = {}
    for result in results:
        results_by_candidate.setdefault(result.candidate_id, []).append(result)
    resolutions: list[CandidateReproductionResolution] = []
    for candidate in sorted(candidates, key=lambda item: item.candidate_id):
        if candidate.severity not in {Severity.HIGH, Severity.CRITICAL}:
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
