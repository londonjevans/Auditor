"""Generate or verify the typed release-evidence JSON schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationReport
from mmaudit.benchmark.development import (
    DevelopmentBenchmarkBinding,
    DevelopmentBenchmarkScore,
    DevelopmentBenchmarkTruth,
    DevelopmentJudgmentImpactScore,
)
from mmaudit.benchmark.development_comparison import DevelopmentBenchmarkComparison
from mmaudit.benchmark.development_corpus import (
    DevelopmentCorpusBenchmarkBinding,
    DevelopmentCorpusBenchmarkScore,
    DevelopmentCorpusBenchmarkTruth,
)
from mmaudit.benchmark.development_corpus_control_measurement import (
    DevelopmentCorpusControlMeasurement,
)
from mmaudit.benchmark.development_corpus_ensemble import DevelopmentCorpusEnsembleScore
from mmaudit.benchmark.development_corpus_resume import DevelopmentCorpusResumeBenchmarkScore
from mmaudit.benchmark.development_ensemble import DevelopmentEnsembleScore
from mmaudit.benchmark.engine import BenchmarkReport
from mmaudit.config import ModelsConfig
from mmaudit.forensic_export import ForensicDeliveryDescriptor
from mmaudit.models.actor_model import ActorModel, ActorModelEvaluation
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerEvidence
from mmaudit.models.authenticated_runner_cost_plan import AuthenticatedRunnerStagedCostPlan
from mmaudit.models.authenticated_runner_durable_bundle import (
    AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT,
    AUTHENTICATED_RUNNER_DURABLE_MAX_ATTEMPTS,
    AUTHENTICATED_RUNNER_DURABLE_ROUTING_KEYS,
    AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT,
    AuthenticatedRunnerDurableEvidenceBundle,
)
from mmaudit.models.authenticated_runner_smoke import AuthenticatedRunnerSmokeEvidenceBundle
from mmaudit.models.authenticated_runner_smoke_corpus import (
    AuthenticatedRunnerSmokeCorpusBundle,
)
from mmaudit.models.autonomous_benchmark_verdict import (
    EvidenceSealVerdictPolicy,
    EvidenceSealVerdictProjection,
)
from mmaudit.models.calibration import ModelCalibrationArtifact
from mmaudit.models.candidate_revocation import CandidateSelectionRevocationRegistry
from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.models.coverage_planning import (
    ModelPortfolioResourcePreflight,
    ModelSurfaceCoveragePlan,
    ModelSurfaceResourcePreflight,
)
from mmaudit.models.development_audit import (
    DevelopmentAuditObservation,
    DevelopmentAuditPlan,
    DevelopmentAuditShardObservation,
    DevelopmentScoredAuditShardObservation,
)
from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusPlan,
    DevelopmentCorpusResponse,
    DevelopmentCorpusShardObservation,
)
from mmaudit.models.development_corpus_ensemble import (
    DevelopmentCorpusEnsembleObservation,
    DevelopmentCorpusEnsemblePlan,
)
from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentObservation,
    DevelopmentCorpusJudgmentPlan,
    DevelopmentCorpusJudgmentResponse,
    DevelopmentCorpusJudgmentShardObservation,
)
from mmaudit.models.development_corpus_resume import (
    DevelopmentCorpusResumeAttempt,
    DevelopmentCorpusResumeHistory,
    DevelopmentCorpusResumePlan,
)
from mmaudit.models.development_costs import DevelopmentCostEstimate, DevelopmentCostPolicy
from mmaudit.models.development_diagnostics import (
    DevelopmentCompletionTelemetry,
    DevelopmentResponseRejection,
)
from mmaudit.models.development_ensemble import (
    DevelopmentEnsembleObservation,
    DevelopmentEnsemblePlan,
)
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentObservation,
    DevelopmentJudgmentPlan,
    DevelopmentJudgmentShardObservation,
)
from mmaudit.models.development_review import (
    DevelopmentJudgmentResponse,
    DevelopmentReviewObservation,
    DevelopmentReviewResponse,
    DevelopmentScoredReviewResponse,
)
from mmaudit.models.development_routing import DevelopmentRoutingEvidence
from mmaudit.models.endpoint_inventory import OpenRouterEndpointInventoryDiagnostic
from mmaudit.models.evidence_seal_authority import EvidenceSealedAuthorityEvidence
from mmaudit.models.frozen_lineage_authority import FrozenModelLineageProvenance
from mmaudit.models.ground_truth_authority import FrozenGroundTruthProvenance
from mmaudit.models.identifiers import EXACT_MODEL_ID_PATTERN
from mmaudit.models.learning import TerminalAuditLearningRecord
from mmaudit.models.lineage_authority import (
    ModelLineageAuthorityEnvelope,
    ModelLineageTrustAnchor,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.openrouter import OpenRouterStructuredRequestCostPreview
from mmaudit.models.policy_eligibility import (
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyEligibilityEvaluation,
    PolicyReviewSignal,
)
from mmaudit.models.policy_eligibility_authority import (
    ModelPolicyEligibilityAuthorityEnvelope,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    ModelPolicyEligibilityTrustAnchor,
    PolicyEligibilitySourceObservation,
)
from mmaudit.models.policy_eligibility_refresh import ModelPolicyEligibilityRefreshArtifact
from mmaudit.models.policy_selection import (
    AuditModelSelection,
    AuditModelSelectionEvidenceBundle,
)
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteReconciliation,
)
from mmaudit.models.public_lineage_authority import (
    PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
    PublicModelLineageEvidenceBundle,
)
from mmaudit.models.qualification import ModelQualificationArtifact, QualificationPolicy
from mmaudit.models.refresh import (
    ModelRefreshAttempt,
    ModelRefreshDiff,
    ModelRefreshFreshness,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
)
from mmaudit.models.refresh_runtime import (
    AuditModelRefreshEvidence,
    AuditModelRefreshPricingEvidence,
)
from mmaudit.models.refresh_staging import ModelRefreshWorkflowStatus
from mmaudit.models.route_runtime_evidence import RouteRuntimeEvidenceArtifact
from mmaudit.models.scheduler import SchedulerArtifact, SchedulerRetainedJournalReference
from mmaudit.models.schemas import (
    ActorModelBaselineArtifact,
    AuditModelRefreshPricingAttemptEvidence,
    ConsensusReviewArtifact,
    HardhatInventoryPhaseRequest,
    HardhatReporterExecution,
    HardhatReporterInventory,
    HardhatTestPhaseRequest,
    KnownIssueTaxonomy,
    KnownIssueTaxonomyCoverage,
    LanguageCapabilityArtifact,
    SolidityGraphFactKind,
    SolidityGraphKind,
    SolidityGraphNodeKind,
)
from mmaudit.models.sharding import (
    SolidityCoverageArtifact,
    SolidityGraphsArtifact,
    SolidityShardsArtifact,
)
from mmaudit.orchestration.autonomy_gate_inventory import (
    AUTONOMY_INVENTORY_PATH,
    AutonomyGateInventory,
    render_autonomy_gate_inventory,
)
from mmaudit.orchestration.context_manifest import ContextManifest
from mmaudit.orchestration.managed_host_tools import ManagedHostToolManifest
from mmaudit.orchestration.managed_provisioning import (
    ManagedProvisioningReceipt,
    ManagedProvisioningState,
)
from mmaudit.orchestration.managed_toolchain import (
    MANAGED_TOOLCHAIN_BUNDLE_RESOURCE,
    ManagedToolchainBundle,
    render_default_managed_toolchain_bundle,
)
from mmaudit.orchestration.manifest import (
    _KNOWN_ISSUE_TAXONOMY_BINDING_IDS,
    AUDIT_MODEL_REFRESH_BINDING_IDS,
    AUDIT_MODEL_REFRESH_EVIDENCE_PATH,
    AUDIT_MODEL_REFRESH_PRICING_BINDING_IDS,
    AUDIT_MODEL_REFRESH_PRICING_EVIDENCE_PATH,
    AUDIT_MODEL_SELECTION_BINDING_IDS,
    AUDIT_MODEL_SELECTION_EVIDENCE_PATH,
    KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
    KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
    MODEL_REVIEW_ARTIFACT_INVENTORY_PATH,
)
from mmaudit.privacy import PrivacyRetentionConsent
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import ReleaseGateEvidenceBundle
from mmaudit.release_observations import BoundReleaseGateResult
from mmaudit.release_report import ReleaseGateReport
from mmaudit.release_run import ReleaseRunBinding
from mmaudit.release_runtime import LocalReleaseGateResult
from mmaudit.release_static import StaticReleaseEvidence
from mmaudit.release_verification import ReleaseRunVerificationBinding
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    CoverageArtifact,
    FindingsArtifact,
    ModelExecutionArtifact,
    ScannerSourceEvidenceArtifact,
)
from mmaudit.reporting.run_authority import (
    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    RunTerminalReportAuthority,
)
from mmaudit.scanners.offline_fork_rpc import OfflineForkRpcArchive

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
SCHEMA_BASE = "https://mmaudit.local/schemas"
MODELS: dict[str, type[BaseModel]] = {
    "actor_model.schema.json": ActorModel,
    "actor_model_baseline.schema.json": ActorModelBaselineArtifact,
    "actor_model_evaluation.schema.json": ActorModelEvaluation,
    "autonomy_gate_inventory.schema.json": AutonomyGateInventory,
    "authenticated_cross_lineage_runner_evidence.schema.json": (
        AuthenticatedCrossLineageRunnerEvidence
    ),
    "authenticated_runner_durable_evidence_bundle.schema.json": (
        AuthenticatedRunnerDurableEvidenceBundle
    ),
    "authenticated_runner_staged_cost_plan.schema.json": AuthenticatedRunnerStagedCostPlan,
    "authenticated_runner_smoke_evidence_bundle.schema.json": (
        AuthenticatedRunnerSmokeEvidenceBundle
    ),
    "authenticated_runner_smoke_corpus_bundle.schema.json": (AuthenticatedRunnerSmokeCorpusBundle),
    "audit_model_refresh_evidence.schema.json": AuditModelRefreshEvidence,
    "audit_model_refresh_pricing_attempt_evidence.schema.json": (
        AuditModelRefreshPricingAttemptEvidence
    ),
    "audit_model_refresh_pricing_evidence.schema.json": AuditModelRefreshPricingEvidence,
    "benchmark_report.schema.json": BenchmarkReport,
    "candidate_selection_revocation_registry.schema.json": (CandidateSelectionRevocationRegistry),
    "candidate_selection_plan.schema.json": CandidateSelectionPlan,
    "audit_model_selection.schema.json": AuditModelSelection,
    "audit_model_selection_evidence.schema.json": AuditModelSelectionEvidenceBundle,
    "consensus_review_artifact.schema.json": ConsensusReviewArtifact,
    "context_manifest.schema.json": ContextManifest,
    "coverage_artifact.schema.json": CoverageArtifact,
    "cross_lineage_adjudication_report.schema.json": CrossLineageAdjudicationReport,
    "development_cost_policy.schema.json": DevelopmentCostPolicy,
    "development_cost_estimate.schema.json": DevelopmentCostEstimate,
    "development_fixture_review_response.schema.json": DevelopmentReviewResponse,
    "development_fixture_review_observation.schema.json": DevelopmentReviewObservation,
    "development_audit_plan.schema.json": DevelopmentAuditPlan,
    "development_audit_shard_observation.schema.json": DevelopmentAuditShardObservation,
    "development_audit_observation.schema.json": DevelopmentAuditObservation,
    "development_routing_observation.schema.json": DevelopmentRoutingEvidence,
    "development_response_rejection.schema.json": DevelopmentResponseRejection,
    "development_completion_telemetry.schema.json": DevelopmentCompletionTelemetry,
    "development_scored_review_response.schema.json": DevelopmentScoredReviewResponse,
    "development_scored_shard_observation.schema.json": DevelopmentScoredAuditShardObservation,
    "development_benchmark_truth.schema.json": DevelopmentBenchmarkTruth,
    "development_benchmark_binding.schema.json": DevelopmentBenchmarkBinding,
    "development_benchmark_score.schema.json": DevelopmentBenchmarkScore,
    "development_benchmark_comparison.schema.json": DevelopmentBenchmarkComparison,
    "development_judgment_response.schema.json": DevelopmentJudgmentResponse,
    "development_judgment_plan.schema.json": DevelopmentJudgmentPlan,
    "development_judgment_shard_observation.schema.json": DevelopmentJudgmentShardObservation,
    "development_judgment_observation.schema.json": DevelopmentJudgmentObservation,
    "development_judgment_impact_score.schema.json": DevelopmentJudgmentImpactScore,
    "development_ensemble_plan.schema.json": DevelopmentEnsemblePlan,
    "development_ensemble_observation.schema.json": DevelopmentEnsembleObservation,
    "development_ensemble_score.schema.json": DevelopmentEnsembleScore,
    "development_corpus_manifest.schema.json": DevelopmentCorpusManifest,
    "development_corpus_material.schema.json": DevelopmentCorpusMaterial,
    "development_corpus_response.schema.json": DevelopmentCorpusResponse,
    "development_corpus_plan.schema.json": DevelopmentCorpusPlan,
    "development_corpus_shard_observation.schema.json": DevelopmentCorpusShardObservation,
    "development_corpus_observation.schema.json": DevelopmentCorpusObservation,
    "development_corpus_resume_plan.schema.json": DevelopmentCorpusResumePlan,
    "development_corpus_resume_attempt.schema.json": DevelopmentCorpusResumeAttempt,
    "development_corpus_resume_history.schema.json": DevelopmentCorpusResumeHistory,
    "development_corpus_resume_benchmark_score.schema.json": DevelopmentCorpusResumeBenchmarkScore,
    "development_corpus_control_measurement.schema.json": DevelopmentCorpusControlMeasurement,
    "development_corpus_ensemble_plan.schema.json": DevelopmentCorpusEnsemblePlan,
    "development_corpus_ensemble_observation.schema.json": DevelopmentCorpusEnsembleObservation,
    "development_corpus_ensemble_score.schema.json": DevelopmentCorpusEnsembleScore,
    "development_corpus_truth.schema.json": DevelopmentCorpusBenchmarkTruth,
    "development_corpus_benchmark_binding.schema.json": DevelopmentCorpusBenchmarkBinding,
    "development_corpus_benchmark_score.schema.json": DevelopmentCorpusBenchmarkScore,
    "development_corpus_judgment_response.schema.json": DevelopmentCorpusJudgmentResponse,
    "development_corpus_judgment_plan.schema.json": DevelopmentCorpusJudgmentPlan,
    "development_corpus_judgment_shard_observation.schema.json": (
        DevelopmentCorpusJudgmentShardObservation
    ),
    "development_corpus_judgment_observation.schema.json": DevelopmentCorpusJudgmentObservation,
    "openrouter_endpoint_inventory_diagnostic.schema.json": (OpenRouterEndpointInventoryDiagnostic),
    "findings_artifact.schema.json": FindingsArtifact,
    "frozen_model_lineage_provenance.schema.json": FrozenModelLineageProvenance,
    "frozen_ground_truth_provenance.schema.json": FrozenGroundTruthProvenance,
    "forensic_delivery_descriptor.schema.json": ForensicDeliveryDescriptor,
    "hardhat_reporter_inventory.schema.json": HardhatReporterInventory,
    "hardhat_reporter_test.schema.json": HardhatReporterExecution,
    "hardhat_request_inventory.schema.json": HardhatInventoryPhaseRequest,
    "hardhat_request_test.schema.json": HardhatTestPhaseRequest,
    "language_capability.schema.json": LanguageCapabilityArtifact,
    "known_issue_taxonomy.schema.json": KnownIssueTaxonomy,
    "known_issue_taxonomy_coverage.schema.json": KnownIssueTaxonomyCoverage,
    "managed_provisioning_state.schema.json": ManagedProvisioningState,
    "managed_provisioning_receipt.schema.json": ManagedProvisioningReceipt,
    "managed_host_tool_material.schema.json": ManagedHostToolManifest,
    "offline_fork_rpc_archive.schema.json": OfflineForkRpcArchive,
    "managed_toolchain_bundle.schema.json": ManagedToolchainBundle,
    "evidence_sealed_authority.schema.json": EvidenceSealedAuthorityEvidence,
    "evidence_seal_verdict.schema.json": EvidenceSealVerdictProjection,
    "evidence_seal_verdict_policy.schema.json": EvidenceSealVerdictPolicy,
    "model_calibration.schema.json": ModelCalibrationArtifact,
    "model_portfolio_resource_preflight.schema.json": ModelPortfolioResourcePreflight,
    "model_surface_coverage_plan.schema.json": ModelSurfaceCoveragePlan,
    "model_surface_resource_preflight.schema.json": ModelSurfaceResourcePreflight,
    "model_lineage_authority.schema.json": ModelLineageAuthorityEnvelope,
    "model_execution_artifact.schema.json": ModelExecutionArtifact,
    "model_lineage_review.schema.json": ModelLineageReviewArtifact,
    "model_lineage_trust_anchor.schema.json": ModelLineageTrustAnchor,
    "model_policy_eligibility.schema.json": ModelPolicyEligibilityArtifact,
    "model_policy_eligibility_authority.schema.json": ModelPolicyEligibilityAuthorityEnvelope,
    "model_policy_eligibility_authority_receipt.schema.json": (
        ModelPolicyEligibilityAuthorityVerificationReceipt
    ),
    "model_policy_eligibility_trust_anchor.schema.json": ModelPolicyEligibilityTrustAnchor,
    "model_policy_eligibility_refresh.schema.json": ModelPolicyEligibilityRefreshArtifact,
    "models_config.schema.json": ModelsConfig,
    "model_qualification.schema.json": ModelQualificationArtifact,
    "model_qualification_policy.schema.json": QualificationPolicy,
    "openrouter_structured_request_cost_preview.schema.json": (
        OpenRouterStructuredRequestCostPreview
    ),
    "model_refresh_attempt.schema.json": ModelRefreshAttempt,
    "model_refresh_diff.schema.json": ModelRefreshDiff,
    "model_refresh_freshness.schema.json": ModelRefreshFreshness,
    "model_refresh_snapshot.schema.json": ModelRefreshSnapshot,
    "model_refresh_source_evidence.schema.json": ModelRefreshSourceEvidence,
    "model_refresh_workflow_status.schema.json": ModelRefreshWorkflowStatus,
    "privacy_retention_consent.schema.json": PrivacyRetentionConsent,
    "client_policy_constraints.schema.json": ClientPolicyConstraints,
    "policy_eligibility_evaluation.schema.json": PolicyEligibilityEvaluation,
    "policy_eligibility_source_observation.schema.json": PolicyEligibilitySourceObservation,
    "policy_review_signal.schema.json": PolicyReviewSignal,
    "prepurchase_quote.schema.json": PrepurchaseQuote,
    "accepted_prepurchase_quote.schema.json": AcceptedPrepurchaseQuote,
    "prepurchase_quote_reconciliation.schema.json": PrepurchaseQuoteReconciliation,
    "public_model_lineage_provenance.schema.json": PublicModelLineageEvidenceBundle,
    "release_candidate_observation.schema.json": ReleaseCandidateObservation,
    "release_bound_gate_result.schema.json": BoundReleaseGateResult,
    "release_gate_evidence.schema.json": ReleaseGateEvidenceBundle,
    "release_gate_report.schema.json": ReleaseGateReport,
    "release_local_gate_result.schema.json": LocalReleaseGateResult,
    "release_run_binding.schema.json": ReleaseRunBinding,
    "release_run_verification_binding.schema.json": ReleaseRunVerificationBinding,
    "release_static_evidence.schema.json": StaticReleaseEvidence,
    "route_runtime_evidence_artifact.schema.json": RouteRuntimeEvidenceArtifact,
    "run_terminal_report_authority.schema.json": RunTerminalReportAuthority,
    "scanner_source_evidence.schema.json": ScannerSourceEvidenceArtifact,
    "scheduler_state.schema.json": SchedulerArtifact,
    "scheduler_retained_journal_reference.schema.json": SchedulerRetainedJournalReference,
    "terminal_audit_learning_record.schema.json": TerminalAuditLearningRecord,
    "semantic_shard_inventory.schema.json": SolidityShardsArtifact,
    "solidity_graphs.schema.json": SolidityGraphsArtifact,
    "solidity_coverage.schema.json": SolidityCoverageArtifact,
}
TITLE_OVERRIDES = {
    "autonomy_gate_inventory.schema.json": (
        "mmaudit nonauthorizing autonomous completion-input gate inventory"
    ),
    "authenticated_cross_lineage_runner_evidence.schema.json": (
        "mmaudit non-authorizing authenticated cross-lineage runner evidence"
    ),
    "authenticated_runner_durable_evidence_bundle.schema.json": (
        "mmaudit non-authorizing durable authenticated runner evidence bundle"
    ),
    "authenticated_runner_staged_cost_plan.schema.json": (
        "mmaudit non-authorizing staged authenticated runner cost plan"
    ),
    "authenticated_runner_smoke_evidence_bundle.schema.json": (
        "mmaudit noncrediting authenticated runner smoke evidence bundle"
    ),
    "authenticated_runner_smoke_corpus_bundle.schema.json": (
        "mmaudit exact noncrediting authenticated runner smoke corpus bundle"
    ),
    "audit_model_refresh_evidence.schema.json": "mmaudit audit-scoped model refresh evidence",
    "audit_model_refresh_pricing_attempt_evidence.schema.json": (
        "mmaudit audit-scoped model refresh pricing attempt evidence"
    ),
    "audit_model_refresh_pricing_evidence.schema.json": (
        "mmaudit audit-scoped model refresh pricing evidence"
    ),
    "audit_model_selection.schema.json": "mmaudit audit-scoped model selection",
    "audit_model_selection_evidence.schema.json": ("mmaudit audit-scoped model selection evidence"),
    "benchmark_report.schema.json": "mmaudit benchmark report",
    "candidate_selection_plan.schema.json": (
        "mmaudit non-authorizing operator-staged model selection plan"
    ),
    "candidate_selection_revocation_registry.schema.json": (
        "mmaudit negative-only candidate selection revocation registry"
    ),
    "consensus_review_artifact.schema.json": (
        "mmaudit exact closed three-review consensus artifact"
    ),
    "coverage_artifact.schema.json": "mmaudit forensic coverage artifact",
    "cross_lineage_adjudication_report.schema.json": (
        "mmaudit non-authorizing cross-lineage adjudication report"
    ),
    "findings_artifact.schema.json": "mmaudit forensic findings artifact",
    "frozen_model_lineage_provenance.schema.json": (
        "mmaudit mechanism-only frozen model lineage provenance"
    ),
    "frozen_ground_truth_provenance.schema.json": ("mmaudit frozen ground-truth provenance"),
    "forensic_delivery_descriptor.schema.json": "mmaudit complete forensic delivery descriptor",
    "hardhat_reporter_inventory.schema.json": "mmaudit Hardhat inventory observation",
    "hardhat_reporter_test.schema.json": "mmaudit Hardhat test observation",
    "hardhat_request_inventory.schema.json": "mmaudit Hardhat inventory phase request",
    "hardhat_request_test.schema.json": "mmaudit Hardhat test phase request",
    "language_capability.schema.json": "mmaudit language capability artifact",
    "managed_provisioning_state.schema.json": (
        "mmaudit incomplete nonauthorizing managed provisioning state"
    ),
    "managed_provisioning_receipt.schema.json": (
        "mmaudit self-contained incomplete nonauthorizing managed provisioning receipt"
    ),
    "managed_host_tool_material.schema.json": (
        "mmaudit nonauthorizing direct host-file material inventory"
    ),
    "offline_fork_rpc_archive.schema.json": "mmaudit incomplete nonauthorizing offline fork reads",
    "managed_toolchain_bundle.schema.json": (
        "mmaudit partial nonauthorizing managed toolchain declaration"
    ),
    "evidence_sealed_authority.schema.json": (
        "mmaudit non-authorizing evidence-seal comparison artifact"
    ),
    "evidence_seal_verdict.schema.json": (
        "mmaudit non-authorizing evidence-seal verdict projection"
    ),
    "evidence_seal_verdict_policy.schema.json": (
        "mmaudit frozen autonomous evidence-seal verdict policy"
    ),
    "model_calibration.schema.json": "mmaudit model calibration artifact",
    "model_portfolio_resource_preflight.schema.json": (
        "mmaudit non-authorizing pre-orientation model portfolio resource preflight"
    ),
    "model_lineage_authority.schema.json": "mmaudit signed model lineage authority",
    "model_execution_artifact.schema.json": "mmaudit model execution artifact",
    "model_lineage_review.schema.json": "mmaudit model lineage review artifact",
    "model_lineage_trust_anchor.schema.json": "mmaudit model lineage trust anchor",
    "model_policy_eligibility.schema.json": "mmaudit model policy eligibility artifact",
    "model_policy_eligibility_authority.schema.json": (
        "mmaudit signed model policy eligibility authority"
    ),
    "model_policy_eligibility_authority_receipt.schema.json": (
        "mmaudit model policy eligibility authority verification receipt"
    ),
    "model_policy_eligibility_trust_anchor.schema.json": (
        "mmaudit model policy eligibility trust anchor"
    ),
    "model_policy_eligibility_refresh.schema.json": (
        "mmaudit model policy eligibility refresh artifact"
    ),
    "models_config.schema.json": "mmaudit models configuration",
    "model_qualification.schema.json": "mmaudit model qualification artifact",
    "model_qualification_policy.schema.json": "mmaudit model qualification policy",
    "openrouter_structured_request_cost_preview.schema.json": (
        "mmaudit non-authorizing OpenRouter structured request cost preview"
    ),
    "openrouter_endpoint_inventory_diagnostic.schema.json": (
        "mmaudit non-authorizing OpenRouter endpoint inventory diagnostic"
    ),
    "model_refresh_attempt.schema.json": "mmaudit model refresh attempt",
    "model_refresh_diff.schema.json": "mmaudit model refresh diff",
    "model_refresh_freshness.schema.json": "mmaudit model refresh freshness",
    "model_refresh_snapshot.schema.json": "mmaudit model refresh snapshot",
    "model_refresh_source_evidence.schema.json": "mmaudit model refresh source evidence",
    "model_refresh_workflow_status.schema.json": "mmaudit model refresh workflow status",
    "client_policy_constraints.schema.json": "mmaudit per-audit client policy constraints",
    "policy_eligibility_evaluation.schema.json": ("mmaudit model policy eligibility evaluation"),
    "policy_eligibility_source_observation.schema.json": (
        "mmaudit current policy eligibility source observation"
    ),
    "policy_review_signal.schema.json": "mmaudit model policy review signal",
    "prepurchase_quote.schema.json": (
        "mmaudit deterministic non-authorizing whole-run pre-purchase quote"
    ),
    "accepted_prepurchase_quote.schema.json": (
        "mmaudit non-authorizing accepted pre-purchase quote constraint"
    ),
    "prepurchase_quote_reconciliation.schema.json": (
        "mmaudit terminal actual-versus-quote cost reconciliation"
    ),
    "public_model_lineage_provenance.schema.json": (
        "mmaudit documentary public model lineage provenance"
    ),
    "route_runtime_evidence_artifact.schema.json": (
        "mmaudit nonauthorizing exact route runtime evidence"
    ),
    "run_terminal_report_authority.schema.json": "mmaudit private terminal report authority",
    "scanner_source_evidence.schema.json": "mmaudit private scanner source evidence",
    "scheduler_state.schema.json": "mmaudit seven-pass scheduler state",
    "scheduler_retained_journal_reference.schema.json": (
        "mmaudit retained scheduler journal reference"
    ),
    "semantic_shard_inventory.schema.json": "mmaudit Solidity semantic shard inventory",
    "solidity_graphs.schema.json": "mmaudit bounded Solidity semantic graphs artifact",
    "solidity_coverage.schema.json": "mmaudit Solidity coverage artifact",
}


def run_evidence_manifest_run_configuration_rules() -> list[dict[str, Any]]:
    """Return the exact version boundary for manifest run-configuration custody."""

    return [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.0"}},
                "required": ["schema_version"],
            },
            "then": {"properties": {"run_configuration": {"type": "null"}}},
        },
        {
            "if": {
                "properties": {"schema_version": {"enum": ["1.1", "1.2", "1.3", "1.4"]}},
                "required": ["schema_version"],
            },
            "then": {
                "required": ["run_configuration"],
                "properties": {"run_configuration": {"$ref": "#/$defs/runConfiguration"}},
            },
        },
    ]


def run_evidence_manifest_report_bundle_rule() -> dict[str, Any]:
    """Return the published schema-1.2+ contract for every manifest-bound report leaf."""

    return {
        "if": {
            "properties": {"schema_version": {"enum": ["1.2", "1.3", "1.4"]}},
            "required": ["schema_version"],
        },
        "then": {
            "properties": {
                "artifacts": {
                    "allOf": [
                        {
                            "contains": {
                                "properties": {"path": {"const": name}},
                                "required": ["path"],
                            },
                            "maxContains": 1,
                            "minContains": 1,
                        }
                        for name in sorted(
                            MANIFEST_BOUND_REPORT_DELIVERABLES
                            | {
                                LANGUAGE_CAPABILITY_ARTIFACT_PATH,
                                RUN_TERMINAL_REPORT_AUTHORITY_PATH,
                            }
                        )
                    ]
                }
            }
        },
    }


def run_evidence_manifest_taxonomy_custody_rules() -> list[dict[str, Any]]:
    """Return the exact schema-1.4 taxonomy and raw-review custody boundary."""

    taxonomy_artifact_paths = sorted(
        {
            KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
            KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
        }
    )
    current_artifact_paths = sorted(
        {*taxonomy_artifact_paths, MODEL_REVIEW_ARTIFACT_INVENTORY_PATH}
    )
    coverage_binding_ids = sorted(_KNOWN_ISSUE_TAXONOMY_BINDING_IDS)
    artifact_matches = [
        {
            "contains": {
                "properties": {"path": {"const": path}},
                "required": ["path"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for path in current_artifact_paths
    ]
    coverage_binding_matches = [
        {
            "contains": {
                "properties": {"identifier": {"const": identifier}},
                "required": ["identifier"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for identifier in coverage_binding_ids
    ]
    any_artifact_match = {
        "properties": {"path": {"enum": current_artifact_paths}},
        "required": ["path"],
    }
    any_coverage_binding_match = {
        "properties": {"identifier": {"enum": coverage_binding_ids}},
        "required": ["identifier"],
    }
    return [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.4"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "artifacts": {"allOf": artifact_matches},
                    "bindings": {
                        "properties": {
                            "coverage": {"allOf": coverage_binding_matches},
                        },
                        "required": ["coverage"],
                    },
                }
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"enum": ["1.0", "1.1", "1.2", "1.3"]}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "artifacts": {"not": {"contains": any_artifact_match}},
                    "bindings": {
                        "properties": {
                            "coverage": {"not": {"contains": any_coverage_binding_match}},
                        },
                        "required": ["coverage"],
                    },
                }
            },
        },
    ]


def run_evidence_manifest_audit_model_selection_rules() -> list[dict[str, Any]]:
    """Return the bidirectional artifact/binding custody contract."""

    artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_SELECTION_EVIDENCE_PATH}},
        "required": ["path"],
    }
    binding_matches = [
        {
            "contains": {
                "properties": {"identifier": {"const": identifier}},
                "required": ["identifier"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for identifier in sorted(AUDIT_MODEL_SELECTION_BINDING_IDS)
    ]
    any_binding_match = {
        "properties": {"identifier": {"enum": sorted(AUDIT_MODEL_SELECTION_BINDING_IDS)}},
        "required": ["identifier"],
    }
    return [
        {
            "if": {
                "properties": {"artifacts": {"contains": artifact_match}},
                "required": ["artifacts"],
            },
            "then": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"allOf": binding_matches},
                        },
                        "required": ["models"],
                    }
                }
            },
        },
        {
            "if": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"contains": any_binding_match},
                        },
                        "required": ["models"],
                    }
                },
                "required": ["bindings"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "contains": artifact_match,
                        "maxContains": 1,
                        "minContains": 1,
                    }
                }
            },
        },
    ]


def run_evidence_manifest_audit_model_refresh_rules() -> list[dict[str, Any]]:
    """Return bidirectional veto-only refresh artifact/binding custody rules."""

    artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_REFRESH_EVIDENCE_PATH}},
        "required": ["path"],
    }
    selection_artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_SELECTION_EVIDENCE_PATH}},
        "required": ["path"],
    }
    binding_matches = [
        {
            "contains": {
                "properties": {"identifier": {"const": identifier}},
                "required": ["identifier"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for identifier in sorted(AUDIT_MODEL_REFRESH_BINDING_IDS)
    ]
    any_binding_match = {
        "properties": {"identifier": {"enum": sorted(AUDIT_MODEL_REFRESH_BINDING_IDS)}},
        "required": ["identifier"],
    }
    return [
        {
            "if": {
                "properties": {"artifacts": {"contains": artifact_match}},
                "required": ["artifacts"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "contains": selection_artifact_match,
                        "maxContains": 1,
                        "minContains": 1,
                    },
                    "bindings": {
                        "properties": {"models": {"allOf": binding_matches}},
                        "required": ["models"],
                    },
                }
            },
        },
        {
            "if": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"contains": any_binding_match},
                        },
                        "required": ["models"],
                    }
                },
                "required": ["bindings"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "contains": artifact_match,
                        "maxContains": 1,
                        "minContains": 1,
                    }
                }
            },
        },
    ]


def run_evidence_manifest_audit_model_refresh_pricing_rules() -> list[dict[str, Any]]:
    """Return bidirectional pricing artifact/binding custody rules."""

    artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_REFRESH_PRICING_EVIDENCE_PATH}},
        "required": ["path"],
    }
    refresh_artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_REFRESH_EVIDENCE_PATH}},
        "required": ["path"],
    }
    selection_artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_SELECTION_EVIDENCE_PATH}},
        "required": ["path"],
    }
    binding_matches = [
        {
            "contains": {
                "properties": {"identifier": {"const": identifier}},
                "required": ["identifier"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for identifier in sorted(AUDIT_MODEL_REFRESH_PRICING_BINDING_IDS)
    ]
    any_binding_match = {
        "properties": {"identifier": {"enum": sorted(AUDIT_MODEL_REFRESH_PRICING_BINDING_IDS)}},
        "required": ["identifier"],
    }
    return [
        {
            "if": {
                "properties": {"artifacts": {"contains": artifact_match}},
                "required": ["artifacts"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "allOf": [
                            {
                                "contains": selection_artifact_match,
                                "maxContains": 1,
                                "minContains": 1,
                            },
                            {
                                "contains": refresh_artifact_match,
                                "maxContains": 1,
                                "minContains": 1,
                            },
                        ]
                    },
                    "bindings": {
                        "properties": {"models": {"allOf": binding_matches}},
                        "required": ["models"],
                    },
                }
            },
        },
        {
            "if": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"contains": any_binding_match},
                        },
                        "required": ["models"],
                    }
                },
                "required": ["bindings"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "contains": artifact_match,
                        "maxContains": 1,
                        "minContains": 1,
                    }
                }
            },
        },
    ]


def _run_evidence_manifest_contract_is_current() -> bool:
    """Verify every exact hand-authored manifest version and custody rule."""

    path = SCHEMA_ROOT / "run_evidence_manifest.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    expected = [
        *run_evidence_manifest_run_configuration_rules(),
        run_evidence_manifest_report_bundle_rule(),
        *run_evidence_manifest_taxonomy_custody_rules(),
        *run_evidence_manifest_audit_model_selection_rules(),
        *run_evidence_manifest_audit_model_refresh_rules(),
        *run_evidence_manifest_audit_model_refresh_pricing_rules(),
    ]
    observed = schema.get("allOf")
    return (
        schema.get("properties", {}).get("schema_version")
        == {"enum": ["1.0", "1.1", "1.2", "1.3", "1.4"]}
        and isinstance(observed, list)
        and len(observed) == len(expected)
        and all(rule in observed for rule in expected)
    )


_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS = (
    "graph_edge_counts",
    "graph_retained_edge_occurrence_counts",
    "graph_candidate_edge_counts",
)
_SOLIDITY_COVERAGE_FACT_DENSE_MAPS = (
    "graph_fact_retained_counts",
    "graph_fact_retained_occurrence_counts",
    "graph_fact_candidate_counts",
)
_SOLIDITY_COVERAGE_GRAPH_MAPS = (
    *_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS,
    "graph_omitted_edge_counts",
    "graph_node_counts",
    *_SOLIDITY_COVERAGE_FACT_DENSE_MAPS,
    "graph_fact_omitted_counts",
    "asset_flow_operation_counts",
    "asset_flow_direction_counts",
    "control_resolution_counts",
    "governance_stage_counts",
    "dependency_resolution_counts",
    "oracle_freshness_counts",
)
_SOLIDITY_COVERAGE_GRAPH_LISTS = (
    "graph_omission_evidence_sha256s",
    "graph_fact_omission_evidence_sha256s",
    "graph_warnings",
)
_SCHEDULER_RECOVERY_COMPLETION_FIELDS = (
    "runtime_completion_evidence_sha256",
    "validated_response_sha256",
    "normalization_evidence_sha256",
    "output_artifact_sha256",
)
_SCHEDULER_RECURSIVE_PROMOTION_FIELDS = (
    "nested_family_id",
    "nested_family_root_sha256",
    "nested_recovery_plan_sha256",
    "nested_family_closure_id",
    "nested_family_closure_sha256",
    "nested_child_result_sha256s",
    "superseded_bridge_result_sha256",
    "promoted_leaf_result_sha256s",
)
_SCHEDULER_RECURSIVE_REQUEST_FIELDS = (
    "promotion_disposition",
    "global_request_ordinal",
    "recovery_family_id",
    "family_root_sha256",
    "recovery_plan_sha256",
    "family_closure_id",
    "family_closure_sha256",
)
_SCHEDULER_RELEASE_TREE_FIELDS = (
    "global_request_ordinal",
    "recovery_family_id",
    "family_root_sha256",
    "recovery_plan_sha256",
    "child_plan_sha256",
)
_SCHEDULER_RELEASE_ACCOUNTING_FIELDS = (
    "result_origin",
    "released_cost_entry_sha256",
    "pre_send_release_reason",
    "provider_attempt_evidence_sha256",
    "accounted_provider_attempts",
    "accounted_completion_tokens",
    "accounted_cost_usd_exact",
    "cost_disposition",
)
_SCHEDULER_RELEASE_ONLY_FIELDS = (
    "child_plan_sha256",
    "dispatch_id",
    "dispatch_sha256",
    *_SCHEDULER_RELEASE_ACCOUNTING_FIELDS,
)
_SCHEDULER_RELEASE_ABSENT_FIELDS = (
    "promotion_entry_sha256",
    "promotion_disposition",
    "family_closure_id",
    "family_closure_sha256",
    "runtime_completion_evidence_sha256",
    "provider_response_sha256",
    "validated_response_sha256",
    "normalization_evidence_sha256",
    "output_artifact_sha256",
    "specialist_accepted_outcome_sha256",
)
_PUBLIC_LINEAGE_ROOT_PATTERN = r"^sha256:[0-9a-f]{64}$"
_PUBLIC_LINEAGE_REQUESTED_SOURCE_PATTERN = (
    r"^https://(?:huggingface\.co/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/resolve/"
    r"[0-9a-f]{40}/[^\s?#]+|raw\.githubusercontent\.com/[A-Za-z0-9._-]+/"
    r"[A-Za-z0-9._-]+/[0-9a-f]{40}/[^\s?#]+)$"
)
_PUBLIC_LINEAGE_FINAL_SOURCE_PATTERN = (
    r"^https://(?:huggingface\.co|raw\.githubusercontent\.com)/[^\s#]+$"
)


def _strengthen_public_model_lineage_contract(schema: dict[str, Any]) -> None:
    """Expose bounded documentary custody at the standalone schema boundary."""

    properties = schema["properties"]
    definitions = schema["$defs"]

    for field_name in (
        "confirmed_exact_model_ids",
        "unconfirmed_exact_model_ids",
        "excluded_exact_model_ids",
    ):
        properties[field_name]["items"]["pattern"] = EXACT_MODEL_ID_PATTERN
        properties[field_name]["uniqueItems"] = True
    properties["approved_root_lineages"]["items"]["pattern"] = _PUBLIC_LINEAGE_ROOT_PATTERN
    properties["approved_root_lineages"]["uniqueItems"] = True
    for field_name in (
        "sources",
        "aliases",
        "claims",
        "decisions",
        "conservative_non_independence_constraints",
    ):
        properties[field_name]["uniqueItems"] = True

    properties["capture_observations_file_binding"] = {
        "allOf": [
            {"$ref": "#/$defs/ManifestFileBinding"},
            {
                "properties": {
                    "path": {"const": PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME},
                    "size": {"maximum": 500_000, "minimum": 1},
                }
            },
        ]
    }

    source = definitions["PublicModelLineageSourceEvidence"]
    source_properties = source["properties"]
    source_properties["requested_url"]["pattern"] = _PUBLIC_LINEAGE_REQUESTED_SOURCE_PATTERN
    source_properties["final_url"]["pattern"] = _PUBLIC_LINEAGE_FINAL_SOURCE_PATTERN
    source_properties["redirect_chain"]["items"]["pattern"] = _PUBLIC_LINEAGE_FINAL_SOURCE_PATTERN
    source_properties["redirect_chain"]["uniqueItems"] = True
    source_properties["file_binding"] = {
        "allOf": [
            {"$ref": "#/$defs/ManifestFileBinding"},
            {
                "properties": {
                    "path": {"pattern": r"^sources/[a-z][a-z0-9-]{0,99}\.md$"},
                    "size": {"maximum": 100_000, "minimum": 1},
                }
            },
        ]
    }

    alias = definitions["PublicModelLineageAliasBinding"]["properties"]
    alias["exact_model_id"]["pattern"] = EXACT_MODEL_ID_PATTERN
    alias["source_ids"]["items"]["pattern"] = r"^[a-z][a-z0-9-]{0,99}$"
    alias["source_ids"]["uniqueItems"] = True

    claim_definition = definitions["PublicModelLineageClaim"]
    claim = claim_definition["properties"]
    claim["subject_exact_model_id"]["pattern"] = EXACT_MODEL_ID_PATTERN
    for option in claim["target_exact_model_id"]["anyOf"]:
        if option.get("type") == "string":
            option["pattern"] = EXACT_MODEL_ID_PATTERN
    claim_definition["allOf"] = [
        {
            "if": {
                "properties": {"claim_kind": {"const": "ROOTS_WITH"}},
                "required": ["claim_kind"],
            },
            "then": {
                "properties": {"target_exact_model_id": {"type": "string"}},
                "required": ["target_exact_model_id"],
            },
            "else": {"properties": {"target_exact_model_id": {"type": "null"}}},
        },
        {
            "if": {
                "properties": {"claim_kind": {"const": "VAGUE"}},
                "required": ["claim_kind"],
            },
            "then": {"properties": {"decisive_primary_publisher": {"const": False}}},
        },
    ]
    claim_definition["$comment"] = (
        "Runtime validation additionally binds the UTF-8 marker length and SHA-256 to its exact "
        "non-overlapping source byte span."
    )

    decision = definitions["PublicModelLineageDecision"]["properties"]
    decision["exact_model_id"]["pattern"] = EXACT_MODEL_ID_PATTERN
    decision["supporting_claim_ids"]["items"]["pattern"] = r"^claim-[a-z][a-z0-9-]{0,95}$"
    decision["supporting_claim_ids"]["uniqueItems"] = True
    decision["unconfirmed_reasons"]["uniqueItems"] = True

    constraint = definitions["PublicModelLineageNonIndependenceConstraint"]["properties"]
    constraint["member_exact_model_ids"]["items"]["pattern"] = EXACT_MODEL_ID_PATTERN
    constraint["member_exact_model_ids"]["uniqueItems"] = True
    constraint["supporting_claim_ids"]["items"]["pattern"] = r"^claim-[a-z][a-z0-9-]{0,95}$"
    constraint["supporting_claim_ids"]["uniqueItems"] = True

    schema["$comment"] = (
        "Runtime validation additionally enforces sorted keyed inventories, exact source and claim "
        "joins, aggregate source-byte bounds, derived decisions, and canonical inventory hashes."
    )


def _strengthen_solidity_coverage_contract(schema: dict[str, Any]) -> None:
    """Expose runtime graph-accounting invariants at the standalone schema boundary."""

    coverage = schema["$defs"]["SolidityCoverage"]
    properties = coverage["properties"]
    edge_kinds = [kind.value for kind in SolidityGraphKind]
    fact_kinds = [kind.value for kind in SolidityGraphFactKind]
    node_kinds = [kind.value for kind in SolidityGraphNodeKind]

    coverage["required"] = sorted(
        {
            *coverage.get("required", []),
            "graph_analysis_state",
            *_SOLIDITY_COVERAGE_GRAPH_MAPS,
            *_SOLIDITY_COVERAGE_GRAPH_LISTS,
        }
    )
    properties["graph_analysis_state"] = {
        "default": "not_analyzed",
        "enum": [
            "not_analyzed",
            "attempted_but_failed",
            "analyzed_with_fallback_parser",
            "deterministic",
        ],
        "title": "Graph Analysis State",
        "type": "string",
    }
    for field_name in (*_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS, "graph_omitted_edge_counts"):
        properties[field_name]["propertyNames"] = {"enum": edge_kinds}
    for field_name in (
        *_SOLIDITY_COVERAGE_FACT_DENSE_MAPS,
        "graph_fact_omitted_counts",
    ):
        properties[field_name]["propertyNames"] = {"enum": fact_kinds}
    properties["graph_node_counts"]["propertyNames"] = {"enum": node_kinds}
    properties["graph_omitted_edge_counts"]["additionalProperties"]["minimum"] = 1
    properties["graph_fact_omitted_counts"]["additionalProperties"]["minimum"] = 1

    empty_graph_evidence = {
        **{field_name: {"maxProperties": 0} for field_name in _SOLIDITY_COVERAGE_GRAPH_MAPS},
        **{field_name: {"maxItems": 0} for field_name in _SOLIDITY_COVERAGE_GRAPH_LISTS},
    }
    dense_analyzed_evidence = {
        **{
            field_name: {
                "maxProperties": len(edge_kinds),
                "minProperties": len(edge_kinds),
            }
            for field_name in _SOLIDITY_COVERAGE_EDGE_DENSE_MAPS
        },
        **{
            field_name: {
                "maxProperties": len(fact_kinds),
                "minProperties": len(fact_kinds),
            }
            for field_name in _SOLIDITY_COVERAGE_FACT_DENSE_MAPS
        },
    }
    coverage["allOf"] = [
        {
            "if": {
                "properties": {"graph_analysis_state": {"const": "not_analyzed"}},
                "required": ["graph_analysis_state"],
            },
            "then": {"properties": empty_graph_evidence},
            "else": {"properties": dense_analyzed_evidence},
        },
        {
            "if": {
                "properties": {"graph_analysis_state": {"const": "attempted_but_failed"}},
                "required": ["graph_analysis_state"],
            },
            "then": {
                "anyOf": [
                    {
                        "properties": {
                            "graph_omitted_edge_counts": {"minProperties": 1},
                            "graph_omission_evidence_sha256s": {"minItems": 1},
                        }
                    },
                    {
                        "properties": {
                            "graph_fact_omitted_counts": {"minProperties": 1},
                            "graph_fact_omission_evidence_sha256s": {"minItems": 1},
                        }
                    },
                ]
            },
        },
        {
            "if": {
                "properties": {
                    "graph_analysis_state": {
                        "enum": ["analyzed_with_fallback_parser", "deterministic"]
                    }
                },
                "required": ["graph_analysis_state"],
            },
            "then": {
                "properties": {
                    "graph_omitted_edge_counts": {"maxProperties": 0},
                    "graph_omission_evidence_sha256s": {"maxItems": 0},
                    "graph_fact_omitted_counts": {"maxProperties": 0},
                    "graph_fact_omission_evidence_sha256s": {"maxItems": 0},
                }
            },
        },
    ]
    coverage["$comment"] = (
        "Runtime validation additionally requires one canonical evidence hash per sparse "
        "omitted-kind entry and exact candidate = retained-occurrence + omitted arithmetic."
    )


def _strengthen_scheduler_recovery_contract(schema: dict[str, Any]) -> None:
    """Expose recovery version and terminal-custody invariants in the public schema."""

    pass_result = schema["$defs"]["SchedulerPassResult"]
    pass_result["allOf"] = [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.1"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {"recovery_promotion_bindings": {"minItems": 1}},
                "required": ["recovery_promotion_bindings"],
            },
            "else": {"not": {"required": ["recovery_promotion_bindings"]}},
        }
    ]

    promotion = schema["$defs"]["SchedulerTruncationRecoveryPromotionBinding"]
    child_results = promotion["properties"]["direct_child_result_sha256s"]
    child_results["uniqueItems"] = True
    for child_result in child_results["prefixItems"]:
        child_result["pattern"] = r"^[0-9a-f]{64}$"
    for field_name in ("nested_child_result_sha256s", "promoted_leaf_result_sha256s"):
        recursive_results = promotion["properties"][field_name]["anyOf"][0]
        recursive_results["uniqueItems"] = True
        for child_result in recursive_results["prefixItems"]:
            child_result["pattern"] = r"^[0-9a-f]{64}$"
    promotion["allOf"] = [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.1"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    field_name: {"not": {"type": "null"}}
                    for field_name in _SCHEDULER_RECURSIVE_PROMOTION_FIELDS
                },
                "required": list(_SCHEDULER_RECURSIVE_PROMOTION_FIELDS),
            },
            "else": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in _SCHEDULER_RECURSIVE_PROMOTION_FIELDS
                    ]
                }
            },
        }
    ]

    request = schema["$defs"]["SchedulerTruncationRecoveryModelRequestEvidence"]
    request["allOf"] = [
        {
            "if": {
                "properties": {"terminal_status": {"const": "SUCCEEDED"}},
                "required": ["terminal_status"],
            },
            "then": {
                "properties": {
                    field_name: {"not": {"type": "null"}}
                    for field_name in _SCHEDULER_RECOVERY_COMPLETION_FIELDS
                },
                "required": list(_SCHEDULER_RECOVERY_COMPLETION_FIELDS),
            },
            "else": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in _SCHEDULER_RECOVERY_COMPLETION_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.2"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    field_name: {"not": {"type": "null"}}
                    for field_name in (
                        "promotion_entry_sha256",
                        *_SCHEDULER_RECURSIVE_REQUEST_FIELDS,
                    )
                },
                "required": [
                    "promotion_entry_sha256",
                    *_SCHEDULER_RECURSIVE_REQUEST_FIELDS,
                ],
            },
            "else": {
                "if": {
                    "properties": {"schema_version": {"const": "1.3"}},
                    "required": ["schema_version"],
                },
                "else": {
                    "not": {
                        "anyOf": [
                            {"required": [field_name]}
                            for field_name in _SCHEDULER_RECURSIVE_REQUEST_FIELDS
                        ]
                    }
                },
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.3"}},
                "required": ["schema_version"],
            },
            "then": {
                "dependentRequired": {
                    "dispatch_id": ["dispatch_sha256"],
                    "dispatch_sha256": ["dispatch_id"],
                },
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in _SCHEDULER_RELEASE_ABSENT_FIELDS
                    ]
                },
                "properties": {
                    **{
                        field_name: {"not": {"type": "null"}}
                        for field_name in (
                            *_SCHEDULER_RELEASE_TREE_FIELDS,
                            *_SCHEDULER_RELEASE_ACCOUNTING_FIELDS,
                            "dispatch_id",
                            "dispatch_sha256",
                        )
                    },
                    "result_origin": {"const": "RUNTIME"},
                    "cost_disposition": {"const": "RELEASED_PRE_SEND_TAIL"},
                    "terminal_status": {"const": "FAILED"},
                },
                "required": [
                    *_SCHEDULER_RELEASE_TREE_FIELDS,
                    *_SCHEDULER_RELEASE_ACCOUNTING_FIELDS,
                    "terminal_status",
                ],
            },
            "else": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]} for field_name in _SCHEDULER_RELEASE_ONLY_FIELDS
                    ]
                },
                "properties": {
                    "terminal_status": {"enum": ["SUCCEEDED", "TRUNCATED"]},
                },
            },
        },
        {
            "if": {
                "properties": {"promotion_disposition": {"const": "SUCCESSFUL_LEAF"}},
                "required": ["promotion_disposition"],
            },
            "then": {
                "properties": {"terminal_status": {"const": "SUCCEEDED"}},
                "required": ["terminal_status"],
            },
        },
        {
            "if": {
                "properties": {"promotion_disposition": {"const": "SUPERSEDED_TRUNCATED_BRIDGE"}},
                "required": ["promotion_disposition"],
            },
            "then": {
                "properties": {"terminal_status": {"const": "TRUNCATED"}},
                "required": ["terminal_status"],
            },
        },
        {
            "if": {
                "allOf": [
                    {
                        "not": {
                            "properties": {"schema_version": {"const": "1.2"}},
                            "required": ["schema_version"],
                        }
                    },
                    {
                        "properties": {"terminal_status": {"const": "TRUNCATED"}},
                        "required": ["terminal_status"],
                    },
                ]
            },
            "then": {"not": {"required": ["promotion_entry_sha256"]}},
        },
    ]


def _strengthen_minimum_floor_recovery_contract(schema: dict[str, Any]) -> None:
    """Preserve versioned recovery-binding presence if a report publishes the floor."""

    floor = schema.get("$defs", {}).get("MinimumAnalysisFloor")
    if floor is None:
        return
    floor["allOf"] = [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.1"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {"recovery_model_usage_bindings": {"minItems": 1}},
                "required": ["recovery_model_usage_bindings"],
            },
            "else": {"not": {"required": ["recovery_model_usage_bindings"]}},
        }
    ]


_AUTHENTICATED_RUNNER_RELEASE_CASE_COUNT = AUTHENTICATED_RUNNER_DURABLE_CASE_COUNT
_AUTHENTICATED_RUNNER_DISALLOWED_ROUTING_FIELDS = (
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
    "private_key",
    "private_context",
    "private_source",
    "private_source_code",
    "raw_private_source",
    "raw_source",
    "registry",
    "registry_state",
    "repository_source",
    "repository_context",
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
)


def _exact_authenticated_runner_case_inventory(property_schema: dict[str, Any]) -> None:
    """Constrain one release inventory to the frozen 24-case protocol."""

    property_schema["minItems"] = _AUTHENTICATED_RUNNER_RELEASE_CASE_COUNT
    property_schema["maxItems"] = _AUTHENTICATED_RUNNER_RELEASE_CASE_COUNT
    property_schema["uniqueItems"] = True


def _authenticated_runner_safe_routing_property_names() -> dict[str, Any]:
    """Return the closed non-secret field-name grammar used at every routing depth."""

    forbidden_pattern = (
        r"api_?key|api_?token|^(?!privacy_authorization$).*authorization(?:_?header)?|"
        r"bearer_?token|"
        r"(?:access|refresh|session|auth|authentication|oauth|id|csrf)_?token|"
        r"client_?secret|secret|credential|mnemonic|password|private_?key|"
        r"(?:session|auth|access|secret)_?key|cookie|session_?id|"
        r"(?:private|raw|repository)_?"
        r"(?:source|context)|source_?(?:code|content|text)|context_?"
        r"(?:package|payload|request_?evidence)$|provider_?visible|registry|"
        r"runner_?(?:authority|capability|custody)"
    )
    return {
        "allOf": [
            {"pattern": r"^[a-z][a-z0-9_]{0,127}$"},
            {"not": {"enum": sorted(_AUTHENTICATED_RUNNER_DISALLOWED_ROUTING_FIELDS)}},
            {"not": {"pattern": forbidden_pattern}},
            {
                "anyOf": [
                    {"not": {"pattern": "capability"}},
                    {"pattern": r"_capability_sha256$"},
                ]
            },
        ]
    }


def _authenticated_runner_safe_routing_value() -> dict[str, Any]:
    """Return a bounded recursive schema for non-secret provider routing evidence."""

    value_ref = {"$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"}
    property_names = _authenticated_runner_safe_routing_property_names()
    return {
        "description": (
            "Bounded non-secret provider routing evidence. Runtime custody independently "
            "replays the exact typed evidence needed for credit."
        ),
        "anyOf": [
            {"type": "null"},
            {"type": "boolean"},
            {"maximum": 2**63 - 1, "minimum": -(2**63), "type": "integer"},
            {"maximum": 1e18, "minimum": -1e18, "type": "number"},
            {"maxLength": 1_000_000, "type": "string"},
            {"items": value_ref, "maxItems": 10_000, "type": "array"},
            {
                "additionalProperties": value_ref,
                "maxProperties": 256,
                "propertyNames": property_names,
                "type": "object",
            },
        ],
    }


def _strengthen_openrouter_request_cost_preview_contract(schema: dict[str, Any]) -> None:
    """Publish the exact bounded, nonauthorizing structured-request preview shape."""

    properties = schema["properties"]
    authority_fields = (
        "authorizes_dispatch",
        "authorizes_budget_reservation",
        "authorizes_provider_transport",
        "grants_review_credit",
        "grants_completion_credit",
    )
    schema["required"] = sorted(
        {
            *schema.get("required", []),
            "artifact_kind",
            "schema_version",
            *authority_fields,
        }
    )
    properties["logical_request_id"]["pattern"] = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    properties["exact_model_id"]["pattern"] = EXACT_MODEL_ID_PATTERN
    properties["provider_endpoint"]["pattern"] = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
    canonical_cost = r"^(?:0|[1-9][0-9]{0,49})(?:\.[0-9]{1,48})?$"
    for field_name in (
        "maximum_cost_usd_per_attempt_exact",
        "maximum_cost_usd_all_attempts_exact",
    ):
        properties[field_name]["pattern"] = canonical_cost
    properties["cost_components"]["uniqueItems"] = True
    schema["$comment"] = (
        "Runtime validation additionally replays exact discovery, route, output, reasoning, "
        "request-body, token-unit, pricing-component, retry, Decimal-cost, and self-hash joins. "
        "This preview grants no dispatch, reservation, transport, or review authority."
    )


def _strengthen_authenticated_runner_cost_plan_contract(schema: dict[str, Any]) -> None:
    """Publish the exact 24-request nonauthorizing staged cost-plan shape."""

    properties = schema["properties"]
    authority_fields = (
        "authorizes_dispatch",
        "authorizes_budget_reservation",
        "authorizes_provider_transport",
        "grants_review_credit",
        "grants_completion_credit",
        "runner_custody_authorized",
        "release_authorized",
    )
    schema["required"] = sorted(
        {
            *schema.get("required", []),
            "artifact_kind",
            "schema_version",
            "logical_request_count",
            *authority_fields,
        }
    )
    properties["exact_model_id"]["pattern"] = EXACT_MODEL_ID_PATTERN
    properties["provider_endpoint"]["pattern"] = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
    canonical_cost = r"^(?:0|[1-9][0-9]{0,49})(?:\.[0-9]{1,48})?$"
    for field_name in (
        "maximum_cost_usd_per_attempt_exact",
        "maximum_cost_usd_per_logical_request_exact",
        "maximum_cost_usd_exact",
    ):
        properties[field_name]["pattern"] = canonical_cost
    properties["case_ids"]["items"] = {
        "pattern": r"^case-[0-9a-f]{16}$",
        "type": "string",
    }
    for field_name in ("case_ids", "request_previews", "provider_attempt_request_ids"):
        properties[field_name]["uniqueItems"] = True
    schema["$comment"] = (
        "Runtime validation additionally replays the exact ordered 24-request preview set, "
        "singleton route/config/discovery/pricing/output/reasoning joins, retry-expanded request "
        "identities, Decimal aggregate, and self-hash. This plan grants no runtime authority."
    )


def _strengthen_prepurchase_quote_contract(schema: dict[str, Any]) -> None:
    """Publish canonical money and closed-set constraints enforced by typed validation."""

    canonical_money_pattern = r"^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,30})?$"
    money_fields = {
        "active_reserved_usd_exact",
        "actual_cost_usd_exact",
        "cap_usd_exact",
        "lower_bound_usd_exact",
        "maximum_cost_usd_per_attempt_exact",
        "remaining_usd_exact",
        "run_hard_ceiling_usd_exact",
        "spent_usd_exact",
        "standard_bound_usd_exact",
        "standard_cost_usd_exact",
        "standard_delta_usd_exact",
        "unconstrained_workflow_worst_usd_exact",
        "worst_case_cost_usd_exact",
        "worst_case_delta_usd_exact",
        "worst_case_usd_exact",
    }

    object_schemas = [schema, *schema.get("$defs", {}).values()]
    for object_schema in object_schemas:
        properties = object_schema.get("properties")
        if not isinstance(properties, dict):
            continue
        for field_name in money_fields & properties.keys():
            property_schema = properties[field_name]
            if property_schema.get("type") == "string":
                property_schema["pattern"] = canonical_money_pattern
                continue
            options = property_schema.get("anyOf", [])
            string_options = [option for option in options if option.get("type") == "string"]
            if len(string_options) != 1:
                raise ValueError(
                    f"pre-purchase quote money field {field_name!r} has an unexpected schema"
                )
            string_options[0]["pattern"] = canonical_money_pattern

        if "covered_task_classes" in properties:
            properties["covered_task_classes"]["uniqueItems"] = True
        if "task_ceilings" in properties:
            properties["task_ceilings"]["uniqueItems"] = True

    schema["$comment"] = (
        "Runtime validation additionally proves canonical ordering, exact task-class and route "
        "coverage, derived aggregate bounds, artifact self-hashes, acceptance custody, and "
        "status-dependent terminal reconciliation fields."
    )


def _strengthen_authenticated_runner_config_version_contract(
    schema: dict[str, Any],
) -> None:
    schema["allOf"] = [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.0"}},
                "required": ["schema_version"],
            },
            "then": {"properties": {"effective_config_sha256": {"type": "null"}}},
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.1"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "effective_config_sha256": {
                        "pattern": r"^[0-9a-f]{64}$",
                        "type": "string",
                    }
                },
                "required": ["effective_config_sha256"],
            },
        },
    ]


def _strengthen_authenticated_runner_contract(
    schema: dict[str, Any],
    *,
    filename: str,
) -> None:
    """Publish only the exact bounded, non-authorizing AUTHRUNNER release view."""

    definitions = schema["$defs"]
    if filename == "authenticated_runner_durable_evidence_bundle.schema.json":
        _strengthen_openrouter_request_cost_preview_contract(
            definitions["OpenRouterStructuredRequestCostPreview"]
        )
        _strengthen_authenticated_runner_cost_plan_contract(
            definitions["AuthenticatedRunnerStagedCostPlan"]
        )
        runner_evidence_definition = definitions["AuthenticatedCrossLineageRunnerEvidence"]
        _strengthen_authenticated_runner_contract(
            {
                "$defs": definitions,
                "properties": runner_evidence_definition["properties"],
            },
            filename="authenticated_cross_lineage_runner_evidence.schema.json",
        )
        _strengthen_authenticated_runner_config_version_contract(runner_evidence_definition)
        _strengthen_authenticated_runner_contract(
            {
                "$defs": definitions,
                "properties": definitions["CrossLineageAdjudicationReport"]["properties"],
            },
            filename="cross_lineage_adjudication_report.schema.json",
        )
        prepared = definitions["CrossLineageAdjudicationPreparedRun"]
        for field_name in ("case_ids", "requests"):
            _exact_authenticated_runner_case_inventory(prepared["properties"][field_name])
            prepared["properties"][field_name]["uniqueItems"] = True
        prepared["properties"]["case_ids"]["items"] = {
            "pattern": r"^case-[0-9a-f]{16}$",
            "type": "string",
        }
        candidate_report = definitions["ModelBenchmarkReport"]
        _exact_authenticated_runner_case_inventory(candidate_report["properties"]["case_ids"])
        candidate_report["properties"]["case_ids"]["uniqueItems"] = True
        candidate_report["properties"]["case_ids"]["items"] = {
            "pattern": r"^case-[0-9a-f]{16}$",
            "type": "string",
        }
        candidate_report["properties"]["results"]["minItems"] = 1
        candidate_report["properties"]["results"]["maxItems"] = 1
        candidate_report["properties"]["results"]["uniqueItems"] = True
        candidate_result = definitions["ModelBenchmarkModelResult"]
        _exact_authenticated_runner_case_inventory(candidate_result["properties"]["cases"])
        candidate_result["properties"]["cases"]["uniqueItems"] = True
        durable_run = definitions["AuthenticatedRunnerDurableRunEvidence"]
        durable_run["required"] = sorted(
            {
                *durable_run.get("required", []),
                "schema_version",
                "candidate_cost_plan",
                "judge_cost_plan",
            }
        )
        durable_run["allOf"] = [
            {
                "if": {
                    "properties": {"schema_version": {"const": "1.0"}},
                    "required": ["schema_version"],
                },
                "then": {
                    "properties": {
                        "candidate_cost_plan": {"type": "null"},
                        "judge_cost_plan": {"type": "null"},
                    }
                },
            },
            {
                "if": {
                    "properties": {"schema_version": {"const": "1.1"}},
                    "required": ["schema_version"],
                },
                "then": {
                    "properties": {
                        field_name: {"$ref": "#/$defs/AuthenticatedRunnerStagedCostPlan"}
                        for field_name in ("candidate_cost_plan", "judge_cost_plan")
                    }
                },
            },
        ]
        schema["required"] = sorted({*schema.get("required", []), "schema_version"})
        for version in ("1.0", "1.1", "1.2"):
            run_version = "1.0" if version == "1.0" else "1.1"
            version_properties: dict[str, Any] = {
                "runs": {
                    "prefixItems": [
                        {
                            "allOf": [
                                {"$ref": "#/$defs/AuthenticatedRunnerDurableRunEvidence"},
                                {
                                    "properties": {"schema_version": {"const": run_version}},
                                    "required": ["schema_version"],
                                },
                            ]
                        }
                        for _run_kind in ("PRIMARY", "REPLAY")
                    ]
                }
            }
            if version in ("1.1", "1.2"):
                version_properties["closed_ledger_evidence"] = {
                    "properties": {
                        "entries": {
                            "items": {
                                "properties": {
                                    "reserved_usd": {
                                        "pattern": r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$",
                                        "type": "string",
                                    }
                                },
                                "required": ["reserved_usd"],
                            }
                        }
                    }
                }
            if version in ("1.0", "1.1"):
                version_properties["effective_config_sha256"] = {"type": "null"}
                version_properties["runner_evidence"] = {
                    "allOf": [
                        {"$ref": "#/$defs/AuthenticatedCrossLineageRunnerEvidence"},
                        {
                            "properties": {"schema_version": {"const": "1.0"}},
                            "required": ["schema_version"],
                        },
                    ]
                }
            else:
                version_properties["effective_config_sha256"] = {
                    "pattern": r"^[0-9a-f]{64}$",
                    "type": "string",
                }
                version_properties["runner_evidence"] = {
                    "allOf": [
                        {"$ref": "#/$defs/AuthenticatedCrossLineageRunnerEvidence"},
                        {
                            "properties": {"schema_version": {"const": "1.1"}},
                            "required": ["schema_version", "effective_config_sha256"],
                        },
                    ]
                }
            schema.setdefault("allOf", []).append(
                {
                    "if": {
                        "properties": {"schema_version": {"const": version}},
                        "required": ["schema_version"],
                    },
                    "then": {
                        "properties": version_properties,
                        **({"required": ["effective_config_sha256"]} if version == "1.2" else {}),
                    },
                }
            )
        runs = schema["properties"]["runs"]
        runs["minItems"] = AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        runs["maxItems"] = AUTHENTICATED_RUNNER_DURABLE_RUN_COUNT
        runs["uniqueItems"] = True
        runs["prefixItems"] = [
            {
                "allOf": [
                    {"$ref": "#/$defs/AuthenticatedRunnerDurableRunEvidence"},
                    {
                        "properties": {"run_kind": {"const": run_kind}},
                        "required": ["run_kind"],
                    },
                ]
            }
            for run_kind in ("PRIMARY", "REPLAY")
        ]
        runs["items"] = False
        runs["allOf"] = [
            {
                "contains": {
                    "properties": {"run_kind": {"const": run_kind}},
                    "required": ["run_kind"],
                },
                "maxContains": 1,
                "minContains": 1,
            }
            for run_kind in ("PRIMARY", "REPLAY")
        ]
        decisions = definitions["AuthenticatedRunnerAuthsealComplete"]["properties"][
            "decision_projections"
        ]
        decisions["minItems"] = 2
        decisions["maxItems"] = 2
        decisions["uniqueItems"] = True
        decisions["prefixItems"] = [
            {
                "allOf": [
                    {"$ref": "#/$defs/EvidenceSealDecisionProjection"},
                    {
                        "properties": {"run_kind": {"const": run_kind}},
                        "required": ["run_kind"],
                    },
                ]
            }
            for run_kind in ("PRIMARY", "REPLAY")
        ]
        decisions["items"] = False
        routing = definitions["UsageRecord"]["properties"]["routing"]
        routing["propertyNames"]["allOf"].append(
            {"enum": list(AUTHENTICATED_RUNNER_DURABLE_ROUTING_KEYS)}
        )
        maximum_attempts = definitions["AuthenticatedCrossLineageCaseExecutionEvidence"][
            "properties"
        ]["attempt_request_ids"]["maxItems"]
        if maximum_attempts != AUTHENTICATED_RUNNER_DURABLE_MAX_ATTEMPTS:
            raise ValueError("durable AUTHRUNNER attempt bound differs from runtime")
        schema["$comment"] = (
            "Offline validation replays the exact PRIMARY/REPLAY prepared requests, reports, "
            "runner hashes, all closed-ledger attempt costs, optional AUTHSEAL comparison "
            "inputs, and the bundle self-hash. Serialized evidence grants no runtime authority."
        )
        return
    if filename == "authenticated_cross_lineage_runner_evidence.schema.json":
        _strengthen_authenticated_runner_config_version_contract(schema)
        _exact_authenticated_runner_case_inventory(schema["properties"]["case_ids"])
        schema["properties"]["case_ids"]["items"] = {
            "pattern": r"^case-[0-9a-f]{16}$",
            "type": "string",
        }
        runs = schema["properties"]["runs"]
        runs["minItems"] = 2
        runs["maxItems"] = 2
        runs["uniqueItems"] = True
        runs["prefixItems"] = [
            {
                "allOf": [
                    {"$ref": "#/$defs/AuthenticatedCrossLineageRunnerRunEvidence"},
                    {
                        "properties": {"run_kind": {"const": run_kind}},
                        "required": ["run_kind"],
                    },
                ]
            }
            for run_kind in ("PRIMARY", "REPLAY")
        ]
        runs["items"] = False
        runs["allOf"] = [
            {
                "contains": {
                    "properties": {"run_kind": {"const": run_kind}},
                    "required": ["run_kind"],
                },
                "maxContains": 1,
                "minContains": 1,
            }
            for run_kind in ("PRIMARY", "REPLAY")
        ]
        run = definitions["AuthenticatedCrossLineageRunnerRunEvidence"]
        for field_name in ("candidate_cases", "judge_cases"):
            _exact_authenticated_runner_case_inventory(run["properties"][field_name])
        run["properties"]["candidate_campaign_report_sha256s"]["uniqueItems"] = True
        case = definitions["AuthenticatedCrossLineageCaseExecutionEvidence"]
        case["properties"]["attempt_request_ids"]["uniqueItems"] = True
        ledger = definitions["AuthenticatedCrossLineageLedgerIntervalEvidence"]
        ledger_entries = ledger["properties"]["entries"]
        logical_request_count = 2 * _AUTHENTICATED_RUNNER_RELEASE_CASE_COUNT * 2
        maximum_attempts_per_request = case["properties"]["attempt_request_ids"]["maxItems"]
        ledger_entries["minItems"] = logical_request_count
        ledger_entries["maxItems"] = logical_request_count * maximum_attempts_per_request
        ledger_entries["uniqueItems"] = True
        schema["$comment"] = (
            "Runtime validation additionally replays exact case/report/generation joins, "
            "independent public roots, unique request identities, closed ledger arithmetic, "
            "and the evidence self-hash using retained PID-local custody."
        )
        return

    if filename != "cross_lineage_adjudication_report.schema.json":
        raise ValueError(f"unexpected authenticated runner schema: {filename}")
    for field_name in ("case_ids", "cases"):
        _exact_authenticated_runner_case_inventory(schema["properties"][field_name])
    schema["properties"]["case_ids"]["items"] = {
        "pattern": r"^case-[0-9a-f]{16}$",
        "type": "string",
    }
    request = definitions["CrossLineageAdjudicationCaseRequest"]
    for field_name in (
        "candidate_dimension_result_sha256s",
        "expected_dimension_outcomes",
    ):
        request["properties"][field_name]["uniqueItems"] = True
    response = definitions["CrossLineageAdjudicationResponse"]
    response["properties"]["dimension_outcomes"]["uniqueItems"] = True
    usage = definitions["UsageRecord"]
    for definition_name in ("UsageRecord", "OpenRouterGenerationEvidence"):
        execution_evidence = definitions[definition_name]["properties"]["execution_evidence"]
        definitions[definition_name]["properties"]["execution_evidence"] = {
            "const": "real",
            **(
                {"default": execution_evidence["default"]}
                if "default" in execution_evidence
                else {}
            ),
            "title": execution_evidence.get("title", "Execution Evidence"),
            "type": "string",
        }
    usage["properties"]["prompt_sha256"]["pattern"] = r"^[0-9a-f]{64}$"
    response_hash = usage["properties"]["response_sha256"]
    response_hash_string = next(
        option for option in response_hash["anyOf"] if option.get("type") == "string"
    )
    response_hash_string["pattern"] = r"^[0-9a-f]{64}$"
    endpoints = usage["properties"]["configured_provider_endpoints"]
    endpoints["minItems"] = 1
    endpoints["maxItems"] = 1
    endpoints["uniqueItems"] = True
    schema["$defs"]["AuthenticatedRunnerSafeRoutingValue"] = (
        _authenticated_runner_safe_routing_value()
    )
    routing = usage["properties"]["routing"]
    routing["additionalProperties"] = {"$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"}
    routing["maxProperties"] = 256
    routing["propertyNames"] = _authenticated_runner_safe_routing_property_names()
    routing["properties"] = {
        "canonical_model": {
            "pattern": r"^[A-Za-z0-9._-]+/[A-Za-z0-9._:/-]+$",
            "type": "string",
        },
        "data_collection": {"const": "deny", "type": "string"},
        "discovery_evidence_sha256": {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        "effective_privacy_policy_sha256": {
            "pattern": r"^[0-9a-f]{64}$",
            "type": "string",
        },
        "endpoint_pricing_sha256": {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        "endpoint_snapshot_sha256": {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        "model_metadata_snapshot_sha256": {
            "pattern": r"^[0-9a-f]{64}$",
            "type": "string",
        },
        "output_capability_sha256": {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        "privacy_authorization": {"const": "STRICT_ZDR_ENFORCED", "type": "string"},
        "privacy_endpoint_policy_class": {"const": "ZDR", "type": "string"},
        "privacy_profile": {"const": "SYNTHETIC_BENCHMARK", "type": "string"},
        "privacy_source_classification": {
            "enum": ["PUBLIC_BENCHMARK", "SYNTHETIC_COMMITTED"],
            "type": "string",
        },
        "privacy_source_proof_kind": {
            "const": "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
            "type": "string",
        },
        "privacy_source_provenance_sha256": {
            "pattern": r"^[0-9a-f]{64}$",
            "type": "string",
        },
        "privacy_source_sha256": {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        "provider_fallbacks_allowed": {"const": False, "type": "boolean"},
        "selected_provider_endpoint": {
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$",
            "type": "string",
        },
        "selected_provider_name": {"maxLength": 200, "minLength": 1, "type": "string"},
        "structured_output_capability_sha256": {
            "pattern": r"^[0-9a-f]{64}$",
            "type": "string",
        },
        "structured_output_mode": {"$ref": "#/$defs/StructuredOutputMode"},
        "zdr_requested": {"const": True, "type": "boolean"},
    }
    routing["required"] = sorted(routing["properties"])
    schema["$comment"] = (
        "Runtime validation additionally proves the canonical prompt is derived only from the "
        "frozen synthetic/public case, joins target/request/wire/host hashes, and replays exact "
        "REAL usage, generation, route, privacy-provenance, and report custody."
    )


def rendered_schema(filename: str, model: type[BaseModel]) -> str:
    """Return one deterministic draft-2020-12 schema."""

    schema = model.model_json_schema()
    _strengthen_minimum_floor_recovery_contract(schema)
    if filename == "models_config.schema.json":
        lineage = schema["$defs"]["ModelLineageConfig"]
        measured_quality = lineage["properties"]["measured_quality"]
        non_null_options = [
            option for option in measured_quality["anyOf"] if option.get("type") != "null"
        ]
        if len(non_null_options) != 1:
            raise ValueError("models configuration schema has an unexpected quality union")
        lineage["properties"]["measured_quality"] = non_null_options[0]
        lineage["properties"]["aliases"]["uniqueItems"] = True
        lineage["$comment"] = (
            "Canonical model ID and aliases are also required to be case-insensitively "
            "distinct by ModelsConfig runtime validation."
        )
        schema["properties"]["registry"]["$comment"] = (
            "Canonical IDs and aliases are required to be globally case-insensitively unique "
            "by ModelsConfig runtime validation; this cross-item relation is not expressible "
            "in JSON Schema draft 2020-12."
        )
        quality = schema["$defs"]["ModelQualityMeasurementConfig"]
        quality["allOf"] = [
            {
                "if": {
                    "properties": {"tier": {"const": tier}},
                    "required": ["tier"],
                },
                "then": {"properties": {"score": {"minimum": minimum, "type": "number"}}},
            }
            for tier, minimum in (("high", 0.75), ("highest", 0.9))
        ]
    if filename in {"coverage_artifact.schema.json", "solidity_coverage.schema.json"}:
        _strengthen_solidity_coverage_contract(schema)
    if filename == "scheduler_state.schema.json":
        _strengthen_scheduler_recovery_contract(schema)
    if filename == "public_model_lineage_provenance.schema.json":
        _strengthen_public_model_lineage_contract(schema)
    if filename in {
        "authenticated_cross_lineage_runner_evidence.schema.json",
        "authenticated_runner_durable_evidence_bundle.schema.json",
        "cross_lineage_adjudication_report.schema.json",
    }:
        _strengthen_authenticated_runner_contract(schema, filename=filename)
    if filename == "openrouter_structured_request_cost_preview.schema.json":
        _strengthen_openrouter_request_cost_preview_contract(schema)
    if filename == "authenticated_runner_staged_cost_plan.schema.json":
        _strengthen_openrouter_request_cost_preview_contract(
            schema["$defs"]["OpenRouterStructuredRequestCostPreview"]
        )
        _strengthen_authenticated_runner_cost_plan_contract(schema)
    if filename in {
        "accepted_prepurchase_quote.schema.json",
        "prepurchase_quote.schema.json",
        "prepurchase_quote_reconciliation.schema.json",
    }:
        _strengthen_prepurchase_quote_contract(schema)
    if filename == "audit_model_selection_evidence.schema.json":
        schema["required"] = sorted({*schema.get("required", []), "technical_evidence_mode"})
    if filename == "model_execution_artifact.schema.json":
        schema.setdefault("allOf", []).extend(
            [
                {
                    "if": {
                        "properties": {
                            field_name: {"not": {"type": "null"}},
                        },
                        "required": [field_name],
                    },
                    "then": {
                        "properties": {"schema_version": {"const": "1.2"}},
                    },
                }
                for field_name in (
                    "audit_model_selection",
                    "audit_model_refresh_evidence",
                    "audit_model_refresh_pricing_evidence",
                )
            ]
        )
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_BASE}/{filename}"
    if filename in TITLE_OVERRIDES:
        schema["title"] = TITLE_OVERRIDES[filename]
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write generated schemas; without this option, verify committed bytes.",
    )
    arguments = parser.parse_args(argv)
    failures: list[str] = []
    for filename, model in sorted(MODELS.items()):
        expected = rendered_schema(filename, model)
        path = SCHEMA_ROOT / filename
        if arguments.write:
            path.write_text(expected, encoding="utf-8")
            continue
        try:
            observed = path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"{filename}: missing")
            continue
        if observed != expected:
            failures.append(f"{filename}: stale")
    toolchain_expected = render_default_managed_toolchain_bundle()
    toolchain_path = ROOT / "src" / "mmaudit" / MANAGED_TOOLCHAIN_BUNDLE_RESOURCE
    if arguments.write:
        toolchain_path.write_text(toolchain_expected, encoding="utf-8")
    else:
        try:
            toolchain_observed = toolchain_path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"{MANAGED_TOOLCHAIN_BUNDLE_RESOURCE}: missing")
        else:
            if toolchain_observed != toolchain_expected:
                failures.append(f"{MANAGED_TOOLCHAIN_BUNDLE_RESOURCE}: stale")
    inventory_expected = render_autonomy_gate_inventory(repository_root=ROOT)
    inventory_path = ROOT / AUTONOMY_INVENTORY_PATH
    if arguments.write:
        inventory_path.write_text(inventory_expected, encoding="utf-8")
    else:
        try:
            inventory_observed = inventory_path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"{AUTONOMY_INVENTORY_PATH}: missing")
        else:
            if inventory_observed != inventory_expected:
                failures.append(f"{AUTONOMY_INVENTORY_PATH}: stale")
    if not _run_evidence_manifest_contract_is_current():
        failures.append("run_evidence_manifest.schema.json: stale report-bundle contract")
    if failures:
        raise SystemExit("release schema verification failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
