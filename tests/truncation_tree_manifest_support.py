"""Byte-consistent synthetic review inputs; no compiler, engine or provider execution."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.config import AuditConfig, AuditConfigOverrides, AuditRunOptions, configured_model_ids
from mmaudit.constants import ANALYSIS_ROLES, SPECIALIST_INVESTIGATOR_ROLES
from mmaudit.isolation.dependencies import DependencyPreparationRun
from mmaudit.models.actor_model import ActorModelInputEvidence, ActorModelInputState
from mmaudit.models.scheduler import (
    SchedulerAnalysisInputInventory,
    SchedulerPrivacyEvidenceCustody,
    SchedulerShardInventory,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    ActorModelBaselineArtifact,
    AuditedSuiteCoverage,
    AuditReport,
    CandidateReviewBatch,
    ContextPackage,
    InvariantSuite,
    LanguageCapabilityFileEvidence,
    Location,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    RepositoryMap,
    SolidityGraphKind,
    SolidityGraphNode,
    SolidityGraphNodeKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SoliditySymbolIndex,
    UsageRecord,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.sharding import SolidityShardInventory
from mmaudit.models.truncation import CandidateReviewNormalizationEvidence
from mmaudit.orchestration.actor_model import build_actor_model_evaluation
from mmaudit.orchestration.assurance import AssuranceRuntime, MaximumAssuranceContract
from mmaudit.orchestration.context import render_context
from mmaudit.orchestration.execution_candidates import ExecutionCandidateBuildResult
from mmaudit.orchestration.pipeline import _build_scheduler_privacy_evidence_custody
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    audit_quality_status_for_run_status,
    minimum_analysis_floor_quality_gate,
)
from mmaudit.orchestration.scheduler_runtime import (
    build_scheduler_analysis_input_inventory,
    build_scheduler_shard_inventory,
)
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceEvidence,
    PrivacySourceProvenanceObservation,
    prove_privacy_source_classification,
    validate_privacy_source_provenance_observation,
)
from mmaudit.solidity.graphs import _entity_node
from mmaudit.solidity.properties import build_property_corpus
from mmaudit.solidity.sharding import build_solidity_shard_inventory
from mmaudit.solidity.taxonomy import (
    build_known_issue_taxonomy_coverage,
    known_issue_taxonomy_quality_gate,
    load_known_issue_taxonomy,
)
from tests.language_capability_support import language_capability_for_files
from tests.unit import test_model_coverage as surfaces


@dataclass(frozen=True)
class ReviewSourceFixture:
    """Retain exact source bytes and every deterministic projection supplied to scheduling."""

    discovery: DiscoveryResult
    repository_map: RepositoryMap
    index: SoliditySymbolIndex
    graphs: SolidityGraphSet
    invariants: InvariantSuite
    suite: AuditedSuiteCoverage
    rich_requests: tuple[ModelSurfaceReviewRequest, ...]
    file_requests: tuple[ModelSurfaceReviewRequest, ...]
    semantic_shards: SolidityShardInventory
    scheduler_shards: SchedulerShardInventory
    analysis_arguments: dict[str, Any]
    analysis_inputs: SchedulerAnalysisInputInventory

    @property
    def sources(self) -> dict[str, str]:
        return {item.relative_path: item.content for item in self.discovery.files}


@dataclass(frozen=True)
class ReviewPrivacyFixture:
    """Retain original private-default provenance and exact pre-campaign file custody."""

    run_directory: Path
    observation: PrivacySourceProvenanceObservation
    provenance: PrivacySourceProvenanceEvidence
    policy: EffectivePrivacyPolicyEvidence
    custody: SchedulerPrivacyEvidenceCustody

    def report_payload(self) -> dict[str, Any]:
        return {
            "fixture_only": True,
            "code_egress_enabled": False,
            "profile": self.policy.privacy_profile.value,
            "source_provenance": self.provenance.model_dump(mode="json"),
            "effective_policy": self.policy.model_dump(mode="json"),
        }


def build_review_privacy_fixture(
    config: AuditConfig,
    source: ReviewSourceFixture,
    run_directory: Path,
    *,
    now: datetime,
) -> ReviewPrivacyFixture:
    """Use production builders before scheduling; never infer public/synthetic consent."""

    options = source.analysis_arguments["run_options"]
    classification = options.privacy_source_classification
    assert classification is PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE
    assert config.privacy.profile is PrivacyProfile.STRICT_ZDR and config.privacy.require_zdr
    assert not options.allow_code_egress
    observation = prove_privacy_source_classification(
        source.discovery,
        requested_classification=classification,
        source_sha256=source.scheduler_shards.source_tree_sha256,
        now=now,
    )
    provenance = validate_privacy_source_provenance_observation(
        observation,
        source_sha256=source.scheduler_shards.source_tree_sha256,
        source_classification=classification,
    )
    policy = resolve_effective_privacy_policy(
        profile=config.privacy.profile,
        require_zdr=config.privacy.require_zdr,
        consent_observation=None,
        source_sha256=provenance.source_sha256,
        source_classification=classification,
        source_provenance_observation=observation,
        configured_model_ids=tuple(
            sorted(set(configured_model_ids(config, include_fallbacks=True)))
        ),
        configured_provider_endpoints=tuple(
            sorted(
                set(config.models.provider_policy.only) | set(config.models.provider_policy.order)
            )
        ),
        requested_budget_usd=Decimal(str(config.execution.budget_usd)),
        now=now,
    )
    run_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    for name, evidence in (
        ("privacy-source-provenance.json", provenance),
        ("privacy-policy.json", policy),
    ):
        path = run_directory / name
        assert not path.exists(), "privacy evidence must precede a fresh original campaign"
        write_json(path, evidence)
        path.chmod(0o600)
    custody = _build_scheduler_privacy_evidence_custody(
        run_directory, provenance=provenance, policy=policy
    )
    return ReviewPrivacyFixture(run_directory, observation, provenance, policy, custody)


def build_review_manifest_report(
    config: AuditConfig,
    source: ReviewSourceFixture,
    runtime: AssuranceRuntime,
    budget_usd_exact: str,
    *,
    privacy: ReviewPrivacyFixture | None = None,
    include_invocation: bool = False,
) -> AuditReport:
    """Derive an incomplete current report without manufacturing absent engine results."""

    generated_at = datetime.now(UTC)
    baseline = ActorModelBaselineArtifact.build(())
    actor = ActorModelInputEvidence.build(
        evaluated_at=generated_at,
        state=ActorModelInputState.MISSING,
        configured=False,
        configured_path=None,
        limitations=("No operator actor model is supplied by the synthetic fixture.",),
    )
    taxonomy = build_known_issue_taxonomy_coverage(
        load_known_issue_taxonomy(),
        invariants=source.invariants,
        model_review_coverage=runtime.model_review_coverage,
    )
    floor = assess_minimum_analysis_floor(
        repository=source.repository_map,
        compilations=runtime.compilations,
        scanner_runs=runtime.scanners,
        usage=runtime.model_usage,
        required_model_roles=ANALYSIS_ROLES,
        coverage_metrics={},
    )
    capability = language_capability_for_files(
        config.language_profile,
        tuple(
            LanguageCapabilityFileEvidence(
                path=item.path,
                sha256=item.sha256,
                size=item.size,
                lines=item.lines,
                language=item.language,
            )
            for item in source.repository_map.files
        ),
        solidity_project_count=len(source.index.projects),
    )
    assessment = MaximumAssuranceContract(config, require=True).evaluate(
        replace(
            runtime,
            taxonomy_coverage=taxonomy,
            artifacts=runtime.artifacts
            | {"known-issue-taxonomy-coverage.json", "known-issue-taxonomy.json"},
        )
    )
    cost = sum(
        (Decimal(usage.accounted_cost_usd_exact) for usage in runtime.model_usage), Decimal("0")
    )
    selection = runtime.audit_model_selection_evidence
    return AuditReport(
        schema_version="1.4",
        run_id="source-consistent-synthetic-model-review",
        generated_at=generated_at,
        completed=floor.minimum_floor_met,
        incomplete_reasons=[
            *floor.limitations,
            "No compiler, scanner, formal or genuine-provider execution supplied.",
        ],
        repository=source.repository_map,
        configuration_hash=config.effective().stable_hash(),
        model_configuration_hash=config.effective().model_hash(),
        privacy=(
            privacy.report_payload()
            if privacy is not None
            else {"fixture_only": True, "code_egress_enabled": False}
        ),
        scanner_runs=runtime.scanners,
        usage=runtime.model_usage,
        budget_usd=float(Decimal(budget_usd_exact)),
        accounted_cost_usd=float(cost),
        accounted_cost_usd_exact=format(cost, "f"),
        findings=[],
        rejected_findings=[],
        audit_profile=config.profile,
        quality_status=audit_quality_status_for_run_status(floor.run_status),
        run_status=floor.run_status,
        minimum_analysis_floor=floor,
        language_capability=capability.assessment,
        maximum_assurance=assessment,
        audit_model_selection=selection.selection if selection is not None else None,
        audit_model_refresh_evidence=runtime.audit_model_refresh_evidence,
        audit_model_refresh_pricing_evidence=runtime.audit_model_refresh_pricing_evidence,
        quality_gates=[
            minimum_analysis_floor_quality_gate(floor),
            known_issue_taxonomy_quality_gate(taxonomy, required=assessment.required),
        ],
        actor_model_baseline=baseline,
        actor_model_evaluation=build_actor_model_evaluation(
            actor_input=actor, findings=(), baseline_artifact=baseline, governance_findings=()
        ),
        judge_decisions=[],
        invariants=source.invariants,
        taxonomy_coverage=taxonomy,
        model_review_coverage=runtime.model_review_coverage,
        metadata={
            **(
                {
                    "run_options": source.analysis_arguments["run_options"].model_dump(mode="json"),
                    "configuration_provenance": {
                        "file_config_sha256": config.effective().stable_hash(),
                        "environment_overrides_sha256": AuditConfigOverrides().stable_hash(),
                        "cli_overrides_sha256": AuditConfigOverrides().stable_hash(),
                        "run_options_sha256": source.analysis_arguments[
                            "run_options"
                        ].stable_hash(),
                    },
                }
                if include_invocation
                else {}
            ),
            "scanner_only": False,
            "solidity": {
                "projects": [project.model_dump(mode="json") for project in source.index.projects],
                "compilation": [item.model_dump(mode="json") for item in runtime.compilations],
                **(
                    {
                        "property_corpus_summary": {
                            "properties": len(
                                source.analysis_arguments["property_corpus"].properties
                            ),
                            "limitations": len(
                                source.analysis_arguments["property_corpus"].limitations
                            ),
                            "corpus_hash": source.analysis_arguments["property_corpus"].corpus_hash,
                        }
                    }
                    if include_invocation
                    else {}
                ),
            },
        },
    )


def file_review_record(request: ModelSurfaceReviewRequest, role: str) -> ModelSurfaceReviewRecord:
    """Describe only the declared comment-only file fixture and its exact source range."""

    citation = ModelSurfaceReviewCitation(location=request.allowed_locations[0])
    return ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role=role,
        status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        rationale="The non-executable synthetic source scope is retained with exact byte custody.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="The supplied comment-only fixture contains no executable body.",
                security_relevance="A review cannot substitute different bytes for the sealed scope.",
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="local synthetic fixture reader",
            preconditions=(),
        ),
        assumptions=(),
        confidence=1,
    )


def review_artifact_for_batch(
    *,
    requests: tuple[ModelSurfaceReviewRequest, ...],
    usage: UsageRecord,
    context: ContextPackage,
    batch: CandidateReviewBatch,
    normalization: CandidateReviewNormalizationEvidence | None,
) -> ModelSurfaceReviewArtifact:
    """Seal exactly the already-produced batch, rather than synthesize a second response."""

    ids = tuple(request.surface_id for request in requests)
    batch.require_exact_surface_set(ids)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "request_id": usage.request_id,
        "review_role": usage.role,
        "requested_surface_ids": list(ids),
        "requested_surface_ids_sha256": scheduler_canonical_sha256(list(ids)),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256(requests)
        ),
        "rendered_context_sha256": hashlib.sha256(render_context(context).encode()).hexdigest(),
        "prompt_sha256": usage.prompt_sha256,
        "response_sha256": usage.response_sha256,
        "validated_response_sha256": usage.validated_response_sha256,
        "response_schema_sha256": usage.schema_sha256,
        "records": [record.model_dump(mode="json") for record in batch.surface_reviews],
    }
    if normalization is not None:
        payload.update(
            schema_version="1.1",
            normalized_response_sha256=normalization.normalized_batch_sha256,
            normalization_evidence=normalization.model_dump(mode="json"),
            normalized_response=batch.model_dump(mode="json"),
        )
    return ModelSurfaceReviewArtifact.model_validate(
        payload | {"artifact_sha256": ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)}
    )


def build_review_source_fixture() -> ReviewSourceFixture:
    """Use actual local bytes; semantic observations remain explicitly synthetic test data."""

    root = Path(__file__).parent / "fixtures" / "truncation_tree"
    source = root / surfaces._PATH
    raw = source.read_bytes()
    assert raw == surfaces._SOURCE.encode(), "shared semantic fixture source changed"
    discovery = DiscoveryResult(
        root=root.resolve(),
        files=(
            DiscoveredFile(
                absolute_path=source.resolve(),
                relative_path=surfaces._PATH,
                content=raw.decode(),
                size=len(raw),
                lines=len(raw.decode().splitlines()),
                sha256=hashlib.sha256(raw).hexdigest(),
                language="Solidity",
                categories=("source",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )
    index, graphs, invariants, _suite, _rich = surfaces._promoted_surface_inputs()
    nodes = {entity.id: _entity_node(entity) for entity in index.entities}
    for edge in graphs.edges:
        for endpoint in (edge.source_id, edge.target_id):
            if endpoint in nodes:
                continue
            kind = {
                "asset": SolidityGraphNodeKind.ASSET,
                "role": SolidityGraphNodeKind.ROLE,
                "external": SolidityGraphNodeKind.EXTERNAL_TARGET,
            }[endpoint.split(":", 1)[0]]
            node = SolidityGraphNode(
                id=endpoint,
                kind=kind,
                label=endpoint,
                path=edge.path,
                start_line=edge.start_line,
                end_line=edge.end_line,
                source_hash=edge.source_hash,
                provenance=edge.provenance,
                confidence=edge.confidence,
                transformation="synthetic_complete_review_graph_endpoint",
            )
            nodes[endpoint] = node
    counts = Counter(edge.graph.value for edge in graphs.edges)
    # This is one fully authored synthetic graph population, not an engine execution.
    # All unrepresented kinds have exactly zero edges in that population.
    graphs = graphs.model_copy(
        update={
            "nodes": sorted(nodes.values(), key=lambda node: node.id),
            "analyzed_graphs": sorted(SolidityGraphKind, key=lambda kind: kind.value),
            "coverage": {kind.value: counts[kind.value] for kind in SolidityGraphKind},
            "retained_occurrences": tuple(
                sorted(
                    (
                        *surfaces._edge_occurrences(graphs.edges),
                        *(
                            SolidityGraphRetainedOccurrence(
                                subject_kind=SolidityGraphOccurrenceKind.GRAPH_NODE,
                                subject_sha256=solidity_graph_occurrence_sha256(
                                    SolidityGraphOccurrenceKind.GRAPH_NODE, node
                                ),
                                occurrence_count=1,
                            )
                            for node in nodes.values()
                        ),
                    ),
                    key=lambda item: (item.subject_kind.value, item.subject_sha256),
                )
            ),
        }
    )
    graphs = SolidityGraphSet.model_validate(graphs.model_dump(mode="python"))
    suite = surfaces._audited_gap_coverage(index, graphs, invariants)
    rich = tuple(
        surfaces.build_model_surface_requests(
            index=index,
            graphs=graphs,
            invariants=invariants,
            economic_simulations=[],
            audited_suite_coverage=suite,
        )
    )
    context = surfaces._promoted_surface_context(
        rich,
        surfaces._usage("source_audit", "synthetic/model", "source-inventory-context"),
        index,
        graphs,
    )
    repository_map = context.repository_map
    semantic_shards = build_solidity_shard_inventory(discovery, index, graphs)
    scheduler_shards = build_scheduler_shard_inventory(repository_map, semantic_shards)
    file_requests = tuple(
        ModelSurfaceReviewRequest(
            surface_id=ModelSurfaceReviewRequest.calculate_surface_id(
                ModelReviewSurfaceKind.SOURCE_FILE, f"source:{item.relative_path}"
            ),
            kind=ModelReviewSurfaceKind.SOURCE_FILE,
            subject_id=f"source:{item.relative_path}",
            contract=item.relative_path,
            function_or_state_surface="synthetic file surface",
            critical=True,
            allowed_locations=(
                Location(
                    path=item.relative_path,
                    start_line=1,
                    end_line=item.lines,
                    content_hash=item.sha256,
                ),
            ),
            invariant_considered="Synthetic source bytes and requested scope remain exact.",
        )
        for item in discovery.files
    )
    assignments = {
        role: list(rich) for role in ("source_audit", "business_logic", "configuration")
    } | {
        role: list(file_requests)
        for role in (
            *(f"specialist:{role}" for role in SPECIALIST_INVESTIGATOR_ROLES),
            *(f"whole_protocol_review:{i}" for i in range(4)),
        )
    }
    arguments: dict[str, Any] = dict(
        run_options=AuditRunOptions(),
        discovery=discovery,
        repository_map=repository_map,
        repository_execution_sha256=None,
        scanner_source_sha256=None,
        dependency_preparation=DependencyPreparationRun([], [], {}),
        scope_assessment=None,
        projects=index.projects,
        compilations=[],
        index=index,
        graphs=graphs,
        semantic_shards=semantic_shards,
        invariants=invariants,
        invariant_harnesses=[],
        invariant_executions=[],
        property_corpus=build_property_corpus(invariants, index, []),
        economic_simulations=[],
        formal_runs=[],
        scanner_runs=[],
        repository_suite_differential=None,
        solidity_coverage=None,
        execution_candidate_build=ExecutionCandidateBuildResult(
            (), (), 0, ("No engine execution is supplied by this source fixture.",)
        ),
        model_surface_requests=sorted((*rich, *file_requests), key=lambda item: item.surface_id),
        model_surface_review_assignments=assignments,
    )
    analysis_inputs = build_scheduler_analysis_input_inventory(**arguments)
    return ReviewSourceFixture(
        discovery,
        repository_map,
        index,
        graphs,
        invariants,
        suite,
        rich,
        file_requests,
        semantic_shards,
        scheduler_shards,
        arguments,
        analysis_inputs,
    )
