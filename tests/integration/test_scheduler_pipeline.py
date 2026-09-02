from __future__ import annotations

import hashlib
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

import mmaudit.orchestration.manifest as manifest_module
import mmaudit.orchestration.pipeline as pipeline_module
from mmaudit.config import AuditConfig, model_lineage_index
from mmaudit.models.actor_model import ActorModelInputState
from mmaudit.models.retrieval import (
    SolidityRetrievalIntent,
    SolidityRetrievalOperation,
    SolidityRetrievalRequestBatch,
)
from mmaudit.models.scheduler import (
    SCHEDULER_PASS_ORDER,
    SchedulerAbsenceReason,
    SchedulerActivationStatus,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCampaignStatus,
    SchedulerEvidencePayloadBinding,
    SchedulerPassKind,
    SchedulerPassResult,
    SchedulerPassStatus,
    SchedulerReproductionHostOutput,
    SchedulerRetainedJournalReference,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskOutput,
    SchedulerTaskPlan,
    SchedulerTaskPurpose,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import (
    AuditReport,
    CandidateFinding,
    CandidateReviewBatch,
    ExecutionEvidenceKind,
    FormalEvidence,
    FormalResultKind,
    FormalToolRun,
    FormalToolStatus,
    Location,
    LocationValidation,
    ModelReviewEvidenceReference,
    ModelReviewSurface,
    ModelReviewSurfaceKind,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewEvidenceObservation,
    ModelSurfaceReviewReachability,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewRequest,
    ModelSurfaceReviewStatus,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphRetainedOccurrence,
    SolidityProvenance,
    SourceSink,
    solidity_graph_occurrence_sha256,
)
from mmaudit.models.truncation import decode_complete_candidate_review_frames
from mmaudit.orchestration.assurance import AssuranceRuntime, MaximumAssuranceContract
from mmaudit.orchestration.context import ContextBudgetError, ContextBuilder
from mmaudit.orchestration.context_manifest import load_context_manifest
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.manifest import (
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    seal_run_evidence_manifest,
    validate_manifest_artifacts,
)
from mmaudit.orchestration.model_coverage import model_review_edge_subject_id
from mmaudit.orchestration.model_review_evidence import build_source_file_review_request
from mmaudit.orchestration.pipeline import (
    _attach_formal_counterexamples,
    _build_cross_shard_integration,
    _build_deterministic_finding_reduction,
    _candidate_payload_sha256s,
    _cross_shard_boundary_surface_requests,
    _cross_shard_overlap_surface_requests,
    _finding_reduction_activation_input,
    _load_exact_resume_privacy_evidence,
    _resolve_scheduler_resume_journal,
    _semantic_shard_context_paths,
    _validate_cross_shard_integration,
    _validate_deterministic_finding_reduction,
)
from mmaudit.orchestration.scheduler import SchedulerJournal
from mmaudit.orchestration.scheduler_runtime import PipelineScheduler
from mmaudit.privacy import EffectivePrivacyPolicyEvidence
from mmaudit.reporting.bundle import (
    FindingsArtifact,
    ModelExecutionArtifact,
    RunCostLedgerEvidence,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import render_client_markdown_from_artifact
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.run_authority import RunTerminalReportAuthority
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import effective_report_status, report_status_metadata
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.repository.privacy_provenance import PrivacySourceProvenanceEvidence
from mmaudit.solidity.graphs import build_solidity_graphs
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.sharding import build_solidity_shard_inventory
from tests.conftest import FIXTURES, model_registry_entry
from tests.fake_openrouter import (
    FakeOpenRouter,
    _candidate_review_wire,
    _request_schema_name,
    _surface_review_path,
)
from tests.integration.test_pipeline import StaticScannerRunner, _maximum_specialists, _run
from tests.qualification_support import synthetic_production_qualification
from tests.unit.test_semantic_sharding import _inventory, _shard_inputs


def _qualifying_synthetic_formal_run(
    *,
    property_id: str,
    property_description: str,
    counterexample: dict[str, Any],
    location: Location,
) -> FormalToolRun:
    evidence = FormalEvidence(
        tool="synthetic-formal",
        property_id=property_id,
        property_description=property_description,
        status=FormalToolStatus.SUCCESS,
        result_kind=FormalResultKind.COUNTEREXAMPLE,
        counterexample=counterexample,
        locations=[location],
        confidence=1,
    )
    provisional = FormalToolRun(
        tool="synthetic-formal",
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="synthetic-formal 1.0.0",
        executable_sha256="a" * 64,
        isolation_backend="sandbox-exec",
        isolation_attestation_sha256="b" * 64,
        status=FormalToolStatus.SUCCESS,
        command=["synthetic-formal", "--machine-output"],
        evidence=[evidence],
        coverage={"indexed_sources": 1},
        stdout_path="synthetic-formal/stdout.txt",
        stderr_path="synthetic-formal/stderr.txt",
        process_exit_code=0,
        stdout_sha256="c" * 64,
        stderr_sha256="d" * 64,
        stdout_bytes=1,
        machine_output_validated=True,
    )
    return FormalToolRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )


_REPORT_QUALITY_MODEL_ID = "hotel/harbor-secure"


class _SyntheticSchedulerCrash(BaseException):
    """Represent an abrupt local process loss outside ordinary exception handling."""


class _CrashAfterDispatchOpenRouter(FakeOpenRouter):
    """Crash once after HTTP dispatch enters the deterministic local transport."""

    def __init__(self, *, extra_model_ids: list[str]) -> None:
        super().__init__(extra_model_ids=extra_model_ids)
        self.crashed = False

    def handler(self, request: Any) -> Any:
        if request.url.path.endswith("/chat/completions") and not self.crashed:
            self.crashed = True
            self.chat_calls += 1
            self.requests.append(json.loads(request.content))
            raise _SyntheticSchedulerCrash
        return super().handler(request)


class _AllInvalidCandidateLocationsOpenRouter(FakeOpenRouter):
    """Keep valid review envelopes while making every candidate location invalid."""

    def handler(self, request: httpx.Request) -> httpx.Response:
        response = super().handler(request)
        if not request.url.path.endswith("/chat/completions") or response.status_code != 200:
            return response
        payload = response.json()
        try:
            content_text = payload["choices"][0]["message"]["content"]
            if not isinstance(content_text, str):
                return response
            content = decode_complete_candidate_review_frames(content_text).model_dump(mode="json")
        except (KeyError, TypeError, ValueError):
            return response
        for finding in content.get("findings", []):
            for location in finding.get("locations", []):
                location["path"] = "missing.py"
                location["symbol"] = None
            if finding.get("source") is not None:
                finding["source"]["path"] = "missing.py"
            if finding.get("sink") is not None:
                finding["sink"]["path"] = "missing.py"
        payload["choices"][0]["message"]["content"] = _candidate_review_wire(content)
        return httpx.Response(200, headers=dict(response.headers), json=payload)


class _InvalidSourcePrimaryOpenRouter(FakeOpenRouter):
    """Return invalid JSON only for the source primary, after retrieval planning succeeds."""

    def handler(self, request: httpx.Request) -> httpx.Response:
        body: dict[str, Any] | None = None
        if request.url.path.endswith("/chat/completions"):
            body = json.loads(request.content)
            metadata = body.get("metadata") or {}
            if (
                _request_schema_name(body) != "mmaudit_solidity_retrieval_request_batch"
                and metadata.get("mmaudit_role") == "source_audit"
            ):
                self.chat_calls += 1
                self.requests.append(body)
                return self._completion(body, "not valid json")
        response = super().handler(request)
        if (
            body is None
            or response.status_code != 200
            or _request_schema_name(body) != "mmaudit_solidity_retrieval_request_batch"
        ):
            return response
        user_prompt = body["messages"][1]["content"]
        policy_payload = json.loads(
            user_prompt.split("<VALIDATED_SOLIDITY_RETRIEVAL_POLICY_JSON>", 1)[1].split(
                "</VALIDATED_SOLIDITY_RETRIEVAL_POLICY_JSON>",
                1,
            )[0]
        )
        subjects = policy_payload["subjects"]
        assert subjects
        batch = SolidityRetrievalRequestBatch(
            requests=(
                SolidityRetrievalIntent(
                    operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
                    subject_id=subjects[0]["subject_id"],
                ),
            )
        )
        payload = response.json()
        payload["choices"][0]["message"]["content"] = batch.model_dump_json()
        return httpx.Response(200, headers=dict(response.headers), json=payload)


class _CurrentActorJudgmentOpenRouter(FakeOpenRouter):
    """Return actor-aware judgment whose classification must remain non-authoritative."""

    def __init__(self, *, actor_context: dict[str, Any], extra_model_ids: list[str]) -> None:
        super().__init__(extra_model_ids=extra_model_ids)
        self.actor_context = actor_context

    def handler(self, request: httpx.Request) -> httpx.Response:
        response = super().handler(request)
        if not request.url.path.endswith("/chat/completions") or response.status_code != 200:
            return response
        body = json.loads(request.content)
        if _request_schema_name(body) != "mmaudit_judgment":
            return response
        payload = response.json()
        content = json.loads(payload["choices"][0]["message"]["content"])
        for decision in content["decisions"]:
            decision.update(
                {
                    "status": "rejected",
                    "severity": "critical",
                    "confidence": 0.01,
                    "actor_model_applicability": "privileged_actor_required",
                    "actor_context": self.actor_context,
                }
            )
        payload["choices"][0]["message"]["content"] = json.dumps(content, sort_keys=True)
        return httpx.Response(200, headers=dict(response.headers), json=payload)


def _only_scheduler_run(output: Path) -> Path:
    runs = tuple(path for path in (output / "runs").iterdir() if path.is_dir())
    assert len(runs) == 1
    return runs[0]


async def _create_activated_scheduler_campaign(
    *,
    config: AuditConfig,
    repository: Path,
    tmp_path: Path,
    output: Path,
    ledger: AtomicCostLedger,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, FakeOpenRouter]:
    fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    original_dispatched = PipelineScheduler.request_dispatched
    crash_observed = False

    def crash_before_dispatch(
        scheduler: PipelineScheduler,
        *,
        logical_request_id: str,
    ) -> None:
        nonlocal crash_observed
        if not crash_observed:
            crash_observed = True
            raise _SyntheticSchedulerCrash
        original_dispatched(scheduler, logical_request_id=logical_request_id)

    with monkeypatch.context() as crash_patch:
        crash_patch.setattr(PipelineScheduler, "request_dispatched", crash_before_dispatch)
        with pytest.raises(_SyntheticSchedulerCrash):
            await _run(
                config,
                repository,
                tmp_path,
                fake,
                cost_ledger=ledger,
                output=output,
            )
    assert crash_observed
    assert fake.chat_calls == 0
    return _only_scheduler_run(output), fake


def _scheduler_binding_with_drift(
    binding: SchedulerBindings,
    *,
    field: str,
) -> SchedulerBindings:
    values = {
        "source_sha256": binding.source_sha256,
        "analysis_input_sha256": binding.analysis_input_sha256,
        "effective_config_sha256": binding.effective_config_sha256,
        "shard_inventory_sha256": binding.shard_inventory_sha256,
        "model_selection_sha256": binding.model_selection_sha256,
        "qualification_sha256": binding.qualification_sha256,
        "prompt_set_sha256": binding.prompt_set_sha256,
        "schema_set_sha256": binding.schema_set_sha256,
        "tool_policy_sha256": binding.tool_policy_sha256,
        "cost_ledger_baseline_sha256": binding.cost_ledger_baseline_sha256,
        "privacy_evidence_custody_sha256": binding.privacy_evidence_custody_sha256,
    }
    assert field in values
    values[field] = hashlib.sha256(f"synthetic-{field}-drift".encode()).hexdigest()
    return SchedulerBindings.build(**values)


def _deep_scheduler_config(config_factory: Any) -> AuditConfig:
    base = config_factory()
    falsifier_model = "golf/gale-secure"
    falsifier_entry = model_registry_entry(falsifier_model)
    registry = [entry.model_dump(mode="json") for entry in base.models.registry]
    registry.append(falsifier_entry)
    return config_factory(
        profile="deep",
        privacy={
            "fail_on_detected_secret": False,
            "approved_model_lineages": sorted({str(entry["root_lineage"]) for entry in registry}),
        },
        models={
            "specialists": {
                "falsifier": {
                    "primary": falsifier_model,
                    "fallbacks": [],
                    "quality_tier": "high",
                    "capabilities": ["structured_json", "security_reasoning"],
                }
            },
            "registry": registry,
        },
    ).effective()


def _deep_scheduler_report_quality_config(config_factory: Any) -> AuditConfig:
    payload = _deep_scheduler_config(config_factory).model_dump(mode="python")
    report_quality_entry = model_registry_entry(_REPORT_QUALITY_MODEL_ID)
    payload["models"]["registry"] = [
        *payload["models"]["registry"],
        report_quality_entry,
    ]
    payload["privacy"]["approved_model_lineages"] = sorted(
        {
            *payload["privacy"]["approved_model_lineages"],
            str(report_quality_entry["root_lineage"]),
        }
    )
    report_quality = dict(payload["models"]["specialists"]["falsifier"])
    report_quality["primary"] = _REPORT_QUALITY_MODEL_ID
    payload["models"]["specialists"]["report_quality"] = report_quality
    configured = AuditConfig.model_validate(payload)
    return AuditConfig.model_validate(configured.effective().model_dump(mode="python"))


def _semantic_scheduler_config(config_factory: Any) -> AuditConfig:
    payload = _deep_scheduler_config(config_factory).model_dump(mode="python")
    payload["language_profile"] = "solidity-evm"
    payload["execution"]["budget_usd"] = 100
    payload["execution"]["max_requests_per_agent"] = 32
    payload["smart_contracts"]["compile"] = False
    payload["reproduction"]["required_for_solidity"] = False
    configured = AuditConfig.model_validate(payload)
    return AuditConfig.model_validate(configured.effective().model_dump(mode="python"))


def _cross_shard_accounting_graphs(
    repository: Path,
    config: AuditConfig,
) -> tuple[Any, Any]:
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index_build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, index_build)
    source = next(
        entity
        for entity in index_build.index.entities
        if entity.contract_name == "Router" and entity.name == "route"
    )
    target = next(
        entity
        for entity in index_build.index.entities
        if entity.contract_name == "Ledger" and entity.name == "record"
    )
    accounting_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.EXTERNAL_CALL,
        source_id=source.id,
        target_id=target.id,
        label="record observed accounting delta",
        provenance=SolidityProvenance.FALLBACK,
        path=source.path,
        start_line=source.start_line,
        end_line=source.end_line,
        source_hash=source.source_hash,
        confidence=0.70,
        transformation="synthetic_local_cross_file_accounting_binding",
        metadata={"resolution": "synthetic_exact_entity_binding"},
    )
    coverage = dict(graphs.coverage)
    coverage[accounting_edge.graph.value] = coverage.get(accounting_edge.graph.value, 0) + 1
    accounting_occurrence = SolidityGraphRetainedOccurrence(
        subject_kind=SolidityGraphOccurrenceKind.EDGE,
        subject_sha256=solidity_graph_occurrence_sha256(
            SolidityGraphOccurrenceKind.EDGE,
            accounting_edge,
        ),
        occurrence_count=1,
    )
    graphs = graphs.model_copy(
        update={
            "edges": [*graphs.edges, accounting_edge],
            "coverage": coverage,
            "retained_occurrences": tuple(
                sorted(
                    (*graphs.retained_occurrences, accounting_occurrence),
                    key=lambda item: (item.subject_kind.value, item.subject_sha256),
                )
            ),
        }
    )
    inventory = build_solidity_shard_inventory(
        discovery,
        index_build.index,
        graphs,
    )
    assert inventory.boundaries
    assert inventory.overlaps
    return graphs, inventory


def _scheduler_outputs(run_dir: Path) -> dict[str, SchedulerTaskOutput]:
    output_dir = run_dir / "private" / "scheduler-journal" / "task-outputs"
    outputs = tuple(
        SchedulerTaskOutput.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(output_dir.glob("*.json"))
    )
    return {output.task_id: output for output in outputs}


def _source_retrieval_task_pairs(
    pass_result: SchedulerPassResult,
) -> tuple[tuple[SchedulerTaskPlan, SchedulerTaskPlan], ...]:
    """Require one exact retrieval-planning child for every source-audit primary."""

    assert pass_result.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    source_primaries = tuple(
        task
        for task in pass_result.plan.tasks
        if task.purpose is SchedulerTaskPurpose.PRIMARY and task.role == "source_audit"
    )
    retrieval_children = tuple(
        task
        for task in pass_result.plan.tasks
        if task.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
    )
    assert source_primaries
    assert len(retrieval_children) == len(source_primaries)
    primary_by_id = {task.task_id: task for task in source_primaries}
    assert {task.parent_task_id for task in retrieval_children} == set(primary_by_id)
    pairs: list[tuple[SchedulerTaskPlan, SchedulerTaskPlan]] = []
    for child in retrieval_children:
        assert child.parent_task_id is not None
        primary = primary_by_id[child.parent_task_id]
        assert child.task_key == f"retrieval-{primary.task_key}"
        assert child.scope == primary.scope
        assert child.role == primary.role
        assert child.requested_model == primary.requested_model
        assert child.root_lineage == primary.root_lineage
        assert child.candidate_ids == primary.candidate_ids
        assert child.model_surface_review_request_manifest_sha256 == (
            primary.model_surface_review_request_manifest_sha256
        )
        pairs.append((primary, child))
    return tuple(pairs)


def _scheduler_activations(run_dir: Path) -> dict[str, SchedulerTaskActivation]:
    activation_dir = run_dir / "private" / "scheduler-journal" / "activations"
    activations = tuple(
        SchedulerTaskActivation.model_validate_json(path.read_text(encoding="utf-8"))
        for path in sorted(activation_dir.glob("*.json"))
    )
    return {activation.task_id: activation for activation in activations}


def _rewrite_public_report_bundle(run_dir: Path, report: AuditReport) -> None:
    """Rewrite every report derivative for a coherent public-artifact tamper assay."""

    retained_findings = FindingsArtifact.model_validate_json(
        (run_dir / "findings.json").read_text(encoding="utf-8")
    )
    candidate_payload = json.loads(
        (run_dir / "candidate-findings.json").read_text(encoding="utf-8")
    )
    candidates = tuple(
        CandidateFinding.model_validate(item) for item in candidate_payload["findings"]
    )
    source_excerpts = {
        record.finding_id: record.source_excerpt
        for record in retained_findings.records
        if record.source_excerpt is not None
    }
    findings_artifact = build_findings_artifact(
        report,
        candidates=candidates,
        reproduction_resolutions=retained_findings.reproduction_resolutions,
        source_excerpts=source_excerpts,
    )
    write_json(run_dir / "final-findings.json", report)
    write_json(run_dir / "findings.json", findings_artifact)
    (run_dir / "client-report.md").write_text(
        render_client_markdown_from_artifact(report, findings_artifact),
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


def _reseal_scheduler_run(
    run_dir: Path,
    manifest: RunEvidenceManifest,
) -> RunEvidenceManifest:
    assert manifest.run_configuration is not None
    return seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )


def _maximum_protocol_overlap_context(
    config_factory: Any,
) -> tuple[ContextBuilder, ModelSurfaceReviewRequest, SolidityGraphEdge, set[str]]:
    repository = FIXTURES / "solidity" / "maximum_assurance_protocol"
    config = config_factory(
        language_profile="solidity-evm",
        repository={"max_total_context_bytes": 5_000_000},
        privacy={"fail_on_detected_secret": False},
    ).effective()
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index_build = build_solidity_index(discovery, projects, [])
    graphs = build_solidity_graphs(discovery, index_build)
    source = next(
        entity
        for entity in index_build.index.entities
        if entity.path == "src/SafeVariants.sol"
        and entity.contract_name == "SafeInflationVault"
        and entity.signature == "deposit(uint256)"
    )
    target = next(
        entity
        for entity in index_build.index.entities
        if entity.path == "src/InflationVault.sol"
        and entity.contract_name == "InflationVault"
        and entity.name == "deposit"
    )
    overlap_edge = SolidityGraphEdge(
        graph=SolidityGraphKind.EXTERNAL_CALL,
        source_id=source.id,
        target_id=target.id,
        label="synthetic exact cross-file deposit dependency",
        provenance=SolidityProvenance.FALLBACK,
        path=source.path,
        start_line=source.start_line,
        end_line=source.end_line,
        source_hash=source.source_hash,
        confidence=0.70,
        transformation="synthetic_local_cross_file_deposit_binding",
        metadata={"resolution": "synthetic_exact_entity_binding"},
    )
    coverage = dict(graphs.coverage)
    coverage[overlap_edge.graph.value] = coverage.get(overlap_edge.graph.value, 0) + 1
    overlap_occurrence = SolidityGraphRetainedOccurrence(
        subject_kind=SolidityGraphOccurrenceKind.EDGE,
        subject_sha256=solidity_graph_occurrence_sha256(
            SolidityGraphOccurrenceKind.EDGE,
            overlap_edge,
        ),
        occurrence_count=1,
    )
    graphs = graphs.model_copy(
        update={
            "edges": [*graphs.edges, overlap_edge],
            "coverage": coverage,
            "retained_occurrences": tuple(
                sorted(
                    (*graphs.retained_occurrences, overlap_occurrence),
                    key=lambda item: (item.subject_kind.value, item.subject_sha256),
                )
            ),
        }
    )
    inventory = build_solidity_shard_inventory(discovery, index_build.index, graphs)
    requests = _cross_shard_overlap_surface_requests(
        inventory,
        graphs,
        index_build.index,
    )
    request = next(
        item
        for item in requests.values()
        if item.allowed_locations[0].path == "src/SafeVariants.sol"
        and "deposit(uint256)" in item.allowed_symbols
    )
    edge = next(
        item for item in graphs.edges if model_review_edge_subject_id(item) == request.subject_id
    )
    paths_by_shard = {shard.shard_id: shard.source_path for shard in inventory.shards}
    overlap_id = next(overlap_id for overlap_id, item in requests.items() if item == request)
    overlap_record = next(item for item in inventory.overlaps if item.overlap_id == overlap_id)
    allowed_paths = {
        paths_by_shard[overlap_record.primary_shard_id],
        paths_by_shard[overlap_record.consumer_shard_id],
    }
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=projects,
        solidity_index=index_build.index,
        solidity_graphs=graphs,
    )
    return builder, request, edge, allowed_paths


def test_pass_four_context_retains_exact_overlap_facts_under_production_budget(
    config_factory: Any,
) -> None:
    builder, request, edge, allowed_paths = _maximum_protocol_overlap_context(config_factory)

    package = builder.build(
        "business_logic",
        requested_budget=111_246,
        requested_model_surfaces=[request],
        allowed_source_paths=allowed_paths,
    )

    assert package.solidity_index is not None
    assert package.solidity_graphs is not None
    assert any(
        model_review_edge_subject_id(item) == request.subject_id
        for item in package.solidity_graphs.edges
    )
    assert {edge.source_id, edge.target_id} <= {node.id for node in package.solidity_graphs.nodes}
    assert edge.source_id in {entity.id for entity in package.solidity_index.entities}
    full_graphs = builder.solidity_graphs
    assert full_graphs is not None
    assert len(package.solidity_graphs.edges) < len(full_graphs.edges)
    assert (
        _surface_review_path(
            request.model_dump(mode="json"),
            entities=[entity.model_dump(mode="json") for entity in package.solidity_index.entities],
            edges=[item.model_dump(mode="json") for item in package.solidity_graphs.edges],
        )
        is not None
    )


def test_pass_four_context_fails_closed_when_exact_overlap_facts_cannot_fit(
    config_factory: Any,
) -> None:
    builder, request, _edge, allowed_paths = _maximum_protocol_overlap_context(config_factory)

    with pytest.raises(ContextBudgetError, match="required model-surface"):
        builder.build(
            "business_logic",
            requested_budget=8_000,
            requested_model_surfaces=[request],
            allowed_source_paths=allowed_paths,
        )


def test_source_audit_call_context_keeps_dependency_facts_without_target_source_leakage(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    config = _semantic_scheduler_config(config_factory)
    repository = tmp_path / "cross-shard-source-audit"
    shutil.copytree(FIXTURES / "solidity" / "cross_shard_accounting" / "unsafe", repository)
    graphs, inventory = _cross_shard_accounting_graphs(repository, config)
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    index_build = build_solidity_index(discovery, projects, [])
    requests = _cross_shard_boundary_surface_requests(
        inventory,
        graphs,
        index_build.index,
    )
    request = next(
        item
        for item in requests.values()
        if "record observed accounting delta" in item.function_or_state_surface
    )
    edge = next(
        item for item in graphs.edges if model_review_edge_subject_id(item) == request.subject_id
    )
    source_file = next(item for item in discovery.files if item.relative_path == edge.path)
    source_request = build_source_file_review_request(
        path=source_file.relative_path,
        size=source_file.size,
        lines=source_file.lines,
        sha256=source_file.sha256,
    )

    package = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        solidity_projects=projects,
        solidity_index=index_build.index,
        solidity_graphs=graphs,
    ).build(
        "source_audit",
        requested_budget=100_000,
        requested_model_surfaces=sorted(
            [source_request, request],
            key=lambda item: item.surface_id,
        ),
        allowed_source_paths={edge.path},
    )

    assert {excerpt.path for excerpt in package.excerpts} == {edge.path}
    assert package.solidity_graphs is not None
    assert package.solidity_index is not None
    assert model_review_edge_subject_id(edge) in {
        model_review_edge_subject_id(item) for item in package.solidity_graphs.edges
    }
    assert {edge.source_id, edge.target_id} <= {node.id for node in package.solidity_graphs.nodes}
    assert {edge.source_id, edge.target_id} <= {
        entity.id for entity in package.solidity_index.entities
    }


def test_scheduler_resume_requires_one_explicit_non_alias_run(tmp_path: Path) -> None:
    output = tmp_path / "output"
    journal = output / "runs" / "run-001" / "private" / "scheduler-journal"
    journal.mkdir(parents=True)

    assert _resolve_scheduler_resume_journal(output, journal.parents[1]) == journal
    with pytest.raises(ValueError, match="latest alias"):
        _resolve_scheduler_resume_journal(output, output / "latest")

    aliased = output / "runs" / "run-alias"
    aliased.symlink_to(journal.parents[1], target_is_directory=True)
    with pytest.raises(ValueError, match="symlinked path component"):
        _resolve_scheduler_resume_journal(output, aliased)

    outside_private = tmp_path / "outside-private"
    (outside_private / "scheduler-journal").mkdir(parents=True)
    private_aliased_run = output / "runs" / "run-private-alias"
    private_aliased_run.mkdir()
    (private_aliased_run / "private").symlink_to(
        outside_private,
        target_is_directory=True,
    )
    with pytest.raises(ValueError, match="private directory"):
        _resolve_scheduler_resume_journal(output, private_aliased_run)


@pytest.mark.asyncio
async def test_scheduler_accepts_default_in_repository_private_output_exclusion(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])

    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        fake,
        output=vulnerable_repo / ".mmaudit",
    )

    assert fake.chat_calls > 0
    assert result.run_dir.parent == vulnerable_repo / ".mmaudit" / "runs"
    assert (
        result.run_dir / "private" / "scheduler-journal" / "analysis-input-inventory.json"
    ).is_file()


@pytest.mark.asyncio
async def test_pipeline_persists_exact_seven_pass_scheduler_evidence(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    observed_runtime: list[AssuranceRuntime] = []
    original_evaluate = MaximumAssuranceContract.evaluate

    def capture_runtime(
        contract: MaximumAssuranceContract,
        runtime: AssuranceRuntime,
    ) -> Any:
        observed_runtime.append(runtime)
        return original_evaluate(contract, runtime)

    monkeypatch.setattr(MaximumAssuranceContract, "evaluate", capture_runtime)

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert artifact.summary.status is SchedulerCampaignStatus.COMPLETE
    private_outputs = _scheduler_outputs(result.run_dir)
    blind_pass = next(
        pass_result
        for pass_result in artifact.summary.pass_results
        if pass_result.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    )
    retrieval_pairs = _source_retrieval_task_pairs(blind_pass)
    blind_results_by_task_id = {item.task_id: item for item in blind_pass.task_results}
    for _primary, child in retrieval_pairs:
        child_result = blind_results_by_task_id[child.task_id]
        if child_result.terminal_status is SchedulerTerminalStatus.SUCCEEDED:
            SolidityRetrievalRequestBatch.model_validate_json(
                json.dumps(private_outputs[child.task_id].payload),
                strict=True,
            )
    candidate_review_tasks = tuple(
        task
        for pass_result in artifact.summary.pass_results
        for task in pass_result.plan.tasks
        if task.purpose is SchedulerTaskPurpose.PRIMARY
        and (
            task.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
            or (
                task.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
                and task.role == "business_logic"
            )
        )
    )
    assert candidate_review_tasks
    for task in candidate_review_tasks:
        output = private_outputs[task.task_id]
        completion = output.model_completion_evidence
        assert completion is not None
        assert completion.schema_version == "1.1"
        assert completion.normalization_evidence is not None
        batch = CandidateReviewBatch.model_validate(output.payload)
        assert (
            completion.normalization_evidence.require_exact_batch(
                batch,
                request_id=task.logical_request_id,
            )
            is completion.normalization_evidence
        )
        assert completion.validated_response_sha256 == (
            completion.normalization_evidence.wire_validated_response_sha256
        )
        assert completion.normalized_output_sha256 == (
            completion.normalization_evidence.normalized_batch_sha256
        )
        assert output.model_surface_review_artifact is not None
        assert output.model_surface_review_artifact.normalization_evidence == (
            completion.normalization_evidence
        )
        assert task.model_surface_review_request_manifest_sha256 == (
            output.model_surface_review_artifact.requested_surface_manifest_sha256
        )
    assert tuple(item.plan.pass_kind for item in artifact.summary.pass_results) == (
        SCHEDULER_PASS_ORDER
    )
    validation_pass = artifact.summary.pass_results[5]
    assert validation_pass.plan.candidate_workset is not None
    expected_candidate_ids = validation_pass.plan.candidate_workset.selected_candidate_ids
    verifier_tasks = tuple(task for task in validation_pass.plan.tasks if task.role == "verifier")
    falsifier_tasks = tuple(
        task for task in validation_pass.plan.tasks if task.role == "candidate_falsifier"
    )
    assert len(verifier_tasks) == 1
    assert len(falsifier_tasks) == 2
    assert all(task.candidate_ids == expected_candidate_ids for task in falsifier_tasks)
    assert len({task.root_lineage for task in falsifier_tasks}) == 2
    assert verifier_tasks[0].root_lineage not in {task.root_lineage for task in falsifier_tasks}
    reproduction_task = next(
        task for task in validation_pass.plan.tasks if task.role == "host:reproduction"
    )
    reproduction_output = SchedulerReproductionHostOutput.model_validate(
        _scheduler_outputs(result.run_dir)[reproduction_task.task_id].payload
    )
    assert reproduction_output.generated_tests is not None
    assert reproduction_output.reproduction_results is not None
    assert reproduction_output.generated_test_ids is None
    assert reproduction_output.reproduction_result_ids is None
    reproduction_artifact = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    assert [item.model_dump(mode="json") for item in reproduction_output.generated_tests] == sorted(
        reproduction_artifact["test_specifications"],
        key=lambda item: (item["candidate_id"], item["name"]),
    )
    assert [
        item.model_dump(mode="json") for item in reproduction_output.reproduction_results
    ] == sorted(
        reproduction_artifact["results"],
        key=lambda item: (item["candidate_id"], item["test_name"]),
    )
    falsifier_requests = tuple(
        request for request in artifact.model_requests if request.role == "candidate_falsifier"
    )
    assert len(falsifier_requests) == 2
    assert all(
        request.reviewed_candidate_ids == expected_candidate_ids for request in falsifier_requests
    )
    scheduled_request_ids = {request.logical_request_id for request in artifact.model_requests}
    emitted_request_ids = {
        str(request["metadata"]["mmaudit_request_id"]) for request in fake.requests
    }
    activated_request_ids = {
        request.logical_request_id
        for request in artifact.model_requests
        if request.activation_status is SchedulerActivationStatus.ACTIVATED
    }
    local_retrieval_failure_ids = {
        request.logical_request_id
        for request in artifact.model_requests
        if request.purpose is SchedulerTaskPurpose.RETRIEVAL_PLANNING
        and request.activation_status is SchedulerActivationStatus.PREFLIGHT_FAILED
    }
    assert emitted_request_ids == activated_request_ids
    assert scheduled_request_ids == emitted_request_ids | local_retrieval_failure_ids
    assert all(request_id.startswith("scheduler-request-") for request_id in emitted_request_ids)
    assert result.report.metadata["scheduler"]["scheduler_artifact_sha256"] == (
        artifact.artifact_sha256
    )
    assert (tmp_path / "output" / "latest" / "scheduler-state.json").read_bytes() == (
        result.run_dir / "scheduler-state.json"
    ).read_bytes()
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    output_snapshot_reads = 0
    pass_result_snapshot_reads = 0
    original_outputs_getter = SchedulerJournal.outputs.fget
    original_pass_results_getter = SchedulerJournal.pass_results.fget
    assert original_outputs_getter is not None
    assert original_pass_results_getter is not None

    def counted_outputs(journal: SchedulerJournal) -> tuple[SchedulerTaskOutput, ...]:
        nonlocal output_snapshot_reads
        output_snapshot_reads += 1
        return original_outputs_getter(journal)

    def counted_pass_results(journal: SchedulerJournal) -> tuple[SchedulerPassResult, ...]:
        nonlocal pass_result_snapshot_reads
        pass_result_snapshot_reads += 1
        return original_pass_results_getter(journal)

    monkeypatch.setattr(SchedulerJournal, "outputs", property(counted_outputs))
    monkeypatch.setattr(SchedulerJournal, "pass_results", property(counted_pass_results))
    reads_before_validation = output_snapshot_reads
    pass_reads_before_validation = pass_result_snapshot_reads
    validate_manifest_artifacts(manifest, result.run_dir)
    assert output_snapshot_reads == reads_before_validation + 1
    assert pass_result_snapshot_reads == pass_reads_before_validation + 1
    assert "scheduler-state.json" in {binding.path for binding in manifest.artifacts}
    assert len(observed_runtime) == 1
    runtime = observed_runtime[0]
    assert runtime.scheduler_artifact == artifact
    assert runtime.expected_scheduler_bindings == artifact.summary.manifest.bindings
    assert runtime.expected_scheduler_shard_inventory == artifact.summary.manifest.shard_inventory
    assert result.report.model_review_coverage is not None
    assert result.report.model_review_coverage.overall.numerator == 0
    assert (
        "mock model usage was excluded from substantive model-review coverage"
        in result.report.model_review_coverage.limitations
    )
    private_review_path = result.run_dir / "private" / "model-review-artifacts.json"
    private_review_bytes = private_review_path.read_bytes()
    private_review_payload = json.loads(private_review_bytes)
    assert private_review_payload["schema_version"] == "1.1"
    private_review_inventory = manifest_module._ModelReviewArtifactInventory.model_validate_json(
        private_review_bytes
    )
    snapshot = manifest_module._SchedulerReportAuthoritySnapshot(
        journal=SimpleNamespace(truncation_recovery_entries=()),
        outputs_by_task_id=private_outputs,
        pass_results_by_kind={
            pass_result.plan.pass_kind: pass_result for pass_result in artifact.summary.pass_results
        },
        tasks_by_task_id={
            task.task_id: task
            for pass_result in artifact.summary.pass_results
            for task in pass_result.plan.tasks
        },
        activations_by_task_id=_scheduler_activations(result.run_dir),
    )
    credited_artifact = private_review_inventory.artifacts[0]
    credited_output = next(
        output
        for output in private_outputs.values()
        if output.model_surface_review_artifact == credited_artifact
    )
    assert credited_output.model_completion_evidence is not None
    credited_usage = credited_output.model_completion_evidence.usage_record
    credited_record = credited_artifact.records[0]
    credited_lineage = model_lineage_index(config)[credited_usage.requested_model.lower()]
    retained_authority = next(
        authority
        for authority in manifest_module._retained_model_surface_review_authorities(snapshot)
        if authority.artifact == credited_artifact
    )
    assert (
        retained_authority.pre_dispatch_requested_surface_manifest_sha256
        == credited_artifact.requested_surface_manifest_sha256
    )
    retained_tasks = dict(snapshot.tasks_by_task_id or {})
    retained_task = retained_tasks[credited_output.task_id]
    retained_tasks[credited_output.task_id] = SimpleNamespace(
        logical_request_id=retained_task.logical_request_id,
        role=retained_task.role,
        model_surface_review_request_manifest_sha256="f" * 64,
    )
    substituted_snapshot = manifest_module._SchedulerReportAuthoritySnapshot(
        journal=snapshot.journal,
        outputs_by_task_id=snapshot.outputs_by_task_id,
        pass_results_by_kind=snapshot.pass_results_by_kind,
        tasks_by_task_id=retained_tasks,
        activations_by_task_id=snapshot.activations_by_task_id,
    )
    substituted_authority = next(
        authority
        for authority in manifest_module._retained_model_surface_review_authorities(
            substituted_snapshot
        )
        if authority.artifact == credited_artifact
    )
    assert (
        "ordinary model review surfaces differed from pre-dispatch scheduler authority"
        in manifest_module._retained_ordinary_model_review_context_failures(
            substituted_authority,
            index=None,
            graphs=None,
        )
    )

    hash_tampered_payload = credited_artifact.model_dump(mode="json")
    hash_tampered_payload["prompt_sha256"] = "f" * 64
    hash_tampered_payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(
        hash_tampered_payload
    )
    hash_tampered_artifact = ModelSurfaceReviewArtifact.model_validate(hash_tampered_payload)
    hash_tampered_inventory = manifest_module._ModelReviewArtifactInventory(
        schema_version="1.0",
        artifacts=tuple(
            hash_tampered_artifact if item == credited_artifact else item
            for item in private_review_inventory.artifacts
        ),
    )
    hash_tampered_outputs = dict(private_outputs)
    hash_tampered_outputs[credited_output.task_id] = credited_output.model_copy(
        update={"model_surface_review_artifact": hash_tampered_artifact}
    )
    hash_tampered_snapshot = manifest_module._SchedulerReportAuthoritySnapshot(
        journal=SimpleNamespace(truncation_recovery_entries=()),
        outputs_by_task_id=hash_tampered_outputs,
        pass_results_by_kind=snapshot.pass_results_by_kind,
    )
    with pytest.raises(
        ValueError,
        match="scheduler model-review artifact differs from its exact retained completion",
    ):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=result.report,
            inventory=hash_tampered_inventory,
            snapshot=hash_tampered_snapshot,
            config=config,
        )

    flipped_reference = ModelReviewEvidenceReference(
        surface_id=credited_record.surface_id,
        request_id=credited_artifact.request_id,
        artifact_sha256=credited_artifact.artifact_sha256,
        requested_model=credited_usage.requested_model,
        model=credited_usage.actual_model,
        review_role=credited_record.review_role,
        status=credited_record.status,
        root_lineage=credited_lineage.root_lineage,
        credited=True,
        reason="Synthetic tamper flips retained MOCK evidence to credited.",
    )
    flipped_surface = ModelReviewSurface(
        surface_id=credited_record.surface_id,
        kind=ModelReviewSurfaceKind.SOURCE_FILE,
        subject_id="synthetic-mock-credit-flip",
        label="Synthetic MOCK credit flip",
        critical=False,
        locations=[],
        evidence_references=[flipped_reference],
    )
    assert not result.report.model_review_coverage.surfaces
    flipped_coverage = result.report.model_review_coverage.model_copy(
        update={"surfaces": [flipped_surface]}
    )
    flipped_report = result.report.model_copy(update={"model_review_coverage": flipped_coverage})
    with pytest.raises(
        ValueError,
        match="credited model-review evidence contradicts exact scheduler artifact custody",
    ):
        manifest_module._validate_model_review_artifact_inventory_against_scheduler(
            report=flipped_report,
            inventory=private_review_inventory,
            snapshot=snapshot,
            config=config,
        )

    assert private_review_payload["artifacts"]
    write_json(
        private_review_path,
        {
            **private_review_payload,
            "artifacts": private_review_payload["artifacts"][1:],
        },
    )
    inventory_tampered_manifest = _reseal_scheduler_run(result.run_dir, manifest)
    with pytest.raises(
        ValueError,
        match="private model-review artifact inventory differs from exact scheduler custody",
    ):
        validate_manifest_artifacts(inventory_tampered_manifest, result.run_dir)
    private_review_path.write_bytes(private_review_bytes)
    model_execution_path = result.run_dir / "model-execution.json"
    model_execution = ModelExecutionArtifact.model_validate_json(
        model_execution_path.read_text(encoding="utf-8")
    )
    assert model_execution.schema_version == "1.2"
    assert isinstance(model_execution.cost_ledger, RunCostLedgerEvidence)
    assert model_execution.cost_ledger.baseline_sha256 == (
        artifact.summary.manifest.cost_ledger_baseline.baseline_sha256
    )
    assert model_execution.cost_ledger.run_entry_count > 0
    assert {
        attempt.logical_request_id
        for attempt in model_execution.cost_ledger.attempts
        if attempt.usage_record_sha256 is not None
    } == {record.request_id for record in result.report.usage}

    coherently_resealed_paths = (
        "candidate-findings.json",
        "findings.json",
        "client-report.md",
        "forensic-report.md",
        "audit-report.md",
        "audit-results.sarif",
    )
    original_public_bytes = {
        name: (result.run_dir / name).read_bytes() for name in coherently_resealed_paths
    }
    candidate_path = result.run_dir / "candidate-findings.json"
    candidate_payload = json.loads(original_public_bytes["candidate-findings.json"])
    assert candidate_payload["findings"]
    candidate_payload["findings"][0]["title"] = "Coherently resealed candidate tamper"
    write_json(candidate_path, candidate_payload)
    tampered_candidates = [
        CandidateFinding.model_validate(candidate) for candidate in candidate_payload["findings"]
    ]
    public_report = AuditReport.model_validate_json(
        (result.run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    original_findings = FindingsArtifact.model_validate_json(original_public_bytes["findings.json"])
    source_excerpts = {
        record.finding_id: record.source_excerpt
        for record in original_findings.records
        if record.source_excerpt is not None
    }
    with pytest.raises(
        ValueError,
        match="forensic consensus review differs from its candidate payload",
    ):
        build_findings_artifact(
            public_report,
            candidates=tampered_candidates,
            reproduction_resolutions=original_findings.reproduction_resolutions,
            source_excerpts=source_excerpts,
        )
    candidate_tampered_manifest = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(result.run_dir),
    )
    reads_before_tamper = output_snapshot_reads
    pass_reads_before_tamper = pass_result_snapshot_reads
    with pytest.raises(
        ValueError,
        match="forensic consensus review differs from its candidate payload",
    ):
        validate_manifest_artifacts(candidate_tampered_manifest, result.run_dir)
    assert output_snapshot_reads == reads_before_tamper
    assert pass_result_snapshot_reads == pass_reads_before_tamper
    for name, payload in original_public_bytes.items():
        (result.run_dir / name).write_bytes(payload)

    tampered_payload = model_execution.model_dump(mode="json")
    cost_payload = tampered_payload["cost_ledger"]
    assert isinstance(cost_payload, dict)
    cost_payload["baseline_sha256"] = "f" * 64
    cost_payload["evidence_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in cost_payload.items() if key != "evidence_sha256"}
    )
    write_json(model_execution_path, tampered_payload)
    tampered_manifest = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(result.run_dir),
    )
    reads_before_cost_tamper = output_snapshot_reads
    pass_reads_before_cost_tamper = pass_result_snapshot_reads
    with pytest.raises(ValueError, match="scheduler baseline"):
        validate_manifest_artifacts(tampered_manifest, result.run_dir)
    assert output_snapshot_reads == reads_before_cost_tamper + 1
    assert pass_result_snapshot_reads == pass_reads_before_cost_tamper + 1


@pytest.mark.asyncio
async def test_current_actor_scheduler_uses_judge_context_without_judge_classification(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    actor_source = FIXTURES / "actor_model" / "synthetic_orchard_actor_model.json"
    actor_path = vulnerable_repo / ".mmaudit" / "operator-actor-model.json"
    raw_actor_model = actor_source.read_bytes()
    actor_path.parent.mkdir(mode=0o700)
    actor_path.write_bytes(raw_actor_model)
    actor_model = json.loads(raw_actor_model)
    scenario_payload = json.loads(
        (FIXTURES / "actor_model" / "synthetic_correction_scenarios.json").read_text(
            encoding="utf-8"
        )
    )
    scenario = next(
        item
        for item in scenario_payload["scenarios"]
        if item["scenario_id"] == "request-cooldown-severity"
    )

    config_payload = _deep_scheduler_config(config_factory).model_dump(mode="python")
    config_payload["actor_model"] = {
        "path": ".mmaudit/operator-actor-model.json",
        "required": True,
        "max_bytes": 1_000_000,
        "expected_subject_id": actor_model["subject_id"],
        "expected_model_sha256": actor_model["artifact_sha256"],
        "expected_source_sha256": hashlib.sha256(raw_actor_model).hexdigest(),
    }
    config = AuditConfig.model_validate(config_payload)
    fake = _CurrentActorJudgmentOpenRouter(
        actor_context=scenario["actor_context"],
        extra_model_ids=["golf/gale-secure"],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    report = result.report
    evaluation = report.actor_model_evaluation
    baseline = report.actor_model_baseline
    assert report.schema_version == "1.4"
    assert evaluation is not None
    assert baseline is not None
    assert evaluation.input_evidence.state is ActorModelInputState.CURRENT
    assert report.judge_decisions
    decisions_by_group = {decision.group_id: decision for decision in report.judge_decisions}
    assert all(decision.status.value == "rejected" for decision in decisions_by_group.values())
    assert all(decision.severity.value == "critical" for decision in decisions_by_group.values())
    assert all(decision.confidence == 0.01 for decision in decisions_by_group.values())

    terminal_findings = (
        *report.findings,
        *report.rejected_findings,
        *report.filtered_findings,
    )
    judged_findings = tuple(
        finding for finding in terminal_findings if finding.group_id in decisions_by_group
    )
    assert judged_findings
    assert {finding.group_id for finding in judged_findings} == set(decisions_by_group)
    baseline_by_id = {record.finding.id: record.finding for record in baseline.findings}
    for finding in judged_findings:
        assert finding.group_id is not None
        decision = decisions_by_group[finding.group_id]
        assessment = finding.actor_assessment
        assert assessment is not None
        assert baseline_by_id[finding.id].severity.value == "high"
        assert assessment.original_severity.value == "high"
        assert finding.severity.value == "medium"
        assert finding.status.value != "rejected"
        assert finding.confidence > decision.confidence
        assert finding.actor_context == decision.actor_context

    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_invalid_candidate_locations_retain_exact_conditional_absence_resolutions(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = _AllInvalidCandidateLocationsOpenRouter(extra_model_ids=["golf/gale-secure"])

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    scheduler_artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    validation_pass = scheduler_artifact.summary.pass_results[5]
    assert validation_pass.plan.pass_kind is (
        SchedulerPassKind.MULTI_LINEAGE_VALIDATION_FALSIFICATION
    )
    assert validation_pass.plan.conditional_absence is not None
    assert validation_pass.plan.conditional_absence.reason is (
        SchedulerAbsenceReason.NO_VALIDATION_CANDIDATES
    )
    assert validation_pass.plan.candidate_workset is not None
    assert validation_pass.plan.candidate_workset.selected_candidate_ids == ()
    assert len(validation_pass.plan.tasks) == 1
    assert validation_pass.plan.tasks[0].task_kind is SchedulerTaskKind.EMPTY_COMPLETION
    assert len(validation_pass.task_results) == 1
    assert validation_pass.task_results[0].terminal_status is (
        SchedulerTerminalStatus.EXPLICIT_EMPTY
    )

    reproduction_payload = json.loads(
        (result.run_dir / "reproduction-results.json").read_text(encoding="utf-8")
    )
    assert reproduction_payload["test_specifications"] == []
    assert reproduction_payload["results"] == []
    candidate_payload = json.loads(
        (result.run_dir / "candidate-findings.json").read_text(encoding="utf-8")
    )
    required_candidate_ids = {
        candidate["candidate_id"]
        for candidate in candidate_payload["findings"]
        if candidate["severity"] in {"high", "critical"}
    }
    assert required_candidate_ids
    assert required_candidate_ids == {
        resolution["candidate_id"] for resolution in reproduction_payload["candidate_resolutions"]
    }
    assert {resolution["kind"] for resolution in reproduction_payload["candidate_resolutions"]} == {
        "inconclusive"
    }

    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)


@pytest.mark.asyncio
async def test_manifest_binds_public_terminal_status_and_achieved_profile_to_private_authority(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    result = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        FakeOpenRouter(extra_model_ids=["golf/gale-secure"]),
    )
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)
    assert manifest.run_configuration is not None
    assert manifest.run_configuration.achieved_profile is None

    authority_path = result.run_dir / "private" / "run-terminal-report-authority.json"
    authority_bytes = authority_path.read_bytes()
    authority = RunTerminalReportAuthority.model_validate_json(authority_bytes)
    assert authority.terminal_exit_code == int(result.exit_code)
    swapped_authority_path = tmp_path / "swapped-terminal-report-authority.json"
    swapped_authority_path.write_text("{}\n", encoding="utf-8")
    original_cost_validation = manifest_module._validate_model_execution_cost_ledger_custody
    swapped = False

    def swap_authority_after_artifact_hash_validation(*args: Any, **kwargs: Any) -> None:
        nonlocal swapped
        original_cost_validation(*args, **kwargs)
        if not swapped:
            swapped = True
            swapped_authority_path.replace(authority_path)

    with monkeypatch.context() as swap_patch:
        swap_patch.setattr(
            manifest_module,
            "_validate_model_execution_cost_ledger_custody",
            swap_authority_after_artifact_hash_validation,
        )
        with pytest.raises(ValueError, match="differs from its sealed binding"):
            validate_manifest_artifacts(manifest, result.run_dir)
    assert swapped
    authority_path.write_bytes(authority_bytes)
    authority_path.chmod(0o600)
    validate_manifest_artifacts(manifest, result.run_dir)

    changed_configuration_payload = manifest.run_configuration.model_dump(mode="json")
    changed_configuration_payload["achieved_profile"] = changed_configuration_payload[
        "requested_profile"
    ]
    changed_configuration_payload["invocation_sha256"] = canonical_sha256(
        {
            "environment_overrides_sha256": changed_configuration_payload[
                "environment_overrides_sha256"
            ],
            "cli_overrides_sha256": changed_configuration_payload["cli_overrides_sha256"],
            "run_options_sha256": changed_configuration_payload["run_options_sha256"],
            "effective_config_sha256": changed_configuration_payload["effective_config_sha256"],
            "requested_profile": changed_configuration_payload["requested_profile"],
            "achieved_profile": changed_configuration_payload["achieved_profile"],
            "requested_language_profile": changed_configuration_payload[
                "requested_language_profile"
            ],
            "achieved_language_profile": changed_configuration_payload["achieved_language_profile"],
            "reduced_language_capability": changed_configuration_payload[
                "reduced_language_capability"
            ],
        }
    )
    changed_configuration = type(manifest.run_configuration).model_validate(
        changed_configuration_payload
    )
    changed_configuration_manifest = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=changed_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(result.run_dir),
        tool_version=manifest.tool_version,
    )
    with pytest.raises(
        ValueError,
        match="run achieved profile differs from private terminal report authority",
    ):
        validate_manifest_artifacts(changed_configuration_manifest, result.run_dir)

    changed_report = AuditReport.model_validate(
        {
            **result.report.model_dump(mode="json"),
            "incomplete_reasons": [
                *result.report.incomplete_reasons,
                "Coherently rewritten public terminal status limitation.",
            ],
        }
    )
    _rewrite_public_report_bundle(result.run_dir, changed_report)
    metadata_path = result.run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(report_status_metadata(changed_report))
    write_json(metadata_path, metadata)
    write_json(result.run_dir / "coverage.json", build_coverage_artifact(changed_report))
    retained_model_execution = ModelExecutionArtifact.model_validate_json(
        (result.run_dir / "model-execution.json").read_text(encoding="utf-8")
    )
    assert isinstance(retained_model_execution.cost_ledger, RunCostLedgerEvidence)
    write_json(
        result.run_dir / "model-execution.json",
        build_model_execution_artifact(
            changed_report,
            cost_ledger_evidence=retained_model_execution.cost_ledger,
            persistent_ledger_configured=True,
        ),
    )
    changed_status = effective_report_status(changed_report)
    changed_coverage_bindings = [
        binding.model_copy(
            update={"sha256": canonical_sha256(changed_status.model_dump(mode="json"))}
        )
        if binding.identifier == "report-status/projection"
        else binding
        for binding in manifest.bindings.coverage
    ]
    changed_bindings = manifest.bindings.model_copy(update={"coverage": changed_coverage_bindings})
    changed_report_manifest = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=changed_bindings,
        artifacts=collect_run_artifacts(result.run_dir),
        tool_version=manifest.tool_version,
    )
    with pytest.raises(
        ValueError,
        match="public report differs from private terminal report authority",
    ):
        validate_manifest_artifacts(changed_report_manifest, result.run_dir)

    authority_path.unlink()
    with pytest.raises(ValueError, match="requires report artifact bindings"):
        seal_run_evidence_manifest(
            run_id=manifest.run_id,
            repository_root_name=manifest.repository_root_name,
            git_commit=manifest.git_commit,
            sources=manifest.sources,
            run_configuration=manifest.run_configuration,
            bindings=changed_bindings,
            artifacts=collect_run_artifacts(result.run_dir),
            tool_version=manifest.tool_version,
        )


@pytest.mark.asyncio
async def test_manifest_rejects_incomplete_terminal_finding_coherent_reseal(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(
        mode="judge_omission",
        extra_model_ids=["golf/gale-secure"],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    scheduler_artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert scheduler_artifact.schema_version == "1.1"
    assert scheduler_artifact.summary.status is SchedulerCampaignStatus.FAILED
    assert result.report.findings
    assert not result.report.completed
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)

    authority_path = (
        result.run_dir / "private" / "scheduler-journal" / "terminal-report-authority.json"
    )
    authority_bytes = authority_path.read_bytes()
    authority_path.unlink()
    missing_authority_manifest = _reseal_scheduler_run(result.run_dir, manifest)
    with pytest.raises(
        ValueError,
        match="scheduler local journal-head checkpoint does not match durable journal evidence",
    ):
        validate_manifest_artifacts(missing_authority_manifest, result.run_dir)
    authority_path.write_bytes(authority_bytes)
    authority_path.chmod(0o600)
    validate_manifest_artifacts(manifest, result.run_dir)

    first = result.report.findings[0]
    tampered = first.model_copy(update={"title": "Coherently resealed terminal tamper"})
    tampered_report = result.report.model_copy(
        update={"findings": [tampered, *result.report.findings[1:]]}
    )
    _rewrite_public_report_bundle(result.run_dir, tampered_report)
    resealed = _reseal_scheduler_run(result.run_dir, manifest)

    with pytest.raises(
        ValueError,
        match="public finding partition differs from scheduler terminal authority",
    ):
        validate_manifest_artifacts(resealed, result.run_dir)


@pytest.mark.asyncio
async def test_manifest_rejects_incomplete_after_pass_five_cross_exam_coherent_reseal(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(
        mode="verifier_omission",
        extra_model_ids=["golf/gale-secure"],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    scheduler_artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert scheduler_artifact.summary.status is SchedulerCampaignStatus.FAILED
    assert scheduler_artifact.summary.pass_results[-1].plan.pass_kind is SCHEDULER_PASS_ORDER[5]
    assert result.report.cross_examination_decisions
    assert not result.report.completed
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)

    first = result.report.cross_examination_decisions[0]
    changed = first.model_copy(
        update={"rationale": "Coherently resealed incomplete pass-five decision."}
    )
    tampered_report = result.report.model_copy(
        update={
            "cross_examination_decisions": [
                changed,
                *result.report.cross_examination_decisions[1:],
            ]
        }
    )
    _rewrite_public_report_bundle(result.run_dir, tampered_report)
    cross_examination_payload = json.loads(
        (result.run_dir / "cross-examination.json").read_text(encoding="utf-8")
    )
    cross_examination_payload["decisions"] = [
        item.model_dump(mode="json") for item in tampered_report.cross_examination_decisions
    ]
    write_json(result.run_dir / "cross-examination.json", cross_examination_payload)
    resealed = _reseal_scheduler_run(result.run_dir, manifest)

    with pytest.raises(
        ValueError,
        match="public cross-examination evidence differs from scheduler terminal authority",
    ):
        validate_manifest_artifacts(resealed, result.run_dir)


@pytest.mark.asyncio
async def test_report_rejects_incomplete_pass_six_verification_consensus_mismatch(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(
        mode="judge_omission",
        extra_model_ids=["golf/gale-secure"],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    scheduler_artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert scheduler_artifact.summary.status is SchedulerCampaignStatus.FAILED
    assert scheduler_artifact.summary.pass_results[-1].plan.pass_kind is SCHEDULER_PASS_ORDER[6]
    assert result.report.verification_decisions
    assert not result.report.completed
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)

    first = result.report.verification_decisions[0]
    changed = first.model_copy(
        update={"rationale": "Coherently resealed incomplete pass-six decision."}
    )
    tampered_report = result.report.model_copy(
        update={
            "verification_decisions": [
                changed,
                *result.report.verification_decisions[1:],
            ]
        }
    )
    with pytest.raises(
        ValueError,
        match="report verification decisions differ from consensus review",
    ):
        _rewrite_public_report_bundle(result.run_dir, tampered_report)


@pytest.mark.asyncio
async def test_manifest_rejects_non_null_report_quality_coherent_reseal(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_report_quality_config(config_factory)
    fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure", _REPORT_QUALITY_MODEL_ID])

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    review = result.report.report_quality_review
    assert review is not None
    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)
    tampered_review = review.model_copy(
        update={"rationale": "Coherently resealed report-quality tamper."}
    )
    tampered_report = result.report.model_copy(update={"report_quality_review": tampered_review})
    _rewrite_public_report_bundle(result.run_dir, tampered_report)
    resealed = _reseal_scheduler_run(result.run_dir, manifest)

    with pytest.raises(
        ValueError,
        match="public report quality differs from scheduler terminal authority",
    ):
        validate_manifest_artifacts(resealed, result.run_dir)


@pytest.mark.asyncio
async def test_partial_report_quality_failure_replays_retained_terminal_judgment(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_report_quality_config(config_factory)
    fake = FakeOpenRouter(
        mode="timeout",
        role="report_quality_review",
        extra_model_ids=["golf/gale-secure", _REPORT_QUALITY_MODEL_ID],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert not result.report.completed
    assert result.report.report_quality_review is None
    scheduler_artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    pass_seven = scheduler_artifact.summary.pass_results[-1]
    assert pass_seven.plan.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
    results_by_task_id = {item.task_id: item for item in pass_seven.task_results}
    judgment_task = next(
        task for task in pass_seven.plan.tasks if task.role == "host:evidence_cap_judgment"
    )
    report_quality_task = next(
        task for task in pass_seven.plan.tasks if task.role == "specialist:report_quality"
    )
    assert (
        results_by_task_id[judgment_task.task_id].terminal_status
        is SchedulerTerminalStatus.SUCCEEDED
    )
    assert (
        results_by_task_id[report_quality_task.task_id].terminal_status
        is SchedulerTerminalStatus.FAILED
    )

    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)

    replay_calls = 0
    original_replay = manifest_module._validate_scheduler_terminal_finding_replay

    def counted_replay(**kwargs: Any) -> None:
        nonlocal replay_calls
        replay_calls += 1
        original_replay(**kwargs)

    monkeypatch.setattr(
        manifest_module,
        "_validate_scheduler_terminal_finding_replay",
        counted_replay,
    )
    validate_manifest_artifacts(manifest, result.run_dir)
    assert replay_calls == 1


@pytest.mark.asyncio
async def test_manifest_rejects_retained_judge_drift_after_report_quality_failure(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_report_quality_config(config_factory)
    fake = FakeOpenRouter(
        mode="timeout",
        role="report_quality_review",
        extra_model_ids=["golf/gale-secure", _REPORT_QUALITY_MODEL_ID],
    )

    class _MismatchedJudgeBinding:
        @staticmethod
        def build(
            *,
            kind: Any,
            subject_id: str,
            payload: Any,
        ) -> SchedulerEvidencePayloadBinding:
            exact = SchedulerEvidencePayloadBinding.build(
                kind=kind,
                subject_id=subject_id,
                payload=payload,
            )
            if kind != "judge":
                return exact
            altered_payload_sha256 = scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.synthetic-mismatched-judge-binding.v1",
                    "exact_payload_sha256": exact.payload_sha256,
                }
            )
            return SchedulerEvidencePayloadBinding(
                record_id=scheduler_canonical_sha256(
                    {
                        "kind": kind,
                        "subject_id": subject_id,
                        "payload_sha256": altered_payload_sha256,
                    }
                ),
                subject_id=subject_id,
                payload_sha256=altered_payload_sha256,
            )

    monkeypatch.setattr(
        pipeline_module,
        "SchedulerEvidencePayloadBinding",
        _MismatchedJudgeBinding,
    )

    with pytest.raises(
        ValueError,
        match="scheduler judgment differs from exact retained judge decisions",
    ):
        await _run(config, vulnerable_repo, tmp_path, fake)

    run_dir = _only_scheduler_run(tmp_path / "output")
    pass_seven = SchedulerPassResult.model_validate_json(
        (
            run_dir / "private" / "scheduler-journal" / "pass-results" / "pass-07-result.json"
        ).read_text(encoding="utf-8")
    )
    assert pass_seven.plan.pass_kind is SchedulerPassKind.EVIDENCE_CAPPED_JUDGMENT
    assert pass_seven.status is SchedulerPassStatus.FAILED
    results_by_task_id = {result.task_id: result for result in pass_seven.task_results}
    host_task = next(
        task for task in pass_seven.plan.tasks if task.role == "host:evidence_cap_judgment"
    )
    report_quality_task = next(
        task for task in pass_seven.plan.tasks if task.role == "specialist:report_quality"
    )
    assert (
        results_by_task_id[host_task.task_id].terminal_status is SchedulerTerminalStatus.SUCCEEDED
    )
    assert (
        results_by_task_id[report_quality_task.task_id].terminal_status
        is SchedulerTerminalStatus.FAILED
    )


@pytest.mark.asyncio
async def test_pipeline_resumes_exact_completed_campaign_without_provider_replay(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    control = tmp_path / "operator-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    first_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    first = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        first_fake,
        cost_ledger=ledger,
    )
    assert first_fake.chat_calls > 0
    ledger_before_resume = ledger.snapshot()
    stable_artifacts = (
        "candidate-findings.json",
        "model-review-coverage.json",
        "scheduler-state.json",
    )
    first_artifact_bytes = {name: (first.run_dir / name).read_bytes() for name in stable_artifacts}
    first_artifact_sha256s = {
        name: hashlib.sha256(payload).hexdigest() for name, payload in first_artifact_bytes.items()
    }
    first_context = load_context_manifest(first.run_dir / "context-manifest.json")
    first_scheduler = SchedulerArtifact.model_validate_json(
        first_artifact_bytes["scheduler-state.json"]
    )
    first_blind_pass = next(
        pass_result
        for pass_result in first_scheduler.summary.pass_results
        if pass_result.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    )
    _source_retrieval_task_pairs(first_blind_pass)

    descriptor_mismatches: list[tuple[str, ...]] = []
    original_resume = PipelineScheduler.resume.__func__

    def capture_resume_inventory(
        cls: type[PipelineScheduler],
        path: Path,
        **kwargs: Any,
    ) -> PipelineScheduler:
        retained = SchedulerAnalysisInputInventory.model_validate_json(
            (path / "analysis-input-inventory.json").read_text(encoding="utf-8")
        )
        current = kwargs["analysis_input_inventory"]
        retained_by_label = {item.label: item for item in retained.descriptors}
        current_by_label = {item.label: item for item in current.descriptors}
        descriptor_mismatches.append(
            tuple(
                label
                for label in sorted(retained_by_label)
                if retained_by_label[label] != current_by_label[label]
            )
        )
        return original_resume(cls, path, **kwargs)

    monkeypatch.setattr(PipelineScheduler, "resume", classmethod(capture_resume_inventory))
    resumed_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=first.run_dir,
    )

    assert descriptor_mismatches == [()]
    assert resumed_fake.chat_calls == 0
    assert not any(
        _request_schema_name(request) == "mmaudit_solidity_retrieval_request_batch"
        for request in resumed_fake.requests
    )
    assert ledger.snapshot() == ledger_before_resume
    assert resumed.report.findings == first.report.findings
    assert resumed.report.usage == first.report.usage
    assert resumed.report.model_review_coverage == first.report.model_review_coverage
    assert resumed.report.metadata["scheduler"] == first.report.metadata["scheduler"]
    resumed_artifact_bytes = {
        name: (resumed.run_dir / name).read_bytes() for name in stable_artifacts
    }
    assert resumed_artifact_bytes == first_artifact_bytes
    assert {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in resumed_artifact_bytes.items()
    } == first_artifact_sha256s
    resumed_scheduler = SchedulerArtifact.model_validate_json(
        resumed_artifact_bytes["scheduler-state.json"]
    )
    assert resumed_scheduler == first_scheduler
    assert resumed_scheduler.artifact_sha256 == first_scheduler.artifact_sha256
    resumed_context = load_context_manifest(resumed.run_dir / "context-manifest.json")
    assert resumed_context.run_id != first_context.run_id
    assert resumed_context.requests == first_context.requests
    assert resumed_context.totals == first_context.totals
    assert tuple(item.evidence_sha256 for item in resumed_context.requests) == tuple(
        item.evidence_sha256 for item in first_context.requests
    )
    assert resumed.run_dir != first.run_dir
    assert not (resumed.run_dir / "private" / "scheduler-journal").exists()
    retained_reference = SchedulerRetainedJournalReference.model_validate_json(
        (resumed.run_dir / "private" / "scheduler-journal-reference.json").read_text(
            encoding="utf-8"
        )
    )
    retained_reference.require_exact(
        owner_run_id=first.run_dir.name,
        consumer_run_id=resumed.run_dir.name,
        artifact=resumed_scheduler,
    )
    resumed_manifest = RunEvidenceManifest.model_validate_json(
        (resumed.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(resumed_manifest, resumed.run_dir)


@pytest.mark.asyncio
async def test_scheduler_resume_privacy_evidence_rejects_atomic_path_replacement(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    first = await _run(config, vulnerable_repo, tmp_path, fake)
    current_provenance = PrivacySourceProvenanceEvidence.model_validate(
        first.report.privacy["source_provenance"]
    )
    current_policy = EffectivePrivacyPolicyEvidence.model_validate(
        first.report.privacy["effective_policy"]
    )
    scheduler_journal = first.run_dir / "private" / "scheduler-journal"
    retained = _load_exact_resume_privacy_evidence(
        scheduler_journal,
        current_provenance=current_provenance,
        current_policy=current_policy,
    )
    assert retained == (current_provenance, current_policy)

    provenance_path = first.run_dir / "privacy-source-provenance.json"
    original_validate = PrivacySourceProvenanceEvidence.model_validate
    replaced = False

    def replace_after_descriptor_read(
        cls: type[PrivacySourceProvenanceEvidence],
        value: Any,
        *args: Any,
        **kwargs: Any,
    ) -> PrivacySourceProvenanceEvidence:
        nonlocal replaced
        if not replaced:
            replaced = True
            replacement = provenance_path.with_name(".privacy-source-provenance.swap")
            replacement.write_bytes(provenance_path.read_bytes())
            os.replace(replacement, provenance_path)
        return original_validate(value, *args, **kwargs)

    monkeypatch.setattr(
        PrivacySourceProvenanceEvidence,
        "model_validate",
        classmethod(replace_after_descriptor_read),
    )

    with pytest.raises(
        pipeline_module.OpenRouterPrivacyError,
        match="manifest-bound validation",
    ):
        _load_exact_resume_privacy_evidence(
            scheduler_journal,
            current_provenance=current_provenance,
            current_policy=current_policy,
        )
    assert replaced


@pytest.mark.asyncio
async def test_partial_scheduler_resume_privacy_rejects_atomic_path_replacement(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    output = tmp_path / "partial-privacy-replacement-output"
    control = tmp_path / "partial-privacy-replacement-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    owner_run, fake = await _create_activated_scheduler_campaign(
        config=config,
        repository=vulnerable_repo,
        tmp_path=tmp_path,
        output=output,
        ledger=ledger,
        monkeypatch=monkeypatch,
    )
    assert not (owner_run / "run-evidence-manifest.json").exists()
    provenance_path = owner_run / "privacy-source-provenance.json"
    policy_path = owner_run / "privacy-policy.json"
    current_provenance = PrivacySourceProvenanceEvidence.model_validate_json(
        provenance_path.read_text(encoding="utf-8")
    )
    current_policy = EffectivePrivacyPolicyEvidence.model_validate_json(
        policy_path.read_text(encoding="utf-8")
    )
    original_validate = PrivacySourceProvenanceEvidence.model_validate
    replaced = False

    def replace_after_descriptor_read(
        cls: type[PrivacySourceProvenanceEvidence],
        value: Any,
        *args: Any,
        **kwargs: Any,
    ) -> PrivacySourceProvenanceEvidence:
        nonlocal replaced
        if not replaced:
            replaced = True
            replacement = provenance_path.with_name(".privacy-source-provenance.partial-swap")
            replacement.write_bytes(provenance_path.read_bytes())
            os.replace(replacement, provenance_path)
        return original_validate(value, *args, **kwargs)

    monkeypatch.setattr(
        PrivacySourceProvenanceEvidence,
        "model_validate",
        classmethod(replace_after_descriptor_read),
    )

    with pytest.raises(
        pipeline_module.OpenRouterPrivacyError,
        match="manifest-bound validation",
    ):
        _load_exact_resume_privacy_evidence(
            owner_run / "private" / "scheduler-journal",
            current_provenance=current_provenance,
            current_policy=current_policy,
        )
    assert replaced
    assert fake.chat_calls == 0


@pytest.mark.asyncio
async def test_partial_scheduler_resume_privacy_rejects_valid_rehashed_tamper(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    output = tmp_path / "partial-privacy-tamper-output"
    control = tmp_path / "partial-privacy-tamper-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    owner_run, fake = await _create_activated_scheduler_campaign(
        config=config,
        repository=vulnerable_repo,
        tmp_path=tmp_path,
        output=output,
        ledger=ledger,
        monkeypatch=monkeypatch,
    )
    provenance_path = owner_run / "privacy-source-provenance.json"
    policy_path = owner_run / "privacy-policy.json"
    current_provenance = PrivacySourceProvenanceEvidence.model_validate_json(
        provenance_path.read_text(encoding="utf-8")
    )
    current_policy = EffectivePrivacyPolicyEvidence.model_validate_json(
        policy_path.read_text(encoding="utf-8")
    )
    provenance_payload = current_provenance.model_dump(mode="python")
    provenance_payload["observed_at"] = current_provenance.observed_at - timedelta(seconds=1)
    provisional_provenance = PrivacySourceProvenanceEvidence.model_construct(**provenance_payload)
    provenance_payload["evidence_sha256"] = canonical_sha256(
        provisional_provenance.model_dump(mode="json", exclude={"evidence_sha256"})
    )
    tampered_provenance = PrivacySourceProvenanceEvidence.model_validate(provenance_payload)
    policy_payload = current_policy.model_dump(mode="python")
    policy_payload["source_provenance_sha256"] = tampered_provenance.evidence_sha256
    provisional_policy = EffectivePrivacyPolicyEvidence.model_construct(**policy_payload)
    policy_payload["evidence_sha256"] = canonical_sha256(
        provisional_policy.model_dump(mode="json", exclude={"evidence_sha256"})
    )
    tampered_policy = EffectivePrivacyPolicyEvidence.model_validate(policy_payload)
    provenance_path.write_text(
        json.dumps(tampered_provenance.model_dump(mode="json"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
    policy_path.write_text(
        json.dumps(tampered_policy.model_dump(mode="json"), sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        pipeline_module.OpenRouterPrivacyError,
        match="manifest-bound validation",
    ):
        _load_exact_resume_privacy_evidence(
            owner_run / "private" / "scheduler-journal",
            current_provenance=current_provenance,
            current_policy=current_policy,
        )
    assert fake.chat_calls == 0


@pytest.mark.asyncio
async def test_pipeline_resumes_activated_request_after_pre_dispatch_crash_once(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    output = tmp_path / "pre-dispatch-output"
    control = tmp_path / "pre-dispatch-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    first_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    original_dispatched = PipelineScheduler.request_dispatched
    crash_observed = False

    def crash_before_dispatch(
        scheduler: PipelineScheduler,
        *,
        logical_request_id: str,
    ) -> None:
        nonlocal crash_observed
        if not crash_observed:
            crash_observed = True
            raise _SyntheticSchedulerCrash
        original_dispatched(scheduler, logical_request_id=logical_request_id)

    monkeypatch.setattr(PipelineScheduler, "request_dispatched", crash_before_dispatch)
    with pytest.raises(_SyntheticSchedulerCrash):
        await _run(
            config,
            vulnerable_repo,
            tmp_path,
            first_fake,
            cost_ledger=ledger,
            output=output,
        )
    owner_run = _only_scheduler_run(output)
    reserved = ledger.snapshot()
    assert crash_observed
    assert first_fake.chat_calls == 0
    assert len(reserved.entries) == 1
    assert reserved.entries[0].status is CostEntryStatus.RESERVED
    assert reserved.active_reserved_usd == reserved.entries[0].reserved_usd
    initial_reservation = reserved.entries[0]

    monkeypatch.setattr(PipelineScheduler, "request_dispatched", original_dispatched)
    resumed_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=owner_run,
        output=output,
    )

    assert resumed_fake.chat_calls > 0
    artifact = SchedulerArtifact.model_validate_json(
        (resumed.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    orientation = artifact.summary.pass_results[0]
    assert orientation.task_results[0].terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert all(
        result.terminal_status is not SchedulerTerminalStatus.UNCERTAIN
        for pass_result in artifact.summary.pass_results
        for result in pass_result.task_results
    )
    orientation_request_id = orientation.plan.tasks[0].logical_request_id
    assert (
        sum(
            request.logical_request_id == orientation_request_id
            for request in artifact.model_requests
        )
        == 1
    )
    assert orientation_request_id == initial_reservation.request_id
    assert (
        sum(
            (request.get("metadata") or {}).get("mmaudit_request_id") == orientation_request_id
            for request in resumed_fake.requests
        )
        == 1
    )
    terminal_ledger = ledger.snapshot()
    assert terminal_ledger.active_reserved_usd == 0
    assert len({entry.request_id for entry in terminal_ledger.entries}) == len(
        terminal_ledger.entries
    )
    resumed_orientation_entry = next(
        entry for entry in terminal_ledger.entries if entry.request_id == orientation_request_id
    )
    assert resumed_orientation_entry.reservation_id == initial_reservation.reservation_id
    assert resumed_orientation_entry.reserved_usd == initial_reservation.reserved_usd
    assert resumed_orientation_entry.status is CostEntryStatus.RECONCILED


@pytest.mark.asyncio
async def test_pipeline_marks_dispatched_crash_uncertain_and_never_retries(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    output = tmp_path / "dispatched-output"
    control = tmp_path / "dispatched-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    first_fake = _CrashAfterDispatchOpenRouter(extra_model_ids=["golf/gale-secure"])
    with pytest.raises(_SyntheticSchedulerCrash):
        await _run(
            config,
            vulnerable_repo,
            tmp_path,
            first_fake,
            cost_ledger=ledger,
            output=output,
        )
    owner_run = _only_scheduler_run(output)
    reserved = ledger.snapshot()
    assert first_fake.chat_calls == 1
    assert len(reserved.entries) == 1
    assert reserved.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert reserved.active_reserved_usd == 0
    assert reserved.spent_usd == reserved.entries[0].reserved_usd

    resumed_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    resumed = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        cost_ledger=ledger,
        resume_run_dir=owner_run,
        output=output,
    )

    assert resumed_fake.chat_calls == 0
    artifact = SchedulerArtifact.model_validate_json(
        (resumed.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert artifact.summary.status is SchedulerCampaignStatus.INCOMPLETE
    assert len(artifact.summary.pass_results) == 1
    orientation = artifact.summary.pass_results[0]
    assert orientation.task_results[0].terminal_status is SchedulerTerminalStatus.UNCERTAIN
    orientation_request_id = orientation.plan.tasks[0].logical_request_id
    accounted = ledger.snapshot()
    assert accounted.active_reserved_usd == 0
    assert len(accounted.entries) == 1
    assert accounted.entries[0].request_id == orientation_request_id
    assert accounted.entries[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    assert accounted.spent_usd == accounted.entries[0].reserved_usd
    expected_exact_cost = format(accounted.entries[0].accounted_cost_usd, "f")
    assert resumed.report.accounted_cost_usd_exact == expected_exact_cost
    assert resumed.report.accounted_cost_usd == float(accounted.entries[0].accounted_cost_usd)
    model_execution = ModelExecutionArtifact.model_validate_json(
        (resumed.run_dir / "model-execution.json").read_text(encoding="utf-8")
    )
    assert model_execution.accounted_cost_usd_exact == expected_exact_cost
    assert isinstance(model_execution.cost_ledger, RunCostLedgerEvidence)
    assert model_execution.cost_ledger.run_accounted_cost_usd_exact == expected_exact_cost
    assert model_execution.usage == []

    second_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    second_resume = await _run(
        config,
        vulnerable_repo,
        tmp_path,
        second_fake,
        cost_ledger=ledger,
        resume_run_dir=owner_run,
        output=output,
    )
    assert second_fake.chat_calls == 0
    assert ledger.snapshot() == accounted
    second_artifact = SchedulerArtifact.model_validate_json(
        (second_resume.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert second_artifact == artifact


@pytest.mark.parametrize(
    "drift_kind",
    ["source", "config", "tool", "model", "analysis", "journal", "ledger"],
)
@pytest.mark.asyncio
async def test_pipeline_resume_rejects_drift_before_provider_transport(
    drift_kind: str,
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    output = tmp_path / f"{drift_kind}-drift-output"
    control = tmp_path / f"{drift_kind}-drift-control"
    control.mkdir(mode=0o700)
    ledger = AtomicCostLedger.initialize(
        (control / "model-cost-ledger.json").resolve(),
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    owner_run, _first_fake = await _create_activated_scheduler_campaign(
        config=config,
        repository=vulnerable_repo,
        tmp_path=tmp_path,
        output=output,
        ledger=ledger,
        monkeypatch=monkeypatch,
    )
    resume_config = config
    resume_ledger = ledger
    scanner_runner: StaticScannerRunner | None = None

    if drift_kind == "source":
        source = vulnerable_repo / "app.py"
        source.write_text(
            source.read_text(encoding="utf-8") + "\n# Synthetic local resume drift.\n",
            encoding="utf-8",
        )
    elif drift_kind == "config":
        payload = config.model_dump(mode="python")
        payload["execution"]["concurrency"] = 1 if config.execution.concurrency != 1 else 2
        resume_config = AuditConfig.model_validate(payload).effective()
    elif drift_kind == "tool":
        original_build_bindings = pipeline_module.build_scheduler_bindings

        def drifted_tool_binding(**kwargs: Any) -> SchedulerBindings:
            return _scheduler_binding_with_drift(
                original_build_bindings(**kwargs),
                field="tool_policy_sha256",
            )

        monkeypatch.setattr(
            pipeline_module,
            "build_scheduler_bindings",
            drifted_tool_binding,
        )
    elif drift_kind == "model":
        payload = config.model_dump(mode="python")
        replacement = config.models.source_audit.primary
        assert replacement != config.models.threat_model.primary
        payload["models"]["threat_model"]["primary"] = replacement
        payload["models"]["threat_model"]["fallbacks"] = []
        resume_config = AuditConfig.model_validate(payload).effective()
    elif drift_kind == "analysis":
        scanner_runner = StaticScannerRunner(scanner_name="codeql")
    elif drift_kind == "journal":
        extra = owner_run / "private" / "scheduler-journal" / "events" / "unmanifested.json"
        extra.write_text("{}\n", encoding="utf-8")
        extra.chmod(0o600)
    else:
        replacement_control = tmp_path / "replacement-ledger-control"
        replacement_control.mkdir(mode=0o700)
        resume_ledger = AtomicCostLedger.initialize(
            (replacement_control / "model-cost-ledger.json").resolve(),
            cap_usd=Decimal(str(config.execution.budget_usd)),
        )

    resumed_fake = FakeOpenRouter(extra_model_ids=["golf/gale-secure"])
    resumed = await _run(
        resume_config,
        vulnerable_repo,
        tmp_path,
        resumed_fake,
        scanner_runner=scanner_runner,
        cost_ledger=resume_ledger,
        resume_run_dir=owner_run,
        output=output,
    )

    assert resumed_fake.chat_calls == 0
    assert resumed.report.incomplete_reasons
    expected_failure = (
        "privacy authorization failed"
        if drift_kind in {"source", "model"}
        else "seven-pass scheduler preflight failed"
    )
    assert any(expected_failure in reason for reason in resumed.report.incomplete_reasons)


@pytest.mark.asyncio
async def test_maximum_scheduler_executes_four_blind_whole_protocol_reviews(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "provider_smoke"
    shutil.copytree(FIXTURES / "solidity" / "provider_smoke", repo)
    specialists = _maximum_specialists()
    base_registry = [
        entry.model_dump(mode="json")
        for entry in config_factory(language_profile="solidity-evm").models.registry
    ]
    specialist_registry = [model_registry_entry(slot["primary"]) for slot in specialists.values()]
    registry = [*base_registry, *specialist_registry]
    config = config_factory(
        profile="maximum-assurance",
        language_profile="solidity-evm",
        privacy={
            "fail_on_detected_secret": False,
            "approved_model_lineages": sorted({str(entry["root_lineage"]) for entry in registry}),
        },
        repository={"max_total_context_bytes": 5_000_000},
        maximum_assurance={"allow_downgrade": True},
        models={"specialists": specialists, "registry": registry},
        smart_contracts={"allow_fork_probing": True},
        reproduction={
            "targets": {"ProviderSmoke": "0x2000000000000000000000000000000000000002"},
            "pinned_block_number": 123456,
            "expected_chain_id": 31337,
        },
    ).effective()
    fake = FakeOpenRouter(
        mode="maximum_assurance",
        extra_model_ids=[slot.primary for slot in config.models.specialists.values()],
        context_length=300_000,
        max_prompt_tokens=280_000,
        max_completion_tokens=65_536,
    )
    qualification = synthetic_production_qualification(
        config,
        datetime.now(UTC).replace(microsecond=0),
        provider_endpoint="synthetic-provider",
    )

    result = await _run(
        config,
        repo,
        tmp_path,
        fake,
        allow_fork_probing=True,
        production_qualification=qualification,
    )

    scheduler = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    blind_pass = scheduler.summary.pass_results[1]
    retrieval_pairs = _source_retrieval_task_pairs(blind_pass)
    retrieval_children = tuple(child for _primary, child in retrieval_pairs)
    retrieval_requests = tuple(
        request
        for request in fake.requests
        if _request_schema_name(request) == "mmaudit_solidity_retrieval_request_batch"
    )
    private_outputs = _scheduler_outputs(result.run_dir)
    results_by_task_id = {item.task_id: item for item in blind_pass.task_results}
    successful_children = {
        child.task_id
        for child in retrieval_children
        if results_by_task_id[child.task_id].terminal_status is SchedulerTerminalStatus.SUCCEEDED
    }
    assert {str(request["metadata"]["mmaudit_request_id"]) for request in retrieval_requests} == {
        child.logical_request_id
        for child in retrieval_children
        if child.task_id in successful_children
    }
    role_budget = blind_pass.plan.retrieval_role_budget_plans[0]
    assert role_budget.role == "source_audit"
    assert {allocation.primary_task_id for allocation in role_budget.allocations} == {
        primary.task_id for primary, _child in retrieval_pairs
    }
    assert role_budget.allocated_maximum_requests == 4
    assert role_budget.allocated_maximum_total_result_utf8_bytes == 16_384
    assert role_budget.allocated_maximum_total_result_tokens == 5_462
    for child in retrieval_children:
        child_result = results_by_task_id[child.task_id]
        if child.task_id not in successful_children:
            assert child_result.terminal_status is SchedulerTerminalStatus.FAILED
            assert child_result.result_origin.value == "LOCAL_PREFLIGHT"
            assert child.task_id not in private_outputs
            continue
        output = private_outputs[child.task_id]
        assert SolidityRetrievalRequestBatch.model_validate_json(
            json.dumps(output.payload),
            strict=True,
        ) == SolidityRetrievalRequestBatch(requests=())
        assert output.model_surface_review_requests == ()
        assert output.model_surface_review_artifact is None
        assert output.reviewed_source_descriptor_sha256s == ()
        assert output.reviewed_candidate_ids == ()
        assert output.accepted_candidates == ()
        assert output.normalization_evidence is None
    whole_tasks = tuple(
        task for task in blind_pass.plan.tasks if task.role.startswith("whole_protocol_review:")
    )
    assert len(whole_tasks) == 4
    assert len({task.requested_model for task in whole_tasks}) == 4
    assert len({task.root_lineage for task in whole_tasks}) == 4
    assert all(task.scope.kind.value == "GLOBAL" for task in whole_tasks)
    whole_results = {
        result.task_id: result
        for result in blind_pass.task_results
        if result.task_id in {task.task_id for task in whole_tasks}
    }
    assert set(whole_results) == {task.task_id for task in whole_tasks}
    assert all(result.terminal_status.value == "SUCCEEDED" for result in whole_results.values())

    source_path = "src/ProviderSmoke.sol"
    source = (repo / source_path).read_bytes()
    source_sha256 = hashlib.sha256(source).hexdigest()
    source_request = build_source_file_review_request(
        path=source_path,
        size=len(source),
        lines=len(source.decode("utf-8").splitlines(keepends=True)),
        sha256=source_sha256,
    )
    source_descriptor = next(
        descriptor
        for shard in scheduler.summary.manifest.shard_inventory.shards
        for descriptor in shard.sources
        if descriptor.path == source_path
    )
    whole_requests = tuple(
        request
        for request in scheduler.model_requests
        if request.role.startswith("whole_protocol_review:")
    )
    assert len(whole_requests) == 4
    assert all(
        request.reviewed_source_descriptor_sha256s == (source_descriptor.source_descriptor_sha256,)
        for request in whole_requests
    )
    review_payload = json.loads(
        (result.run_dir / "private/model-review-artifacts.json").read_text(encoding="utf-8")
    )
    whole_artifacts = tuple(
        ModelSurfaceReviewArtifact.model_validate(item)
        for item in review_payload["artifacts"]
        if str(item["review_role"]).startswith("whole_protocol_review:")
    )
    assert len(whole_artifacts) == 4
    assert len({artifact.review_role for artifact in whole_artifacts}) == 4
    assert all(
        artifact.requested_surface_ids == (source_request.surface_id,)
        and len(artifact.records) == 1
        and artifact.records[0].citation.location is not None
        and artifact.records[0].citation.location.path == source_path
        and artifact.records[0].citation.location.content_hash == source_sha256
        for artifact in whole_artifacts
    )


@pytest.mark.asyncio
async def test_failed_retrieval_primary_keeps_private_transcript_and_public_hashes(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "failed-retrieval-primary"
    shutil.copytree(FIXTURES / "solidity" / "provider_smoke", repository)
    config_payload = _semantic_scheduler_config(config_factory).model_dump(mode="python")
    config_payload["repository"]["max_total_context_bytes"] = 5_000_000
    config = AuditConfig.model_validate(config_payload).effective()
    monkeypatch.setattr(
        pipeline_module,
        "solidity_retrieval_context_reserve_bytes",
        lambda _policy: 0,
    )
    fake = _InvalidSourcePrimaryOpenRouter(
        extra_model_ids=["golf/gale-secure"],
    )
    result = await _run(
        config,
        repository,
        tmp_path,
        fake,
    )

    scheduler = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    blind_pass = next(
        item
        for item in scheduler.summary.pass_results
        if item.plan.pass_kind is SchedulerPassKind.BLIND_SHARD_REVIEW
    )
    primary, planner = _source_retrieval_task_pairs(blind_pass)[0]
    results = {item.task_id: item for item in blind_pass.task_results}
    failed = results[primary.task_id]
    public_request = next(
        item for item in scheduler.model_requests if item.task_id == primary.task_id
    )
    private_binding_path = next(
        (result.run_dir / "private" / "scheduler-journal" / "retrieval-bindings").glob(
            f"{primary.task_id}-*.json"
        )
    )
    private_binding = json.loads(private_binding_path.read_text(encoding="utf-8"))

    assert results[planner.task_id].terminal_status is SchedulerTerminalStatus.SUCCEEDED
    assert failed.terminal_status in {
        SchedulerTerminalStatus.INVALID,
        SchedulerTerminalStatus.FAILED,
    }
    assert failed.output_artifact_sha256 is None
    assert failed.retrieval_custody is not None
    assert public_request.retrieval_custody == failed.retrieval_custody
    assert (
        private_binding["transcript"]["transcript_sha256"]
        == failed.retrieval_custody.transcript_sha256
    )
    assert len(private_binding["transcript"]["exchanges"]) == 1
    assert len(failed.retrieval_custody.request_sha256s) == 1
    assert len(failed.retrieval_custody.result_sha256s) == 1
    assert len(failed.retrieval_custody.exchange_sha256s) == 1
    primary_requests = tuple(
        request
        for request in fake.requests
        if (request.get("metadata") or {}).get("mmaudit_request_id") == primary.logical_request_id
    )
    assert len(primary_requests) == 1
    assert primary.task_id not in _scheduler_outputs(result.run_dir)
    assert '"exchanges"' not in json.dumps(public_request.model_dump(mode="json"))


@pytest.mark.asyncio
async def test_pass_four_model_discovery_distinguishes_unsafe_and_safe_cross_shard_accounting(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    config = _semantic_scheduler_config(config_factory)
    observations: dict[str, tuple[Any, SchedulerArtifact, dict[str, SchedulerTaskOutput]]] = {}
    for variant in ("unsafe", "safe"):
        source = FIXTURES / "solidity" / "cross_shard_accounting" / variant
        repository = tmp_path / f"cross-shard-{variant}"
        shutil.copytree(source, repository)
        graphs, inventory = _cross_shard_accounting_graphs(repository, config)
        monkeypatch.setattr(
            "mmaudit.orchestration.pipeline.build_solidity_graphs",
            lambda _discovery, _index_build, exact=graphs, **_kwargs: exact,
        )
        fake = FakeOpenRouter(
            mode="semantic_accounting",
            extra_model_ids=["golf/gale-secure"],
        )
        run_root = tmp_path / f"run-{variant}"
        run_root.mkdir(mode=0o700)
        result = await _run(
            config,
            repository,
            run_root,
            fake,
        )
        artifact = SchedulerArtifact.model_validate_json(
            (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
        )
        assert artifact.summary.status is SchedulerCampaignStatus.COMPLETE
        observations[variant] = (
            inventory,
            artifact,
            _scheduler_outputs(result.run_dir),
        )

    for inventory, artifact, outputs in observations.values():
        pass_four = artifact.summary.pass_results[3]
        expected_relationship_ids = {
            *(boundary.boundary_id for boundary in inventory.boundaries),
            *(overlap.overlap_id for overlap in inventory.overlaps),
        }
        relationship_tasks = {
            task.task_key.removeprefix("boundary-review-").removeprefix("overlap-review-"): task
            for task in pass_four.plan.tasks
            if task.task_key.startswith(("boundary-review-", "overlap-review-"))
        }
        assert set(relationship_tasks) == expected_relationship_ids
        assert all(task.task_id in outputs for task in relationship_tasks.values())
        assert all(
            result.terminal_status.value == "SUCCEEDED"
            for result in pass_four.task_results
            if result.task_id in {task.task_id for task in relationship_tasks.values()}
        )

    unsafe_inventory, unsafe_artifact, unsafe_outputs = observations["unsafe"]
    safe_inventory, safe_artifact, safe_outputs = observations["safe"]
    assert len(unsafe_inventory.boundaries) == len(safe_inventory.boundaries)
    assert len(unsafe_inventory.overlaps) == len(safe_inventory.overlaps)

    unsafe_pass_three = unsafe_artifact.summary.pass_results[2]
    safe_pass_three = safe_artifact.summary.pass_results[2]
    unsafe_reduction = unsafe_outputs[unsafe_pass_three.plan.tasks[0].task_id].payload
    safe_reduction = safe_outputs[safe_pass_three.plan.tasks[0].task_id].payload
    assert unsafe_reduction["candidate_ids"] == []
    assert safe_reduction["candidate_ids"] == []

    unsafe_pass_four = unsafe_artifact.summary.pass_results[3]
    safe_pass_four = safe_artifact.summary.pass_results[3]
    unsafe_host = next(
        task for task in unsafe_pass_four.plan.tasks if task.role == "host:cross_shard_integrator"
    )
    safe_host = next(
        task for task in safe_pass_four.plan.tasks if task.role == "host:cross_shard_integrator"
    )
    unsafe_host_payload = unsafe_outputs[unsafe_host.task_id].payload
    safe_host_payload = safe_outputs[safe_host.task_id].payload
    assert unsafe_host_payload["candidate_ids"]
    assert safe_host_payload["candidate_ids"] == []
    assert unsafe_host_payload != safe_host_payload

    unsafe_model_payloads = [
        unsafe_outputs[task.task_id].payload
        for task in unsafe_pass_four.plan.tasks
        if task.task_key.startswith(("boundary-review-", "overlap-review-"))
    ]
    safe_model_payloads = [
        safe_outputs[task.task_id].payload
        for task in safe_pass_four.plan.tasks
        if task.task_key.startswith(("boundary-review-", "overlap-review-"))
    ]
    assert all(payload["findings"] for payload in unsafe_model_payloads)
    assert all(payload["findings"] == [] for payload in safe_model_payloads)

    unsafe_workset = unsafe_artifact.summary.pass_results[4].plan.candidate_workset
    safe_workset = safe_artifact.summary.pass_results[4].plan.candidate_workset
    assert unsafe_workset is not None
    assert safe_workset is not None
    assert unsafe_workset.candidate_ids
    assert safe_workset.candidate_ids == ()
    assert unsafe_workset.workset_sha256 != safe_workset.workset_sha256


@pytest.mark.asyncio
async def test_failed_mandatory_scheduler_pass_stops_later_provider_calls(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(
        mode="timeout",
        role="threat_model",
        extra_model_ids=["golf/gale-secure"],
    )
    observed_runtime: list[AssuranceRuntime] = []
    original_evaluate = MaximumAssuranceContract.evaluate

    def capture_runtime(
        contract: MaximumAssuranceContract,
        runtime: AssuranceRuntime,
    ) -> Any:
        observed_runtime.append(runtime)
        return original_evaluate(contract, runtime)

    monkeypatch.setattr(MaximumAssuranceContract, "evaluate", capture_runtime)

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert artifact.summary.status is SchedulerCampaignStatus.FAILED
    assert len(artifact.summary.pass_results) == 1
    assert artifact.summary.pass_results[0].plan.pass_kind is SCHEDULER_PASS_ORDER[0]
    assert fake.chat_calls == 1
    assert {record.role for record in result.report.usage} == {"threat_model"}
    assert artifact.journal_evidence.provider_attempt_count == 1
    provider_attempts = tuple(
        (result.run_dir / "private" / "scheduler-journal" / "provider-attempts").glob("*.json")
    )
    assert len(provider_attempts) == 1
    provider_attempt = json.loads(provider_attempts[0].read_text(encoding="utf-8"))
    assert artifact.journal_evidence.provider_attempt_evidence_sha256s == (
        provider_attempt["attempt_evidence_sha256"],
    )
    assert provider_attempt["usage_record"]["request_id"] == (
        artifact.summary.pass_results[0].plan.tasks[0].logical_request_id
    )
    assert len(observed_runtime) == 1
    assert {record.request_id for record in observed_runtime[0].model_usage} == {
        provider_attempt["usage_record"]["request_id"]
    }
    assert "threat_model" not in observed_runtime[0].model_roles_completed
    assert not result.report.completed


@pytest.mark.asyncio
async def test_scheduler_bound_primary_failure_never_routes_to_configured_fallback(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
) -> None:
    base = _deep_scheduler_config(config_factory)
    fallback_model = "hotel/harbor-secure"
    payload = base.model_dump(mode="python")
    payload["models"]["registry"] = [
        *payload["models"]["registry"],
        model_registry_entry(fallback_model),
    ]
    payload["privacy"]["approved_model_lineages"] = sorted(
        {
            *(str(item) for item in payload["privacy"]["approved_model_lineages"]),
            str(payload["models"]["registry"][-1]["root_lineage"]),
        }
    )
    payload["models"]["threat_model"]["fallbacks"] = [fallback_model]
    config = AuditConfig.model_validate(payload).effective()
    fake = FakeOpenRouter(
        mode="timeout",
        role="threat_model",
        extra_model_ids=["golf/gale-secure", fallback_model],
    )

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    assert fake.chat_calls == 1
    assert {str(request["model"]) for request in fake.requests} == {
        config.models.threat_model.primary
    }
    artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert artifact.summary.status is SchedulerCampaignStatus.FAILED


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "failed_pass"),
    [
        ("verifier_omission", SCHEDULER_PASS_ORDER[5]),
        ("judge_omission", SCHEDULER_PASS_ORDER[6]),
    ],
)
async def test_omitted_scheduled_decisions_fail_their_mandatory_pass(
    config_factory: Any,
    vulnerable_repo: Path,
    tmp_path: Path,
    mode: str,
    failed_pass: Any,
) -> None:
    config = _deep_scheduler_config(config_factory)
    fake = FakeOpenRouter(mode=mode, extra_model_ids=["golf/gale-secure"])

    result = await _run(config, vulnerable_repo, tmp_path, fake)

    artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    assert artifact.summary.status is SchedulerCampaignStatus.FAILED
    failed = artifact.summary.pass_results[-1]
    assert failed.plan.pass_kind is failed_pass
    assert failed.status.value == "FAILED"
    assert not result.report.completed


def _cross_file_candidate(
    candidate_factory: Any,
    *,
    source_path: str,
    target_path: str,
    candidate_id: str,
) -> CandidateFinding:
    candidate = candidate_factory(candidate_id=candidate_id, path=source_path)
    return CandidateFinding.model_validate(
        candidate.model_copy(
            update={
                "locations": [
                    Location(path=source_path, start_line=1, end_line=1),
                    Location(path=target_path, start_line=1, end_line=1),
                ],
                "source": SourceSink(
                    description="synthetic source-side state transition",
                    path=source_path,
                    line=1,
                ),
                "sink": SourceSink(
                    description="synthetic target-side accounting transition",
                    path=target_path,
                    line=1,
                ),
            }
        ).model_dump(mode="python")
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _boundary_artifact(
    request: ModelSurfaceReviewRequest,
    *,
    status: ModelSurfaceReviewStatus,
) -> ModelSurfaceReviewArtifact:
    citation = ModelSurfaceReviewCitation(
        location=request.allowed_locations[0] if request.allowed_locations else None,
        symbol=None if request.allowed_locations else request.allowed_symbols[0],
    )
    record = ModelSurfaceReviewRecord(
        surface_id=request.surface_id,
        contract=request.contract,
        function_or_state_surface=request.function_or_state_surface,
        review_role="business_logic",
        status=status,
        rationale="Synthetic local boundary evidence reaches an explicit safe disposition.",
        citation=citation,
        invariant_considered=request.invariant_considered,
        evidence_observations=(
            ModelSurfaceReviewEvidenceObservation(
                citation=citation,
                observed_behavior="The exact local boundary call updates the typed target state.",
                security_relevance="Authorization and accounting integrity are checked at the boundary.",
            ),
        ),
        reachability=ModelSurfaceReviewReachability(
            entry_point=citation,
            path=(citation,),
            actor_or_caller="synthetic local caller",
            preconditions=(),
        ),
        assumptions=(),
        confidence=1,
    )
    requested_ids = (request.surface_id,)
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "request_id": f"synthetic-boundary-{request.surface_id[-16:]}",
        "review_role": "business_logic",
        "requested_surface_ids": requested_ids,
        "requested_surface_ids_sha256": _canonical_sha256(list(requested_ids)),
        "requested_surface_manifest_sha256": (
            ModelSurfaceReviewArtifact.calculate_requested_surface_manifest_sha256((request,))
        ),
        "rendered_context_sha256": "1" * 64,
        "prompt_sha256": "2" * 64,
        "response_sha256": "3" * 64,
        "validated_response_sha256": "4" * 64,
        "response_schema_sha256": "5" * 64,
        "records": [record.model_dump(mode="json")],
    }
    payload["artifact_sha256"] = ModelSurfaceReviewArtifact.calculate_artifact_sha256(payload)
    return ModelSurfaceReviewArtifact.model_validate(payload)


def test_deterministic_reduction_partitions_exact_inventory_and_rejects_metadata_noop(
    candidate_factory: Any,
) -> None:
    first = candidate_factory(candidate_id="blind-one")
    second = candidate_factory(candidate_id="blind-two")
    candidates = [first, second]
    validations = {
        candidate.candidate_id: LocationValidation(valid=True) for candidate in candidates
    }

    reduction = _build_deterministic_finding_reduction(
        candidates,
        validations,
        blind_candidate_ids={"blind-one", "blind-two"},
        execution_candidate_ids=set(),
    )
    _validate_deterministic_finding_reduction(
        reduction,
        expected_candidate_ids={"blind-one", "blind-two"},
    )
    assert len(reduction["groups"]) == 1
    assert reduction["canonical_candidate_ids"] == ["blind-one"]

    with pytest.raises(ValueError, match="exact typed projection"):
        _validate_deterministic_finding_reduction(
            {"candidate_ids": ["blind-one", "blind-two"]},
            expected_candidate_ids={"blind-one", "blind-two"},
        )


def test_finding_reduction_activation_binds_pending_and_formal_candidate_payloads(
    candidate_factory: Any,
) -> None:
    blind = candidate_factory(candidate_id="blind-candidate")
    execution = candidate_factory(
        candidate_id="execution-candidate",
        path="config.py",
        start_line=3,
        end_line=3,
    )
    unverified_formal_run = FormalToolRun(
        tool="synthetic-formal",
        status=FormalToolStatus.SUCCESS,
        evidence=[
            FormalEvidence(
                tool="synthetic-formal",
                property_id="synthetic-accounting-property",
                property_description="Observed accounting must equal the committed delta.",
                status=FormalToolStatus.SUCCESS,
                result_kind=FormalResultKind.COUNTEREXAMPLE,
                counterexample={"observed_delta": 0, "committed_delta": 1},
                locations=[Location(path="config.py", start_line=3, end_line=3)],
                confidence=1,
            )
        ],
    )
    unverified_candidates = _attach_formal_counterexamples(
        [blind, execution],
        [unverified_formal_run],
    )
    assert all(
        evidence.type != "formal"
        for candidate in unverified_candidates
        for evidence in candidate.evidence
    )

    formal_run = _qualifying_synthetic_formal_run(
        property_id="synthetic-accounting-property",
        property_description="Observed accounting must equal the committed delta.",
        counterexample={"observed_delta": 0, "committed_delta": 1},
        location=Location(path="config.py", start_line=3, end_line=3),
    )
    candidates = _attach_formal_counterexamples([blind, execution], [formal_run])
    activation_input = _finding_reduction_activation_input(
        candidates,
        blind_candidate_ids={blind.candidate_id},
        execution_candidate_ids={execution.candidate_id},
    )
    validations = {
        candidate.candidate_id: LocationValidation(valid=True) for candidate in candidates
    }
    reduction = _build_deterministic_finding_reduction(
        candidates,
        validations,
        blind_candidate_ids={blind.candidate_id},
        execution_candidate_ids={execution.candidate_id},
    )

    assert activation_input == {
        "blind_candidate_ids": reduction["blind_candidate_ids"],
        "execution_candidate_ids": reduction["execution_candidate_ids"],
        "candidate_payload_sha256s": reduction["candidate_payload_sha256s"],
    }
    bound_execution = next(
        candidate for candidate in candidates if candidate.candidate_id == execution.candidate_id
    )
    assert any(
        item.type == "formal" and item.source == "synthetic-formal"
        for item in bound_execution.evidence
    )
    _validate_deterministic_finding_reduction(
        reduction,
        expected_candidate_ids={blind.candidate_id, execution.candidate_id},
    )


@pytest.mark.asyncio
async def test_pipeline_activates_pass_three_after_overlapping_formal_evidence_is_bound(
    config_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    repository = tmp_path / "formal-ordering"
    shutil.copytree(FIXTURES / "solidity" / "foundry", repository)
    config_payload = _deep_scheduler_config(config_factory).model_dump(mode="python")
    config_payload["language_profile"] = "solidity-evm"
    config_payload["smart_contracts"]["compile"] = False
    config_payload["formal"]["enabled"] = True
    config_payload["reproduction"]["required_for_solidity"] = False
    config = AuditConfig.model_validate(config_payload).effective()

    class OverlappingFormalRunner:
        def run(self, **_kwargs: Any) -> list[FormalToolRun]:
            return [
                _qualifying_synthetic_formal_run(
                    property_id="synthetic-withdrawal-property",
                    property_description="Withdrawal authorization must be preserved.",
                    counterexample={"authorized": False},
                    location=Location(path="src/Vault.sol", start_line=20, end_line=22),
                )
            ]

    attachment_projections: list[tuple[dict[str, str], dict[str, str]]] = []
    formally_bound_candidate_ids: set[str] = set()
    original_attach = pipeline_module._attach_formal_counterexamples

    def capture_attachment(
        candidates: list[CandidateFinding],
        formal_runs: list[FormalToolRun],
    ) -> list[CandidateFinding]:
        before = _candidate_payload_sha256s(candidates)
        attached = original_attach(candidates, formal_runs)
        formally_bound_candidate_ids.update(
            candidate.candidate_id
            for candidate in attached
            if any(
                evidence.type == "formal" and evidence.source == "synthetic-formal"
                for evidence in candidate.evidence
            )
        )
        attachment_projections.append((before, _candidate_payload_sha256s(attached)))
        return attached

    monkeypatch.setattr(pipeline_module, "_attach_formal_counterexamples", capture_attachment)
    result = await _run(
        config,
        repository,
        tmp_path,
        FakeOpenRouter(mode="solidity_reproduction", extra_model_ids=["golf/gale-secure"]),
        formal_runner=OverlappingFormalRunner(),
    )

    artifact = SchedulerArtifact.model_validate_json(
        (result.run_dir / "scheduler-state.json").read_text(encoding="utf-8")
    )
    reduction_pass = next(
        item
        for item in artifact.summary.pass_results
        if item.plan.pass_kind is SchedulerPassKind.FINDING_REDUCTION
    )
    assert reduction_pass.status.value == "COMPLETE"
    reduction_task = reduction_pass.plan.tasks[0]
    journal = result.run_dir / "private" / "scheduler-journal"
    activation_path = next((journal / "activations").glob(f"{reduction_task.task_id}-*.json"))
    output_path = next((journal / "task-outputs").glob(f"{reduction_task.task_id}-*.json"))
    activation = SchedulerTaskActivation.model_validate_json(
        activation_path.read_text(encoding="utf-8")
    )
    output = SchedulerTaskOutput.model_validate_json(output_path.read_text(encoding="utf-8"))
    assert isinstance(output.payload, dict)
    fixed_input = {
        "blind_candidate_ids": output.payload["blind_candidate_ids"],
        "execution_candidate_ids": output.payload["execution_candidate_ids"],
        "candidate_payload_sha256s": output.payload["candidate_payload_sha256s"],
    }
    assert scheduler_canonical_sha256(fixed_input) == activation.actual_input_sha256

    before, after = next(
        (before, after) for before, after in attachment_projections if before != after
    )
    old_order_input = {**fixed_input, "candidate_payload_sha256s": before}
    assert formally_bound_candidate_ids
    assert formally_bound_candidate_ids <= set(output.payload["candidate_payload_sha256s"])
    assert after == output.payload["candidate_payload_sha256s"]
    assert scheduler_canonical_sha256(old_order_input) != activation.actual_input_sha256

    manifest = RunEvidenceManifest.model_validate_json(
        (result.run_dir / "run-evidence-manifest.json").read_text(encoding="utf-8")
    )
    validate_manifest_artifacts(manifest, result.run_dir)

    def invent_non_formal_candidate_change(
        candidates: list[CandidateFinding],
        formal_runs: list[FormalToolRun],
    ) -> list[CandidateFinding]:
        attached = original_attach(candidates, formal_runs)
        return [
            candidate.model_copy(update={"title": f"{candidate.title} (invented change)"})
            for candidate in attached
        ]

    monkeypatch.setattr(
        pipeline_module,
        "_attach_formal_counterexamples",
        invent_non_formal_candidate_change,
    )
    tampered_root = tmp_path / "tampered-formal-authority"
    tampered_root.mkdir(mode=0o700)
    with pytest.raises(
        ValueError,
        match="scheduler pass-three differs from accepted blind candidates",
    ):
        await _run(
            config,
            repository,
            tampered_root,
            FakeOpenRouter(
                mode="solidity_reproduction",
                extra_model_ids=["golf/gale-secure"],
            ),
            formal_runner=OverlappingFormalRunner(),
        )


def test_cross_shard_integration_distinguishes_unsafe_and_safe_boundary_evidence(
    config_factory: Any,
    candidate_factory: Any,
    tmp_path: Path,
) -> None:
    inputs = _shard_inputs(tmp_path, config_factory)
    inventory = _inventory(inputs)
    assert inventory.boundaries
    boundary = inventory.boundaries[0]
    paths_by_shard = {shard.shard_id: shard.source_path for shard in inventory.shards}
    source_path = paths_by_shard[boundary.source_shard_id]
    target_path = paths_by_shard[boundary.target_shard_id]
    unsafe = _cross_file_candidate(
        candidate_factory,
        source_path=source_path,
        target_path=target_path,
        candidate_id="unsafe-cross-boundary",
    )
    safe = candidate_factory(candidate_id="safe-single-shard", path=source_path)
    boundary_requests = _cross_shard_boundary_surface_requests(
        inventory,
        inputs.graphs,
        inputs.index,
    )
    overlap_requests = _cross_shard_overlap_surface_requests(
        inventory,
        inputs.graphs,
        inputs.index,
    )
    unsafe_boundary_id = boundary.boundary_id
    unsafe_artifacts = {
        boundary_id: _boundary_artifact(
            request,
            status=(
                ModelSurfaceReviewStatus.CANDIDATE
                if boundary_id == unsafe_boundary_id
                else ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE
            ),
        )
        for boundary_id, request in boundary_requests.items()
    }
    safe_artifacts = {
        boundary_id: _boundary_artifact(
            request,
            status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        )
        for boundary_id, request in boundary_requests.items()
    }
    overlap_artifacts = {
        overlap_id: _boundary_artifact(
            request,
            status=ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        )
        for overlap_id, request in overlap_requests.items()
    }

    unsafe_output = _build_cross_shard_integration(
        inventory,
        [unsafe],
        {unsafe.candidate_id: LocationValidation(valid=True)},
        shard_ids=tuple(shard.shard_id for shard in inventory.shards),
        invariant_review=None,
        boundary_surface_requests=boundary_requests,
        boundary_review_artifacts=unsafe_artifacts,
        boundary_candidate_ids={
            boundary_id: ({unsafe.candidate_id} if boundary_id == unsafe_boundary_id else set())
            for boundary_id in boundary_requests
        },
        overlap_surface_requests=overlap_requests,
        overlap_review_artifacts=overlap_artifacts,
        overlap_candidate_ids={overlap_id: set() for overlap_id in overlap_requests},
    )
    safe_output = _build_cross_shard_integration(
        inventory,
        [safe],
        {safe.candidate_id: LocationValidation(valid=True)},
        shard_ids=tuple(shard.shard_id for shard in inventory.shards),
        invariant_review=None,
        boundary_surface_requests=boundary_requests,
        boundary_review_artifacts=safe_artifacts,
        boundary_candidate_ids={boundary_id: set() for boundary_id in boundary_requests},
        overlap_surface_requests=overlap_requests,
        overlap_review_artifacts=overlap_artifacts,
        overlap_candidate_ids={overlap_id: set() for overlap_id in overlap_requests},
    )
    relationship_ids = {item.boundary_id for item in inventory.boundaries} | {
        item.overlap_id for item in inventory.overlaps
    }
    _validate_cross_shard_integration(
        unsafe_output,
        expected_candidate_ids={unsafe.candidate_id},
        expected_relationship_ids=relationship_ids,
    )
    _validate_cross_shard_integration(
        safe_output,
        expected_candidate_ids={safe.candidate_id},
        expected_relationship_ids=relationship_ids,
    )
    unsafe_linked = {
        candidate_id
        for decision in unsafe_output["decisions"]
        for candidate_id in decision["linked_candidate_ids"]
    }
    safe_linked = {
        candidate_id
        for decision in safe_output["decisions"]
        for candidate_id in decision["linked_candidate_ids"]
    }
    assert unsafe.candidate_id in unsafe_linked
    assert safe.candidate_id not in safe_linked

    with pytest.raises(ValueError, match="exact typed projection"):
        _validate_cross_shard_integration(
            {
                "candidate_ids": [unsafe.candidate_id],
                "shard_ids": sorted(paths_by_shard),
            },
            expected_candidate_ids={unsafe.candidate_id},
            expected_relationship_ids=relationship_ids,
        )


def test_semantic_blind_context_includes_exact_overlap_and_boundary_paths(
    config_factory: Any,
    tmp_path: Path,
) -> None:
    inventory = _inventory(_shard_inputs(tmp_path, config_factory))
    boundary = inventory.boundaries[0]
    paths_by_shard = {shard.shard_id: shard.source_path for shard in inventory.shards}

    observed = _semantic_shard_context_paths(
        inventory,
        shard_id=boundary.source_shard_id,
        primary_paths={paths_by_shard[boundary.source_shard_id]},
    )

    assert paths_by_shard[boundary.source_shard_id] in observed
    assert paths_by_shard[boundary.target_shard_id] in observed
