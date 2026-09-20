"""Emit original synthetic run projections, with absent engines kept explicitly absent."""

from typing import Any

from pydantic import BaseModel, TypeAdapter

from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import LanguageCapabilityArtifact, LanguageCapabilityFileEvidence
from mmaudit.orchestration import manifest
from mmaudit.orchestration.context_manifest import (
    ContextManifestReportBinding,
    build_context_manifest,
)
from mmaudit.reporting.bundle import (
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
    build_run_cost_ledger_evidence,
)
from mmaudit.reporting.client import (
    build_client_source_excerpts,
    render_client_markdown_from_artifact,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import report_status_metadata
from mmaudit.repository.ignore import DEFAULT_EXCLUSIONS
from mmaudit.solidity.taxonomy import load_known_issue_taxonomy
from tests.report_authority_fixtures import write_run_terminal_report_authority


def write_original_run_artifacts(config: Any, fixture: Any, report: Any) -> Any:
    """Use the original source, outputs and ledger; never fill gaps with invented engines."""

    root = fixture.privacy.run_directory
    source = fixture.source
    state = fixture.candidate_report
    public = fixture.journal.artifact()
    accounting = fixture.run_accounting
    assert accounting is not None and not accounting.pending
    assert not report.completed and not report.scanner_runs and not report.reproductions
    context = build_context_manifest(
        run_id=report.run_id,
        usage_records=report.usage,
        recovery_request_limit_coordinates=tuple(
            (
                request.logical_request_id,
                request.request_limit_scope,
                request.request_limit_count_before,
            )
            for request in public.recovery_model_requests
        ),
    )
    report = report.model_copy(
        update={
            "metadata": report.metadata
            | {
                "context_manifest": ContextManifestReportBinding.build(context).model_dump(
                    mode="json"
                ),
            }
        }
    )
    cost = build_run_cost_ledger_evidence(
        baseline=accounting.baseline,
        final_snapshot=accounting.ledger.snapshot(),
        campaign_logical_request_ids=tuple(
            r.logical_request_id for r in (*public.model_requests, *public.recovery_model_requests)
        ),
        usage_records=report.usage,
        campaign_id=public.summary.manifest.campaign_id,
        campaign_manifest_sha256=public.summary.manifest.manifest_sha256,
    )
    qualification = ModelRegistry.validate_production_qualification(
        config, fixture.authorities.qualification, now=fixture.authorities.qualification.verified_at
    )
    assert qualification.valid, qualification.errors
    projection = fixture.projection
    promoted = manifest._PromotedModelReviewArtifactInventory(
        schema_version="1.2",
        promotions=(
            manifest._FullTreePromotedModelReviewArtifact(
                promotion_entry_sha256=projection.promotion_entry_sha256,
                recovered_output_artifact_sha256=projection.recovered_output_artifact_sha256,
                recursive_tree=True,
                full_tree=True,
                artifact=projection.artifact,
            ),
        ),
    )
    language = LanguageCapabilityArtifact(
        assessment=report.language_capability,
        files=tuple(
            LanguageCapabilityFileEvidence(
                path=item.path,
                sha256=item.sha256,
                size=item.size,
                lines=item.lines,
                language=item.language,
            )
            for item in report.repository.files
        ),
        omitted=tuple(report.repository.omitted_files),
        effective_ignore_rules=DEFAULT_EXCLUSIONS,
        runtime_output_exclusion_root=None,
    )
    payloads: dict[str, Any] = {
        "report.json": report,
        "final-findings.json": report,
        "context-manifest.json": context,
        "scheduler-state.json": public,
        "model-qualification-runtime.json": qualification.as_dict(),
        "audit-model-selection-evidence.json": fixture.authorities.evidence_bundle,
        "audit-model-refresh-evidence.json": fixture.runtime.audit_model_refresh_evidence,
        "audit-model-refresh-pricing-evidence.json": fixture.runtime.audit_model_refresh_pricing_evidence,
        "language-capability.json": language,
        "solidity-projects.json": {"schema_version": "1.0", "projects": source.index.projects},
        "solidity-index.json": {"schema_version": "1.0", "index": source.index},
        "solidity-graphs.json": {"schema_version": "1.0", "graphs": source.graphs},
        "solidity-shards.json": {"schema_version": "1.0", "inventory": source.semantic_shards},
        "solidity-compilation.json": {
            "schema_version": "1.0",
            "results": source.analysis_arguments["compilations"],
        },
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": source.analysis_arguments["invariant_harnesses"],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": source.analysis_arguments["property_corpus"],
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "harnesses": [],
            "results": report.invariant_executions,
        },
        "formal-results.json": {
            "schema_version": "1.0",
            "runs": report.formal_runs,
            "dynamic_engine_comparisons": [],
        },
        "solidity-invariants.json": {"schema_version": "1.0", "invariants": source.invariants},
        "invariant-review.json": {"schema_version": "1.0", "review": report.invariant_review},
        "economic-simulation-plan.json": {
            "schema_version": "1.0",
            "templates": report.economic_simulations,
        },
        "execution-origin-dispositions.json": {
            "schema_version": "1.0",
            "dispositions": report.execution_origin_dispositions,
        },
        "scanner-results.json": {"schema_version": "1.0", "runs": report.scanner_runs},
        "solidity-coverage.json": {
            "schema_version": "1.0",
            "evidence_authority": "comparison_required",
            "coverage": report.solidity_coverage,
        },
        "model-review-coverage.json": {
            "schema_version": "1.0",
            "coverage": report.model_review_coverage,
        },
        "scope-assessment.json": {
            "schema_version": "1.0",
            "assessment": source.analysis_arguments["scope_assessment"],
        },
        "verification-results.json": {
            "schema_version": "1.2",
            "decisions": report.verification_decisions,
            "threat_model": None,
            "threat_model_location_rejections": [],
        },
        "cross-examination.json": {
            "schema_version": "1.2",
            "decisions": report.cross_examination_decisions,
        },
        "candidate-findings.json": {"schema_version": "1.1", "findings": state.candidates},
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": report.reproductions,
            "candidate_resolutions": state.resolutions,
            "falsification_decisions": report.falsification_decisions,
        },
        manifest.MODEL_REVIEW_ARTIFACT_INVENTORY_PATH: manifest.build_model_review_artifact_inventory(
            artifacts=fixture.runtime.model_surface_review_artifacts,
            review_contexts_by_request=fixture.coverage_arguments["review_contexts_by_request"],
        ),
        manifest.PROMOTED_MODEL_REVIEW_ARTIFACT_INVENTORY_PATH: promoted,
        manifest.ACTOR_MODEL_BASELINE_ARTIFACT_PATH: report.actor_model_baseline,
        manifest.ACTOR_MODEL_EVALUATION_ARTIFACT_PATH: report.actor_model_evaluation,
        manifest.KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH: report.taxonomy_coverage,
        "metadata.json": {
            "schema_version": report.schema_version,
            "run_id": report.run_id,
            "generated_at": report.generated_at.isoformat(),
            **report_status_metadata(report),
            "minimum_analysis_floor": report.minimum_analysis_floor,
            "configuration_hash": report.configuration_hash,
            "model_configuration_hash": report.model_configuration_hash,
            "privacy": report.privacy,
            "repository_suite_differential": report.repository_suite_differential,
            "metadata": report.metadata,
        },
    }
    findings = build_findings_artifact(
        report,
        candidates=state.candidates,
        reproduction_resolutions=state.resolutions,
        source_excerpts=build_client_source_excerpts(report, source.sources),
    )
    payloads.update(
        {
            "findings.json": findings,
            "coverage.json": build_coverage_artifact(report),
            "model-execution.json": build_model_execution_artifact(
                report, cost_ledger_evidence=cost, persistent_ledger_configured=True
            ),
            "audit-results.sarif": generate_report_sarif(report, findings_artifact=findings),
        }
    )
    for name, payload in payloads.items():
        path = root / name
        assert not path.exists(), "original artifact destination already exists"
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_json(
            path,
            payload
            if isinstance(payload, BaseModel)
            else TypeAdapter(Any).dump_python(payload, mode="json"),
        )
        path.chmod(0o600)
    (root / manifest.KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).write_bytes(
        load_known_issue_taxonomy().raw_bytes
    )
    (root / manifest.KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).chmod(0o600)
    for name, content in (
        ("client-report.md", render_client_markdown_from_artifact(report, findings)),
        ("forensic-report.md", render_forensic_markdown(report, findings_artifact=findings)),
        ("audit-report.md", render_markdown(report, findings_artifact=findings)),
    ):
        (root / name).write_text(content, encoding="utf-8")
        (root / name).chmod(0o600)
    write_run_terminal_report_authority(root, report, scheduler_artifact=public)
    return report
