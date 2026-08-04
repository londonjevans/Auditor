from __future__ import annotations

import errno
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

import mmaudit.orchestration.manifest as manifest_module
from mmaudit.cli import app
from mmaudit.config import (
    _AUDIT_OVERRIDE_PATHS,
    _AUDIT_OVERRIDE_VALUE_TYPES,
    AuditConfig,
    AuditConfigOverride,
    AuditConfigOverrides,
    AuditRunOptions,
    LoadedAuditConfig,
)
from mmaudit.constants import ExitCode
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.reasoning import (
    ReasoningExecutionEvidence,
    ReasoningRequestPlanEvidence,
    resolve_reasoning_request_role,
)
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.runtime import build_reasoning_policy
from mmaudit.models.scheduler import SchedulerArtifact
from mmaudit.models.schemas import (
    AuditReport,
    CandidateFinding,
    CandidateReproductionResolution,
    ExecutionEvidenceKind,
    Location,
    ModelRequestValidationStatus,
    RepositoryDifferentialRunStatus,
    RepositoryFile,
    RepositoryForkRpcPrivacyEvidence,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ScannerRun,
    ScannerStatus,
    UsageRecord,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    _model_bindings,
    _seed_bindings,
    _validate_scanner_stream_artifact_custody,
    build_run_evidence_manifest,
    canonical_sha256,
    collect_run_artifacts,
    load_run_evidence_manifest,
    open_manifest_bound_json_artifacts,
    rebuild_run_evidence_manifest_for_verification,
    seal_run_evidence_manifest,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.orchestration.verification import (
    RunVerification,
    RunVerificationCategory,
    RunVerificationMismatchKind,
    RunVerificationStatus,
    verify_run_evidence,
)
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import (
    build_client_source_excerpts,
    render_client_markdown_from_artifact,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.run_authority import RUN_TERMINAL_REPORT_AUTHORITY_PATH
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import report_status_metadata
from mmaudit.repository.locations import validate_location
from mmaudit.scanners.normalization import reparse_trusted_scanner_stdout
from mmaudit.scanners.projection import project_scanner_finding
from tests.identity_fixtures import (
    bind_synthetic_usage_identity,
    reattest_synthetic_real_usage,
    synthetic_token_plan_routing,
)
from tests.output_evidence_fixtures import synthetic_structured_output_routing
from tests.report_authority_fixtures import write_run_terminal_report_authority
from tests.unit.test_model_registry import _verified_production_config_and_capability

runner = CliRunner()


def _report(config) -> AuditReport:
    empty_overrides = AuditConfigOverrides()
    run_options = AuditRunOptions()
    return AuditReport(
        schema_version="1.0",
        run_id="manifest-test-run",
        generated_at=datetime(2026, 1, 2, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-manifest-repository",
            languages={"Solidity": 1},
            frameworks=["Foundry"],
            manifests=["foundry.toml"],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=["foundry.toml"],
            sensitive_processing=[],
            security_tests=[],
            files=[
                RepositoryFile(
                    path="src/Vault.sol",
                    size=32,
                    lines=1,
                    sha256="a" * 64,
                    language="Solidity",
                )
            ],
        ),
        configuration_hash=config.stable_hash(),
        model_configuration_hash=config.model_hash(),
        privacy={"code_egress_enabled": False},
        scanner_runs=[],
        usage=[],
        budget_usd=20,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        metadata={
            "run_options": run_options.model_dump(mode="json"),
            "configuration_provenance": {
                "file_config_sha256": config.stable_hash(),
                "environment_overrides_sha256": empty_overrides.stable_hash(),
                "cli_overrides_sha256": empty_overrides.stable_hash(),
                "run_options_sha256": run_options.stable_hash(),
            },
        },
    )


def _qualified_reasoning_usage(
    config: AuditConfig,
    qualification: VerifiedProductionQualification,
    *,
    observed_at: datetime,
    role: str = "source_audit",
) -> UsageRecord:
    """Build one synthetic request with the complete opaque qualification projection."""

    policy = build_reasoning_policy(config)
    resolution = resolve_reasoning_request_role(role)
    model_id = config.models.role(role).primary
    model = qualification.model_for(model_id, now=observed_at)
    matching_routes = tuple(
        route
        for route in model.reasoning_bindings
        if route.qualified_role == resolution.qualification_role
        and route.configured_policy_role == resolution.configured_policy_role
    )
    assert len(matching_routes) == 1
    route = matching_routes[0]
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role=role,
        policy=policy,
        endpoint_capability_sha256=route.endpoint_reasoning_capability_sha256,
        qualification_binding_sha256=route.binding_sha256,
    )
    request_id = "request-qualified-reasoning-manifest"
    generation_id = "generation-qualified-reasoning-manifest"
    started_at = observed_at
    ended_at = observed_at.replace(second=min(59, observed_at.second + 1))
    prompt_sha256 = "c" * 64
    request_body_sha256 = "d" * 64
    response_sha256 = "e" * 64
    validated_response_sha256 = "f" * 64
    schema_sha256 = "1" * 64
    provider_policy_sha256 = "2" * 64
    observed_reasoning_tokens = 0 if reasoning_plan.control_profile.mode == "disabled" else 1
    routing: dict[str, object] = {
        "generation_id": generation_id,
        "selected_model": model.canonical_model_slug,
        "canonical_model": model.canonical_model_slug,
        "selected_provider_endpoint": model.approved_provider_endpoint,
        "selected_provider_name": model.approved_provider_name,
        "router_strategy": "direct",
        "router_attempt": 1,
        "router_attempt_count": 1,
        "router_pipeline": [],
        "finish_reason": "stop",
        "schema_sha256": schema_sha256,
        "router_metadata_sha256": "3" * 64,
        "provider_policy_sha256": provider_policy_sha256,
        "provider_fallbacks_allowed": False,
        "certification_request": True,
        "endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "output_capability_sha256": model.output_capability_sha256,
        "endpoint_pricing_sha256": model.pricing_snapshot_sha256,
        "model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "catalog_identity_binding_sha256": canonical_sha256(
            {
                "canonical_slug": model.canonical_model_slug,
                "id": model.exact_model_id,
            }
        ),
        "catalog_snapshot_sha256": "4" * 64,
        "discovery_provenance_sha256": "5" * 64,
        "discovery_evidence_sha256": "6" * 64,
        "validation_status": "valid",
        "zdr_requested": True,
        "data_collection": "deny",
        "repair_used": False,
        "repair_request": False,
        "request_started_at": started_at.isoformat(),
        "request_ended_at": ended_at.isoformat(),
        "latency_ms": 1_000,
        "structured_output": synthetic_structured_output_routing(
            configured_provider_endpoints=(model.approved_provider_endpoint,),
            selected_provider_endpoint=model.approved_provider_endpoint,
            endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
            output_capability_sha256=model.output_capability_sha256,
            prompt_sha256=prompt_sha256,
            request_body_sha256=request_body_sha256,
            provider_policy_sha256=provider_policy_sha256,
            schema_sha256=schema_sha256,
            original_response_sha256=response_sha256,
            validated_response_sha256=validated_response_sha256,
            mode=model.structured_output_mode,
            reasoning_requested=reasoning_plan.control_profile.mode != "disabled",
        ),
        "qualified_exact_model_id": model.exact_model_id,
        "qualified_canonical_model_slug": model.canonical_model_slug,
        "qualified_root_lineage": model.root_lineage,
        "qualified_provider_endpoint": model.approved_provider_endpoint,
        "qualified_provider_name": model.approved_provider_name,
        "qualified_endpoint_snapshot_sha256": model.endpoint_snapshot_sha256,
        "qualified_output_capability_sha256": model.output_capability_sha256,
        "qualified_structured_output_mode": model.structured_output_mode.value,
        "qualified_model_metadata_snapshot_sha256": model.model_metadata_snapshot_sha256,
        "qualified_pricing_snapshot_sha256": model.pricing_snapshot_sha256,
        "qualified_roles": list(model.approved_roles),
        "qualification_verified_at": qualification.verified_at.isoformat(),
        "qualification_expires_at": model.expires_at.isoformat(),
        "qualification_artifact_sha256": qualification.artifact_sha256,
        "qualification_verification_sha256": (qualification.qualification_verification_sha256),
        "production_selection_sha256": qualification.production_selection_sha256,
        "selection_verification_sha256": qualification.selection_verification_sha256,
        "qualification_result_sha256": model.qualification_result_sha256,
        "benchmark_report_sha256": model.benchmark_report_sha256,
        "qualified_reasoning_binding_sha256": [
            binding.binding_sha256 for binding in model.reasoning_bindings
        ],
    }
    provisional = UsageRecord(
        request_id=request_id,
        role=role,
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=model.exact_model_id,
        returned_model=model.canonical_model_slug,
        actual_model=model.canonical_model_slug,
        provider=model.approved_provider_name,
        model_family=model.exact_model_id,
        timestamp=observed_at,
        prompt_tokens=10,
        completion_tokens=10,
        total_tokens=20,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        routing=routing,
        prompt_sha256=prompt_sha256,
        response_sha256=response_sha256,
        validated_response_sha256=validated_response_sha256,
        request_body_sha256=request_body_sha256,
        schema_sha256=schema_sha256,
        openrouter_generation_id=generation_id,
        configured_provider_endpoints=[model.approved_provider_endpoint],
        actual_provider_endpoint=model.approved_provider_endpoint,
        started_at=started_at,
        ended_at=ended_at,
        latency_ms=1_000,
        finish_reason="stop",
        retry_count=0,
        validation_status=ModelRequestValidationStatus.VALID,
        status="success",
        attempts=1,
    )
    return bind_synthetic_usage_identity(
        provisional,
        reasoning_plan=reasoning_plan,
        observed_reasoning_tokens=observed_reasoning_tokens,
    )


def _reseal_qualification_validation(payload: dict[str, object]) -> None:
    payload["validation_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "validation_sha256"}
    )


def _write_required_artifacts(
    run_dir: Path,
    report: AuditReport,
    *,
    legacy_model_execution: bool = False,
    source_contents: dict[str, str] | None = None,
    scheduler_artifact: SchedulerArtifact | None = None,
    candidates: tuple[CandidateFinding, ...] = (),
    reproduction_resolutions: tuple[CandidateReproductionResolution, ...] = (),
) -> None:
    payloads = {
        "solidity-compilation.json": {"schema_version": "1.0", "results": []},
        "invariant-harness-plan.json": {
            "schema_version": "1.0",
            "harnesses": [{"name": "InvariantHarness", "invariant_id": "inv-1"}],
        },
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": {
                "corpus_hash": "b" * 64,
                "properties": [{"property_id": "property-1", "campaign": {"seed": 17}}],
            },
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "results": [{"harness_name": "InvariantHarness", "campaign_seed": 17}],
        },
        "formal-results.json": {
            "schema_version": "1.0",
            "runs": [{"tool": "synthetic-formal", "campaign_seed": 23}],
        },
        "reproduction-results.json": {
            "schema_version": "1.0",
            "test_specifications": [],
            "results": [],
            "candidate_resolutions": [],
            "falsification_decisions": [],
        },
        "solidity-coverage.json": {"schema_version": "1.0", "coverage": None},
        "model-review-coverage.json": {"schema_version": "1.0", "coverage": None},
        "scope-assessment.json": {"schema_version": "1.0", "assessment": None},
        "scanner-results.json": {
            "schema_version": "1.0",
            "runs": [run.model_dump(mode="json") for run in report.scanner_runs],
        },
        "verification-results.json": {
            "schema_version": "1.2",
            "decisions": [
                decision.model_dump(mode="json") for decision in report.verification_decisions
            ],
            "threat_model": None,
            "threat_model_location_rejections": [],
        },
        "cross-examination.json": {
            "schema_version": "1.2",
            "decisions": [
                decision.model_dump(mode="json") for decision in report.cross_examination_decisions
            ],
        },
        "candidate-findings.json": {
            "schema_version": "1.1",
            "findings": [candidate.model_dump(mode="json") for candidate in candidates],
        },
    }
    run_dir.mkdir(exist_ok=True)
    for name, payload in payloads.items():
        (run_dir / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if report.repository_suite_differential is not None:
        (run_dir / "repository-suite-differential.json").write_text(
            report.repository_suite_differential.model_dump_json(),
            encoding="utf-8",
        )
        (run_dir / "privacy-fork-rpc-egress.json").write_text(
            json.dumps(report.privacy["fork_rpc_egress"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "generated_at": report.generated_at.isoformat(),
                **report_status_metadata(report),
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
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "final-findings.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    findings_artifact = build_findings_artifact(
        report,
        candidates=candidates,
        reproduction_resolutions=reproduction_resolutions,
        source_excerpts=(
            build_client_source_excerpts(report, source_contents)
            if source_contents is not None
            else None
        ),
    )
    write_json(run_dir / "findings.json", findings_artifact)
    write_json(run_dir / "coverage.json", build_coverage_artifact(report))
    write_json(
        run_dir / "model-execution.json",
        build_model_execution_artifact(
            report,
            legacy_schema_1_0=legacy_model_execution,
        ),
    )
    write_json(
        run_dir / "audit-results.sarif",
        generate_report_sarif(report, findings_artifact=findings_artifact),
    )
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
    write_run_terminal_report_authority(
        run_dir,
        report,
        scheduler_artifact=scheduler_artifact,
    )


def _write_verifiable_run(
    root: Path,
    config,
) -> tuple[Path, Path, RunEvidenceManifest, AuditReport]:
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_contents = "contract Vault { function safe() external {} }\n"
    source.write_text(source_contents, encoding="utf-8")
    report = _report(config)
    report = report.model_copy(
        update={
            "repository": report.repository.model_copy(
                update={
                    "root_name": repository.name,
                    "files": [
                        RepositoryFile(
                            path="src/Vault.sol",
                            size=len(source_contents.encode("utf-8")),
                            lines=1,
                            sha256=hashlib.sha256(source_contents.encode("utf-8")).hexdigest(),
                            language="Solidity",
                        )
                    ],
                }
            )
        }
    )
    run_dir = root / "run"
    _write_required_artifacts(run_dir, report)
    (run_dir / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "generated_at": report.generated_at.isoformat(),
                **report_status_metadata(report),
                "minimum_analysis_floor": (
                    report.minimum_analysis_floor.model_dump(mode="json")
                    if report.minimum_analysis_floor is not None
                    else None
                ),
                "configuration_hash": report.configuration_hash,
                "model_configuration_hash": report.model_configuration_hash,
                "privacy": report.privacy,
                "metadata": report.metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "final-findings.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"current"}\n',
        encoding="utf-8",
    )
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        manifest,
    )
    return repository, run_dir, manifest, report


def _reseal_current_artifacts(
    run_dir: Path,
    manifest: RunEvidenceManifest,
) -> RunEvidenceManifest:
    assert manifest.run_configuration is not None
    resealed = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", resealed)
    return resealed


def _rewrite_as_sealed_schema_1_1(
    run_dir: Path,
    current: RunEvidenceManifest,
    report: AuditReport,
    *,
    retain_model_execution: bool = False,
) -> RunEvidenceManifest:
    """Project an already-sealed pre-report-bundle manifest for compatibility tests."""

    retained = {"audit-results.sarif"}
    if retain_model_execution:
        retained.add("model-execution.json")
    for artifact_name in MANIFEST_BOUND_REPORT_DELIVERABLES - retained:
        (run_dir / artifact_name).unlink()
    (run_dir / RUN_TERMINAL_REPORT_AUTHORITY_PATH).unlink()
    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["completed"] = report.completed
    metadata["incomplete_reasons"] = report.incomplete_reasons
    for current_status_field in (
        "quality_status",
        "run_status",
        "quality_gates",
        "limitations",
        "minimum_analysis_floor",
    ):
        metadata.pop(current_status_field, None)
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    payload = current.model_dump(mode="json")
    payload["schema_version"] = "1.1"
    legacy_coverage = [
        binding
        for binding in payload["bindings"]["coverage"]
        if binding["identifier"] not in {"quality-gates/report", "report-status/projection"}
    ]
    legacy_coverage.append(
        ManifestHashBinding(
            identifier="quality-gates/report",
            sha256=canonical_sha256(
                [gate.model_dump(mode="json") for gate in report.quality_gates]
            ),
            details={"gates": str(len(report.quality_gates))},
        ).model_dump(mode="json")
    )
    payload["bindings"]["coverage"] = sorted(
        legacy_coverage,
        key=lambda item: item["identifier"],
    )
    payload["artifacts"] = [
        artifact.model_dump(mode="json") for artifact in collect_run_artifacts(run_dir)
    ]
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    legacy = RunEvidenceManifest.model_validate(payload)
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", legacy)
    return legacy


def _write_qualified_verifiable_run(
    root: Path,
) -> tuple[
    AuditConfig,
    Path,
    Path,
    RunEvidenceManifest,
    AuditReport,
]:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    repository = root / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_contents = "contract Vault { function safe() external {} }\n"
    source.write_text(source_contents, encoding="utf-8")
    base_report = _report(config)
    report = base_report.model_copy(
        update={
            "repository": base_report.repository.model_copy(
                update={
                    "root_name": repository.name,
                    "files": [
                        RepositoryFile(
                            path="src/Vault.sol",
                            size=len(source_contents.encode("utf-8")),
                            lines=1,
                            sha256=hashlib.sha256(source_contents.encode("utf-8")).hexdigest(),
                            language="Solidity",
                        )
                    ],
                }
            ),
        }
    )
    run_dir = root / "run"
    _write_required_artifacts(run_dir, report)
    (run_dir / "model-qualification-runtime.json").write_text(
        json.dumps(validation.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        production_qualification=qualification,
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    return config, repository, run_dir, manifest, report


def test_manifest_serialization_and_all_required_bindings_are_stable(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    first_run = tmp_path / "first"
    second_run = tmp_path / "second"
    report = _report(config)
    _write_required_artifacts(first_run, report)
    _write_required_artifacts(second_run, report)

    first = build_run_evidence_manifest(
        run_dir=first_run,
        report=report,
        config=config,
    )
    second = build_run_evidence_manifest(
        run_dir=second_run,
        report=report,
        config=config,
    )

    assert first.model_dump_json() == second.model_dump_json()
    assert first.manifest_sha256 == second.manifest_sha256
    assert first.source_tree_sha256
    assert first.schema_version == "1.2"
    assert first.run_configuration is not None
    assert first.run_configuration.requested_profile.value == "standard"
    assert first.run_configuration.achieved_profile is None
    metadata = json.loads((first_run / "metadata.json").read_text(encoding="utf-8"))
    for field_name, expected_value in report_status_metadata(report).items():
        assert metadata[field_name] == expected_value
    assert first.run_configuration.effective_config_sha256 == config.stable_hash()
    assert first.run_configuration.model_config_sha256 == config.model_hash()
    assert set(ManifestBindingSet.model_fields) == {
        name for name, bindings in first.bindings if bindings
    }
    assert any(binding.identifier.startswith("seed/") for binding in first.bindings.seeds)
    assert {binding.path for binding in first.artifacts} == {
        binding.path for binding in collect_run_artifacts(first_run)
    }


def test_legacy_completed_report_new_issuance_uses_fail_closed_status_projection(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    assert report.schema_version == "1.0"
    assert report.completed
    _write_required_artifacts(run_dir, report)

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    metadata = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8"))

    assert manifest.schema_version == "1.2"
    assert manifest.run_configuration is not None
    assert manifest.run_configuration.achieved_profile is None
    for field_name, expected_value in report_status_metadata(report).items():
        assert metadata[field_name] == expected_value
    assert metadata["completed"] is False
    assert metadata["quality_status"] == "incomplete"
    assert metadata["run_status"] == "INCOMPLETE"


@pytest.mark.parametrize("retained_report_leaves", [set(), {"audit-results.sarif"}])
def test_new_manifest_issuance_rejects_zero_or_partial_report_bundle(
    tmp_path: Path,
    config_factory,
    retained_report_leaves: set[str],
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    for artifact_name in MANIFEST_BOUND_REPORT_DELIVERABLES - retained_report_leaves:
        (run_dir / artifact_name).unlink()

    with pytest.raises(ValueError, match="client/forensic report bundle is incomplete"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    [
        ("completed", True),
        ("quality_status", "completed"),
        ("run_status", "COMPLETE"),
        ("incomplete_reasons", []),
        ("quality_gates", []),
        ("limitations", []),
        ("minimum_analysis_floor", {"tampered": True}),
    ],
)
def test_new_manifest_issuance_rejects_metadata_status_drift(
    tmp_path: Path,
    config_factory,
    field_name: str,
    tampered_value: object,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata[field_name] = tampered_value
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(ValueError, match=rf"metadata.json {field_name}"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_public_manifest_sealer_cannot_issue_a_new_schema_1_1_manifest(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    current = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    assert current.run_configuration is not None

    with pytest.raises(ValueError, match=r"new manifest issuance requires schema 1\.2"):
        seal_run_evidence_manifest(
            run_id=current.run_id,
            repository_root_name=current.repository_root_name,
            git_commit=current.git_commit,
            sources=current.sources,
            run_configuration=current.run_configuration,
            bindings=current.bindings,
            artifacts=current.artifacts,
            schema_version="1.1",
            tool_version=current.tool_version,
        )


def test_new_manifest_issuance_rejects_legacy_model_execution_custody(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "legacy-model-execution"
    report = _report(config)
    _write_required_artifacts(run_dir, report, legacy_model_execution=True)

    with pytest.raises(ValueError, match="current typed model-execution custody"):
        build_run_evidence_manifest(run_dir=run_dir, report=report, config=config)


def test_sealed_legacy_manifest_accepts_legacy_model_execution_custody(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "sealed-legacy-model-execution"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    current = build_run_evidence_manifest(run_dir=run_dir, report=report, config=config)
    write_json(
        run_dir / "model-execution.json",
        build_model_execution_artifact(report, legacy_schema_1_0=True),
    )
    legacy = _rewrite_as_sealed_schema_1_1(
        run_dir,
        current,
        report,
        retain_model_execution=True,
    )

    validate_manifest_artifacts(legacy, run_dir)


def test_manifest_seed_bindings_include_repository_suite_fuzz_seed() -> None:
    fuzz_seed = "0x" + "ab" * 32

    bindings = _seed_bindings(
        {
            "runs": [
                {
                    "repository_suite_execution_policy": {
                        "fuzz_seed": fuzz_seed,
                    }
                }
            ]
        }
    )

    assert any(
        binding.details.get("value") == fuzz_seed
        and binding.details.get("field", "").endswith("/fuzz_seed")
        for binding in bindings
    )


def test_manifest_reconstructs_per_role_reasoning_policy_bindings(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory(
        models={
            "reasoning": {
                "effort": "low",
                "reserved_tokens": 512,
            },
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {
                    "effort": "high",
                    "reserved_tokens": 2_048,
                },
            },
        }
    )
    run_dir = tmp_path / "reasoning-run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    model_bindings = {binding.identifier: binding for binding in manifest.bindings.models}

    assert model_bindings["reasoning/policy"].details["roles"]
    assert model_bindings["reasoning/configured/source_audit"].details == {
        "mode": "effort",
        "effort": "high",
        "max_tokens": "0",
        "reserved_reasoning_tokens": "2048",
        "profile_sha256": model_bindings["reasoning/configured/source_audit"].details[
            "profile_sha256"
        ],
    }
    assert model_bindings["reasoning/configured/judge"].details["effort"] == "low"


def test_manifest_binds_reasoning_execution_and_rejects_effective_policy_drift(
    config_factory,
) -> None:
    config = config_factory(
        models={
            "reasoning": {"effort": "low", "reserved_tokens": 512},
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {"effort": "high", "reserved_tokens": 2_048},
            },
        }
    )
    policy = build_reasoning_policy(config)
    reasoning_plan = ReasoningRequestPlanEvidence.build(
        request_role="source_audit",
        policy=policy,
        endpoint_capability_sha256="a" * 64,
    )
    provisional = UsageRecord(
        request_id="request-reasoning-manifest",
        role="source_audit",
        requested_model="alpha/atlas-secure",
        returned_model="alpha/atlas-secure",
        actual_model="alpha/atlas-secure",
        provider="Synthetic Provider",
        model_family="alpha/atlas-secure",
        timestamp=datetime(2026, 1, 2, tzinfo=UTC),
        prompt_tokens=10,
        completion_tokens=10,
        total_tokens=20,
        accounted_cost_usd=0,
        routing={},
        prompt_sha256="c" * 64,
        request_body_sha256="d" * 64,
        configured_provider_endpoints=["synthetic-provider"],
        actual_provider_endpoint="synthetic-provider",
        status="success",
        attempts=1,
    )
    routing = synthetic_token_plan_routing(
        provisional,
        provisional.routing,
        reasoning_plan=reasoning_plan,
    )
    token_plan_sha256 = routing["request_token_plan_sha256"]
    assert isinstance(token_plan_sha256, str)
    execution = ReasoningExecutionEvidence.build(
        request_plan=reasoning_plan,
        observed_reasoning_tokens=2,
        provider_completion_tokens=10,
        request_token_plan_sha256=token_plan_sha256,
        request_body_sha256="d" * 64,
    )
    usage = UsageRecord.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "routing": routing,
            "reasoning_tokens": 2,
            "reasoning_evidence": execution.model_dump(mode="json"),
        }
    )
    report = _report(config).model_copy(update={"usage": [usage]})

    bindings = {
        binding.identifier: binding
        for binding in _model_bindings(config, report, qualification_runtime=None)
    }

    assert bindings["reasoning/execution/request-reasoning-manifest"].sha256 == (
        execution.evidence_sha256
    )
    assert bindings["reasoning/capability/request-reasoning-manifest"].sha256 == "a" * 64
    assert "reasoning/qualification/request-reasoning-manifest" not in bindings

    changed_config = config_factory(
        models={
            "reasoning": {"effort": "low", "reserved_tokens": 512},
            "source_audit": {
                "primary": "alpha/atlas-secure",
                "reasoning": {"effort": "medium", "reserved_tokens": 1_024},
            },
        }
    )
    changed_report = _report(changed_config).model_copy(update={"usage": [usage]})
    with pytest.raises(ValueError, match="differs from the effective configuration"):
        _model_bindings(
            changed_config,
            changed_report,
            qualification_runtime=None,
        )


def test_manifest_rejects_scanner_results_that_differ_from_report(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    now = datetime(2026, 1, 2, tzinfo=UTC)
    scanner_run = ScannerRun(
        scanner="synthetic",
        status=ScannerStatus.SKIPPED,
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        error="disabled in synthetic manifest test",
    )
    report = AuditReport.model_validate(
        {
            **report.model_dump(mode="json"),
            "scanner_runs": [scanner_run.model_dump(mode="json")],
        }
    )
    _write_required_artifacts(run_dir, report)
    (run_dir / "scanner-results.json").write_text(
        json.dumps({"schema_version": "1.0", "runs": []}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"scanner-results\.json"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_current_scanner_stream_custody_binds_production_shaped_bytes_and_owner(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    scanner_root = run_dir / "private" / "scanner-output"
    tool_root = scanner_root / "semgrep"
    tool_root.mkdir(parents=True)
    (tool_root / "workspace").mkdir()
    stdout = tool_root / "semgrep.json"
    stderr = tool_root / "semgrep.stderr.txt"
    stdout_bytes = b'{"errors":[],"results":[]}'
    stdout.write_bytes(stdout_bytes)
    stderr.write_bytes(b"")
    now = datetime(2026, 1, 2, tzinfo=UTC)
    provisional = ScannerRun(
        scanner="semgrep",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="semgrep-1.0",
        executable_sha256="1" * 64,
        command=["/trusted/semgrep", "--json"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        raw_output_path="semgrep/semgrep.json",
        raw_output_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        raw_output_bytes=len(stdout_bytes),
        private_stderr_path="semgrep/semgrep.stderr.txt",
        private_stderr_sha256=hashlib.sha256(b"").hexdigest(),
        private_stderr_bytes=0,
        process_exit_code=0,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="2" * 64,
        machine_output_validated=True,
    )
    scanner_run = ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": provisional.expected_execution_observation_sha256(),
        }
    )
    report = _report(config).model_copy(update={"scanner_runs": [scanner_run]})
    _write_required_artifacts(run_dir, report)

    _validate_scanner_stream_artifact_custody(run_dir, report.scanner_runs)
    build_run_evidence_manifest(run_dir=run_dir, report=report, config=config)

    stdout.write_bytes(b'{"changed":true}')
    with pytest.raises(ValueError, match="differs from its exact byte custody"):
        _validate_scanner_stream_artifact_custody(run_dir, report.scanner_runs)
    stdout.write_bytes(stdout_bytes)

    other_root = scanner_root / "other"
    other_root.mkdir()
    other = other_root / "semgrep.json"
    other.write_bytes(stdout_bytes)
    swapped = scanner_run.model_copy(update={"raw_output_path": "other/semgrep.json"})
    with pytest.raises(ValueError, match="path is unsafe or repeated"):
        _validate_scanner_stream_artifact_custody(run_dir, [swapped])


def test_manifest_rejects_coherently_resealed_scanner_projection_tamper(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository = tmp_path / "repository"
    source = repository / "src" / "Vault.sol"
    source.parent.mkdir(parents=True)
    source_content = "contract Vault { function guarded() external {} }\n"
    source.write_text(source_content, encoding="utf-8")
    location = Location(path="src/Vault.sol", start_line=1, end_line=1, symbol="guarded")
    validation = validate_location(repository, location)
    run_dir = tmp_path / "run"
    scanner_root = run_dir / "private" / "scanner-output" / "semgrep"
    workspace_source = scanner_root / "workspace" / location.path
    workspace_source.parent.mkdir(parents=True)
    workspace_source.write_text(source_content, encoding="utf-8")
    stdout_bytes = json.dumps(
        {
            "results": [
                {
                    "check_id": "synthetic-rule",
                    "path": location.path,
                    "start": {"line": location.start_line, "col": 1},
                    "end": {"line": location.end_line, "col": 1},
                    "extra": {
                        "message": "Synthetic deterministic scanner observation.",
                        "severity": "ERROR",
                        "metadata": {"cwe": ["CWE-284"]},
                    },
                }
            ],
            "errors": [],
        },
        separators=(",", ":"),
    ).encode()
    (scanner_root / "semgrep.json").write_bytes(stdout_bytes)
    (scanner_root / "semgrep.stderr.txt").write_bytes(b"")
    parsed = reparse_trusted_scanner_stdout(
        scanner="semgrep",
        repository_root=scanner_root / "workspace",
        retained_stdout=stdout_bytes,
    )
    assert len(parsed) == 1
    scanner_finding = parsed[0].model_copy(
        update={
            "metadata": {
                **parsed[0].metadata,
                "location_validation": [validation.model_dump(mode="json")],
            }
        }
    )
    now = datetime(2026, 1, 2, tzinfo=UTC)
    provisional_scanner_run = ScannerRun(
        scanner="semgrep",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="semgrep-1.0",
        executable_sha256="1" * 64,
        command=["/trusted/semgrep", "--json"],
        started_at=now,
        finished_at=now,
        duration_seconds=0,
        findings=[scanner_finding],
        raw_output_path="semgrep/semgrep.json",
        raw_output_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
        raw_output_bytes=len(stdout_bytes),
        private_stderr_path="semgrep/semgrep.stderr.txt",
        private_stderr_sha256=hashlib.sha256(b"").hexdigest(),
        process_exit_code=0,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="2" * 64,
        machine_output_validated=True,
    )
    scanner_run = provisional_scanner_run.model_copy(
        update={
            "execution_observation_sha256": (
                provisional_scanner_run.expected_execution_observation_sha256()
            )
        }
    )
    projected = project_scanner_finding(
        scanner_finding,
        [validation],
        validated_at=validation.validated_at,
    )
    base_report = _report(config)
    repository_map = base_report.repository.model_copy(
        update={
            "root_name": repository.name,
            "files": [
                RepositoryFile(
                    path=location.path,
                    size=len(source_content.encode()),
                    lines=1,
                    sha256=hashlib.sha256(source_content.encode()).hexdigest(),
                    language="Solidity",
                )
            ],
        }
    )
    report = base_report.model_copy(
        update={
            "repository": repository_map,
            "scanner_runs": [scanner_run],
            "findings": [projected],
        }
    )
    source_contents = {location.path: source_content}
    _write_required_artifacts(run_dir, report, source_contents=source_contents)
    manifest = build_run_evidence_manifest(run_dir=run_dir, report=report, config=config)
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    validate_manifest_artifacts(manifest, run_dir)

    tampered_finding = projected.model_copy(
        update={"impact": "A contradictory narrative not emitted by the scanner projection."}
    )
    tampered_report = report.model_copy(update={"findings": [tampered_finding]})
    _write_required_artifacts(
        run_dir,
        tampered_report,
        source_contents=source_contents,
    )
    resealed = _reseal_current_artifacts(run_dir, manifest)
    with pytest.raises(ValueError, match="authoritative scanner projection"):
        validate_manifest_artifacts(resealed, run_dir)

    unverified_provisional = ScannerRun.model_validate(
        {
            **scanner_run.model_dump(mode="json"),
            "execution_evidence": ExecutionEvidenceKind.UNVERIFIED,
            "execution_observation_sha256": None,
        }
    )
    unverified_scanner_run = ScannerRun.model_validate(
        {
            **unverified_provisional.model_dump(mode="json"),
            "execution_observation_sha256": (
                unverified_provisional.expected_execution_observation_sha256()
            ),
        }
    )
    coherently_resealed_report = report.model_copy(
        update={"scanner_runs": [unverified_scanner_run]}
    )
    _write_required_artifacts(
        run_dir,
        coherently_resealed_report,
        source_contents=source_contents,
    )
    coherently_resealed = _reseal_current_artifacts(run_dir, manifest)
    with pytest.raises(ValueError, match="replay-authorized scanner evidence"):
        validate_manifest_artifacts(coherently_resealed, run_dir)

    uncredited_raw_report = coherently_resealed_report.model_copy(update={"findings": []})
    _write_required_artifacts(
        run_dir,
        uncredited_raw_report,
        source_contents=source_contents,
    )
    uncredited_raw_resealed = _reseal_current_artifacts(run_dir, manifest)
    validate_manifest_artifacts(uncredited_raw_resealed, run_dir)

    invalid_fingerprint = scanner_finding.model_copy(update={"fingerprint": "f" * 64})
    with pytest.raises(ValueError, match="fingerprint differs from its canonical semantics"):
        project_scanner_finding(
            invalid_fingerprint,
            [validation],
            validated_at=validation.validated_at,
        )


def test_manifest_binds_differential_and_fork_rpc_privacy_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory(
        smart_contracts={
            "repository_suite": {
                "fork_matrix_states": [
                    {
                        "state_id": "clean-local",
                        "kind": "clean_local",
                        "expected_chain_id": 31_337,
                        "anvil_executable_env": "MMAUDIT_ANVIL_EXECUTABLE",
                        "anvil_version": "anvil Version: 1.3.2-stable",
                        "anvil_sha256": "a" * 64,
                        "hardfork": "cancun",
                        "genesis_timestamp": 1,
                        "startup_timeout_seconds": 5,
                        "shutdown_timeout_seconds": 5,
                    },
                    {
                        "state_id": "pinned-state",
                        "kind": "pinned_fork",
                        "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
                        "expected_chain_id": 1,
                        "pinned_block_number": 20_000_000,
                        "state_source_sha256": "b" * 64,
                    },
                ],
                "fork_matrix_repetitions": 2,
            }
        }
    )
    differential = RepositorySuiteDifferentialRun.sealed(
        status=RepositoryDifferentialRunStatus.FAILED,
        configuration_sha256=config.smart_contracts.repository_suite.stable_hash(),
        requested_state_ids=("clean-local", "pinned-state"),
        required_repetitions=2,
        matrix=None,
        limitations=("The configured local execution state was unavailable.",),
    )
    privacy = RepositoryForkRpcPrivacyEvidence.from_differential(differential)
    report_payload = _report(config).model_dump(mode="python")
    report_payload["repository_suite_differential"] = differential
    report_payload["privacy"] = {
        **report_payload["privacy"],
        "fork_rpc_egress": privacy.model_dump(mode="json"),
    }
    report = AuditReport.model_validate(report_payload)
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir, report)

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )

    artifact_names = {artifact.path for artifact in manifest.artifacts}
    assert "repository-suite-differential.json" in artifact_names
    assert "privacy-fork-rpc-egress.json" in artifact_names

    (run_dir / "privacy-fork-rpc-egress.json").write_text(
        json.dumps(
            {
                **privacy.model_dump(mode="json"),
                "differential_result_sha256": "f" * 64,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="privacy-fork-rpc-egress"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_manifest_self_hash_and_artifact_hashes_reject_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    manifest_path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(manifest_path, manifest)
    validate_manifest_artifacts(manifest, run_dir)

    altered_manifest = manifest.model_dump(mode="json")
    altered_manifest["repository_root_name"] = "tampered"
    with pytest.raises(ValidationError, match="self-hash"):
        RunEvidenceManifest.model_validate(altered_manifest)

    (run_dir / "solidity-coverage.json").write_text(
        '{"schema_version":"1.0","coverage":{"tampered":true}}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        validate_manifest_artifacts(manifest, run_dir)


def test_manifest_rejects_coherently_resealed_compatibility_markdown(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    _repository, run_dir, manifest, _report_value = _write_verifiable_run(tmp_path, config)
    (run_dir / "audit-report.md").write_text(
        "# Corrovera Security Assurance Report\n\nContradictory replacement.\n",
        encoding="utf-8",
    )
    resealed = _reseal_current_artifacts(run_dir, manifest)

    with pytest.raises(ValueError, match=r"audit-report\.md differs"):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_rejects_resealed_metadata_privacy_disagreement(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    _repository, run_dir, manifest, report = _write_verifiable_run(tmp_path, config)
    metadata_path = run_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["privacy"] = {
        **metadata["privacy"],
        "code_egress_enabled": not metadata["privacy"]["code_egress_enabled"],
    }
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"metadata\.json privacy"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )

    assert manifest.run_configuration is not None
    resealed = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=manifest.bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )
    with pytest.raises(ValueError, match=r"metadata\.json privacy"):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_provenance_hashes_fail_closed_and_v1_0_remains_readable(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )

    tampered = manifest.model_dump(mode="json")
    tampered["run_configuration"]["cli_overrides_sha256"] = "0" * 64
    tampered["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in tampered.items() if key != "manifest_sha256"}
    )
    with pytest.raises(ValidationError, match="CLI-override hash"):
        RunEvidenceManifest.model_validate(tampered)

    missing_provenance = manifest.model_dump(mode="json")
    missing_provenance.pop("run_configuration")
    missing_provenance["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in missing_provenance.items() if key != "manifest_sha256"}
    )
    with pytest.raises(ValidationError, match="requires run configuration provenance"):
        RunEvidenceManifest.model_validate(missing_provenance)

    legacy = manifest.model_dump(mode="json")
    legacy["schema_version"] = "1.0"
    legacy.pop("run_configuration")
    legacy["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in legacy.items() if key != "manifest_sha256"}
    )
    parsed_legacy = RunEvidenceManifest.model_validate(legacy)
    assert parsed_legacy.schema_version == "1.0"
    assert parsed_legacy.run_configuration is None

    legacy_with_provenance = manifest.model_dump(mode="json")
    legacy_with_provenance["schema_version"] = "1.0"
    legacy_with_provenance["manifest_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in legacy_with_provenance.items()
            if key not in {"manifest_sha256", "run_configuration"}
        }
    )
    with pytest.raises(ValidationError, match="requires run configuration provenance"):
        RunEvidenceManifest.model_validate(legacy_with_provenance)


def test_manifest_semantically_binds_runtime_model_qualification(
    tmp_path: Path,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    assert validation.valid
    run_dir = tmp_path / "qualified-run"
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    qualification_path = run_dir / "model-qualification-runtime.json"
    qualification_path.write_text(
        json.dumps(validation.as_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        production_qualification=qualification,
    )

    model_bindings = {binding.identifier: binding for binding in manifest.bindings.models}
    assert (
        model_bindings["qualification/opaque-authority"].sha256 == qualification.capability_sha256
    )
    assert (
        model_bindings["qualification/runtime-validation"].details["authority"] == "opaque_joined"
    )
    reasoning_route_bindings = [
        binding
        for identifier, binding in model_bindings.items()
        if identifier.startswith("qualification/reasoning-route/")
    ]
    assert len(reasoning_route_bindings) == sum(
        len(model.reasoning_bindings) for model in qualification.models
    )
    assert all(
        binding.details["authority"] == "opaque_joined" for binding in reasoning_route_bindings
    )
    assert {binding.sha256 for binding in reasoning_route_bindings} == {
        route.binding_sha256 for model in qualification.models for route in model.reasoning_bindings
    }
    assert model_bindings["qualification/artifact"].sha256 == qualification.artifact_sha256
    assert (
        model_bindings["qualification/production-selection"].sha256
        == qualification.production_selection_sha256
    )
    assert (
        model_bindings["qualification/production-effective-config"].sha256
        == qualification.production_effective_config_sha256
    )
    assert (
        model_bindings["qualification/release-observation"].sha256
        == qualification.release_observation_sha256
    )
    per_model_kinds = {
        "result": "qualification_result_sha256",
        "benchmark-report": "benchmark_report_sha256",
        "benchmark-verification": "benchmark_verification_sha256",
        "fresh-benchmark-evidence": "fresh_benchmark_evidence_sha256",
        "endpoint-snapshot": "endpoint_snapshot_sha256",
        "output-capability": "output_capability_sha256",
        "model-metadata-snapshot": "model_metadata_snapshot_sha256",
        "pricing-snapshot": "pricing_snapshot_sha256",
    }
    for kind, attribute in per_model_kinds.items():
        qualified_bindings = [
            binding
            for identifier, binding in model_bindings.items()
            if identifier.startswith(f"qualification/{kind}/")
        ]
        assert len(qualified_bindings) == len(qualification.models)
        assert {binding.sha256 for binding in qualified_bindings} == {
            getattr(model, attribute) for model in qualification.models
        }
        assert all(
            int(binding.details["benchmark_case_count"]) > 0 for binding in qualified_bindings
        )
        assert all(binding.details["evaluated_at"] for binding in qualified_bindings)
        assert all(binding.details["expires_at"] for binding in qualified_bindings)
        assert {binding.details["structured_output_mode"] for binding in qualified_bindings} == {
            model.structured_output_mode.value for model in qualification.models
        }

    tampered = validation.as_dict()
    tampered["qualification_artifact_sha256"] = "f" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=r"self-hash|reasoning qualification",
    ):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            production_qualification=qualification,
        )

    tampered = validation.as_dict()
    tampered["model_bindings"][0]["benchmark_report_sha256"] = "e" * 64
    qualification_path.write_text(
        json.dumps(tampered, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ValidationError,
        match=r"self-hash|reasoning qualification",
    ):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
            production_qualification=qualification,
        )


def test_manifest_requires_opaque_authority_before_granting_reasoning_credit() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})

    projection_only = {
        binding.identifier: binding
        for binding in _model_bindings(
            config,
            _report(config),
            qualification_runtime=validation.as_dict(),
        )
    }
    assert "qualification/opaque-authority" not in projection_only
    assert (
        projection_only["qualification/runtime-validation"].details["authority"]
        == "serialized_projection_only"
    )
    assert all(
        binding.details["authority"] == "serialized_projection_only"
        for identifier, binding in projection_only.items()
        if identifier.startswith("qualification/reasoning-route/")
    )

    with pytest.raises(ValueError, match="opaque production qualification authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=validation.as_dict(),
        )

    mock_usage = usage.model_copy(update={"execution_evidence": ExecutionEvidenceKind.MOCK})
    with pytest.raises(ValueError, match="creditable real opaque-authority evidence"):
        _model_bindings(
            config,
            _report(config).model_copy(update={"usage": [mock_usage]}),
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )

    bindings = {
        binding.identifier: binding
        for binding in _model_bindings(
            config,
            report,
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )
    }

    request_binding = bindings["reasoning/qualification/request-qualified-reasoning-manifest"]
    assert (
        request_binding.sha256 == usage.reasoning_evidence.request_plan.qualification_binding_sha256
    )
    assert request_binding.details["authority"] == "opaque_production_qualification"
    assert (
        request_binding.details["qualification_verification_sha256"]
        == qualification.qualification_verification_sha256
    )
    qualified_route = next(
        route
        for route in qualification.model_for(
            usage.requested_model,
            now=observed_at,
        ).reasoning_bindings
        if route.binding_sha256 == request_binding.sha256
    )
    assert request_binding.details["reasoning_benchmark_report_sha256"] == (
        qualified_route.reasoning_benchmark_report_sha256
    )
    assert request_binding.details["reasoning_benchmark_verification_sha256"] == (
        qualified_route.reasoning_benchmark_verification_sha256
    )
    assert request_binding.details["reasoning_benchmark_fresh_evidence_sha256"] == (
        qualified_route.reasoning_benchmark_fresh_evidence_sha256
    )
    assert bindings["qualification/opaque-authority"].sha256 == qualification.capability_sha256


def test_current_manifest_bindings_reject_resealed_qualified_usage_routing_tamper() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})
    assert any(
        binding.identifier == "reasoning/qualification/request-qualified-reasoning-manifest"
        for binding in _model_bindings(
            config,
            report,
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )
    )

    routing = dict(usage.routing)
    routing["qualified_provider_name"] = "Resealed Synthetic Provider"
    tampered_usage = reattest_synthetic_real_usage(usage.model_copy(update={"routing": routing}))

    with pytest.raises(
        ValueError,
        match=r"qualification|opaque production authority|routing differs",
    ):
        _model_bindings(
            config,
            report.model_copy(update={"usage": [tampered_usage]}),
            qualification_runtime=validation.as_dict(),
            production_qualification=qualification,
        )


def test_manifest_rejects_truncated_serialized_reasoning_route_inventory() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})
    payload = validation.as_dict()
    model_bindings = payload["model_bindings"]
    assert isinstance(model_bindings, list)
    reasoning_bindings = model_bindings[0]["reasoning_bindings"]
    assert isinstance(reasoning_bindings, list)
    reasoning_bindings.pop()
    _reseal_qualification_validation(payload)

    with pytest.raises(ValueError, match=r"reasoning.*routes|opaque runtime authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=payload,
            production_qualification=qualification,
        )


@pytest.mark.parametrize(
    "field",
    [
        "reasoning_policy_artifact_sha256",
        "reasoning_policy_role_binding_sha256",
        "endpoint_reasoning_capability_sha256",
    ],
)
def test_manifest_rejects_resealed_nested_reasoning_authority_tamper(
    field: str,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    validation = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        required=True,
        now=observed_at,
    )
    usage = _qualified_reasoning_usage(
        config,
        qualification,
        observed_at=observed_at,
    )
    report = _report(config).model_copy(update={"usage": [usage]})
    payload = validation.as_dict()
    model_bindings = payload["model_bindings"]
    assert isinstance(model_bindings, list)
    reasoning_bindings = model_bindings[0]["reasoning_bindings"]
    assert isinstance(reasoning_bindings, list)
    route = reasoning_bindings[0]
    assert isinstance(route, dict)
    route[field] = "f" * 64
    route["binding_sha256"] = canonical_sha256(
        {key: value for key, value in route.items() if key != "binding_sha256"}
    )
    _reseal_qualification_validation(payload)

    with pytest.raises(ValueError, match="opaque runtime authority"):
        _model_bindings(
            config,
            report,
            qualification_runtime=payload,
            production_qualification=qualification,
        )


def test_manifest_rejects_linked_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")
    try:
        (run_dir / "linked.json").symlink_to(outside)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="links"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=config,
        )


def test_manifest_bound_artifacts_propagate_consumer_abort_and_close_descriptors(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ConsumerAbort(BaseException):
        pass

    config = config_factory()
    report = _report(config)
    run_dir = tmp_path / report.run_id
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)

    original_open = os.open
    original_close = os.close
    original_fstat = os.fstat
    opened_descriptors: list[int] = []
    closed_descriptors: list[int] = []
    fstat_descriptors: list[int] = []

    def observed_open(path: os.PathLike[str] | str, flags: int, mode: int = 0o777) -> int:
        descriptor = original_open(path, flags, mode)
        opened_descriptors.append(descriptor)
        return descriptor

    def observed_close(descriptor: int) -> None:
        closed_descriptors.append(descriptor)
        original_close(descriptor)

    def observed_fstat(descriptor: int) -> os.stat_result:
        fstat_descriptors.append(descriptor)
        return original_fstat(descriptor)

    monkeypatch.setattr(manifest_module.os, "open", observed_open)
    monkeypatch.setattr(manifest_module.os, "close", observed_close)
    monkeypatch.setattr(manifest_module.os, "fstat", observed_fstat)

    names = ("metadata.json", "final-findings.json")
    sentinel = ConsumerAbort("synthetic consumer abort")
    with (
        pytest.raises(ConsumerAbort) as raised,
        open_manifest_bound_json_artifacts(run_dir, names) as payloads,
    ):
        assert set(payloads) == set(names)
        raise sentinel

    assert raised.value is sentinel
    assert len(opened_descriptors) == 3
    assert len(set(opened_descriptors)) == 3
    assert closed_descriptors == list(reversed(opened_descriptors))
    assert all(fstat_descriptors.count(descriptor) == 3 for descriptor in opened_descriptors)
    for descriptor in opened_descriptors:
        with pytest.raises(OSError) as closed:
            original_fstat(descriptor)
        assert closed.value.errno == errno.EBADF


def test_manifest_file_bindings_reject_sensitive_paths() -> None:
    with pytest.raises(ValidationError, match="identify a file"):
        ManifestFileBinding(path=".env", sha256="a" * 64, size=1)


def test_published_manifest_schema_is_strict_and_bounded() -> None:
    schema_path = (
        Path(__file__).resolve().parents[2] / "schemas" / ("run_evidence_manifest.schema.json")
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["additionalProperties"] is False
    assert schema["properties"]["artifacts"]["maxItems"] == 100_000
    assert schema["$defs"]["fileBinding"]["additionalProperties"] is False
    assert schema["$defs"]["hashBinding"]["additionalProperties"] is False
    assert schema["$defs"]["bindingSet"]["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["enum"] == ["1.0", "1.1", "1.2"]
    expected_profiles = {"quick", "standard", "deep", "maximum-assurance"}
    assert (
        set(schema["$defs"]["runConfiguration"]["properties"]["requested_profile"]["enum"])
        == expected_profiles
    )
    achieved_profile = schema["$defs"]["runConfiguration"]["properties"]["achieved_profile"]
    assert set(achieved_profile["anyOf"][0]["enum"]) == expected_profiles
    assert schema["$defs"]["runConfiguration"]["additionalProperties"] is False
    assert set(schema["$defs"]["runConfiguration"]["required"]) == set(
        RunConfigurationBinding.model_fields
    )
    assert schema["$defs"]["auditConfigOverride"]["additionalProperties"] is False
    assert schema["$defs"]["auditConfigOverrides"]["additionalProperties"] is False
    assert schema["$defs"]["auditRunOptions"]["additionalProperties"] is False
    assert set(schema["$defs"]["auditConfigOverride"]["required"]) == set(
        AuditConfigOverride.model_fields
    )
    assert set(schema["$defs"]["auditConfigOverrides"]["required"]) == set(
        AuditConfigOverrides.model_fields
    )
    assert set(schema["$defs"]["auditRunOptions"]["required"]) == set(AuditRunOptions.model_fields)
    assert set(schema["$defs"]["auditConfigOverride"]["properties"]["path"]["enum"]) == set(
        _AUDIT_OVERRIDE_PATHS
    )
    assert schema["$defs"]["auditConfigOverrides"]["properties"]["entries"]["maxItems"] == len(
        _AUDIT_OVERRIDE_PATHS
    )
    override_variants = schema["$defs"]["auditConfigOverride"]["oneOf"]
    schema_paths_by_type = {
        variant["properties"]["value"]["type"]: set(variant["properties"]["path"]["enum"])
        for variant in override_variants
    }
    expected_paths_by_type = {
        "boolean": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (bool,)
        },
        "integer": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (int,)
        },
        "number": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (float,)
        },
        "string": {
            path
            for path, value_types in _AUDIT_OVERRIDE_VALUE_TYPES.items()
            if value_types == (str,)
        },
    }
    assert schema_paths_by_type == expected_paths_by_type
    assert set().union(*schema_paths_by_type.values()) == set(_AUDIT_OVERRIDE_PATHS)
    serialized_schema = json.dumps(schema, sort_keys=True)
    assert "OPENROUTER_API_KEY" not in serialized_schema
    assert "MMAUDIT_SECRETS_ENV_FILE" not in serialized_schema

    compatibility = schema["allOf"]
    legacy_rule = next(
        rule
        for rule in compatibility
        if rule["if"]["properties"]["schema_version"].get("const") == "1.0"
    )
    current_rule = next(
        rule
        for rule in compatibility
        if set(rule["if"]["properties"]["schema_version"].get("enum", [])) == {"1.1", "1.2"}
    )
    report_bundle_rule = next(
        rule
        for rule in compatibility
        if rule["if"]["properties"]["schema_version"].get("const") == "1.2"
    )
    assert legacy_rule["then"]["properties"]["run_configuration"] == {"type": "null"}
    assert "run_configuration" in current_rule["then"]["required"]
    assert current_rule["then"]["properties"]["run_configuration"] == {
        "$ref": "#/$defs/runConfiguration"
    }
    report_bundle_contracts = report_bundle_rule["then"]["properties"]["artifacts"]["allOf"]
    assert {
        contract["contains"]["properties"]["path"]["const"] for contract in report_bundle_contracts
    } == MANIFEST_BOUND_REPORT_DELIVERABLES | {RUN_TERMINAL_REPORT_AUTHORITY_PATH}
    assert all(
        contract["minContains"] == contract["maxContains"] == 1
        for contract in report_bundle_contracts
    )


def test_manifest_loader_rejects_duplicate_json_keys(tmp_path: Path, config_factory) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    report = _report(config)
    _write_required_artifacts(run_dir, report)
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
    )
    path = run_dir / "run-evidence-manifest.json"
    write_run_evidence_manifest(path, manifest)
    duplicate = path.read_text(encoding="utf-8").replace(
        "{",
        '{"schema_version":"1.1",',
        1,
    )
    path.write_text(duplicate, encoding="utf-8")

    with pytest.raises(ValueError, match="duplicate keys"):
        load_run_evidence_manifest(path)


def test_verify_run_is_current_and_serializes_deterministically(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository, run_dir, manifest, _ = _write_verifiable_run(tmp_path, config)

    first = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )
    second = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert first == second
    assert first.status is RunVerificationStatus.CURRENT
    assert not first.mismatches
    assert first.manifest_sha256 == manifest.manifest_sha256
    assert RunVerification.model_validate_json(first.model_dump_json()) == first

    tampered = first.model_dump(mode="json")
    tampered["status"] = RunVerificationStatus.STALE
    with pytest.raises(ValidationError, match="inconsistent"):
        RunVerification.model_validate(tampered)


def test_verify_run_reconstructs_an_already_sealed_schema_1_1_manifest(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository, run_dir, current, report = _write_verifiable_run(tmp_path, config)
    legacy = _rewrite_as_sealed_schema_1_1(run_dir, current, report)

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert legacy.schema_version == "1.1"
    assert verification.status is RunVerificationStatus.CURRENT
    assert not verification.mismatches


def test_legacy_rebuild_requires_the_exact_on_disk_sealed_manifest(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    _repository, run_dir, current, report = _write_verifiable_run(tmp_path, config)
    legacy = _rewrite_as_sealed_schema_1_1(run_dir, current, report)
    (run_dir / "run-evidence-manifest.json").unlink()

    with pytest.raises(ValueError, match=r"run-evidence-manifest\.json"):
        rebuild_run_evidence_manifest_for_verification(
            run_dir=run_dir,
            report=report,
            config=config,
            sealed_manifest=legacy,
        )


def test_rebuild_rejects_a_different_in_memory_manifest_than_the_sealed_file(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    _repository, run_dir, current, report = _write_verifiable_run(tmp_path, config)
    assert current.run_configuration is not None
    different = seal_run_evidence_manifest(
        run_id=current.run_id,
        repository_root_name=current.repository_root_name,
        git_commit=current.git_commit,
        sources=current.sources,
        run_configuration=current.run_configuration,
        bindings=current.bindings,
        artifacts=current.artifacts,
        tool_version=f"{current.tool_version}-different",
    )

    with pytest.raises(ValueError, match="differs from the exact sealed on-disk manifest"):
        rebuild_run_evidence_manifest_for_verification(
            run_dir=run_dir,
            report=report,
            config=config,
            sealed_manifest=different,
        )


def test_verify_run_checks_sealed_qualified_evidence_without_recreating_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest.validate_report_privacy_consistency",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._validated_context_manifest",
        lambda *_args, **_kwargs: None,
    )
    config, repository, run_dir, manifest, report = _write_qualified_verifiable_run(tmp_path)
    observed_manifest = rebuild_run_evidence_manifest_for_verification(
        run_dir=run_dir,
        report=report,
        config=config,
        sealed_manifest=manifest,
    )
    assert observed_manifest.bindings.models == manifest.bindings.models
    rebuild_errors: list[Exception] = []

    def capture_rebuild_error(**kwargs):
        try:
            return rebuild_run_evidence_manifest_for_verification(**kwargs)
        except Exception as exc:
            rebuild_errors.append(exc)
            raise

    monkeypatch.setattr(
        "mmaudit.orchestration.verification.rebuild_run_evidence_manifest_for_verification",
        capture_rebuild_error,
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert not rebuild_errors, rebuild_errors
    assert verification.status is RunVerificationStatus.CURRENT, [
        (item.category.value, item.identifier, item.kind.value) for item in verification.mismatches
    ]
    assert not verification.mismatches
    assert verification.manifest_sha256 == manifest.manifest_sha256


@pytest.mark.parametrize(
    "tamper",
    ["report_cost_projection", "qualification_route", "manifest_authority"],
)
def test_verify_run_rejects_resealed_qualified_evidence_tamper(
    tmp_path: Path,
    tamper: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest.validate_report_privacy_consistency",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._validated_context_manifest",
        lambda *_args, **_kwargs: None,
    )
    config, repository, run_dir, manifest, _ = _write_qualified_verifiable_run(tmp_path)
    manifest_payload = manifest.model_dump(mode="json")

    if tamper == "report_cost_projection":
        report_path = run_dir / "final-findings.json"
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        report_payload["accounted_cost_usd"] = 1
        report_path.write_text(
            json.dumps(report_payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        artifact_name = report_path.name
    elif tamper == "qualification_route":
        qualification_path = run_dir / "model-qualification-runtime.json"
        qualification_payload = json.loads(qualification_path.read_text(encoding="utf-8"))
        route = qualification_payload["model_bindings"][0]["reasoning_bindings"][0]
        route["reasoning_benchmark_report_sha256"] = "9" * 64
        route["binding_sha256"] = canonical_sha256(
            {key: value for key, value in route.items() if key != "binding_sha256"}
        )
        qualification_payload["validation_sha256"] = canonical_sha256(
            {
                key: value
                for key, value in qualification_payload.items()
                if key != "validation_sha256"
            }
        )
        qualification_path.write_text(
            json.dumps(qualification_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        artifact_name = qualification_path.name
    else:
        opaque = next(
            binding
            for binding in manifest_payload["bindings"]["models"]
            if binding["identifier"] == "qualification/opaque-authority"
        )
        opaque["sha256"] = "8" * 64
        artifact_name = None

    if artifact_name is not None:
        artifact_path = run_dir / artifact_name
        artifact_bytes = artifact_path.read_bytes()
        artifact = next(
            binding for binding in manifest_payload["artifacts"] if binding["path"] == artifact_name
        )
        artifact["sha256"] = hashlib.sha256(artifact_bytes).hexdigest()
        artifact["size"] = len(artifact_bytes)
    manifest_payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in manifest_payload.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(manifest_payload),
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=config,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert any(
        mismatch.identifier == "bindings/recalculation"
        or mismatch.category is RunVerificationCategory.MODEL
        for mismatch in verification.mismatches
    )


def test_verify_run_rejects_report_configuration_identity_resealed_into_manifest(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    repository, run_dir, manifest, report = _write_verifiable_run(tmp_path, config)
    tampered_report = report.model_copy(
        update={
            "configuration_hash": "d" * 64,
            "model_configuration_hash": "e" * 64,
        }
    )
    report_bytes = tampered_report.model_dump_json().encode("utf-8")
    (run_dir / "final-findings.json").write_bytes(report_bytes)

    resealed = manifest.model_dump(mode="json")
    for artifact in resealed["artifacts"]:
        if artifact["path"] == "final-findings.json":
            artifact["sha256"] = hashlib.sha256(report_bytes).hexdigest()
            artifact["size"] = len(report_bytes)
    resealed["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in resealed.items() if key != "manifest_sha256"}
    )
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(resealed),
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert {
        mismatch.identifier
        for mismatch in verification.mismatches
        if mismatch.category is RunVerificationCategory.CONFIGURATION
    } >= {
        "report/configuration-hash",
        "report/model-configuration-hash",
    }


def test_verify_run_detects_every_security_relevant_drift_category(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    repository, run_dir, current, report = _write_verifiable_run(tmp_path, config)
    _rewrite_as_sealed_schema_1_1(run_dir, current, report)
    (repository / "src" / "Vault.sol").write_text(
        "contract Vault { function changed() external {} }\n",
        encoding="utf-8",
    )
    (run_dir / "solidity-compilation.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "results": [
                    {
                        "framework": "foundry",
                        "project_root": ".",
                        "status": "passed",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (run_dir / "benchmark-certificate-verification.json").write_text(
        '{"schema_version":"1.0","status":"stale"}\n',
        encoding="utf-8",
    )
    changed_role = config.models.threat_model.model_copy(
        update={"primary": config.models.source_audit.primary}
    )
    changed_config = config.model_copy(
        update={"models": config.models.model_copy(update={"threat_model": changed_role})}
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._prompt_bindings",
        lambda _report: [
            ManifestHashBinding(
                identifier="template/synthetic-changed.md",
                sha256="d" * 64,
            )
        ],
    )
    monkeypatch.setattr(
        "mmaudit.orchestration.manifest._tool_bindings",
        lambda _config, _report: [
            ManifestHashBinding(
                identifier="configured/changed-tool",
                sha256="e" * 64,
            )
        ],
    )
    original_rebuild = rebuild_run_evidence_manifest_for_verification
    rebuild_errors: list[Exception] = []

    def capture_rebuild_error(**kwargs):
        try:
            return original_rebuild(**kwargs)
        except Exception as exc:
            rebuild_errors.append(exc)
            raise

    monkeypatch.setattr(
        "mmaudit.orchestration.verification.rebuild_run_evidence_manifest_for_verification",
        capture_rebuild_error,
    )

    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=repository,
        config=changed_config,
    )

    assert verification.status is RunVerificationStatus.STALE
    assert not rebuild_errors, rebuild_errors
    categories = {mismatch.category for mismatch in verification.mismatches}
    assert categories >= {
        RunVerificationCategory.SOURCE,
        RunVerificationCategory.CONFIGURATION,
        RunVerificationCategory.PROMPT,
        RunVerificationCategory.MODEL,
        RunVerificationCategory.TOOL,
        RunVerificationCategory.COMPILER,
        RunVerificationCategory.ARTIFACT,
        RunVerificationCategory.CERTIFICATE,
    }
    assert all(
        mismatch.kind
        in {
            RunVerificationMismatchKind.CHANGED,
            RunVerificationMismatchKind.MISSING,
            RunVerificationMismatchKind.UNEXPECTED,
        }
        for mismatch in verification.mismatches
    )


def test_verify_run_cli_clean_tampered_and_missing_artifact(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    config = config_factory()
    monkeypatch.setattr(
        "mmaudit.cli.load_config_with_provenance",
        lambda _path, **_kwargs: LoadedAuditConfig(
            file_config=config,
            environment_overrides=AuditConfigOverrides(),
            effective_config=config,
        ),
    )

    clean_repository, clean_run, _, _ = _write_verifiable_run(
        tmp_path / "clean",
        config,
    )
    clean_output = tmp_path / "clean-verification.json"
    clean = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(clean_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(clean_run),
            "--repo",
            str(clean_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(clean_output),
            "--no-color",
        ],
    )
    assert clean.exit_code == ExitCode.SUCCESS
    assert (
        RunVerification.model_validate_json(clean_output.read_text(encoding="utf-8")).status
        is RunVerificationStatus.CURRENT
    )

    changed_repository, changed_run, _, _ = _write_verifiable_run(
        tmp_path / "changed",
        config,
    )
    (changed_repository / "src" / "Vault.sol").write_text(
        "contract Vault { function changed() external {} }\n",
        encoding="utf-8",
    )
    changed_output = tmp_path / "changed-verification.json"
    changed = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(changed_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(changed_run),
            "--repo",
            str(changed_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(changed_output),
            "--no-color",
        ],
    )
    assert changed.exit_code == ExitCode.INCOMPLETE
    assert (
        RunVerification.model_validate_json(changed_output.read_text(encoding="utf-8")).status
        is RunVerificationStatus.STALE
    )

    missing_repository, missing_run, _, _ = _write_verifiable_run(
        tmp_path / "missing",
        config,
    )
    (missing_run / "scope-assessment.json").unlink()
    missing_output = tmp_path / "missing-verification.json"
    missing = runner.invoke(
        app,
        [
            "verify-run",
            "--manifest",
            str(missing_run / "run-evidence-manifest.json"),
            "--run-dir",
            str(missing_run),
            "--repo",
            str(missing_repository),
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--output",
            str(missing_output),
            "--no-color",
        ],
    )
    assert missing.exit_code == ExitCode.INCOMPLETE
    missing_verification = RunVerification.model_validate_json(
        missing_output.read_text(encoding="utf-8")
    )
    assert any(
        mismatch.identifier == "scope-assessment.json"
        and mismatch.kind is RunVerificationMismatchKind.MISSING
        for mismatch in missing_verification.mismatches
    )


def test_published_run_verification_schema_is_strict_and_bounded() -> None:
    schema = json.loads(
        (
            Path(__file__).resolve().parents[2] / "schemas" / "run_verification.schema.json"
        ).read_text(encoding="utf-8")
    )

    assert schema["additionalProperties"] is False
    assert schema["properties"]["mismatches"]["maxItems"] == 200_000
    assert schema["$defs"]["mismatch"]["additionalProperties"] is False
    assert schema["properties"]["verification_sha256"] == {"$ref": "#/$defs/sha256"}
