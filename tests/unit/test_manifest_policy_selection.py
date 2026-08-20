from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig
from mmaudit.constants import ANALYSIS_ROLES
from mmaudit.models.policy_eligibility import PolicyExclusionReason
from mmaudit.models.policy_selection import (
    AuditModelSelectionEvidenceBundle,
    VerifiedAuditModelSelection,
)
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.registry import ModelRegistry
from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    LanguageCapabilityArtifact,
    LanguageCapabilityFileEvidence,
    PropertyCorpus,
    RepositoryFile,
    UsageRecord,
)
from mmaudit.orchestration.coverage import generic_source_coverage_metrics
from mmaudit.orchestration.manifest import (
    AUDIT_MODEL_REFRESH_BINDING_IDS,
    AUDIT_MODEL_REFRESH_EVIDENCE_PATH,
    AUDIT_MODEL_SELECTION_BINDING_IDS,
    AUDIT_MODEL_SELECTION_EVIDENCE_PATH,
    ManifestFileBinding,
    RunEvidenceManifest,
    _audit_model_selection_bindings,
    build_run_evidence_manifest,
    canonical_sha256,
    collect_run_artifacts,
    seal_run_evidence_manifest,
    validate_manifest_artifacts,
)
from mmaudit.orchestration.run_status import (
    assess_minimum_analysis_floor,
    audit_quality_status_for_run_status,
    minimum_analysis_floor_quality_gate,
)
from mmaudit.privacy import PrivacyProfile, PrivacySourceClassification
from mmaudit.reporting.bundle import (
    ModelExecutionArtifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.markdown import render_forensic_markdown
from tests.language_capability_support import (
    language_capability_for_files,
)
from tests.qualification_support import synthetic_production_qualification
from tests.refresh_runtime_support import (
    SyntheticRefreshRuntime,
    _candidate_registry,
    bind_usage_to_refresh_pricing_runtime,
    bind_usage_to_refresh_runtime,
    synthetic_refresh_runtime_for_authorities,
)
from tests.unit.test_manifest import _report, _write_required_artifacts
from tests.unit.test_model_policy_selection import (
    BASE_TIME,
    _policy_authority,
    _policy_bundle,
    _resolve,
)
from tests.unit.test_pipeline_policy_selection import _selection_config
from tests.unit.test_usage import _creditable_record, _token_plan_for_record


@dataclass(frozen=True)
class _PolicyManifestFixture:
    config: AuditConfig
    report: AuditReport
    evidence: AuditModelSelectionEvidenceBundle
    capability: VerifiedAuditModelSelection
    technical: VerifiedProductionQualification
    refresh: SyntheticRefreshRuntime
    qualification_runtime: dict[str, object]
    manifest: RunEvidenceManifest
    run_dir: Path


def _policy_config() -> AuditConfig:
    payload = _selection_config().model_dump(mode="json")
    payload["models"]["provider_policy"]["only"] = ["openrouter/provider-a"]
    return AuditConfig.model_validate(payload)


def _current_report(
    config: AuditConfig,
    *,
    selection: object | None = None,
    refresh: object | None = None,
    refresh_pricing: object | None = None,
    usage: list[UsageRecord] | None = None,
) -> tuple[AuditReport, LanguageCapabilityArtifact, PropertyCorpus]:
    records = [] if usage is None else usage
    base = _report(config)
    content = b"def safe():\n    return True\n"
    source = RepositoryFile(
        path="src/safe.py",
        size=len(content),
        lines=2,
        sha256=hashlib.sha256(content).hexdigest(),
        language="Python",
    )
    repository = base.repository.model_copy(
        update={
            "languages": {"Python": 1},
            "frameworks": [],
            "manifests": ["pyproject.toml"],
            "configuration_files": ["pyproject.toml"],
            "files": [source],
        }
    )
    language_file = LanguageCapabilityFileEvidence(
        path=source.path,
        size=source.size,
        lines=source.lines,
        sha256=source.sha256,
        language=source.language,
    )
    language = language_capability_for_files(
        config.language_profile,
        (language_file,),
        solidity_project_count=0,
    )
    coverage = generic_source_coverage_metrics(
        repository,
        [],
        require_scanner_completion=False,
    )
    floor = assess_minimum_analysis_floor(
        repository=repository,
        compilations=[],
        scanner_runs=[],
        usage=records,
        required_model_roles=ANALYSIS_ROLES,
        coverage_metrics=coverage,
        solidity_applicable=False,
        static_analysis_applicable=False,
        scanner_only=False,
        surface_analysis_feasible=True,
    )
    empty_corpus = PropertyCorpus(
        properties=[],
        limitations=[],
        corpus_hash=canonical_sha256(
            {
                "schema_version": "1.0",
                "property_hashes": [],
                "limitations": [],
            }
        ),
    )
    payload = base.model_dump(mode="python")
    payload.update(
        schema_version="1.2",
        run_id="policy-manifest-run",
        generated_at=BASE_TIME + timedelta(hours=2),
        completed=False,
        incomplete_reasons=floor.limitations,
        quality_status=audit_quality_status_for_run_status(floor.run_status),
        run_status=floor.run_status,
        minimum_analysis_floor=floor,
        quality_gates=[minimum_analysis_floor_quality_gate(floor)],
        repository=repository,
        language_capability=language.assessment,
        solidity_coverage=None,
        usage=records,
        accounted_cost_usd=sum(record.accounted_cost_usd for record in records),
        accounted_cost_usd_exact="0",
    )
    if selection is not None:
        payload["audit_model_selection"] = selection
    if refresh is not None:
        payload["audit_model_refresh_evidence"] = refresh
    if refresh_pricing is not None:
        payload["audit_model_refresh_pricing_evidence"] = refresh_pricing
    payload["metadata"] = {
        **base.metadata,
        "scanner_only": False,
        "solidity": {
            "projects": [],
            "compilation": [],
            "index_summary": {"entities": 0, "ast_sources": 0, "fallback_sources": 0},
            "graph_summary": {"edges": 0, "warnings": 0},
            "property_corpus_summary": {
                "properties": 0,
                "limitations": 0,
                "corpus_hash": empty_corpus.corpus_hash,
            },
        },
    }
    return AuditReport.model_validate(payload), language, empty_corpus


def _write_current_artifact_shapes(
    run_dir: Path,
    *,
    corpus: PropertyCorpus,
) -> None:
    payloads = {
        "solidity-projects.json": {"schema_version": "1.0", "projects": []},
        "solidity-index.json": {"schema_version": "1.0", "index": None},
        "solidity-graphs.json": {"schema_version": "1.0", "graphs": None},
        "solidity-shards.json": {"schema_version": "1.0", "inventory": None},
        "solidity-invariants.json": {"schema_version": "1.0", "invariants": None},
        "invariant-harness-plan.json": {"schema_version": "1.0", "harnesses": []},
        "property-corpus.json": {
            "schema_version": "1.0",
            "corpus": corpus.model_dump(mode="json"),
        },
        "invariant-execution-results.json": {
            "schema_version": "1.0",
            "harnesses": [],
            "results": [],
        },
        "formal-results.json": {
            "schema_version": "1.0",
            "runs": [],
            "dynamic_engine_comparisons": [],
        },
        "invariant-review.json": {"schema_version": "1.0", "review": None},
        "economic-simulation-plan.json": {"schema_version": "1.0", "templates": []},
        "execution-origin-dispositions.json": {
            "schema_version": "1.0",
            "dispositions": [],
        },
    }
    for name, payload in payloads.items():
        (run_dir / name).write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


@pytest.fixture(scope="module")
def policy_manifest_fixture(tmp_path_factory: pytest.TempPathFactory) -> _PolicyManifestFixture:
    root = tmp_path_factory.mktemp("policy-manifest")
    config = _policy_config()
    unselected, _language, _corpus = _current_report(config)
    source_sha256 = canonical_sha256(
        [
            ManifestFileBinding(path=item.path, sha256=item.sha256, size=item.size).model_dump(
                mode="json"
            )
            for item in unselected.repository.files
        ]
    )
    model_ids = tuple(sorted(entry.canonical_model_id for entry in config.models.registry))
    candidate_registry = _candidate_registry(
        config=config,
        model_ids=model_ids,
        roots=tuple(sorted(config.privacy.approved_model_lineages)),
        created_at=BASE_TIME,
        provider_endpoint="openrouter/provider-a",
    )
    technical = synthetic_production_qualification(
        config,
        BASE_TIME,
        candidate_registry=candidate_registry,
    )
    excluded_id = technical.models[-1].exact_model_id
    policy = _policy_bundle(
        technical,
        excluded_ids=frozenset({excluded_id}),
        source_sha256_override=source_sha256,
    )
    authority = _policy_authority(root / "authority", policy)
    selection, evidence, capability = _resolve(technical, policy, authority)
    refresh = synthetic_refresh_runtime_for_authorities(
        config=config,
        candidate_registry=candidate_registry,
        technical_qualification=technical,
        audit_selection_evidence=evidence,
        audit_selection=capability,
        verified_at=capability.selected_at,
    )
    report, language, corpus = _current_report(
        config,
        selection=selection,
        refresh=refresh.evidence,
    )
    run_dir = root / "run"
    _write_required_artifacts(run_dir, report, language_artifact=language)
    _write_current_artifact_shapes(run_dir, corpus=corpus)
    (run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_PATH).write_text(
        evidence.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    (run_dir / AUDIT_MODEL_REFRESH_EVIDENCE_PATH).write_text(
        refresh.evidence.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    qualification = ModelRegistry.validate_production_qualification(
        config,
        technical,
        required=True,
        now=BASE_TIME,
    )
    assert qualification.valid
    qualification_runtime = qualification.as_dict()
    (run_dir / "model-qualification-runtime.json").write_text(
        json.dumps(qualification_runtime, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = build_run_evidence_manifest(
        run_dir=run_dir,
        report=report,
        config=config,
        production_qualification=technical,
    )
    validate_manifest_artifacts(manifest, run_dir)
    return _PolicyManifestFixture(
        config=config,
        report=report,
        evidence=evidence,
        capability=capability,
        technical=technical,
        refresh=refresh,
        qualification_runtime=qualification_runtime,
        manifest=manifest,
        run_dir=run_dir,
    )


def _copied_run(
    tmp_path: Path,
    fixture: _PolicyManifestFixture,
) -> tuple[Path, RunEvidenceManifest]:
    run_dir = tmp_path / "run"
    shutil.copytree(fixture.run_dir, run_dir)
    return run_dir, fixture.manifest


def _paid_usage(
    fixture: _PolicyManifestFixture,
    *,
    requested_index: int = 0,
    routed_index: int = 0,
) -> UsageRecord:
    selection = fixture.evidence.selection
    requested = selection.models[requested_index]
    routed = selection.models[routed_index]
    now = fixture.refresh.evidence.verified_at + timedelta(minutes=1)
    evidence = fixture.capability.routing_evidence(
        routed.exact_model_id,
        now=now,
        expected_audit_scope_sha256=selection.audit_scope_sha256,
        expected_source_sha256=selection.source_sha256,
        expected_audit_context_sha256=selection.audit_context_sha256,
        expected_client_constraints_sha256=selection.client_constraints_sha256,
    )
    routing: dict[str, object] = dict(evidence.request_metadata())
    routing_sha256 = routing.pop("routing_evidence_sha256")
    routing.update(
        {
            "audit_policy_routing_evidence_sha256": routing_sha256,
            "audit_selection_capability_sha256": fixture.capability.capability_sha256,
            "audit_model_routing_evidence": evidence.model_dump(mode="json"),
            "endpoint_snapshot_sha256": routed.endpoint_snapshot_sha256,
        }
    )
    record = UsageRecord(
        request_id=f"paid-audit-{requested_index}-{routed_index}",
        role="source_audit",
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=requested.exact_model_id,
        returned_model=routed.canonical_model_slug,
        actual_model=routed.canonical_model_slug,
        provider=routed.approved_provider_name,
        model_family=requested.exact_model_id,
        timestamp=now,
        prompt_tokens=1,
        completion_tokens=1,
        total_tokens=2,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        routing=routing,
        prompt_sha256="a" * 64,
        configured_provider_endpoints=[routed.approved_provider_endpoint],
        actual_provider_endpoint=routed.approved_provider_endpoint,
        started_at=now,
        ended_at=now,
        latency_ms=0,
        retry_count=0,
        request_body_sha256="b" * 64,
        reported_cost_usd_exact="0",
        accounted_cost_usd_exact="0",
        status="success",
        attempts=1,
    )
    return bind_usage_to_refresh_pricing_runtime(
        bind_usage_to_refresh_runtime(record, fixture.refresh),
        fixture.refresh,
    )


def test_manifest_retains_first_class_non_authorizing_policy_selection_custody(
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    fixture = policy_manifest_fixture
    validate_manifest_artifacts(fixture.manifest, fixture.run_dir)
    selection = fixture.evidence.selection
    model_execution = ModelExecutionArtifact.model_validate_json(
        (fixture.run_dir / "model-execution.json").read_text(encoding="utf-8")
    )
    artifacts = {binding.path: binding for binding in fixture.manifest.artifacts}
    bindings = {
        binding.identifier: binding
        for binding in fixture.manifest.bindings.models
        if binding.identifier in AUDIT_MODEL_SELECTION_BINDING_IDS
    }

    assert AUDIT_MODEL_SELECTION_EVIDENCE_PATH in artifacts
    assert set(bindings) == AUDIT_MODEL_SELECTION_BINDING_IDS
    assert fixture.report.audit_model_selection == selection
    assert model_execution.audit_model_selection == selection
    assert len(selection.technical_model_ids) == 9
    assert len(selection.selected_model_ids) == 8
    assert len(selection.policy_excluded_model_ids) == 1
    assert selection.policy_exclusions[0].reasons == (PolicyExclusionReason.DECISION_INELIGIBLE,)
    assert all(
        binding.details["authority"] == "structural_hash_custody"
        and binding.details["external_comparison_required"] == "true"
        and binding.details["technical_tier_a_models"] == "9"
        and binding.details["policy_selected_models"] == "8"
        and binding.details["policy_excluded_models"] == "1"
        for binding in bindings.values()
    )


def test_client_and_forensic_reports_distinguish_technical_and_policy_populations(
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    report = policy_manifest_fixture.report
    selection = policy_manifest_fixture.evidence.selection
    rendered_reports = (
        render_client_markdown(report, {}),
        render_forensic_markdown(report),
    )

    for rendered in rendered_reports:
        assert "NON-AUTHORIZING CUSTODY" in rendered
        assert "Technically qualified Tier-A population: **9**" in rendered
        assert "Policy-selected models for this audit: **8**" in rendered
        assert "Policy-excluded technical models: **1**" in rendered
        assert selection.policy_excluded_model_ids[0] in rendered
        assert PolicyExclusionReason.DECISION_INELIGIBLE.value.replace("_", "\\_") in rendered
    assert AUDIT_MODEL_SELECTION_EVIDENCE_PATH in rendered_reports[0]


def test_report_rejects_policy_selection_on_legacy_schema(
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    payload = policy_manifest_fixture.report.model_dump(mode="json")
    payload["schema_version"] = "1.1"
    payload["run_status"] = None
    payload["minimum_analysis_floor"] = None

    with pytest.raises(ValidationError, match=r"requires report schema 1\.2"):
        AuditReport.model_validate(payload)

    model_execution = json.loads(
        (policy_manifest_fixture.run_dir / "model-execution.json").read_text(encoding="utf-8")
    )
    model_execution["schema_version"] = "1.1"
    model_execution.pop("language_capability")
    with pytest.raises(ValidationError, match="legacy model-execution evidence"):
        ModelExecutionArtifact.model_validate(model_execution)


def test_manifest_rejects_tampered_policy_bundle_bytes(
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    run_dir, manifest = _copied_run(tmp_path, policy_manifest_fixture)
    path = run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_PATH
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["selection"]["source_sha256"] = "f" * 64
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="artifact hash mismatch"):
        validate_manifest_artifacts(manifest, run_dir)


def test_manifest_rejects_coherently_resealed_missing_policy_bundle(
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    run_dir, manifest = _copied_run(tmp_path, policy_manifest_fixture)
    (run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_PATH).unlink()
    (run_dir / AUDIT_MODEL_REFRESH_EVIDENCE_PATH).unlink()
    retained_models = [
        binding
        for binding in manifest.bindings.models
        if binding.identifier
        not in AUDIT_MODEL_SELECTION_BINDING_IDS | AUDIT_MODEL_REFRESH_BINDING_IDS
    ]
    bindings = manifest.bindings.model_copy(update={"models": retained_models})
    assert manifest.run_configuration is not None
    resealed = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )

    with pytest.raises(ValueError, match="presence differs from the final report"):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_rejects_coherently_resealed_swapped_policy_bundle(
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    fixture = policy_manifest_fixture
    run_dir, manifest = _copied_run(tmp_path, fixture)
    excluded_id = fixture.technical.models[-1].exact_model_id
    swapped_policy = _policy_bundle(
        fixture.technical,
        excluded_ids=frozenset({excluded_id}),
        context_tag="swapped",
        source_sha256_override=fixture.evidence.selection.source_sha256,
    )
    authority = _policy_authority(tmp_path / "swapped-authority", swapped_policy)
    _selection, swapped, _capability = _resolve(
        fixture.technical,
        swapped_policy,
        authority,
    )
    (run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_PATH).write_text(
        swapped.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    retained_models = [
        binding
        for binding in manifest.bindings.models
        if binding.identifier not in AUDIT_MODEL_SELECTION_BINDING_IDS
    ]
    retained_models.extend(_audit_model_selection_bindings(root=run_dir, evidence=swapped))
    retained_models.sort(key=lambda binding: binding.identifier)
    bindings = manifest.bindings.model_copy(update={"models": retained_models})
    assert manifest.run_configuration is not None
    resealed = seal_run_evidence_manifest(
        run_id=manifest.run_id,
        repository_root_name=manifest.repository_root_name,
        git_commit=manifest.git_commit,
        sources=manifest.sources,
        run_configuration=manifest.run_configuration,
        bindings=bindings,
        artifacts=collect_run_artifacts(run_dir),
        tool_version=manifest.tool_version,
    )

    with pytest.raises(ValueError, match="bundle differs from the final report"):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_rejects_resealed_technical_vs_policy_hash_drift(
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    run_dir, manifest = _copied_run(tmp_path, policy_manifest_fixture)
    payload = json.loads((run_dir / "model-qualification-runtime.json").read_text(encoding="utf-8"))
    payload["production_selection_sha256"] = "f" * 64
    payload["validation_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "validation_sha256"}
    )
    (run_dir / "model-qualification-runtime.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
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

    with pytest.raises(
        ValueError,
        match="differs from technical qualification runtime evidence",
    ):
        validate_manifest_artifacts(resealed, run_dir)


@pytest.mark.parametrize(
    ("population", "field_name", "field_value", "expected_error"),
    (
        (
            "selected",
            "overall_score",
            0.123456,
            "policy-selected model differs from technical qualification runtime evidence",
        ),
        (
            "excluded",
            "approved_provider_endpoint",
            "openrouter/changed-provider",
            "policy-excluded route differs from technical qualification runtime evidence",
        ),
    ),
)
def test_manifest_rejects_resealed_technical_model_projection_drift(
    population: str,
    field_name: str,
    field_value: object,
    expected_error: str,
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    run_dir, manifest = _copied_run(tmp_path, policy_manifest_fixture)
    runtime_path = run_dir / "model-qualification-runtime.json"
    payload = json.loads(runtime_path.read_text(encoding="utf-8"))
    selection = policy_manifest_fixture.evidence.selection
    target_id = (
        selection.selected_model_ids[0]
        if population == "selected"
        else selection.policy_excluded_model_ids[0]
    )
    binding = next(
        item for item in payload["model_bindings"] if item["exact_model_id"] == target_id
    )
    binding[field_name] = field_value
    if field_name in {"approved_provider_endpoint", "approved_provider_name"}:
        for reasoning_binding in binding["reasoning_bindings"]:
            reasoning_binding[field_name] = field_value
            reasoning_binding["binding_sha256"] = canonical_sha256(
                {key: value for key, value in reasoning_binding.items() if key != "binding_sha256"}
            )
    payload["validation_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "validation_sha256"}
    )
    runtime_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
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

    with pytest.raises(ValueError, match=expected_error):
        validate_manifest_artifacts(resealed, run_dir)


def test_manifest_build_rejects_extra_policy_bundle_without_report_selection(
    tmp_path: Path,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    fixture = policy_manifest_fixture
    report, language, corpus = _current_report(fixture.config)
    run_dir = tmp_path / "run"
    _write_required_artifacts(run_dir, report, language_artifact=language)
    _write_current_artifact_shapes(run_dir, corpus=corpus)
    (run_dir / AUDIT_MODEL_SELECTION_EVIDENCE_PATH).write_text(
        fixture.evidence.model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    (run_dir / "model-qualification-runtime.json").write_text(
        json.dumps(fixture.qualification_runtime, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="presence differs from the final report"):
        build_run_evidence_manifest(
            run_dir=run_dir,
            report=report,
            config=fixture.config,
            production_qualification=fixture.technical,
        )


def test_report_rejects_real_paid_usage_without_exact_policy_routing(
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    selected = policy_manifest_fixture.evidence.selection.models[0]
    usage = UsageRecord(
        request_id="paid-audit-routing-missing",
        role="source_audit",
        execution_evidence=ExecutionEvidenceKind.REAL,
        requested_model=selected.exact_model_id,
        returned_model=selected.canonical_model_slug,
        actual_model=selected.canonical_model_slug,
        provider=selected.approved_provider_name,
        model_family=selected.exact_model_id,
        timestamp=policy_manifest_fixture.evidence.selection.selected_at + timedelta(minutes=1),
        prompt_tokens=1,
        completion_tokens=1,
        total_tokens=2,
        reported_cost_usd=0,
        accounted_cost_usd=0,
        prompt_sha256="a" * 64,
        configured_provider_endpoints=[selected.approved_provider_endpoint],
        actual_provider_endpoint=selected.approved_provider_endpoint,
        status="success",
        attempts=1,
    )

    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        _current_report(
            policy_manifest_fixture.config,
            selection=policy_manifest_fixture.evidence.selection,
            usage=[usage],
        )


def test_report_accepts_exact_paid_routing_and_rejects_swapped_selected_model(
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    report, _language, _corpus = _current_report(
        policy_manifest_fixture.config,
        selection=policy_manifest_fixture.evidence.selection,
        refresh=policy_manifest_fixture.refresh.evidence,
        refresh_pricing=policy_manifest_fixture.refresh.pricing_evidence,
        usage=[_paid_usage(policy_manifest_fixture)],
    )

    assert report.usage[0].routing["audit_model_selection_bundle_sha256"] == (
        policy_manifest_fixture.evidence.bundle_sha256
    )
    assert report.usage[0].routing["selected_model_set_sha256"] == (
        policy_manifest_fixture.evidence.selection.selected_model_set_sha256
    )
    with pytest.raises(ValidationError, match="differs from report selection"):
        _current_report(
            policy_manifest_fixture.config,
            selection=policy_manifest_fixture.evidence.selection,
            refresh=policy_manifest_fixture.refresh.evidence,
            refresh_pricing=policy_manifest_fixture.refresh.pricing_evidence,
            usage=[
                _paid_usage(
                    policy_manifest_fixture,
                    requested_index=0,
                    routed_index=1,
                )
            ],
        )


@pytest.mark.parametrize(
    "source_classification",
    (
        PrivacySourceClassification.PUBLIC_BENCHMARK,
        PrivacySourceClassification.SYNTHETIC_COMMITTED,
    ),
)
def test_report_rejects_detached_public_or_synthetic_prequalification_claim(
    source_classification: PrivacySourceClassification,
    policy_manifest_fixture: _PolicyManifestFixture,
) -> None:
    record = _creditable_record(execution_evidence=ExecutionEvidenceKind.REAL)
    prequalification = record.model_copy(
        update={
            "role": "model_benchmark",
            "accounted_cost_usd": 0,
            "accounted_cost_usd_exact": "0",
            "reported_cost_usd": 0,
            "reported_cost_usd_exact": "0",
            "routing": {
                **record.routing,
                "privacy_profile": PrivacyProfile.SYNTHETIC_BENCHMARK.value,
                "privacy_source_classification": source_classification.value,
                "privacy_source_proof_kind": "RELEASE_PINNED_MODEL_BENCHMARK",
            },
        }
    )
    token_plan, reservation = _token_plan_for_record(prequalification)
    prequalification = prequalification.model_copy(
        update={
            "routing": {
                **prequalification.routing,
                "request_token_plan": token_plan.model_dump(mode="json"),
                "request_token_plan_sha256": token_plan.plan_sha256,
                "atomic_token_reservations": [reservation.model_dump(mode="json")],
                "atomic_token_reservation_sha256s": [reservation.evidence_sha256],
                "atomic_token_reservation": reservation.model_dump(mode="json"),
                "atomic_token_reservation_sha256": reservation.evidence_sha256,
            }
        }
    )

    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        _current_report(
            policy_manifest_fixture.config,
            usage=[prequalification],
        )

    model_execution_payload = json.loads(
        (policy_manifest_fixture.run_dir / "model-execution.json").read_text(encoding="utf-8")
    )
    model_execution_payload["audit_model_selection"] = None
    model_execution_payload["usage"] = [prequalification.model_dump(mode="json")]
    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        ModelExecutionArtifact.model_validate(model_execution_payload)

    class UsageRecordSubclass(UsageRecord):
        pass

    subclass_record = UsageRecordSubclass.model_validate(prequalification.model_dump(mode="python"))
    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        _current_report(policy_manifest_fixture.config, usage=[subclass_record])
    model_execution_payload["usage"] = [subclass_record]
    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        ModelExecutionArtifact.model_validate(model_execution_payload)

    private = prequalification.model_copy(
        update={
            "routing": {
                **prequalification.routing,
                "privacy_source_classification": (
                    PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE.value
                ),
            }
        }
    )
    with pytest.raises(ValidationError, match="lacks typed audit routing evidence"):
        _current_report(policy_manifest_fixture.config, usage=[private])
