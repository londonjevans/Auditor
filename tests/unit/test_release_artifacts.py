from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.release_artifacts as release_artifact_module
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
)
from mmaudit.models.schemas import (
    AuditProfile,
    AuditReport,
    CandidateFindingArtifact,
    RepositoryMap,
)
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    seal_run_evidence_manifest,
    validate_manifest_artifacts,
    write_run_evidence_manifest,
)
from mmaudit.release_artifacts import (
    ReleaseArtifactEvidence,
    load_release_artifact_evidence,
    observe_release_artifacts,
    write_release_artifact_evidence,
)
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    build_coverage_artifact,
    build_findings_artifact,
    build_model_execution_artifact,
)
from mmaudit.reporting.client import render_client_markdown
from mmaudit.reporting.json_report import write_json
from mmaudit.reporting.markdown import render_forensic_markdown, render_markdown
from mmaudit.reporting.run_authority import RUN_TERMINAL_REPORT_AUTHORITY_PATH
from mmaudit.reporting.sarif import generate_report_sarif
from mmaudit.reporting.status import report_status_metadata
from mmaudit.traceability import (
    ImplementationStatus,
    build_traceability_matrix,
    write_traceability_artifact,
)
from scripts import validate_release_evidence as release_evidence_cli
from tests.report_authority_fixtures import write_run_terminal_report_authority
from tests.language_capability_support import (
    empty_language_capability,
    write_language_capability_artifact,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "schemas" / "release_artifact_evidence.schema.json"
SCHEMA_URI = "https://mmaudit.local/schemas/release_artifact_evidence.schema.json"
COMMIT = "a" * 40
RUN_ID = "release-artifact-test"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _bindings() -> ManifestBindingSet:
    values: dict[str, list[ManifestHashBinding]] = {}
    for name in ManifestBindingSet.model_fields:
        values[name] = [
            ManifestHashBinding(
                identifier=f"{name}/synthetic",
                sha256=_sha(name),
                details={"kind": "synthetic"},
            )
        ]
    return ManifestBindingSet.model_validate(values)


def _run_configuration(config: AuditConfig) -> RunConfigurationBinding:
    effective = config.effective()
    environment = AuditConfigOverrides()
    cli = AuditConfigOverrides()
    options = AuditRunOptions()
    invocation = {
        "environment_overrides_sha256": environment.stable_hash(),
        "cli_overrides_sha256": cli.stable_hash(),
        "run_options_sha256": options.stable_hash(),
        "effective_config_sha256": effective.stable_hash(),
        "requested_profile": effective.profile.value,
        "achieved_profile": None,
        "requested_language_profile": effective.language_profile.value,
        "achieved_language_profile": None,
        "reduced_language_capability": False,
    }
    return RunConfigurationBinding(
        file_configuration_json=canonical_audit_config_json(config),
        file_config_sha256=config.stable_hash(),
        environment_overrides=environment,
        environment_overrides_sha256=environment.stable_hash(),
        cli_overrides=cli,
        cli_overrides_sha256=cli.stable_hash(),
        run_options=options,
        run_options_sha256=options.stable_hash(),
        effective_configuration_json=canonical_audit_config_json(effective),
        effective_config_sha256=effective.stable_hash(),
        model_config_sha256=effective.model_hash(),
        invocation_sha256=canonical_sha256(invocation),
        requested_profile=effective.profile,
        achieved_profile=None,
        requested_language_profile=effective.language_profile,
        achieved_language_profile=None,
        reduced_language_capability=False,
    )


def _seal_manifest(
    run_dir: Path,
    config: AuditConfig,
    *,
    commit: str = COMMIT,
) -> RunEvidenceManifest:
    manifest = seal_run_evidence_manifest(
        run_id=RUN_ID,
        repository_root_name="synthetic-release-repository",
        git_commit=commit,
        sources=[],
        run_configuration=_run_configuration(config),
        bindings=_bindings(),
        artifacts=collect_run_artifacts(run_dir),
        schema_version="1.2",
        tool_version="test",
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    return manifest


def _report(config: AuditConfig, *, commit: str = COMMIT) -> AuditReport:
    effective = config.effective()
    capability = empty_language_capability(effective.language_profile)
    return AuditReport(
        schema_version="1.0",
        run_id=RUN_ID,
        generated_at=datetime(2026, 1, 2, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-release-repository",
            git_commit=commit,
            languages={},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash=effective.stable_hash(),
        model_configuration_hash=effective.model_hash(),
        privacy={
            "profile": effective.privacy.profile.value,
            "code_egress_enabled": False,
            "effective_policy": None,
            "source_provenance": None,
        },
        scanner_runs=[],
        usage=[],
        budget_usd=effective.execution.budget_usd,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
        audit_profile=effective.profile,
        language_capability=capability.assessment,
    )


def _write_report_artifacts(run_dir: Path, report: AuditReport) -> None:
    assert report.language_capability is not None
    capability = empty_language_capability(report.language_capability.requested_profile)
    assert capability.assessment == report.language_capability
    write_language_capability_artifact(run_dir, capability)
    (run_dir / "final-findings.json").write_text(
        report.model_dump_json(),
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
                "metadata": report.metadata,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "scanner-results.json").write_text(
        json.dumps(
            {
                "schema_version": report.schema_version,
                "run_id": report.run_id,
                "runs": [run.model_dump(mode="json") for run in report.scanner_runs],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    write_json(
        run_dir / "verification-results.json",
        {
            "schema_version": report.schema_version,
            "decisions": [
                decision.model_dump(mode="json") for decision in report.verification_decisions
            ],
            "threat_model": None,
            "threat_model_location_rejections": [],
        },
    )
    write_json(
        run_dir / "cross-examination.json",
        {
            "schema_version": report.schema_version,
            "decisions": [
                decision.model_dump(mode="json") for decision in report.cross_examination_decisions
            ],
        },
    )
    (run_dir / "candidate-findings.json").write_text(
        CandidateFindingArtifact(
            schema_version="1.1",
            findings=[],
        ).model_dump_json(),
        encoding="utf-8",
    )
    (run_dir / "reproduction-results.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "test_specifications": [],
                "results": [],
                "candidate_resolutions": [],
                "falsification_decisions": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    findings_artifact = build_findings_artifact(report)
    write_json(run_dir / "findings.json", findings_artifact)
    write_json(run_dir / "coverage.json", build_coverage_artifact(report))
    write_json(run_dir / "model-execution.json", build_model_execution_artifact(report))
    write_json(
        run_dir / "audit-results.sarif",
        generate_report_sarif(report, findings_artifact=findings_artifact),
    )
    (run_dir / "client-report.md").write_text(
        render_client_markdown(report, {}),
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
    write_run_terminal_report_authority(run_dir, report)


def _write_run(run_dir: Path, config: AuditConfig) -> RunEvidenceManifest:
    run_dir.mkdir(parents=True)
    traceability = build_traceability_matrix(COMMIT)
    write_traceability_artifact(
        run_dir / "maximum_assurance_traceability.json",
        traceability,
    )
    required_artifacts = {
        artifact
        for requirement in traceability.requirements
        if requirement.implementation_status is ImplementationStatus.IMPLEMENTED
        for artifact in requirement.runtime_artifacts
    }
    required_artifacts.discard("run-evidence-manifest.json")
    required_artifacts.discard("maximum_assurance_traceability.json")
    for name in sorted(required_artifacts):
        (run_dir / name).write_text('{"synthetic":true}\n', encoding="utf-8")
    _write_report_artifacts(run_dir, _report(config))
    return _seal_manifest(run_dir, config)


def _generated_schema() -> dict[str, Any]:
    schema = ReleaseArtifactEvidence.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = SCHEMA_URI
    schema["title"] = "mmaudit observed release artifact evidence"
    return schema


def test_observer_binds_actual_manifest_inventory_and_traceability(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    manifest = _write_run(run_dir, config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE))

    evidence = observe_release_artifacts(run_dir, ROOT)

    assert evidence.run_id == manifest.run_id
    assert evidence.manifest_sha256 == manifest.manifest_sha256
    assert (
        evidence.manifest_file_sha256
        == hashlib.sha256((run_dir / "run-evidence-manifest.json").read_bytes()).hexdigest()
    )
    assert evidence.artifacts == manifest.artifacts
    assert evidence.artifact_count == len(manifest.artifacts)
    assert evidence.artifact_inventory_sha256 == canonical_sha256(
        [binding.model_dump(mode="json") for binding in manifest.artifacts]
    )
    assert evidence.evidence_sha256 == canonical_sha256(
        evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    )

    output = tmp_path / "release-artifact-evidence.json"
    write_release_artifact_evidence(output, evidence)
    assert load_release_artifact_evidence(output) == evidence
    assert oct(output.stat().st_mode & 0o777) == "0o600"


@pytest.mark.parametrize(
    "artifact_name",
    sorted(MANIFEST_BOUND_REPORT_DELIVERABLES | {RUN_TERMINAL_REPORT_AUTHORITY_PATH}),
)
def test_manifest_schema_1_2_rejects_coherently_resealed_missing_report_deliverable(
    tmp_path: Path,
    config_factory,
    artifact_name: str,
) -> None:
    run_dir = tmp_path / "run"
    manifest = _write_run(run_dir, config_factory())
    (run_dir / artifact_name).unlink()
    payload = manifest.model_dump(mode="json")
    payload["artifacts"] = [
        binding for binding in payload["artifacts"] if binding["path"] != artifact_name
    ]
    payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    with pytest.raises(
        ValidationError,
        match=r"manifest 1\.2 requires report artifact bindings",
    ):
        RunEvidenceManifest.model_validate(payload)


def test_manifest_schema_1_1_retains_legacy_sarif_only_compatibility(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    current = _write_run(run_dir, config)
    for artifact_name in MANIFEST_BOUND_REPORT_DELIVERABLES - {"audit-results.sarif"}:
        (run_dir / artifact_name).unlink()
    (run_dir / RUN_TERMINAL_REPORT_AUTHORITY_PATH).unlink()
    assert current.run_configuration is not None
    legacy_payload = current.model_dump(mode="json")
    legacy_payload["schema_version"] = "1.1"
    legacy_payload["artifacts"] = [
        artifact.model_dump(mode="json") for artifact in collect_run_artifacts(run_dir)
    ]
    legacy_payload["manifest_sha256"] = canonical_sha256(
        {key: value for key, value in legacy_payload.items() if key != "manifest_sha256"}
    )
    legacy = RunEvidenceManifest.model_validate(legacy_payload)

    validate_manifest_artifacts(legacy, run_dir)


@pytest.mark.parametrize("artifact_name", ["client-report.md", "forensic-report.md"])
def test_observer_rejects_coherently_resealed_markdown_report_tamper(
    tmp_path: Path,
    config_factory,
    artifact_name: str,
) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    _write_run(run_dir, config)
    (run_dir / artifact_name).write_text(
        "# Coherently replaced report\n",
        encoding="utf-8",
    )
    _seal_manifest(run_dir, config)

    with pytest.raises(ValueError, match=rf"{re.escape(artifact_name)} differs"):
        observe_release_artifacts(run_dir, ROOT)


@pytest.mark.parametrize("tamper", ["quality_gates", "limitations"])
def test_observer_rejects_coherently_resealed_findings_status_evidence_tamper(
    tmp_path: Path,
    config_factory,
    tamper: str,
) -> None:
    run_dir = tmp_path / "run"
    config = config_factory()
    _write_run(run_dir, config)
    findings_path = run_dir / "findings.json"
    payload = json.loads(findings_path.read_text(encoding="utf-8"))
    if tamper == "quality_gates":
        payload["quality_gates"][0]["detail"] = "coherently replaced quality evidence"
    else:
        payload["limitations"] = ["coherently replaced limitation evidence"]
    findings_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    _seal_manifest(run_dir, config)

    with pytest.raises(ValueError, match=r"findings\.json differs"):
        observe_release_artifacts(run_dir, ROOT)


def test_observer_parses_the_exact_safely_read_manifest_bytes(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    manifest = _write_run(run_dir, config_factory())
    wrong_payload = manifest.model_dump(mode="json", exclude={"manifest_sha256"})
    wrong_payload["run_id"] = "transient-wrong-manifest"
    wrong_manifest = RunEvidenceManifest.model_validate(
        {
            **wrong_payload,
            "manifest_sha256": canonical_sha256(wrong_payload),
        }
    )
    monkeypatch.setattr(
        release_artifact_module,
        "load_run_evidence_manifest",
        lambda _path: wrong_manifest,
        raising=False,
    )

    evidence = observe_release_artifacts(run_dir, ROOT)

    assert evidence.run_id == manifest.run_id
    assert evidence.manifest_sha256 == manifest.manifest_sha256


def test_observer_requires_fixed_manifest_in_the_explicit_run_directory(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    manifest = run_dir / "run-evidence-manifest.json"
    sibling = tmp_path / "same-name-elsewhere" / manifest.name
    sibling.parent.mkdir()
    sibling.write_bytes(manifest.read_bytes())
    manifest.unlink()

    with pytest.raises(ValueError, match="manifest is missing"):
        observe_release_artifacts(run_dir, ROOT)


@pytest.mark.parametrize("ancestor_link", [False, True])
def test_observer_rejects_linked_run_root_or_ancestor(
    tmp_path: Path,
    config_factory,
    ancestor_link: bool,
) -> None:
    real_parent = tmp_path / "real-parent"
    run_dir = real_parent / "run"
    _write_run(run_dir, config_factory())
    if ancestor_link:
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        observed_path = linked_parent / "run"
    else:
        observed_path = tmp_path / "linked-run"
        observed_path.symlink_to(run_dir, target_is_directory=True)

    with pytest.raises(ValueError, match="may not traverse a link"):
        observe_release_artifacts(observed_path, ROOT)


def test_observer_rejects_linked_and_hardlinked_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    symlink_run = tmp_path / "symlink-run"
    _write_run(symlink_run, config_factory())
    artifact = symlink_run / "final-findings.json"
    outside = tmp_path / "outside.json"
    outside.write_bytes(artifact.read_bytes())
    artifact.unlink()
    artifact.symlink_to(outside)
    with pytest.raises(ValueError, match="links"):
        observe_release_artifacts(symlink_run, ROOT)

    hardlink_run = tmp_path / "hardlink-run"
    _write_run(hardlink_run, config_factory())
    artifact = hardlink_run / "final-findings.json"
    outside_hardlink = tmp_path / "outside-hardlink.json"
    outside_hardlink.write_bytes(artifact.read_bytes())
    artifact.unlink()
    os.link(outside_hardlink, artifact)
    with pytest.raises(ValueError, match="unique regular files"):
        observe_release_artifacts(hardlink_run, ROOT)


def test_observer_rejects_missing_undeclared_and_hash_changed_artifacts(
    tmp_path: Path,
    config_factory,
) -> None:
    missing_run = tmp_path / "missing-run"
    _write_run(missing_run, config_factory())
    (missing_run / "final-findings.json").unlink()
    with pytest.raises(ValueError, match="artifact set"):
        observe_release_artifacts(missing_run, ROOT)

    extra_run = tmp_path / "extra-run"
    _write_run(extra_run, config_factory())
    (extra_run / "undeclared.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact set"):
        observe_release_artifacts(extra_run, ROOT)

    changed_run = tmp_path / "changed-run"
    _write_run(changed_run, config_factory())
    (changed_run / "final-findings.json").write_text(
        '{"synthetic":"changed"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        observe_release_artifacts(changed_run, ROOT)


def test_observer_rejects_resealed_manifest_missing_required_runtime_artifact(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    _write_run(run_dir, config)
    (run_dir / "final-findings.json").unlink()
    _seal_manifest(run_dir, config)

    with pytest.raises(
        ValueError,
        match=r"requires emitted artifact: final-findings\.json|lacks runtime artifacts",
    ):
        observe_release_artifacts(run_dir, ROOT)


def test_artifact_collection_rejects_path_swap_before_open(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    artifact = run_dir / "final-findings.json"
    original = tmp_path / "original.json"
    replacement = tmp_path / "replacement.json"
    replacement.write_bytes(artifact.read_bytes())
    real_open = os.open
    swapped = False

    def swap_then_open(
        path: os.PathLike[str] | str,
        flags: int,
        mode: int = 0o777,
    ) -> int:
        nonlocal swapped
        if Path(path) == artifact and not swapped:
            swapped = True
            artifact.rename(original)
            artifact.symlink_to(replacement)
        return real_open(path, flags, mode)

    monkeypatch.setattr(release_artifact_module.os, "open", swap_then_open)

    with pytest.raises(ValueError, match="opened safely"):
        collect_run_artifacts(run_dir)


def test_observer_rejects_resealed_stale_traceability(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    run_dir = tmp_path / "run"
    _write_run(run_dir, config)
    write_traceability_artifact(
        run_dir / "maximum_assurance_traceability.json",
        build_traceability_matrix("b" * 40),
    )
    _seal_manifest(run_dir, config, commit=COMMIT)

    with pytest.raises(ValueError, match="traceability is stale"):
        observe_release_artifacts(run_dir, ROOT)


def test_observer_rejects_legacy_manifest_without_reconstructable_config(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    current = _write_run(run_dir, config_factory())
    payload = current.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("run_configuration")
    payload.pop("manifest_sha256")
    payload["manifest_sha256"] = canonical_sha256(payload)
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(payload),
    )

    with pytest.raises(ValueError, match=r"schema 1\.2"):
        observe_release_artifacts(run_dir, ROOT)


def test_evidence_loader_and_writer_reject_links_and_existing_destinations(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    evidence = observe_release_artifacts(run_dir, ROOT)
    output = tmp_path / "evidence.json"
    write_release_artifact_evidence(output, evidence)

    linked = tmp_path / "linked-evidence.json"
    linked.symlink_to(output)
    with pytest.raises(ValueError, match="unshared regular file"):
        load_release_artifact_evidence(linked)
    with pytest.raises(ValueError, match="fresh file"):
        write_release_artifact_evidence(output, evidence)

    hardlinked = tmp_path / "hardlinked-evidence.json"
    os.link(output, hardlinked)
    with pytest.raises(ValueError, match="unshared regular file"):
        load_release_artifact_evidence(hardlinked)


def test_evidence_writer_rejects_same_size_path_replacement_after_close(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    evidence = observe_release_artifacts(run_dir, ROOT)
    output = tmp_path / "evidence.json"
    replacement = tmp_path / "replacement.json"
    serialized_size = len(release_artifact_module.stable_json(evidence).encode("utf-8"))
    replacement.write_bytes(b"x" * serialized_size)
    real_close = os.close
    swapped = False

    def close_then_swap(descriptor: int) -> None:
        nonlocal swapped
        real_close(descriptor)
        if not swapped and output.exists():
            swapped = True
            output.unlink()
            replacement.rename(output)

    monkeypatch.setattr(release_artifact_module.os, "close", close_then_swap)

    with pytest.raises(ValueError, match="not a unique regular file"):
        write_release_artifact_evidence(output, evidence)
    assert output.read_bytes() == b"x" * serialized_size


def test_evidence_model_rejects_inventory_and_self_hash_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    evidence = observe_release_artifacts(run_dir, ROOT)
    payload = evidence.model_dump(mode="json")
    payload["artifact_count"] += 1
    with pytest.raises(ValidationError, match="artifact count"):
        ReleaseArtifactEvidence.model_validate(payload)

    payload = evidence.model_dump(mode="json")
    payload["evidence_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="evidence hash"):
        ReleaseArtifactEvidence.model_validate(payload)


def test_release_validator_requires_an_explicit_mode() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/validate_release_evidence.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert "--artifact-only" in result.stderr
    assert "--full" in result.stderr
    assert "valid" not in result.stdout


def test_release_validator_rejects_legacy_implicit_report_invocation(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--run-dir",
            str(run_dir),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert "--artifact-only" in result.stderr
    assert "--full" in result.stderr
    assert "valid" not in result.stdout


def test_release_validator_artifact_only_requires_run_directory() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--artifact-only",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert "--artifact-only requires --run-dir" in result.stderr
    assert "valid" not in result.stdout


def test_release_validator_full_mode_requires_every_authoritative_input(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--full",
            "--run-dir",
            str(tmp_path / "run"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert "--report-root" in result.stderr
    assert "--report-path" in result.stderr
    assert "--evidence-root" in result.stderr
    assert "--release-repository" in result.stderr
    assert "--target-repository" in result.stderr
    assert "--artifact-evidence-file" in result.stderr
    assert "--run-verification-file" in result.stderr
    assert "valid" not in result.stdout


def test_release_validator_artifact_only_rejects_report_inputs(tmp_path: Path) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--artifact-only",
            "--run-dir",
            str(tmp_path / "run"),
            "--report-root",
            str(tmp_path / "reports"),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 2
    assert "--artifact-only does not accept full-report options" in result.stderr
    assert "valid" not in result.stdout


def test_release_validator_full_mode_forwards_only_explicit_authoritative_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def validate(**kwargs: object) -> SimpleNamespace:
        observed.update(kwargs)
        return SimpleNamespace(
            status=SimpleNamespace(value="blocked_technical"),
            passed_gates=7,
            total_gates=12,
        )

    monkeypatch.setattr(release_evidence_cli, "validate_release_report", validate)
    paths = {
        "report_root": tmp_path / "report-root",
        "evidence_root": tmp_path / "evidence-root",
        "release_repository_root": tmp_path / "release-repository",
        "emitted_run_dir": tmp_path / "run",
        "target_repository_root": tmp_path / "target-repository",
        "artifact_evidence_path": tmp_path / "artifact-evidence.json",
        "run_verification_path": tmp_path / "raw-run-verification.json",
    }

    release_evidence_cli.main(
        [
            "--full",
            "--report-root",
            str(paths["report_root"]),
            "--report-path",
            "release-report.json",
            "--evidence-root",
            str(paths["evidence_root"]),
            "--release-repository",
            str(paths["release_repository_root"]),
            "--run-dir",
            str(paths["emitted_run_dir"]),
            "--target-repository",
            str(paths["target_repository_root"]),
            "--artifact-evidence-file",
            str(paths["artifact_evidence_path"]),
            "--run-verification-file",
            str(paths["run_verification_path"]),
        ]
    )

    assert observed == {
        **paths,
        "report_relative_path": "release-report.json",
        "require_complete": False,
    }
    assert (
        capsys.readouterr().out == "release report integrity valid: "
        "release_status=blocked_technical passed_gates=7/12\n"
    )


def test_release_validator_require_complete_propagates_fail_closed_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_incomplete(**kwargs: object) -> SimpleNamespace:
        assert kwargs["require_complete"] is True
        raise ValueError("release does not satisfy the complete maximum-assurance policy")

    monkeypatch.setattr(release_evidence_cli, "validate_release_report", reject_incomplete)

    with pytest.raises(ValueError, match="does not satisfy"):
        release_evidence_cli.main(
            [
                "--full",
                "--report-root",
                str(tmp_path / "report-root"),
                "--report-path",
                "release-report.json",
                "--evidence-root",
                str(tmp_path / "evidence-root"),
                "--release-repository",
                str(tmp_path / "release-repository"),
                "--run-dir",
                str(tmp_path / "run"),
                "--target-repository",
                str(tmp_path / "target-repository"),
                "--artifact-evidence-file",
                str(tmp_path / "artifact-evidence.json"),
                "--run-verification-file",
                str(tmp_path / "raw-run-verification.json"),
                "--require-complete",
            ]
        )


def test_release_validator_observes_run_and_writes_sealed_evidence(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    manifest = _write_run(run_dir, config_factory())
    output = tmp_path / "observed-release-artifacts.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--artifact-only",
            "--run-dir",
            str(run_dir),
            "--artifact-evidence-output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "release artifact observation valid" in result.stdout
    assert "release report" not in result.stdout
    evidence = load_release_artifact_evidence(output)
    assert evidence.run_id == manifest.run_id
    assert evidence.manifest_sha256 == manifest.manifest_sha256


def test_release_validator_refuses_to_write_observation_inside_the_run(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory())
    output = run_dir / "post-validation-observation.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--artifact-only",
            "--run-dir",
            str(run_dir),
            "--artifact-evidence-output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "must be outside the emitted run" in result.stderr
    assert not output.exists()


@pytest.mark.parametrize("alias_kind", ["case", "unicode"])
def test_release_validator_refuses_case_or_unicode_alias_inside_run(
    tmp_path: Path,
    config_factory,
    alias_kind: str,
) -> None:
    import unicodedata

    run_name = "rélease-run"
    run_dir = tmp_path / run_name
    _write_run(run_dir, config_factory())
    if alias_kind == "case":
        alias = run_dir.with_name(run_name.upper())
    else:
        alias = run_dir.with_name(unicodedata.normalize("NFD", run_name))
    try:
        aliases_same_directory = alias.samefile(run_dir)
    except OSError:
        aliases_same_directory = False
    if not aliases_same_directory or alias == run_dir:
        pytest.skip(f"filesystem does not expose a distinct {alias_kind} alias")
    output = alias / f"{alias_kind}-observation.json"

    result = subprocess.run(
        [
            sys.executable,
            "scripts/validate_release_evidence.py",
            "--artifact-only",
            "--run-dir",
            str(run_dir),
            "--artifact-evidence-output",
            str(output),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode != 0
    assert "must be outside the emitted run" in result.stderr
    assert not output.exists()


def test_published_release_artifact_schema_matches_typed_contract() -> None:
    published = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert published == _generated_schema()
    assert published["additionalProperties"] is False
    assert set(published["required"]) == {
        name for name, field in ReleaseArtifactEvidence.model_fields.items() if field.is_required()
    }
    assert published["properties"]["artifacts"]["minItems"] == 1
    assert published["properties"]["artifacts"]["maxItems"] == 100_000
