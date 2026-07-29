from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.release_run as release_run_module
from mmaudit.config import (
    AuditConfig,
    AuditConfigOverrides,
    AuditRunOptions,
    canonical_audit_config_json,
)
from mmaudit.models.schemas import AuditProfile, AuditReport, RepositoryMap
from mmaudit.orchestration.manifest import (
    ManifestBindingSet,
    ManifestFileBinding,
    ManifestHashBinding,
    RunConfigurationBinding,
    RunEvidenceManifest,
    canonical_sha256,
    collect_run_artifacts,
    seal_run_evidence_manifest,
    write_run_evidence_manifest,
)
from mmaudit.release_artifacts import (
    observe_release_artifacts,
    write_release_artifact_evidence,
)
from mmaudit.release_run import ReleaseRunBinding, observe_release_run_binding
from mmaudit.traceability import (
    ImplementationStatus,
    build_traceability_matrix,
    write_traceability_artifact,
)

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "a" * 40


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
        "achieved_profile": effective.profile.value,
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
        achieved_profile=effective.profile,
    )


def _report(
    config: AuditConfig,
    *,
    run_id: str,
    commit: str,
) -> AuditReport:
    effective = config.effective()
    return AuditReport(
        schema_version="1.0",
        run_id=run_id,
        generated_at=datetime(2026, 1, 2, tzinfo=UTC),
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-target-repository",
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
    )


def _write_report_artifacts(run_dir: Path, report: AuditReport) -> None:
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
                "completed": report.completed,
                "incomplete_reasons": report.incomplete_reasons,
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


def _write_run(
    run_dir: Path,
    config: AuditConfig,
    *,
    run_id: str,
    commit: str = COMMIT,
) -> RunEvidenceManifest:
    run_dir.mkdir(parents=True)
    traceability = build_traceability_matrix(commit)
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
    _write_report_artifacts(
        run_dir,
        _report(
            config,
            run_id=run_id,
            commit=commit,
        ),
    )
    source = ManifestFileBinding(
        path="contracts/Synthetic.sol",
        sha256=_sha("synthetic target source"),
        size=len("synthetic target source"),
    )
    manifest = seal_run_evidence_manifest(
        run_id=run_id,
        repository_root_name="synthetic-target-repository",
        git_commit=commit,
        sources=[source],
        run_configuration=_run_configuration(config),
        bindings=_bindings(),
        artifacts=collect_run_artifacts(run_dir),
        tool_version="test",
    )
    write_run_evidence_manifest(run_dir / "run-evidence-manifest.json", manifest)
    return manifest


def _write_evidence(run_dir: Path, path: Path) -> None:
    write_release_artifact_evidence(path, observe_release_artifacts(run_dir, ROOT))


def test_observer_binds_target_run_configuration_and_exact_evidence_file(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory(profile=AuditProfile.MAXIMUM_ASSURANCE)
    run_dir = tmp_path / "run"
    manifest = _write_run(run_dir, config, run_id="release-run-binding")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    _write_evidence(run_dir, evidence_path)
    evidence = observe_release_artifacts(run_dir, ROOT)
    run_configuration = manifest.run_configuration
    assert run_configuration is not None

    binding = observe_release_run_binding(run_dir, ROOT, evidence_path)

    assert binding.run_id == manifest.run_id
    assert binding.target_repository_name == manifest.repository_root_name
    assert binding.target_git_commit == manifest.git_commit
    assert binding.target_source_tree_sha256 == manifest.source_tree_sha256
    assert (
        binding.manifest_file_sha256
        == hashlib.sha256((run_dir / "run-evidence-manifest.json").read_bytes()).hexdigest()
    )
    assert binding.manifest_sha256 == manifest.manifest_sha256
    assert binding.run_configuration_sha256 == canonical_sha256(
        run_configuration.model_dump(mode="json")
    )
    assert binding.file_config_sha256 == run_configuration.file_config_sha256
    assert binding.environment_overrides_sha256 == run_configuration.environment_overrides_sha256
    assert binding.cli_overrides_sha256 == run_configuration.cli_overrides_sha256
    assert binding.run_options_sha256 == run_configuration.run_options_sha256
    assert binding.effective_config_sha256 == run_configuration.effective_config_sha256
    assert binding.model_config_sha256 == run_configuration.model_config_sha256
    assert binding.invocation_sha256 == run_configuration.invocation_sha256
    assert binding.requested_profile is run_configuration.requested_profile
    assert binding.achieved_profile is run_configuration.achieved_profile
    assert (
        binding.artifact_evidence_file_sha256
        == hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    )
    assert binding.artifact_evidence_file_size == evidence_path.stat().st_size
    assert binding.artifact_evidence_sha256 == evidence.evidence_sha256
    assert binding.artifact_inventory_sha256 == evidence.artifact_inventory_sha256
    assert binding.artifact_count == evidence.artifact_count
    assert binding.traceability_sha256 == evidence.traceability_sha256
    assert binding.observed_at.tzinfo is not None
    assert binding.observed_at.utcoffset() is not None
    assert binding.observed_at.microsecond == 0
    assert binding.binding_sha256 == canonical_sha256(
        binding.model_dump(mode="json", exclude={"binding_sha256"})
    )
    assert "product_candidate_commit" not in ReleaseRunBinding.model_fields


def test_observer_rejects_artifact_evidence_from_another_run(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    first_run = tmp_path / "first-run"
    second_run = tmp_path / "second-run"
    _write_run(first_run, config, run_id="first-run")
    _write_run(second_run, config, run_id="second-run")
    evidence_path = tmp_path / "first-evidence.json"
    _write_evidence(first_run, evidence_path)

    with pytest.raises(ValueError, match="differs from the explicit emitted run"):
        observe_release_run_binding(second_run, ROOT, evidence_path)


def test_observer_rejects_resealed_evidence_identity_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id="untampered-run")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    evidence = observe_release_artifacts(run_dir, ROOT)
    payload = evidence.model_dump(mode="json")
    payload["run_id"] = "rebound-to-another-run"
    payload["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )
    evidence_path.write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="differs from the explicit emitted run"):
        observe_release_run_binding(run_dir, ROOT, evidence_path)


def test_binding_model_rejects_field_and_self_hash_tampering(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id="binding-model")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    _write_evidence(run_dir, evidence_path)
    binding = observe_release_run_binding(run_dir, ROOT, evidence_path)

    payload = binding.model_dump(mode="json")
    payload["artifact_count"] += 1
    with pytest.raises(ValidationError, match="binding hash"):
        ReleaseRunBinding.model_validate(payload)

    for malformed_commit in ("1" * 39, "1" * 41, "1" * 63, "1" * 65):
        payload = binding.model_dump(mode="json")
        payload["target_git_commit"] = malformed_commit
        with pytest.raises(ValidationError, match="target_git_commit"):
            ReleaseRunBinding.model_validate(payload)

    payload = binding.model_dump(mode="json")
    payload["binding_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="binding hash"):
        ReleaseRunBinding.model_validate(payload)


@pytest.mark.parametrize("kind", ["file_symlink", "ancestor_symlink", "hardlink"])
def test_observer_rejects_linked_or_shared_artifact_evidence(
    tmp_path: Path,
    config_factory,
    kind: str,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id=f"linked-{kind}")
    real_parent = tmp_path / "real-evidence"
    real_parent.mkdir()
    real_evidence = real_parent / "evidence.json"
    _write_evidence(run_dir, real_evidence)

    if kind == "file_symlink":
        evidence_path = tmp_path / "linked-evidence.json"
        evidence_path.symlink_to(real_evidence)
    elif kind == "ancestor_symlink":
        linked_parent = tmp_path / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        evidence_path = linked_parent / real_evidence.name
    else:
        evidence_path = tmp_path / "hardlinked-evidence.json"
        os.link(real_evidence, evidence_path)

    with pytest.raises(ValueError, match=r"link|unshared regular file"):
        observe_release_run_binding(run_dir, ROOT, evidence_path)


def test_observer_rejects_linked_run_ancestor(
    tmp_path: Path,
    config_factory,
) -> None:
    real_parent = tmp_path / "real-parent"
    run_dir = real_parent / "run"
    _write_run(run_dir, config_factory(), run_id="linked-run")
    evidence_path = tmp_path / "evidence.json"
    _write_evidence(run_dir, evidence_path)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="may not traverse a link"):
        observe_release_run_binding(linked_parent / "run", ROOT, evidence_path)


def test_observer_refuses_artifact_evidence_inside_the_emitted_run(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id="contained-evidence")
    external = tmp_path / "external-evidence.json"
    _write_evidence(run_dir, external)
    internal = run_dir / "release-artifact-evidence.json"
    internal.write_bytes(external.read_bytes())

    with pytest.raises(ValueError, match="must be outside the emitted run"):
        observe_release_run_binding(run_dir, ROOT, internal)


def test_observer_detects_artifact_evidence_race(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id="racing-evidence")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    _write_evidence(run_dir, evidence_path)
    real_observer = release_run_module.observe_release_artifacts
    observations = 0

    def observe_then_change_evidence(
        observed_run: Path,
        repository_root: Path,
    ):
        nonlocal observations
        result = real_observer(observed_run, repository_root)
        observations += 1
        if observations == 1:
            evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(
        release_run_module,
        "observe_release_artifacts",
        observe_then_change_evidence,
    )

    with pytest.raises(ValueError, match="changed while being bound"):
        observe_release_run_binding(run_dir, ROOT, evidence_path)


def test_observer_detects_run_manifest_race(
    tmp_path: Path,
    config_factory,
    monkeypatch,
) -> None:
    run_dir = tmp_path / "run"
    _write_run(run_dir, config_factory(), run_id="racing-manifest")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    _write_evidence(run_dir, evidence_path)
    real_observer = release_run_module.observe_release_artifacts
    observations = 0

    def observe_then_change_manifest(
        observed_run: Path,
        repository_root: Path,
    ):
        nonlocal observations
        result = real_observer(observed_run, repository_root)
        observations += 1
        if observations == 1:
            manifest_path = run_dir / "run-evidence-manifest.json"
            manifest_path.write_bytes(manifest_path.read_bytes() + b"\n")
        return result

    monkeypatch.setattr(
        release_run_module,
        "observe_release_artifacts",
        observe_then_change_manifest,
    )

    with pytest.raises(
        ValueError,
        match=(
            r"changed while being bound|differs from the explicit emitted run|"
            "manifest differs from the bound"
        ),
    ):
        observe_release_run_binding(run_dir, ROOT, evidence_path)


def test_observer_requires_reconstructable_manifest_schema(
    tmp_path: Path,
    config_factory,
) -> None:
    run_dir = tmp_path / "run"
    current = _write_run(run_dir, config_factory(), run_id="legacy-manifest")
    evidence_path = tmp_path / "release-artifact-evidence.json"
    _write_evidence(run_dir, evidence_path)
    payload = current.model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("run_configuration")
    payload.pop("manifest_sha256")
    payload["manifest_sha256"] = canonical_sha256(payload)
    write_run_evidence_manifest(
        run_dir / "run-evidence-manifest.json",
        RunEvidenceManifest.model_validate(payload),
    )

    with pytest.raises(ValueError, match=r"schema 1\.1"):
        observe_release_run_binding(run_dir, ROOT, evidence_path)
