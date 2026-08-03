from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.forensic_export as forensic_export_module
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.forensic_export import (
    ForensicDeliveryDescriptor,
    export_complete_forensic_bundle,
    verify_complete_forensic_bundle,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_release_artifacts import _seal_manifest, _write_run

runner = CliRunner()
CANARY = b"SYNTHETIC-FORENSIC-PRIVATE-CANARY"


def _complete_run(tmp_path: Path, config_factory) -> Path:
    run_dir = tmp_path / "original-run"
    config = config_factory()
    _write_run(run_dir, config)
    private = run_dir / "private" / "scanner-output"
    private.mkdir(parents=True)
    (private / "raw-output.bin").write_bytes(b"\x00" + CANARY + b"\xff\n")
    logs = run_dir / "logs" / "engine"
    logs.mkdir(parents=True)
    (logs / "execution.log").write_text("bounded local execution evidence\n", encoding="utf-8")
    (logs / "empty.log").write_bytes(b"")
    _seal_manifest(run_dir, config)
    return run_dir


def test_export_retains_exact_private_logs_and_is_portable_without_original(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"

    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )

    assert descriptor.bundle_kind == "COMPLETE_FORENSIC_BUNDLE"
    assert descriptor.evidence_inclusion_policy == (
        "ALL_MANIFEST_BOUND_AND_REQUIRED_DEPENDENCY_ARTIFACTS"
    )
    assert descriptor.private_evidence_included
    assert descriptor.logs_included
    assert descriptor.private_artifact_count == 1
    assert descriptor.log_artifact_count == 2
    observed_inventory = sorted(
        path.relative_to(destination).as_posix()
        for path in (destination / "runs").rglob("*")
        if path.is_file()
    )
    assert [binding.path for binding in descriptor.artifacts] == observed_inventory
    exported_run = destination / descriptor.primary_run_directory
    assert (exported_run / "private" / "scanner-output" / "raw-output.bin").read_bytes() == (
        source / "private" / "scanner-output" / "raw-output.bin"
    ).read_bytes()
    assert (exported_run / "logs" / "engine" / "empty.log").read_bytes() == b""
    assert not (destination / "INCOMPLETE_FORENSIC_EXPORT").exists()
    assert CANARY.decode() not in (destination / "forensic-delivery.json").read_text(
        encoding="utf-8"
    )
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "runs").stat().st_mode) == 0o700
    assert stat.S_IMODE(exported_run.stat().st_mode) == 0o700
    assert stat.S_IMODE((destination / "forensic-delivery.json").stat().st_mode) == 0o600

    source.rename(tmp_path / "original-run-removed")
    verified = verify_complete_forensic_bundle(
        delivery_root=destination,
        acknowledge_sensitive_evidence=True,
    )

    assert verified == descriptor
    assert verified.artifact_inventory_sha256 == canonical_sha256(
        [binding.model_dump(mode="json") for binding in verified.artifacts]
    )


def test_descriptor_does_not_overclaim_absent_sensitive_classes(
    tmp_path: Path,
    config_factory,
) -> None:
    source = tmp_path / "run-without-sensitive-classes"
    _write_run(source, config_factory())

    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=tmp_path / "export-without-sensitive-classes",
        acknowledge_sensitive_evidence=True,
    )

    assert not descriptor.private_evidence_included
    assert not descriptor.logs_included
    assert descriptor.private_artifact_count == 0
    assert descriptor.log_artifact_count == 0


def test_export_requires_acknowledgement_before_creating_destination(
    tmp_path: Path,
) -> None:
    source = tmp_path / "must-not-be-observed"
    destination = tmp_path / "refused"

    with pytest.raises(ValueError, match="explicit sensitive-evidence acknowledgement"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=False,
        )

    assert not destination.exists()


def test_descriptor_size_rejection_occurs_before_destination_creation(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "descriptor-too-large"
    monkeypatch.setattr(forensic_export_module, "_MAX_DESCRIPTOR_BYTES", 1)

    with pytest.raises(ValueError, match="descriptor exceeds its output bound"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert not destination.exists()


def test_verifier_requires_sensitive_evidence_acknowledgement(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "must-not-be-observed"

    with pytest.raises(ValueError, match="explicit sensitive-evidence acknowledgement"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=False,
        )


def test_export_refuses_existing_destination_without_changing_it(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "existing"
    destination.mkdir()
    sentinel = destination / "sentinel"
    sentinel.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must not already exist"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert sentinel.read_text(encoding="utf-8") == "preserve\n"


def test_export_refuses_source_destination_overlap_by_identity(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)

    with pytest.raises(ValueError, match="may not overlap"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=source / "nested-export",
            acknowledge_sensitive_evidence=True,
        )

    assert not (source / "nested-export").exists()


def test_export_refuses_linked_source_root(tmp_path: Path, config_factory) -> None:
    source = _complete_run(tmp_path, config_factory)
    linked = tmp_path / "linked-run"
    linked.symlink_to(source, target_is_directory=True)

    with pytest.raises(ValueError, match="link"):
        export_complete_forensic_bundle(
            source_run=linked,
            destination=tmp_path / "refused-linked-source",
            acknowledge_sensitive_evidence=True,
        )


def test_export_refuses_shared_source_artifact(tmp_path: Path, config_factory) -> None:
    source = _complete_run(tmp_path, config_factory)
    artifact = source / "logs" / "engine" / "execution.log"
    os.link(artifact, tmp_path / "shared-source-artifact.log")

    with pytest.raises(ValueError, match=r"unique regular|unshared"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=tmp_path / "refused-shared-source",
            acknowledge_sensitive_evidence=True,
        )


def test_export_refuses_parent_traversal_and_destination_link(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    traversal = tmp_path / "not-created" / ".." / "escaped"
    with pytest.raises(ValueError, match="parent traversal"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=traversal,
            acknowledge_sensitive_evidence=True,
        )
    assert not (tmp_path / "escaped").exists()

    linked_destination = tmp_path / "linked-destination"
    linked_destination.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="must not already exist"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=linked_destination,
            acknowledge_sensitive_evidence=True,
        )


def test_export_refuses_ci_public_subset_marker(tmp_path: Path, config_factory) -> None:
    source = _complete_run(tmp_path, config_factory)
    (source / "public-evidence-subset-manifest.json").write_text(
        '{"bundle_kind":"NON_FORENSIC_PUBLIC_SUBSET"}\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="CI public subset"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=tmp_path / "refused-public-subset",
            acknowledge_sensitive_evidence=True,
        )


@pytest.mark.parametrize("mutation", ["tamper", "missing", "symlink", "hardlink"])
def test_verifier_rejects_changed_missing_or_shared_export_artifact(
    tmp_path: Path,
    config_factory,
    mutation: str,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    artifact = destination / "runs" / source.name / "logs" / "engine" / "execution.log"
    if mutation == "tamper":
        artifact.write_text("coherently changed\n", encoding="utf-8")
    elif mutation == "missing":
        artifact.unlink()
    else:
        original = tmp_path / f"{mutation}-target.log"
        artifact.replace(original)
        if mutation == "symlink":
            artifact.symlink_to(original)
        else:
            os.link(original, artifact)

    with pytest.raises(ValueError, match=r"artifact|link|regular|shared|manifest"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )


def test_verifier_reobserves_run_after_final_descriptor_read(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    artifact = destination / "runs" / source.name / "logs" / "engine" / "execution.log"
    real_reader = forensic_export_module.read_json_evidence
    descriptor_reads = 0

    def mutate_after_final_descriptor_read(**kwargs):
        nonlocal descriptor_reads
        observation = real_reader(**kwargs)
        if kwargs["relative_path"] == "forensic-delivery.json":
            descriptor_reads += 1
            if descriptor_reads == 2:
                artifact.write_text("changed after final descriptor read\n", encoding="utf-8")
        return observation

    monkeypatch.setattr(
        forensic_export_module,
        "read_json_evidence",
        mutate_after_final_descriptor_read,
    )

    with pytest.raises(ValueError, match=r"artifact|manifest|changed during verification"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert descriptor_reads == 2


def test_verifier_rejects_descriptor_tamper_and_wrapper_extras(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    descriptor_path = destination / "forensic-delivery.json"
    payload = json.loads(descriptor_path.read_text(encoding="utf-8"))
    payload["artifact_total_bytes"] += 1
    descriptor_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match=r"descriptor|byte total"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    descriptor_path.unlink()
    (destination / "unexpected.txt").write_text("not bound\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"wrapper inventory|file is missing"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )


def test_failed_copy_retains_explicit_incomplete_marker(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "interrupted-export"
    real_copier = forensic_export_module.copy_file_evidence
    copied = False

    def fail_first_copy(**kwargs):
        nonlocal copied
        if not copied:
            copied = True
            raise ValueError("synthetic bounded copy failure")
        return real_copier(**kwargs)

    monkeypatch.setattr(forensic_export_module, "copy_file_evidence", fail_first_copy)

    with pytest.raises(ValueError, match="synthetic bounded copy failure"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").read_bytes() == (
        b"INCOMPLETE_FORENSIC_EXPORT\n"
    )
    assert not (destination / "forensic-delivery.json").exists()


def test_marker_creation_failure_rolls_back_exact_empty_wrapper(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "marker-refused"

    def fail_marker(_descriptor: int) -> None:
        raise ValueError("synthetic marker creation failure")

    monkeypatch.setattr(forensic_export_module, "_write_incomplete_marker", fail_marker)

    with pytest.raises(ValueError, match="synthetic marker creation failure"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert not destination.exists()


def test_marker_finalization_fsync_failure_restores_incomplete_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = tmp_path / "wrapper"
    wrapper.mkdir(mode=0o700)
    descriptor = forensic_export_module._open_directory_descriptor(wrapper)
    forensic_export_module._write_incomplete_marker(descriptor)
    real_fsync = forensic_export_module.os.fsync
    calls = 0

    def fail_once(file_descriptor: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("synthetic directory fsync failure")
        real_fsync(file_descriptor)

    monkeypatch.setattr(forensic_export_module.os, "fsync", fail_once)
    try:
        with pytest.raises(ValueError, match="incomplete marker restored"):
            forensic_export_module._remove_incomplete_marker(descriptor)
    finally:
        os.close(descriptor)

    assert (wrapper / "INCOMPLETE_FORENSIC_EXPORT").read_bytes() == (
        b"INCOMPLETE_FORENSIC_EXPORT\n"
    )


def test_final_verifier_failure_restores_incomplete_marker(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "verification-failed"

    def fail_final_verification(**_kwargs):
        raise ValueError("synthetic final verifier failure")

    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        fail_final_verification,
    )

    with pytest.raises(ValueError, match="synthetic final verifier failure"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").read_bytes() == (
        b"INCOMPLETE_FORENSIC_EXPORT\n"
    )


@pytest.mark.parametrize(
    "paths",
    [
        ["runs/Primary/Report.json", "runs/primary/report.json"],
        ["runs/primary/Evidence", "runs/primary/evidence/child.json"],
    ],
)
def test_portable_path_collisions_are_rejected_before_copy(paths: list[str]) -> None:
    with pytest.raises(ValueError, match="portable-name collision"):
        forensic_export_module._require_portable_paths(paths)


@pytest.mark.parametrize("changed_directory", ["wrapper", "primary"])
def test_verifier_rejects_directory_mode_drift_after_final_descriptor_read(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
    changed_directory: str,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    changed = (
        destination
        if changed_directory == "wrapper"
        else destination / descriptor.primary_run_directory
    )
    real_reader = forensic_export_module.read_json_evidence
    descriptor_reads = 0

    def chmod_after_final_descriptor_read(**kwargs):
        nonlocal descriptor_reads
        observation = real_reader(**kwargs)
        if kwargs["relative_path"] == "forensic-delivery.json":
            descriptor_reads += 1
            if descriptor_reads == 2:
                changed.chmod(0o777)
        return observation

    monkeypatch.setattr(
        forensic_export_module,
        "read_json_evidence",
        chmod_after_final_descriptor_read,
    )

    with pytest.raises(ValueError, match=r"authority changed|unsafe"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )


@pytest.mark.parametrize("swapped_directory", ["wrapper", "primary"])
def test_verifier_rejects_byte_identical_directory_swap(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
    swapped_directory: str,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    target = (
        destination
        if swapped_directory == "wrapper"
        else destination / descriptor.primary_run_directory
    )
    twin = tmp_path / f"{swapped_directory}-twin"
    displaced = tmp_path / f"{swapped_directory}-displaced"
    shutil.copytree(target, twin, copy_function=shutil.copy2)
    real_reader = forensic_export_module.read_json_evidence
    descriptor_reads = 0

    def swap_after_final_descriptor_read(**kwargs):
        nonlocal descriptor_reads
        observation = real_reader(**kwargs)
        if kwargs["relative_path"] == "forensic-delivery.json":
            descriptor_reads += 1
            if descriptor_reads == 2:
                target.rename(displaced)
                twin.rename(target)
        return observation

    monkeypatch.setattr(
        forensic_export_module,
        "read_json_evidence",
        swap_after_final_descriptor_read,
    )

    with pytest.raises(ValueError, match=r"identity changed|authority changed"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )


def test_cli_help_and_acknowledgement_exit_behavior(tmp_path: Path) -> None:
    root_help = runner.invoke(app, ["--help"])
    export_help = runner.invoke(app, ["export-forensic", "--help"], env={"COLUMNS": "300"})
    verify_help = runner.invoke(
        app,
        ["verify-forensic-export", "--help"],
        env={"COLUMNS": "300"},
    )

    assert root_help.exit_code == 0
    assert "export-forensic" in root_help.stdout
    assert "verify-forensic-export" in root_help.stdout
    assert export_help.exit_code == 0
    assert "--acknowledge-sensitive-evidence" in export_help.stdout
    assert verify_help.exit_code == 0
    assert "--acknowledge-sensitive-evidence" in verify_help.stdout

    source = tmp_path / "must-not-be-observed"
    destination = tmp_path / "cli-refused"
    refused = runner.invoke(
        app,
        [
            "export-forensic",
            "--run-dir",
            str(source),
            "--destination",
            str(destination),
            "--no-color",
        ],
    )

    assert refused.exit_code == ExitCode.CONFIGURATION
    assert "requires explicit sensitive-evidence acknowledgement" in " ".join(
        refused.stdout.split()
    )
    assert not destination.exists()


def test_cli_exports_and_verifies_complete_forensic_bundle(
    tmp_path: Path,
    config_factory,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "cli-complete"

    exported = runner.invoke(
        app,
        [
            "export-forensic",
            "--run-dir",
            str(source),
            "--destination",
            str(destination),
            "--acknowledge-sensitive-evidence",
            "--no-color",
        ],
    )
    verified = runner.invoke(
        app,
        [
            "verify-forensic-export",
            "--bundle",
            str(destination),
            "--acknowledge-sensitive-evidence",
            "--no-color",
        ],
    )

    assert exported.exit_code == 0, exported.stdout
    assert "Complete forensic bundle exported" in exported.stdout
    assert CANARY.decode() not in exported.stdout
    assert verified.exit_code == 0, verified.stdout
    assert "Complete forensic bundle verified" in verified.stdout
    descriptor = ForensicDeliveryDescriptor.model_validate_json(
        (destination / "forensic-delivery.json").read_text(encoding="utf-8")
    )
    assert descriptor.private_evidence_included
    assert descriptor.logs_included
