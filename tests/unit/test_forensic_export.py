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
from mmaudit.orchestration.manifest import (
    canonical_sha256,
    collect_run_artifacts,
    seal_run_evidence_manifest,
    write_run_evidence_manifest,
)
from mmaudit.reporting.json_report import write_json
from tests.taxonomy_custody_support import write_exact_taxonomy_custody
from tests.unit.test_release_artifacts import _seal_manifest, _write_run
from tests.unit.test_scheduler_retained_journal_manifest import (
    _seal_retained_consumer_for_export,
)
from tests.unit.test_scheduler_retained_journal_manifest import (
    retained_case as _retained_case_fixture,
)

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

    assert (
        json.loads((source / "run-evidence-manifest.json").read_text(encoding="utf-8"))[
            "schema_version"
        ]
        == "1.3"
    )
    assert descriptor.bundle_kind == "COMPLETE_FORENSIC_BUNDLE"
    assert descriptor.evidence_inclusion_policy == (
        "ALL_MANIFEST_BOUND_AND_REQUIRED_DEPENDENCY_ARTIFACTS"
    )
    assert descriptor.private_evidence_included
    assert descriptor.logs_included
    assert descriptor.private_artifact_count == 2
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
    assert (exported_run / "private" / "run-terminal-report-authority.json").is_file()
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


def test_export_keeps_incomplete_marker_through_nested_verification(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    marker = destination / "INCOMPLETE_FORENSIC_EXPORT"
    real_verify = forensic_export_module.verify_complete_forensic_bundle
    real_remove = forensic_export_module._remove_incomplete_marker
    events: list[str] = []

    def verify_while_incomplete(**kwargs):
        assert marker.read_bytes() == b"INCOMPLETE_FORENSIC_EXPORT\n"
        events.append("verified-snapshot")
        verified = real_verify(**kwargs)
        assert marker.read_bytes() == b"INCOMPLETE_FORENSIC_EXPORT\n"
        return verified

    def remove_as_final_publication_action(wrapper_descriptor: int) -> None:
        assert events == ["verified-snapshot"]
        assert marker.read_bytes() == b"INCOMPLETE_FORENSIC_EXPORT\n"
        events.append("removed-marker")
        real_remove(wrapper_descriptor)

    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        verify_while_incomplete,
    )
    monkeypatch.setattr(
        forensic_export_module,
        "_remove_incomplete_marker",
        remove_as_final_publication_action,
    )

    export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )

    assert events == ["verified-snapshot", "removed-marker"]
    assert not marker.exists()


def test_descriptor_counts_required_private_authority_without_overclaiming_optional_classes(
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

    assert descriptor.private_evidence_included
    assert not descriptor.logs_included
    assert descriptor.private_artifact_count == 1
    assert descriptor.log_artifact_count == 0
    assert [artifact.path for artifact in descriptor.artifacts if "/private/" in artifact.path] == [
        "runs/run-without-sensitive-classes/private/run-terminal-report-authority.json"
    ]


def test_complete_run_observer_accepts_manifest_14(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "current-run"
    legacy = _write_run(source, config_factory())
    taxonomy_bindings = write_exact_taxonomy_custody(source)
    write_json(
        source / "private" / "model-review-artifacts.json",
        {"schema_version": "1.0", "artifacts": []},
    )
    current_bindings = legacy.bindings.model_copy(
        update={
            "coverage": sorted(
                [*legacy.bindings.coverage, *taxonomy_bindings],
                key=lambda binding: binding.identifier,
            )
        }
    )
    assert legacy.run_configuration is not None
    current = seal_run_evidence_manifest(
        run_id=legacy.run_id,
        repository_root_name=legacy.repository_root_name,
        git_commit=legacy.git_commit,
        sources=legacy.sources,
        run_configuration=legacy.run_configuration,
        bindings=current_bindings,
        artifacts=collect_run_artifacts(source),
        tool_version="test",
    )
    write_run_evidence_manifest(source / "run-evidence-manifest.json", current)
    monkeypatch.setattr(
        forensic_export_module,
        "validate_manifest_artifacts",
        lambda *_args, **_kwargs: None,
    )

    observed, _manifest_bytes, inventory = forensic_export_module._observe_complete_run(source)

    assert observed.schema_version == "1.4"
    assert len(inventory) == len(current.artifacts) + 1


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


def test_export_rejects_destination_parent_swap_and_restore_before_creation(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination_parent = tmp_path / "destination-parent"
    replacement_parent = tmp_path / "replacement-parent"
    held_original_parent = tmp_path / "held-original-parent"
    displaced_replacement_parent = tmp_path / "displaced-replacement-parent"
    destination_parent.mkdir()
    replacement_parent.mkdir()
    destination = destination_parent / "complete-forensic"
    real_create = forensic_export_module._create_fresh_wrapper
    real_verify = forensic_export_module.verify_complete_forensic_bundle
    swapped = False
    restored = False

    def restore_parent() -> None:
        nonlocal restored
        if restored:
            return
        if destination_parent.exists():
            destination_parent.rename(displaced_replacement_parent)
        if held_original_parent.exists():
            held_original_parent.rename(destination_parent)
        restored = True

    def swap_before_creation(candidate):
        nonlocal swapped
        destination_parent.rename(held_original_parent)
        replacement_parent.rename(destination_parent)
        swapped = True
        return real_create(candidate)

    def restore_after_final_verification(**kwargs):
        verified = real_verify(**kwargs)
        restore_parent()
        return verified

    monkeypatch.setattr(
        forensic_export_module,
        "_create_fresh_wrapper",
        swap_before_creation,
    )
    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        restore_after_final_verification,
    )

    try:
        with pytest.raises(ValueError, match="destination parent root changed"):
            export_complete_forensic_bundle(
                source_run=source,
                destination=destination,
                acknowledge_sensitive_evidence=True,
            )
    finally:
        restore_parent()

    assert swapped
    assert restored
    assert not destination.exists()
    assert not (displaced_replacement_parent / destination.name).exists()


def test_export_rejects_destination_ancestor_adoption_with_same_parent_inode(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_parent = tmp_path / "source-parent"
    source_parent.mkdir()
    source = _complete_run(source_parent, config_factory)
    destination_zone = tmp_path / "destination-zone"
    trusted_ancestor = destination_zone / "trusted-ancestor"
    replacement_ancestor = destination_zone / "replacement-ancestor"
    held_ancestor = destination_zone / "held-ancestor"
    displaced_ancestor = destination_zone / "displaced-ancestor"
    destination_parent = trusted_ancestor / "destination-parent"
    destination_parent.mkdir(parents=True)
    replacement_ancestor.mkdir()
    destination = destination_parent / "complete-forensic"
    original_parent_inode = destination_parent.stat().st_ino
    real_reobserve = forensic_export_module.reobserve_same_unlinked_directory
    transferred = False

    def transfer_ancestor_before_rebaseline(*args, **kwargs):
        nonlocal transferred
        if kwargs.get("label") == "forensic destination parent" and not transferred:
            trusted_ancestor.rename(held_ancestor)
            (held_ancestor / destination_parent.name).rename(
                replacement_ancestor / destination_parent.name
            )
            replacement_ancestor.rename(trusted_ancestor)
            transferred = True
        return real_reobserve(*args, **kwargs)

    monkeypatch.setattr(
        forensic_export_module,
        "reobserve_same_unlinked_directory",
        transfer_ancestor_before_rebaseline,
    )

    try:
        with pytest.raises(ValueError, match="metadata rebaseline"):
            export_complete_forensic_bundle(
                source_run=source,
                destination=destination,
                acknowledge_sensitive_evidence=True,
            )
    finally:
        if trusted_ancestor.exists():
            trusted_ancestor.rename(displaced_ancestor)
        moved_parent = displaced_ancestor / destination_parent.name
        if moved_parent.exists():
            moved_parent.rename(held_ancestor / destination_parent.name)
        if held_ancestor.exists():
            held_ancestor.rename(trusted_ancestor)

    assert transferred
    assert destination_parent.stat().st_ino == original_parent_inode
    assert not destination.exists()


def test_export_rejects_source_run_swap_use_restore_during_copy(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_parent = tmp_path / "source-parent"
    destination_parent = tmp_path / "destination-parent"
    source_parent.mkdir()
    destination_parent.mkdir()
    source = _complete_run(source_parent, config_factory)
    twin = source_parent / "source-twin"
    held = source_parent / "source-held"
    displaced = source_parent / "source-displaced"
    shutil.copytree(source, twin, copy_function=shutil.copy2)
    destination = destination_parent / "complete-forensic"
    real_copy = forensic_export_module._copy_bound_inventory
    swapped = False

    def copy_from_twin(**kwargs):
        nonlocal swapped
        if kwargs["source_root"] != source or swapped:
            return real_copy(**kwargs)
        source.rename(held)
        twin.rename(source)
        swapped = True
        try:
            return real_copy(**kwargs)
        finally:
            source.rename(displaced)
            held.rename(source)

    monkeypatch.setattr(forensic_export_module, "_copy_bound_inventory", copy_from_twin)

    with pytest.raises(ValueError, match="source run root changed during custody"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert swapped
    assert source.is_dir()
    assert displaced.is_dir()
    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_source_descendant_directory_twin_swap_use_restore_during_copy(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    nested = source / "logs" / "engine"
    stash = tmp_path / "source-descendant-stash"
    twin = stash / "engine-twin"
    held = stash / "engine-held"
    displaced = stash / "engine-displaced"
    stash.mkdir()
    shutil.copytree(nested, twin, copy_function=shutil.copy2)
    destination = tmp_path / "complete-forensic"
    real_copy = forensic_export_module._copy_bound_inventory
    swapped = False

    def copy_from_descendant_twin(**kwargs):
        nonlocal swapped
        if kwargs["source_root"] != source or swapped:
            return real_copy(**kwargs)
        nested.rename(held)
        twin.rename(nested)
        swapped = True
        try:
            return real_copy(**kwargs)
        finally:
            nested.rename(displaced)
            held.rename(nested)

    monkeypatch.setattr(
        forensic_export_module,
        "_copy_bound_inventory",
        copy_from_descendant_twin,
    )

    with pytest.raises(ValueError, match="source run descendant directory authority changed"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert swapped
    assert nested.is_dir()
    assert displaced.is_dir()
    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_retained_journal_swap_use_restore_during_copy(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_root = tmp_path / "retained-case"
    retained = _retained_case_fixture.__wrapped__(case_root, config_factory)
    consumer, _manifest = _seal_retained_consumer_for_export(retained)
    journal = retained.owner / "private" / "scheduler-journal"
    twin = retained.owner / "private" / "journal-twin"
    held = retained.owner / "private" / "journal-held"
    displaced = retained.owner / "private" / "journal-displaced"
    shutil.copytree(journal, twin, copy_function=shutil.copy2)
    destination_parent = tmp_path / "retained-destination"
    destination_parent.mkdir()
    destination = destination_parent / "complete-forensic"
    real_copy = forensic_export_module._copy_bound_inventory
    swapped = False

    def copy_from_twin(**kwargs):
        nonlocal swapped
        if kwargs["source_root"] != journal or swapped:
            return real_copy(**kwargs)
        journal.rename(held)
        twin.rename(journal)
        swapped = True
        try:
            return real_copy(**kwargs)
        finally:
            journal.rename(displaced)
            held.rename(journal)

    monkeypatch.setattr(forensic_export_module, "_copy_bound_inventory", copy_from_twin)

    with pytest.raises(ValueError, match="retained scheduler journal root changed during custody"):
        export_complete_forensic_bundle(
            source_run=consumer,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert swapped
    assert journal.is_dir()
    assert displaced.is_dir()
    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_retained_journal_descendant_twin_swap_use_restore_during_copy(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_root = tmp_path / "retained-case"
    retained = _retained_case_fixture.__wrapped__(case_root, config_factory)
    consumer, _manifest = _seal_retained_consumer_for_export(retained)
    journal = retained.owner / "private" / "scheduler-journal"
    nested_parent = journal / "events"
    nested = nested_parent / "synthetic-depth-two"
    nested.mkdir()
    (nested / "custody.bin").write_bytes(b"synthetic retained descendant custody\n")
    stash = tmp_path / "retained-descendant-stash"
    twin = stash / "depth-two-twin"
    held = stash / "depth-two-held"
    displaced = stash / "depth-two-displaced"
    stash.mkdir()
    shutil.copytree(nested, twin, copy_function=shutil.copy2)
    destination = tmp_path / "complete-forensic-retained"
    real_copy = forensic_export_module._copy_bound_inventory
    swapped = False

    def copy_from_descendant_twin(**kwargs):
        nonlocal swapped
        if kwargs["source_root"] != journal or swapped:
            return real_copy(**kwargs)
        nested.rename(held)
        twin.rename(nested)
        swapped = True
        try:
            return real_copy(**kwargs)
        finally:
            nested.rename(displaced)
            held.rename(nested)

    monkeypatch.setattr(
        forensic_export_module,
        "validate_manifest_artifacts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        forensic_export_module,
        "_copy_bound_inventory",
        copy_from_descendant_twin,
    )

    with pytest.raises(
        ValueError,
        match="retained scheduler journal descendant directory authority changed",
    ):
        export_complete_forensic_bundle(
            source_run=consumer,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert swapped
    assert nested.is_dir()
    assert displaced.is_dir()
    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_destination_parent_edit_restored_after_final_verification(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination_parent = tmp_path / "destination-parent"
    destination_parent.mkdir()
    destination = destination_parent / "complete-forensic"
    real_verify = forensic_export_module.verify_complete_forensic_bundle

    def edit_and_restore_parent_after_verification(**kwargs):
        verified = real_verify(**kwargs)
        transient = destination_parent / "transient-after-verification"
        transient.write_text("temporary\n", encoding="utf-8")
        transient.unlink()
        return verified

    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        edit_and_restore_parent_after_verification,
    )

    with pytest.raises(ValueError, match="destination parent root changed"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_artifact_edit_after_nested_verification(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    real_verify = forensic_export_module.verify_complete_forensic_bundle

    def verify_then_edit_artifact(**kwargs):
        verified = real_verify(**kwargs)
        artifact = next((destination / "runs").rglob("execution.log"))
        artifact.write_text("changed after nested verification\n", encoding="utf-8")
        return verified

    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        verify_then_edit_artifact,
    )

    with pytest.raises(ValueError, match=r"file authority|custody changed"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


def test_export_rejects_earlier_artifact_edit_during_later_final_custody_check(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    earlier_artifact = destination / "runs" / source.name / "logs" / "engine" / "execution.log"
    later_path = f"runs/{source.name}/run-evidence-manifest.json"
    real_observer = forensic_export_module._observe_bound_delivery_file
    real_verify = forensic_export_module.verify_complete_forensic_bundle
    nested_verification_complete = False
    later_checks_after_nested_verification = 0
    mutated = False

    def verify_then_enable_final_mutation(**kwargs):
        nonlocal nested_verification_complete
        verified = real_verify(**kwargs)
        nested_verification_complete = True
        return verified

    def observe_with_late_edit(wrapper_descriptor, binding):
        nonlocal later_checks_after_nested_verification, mutated
        observed = real_observer(wrapper_descriptor, binding)
        if nested_verification_complete and binding.path == later_path:
            later_checks_after_nested_verification += 1
            if later_checks_after_nested_verification == 3:
                original = earlier_artifact.read_bytes()
                earlier_artifact.write_bytes(b"X" * len(original))
                mutated = True
        return observed

    monkeypatch.setattr(
        forensic_export_module,
        "verify_complete_forensic_bundle",
        verify_then_enable_final_mutation,
    )
    monkeypatch.setattr(
        forensic_export_module,
        "_observe_bound_delivery_file",
        observe_with_late_edit,
    )

    with pytest.raises(ValueError, match=r"file authority|bounded custody"):
        export_complete_forensic_bundle(
            source_run=source,
            destination=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert later_checks_after_nested_verification >= 3
    assert mutated
    assert (destination / "INCOMPLETE_FORENSIC_EXPORT").is_file()


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


def test_verifier_rejects_artifact_edit_after_final_inventory(
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
    real_revalidate = forensic_export_module._revalidate_delivery_anchors
    revalidation_calls = 0
    mutated = False

    def revalidate_then_edit(wrapper_root, descriptor, anchors):
        nonlocal mutated, revalidation_calls
        real_revalidate(wrapper_root, descriptor, anchors)
        revalidation_calls += 1
        if revalidation_calls == 2:
            artifact.write_text("changed after final inventory\n", encoding="utf-8")
            mutated = True

    monkeypatch.setattr(
        forensic_export_module,
        "_revalidate_delivery_anchors",
        revalidate_then_edit,
    )

    with pytest.raises(ValueError, match=r"file authority|custody changed"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert revalidation_calls == 2
    assert mutated


def test_verifier_rejects_earlier_artifact_edit_during_later_final_custody_check(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    earlier_binding = next(
        binding for binding in descriptor.artifacts if binding.path.endswith("/execution.log")
    )
    later_binding = next(
        binding
        for binding in descriptor.artifacts
        if binding.path.endswith("/run-evidence-manifest.json")
    )
    assert descriptor.artifacts.index(earlier_binding) < descriptor.artifacts.index(later_binding)
    earlier_artifact = destination / earlier_binding.path
    real_observer = forensic_export_module._observe_bound_delivery_file
    later_checks = 0
    mutated = False

    def observe_with_late_edit(wrapper_descriptor, binding):
        nonlocal later_checks, mutated
        observed = real_observer(wrapper_descriptor, binding)
        if binding.path == later_binding.path:
            later_checks += 1
            if later_checks == 5:
                original = earlier_artifact.read_bytes()
                earlier_artifact.write_bytes(b"X" * len(original))
                mutated = True
        return observed

    monkeypatch.setattr(
        forensic_export_module,
        "_observe_bound_delivery_file",
        observe_with_late_edit,
    )

    with pytest.raises(ValueError, match=r"file authority|bounded custody"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert later_checks >= 5
    assert mutated


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


def test_partial_marker_write_removes_only_its_created_inode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wrapper = tmp_path / "wrapper"
    wrapper.mkdir(mode=0o700)
    descriptor = forensic_export_module._open_directory_descriptor(wrapper)
    real_write = forensic_export_module.os.write
    attempted = False

    def fail_after_partial_write(file_descriptor: int, content) -> int:
        nonlocal attempted
        if not attempted:
            attempted = True
            real_write(file_descriptor, content[:1])
            raise OSError("synthetic partial marker write failure")
        return real_write(file_descriptor, content)

    monkeypatch.setattr(forensic_export_module.os, "write", fail_after_partial_write)
    try:
        with pytest.raises(ValueError, match="could not be created safely"):
            forensic_export_module._write_incomplete_marker(descriptor)
    finally:
        os.close(descriptor)

    assert attempted
    assert not (wrapper / "INCOMPLETE_FORENSIC_EXPORT").exists()


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


def test_directory_inventory_count_is_bounded_before_delivery_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "many-directories"
    (root / "one").mkdir(parents=True)
    (root / "two").mkdir()
    monkeypatch.setattr(forensic_export_module, "_MAX_ARTIFACTS", 1)

    with pytest.raises(ValueError, match="directory inventory exceeds its count bound"):
        forensic_export_module._observe_directory_inventory(root)


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


def test_verifier_rejects_primary_directory_twin_swap_use_restore(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _complete_run(tmp_path, config_factory)
    destination = tmp_path / "complete-forensic"
    descriptor = export_complete_forensic_bundle(
        source_run=source,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    primary = destination / descriptor.primary_run_directory
    stash = tmp_path / "swap-stash"
    twin = stash / "primary-twin"
    held = stash / "primary-held"
    stash.mkdir()
    shutil.copytree(primary, twin, copy_function=shutil.copy2)
    real_inventory = forensic_export_module._observe_delivery_inventory
    inventory_calls = 0
    swapped = False

    def observe_with_transient_twin(**kwargs):
        nonlocal inventory_calls, swapped
        inventory_calls += 1
        if inventory_calls != 2:
            return real_inventory(**kwargs)
        primary.rename(held)
        twin.rename(primary)
        swapped = True
        try:
            return real_inventory(**kwargs)
        finally:
            primary.rename(twin)
            held.rename(primary)

    monkeypatch.setattr(
        forensic_export_module,
        "_observe_delivery_inventory",
        observe_with_transient_twin,
    )

    with pytest.raises(ValueError, match=r"directory authority|custody changed"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert inventory_calls == 2
    assert swapped
    assert primary.is_dir()


def test_verifier_rejects_retained_journal_twin_swap_use_restore(
    tmp_path: Path,
    config_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case_root = tmp_path / "retained-case"
    retained = _retained_case_fixture.__wrapped__(case_root, config_factory)
    consumer, _manifest = _seal_retained_consumer_for_export(retained)
    destination = tmp_path / "complete-forensic-retained"
    descriptor = export_complete_forensic_bundle(
        source_run=consumer,
        destination=destination,
        acknowledge_sensitive_evidence=True,
    )
    dependency = descriptor.retained_journal_dependencies[0]
    journal = destination / dependency.journal_directory
    stash = tmp_path / "retained-swap-stash"
    twin = stash / "journal-twin"
    held = stash / "journal-held"
    stash.mkdir()
    shutil.copytree(journal, twin, copy_function=shutil.copy2)
    real_inventory = forensic_export_module._observe_delivery_inventory
    inventory_calls = 0
    swapped = False

    def observe_with_transient_twin(**kwargs):
        nonlocal inventory_calls, swapped
        inventory_calls += 1
        if inventory_calls != 2:
            return real_inventory(**kwargs)
        journal.rename(held)
        twin.rename(journal)
        swapped = True
        try:
            return real_inventory(**kwargs)
        finally:
            journal.rename(twin)
            held.rename(journal)

    monkeypatch.setattr(
        forensic_export_module,
        "_observe_delivery_inventory",
        observe_with_transient_twin,
    )

    with pytest.raises(ValueError, match=r"directory authority|custody changed"):
        verify_complete_forensic_bundle(
            delivery_root=destination,
            acknowledge_sensitive_evidence=True,
        )

    assert inventory_calls == 2
    assert swapped
    assert journal.is_dir()


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
