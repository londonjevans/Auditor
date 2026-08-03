"""Adversarial custody tests for no-copy retained scheduler journals."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import mmaudit.orchestration.manifest as manifest_module
import mmaudit.orchestration.scheduler as scheduler_module
from mmaudit.config import AuditConfig
from mmaudit.models.scheduler import (
    SchedulerArtifact,
    SchedulerRetainedJournalReference,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
)
from mmaudit.models.schemas import AuditReport
from mmaudit.orchestration.manifest import (
    SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME,
    RunEvidenceManifest,
    build_run_evidence_manifest,
    validate_manifest_artifacts,
    validate_scheduler_artifact,
)
from tests.unit.test_scheduler_manifest import (
    _live_scheduler_journal,
    _non_solidity_report,
    _scheduler_artifact,
    _with_scheduler,
    _write_scheduler_run,
)


@dataclass(frozen=True)
class _RetainedJournalCase:
    config: AuditConfig
    report: AuditReport
    artifact: SchedulerArtifact
    owner: Path
    consumer: Path
    reference_path: Path
    manifest: RunEvidenceManifest


def _write_reference(path: Path, reference: SchedulerRetainedJournalReference) -> None:
    path.write_text(reference.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _copy_public_run(owner: Path, consumer: Path) -> None:
    consumer.mkdir(mode=0o700)
    for source in sorted(owner.iterdir(), key=lambda item: item.name):
        if source.is_file():
            shutil.copy2(source, consumer / source.name)
    (consumer / "private").mkdir(mode=0o700)


@pytest.fixture
def retained_case(
    tmp_path: Path,
    config_factory: Any,
) -> _RetainedJournalCase:
    config = config_factory()
    base_report = _non_solidity_report(config)
    artifact, _request = _scheduler_artifact(
        base_report,
        config=config,
        terminal_status=SchedulerTerminalStatus.INVALID,
    )
    report = _with_scheduler(base_report, artifact)
    runs = tmp_path / "output" / "runs"
    runs.mkdir(parents=True, mode=0o700)
    owner = runs / "run-owner"
    consumer = runs / "run-consumer"
    _write_scheduler_run(owner, report, artifact)
    _copy_public_run(owner, consumer)
    reference_path = consumer / "private" / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME
    _write_reference(
        reference_path,
        SchedulerRetainedJournalReference.from_artifact(
            owner_run_id=owner.name,
            consumer_run_id=consumer.name,
            artifact=artifact,
        ),
    )
    with _live_scheduler_journal(owner, artifact) as journal:
        manifest = build_run_evidence_manifest(
            run_dir=consumer,
            report=report,
            config=config,
            scheduler_runtime_journal=journal,
        )
    return _RetainedJournalCase(
        config=config,
        report=report,
        artifact=artifact,
        owner=owner,
        consumer=consumer,
        reference_path=reference_path,
        manifest=manifest,
    )


def _validate(case: _RetainedJournalCase) -> SchedulerArtifact | None:
    reference_path = f"private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
    reference_binding = next(
        binding for binding in case.manifest.artifacts if binding.path == reference_path
    )
    return validate_scheduler_artifact(
        case.consumer,
        case.report,
        config=case.config,
        scheduler_reference_binding=reference_binding,
    )


def _write_resealed_reference_payload(case: _RetainedJournalCase, **changes: Any) -> None:
    payload = json.loads(case.reference_path.read_text(encoding="utf-8"))
    payload.update(changes)
    payload["reference_sha256"] = scheduler_canonical_sha256(
        {key: value for key, value in payload.items() if key != "reference_sha256"}
    )
    case.reference_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def test_detached_retained_journal_reconstructs_after_physical_owner_closed(
    retained_case: _RetainedJournalCase,
) -> None:
    assert _validate(retained_case) == retained_case.artifact
    validate_manifest_artifacts(retained_case.manifest, retained_case.consumer)
    bindings = {item.path: item for item in retained_case.manifest.artifacts}
    relative_reference = f"private/{SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME}"
    assert relative_reference in bindings
    reference_bytes = retained_case.reference_path.read_bytes()
    assert bindings[relative_reference].size == len(reference_bytes)
    assert bindings[relative_reference].sha256 == hashlib.sha256(reference_bytes).hexdigest()


def test_detached_retained_journal_requires_its_sealed_reference_binding(
    retained_case: _RetainedJournalCase,
) -> None:
    with pytest.raises(ValueError, match="lacks its sealed manifest binding"):
        validate_scheduler_artifact(
            retained_case.consumer,
            retained_case.report,
            config=retained_case.config,
        )


@pytest.mark.parametrize("missing", ("owner", "journal"))
def test_retained_journal_rejects_missing_physical_owner_or_journal(
    retained_case: _RetainedJournalCase,
    tmp_path: Path,
    missing: str,
) -> None:
    source = (
        retained_case.owner
        if missing == "owner"
        else retained_case.owner / "private" / "scheduler-journal"
    )
    source.rename(tmp_path / f"detached-{missing}")

    with pytest.raises(ValueError, match="retained journal is unavailable"):
        _validate(retained_case)


def test_retained_journal_rejects_tampered_reference(
    retained_case: _RetainedJournalCase,
) -> None:
    payload = json.loads(retained_case.reference_path.read_text(encoding="utf-8"))
    payload["scheduler_artifact_sha256"] = "f" * 64
    retained_case.reference_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="differs from its sealed binding"):
        _validate(retained_case)


def test_retained_journal_rejects_semantically_valid_owner_swap(
    retained_case: _RetainedJournalCase,
) -> None:
    alternate_artifact, _request = _scheduler_artifact(
        retained_case.report,
        config=retained_case.config,
        terminal_status=SchedulerTerminalStatus.UNCERTAIN,
    )
    alternate_owner = retained_case.owner.parent / "run-alternate-owner"
    _write_scheduler_run(alternate_owner, retained_case.report, alternate_artifact)
    _write_reference(
        retained_case.reference_path,
        SchedulerRetainedJournalReference.from_artifact(
            owner_run_id=alternate_owner.name,
            consumer_run_id=retained_case.consumer.name,
            artifact=retained_case.artifact,
        ),
    )

    with pytest.raises(ValueError, match="differs from its sealed binding"):
        _validate(retained_case)


def test_manifest_rejects_reference_replacement_after_inventory_observation(
    retained_case: _RetainedJournalCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alternate_owner = retained_case.owner.parent / "run-race-owner"
    _write_scheduler_run(alternate_owner, retained_case.report, retained_case.artifact)
    replacement = SchedulerRetainedJournalReference.from_artifact(
        owner_run_id=alternate_owner.name,
        consumer_run_id=retained_case.consumer.name,
        artifact=retained_case.artifact,
    )
    original = manifest_module.validate_scheduler_artifact
    replaced = False

    def replace_after_inventory(*args: Any, **kwargs: Any) -> SchedulerArtifact | None:
        nonlocal replaced
        if not replaced:
            _write_reference(retained_case.reference_path, replacement)
            replaced = True
        return original(*args, **kwargs)

    monkeypatch.setattr(manifest_module, "validate_scheduler_artifact", replace_after_inventory)
    with pytest.raises(ValueError, match="differs from its sealed binding"):
        validate_manifest_artifacts(retained_case.manifest, retained_case.consumer)
    assert replaced


def test_manifest_rejects_owner_chain_injected_during_journal_reconstruction(
    retained_case: _RetainedJournalCase,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner_reference = (
        retained_case.owner / "private" / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME
    )
    original = scheduler_module.open_scheduler_journal_for_verification
    injected = False

    def inject_after_owner_check(*args: Any, **kwargs: Any) -> Any:
        nonlocal injected
        if not injected:
            owner_reference.write_text("{}\n", encoding="utf-8")
            injected = True
        return original(*args, **kwargs)

    monkeypatch.setattr(
        scheduler_module,
        "open_scheduler_journal_for_verification",
        inject_after_owner_check,
    )
    with pytest.raises(ValueError, match=r"custody changed|reference chains are forbidden"):
        validate_manifest_artifacts(retained_case.manifest, retained_case.consumer)
    assert injected


def test_manifest_rejects_reference_replacement_during_journal_reconstruction(
    retained_case: _RetainedJournalCase,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alternate_owner = retained_case.owner.parent / "run-in-window-owner"
    _write_scheduler_run(alternate_owner, retained_case.report, retained_case.artifact)
    replacement_path = tmp_path / "replacement-reference.json"
    _write_reference(
        replacement_path,
        SchedulerRetainedJournalReference.from_artifact(
            owner_run_id=alternate_owner.name,
            consumer_run_id=retained_case.consumer.name,
            artifact=retained_case.artifact,
        ),
    )
    original = scheduler_module.open_scheduler_journal_for_verification
    replaced = False

    def replace_after_reference_open(*args: Any, **kwargs: Any) -> Any:
        nonlocal replaced
        if not replaced:
            replacement_path.replace(retained_case.reference_path)
            replaced = True
        return original(*args, **kwargs)

    monkeypatch.setattr(
        scheduler_module,
        "open_scheduler_journal_for_verification",
        replace_after_reference_open,
    )
    with pytest.raises(
        ValueError,
        match=r"custody changed|changed during semantic validation",
    ):
        validate_manifest_artifacts(retained_case.manifest, retained_case.consumer)
    assert replaced


@pytest.mark.parametrize(
    "linked_component",
    ("reference", "owner", "owner_private", "owner_journal", "consumer_private"),
)
def test_retained_journal_rejects_symlinked_custody_components(
    retained_case: _RetainedJournalCase,
    tmp_path: Path,
    linked_component: str,
) -> None:
    if linked_component == "reference":
        destination = tmp_path / "external-reference.json"
        retained_case.reference_path.rename(destination)
        retained_case.reference_path.symlink_to(destination)
    elif linked_component == "owner":
        destination = tmp_path / "external-owner"
        retained_case.owner.rename(destination)
        retained_case.owner.symlink_to(destination, target_is_directory=True)
    elif linked_component == "owner_private":
        source = retained_case.owner / "private"
        destination = tmp_path / "external-owner-private"
        source.rename(destination)
        source.symlink_to(destination, target_is_directory=True)
    elif linked_component == "owner_journal":
        source = retained_case.owner / "private" / "scheduler-journal"
        destination = tmp_path / "external-owner-journal"
        source.rename(destination)
        source.symlink_to(destination, target_is_directory=True)
    else:
        source = retained_case.consumer / "private"
        destination = tmp_path / "external-consumer-private"
        source.rename(destination)
        source.symlink_to(destination, target_is_directory=True)

    with pytest.raises(ValueError):
        _validate(retained_case)


def test_detached_manifest_rejects_symlinked_consumer_run(
    retained_case: _RetainedJournalCase,
) -> None:
    alias = retained_case.consumer.parent / "run-consumer-alias"
    alias.symlink_to(retained_case.consumer, target_is_directory=True)

    with pytest.raises(ValueError, match="link"):
        validate_manifest_artifacts(retained_case.manifest, alias)


def test_retained_journal_rejects_owner_reference_chain(
    retained_case: _RetainedJournalCase,
) -> None:
    upstream_owner = retained_case.owner.parent / "run-upstream-owner"
    _write_scheduler_run(upstream_owner, retained_case.report, retained_case.artifact)
    _write_reference(
        retained_case.owner / "private" / SCHEDULER_RETAINED_JOURNAL_REFERENCE_FILENAME,
        SchedulerRetainedJournalReference.from_artifact(
            owner_run_id=upstream_owner.name,
            consumer_run_id=retained_case.owner.name,
            artifact=retained_case.artifact,
        ),
    )

    with pytest.raises(ValueError, match="reference chains are forbidden"):
        _validate(retained_case)


@pytest.mark.parametrize(
    ("owner_run_id", "relative_path"),
    (
        ("run-consumer", "run-consumer/private/scheduler-journal"),
        ("../run-owner", "../run-owner/private/scheduler-journal"),
        ("run-owner", "run-owner/private/../scheduler-journal"),
        ("latest", "latest/private/scheduler-journal"),
    ),
)
def test_retained_journal_rejects_same_run_and_path_tricks(
    retained_case: _RetainedJournalCase,
    owner_run_id: str,
    relative_path: str,
) -> None:
    _write_resealed_reference_payload(
        retained_case,
        owner_run_id=owner_run_id,
        relative_journal_path=relative_path,
    )

    with pytest.raises(ValueError, match="differs from its sealed binding"):
        _validate(retained_case)
