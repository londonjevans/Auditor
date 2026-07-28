"""Fixed, provider-free collection of one candidate-bound release report."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from pydantic import BaseModel

from mmaudit.release import ReleaseGateId
from mmaudit.release_candidate import observe_release_candidate
from mmaudit.release_gates import build_release_gate_evidence_bundle
from mmaudit.release_io import write_json_evidence
from mmaudit.release_observations import collect_bound_release_gate_receipt
from mmaudit.release_report import (
    ReleaseGateReport,
    ReleaseReportInputBinding,
    ReleaseReportInputRole,
    _assemble_release_gate_report,
)
from mmaudit.release_run import observe_release_run_binding
from mmaudit.release_runtime import execute_local_release_gate
from mmaudit.release_static import collect_static_release_evidence
from mmaudit.release_validation import validate_release_report_integrity
from mmaudit.release_verification import observe_release_run_verification

RELEASE_REPORT_PATH: Final = "release-gate-report.json"
_LOCAL_GATE_IDS: Final = frozenset(
    {
        ReleaseGateId.MYPY,
        ReleaseGateId.PYTEST,
        ReleaseGateId.RUFF_CHECK,
        ReleaseGateId.RUFF_FORMAT,
    }
)
_INPUT_PATHS: Final = {
    ReleaseReportInputRole.CANDIDATE: "candidate-observation.json",
    ReleaseReportInputRole.GATE_EVIDENCE: "gate-evidence.json",
    ReleaseReportInputRole.RUN: "run-binding.json",
    ReleaseReportInputRole.RUN_VERIFICATION: "run-verification-binding.json",
    ReleaseReportInputRole.STATIC_EVIDENCE: "static-evidence.json",
}


@dataclass(frozen=True, slots=True)
class _CollectionRoot:
    path: Path
    identity: tuple[int, int, int]


def collect_release_report(
    *,
    release_id: str,
    release_repository_root: Path,
    target_repository_root: Path,
    emitted_run_dir: Path,
    artifact_evidence_path: Path,
    run_verification_path: Path,
    evidence_root: Path,
    report_root: Path,
) -> ReleaseGateReport:
    """Execute the fixed local portfolio and authoritatively validate its report."""

    roots = _preflight_collection_roots(
        release_repository_root=release_repository_root,
        target_repository_root=target_repository_root,
        emitted_run_dir=emitted_run_dir,
        evidence_root=evidence_root,
        report_root=report_root,
    )
    candidate = observe_release_candidate(roots.release_repository.path)
    run = observe_release_run_binding(
        roots.run.path,
        roots.release_repository.path,
        artifact_evidence_path,
    )
    verification = observe_release_run_verification(
        run_dir=roots.run.path,
        target_repository_root=roots.target_repository.path,
        release_repository_root=roots.release_repository.path,
        artifact_evidence_path=artifact_evidence_path,
        verification_path=run_verification_path,
        run_binding=run,
    )
    static = collect_static_release_evidence(
        roots.release_repository.path,
        candidate=candidate,
    )

    input_bindings = [
        _write_report_input(
            evidence_root=roots.evidence.path,
            role=ReleaseReportInputRole.CANDIDATE,
            value=candidate,
            evidence_sha256=candidate.observation_sha256,
        ),
        _write_report_input(
            evidence_root=roots.evidence.path,
            role=ReleaseReportInputRole.RUN,
            value=run,
            evidence_sha256=run.binding_sha256,
        ),
        _write_report_input(
            evidence_root=roots.evidence.path,
            role=ReleaseReportInputRole.RUN_VERIFICATION,
            value=verification,
            evidence_sha256=verification.binding_sha256,
        ),
        _write_report_input(
            evidence_root=roots.evidence.path,
            role=ReleaseReportInputRole.STATIC_EVIDENCE,
            value=static,
            evidence_sha256=static.evidence_sha256,
        ),
    ]

    receipts = []
    for gate_id in sorted(ReleaseGateId, key=lambda item: item.value):
        if gate_id in _LOCAL_GATE_IDS:
            receipt = execute_local_release_gate(
                gate_id=gate_id,
                repository_root=roots.release_repository.path,
                evidence_root=roots.evidence.path,
                candidate_observation_sha256=candidate.observation_sha256,
                run_binding_sha256=run.binding_sha256,
            )
        else:
            receipt = collect_bound_release_gate_receipt(
                gate_id=gate_id,
                evidence_root=roots.evidence.path,
                candidate=candidate,
                run=run,
                run_verification=verification,
                static_evidence=static,
                input_bindings=input_bindings,
            )
        receipts.append(receipt)

    gate_evidence = build_release_gate_evidence_bundle(
        candidate_observation_sha256=candidate.observation_sha256,
        run_binding_sha256=run.binding_sha256,
        receipts=receipts,
    )
    input_bindings.append(
        _write_report_input(
            evidence_root=roots.evidence.path,
            role=ReleaseReportInputRole.GATE_EVIDENCE,
            value=gate_evidence,
            evidence_sha256=gate_evidence.bundle_sha256,
        )
    )
    expected_evidence_files = {
        *(binding.path for binding in input_bindings),
        *(
            binding.path
            for receipt in gate_evidence.receipts
            for binding in receipt.artifact_bindings
        ),
    }
    _require_exact_flat_file_inventory(
        roots.evidence.path,
        expected_paths=expected_evidence_files,
        label="release evidence",
    )
    generated_at = datetime.now(UTC).replace(microsecond=0)
    report = _assemble_release_gate_report(
        release_id=release_id,
        generated_at=generated_at,
        candidate=candidate,
        run=run,
        run_verification=verification,
        static_evidence=static,
        gate_evidence=gate_evidence,
        input_files=input_bindings,
        limitations=[],
    )
    write_json_evidence(
        evidence_root=roots.report.path,
        relative_path=RELEASE_REPORT_PATH,
        value=report,
    )
    _require_exact_flat_file_inventory(
        roots.report.path,
        expected_paths={RELEASE_REPORT_PATH},
        label="release report",
    )
    validated = validate_release_report_integrity(
        report_root=roots.report.path,
        report_relative_path=RELEASE_REPORT_PATH,
        evidence_root=roots.evidence.path,
        release_repository_root=roots.release_repository.path,
        emitted_run_dir=roots.run.path,
        target_repository_root=roots.target_repository.path,
        artifact_evidence_path=artifact_evidence_path,
        run_verification_path=run_verification_path,
    )
    if validated != report:
        raise ValueError("collected release report differs from authoritative validation")
    _require_exact_flat_file_inventory(
        roots.evidence.path,
        expected_paths=expected_evidence_files,
        label="release evidence",
    )
    _require_exact_flat_file_inventory(
        roots.report.path,
        expected_paths={RELEASE_REPORT_PATH},
        label="release report",
    )
    _revalidate_collection_roots(roots)
    return validated


@dataclass(frozen=True, slots=True)
class _CollectionRoots:
    release_repository: _CollectionRoot
    target_repository: _CollectionRoot
    run: _CollectionRoot
    evidence: _CollectionRoot
    report: _CollectionRoot


def _write_report_input(
    *,
    evidence_root: Path,
    role: ReleaseReportInputRole,
    value: BaseModel,
    evidence_sha256: str,
) -> ReleaseReportInputBinding:
    binding = write_json_evidence(
        evidence_root=evidence_root,
        relative_path=_INPUT_PATHS[role],
        value=value,
    )
    return ReleaseReportInputBinding(
        role=role,
        path=binding.path,
        file_sha256=binding.sha256,
        file_size=binding.size,
        evidence_sha256=evidence_sha256,
    )


def _preflight_collection_roots(
    *,
    release_repository_root: Path,
    target_repository_root: Path,
    emitted_run_dir: Path,
    evidence_root: Path,
    report_root: Path,
) -> _CollectionRoots:
    roots = _CollectionRoots(
        release_repository=_observe_directory(
            release_repository_root,
            label="release repository",
            require_empty=False,
        ),
        target_repository=_observe_directory(
            target_repository_root,
            label="target repository",
            require_empty=False,
        ),
        run=_observe_directory(
            emitted_run_dir,
            label="emitted run",
            require_empty=False,
        ),
        evidence=_observe_directory(
            evidence_root,
            label="release evidence",
            require_empty=True,
        ),
        report=_observe_directory(
            report_root,
            label="release report",
            require_empty=True,
        ),
    )
    if os.path.samestat(
        _stat_root(roots.evidence.path),
        _stat_root(roots.report.path),
    ):
        raise ValueError("release evidence and report roots must be distinct")
    for output in (roots.evidence.path, roots.report.path):
        for controlled in (
            roots.release_repository.path,
            roots.target_repository.path,
            roots.run.path,
        ):
            if _directory_is_within(output, controlled) or _directory_is_within(
                controlled,
                output,
            ):
                raise ValueError(
                    "release output roots must be disjoint from candidate, target, and run"
                )
    return roots


def _revalidate_collection_roots(roots: _CollectionRoots) -> None:
    for initial, label in (
        (roots.release_repository, "release repository"),
        (roots.target_repository, "target repository"),
        (roots.run, "emitted run"),
        (roots.evidence, "release evidence"),
        (roots.report, "release report"),
    ):
        current = _observe_directory(initial.path, label=label, require_empty=False)
        if current != initial:
            raise ValueError("release collection root changed during evidence generation")


def _observe_directory(
    path: Path,
    *,
    label: str,
    require_empty: bool,
) -> _CollectionRoot:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError(f"{label} path may not traverse a link")
        before = absolute.lstat()
        entries = tuple(absolute.iterdir()) if require_empty else ()
        after = absolute.lstat()
    except OSError as exc:
        raise ValueError(f"{label} root is unavailable") from exc
    if not stat.S_ISDIR(before.st_mode) or _directory_identity(before) != _directory_identity(
        after
    ):
        raise ValueError(f"{label} root must be a stable directory")
    if require_empty and stat.S_IMODE(after.st_mode) & 0o077:
        raise ValueError(f"{label} output root must be private")
    if require_empty and entries:
        raise ValueError(f"{label} root must be empty")
    return _CollectionRoot(
        path=absolute.resolve(strict=True),
        identity=_directory_identity(after),
    )


def _stat_root(path: Path) -> os.stat_result:
    try:
        return path.stat()
    except OSError as exc:
        raise ValueError("release collection root identity is unavailable") from exc


def _directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _directory_is_within(candidate: Path, directory: Path) -> bool:
    try:
        expected = directory.stat()
        current = candidate
        while True:
            if os.path.samestat(current.stat(), expected):
                return True
            parent = current.parent
            if parent == current:
                return False
            current = parent
    except OSError as exc:
        raise ValueError("release collection containment is unavailable") from exc


def _require_exact_flat_file_inventory(
    root: Path,
    *,
    expected_paths: set[str],
    label: str,
) -> None:
    if any(
        not path or "/" in path or "\\" in path or path in {".", ".."} or Path(path).name != path
        for path in expected_paths
    ):
        raise ValueError(f"{label} expected inventory is not a flat file set")
    first = _observe_flat_file_inventory(root, label=label)
    second = _observe_flat_file_inventory(root, label=label)
    if first != second:
        raise ValueError(f"{label} inventory changed while being observed")
    if set(second) != expected_paths:
        raise ValueError(f"{label} inventory contains missing or undeclared files")


def _observe_flat_file_inventory(
    root: Path,
    *,
    label: str,
) -> dict[str, tuple[int, int, int, int, int, int, int]]:
    observed: dict[str, tuple[int, int, int, int, int, int, int]] = {}
    try:
        entries = sorted(root.iterdir(), key=lambda item: item.name)
        for entry in entries:
            metadata = entry.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or entry.is_junction()
                or metadata.st_nlink != 1
            ):
                raise ValueError(f"{label} inventory contains a linked or non-file entry")
            observed[entry.name] = (
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_mtime_ns,
                metadata.st_ctime_ns,
            )
    except OSError as exc:
        raise ValueError(f"{label} inventory is unavailable") from exc
    return observed
