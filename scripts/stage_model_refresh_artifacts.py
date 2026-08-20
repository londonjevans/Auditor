"""Validate and stage exact model-refresh workflow evidence."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from contextlib import suppress
from pathlib import Path

from mmaudit.models.policy_eligibility_refresh import (
    POLICY_ELIGIBILITY_REFRESH_FILENAME,
    load_model_policy_eligibility_artifact,
    load_policy_eligibility_checked_routes,
    load_policy_eligibility_source_observation,
)
from mmaudit.models.qualification import CandidateRegistry, load_candidate_registry
from mmaudit.models.refresh import (
    ATTEMPT_FILENAME,
    CANDIDATE_REGISTRY_FILENAME,
    DIFF_FILENAME,
    FRESHNESS_FILENAME,
    SNAPSHOT_FILENAME,
    SOURCE_EVIDENCE_FILENAME,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
    load_model_refresh_snapshot,
    load_model_refresh_source_evidence,
)
from mmaudit.models.refresh_staging import (
    PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
    PREVIOUS_SNAPSHOT_FILENAME,
    PREVIOUS_SOURCE_EVIDENCE_FILENAME,
    PREVIOUS_WORKFLOW_STATUS_FILENAME,
    WORKFLOW_STATUS_FILENAME,
    ModelRefreshStagingError,
    ModelRefreshWorkflowStatus,
    load_previous_model_refresh_history,
    stage_model_refresh_evidence,
)

_MAX_HISTORY_ARCHIVE_BYTES = 32_000_000
_MAX_HISTORY_FILE_BYTES = 20_000_000
_MAX_HISTORY_TOTAL_BYTES = 12 * _MAX_HISTORY_FILE_BYTES
_HISTORY_FILENAMES = frozenset(
    {
        CANDIDATE_REGISTRY_FILENAME,
        SOURCE_EVIDENCE_FILENAME,
        SNAPSHOT_FILENAME,
        DIFF_FILENAME,
        ATTEMPT_FILENAME,
        FRESHNESS_FILENAME,
        WORKFLOW_STATUS_FILENAME,
    }
)
_POLICY_HISTORY_FILENAMES = _HISTORY_FILENAMES | {POLICY_ELIGIBILITY_REFRESH_FILENAME}
_PREDECESSOR_HISTORY_FILENAMES = frozenset(
    {
        PREVIOUS_WORKFLOW_STATUS_FILENAME,
        PREVIOUS_CANDIDATE_REGISTRY_FILENAME,
        PREVIOUS_SOURCE_EVIDENCE_FILENAME,
        PREVIOUS_SNAPSHOT_FILENAME,
    }
)
_CHAINED_HISTORY_FILENAMES = _HISTORY_FILENAMES | _PREDECESSOR_HISTORY_FILENAMES
_POLICY_CHAINED_HISTORY_FILENAMES = _POLICY_HISTORY_FILENAMES | _PREDECESSOR_HISTORY_FILENAMES
_ALLOWED_HISTORY_INVENTORIES = frozenset(
    {
        _HISTORY_FILENAMES,
        _POLICY_HISTORY_FILENAMES,
        _CHAINED_HISTORY_FILENAMES,
        _POLICY_CHAINED_HISTORY_FILENAMES,
    }
)


def _bounded_path(value: str) -> Path:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("path must be bounded single-line text")
    return Path(value)


def _bounded_identity(value: str) -> str:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("identity must be bounded single-line text")
    return value


def main(argv: list[str] | None = None) -> int:
    arguments_list = list(sys.argv[1:] if argv is None else argv)
    if arguments_list[:1] == ["extract-history"]:
        return _extract_history(arguments_list[1:])
    if arguments_list[:1] == ["validate-history"]:
        return _validate_history(arguments_list[1:])
    parser = argparse.ArgumentParser(
        description="Strictly validate and stage one model-refresh workflow bundle."
    )
    parser.add_argument("--output-dir", type=_bounded_path, required=True)
    parser.add_argument("--staging-dir", type=_bounded_path, required=True)
    parser.add_argument("--candidate-registry", type=_bounded_path, required=True)
    parser.add_argument("--previous-candidate-registry", type=_bounded_path)
    parser.add_argument("--previous-snapshot", type=_bounded_path)
    parser.add_argument("--previous-source-evidence", type=_bounded_path)
    parser.add_argument("--previous-history-dir", type=_bounded_path)
    parser.add_argument("--expected-previous-workflow-run-id", type=_bounded_identity)
    parser.add_argument("--expected-previous-workflow-run-attempt", type=_bounded_identity)
    parser.add_argument("--expected-previous-source-commit", type=_bounded_identity)
    parser.add_argument("--policy-eligibility-artifact", type=_bounded_path)
    parser.add_argument("--policy-source-observation", type=_bounded_path)
    parser.add_argument("--policy-checked-routes", type=_bounded_path)
    parser.add_argument("--refresh-exit-status", type=int, required=True)
    parser.add_argument("--source-commit", type=_bounded_identity, required=True)
    parser.add_argument("--workflow-run-id", type=_bounded_identity, required=True)
    parser.add_argument("--workflow-run-attempt", type=_bounded_identity, required=True)
    parser.add_argument("--pricing-tolerance-fraction", type=_bounded_identity, required=True)
    parser.add_argument("--soft-max-age-hours", type=int, required=True)
    parser.add_argument("--hard-max-age-hours", type=int, required=True)
    arguments = parser.parse_args(arguments_list)
    try:
        registry = load_candidate_registry(arguments.candidate_registry)
        direct_previous_paths = (
            arguments.previous_candidate_registry,
            arguments.previous_snapshot,
            arguments.previous_source_evidence,
        )
        expected_history_identity = (
            arguments.expected_previous_workflow_run_id,
            arguments.expected_previous_workflow_run_attempt,
            arguments.expected_previous_source_commit,
        )
        if arguments.previous_history_dir is not None and any(
            path is not None for path in direct_previous_paths
        ):
            raise ModelRefreshStagingError(
                "previous history directory and direct previous evidence are mutually exclusive"
            )
        if any(path is not None for path in direct_previous_paths) and not all(
            path is not None for path in direct_previous_paths
        ):
            raise ModelRefreshStagingError(
                "previous candidate registry, snapshot, and source evidence "
                "must be supplied together"
            )
        if arguments.previous_history_dir is None and any(
            value is not None for value in expected_history_identity
        ):
            raise ModelRefreshStagingError(
                "expected previous workflow identity requires a previous history directory"
            )
        if arguments.previous_history_dir is not None and not all(
            value is not None for value in expected_history_identity
        ):
            raise ModelRefreshStagingError(
                "previous history directory requires the exact expected workflow identity"
            )
        policy_paths = (
            arguments.policy_eligibility_artifact,
            arguments.policy_source_observation,
            arguments.policy_checked_routes,
        )
        if any(path is not None for path in policy_paths) and not all(
            path is not None for path in policy_paths
        ):
            raise ModelRefreshStagingError(
                "policy artifact, source observation, and checked routes must be supplied together"
            )
        previous_registry: CandidateRegistry | None
        previous_snapshot: ModelRefreshSnapshot | None
        previous_source_evidence: ModelRefreshSourceEvidence | None
        previous_workflow_status: ModelRefreshWorkflowStatus | None = None
        if arguments.previous_history_dir is not None:
            assert arguments.expected_previous_workflow_run_id is not None
            assert arguments.expected_previous_workflow_run_attempt is not None
            assert arguments.expected_previous_source_commit is not None
            history = load_previous_model_refresh_history(
                arguments.previous_history_dir,
                expected_workflow_run_id=arguments.expected_previous_workflow_run_id,
                expected_workflow_run_attempt=arguments.expected_previous_workflow_run_attempt,
                expected_source_commit=arguments.expected_previous_source_commit,
            )
            previous_registry = history.candidate_registry
            previous_snapshot = history.snapshot
            previous_source_evidence = history.source_evidence
            previous_workflow_status = history.workflow_status
        else:
            previous_registry = (
                load_candidate_registry(arguments.previous_candidate_registry)
                if arguments.previous_candidate_registry is not None
                else None
            )
            previous_snapshot = (
                load_model_refresh_snapshot(arguments.previous_snapshot)
                if arguments.previous_snapshot is not None
                else None
            )
            previous_source_evidence = (
                load_model_refresh_source_evidence(arguments.previous_source_evidence)
                if arguments.previous_source_evidence is not None
                else None
            )
        policy_artifact = (
            load_model_policy_eligibility_artifact(arguments.policy_eligibility_artifact)
            if arguments.policy_eligibility_artifact is not None
            else None
        )
        policy_observation = (
            load_policy_eligibility_source_observation(arguments.policy_source_observation)
            if arguments.policy_source_observation is not None
            else None
        )
        policy_routes = (
            load_policy_eligibility_checked_routes(arguments.policy_checked_routes)
            if arguments.policy_checked_routes is not None
            else None
        )
        status = stage_model_refresh_evidence(
            output_dir=arguments.output_dir,
            staging_dir=arguments.staging_dir,
            candidate_registry=registry,
            refresh_exit_status=arguments.refresh_exit_status,
            source_commit=arguments.source_commit,
            workflow_run_id=arguments.workflow_run_id,
            workflow_run_attempt=arguments.workflow_run_attempt,
            pricing_tolerance_fraction=arguments.pricing_tolerance_fraction,
            soft_max_age_hours=arguments.soft_max_age_hours,
            hard_max_age_hours=arguments.hard_max_age_hours,
            previous_snapshot=previous_snapshot,
            previous_source_evidence=previous_source_evidence,
            previous_candidate_registry=previous_registry,
            previous_workflow_status=previous_workflow_status,
            policy_eligibility_artifact=policy_artifact,
            policy_source_observation=policy_observation,
            policy_checked_routes=policy_routes,
        )
    except (ModelRefreshStagingError, ValueError):
        print("model-refresh artifact staging failed")
        return 74
    print(
        "model-refresh artifacts staged: "
        f"disposition={status.disposition.value} artifacts={len(status.artifacts)}"
    )
    return 0


def _extract_history(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="stage_model_refresh_artifacts.py extract-history",
        description="Bound and extract one exact model-refresh history archive.",
    )
    parser.add_argument("--archive", type=_bounded_path, required=True)
    parser.add_argument("--history-dir", type=_bounded_path, required=True)
    parser.add_argument("--expected-archive-bytes", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        _extract_exact_history_archive(
            archive_path=arguments.archive,
            history_dir=arguments.history_dir,
            expected_archive_bytes=arguments.expected_archive_bytes,
        )
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        print("model-refresh history extraction failed")
        return 74
    print("model-refresh history extracted")
    return 0


def _validate_history(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="stage_model_refresh_artifacts.py validate-history",
        description="Validate one exact prior model-refresh workflow artifact set.",
    )
    parser.add_argument("--history-dir", type=_bounded_path, required=True)
    parser.add_argument("--expected-workflow-run-id", type=_bounded_identity, required=True)
    parser.add_argument("--expected-workflow-run-attempt", type=_bounded_identity, required=True)
    parser.add_argument("--expected-source-commit", type=_bounded_identity, required=True)
    arguments = parser.parse_args(argv)
    try:
        history = load_previous_model_refresh_history(
            arguments.history_dir,
            expected_workflow_run_id=arguments.expected_workflow_run_id,
            expected_workflow_run_attempt=arguments.expected_workflow_run_attempt,
            expected_source_commit=arguments.expected_source_commit,
        )
    except (ModelRefreshStagingError, ValueError):
        print("model-refresh history validation failed")
        return 74
    print(
        f"model-refresh history validated: disposition={history.workflow_status.disposition.value}"
    )
    return 0


def _extract_exact_history_archive(
    *,
    archive_path: Path,
    history_dir: Path,
    expected_archive_bytes: int,
) -> None:
    archive_fd = _open_regular_file_no_follow(archive_path)
    output_parent_fd, output_name = _open_parent_directory(history_dir)
    output_fd: int | None = None
    created = False
    try:
        archive_stat = os.fstat(archive_fd)
        if (
            isinstance(expected_archive_bytes, bool)
            or not 1 <= expected_archive_bytes <= _MAX_HISTORY_ARCHIVE_BYTES
            or archive_stat.st_nlink != 1
            or archive_stat.st_size != expected_archive_bytes
        ):
            raise ValueError("history archive identity or size is invalid")
        os.mkdir(output_name, mode=0o700, dir_fd=output_parent_fd)
        created = True
        output_fd = os.open(
            output_name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=output_parent_fd,
        )
        os.fchmod(output_fd, 0o700)
        with (
            os.fdopen(archive_fd, "rb", closefd=False) as archive_stream,
            zipfile.ZipFile(archive_stream, mode="r") as archive,
        ):
            entries = archive.infolist()
            names = tuple(entry.filename for entry in entries)
            if (
                len(names) != len(set(names))
                or frozenset(names) not in _ALLOWED_HISTORY_INVENTORIES
            ):
                raise ValueError("history archive inventory is invalid")
            total_size = 0
            for entry in entries:
                entry_mode = (entry.external_attr >> 16) & 0xFFFF
                if (
                    entry.is_dir()
                    or entry.filename != Path(entry.filename).name
                    or entry.filename in {"", ".", ".."}
                    or (entry_mode != 0 and not stat.S_ISREG(entry_mode))
                    or entry.compress_type != zipfile.ZIP_DEFLATED
                    or not 1 <= entry.file_size <= _MAX_HISTORY_FILE_BYTES
                    or entry.compress_size > _MAX_HISTORY_ARCHIVE_BYTES
                ):
                    raise ValueError("history archive entry is unsafe")
                total_size += entry.file_size
                if total_size > _MAX_HISTORY_TOTAL_BYTES:
                    raise ValueError("history archive expands beyond its bound")
            for entry in entries:
                output_file_fd = os.open(
                    entry.filename,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=output_fd,
                )
                try:
                    os.fchmod(output_file_fd, 0o600)
                    written = 0
                    with archive.open(entry, mode="r") as source:
                        while True:
                            chunk = source.read(min(65_536, entry.file_size - written + 1))
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > entry.file_size:
                                raise ValueError("history archive entry exceeds its declared size")
                            view = memoryview(chunk)
                            while view:
                                count = os.write(output_file_fd, view)
                                if count <= 0:
                                    raise OSError("history archive write made no progress")
                                view = view[count:]
                    if written != entry.file_size:
                        raise ValueError("history archive entry size is inconsistent")
                    os.fsync(output_file_fd)
                finally:
                    os.close(output_file_fd)
        os.fsync(output_fd)
        observed_dir = os.stat(output_name, dir_fd=output_parent_fd, follow_symlinks=False)
        held_dir = os.fstat(output_fd)
        if (
            not stat.S_ISDIR(observed_dir.st_mode)
            or observed_dir.st_dev != held_dir.st_dev
            or observed_dir.st_ino != held_dir.st_ino
            or stat.S_IMODE(observed_dir.st_mode) != 0o700
        ):
            raise ValueError("history extraction directory identity changed")
    except BaseException:
        if output_fd is not None:
            _remove_extracted_files(output_fd)
        if created:
            with suppress(OSError):
                os.rmdir(output_name, dir_fd=output_parent_fd)
        raise
    finally:
        if output_fd is not None:
            os.close(output_fd)
        os.close(output_parent_fd)
        os.close(archive_fd)


def _open_regular_file_no_follow(path: Path) -> int:
    parent_fd, name = _open_parent_directory(path)
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    file_stat = os.fstat(file_fd)
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(file_fd)
        raise ValueError("history archive is not a regular file")
    return file_fd


def _open_parent_directory(path: Path) -> tuple[int, str]:
    absolute = Path(os.path.abspath(path))
    if absolute.name in {"", ".", ".."}:
        raise ValueError("history path has no safe leaf name")
    parts = absolute.parent.parts
    directory_fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[1:]:
            next_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
    except BaseException:
        os.close(directory_fd)
        raise
    return directory_fd, absolute.name


def _remove_extracted_files(directory_fd: int) -> None:
    for name in os.listdir(directory_fd):
        with suppress(OSError):
            os.unlink(name, dir_fd=directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())
