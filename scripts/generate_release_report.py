"""Fail closed while exact candidate-bound release collection is unavailable."""

from __future__ import annotations

import argparse
from pathlib import Path

from mmaudit.release_collection import (
    RELEASE_REPORT_DIRECTORY,
    RELEASE_REPORT_PATH,
    ReleaseCollectionUnavailableError,
    collect_release_report,
)


def _explicit_path(value: str) -> Path:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("path must be explicit bounded single-line text")
    return Path(value)


def _release_id(value: str) -> str:
    if (
        not value
        or len(value) > 128
        or not value[0].isalnum()
        or any(
            not (character.isascii() and (character.isalnum() or character in "._-"))
            for character in value
        )
    ):
        raise argparse.ArgumentTypeError("release ID must use bounded ASCII identifier syntax")
    return value


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-id", type=_release_id, required=True)
    parser.add_argument("--release-repository", type=_explicit_path, required=True)
    parser.add_argument("--target-repository", type=_explicit_path, required=True)
    parser.add_argument("--configuration-root", type=_explicit_path, required=True)
    parser.add_argument("--run-dir", type=_explicit_path, required=True)
    parser.add_argument("--artifact-evidence-file", type=_explicit_path, required=True)
    parser.add_argument("--run-verification-file", type=_explicit_path, required=True)
    parser.add_argument(
        "--publication-root",
        type=_explicit_path,
        required=True,
        help="Reserved publication path; collection currently fails closed before using it.",
    )
    arguments = parser.parse_args(argv)
    try:
        snapshot = collect_release_report(
            release_id=arguments.release_id,
            release_repository_root=arguments.release_repository,
            target_repository_root=arguments.target_repository,
            configuration_root=arguments.configuration_root,
            emitted_run_dir=arguments.run_dir,
            artifact_evidence_path=arguments.artifact_evidence_file,
            run_verification_path=arguments.run_verification_file,
            publication_root=arguments.publication_root,
        )
    except ReleaseCollectionUnavailableError as exc:
        parser.error(str(exc))
    report = snapshot.report
    print(
        "release snapshot validated: "
        f"path={RELEASE_REPORT_DIRECTORY}/{RELEASE_REPORT_PATH} "
        f"snapshot_sha256={snapshot.snapshot_sha256} "
        "mutable_paths_require_revalidation=true "
        f"release_status={report.status.value} "
        f"passed_gates={report.passed_gates}/{report.total_gates}"
    )


if __name__ == "__main__":
    main()
