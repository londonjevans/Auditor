"""Generate and authoritatively validate one fresh candidate-bound release report."""

from __future__ import annotations

import argparse
from pathlib import Path

from mmaudit.release_collection import RELEASE_REPORT_PATH, collect_release_report


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
    parser.add_argument("--run-dir", type=_explicit_path, required=True)
    parser.add_argument("--artifact-evidence-file", type=_explicit_path, required=True)
    parser.add_argument("--run-verification-file", type=_explicit_path, required=True)
    parser.add_argument(
        "--evidence-root",
        type=_explicit_path,
        required=True,
        help="Pre-existing empty private external directory for evidence inputs and gate results.",
    )
    parser.add_argument(
        "--report-root",
        type=_explicit_path,
        required=True,
        help="Pre-existing empty private external directory for the generated report.",
    )
    arguments = parser.parse_args(argv)
    report = collect_release_report(
        release_id=arguments.release_id,
        release_repository_root=arguments.release_repository,
        target_repository_root=arguments.target_repository,
        emitted_run_dir=arguments.run_dir,
        artifact_evidence_path=arguments.artifact_evidence_file,
        run_verification_path=arguments.run_verification_file,
        evidence_root=arguments.evidence_root,
        report_root=arguments.report_root,
    )
    print(
        "release report generated and integrity-validated: "
        f"path={RELEASE_REPORT_PATH} "
        f"release_status={report.status.value} "
        f"passed_gates={report.passed_gates}/{report.total_gates}"
    )


if __name__ == "__main__":
    main()
