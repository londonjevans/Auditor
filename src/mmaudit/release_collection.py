"""Fail-closed boundary for release-report collection and publication.

POSIX does not provide a portable operation that both creates a directory and returns the exact
created directory object. A same-EUID actor can therefore replace a freshly created name between
``mkdir`` and ``open``. Directory-based collection is disabled until every evidence writer can use
held directory descriptors or an in-memory builder can publish one exact regular-file bundle.

Standalone validation in :mod:`mmaudit.release_validation` remains available for evidence prepared
outside this disabled collection path.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from mmaudit.release_validation import ValidatedReleaseReportSnapshot

RELEASE_REPORT_PATH: Final = "release-gate-report.json"
RELEASE_EVIDENCE_DIRECTORY: Final = "evidence"
RELEASE_REPORT_DIRECTORY: Final = "report"
RELEASE_COLLECTION_BLOCKER: Final = (
    "release collection is blocked: exact output-directory creation against same-EUID name "
    "adoption is unavailable; prepare evidence externally and use standalone snapshot validation"
)


class ReleaseCollectionUnavailableError(RuntimeError):
    """Raised before any collection process, output write, or directory creation occurs."""


def collect_release_report(
    *,
    release_id: str,
    release_repository_root: Path,
    target_repository_root: Path,
    configuration_root: Path,
    emitted_run_dir: Path,
    artifact_evidence_path: Path,
    run_verification_path: Path,
    publication_root: Path,
) -> ValidatedReleaseReportSnapshot:
    """Fail closed before side effects until exact publication custody is implementable.

    The arguments remain explicit so existing callers receive a precise technical blocker instead
    of accidentally selecting an older, weaker two-directory publication route. No argument is
    observed because even a read-before-failure could be mistaken for collection progress.
    """

    raise ReleaseCollectionUnavailableError(RELEASE_COLLECTION_BLOCKER)
