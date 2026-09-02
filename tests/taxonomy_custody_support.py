from __future__ import annotations

from pathlib import Path

from mmaudit.orchestration.manifest import (
    KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
    KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
    ManifestHashBinding,
    canonical_sha256,
)
from mmaudit.reporting.json_report import write_json
from mmaudit.solidity.taxonomy import (
    build_known_issue_taxonomy_coverage,
    load_known_issue_taxonomy,
)


def write_exact_taxonomy_custody(run_dir: Path) -> list[ManifestHashBinding]:
    """Write the committed corpus and its exact deterministic no-evidence coverage."""

    resource = load_known_issue_taxonomy()
    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=None,
        model_review_coverage=None,
    )
    assert coverage.profile_assessment is None
    (run_dir / KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).write_bytes(resource.raw_bytes)
    write_json(run_dir / KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH, coverage)
    return [
        ManifestHashBinding(
            identifier="known-issue-taxonomy/corpus",
            sha256=coverage.corpus.corpus_sha256,
            details={
                "artifact": KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
                "items": str(len(coverage.corpus.items)),
                "taxonomy_version": coverage.corpus.taxonomy_version,
            },
        ),
        ManifestHashBinding(
            identifier="known-issue-taxonomy/corpus-raw",
            sha256=resource.raw_sha256,
            details={"artifact": KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH},
        ),
        ManifestHashBinding(
            identifier="known-issue-taxonomy/coverage",
            sha256=coverage.coverage_sha256,
            details={
                "artifact": KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
                "critical_gaps": str(len(coverage.critical_gap_ids)),
            },
        ),
        ManifestHashBinding(
            identifier="known-issue-taxonomy/profile-assessment",
            sha256=canonical_sha256({"present": False}),
            details={"state": "absent"},
        ),
    ]
