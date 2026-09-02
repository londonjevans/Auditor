from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import InvariantSuite, ProtocolProfileKind
from mmaudit.orchestration.manifest import (
    KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
    KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
    MODEL_REVIEW_ARTIFACT_INVENTORY_PATH,
    ManifestBindingSet,
    ManifestFileBinding,
    RunEvidenceManifest,
    _known_issue_taxonomy_bindings,
    _seal_run_evidence_manifest,
    _validate_known_issue_taxonomy_artifacts,
    build_run_evidence_manifest,
    canonical_sha256,
    seal_run_evidence_manifest,
)
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    build_findings_artifact,
)
from mmaudit.reporting.run_authority import RUN_TERMINAL_REPORT_AUTHORITY_PATH
from mmaudit.solidity.taxonomy import (
    build_known_issue_taxonomy_coverage,
    load_known_issue_taxonomy,
)
from tests.unit import test_known_issue_taxonomy as taxonomy_support
from tests.unit import test_release_artifacts as release_support
from tests.unit import test_taxonomy_reporting as reporting_support


def _current_report():
    resource = load_known_issue_taxonomy()
    coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=None,
        model_review_coverage=None,
    )
    return reporting_support._report_with_taxonomy(coverage), resource


def _artifact_binding(path: str) -> ManifestFileBinding:
    payload = f"synthetic:{path}".encode()
    return ManifestFileBinding(
        path=path,
        sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def _manifest_artifacts(*, taxonomy: bool) -> list[ManifestFileBinding]:
    paths = {
        *MANIFEST_BOUND_REPORT_DELIVERABLES,
        "final-findings.json",
        "metadata.json",
        LANGUAGE_CAPABILITY_ARTIFACT_PATH,
        RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    }
    if taxonomy:
        paths.update(
            {
                KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH,
                KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH,
                MODEL_REVIEW_ARTIFACT_INVENTORY_PATH,
            }
        )
    return [_artifact_binding(path) for path in sorted(paths)]


def _manifest_bindings(*, taxonomy: bool) -> ManifestBindingSet:
    bindings = release_support._bindings()
    if not taxonomy:
        return bindings
    report, _resource = _current_report()
    return bindings.model_copy(
        update={
            "coverage": sorted(
                [*bindings.coverage, *_known_issue_taxonomy_bindings(report)],
                key=lambda binding: binding.identifier,
            )
        }
    )


def test_public_manifest_issuance_is_14_and_retained_13_round_trips(
    config_factory,
) -> None:
    config = config_factory()
    current = seal_run_evidence_manifest(
        run_id="taxonomy-current",
        repository_root_name="synthetic-taxonomy-repository",
        git_commit="a" * 40,
        sources=[],
        run_configuration=release_support._run_configuration(config),
        bindings=_manifest_bindings(taxonomy=True),
        artifacts=_manifest_artifacts(taxonomy=True),
        tool_version="test",
    )

    assert current.schema_version == "1.4"
    assert RunEvidenceManifest.model_validate_json(current.model_dump_json()) == current

    legacy = _seal_run_evidence_manifest(
        run_id="taxonomy-legacy",
        repository_root_name="synthetic-taxonomy-repository",
        git_commit="a" * 40,
        sources=[],
        run_configuration=release_support._run_configuration(config),
        bindings=_manifest_bindings(taxonomy=False),
        artifacts=_manifest_artifacts(taxonomy=False),
        schema_version="1.3",
        tool_version="test",
    )
    assert RunEvidenceManifest.model_validate_json(legacy.model_dump_json()) == legacy

    with pytest.raises(ValueError, match=r"new manifest issuance requires schema 1\.4"):
        seal_run_evidence_manifest(
            run_id=legacy.run_id,
            repository_root_name=legacy.repository_root_name,
            git_commit=legacy.git_commit,
            sources=legacy.sources,
            run_configuration=release_support._run_configuration(config),
            bindings=legacy.bindings,
            artifacts=legacy.artifacts,
            schema_version="1.3",
            tool_version="test",
        )


def test_manifest_version_boundary_rejects_missing_or_legacy_taxonomy_custody(
    config_factory,
) -> None:
    config = config_factory()
    with pytest.raises(ValidationError, match="complete known-issue taxonomy custody"):
        seal_run_evidence_manifest(
            run_id="taxonomy-missing",
            repository_root_name="synthetic-taxonomy-repository",
            git_commit="a" * 40,
            sources=[],
            run_configuration=release_support._run_configuration(config),
            bindings=_manifest_bindings(taxonomy=True),
            artifacts=[
                binding
                for binding in _manifest_artifacts(taxonomy=True)
                if binding.path != KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH
            ],
            tool_version="test",
        )

    with pytest.raises(ValidationError, match="model-review artifact inventory"):
        seal_run_evidence_manifest(
            run_id="review-inventory-missing",
            repository_root_name="synthetic-taxonomy-repository",
            git_commit="a" * 40,
            sources=[],
            run_configuration=release_support._run_configuration(config),
            bindings=_manifest_bindings(taxonomy=True),
            artifacts=[
                binding
                for binding in _manifest_artifacts(taxonomy=True)
                if binding.path != MODEL_REVIEW_ARTIFACT_INVENTORY_PATH
            ],
            tool_version="test",
        )

    legacy = _seal_run_evidence_manifest(
        run_id="taxonomy-legacy",
        repository_root_name="synthetic-taxonomy-repository",
        git_commit="a" * 40,
        sources=[],
        run_configuration=release_support._run_configuration(config),
        bindings=_manifest_bindings(taxonomy=False),
        artifacts=_manifest_artifacts(taxonomy=False),
        schema_version="1.3",
        tool_version="test",
    )
    payload = legacy.model_dump(mode="json", exclude={"manifest_sha256"})
    payload["artifacts"] = [
        *payload["artifacts"],
        _artifact_binding(KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).model_dump(mode="json"),
    ]
    payload["artifacts"] = sorted(payload["artifacts"], key=lambda item: item["path"])
    payload["manifest_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValidationError, match="pre-taxonomy manifests cannot retain"):
        RunEvidenceManifest.model_validate(payload)

    payload = legacy.model_dump(mode="json", exclude={"manifest_sha256"})
    payload["artifacts"] = sorted(
        [
            *payload["artifacts"],
            _artifact_binding(MODEL_REVIEW_ARTIFACT_INVENTORY_PATH).model_dump(mode="json"),
        ],
        key=lambda item: item["path"],
    )
    payload["manifest_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValidationError, match=r"pre-1\.4 manifests cannot retain"):
        RunEvidenceManifest.model_validate(payload)


def test_unsealed_manifest_build_rejects_pre_taxonomy_report(
    tmp_path: Path,
    config_factory,
) -> None:
    config = config_factory()
    tmp_path.mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="same taxonomy boundary"):
        build_run_evidence_manifest(
            run_dir=tmp_path,
            report=release_support._report(config),
            config=config,
        )


def test_current_taxonomy_leaves_are_exact_and_findings_remain_13(tmp_path: Path) -> None:
    report, resource = _current_report()
    (tmp_path / KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).write_bytes(resource.raw_bytes)
    (tmp_path / KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH).write_text(
        report.taxonomy_coverage.model_dump_json() if report.taxonomy_coverage is not None else "",
        encoding="utf-8",
    )

    _validate_known_issue_taxonomy_artifacts(tmp_path, report, required=True)
    taxonomy_bindings = {
        binding.identifier: binding for binding in _known_issue_taxonomy_bindings(report)
    }
    assert taxonomy_bindings["known-issue-taxonomy/corpus-raw"].sha256 == resource.raw_sha256
    assert build_findings_artifact(report).schema_version == "1.3"

    wrong_coverage = reporting_support._taxonomy_coverage()
    (tmp_path / KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH).write_text(
        wrong_coverage.model_dump_json(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="standalone taxonomy coverage differs"):
        _validate_known_issue_taxonomy_artifacts(tmp_path, report, required=True)

    assert report.taxonomy_coverage is not None
    (tmp_path / KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH).write_text(
        report.taxonomy_coverage.model_dump_json(),
        encoding="utf-8",
    )
    (tmp_path / KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).write_text(
        json.dumps(resource.corpus.model_dump(mode="json"), separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="committed corpus bytes"):
        _validate_known_issue_taxonomy_artifacts(tmp_path, report, required=True)


def test_manifest_recomputes_taxonomy_against_report_evidence_after_model_copy_tamper(
    tmp_path: Path,
) -> None:
    report, resource = _current_report()
    assessment = taxonomy_support._profile_assessment()
    invariants = InvariantSuite(
        protocol_profiles=[ProtocolProfileKind.SOLIDITY_GENERAL.value],
        protocol_profile_assessment=assessment,
    )
    forged_coverage = build_known_issue_taxonomy_coverage(
        resource,
        invariants=invariants,
        model_review_coverage=None,
    )
    forged_report = report.model_copy(update={"taxonomy_coverage": forged_coverage})
    (tmp_path / KNOWN_ISSUE_TAXONOMY_ARTIFACT_PATH).write_bytes(resource.raw_bytes)
    (tmp_path / KNOWN_ISSUE_TAXONOMY_COVERAGE_ARTIFACT_PATH).write_text(
        forged_coverage.model_dump_json(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="retained profile and model-review evidence"):
        _validate_known_issue_taxonomy_artifacts(
            tmp_path,
            forged_report,
            required=True,
        )
