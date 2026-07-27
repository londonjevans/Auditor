from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.adversarial_acceptance import (
    AdversarialAcceptanceManifest,
    AdversarialAcceptanceObservation,
    AdversarialAcceptanceReport,
    AdversarialAcceptanceStatus,
    AdversarialCaseId,
    AdversarialDisposition,
    AdversarialEvidenceKind,
    build_adversarial_acceptance_report,
    load_adversarial_acceptance_manifest,
    write_adversarial_acceptance_report,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "tests" / "fixtures" / "adversarial_repository" / "cases.json"
_RUNTIME_CASES = {
    AdversarialCaseId.ENVIRONMENT_READ,
    AdversarialCaseId.HOME_READ,
    AdversarialCaseId.NETWORK_SOCKET,
    AdversarialCaseId.OUTPUT_ABUSE,
    AdversarialCaseId.PATH_TRAVERSAL,
    AdversarialCaseId.PROCESS_RESOURCE_ABUSE,
}


def _manifest() -> AdversarialAcceptanceManifest:
    return load_adversarial_acceptance_manifest(MANIFEST_PATH)


def _fail_closed_observations() -> list[AdversarialAcceptanceObservation]:
    limitation = ["real rootless containment not executed"]
    return [
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.CRAFTED_NAMES,
            disposition=AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            evidence_kind=AdversarialEvidenceKind.PATH_NORMALIZATION,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.ENVIRONMENT_READ,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.FAKE_BINARIES,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.EXTERNAL_EXECUTABLE_VALIDATION,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.HOME_READ,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.NETWORK_SOCKET,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.REPOSITORY_CODE_FAIL_CLOSED,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.OUTPUT_ABUSE,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.BOUNDED_OUTPUT,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.PATH_TRAVERSAL,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.WORKSPACE_VALIDATION,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.PROCESS_RESOURCE_ABUSE,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.BOUNDED_PROCESS,
            limitations=limitation,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.PROMPT_INJECTION,
            disposition=AdversarialDisposition.DETERMINISTICALLY_CONTAINED,
            evidence_kind=AdversarialEvidenceKind.UNTRUSTED_CONTEXT,
        ),
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.SYMLINK_ESCAPE,
            disposition=AdversarialDisposition.REJECTED_BEFORE_HOST_EXECUTION,
            evidence_kind=AdversarialEvidenceKind.WORKSPACE_VALIDATION,
        ),
    ]


def _real_observations() -> list[AdversarialAcceptanceObservation]:
    observations = _fail_closed_observations()
    return [
        (
            item.model_copy(
                update={
                    "disposition": AdversarialDisposition.REAL_ISOLATION_CONTAINED,
                    "evidence_kind": AdversarialEvidenceKind.ROOTLESS_RUNTIME,
                    "real_isolation_backend": "rootless-container",
                    "limitations": [],
                }
            )
            if item.case_id in _RUNTIME_CASES
            else item
        )
        for item in observations
    ]


def test_manifest_is_source_bound_and_exhaustive() -> None:
    manifest = _manifest()

    assert [item.case_id for item in manifest.cases] == sorted(AdversarialCaseId)
    assert len(manifest.fixture_files) == 7
    assert sum(item.size for item in manifest.fixture_files) < 50_000
    assert all(item.path != MANIFEST_PATH.name for item in manifest.fixture_files)


def test_fail_closed_report_is_safe_but_does_not_claim_real_isolation(
    tmp_path: Path,
) -> None:
    manifest = _manifest()
    report = build_adversarial_acceptance_report(
        manifest,
        _fail_closed_observations(),
    )

    assert report.status is AdversarialAcceptanceStatus.FAIL_CLOSED
    assert report.safe_cases == report.total_cases == 10
    assert report.rejected_before_host_execution == 8
    assert report.deterministically_contained == 2
    assert report.real_isolation_contained == 0
    assert report.hostile_host_executions == 0
    assert not report.real_isolation_executed
    assert report.blocked_integrations == ["real_rootless_containment"]

    output = tmp_path / "adversarial-acceptance.json"
    write_adversarial_acceptance_report(output, report)
    assert (
        AdversarialAcceptanceReport.model_validate_json(output.read_text(encoding="utf-8"))
        == report
    )


def test_real_runtime_observations_produce_passing_report() -> None:
    report = build_adversarial_acceptance_report(
        _manifest(),
        _real_observations(),
    )

    assert report.status is AdversarialAcceptanceStatus.PASSED
    assert report.safe_cases == 10
    assert report.real_isolation_contained == 6
    assert report.real_isolation_executed
    assert report.blocked_integrations == []


def test_host_execution_or_wrong_boundary_evidence_fails_acceptance() -> None:
    observations = _fail_closed_observations()
    observations[0] = observations[0].model_copy(
        update={"hostile_repository_code_executed_on_host": True}
    )
    report = build_adversarial_acceptance_report(_manifest(), observations)
    assert report.status is AdversarialAcceptanceStatus.FAILED
    assert report.safe_cases == 9
    assert report.hostile_host_executions == 1

    observations = _fail_closed_observations()
    observations[0] = observations[0].model_copy(
        update={"evidence_kind": AdversarialEvidenceKind.BOUNDED_OUTPUT}
    )
    report = build_adversarial_acceptance_report(_manifest(), observations)
    assert report.status is AdversarialAcceptanceStatus.FAILED
    assert not report.outcomes[0].passed


def test_duplicate_missing_and_invalid_backend_observations_are_rejected() -> None:
    observations = _fail_closed_observations()
    with pytest.raises(ValueError, match="uniquely cover"):
        build_adversarial_acceptance_report(_manifest(), observations[:-1])
    with pytest.raises(ValidationError, match="backend"):
        AdversarialAcceptanceObservation(
            case_id=AdversarialCaseId.NETWORK_SOCKET,
            disposition=AdversarialDisposition.REAL_ISOLATION_CONTAINED,
            evidence_kind=AdversarialEvidenceKind.ROOTLESS_RUNTIME,
        )


def test_manifest_tamper_content_drift_extra_files_and_links_are_rejected(
    tmp_path: Path,
) -> None:
    payload = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["cases"][0]["expected_boundary"] = "bounded_output"
    tampered = tmp_path / "cases.json"
    tampered.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        ValidationError,
        match=r"expected hostile case|manifest hash",
    ):
        load_adversarial_acceptance_manifest(tampered)

    copied = tmp_path / "copied"
    shutil.copytree(MANIFEST_PATH.parent, copied)
    (copied / "package.json").write_text('{"changed":true}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="inventory or content hash"):
        load_adversarial_acceptance_manifest(copied / "cases.json")

    copied = tmp_path / "extra"
    shutil.copytree(MANIFEST_PATH.parent, copied)
    (copied / "extra.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inventory or content hash"):
        load_adversarial_acceptance_manifest(copied / "cases.json")

    linked = tmp_path / "linked-cases.json"
    linked.symlink_to(MANIFEST_PATH)
    with pytest.raises(ValueError, match="regular non-link"):
        load_adversarial_acceptance_manifest(linked)


def test_report_tamper_and_link_destination_are_rejected(tmp_path: Path) -> None:
    report = build_adversarial_acceptance_report(
        _manifest(),
        _fail_closed_observations(),
    )
    payload = report.model_dump(mode="json")
    payload["safe_cases"] = 0
    with pytest.raises(ValidationError, match="totals"):
        AdversarialAcceptanceReport.model_validate(payload)

    real_output = tmp_path / "real.json"
    real_output.write_text("{}\n", encoding="utf-8")
    linked_output = tmp_path / "linked.json"
    linked_output.symlink_to(real_output)
    with pytest.raises(ValueError, match="may not be a link"):
        write_adversarial_acceptance_report(linked_output, report)


def test_manifest_and_report_schemas_are_strict_and_complete() -> None:
    manifest_schema = json.loads(
        (ROOT / "schemas/adversarial_acceptance_manifest.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (ROOT / "schemas/adversarial_acceptance_report.schema.json").read_text(encoding="utf-8")
    )

    assert manifest_schema["additionalProperties"] is False
    assert manifest_schema["$defs"]["case"]["additionalProperties"] is False
    assert manifest_schema["$defs"]["fileBinding"]["additionalProperties"] is False
    assert set(manifest_schema["required"]) == set(AdversarialAcceptanceManifest.model_fields)
    assert report_schema["additionalProperties"] is False
    assert report_schema["$defs"]["outcome"]["additionalProperties"] is False
    assert set(report_schema["required"]) == set(AdversarialAcceptanceReport.model_fields)
