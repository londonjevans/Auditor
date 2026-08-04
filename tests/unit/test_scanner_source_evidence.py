from __future__ import annotations

import hashlib
import importlib
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditReport,
    EvidenceStrength,
    ExecutionEvidenceKind,
    Finding,
    FindingOriginKind,
    FindingStatus,
    Location,
    LocationValidation,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.reporting.bundle import (
    SCANNER_SOURCE_EVIDENCE_PATH,
    ScannerSourceEvidenceArtifact,
    ScannerSourceEvidenceRecord,
    SourceExcerptEvidence,
    build_scanner_source_evidence_artifact,
    scanner_source_authority,
    scanner_source_authority_from_runs,
)
from mmaudit.repository.chunking import line_range_hash
from mmaudit.scanners.base import scanner_fingerprint
from mmaudit.scanners.projection import project_scanner_finding
from tests.unit.test_client_forensic_reporting import _report

NOW = datetime(2026, 8, 4, 1, 30, tzinfo=UTC)
IGNORED_PATH = "requirements.lock"
START_LINE = 2
END_LINE = 3
IGNORED_SOURCE = """package==1.0
dependency==2.0
transitive==3.0
"""


def _scanner_evidence() -> tuple[ScannerRun, Finding, LocationValidation]:
    raw_location = Location(
        path=IGNORED_PATH,
        start_line=START_LINE,
        end_line=END_LINE,
        symbol=None,
    )
    validation = LocationValidation(
        valid=True,
        content_hash=line_range_hash(IGNORED_SOURCE, START_LINE, END_LINE),
        errors=[],
        validated_at=NOW,
    )
    fingerprint = scanner_fingerprint(
        "semgrep",
        "synthetic.lockfile.rule",
        IGNORED_PATH,
        START_LINE,
        "Synthetic local dependency finding.",
    )
    scanner_finding = ScannerFinding(
        scanner="semgrep",
        rule_id="synthetic.lockfile.rule",
        title="Synthetic ignored dependency condition",
        severity=Severity.MEDIUM,
        message="Synthetic local dependency finding.",
        locations=[raw_location],
        evidence_strength=EvidenceStrength.DETERMINISTIC_ANALYZER,
        fingerprint=fingerprint,
        metadata={"location_validation": [validation.model_dump(mode="json")]},
    )
    final_finding = project_scanner_finding(
        scanner_finding,
        [validation],
        validated_at=NOW,
    )
    provisional = ScannerRun(
        scanner="semgrep",
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        version="semgrep 1.0",
        executable_sha256="a" * 64,
        command=["/trusted/semgrep", "--json"],
        started_at=NOW,
        finished_at=NOW,
        duration_seconds=0,
        findings=[scanner_finding],
        raw_output_path="semgrep/output.json",
        raw_output_sha256="b" * 64,
        raw_output_bytes=1,
        process_exit_code=0,
        isolation_backend="synthetic-rootless",
        isolation_attestation_sha256="c" * 64,
        machine_output_validated=True,
    )
    run = ScannerRun.model_validate(
        {
            **provisional.model_dump(mode="json"),
            "execution_observation_sha256": (provisional.expected_execution_observation_sha256()),
        }
    )
    return run, final_finding, validation


def _reseal_run(run: ScannerRun, **updates: object) -> ScannerRun:
    unsealed = run.model_copy(
        update={
            **updates,
            "execution_observation_sha256": None,
        }
    )
    return ScannerRun.model_validate(
        {
            **unsealed.model_dump(mode="json"),
            "execution_observation_sha256": unsealed.expected_execution_observation_sha256(),
        }
    )


def _report_with(run: ScannerRun, finding: Finding) -> AuditReport:
    return AuditReport.model_validate(
        {
            **_report().model_dump(mode="json"),
            "scanner_runs": [run.model_dump(mode="json")],
            "findings": [finding.model_dump(mode="json")],
        }
    )


def _excerpt(location: Location) -> SourceExcerptEvidence:
    return SourceExcerptEvidence(
        path=location.path,
        symbol=location.symbol,
        file_sha256=hashlib.sha256(IGNORED_SOURCE.encode()).hexdigest(),
        cited_start_line=location.start_line,
        cited_end_line=location.end_line,
        cited_content_sha256=line_range_hash(
            IGNORED_SOURCE,
            location.start_line,
            location.end_line,
        ),
        excerpt_start_line=1,
        excerpt_end_line=len(IGNORED_SOURCE.splitlines()),
        content=IGNORED_SOURCE,
        content_sha256=hashlib.sha256(IGNORED_SOURCE.encode()).hexdigest(),
        omitted_before=False,
        omitted_after=False,
    )


def _record(
    run: ScannerRun,
    finding: Finding,
    *,
    finding_id: str | None = None,
) -> ScannerSourceEvidenceRecord:
    observation = run.execution_observation_sha256
    assert observation is not None
    location = finding.locations[0]
    return ScannerSourceEvidenceRecord(
        finding_id=finding_id or finding.id,
        scanner=run.scanner,
        scanner_fingerprint=finding.contributing_candidate_ids[0],
        scanner_execution_observation_sha256=observation,
        source_size=len(IGNORED_SOURCE.encode()),
        source_line_count=len(IGNORED_SOURCE.splitlines()),
        location=location,
        source_excerpt=_excerpt(location),
    )


def test_scanner_source_authority_resolves_exact_real_runtime_evidence() -> None:
    run, finding, validation = _scanner_evidence()
    report = _report_with(run, finding)

    from_report = scanner_source_authority(report, finding, finding.locations[0])
    from_runs = scanner_source_authority_from_runs([run], finding, finding.locations[0])

    assert from_report == from_runs
    assert from_report.scanner_run == run
    assert from_report.scanner_finding == run.findings[0]
    assert from_report.location_validation == validation


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("model_origin", "static-analyzer"),
        ("ambiguous_fingerprint", "exactly one contributing fingerprint"),
        ("mock_run", "machine-validated REAL execution"),
        ("unvalidated_output", "machine-validated REAL execution"),
        ("missing_observation", "machine-validated REAL execution"),
        ("legacy_observation", "machine-validated REAL execution"),
        ("failed_run", "machine-validated REAL execution"),
        ("scanner_mismatch", "inconsistent scanner identities"),
        ("missing_host_validation", "host location validation"),
        ("invalid_range_hash", "exact scanner projection"),
        ("duplicate_scanner_finding", "one exact scanner finding"),
    ],
)
def test_scanner_source_authority_fails_closed(
    mutation: str,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run, finding, _validation = _scanner_evidence()
    if mutation == "model_origin":
        finding = finding.model_copy(update={"origin_kind": FindingOriginKind.MODEL_REVIEW})
    elif mutation == "ambiguous_fingerprint":
        finding = finding.model_copy(
            update={
                "contributing_candidate_ids": [
                    *finding.contributing_candidate_ids,
                    "d" * 64,
                ]
            }
        )
    elif mutation == "mock_run":
        run = _reseal_run(run, execution_evidence=ExecutionEvidenceKind.MOCK)
    elif mutation == "unvalidated_output":
        run = _reseal_run(run, machine_output_validated=False)
    elif mutation == "missing_observation":
        run = run.model_copy(update={"execution_observation_sha256": None})
    elif mutation == "legacy_observation":
        monkeypatch.setattr(
            ScannerRun,
            "execution_observation_sha256_is_valid",
            lambda _run: True,
        )
        run = run.model_copy(update={"execution_observation_sha256": "0" * 64})
    elif mutation == "failed_run":
        run = _reseal_run(run, status=ScannerStatus.FAILED)
    elif mutation == "scanner_mismatch":
        run = _reseal_run(run, scanner="slither")
    elif mutation == "missing_host_validation":
        scanner_finding = run.findings[0].model_copy(update={"metadata": {}})
        run = _reseal_run(run, findings=[scanner_finding])
    elif mutation == "invalid_range_hash":
        location = finding.locations[0].model_copy(update={"content_hash": "d" * 64})
        finding = finding.model_copy(update={"locations": [location]})
    elif mutation == "duplicate_scanner_finding":
        run = _reseal_run(run, findings=[run.findings[0], run.findings[0]])
    else:  # pragma: no cover - keeps the parameter inventory exhaustive
        raise AssertionError(f"unhandled mutation: {mutation}")

    with pytest.raises(ValueError, match=message):
        scanner_source_authority_from_runs([run], finding, finding.locations[0])


def test_report_wrapper_accepts_exact_filtered_finding() -> None:
    run, finding, _validation = _scanner_evidence()
    typed_report_fixtures = importlib.import_module("tests.unit.test_run_status")
    coverage = typed_report_fixtures._coverage()
    floor = typed_report_fixtures._assessment(
        scanner_runs=[run],
        coverage=coverage,
        required_model_roles=(),
        scanner_only=True,
        explicit_downgrade_reason="Synthetic scanner-only reporting regression.",
    )
    payload = typed_report_fixtures._typed_report_payload(
        floor=floor,
        scanner_runs=[run],
        usage=[],
        coverage=coverage,
    )
    metadata = payload["metadata"]
    assert isinstance(metadata, dict)
    payload.update(
        {
            "findings": [],
            "filtered_findings": [finding],
            "metadata": {
                **metadata,
                "severity_threshold": Severity.HIGH.value,
            },
        }
    )
    report = AuditReport.model_validate(payload)

    authority = scanner_source_authority(report, finding, finding.locations[0])

    assert authority.scanner_finding.fingerprint == finding.contributing_candidate_ids[0]


def test_report_wrapper_rejects_finding_outside_active_and_filtered_inventory() -> None:
    run, finding, _validation = _scanner_evidence()
    report = _report_with(run, finding).model_copy(
        update={
            "findings": [],
            "rejected_findings": [finding.model_copy(update={"status": FindingStatus.REJECTED})],
        }
    )

    with pytest.raises(ValueError, match=r"one exact final finding|active or filtered"):
        scanner_source_authority(report, finding, finding.locations[0])


def test_scanner_source_evidence_artifact_is_private_sorted_and_location_bound() -> None:
    run, finding, _validation = _scanner_evidence()
    first = _record(run, finding, finding_id="MMA-A")
    second = _record(run, finding, finding_id="MMA-B")

    artifact = build_scanner_source_evidence_artifact(
        scanner_source_inventory_sha256="e" * 64,
        records=[second, first],
    )

    assert SCANNER_SOURCE_EVIDENCE_PATH == "private/scanner-source-evidence.json"
    assert artifact.schema_version == "1.0"
    assert [record.finding_id for record in artifact.records] == ["MMA-A", "MMA-B"]
    with pytest.raises(ValidationError, match="unique and sorted"):
        ScannerSourceEvidenceArtifact(
            scanner_source_inventory_sha256="e" * 64,
            records=[first, first],
        )

    mismatched_location = first.location.model_copy(update={"content_hash": "f" * 64})
    with pytest.raises(ValidationError, match="exact cited location"):
        ScannerSourceEvidenceRecord(
            **{
                **first.model_dump(mode="python"),
                "location": mismatched_location,
            }
        )
    with pytest.raises(ValidationError, match="size or line count"):
        ScannerSourceEvidenceRecord(
            **{
                **first.model_dump(mode="python"),
                "source_size": 1,
            }
        )

    mismatched_file_excerpt = first.source_excerpt.model_copy(update={"file_sha256": "0" * 64})
    with pytest.raises(ValidationError, match="raw file identity"):
        ScannerSourceEvidenceRecord(
            **{
                **first.model_dump(mode="python"),
                "source_excerpt": mismatched_file_excerpt,
            }
        )
