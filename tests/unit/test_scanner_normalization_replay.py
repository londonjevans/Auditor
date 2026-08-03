from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest

from mmaudit.models.schemas import (
    EvidenceStrength,
    ExecutionEvidenceKind,
    Location,
    ScannerFinding,
    ScannerRun,
    ScannerStatus,
    Severity,
)
from mmaudit.scanners.base import ScannerAdapter
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.normalization import (
    CODEQL_AUXILIARY_SARIF_REPLAY_REQUIREMENT,
    ScannerNormalizationReplayError,
    reparse_trusted_scanner_stdout,
    trusted_stdout_scanner_names,
    validate_real_scanner_normalization_replay,
)
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _slither_stdout() -> bytes:
    return json.dumps(
        {
            "success": True,
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Synthetic reentrancy issue",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "source_mapping": {
                                    "filename_relative": "app.py",
                                    "lines": [11, 12],
                                },
                            }
                        ],
                    }
                ]
            },
        },
        separators=(",", ":"),
    ).encode()


def _stdout(scanner: str) -> bytes:
    if scanner == "slither":
        return _slither_stdout()
    return (FIXTURES / "scanner_outputs" / f"{scanner}.json").read_bytes()


def _adapter(scanner: str) -> ScannerAdapter:
    factories: dict[str, Callable[[], ScannerAdapter]] = {
        "gitleaks": GitleaksScanner,
        "osv": OsvScanner,
        "semgrep": SemgrepScanner,
        "slither": SlitherScanner,
        "trivy": TrivyScanner,
    }
    return factories[scanner]()


def _annotated(findings: list[ScannerFinding]) -> list[ScannerFinding]:
    return [
        finding.model_copy(
            update={
                "metadata": {
                    **finding.metadata,
                    "location_validation": [
                        {
                            "valid": True,
                            "content_hash": "a" * 64,
                            "errors": [],
                            "validated_at": "2026-08-03T00:00:00Z",
                        }
                        for _location in finding.locations
                    ],
                }
            }
        )
        for finding in findings
    ]


def _run(scanner: str, stdout: bytes, findings: list[ScannerFinding]) -> ScannerRun:
    observed_at = datetime(2026, 8, 3, tzinfo=UTC)
    return ScannerRun(
        scanner=scanner,
        status=ScannerStatus.SUCCESS,
        execution_evidence=ExecutionEvidenceKind.REAL,
        command=[scanner, "synthetic-local-scan"],
        started_at=observed_at,
        finished_at=observed_at,
        duration_seconds=0,
        findings=findings,
        raw_output_path=f"{scanner}/stdout.json",
        raw_output_sha256=hashlib.sha256(stdout).hexdigest(),
        raw_output_bytes=len(stdout),
        process_exit_code=0,
        machine_output_validated=True,
    )


@pytest.mark.parametrize("scanner", sorted(trusted_stdout_scanner_names()))
def test_real_builtin_scanner_replay_preserves_every_parser_semantic(
    scanner: str,
    vulnerable_repo: Path,
) -> None:
    stdout = _stdout(scanner)
    direct = _adapter(scanner).parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    run = _run(scanner, stdout, _annotated(direct))

    replayed = validate_real_scanner_normalization_replay(
        run=run,
        repository_root=vulnerable_repo,
        retained_stdout=stdout,
    )

    assert replayed == tuple(direct)
    assert all("location_validation" not in finding.metadata for finding in replayed)


@pytest.mark.parametrize(
    "field,changed",
    [
        ("scanner", "custom-semgrep"),
        ("rule_id", "changed-rule"),
        ("title", "Changed title"),
        ("severity", Severity.LOW),
        ("message", "Changed message"),
        ("locations", [Location(path="app.py", start_line=1, end_line=1)]),
        ("cwe", ["CWE-999"]),
        ("metadata", {"engine_kind": None, "changed": True}),
        ("evidence_strength", EvidenceStrength.DETERMINISTIC_ANALYZER),
        ("fingerprint", "f" * 64),
    ],
)
def test_replay_rejects_every_non_host_scanner_semantic_change(
    field: str,
    changed: object,
    vulnerable_repo: Path,
) -> None:
    stdout = _stdout("semgrep")
    parsed = SemgrepScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    payload = parsed[0].model_dump(mode="python")
    payload[field] = changed
    altered = ScannerFinding.model_validate(payload)
    run = _run("semgrep", stdout, [altered])

    with pytest.raises(ScannerNormalizationReplayError, match="complete normalized finding"):
        validate_real_scanner_normalization_replay(
            run=run,
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


@pytest.mark.parametrize("scanner", ["custom", "codeql", "foundry", "semgrep-subclass"])
def test_unknown_or_auxiliary_scanner_cannot_mint_real_normalization_authority(
    scanner: str,
    vulnerable_repo: Path,
) -> None:
    stdout = b"{}"
    run = _run(scanner, stdout, [])

    with pytest.raises(ScannerNormalizationReplayError, match="no trusted built-in"):
        validate_real_scanner_normalization_replay(
            run=run,
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


def test_replay_requires_exact_retained_stdout_byte_custody(vulnerable_repo: Path) -> None:
    stdout = _stdout("semgrep")
    parsed = SemgrepScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    run = _run("semgrep", stdout, parsed)

    with pytest.raises(ScannerNormalizationReplayError, match="byte length differs"):
        validate_real_scanner_normalization_replay(
            run=run,
            repository_root=vulnerable_repo,
            retained_stdout=stdout + b" ",
        )
    changed_hash = run.model_copy(update={"raw_output_sha256": "0" * 64})
    with pytest.raises(ScannerNormalizationReplayError, match="SHA-256 differs"):
        validate_real_scanner_normalization_replay(
            run=changed_hash,
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


def test_replay_rejects_malformed_or_incomplete_host_location_annotation(
    vulnerable_repo: Path,
) -> None:
    stdout = _stdout("semgrep")
    parsed = SemgrepScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    malformed = parsed[0].model_copy(
        update={"metadata": {**parsed[0].metadata, "location_validation": []}}
    )

    with pytest.raises(ScannerNormalizationReplayError, match="exact location inventory"):
        validate_real_scanner_normalization_replay(
            run=_run("semgrep", stdout, [malformed]),
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


@pytest.mark.parametrize("annotation", [None, [{"valid": "not-a-boolean"}]])
def test_replay_does_not_strip_untyped_location_metadata(
    annotation: object,
    vulnerable_repo: Path,
) -> None:
    stdout = _stdout("semgrep")
    parsed = SemgrepScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    malformed = parsed[0].model_copy(
        update={"metadata": {**parsed[0].metadata, "location_validation": annotation}}
    )

    with pytest.raises(ScannerNormalizationReplayError, match="location validation"):
        validate_real_scanner_normalization_replay(
            run=_run("semgrep", stdout, [malformed]),
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


def test_replay_requires_exact_finding_count_and_order(vulnerable_repo: Path) -> None:
    stdout = _stdout("trivy")
    parsed = TrivyScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    assert len(parsed) == 2

    for altered in (parsed[:1], list(reversed(parsed)), [*parsed, parsed[0]]):
        with pytest.raises(ScannerNormalizationReplayError, match="complete normalized finding"):
            validate_real_scanner_normalization_replay(
                run=_run("trivy", stdout, altered),
                repository_root=vulnerable_repo,
                retained_stdout=stdout,
            )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"execution_evidence": ExecutionEvidenceKind.MOCK}, "requires REAL evidence"),
        ({"status": ScannerStatus.FAILED}, "successful validated machine output"),
        ({"machine_output_validated": False}, "successful validated machine output"),
        ({"process_exit_code": None}, "observed process exit code"),
        ({"process_exit_code": 99}, "exit code rejected"),
        ({"raw_output_path": None}, "retained stdout byte custody"),
    ],
)
def test_nonqualifying_run_state_cannot_mint_normalization_authority(
    updates: dict[str, object],
    message: str,
    vulnerable_repo: Path,
) -> None:
    stdout = _stdout("semgrep")
    parsed = SemgrepScanner().parse(vulnerable_repo, stdout.decode(), vulnerable_repo)
    run = _run("semgrep", stdout, parsed).model_copy(update=updates)

    with pytest.raises(ScannerNormalizationReplayError, match=message):
        validate_real_scanner_normalization_replay(
            run=run,
            repository_root=vulnerable_repo,
            retained_stdout=stdout,
        )


def test_raw_reparser_rejects_unknown_scanners_and_malformed_machine_output(
    vulnerable_repo: Path,
) -> None:
    with pytest.raises(ScannerNormalizationReplayError, match="no trusted built-in"):
        reparse_trusted_scanner_stdout(
            scanner="operator/custom",
            repository_root=vulnerable_repo,
            retained_stdout=b"{}",
        )
    with pytest.raises(ScannerNormalizationReplayError, match="failed trusted normalization"):
        reparse_trusted_scanner_stdout(
            scanner="semgrep",
            repository_root=vulnerable_repo,
            retained_stdout=b"{}",
        )


@pytest.mark.parametrize(
    ("scanner", "payload"),
    [
        ("osv", {}),
        ("osv", {"results": [None]}),
        (
            "osv",
            {
                "results": [
                    {
                        "source": {"path": "requirements.txt"},
                        "packages": [None],
                    }
                ]
            },
        ),
        (
            "osv",
            {
                "results": [
                    {
                        "source": {"path": "requirements.txt"},
                        "packages": [
                            {
                                "package": {"name": "synthetic"},
                                "vulnerabilities": [None],
                            }
                        ],
                    }
                ]
            },
        ),
        ("trivy", {}),
        ("trivy", {"Results": [None]}),
        (
            "trivy",
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [None],
                    }
                ]
            },
        ),
    ],
)
def test_osv_and_trivy_replay_rejects_vacuous_or_skipped_machine_records(
    scanner: str,
    payload: object,
    vulnerable_repo: Path,
) -> None:
    with pytest.raises(ScannerNormalizationReplayError, match="failed trusted normalization"):
        reparse_trusted_scanner_stdout(
            scanner=scanner,
            repository_root=vulnerable_repo,
            retained_stdout=json.dumps(payload).encode(),
        )


@pytest.mark.parametrize(
    ("scanner", "payload", "adapter"),
    [
        ("osv", {"results": []}, OsvScanner()),
        ("trivy", {"Results": []}, TrivyScanner()),
    ],
)
def test_osv_and_trivy_replay_accepts_only_explicit_empty_result_arrays(
    scanner: str,
    payload: object,
    adapter: ScannerAdapter,
    vulnerable_repo: Path,
) -> None:
    assert adapter.strict_machine_output is True
    assert (
        reparse_trusted_scanner_stdout(
            scanner=scanner,
            repository_root=vulnerable_repo,
            retained_stdout=json.dumps(payload).encode(),
        )
        == ()
    )


def test_codeql_auxiliary_sarif_remains_explicitly_non_authoritative() -> None:
    requirement = CODEQL_AUXILIARY_SARIF_REPLAY_REQUIREMENT

    assert requirement.scanner == "codeql"
    assert requirement.artifact_name == "codeql.sarif"
    assert requirement.required_bindings == ("normalized path", "SHA-256", "byte length")
    assert requirement.supported is False
    assert "does not yet bind" in requirement.reason
