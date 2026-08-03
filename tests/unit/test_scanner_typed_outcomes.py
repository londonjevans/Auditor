from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.schemas import (
    AuditReport,
    ExecutionEvidenceKind,
    RepositoryMap,
    ScannerRun,
    ScannerStatus,
)
from mmaudit.reporting.json_report import stable_json
from mmaudit.reporting.markdown import render_markdown
from mmaudit.reporting.sarif import generate_sarif
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.scanners.trivy import TrivyScanner


class _MockIsolation:
    name = "synthetic-isolation"
    execution_evidence = ExecutionEvidenceKind.MOCK

    def wrap(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del workspace, private_dir, rpc_port
        return command


def _install_scanner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    name: str,
    version: str,
    stderr: str,
    exit_code: int,
) -> None:
    trusted_bin = tmp_path / "trusted-bin"
    trusted_bin.mkdir(exist_ok=True)
    executable = trusted_bin / name
    executable.write_text(
        "\n".join(
            (
                f"#!{sys.executable}",
                "import sys",
                'if "--version" in sys.argv:',
                f"    print({version!r})",
                "    raise SystemExit(0)",
                f"sys.stderr.write({stderr!r})",
                f"raise SystemExit({exit_code})",
                "",
            )
        ),
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(trusted_bin))


def _report(run: ScannerRun) -> AuditReport:
    now = datetime.now(UTC)
    return AuditReport(
        schema_version="1.0",
        run_id="typed-scanner-outcome",
        generated_at=now,
        completed=True,
        incomplete_reasons=[],
        repository=RepositoryMap(
            root_name="synthetic-solidity-target",
            languages={"Solidity": 1},
            frameworks=[],
            manifests=[],
            entry_points=[],
            api_surfaces=[],
            auth_components=[],
            data_layers=[],
            network_clients=[],
            file_handlers=[],
            configuration_files=[],
            sensitive_processing=[],
            security_tests=[],
            files=[],
        ),
        configuration_hash="synthetic-config",
        model_configuration_hash="synthetic-model-config",
        privacy={},
        scanner_runs=[run],
        usage=[],
        budget_usd=0,
        accounted_cost_usd=0,
        findings=[],
        rejected_findings=[],
    )


def test_osv_no_package_sources_is_not_applicable_and_not_a_required_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    private_diagnostic = "No package sources found, --help for usage information.\n"
    _install_scanner(
        tmp_path,
        monkeypatch,
        name="osv-scanner",
        version="osv-scanner version 2.4.0",
        stderr=private_diagnostic,
        exit_code=128,
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")

    run = OsvScanner().run(
        target,
        tmp_path / "private" / "osv",
        5,
        backend=_MockIsolation(),
    )

    assert run.status is ScannerStatus.NOT_APPLICABLE
    assert not run.status.is_failure
    assert run.process_exit_code == 128
    assert run.execution_evidence is ExecutionEvidenceKind.MOCK
    assert run.private_stderr_path == "osv/osv.stderr.txt"
    assert run.private_stderr_bytes == len(private_diagnostic.encode())
    assert run.private_stderr_sha256 is not None
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    assert run.operator_preparation_step is None
    config = config_factory(scanners={"osv": {"enabled": True, "required": True}})
    runner = ScannerRunner(config, adapters={"osv": OsvScanner()}, backend=_MockIsolation())
    assert runner.required_failures([run]) == []

    report = _report(run)
    json_report = stable_json(report)
    markdown = render_markdown(report)
    sarif = generate_sarif([], scanner_runs=[run])
    public = "\n".join((json_report, markdown, stable_json(sarif)))
    assert private_diagnostic.strip() not in public
    assert "not_applicable" in public
    assert "Scanners not applicable to this scope" in markdown
    assert "Scanner limitations/failures" not in markdown
    scanner_record = sarif["runs"][0]["properties"]["scannerExecutions"][0]
    assert scanner_record["status"] == "not_applicable"
    notification = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False
    assert notification["level"] == "note"
    assert notification["properties"]["status"] == "not_applicable"


def test_trivy_missing_offline_database_is_an_unmet_prerequisite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    private_diagnostic = (
        "2026-08-03T00:00:00Z FATAL [vulndb] The first run cannot skip downloading DB\n"
    )
    _install_scanner(
        tmp_path,
        monkeypatch,
        name="trivy",
        version="Version: 0.72.0",
        stderr=private_diagnostic,
        exit_code=1,
    )
    target = tmp_path / "target"
    target.mkdir()
    (target / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")

    run = TrivyScanner().run(
        target,
        tmp_path / "private" / "trivy",
        5,
        backend=_MockIsolation(),
    )

    assert run.status is ScannerStatus.UNMET_PREREQUISITE
    assert run.status.is_failure
    assert run.operator_preparation_step == "prepare_trivy_offline_vulnerability_database"
    assert run.private_stderr_path == "trivy/trivy.stderr.txt"
    assert run.private_stderr_bytes == len(private_diagnostic.encode())
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()
    config = config_factory(scanners={"trivy": {"enabled": True, "required": True}})
    runner = ScannerRunner(config, adapters={"trivy": TrivyScanner()}, backend=_MockIsolation())
    assert runner.required_failures([run]) == ["trivy: unmet_prerequisite"]

    report = _report(run)
    json_report = stable_json(report)
    markdown = render_markdown(report)
    sarif = generate_sarif([], scanner_runs=[run])
    public = "\n".join((json_report, markdown, stable_json(sarif)))
    assert private_diagnostic.strip() not in public
    assert "unmet_prerequisite" in public
    assert "prepare_trivy_offline_vulnerability_database" in public
    assert "private stderr: trivy/trivy.stderr.txt" in markdown
    scanner_record = sarif["runs"][0]["properties"]["scannerExecutions"][0]
    assert scanner_record["status"] == "unmet_prerequisite"
    notification = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"][0]
    assert notification["level"] == "warning"
    assert notification["properties"]["status"] == "unmet_prerequisite"


def test_scanner_diagnostics_do_not_misclassify_unrecognized_failures() -> None:
    assert (
        OsvScanner().classify_non_success_exit(
            return_code=128,
            stdout=b"",
            stderr=b"No package sources found\nadditional failure",
        )
        is None
    )
    assert (
        TrivyScanner().classify_non_success_exit(
            return_code=1,
            stdout=b'{"partial": true}',
            stderr=b"FATAL [vulndb] The first run cannot skip downloading DB",
        )
        is None
    )


@pytest.mark.parametrize(
    "diagnostic",
    [
        b"No package sources found\n",
        b"No package sources found, --help for usage information.\n",
    ],
)
def test_osv_recognizes_only_bounded_no_source_diagnostics(diagnostic: bytes) -> None:
    classification = OsvScanner().classify_non_success_exit(
        return_code=128,
        stdout=b"",
        stderr=diagnostic,
    )

    assert classification is not None
    assert classification.status is ScannerStatus.NOT_APPLICABLE


def test_unmet_prerequisite_schema_requires_bound_artifacts_and_preparation() -> None:
    now = datetime.now(UTC)
    payload = {
        "scanner": "trivy",
        "status": ScannerStatus.UNMET_PREREQUISITE,
        "command": ["trivy", "fs"],
        "started_at": now,
        "finished_at": now,
        "duration_seconds": 0,
        "raw_output_path": "trivy/trivy.json",
        "raw_output_sha256": "1" * 64,
        "private_stderr_path": "trivy/trivy.stderr.txt",
        "private_stderr_sha256": "2" * 64,
        "private_stderr_bytes": 10,
        "process_exit_code": 1,
    }

    with pytest.raises(ValidationError, match="operator preparation step"):
        ScannerRun.model_validate(payload)
    with pytest.raises(ValidationError, match="bound process artifacts"):
        ScannerRun.model_validate(
            {
                **payload,
                "operator_preparation_step": "prepare_trivy_offline_vulnerability_database",
                "private_stderr_path": None,
                "private_stderr_sha256": None,
                "private_stderr_bytes": 0,
            }
        )
    with pytest.raises(ValidationError, match="requires an unmet scanner prerequisite"):
        ScannerRun.model_validate(
            {
                **payload,
                "status": ScannerStatus.FAILED,
                "operator_preparation_step": "prepare_trivy_offline_vulnerability_database",
            }
        )
    with pytest.raises(ValidationError, match="typed scanner output path must be safe"):
        ScannerRun.model_validate(
            {
                **payload,
                "operator_preparation_step": "prepare_trivy_offline_vulnerability_database",
                "raw_output_path": "/private/trivy.json",
            }
        )
    with pytest.raises(ValidationError, match="bound stdout digest"):
        ScannerRun.model_validate(
            {
                **payload,
                "operator_preparation_step": "prepare_trivy_offline_vulnerability_database",
                "raw_output_sha256": None,
            }
        )


@pytest.mark.parametrize(
    "private_path",
    [
        "/private/scanner.stderr.txt",
        "../scanner.stderr.txt",
        "scanner/../../escape.stderr.txt",
        "scanner\\stderr.txt",
        "C:/private/scanner.stderr.txt",
        "scanner:alternate/stderr.txt",
        "scanner//stderr.txt",
        "scanner/\nstderr.txt",
        "scanner/\u202estderr.txt",
    ],
)
def test_private_stderr_path_rejects_unsafe_artifact_locations(private_path: str) -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValidationError, match="safe and relative"):
        ScannerRun(
            scanner="synthetic",
            status=ScannerStatus.FAILED,
            started_at=now,
            finished_at=now,
            duration_seconds=0,
            private_stderr_path=private_path,
            private_stderr_sha256="1" * 64,
        )


def test_pre_typed_outcome_observation_digest_remains_narrowly_compatible() -> None:
    now = datetime.now(UTC)
    run = ScannerRun(
        scanner="semgrep",
        status=ScannerStatus.SUCCESS,
        started_at=now,
        finished_at=now,
        duration_seconds=0,
    )
    historical_payload = run.model_dump(
        mode="json",
        exclude={
            "private_stderr_path",
            "private_stderr_sha256",
            "private_stderr_bytes",
            "operator_preparation_step",
            "execution_observation_sha256",
        },
    )
    historical_digest = hashlib.sha256(
        json.dumps(
            historical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()
    historical_payload["execution_observation_sha256"] = historical_digest

    restored = ScannerRun.model_validate(historical_payload)

    assert restored.execution_observation_sha256_is_valid()
    assert ScannerRun.model_validate_json(restored.model_dump_json()) == restored
    tampered = restored.model_dump(mode="json")
    tampered.update(
        {
            "private_stderr_path": "semgrep/semgrep.stderr.txt",
            "private_stderr_sha256": "2" * 64,
        }
    )
    with pytest.raises(ValidationError, match="execution observation hash"):
        ScannerRun.model_validate(tampered)
