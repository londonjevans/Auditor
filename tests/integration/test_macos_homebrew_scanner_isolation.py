"""Real macOS regression for Homebrew scanner execution under sandbox-exec."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.isolation.provenance import isolation_execution_evidence
from mmaudit.models.schemas import AuditReport, ExecutionEvidenceKind, ScannerRun, ScannerStatus
from mmaudit.orchestration.verification import RunVerificationStatus, verify_run_evidence
from mmaudit.repository.locations import validate_location
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.trivy import TrivyScanner
from mmaudit.solidity.reproduction import default_isolation_backend

ROOT = Path(__file__).resolve().parents[2]
RUNNER = CliRunner()


def _trusted_solidity_compiler(tmp_path: Path) -> Path:
    candidates: list[Path] = []
    if explicit := os.environ.get("MMAUDIT_TEST_SOLC_EXECUTABLE"):
        candidates.append(Path(explicit))
    candidates.extend(
        (
            Path("/opt/homebrew/opt/solidity/bin/solc"),
            Path("/usr/local/opt/solidity/bin/solc"),
        )
    )
    compiler_home = tmp_path / "compiler-version-home"
    compiler_home.mkdir(mode=0o700)
    for candidate in candidates:
        try:
            compiler = candidate.resolve(strict=True)
            metadata = compiler.lstat()
        except OSError:
            continue
        current_uid = os.geteuid() if hasattr(os, "geteuid") else None
        if (
            not compiler.is_absolute()
            or compiler.is_symlink()
            or compiler.is_junction()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (current_uid is not None and metadata.st_uid not in {0, current_uid})
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            or compiler.is_relative_to(ROOT)
        ):
            continue
        identity = subprocess.run(
            [str(compiler), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env={
                "HOME": str(compiler_home),
                "LANG": "C",
                "LC_ALL": "C",
                "NO_COLOR": "1",
                "PATH": "/usr/bin:/bin",
            },
            shell=False,
        )
        if identity.returncode == 0 and re.search(
            r"\bVersion:\s*0\.8\.30\b",
            identity.stdout,
        ):
            return compiler
    pytest.skip("real Slither regression requires a trusted canonical Solidity 0.8.30 compiler")


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_semgrep_emits_normalized_finding_under_sandbox(
    tmp_path: Path,
) -> None:
    discovered = shutil.which("semgrep")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed semgrep")
    semgrep = Path(discovered).resolve(strict=True)
    if not {"Cellar", "Caskroom"} & set(semgrep.parts):
        pytest.skip(
            "real scanner isolation regression requires semgrep resolved from a Homebrew prefix"
        )
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    target = tmp_path / "synthetic-target"
    target.mkdir()
    (target / "unsafe_condition.py").write_text(
        "import os\n\nos.system('synthetic fixed local command')\n",
        encoding="utf-8",
    )

    run = SemgrepScanner().run(
        target,
        tmp_path / "private" / "semgrep",
        60,
        backend=backend,
    )

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.raw_output_bytes > 0
    assert run.findings
    assert run.findings[0].locations[0].path == "unsafe_condition.py"
    policy = (tmp_path / "private" / "semgrep" / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_semgrep_emits_validated_output_for_committed_solidity_fixture(
    tmp_path: Path,
) -> None:
    discovered = shutil.which("semgrep")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed semgrep")
    semgrep = Path(discovered).resolve(strict=True)
    if "Cellar" not in semgrep.parts or "semgrep" not in semgrep.parts:
        pytest.skip("real scanner isolation regression requires semgrep resolved from Homebrew")
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    target = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    assert target.is_dir()
    private = tmp_path / "private" / "semgrep-solidity"

    run = SemgrepScanner().run(target, private, 60, backend=backend)

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.machine_output_validated
    assert run.raw_output_bytes > 0
    raw = json.loads((private / "semgrep.json").read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    assert isinstance(raw.get("results"), list)
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy
    trusted_inputs = (private / "trusted-inputs").resolve(strict=True)
    assert f'(deny file-write* (subpath "{trusted_inputs}"))' in policy


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_gitleaks_reads_staged_rules_under_sandbox(
    tmp_path: Path,
) -> None:
    discovered = shutil.which("gitleaks")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed gitleaks")
    gitleaks = Path(discovered).resolve(strict=True)
    if not {"Cellar", "Caskroom"} & set(gitleaks.parts):
        pytest.skip(
            "real scanner isolation regression requires gitleaks resolved from a Homebrew prefix"
        )
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    target = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    assert target.is_dir()

    run = GitleaksScanner().run(
        target,
        tmp_path / "private" / "gitleaks",
        60,
        backend=backend,
    )

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.machine_output_validated
    assert run.raw_output_bytes > 0
    report_path = tmp_path / "private" / "gitleaks" / "gitleaks.json"
    report_bytes = report_path.read_bytes()
    assert report_bytes
    assert isinstance(json.loads(report_bytes), list)
    policy = (tmp_path / "private" / "gitleaks" / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy
    trusted_inputs = (tmp_path / "private" / "gitleaks" / "trusted-inputs").resolve(strict=True)
    assert f'(deny file-write* (subpath "{trusted_inputs}"))' in policy
    config_index = run.command.index("--config") + 1
    staged = Path(run.command[config_index]).resolve(strict=True)
    staged.relative_to((tmp_path / "private" / "gitleaks").resolve(strict=True))


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_osv_reports_solidity_scope_not_applicable(
    tmp_path: Path,
) -> None:
    discovered = shutil.which("osv-scanner")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed osv-scanner")
    osv = Path(discovered).resolve(strict=True)
    if not {"Cellar", "Caskroom"} & set(osv.parts):
        pytest.skip("real scanner isolation regression requires osv-scanner from Homebrew")
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")

    target = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    private = tmp_path / "private" / "osv"
    run = OsvScanner().run(target, private, 60, backend=backend)

    assert run.status is ScannerStatus.NOT_APPLICABLE, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.process_exit_code == 128
    assert run.operator_preparation_step is None
    assert run.private_stderr_path == "osv/osv.stderr.txt"
    assert run.private_stderr_bytes > 0
    assert run.execution_observation_sha256_is_valid()
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_trivy_reports_missing_offline_database_prerequisite(
    tmp_path: Path,
) -> None:
    discovered = shutil.which("trivy")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed trivy")
    trivy = Path(discovered).resolve(strict=True)
    if not {"Cellar", "Caskroom"} & set(trivy.parts):
        pytest.skip("real scanner isolation regression requires trivy resolved from Homebrew")
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")

    target = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    private = tmp_path / "private" / "trivy"
    run = TrivyScanner().run(target, private, 60, backend=backend)

    assert run.status is ScannerStatus.UNMET_PREREQUISITE, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.process_exit_code not in {None, 0}
    assert run.operator_preparation_step == "prepare_trivy_offline_vulnerability_database"
    assert run.private_stderr_path == "trivy/trivy.stderr.txt"
    assert run.private_stderr_bytes > 0
    assert run.execution_observation_sha256_is_valid()
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy


@pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="real Homebrew scanner isolation regression requires macOS sandbox-exec",
)
def test_real_homebrew_slither_emits_validated_machine_output_under_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    discovered = shutil.which("slither")
    if discovered is None:
        pytest.skip("real scanner isolation regression requires Homebrew-installed slither")
    slither = Path(discovered).resolve(strict=True)
    if (
        "Cellar" not in slither.parts
        or "slither-analyzer" not in slither.parts
        or "0.11.6" not in slither.parts
    ):
        pytest.skip("real scanner isolation regression requires Homebrew Slither 0.11.6")
    compiler = _trusted_solidity_compiler(tmp_path)
    compiler_sha256 = hashlib.sha256(compiler.read_bytes()).hexdigest()
    slither_sha256 = hashlib.sha256(slither.read_bytes()).hexdigest()
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(compiler))
    ambient_home = tmp_path / "ambient-home"
    ambient_state = ambient_home / ".solc-select"
    ambient_state.mkdir(parents=True)
    (ambient_state / "global-version").write_text("0.4.26\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(ambient_home))
    monkeypatch.setenv("SOLC_VERSION", "0.4.26")
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / "ambient-virtual-environment"))
    secret_canary = "synthetic-slither-environment-secret-canary"
    monkeypatch.setenv("OPENROUTER_API_KEY", secret_canary)
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    target = ROOT / "tests/fixtures/solidity/realistic_scale/solidity_005k"
    config_path = tmp_path / "mmaudit.toml"
    config_contents = (ROOT / "mmaudit.example.toml").read_text(encoding="utf-8")
    replacements = (
        ("scanner_timeout_seconds = 900", "scanner_timeout_seconds = 180"),
        ('# solc_version = "0.8.30"', 'solc_version = "0.8.30"'),
        ('# solc_sha256 = "<sha256>"', f'solc_sha256 = "{compiler_sha256}"'),
        ("[scanners.semgrep]\nenabled = true", "[scanners.semgrep]\nenabled = false"),
        ("[scanners.gitleaks]\nenabled = true", "[scanners.gitleaks]\nenabled = false"),
        ("[scanners.trivy]\nenabled = true", "[scanners.trivy]\nenabled = false"),
        ("[scanners.osv]\nenabled = true", "[scanners.osv]\nenabled = false"),
        (
            "[scanners.slither]\nenabled = false\nrequired = false",
            "[scanners.slither]\nenabled = false\nrequired = false\n"
            f'version = "0.11.6"\nsha256 = "{slither_sha256}"',
        ),
    )
    for original, replacement in replacements:
        assert config_contents.count(original) == 1
        config_contents = config_contents.replace(original, replacement, 1)
    config_path.write_text(config_contents, encoding="utf-8")
    output = tmp_path / "output"

    result = RUNNER.invoke(
        app,
        [
            "scan",
            "--config",
            str(config_path),
            "--repo",
            str(target),
            "--output",
            str(output),
            "--run-slither",
            "--language-profile",
            "solidity-evm",
            "--no-compile",
            "--skip-codeql",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE, result.stdout
    run_dirs = sorted(path for path in (output / "runs").iterdir() if path.is_dir())
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    scanner_payload = json.loads((run_dir / "scanner-results.json").read_text(encoding="utf-8"))
    scanner_runs = [ScannerRun.model_validate(value) for value in scanner_payload["runs"]]
    run = next(value for value in scanner_runs if value.scanner == "slither")

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.isolation_backend == "sandbox-exec"
    assert run.version == "0.11.6"
    assert run.executable_sha256 == slither_sha256
    assert run.process_exit_code == 0
    assert run.machine_output_validated
    assert run.execution_observation_sha256_is_valid()
    scanner_private_root = run_dir / "private" / "scanner-output"
    assert run.raw_output_path is not None
    raw_path = scanner_private_root / run.raw_output_path
    raw_bytes = raw_path.read_bytes()
    assert hashlib.sha256(raw_bytes).hexdigest() == run.raw_output_sha256
    assert len(raw_bytes) == run.raw_output_bytes
    raw = json.loads(raw_bytes)
    assert raw["success"] is True
    assert raw["error"] is None
    detector_count = len(raw["results"]["detectors"])
    assert 200 <= detector_count <= 260
    assert len(run.findings) == detector_count
    assert run.private_stderr_path is not None
    stderr_path = scanner_private_root / run.private_stderr_path
    stderr_bytes = stderr_path.read_bytes()
    assert hashlib.sha256(stderr_bytes).hexdigest() == run.private_stderr_sha256
    assert len(stderr_bytes) == run.private_stderr_bytes

    report = AuditReport.model_validate_json(
        (run_dir / "final-findings.json").read_text(encoding="utf-8")
    )
    assert len(report.findings) == detector_count
    assert all(finding.location_validation.valid for finding in report.findings)
    assert all(
        validate_location(target, location).valid
        for finding in report.findings
        for location in finding.locations
    )
    assert f"static analyzer={detector_count}." in (run_dir / "audit-report.md").read_text(
        encoding="utf-8"
    )
    sarif = json.loads((run_dir / "audit-results.sarif").read_text(encoding="utf-8"))
    slither_sarif = next(
        value
        for value in sarif["runs"][0]["properties"]["scannerExecutions"]
        if value["scanner"] == "slither"
    )
    assert slither_sarif["findingCount"] == detector_count
    assert slither_sarif["status"] == "success"
    assert slither_sarif["executionEvidence"] == "real"
    verification = verify_run_evidence(
        manifest_path=run_dir / "run-evidence-manifest.json",
        run_dir=run_dir,
        repository_root=target,
    )
    assert verification.status is RunVerificationStatus.CURRENT, verification.mismatches

    private = scanner_private_root / "slither"
    assert run.private_stderr_path == "slither/slither.stderr.txt"
    staged_compiler = Path(run.command[run.command.index("--solc") + 1])
    staged_compiler.relative_to(private.resolve(strict=True))
    assert hashlib.sha256(staged_compiler.read_bytes()).hexdigest() == compiler_sha256
    assert stat.S_IMODE(staged_compiler.stat().st_mode) == 0o500
    private_home = private / "home"
    private_state = private_home / ".solc-select"
    private_artifacts = private_state / "artifacts"
    for path in (private_home, private_state, private_artifacts):
        assert not path.is_symlink()
        assert not path.is_junction()
        assert stat.S_IMODE(path.stat().st_mode) == 0o700
    assert list(private_artifacts.iterdir()) == []
    assert not (private_state / "global-version").exists()
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy
    assert policy.count("(allow file-write*") == 1
    assert f'(allow file-write* (subpath "{private.resolve(strict=True)}"))' in policy
    serialized_execution = "\n".join((*run.command, policy, stderr_bytes.decode(errors="replace")))
    for excluded in (
        str(compiler),
        str(target),
        str(ambient_home),
        "SOLC_VERSION",
        "VIRTUAL_ENV",
        secret_canary,
    ):
        assert excluded not in serialized_execution
