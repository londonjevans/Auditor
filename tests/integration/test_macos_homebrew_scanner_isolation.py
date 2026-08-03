"""Real macOS regression for Homebrew scanner execution under sandbox-exec."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
from pathlib import Path

import pytest

from mmaudit.config import SmartContractsConfig
from mmaudit.isolation.provenance import isolation_execution_evidence
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.scanners.gitleaks import GitleaksScanner
from mmaudit.scanners.osv import OsvScanner
from mmaudit.scanners.semgrep import SemgrepScanner
from mmaudit.scanners.slither import SlitherScanner
from mmaudit.scanners.trivy import TrivyScanner
from mmaudit.solidity.reproduction import default_isolation_backend


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
    if "Cellar" not in slither.parts or "slither-analyzer" not in slither.parts:
        pytest.skip("real scanner isolation regression requires slither resolved from Homebrew")
    compiler: Path | None = None
    for candidate in (
        Path("/opt/homebrew/opt/solidity/bin/solc"),
        Path("/usr/local/opt/solidity/bin/solc"),
    ):
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            continue
        if resolved.is_file() and "Cellar" in resolved.parts and "solidity" in resolved.parts:
            compiler = resolved
            break
    if compiler is None:
        pytest.skip("real Slither regression requires a native Homebrew Solidity compiler")
    compiler_sha256 = hashlib.sha256(compiler.read_bytes()).hexdigest()
    monkeypatch.setenv("MMAUDIT_SOLC_EXECUTABLE", str(compiler))
    backend = default_isolation_backend("sandbox-exec")
    if backend is None:
        pytest.skip("process-attested macOS sandbox-exec isolation is unavailable")
    assert isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL

    target = Path(__file__).parents[1] / "fixtures/solidity/realistic_scale/solidity_005k"
    private = tmp_path / "private" / "slither"
    run = SlitherScanner(
        SmartContractsConfig(
            solc_version="0.8.30",
            solc_sha256=compiler_sha256,
        )
    ).run(
        target,
        private,
        120,
        backend=backend,
    )

    assert run.status is ScannerStatus.SUCCESS, run.error
    assert run.execution_evidence is ExecutionEvidenceKind.REAL
    assert run.machine_output_validated
    assert run.raw_output_bytes > 0
    assert run.findings
    raw = json.loads((private / "slither.json").read_text(encoding="utf-8"))
    assert raw["success"] is True
    assert raw["error"] is None
    assert raw["results"]["detectors"]
    assert run.private_stderr_path == "slither/slither.stderr.txt"
    assert (tmp_path / "private" / run.private_stderr_path).is_file()
    staged_compiler = Path(run.command[run.command.index("--solc") + 1])
    staged_compiler.relative_to(private.resolve(strict=True))
    assert hashlib.sha256(staged_compiler.read_bytes()).hexdigest() == compiler_sha256
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert "(allow network" not in policy
