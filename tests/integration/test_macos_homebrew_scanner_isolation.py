"""Real macOS regression for Homebrew scanner execution under sandbox-exec."""

from __future__ import annotations

import platform
import shutil
from pathlib import Path

import pytest

from mmaudit.isolation.provenance import isolation_execution_evidence
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.scanners.semgrep import SemgrepScanner
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
