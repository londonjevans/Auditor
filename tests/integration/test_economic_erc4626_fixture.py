from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import InvariantExecutionStatus
from mmaudit.solidity.invariant_execution import normalize_foundry_invariant_output

FIXTURE = Path("tests/fixtures/solidity/economic_erc4626")


def _run_contract(
    forge: str,
    contract: str,
    tmp_path: Path,
    *,
    match_test: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        forge,
        "test",
        "--root",
        str(FIXTURE),
        "--offline",
        "--color",
        "never",
        "--cache-path",
        str(tmp_path / f"cache-{contract}-{match_test or 'all'}"),
        "--out",
        str(tmp_path / f"out-{contract}-{match_test or 'all'}"),
        "--match-contract",
        contract,
    ]
    if match_test is not None:
        command.extend(["--match-test", match_test])
    command.append("-vv")
    return subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _normalized(result: subprocess.CompletedProcess[str]) -> InvariantExecutionStatus:
    status, _, _ = normalize_foundry_invariant_output(
        result.returncode,
        result.stdout + result.stderr,
    )
    return status


def test_real_foundry_erc4626_regression_is_replayable_and_minimal(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    assert not Path(forge).resolve().is_relative_to(FIXTURE.resolve())
    source = FIXTURE / "src" / "EconomicVaults.sol"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    first = _run_contract(forge, "UnsafeERC4626Invariant", tmp_path / "first")
    second = _run_contract(forge, "UnsafeERC4626Invariant", tmp_path / "second")
    assert _normalized(first) is InvariantExecutionStatus.COUNTEREXAMPLE
    assert _normalized(second) is InvariantExecutionStatus.COUNTEREXAMPLE

    safe = _run_contract(forge, "SafeERC4626Invariant", tmp_path / "safe")
    assert safe.returncode == 0, safe.stdout + safe.stderr
    assert _normalized(safe) is InvariantExecutionStatus.PASSED

    for control in (
        "testSetupAloneDoesNotPerformVictimTransition",
        "testOneVictimDepositIsMinimalUnsafeTransition",
        "testSafeOneVictimDepositMintsShares",
    ):
        result = _run_contract(
            forge,
            "ERC4626MinimalityControls",
            tmp_path / "controls",
            match_test=control,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
