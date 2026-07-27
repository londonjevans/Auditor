from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import InvariantExecutionStatus
from mmaudit.solidity.invariant_execution import normalize_foundry_invariant_output

FIXTURE = Path("tests/fixtures/solidity/economic_state_ordering")


def _run_contract(
    forge: str,
    root: Path,
    contract: str,
    tmp_path: Path,
    *,
    match_test: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        forge,
        "test",
        "--root",
        str(root),
        "--offline",
        "--color",
        "never",
        "--cache-path",
        str(tmp_path / f"cache-{contract}-{match_test or 'all'}"),
        "--out",
        str(tmp_path / f"out-{contract}-{match_test or 'all'}"),
        "--match-contract",
        contract,
        "--fuzz-runs",
        "32",
        "--fuzz-seed",
        "18",
    ]
    if match_test is not None:
        command.extend(["--match-test", match_test])
    command.append("-vvv")
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


def test_real_foundry_state_ordering_replays_minimal_two_action_sequence(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    assert not Path(forge).resolve().is_relative_to(FIXTURE.resolve())
    root = tmp_path / "economic-state-ordering"
    shutil.copytree(FIXTURE, root)
    source = root / "src" / "StateOrdering.sol"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()

    first = _run_contract(
        forge,
        root,
        "UnsafeStateOrderingInvariant",
        tmp_path / "unsafe-first",
    )
    second = _run_contract(
        forge,
        root,
        "UnsafeStateOrderingInvariant",
        tmp_path / "unsafe-second",
    )
    assert _normalized(first) is InvariantExecutionStatus.COUNTEREXAMPLE
    assert _normalized(second) is InvariantExecutionStatus.COUNTEREXAMPLE
    for result in (first, second):
        output = result.stdout + result.stderr
        assert "[Sequence] (original: 2, shrunk: 2)" in output
        assert output.index("calldata=action_PrepareState()") < output.index(
            "calldata=action_CommitState()"
        )

    safe = _run_contract(
        forge,
        root,
        "SafeStateOrderingInvariant",
        tmp_path / "safe",
    )
    assert safe.returncode == 0, safe.stdout + safe.stderr
    assert _normalized(safe) is InvariantExecutionStatus.PASSED

    for control in (
        "testPrepareAlonePreservesState",
        "testCommitAlonePreservesState",
        "testUnsafeTwoStepSequenceReachesInvalidState",
        "testSafeTwoStepSequenceConsumesPreparedState",
    ):
        result = _run_contract(
            forge,
            root,
            "StateOrderingMinimalityControls",
            tmp_path / "controls",
            match_test=control,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()
