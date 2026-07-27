from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    EconomicSimulationKind,
    ForkActor,
    ForkCallStep,
    FoundryInvariantHarnessSpec,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    SolidityProjectMetadata,
    SolidityProjectType,
    StatefulActionSpec,
)
from mmaudit.solidity.invariant_execution import (
    FoundryInvariantRunner,
    normalize_foundry_invariant_output,
)
from mmaudit.solidity.reproduction import default_isolation_backend

FIXTURE = Path("tests/fixtures/solidity/economic_state_growth")


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


def test_real_foundry_state_growth_regressions_are_capped_and_minimal(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    if forge is None:
        pytest.skip("forge is not installed")
    assert not Path(forge).resolve().is_relative_to(FIXTURE.resolve())
    source = FIXTURE / "src" / "StateGrowth.sol"
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    source_text = source.read_text(encoding="utf-8")
    assert "while (" not in source_text
    assert "for (" not in source_text

    first = _run_contract(forge, "UnsafeStateGrowthInvariant", tmp_path / "first")
    second = _run_contract(forge, "UnsafeStateGrowthInvariant", tmp_path / "second")
    assert _normalized(first) is InvariantExecutionStatus.COUNTEREXAMPLE
    assert _normalized(second) is InvariantExecutionStatus.COUNTEREXAMPLE

    safe = _run_contract(forge, "SafeStateGrowthInvariant", tmp_path / "safe")
    assert safe.returncode == 0, safe.stdout + safe.stderr
    assert _normalized(safe) is InvariantExecutionStatus.PASSED

    for control in (
        "testUnsafeFourActionsReachButDoNotExceedThreshold",
        "testUnsafeFifthActionIsMinimalThresholdViolation",
        "testSafeFifthActionIsRejectedAndStateIsPreserved",
    ):
        result = _run_contract(
            forge,
            "StateGrowthControls",
            tmp_path / "controls",
            match_test=control,
        )
        assert result.returncode == 0, result.stdout + result.stderr

    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    assert not (FIXTURE / "cache").exists()
    assert not (FIXTURE / "out").exists()


def test_state_growth_campaign_timeout_is_enforced_by_real_local_isolation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = default_isolation_backend("auto")
    if backend is None or not getattr(backend, "supports_local_fork_rpc", True):
        pytest.skip("no real local-fork-capable isolation backend is available")
    repository = tmp_path / "repository"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "StateGrowth.sol").write_text(
        "pragma solidity ^0.8.20; contract StateGrowth {}\n",
        encoding="utf-8",
    )
    forge = tmp_path / "forge"
    forge.write_text("#!/bin/sh\nsleep 2\n", encoding="utf-8")
    forge.chmod(0o700)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = FoundryInvariantHarnessSpec(
        invariant_id="inv-state-growth-timeout",
        name="BoundedStateGrowthTimeout",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000002",
            )
        ],
        setup_calls=[
            ForkCallStep(
                step_id=f"FillEntry{index}",
                actor="attacker",
                target="StateGrowth",
                function_signature="appendPreset()",
            )
            for index in range(1, 5)
        ],
        actions=[
            StatefulActionSpec(
                action_id="AppendBeyondConfiguredThreshold",
                target="StateGrowth",
                function_signature="appendPreset()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="EntryCountWithinGrowthThreshold",
                left=InvariantProbe(
                    target="StateGrowth",
                    function_signature="entryCount()",
                ),
                relation=InvariantRelation.LTE,
                right=InvariantProbe(
                    target="StateGrowth",
                    function_signature="growthThreshold()",
                ),
            )
        ],
        runs=8,
        depth=1,
        economic_template=EconomicSimulationKind.BOUNDED_STATE_GROWTH,
    )
    result = FoundryInvariantRunner(
        ReproductionConfig(
            timeout_seconds=0.05,
            expected_chain_id=1,
            targets={
                "StateGrowth": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=backend,
        forge_executable=forge,
    ).run(
        repository_root=repository,
        project=SolidityProjectMetadata(
            project_type=SolidityProjectType.FOUNDRY,
            project_root=".",
            source_directories=["src"],
        ),
        specification=specification,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.TIMED_OUT
    assert result.duration_seconds < 1
