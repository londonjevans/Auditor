from __future__ import annotations

import os
import shutil
import stat
from pathlib import Path

import pytest

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.models.schemas import (
    ForkActor,
    FoundryInvariantHarnessSpec,
    InvariantExecutionStatus,
    InvariantProbe,
    InvariantPropertySpec,
    InvariantRelation,
    LocalInvariantDeployment,
    SolidityProjectMetadata,
    SolidityProjectType,
    StatefulActionSpec,
)
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import default_isolation_backend

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "solidity" / "offline_replay"
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _explicit_test_compiler() -> Path:
    raw = os.environ.get("MMAUDIT_TEST_SOLC_EXECUTABLE", "")
    if not raw:
        pytest.skip("real local Foundry replay requires an explicit test compiler")
    compiler = Path(raw)
    try:
        metadata = compiler.lstat()
        resolved = compiler.resolve(strict=True)
    except OSError:
        pytest.skip("the explicit test compiler is unavailable")
    if (
        not compiler.is_absolute()
        or resolved != compiler
        or compiler.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        or resolved.is_relative_to(REPOSITORY_ROOT)
    ):
        pytest.skip("the explicit test compiler is not a trusted canonical regular file")
    return compiler


def test_saved_counterexample_replays_with_real_local_foundry_in_isolation(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    solc = _explicit_test_compiler()
    backend = default_isolation_backend("auto")
    if forge is None:
        pytest.skip("real local Foundry replay requires an external forge executable")
    if backend is None:
        pytest.skip("real local Foundry replay requires a hardened isolation backend")

    repository = tmp_path / "offline-replay"
    shutil.copytree(FIXTURE, repository)
    harness = FoundryInvariantHarnessSpec(
        invariant_id="inv-offline-replay",
        name="OfflineReplayCounterexample",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        local_deployments=[
            LocalInvariantDeployment(
                target_alias="ReplayCounter",
                contract_name="ReplayCounter",
                source_path="src/ReplayCounter.sol",
            )
        ],
        actions=[
            StatefulActionSpec(
                action_id="Touch",
                target="ReplayCounter",
                function_signature="touch()",
                actor_names=["attacker"],
            )
        ],
        properties=[
            InvariantPropertySpec(
                property_id="StateRemainsZero",
                left=InvariantProbe(
                    target="ReplayCounter",
                    function_signature="state()",
                ),
                relation=InvariantRelation.LTE,
                expected_uint=0,
            )
        ],
        runs=2,
        depth=1,
        seed=27,
    )
    result = FoundryInvariantRunner(
        ReproductionConfig(
            repetitions=2,
            timeout_seconds=30,
            targets={
                "ReplayCounter": "0x2000000000000000000000000000000000000002",
            },
        ),
        SmartContractsConfig(),
        backend=backend,
        forge_executable=Path(forge),
        solc_executable=solc,
    ).run(
        repository_root=repository,
        project=SolidityProjectMetadata(
            project_type=SolidityProjectType.FOUNDRY,
            project_root=".",
            source_directories=["src"],
            test_directories=["test"],
        ),
        specification=harness,
        private_dir=tmp_path / "private",
    )

    assert result.status is InvariantExecutionStatus.COUNTEREXAMPLE
    assert result.replay_confirmed
    assert result.attempts == result.successful_attempts == 2
    assert result.source_sha256
    assert result.compiler_sha256
    assert result.isolation_backend == backend.name
    assert all("--fork-url" not in item for item in result.command)
