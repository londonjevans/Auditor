from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

from mmaudit.benchmark.mutations import (
    MutationKind,
    SourceMutationSpec,
    apply_source_mutation,
    revert_source_mutation,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mutations"
SOURCE_PATH = "solidity/SafeMutationTargets.sol"


def _solc_0_8_30() -> Path | None:
    candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _specifications() -> list[SourceMutationSpec]:
    source_sha256 = hashlib.sha256((FIXTURE / SOURCE_PATH).read_bytes()).hexdigest()
    common = {
        "path": SOURCE_PATH,
        "expected_file_sha256": source_sha256,
    }
    return [
        SourceMutationSpec(
            id="mut-access-control",
            kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
            line=16,
            expected_line='        require(msg.sender == owner, "not owner");',
            **common,
        ),
        SourceMutationSpec(
            id="mut-replay-state",
            kind=MutationKind.REPLAY_STATE_UPDATE_REMOVAL,
            line=22,
            expected_line="        consumedIdentifiers[identifier] = true;",
            **common,
        ),
        SourceMutationSpec(
            id="mut-boundary",
            kind=MutationKind.BOUNDARY_CHECK_WEAKENING,
            line=26,
            expected_line='        require(amount < limit, "limit reached");',
            original_operator="<",
            replacement_operator="<=",
            **common,
        ),
        SourceMutationSpec(
            id="mut-accounting",
            kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
            line=31,
            expected_line="        return assets - fee;",
            original_operator="-",
            replacement_operator="+",
            **common,
        ),
        SourceMutationSpec(
            id="mut-call-result",
            kind=MutationKind.EXTERNAL_CALL_RESULT_CHECK_REMOVAL,
            line=36,
            expected_line='        require(success, "delivery failed");',
            **common,
        ),
    ]


def test_all_source_local_mutants_compile_and_restore(
    tmp_path: Path,
) -> None:
    solc = _solc_0_8_30()
    if solc is None:
        pytest.skip("external Foundry-managed solc 0.8.30 is not installed")

    for index, specification in enumerate(_specifications(), start=1):
        application = apply_source_mutation(
            source_repository=FIXTURE,
            workspace=tmp_path / f"mutant-{index}",
            specification=specification,
        )
        completed = subprocess.run(
            [
                str(solc),
                "--base-path",
                str(application.workspace),
                "--bin",
                str(application.workspace / SOURCE_PATH),
            ],
            cwd=application.workspace,
            env={
                "HOME": str(tmp_path),
                "LANG": "C",
                "LC_ALL": "C",
            },
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert completed.returncode == 0, completed.stderr
        assert revert_source_mutation(application).exact_restoration
