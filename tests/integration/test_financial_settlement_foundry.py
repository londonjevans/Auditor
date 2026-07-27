from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import (
    AttackerCapability,
    AttackerCapabilityPolicy,
    FinancialAssetKind,
    FinancialSettlementEvidence,
    ForkActor,
    ForkAssertion,
    ForkCallStep,
    ForkTestType,
    GeneratedFoundryTestSpec,
)
from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity.reproduction import translate_foundry_test


def _external_solc() -> Path | None:
    candidates = (
        Path.home() / "Library" / "Application Support" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".local" / "share" / "svm" / "0.8.30" / "solc-0.8.30",
        Path.home() / ".svm" / "0.8.30" / "solc-0.8.30",
    )
    return next((candidate for candidate in candidates if candidate.is_file()), None)


def _specification() -> GeneratedFoundryTestSpec:
    return GeneratedFoundryTestSpec(
        candidate_id="candidate-financial-settlement",
        name="FinancialSettlementSerialization",
        test_type=ForkTestType.ACCOUNTING_INVARIANT,
        rationale="Validate observed endpoint balances and settled cashflow serialization.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
                initial_native_balance_wei=100,
            )
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            starting_native_capital_wei=100,
            capability_justifications={
                AttackerCapability.STARTING_CAPITAL: "Synthetic local balance only."
            },
        ),
        attack_calls=[
            ForkCallStep(
                step_id="ObserveNoop",
                actor="attacker",
                target="SyntheticNoop",
                function_signature="noop()",
            )
        ],
        assertions=[ForkAssertion(kind="call_succeeds", step_id="ObserveNoop")],
        financial_settlement=FinancialSettlementEvidence(
            actor="attacker",
            asset_kind=FinancialAssetKind.NATIVE,
            starting_assets=100,
            borrowed_assets=0,
            repaid_assets=0,
            gross_assets_received=0,
            fees_paid=0,
            slippage_loss=0,
            ending_assets=100,
            net_impact=0,
        ),
    )


def test_generated_financial_settlement_compiles_executes_and_serializes(
    tmp_path: Path,
) -> None:
    forge = shutil.which("forge")
    solc = _external_solc()
    if forge is None or solc is None:
        pytest.skip("forge and an external Foundry-managed solc 0.8.30 are required")

    project = tmp_path / "financial-settlement"
    (project / "test").mkdir(parents=True)
    forge_std = project / "lib" / "forge-std" / "src"
    forge_std.mkdir(parents=True)
    (project / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\nlibs = ['lib']\n",
        encoding="utf-8",
    )
    (project / "src").mkdir()
    (project / "src" / "Placeholder.sol").write_text(
        "pragma solidity ^0.8.20; contract Placeholder {}\n",
        encoding="utf-8",
    )
    (forge_std / "Test.sol").write_text(
        "// SPDX-License-Identifier: UNLICENSED\n"
        "pragma solidity ^0.8.20;\n"
        "interface Vm {"
        " function deal(address account, uint256 balance) external;"
        " function prank(address caller) external;"
        "}\n"
        "abstract contract Test {\n"
        " Vm internal constant vm = Vm("
        "address(uint160(uint256(keccak256('hevm cheat code')))));\n"
        " event log_named_uint(string key, uint256 value);\n"
        " event log_named_int(string key, int256 value);\n"
        " function assertTrue(bool value, string memory reason) internal pure {"
        " require(value, reason);"
        " }\n"
        " function assertEq(uint256 left, uint256 right, string memory reason)"
        " internal pure { require(left == right, reason); }\n"
        "}\n",
        encoding="utf-8",
    )
    generated = translate_foundry_test(
        _specification(),
        targets={"SyntheticNoop": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=None,
    )
    generated_path = project / "test" / "FinancialSettlementSerialization.t.sol"
    generated_path.write_text(generated, encoding="utf-8")
    source_sha256 = hashlib.sha256(generated_path.read_bytes()).hexdigest()

    result = subprocess.run(
        [
            forge,
            "test",
            "--root",
            str(project),
            "--offline",
            "--use",
            str(solc),
            "--cache-path",
            str(tmp_path / "cache"),
            "--out",
            str(tmp_path / "out"),
            "--match-test",
            "test_MMAudit_FinancialSettlementSerialization",
            "--color",
            "never",
            "-vvv",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=sanitized_scanner_environment(tmp_path / "environment"),
    )

    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "MMAUDIT_STARTING_ASSETS" in output
    assert "MMAUDIT_ENDING_ASSETS" in output
    assert "MMAUDIT_NET_IMPACT" in output
    assert hashlib.sha256(generated_path.read_bytes()).hexdigest() == source_sha256
