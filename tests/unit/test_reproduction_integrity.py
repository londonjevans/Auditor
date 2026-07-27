from __future__ import annotations

import hashlib
from pathlib import Path

from mmaudit.config import ReproductionConfig, SmartContractsConfig
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
    ReproductionIntegrityCheckKind,
    ReproductionIntegrityStatus,
    ReproductionResult,
    ReproductionSettlementStatus,
    ReproductionState,
)
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.solidity.index import build_solidity_index
from mmaudit.solidity.projects import discover_solidity_projects
from mmaudit.solidity.reproduction import ForkReproductionRunner, translate_foundry_test
from mmaudit.solidity.reproduction_integrity import verify_reproduction_integrity

TARGETS = {"Vault": "0x2000000000000000000000000000000000000002"}


class _TestIsolationBackend:
    name = "synthetic-integrity-isolation"

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


def _repository(tmp_path: Path, *, patched: bool) -> Path:
    root = tmp_path / ("patched" if patched else "unsafe")
    (root / "src").mkdir(parents=True)
    (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n", encoding="utf-8")
    guard = "require(msg.sender == owner, 'not owner'); " if patched else ""
    (root / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    address owner;\n"
        f"    function withdraw(uint256 amount) external {{ {guard}owner; amount; }}\n"
        "}\n",
        encoding="utf-8",
    )
    return root


def _specification(*, flash_liquidity: bool = False) -> GeneratedFoundryTestSpec:
    capability = (
        {AttackerCapability.FLASH_LIQUIDITY: "Bounded synthetic liquidity for rejection."}
        if flash_liquidity
        else {}
    )
    return GeneratedFoundryTestSpec(
        candidate_id="candidate-integrity",
        name="IntegrityRegression",
        test_type=ForkTestType.AUTHORIZATION_MATRIX,
        rationale="Validate the cited authorization state transition.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            flash_liquidity_wei=1 if flash_liquidity else 0,
            capability_justifications=capability,
        ),
        attack_calls=[
            ForkCallStep(
                step_id="withdraw",
                actor="attacker",
                target="Vault",
                function_signature="withdraw(uint256)",
                arguments=[{"kind": "uint256", "value": "1"}],
            )
        ],
        assertions=[ForkAssertion(kind="call_succeeds", step_id="withdraw")],
        assumptions=["The synthetic target is bound to the configured local chain state."],
        required_block_number=7,
        expected_chain_id=31337,
    )


def _run_and_verify(
    *,
    root: Path,
    forge: Path,
    candidate_factory,
    config_factory,
    tmp_path: Path,
    specification: GeneratedFoundryTestSpec | None = None,
) -> tuple[ReproductionResult, object]:
    specification = specification or _specification()
    config = config_factory(smart_contracts={"enabled": True})
    discovery = discover_repository(root, config.repository, IgnoreMatcher())
    projects = discover_solidity_projects(discovery, config.smart_contracts)
    project = projects[0]
    index = build_solidity_index(discovery, projects, []).index
    candidate = candidate_factory(
        candidate_id="candidate-integrity",
        path="src/Vault.sol",
        start_line=4,
        end_line=4,
    )
    runner = ForkReproductionRunner(
        ReproductionConfig(
            repetitions=2,
            pinned_block_number=7,
            expected_chain_id=31337,
            targets=TARGETS,
        ),
        SmartContractsConfig(),
        backend=_TestIsolationBackend(),
        forge_executable=forge,
    )
    raw = runner.run(
        repository_root=root,
        project=project,
        candidate=candidate,
        specification=specification,
        private_dir=tmp_path / "private",
    )
    source = translate_foundry_test(
        specification,
        targets=TARGETS,
        expected_chain_id=31337,
    )
    verified = verify_reproduction_integrity(
        repository_root=root,
        project=project,
        candidate=candidate,
        specification=specification,
        result=raw,
        index=index,
        targets=TARGETS,
        expected_generated_test_sha256=hashlib.sha256(source.encode()).hexdigest(),
    )
    return verified, (project, index, candidate, specification, raw)


def _fake_forge(path: Path, *, reproduced: bool) -> Path:
    path.write_text(
        "#!/bin/sh\n" + ("exit 0\n" if reproduced else "exit 1\n"),
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_unsafe_fixture_has_verified_clean_minimized_integrity(
    tmp_path: Path,
    candidate_factory,
    config_factory,
    monkeypatch,
) -> None:
    root = _repository(tmp_path, patched=False)
    forge = _fake_forge(tmp_path / "forge-unsafe", reproduced=True)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")

    result, _context = _run_and_verify(
        root=root,
        forge=forge,
        candidate_factory=candidate_factory,
        config_factory=config_factory,
        tmp_path=tmp_path,
    )

    assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED
    assert len(result.attempt_evidence) == 2
    assert all(attempt.fresh_workspace for attempt in result.attempt_evidence)
    assert result.integrity is not None
    assert result.integrity.status is ReproductionIntegrityStatus.VERIFIED
    assert [check.check for check in result.integrity.checks] == list(
        ReproductionIntegrityCheckKind
    )
    assert all(check.passed for check in result.integrity.checks)
    assert result.integrity.settlement.status is (ReproductionSettlementStatus.ASSERTIONS_SATISFIED)
    assert ReproductionResult.model_validate_json(result.model_dump_json()) == result


def test_financial_settlement_is_hash_linked_to_verified_clean_replay(
    tmp_path: Path,
    candidate_factory,
    config_factory,
    monkeypatch,
) -> None:
    root = _repository(tmp_path, patched=False)
    forge = _fake_forge(tmp_path / "forge-financial", reproduced=True)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    specification = _specification().model_copy(
        update={
            "financial_settlement": FinancialSettlementEvidence(
                actor="attacker",
                asset_kind=FinancialAssetKind.NATIVE,
                starting_assets=0,
                borrowed_assets=0,
                repaid_assets=0,
                gross_assets_received=0,
                fees_paid=0,
                slippage_loss=0,
                ending_assets=0,
                net_impact=0,
            )
        }
    )

    result, _context = _run_and_verify(
        root=root,
        forge=forge,
        candidate_factory=candidate_factory,
        config_factory=config_factory,
        tmp_path=tmp_path,
        specification=specification,
    )

    assert result.financial_settlement_verified
    assert result.integrity is not None
    assert result.integrity.status is ReproductionIntegrityStatus.VERIFIED
    assert result.integrity.settlement.financial_settlement_verified
    assert result.integrity.settlement.financial_settlement_sha256 is not None


def test_patched_fixture_consistently_rejects_the_unsafe_state(
    tmp_path: Path,
    candidate_factory,
    config_factory,
    monkeypatch,
) -> None:
    root = _repository(tmp_path, patched=True)
    forge = _fake_forge(tmp_path / "forge-patched", reproduced=False)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")

    result, _context = _run_and_verify(
        root=root,
        forge=forge,
        candidate_factory=candidate_factory,
        config_factory=config_factory,
        tmp_path=tmp_path,
    )

    assert result.state is ReproductionState.NOT_REPRODUCED
    assert result.attempts == 2
    assert result.integrity is not None
    assert result.integrity.status is ReproductionIntegrityStatus.VERIFIED
    assert result.integrity.settlement.status is (ReproductionSettlementStatus.CLAIM_NOT_REPRODUCED)


def test_tampered_source_and_false_minimization_claim_are_rejected(
    tmp_path: Path,
    candidate_factory,
    config_factory,
    monkeypatch,
) -> None:
    root = _repository(tmp_path, patched=False)
    forge = _fake_forge(tmp_path / "forge-tamper", reproduced=True)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    verified, context = _run_and_verify(
        root=root,
        forge=forge,
        candidate_factory=candidate_factory,
        config_factory=config_factory,
        tmp_path=tmp_path,
    )
    project, index, candidate, specification, raw = context

    source_path = root / "src" / "Vault.sol"
    source_path.write_text(
        source_path.read_text(encoding="utf-8").replace(
            "owner; amount;",
            "owner; amount; uint256 changed; changed;",
        ),
        encoding="utf-8",
    )
    expected = verified.generated_test_sha256
    assert expected is not None
    tampered = verify_reproduction_integrity(
        repository_root=root,
        project=project,
        candidate=candidate,
        specification=specification,
        result=raw.model_copy(update={"minimization_evidence": None}),
        index=index,
        targets=TARGETS,
        expected_generated_test_sha256=expected,
    )

    assert tampered.integrity is not None
    assert tampered.integrity.status is ReproductionIntegrityStatus.REJECTED
    failed = {check.check for check in tampered.integrity.checks if not check.passed}
    assert ReproductionIntegrityCheckKind.REPOSITORY_HASH in failed
    assert ReproductionIntegrityCheckKind.CITED_REACHABILITY in failed
    assert ReproductionIntegrityCheckKind.MINIMIZATION in failed


def test_prohibited_capability_never_becomes_verified_execution(
    tmp_path: Path,
    candidate_factory,
    config_factory,
    monkeypatch,
) -> None:
    root = _repository(tmp_path, patched=False)
    marker = tmp_path / "forge-ran"
    forge = tmp_path / "forge-prohibited"
    forge.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
    forge.chmod(0o700)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")

    result, _context = _run_and_verify(
        root=root,
        forge=forge,
        candidate_factory=candidate_factory,
        config_factory=config_factory,
        tmp_path=tmp_path,
        specification=_specification(flash_liquidity=True),
    )

    assert result.state is ReproductionState.GENERATION_FAILED
    assert result.attempts == 0
    assert not marker.exists()
    assert result.integrity is not None
    assert result.integrity.status is ReproductionIntegrityStatus.INCONCLUSIVE
