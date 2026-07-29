from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import ReproductionConfig, SmartContractsConfig
from mmaudit.isolation.provenance import (
    _IsolationProbeResults,
    isolation_execution_evidence,
)
from mmaudit.models.schemas import (
    AttackerCapability,
    AttackerCapabilityPolicy,
    CrossChainMessageCapability,
    ExecutionEvidenceKind,
    FinancialAssetKind,
    FinancialSettlementEvidence,
    ForkActor,
    ForkAssertion,
    ForkCallStep,
    ForkSetupCallStep,
    ForkTestType,
    GeneratedFoundryTestSpec,
    OracleInfluenceCapability,
    ReproductionResult,
    ReproductionState,
    SolidityProjectMetadata,
    SolidityProjectType,
    TransactionOrderingCapability,
)
from mmaudit.solidity.reproduction import (
    BubblewrapBackend,
    ForkReproductionRunner,
    MacOSSandboxBackend,
    capability_policy_error,
    default_isolation_backend,
    translate_foundry_test,
)


class TestIsolationBackend:
    name = "synthetic-test-isolation"

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


class SelfAssertedRealIsolationBackend(TestIsolationBackend):
    """Adversarial injected backend that must not mint real provenance."""

    name = "sandbox-exec"
    execution_evidence = ExecutionEvidenceKind.REAL


def _spec() -> GeneratedFoundryTestSpec:
    return GeneratedFoundryTestSpec(
        candidate_id="candidate-solidity",
        name="UnauthorizedWithdraw",
        test_type=ForkTestType.AUTHORIZATION_MATRIX,
        rationale="An ordinary actor attempts the privileged withdrawal.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            )
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
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
        assertions=[
            ForkAssertion(kind="call_succeeds", step_id="withdraw"),
        ],
        assumptions=["Vault points to the deployment at the pinned fork block"],
        required_block_number=123,
        expected_chain_id=1,
    )


def _financial_spec() -> GeneratedFoundryTestSpec:
    payload = _spec().model_dump(mode="json")
    payload["attacker_policy"].update(
        {
            "flash_liquidity_wei": 5,
            "capability_justifications": {
                "flash_liquidity": "Bounded synthetic principal for settlement validation."
            },
        }
    )
    payload["attack_calls"][0]["required_capabilities"] = ["flash_liquidity"]
    payload["financial_settlement"] = {
        "actor": "attacker",
        "asset_kind": "native",
        "asset_target": None,
        "unit": "base_units",
        "starting_assets": 0,
        "borrowed_assets": 5,
        "repaid_assets": 5,
        "gross_assets_received": 0,
        "fees_paid": 0,
        "slippage_loss": 0,
        "ending_assets": 0,
        "net_impact": 0,
    }
    return GeneratedFoundryTestSpec.model_validate(payload)


def _project() -> SolidityProjectMetadata:
    return SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
        test_directories=["test"],
        build_command=["forge", "build"],
        test_command=["forge", "test"],
    )


def _runner(
    fake_forge: Path,
    *,
    timeout: float = 2,
    max_flash_liquidity_wei: int = 0,
) -> ForkReproductionRunner:
    return ForkReproductionRunner(
        ReproductionConfig(
            repetitions=2,
            timeout_seconds=timeout,
            pinned_block_number=123,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
            max_flash_liquidity_wei=max_flash_liquidity_wei,
        ),
        SmartContractsConfig(),
        backend=TestIsolationBackend(),
        forge_executable=fake_forge,
    )


def _fake_forge(path: Path, body: str) -> Path:
    path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
    path.chmod(0o700)
    return path


def test_declarative_spec_translates_without_commands_or_wallet_operations() -> None:
    source = translate_foundry_test(
        _spec(),
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "target_Vault.call" in source
    assert "vm.prank(actor_attacker)" in source
    for forbidden in ("ffi", "broadcast", "privateKey", "vm.sign", "system("):
        assert forbidden not in source


def test_financial_settlement_arithmetic_rejects_inconsistent_evidence() -> None:
    valid = FinancialSettlementEvidence(
        actor="attacker",
        asset_kind=FinancialAssetKind.NATIVE,
        starting_assets=100,
        borrowed_assets=50,
        repaid_assets=50,
        gross_assets_received=30,
        fees_paid=5,
        slippage_loss=2,
        ending_assets=123,
        net_impact=23,
    )
    assert FinancialSettlementEvidence.model_validate_json(valid.model_dump_json()) == valid

    invalid_cases = (
        ({"repaid_assets": 49}, "full principal repayment"),
        ({"ending_assets": 124}, "do not reconcile"),
        ({"net_impact": 24}, "ending assets minus starting assets"),
        ({"fees_paid": 1_000}, "outside uint256 bounds"),
    )
    for updates, expected in invalid_cases:
        payload = valid.model_dump(mode="json")
        payload.update(updates)
        with pytest.raises(ValidationError, match=expected):
            FinancialSettlementEvidence.model_validate(payload)


def test_financial_reproduction_requires_settlement_and_translates_all_fields() -> None:
    payload = _financial_spec().model_dump(mode="json")
    payload["financial_settlement"] = None
    with pytest.raises(ValidationError, match="requires arithmetically settled impact"):
        GeneratedFoundryTestSpec.model_validate(payload)

    source = translate_foundry_test(
        _financial_spec(),
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    assert "uint256 mmauditStartingAssets = actor_attacker.balance;" in source
    assert "uint256 mmauditEndingAssets = actor_attacker.balance;" in source
    for label in (
        "MMAUDIT_STARTING_ASSETS",
        "MMAUDIT_BORROWED_ASSETS",
        "MMAUDIT_REPAID_ASSETS",
        "MMAUDIT_GROSS_ASSETS_RECEIVED",
        "MMAUDIT_FEES_PAID",
        "MMAUDIT_SLIPPAGE_LOSS",
        "MMAUDIT_ENDING_ASSETS",
        "MMAUDIT_NET_IMPACT",
    ):
        assert label in source


def test_mocked_runner_serializes_verified_financial_settlement(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repo"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge, max_flash_liquidity_wei=5).run(
        repository_root=repository,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_financial_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED
    assert result.financial_settlement == _financial_spec().financial_settlement
    assert result.financial_settlement_verified
    assert ReproductionResult.model_validate_json(result.model_dump_json()) == result


def test_setup_calls_are_explicit_and_translated_before_the_attack_phase() -> None:
    base = _spec()
    specification = base.model_copy(
        update={
            "actors": [
                ForkActor(
                    name="administrator",
                    address="0x1000000000000000000000000000000000000002",
                ),
                *base.actors,
            ],
            "setup_calls": [
                ForkSetupCallStep(
                    step_id="prepare",
                    actor="administrator",
                    target="Vault",
                    function_signature="prepare()",
                )
            ],
        }
    )

    first = translate_foundry_test(
        specification,
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )
    second = translate_foundry_test(
        specification,
        targets={"Vault": "0x2000000000000000000000000000000000000002"},
        expected_chain_id=1,
    )

    assert first == second
    setup_marker = first.index("// Setup phase: explicit harness preconditions only.")
    setup_call = first.index("success_prepare")
    setup_assertion = first.index('assertTrue(success_prepare, "setup call prepare failed")')
    attack_marker = first.index("// Attack phase: declared actor calls only.")
    attack_call = first.index("success_withdraw")
    assert setup_marker < setup_call < setup_assertion < attack_marker < attack_call
    attack_source = first[attack_marker:]
    for forbidden in ("vm.deal", "vm.store", "vm.warp", "vm.roll", "vm.sign", "vm.ffi"):
        assert forbidden not in attack_source


def test_macos_policy_allows_compiler_children_but_not_host_or_remote_access(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = MacOSSandboxBackend(executable="/usr/bin/sandbox-exec")
    command = backend.wrap(
        ["/usr/local/bin/forge", "test"],
        workspace=workspace,
        private_dir=private,
        rpc_port=8545,
    )
    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert command[:2] == ["/usr/bin/sandbox-exec", "-f"]
    assert "(allow process-exec)" in policy
    assert '(allow mach-lookup (global-name "com.apple.SystemConfiguration.configd"))' in policy
    assert "localhost:8545" in policy
    assert "(allow network-outbound)" not in policy
    assert str(Path.home()) not in policy


def test_macos_inventory_policy_grants_no_network_entitlement(tmp_path: Path) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    compiler = private / "toolchain" / "solc"
    compiler.parent.mkdir()
    compiler.write_bytes(b"synthetic pinned compiler")
    backend = MacOSSandboxBackend(executable="/usr/bin/sandbox-exec")

    command = backend.wrap_without_network(
        ["/usr/local/bin/forge", "test", "--use", str(compiler)],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )

    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert command[:2] == ["/usr/bin/sandbox-exec", "-f"]
    assert "(allow process-exec)" in policy
    assert "(allow network" not in policy
    assert f'(literal "{compiler}")' in policy


def test_macos_policy_grants_no_network_entitlement_without_rpc(tmp_path: Path) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = MacOSSandboxBackend(executable="/usr/bin/sandbox-exec")

    command = backend.wrap(
        ["/usr/local/bin/forge", "test"],
        workspace=workspace,
        private_dir=private,
        rpc_port=0,
    )

    policy = (private / "sandbox.sb").read_text(encoding="utf-8")
    assert command[:2] == ["/usr/bin/sandbox-exec", "-f"]
    assert "(allow network" not in policy
    assert "localhost:0" not in policy


def test_bubblewrap_denies_network_and_mounts_only_private_workspace(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = BubblewrapBackend(executable="/usr/bin/bwrap")
    command = backend.wrap(
        ["/usr/bin/forge", "test"],
        workspace=workspace,
        private_dir=private,
        rpc_port=8545,
    )
    assert "--unshare-net" in command
    assert ["--bind", str(private.resolve()), str(private.resolve())] == command[
        command.index("--bind") : command.index("--bind") + 3
    ]
    assert str(Path.home()) not in command
    networked = backend.wrap_allowing_network(
        ["/usr/bin/forge", "build"],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    assert "--unshare-net" not in networked


def test_bubblewrap_never_claims_local_fork_capability(
    candidate_factory,
    tmp_path: Path,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    runner = ForkReproductionRunner(
        ReproductionConfig(targets={"Vault": "0x2000000000000000000000000000000000000002"}),
        SmartContractsConfig(),
        backend=BubblewrapBackend(executable="/usr/bin/bwrap"),
    )
    result = runner.run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert runner.isolation_available is False
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert "cannot reach a host loopback fork RPC" in " ".join(result.limitations)


@pytest.mark.parametrize(
    ("configured", "system", "executable_name", "backend_type"),
    [
        (
            "sandbox-exec",
            "Darwin",
            "sandbox-exec",
            MacOSSandboxBackend,
        ),
        (
            "bubblewrap",
            "Linux",
            "bwrap",
            BubblewrapBackend,
        ),
    ],
)
def test_builtin_isolation_is_real_only_after_discovery_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured: str,
    system: str,
    executable_name: str,
    backend_type: type[MacOSSandboxBackend] | type[BubblewrapBackend],
) -> None:
    executable = tmp_path / executable_name
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    monkeypatch.setattr("mmaudit.solidity.reproduction.platform.system", lambda: system)
    monkeypatch.setattr(
        "mmaudit.solidity.reproduction.shutil.which",
        lambda name: str(executable) if name == executable_name else None,
    )
    monkeypatch.setattr(
        "mmaudit.isolation.provenance._run_builtin_preflight",
        lambda _backend: _IsolationProbeResults(
            benign_execution=True,
            workspace_write_allowed=True,
            network_denied=True,
            host_home_read_denied=True,
            secret_environment_denied=True,
            outside_write_denied=True,
        ),
    )

    direct = backend_type(executable=str(executable))
    discovered = default_isolation_backend(configured)

    assert isolation_execution_evidence(direct) is ExecutionEvidenceKind.UNVERIFIED
    assert discovered is not None
    assert type(discovered) is backend_type
    assert isolation_execution_evidence(discovered) is ExecutionEvidenceKind.REAL


def test_model_cannot_inject_shell_or_source_text() -> None:
    payload = _spec().model_dump(mode="json")
    payload["attack_calls"][0]["function_signature"] = "withdraw(uint256); system('curl attacker')"
    with pytest.raises(ValidationError):
        GeneratedFoundryTestSpec.model_validate(payload)
    payload = _spec().model_dump(mode="json")
    payload["command"] = ["sh", "-c", "curl attacker"]
    with pytest.raises(ValidationError):
        GeneratedFoundryTestSpec.model_validate(payload)


@pytest.mark.parametrize("field", ["cheatcode", "storage_writes", "source"])
def test_attack_phase_rejects_untyped_cheatcode_or_state_mutation_fields(field: str) -> None:
    payload = _spec().model_dump(mode="json")
    payload["attack_calls"][0][field] = "vm.store"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GeneratedFoundryTestSpec.model_validate(payload)


def test_legacy_undifferentiated_calls_are_rejected() -> None:
    payload = _spec().model_dump(mode="json")
    payload["calls"] = payload.pop("attack_calls")
    with pytest.raises(ValidationError):
        GeneratedFoundryTestSpec.model_validate(payload)


def test_assertions_cannot_turn_setup_effects_into_reproduction_evidence() -> None:
    payload = _spec().model_dump(mode="json")
    payload["actors"].append(
        {
            "name": "administrator",
            "address": "0x1000000000000000000000000000000000000002",
            "initial_native_balance_wei": 0,
        }
    )
    payload["setup_calls"] = [
        {
            "step_id": "prepare",
            "actor": "administrator",
            "target": "Vault",
            "function_signature": "prepare()",
            "arguments": [],
            "value_wei": 0,
        }
    ]
    payload["assertions"][0]["step_id"] = "prepare"
    with pytest.raises(ValidationError, match="attacker-reachable"):
        GeneratedFoundryTestSpec.model_validate(payload)


def test_foundry_cheatcode_address_cannot_be_a_phase_target() -> None:
    payload = _spec().model_dump(mode="json")
    payload["attack_calls"][0].update(
        {
            "target": "Cheatcodes",
            "function_signature": "store(address,bytes32,bytes32)",
            "arguments": [
                {
                    "kind": "address",
                    "value": "0x2000000000000000000000000000000000000002",
                },
                {"kind": "bytes32", "value": "0x" + "00" * 32},
                {"kind": "bytes32", "value": "0x" + "00" * 32},
            ],
        }
    )
    specification = GeneratedFoundryTestSpec.model_validate(payload)
    with pytest.raises(ValueError, match="cheatcode"):
        translate_foundry_test(
            specification,
            targets={"Cheatcodes": "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"},
            expected_chain_id=1,
        )


def test_reproduction_requires_an_explicit_attacker_policy() -> None:
    payload = _spec().model_dump(mode="json")
    payload.pop("attacker_policy")
    with pytest.raises(ValidationError, match="attacker_policy"):
        GeneratedFoundryTestSpec.model_validate(payload)


def test_policy_rejects_undeclared_actor_capital_and_call_capability() -> None:
    payload = _spec().model_dump(mode="json")
    payload["attacker_policy"]["attacker_controlled_actors"] = ["other"]
    with pytest.raises(ValidationError, match="undeclared actors"):
        GeneratedFoundryTestSpec.model_validate(payload)

    payload = _spec().model_dump(mode="json")
    payload["actors"][0]["initial_native_balance_wei"] = 1
    with pytest.raises(ValidationError, match="starting capital"):
        GeneratedFoundryTestSpec.model_validate(payload)

    payload = _spec().model_dump(mode="json")
    payload["attack_calls"][0]["required_capabilities"] = ["oracle_influence"]
    with pytest.raises(ValidationError, match="undeclared capabilities"):
        GeneratedFoundryTestSpec.model_validate(payload)


def test_active_capability_requires_exact_justification() -> None:
    with pytest.raises(ValidationError, match="lack justification"):
        AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            flash_liquidity_wei=1,
        )
    with pytest.raises(ValidationError, match="inactive capabilities"):
        AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker"],
            capability_justifications={AttackerCapability.FLASH_LIQUIDITY: "Not actually active."},
        )


@pytest.mark.parametrize(
    ("policy_updates", "config_updates", "expected"),
    [
        (
            {
                "flash_liquidity_wei": 1,
                "capability_justifications": {
                    AttackerCapability.FLASH_LIQUIDITY: "Bounded synthetic liquidity."
                },
            },
            {},
            "flash liquidity",
        ),
        (
            {
                "attacker_controlled_contracts": [
                    "HarnessOne",
                    "HarnessTwo",
                    "HarnessThree",
                    "HarnessFour",
                    "HarnessFive",
                ],
            },
            {},
            "contract count",
        ),
        (
            {
                "token_approval_targets": ["Vault"],
                "capability_justifications": {
                    AttackerCapability.TOKEN_APPROVAL: "Existing bounded approval."
                },
            },
            {},
            "token approval",
        ),
        (
            {
                "max_time_shift_seconds": 1,
                "capability_justifications": {
                    AttackerCapability.TIMING: "One second of declared passage."
                },
            },
            {},
            "time shift",
        ),
        (
            {
                "transaction_ordering": TransactionOrderingCapability.SAME_BLOCK,
                "capability_justifications": {
                    AttackerCapability.TRANSACTION_ORDERING: "Declared same-block ordering."
                },
            },
            {},
            "transaction-ordering",
        ),
        (
            {
                "oracle_influence": OracleInfluenceCapability.BOUNDED_MARKET,
                "capability_justifications": {
                    AttackerCapability.ORACLE_INFLUENCE: "Bounded synthetic market movement."
                },
            },
            {},
            "oracle influence",
        ),
        (
            {
                "governance_rights": True,
                "capability_justifications": {
                    AttackerCapability.GOVERNANCE_RIGHTS: "Candidate declares voting rights."
                },
            },
            {},
            "governance rights",
        ),
        (
            {
                "privileged_roles": ["Guardian"],
                "capability_justifications": {
                    AttackerCapability.PRIVILEGED_ROLE: "Candidate declares Guardian."
                },
            },
            {},
            "privileged roles",
        ),
        (
            {
                "cross_chain_messages": CrossChainMessageCapability.VALID_MESSAGE,
                "capability_justifications": {
                    AttackerCapability.CROSS_CHAIN_MESSAGE: "Valid synthetic message."
                },
            },
            {},
            "cross-chain",
        ),
    ],
)
def test_operator_limits_reject_unapproved_capabilities(
    policy_updates: dict[str, object],
    config_updates: dict[str, object],
    expected: str,
) -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        **policy_updates,
    )
    specification = _spec().model_copy(update={"attacker_policy": policy})
    error = capability_policy_error(
        specification,
        ReproductionConfig(**config_updates),
    )
    assert error is not None
    assert expected in error


def test_operator_limits_attacker_controlled_actor_count() -> None:
    specification = GeneratedFoundryTestSpec(
        candidate_id="candidate-solidity",
        name="TwoActorSequence",
        test_type=ForkTestType.TRANSACTION_SEQUENCE,
        rationale="Two declared actors exercise a bounded sequence.",
        actors=[
            ForkActor(
                name="attacker",
                address="0x1000000000000000000000000000000000000001",
            ),
            ForkActor(
                name="assistant",
                address="0x1000000000000000000000000000000000000002",
            ),
        ],
        attacker_policy=AttackerCapabilityPolicy(
            attacker_controlled_actors=["attacker", "assistant"],
        ),
        attack_calls=[
            ForkCallStep(
                step_id="withdraw",
                actor="attacker",
                target="Vault",
                function_signature="withdraw(uint256)",
                arguments=[{"kind": "uint256", "value": "1"}],
            ),
        ],
        assertions=[ForkAssertion(kind="call_succeeds", step_id="withdraw")],
    )
    error = capability_policy_error(
        specification,
        ReproductionConfig(max_attacker_controlled_actors=1),
    )
    assert error is not None
    assert "actor count" in error


def test_operator_can_approve_named_token_target() -> None:
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        token_approval_targets=["Vault"],
        capability_justifications={AttackerCapability.TOKEN_APPROVAL: "Existing bounded approval."},
    )
    specification = _spec().model_copy(update={"attacker_policy": policy})
    assert (
        capability_policy_error(
            specification,
            ReproductionConfig(allowed_token_approval_targets=["Vault"]),
        )
        is None
    )


def test_runner_rejects_capability_before_forge_execution(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    marker = tmp_path / "forge-ran"
    forge = _fake_forge(tmp_path / "forge", f"touch {marker}; exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    policy = AttackerCapabilityPolicy(
        attacker_controlled_actors=["attacker"],
        flash_liquidity_wei=1,
        capability_justifications={
            AttackerCapability.FLASH_LIQUIDITY: "Bounded synthetic liquidity."
        },
    )
    result = _runner(forge).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec().model_copy(update={"attacker_policy": policy}),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.GENERATION_FAILED
    assert "flash liquidity" in " ".join(result.limitations)
    assert not marker.exists()


def test_reproduced_test_is_repeated_and_single_step_is_minimal(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20; contract Vault {}\n",
        encoding="utf-8",
    )
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED
    assert result.attempts == result.successful_attempts == 2
    assert result.command[0] == "[FORGE]"
    assert "127.0.0.1" not in " ".join(result.command)
    assert not (repo / "test").exists()


def test_injected_reproduction_backend_cannot_self_assert_real(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    runner = ForkReproductionRunner(
        ReproductionConfig(
            repetitions=2,
            timeout_seconds=2,
            pinned_block_number=123,
            expected_chain_id=1,
            targets={"Vault": "0x2000000000000000000000000000000000000002"},
        ),
        SmartContractsConfig(),
        backend=SelfAssertedRealIsolationBackend(),
        forge_executable=forge,
    )

    result = runner.run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )

    assert result.state is ReproductionState.REPRODUCED_AND_MINIMIZED
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert not runner.isolation_available


def test_patched_control_does_not_reproduce(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    forge = _fake_forge(tmp_path / "forge", "echo '[FAIL] assertion'; exit 1")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.NOT_REPRODUCED
    assert result.successful_attempts == 0


def test_repository_symlink_escape_is_rejected(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    outside = tmp_path / "outside.sol"
    outside.write_text("secret", encoding="utf-8")
    os.symlink(outside, repo / "src" / "Escape.sol")
    forge = _fake_forge(tmp_path / "forge", "exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(forge).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.GENERATION_FAILED
    assert "symlink" in " ".join(result.limitations)


@pytest.mark.parametrize(
    "unsafe_rpc",
    [
        "https://127.0.0.1:8545",
        "http://rpc.example.test:8545",
        "http://user:password@127.0.0.1:8545",
        "http://127.0.0.1:8545?api_key=secret",
        "http://127.0.0.1",
    ],
)
def test_non_local_or_credentialed_fork_rpc_is_rejected_before_execution(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_rpc: str,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    marker = tmp_path / "forge-ran"
    forge = _fake_forge(tmp_path / "forge", f"touch {marker}; exit 0")
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", unsafe_rpc)
    result = _runner(forge).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is ReproductionState.ENVIRONMENT_BLOCKED
    assert not marker.exists()
    assert result.limitations


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("echo 'ParserError: missing compiler'; exit 1", ReproductionState.COMPILE_FAILED),
        ("sleep 2; exit 0", ReproductionState.ENVIRONMENT_BLOCKED),
    ],
)
def test_compiler_failure_and_timeout_are_limitations(
    candidate_factory,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    body: str,
    expected: ReproductionState,
) -> None:
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
    forge = _fake_forge(tmp_path / "forge", body)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    result = _runner(
        forge,
        timeout=0.1 if expected is ReproductionState.ENVIRONMENT_BLOCKED else 2,
    ).run(
        repository_root=repo,
        project=_project(),
        candidate=candidate_factory(
            candidate_id="candidate-solidity",
            path="src/Vault.sol",
            start_line=1,
            end_line=1,
        ),
        specification=_spec(),
        private_dir=tmp_path / "private",
    )
    assert result.state is expected
    assert result.limitations
