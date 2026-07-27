from __future__ import annotations

import os
from pathlib import Path

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import (
    FormalResultKind,
    FormalToolStatus,
    InvariantSuite,
    SolidityEntity,
    SolidityEntityKind,
    SolidityProjectMetadata,
    SolidityProjectType,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.solidity.formal import (
    EchidnaAdapter,
    FormalAdapter,
    FormalRunner,
    MedusaAdapter,
    SolcSMTCheckerAdapter,
)


class PassthroughIsolation:
    name = "test-isolation"

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


class FixedAdapter(FormalAdapter):
    name = "solc-smtchecker"
    executable = "fixed-formal"

    def applicable(
        self,
        index: SoliditySymbolIndex,
        invariants: InvariantSuite,
    ) -> tuple[bool, str]:
        del index, invariants
        return True, ""

    def build_command(
        self,
        executable: Path,
        workspace: Path,
        output_path: Path,
        index: SoliditySymbolIndex,
        config: FormalConfig,
    ) -> list[str]:
        del workspace, output_path, index, config
        return [str(executable), "run"]

    def parse(
        self,
        stdout: str,
        stderr: str,
        index: SoliditySymbolIndex,
    ) -> list:
        del stdout, stderr, index
        return []


def _index() -> SoliditySymbolIndex:
    project = _project()
    return SoliditySymbolIndex(
        projects=[project],
        entities=[
            SolidityEntity(
                id="function:Vault:withdraw",
                kind=SolidityEntityKind.FUNCTION,
                name="withdraw",
                contract_name="Vault",
                path="src/Vault.sol",
                start_line=4,
                end_line=8,
                byte_start=0,
                byte_end=1,
                source_hash="a" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic_test_entity",
                visibility="external",
            )
        ],
        ast_sources=["src/Vault.sol"],
    )


def _property_index() -> SoliditySymbolIndex:
    project = _project()
    return SoliditySymbolIndex(
        projects=[project],
        entities=[
            SolidityEntity(
                id="function:Vault:echidna_assets_backed",
                kind=SolidityEntityKind.FUNCTION,
                name="echidna_assets_backed",
                contract_name="Vault",
                path="src/VaultProperties.sol",
                start_line=12,
                end_line=16,
                byte_start=0,
                byte_end=1,
                source_hash="b" * 64,
                provenance=SolidityProvenance.COMPILER,
                confidence=1,
                transformation="synthetic_test_entity",
                visibility="public",
            )
        ],
        ast_sources=["src/VaultProperties.sol"],
    )


def _project() -> SolidityProjectMetadata:
    return SolidityProjectMetadata(
        project_type=SolidityProjectType.FOUNDRY,
        project_root=".",
        source_directories=["src"],
    )


def _repository(path: Path) -> Path:
    root = path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\ncontract Vault {\nuint x;\n"
        "function withdraw() external {\nassert(x == 0);\n}\n}\n",
        encoding="utf-8",
    )
    return root


def test_unavailable_formal_tool_is_not_a_vulnerability(tmp_path: Path) -> None:
    adapter = FixedAdapter()
    runner = FormalRunner(
        FormalConfig(enabled=True),
        backend=PassthroughIsolation(),
        adapters=[adapter],
    )
    root = _repository(tmp_path)
    runs = runner.run(
        repository_root=root,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=tmp_path / "private",
    )
    assert runs[0].status is FormalToolStatus.UNAVAILABLE
    assert runs[0].evidence == []
    assert "unavailable outside" in (runs[0].failure_reason or "")


def test_smt_counterexample_is_normalized_to_hashed_source_location() -> None:
    evidence = SolcSMTCheckerAdapter().parse(
        "",
        "Warning: CHC: Assertion violation happens here.\n"
        "Counterexample:\nsrc/Vault.sol:5: value = 1",
        _index(),
    )
    assert len(evidence) == 1
    assert evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence[0].locations[0].path == "src/Vault.sol"
    assert evidence[0].locations[0].content_hash == "a" * 64


def test_echidna_json_counterexample_is_normalized_to_property_location() -> None:
    evidence = EchidnaAdapter().parse(
        "bounded campaign diagnostics\n",
        '{"tests":[{"name":"echidna_assets_backed","status":"falsified",'
        '"callseq":[{"function":"withdraw()"}],"seed":7}]}',
        _property_index(),
    )
    assert len(evidence) == 1
    assert evidence[0].tool == "echidna"
    assert evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence[0].property_id == "echidna_assets_backed"
    assert evidence[0].locations[0].path == "src/VaultProperties.sol"
    assert evidence[0].locations[0].content_hash == "b" * 64
    assert evidence[0].counterexample["sequence"] == [{"function": "withdraw()"}]
    assert evidence[0].counterexample["seed"] == 7


def test_medusa_json_counterexample_is_normalized_to_property_location() -> None:
    evidence = MedusaAdapter().parse(
        '{"campaign":{"testCases":[{"property":"echidna_assets_backed",'
        '"result":"property_test_failed","sequence":["deposit"]}]}}',
        "",
        _property_index(),
    )
    assert len(evidence) == 1
    assert evidence[0].tool == "medusa"
    assert evidence[0].result_kind is FormalResultKind.COUNTEREXAMPLE
    assert evidence[0].property_id == "echidna_assets_backed"
    assert evidence[0].locations[0].path == "src/VaultProperties.sol"


def test_timeout_is_inconclusive_and_preserves_no_safety_claim(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    executable = tmp_path / "fixed-formal"
    executable.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "fixed 1.0"; exit 0; fi\nsleep 2\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    adapter = FixedAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(enabled=True, timeout_seconds=0.05),
        backend=PassthroughIsolation(),
        adapters=[adapter],
    )
    runs = runner.run(
        repository_root=root,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=tmp_path / "private",
    )
    assert runs[0].status is FormalToolStatus.TIMED_OUT
    assert runs[0].evidence == []
    assert "wall-clock" in (runs[0].failure_reason or "")


def test_repository_local_formal_binary_is_rejected(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = _repository(tmp_path)
    binary_dir = root / "bin"
    binary_dir.mkdir()
    binary = binary_dir / "fixed-formal"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    monkeypatch.setenv("PATH", f"{binary_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    assert FixedAdapter().available(root) is None


def test_formal_runner_does_not_copy_secret_files_to_workspace(tmp_path: Path) -> None:
    root = _repository(tmp_path)
    (root / ".env").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "wallet.pem").write_text("synthetic pem\n", encoding="utf-8")
    (root / "signing.key").write_text("synthetic key\n", encoding="utf-8")
    (root / "id_rsa").write_text("synthetic ssh key\n", encoding="utf-8")
    (root / "mnemonic.txt").write_text("synthetic seed phrase\n", encoding="utf-8")
    (root / "wallet.json").write_text("synthetic wallet\n", encoding="utf-8")
    (root / ".ENV.PROD").write_text("PRIVATE_KEY=synthetic\n", encoding="utf-8")
    (root / "WALLET.PEM").write_text("synthetic pem\n", encoding="utf-8")
    (root / "ID_ED25519").write_text("synthetic ssh key\n", encoding="utf-8")
    executable = tmp_path / "fixed-formal"
    executable.write_text(
        '#!/bin/sh\nif [ "$1" = "--version" ]; then echo "fixed 1.0"; exit 0; fi\n'
        'test ! -e ".env"\n'
        'test ! -e "wallet.pem"\n'
        'test ! -e "signing.key"\n'
        'test ! -e "id_rsa"\n'
        'test ! -e "mnemonic.txt"\n'
        'test ! -e "wallet.json"\n'
        'test ! -e ".ENV.PROD"\n'
        'test ! -e "WALLET.PEM"\n'
        'test ! -e "ID_ED25519"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    adapter = FixedAdapter()
    adapter.available = lambda repository_root: executable  # type: ignore[method-assign]
    runner = FormalRunner(
        FormalConfig(enabled=True),
        backend=PassthroughIsolation(),
        adapters=[adapter],
    )
    runs = runner.run(
        repository_root=root,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=tmp_path / "private",
    )
    assert runs[0].status is FormalToolStatus.SUCCESS
    assert runs[0].isolation_backend == "test-isolation"
