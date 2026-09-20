"""Real offline Foundry compilation through property adapters, not replay qualification."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from mmaudit.config import FormalConfig, ScannerConfig, SmartContractsConfig
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.solidity.formal import EchidnaAdapter, FormalRunner, MedusaAdapter
from mmaudit.solidity.reproduction import MacOSSandboxBackend, default_isolation_backend
from tests.unit.test_echidna import FIXTURE, _inputs


@pytest.mark.parametrize("engine", ["medusa", "echidna"])
@pytest.mark.parametrize("via_ir", [False, True])
def test_native_property_adapter_preserves_pinned_foundry_compilation(
    tmp_path, monkeypatch, config_factory, engine, via_ir
):
    """Assert real compiled artifacts/settings; full native replay is a separate gate."""
    names = [
        f"MMAUDIT_TEST_{engine.upper()}_VERSION",
        "MMAUDIT_TEST_FORGE_VERSION",
        "MMAUDIT_TEST_FORGE_SHA256",
        "MMAUDIT_TEST_SOLC_VERSION",
        "MMAUDIT_TEST_SOLC_SHA256",
        "MMAUDIT_SOLC_EXECUTABLE",
    ]
    selected = {name: os.environ.get(name) for name in names}
    if not all(selected.values()):
        pytest.skip("explicit native property compiler test pins are not configured")
    raw_engine = shutil.which(engine)
    if raw_engine is None or shutil.which("forge") is None:
        pytest.skip("native property engine or Forge is unavailable")
    backend = default_isolation_backend("auto")
    if not isinstance(backend, MacOSSandboxBackend):
        pytest.skip("this local native check requires the available macOS isolation backend")
    original_wrap = MacOSSandboxBackend.wrap

    def offline(self, command, *, workspace, private_dir, rpc_port):
        del rpc_port
        return original_wrap(
            self, command, workspace=workspace, private_dir=private_dir, rpc_port=0
        )

    monkeypatch.setattr(MacOSSandboxBackend, "wrap", offline)
    repository = tmp_path / "repository with spaces"
    shutil.copytree(FIXTURE, repository)
    settings = repository / "foundry.toml"
    settings.write_text(settings.read_text() + f"via_ir = {str(via_ir).lower()}\n")
    original_settings = settings.read_bytes()
    compiler = SmartContractsConfig(
        solc_version=selected["MMAUDIT_TEST_SOLC_VERSION"],
        solc_sha256=selected["MMAUDIT_TEST_SOLC_SHA256"],
    )
    forge = ScannerConfig(
        version=selected["MMAUDIT_TEST_FORGE_VERSION"],
        sha256=selected["MMAUDIT_TEST_FORGE_SHA256"],
    )
    projects, index, suite, corpus = _inputs(repository, config_factory())
    executable = Path(raw_engine).resolve(strict=True)
    adapter_type = MedusaAdapter if engine == "medusa" else EchidnaAdapter
    adapter = adapter_type(compiler_config=compiler, forge_config=forge)
    monkeypatch.setattr(adapter, "available", lambda root: executable)
    config = FormalConfig(
        enabled=True,
        timeout_seconds=30,
        **{
            f"{engine}_version": selected[names[0]],
            f"{engine}_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        },
    )
    private = tmp_path / "native run"
    result = FormalRunner(config, backend=backend, adapters=[adapter]).run(
        repository_root=repository,
        projects=projects,
        index=index,
        invariants=suite,
        property_corpus=corpus,
        private_dir=private,
    )[0]
    assert [(item.name, item.executable_sha256) for item in result.dependencies] == [
        ("forge", forge.sha256),
        ("solc", compiler.solc_sha256),
    ], result.failure_reason
    workspace = private / engine / "workspace"
    artifacts = sorted((workspace / "out" / "build-info").glob("*.json"))
    assert artifacts, result.failure_reason
    documents = [json.loads(path.read_text()) for path in artifacts]
    generated = f"mmaudit-{engine}/MMAudit{engine.title()}.sol"
    compiled = [doc for doc in documents if generated in doc["output"]["contracts"]]
    assert len(compiled) == 1
    document = compiled[0]
    assert document["solcVersion"] == compiler.solc_version
    assert document["input"]["settings"]["optimizer"] == {"enabled": True, "runs": 200}
    assert document["input"]["settings"]["viaIR"] is via_ir
    contract = document["output"]["contracts"][generated][f"MMAudit{engine.title()}Properties"]
    assert contract["evm"]["bytecode"]["object"]
    assert (
        document["input"]["sources"]["src/Counter.sol"]["content"]
        == (repository / "src" / "Counter.sol").read_text()
    )
    assert (workspace / "foundry.toml").read_bytes() == original_settings == settings.read_bytes()
    assert not (repository / "out").exists() and not (repository / "cache").exists()
    assert "(allow network" not in (private / engine / "sandbox.sb").read_text()
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
