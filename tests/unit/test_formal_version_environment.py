"""Version-only startup restrictions must not alter formal campaigns or trust."""

from __future__ import annotations

import hashlib

import pytest

from mmaudit.config import FormalConfig
from mmaudit.scanners import base
from mmaudit.scanners.diagnostics import ExecutableVersionProbe, ExecutableVersionProbeStatus
from mmaudit.solidity import formal
from tests.unit.test_formal_property_compiler import compiler_case as compiler_case


@pytest.mark.parametrize("ambient_runtime", [None, "-N64 -M64g"])
def test_only_echidna_version_startup_gets_fixed_restrictive_runtime(ambient_runtime):
    environment = {"PATH": "/inert/tools", "FOUNDRY_OFFLINE": "true"}
    if ambient_runtime is not None:
        environment["GHCRTS"] = ambient_runtime
    before = dict(environment)
    runner = formal.FormalRunner(FormalConfig(), backend=object())
    for adapter in runner.adapters:
        selected = adapter.version_environment(environment)
        assert selected == (
            {**before, "GHCRTS": "-N1 -M512m"} if adapter.name == "echidna" else before
        )
        assert environment == before
    assert base._VERSION_PROBE_MEMORY_BYTES == 1024**3
    assert formal._FORMAL_MEMORY_BYTES == 4 * 1024**3


@pytest.mark.parametrize("preflight", [False, True])
def test_version_restriction_does_not_leak_to_compiler_probes_or_campaign(
    compiler_case, tmp_path, monkeypatch, preflight
):
    adapter, repository, index, corpus, *_ = compiler_case
    adapter.requires_preflight_trust = preflight
    engine = tmp_path / "inert-engine"
    engine.write_bytes(b"Inert local engine; no execution.\n")
    engine.chmod(0o500)
    monkeypatch.setattr(adapter, "available", lambda root: engine)
    probes, campaigns = [], []

    def version(executable, **kwargs):
        expected = "-N1 -M512m" if executable == engine and adapter.name == "echidna" else None
        assert kwargs["environment"].get("GHCRTS") == expected
        probes.append(executable.name)
        return "0.8.30" if executable.name == "solc" else "1.5.1"

    def process(command, **kwargs):
        assert "GHCRTS" not in kwargs["environment"]
        campaigns.append(command)
        kwargs["stdout_path"].write_text("")
        kwargs["stderr_path"].write_text("")
        return 0

    class Backend:
        name = "inert-version-scope"

        def wrap(self, command, **kwargs):
            return command

    monkeypatch.setattr(formal, "_isolated_tool_version", version)
    monkeypatch.setattr(formal, "_bounded_process", process)
    result = formal.FormalRunner(
        FormalConfig(
            enabled=True,
            **{
                f"{adapter.name}_version": "1.5.1",
                f"{adapter.name}_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
            },
        ),
        adapters=[adapter],
        backend=Backend(),
    ).run(
        repository_root=repository,
        projects=index.projects,
        index=index,
        invariants=formal.InvariantSuite(),
        property_corpus=corpus,
        private_dir=tmp_path / "run",
    )[0]
    assert probes == (
        ["inert-engine", "forge", "solc"] if preflight else ["forge", "solc", "inert-engine"]
    )
    assert len(campaigns) == 1 and result.status is formal.FormalToolStatus.SUCCESS
    assert result.execution_evidence is formal.ExecutionEvidenceKind.UNVERIFIED
    assert not result.machine_output_validated and not result.evidence


@pytest.mark.parametrize(
    "status",
    [
        value
        for value in ExecutableVersionProbeStatus
        if value is not ExecutableVersionProbeStatus.SUCCESS
    ],
)
def test_restricted_startup_does_not_turn_failed_probe_into_admission(
    compiler_case, tmp_path, monkeypatch, status
):
    adapter, repository, index, corpus, *_ = compiler_case
    engine = tmp_path / "inert-engine"
    engine.write_bytes(b"Inert local engine; no execution.\n")
    engine.chmod(0o500)
    monkeypatch.setattr(adapter, "available", lambda root: engine)
    probes = []

    def probe(executable, environment, *args, **kwargs):
        assert executable == engine
        expected = "-N1 -M512m" if adapter.name == "echidna" else None
        assert environment.get("GHCRTS") == expected
        probes.append(status)
        # Even version-shaped text in a failed observation cannot be admitted.
        return ExecutableVersionProbe(status, "1.5.1", "synthetic rejected probe", -9)

    def forbidden(*args, **kwargs):
        pytest.fail("failed version probes must not reach a campaign")

    monkeypatch.setattr(formal, "isolated_executable_version_probe", probe)
    monkeypatch.setattr(formal, "_bounded_process", forbidden)
    result = formal.FormalRunner(
        FormalConfig(
            enabled=True,
            **{
                f"{adapter.name}_version": "1.5.1",
                f"{adapter.name}_sha256": hashlib.sha256(engine.read_bytes()).hexdigest(),
            },
        ),
        adapters=[adapter],
        backend=object(),
    ).run(
        repository_root=repository,
        projects=index.projects,
        index=index,
        invariants=formal.InvariantSuite(),
        property_corpus=corpus,
        private_dir=tmp_path / "run",
    )[0]
    assert probes == [status]
    assert result.status is formal.FormalToolStatus.INCONCLUSIVE
    assert result.version is None and not result.dependencies and not result.evidence
