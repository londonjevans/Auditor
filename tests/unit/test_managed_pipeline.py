"""Prepared pipeline composition with inert files and no external execution."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.repository.discovery import RepositorySafetyError
from mmaudit.scanners.fork_matrix import RepositoryForkMatrixRunner
from mmaudit.scanners.runner import ScannerRunner
from mmaudit.solidity.formal import FormalRunner
from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
from mmaudit.solidity.reproduction import ForkReproductionRunner
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_toolchain_support import synthetic_pinned_members


class _Backend:
    name = "unverified-prepared-pipeline-control"
    supports_local_fork_rpc = False

    def wrap(self, *args, **kwargs):
        pytest.fail("invariant: inert composition must never launch a tool")


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: prepared composition cannot discover or execute ambient tools")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    config = config_factory(
        scanners={"semgrep": {"enabled": True, "required": True}},
        smart_contracts={"compile": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        invariants={"enabled": False},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    return repository, material, tmp_path / "audit-output"


def _pipeline(prepared, **kwargs):
    repository, material, output = prepared
    return AuditPipeline(
        kwargs.pop("config", material.config),
        repo=kwargs.pop("repo", repository),
        output=kwargs.pop("output", output),
        host_tools=kwargs.pop("host_tools", material),
        managed_backend=kwargs.pop("managed_backend", _Backend()),
        **kwargs,
    )


def test_fixed_consumers_share_prepared_backend_even_when_reproduction_is_disabled(prepared):
    pipeline = _pipeline(prepared)
    assert not pipeline.config.reproduction.enabled
    for runner, kind in (
        (pipeline.scanner_runner, ScannerRunner),
        (pipeline.reproduction_runner, ForkReproductionRunner),
        (pipeline.invariant_runner, FoundryInvariantRunner),
        (pipeline.formal_runner, FormalRunner),
        (pipeline.repository_fork_matrix_runner, RepositoryForkMatrixRunner),
    ):
        assert type(runner) is kind
        assert runner.backend is pipeline.reproduction_runner.backend
    assert pipeline.scanner_runner._managed_host_tools is prepared[1]
    assert pipeline.reproduction_runner._managed.material is prepared[1]
    assert pipeline.invariant_runner._managed.material is prepared[1]
    assert pipeline.formal_runner._managed.material is prepared[1]
    pipeline._verify_managed_tools()
    assert not prepared[2].exists()
    assert prepared[1].runtime_authority is prepared[1].managed_run_ready is False


def test_omitted_backend_is_built_exactly_once_without_reproduction_dependency(
    prepared, monkeypatch
):
    calls = []
    backend = _Backend()

    def factory(material):
        assert material is prepared[1]
        calls.append(material)
        return backend

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    pipeline = _pipeline(prepared, managed_backend=None)
    assert calls == [prepared[1]]
    assert pipeline.scanner_runner.backend is pipeline.formal_runner.backend is backend


def test_failed_backend_factory_has_no_ambient_fallback(prepared, monkeypatch):
    def factory(material):
        raise managed_isolation.ManagedIsolationError("synthetic unavailable managed isolation")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    with pytest.raises(ValueError, match="unavailable managed isolation"):
        _pipeline(prepared, managed_backend=None)
    assert not prepared[2].exists()


@pytest.mark.parametrize(
    "name",
    [
        "scanner_runner",
        "reproduction_runner",
        "invariant_runner",
        "formal_runner",
        "repository_fork_matrix_runner",
    ],
)
def test_managed_mode_refuses_mixed_custom_consumers_before_backend(prepared, monkeypatch, name):
    def factory(material):
        pytest.fail("invariant: mixed managed consumers refuse before isolation preflight")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    with pytest.raises(ValueError, match=r"managed.*consumer"):
        _pipeline(prepared, managed_backend=None, **{name: object()})
    assert not prepared[2].exists()


@pytest.mark.parametrize("bad", [object(), {}, "not-material"])
@pytest.mark.parametrize("field", ["config", "host_tools"])
def test_managed_mode_requires_exact_types(prepared, field, bad):
    with pytest.raises(ValueError, match=r"managed.*exact"):
        _pipeline(prepared, **{field: bad})


def test_managed_backend_without_material_is_not_a_legacy_override(prepared):
    with pytest.raises(ValueError, match=r"managed.*material"):
        _pipeline(prepared, host_tools=None)


def test_config_mismatch_is_rejected_without_changing_the_input(prepared):
    config = prepared[1].config
    config.reporting.markdown = not config.reporting.markdown
    original = config.model_dump_json()
    with pytest.raises(ValueError, match=r"managed.*config"):
        _pipeline(prepared, config=config)
    assert config.model_dump_json() == original


@pytest.mark.parametrize("root", ["repo", "output"])
@pytest.mark.parametrize("relation", ["equal", "parent", "child"])
def test_material_cannot_overlap_pipeline_roots(prepared, root, relation):
    directory = prepared[1].directory
    path = {
        "equal": directory,
        "parent": directory.parent,
        "child": directory / "scanner-private",
    }[relation]
    with pytest.raises(
        (OSError, ValueError, RepositorySafetyError),
        match=r"managed|material|directory|inaccessible",
    ):
        _pipeline(prepared, **{root: path})
    assert not prepared[2].exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["bytes", "replacement", "missing"])
async def test_retained_tool_identity_refuses_run_before_output(prepared, mutation):
    pipeline = _pipeline(prepared, api_key="synthetic-cleanup-canary")
    path = prepared[1].directory / prepared[1].manifest.files[0].locator
    if mutation == "replacement":
        replacement = path.with_suffix(".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o500)
        replacement.replace(path)
    elif mutation == "missing":
        path.unlink()
    else:
        path.chmod(0o600)
        path.write_bytes(b"Changed synthetic inert control; must never execute.\n")
        path.chmod(0o500)
    with pytest.raises(ValueError, match=r"managed|material"):
        await pipeline.run(scanner_only=True)
    assert pipeline.api_key == ""
    assert not prepared[2].exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "config",
        "repo",
        "output",
        "consumer",
        "backend",
        "scanner_config",
        "formal_config",
        "matrix_consumer",
        "matrix_backend",
        "matrix_config",
        "matrix_dependencies",
    ],
)
async def test_managed_selection_drift_refuses_before_output(prepared, tmp_path, mutation):
    pipeline = _pipeline(prepared, api_key="synthetic-cleanup-canary")
    if mutation == "config":
        pipeline.config.reporting.markdown = not pipeline.config.reporting.markdown
    elif mutation in {"repo", "output"}:
        setattr(pipeline, "repo_input" if mutation == "repo" else mutation, tmp_path)
    elif mutation == "consumer":
        pipeline.scanner_runner = object()
    elif mutation == "backend":
        pipeline.formal_runner.backend = _Backend()
    elif mutation == "scanner_config":
        pipeline.scanner_runner.config.execution.concurrency += 1
    elif mutation == "matrix_consumer":
        pipeline.repository_fork_matrix_runner = object()
    elif mutation == "matrix_backend":
        pipeline.repository_fork_matrix_runner.backend = _Backend()
    elif mutation == "matrix_config":
        pipeline.repository_fork_matrix_runner.reproduction.expected_chain_id = 31338
    elif mutation == "matrix_dependencies":
        pipeline.repository_fork_matrix_runner.dependencies = object()
    else:
        pipeline.formal_runner.config.enabled = True
    with pytest.raises(ValueError, match="managed"):
        await pipeline.run(scanner_only=True)
    assert pipeline.api_key == ""
    assert not prepared[2].exists()


@pytest.mark.asyncio
async def test_result_boundary_revalidates_and_still_clears_credentials(prepared, monkeypatch):
    pipeline = _pipeline(prepared, api_key="synthetic-cleanup-canary")

    async def changed_result(**kwargs):
        pipeline.scanner_runner.backend = _Backend()
        return object()

    monkeypatch.setattr(pipeline, "_run_with_provider", changed_result)
    with pytest.raises(ValueError, match="managed"):
        await pipeline.run(scanner_only=True)
    assert pipeline.api_key == ""
    assert not prepared[2].exists()


@pytest.mark.asyncio
async def test_prepared_tools_do_not_supply_missing_provider_authority(prepared):
    pipeline = _pipeline(prepared, api_key="synthetic-cleanup-canary")
    with pytest.raises(ValueError, match="exact model-selection evidence and live authority"):
        await pipeline.run(allow_code_egress=True)
    assert pipeline.api_key == ""
    assert pipeline.client is None
    assert not prepared[2].exists()


@pytest.mark.asyncio
async def test_log_close_failure_cannot_prevent_credential_cleanup(prepared, monkeypatch):
    pipeline = _pipeline(prepared, api_key="synthetic-cleanup-canary")

    class FailingClose:
        def close(self):
            raise OSError("synthetic log close failure")

    async def result(**kwargs):
        pipeline._run_log_handler = FailingClose()
        return object()

    monkeypatch.setattr(pipeline, "_run_with_provider", result)
    with pytest.raises(OSError, match="synthetic log close failure"):
        await pipeline.run(scanner_only=True)
    assert pipeline.api_key == ""
    assert pipeline._run_log_handler is None


def test_material_identity_is_retained_before_backend_construction(prepared, monkeypatch):
    def factory(material):
        path = material.directory / material.manifest.files[0].locator
        replacement = path.with_suffix(".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o500)
        replacement.replace(path)
        return _Backend()

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    with pytest.raises(ValueError, match="managed pipeline tool identity changed"):
        _pipeline(prepared, managed_backend=None)
    assert not prepared[2].exists()


def test_matrix_without_prepared_foundry_is_refused_before_any_backend_or_endpoint(
    tmp_path, config_factory, monkeypatch
):
    inert = (Path(__file__).parents[1] / "fixtures/scanners/identity-inert.txt").read_bytes()
    anvil_digest = hashlib.sha256(inert + b"Synthetic role: anvil\n").hexdigest()
    anvil = next(m for m in synthetic_pinned_members() if m.role is ManagedToolchainRole.ANVIL)
    config = config_factory(
        reproduction={"isolation_backend": "bubblewrap"},
        smart_contracts={
            "repository_suite": {
                "fork_matrix_states": [
                    {
                        "state_id": "clean-local",
                        "kind": "clean_local",
                        "expected_chain_id": 31337,
                        "anvil_version": f"anvil Version: {anvil.version}",
                        "anvil_sha256": anvil_digest,
                        "hardfork": "cancun",
                        "genesis_timestamp": 1,
                        "startup_timeout_seconds": 1,
                        "shutdown_timeout_seconds": 1,
                    },
                    {
                        "state_id": "synthetic-offline",
                        "kind": "pinned_fork",
                        "rpc_url_env": "MMAUDIT_SYNTHETIC_PIPELINE_RPC",
                        "expected_chain_id": 31337,
                        "pinned_block_number": 7,
                        "state_source_sha256": "b" * 64,
                    },
                ]
            }
        },
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            member.model_copy(update={"version": f"anvil Version: {anvil.version}"})
            if member.role is ManagedToolchainRole.ANVIL
            else member
            for member in bundle.members
        ),
        target_platform=bundle.target_platform,
    )
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )

    def forbidden(material):
        pytest.fail("invariant: unsupported fork matrix refuses before backend preflight")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="requires prepared Foundry, Solc and Anvil roles"):
        _pipeline((repository, material, tmp_path / "audit-output"), managed_backend=None)
    assert not (tmp_path / "audit-output").exists()
