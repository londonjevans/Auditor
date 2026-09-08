"""Prepared matrix composition with inert files: no engine, RPC or execution credit."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from datetime import UTC, datetime

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, RepositoryDifferentialRunStatus
from mmaudit.orchestration import managed_fork_matrix
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.orchestration.pipeline import AuditPipeline
from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
from mmaudit.scanners.fork_matrix import (
    ForkMatrixDependencies,
    RepositoryForkMatrixRunner,
    _unavailable_run,
)
from mmaudit.scanners.foundry import FoundryForkScanner
from tests.unit.test_managed_clean_chain import _prepared


class _Backend:
    name = "unverified-prepared-matrix-control"
    supports_local_fork_rpc = False

    def wrap(self, *args, **kwargs):
        pytest.fail("invariant: inert matrix composition cannot execute tools")


def prepared_matrix(tmp_path, config_factory, *, enabled=True):
    def matrix_config(**kwargs):
        kwargs["language_profile"] = "solidity-evm"
        kwargs["scanners"] = {"foundry_fork": {"enabled": True, "required": True}}
        kwargs["smart_contracts"].update(framework="foundry", allow_fork_probing=True)
        return config_factory(**kwargs)

    return _prepared(tmp_path, matrix_config, select_anvil=enabled)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_matrix(tmp_path, config_factory)


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: managed matrix cannot discover ambient tools or execute/connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


def _runner(prepared, **kwargs):
    config = prepared[1].config
    return RepositoryForkMatrixRunner(
        kwargs.pop("smart_contracts", config.smart_contracts),
        kwargs.pop("reproduction", config.reproduction),
        host_tools=kwargs.pop("host_tools", prepared[1]),
        managed_backend=kwargs.pop("managed_backend", _Backend()),
        **kwargs,
    )


def _run(runner, prepared, **kwargs):
    return runner.run(
        prepared[0],
        prepared[2],
        projects=(),
        repository_sha256="a" * 64,
        repository_exclusion_root=prepared[2],
        backend=kwargs.pop("backend", runner.backend),
        baseline_run=_unavailable_run("synthetic missing baseline", now=lambda: datetime.now(UTC)),
        absolute_deadline=time.monotonic() + 10,
        **kwargs,
    )


def test_fixed_matrix_composes_prepared_scanner_and_clean_launcher(prepared):
    runner = _runner(prepared)
    assert type(runner.dependencies.clean_state_provider) is TrustedCleanAnvilLauncher
    assert runner.dependencies.environment is None
    assert runner.dependencies.clean_state_provider._managed.material is prepared[1]
    runner.verify_managed_selection()
    assert not list(prepared[2].iterdir())
    assert prepared[1].runtime_authority is prepared[1].managed_run_ready is False


@pytest.mark.parametrize("index", [0, 1])
def test_factory_uses_pinned_forge_solc_and_detached_declared_state_configs(prepared, index):
    runner = _runner(prepared)
    config = prepared[1].config
    state = config.smart_contracts.repository_suite.fork_matrix_states[index]
    smart = config.smart_contracts.model_copy(
        update={
            "fork_rpc_url_env": getattr(
                state, "rpc_url_env", config.smart_contracts.fork_rpc_url_env
            )
        }
    )
    reproduction = config.reproduction.model_copy(
        update={
            "expected_chain_id": state.expected_chain_id,
            "pinned_block_number": getattr(state, "pinned_block_number", 0),
        }
    )

    class Bridge:
        endpoint = "http://127.0.0.1:18545"

    scanner = runner.dependencies.scanner_factory(
        smart,
        reproduction=reproduction,
        projects=(),
        allow_fork_probing=True,
        expected_repository_sha256="a" * 64,
        repository_exclusion_root=prepared[2],
        fork_rpc_url_override=Bridge.endpoint,
        fork_rpc_scope_recorder=Bridge(),
        attempt_binding_sha256="c" * 64,
    )
    assert type(scanner) is FoundryForkScanner
    assert scanner.executable == str(prepared[1].executable_for(ManagedToolchainRole.FORGE))
    assert scanner.solc_path == prepared[1].executable_for(ManagedToolchainRole.SOLC)
    assert scanner.config == smart and scanner.config is not smart
    assert scanner.reproduction == reproduction and scanner.reproduction is not reproduction
    smart.foundry_fuzz_runs += 1
    reproduction.expected_chain_id += 1
    assert scanner.config != smart and scanner.reproduction != reproduction


@pytest.mark.parametrize("dependencies", [ForkMatrixDependencies(), object()])
def test_managed_matrix_refuses_custom_dependencies(prepared, dependencies):
    with pytest.raises(ValueError, match=r"managed.*dependencies"):
        _runner(prepared, dependencies=dependencies)


@pytest.mark.parametrize("material", [object(), {}, "synthetic"])
def test_managed_matrix_requires_exact_material(prepared, material):
    with pytest.raises(ValueError, match=r"exact.*material|material.*type"):
        _runner(prepared, host_tools=material)


def test_backend_without_material_is_not_a_legacy_override(prepared):
    with pytest.raises(ValueError, match=r"managed.*material"):
        _runner(prepared, host_tools=None)


def test_disabled_matrix_still_verifies_prepared_config(tmp_path, config_factory):
    prepared = prepared_matrix(tmp_path, config_factory, enabled=False)
    runner = _runner(prepared)
    assert runner.dependencies.clean_state_provider is None
    assert _run(runner, prepared) is None
    runner.smart_contracts.foundry_fuzz_runs += 1
    with pytest.raises(ValueError, match=r"managed.*config"):
        _run(runner, prepared)


@pytest.mark.parametrize("rpc_flag", [False, True])
def test_unverified_backend_cannot_open_rpc_or_private_matrix(prepared, rpc_flag):
    backend = _Backend()
    backend.supports_local_fork_rpc = rpc_flag
    runner = _runner(prepared, managed_backend=backend)
    result = _run(runner, prepared)
    assert result.status is RepositoryDifferentialRunStatus.FAILED
    assert result.matrix is None
    assert any("isolation" in item for item in result.limitations)
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("field", ["smart_contracts", "reproduction", "dependencies", "backend"])
def test_selection_drift_is_refused_before_run(prepared, field):
    runner = _runner(prepared)
    if field == "smart_contracts":
        runner.smart_contracts.repository_suite.fork_matrix_states = ()
    elif field == "reproduction":
        runner.reproduction.expected_chain_id = 31338
    elif field == "dependencies":
        runner.dependencies = ForkMatrixDependencies()
    else:
        runner.backend = _Backend()
    with pytest.raises(ValueError, match="managed"):
        _run(runner, prepared)
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize(
    "role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC, ManagedToolchainRole.ANVIL]
)
def test_same_byte_tool_replacement_invalidates_retained_selection(prepared, role):
    runner = _runner(prepared)
    executable = prepared[1].executable_for(role)
    replacement = executable.with_suffix(".replacement")
    shutil.copyfile(executable, replacement)
    replacement.chmod(0o500)
    replacement.replace(executable)
    with pytest.raises(ValueError, match=r"managed.*identity"):
        _run(runner, prepared)


def test_pipeline_composes_matrix_as_fifth_shared_backend_consumer(prepared):
    backend = _Backend()
    pipeline = AuditPipeline(
        prepared[1].config,
        repo=prepared[0],
        output=prepared[2],
        host_tools=prepared[1],
        managed_backend=backend,
    )
    matrix = pipeline.repository_fork_matrix_runner
    assert type(matrix) is RepositoryForkMatrixRunner
    assert matrix.backend is pipeline.scanner_runner.backend is backend
    pipeline._verify_managed_tools()
    pipeline.repository_fork_matrix_runner = _runner(prepared, managed_backend=backend)
    with pytest.raises(ValueError, match="managed pipeline consumer selection changed"):
        pipeline._verify_managed_tools()


@pytest.mark.parametrize("field", ["smart_contracts", "reproduction"])
def test_constructor_refuses_config_drift(prepared, field):
    value = getattr(prepared[1].config, field)
    if field == "smart_contracts":
        value.foundry_fuzz_runs += 1
    else:
        value.expected_chain_id = 31338
    with pytest.raises(ValueError, match=r"managed.*config"):
        _runner(prepared, **{field: value})


@pytest.mark.parametrize("root_name", ["source", "private", "exclusion"])
@pytest.mark.parametrize("relation", ["equal", "parent", "child", "alias"])
def test_material_cannot_overlap_or_alias_matrix_roots(prepared, root_name, relation):
    runner = _runner(prepared)
    material = prepared[1]
    path = {
        "equal": material.directory,
        "parent": material.directory.parent,
        "child": material.directory / "private-child",
        "alias": prepared[2] / "alias",
    }[relation]
    if relation == "alias":
        path.symlink_to(prepared[0], target_is_directory=True)
    roots = dict(source=prepared[0], private=prepared[2], exclusion=prepared[2])
    roots[root_name] = path
    with pytest.raises(ValueError, match=r"managed.*roots"):
        runner._managed.verify_roots(*roots.values())


@pytest.mark.parametrize(
    "mutation", ["other_config", "mixed_state_pair", "endpoint", "recorder", "permission"]
)
def test_factory_refuses_undeclared_context_without_execution(prepared, mutation):
    runner = _runner(prepared)
    config = prepared[1].config
    smart = config.smart_contracts
    reproduction = config.reproduction.model_copy(
        update={"expected_chain_id": 31337, "pinned_block_number": 0}
    )

    class Bridge:
        endpoint = "http://127.0.0.1:18545"

    endpoint = Bridge.endpoint
    if mutation == "other_config":
        smart.foundry_fuzz_runs += 1
    elif mutation == "mixed_state_pair":
        reproduction.pinned_block_number = 7
    elif mutation == "endpoint":
        endpoint = "http://localhost:18545"
    elif mutation == "recorder":
        endpoint = "http://127.0.0.1:18546"
    with pytest.raises(ValueError):
        runner.dependencies.scanner_factory(
            smart,
            reproduction=reproduction,
            projects=(),
            allow_fork_probing=mutation != "permission",
            expected_repository_sha256="a" * 64,
            repository_exclusion_root=prepared[2],
            fork_rpc_url_override=endpoint,
            fork_rpc_scope_recorder=Bridge(),
            attempt_binding_sha256="c" * 64,
        )


def test_flags_and_serialized_real_claim_do_not_attest_backend(prepared):
    backend = _Backend()
    backend.supports_local_fork_rpc = True
    backend.execution_evidence = ExecutionEvidenceKind.REAL
    backend.isolation_attestation_sha256 = "d" * 64
    runner = _runner(prepared, managed_backend=backend)
    assert runner._managed.backend_attestation_sha256 is None
    assert _run(runner, prepared).matrix is None


@pytest.mark.parametrize("change", ["none", "version", "hash", "baseline_seal", "current_seal"])
def test_prepared_baseline_pin_join_retains_independent_missing_baseline_refusal(
    prepared, monkeypatch, change
):
    # Unit-only provenance boundary stubs: no backend seal, process or real
    # evidence is created. The unchanged legacy baseline gate must still refuse.
    monkeypatch.setattr(
        managed_fork_matrix, "isolation_attestation_sha256", lambda backend: "d" * 64
    )
    monkeypatch.setattr(
        managed_fork_matrix,
        "isolation_execution_evidence",
        lambda backend: ExecutionEvidenceKind.REAL,
    )
    backend = _Backend()
    backend.supports_local_fork_rpc = True
    runner = _runner(prepared, managed_backend=backend)
    forge = next(
        item for item in prepared[1].manifest.files if item.role is ManagedToolchainRole.FORGE
    )
    baseline = _unavailable_run("synthetic incomplete", now=lambda: datetime.now(UTC)).model_copy(
        update={
            "version": "changed" if change == "version" else forge.version,
            "executable_sha256": "e" * 64 if change == "hash" else forge.sha256,
            "isolation_attestation_sha256": "e" * 64 if change == "baseline_seal" else "d" * 64,
        }
    )
    if change == "current_seal":
        monkeypatch.setattr(
            managed_fork_matrix, "isolation_attestation_sha256", lambda backend: "e" * 64
        )
        assert runner._managed.backend_limitation(backend) is not None
    elif change != "none":
        assert runner._managed.baseline_limitation(baseline) is not None
    else:
        assert runner._managed.baseline_limitation(baseline) is None
        result = runner.run(
            prepared[0],
            prepared[2],
            projects=(),
            repository_sha256="a" * 64,
            repository_exclusion_root=prepared[2],
            backend=backend,
            baseline_run=baseline,
            absolute_deadline=time.monotonic() + 10,
        )
        assert result.status is RepositoryDifferentialRunStatus.FAILED
        assert result.matrix is None
        assert any(
            "baseline Foundry execution evidence was incomplete" in item
            for item in result.limitations
        )
    assert not list(prepared[2].iterdir())
