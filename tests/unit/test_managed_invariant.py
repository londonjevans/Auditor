"""Prepared source-local invariant tools with inert executables and no RPC."""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from mmaudit.isolation import managed as managed_isolation
from mmaudit.models.schemas import (
    AttackerCapability,
    AttackerCapabilityPolicy,
    EconomicSimulationKind,
    ExecutionEvidenceKind,
    InvariantExecutionStatus,
    StatefulActionSpec,
    TransactionOrderingCapability,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.solidity import invariant_execution as invariant
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_invariant_support import (
    SYNTHETIC_TARGET,
    local_invariant_control_output,
    local_invariant_inputs,
)


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: inert local handoff cannot execute, discover PATH tools or use RPC")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(invariant, "_local_rpc", forbidden)
    monkeypatch.setattr(invariant, "_external_executable", forbidden)


class _Backend:
    name = "unverified-local-invariant-control"
    supports_local_fork_rpc = False

    def __init__(self, mutate=None):
        self.commands = []
        self.mutate = mutate

    def wrap(self, command, *, workspace, private_dir, rpc_port):
        assert rpc_port == 0
        self.commands.append(command.copy())
        if self.mutate is not None:
            self.mutate()
        return command


@pytest.fixture
def prepared(tmp_path, config_factory, request):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False, "framework": "foundry"},
        reproduction={
            "enabled": False,
            "isolation_backend": "bubblewrap",
            "targets": {"FixtureMachine": SYNTHETIC_TARGET},
            "allowed_transaction_ordering": (
                "multi_transaction" if getattr(request, "param", False) else "none"
            ),
        },
        invariants={"enabled": True, "execute_generated": True},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    project, specification = local_invariant_inputs(repository)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    return repository, material, project, specification


def _runner(prepared, **kwargs):
    material = prepared[1]
    return invariant.FoundryInvariantRunner(
        kwargs.pop("reproduction", material.config.reproduction),
        kwargs.pop("smart_contracts", material.config.smart_contracts),
        host_tools=kwargs.pop("host_tools", material),
        backend=kwargs.pop("backend", _Backend()),
        **kwargs,
    )


def _run(runner, prepared, tmp_path, **kwargs):
    repository, _, project, specification = prepared
    return runner.run(
        repository_root=kwargs.pop("repository_root", repository),
        project=project,
        specification=kwargs.pop("specification", specification),
        private_dir=kwargs.pop("private_dir", tmp_path / "invariant-private"),
        **kwargs,
    )


def _change(material, role, mutation="bytes"):
    path = material.executable_for(role)
    if mutation == "replacement":
        replacement = path.with_name(path.name + ".replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o500)
        replacement.replace(path)
    else:
        path.chmod(0o600)
        path.write_bytes(b"Changed inert local invariant fixture; never execute.\n")
        path.chmod(0o500)


def _fake_execution(
    monkeypatch, material, *, during_probe=None, after_run=None, wrong_version=None
):
    probes, launches = [], []
    versions = {item.locator: item.version for item in material.manifest.files}

    def probe(executable, **kwargs):
        assert kwargs["expected_host_observation"].sha256
        probes.append(executable.name)
        if during_probe is not None:
            during_probe(executable)
        return "wrong-version" if executable.name == wrong_version else versions[executable.name]

    class Process:
        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    def launch(command, **kwargs):
        assert kwargs["shell"] is False
        assert command[0] == str(material.executable_for(ManagedToolchainRole.FORGE))
        assert "--fork-url" not in command
        assert kwargs["env"]["FOUNDRY_FFI"] == "false"
        launches.append(command.copy())
        kwargs["stdout"].write(local_invariant_control_output().encode())
        if after_run is not None:
            after_run(len(launches))
        return Process()

    monkeypatch.setattr(invariant, "_external_executable_version", probe)
    monkeypatch.setattr(subprocess, "Popen", launch)
    return probes, launches


def test_prepared_tools_are_used_directly_across_clean_replay(prepared, tmp_path, monkeypatch):
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(_runner(prepared), prepared, tmp_path)
    assert probes == ["forge", "solc"]
    assert len(launches) == 2 and result.replay_confirmed
    assert result.status is InvariantExecutionStatus.PASSED
    assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert result.compiler_version == "1.2.3"
    compiler = prepared[1].executable_for(ManagedToolchainRole.SOLC)
    for command in launches:
        assert command[command.index("--use") + 1] == str(compiler)
        assert "--no-auto-detect" in command and "--offline" in command
    assert not list((tmp_path / "invariant-private").rglob("toolchain/solc"))
    assert str(compiler) not in str(result.command)
    assert "[PINNED_SOLC]" in result.command


@pytest.mark.parametrize("bad", [False, {}, "material", object()])
def test_wrong_material_type_refuses_before_backend_discovery(prepared, bad):
    with pytest.raises(ValueError, match=r"managed|material"):
        _runner(prepared, host_tools=bad, backend=None)


@pytest.mark.parametrize(
    "branch,field,value",
    [
        ("reproduction", "timeout_seconds", 17),
        ("smart_contracts", "allow_network", True),
        ("smart_contracts", "solc_sha256", "0" * 64),
    ],
)
def test_mixed_configuration_refuses_before_writes(prepared, tmp_path, branch, field, value):
    config = getattr(prepared[1].config, branch).model_copy(update={field: value})
    with pytest.raises(ValueError, match=r"managed|config"):
        _runner(prepared, **{branch: config})
    assert not (tmp_path / "invariant-private").exists()


@pytest.mark.parametrize("argument", ["forge_executable", "solc_executable"])
def test_explicit_path_overrides_cannot_mix_with_prepared_selection(prepared, argument):
    with pytest.raises(ValueError, match=r"managed|selection|override"):
        _runner(prepared, **{argument: Path("/forbidden/custom-tool")})


@pytest.mark.parametrize("role", [ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC])
@pytest.mark.parametrize("mutation", ["bytes", "replacement"])
def test_selected_tool_drift_refuses_before_writes(prepared, tmp_path, role, mutation):
    runner = _runner(prepared)
    _change(prepared[1], role, mutation)
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(runner, prepared, tmp_path)
    assert not (tmp_path / "invariant-private").exists()


@pytest.mark.parametrize("stage", ["probe", "wrap", "first-outcome", "replay-outcome"])
def test_drift_during_probe_launch_or_replay_cannot_return_a_result(
    prepared, tmp_path, monkeypatch, stage
):
    def mutate(*args):
        _change(prepared[1], ManagedToolchainRole.SOLC, "replacement")

    def after_run(attempt):
        if attempt == (2 if stage == "replay-outcome" else 1):
            mutate()

    probes, launches = _fake_execution(
        monkeypatch,
        prepared[1],
        during_probe=mutate if stage == "probe" else None,
        after_run=after_run if stage.endswith("outcome") else None,
    )
    runner = _runner(prepared, backend=_Backend(mutate if stage == "wrap" else None))
    with pytest.raises(ValueError, match=r"managed|material|identity"):
        _run(runner, prepared, tmp_path)
    assert len(probes) == (1 if stage == "probe" else 2)
    assert len(launches) == {"probe": 0, "wrap": 0, "first-outcome": 1, "replay-outcome": 2}[stage]


@pytest.mark.parametrize("name", ["forge", "solc"])
def test_wrong_declared_version_is_blocked_before_target_execution(
    prepared, tmp_path, monkeypatch, name
):
    probes, launches = _fake_execution(monkeypatch, prepared[1], wrong_version=name)
    result = _run(_runner(prepared), prepared, tmp_path)
    assert probes == (["forge"] if name == "forge" else ["forge", "solc"])
    assert not launches and result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED


@pytest.mark.parametrize("root", ["source", "private", "ancestor", "descendant"])
def test_material_cannot_overlap_source_or_writable_state(prepared, tmp_path, root):
    material_root = prepared[1].directory
    kwargs = (
        {"repository_root": material_root}
        if root == "source"
        else {
            "private_dir": {
                "private": material_root,
                "ancestor": material_root.parent,
                "descendant": material_root / "private",
            }[root]
        }
    )
    with pytest.raises(ValueError, match=r"managed|overlap"):
        _run(_runner(prepared), prepared, tmp_path, **kwargs)


def test_nonlocal_harness_refuses_without_rpc_or_tool_probe(prepared, tmp_path):
    specification = prepared[3].model_copy(update={"local_deployments": []})
    result = _run(_runner(prepared), prepared, tmp_path, specification=specification)
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert result.limitations == ["managed invariant fork archive is unavailable"]
    assert not (tmp_path / "invariant-private").exists()


def test_mutable_executable_views_do_not_redirect_prepared_selection(
    prepared, tmp_path, monkeypatch
):
    runner = _runner(prepared)
    runner.forge_executable = runner.solc_executable = Path("/forbidden/custom-tool")
    _, launches = _fake_execution(monkeypatch, prepared[1])
    result = _run(runner, prepared, tmp_path)
    assert result.replay_confirmed and len(launches) == 2


def test_omitted_backend_uses_managed_factory_and_preserves_explicit_backend(prepared, monkeypatch):
    backend, selected = _Backend(), []

    def factory(material):
        selected.append(material)
        return backend

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", factory)
    assert _runner(prepared, backend=None).backend is backend
    assert selected == [prepared[1]]
    explicit = _Backend()
    assert _runner(prepared, backend=explicit).backend is explicit
    assert selected == [prepared[1]]


def test_failed_managed_backend_has_no_ambient_fallback(prepared, monkeypatch):
    def unavailable(material):
        raise ValueError("managed isolation unavailable for this local case")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", unavailable)
    with pytest.raises(ValueError, match="managed isolation unavailable"):
        _runner(prepared, backend=None)


@pytest.mark.parametrize("field", ["enabled", "execute_generated"])
def test_unselected_generated_invariants_do_not_probe_or_build_backend(
    tmp_path, config_factory, monkeypatch, field
):
    flags = {"enabled": True, "execute_generated": True, field: False}
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        invariants=flags,
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    project, specification = local_invariant_inputs(repository)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )

    def forbidden(*args):
        pytest.fail("disabled generated invariants cannot initialize isolation")

    monkeypatch.setattr(managed_isolation, "managed_isolation_backend", forbidden)
    runner = _runner((repository, material), backend=None)
    assert runner.backend is None
    result = runner.run(
        repository_root=repository,
        project=project,
        specification=specification,
        private_dir=tmp_path / "invariant-private",
    )
    assert result.status is InvariantExecutionStatus.ENVIRONMENT_BLOCKED
    assert not (tmp_path / "invariant-private").exists()


def test_harness_and_project_inputs_are_detached_before_probes(prepared, tmp_path, monkeypatch):
    project, specification = prepared[2:]
    expected_hash = specification.specification_sha256()

    def mutate(*args):
        project.project_root = "../forbidden"
        specification.name = "ChangedHarness"
        specification.actions.clear()
        specification.local_deployments.clear()

    _, launches = _fake_execution(monkeypatch, prepared[1], during_probe=mutate)
    result = _run(_runner(prepared), prepared, tmp_path)
    assert result.replay_confirmed and result.harness_spec_sha256 == expected_hash
    assert len(launches) == 2
    assert all("MMAuditInvariant_ManagedLocalState" in command for command in launches)


@pytest.mark.parametrize("field,value", [("runs", 0), ("name", "../unsafe")])
def test_invalid_mutable_harness_copy_refuses_before_writes(prepared, tmp_path, field, value):
    draft = prepared[3].model_copy(update={field: value})
    with pytest.raises(ValueError):
        _run(_runner(prepared), prepared, tmp_path, specification=draft)
    assert not (tmp_path / "invariant-private").exists()


@pytest.mark.parametrize("branch", ["reproduction", "smart_contracts"])
@pytest.mark.parametrize("stage", ["probe", "wrap", "outcome"])
def test_config_mutation_cannot_escape_probe_or_execution_boundaries(
    prepared, tmp_path, monkeypatch, branch, stage
):
    runner = _runner(prepared)

    def mutate(*args):
        if branch == "reproduction":
            runner.reproduction.timeout_seconds = 19
        else:
            runner.smart_contracts.allow_network = True

    _, launches = _fake_execution(
        monkeypatch,
        prepared[1],
        during_probe=mutate if stage == "probe" else None,
        after_run=mutate if stage == "outcome" else None,
    )
    if stage == "wrap":
        runner.backend = _Backend(mutate)
    with pytest.raises(ValueError, match=r"managed|config"):
        _run(runner, prepared, tmp_path)
    assert len(launches) == (1 if stage == "outcome" else 0)


def test_reassigned_config_is_checked_after_wrapper_preparation(prepared, tmp_path, monkeypatch):
    runner = _runner(prepared)

    def mutate():
        runner.reproduction = runner.reproduction.model_copy(update={"timeout_seconds": 19})

    runner.backend = _Backend(mutate)
    _, launches = _fake_execution(monkeypatch, prepared[1])
    with pytest.raises(ValueError, match=r"managed|config"):
        _run(runner, prepared, tmp_path)
    assert not launches


def test_private_stream_preparation_cannot_replace_forge_before_popen(
    prepared, tmp_path, monkeypatch
):
    runner = _runner(prepared)
    probes, launches = _fake_execution(monkeypatch, prepared[1])
    original_open = Path.open

    def guarded_open(path, mode="r", *args, **kwargs):
        handle = original_open(path, mode, *args, **kwargs)
        if path.name == "stderr.txt" and mode == "wb":
            _change(prepared[1], ManagedToolchainRole.FORGE, "replacement")
        return handle

    monkeypatch.setattr(Path, "open", guarded_open)
    with pytest.raises(ValueError, match=r"managed|identity"):
        _run(runner, prepared, tmp_path)
    assert probes == ["forge", "solc"] and not launches


@pytest.mark.parametrize("prepared", [True], indirect=True)
@pytest.mark.parametrize("mutate_minimization", [False, True])
def test_recursive_minimization_retains_original_prepared_identities(
    prepared, tmp_path, monkeypatch, mutate_minimization
):
    # Synthetic outcome doubles exercise recursion, not an actual fixture state violation.
    specification = prepared[3]
    actions = [
        *specification.actions,
        StatefulActionSpec(
            action_id="CommitState",
            target="FixtureMachine",
            function_signature="commitPreset()",
            actor_names=["observer"],
        ),
    ]
    action_ids = [action.action_id for action in actions]
    specification = specification.model_copy(
        update={
            "actions": actions,
            "required_action_sequence": action_ids,
            "depth": 2,
            "properties": [
                item.model_copy(update={"required_action_ids": action_ids})
                for item in specification.properties
            ],
            "economic_template": EconomicSimulationKind.STATE_ORDERING,
            "required_transaction_ordering": TransactionOrderingCapability.MULTI_TRANSACTION,
            "capability_policy": AttackerCapabilityPolicy(
                attacker_controlled_actors=["observer"],
                transaction_ordering=TransactionOrderingCapability.MULTI_TRANSACTION,
                capability_justifications={
                    AttackerCapability.TRANSACTION_ORDERING: "Two synthetic local state transitions only."
                },
            ),
        }
    )
    runner = _runner(prepared)
    commands = []

    def during_probe(*args):
        if mutate_minimization and len(probes) == 3:
            _change(prepared[1], ManagedToolchainRole.SOLC, "replacement")

    probes, launches = _fake_execution(monkeypatch, prepared[1], during_probe=during_probe)

    def execution(command, *, private_dir, action_functions, property_ids, **kwargs):
        assert command[0] == str(prepared[1].executable_for(ManagedToolchainRole.FORGE))
        assert command[command.index("--use") + 1] == str(
            prepared[1].executable_for(ManagedToolchainRole.SOLC)
        )
        commands.append(command)
        stdout, stderr = private_dir / "stdout.txt", private_dir / "stderr.txt"
        stdout.write_text("synthetic minimization bookkeeping control\n")
        stderr.write_text("")
        full = len(action_functions) == 2
        return invariant._InvariantExecution(
            status=InvariantExecutionStatus.COUNTEREXAMPLE
            if full
            else InvariantExecutionStatus.PASSED,
            stdout_path=stdout,
            stderr_path=stderr,
            limitations=[],
            counterexample_summary="synthetic outcome control" if full else None,
            counterexample_action_ids=action_ids if full else [],
            original_sequence_length=2 if full else None,
            shrunk_sequence_length=2 if full else None,
            observed_action_functions=sorted(action_functions.values()),
            observed_state_properties=sorted(property_ids),
            observed_sequence_lengths=[2 if full else 1],
            process_exit_code=1 if full else 0,
            machine_output_validated=True,
            campaign_runs=2,
            campaign_calls=2,
        )

    monkeypatch.setattr(runner, "_execute", execution)
    if mutate_minimization:
        with pytest.raises(ValueError, match=r"managed|identity"):
            _run(runner, prepared, tmp_path, specification=specification)
        assert len(probes) == 3 and len(commands) == 2
    else:
        result = _run(runner, prepared, tmp_path, specification=specification)
        assert len(probes) == 6 and len(commands) == 6
        assert result.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
        assert result.minimization_evidence is not None
        assert len(result.minimization_evidence.removal_trials) == 2
    assert not launches
