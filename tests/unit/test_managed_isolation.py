"""Managed Linux selection using inert files; all boundary probes are explicitly mocked."""

from __future__ import annotations

import importlib
import platform
import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.isolation import provenance
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainMemberKind,
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import runner as scanner_runner
from mmaudit.solidity.reproduction import BubblewrapBackend
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_toolchain_support import synthetic_pinned_bundle

_PROBES = provenance._IsolationProbeResults(True, True, True, True, True, True)


@pytest.fixture(autouse=True)
def fixed_linux_without_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail(
            "invariant: inert managed isolation fixtures must not execute, discover or network"
        )

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    monkeypatch.setattr(platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(provenance, "_run_builtin_preflight", lambda *_a, **_k: _PROBES)


@pytest.fixture
def prepared(tmp_path, config_factory):
    config = config_factory(
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        scanners={"semgrep": {"enabled": True, "required": True}},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    return materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )


def _factory(material):
    return importlib.import_module("mmaudit.isolation.managed").managed_isolation_backend(material)


def _replace_tool(material, role, *, same_bytes=False):
    original = material.directory / next(
        item.locator for item in material.manifest.files if item.role is role
    )
    replacement = original.with_name("temporary-replacement")
    replacement.write_bytes(
        original.read_bytes() if same_bytes else b"changed inert tool fixture\n"
    )
    replacement.chmod(0o500)
    replacement.replace(original)


def test_factory_uses_only_exact_selected_launcher_and_preserves_false_readiness(prepared):
    backend = _factory(prepared)
    assert type(backend) is BubblewrapBackend
    assert backend.executable == str(prepared.executable_for(ManagedToolchainRole.BUBBLEWRAP))
    assert backend.host_tools is prepared
    assert backend.supports_local_fork_rpc is False
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.REAL
    assert prepared.runtime_authority is prepared.managed_run_ready is False
    assert (
        prepared.manifest.runtime_authority
        is prepared.manifest.execution_evidence_verified
        is False
    )


@pytest.mark.parametrize(
    "system,machine",
    [("Darwin", "arm64"), ("Windows", "AMD64"), ("Linux", "aarch64"), ("Linux", "unknown")],
)
def test_wrong_host_platform_refuses_before_preflight(prepared, monkeypatch, system, machine):
    monkeypatch.setattr(platform, "system", lambda: system)
    monkeypatch.setattr(platform, "machine", lambda: machine)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: mismatched managed platform must not reach preflight")

    monkeypatch.setattr(provenance, "_run_builtin_preflight", forbidden)
    with pytest.raises(ValueError, match="managed"):
        _factory(prepared)


@pytest.mark.parametrize("failed_property", list(_PROBES.__dataclass_fields__))
def test_managed_factory_keeps_every_mandatory_boundary_property(
    prepared, monkeypatch, failed_property
):
    monkeypatch.setattr(
        provenance,
        "_run_builtin_preflight",
        lambda *_a, **_k: replace(_PROBES, **{failed_property: False}),
    )
    with pytest.raises(ValueError, match="managed"):
        _factory(prepared)


@pytest.mark.parametrize("allow_network", [False, True])
def test_wrapper_adds_only_exact_read_only_material_and_empty_parent_directories(
    prepared, tmp_path, allow_network
):
    backend = _factory(prepared)
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    command = [str(prepared.executable_for(ManagedToolchainRole.SEMGREP)), "--version"]
    method = backend.wrap_allowing_network if allow_network else backend.wrap
    argv = method(command, workspace=workspace, private_dir=private, rpc_port=0)
    baseline = BubblewrapBackend(executable=backend.executable)
    baseline_method = baseline.wrap_allowing_network if allow_network else baseline.wrap
    old = baseline_method(command, workspace=workspace, private_dir=private, rpc_port=0)

    def mounts(arguments, flag):
        return [
            tuple(arguments[index + 1 : index + 3])
            for index, token in enumerate(arguments)
            if token == flag
        ]

    assert mounts(argv, "--bind") == [(str(private), str(private))]
    assert mounts(argv, "--ro-bind") == [
        *mounts(old, "--ro-bind"),
        (str(prepared.directory), str(prepared.directory)),
    ]
    assert ("--unshare-net" in argv) is not allow_network
    assert argv[-len(command) :] == command
    assert str(prepared.directory.parent) not in {source for source, _ in mounts(argv, "--ro-bind")}


@pytest.mark.parametrize("overlap", ["same", "ancestor", "descendant"])
def test_material_cannot_overlap_any_writable_private_mount(prepared, overlap):
    backend = _factory(prepared)
    private = prepared.directory if overlap == "same" else prepared.directory.parent
    if overlap == "descendant":
        private = prepared.directory / "unexpected-private-directory"
        private.mkdir()
    with pytest.raises(ValueError, match=r"managed|material"):
        backend.wrap(["/usr/bin/true"], workspace=private, private_dir=private, rpc_port=0)


@pytest.mark.parametrize("role", [ManagedToolchainRole.BUBBLEWRAP, ManagedToolchainRole.SEMGREP])
def test_every_wrap_reverifies_material_after_factory_return(prepared, tmp_path, role):
    backend = _factory(prepared)
    _replace_tool(prepared, role)
    private = tmp_path / "private"
    private.mkdir()
    with pytest.raises(ValueError, match=r"managed|material"):
        backend.wrap(["/usr/bin/true"], workspace=private, private_dir=private, rpc_port=0)
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize("same_bytes", [False, True])
def test_pin_admission_is_retained_across_sealer_handoff(prepared, monkeypatch, same_bytes):
    managed = importlib.import_module("mmaudit.isolation.managed")
    original = managed._seal_builtin_isolation_backend

    def changed(backend, *, admission):
        expected = next(
            item.sha256
            for item in prepared.manifest.files
            if item.role is ManagedToolchainRole.BUBBLEWRAP
        )
        assert admission.observation.sha256 == expected
        _replace_tool(prepared, ManagedToolchainRole.BUBBLEWRAP, same_bytes=same_bytes)
        return original(backend, admission=admission)

    monkeypatch.setattr(managed, "_seal_builtin_isolation_backend", changed)
    with pytest.raises(ValueError, match="managed"):
        _factory(prepared)


def test_runner_constructs_the_managed_backend_without_manual_selection(prepared):
    runner = scanner_runner.ScannerRunner(prepared.config, host_tools=prepared)
    assert type(runner.backend) is BubblewrapBackend
    assert runner.backend.host_tools is prepared
    assert runner.adapters["semgrep"].executable == str(
        prepared.executable_for(ManagedToolchainRole.SEMGREP)
    )


def test_bundle_view_is_detached_and_cannot_change_retained_platform(prepared):
    view = prepared.bundle
    object.__setattr__(view, "target_platform", "unresolved")
    assert prepared.bundle.target_platform == "linux-amd64"
    prepared.verify()


@pytest.mark.parametrize("invalid", [None, {}, Path("/unselected-material"), object()])
def test_factory_rejects_non_material_inputs_without_ambient_fallback(invalid):
    with pytest.raises(ValueError, match="managed"):
        _factory(invalid)


@pytest.mark.parametrize("boundary", ["before-admission", "during-preflight", "after-seal"])
def test_factory_refuses_material_drift_at_each_construction_boundary(
    prepared, monkeypatch, boundary
):
    managed = importlib.import_module("mmaudit.isolation.managed")
    if boundary == "before-admission":
        original_admit = managed._admit_isolation_executable

        def changed_admit(backend):
            _replace_tool(prepared, ManagedToolchainRole.BUBBLEWRAP)
            return original_admit(backend)

        monkeypatch.setattr(managed, "_admit_isolation_executable", changed_admit)
    elif boundary == "during-preflight":

        def changed_probes(*args, **kwargs):
            _replace_tool(prepared, ManagedToolchainRole.SEMGREP)
            return _PROBES

        monkeypatch.setattr(provenance, "_run_builtin_preflight", changed_probes)
    else:
        original_seal = managed._seal_builtin_isolation_backend

        def changed_seal(backend, *, admission):
            result = original_seal(backend, admission=admission)
            _replace_tool(prepared, ManagedToolchainRole.SEMGREP)
            return result

        monkeypatch.setattr(managed, "_seal_builtin_isolation_backend", changed_seal)
    with pytest.raises(ValueError, match="managed"):
        _factory(prepared)


def test_direct_backend_cannot_substitute_launcher_for_valid_material(prepared, tmp_path):
    backend = BubblewrapBackend(executable="/usr/bin/unselected-bwrap", host_tools=prepared)
    private = tmp_path / "private"
    private.mkdir()
    with pytest.raises(ValueError, match="managed"):
        backend.wrap(["/usr/bin/true"], workspace=private, private_dir=private, rpc_port=0)


@pytest.mark.parametrize("case", ["extra-file", "linked-tool", "missing-tool", "linked-directory"])
def test_factory_refuses_incomplete_or_aliased_material(prepared, case):
    executable = prepared.executable_for(ManagedToolchainRole.SEMGREP)
    if case == "extra-file":
        (prepared.directory / "unselected.txt").write_text("synthetic unexpected entry")
    elif case == "missing-tool":
        executable.unlink()
    elif case == "linked-tool":
        other = prepared.directory.parent / "unselected-target"
        executable.rename(other)
        executable.symlink_to(other)
    else:
        other = prepared.directory.with_name("moved-material")
        prepared.directory.rename(other)
        prepared.directory.symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="managed"):
        _factory(prepared)


@pytest.mark.parametrize("conflict", ["config", "adapters"])
def test_runner_rejects_mixed_input_before_automatic_backend_construction(
    prepared, monkeypatch, conflict
):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: mismatched runner input must not trigger isolation preflight")

    monkeypatch.setattr(scanner_runner, "managed_isolation_backend", forbidden)
    config = prepared.config
    options = {}
    if conflict == "config":
        config.execution.scanner_timeout_seconds += 1
    else:
        options["adapters"] = {}
    with pytest.raises(ValueError, match="managed"):
        scanner_runner.ScannerRunner(config, host_tools=prepared, **options)


def test_automatic_backend_refusal_does_not_use_default_discovery(prepared, monkeypatch):
    def unavailable(*args, **kwargs):
        raise ValueError("managed isolation is unavailable")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: managed refusal cannot fall back to host discovery")

    monkeypatch.setattr(scanner_runner, "managed_isolation_backend", unavailable)
    monkeypatch.setattr(scanner_runner, "default_isolation_backend", forbidden)
    with pytest.raises(ValueError, match="managed"):
        scanner_runner.ScannerRunner(prepared.config, host_tools=prepared)


def test_explicit_backend_remains_explicit_without_automatic_preflight(prepared, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: an explicitly supplied backend must not trigger a second selection")

    monkeypatch.setattr(scanner_runner, "managed_isolation_backend", forbidden)
    backend = BubblewrapBackend(executable="/unverified-explicit-placeholder")
    runner = scanner_runner.ScannerRunner(prepared.config, host_tools=prepared, backend=backend)
    assert runner.backend is backend
    assert provenance.isolation_execution_evidence(backend) is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize("selected", ["auto", "sandbox-exec", "rootless-container", "no-host-role"])
def test_other_backend_selections_and_absent_host_role_are_refused(
    tmp_path, config_factory, selected
):
    rootless = {}
    if selected == "rootless-container":
        members = {item.role: item for item in synthetic_pinned_bundle().members}
        rootless = {
            "rootless_container_image": members[
                ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
            ].locator,
            "rootless_container_runtime": members[ManagedToolchainRole.CONTAINER_RUNTIME].locator,
        }
    config = config_factory(
        reproduction={
            "enabled": False,
            "isolation_backend": "bubblewrap" if selected == "no-host-role" else selected,
            "rootless_container_runtime": "podman",
            **rootless,
        },
        scanners={"semgrep": {"enabled": selected == "sandbox-exec", "required": False}},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    with pytest.raises(ValueError, match="managed"):
        _factory(material)


@pytest.mark.parametrize(
    "target,machine",
    [
        ("linux-amd64", "x86_64"),
        ("linux-amd64", "AMD64"),
        ("linux-arm64", "aarch64"),
        ("linux-arm64", "arm64"),
    ],
)
def test_each_supported_declared_platform_must_match_its_native_cpu_label(
    tmp_path, config_factory, monkeypatch, target, machine
):
    config = config_factory(
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        scanners={"semgrep": {"enabled": True, "required": True}},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            item.model_copy(update={"platform": target})
            if item.kind is ManagedToolchainMemberKind.OCI_IMAGE
            else item
            for item in bundle.members
        ),
        target_platform=target,
    )
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    monkeypatch.setattr(platform, "machine", lambda: machine)
    assert type(_factory(material)) is BubblewrapBackend
    assert material.manifest.architecture_verified is False
