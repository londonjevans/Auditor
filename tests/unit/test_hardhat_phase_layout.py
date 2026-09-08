"""Fail-closed phase construction without sockets, runtime processes or image admission."""

from __future__ import annotations

import dataclasses
import socket
import subprocess

import pytest

from mmaudit.isolation.container import HardhatPhaseCommand, HardhatReadOnlyRpcBridgeBinding
from tests.unit.test_hardhat_isolation_backend import _backend
from tests.unit.test_hardhat_protocol import _inventory_request


@pytest.fixture(autouse=True)
def no_runtime_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: phase validation must not start a runtime or network connection")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)


@pytest.fixture
def local_layout(tmp_path):
    private = tmp_path.resolve() / "private"
    private.mkdir(mode=0o700)
    workspace = private / "workspace"
    workspace.mkdir()
    backend = _backend()
    # Deliberately unregistered lookalike: no factory call or live authority exists.
    binding = object.__new__(HardhatReadOnlyRpcBridgeBinding)
    binding._backend_identity = id(backend)
    binding._closed = False
    binding._seal_nonce = "synthetic-no-seal"
    return private, workspace, backend, binding


@pytest.mark.parametrize("request_value", [None, {}, "inventory", object()])
def test_exact_phase_request_required_before_files_are_created(local_layout, request_value):
    private, workspace, backend, binding = local_layout
    with pytest.raises(ValueError, match="exact typed request"):
        backend.wrap_hardhat_phase(
            ("hardhat",), request_value, workspace=workspace, private_dir=private, binding=binding
        )
    assert list(private.iterdir()) == [workspace]


@pytest.mark.parametrize(
    "command",
    [
        [],
        ["hardhat"],
        (),
        ("node",),
        ("/usr/local/bin/hardhat",),
        ("hardhat", ""),
        ("hardhat", None),
        ("hardhat", "line\nbreak"),
        ("hardhat", "null\x00byte"),
        ("hardhat", "delete\x7fbyte"),
        ("hardhat", "a" * (128 * 1024)),
        ("hardhat", "é" * (70 * 1024)),
        ("hardhat",) * 257,
    ],
)
def test_unbounded_or_non_image_command_refuses_without_writes(local_layout, command):
    private, workspace, backend, binding = local_layout
    with pytest.raises(ValueError, match="bounded image-side"):
        backend.wrap_hardhat_phase(
            command, _inventory_request(), workspace=workspace, private_dir=private, binding=binding
        )
    assert list(private.iterdir()) == [workspace]


def test_mutated_request_hash_refuses_before_layout_creation(local_layout):
    private, workspace, backend, binding = local_layout
    request = _inventory_request()
    object.__setattr__(request, "chain_id", 1)
    with pytest.raises(ValueError, match="request hash"):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert list(private.iterdir()) == [workspace]


@pytest.mark.parametrize("shape", ["equal", "outside", "alias", "file", "relative"])
def test_noncanonical_or_overlapping_source_refuses_without_writes(local_layout, shape):
    private, workspace, backend, binding = local_layout
    if shape == "equal":
        workspace = private
    elif shape == "outside":
        workspace = private.parent
    elif shape == "alias":
        alias = private / "alias"
        alias.symlink_to(workspace, target_is_directory=True)
        workspace = alias
    elif shape == "file":
        workspace = private / "source-file"
        workspace.write_text("synthetic source")
    else:
        workspace = workspace.relative_to(private)
    before = set(private.iterdir())
    with pytest.raises(ValueError, match="source"):
        backend.wrap_hardhat_phase(
            ("hardhat",),
            _inventory_request(),
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )
    assert set(private.iterdir()) == before


@pytest.mark.parametrize("shape", ["mode", "alias", "relative"])
def test_nonprivate_or_aliased_bridge_root_refuses(local_layout, shape):
    private, workspace, backend, binding = local_layout
    if shape == "mode":
        private.chmod(0o755)
    elif shape == "alias":
        alias = private.parent / "alias"
        alias.symlink_to(private, target_is_directory=True)
        private = alias
    else:
        private = private.relative_to(private.parent)
    with pytest.raises(ValueError, match="private directory"):
        backend.wrap_hardhat_phase(
            ("hardhat",),
            _inventory_request(),
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )


def test_unregistered_handle_cannot_create_phase_output(local_layout):
    private, workspace, backend, binding = local_layout
    with pytest.raises(ValueError, match="exact retained"):
        backend.wrap_hardhat_phase(
            ("hardhat",),
            _inventory_request(),
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )
    assert list(private.iterdir()) == [workspace]


def test_constructible_layout_observation_is_frozen_and_nonauthorizing(local_layout):
    private, workspace, _, _ = local_layout
    value = HardhatPhaseCommand("inventory", "a" * 64, private, workspace, ("synthetic",))
    assert value.execution_credit is value.runtime_authority is False
    assert str(private) not in repr(value) and "synthetic" not in repr(value)
    with pytest.raises(dataclasses.FrozenInstanceError):
        value.command = ("changed",)
