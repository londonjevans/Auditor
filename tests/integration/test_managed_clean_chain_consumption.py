"""Real private-copy/version-only handoff; never a running chain or Anvil attestation."""

from __future__ import annotations

import hashlib
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from mmaudit.orchestration.managed_toolchain import ManagedToolchainRole
from mmaudit.scanners import clean_chain
from tests.unit.test_clean_chain import clean_chain_private_root as clean_chain_private_root
from tests.unit.test_managed_clean_chain import _prepared


@pytest.mark.parametrize("wrong_version", [False, True])
def test_prepared_copy_reaches_bounded_version_control_without_environment_or_chain(
    tmp_path, config_factory, clean_chain_private_root, monkeypatch, wrong_version
):
    content = (
        Path(__file__).parents[1] / "fixtures/scanners/managed-anvil-version-control.sh"
    ).read_bytes()
    if wrong_version:
        content = content.replace(b"mmaudit-synthetic-control", b"different-synthetic-control")
    repository, material, _, config = _prepared(tmp_path, config_factory, content=content)
    private = clean_chain_private_root
    host_path = material.executable_for(ManagedToolchainRole.ANVIL)
    before = host_path.read_bytes(), host_path.stat(), config.model_dump_json()
    calls = []
    popen = subprocess.Popen

    def version_only(command, **kwargs):
        assert len(command) == 2 and command[1] == "--version"
        assert kwargs["shell"] is False and kwargs["start_new_session"] is True
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert Path(kwargs["cwd"]).is_relative_to(private)
        assert Path(command[0]) != host_path
        if command[0].startswith("/proc/self/fd/"):
            descriptor = int(command[0].rsplit("/", 1)[1])
            assert descriptor in kwargs["pass_fds"]
            assert os.fstat(descriptor).st_size == len(content)
        else:
            assert Path(command[0]).is_relative_to(private)
            assert hashlib.sha256(Path(command[0]).read_bytes()).hexdigest() == config.anvil_sha256
        calls.append((command, kwargs))
        return popen(command, **kwargs)

    def no_chain():
        raise clean_chain.CleanAnvilUnavailableError("synthetic version-only boundary")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: version-only control cannot discover tools or open sockets")

    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", forbidden)
        patch.setattr(shutil, "which", forbidden)
        launcher = clean_chain.TrustedCleanAnvilLauncher(
            host_tools=material, process_factory=version_only, port_supplier=no_chain
        )
        message = "exact configured version" if wrong_version else "synthetic version-only boundary"
        for _ in range(2):
            with pytest.raises(clean_chain.CleanAnvilError, match=message):
                launcher.start(config, repository, private, time.monotonic() + 5)
            assert not list(private.iterdir())
    assert len(calls) == 2
    assert (host_path.read_bytes(), host_path.stat(), config.model_dump_json()) == before
    assert material.runtime_authority is material.managed_run_ready is False
    material.verify()


@pytest.mark.parametrize("mutation", ["same-bytes-replacement", "config"])
def test_material_change_during_private_copy_prevents_dispatch_and_cleans_workspace(
    tmp_path, config_factory, clean_chain_private_root, monkeypatch, mutation
):
    repository, material, _, config = _prepared(tmp_path, config_factory)
    private = clean_chain_private_root
    path = material.executable_for(ManagedToolchainRole.ANVIL)
    original_copy = clean_chain._copy_pinned_executable

    def copy_then_drift(*args, **kwargs):
        copied = original_copy(*args, **kwargs)
        if mutation == "config":
            config.genesis_timestamp += 1
        else:
            content = path.read_bytes()
            path.rename(tmp_path / "retained-original")
            path.write_bytes(content)
            path.chmod(0o500)
        return copied

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: copy-time selection drift cannot dispatch a version or node")

    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    with monkeypatch.context() as patch:
        patch.setattr(clean_chain, "_copy_pinned_executable", copy_then_drift)
        patch.setattr(clean_chain.TrustedCleanAnvilLauncher, "_start_trusted", forbidden)
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(socket, "socket", forbidden)
        with pytest.raises(ValueError):
            launcher.start(config, repository, private, time.monotonic() + 5)
    assert not list(private.iterdir())


def test_managed_dispatch_owns_a_detached_prepared_clean_state(
    tmp_path, config_factory, clean_chain_private_root, monkeypatch
):
    repository, material, _, config = _prepared(tmp_path, config_factory)
    private = clean_chain_private_root
    before = config.model_dump_json()

    def dispatch(self, **kwargs):
        selected = kwargs["config"]
        assert selected is not config and selected.model_dump_json() == before
        config.genesis_timestamp += 1
        assert selected.model_dump_json() == before
        assert kwargs["executable"].sha256 == selected.anvil_sha256
        raise clean_chain.CleanAnvilUnavailableError("synthetic detached-state boundary")

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: detached-state copy control cannot execute or connect")

    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    with monkeypatch.context() as patch:
        patch.setattr(clean_chain.TrustedCleanAnvilLauncher, "_start_trusted", dispatch)
        patch.setattr(subprocess, "Popen", forbidden)
        patch.setattr(socket, "socket", forbidden)
        with pytest.raises(clean_chain.CleanAnvilUnavailableError, match="detached-state boundary"):
            launcher.start(config, repository, private, time.monotonic() + 5)
    assert not list(private.iterdir())
    assert material.config.smart_contracts.repository_suite.fork_matrix_states[
        0
    ].model_dump_json() == (before)
