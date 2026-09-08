"""Prepared clean-chain selection with inert files and no process or socket execution."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest

from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)
from mmaudit.scanners import clean_chain
from tests.host_tool_material_support import setup_host_material_inputs

VERSION = "anvil Version: mmaudit-synthetic-control"


def _prepared(tmp_path, config_factory, *, content=None, select_anvil=True):
    if content is None:
        content = (
            Path(__file__).parents[1] / "fixtures/scanners/identity-inert.txt"
        ).read_bytes() + b"Synthetic role: anvil\n"
    digest = hashlib.sha256(content).hexdigest()
    states = [
        {
            "state_id": "clean-local",
            "kind": "clean_local",
            "expected_chain_id": 31337,
            "anvil_version": VERSION,
            "anvil_sha256": digest,
            "hardfork": "cancun",
            "genesis_timestamp": 1,
            "startup_timeout_seconds": 1,
            "shutdown_timeout_seconds": 1,
        },
        {
            "state_id": "synthetic-offline",
            "kind": "pinned_fork",
            "rpc_url_env": "MMAUDIT_SYNTHETIC_CLEAN_CHAIN_RPC",
            "expected_chain_id": 31337,
            "pinned_block_number": 7,
            "state_source_sha256": "b" * 64,
        },
    ]
    config = config_factory(
        scanners={"semgrep": {"enabled": True}},
        smart_contracts={
            "compile": False,
            "repository_suite": {"fork_matrix_states": states if select_anvil else []},
        },
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        invariants={"enabled": False},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    if select_anvil:
        blob = store / f"{digest}.blob"
        blob.write_bytes(content)
        blob.chmod(0o600)
    bundle = seal_managed_toolchain_bundle(
        members=tuple(
            item.model_copy(update={"sha256": digest, "version": VERSION})
            if item.role is ManagedToolchainRole.ANVIL
            else item
            for item in bundle.members
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
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    clean = material.config.smart_contracts.repository_suite.fork_matrix_states
    return repository, material, private, clean[0] if clean else None


@pytest.fixture
def prepared(tmp_path, config_factory):
    return _prepared(tmp_path, config_factory)


@pytest.fixture(autouse=True)
def forbid_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: inert managed clean-chain tests cannot execute or connect")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


class _BeforeCopy(Exception):
    pass


def _stop_before_copy(monkeypatch):
    def stop(*args, **kwargs):
        raise _BeforeCopy

    monkeypatch.setattr(clean_chain, "_prepare_private_workspace", stop)


@pytest.mark.parametrize("repeat", [False, True])
def test_prepared_anvil_needs_no_environment_lookup_or_config_mutation(
    prepared, monkeypatch, repeat
):
    repository, material, private, config = prepared
    before = material.config.model_dump_json(), config.model_dump_json()
    _stop_before_copy(monkeypatch)

    class ForbiddenEnvironment(dict):
        def get(self, *args, **kwargs):
            pytest.fail("invariant: prepared Anvil cannot consult ambient executable paths")

    with monkeypatch.context() as patch:
        patch.setattr(clean_chain.os, "environ", ForbiddenEnvironment())
        launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
        for _ in range(2 if repeat else 1):
            with pytest.raises(_BeforeCopy):
                launcher.start(config, repository, private, time.monotonic() + 3)
    assert (material.config.model_dump_json(), config.model_dump_json()) == before
    assert not list(private.iterdir())
    assert material.runtime_authority is material.managed_run_ready is False


@pytest.mark.parametrize("environment", [{}, {"MMAUDIT_ANVIL_EXECUTABLE": "/synthetic/unused"}])
def test_prepared_anvil_refuses_mixed_environment_selection(prepared, environment):
    with pytest.raises(ValueError, match=r"managed.*environment|environment.*managed"):
        clean_chain.TrustedCleanAnvilLauncher(host_tools=prepared[1], environment=environment)


@pytest.mark.parametrize("material", [object(), {}, "synthetic"])
def test_prepared_anvil_refuses_non_material_types(material):
    with pytest.raises(ValueError, match=r"exact.*material|material.*type"):
        clean_chain.TrustedCleanAnvilLauncher(host_tools=material)


def test_prepared_anvil_requires_a_selected_anvil_role(tmp_path, config_factory):
    _, material, _, _ = _prepared(tmp_path, config_factory, select_anvil=False)
    with pytest.raises(ValueError, match=r"selected|clean-state"):
        clean_chain.TrustedCleanAnvilLauncher(host_tools=material)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("state_id", "other-clean"),
        ("expected_chain_id", 31338),
        ("genesis_timestamp", 2),
        ("hardfork", "paris"),
        ("startup_timeout_seconds", 2),
        ("shutdown_timeout_seconds", 2),
        ("anvil_executable_env", "MMAUDIT_OTHER_ANVIL"),
        ("anvil_version", "anvil Version: other"),
        ("anvil_sha256", "a" * 64),
    ],
)
def test_prepared_anvil_refuses_clean_state_config_drift_before_workspace(
    prepared, monkeypatch, field, value
):
    repository, material, private, config = prepared
    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    _stop_before_copy(monkeypatch)
    changed = config.model_copy(update={field: value})
    with pytest.raises(ValueError, match=r"prepared.*state|state.*prepared"):
        launcher.start(changed, repository, private, time.monotonic() + 3)
    assert not list(private.iterdir())


@pytest.mark.parametrize("mutation", ["bytes", "same-bytes-replacement", "linked", "other-tool"])
def test_prepared_anvil_rechecks_all_material_and_retained_identity_before_copy(
    prepared, monkeypatch, tmp_path, mutation
):
    repository, material, private, config = prepared
    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    _stop_before_copy(monkeypatch)
    path = material.executable_for(ManagedToolchainRole.ANVIL)
    if mutation == "other-tool":
        path = material.executable_for(ManagedToolchainRole.SEMGREP)
    content = path.read_bytes()
    if mutation == "same-bytes-replacement":
        path.rename(tmp_path / "retained-original")
        path.write_bytes(content)
        path.chmod(0o500)
    elif mutation == "linked":
        path.rename(tmp_path / "retained-original")
        path.symlink_to(tmp_path / "retained-original")
    else:
        path.chmod(0o700)
        path.write_bytes(content + b"changed\n")
        path.chmod(0o500)
    with pytest.raises(ValueError):
        launcher.start(config, repository, private, time.monotonic() + 3)
    assert not list(private.iterdir())


@pytest.mark.parametrize("root", ["repository", "private"])
@pytest.mark.parametrize("ancestor", [False, True])
def test_prepared_anvil_rejects_material_root_overlap_before_workspace(
    prepared, monkeypatch, root, ancestor
):
    repository, material, private, config = prepared
    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    _stop_before_copy(monkeypatch)
    overlapping = material.directory.parent if ancestor else material.directory
    with pytest.raises(ValueError, match="overlap"):
        launcher.start(
            config,
            overlapping if root == "repository" else repository,
            overlapping if root == "private" else private,
            time.monotonic() + 3,
        )
    assert not list(private.iterdir())


def test_legacy_clean_anvil_still_requires_its_explicit_environment(prepared):
    repository, _, private, config = prepared
    launcher = clean_chain.TrustedCleanAnvilLauncher(environment={})
    with pytest.raises(ValueError, match="environment variable is missing"):
        launcher.start(config, repository, private, time.monotonic() + 3)
    assert not list(private.iterdir())


@pytest.mark.parametrize("config", [object(), {}, "synthetic"])
def test_prepared_anvil_requires_an_exact_clean_state_type(prepared, monkeypatch, config):
    repository, material, private, _ = prepared
    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    _stop_before_copy(monkeypatch)
    with pytest.raises(ValueError, match="prepared clean-state selection"):
        launcher.start(config, repository, private, time.monotonic() + 3)
    assert not list(private.iterdir())


def test_prepared_anvil_refuses_a_private_root_alias(prepared, monkeypatch, tmp_path):
    repository, material, private, config = prepared
    alias = tmp_path / "private-alias"
    alias.symlink_to(private, target_is_directory=True)
    launcher = clean_chain.TrustedCleanAnvilLauncher(host_tools=material)
    _stop_before_copy(monkeypatch)
    with pytest.raises(ValueError, match="private root is not canonical"):
        launcher.start(config, repository, alias, time.monotonic() + 3)
    assert not list(private.iterdir())
