"""Bounded local materialization and no-overwrite/no-execution invariants."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from mmaudit.orchestration import managed_host_tools as material
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainRole,
    load_packaged_managed_toolchain_bundle,
    required_managed_toolchain_roles,
)
from mmaudit.scanners.base import scanner_workspace_sha256
from tests.host_tool_material_support import setup_host_material_inputs


@pytest.fixture(autouse=True)
def forbid_execution_and_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> Any:
        pytest.fail("invariant: tool materialization must not execute or access a network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(material.scanner_base.shutil, "which", forbidden)


def test_materializes_exact_selected_host_files_and_detached_consumer_config(
    tmp_path, config_factory
):
    config = config_factory(
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={"isolation_backend": "bubblewrap"},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    before_config = config.model_dump(mode="json")
    before_source = scanner_workspace_sha256(repository)
    result = material.materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )

    assert result.action == "CREATED"
    assert result.config.scanners.semgrep.sha256 is not None
    assert result.config.scanners.semgrep.version == "1.2.3"
    assert config.model_dump(mode="json") == before_config
    assert scanner_workspace_sha256(repository) == before_source
    assert result.manifest.required_roles == required_managed_toolchain_roles(config)
    assert {item.role for item in result.manifest.files} == {
        ManagedToolchainRole.SEMGREP,
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.BUBBLEWRAP,
    }
    assert {path.name for path in result.directory.iterdir()} == {
        "semgrep",
        "python3",
        "git",
        "bwrap",
        "host-tool-material.json",
    }
    assert stat.S_IMODE(result.directory.stat().st_mode) == 0o700
    for item in result.manifest.files:
        path = result.executable_for(item.role)
        assert path.read_bytes() == (store / f"{item.sha256}.blob").read_bytes()
        assert stat.S_IMODE(path.stat().st_mode) == 0o500
        assert path.stat().st_nlink == 1
        assert path.stat().st_uid == os.geteuid()
    assert result.runtime_authority is result.managed_run_ready is False
    assert all(getattr(result.manifest, name) is False for name in material._AUTHORITY_FIELDS)
    detached = result.config
    detached.scanners.semgrep.sha256 = "a" * 64
    assert result.config.scanners.semgrep.sha256 != "a" * 64
    with pytest.raises(material.ManagedHostToolError, match="no selected direct host material"):
        result.executable_for(ManagedToolchainRole.SOLC)


@pytest.mark.parametrize("verify_only", [False, True])
def test_repeat_without_source_store_verifies_exact_bytes_without_overwrite(
    tmp_path, config_factory, verify_only
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(bundle=bundle, config=config, repository=repository, output_root=output)
    result = material.materialize_managed_host_tools(
        **arguments,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    identities = {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
        for path in result.directory.iterdir()
    }
    repeated = material.materialize_managed_host_tools(
        **arguments,
        source=material.ManagedHostToolSource(),
        verify_only=verify_only,
    )
    assert repeated.action == "VERIFIED_EXISTING"
    assert repeated.manifest == result.manifest
    assert repeated.config == result.config
    assert identities == {
        path.name: (path.stat().st_ino, path.stat().st_mtime_ns, path.read_bytes())
        for path in result.directory.iterdir()
    }


@pytest.mark.parametrize("with_store", [False, True])
def test_verify_only_cannot_create_any_output(tmp_path, config_factory, with_store):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(
            bundle=bundle,
            config=config,
            repository=repository,
            output_root=output,
            source=material.ManagedHostToolSource(blob_root=store if with_store else None),
            verify_only=True,
        )
    assert list(output.iterdir()) == []


def test_unresolved_required_host_roles_fail_before_output_creation(tmp_path, config_factory):
    config = config_factory()
    repository, store, output, _ = setup_host_material_inputs(tmp_path, config)
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(
            bundle=load_packaged_managed_toolchain_bundle(),
            config=config,
            repository=repository,
            output_root=output,
            source=material.ManagedHostToolSource(blob_root=store),
        )
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("damage", ["bytes", "manifest", "missing", "extra", "mode", "hardlink"])
def test_corrupt_or_incomplete_existing_material_is_not_repaired_or_returned(
    tmp_path, config_factory, damage
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    result = material.materialize_managed_host_tools(**arguments)
    target = result.executable_for(ManagedToolchainRole.GIT)
    if damage == "bytes":
        target.chmod(0o700)
        target.write_bytes(b"different inert material\n")
        target.chmod(0o500)
    elif damage == "manifest":
        (result.directory / "host-tool-material.json").write_text("{}\n")
    elif damage == "missing":
        target.unlink()
    elif damage == "extra":
        (result.directory / "extra").write_bytes(b"inert\n")
    elif damage == "mode":
        target.chmod(0o700)
    else:
        os.link(target, output / "shared")
    before = {
        path.name: (path.lstat().st_ino, path.read_bytes()) for path in result.directory.iterdir()
    }
    with pytest.raises(material.ManagedHostToolError):
        result.executable_for(ManagedToolchainRole.PYTHON_RUNTIME)
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(**arguments)
    after = {
        path.name: (path.lstat().st_ino, path.read_bytes()) for path in result.directory.iterdir()
    }
    assert after == before


@pytest.mark.parametrize("field", material._AUTHORITY_FIELDS)
@pytest.mark.parametrize("value", [True, 0, "false"])
def test_manifest_cannot_promote_material_into_authority(tmp_path, config_factory, field, value):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    result = material.materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    payload = result.manifest.model_dump(mode="json")
    payload[field] = value
    payload["manifest_sha256"] = material.canonical_sha256(
        {key: item for key, item in payload.items() if key != "manifest_sha256"}
    )
    with pytest.raises(ValueError, match="cannot grant trust"):
        material.ManagedHostToolManifest.model_validate_json(json.dumps(payload), strict=True)


@pytest.mark.parametrize("value", [0, -1, True, 1.5, 8 * 1024**3 + 1])
@pytest.mark.parametrize("name", ["max_file_bytes", "max_total_bytes"])
def test_local_disk_limits_are_strict_and_hard_bounded(name, value):
    with pytest.raises(ValueError):
        material.ManagedHostToolLimits.model_validate({name: value}, strict=True)


@pytest.mark.parametrize("name", ["max_file_bytes", "max_total_bytes"])
def test_selected_limits_apply_before_creating_material_and_to_repeated_reads(
    tmp_path, config_factory, name
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(bundle=bundle, config=config, repository=repository, output_root=output)
    small = material.ManagedHostToolSource(
        blob_root=store, limits=material.ManagedHostToolLimits.model_validate({name: 1})
    )
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(**arguments, source=small)
    assert list(output.iterdir()) == []
    original = material.materialize_managed_host_tools(
        **arguments, source=material.ManagedHostToolSource(blob_root=store)
    )
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(**arguments, source=small, verify_only=True)
    original.verify()


@pytest.mark.parametrize(
    "invalid",
    [
        "source-is-repository",
        "source-is-output",
        "output-in-repository",
        "source-link",
        "output-link",
        "public-output",
        "relative-output",
    ],
)
def test_provisioning_roots_are_private_unlinked_and_disjoint(tmp_path, config_factory, invalid):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    selected_source, selected_output = store, output
    if invalid == "source-is-repository":
        selected_source = repository
    elif invalid == "source-is-output":
        selected_source = output
    elif invalid == "output-in-repository":
        selected_output = repository / "tools"
        selected_output.mkdir(mode=0o700)
    elif invalid == "source-link":
        selected_source = tmp_path / "source-alias"
        selected_source.symlink_to(store, target_is_directory=True)
    elif invalid == "output-link":
        selected_output = tmp_path / "output-alias"
        selected_output.symlink_to(output, target_is_directory=True)
    elif invalid == "public-output":
        output.chmod(0o755)
    else:
        selected_output = Path("host-output")
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(
            bundle=bundle,
            config=config,
            repository=repository,
            output_root=selected_output,
            source=material.ManagedHostToolSource(blob_root=selected_source),
        )
    assert list(output.iterdir()) == []


@pytest.mark.parametrize("invalid", ["missing", "symlink", "hardlink", "fifo", "digest"])
def test_bad_supplied_blob_never_publishes_a_manifest_and_partial_output_is_not_reset(
    tmp_path, config_factory, invalid
):
    if invalid == "fifo" and not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs unavailable")
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    python = next(
        member for member in bundle.members if member.role is ManagedToolchainRole.PYTHON_RUNTIME
    )
    target = store / f"{python.sha256}.blob"
    original = target.read_bytes()
    if invalid == "missing":
        target.unlink()
    elif invalid == "symlink":
        renamed = store / "synthetic-source"
        target.rename(renamed)
        target.symlink_to(renamed)
    elif invalid == "hardlink":
        os.link(target, store / "shared-synthetic-source")
    elif invalid == "fifo":
        target.unlink()
        os.mkfifo(target, mode=0o600)
    else:
        target.write_bytes(b"x" * len(original))
    arguments = dict(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(**arguments)
    assert not list(output.glob("*/host-tool-material.json"))
    if invalid != "digest":
        assert list(output.iterdir()) == []
    else:
        partial = next(output.iterdir())
        assert (partial / "git").is_file()
        original_identity = (partial / "git").stat().st_ino
        target.write_bytes(original)
        with pytest.raises(material.ManagedHostToolError):
            material.materialize_managed_host_tools(**arguments)
        assert (partial / "git").stat().st_ino == original_identity
        assert not (partial / "host-tool-material.json").exists()


@pytest.mark.parametrize("changed", ["bundle", "config", "version", "digest"])
def test_coherently_rehashed_manifest_cannot_change_the_exact_selection(
    tmp_path, config_factory, monkeypatch, changed
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    arguments = dict(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    result = material.materialize_managed_host_tools(**arguments)
    payload = result.manifest.model_dump(mode="json")
    if changed in {"bundle", "config"}:
        key = "source_bundle_sha256" if changed == "bundle" else "effective_config_sha256"
        payload[key] = "a" * 64
    else:
        payload["files"][0]["version" if changed == "version" else "sha256"] = (
            "9.9.9" if changed == "version" else "a" * 64
        )
    payload["manifest_sha256"] = material.canonical_sha256(
        {key: value for key, value in payload.items() if key != "manifest_sha256"}
    )
    (result.directory / "host-tool-material.json").write_text(material.stable_json(payload))

    def forbidden_tools(*args, **kwargs):
        pytest.fail("invariant: wrong selection must fail before observing material tools")

    monkeypatch.setattr(material, "_verify_tool_files", forbidden_tools)
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(**arguments)


def test_image_requirements_remain_explicit_without_being_materialized_or_attested(
    tmp_path, config_factory
):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False},
        formal={"enabled": False},
        scanners={"hardhat_fork": {"enabled": True, "required": True}},
        reproduction={"enabled": False, "isolation_backend": "auto"},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    result = material.materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    assert ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE in result.manifest.required_roles
    assert all(
        item.role is not ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
        for item in result.manifest.files
    )
    assert result.manifest.image_side_attestation_verified is False
    assert result.manifest.installed_members_verified is False
    assert result.manifest.managed_run_ready is False
    with pytest.raises(material.ManagedHostToolError, match="no selected direct host material"):
        result.executable_for(ManagedToolchainRole.HARDHAT_IMAGE_NODE)


@pytest.mark.parametrize(
    "role,locator",
    [
        ("rootless-toolchain-image", "docker"),
        ("hardhat-image-node", "node"),
        ("git", "python3"),
        ("git", "../git"),
        ("git", "/usr/bin/git"),
    ],
)
def test_runtime_and_exported_schema_reject_invalid_host_role_locator_joins(role, locator):
    values = dict(role=role, locator=locator, version="1.2.3", sha256="a" * 64, size=1)
    with pytest.raises(ValueError):
        material.ManagedHostToolFile.model_validate_json(json.dumps(values), strict=True)
    validator = Draft202012Validator(material.ManagedHostToolFile.model_json_schema())
    assert list(validator.iter_errors(values))


def test_earlier_file_change_and_restore_during_later_verification_is_refused(
    tmp_path, config_factory, monkeypatch
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    result = material.materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=material.ManagedHostToolSource(blob_root=store),
    )
    earlier = result.directory / result.manifest.files[0].locator
    original_content = earlier.read_bytes()
    real_observe = material.scanner_base._observe_scanner_executable
    changed = False

    def mutate_during_later_file(path: Path):
        nonlocal changed
        observed = real_observe(path)
        if path != earlier and not changed:
            earlier.chmod(0o700)
            earlier.write_bytes(b"different inert content\n")
            earlier.write_bytes(original_content)
            earlier.chmod(0o500)
            changed = True
        return observed

    monkeypatch.setattr(
        material.scanner_base, "_observe_scanner_executable", mutate_during_later_file
    )
    with pytest.raises(material.ManagedHostToolError):
        result.executable_for(ManagedToolchainRole.PYTHON_RUNTIME)
    assert changed
    assert earlier.read_bytes() == original_content


def test_output_root_replacement_cannot_redirect_or_publish_material(
    tmp_path, config_factory, monkeypatch
):
    config = config_factory()
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    moved = output.with_name("original-host-output")
    real_make_executable = material._make_private_executable
    replaced = False

    def replace_parent(descriptor, item):
        nonlocal replaced
        real_make_executable(descriptor, item)
        if not replaced:
            output.rename(moved)
            output.mkdir(mode=0o700)
            (output / "foreign-canary").write_bytes(b"preserve synthetic foreign material\n")
            replaced = True

    monkeypatch.setattr(material, "_make_private_executable", replace_parent)
    with pytest.raises(material.ManagedHostToolError):
        material.materialize_managed_host_tools(
            bundle=bundle,
            config=config,
            repository=repository,
            output_root=output,
            source=material.ManagedHostToolSource(blob_root=store),
        )
    assert replaced
    assert (output / "foreign-canary").read_bytes() == b"preserve synthetic foreign material\n"
    assert not list(output.glob("*/host-tool-material.json"))
    assert not list(moved.glob("*/host-tool-material.json"))
