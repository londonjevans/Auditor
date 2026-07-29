from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import stat
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import RepositoryCleanForkMatrixStateConfig
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.scanners.clean_chain import (
    CleanAnvilUnavailableError,
    TrustedCleanAnvilLauncher,
    _ExecutableIdentity,
    _observe_pristine_head,
    _process_group_exists,
    _process_owns_loopback_listener,
    _runtime_executable_matches,
)

_PINNED_ANVIL = Path("/Users/josevans/.foundry/bin/anvil")
_PINNED_ANVIL_VERSION = "anvil Version: 1.3.2-stable"
_PINNED_ANVIL_SHA256 = "80ff77a2dfe71fac6bd9810d942c4f1b0447e42f4c086956417d9e63f5f7f0d3"
_SYNTHETIC_SECRET_CANARY = "clean-chain-integration-secret-canary"


class _RecordingProcessFactory:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, Any], subprocess.Popen[bytes]]] = []

    def __call__(self, args: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(args, **kwargs)
        self.calls.append((tuple(args), dict(kwargs), process))
        return process


def _require_pinned_local_anvil() -> Path:
    try:
        metadata = _PINNED_ANVIL.lstat()
        resolved = _PINNED_ANVIL.resolve(strict=True)
    except OSError:
        pytest.skip("the exact trusted local Anvil integration binary is unavailable")
    if (
        resolved != _PINNED_ANVIL
        or _PINNED_ANVIL.is_symlink()
        or _PINNED_ANVIL.is_junction()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or hashlib.sha256(_PINNED_ANVIL.read_bytes()).hexdigest() != _PINNED_ANVIL_SHA256
    ):
        pytest.skip("the exact trusted local Anvil integration binary is not installed")
    return resolved


def _require_local_lifecycle_capability() -> None:
    if platform.system() not in {"Darwin", "Linux"}:
        pytest.skip("PID-bound local listener attribution is unavailable on this platform")
    if platform.system() == "Darwin":
        lsof = Path("/usr/sbin/lsof")
        try:
            metadata = lsof.lstat()
        except OSError:
            pytest.skip("the trusted Darwin listener-attribution tool is unavailable")
        if (
            lsof.resolve(strict=True) != lsof
            or lsof.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            pytest.skip("the trusted Darwin listener-attribution tool is unavailable")
        if not hasattr(os, "chflags") or getattr(stat, "UF_IMMUTABLE", 0) == 0:
            pytest.skip("Darwin immutable executable-path binding is unavailable")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
    except OSError:
        pytest.skip("the managed environment denies numeric-loopback listener creation")


def _config() -> RepositoryCleanForkMatrixStateConfig:
    return RepositoryCleanForkMatrixStateConfig(
        state_id="clean-local",
        expected_chain_id=31_337,
        anvil_executable_env="MMAUDIT_ANVIL_EXECUTABLE",
        anvil_version=_PINNED_ANVIL_VERSION,
        anvil_sha256=_PINNED_ANVIL_SHA256,
        hardfork="cancun",
        genesis_timestamp=1_700_000_000,
        startup_timeout_seconds=8.0,
        shutdown_timeout_seconds=3.0,
    )


def test_real_trusted_clean_anvil_lifecycle_is_pid_and_state_bound(
    tmp_path: Path,
) -> None:
    anvil = _require_pinned_local_anvil()
    _require_local_lifecycle_capability()
    repository = tmp_path / "synthetic-target"
    repository.mkdir(mode=0o755)
    (repository / "foundry.toml").write_text(
        '[profile.default]\neth_rpc_url = "http://127.0.0.1:1"\n',
        encoding="utf-8",
    )
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    repository = repository.resolve(strict=True)
    private = private.resolve(strict=True)
    factory = _RecordingProcessFactory()
    launcher = TrustedCleanAnvilLauncher(
        environment={
            "MMAUDIT_ANVIL_EXECUTABLE": str(anvil),
            "OPENROUTER_API_KEY": _SYNTHETIC_SECRET_CANARY,
            "FOUNDRY_CONFIG": str(repository / "foundry.toml"),
            "ETH_RPC_URL": "http://127.0.0.1:1",
            "SSH_AUTH_SOCK": str(repository / "synthetic-agent"),
        },
        process_factory=factory,
    )

    lease = launcher.start(
        _config(),
        repository,
        private,
        time.monotonic() + 12,
    )
    assert len(factory.calls) == 2
    version_command, version_options, version_process = factory.calls[0]
    node_command, node_options, node_process = factory.calls[1]
    copied_executable = Path(node_command[0])
    executable_identity = _ExecutableIdentity.from_stat(copied_executable.stat())
    endpoint = lease.endpoint
    process_group_id = node_process.pid
    try:
        assert version_process.poll() is not None
        assert not _process_group_exists(version_process.pid)
        assert _process_owns_loopback_listener(
            node_process,
            host="127.0.0.1",
            port=int(endpoint.rsplit(":", maxsplit=1)[1]),
            deadline=time.monotonic() + 1,
        )
        assert _runtime_executable_matches(node_process, executable_identity)
        head = _observe_pristine_head(endpoint, timeout_seconds=1)
        assert head.block_number == 0
        assert head.block_hash == lease.initial_observation.block_hash
        assert len(head.state_root) == 66
        assert lease.reobserve() == lease.initial_observation

        forbidden_arguments = {
            "--fork-url",
            "--fork-block-number",
            "--state",
            "--load-state",
            "--dump-state",
            "--init",
            "--config-out",
            "--ipc",
            "--mnemonic",
            "--auto-impersonate",
        }
        assert forbidden_arguments.isdisjoint(node_command)
        assert version_command == (str(copied_executable), "--version")
        assert node_options["cwd"] == str(private / "clean-anvil" / "work")
        assert version_options["env"] == node_options["env"]
        child_environment = node_options["env"]
        assert set(child_environment) == {
            "HOME",
            "LANG",
            "LC_ALL",
            "NO_COLOR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "TZ",
            "XDG_CACHE_HOME",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
        }
        serialized_child_input = json.dumps(
            {
                "command": node_command,
                "cwd": node_options["cwd"],
                "environment": child_environment,
            },
            sort_keys=True,
        )
        assert str(repository) not in serialized_child_input
        assert str(repository / "foundry.toml") not in serialized_child_input
        assert _SYNTHETIC_SECRET_CANARY not in serialized_child_input
        assert node_options["shell"] is False
        assert node_options["close_fds"] is True
        assert node_options["start_new_session"] is True
    finally:
        lease.stop(time.monotonic() + 4)

    evidence = lease.attestation()
    assert evidence.execution_evidence is ExecutionEvidenceKind.REAL
    assert evidence.listener_owner_pid_bound is True
    assert evidence.runtime_executable_matches_pinned_copy is True
    assert evidence.version_probe_process_group_absent is True
    assert evidence.genesis_block_number == 0
    assert evidence.initial_head_block_number == 0
    assert evidence.final_head_block_number == 0
    assert evidence.initial_head_block_hash == evidence.genesis_block_hash
    assert evidence.final_head_block_hash == evidence.genesis_block_hash
    assert evidence.initial_head_state_root == evidence.final_head_state_root
    assert evidence.pristine_head_pre_post_match is True
    assert evidence.process_group_absent is True
    assert evidence.collector_threads_closed is True
    assert evidence.executable_descriptor_closed is True
    assert evidence.private_workspace_removed is True
    assert evidence.ancestor_config_absent is True
    assert evidence.no_upstream_fork_configuration is True
    assert evidence.target_arguments_inherited is False
    assert evidence.target_environment_inherited is False
    assert evidence.fork_or_state_arguments_present is False
    assert evidence.target_state_input_present is False
    assert node_process.poll() is not None
    assert not _process_group_exists(process_group_id)
    assert not copied_executable.exists()
    assert not (private / "clean-anvil").exists()
    with pytest.raises(CleanAnvilUnavailableError, match="no longer available"):
        _ = lease.endpoint
