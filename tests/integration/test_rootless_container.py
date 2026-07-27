from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from mmaudit.isolation.container import (
    discover_rootless_container_backend,
    rootless_runtime_environment,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "solidity"


def test_real_rootless_container_enforces_read_only_source_and_private_output(
    tmp_path: Path,
) -> None:
    image = os.environ.get("MMAUDIT_TEST_ROOTLESS_IMAGE")
    if image is None:
        pytest.skip("MMAUDIT_TEST_ROOTLESS_IMAGE is not configured")
    backend = discover_rootless_container_backend(image)
    if backend is None:
        pytest.skip("no verified rootless Docker or Podman runtime is available")

    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    source = workspace / "source.txt"
    source.write_text("immutable synthetic input\n", encoding="utf-8")
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    writable = backend.writable_path(private)
    command = backend.wrap(
        [
            "/bin/sh",
            "-c",
            (
                "test -r source.txt; "
                "if printf changed >> source.txt 2>/dev/null; then exit 30; fi; "
                'test "$HOME" = /home/mmaudit; '
                'test -z "${OPENROUTER_API_KEY+x}"; '
                "test ! -e /var/run/docker.sock; "
                "printf isolated > /mmaudit-output/result.txt"
            ),
        ],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        cwd=workspace,
        env=rootless_runtime_environment(private / "runtime-client"),
        shell=False,
    )
    try:
        assert result.returncode == 0, result.stdout + result.stderr
        assert (writable / "result.txt").read_text(encoding="utf-8") == "isolated"
        assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash
    finally:
        backend.cleanup(private)
    assert not (private / "container-runtime" / "container.cid").exists()


def test_real_rootless_container_contains_synthetic_hardhat_configuration(
    tmp_path: Path,
) -> None:
    image = os.environ.get("MMAUDIT_TEST_ROOTLESS_IMAGE")
    if image is None:
        pytest.skip("MMAUDIT_TEST_ROOTLESS_IMAGE is not configured")
    backend = discover_rootless_container_backend(image)
    if backend is None:
        pytest.skip("no verified rootless Docker or Podman runtime is available")

    source_fixture = FIXTURES / "hardhat_isolation"
    private = tmp_path / "private-hardhat"
    workspace = private / "workspace"
    shutil.copytree(source_fixture, workspace)
    command = backend.wrap_repository_javascript(
        [
            "/bin/sh",
            "-c",
            "command -v node >/dev/null 2>&1 || exit 77; node hardhat.config.js",
        ],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    assert str(source_fixture.resolve()) not in " ".join(command)
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=workspace,
            env=rootless_runtime_environment(private / "runtime-client"),
            shell=False,
        )
    finally:
        backend.cleanup(private)
    if result.returncode == 77:
        pytest.skip("configured rootless image does not contain Node.js")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (workspace / "repository-config-executed.marker").is_file()
    assert not (source_fixture / "repository-config-executed.marker").exists()
    assert not (private / "container-runtime" / "container.cid").exists()
