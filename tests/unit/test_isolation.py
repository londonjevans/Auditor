from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import ReproductionConfig
from mmaudit.isolation.container import (
    RootlessContainerBackend,
    RootlessContainerLimits,
    discover_rootless_container_backend,
    isolation_host_environment,
    rootless_runtime_environment,
)
from mmaudit.isolation.repository_code import contains_hardhat_repository_code

_IMAGE = "registry.example/mmaudit-toolchain@sha256:" + "a" * 64


def _backend(**updates: object) -> RootlessContainerBackend:
    values: dict[str, object] = {
        "executable": "/usr/bin/podman",
        "image": _IMAGE,
        "runtime": "podman",
        "rootless_verified": True,
        "host_uid": 1000,
        "host_gid": 1000,
    }
    values.update(updates)
    return RootlessContainerBackend(**values)  # type: ignore[arg-type]


def test_rootless_container_configuration_requires_digest_pin() -> None:
    with pytest.raises(ValidationError, match="digest-pinned"):
        ReproductionConfig(isolation_backend="rootless-container")
    with pytest.raises(ValidationError, match="lowercase sha256"):
        ReproductionConfig(
            isolation_backend="rootless-container",
            rootless_container_image="registry.example/toolchain:latest",
        )

    config = ReproductionConfig(
        isolation_backend="rootless-container",
        rootless_container_runtime="podman",
        rootless_container_image=_IMAGE,
    )
    assert config.rootless_container_image == _IMAGE
    assert config.rootless_container_runtime == "podman"


def test_container_dockerfile_requires_operator_supplied_base_reference() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.startswith("ARG MMAUDIT_BASE_IMAGE\nFROM ${MMAUDIT_BASE_IMAGE}\n")
    assert "FROM python:" not in dockerfile


def test_rootless_backend_discovery_requires_verified_non_repository_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = tmp_path / "podman"
    runtime.write_text("synthetic runtime marker\n", encoding="utf-8")
    monkeypatch.setattr("mmaudit.isolation.container.shutil.which", lambda _: str(runtime))
    monkeypatch.setattr("mmaudit.isolation.container.os.getuid", lambda: 1000, raising=False)
    monkeypatch.setattr("mmaudit.isolation.container.os.getgid", lambda: 1000, raising=False)
    monkeypatch.setattr("mmaudit.isolation.container._runtime_is_rootless", lambda *_: False)
    assert discover_rootless_container_backend(_IMAGE, runtime="podman") is None

    monkeypatch.setattr("mmaudit.isolation.container._runtime_is_rootless", lambda *_: True)
    backend = discover_rootless_container_backend(_IMAGE, runtime="podman")
    assert backend is not None
    assert backend.rootless_verified
    assert backend.image == _IMAGE


def test_rootless_container_command_has_fixed_isolation_and_resource_controls(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = _backend(
        limits=RootlessContainerLimits(
            memory_bytes=536_870_912,
            cpu_count=0.5,
            pids=64,
            open_files=128,
        )
    )
    writable = backend.writable_path(private)
    command = backend.wrap(
        [
            "/usr/local/bin/forge",
            "test",
            "--root",
            str(workspace),
            "--cache-path",
            str(writable / "forge-cache"),
        ],
        workspace=workspace,
        private_dir=private,
        rpc_port=8545,
    )

    rendered = " ".join(command)
    assert command[:2] == ["/usr/bin/podman", "run"]
    assert command[command.index("--pull") : command.index("--pull") + 2] == ["--pull", "never"]
    assert command[command.index("--network") : command.index("--network") + 2] == [
        "--network",
        "none",
    ]
    assert "--read-only" in command
    assert command[command.index("--cap-drop") : command.index("--cap-drop") + 2] == [
        "--cap-drop",
        "ALL",
    ]
    assert "no-new-privileges" in command
    assert command[command.index("--pids-limit") : command.index("--pids-limit") + 2] == [
        "--pids-limit",
        "64",
    ]
    assert command[command.index("--memory") : command.index("--memory") + 2] == [
        "--memory",
        "536870912",
    ]
    assert command[command.index("--memory-swap") : command.index("--memory-swap") + 2] == [
        "--memory-swap",
        "536870912",
    ]
    assert command[command.index("--cpus") : command.index("--cpus") + 2] == ["--cpus", "0.5"]
    assert command[command.index("--user") : command.index("--user") + 2] == [
        "--user",
        "1000:1000",
    ]
    assert f"src={workspace.resolve()},dst=/workspace,readonly" in rendered
    assert f"src={writable.resolve()},dst=/mmaudit-output,rw" in rendered
    assert "HOME=/home/mmaudit" in command
    assert "/home/mmaudit:rw,noexec,nosuid,nodev" in rendered
    assert "/tmp:rw,noexec,nosuid,nodev" in rendered
    assert command[command.index("--entrypoint") + 1] == "forge"
    assert "/workspace" in command
    assert "/mmaudit-output/forge-cache" in command
    assert _IMAGE in command
    assert "docker.sock" not in rendered
    assert str(Path.home()) not in rendered
    assert all(
        token not in rendered
        for token in (
            "OPENROUTER_API_KEY",
            "MMAUDIT_SECRETS_ENV_FILE",
            "AWS_SECRET_ACCESS_KEY",
            ".docker/config.json",
        )
    )

    seccomp_path = Path(command[command.index("no-new-privileges") + 2].removeprefix("seccomp="))
    profile = json.loads(seccomp_path.read_text(encoding="utf-8"))
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    allowed = set(profile["syscalls"][0]["names"])
    assert {"read", "write", "execve"} <= allowed
    assert {
        "socket",
        "socketpair",
        "connect",
        "bind",
        "mount",
        "ptrace",
    }.isdisjoint(allowed)


def test_repository_javascript_uses_only_writable_disposable_workspace(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = _backend()

    command = backend.wrap_repository_javascript(
        ["node", "hardhat.config.js"],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )

    rendered = " ".join(command)
    source_mount = f"type=bind,src={workspace.resolve()},dst=/workspace"
    assert source_mount in command
    assert f"{source_mount},readonly" not in rendered
    assert "--read-only" in command
    assert command[command.index("--network") + 1] == "none"
    assert "HARDHAT_DISABLE_TELEMETRY_PROMPT=true" in command
    assert str(Path("tests/fixtures").resolve()) not in rendered


def test_hardhat_repository_code_detection_is_static_and_conservative(tmp_path: Path) -> None:
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "package.json").write_text(
        '{"name":"synthetic-clean","private":true}\n',
        encoding="utf-8",
    )
    assert not contains_hardhat_repository_code(clean)

    configured = tmp_path / "configured"
    configured.mkdir()
    (configured / "hardhat.config.cjs").write_text(
        "throw new Error('must not execute during static detection');\n",
        encoding="utf-8",
    )
    assert contains_hardhat_repository_code(configured)

    package_only = tmp_path / "package-only"
    package_only.mkdir()
    (package_only / "package.json").write_text(
        '{"devDependencies":{"@nomicfoundation/hardhat-toolbox":"0.0.0-synthetic"}}\n',
        encoding="utf-8",
    )
    assert contains_hardhat_repository_code(package_only)


def test_rootless_container_rejects_unmounted_host_paths_and_root_execution(
    tmp_path: Path,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = _backend()

    with pytest.raises(ValueError, match="outside isolated mounts"):
        backend.wrap(
            ["/usr/bin/tool", str(tmp_path / "host-input")],
            workspace=workspace,
            private_dir=private,
            rpc_port=1,
        )
    with pytest.raises(ValueError, match="non-root"):
        _backend(host_uid=0)
    with pytest.raises(ValueError, match="sha256 digest"):
        _backend(image="registry.example/toolchain:latest")


def test_rootless_container_cleanup_force_removes_and_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private = tmp_path / "private"
    workspace = private / "workspace"
    workspace.mkdir(parents=True)
    backend = _backend()
    backend.wrap(
        ["/usr/bin/tool"],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    cidfile = private / "container-runtime" / "container.cid"
    cidfile.write_text("a" * 64, encoding="utf-8")
    calls: list[list[str]] = []
    results = iter((0, 0, 1))

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(command)
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(command, next(results), "", "")

    monkeypatch.setattr("mmaudit.isolation.container.subprocess.run", fake_run)
    backend.cleanup(private)

    assert calls[0][-2:] == ["inspect", "a" * 64]
    assert calls[1][-3:] == ["rm", "--force", "a" * 64]
    assert calls[2] == calls[0]
    assert not cidfile.exists()


def test_rootless_runtime_environment_omits_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///run/user/1000/docker.sock")
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-secret")
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", "/synthetic/operator.env")
    monkeypatch.setenv("DOCKER_CONFIG", "/synthetic/credential-store")
    monkeypatch.setenv("REGISTRY_AUTH_FILE", "/synthetic/auth.json")

    environment = rootless_runtime_environment(tmp_path)

    assert environment["DOCKER_HOST"] == "unix:///run/user/1000/docker.sock"
    assert "OPENROUTER_API_KEY" not in environment
    assert "MMAUDIT_SECRETS_ENV_FILE" not in environment
    assert "DOCKER_CONFIG" not in environment
    assert "REGISTRY_AUTH_FILE" not in environment


def test_backend_host_environment_cannot_reintroduce_control_plane_secrets(
    tmp_path: Path,
) -> None:
    class UnsafeBackend:
        def host_environment(self, _private_dir: Path) -> dict[str, str]:
            return {
                "PATH": "/trusted/bin",
                "OPENROUTER_API_KEY": "synthetic-canary",
                "MMAUDIT_SECRETS_ENV_FILE": "/synthetic/operator.env",
            }

    environment = isolation_host_environment(
        UnsafeBackend(),
        tmp_path,
        {"PATH": "/fallback/bin"},
    )

    assert environment == {"PATH": "/trusted/bin"}
