from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from mmaudit.config import ScannerConfig, SmartContractsConfig
from mmaudit.isolation.container import RootlessContainerBackend
from mmaudit.models.schemas import ExecutionEvidenceKind, ScannerStatus
from mmaudit.scanners.hardhat import HardhatForkScanner

_IMAGE = "registry.example/mmaudit-toolchain@sha256:" + "a" * 64


def _scanner() -> HardhatForkScanner:
    return HardhatForkScanner(
        SmartContractsConfig(allow_fork_probing=True),
        ScannerConfig(
            enabled=True,
            version="2.22.0",
            sha256="b" * 64,
        ),
    )


def _backend(*, supports_local_fork_rpc: bool = True) -> RootlessContainerBackend:
    return RootlessContainerBackend(
        executable="/usr/bin/podman",
        image=_IMAGE,
        runtime="podman",
        rootless_verified=True,
        host_uid=1000,
        host_gid=1000,
        supports_local_fork_rpc=supports_local_fork_rpc,
    )


def _target(tmp_path: Path, config: str = "export default { solidity: '0.8.20' };\n") -> Path:
    root = tmp_path / "target"
    root.mkdir()
    (root / "hardhat.config.ts").write_text(config, encoding="utf-8")
    (root / "package.json").write_text(
        '{"name":"synthetic-hardhat","private":true,"scripts":{"test":"hardhat test"}}\n',
        encoding="utf-8",
    )
    return root


def _forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> subprocess.Popen[bytes]:
        pytest.fail("Hardhat preflight must not start a subprocess")

    monkeypatch.setattr(subprocess, "Popen", fail)


def _attest_backend(monkeypatch: pytest.MonkeyPatch, backend: RootlessContainerBackend) -> None:
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat.isolation_execution_evidence",
        lambda observed: (
            ExecutionEvidenceKind.REAL if observed is backend else ExecutionEvidenceKind.UNVERIFIED
        ),
    )
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat.isolation_attestation_sha256",
        lambda observed: "c" * 64 if observed is backend else None,
    )


def test_missing_backend_is_unavailable_before_target_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    _forbid_subprocess(monkeypatch)
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat._target_configuration_error",
        lambda _root: pytest.fail("unqualified isolation must stop before target inspection"),
    )

    run = _scanner().run(root, tmp_path / "private", 1, backend=None)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert "exact digest-pinned rootless" in (run.error or "")
    assert run.execution_observation_sha256 == run.expected_execution_observation_sha256()


def test_self_asserted_or_non_fork_backend_is_unavailable_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    _forbid_subprocess(monkeypatch)
    backend = _backend(supports_local_fork_rpc=False)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert "process-attested REAL provenance" in (run.error or "")
    assert not (root / "repository-config-executed.marker").exists()


def test_missing_rpc_is_unavailable_before_target_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _backend()
    _attest_backend(monkeypatch, backend)
    _forbid_subprocess(monkeypatch)
    monkeypatch.delenv("MMAUDIT_FORK_RPC_URL", raising=False)
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat._target_configuration_error",
        lambda _root: pytest.fail("missing RPC must stop before target inspection"),
    )

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert "MMAUDIT_FORK_RPC_URL is not set" in (run.error or "")


@pytest.mark.parametrize(
    "unsafe_config",
    [
        "export default { networks: { live: { url: 'http://example.invalid' } } };\n",
        "import { execSync } from 'node:child_process';\nexport default {};\n",
        "const key = process.env.PRIVATE_KEY;\nexport default {};\n",
        "task('synthetic-hook', async () => {});\nexport default {};\n",
    ],
)
def test_unsafe_target_configuration_fails_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_config: str,
) -> None:
    root = _target(tmp_path, unsafe_config)
    backend = _backend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setattr(
        RootlessContainerBackend,
        "approved_loopback_rpc_port",
        8545,
        raising=False,
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.FAILED
    assert "prohibited" in (run.error or "") or "wallet" in (run.error or "")
    assert not (root / "repository-config-executed.marker").exists()


@pytest.mark.parametrize(
    "package_json",
    [
        ('{"name":"synthetic-hardhat","private":true,"scripts":{"postinstall":"node setup.js"}}\n'),
        (
            '{"name":"synthetic-hardhat","private":true,'
            '"scripts":{"test":"hardhat test --network live"}}\n'
        ),
        ('{"name":"synthetic-hardhat","private":true,"devDependencies":{"shelljs":"1.0.0"}}\n'),
        ('{"name":"synthetic-hardhat","private":true,"wallet":{"privateKey":"synthetic-value"}}\n'),
    ],
)
def test_unsafe_package_hooks_and_wallet_options_fail_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    package_json: str,
) -> None:
    root = _target(tmp_path)
    (root / "package.json").write_text(package_json, encoding="utf-8")
    backend = _backend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setattr(
        RootlessContainerBackend,
        "approved_loopback_rpc_port",
        8545,
        raising=False,
    )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.FAILED
    assert "Hardhat package" in (run.error or "")


def test_current_rootless_backend_never_silently_enables_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _backend(supports_local_fork_rpc=False)
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert "cannot reach one approved loopback" in (run.error or "")
