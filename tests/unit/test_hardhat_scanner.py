from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import NoReturn

import pytest
from pydantic import ValidationError

from mmaudit.config import (
    RepositoryForkSuiteConfig,
    ScannerConfig,
    SmartContractsConfig,
)
from mmaudit.isolation.container import RootlessContainerBackend
from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    HardhatReporterExecution,
    HardhatReporterInventory,
    HardhatReporterTestResult,
    RepositorySuiteFramework,
    RepositorySuiteSelection,
    RepositorySuiteTestDescriptor,
    RepositoryTestExecutionStatus,
    ScannerStatus,
)
from mmaudit.scanners.hardhat import (
    HardhatForkScanner,
    HardhatReporterError,
    parse_hardhat_execution_report,
    parse_hardhat_inventory_report,
    select_hardhat_repository_suite,
)

_IMAGE = "registry.example/mmaudit-toolchain@sha256:" + "a" * 64
_REPORTER_SHA256 = "d" * 64
_REPOSITORY_SHA256 = "e" * 64
_BLOCK_HASH = "0x" + ("f" * 64)
_SEED = "0x" + ("0" * 63) + "1"


class _MockHardhatLoopbackBackend:
    name = "mock-hardhat-loopback"
    image = _IMAGE
    rootless_verified = True
    approved_loopback_rpc_port = 8545
    hardhat_network_policy = "single-loopback-rpc"
    broad_network_enabled = False
    hardhat_loopback_capability_sha256 = "c" * 64

    def wrap_hardhat_fork_suite(
        self,
        command: list[str],
        *,
        workspace: Path,
        private_dir: Path,
        rpc_port: int,
    ) -> list[str]:
        del command, workspace, private_dir, rpc_port
        pytest.fail("mock capability preflight must not execute repository JavaScript")

    def writable_path(self, private_dir: Path) -> Path:
        return private_dir

    def cleanup(self, private_dir: Path) -> None:
        del private_dir

    def host_environment(self, private_dir: Path) -> dict[str, str]:
        del private_dir
        return {}


def _scanner() -> HardhatForkScanner:
    return HardhatForkScanner(
        SmartContractsConfig(
            allow_fork_probing=True,
            repository_suite=RepositoryForkSuiteConfig(
                profile="explicit",
                foundry_include_paths=(),
                foundry_include_tests=(),
                hardhat_include_paths=("test/audit/*.ts",),
                hardhat_include_tests=("*",),
            ),
        ),
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


def _descriptor(
    *,
    path: str = "test/audit/Vault.ts",
    suite_name: str = "Vault",
    test_name: str = "preserves accounting",
) -> RepositorySuiteTestDescriptor:
    return RepositorySuiteTestDescriptor.sealed(
        framework=RepositorySuiteFramework.HARDHAT,
        project_root=".",
        path=path,
        suite_name=suite_name,
        test_name=test_name,
        source_sha256="1" * 64,
        start_line=3,
        end_line=3,
    )


def _inventory(
    *descriptors: RepositorySuiteTestDescriptor,
) -> HardhatReporterInventory:
    return HardhatReporterInventory.sealed(
        reporter_version="1.0.0",
        reporter_sha256=_REPORTER_SHA256,
        repository_sha256=_REPOSITORY_SHA256,
        tests=tuple(sorted(descriptors or (_descriptor(),), key=lambda item: item.canonical_key)),
    )


def _forbid_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("Hardhat preflight must not start a process")

    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    monkeypatch.setattr(subprocess, "call", fail)
    monkeypatch.setattr(subprocess, "check_call", fail)
    monkeypatch.setattr(subprocess, "check_output", fail)
    monkeypatch.setattr(os, "system", fail)
    monkeypatch.setattr(os, "popen", fail)


def _attest_backend(monkeypatch: pytest.MonkeyPatch, backend: object) -> None:
    capability_sha256 = (
        backend.hardhat_loopback_capability_sha256
        if isinstance(backend, _MockHardhatLoopbackBackend)
        else None
    )
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
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat._hardhat_loopback_capability_attestation_sha256",
        lambda observed: capability_sha256 if observed is backend else None,
    )


def _selection_and_report(
    *descriptors: RepositorySuiteTestDescriptor,
    reporter_version: str = "1.0.0",
    reporter_sha256: str = _REPORTER_SHA256,
    repository_sha256: str = _REPOSITORY_SHA256,
    selection_sha256: str | None = None,
    chain_id: int = 31_337,
    block_number: int = 0,
    block_hash: str = _BLOCK_HASH,
    fuzz_seed: str = _SEED,
    result_overrides: dict[str, object] | None = None,
) -> tuple[RepositorySuiteSelection, HardhatReporterExecution]:
    selection = select_hardhat_repository_suite(
        _inventory(*(descriptors or (_descriptor(),))),
        _scanner().smart_contracts,
        repository_exclusion_path=".mmaudit",
    )
    results = []
    for descriptor in selection.tests:
        values: dict[str, object] = {
            "descriptor_sha256": descriptor.descriptor_sha256,
            "path": descriptor.path,
            "suite_name": descriptor.suite_name,
            "test_name": descriptor.test_name,
            "status": RepositoryTestExecutionStatus.PASSED,
            "duration_seconds": 0.25,
        }
        values.update(result_overrides or {})
        results.append(HardhatReporterTestResult.sealed(**values))
    report = HardhatReporterExecution.sealed(
        reporter_version=reporter_version,
        reporter_sha256=reporter_sha256,
        repository_sha256=repository_sha256,
        selection_sha256=selection_sha256 or selection.selection_sha256,
        chain_id=chain_id,
        block_number=block_number,
        block_hash=block_hash,
        fuzz_seed=fuzz_seed,
        results=tuple(sorted(results, key=lambda item: item.descriptor_sha256)),
    )
    return selection, report


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _reseal_payload(payload: dict[str, object], hash_field: str) -> dict[str, object]:
    resealed = {**payload, hash_field: "0" * 64}
    resealed[hash_field] = _canonical_sha256(
        {key: value for key, value in resealed.items() if key != hash_field}
    )
    return resealed


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
    assert "dedicated digest-pinned rootless" in (run.error or "")
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
    assert "current no-network RootlessContainerBackend" in (run.error or "")
    assert not (root / "repository-config-executed.marker").exists()


def test_missing_rpc_is_unavailable_before_target_inspection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
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
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
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
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
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
    assert "current no-network RootlessContainerBackend" in (run.error or "")


def test_mock_dedicated_capability_remains_unavailable_without_real_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
    assert run.repository_code_execution.value == "blocked"
    assert "no production single-loopback backend" in (run.error or "")


@pytest.mark.parametrize(
    ("attribute", "value", "expected_error"),
    [
        ("rootless_verified", False, "verified digest-pinned rootless"),
        ("image", "registry.example/mmaudit-toolchain:latest", "digest-pinned rootless"),
        ("hardhat_network_policy", "broad-network", "deny broad networking"),
        ("broad_network_enabled", True, "deny broad networking"),
        ("hardhat_loopback_capability_sha256", "invalid", "invalid single-loopback"),
    ],
)
def test_unattested_or_broad_backend_policy_is_rejected_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attribute: str,
    value: object,
    expected_error: str,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    setattr(backend, attribute, value)
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert expected_error in (run.error or "")
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize(
    ("missing_evidence", "expected_error"),
    [
        ("real", "process-attested REAL provenance"),
        ("process", "current process attestation"),
        ("capability", "process-bound attestation"),
    ],
)
def test_missing_process_attestation_is_rejected_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    missing_evidence: str,
    expected_error: str,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    if missing_evidence == "real":
        monkeypatch.setattr(
            "mmaudit.scanners.hardhat.isolation_execution_evidence",
            lambda _observed: ExecutionEvidenceKind.UNVERIFIED,
        )
    elif missing_evidence == "process":
        monkeypatch.setattr(
            "mmaudit.scanners.hardhat.isolation_attestation_sha256",
            lambda _observed: None,
        )
    else:
        monkeypatch.setattr(
            "mmaudit.scanners.hardhat._hardhat_loopback_capability_attestation_sha256",
            lambda _observed: "f" * 64,
        )
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert expected_error in (run.error or "")
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_unapproved_loopback_port_is_rejected_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    backend.approved_loopback_rpc_port = 9545
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.UNAVAILABLE
    assert "single-port loopback RPC capability" in (run.error or "")


@pytest.mark.parametrize(
    "rpc_url",
    [
        "https://127.0.0.1:8545",
        "http://synthetic-user:synthetic-password@127.0.0.1:8545",
        "http://example.invalid:8545",
        "http://127.0.0.1:8545/rpc",
        "http://127.0.0.1:8545/?key=value",
        "http://127.0.0.1",
    ],
)
def test_non_exact_loopback_rpc_is_rejected_without_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rpc_url: str,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", rpc_url)
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.FAILED
    assert "credential-free plain HTTP loopback" in (run.error or "")
    assert run.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


def test_missing_descriptor_relative_nofollow_support_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    monkeypatch.setattr(
        "mmaudit.scanners.hardhat._DESCRIPTOR_RELATIVE_OPEN_SUPPORTED",
        False,
    )
    _forbid_subprocess(monkeypatch)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert run.status is ScannerStatus.FAILED
    assert "could not be validated safely" in (run.error or "")


@pytest.mark.parametrize(
    ("target_name", "replacement_content"),
    [
        ("hardhat.config.ts", "export default {};\n"),
        ("package.json", '{"name":"outside","private":true}\n'),
    ],
)
def test_configuration_name_swap_is_rejected_by_descriptor_relative_nofollow_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target_name: str,
    replacement_content: str,
) -> None:
    root = _target(tmp_path)
    target_path = root / target_name
    replacement = tmp_path / "outside"
    replacement.write_text(replacement_content, encoding="utf-8")
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)
    real_open = os.open
    observed_flags: list[int] = []
    swapped = False

    def swap_then_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal swapped
        if path == target_name and dir_fd is not None:
            observed_flags.append(flags)
            if not swapped:
                target_path.unlink()
                target_path.symlink_to(replacement)
                swapped = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", swap_then_open)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert swapped is True, run.error
    assert observed_flags and all(flags & os.O_NOFOLLOW for flags in observed_flags)
    assert run.status is ScannerStatus.FAILED
    assert "could not be validated safely" in (run.error or "")


def test_configuration_content_race_is_rejected_after_snapshot_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = _target(tmp_path)
    config_path = root / "hardhat.config.ts"
    backend = _MockHardhatLoopbackBackend()
    _attest_backend(monkeypatch, backend)
    monkeypatch.setenv("MMAUDIT_FORK_RPC_URL", "http://127.0.0.1:8545")
    _forbid_subprocess(monkeypatch)
    real_open = os.open
    real_read = os.read
    config_descriptor: int | None = None
    mutated = False

    def observe_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal config_descriptor
        descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
        if path == "hardhat.config.ts" and dir_fd is not None:
            config_descriptor = descriptor
        return descriptor

    def mutate_after_read(descriptor: int, length: int) -> bytes:
        nonlocal mutated
        content = real_read(descriptor, length)
        if descriptor == config_descriptor and content and not mutated:
            config_path.write_text("export default { solidity: '0.8.21' };\n", encoding="utf-8")
            mutated = True
        return content

    monkeypatch.setattr(os, "open", observe_open)
    monkeypatch.setattr(os, "read", mutate_after_read)

    run = _scanner().run(root, tmp_path / "private", 1, backend=backend)

    assert mutated is True, run.error
    assert run.status is ScannerStatus.FAILED
    assert "could not be validated safely" in (run.error or "")


def test_inventory_parser_and_selector_bind_explicit_configured_suite() -> None:
    omitted = _descriptor(
        path="test/other/Other.ts",
        suite_name="Other",
        test_name="unselected behavior",
    )
    inventory = _inventory(_descriptor(), omitted)

    parsed = parse_hardhat_inventory_report(
        inventory.model_dump_json(),
        expected_reporter_version="1.0.0",
        expected_reporter_sha256=_REPORTER_SHA256,
        expected_repository_sha256=_REPOSITORY_SHA256,
        maximum_bytes=100_000,
    )
    selection = select_hardhat_repository_suite(
        parsed,
        _scanner().smart_contracts,
        repository_exclusion_path=".mmaudit",
    )

    assert selection.repository_sha256 == _REPOSITORY_SHA256
    assert selection.selected_test_count == 1
    assert selection.omitted_test_count == 1
    assert selection.tests[0].descriptor_sha256 == _descriptor().descriptor_sha256


def test_inventory_parser_rejects_duplicates_extra_fields_and_wrong_pins() -> None:
    inventory = _inventory()
    payload = inventory.model_dump(mode="json")
    payload["unexpected"] = True
    with pytest.raises(HardhatReporterError, match="strict validation"):
        parse_hardhat_inventory_report(
            json.dumps(payload),
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_repository_sha256=_REPOSITORY_SHA256,
            maximum_bytes=100_000,
        )

    duplicate = '{"schema_version":"1.0","schema_version":"1.0",' + inventory.model_dump_json()[1:]
    with pytest.raises(HardhatReporterError, match="strict JSON"):
        parse_hardhat_inventory_report(
            duplicate,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_repository_sha256=_REPOSITORY_SHA256,
            maximum_bytes=100_000,
        )

    with pytest.raises(HardhatReporterError, match="trust pins"):
        parse_hardhat_inventory_report(
            inventory.model_dump_json(),
            expected_reporter_version="2.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_repository_sha256=_REPOSITORY_SHA256,
            maximum_bytes=100_000,
        )


@pytest.mark.parametrize(
    ("expected_version", "expected_reporter_sha256", "expected_repository_sha256", "error"),
    [
        ("1.0.0", "a" * 64, _REPOSITORY_SHA256, "trust pins"),
        ("1.0.0", _REPORTER_SHA256, "a" * 64, "frozen repository"),
    ],
)
def test_inventory_parser_rejects_reporter_hash_or_repository_mismatch(
    expected_version: str,
    expected_reporter_sha256: str,
    expected_repository_sha256: str,
    error: str,
) -> None:
    with pytest.raises(HardhatReporterError, match=error):
        parse_hardhat_inventory_report(
            _inventory().model_dump_json(),
            expected_reporter_version=expected_version,
            expected_reporter_sha256=expected_reporter_sha256,
            expected_repository_sha256=expected_repository_sha256,
            maximum_bytes=100_000,
        )


@pytest.mark.parametrize(
    ("content", "maximum_bytes", "error"),
    [
        ("{", 100_000, "strict JSON"),
        (_inventory().model_dump_json() + (" " * 2_000), 1_024, "byte ceiling"),
        (_inventory().model_dump_json(), 1_023, "out of bounds"),
    ],
)
def test_inventory_parser_rejects_malformed_or_unbounded_output(
    content: str,
    maximum_bytes: int,
    error: str,
) -> None:
    with pytest.raises(HardhatReporterError, match=error):
        parse_hardhat_inventory_report(
            content,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_repository_sha256=_REPOSITORY_SHA256,
            maximum_bytes=maximum_bytes,
        )


def test_execution_report_requires_exact_selection_and_fork_binding() -> None:
    inventory = _inventory()
    selection = select_hardhat_repository_suite(
        inventory,
        _scanner().smart_contracts,
        repository_exclusion_path=".mmaudit",
    )
    descriptor = selection.tests[0]
    result = HardhatReporterTestResult.sealed(
        descriptor_sha256=descriptor.descriptor_sha256,
        path=descriptor.path,
        suite_name=descriptor.suite_name,
        test_name=descriptor.test_name,
        status=RepositoryTestExecutionStatus.PASSED,
        duration_seconds=0.25,
    )
    report = HardhatReporterExecution.sealed(
        reporter_version="1.0.0",
        reporter_sha256=_REPORTER_SHA256,
        repository_sha256=_REPOSITORY_SHA256,
        selection_sha256=selection.selection_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash=_BLOCK_HASH,
        fuzz_seed=_SEED,
        results=(result,),
    )

    parsed = parse_hardhat_execution_report(
        report.model_dump_json(),
        selection=selection,
        expected_reporter_version="1.0.0",
        expected_reporter_sha256=_REPORTER_SHA256,
        expected_chain_id=31_337,
        expected_block_number=0,
        expected_block_hash=_BLOCK_HASH,
        expected_fuzz_seed=_SEED,
        per_test_timeout_seconds=1,
        maximum_bytes=100_000,
    )
    assert parsed.report_sha256 == report.report_sha256

    incomplete = HardhatReporterExecution.sealed(
        reporter_version="1.0.0",
        reporter_sha256=_REPORTER_SHA256,
        repository_sha256=_REPOSITORY_SHA256,
        selection_sha256=selection.selection_sha256,
        chain_id=31_337,
        block_number=0,
        block_hash=_BLOCK_HASH,
        fuzz_seed=_SEED,
        results=(),
    )
    with pytest.raises(HardhatReporterError, match="exact selected test set"):
        parse_hardhat_execution_report(
            incomplete.model_dump_json(),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )


@pytest.mark.parametrize(
    ("report_overrides", "expected_overrides", "error"),
    [
        ({"reporter_version": "2.0.0"}, {}, "trust pins"),
        ({"reporter_sha256": "a" * 64}, {}, "trust pins"),
        ({"repository_sha256": "a" * 64}, {}, "suite selection"),
        ({"selection_sha256": "a" * 64}, {}, "suite selection"),
        ({}, {"expected_chain_id": 1}, "pinned fork state"),
        ({}, {"expected_block_number": 1}, "pinned fork state"),
        ({}, {"expected_block_hash": "0x" + ("a" * 64)}, "pinned fork state"),
        ({}, {"expected_fuzz_seed": "0x" + ("a" * 64)}, "pinned fork state"),
    ],
)
def test_execution_report_rejects_trust_selection_and_fork_mismatches(
    report_overrides: dict[str, object],
    expected_overrides: dict[str, object],
    error: str,
) -> None:
    selection, baseline = _selection_and_report()
    values: dict[str, object] = {
        "reporter_version": baseline.reporter_version,
        "reporter_sha256": baseline.reporter_sha256,
        "repository_sha256": baseline.repository_sha256,
        "selection_sha256": baseline.selection_sha256,
        "chain_id": baseline.chain_id,
        "block_number": baseline.block_number,
        "block_hash": baseline.block_hash,
        "fuzz_seed": baseline.fuzz_seed,
        "results": baseline.results,
    }
    values.update(report_overrides)
    report = HardhatReporterExecution.sealed(**values)
    expected: dict[str, object] = {
        "expected_reporter_version": "1.0.0",
        "expected_reporter_sha256": _REPORTER_SHA256,
        "expected_chain_id": 31_337,
        "expected_block_number": 0,
        "expected_block_hash": _BLOCK_HASH,
        "expected_fuzz_seed": _SEED,
    }
    expected.update(expected_overrides)

    with pytest.raises(HardhatReporterError, match=error):
        parse_hardhat_execution_report(
            report.model_dump_json(),
            selection=selection,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
            **expected,
        )


def test_execution_report_rejects_result_identity_or_deadline_mismatch() -> None:
    selection, identity_mismatch = _selection_and_report(
        result_overrides={"test_name": "different test identity"}
    )
    with pytest.raises(HardhatReporterError, match="test identity"):
        parse_hardhat_execution_report(
            identity_mismatch.model_dump_json(),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )

    selection, too_slow = _selection_and_report(result_overrides={"duration_seconds": 1.01})
    with pytest.raises(HardhatReporterError, match="per-test deadline"):
        parse_hardhat_execution_report(
            too_slow.model_dump_json(),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )


def test_execution_report_rejects_duplicate_unsorted_or_extra_results() -> None:
    first = _descriptor(test_name="first")
    second = _descriptor(test_name="second")
    selection, report = _selection_and_report(first, second)
    payload = report.model_dump(mode="json")

    duplicate = {
        **payload,
        "results": [payload["results"][0], payload["results"][0]],
    }
    duplicate = _reseal_payload(duplicate, "report_sha256")
    with pytest.raises(HardhatReporterError, match="strict validation"):
        parse_hardhat_execution_report(
            json.dumps(duplicate),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )

    unsorted = {
        **payload,
        "results": list(reversed(payload["results"])),
    }
    unsorted = _reseal_payload(unsorted, "report_sha256")
    with pytest.raises(HardhatReporterError, match="strict validation"):
        parse_hardhat_execution_report(
            json.dumps(unsorted),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )

    extra = {**payload, "unexpected": True}
    with pytest.raises(HardhatReporterError, match="strict validation"):
        parse_hardhat_execution_report(
            json.dumps(extra),
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )

    duplicate_key = '{"schema_version":"1.0","schema_version":"1.0",' + report.model_dump_json()[1:]
    with pytest.raises(HardhatReporterError, match="strict JSON"):
        parse_hardhat_execution_report(
            duplicate_key,
            selection=selection,
            expected_reporter_version="1.0.0",
            expected_reporter_sha256=_REPORTER_SHA256,
            expected_chain_id=31_337,
            expected_block_number=0,
            expected_block_hash=_BLOCK_HASH,
            expected_fuzz_seed=_SEED,
            per_test_timeout_seconds=1,
            maximum_bytes=100_000,
        )


def test_reporter_schema_rejects_unclassified_or_unbounded_results() -> None:
    descriptor = _descriptor()
    with pytest.raises(ValidationError, match="classified terminal"):
        HardhatReporterTestResult.sealed(
            descriptor_sha256=descriptor.descriptor_sha256,
            path=descriptor.path,
            suite_name=descriptor.suite_name,
            test_name=descriptor.test_name,
            status=RepositoryTestExecutionStatus.TIMED_OUT,
            duration_seconds=1,
        )
    with pytest.raises(ValidationError):
        HardhatReporterTestResult.sealed(
            descriptor_sha256=descriptor.descriptor_sha256,
            path=descriptor.path,
            suite_name=descriptor.suite_name,
            test_name=descriptor.test_name,
            status=RepositoryTestExecutionStatus.PASSED,
            terminal_detail="unexpected",
            duration_seconds=1,
        )
