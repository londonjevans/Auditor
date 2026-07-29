from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import RepositoryCleanForkMatrixStateConfig
from mmaudit.scanners.clean_chain import (
    CleanAnvilConfigurationError,
    CleanAnvilIdentityError,
    CleanAnvilUnavailableError,
    TrustedCleanAnvilLauncher,
    _HeadObservation,
)
from mmaudit.scanners.fork_rpc import ForkRpcUnavailableError, PinnedForkObservation

_VERSION = "anvil Version: 1.3.2-stable"
_GENESIS_HASH = "0x" + ("ab" * 32)
_OTHER_GENESIS_HASH = "0x" + ("cd" * 32)
_STATE_ROOT = "0x" + ("ef" * 32)


class _RecordingProcessFactory:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, Any], subprocess.Popen[bytes]]] = []

    def __call__(self, args: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        process = subprocess.Popen(args, **kwargs)
        self.calls.append((tuple(args), dict(kwargs), process))
        return process


class _ObservationSequence:
    def __init__(
        self,
        *results: PinnedForkObservation | BaseException,
        default: PinnedForkObservation | BaseException | None = None,
    ) -> None:
        self._results = list(results)
        self._default = default
        self.calls: list[tuple[str, int | None, int | None, float]] = []

    def __call__(
        self,
        endpoint: str,
        *,
        expected_chain_id: int | None,
        pinned_block_number: int | None,
        timeout_seconds: float,
    ) -> PinnedForkObservation:
        self.calls.append((endpoint, expected_chain_id, pinned_block_number, timeout_seconds))
        result = self._results.pop(0) if self._results else self._default
        if result is None:
            raise AssertionError("unexpected clean-chain observation")
        if isinstance(result, BaseException):
            raise result
        return result


def _observation(
    *,
    chain_id: int = 31_337,
    block_hash: str = _GENESIS_HASH,
) -> PinnedForkObservation:
    return PinnedForkObservation(
        chain_id=chain_id,
        block_number=0,
        block_hash=block_hash,
    )


def _head(
    block_number: int = 0,
    *,
    block_hash: str = _GENESIS_HASH,
) -> _HeadObservation:
    return _HeadObservation(
        block_number=block_number,
        block_hash=block_hash,
        state_root=_STATE_ROOT,
    )


def _fake_anvil_source(
    root: Path,
    *,
    version: str = _VERSION,
    first_port_exit: int | None = None,
    ignore_term: bool = False,
    emit_excess_output: bool = False,
    leave_version_descendant: bool = False,
) -> Path:
    trusted = root / "trusted-toolchain"
    trusted.mkdir(mode=0o700)
    executable = trusted / "anvil"
    port_guard = (
        f'case " $* " in *" --port {first_port_exit} "*) exit 98 ;; esac\n'
        if first_port_exit is not None
        else ""
    )
    trap = "trap '' TERM\n" if ignore_term else "trap 'exit 0' TERM INT HUP\n"
    output = "/usr/bin/yes synthetic | /usr/bin/head -c 70000\n" if emit_excess_output else ""
    version_descendant = "  (trap '' TERM; /bin/sleep 60) &\n" if leave_version_descendant else ""
    executable.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "--version" ]; then\n'
        f"{version_descendant}"
        f"  printf '%s\\n' '{version}'\n"
        "  printf '%s\\n' 'Commit SHA: synthetic-local-fixture'\n"
        "  printf '%s\\n' 'Build Profile: synthetic-test'\n"
        "  exit 0\n"
        "fi\n"
        f"{port_guard}"
        f"{trap}"
        f"{output}"
        "while :; do\n"
        "  /bin/sleep 60\n"
        "done\n",
        encoding="utf-8",
    )
    executable.chmod(0o500)
    return executable.resolve(strict=True)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _config(
    executable: Path,
    *,
    version: str = _VERSION,
    sha256: str | None = None,
    startup_timeout_seconds: float = 1.0,
    shutdown_timeout_seconds: float = 1.0,
) -> RepositoryCleanForkMatrixStateConfig:
    return RepositoryCleanForkMatrixStateConfig(
        state_id="clean-local",
        expected_chain_id=31_337,
        anvil_executable_env="MMAUDIT_ANVIL_EXECUTABLE",
        anvil_version=version,
        anvil_sha256=sha256 or _sha256(executable),
        hardfork="cancun",
        genesis_timestamp=1_700_000_000,
        startup_timeout_seconds=startup_timeout_seconds,
        shutdown_timeout_seconds=shutdown_timeout_seconds,
    )


def _roots(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o755)
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    private.chmod(0o700)
    return repository.resolve(strict=True), private.resolve(strict=True)


def _launcher(
    executable: Path,
    *,
    factory: _RecordingProcessFactory,
    observer: _ObservationSequence,
    ports: Sequence[int] = (19_345,),
    environment: dict[str, str] | None = None,
) -> TrustedCleanAnvilLauncher:
    remaining_ports = iter(ports)
    return TrustedCleanAnvilLauncher(
        environment=environment
        or {
            "MMAUDIT_ANVIL_EXECUTABLE": str(executable),
            "OPENROUTER_API_KEY": "synthetic-secret-canary",
            "HTTPS_PROXY": "http://127.0.0.1:1",
            "SSH_AUTH_SOCK": "/private/synthetic-agent",
            "FOUNDRY_PROFILE": "target-controlled",
            "ANVIL_IP_ADDR": "0.0.0.0",
        },
        process_factory=factory,
        observer=observer,
        head_observer=lambda *_args, **_kwargs: _head(),
        listener_owner_verifier=lambda *_args, **_kwargs: True,
        runtime_executable_verifier=lambda *_args, **_kwargs: True,
        port_supplier=lambda: next(remaining_ports),
    )


def test_trusted_clean_anvil_launcher_is_importable() -> None:
    assert TrustedCleanAnvilLauncher is not None


def test_trusted_clean_anvil_uses_fixed_argv_sanitized_environment_and_sealed_stop(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    observer = _ObservationSequence(default=_observation())
    launcher = _launcher(executable, factory=factory, observer=observer)

    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 3,
    )

    assert lease.endpoint == "http://127.0.0.1:19345"
    assert lease.initial_observation == _observation()
    assert len(observer.calls) == 2
    assert lease.reobserve() == _observation()
    assert len(observer.calls) == 3
    assert len(factory.calls) == 2
    version_command, version_options, _ = factory.calls[0]
    node_command, node_options, node_process = factory.calls[1]
    copied_executable = Path(version_command[0])
    assert version_command == (str(copied_executable), "--version")
    assert copied_executable != executable
    assert stat.S_IMODE(copied_executable.stat().st_mode) == 0o500
    assert _sha256(copied_executable) == _sha256(executable)
    assert node_command == (
        str(copied_executable),
        "--host",
        "127.0.0.1",
        "--port",
        "19345",
        "--chain-id",
        "31337",
        "--number",
        "0",
        "--timestamp",
        "1700000000",
        "--hardfork",
        "cancun",
        "--gas-limit",
        "30000000",
        "--block-base-fee-per-gas",
        "1000000000",
        "--gas-price",
        "1000000000",
        "--accounts",
        "0",
        "--no-mining",
        "--threads",
        "1",
        "--disable-default-create2-deployer",
        "--no-cors",
        "--quiet",
        "--color",
        "never",
    )
    for forbidden in (
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
    ):
        assert forbidden not in node_command
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
    assert "synthetic-secret-canary" not in json.dumps(child_environment)
    assert all(
        token not in child_environment
        for token in (
            "OPENROUTER_API_KEY",
            "HTTPS_PROXY",
            "SSH_AUTH_SOCK",
            "FOUNDRY_PROFILE",
            "ANVIL_IP_ADDR",
            "PATH",
        )
    )
    assert node_options["cwd"] == str(private / "clean-anvil" / "work")
    assert node_options["shell"] is False
    assert node_options["close_fds"] is True
    assert node_options["start_new_session"] is True

    endpoint = lease.endpoint
    process_id = node_process.pid
    lease.stop(time.monotonic() + 2)
    assert node_process.poll() is not None
    assert len(observer.calls) == 4
    with pytest.raises(CleanAnvilUnavailableError, match="no longer available"):
        _ = lease.endpoint
    evidence = lease.attestation()
    assert evidence.configured_tool_version == _VERSION
    assert evidence.observed_tool_version == _VERSION
    assert evidence.configured_tool_sha256 == _sha256(executable)
    assert evidence.observed_tool_sha256 == _sha256(executable)
    assert evidence.genesis_block_hash == _GENESIS_HASH
    assert evidence.outbound_network_isolation == "not_attested"
    assert evidence.no_upstream_fork_configuration is True
    assert evidence.process_group_absent is True
    assert evidence.endpoint_retained is False
    assert evidence.executable_path_retained is False
    assert evidence.port_retained is False
    assert evidence.process_id_retained is False
    assert evidence.raw_output_retained is False
    leaves = set(_scalar_leaves(evidence.model_dump(mode="json")))
    assert endpoint not in leaves
    assert str(executable) not in leaves
    assert str(copied_executable) not in leaves
    assert process_id not in leaves
    assert "synthetic-secret-canary" not in leaves
    assert evidence.attestation_sha256 == evidence.expected_attestation_sha256()


def test_trusted_clean_anvil_never_falls_back_to_path(tmp_path: Path) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = TrustedCleanAnvilLauncher(
        environment={"PATH": str(executable.parent)},
        process_factory=factory,
        observer=_ObservationSequence(default=_observation()),
        port_supplier=lambda: 19_345,
    )

    with pytest.raises(CleanAnvilConfigurationError, match="variable is missing"):
        launcher.start(_config(executable), repository, private, time.monotonic() + 2)

    assert factory.calls == []


@pytest.mark.parametrize("unsafe_kind", ["repository", "symlink", "hardlink", "writable"])
def test_trusted_clean_anvil_rejects_unsafe_executable_identity(
    tmp_path: Path,
    unsafe_kind: str,
) -> None:
    repository, private = _roots(tmp_path)
    external = _fake_anvil_source(tmp_path)
    candidate = external
    if unsafe_kind == "repository":
        candidate = repository / "anvil"
        candidate.write_bytes(external.read_bytes())
        candidate.chmod(0o500)
    elif unsafe_kind == "symlink":
        candidate = tmp_path / "anvil-link"
        candidate.symlink_to(external)
    elif unsafe_kind == "hardlink":
        candidate = tmp_path / "anvil-hardlink"
        os.link(external, candidate)
    else:
        candidate.chmod(0o520)
    candidate_hash = _sha256(candidate.resolve(strict=True))
    config = _config(external, sha256=candidate_hash)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        candidate.absolute(),
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )

    with pytest.raises(CleanAnvilConfigurationError, match="approved external regular file"):
        launcher.start(config, repository, private, time.monotonic() + 2)

    assert factory.calls == []


def test_trusted_clean_anvil_rejects_hash_and_exact_version_mismatches(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=_ObservationSequence(default=_observation()),
        head_observer=lambda *_args, **_kwargs: _head(),
        port_supplier=lambda: 19_345,
    )
    with pytest.raises(CleanAnvilConfigurationError, match="SHA-256"):
        launcher.start(
            _config(executable, sha256="a" * 64),
            repository,
            private,
            time.monotonic() + 2,
        )

    second_private = tmp_path / "second-private"
    second_private.mkdir(mode=0o700)
    second_private.chmod(0o700)
    factory = _RecordingProcessFactory()
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=_ObservationSequence(default=_observation()),
        head_observer=lambda *_args, **_kwargs: _head(),
        port_supplier=lambda: 19_345,
    )
    with pytest.raises(CleanAnvilConfigurationError, match="exact configured version"):
        launcher.start(
            _config(executable, version="anvil Version: 9.9.9-stable"),
            repository,
            second_private.resolve(strict=True),
            time.monotonic() + 2,
        )

    assert len(factory.calls) == 1
    assert factory.calls[0][2].poll() is not None


def test_trusted_clean_anvil_rejects_changing_genesis_and_cleans_process(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    observer = _ObservationSequence(
        _observation(),
        _observation(block_hash=_OTHER_GENESIS_HASH),
    )
    heads = iter((_head(), _head(block_hash=_OTHER_GENESIS_HASH)))
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=observer,
        head_observer=lambda *_args, **_kwargs: next(heads),
        listener_owner_verifier=lambda *_args, **_kwargs: True,
        runtime_executable_verifier=lambda *_args, **_kwargs: True,
        port_supplier=lambda: 19_345,
    )

    with pytest.raises(CleanAnvilIdentityError, match="changed during startup"):
        launcher.start(_config(executable), repository, private, time.monotonic() + 2)

    assert len(factory.calls) == 2
    assert factory.calls[1][2].poll() is not None


def test_trusted_clean_anvil_retries_one_early_port_race_with_a_new_port(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path, first_port_exit=19_345)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()

    class _PortAwareObserver:
        def __call__(
            self,
            endpoint: str,
            *,
            expected_chain_id: int | None,
            pinned_block_number: int | None,
            timeout_seconds: float,
        ) -> PinnedForkObservation:
            del expected_chain_id, pinned_block_number, timeout_seconds
            if endpoint.endswith(":19345"):
                raise ForkRpcUnavailableError("synthetic occupied port")
            return _observation()

    ports = iter((19_345, 19_346))
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=_PortAwareObserver(),
        head_observer=lambda *_args, **_kwargs: _head(),
        listener_owner_verifier=lambda *_args, **_kwargs: True,
        runtime_executable_verifier=lambda *_args, **_kwargs: True,
        port_supplier=lambda: next(ports),
    )

    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 3,
    )

    assert lease.endpoint == "http://127.0.0.1:19346"
    assert len(factory.calls) == 3
    assert factory.calls[1][2].poll() is not None
    lease.stop(time.monotonic() + 2)
    assert lease.attestation().process_group_absent is True


def test_trusted_clean_anvil_escalates_to_bounded_group_kill(tmp_path: Path) -> None:
    executable = _fake_anvil_source(tmp_path, ignore_term=True)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    lease = launcher.start(
        _config(executable, shutdown_timeout_seconds=0.4),
        repository,
        private,
        time.monotonic() + 2,
    )
    time.sleep(0.05)

    lease.stop(time.monotonic() + 1)

    evidence = lease.attestation()
    assert evidence.termination_method == "kill"
    assert evidence.termination_duration_seconds <= 0.4
    assert factory.calls[1][2].poll() is not None


def test_trusted_clean_anvil_rejects_and_cleans_excess_process_output(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path, emit_excess_output=True)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )

    with pytest.raises(CleanAnvilUnavailableError, match="bounded diagnostic output"):
        launcher.start(_config(executable), repository, private, time.monotonic() + 2)

    assert factory.calls[1][2].poll() is not None


def test_failed_reobservation_prevents_attestation_but_still_cleans_process(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    observer = _ObservationSequence(
        _observation(),
        _observation(),
        _observation(block_hash=_OTHER_GENESIS_HASH),
        default=_observation(),
    )
    heads = iter((_head(), _head(), _head(block_hash=_OTHER_GENESIS_HASH)))
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=observer,
        head_observer=lambda *_args, **_kwargs: next(heads),
        listener_owner_verifier=lambda *_args, **_kwargs: True,
        runtime_executable_verifier=lambda *_args, **_kwargs: True,
        port_supplier=lambda: 19_345,
    )
    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 2,
    )

    with pytest.raises(CleanAnvilIdentityError, match="no longer matches"):
        lease.reobserve()
    with pytest.raises(CleanAnvilIdentityError, match="unchanged pre/post"):
        lease.stop(time.monotonic() + 2)
    assert factory.calls[1][2].poll() is not None
    with pytest.raises(CleanAnvilUnavailableError, match="unavailable before"):
        lease.attestation()


def test_spawned_process_must_own_the_observed_loopback_listener(tmp_path: Path) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=_ObservationSequence(default=_observation()),
        head_observer=lambda *_args, **_kwargs: _head(),
        port_supplier=lambda: 19_345,
    )
    lease = None
    try:
        with pytest.raises(CleanAnvilUnavailableError, match=r"own.*listener"):
            lease = launcher.start(
                _config(executable),
                repository,
                private,
                time.monotonic() + 2,
            )
    finally:
        if lease is not None:
            lease.stop(time.monotonic() + 1)


def test_mutated_current_head_cannot_seal_pristine_clean_attestation(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    heads = iter((_head(), _head(), _head(1, block_hash=_OTHER_GENESIS_HASH)))
    launcher = TrustedCleanAnvilLauncher(
        environment={"MMAUDIT_ANVIL_EXECUTABLE": str(executable)},
        process_factory=factory,
        observer=_ObservationSequence(default=_observation()),
        port_supplier=lambda: 19_345,
        listener_owner_verifier=lambda *_args, **_kwargs: True,
        runtime_executable_verifier=lambda *_args, **_kwargs: True,
        head_observer=lambda *_args, **_kwargs: next(heads),
    )
    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 2,
    )

    with pytest.raises(CleanAnvilIdentityError, match="pristine"):
        lease.stop(time.monotonic() + 1)
    with pytest.raises(CleanAnvilUnavailableError, match="unavailable before"):
        lease.attestation()


def test_version_probe_descendant_is_killed_and_cannot_hold_collectors(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path, leave_version_descendant=True)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    version_process: subprocess.Popen[bytes] | None = None
    try:
        with pytest.raises(CleanAnvilConfigurationError, match=r"version.*process group"):
            launcher.start(
                _config(executable, startup_timeout_seconds=0.4),
                repository,
                private,
                time.monotonic() + 1,
            )
        version_process = factory.calls[0][2]
        assert version_process.poll() is not None
        assert not _process_group_exists(version_process.pid)
    finally:
        if version_process is None and factory.calls:
            version_process = factory.calls[0][2]
        if version_process is not None and _process_group_exists(version_process.pid):
            os.killpg(version_process.pid, 9)


def test_context_manager_stops_and_removes_workspace_on_caller_exception(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )

    class _CallerFailure(Exception):
        pass

    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 2,
    )
    try:
        with pytest.raises(_CallerFailure), lease:
            raise _CallerFailure
    finally:
        if factory.calls[1][2].poll() is None:
            lease.stop(time.monotonic() + 1)

    assert factory.calls[1][2].poll() is not None
    assert not (private / "clean-anvil").exists()
    assert lease.attestation().process_group_absent is True


@pytest.mark.parametrize("ancestor_name", [".env.synthetic", "foundry.toml"])
def test_clean_anvil_rejects_ancestor_control_files(
    tmp_path: Path,
    ancestor_name: str,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    (tmp_path / ancestor_name).write_text("SYNTHETIC_CANARY=untrusted\n", encoding="utf-8")
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    lease = None
    try:
        with pytest.raises(CleanAnvilConfigurationError, match="ancestor"):
            lease = launcher.start(
                _config(executable),
                repository,
                private,
                time.monotonic() + 2,
            )
    finally:
        if lease is not None:
            lease.stop(time.monotonic() + 1)


def test_clean_stop_removes_private_executable_and_workspace(tmp_path: Path) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 2,
    )
    copied_path = Path(factory.calls[0][0][0])

    lease.stop(time.monotonic() + 1)

    assert not copied_path.exists()
    assert not (private / "clean-anvil").exists()


def test_late_ancestor_control_file_prevents_clean_attestation(tmp_path: Path) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    injected_control = tmp_path / "foundry.toml"

    class _InjectingProcessFactory(_RecordingProcessFactory):
        def __call__(self, args: Sequence[str], **kwargs: Any) -> subprocess.Popen[bytes]:
            process = super().__call__(args, **kwargs)
            if not injected_control.exists():
                injected_control.write_text(
                    '[profile.default]\neth_rpc_url = "http://127.0.0.1:1"\n',
                    encoding="utf-8",
                )
            return process

    factory = _InjectingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    lease = None
    try:
        with pytest.raises(CleanAnvilConfigurationError, match="ancestor"):
            lease = launcher.start(
                _config(executable),
                repository,
                private,
                time.monotonic() + 2,
            )
    finally:
        if lease is not None:
            lease.stop(time.monotonic() + 1)
        injected_control.unlink(missing_ok=True)

    assert len(factory.calls) == 1
    assert factory.calls[0][2].poll() is not None
    assert not (private / "clean-anvil").exists()


def test_ancestor_control_file_added_during_lease_prevents_attestation(
    tmp_path: Path,
) -> None:
    executable = _fake_anvil_source(tmp_path)
    repository, private = _roots(tmp_path)
    factory = _RecordingProcessFactory()
    launcher = _launcher(
        executable,
        factory=factory,
        observer=_ObservationSequence(default=_observation()),
    )
    lease = launcher.start(
        _config(executable),
        repository,
        private,
        time.monotonic() + 2,
    )
    injected_control = tmp_path / ".env.synthetic"
    injected_control.write_text("SYNTHETIC_CANARY=untrusted\n", encoding="utf-8")
    try:
        with pytest.raises(CleanAnvilIdentityError, match="unchanged pre/post"):
            lease.stop(time.monotonic() + 1)
    finally:
        injected_control.unlink(missing_ok=True)

    assert factory.calls[1][2].poll() is not None
    assert not _process_group_exists(factory.calls[1][2].pid)
    assert not (private / "clean-anvil").exists()
    with pytest.raises(CleanAnvilUnavailableError, match="unavailable before"):
        lease.attestation()


def _scalar_leaves(value: object) -> list[object]:
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _scalar_leaves(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _scalar_leaves(item)]
    return [value]


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    return True
