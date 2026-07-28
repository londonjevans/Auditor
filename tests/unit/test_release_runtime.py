from __future__ import annotations

import hashlib
import inspect
import os
import stat
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.release_runtime as runtime_module
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release import ReleaseGateId, ReleaseGateStatus
from mmaudit.release_gates import get_release_gate_fixed_plan
from mmaudit.release_io import read_json_evidence
from mmaudit.release_runtime import (
    JUnitValidationStatus,
    LocalReleaseGateResult,
    execute_local_release_gate,
    validate_local_release_gate_result_artifact,
)

ROOT = Path(__file__).resolve().parents[2]
START = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
END = datetime(2026, 7, 28, 12, 1, tzinfo=UTC)
CANDIDATE_SHA256 = "a" * 64
RUN_BINDING_SHA256 = "b" * 64
PYTHON_SHA256 = "c" * 64
DISTRIBUTION_SHA256 = "d" * 64
VALID_JUNIT = (
    b'<?xml version="1.0"?>'
    b'<testsuites><testsuite tests="5" failures="0" errors="0" skipped="2"/>'
    b"</testsuites>"
)


class _FakeProcess:
    def __init__(self, *, argv: list[str], returncode: int, timed_out: bool) -> None:
        self.argv = argv
        self.returncode = returncode
        self.timed_out = timed_out
        self.pid = 424_242
        self.wait_calls = 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.wait_calls += 1
        if self.timed_out and self.wait_calls == 1:
            raise subprocess.TimeoutExpired(self.argv, 1)
        return -9 if self.timed_out else self.returncode

    def kill(self) -> None:
        self.returncode = -9


class _FakePopenFactory:
    def __init__(
        self,
        *,
        returncode: int = 0,
        timed_out: bool = False,
        stdout: bytes = b"synthetic stdout",
        stderr: bytes = b"",
        junit: bytes | None = VALID_JUNIT,
    ) -> None:
        self.returncode = returncode
        self.timed_out = timed_out
        self.stdout = stdout
        self.stderr = stderr
        self.junit = junit
        self.calls: list[tuple[list[str], dict[str, Any]]] = []
        self.guard_sha256: str | None = None
        self.guard_mode: int | None = None

    def __call__(self, argv: list[str], **kwargs: Any) -> _FakeProcess:
        self.calls.append((list(argv), dict(kwargs)))
        stdout = kwargs["stdout"]
        stderr = kwargs["stderr"]
        stdout.write(self.stdout)
        stderr.write(self.stderr)
        if "--junitxml" in argv and self.junit is not None:
            Path(argv[-1]).write_bytes(self.junit)
        environment = kwargs["env"]
        guard = Path(environment["PYTHONPATH"]) / "sitecustomize.py"
        self.guard_sha256 = hashlib.sha256(guard.read_bytes()).hexdigest()
        self.guard_mode = stat.S_IMODE(guard.stat().st_mode)
        return _FakeProcess(
            argv=argv,
            returncode=self.returncode,
            timed_out=self.timed_out,
        )


def _fake_executable() -> runtime_module._ExecutableObservation:
    return runtime_module._ExecutableObservation(
        declared_path=sys.executable,
        resolved_path=sys.executable,
        sha256=PYTHON_SHA256,
        identity=(1, 2, 3, 4, 5, 6, 7),
        declared_identity=(1, 2, 3, 4, 5, 6, 7),
    )


def _fake_distribution(name: str) -> runtime_module._DistributionObservation:
    return runtime_module._DistributionObservation(
        name=name,
        version="1.2.3",
        inventory_sha256=DISTRIBUTION_SHA256,
    )


def _install_fake_process(
    monkeypatch: pytest.MonkeyPatch,
    factory: _FakePopenFactory,
) -> None:
    timestamps = iter((START, END))
    monkeypatch.setattr(runtime_module, "_utc_now", lambda: next(timestamps))
    monkeypatch.setattr(runtime_module, "_observe_executing_python", _fake_executable)
    monkeypatch.setattr(runtime_module, "_observe_tool_distribution", _fake_distribution)
    monkeypatch.setattr(runtime_module.subprocess, "Popen", factory)
    monkeypatch.setattr(runtime_module, "_stop_process", lambda _process: None)
    monkeypatch.setattr(
        runtime_module,
        "_terminate_release_process_group",
        lambda _process_group_id: None,
    )


def _result_for_receipt(
    evidence_root: Path,
    gate_id: ReleaseGateId,
) -> tuple[LocalReleaseGateResult, Any]:
    plan = get_release_gate_fixed_plan(gate_id)
    observation = read_json_evidence(
        evidence_root=evidence_root,
        relative_path=plan.result_artifact_path,
    )
    return LocalReleaseGateResult.model_validate(observation.value), observation.binding


@pytest.mark.parametrize(
    ("gate_id", "suffix"),
    (
        (ReleaseGateId.RUFF_FORMAT, ("ruff", "format", "--check", ".")),
        (ReleaseGateId.RUFF_CHECK, ("ruff", "check", ".")),
        (ReleaseGateId.MYPY, ("mypy",)),
        (
            ReleaseGateId.PYTEST,
            ("pytest", "-q", "--junitxml", "release-gate-pytest-junit.xml"),
        ),
    ),
)
def test_fixed_local_executor_uses_only_canonical_safe_path_plans(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    gate_id: ReleaseGateId,
    suffix: tuple[str, ...],
) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "synthetic-canary-must-not-propagate")
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", "synthetic-control-path")
    factory = _FakePopenFactory()
    _install_fake_process(monkeypatch, factory)

    receipt = execute_local_release_gate(
        gate_id=gate_id,
        repository_root=ROOT,
        evidence_root=tmp_path,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
    )

    assert len(factory.calls) == 1
    argv, invocation = factory.calls[0]
    assert argv[:3] == [sys.executable, "-P", "-m"]
    if gate_id is ReleaseGateId.PYTEST:
        assert tuple(argv[3:-1]) == suffix[:-1]
        assert Path(argv[-1]) == tmp_path / suffix[-1]
    else:
        assert tuple(argv[3:]) == suffix
    assert invocation["cwd"] == ROOT
    assert invocation["shell"] is False
    assert invocation["close_fds"] is True
    assert invocation["start_new_session"] is True
    environment = invocation["env"]
    assert "OPENROUTER_API_KEY" not in environment
    assert "MMAUDIT_SECRETS_ENV_FILE" not in environment
    assert environment["PYTHONSAFEPATH"] == "1"
    assert set(environment) == set(
        runtime_module.get_release_gate_child_environment_contract(gate_id)
    )

    plan = get_release_gate_fixed_plan(gate_id)
    assert plan.python_safe_path is True
    assert factory.guard_sha256 == plan.network_guard_sha256
    assert factory.guard_mode == 0o600
    assert receipt.status is ReleaseGateStatus.PASSED
    assert receipt.candidate_observation_sha256 == CANDIDATE_SHA256
    assert receipt.run_binding_sha256 == RUN_BINDING_SHA256
    assert receipt.fixed_plan_sha256 == plan.fixed_plan_sha256
    assert receipt.tool_executable_sha256 == PYTHON_SHA256
    assert receipt.tool_distribution_sha256 == DISTRIBUTION_SHA256

    result, _binding = _result_for_receipt(tmp_path, gate_id)
    assert result.schema_version == "1.0"
    assert result.generated_by == "mmaudit"
    assert result.python_executable_sha256 == PYTHON_SHA256
    assert result.tool_distribution_sha256 == DISTRIBUTION_SHA256
    assert result.child_environment_contract_sha256 == canonical_sha256(
        result.child_environment_contract
    )
    assert result.network_guard_sha256 == plan.network_guard_sha256
    serialized = result.model_dump_json()
    assert ".mmaudit-release-runtime-" not in serialized
    assert "synthetic-canary-must-not-propagate" not in serialized
    if gate_id is ReleaseGateId.PYTEST:
        assert result.junit_status is JUnitValidationStatus.VALID
        assert result.junit_counts is not None
        assert result.junit_counts.tests == 5
        assert result.junit_counts.passed == 3
    else:
        assert result.junit_status is JUnitValidationStatus.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("returncode", "timed_out", "expected_process_exit"),
    ((7, False, 7), (0, True, -9)),
)
def test_nonzero_and_timed_out_local_execution_emit_failed_real_evidence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    returncode: int,
    timed_out: bool,
    expected_process_exit: int,
) -> None:
    factory = _FakePopenFactory(returncode=returncode, timed_out=timed_out)
    _install_fake_process(monkeypatch, factory)

    receipt = execute_local_release_gate(
        gate_id=ReleaseGateId.RUFF_CHECK,
        repository_root=ROOT,
        evidence_root=tmp_path,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
    )
    result, _binding = _result_for_receipt(tmp_path, ReleaseGateId.RUFF_CHECK)

    assert receipt.status is ReleaseGateStatus.FAILED
    assert receipt.timed_out is timed_out
    assert receipt.exit_code is (None if timed_out else expected_process_exit)
    assert receipt.result_summary.checks_total == 1
    assert receipt.result_summary.checks_failed == 1
    assert result.status is ReleaseGateStatus.FAILED
    assert result.process_exit_code == expected_process_exit
    assert result.timed_out is timed_out


@pytest.mark.parametrize("junit", (None, b"<not-xml>", b"<testsuites/>"))
def test_successful_pytest_without_valid_nonempty_junit_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    junit: bytes | None,
) -> None:
    factory = _FakePopenFactory(junit=junit)
    _install_fake_process(monkeypatch, factory)

    with pytest.raises(ValueError, match="valid nonempty JUnit"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.PYTEST,
            repository_root=ROOT,
            evidence_root=tmp_path,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )
    assert not (
        tmp_path / get_release_gate_fixed_plan(ReleaseGateId.PYTEST).result_artifact_path
    ).exists()


def test_local_executor_rejects_output_overflow_without_a_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    factory = _FakePopenFactory(stdout=b"x" * (4 * 1024 * 1024 + 1))
    _install_fake_process(monkeypatch, factory)

    with pytest.raises(ValueError, match="output exceeds"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=ROOT,
            evidence_root=tmp_path,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )
    assert not (
        tmp_path / get_release_gate_fixed_plan(ReleaseGateId.RUFF_CHECK).result_artifact_path
    ).exists()


def test_local_executor_exposes_no_arbitrary_command_surface_and_rejects_unsafe_roots(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    assert "argv" not in inspect.signature(execute_local_release_gate).parameters
    monkeypatch.setattr(
        runtime_module.subprocess,
        "Popen",
        lambda *_args, **_kwargs: pytest.fail("unsafe input reached process execution"),
    )

    with pytest.raises(ValueError, match="only fixed local release gates"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.DOCTOR,
            repository_root=ROOT,
            evidence_root=tmp_path,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )
    with pytest.raises(ValueError, match="release repository package"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=tmp_path,
            evidence_root=tmp_path,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )

    result_path = (
        tmp_path / get_release_gate_fixed_plan(ReleaseGateId.RUFF_CHECK).result_artifact_path
    )
    result_path.write_text("preexisting", encoding="utf-8")
    with pytest.raises(ValueError, match="must be fresh"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=ROOT,
            evidence_root=tmp_path,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )

    real_evidence = tmp_path / "real-evidence"
    real_evidence.mkdir()
    linked_evidence = tmp_path / "linked-evidence"
    linked_evidence.symlink_to(real_evidence, target_is_directory=True)
    with pytest.raises(ValueError, match="may not traverse a link"):
        execute_local_release_gate(
            gate_id=ReleaseGateId.RUFF_CHECK,
            repository_root=ROOT,
            evidence_root=linked_evidence,
            candidate_observation_sha256=CANDIDATE_SHA256,
            run_binding_sha256=RUN_BINDING_SHA256,
        )


def test_result_validation_rejects_candidate_and_fresh_tool_rebinding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    factory = _FakePopenFactory()
    _install_fake_process(monkeypatch, factory)
    receipt = execute_local_release_gate(
        gate_id=ReleaseGateId.RUFF_CHECK,
        repository_root=ROOT,
        evidence_root=tmp_path,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
    )
    _result, binding = _result_for_receipt(tmp_path, ReleaseGateId.RUFF_CHECK)

    with pytest.raises(ValueError, match="receipt projection"):
        validate_local_release_gate_result_artifact(
            evidence_root=tmp_path,
            binding=binding,
            expected_candidate_observation_sha256="e" * 64,
            expected_run_binding_sha256=RUN_BINDING_SHA256,
            expected_receipt=receipt,
        )

    monkeypatch.setattr(
        runtime_module,
        "_observe_tool_distribution",
        lambda name: runtime_module._DistributionObservation(
            name=name,
            version="1.2.3",
            inventory_sha256="f" * 64,
        ),
    )
    with pytest.raises(ValueError, match="receipt projection"):
        validate_local_release_gate_result_artifact(
            evidence_root=tmp_path,
            binding=binding,
            expected_candidate_observation_sha256=CANDIDATE_SHA256,
            expected_run_binding_sha256=RUN_BINDING_SHA256,
            expected_receipt=receipt,
        )


def test_result_schema_rejects_missing_generator_and_rehashed_guard_tampering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    factory = _FakePopenFactory()
    _install_fake_process(monkeypatch, factory)
    execute_local_release_gate(
        gate_id=ReleaseGateId.RUFF_CHECK,
        repository_root=ROOT,
        evidence_root=tmp_path,
        candidate_observation_sha256=CANDIDATE_SHA256,
        run_binding_sha256=RUN_BINDING_SHA256,
    )
    result, _binding = _result_for_receipt(tmp_path, ReleaseGateId.RUFF_CHECK)

    payload = result.model_dump(mode="json")
    del payload["generated_by"]
    with pytest.raises(ValidationError, match="generated_by"):
        LocalReleaseGateResult.model_validate(payload)

    payload = result.model_dump(mode="json", exclude={"result_sha256"})
    payload["network_guard_sha256"] = "0" * 64
    payload["result_sha256"] = canonical_sha256(payload)
    with pytest.raises(ValidationError, match="network guard"):
        LocalReleaseGateResult.model_validate(payload)


def test_safe_path_guard_loads_and_denies_direct_network_apis(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    gate_id = ReleaseGateId.RUFF_CHECK
    guard_root = runtime_module._install_network_guard(runtime_root, gate_id=gate_id)
    environment = runtime_module._fixed_child_environment(
        runtime_root,
        network_guard_root=guard_root,
        gate_id=gate_id,
    )
    script = """
import _socket
import socket

actions = (
    lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("127.0.0.1", 9)),
    lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM).connect(("::1", 9)),
    lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect("/tmp/absent"),
    lambda: socket.create_connection(("127.0.0.1", 9)),
    lambda: socket.getaddrinfo("localhost", 9),
    lambda: _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM).connect(("127.0.0.1", 9)),
)
denied = 0
for action in actions:
    try:
        action()
    except PermissionError:
        denied += 1
print("denied" if denied == len(actions) else "unsafe")
"""

    completed = subprocess.run(
        [sys.executable, "-P", "-c", script],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        timeout=10,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"denied\n"
    assert completed.stderr == b""


def test_safe_path_rejects_repository_local_tool_shadow(tmp_path: Path) -> None:
    runtime_root = tmp_path / "runtime"
    repository = tmp_path / "shadow-repository"
    runtime_root.mkdir()
    repository.mkdir()
    (repository / "ruff.py").write_text(
        'raise RuntimeError("repository-local shadow was imported")\n',
        encoding="utf-8",
    )
    gate_id = ReleaseGateId.RUFF_CHECK
    guard_root = runtime_module._install_network_guard(runtime_root, gate_id=gate_id)
    environment = runtime_module._fixed_child_environment(
        runtime_root,
        network_guard_root=guard_root,
        gate_id=gate_id,
    )

    outcome = runtime_module._execute_fixed_process(
        argv=(sys.executable, "-P", "-m", "ruff", "--version"),
        repository_root=repository,
        runtime_root=runtime_root,
        environment=environment,
        timeout_seconds=10,
    )

    assert outcome.returncode == 0
    assert outcome.stdout.startswith(b"ruff ")
    assert b"shadow" not in outcome.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group containment")
def test_successful_process_cleans_up_surviving_descendant_group(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_root = tmp_path / "runtime"
    repository = tmp_path / "repository"
    runtime_root.mkdir()
    repository.mkdir()
    gate_id = ReleaseGateId.RUFF_CHECK
    guard_root = runtime_module._install_network_guard(runtime_root, gate_id=gate_id)
    environment = runtime_module._fixed_child_environment(
        runtime_root,
        network_guard_root=guard_root,
        gate_id=gate_id,
    )
    real_popen: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen
    process_groups: list[int] = []

    def recording_popen(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        process = real_popen(*args, **kwargs)
        process_groups.append(process.pid)
        return process

    monkeypatch.setattr(runtime_module.subprocess, "Popen", recording_popen)
    script = (
        "import subprocess, sys; "
        "child = subprocess.Popen("
        "[sys.executable, '-P', '-c', 'import time; time.sleep(60)']); "
        "print(child.pid, flush=True)"
    )
    outcome = runtime_module._execute_fixed_process(
        argv=(sys.executable, "-P", "-c", script),
        repository_root=repository,
        runtime_root=runtime_root,
        environment=environment,
        timeout_seconds=10,
    )

    assert outcome.returncode == 0
    assert outcome.stdout.strip().isdigit()
    assert len(process_groups) == 1
    with pytest.raises(ProcessLookupError):
        os.killpg(process_groups[0], 0)


def test_real_distribution_inventory_is_nonempty_and_deterministic() -> None:
    first = runtime_module._observe_tool_distribution("ruff")
    second = runtime_module._observe_tool_distribution("ruff")

    assert first == second
    assert first.name.casefold() == "ruff"
    assert len(first.inventory_sha256) == 64
