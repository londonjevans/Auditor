"""Offline controls: failed formal-process bounds must never become successful evidence."""

from __future__ import annotations

import subprocess
import sys
from types import SimpleNamespace

import pytest

from mmaudit.config import FormalConfig
from mmaudit.models.schemas import FormalToolStatus, InvariantSuite
from mmaudit.solidity import formal
from tests.unit.test_formal import (
    FixedAdapter,
    PassthroughIsolation,
    _index,
    _project,
    _repository,
)


@pytest.fixture
def supervised(monkeypatch, tmp_path):
    class Process:
        pid = 987654321  # Inert identity; every process operation is replaced below.
        returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout):
            if self.returncode is None:
                raise subprocess.TimeoutExpired("synthetic formal process", timeout)
            return self.returncode

    process = Process()
    calls = []
    launches = []
    now = [0.0]

    def launch(command, **kwargs):
        launches.append((command, kwargs))
        return process

    def stop(selected):
        assert selected is process
        calls.append("stop")
        process.returncode = -9

    def cleanup(selected, *, diagnostic):
        assert selected is process
        calls.append("cleanup")
        return None

    def ceiling(allowance):
        calls.append(("ceiling", allowance))
        return 321

    monkeypatch.setattr(formal.subprocess, "Popen", launch)
    monkeypatch.setattr(formal, "_stop_process", stop)
    monkeypatch.setattr(formal, "_cleanup_lingering_process_group", cleanup, raising=False)
    monkeypatch.setattr(formal, "_darwin_uid_process_ceiling", ceiling, raising=False)
    monkeypatch.setattr(formal, "_darwin_process_group_rss_bytes", lambda pid: 0, raising=False)
    monkeypatch.setattr(formal.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(formal.time, "sleep", lambda seconds: now.__setitem__(0, now[0] + seconds))
    arguments = dict(
        command=["inert-formal-fixture"],
        cwd=tmp_path,
        environment={},
        stdout_path=tmp_path / "stdout.txt",
        stderr_path=tmp_path / "stderr.txt",
        timeout=0.15,
        max_output_bytes=128,
    )
    return process, calls, launches, arguments


def test_formal_launch_uses_observed_uid_ceiling_and_attests_group_exit(supervised, monkeypatch):
    process, calls, launches, arguments = supervised
    process.returncode = 0
    limits = []
    monkeypatch.setattr(formal, "_limit_process", lambda **kwargs: limits.append(kwargs))

    assert formal._bounded_process(**arguments) == 0

    assert calls == [("ceiling", 64), "cleanup"]
    assert len(launches) == 1
    options = launches[0][1]
    assert options["shell"] is False and options["start_new_session"] is True
    options["preexec_fn"]()
    assert limits == [{"nproc_ceiling": 321}]


@pytest.mark.parametrize("observed", [4 * 1024**3 + 1, 8 * 1024**3])
def test_formal_memory_bound_kills_before_reporting_success(supervised, monkeypatch, observed):
    _, calls, _, arguments = supervised
    monkeypatch.setattr(formal, "_darwin_process_group_rss_bytes", lambda pid: observed)

    assert formal._bounded_process(**arguments) == "memory_exceeded"
    assert calls == [("ceiling", 64), "stop", "cleanup"]


def test_formal_missing_memory_observation_is_not_success(supervised, monkeypatch):
    _, calls, _, arguments = supervised

    def unavailable(pid):
        raise OSError("synthetic unavailable process observation")

    monkeypatch.setattr(formal, "_darwin_process_group_rss_bytes", unavailable)
    assert formal._bounded_process(**arguments) == "memory_unavailable"
    assert calls == [("ceiling", 64), "stop", "cleanup"]


def test_formal_memory_observation_exit_race_still_checks_group_absence(supervised, monkeypatch):
    process, calls, _, arguments = supervised

    def exited(pid):
        process.returncode = 0
        raise OSError("synthetic leader exited during observation")

    monkeypatch.setattr(formal, "_darwin_process_group_rss_bytes", exited)
    assert formal._bounded_process(**arguments) == 0
    assert calls == [("ceiling", 64), "cleanup"]


def test_formal_missing_uid_observation_refuses_before_launch(supervised, monkeypatch):
    _, _, launches, arguments = supervised

    def unavailable(allowance):
        raise OSError("synthetic unavailable UID observation")

    monkeypatch.setattr(formal, "_darwin_uid_process_ceiling", unavailable)
    with pytest.raises(OSError, match="UID observation"):
        formal._bounded_process(**arguments)
    assert launches == []


def test_formal_timeout_keeps_original_deadline_and_cleans_group(supervised):
    _, calls, _, arguments = supervised
    assert formal._bounded_process(**arguments) == "timed_out"
    assert calls == [("ceiling", 64), "stop", "cleanup"]


@pytest.mark.parametrize("stream", ["stdout_path", "stderr_path", "additional"])
@pytest.mark.parametrize("already_exited", [False, True])
def test_formal_output_bound_also_applies_to_fast_completed_processes(
    supervised, monkeypatch, stream, already_exited
):
    process, calls, launches, arguments = supervised
    if already_exited:
        process.returncode = 0
    output = arguments["cwd"] / "result.json"
    arguments["additional_output_paths"] = [output]
    selected = output if stream == "additional" else arguments[stream]
    original = formal.subprocess.Popen

    def launch(*args, **kwargs):
        selected.write_bytes(b"x" * 129)
        return original(*args, **kwargs)

    monkeypatch.setattr(formal.subprocess, "Popen", launch)
    assert formal._bounded_process(**arguments) == "output_exceeded"
    assert len(launches) == 1
    assert calls[-1] == "cleanup"


def test_formal_descendants_cannot_outlive_successful_leader(supervised, monkeypatch):
    process, _, _, arguments = supervised
    process.returncode = 0
    monkeypatch.setattr(
        formal,
        "_cleanup_lingering_process_group",
        lambda process, **kwargs: "synthetic lingering descendant refused",
    )
    assert formal._bounded_process(**arguments) == "descendants_remaining"


def test_formal_unexpected_monitor_failure_still_cleans_owned_process(supervised, monkeypatch):
    _, calls, _, arguments = supervised

    def failed_sleep(seconds):
        raise RuntimeError("synthetic supervisor interruption")

    monkeypatch.setattr(formal.time, "sleep", failed_sleep)
    with pytest.raises(RuntimeError, match="supervisor interruption"):
        formal._bounded_process(**arguments)
    assert calls == [("ceiling", 64), "stop", "cleanup"]


@pytest.fixture
def limits(monkeypatch):
    observed = {}
    module = SimpleNamespace(
        RLIMIT_CPU="CPU",
        RLIMIT_FSIZE="FSIZE",
        RLIMIT_NOFILE="NOFILE",
        RLIMIT_NPROC="NPROC",
        RLIMIT_AS="AS",
        setrlimit=lambda kind, value: observed.__setitem__(kind, value),
    )
    monkeypatch.setitem(sys.modules, "resource", module)
    monkeypatch.setattr(sys, "platform", "linux")
    return module, observed


@pytest.mark.parametrize("ceiling", [None, 321])
def test_formal_limiter_preserves_original_numeric_bounds(limits, ceiling):
    _, observed = limits
    formal._limit_process(nproc_ceiling=ceiling)
    assert observed == {
        "CPU": (600, 600),
        "FSIZE": (100_000_000, 100_000_000),
        "NOFILE": (256, 256),
        "NPROC": ((64, 64) if ceiling is None else (321, 321)),
        "AS": (4 * 1024**3, 4 * 1024**3),
    }


@pytest.mark.parametrize("limit", ["CPU", "FSIZE", "NOFILE", "NPROC", "AS"])
@pytest.mark.parametrize("failure", [OSError, ValueError])
@pytest.mark.parametrize("platform", ["linux", "darwin"])
def test_formal_limit_install_failure_is_not_silently_ignored(
    limits, monkeypatch, limit, failure, platform
):
    module, observed = limits
    monkeypatch.setattr(sys, "platform", platform)

    def apply(kind, value):
        if kind == limit:
            raise failure("synthetic rejected resource bound")
        observed[kind] = value

    module.setrlimit = apply
    if platform == "darwin" and limit == "AS":
        formal._limit_process(nproc_ceiling=321)
        assert observed["NPROC"] == (321, 321)
        assert "AS" not in observed
    else:
        with pytest.raises(RuntimeError, match="resource bounds"):
            formal._limit_process(nproc_ceiling=321)


@pytest.mark.parametrize("ceiling", [None, 0, -1, True])
def test_darwin_formal_limiter_requires_a_real_parent_observed_ceiling(
    limits, monkeypatch, ceiling
):
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(RuntimeError, match="resource bounds"):
        formal._limit_process(nproc_ceiling=ceiling)
    assert limits[1] == {}


def test_formal_missing_resource_module_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)
    with pytest.raises(RuntimeError, match="resource bounds"):
        formal._limit_process()


@pytest.mark.parametrize(
    "outcome",
    [
        "memory_exceeded",
        "memory_unavailable",
        "descendants_remaining",
        "unknown_failure",
        True,
        None,
        subprocess.SubprocessError("synthetic preexec failed"),
    ],
)
def test_formal_runner_never_promotes_resource_failure_to_success(tmp_path, monkeypatch, outcome):
    root = _repository(tmp_path)
    executable = tmp_path / "inert-formal-fixture"
    executable.write_text("inert fixture; never executed\n")
    executable.chmod(0o700)
    adapter = FixedAdapter()
    adapter.available = lambda repository_root: executable
    monkeypatch.setattr(formal, "_isolated_tool_version", lambda *args, **kwargs: "fixed 1.0")

    def bounded(*args, **kwargs):
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    monkeypatch.setattr(formal, "_bounded_process", bounded)
    runner = formal.FormalRunner(
        FormalConfig(enabled=True), backend=PassthroughIsolation(), adapters=[adapter]
    )
    result = runner.run(
        repository_root=root,
        projects=[_project()],
        index=_index(),
        invariants=InvariantSuite(),
        private_dir=tmp_path / "private",
    )[0]
    assert result.status is FormalToolStatus.FAILED
    assert result.evidence == []
    assert result.failure_reason
