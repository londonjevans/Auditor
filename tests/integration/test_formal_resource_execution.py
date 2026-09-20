"""Real, inert local child processes exercise formal limits without compiling a target."""

from __future__ import annotations

import json
import sys

import pytest

from mmaudit.scanners.base import sanitized_scanner_environment
from mmaudit.solidity import formal
from mmaudit.solidity.reproduction import default_isolation_backend

pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="Darwin resource compatibility")


def _arguments(tmp_path, code):
    backend = default_isolation_backend("auto")
    if backend is None:
        pytest.skip("no hardened local isolation backend is available")
    private = tmp_path / "private"
    environment = sanitized_scanner_environment(private)
    workspace = private / "workspace"
    workspace.mkdir()
    command = backend.wrap(
        [sys.executable, "-I", "-c", code],
        workspace=workspace,
        private_dir=private,
        rpc_port=1,
    )
    return dict(
        command=command,
        cwd=workspace,
        environment=environment,
        stdout_path=private / "stdout.txt",
        stderr_path=private / "stderr.txt",
        timeout=10,
        max_output_bytes=4096,
    )


def test_formal_real_child_inherits_fixed_bounds_and_exits_locally(tmp_path, monkeypatch):
    observed = []
    original = formal._darwin_uid_process_ceiling

    def ceiling(allowance):
        result = original(allowance)
        observed.append((allowance, result))
        return result

    monkeypatch.setattr(formal, "_darwin_uid_process_ceiling", ceiling)
    child = (
        "import json,resource; "
        "names=('RLIMIT_CPU','RLIMIT_FSIZE','RLIMIT_NOFILE','RLIMIT_NPROC'); "
        "print(json.dumps({name:resource.getrlimit(getattr(resource,name)) for name in names}))"
    )
    code = f"import subprocess,sys; subprocess.run([sys.executable,'-I','-c',{child!r}],check=True)"
    arguments = _arguments(tmp_path, code)

    assert formal._bounded_process(**arguments) == 0

    limits = json.loads(arguments["stdout_path"].read_text())
    assert len(observed) == 1 and observed[0][0] == 64
    assert limits == {
        "RLIMIT_CPU": [600, 600],
        "RLIMIT_FSIZE": [100_000_000, 100_000_000],
        "RLIMIT_NOFILE": [256, 256],
        "RLIMIT_NPROC": [observed[0][1], observed[0][1]],
    }
    assert arguments["stderr_path"].read_bytes() == b""


@pytest.mark.parametrize("unavailable", [False, True])
def test_formal_real_process_stops_on_injected_memory_supervision_failure(
    tmp_path, monkeypatch, unavailable
):
    # No large allocation: deterministic observation failure while one inert
    # local process sleeps. The real supervisor must stop and reap that process.
    arguments = _arguments(tmp_path, "import time; time.sleep(5)")
    processes = []
    original = formal.subprocess.Popen

    def launch(*args, **kwargs):
        process = original(*args, **kwargs)
        processes.append(process)
        return process

    def memory(pid):
        assert pid == processes[0].pid
        if unavailable:
            raise OSError("synthetic failed memory observation")
        return 4 * 1024**3 + 1

    monkeypatch.setattr(formal.subprocess, "Popen", launch)
    monkeypatch.setattr(formal, "_darwin_process_group_rss_bytes", memory)

    result = formal._bounded_process(**arguments)

    assert result == ("memory_unavailable" if unavailable else "memory_exceeded")
    assert len(processes) == 1 and processes[0].returncode is not None
    assert processes[0].poll() is not None
    assert arguments["stdout_path"].read_bytes() == b""
