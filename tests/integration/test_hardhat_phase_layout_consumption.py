"""Owned local bridge/layout controls; constructed container commands are never executed."""

from __future__ import annotations

import copy
import stat
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from mmaudit import release_io
from mmaudit.isolation import container
from mmaudit.isolation.container import bind_hardhat_read_only_rpc_bridge
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.scanners.hardhat_supervision import supervise_hardhat_phase_process
from tests.hardhat_layout_support import layout_requests
from tests.integration.test_hardhat_supervision_consumption import CONTROL
from tests.unit.test_hardhat_isolation_backend import (
    live_private_bridge as live_private_bridge,
)
from tests.unit.test_hardhat_isolation_backend import (
    loopback_origin as loopback_origin,
)


@pytest.fixture
def short_private_root():
    # A canonical short POSIX temp path fits AF_UNIX limits on both macOS and Linux.
    with TemporaryDirectory(
        prefix="mmaudit-hh-layout-", dir=Path("/tmp").resolve(strict=True)
    ) as value:
        root = Path(value)
        root.chmod(0o700)
        yield root


@pytest.fixture(autouse=True)
def no_runtime_processes(monkeypatch):
    original = subprocess.Popen
    processes = []

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: layout checks cannot invoke a container or repository executable")

    def fixed_control_only(command, **kwargs):
        assert command[:3] == (str(Path(sys.executable).resolve(strict=True)), "-I", str(CONTROL))
        assert kwargs["env"] == {} and kwargs["shell"] is False
        assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
        process = original(command, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", fixed_control_only)
    yield
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned supervisor child required test-fixture cleanup"
        assert process.stdout.closed and process.stderr.closed


def _layouts(live):
    private, workspace, backend, _, binding = live
    return tuple(
        backend.wrap_hardhat_phase(
            ("hardhat", "test"),
            request,
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )
        for request in layout_requests(live)
    )


def test_phases_share_readonly_source_bridge_but_not_output_or_cleanup(live_private_bridge):
    private, workspace, backend, _, binding = live_private_bridge
    inventory, test = _layouts(live_private_bridge)
    assert inventory.private_dir != test.private_dir
    assert inventory.output_root != test.output_root
    for layout in (inventory, test):
        assert layout.private_dir.parent == private
        assert layout.output_root == layout.private_dir / "container-output"
        assert layout.execution_credit is layout.runtime_authority is False
        for directory in (
            layout.private_dir,
            layout.output_root,
            layout.private_dir / "container-runtime",
        ):
            assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        command = layout.command
        assert command[command.index("--network") + 1] == "none"
        assert command[command.index("--cidfile") + 1] == str(
            layout.private_dir / "container-runtime/container.cid"
        )
        mounts = [command[index + 1] for index, value in enumerate(command) if value == "--mount"]
        assert len(mounts) == 3
        assert any(f"src={workspace}," in item and item.endswith(",readonly") for item in mounts)
        assert any(
            f"src={backend.bridge_socket_path(private)}," in item and item.endswith(",readonly")
            for item in mounts
        )
        assert sum(item.endswith(",rw") for item in mounts) == 1
        assert any(f"src={layout.output_root}," in item and item.endswith(",rw") for item in mounts)
        assert not any(f"src={private}," in item for item in mounts)
        assert f"seccomp={layout.private_dir / 'container-runtime/hardhat-seccomp.json'}" in command
        backend.cleanup(layout.private_dir)  # No CID exists, so no runtime invocation is possible.
    binding.verify(backend, private)
    assert backend.execution_evidence is ExecutionEvidenceKind.UNVERIFIED


@pytest.mark.parametrize("index", [0, 1])
def test_argument_paths_translate_only_into_selected_phase_mounts(live_private_bridge, index):
    private, workspace, backend, _, binding = live_private_bridge
    request = layout_requests(live_private_bridge)[index]
    phase = private / f"hardhat-{request.phase}-{request.request_sha256}"
    layout = backend.wrap_hardhat_phase(
        (
            "hardhat",
            "test",
            str(workspace / "synthetic.ts"),
            str(phase / "container-output/hardhat-report.json"),
        ),
        request,
        workspace=workspace,
        private_dir=private,
        binding=binding,
    )
    assert layout.command[-2:] == (
        str(container._CONTAINER_WORKSPACE / "synthetic.ts"),
        str(container._CONTAINER_WRITABLE / "hardhat-report.json"),
    )


def test_phase_cannot_reference_previous_phase_output(live_private_bridge):
    private, workspace, backend, _, binding = live_private_bridge
    first, second = layout_requests(live_private_bridge)
    inventory = backend.wrap_hardhat_phase(
        ("hardhat",), first, workspace=workspace, private_dir=private, binding=binding
    )
    with pytest.raises(ValueError, match="outside isolated mounts"):
        backend.wrap_hardhat_phase(
            ("hardhat", str(inventory.output_root / "hardhat-report.json")),
            second,
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )
    assert (private / f"hardhat-test-{second.request_sha256}").is_dir()
    with pytest.raises(FileExistsError):
        backend.wrap_hardhat_phase(
            ("hardhat",), second, workspace=workspace, private_dir=private, binding=binding
        )


def test_phase_root_cannot_contain_the_source_workspace(live_private_bridge):
    private, _, backend, _, binding = live_private_bridge
    request, _ = layout_requests(live_private_bridge)
    workspace = private / f"hardhat-inventory-{request.request_sha256}" / "source"
    workspace.mkdir(parents=True)
    with pytest.raises(ValueError, match="overlaps its read-only source"):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert list(workspace.parent.iterdir()) == [workspace]


@pytest.mark.parametrize("index", [0, 1])
def test_same_request_cannot_reuse_output_or_cleanup_state(live_private_bridge, index):
    private, workspace, backend, _, binding = live_private_bridge
    layout = _layouts(live_private_bridge)[index]
    report = layout.output_root / "hardhat-report.json"
    cid = layout.private_dir / "container-runtime/container.cid"
    report.write_bytes(b"retained synthetic report")
    cid.write_bytes(b"a" * 64)
    with pytest.raises(FileExistsError):
        backend.wrap_hardhat_phase(
            ("hardhat", "test"),
            layout_requests(live_private_bridge)[index],
            workspace=workspace,
            private_dir=private,
            binding=binding,
        )
    assert report.read_bytes() == b"retained synthetic report" and cid.read_bytes() == b"a" * 64


@pytest.mark.parametrize("shape", ["directory", "file", "symlink"])
def test_preexisting_phase_target_is_not_replaced(live_private_bridge, shape):
    private, workspace, backend, _, binding = live_private_bridge
    request, _ = layout_requests(live_private_bridge)
    root = private / f"hardhat-inventory-{request.request_sha256}"
    canary = private / "owned-canary"
    canary.write_bytes(b"unchanged")
    if shape == "directory":
        root.mkdir(mode=0o700)
    elif shape == "file":
        root.write_bytes(b"unchanged")
    else:
        root.symlink_to(canary)
    with pytest.raises(FileExistsError):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert canary.read_bytes() == b"unchanged"
    assert root.is_dir() if shape == "directory" else root.read_bytes() == b"unchanged"


@pytest.mark.parametrize(
    "field,value",
    [
        ("image", "registry.example/other@sha256:" + "b" * 64),
        ("isolation_capability_sha256", "b" * 64),
        ("bridge_policy_sha256", "b" * 64),
        ("chain_id", 1),
        ("block_number", 1),
        ("block_hash", "0x" + "a" * 64),
    ],
)
def test_resealed_request_must_match_live_backend_and_state(live_private_bridge, field, value):
    private, workspace, backend, _, binding = live_private_bridge
    request, _ = layout_requests(live_private_bridge)
    values = request.model_dump(exclude={"request_sha256"})
    values[field] = value
    request = type(request).sealed(**values)
    before = set(private.iterdir())
    with pytest.raises(ValueError, match="live backend or pinned state"):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert set(private.iterdir()) == before


@pytest.mark.parametrize("change", ["closed", "copied_backend", "stopped", "other_root", "rebound"])
def test_retained_handle_is_exact_and_live(live_private_bridge, change):
    private, _, backend, bridge, binding = live_private_bridge
    replacement = None
    if change == "closed":
        binding.close()
    elif change == "copied_backend":
        backend = copy.copy(backend)
    elif change == "stopped":
        bridge.stop()
    elif change == "other_root":
        private = private / "other"
        private.mkdir(mode=0o700)
    else:
        binding.close()
        replacement = bind_hardhat_read_only_rpc_bridge(backend, private, bridge)
        replacement.verify(backend, private)
    try:
        with pytest.raises(ValueError):
            binding.verify(backend, private)
    finally:
        if replacement is not None:
            replacement.close()


@pytest.mark.parametrize(
    "change", ["request", "binding", "bridge", "backend", "source", "phase", "output", "runtime"]
)
def test_midconstruction_drift_never_returns_command(live_private_bridge, monkeypatch, change):
    private, workspace, backend, bridge, binding = live_private_bridge
    request, _ = layout_requests(live_private_bridge)
    original = release_io.write_file_evidence
    phase_root = private / f"hardhat-inventory-{request.request_sha256}"

    def mutate(**kwargs):
        result = original(**kwargs)
        if change == "request":
            object.__setattr__(request, "chain_id", 1)
        elif change == "binding":
            binding.close()
        elif change == "bridge":
            bridge.stop()
        elif change == "backend":
            object.__setattr__(backend, "image", "registry.example/changed@sha256:" + "c" * 64)
        elif change == "source":
            workspace.rename(private / "retained-workspace")
            workspace.mkdir()
        else:
            target = {
                "phase": phase_root,
                "output": phase_root / "container-output",
                "runtime": phase_root / "container-runtime",
            }[change]
            target.chmod(0o755)
        return result

    monkeypatch.setattr(release_io, "write_file_evidence", mutate)
    with pytest.raises(ValueError):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert phase_root.is_dir(), "failed phase claims must not be recycled"


def test_seccomp_preexisting_link_cannot_overwrite_owned_canary(live_private_bridge, monkeypatch):
    private, workspace, backend, _, binding = live_private_bridge
    request, _ = layout_requests(live_private_bridge)
    canary = private / "owned-canary"
    canary.write_bytes(b"unchanged")
    original = release_io.write_file_evidence

    def inject_link(**kwargs):
        (kwargs["evidence_root"] / kwargs["relative_path"]).symlink_to(canary)
        return original(**kwargs)

    monkeypatch.setattr(release_io, "write_file_evidence", inject_link)
    with pytest.raises((ValueError, OSError)):
        backend.wrap_hardhat_phase(
            ("hardhat",), request, workspace=workspace, private_dir=private, binding=binding
        )
    assert canary.read_bytes() == b"unchanged"


def test_cleanup_routing_targets_only_selected_phase_mock(live_private_bridge, monkeypatch):
    private, _, backend, _, _ = live_private_bridge
    inventory, test = _layouts(live_private_bridge)
    legacy = private / "container-runtime"
    legacy.mkdir(mode=0o700)
    roots = [
        inventory.private_dir / "container-runtime",
        test.private_dir / "container-runtime",
        legacy,
    ]
    for root, letter in zip(roots, "abc", strict=True):
        (root / "container.cid").write_text(letter * 64)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        assert command[-1] in {"a" * 64, "id=" + "a" * 64}
        assert kwargs["runtime_dir"] == roots[0]
        return b"" if len(calls) == 3 else b"a" * 64 + b"\n"

    monkeypatch.setattr("mmaudit.isolation.container_cleanup._run_control_command", fake_run)
    monkeypatch.setattr("mmaudit.isolation.container_cleanup._runtime_identity", lambda *_: "mock")
    # Cleanup CLI responses are mocked; use a real canonical external host-file observation.
    replace(backend, executable=str(Path(sys.executable).resolve(strict=True))).cleanup(
        inventory.private_dir
    )
    assert [call[1] for call in calls] == ["container", "rm", "container"]
    assert not (roots[0] / "container.cid").exists()
    assert (roots[1] / "container.cid").read_text() == "b" * 64
    assert (roots[2] / "container.cid").read_text() == "c" * 64


def test_both_layouts_consumed_once_by_real_fixed_parent_capture(live_private_bridge):
    private, workspace, backend, _, binding = live_private_bridge
    layouts = _layouts(live_private_bridge)
    for request, layout in zip(layout_requests(live_private_bridge), layouts, strict=True):
        capture = supervise_hardhat_phase_process(
            request,
            command=(
                str(Path(sys.executable).resolve(strict=True)),
                "-I",
                str(CONTROL),
                "success",
                str(layout.output_root),
            ),
            workspace=workspace,
            output_root=layout.output_root,
            environment={},
        )
        assert capture.complete and capture.process_exit_code == 0
        assert capture.report == b'{"synthetic":true}\n'
        assert capture.execution_credit is capture.runtime_authority is False
        claims = list(layout.private_dir.glob(".mmaudit-hardhat-*.claim"))
        assert len(claims) == 1 and not claims[0].is_relative_to(layout.output_root)
        assert not layout.output_root.is_relative_to(
            layouts[1 if layout is layouts[0] else 0].private_dir
        )
        binding.verify(backend, private)
    assert backend.execution_evidence is ExecutionEvidenceKind.UNVERIFIED
