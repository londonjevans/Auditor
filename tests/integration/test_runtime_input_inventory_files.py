"""Read-only discovery over disposable copies of supplied tooling source; no execution."""

from __future__ import annotations

import socket
import subprocess
from pathlib import Path
from typing import NoReturn

import pytest

from mmaudit.orchestration import autonomy_gate_inventory as inventory

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def no_network_or_child(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("input inventory attempted network or child execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def runtime_tree(tmp_path: Path) -> Path:
    source_root = ROOT / "src/mmaudit"
    root = tmp_path / "copied-runtime"
    root.mkdir()
    for original in inventory._python_source_paths(source_root):
        path = root / original.relative_to(source_root)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(original.read_bytes())
    return root


@pytest.mark.parametrize(
    "module,before,after",
    [
        (
            "scanners/foundry.py",
            "process.wait(timeout=_remaining_deadline_seconds(deadline, maximum=0.1))",
            "process.wait(timeout=_remaining_deadline_seconds(deadline, maximum=0.2))",
        ),
        ("scanners/foundry.py", "result.stdout", "result.stderr"),
        ("scanners/foundry_debugger.py", "call.stdin", "call.stderr"),
        (
            "repository/file_custody.py",
            "os.close(parent_descriptor)",
            "os.close(root.descriptor)",
        ),
        ("solidity/solc_capture_worker.py", "time.monotonic()", "time.perf_counter()"),
        (
            "solidity/solc_capture_worker.py",
            "min(65_536, maximum + 1 - len(raw))",
            "min(65_537, maximum + 1 - len(raw))",
        ),
        ("solidity/solc_capture_worker.py", "shell=False", "shell=True"),
        ("solidity/solc_capture_worker.py", "sys.flags", "sys.__dict__"),
        ("scanners/solc_capture.py", " -IBS\\n", " -I\\n"),
        ("scanners/solc_capture.py", "namespace['capture_main']", "namespace['other_entrypoint']"),
        (
            "scanners/solc_capture.py",
            "namespace['debugger_launch_main']",
            "namespace['other_entrypoint']",
        ),
        ("solidity/solc_capture_worker.py", "os.dup2(handles[-1], 0)", "os.dup2(handles[-1], 1)"),
        (
            "scanners/solc_capture.py",
            "namespace['coverage_launch_main']",
            "namespace['other_entrypoint']",
        ),
    ],
)
def test_changed_runtime_input_refuses_against_the_same_accepted_tree(
    runtime_tree: Path, module: str, before: str, after: str
) -> None:
    accepted = inventory._discover_runtime_execution_sources(runtime_tree)
    assert len(accepted) == 1481
    path = runtime_tree / module
    original = path.read_text()
    assert before in original
    path.write_text(original.replace(before, after, 1))
    with pytest.raises(inventory.AutonomyInventoryError, match="runtime execution"):
        inventory._discover_runtime_execution_sources(runtime_tree)


@pytest.mark.parametrize(
    "before,after",
    [
        (
            "for path, identity in selected.parent.component_identities:\n        metadata = path.lstat()",
            "for path, identity in selected.parent.component_identities:\n        metadata = path.stat()",
        ),
        ("os.fstat(root.descriptor)", "os.fstat(parent_descriptor)"),
        ("os.fstat(parent_descriptor)", "os.fstat(root.descriptor)"),
    ],
)
def test_batch_directory_observations_cannot_change_in_the_accepted_source_tree(
    runtime_tree: Path, before: str, after: str
) -> None:
    accepted = inventory._discover_external_input_sources(runtime_tree)
    assert len(accepted) == 2329
    path = runtime_tree / "repository/file_custody.py"
    original = path.read_text()
    assert original.count(before) == 1
    path.write_text(original.replace(before, after, 1))
    with pytest.raises(inventory.AutonomyInventoryError, match="filesystem input"):
        inventory._discover_external_input_sources(runtime_tree)


@pytest.mark.parametrize(
    "module", ["solidity/solc_capture_worker.py", "scanners/foundry_debugger.py"]
)
def test_missing_capture_module_cannot_disappear_from_the_closed_runtime_population(
    runtime_tree: Path,
    module: str,
) -> None:
    assert len(inventory._discover_runtime_execution_sources(runtime_tree)) == 1481
    (runtime_tree / module).unlink()
    with pytest.raises(inventory.AutonomyInventoryError, match="runtime execution"):
        inventory._discover_runtime_execution_sources(runtime_tree)


def test_canonical_inventory_round_trips_without_promoting_runtime_authority(
    tmp_path: Path,
) -> None:
    raw = inventory.render_autonomy_gate_inventory(repository_root=ROOT)
    assert raw == (ROOT / inventory.AUTONOMY_INVENTORY_PATH).read_text()
    path = tmp_path / "inventory.json"
    path.write_text(raw)
    result = inventory.load_autonomy_gate_inventory(path)
    assert result.source_count == 6125 and result.source_occurrence_count == 6128
    assert result.logical_gate_count == 35
    assert result.unsatisfied_gate_count == 29 and result.current_manual_gate_count == 15
    assert result.runtime_authority is result.managed_run_ready is False
    assert result.provider_or_network_accessed is result.secret_material_read is False
    path.write_text(raw[:-1])
    with pytest.raises(inventory.AutonomyInventoryError, match="not canonical"):
        inventory.load_autonomy_gate_inventory(path)
