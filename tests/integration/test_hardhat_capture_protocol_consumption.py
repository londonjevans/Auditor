"""Real finite Node/reporter capture, explicitly MOCK and never Hardhat/Mocha execution."""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from mmaudit.models.schemas import ExecutionEvidenceKind, RepositoryTestExecutionStatus
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SOURCE_PATH
from mmaudit.scanners.hardhat_protocol import (
    HardhatProtocolBindingError,
    consume_hardhat_test_phase_capture,
    prepare_hardhat_test_phase_from_capture,
)
from mmaudit.scanners.hardhat_supervision import (
    HARDHAT_PHASE_REPORT_NAME,
    supervise_hardhat_phase_process,
)
from tests.hardhat_capture_support import inputs

CONTROL = Path(__file__).parents[1] / "fixtures/hardhat_supervision/reporter_control.cjs"


@pytest.fixture
def node():
    selected = shutil.which("node")
    if selected is None:
        pytest.skip("INCONCLUSIVE: Node is unavailable for the fixed reference-reporter control")
    return str(Path(selected).resolve(strict=True))


@pytest.fixture(autouse=True)
def owned_offline_processes(monkeypatch, node):
    def no_socket(*args, **kwargs):
        pytest.fail("invariant: fixed reporter controls cannot open network connections")

    original = subprocess.Popen
    processes = []

    def launch(command, **kwargs):
        assert command[:3] == (node, str(CONTROL), str(HARDHAT_REPORTER_SOURCE_PATH))
        assert kwargs["env"] == {} and kwargs["shell"] is False
        assert kwargs["start_new_session"] is True and kwargs["close_fds"] is True
        process = original(command, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(socket, "socket", no_socket)
    monkeypatch.setattr(subprocess, "Popen", launch)
    yield processes
    for process in processes:
        alive = process.poll() is None
        if alive:
            process.kill()
            process.wait(timeout=2)
        assert not alive, "owned reporter child required emergency fixture cleanup"
        assert process.stdout.closed and process.stderr.closed


def _capture(
    node, request, root, output, *, selection=None, mode="pass", exit_code=0, stale_request=False
):
    output.mkdir(mode=0o700)
    payload = request.model_dump(mode="json")
    if stale_request:
        payload["request_sha256"] = "a" * 64
    command = (
        node,
        str(CONTROL),
        str(HARDHAT_REPORTER_SOURCE_PATH),
        str(output / HARDHAT_PHASE_REPORT_NAME),
        str(root),
        json.dumps(payload),
        selection.model_dump_json() if selection is not None else "{}",
        mode,
        str(exit_code),
    )
    return supervise_hardhat_phase_process(
        request, command=command, workspace=root, output_root=output, environment={}
    )


@pytest.mark.parametrize(
    "mode,exit_code,status",
    [
        ("pass", 0, RepositoryTestExecutionStatus.PASSED),
        ("fail", 7, RepositoryTestExecutionStatus.FAILED),
        ("skip", 0, RepositoryTestExecutionStatus.SKIPPED),
    ],
)
def test_actual_captured_two_phase_protocol_preserves_noncrediting_observations(
    tmp_path, node, mode, exit_code, status
):
    root, config, request, _ = inputs(tmp_path)
    inventory_capture = _capture(node, request, root, tmp_path / "inventory-output")
    prepared = prepare_hardhat_test_phase_from_capture(
        request, inventory_capture, root=root, smart_contracts=config
    )
    test_capture = _capture(
        node,
        prepared.test_request,
        root,
        tmp_path / "test-output",
        selection=prepared.selection,
        mode=mode,
        exit_code=exit_code,
    )
    report = consume_hardhat_test_phase_capture(
        prepared, test_capture, root=root, smart_contracts=config
    )
    execution_evidence = ExecutionEvidenceKind.MOCK
    assert execution_evidence is ExecutionEvidenceKind.MOCK
    assert report.results[0].status is status
    assert report.execution_credit is report.authorship_claim is report.safety_claim is False
    assert prepared.runtime_authority is prepared.execution_credit is False
    assert test_capture.process_exit_code == exit_code
    assert test_capture.stdout == test_capture.stderr == b""
    assert report.request_sha256 == prepared.test_request.request_sha256
    assert report.selection_sha256 == prepared.selection.selection_sha256
    assert len(prepared.selection.tests) == 1


@pytest.mark.parametrize(
    "mode,exit_code,stale_request", [("pass", 7, False), ("fail", 0, False), ("pass", 0, True)]
)
def test_actual_report_cannot_override_exit_or_request_binding(
    tmp_path, node, mode, exit_code, stale_request
):
    root, config, request, _ = inputs(tmp_path)
    inventory_capture = _capture(node, request, root, tmp_path / "inventory-output")
    prepared = prepare_hardhat_test_phase_from_capture(
        request, inventory_capture, root=root, smart_contracts=config
    )
    test_capture = _capture(
        node,
        prepared.test_request,
        root,
        tmp_path / "test-output",
        selection=prepared.selection,
        mode=mode,
        exit_code=exit_code,
        stale_request=stale_request,
    )
    with pytest.raises(HardhatProtocolBindingError):
        consume_hardhat_test_phase_capture(
            prepared, test_capture, root=root, smart_contracts=config
        )


def test_actual_stale_inventory_refuses_before_a_second_phase_is_prepared(
    tmp_path, node, owned_offline_processes
):
    root, config, request, _ = inputs(tmp_path)
    inventory_capture = _capture(
        node, request, root, tmp_path / "inventory-output", stale_request=True
    )
    with pytest.raises(HardhatProtocolBindingError):
        prepare_hardhat_test_phase_from_capture(
            request, inventory_capture, root=root, smart_contracts=config
        )
    assert len(owned_offline_processes) == 1


def test_actual_captured_report_is_rejected_after_source_drift(tmp_path, node):
    root, config, request, _ = inputs(tmp_path)
    inventory_capture = _capture(node, request, root, tmp_path / "inventory-output")
    prepared = prepare_hardhat_test_phase_from_capture(
        request, inventory_capture, root=root, smart_contracts=config
    )
    test_capture = _capture(
        node, prepared.test_request, root, tmp_path / "test-output", selection=prepared.selection
    )
    (root / "test/audit/Vault.ts").write_text("// synthetic changed source after child cleanup\n")
    with pytest.raises(HardhatProtocolBindingError):
        consume_hardhat_test_phase_capture(
            prepared, test_capture, root=root, smart_contracts=config
        )
