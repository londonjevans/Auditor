"""Actual fixed Python children enforce shared ceilings without any Hardhat/image authority."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

from mmaudit.scanners.hardhat_supervision import (
    HardhatCaptureOutcome,
    supervise_hardhat_phase_process,
)
from tests.integration.test_hardhat_supervision_consumption import CONTROL
from tests.integration.test_hardhat_supervision_consumption import no_network as no_network
from tests.integration.test_hardhat_supervision_consumption import (
    track_fixed_owned_processes as track_fixed_owned_processes,
)
from tests.unit.test_hardhat_protocol import _inventory_request


@pytest.mark.parametrize("bound", ["shared_deadline", "sealed_deadline", "shared_output"])
def test_actual_capture_obeys_tighter_allowance_and_reaps_child(tmp_path, bound):
    workspace, output = tmp_path / "workspace", tmp_path / "output"
    workspace.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    request = _inventory_request()
    if bound == "sealed_deadline":
        values = request.model_dump(exclude={"request_sha256"})
        values["timeout_seconds"] = 0.15
        request = type(request).sealed(**values)
    started = time.monotonic()
    result = supervise_hardhat_phase_process(
        request,
        command=(
            str(Path(sys.executable).resolve(strict=True)),
            "-I",
            str(CONTROL),
            "stream_limit" if bound == "shared_output" else "timeout",
            str(output),
        ),
        workspace=workspace,
        output_root=output,
        environment={},
        absolute_deadline=started + (0.15 if bound == "shared_deadline" else 5),
        maximum_output_bytes=1024 if bound == "shared_output" else None,
    )
    assert time.monotonic() - started < 1.5
    assert result.outcome is (
        HardhatCaptureOutcome.OUTPUT_LIMIT
        if bound == "shared_output"
        else HardhatCaptureOutcome.TIMED_OUT
    )
    assert not result.complete and result.report is None
    assert result.execution_credit is result.runtime_authority is False
    assert len(result.stdout) + len(result.stderr) <= 1024
    assert result.request_sha256 == request.request_sha256
