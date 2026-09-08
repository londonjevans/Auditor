"""Shared supervisor bounds narrow requests without altering their pinned identity."""

from __future__ import annotations

import subprocess

import pytest

from mmaudit.scanners import hardhat_supervision as supervision
from tests.unit.test_hardhat_supervision import inputs as inputs
from tests.unit.test_hardhat_supervision import no_execution as no_execution


@pytest.mark.parametrize("deadline", [True, "later", -1, 0, float("nan"), float("inf")])
def test_invalid_deadline_cannot_claim_or_launch(inputs, deadline):
    with pytest.raises(supervision.HardhatSupervisionError, match="deadline"):
        supervision.supervise_hardhat_phase_process(**inputs, absolute_deadline=deadline)
    assert not list(inputs["output_root"].parent.glob("*.claim"))


@pytest.mark.parametrize("allowance", [True, "1", -1, 0, 100_001, float("nan"), 1.5])
def test_output_allowance_cannot_expand_request_or_use_invalid_types(inputs, allowance):
    with pytest.raises(supervision.HardhatSupervisionError, match="allowance"):
        supervision.supervise_hardhat_phase_process(**inputs, maximum_output_bytes=allowance)


def test_expiry_during_launch_input_preparation_prevents_spawn(inputs, monkeypatch):
    clock = [100.0]
    original = supervision._command_and_environment

    def prepare(*args):
        result = original(*args)
        clock[0] = 102.0
        return result

    monkeypatch.setattr(supervision.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(supervision, "_command_and_environment", prepare)
    with pytest.raises(supervision.HardhatSupervisionError, match="before launch"):
        supervision.supervise_hardhat_phase_process(**inputs, absolute_deadline=101.0)


def test_shared_bounds_reach_capture_without_resealing_request(inputs, monkeypatch):
    class Pipe:
        def close(self):
            pass

    class Process:
        stdout, stderr = Pipe(), Pipe()
        returncode = 0

    def capture(process, **kwargs):
        assert kwargs["maximum_bytes"] == 128 and kwargs["deadline"] == 101.0
        (inputs["output_root"] / "hardhat-report.json").write_bytes(b"{}")
        return supervision.HardhatCaptureOutcome.EXITED, b"", b""

    original = inputs["request"].model_dump_json()
    monkeypatch.setattr(supervision.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(supervision, "_capture_pipes", capture)
    monkeypatch.setattr(supervision, "_cleanup_child", lambda child: True)
    result = supervision.supervise_hardhat_phase_process(
        **inputs, absolute_deadline=101.0, maximum_output_bytes=128
    )
    assert result.complete and result.request_sha256 == inputs["request"].request_sha256
    assert inputs["request"].model_dump_json() == original
