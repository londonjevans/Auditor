"""Actual disposable filesystem failures with an explicitly isolated native lease.

No provider, REAL runner registration or positive authenticated campaign is used.
"""

from __future__ import annotations

import os

import pytest

from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)
from tests.unit.test_registered_calibration_measurement import read_result


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["bytes", "same_bytes_inode", "symlink", "ancestor", "extra"])
async def test_changed_staged_file_or_ancestor_cannot_publish_completion(
    measurement_protocol, change
):
    state = measurement_protocol()
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            path = state.output / "calibration.json"
            if change == "bytes":
                path.write_bytes(path.read_bytes() + b"\n")
            elif change == "same_bytes_inode":
                replacement = state.output / "replacement.json"
                replacement.write_bytes(path.read_bytes())
                replacement.chmod(0o600)
                os.replace(replacement, path)
            elif change == "symlink":
                moved = state.output / "retained.json"
                path.rename(moved)
                path.symlink_to(moved)
            elif change == "ancestor":
                moved = state.output.with_name("moved-output")
                state.output.rename(moved)
                state.output.mkdir(mode=0o700)
                (moved / "calibration.json").rename(path)
            else:
                (state.output / "unregistered.json").write_text("{}")
    assert state.closed and not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["occupied", "public_parent", "linked_parent", "same_root"])
async def test_output_refusal_happens_before_runner_entry(measurement_protocol, change):
    state = measurement_protocol()
    if change == "occupied":
        (state.output / "measurement.json").write_text("preserve me")
    elif change == "public_parent":
        state.output.chmod(0o755)
    elif change == "linked_parent":
        target = state.output.with_name("private-target")
        state.output.rename(target)
        state.output.symlink_to(target, target_is_directory=True)
    else:
        state.args["output_root"] = state.root
    with pytest.raises(ValueError):
        async with state.scope(**state.args):
            pytest.fail("output preflight allowed runner entry")
    assert not state.entered
    if change == "occupied":
        assert (state.output / "measurement.json").read_text() == "preserve me"


@pytest.mark.asyncio
async def test_consumed_runner_journal_is_not_a_completed_measurement_after_publication_failure(
    measurement_protocol,
):
    state = measurement_protocol()
    original = state.namespace["write_json_evidence"]

    def fail_receipt(**kwargs):
        if kwargs["relative_path"] == "measurement.json":
            raise OSError("synthetic publication storage failure")
        return original(**kwargs)

    state.namespace["write_json_evidence"] = fail_receipt
    with pytest.raises(OSError, match="storage failure"):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
    assert state.closed and state.journal.current.disposition == "CONSUMED"
    assert (state.output / "calibration.json").exists()
    assert not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError):
        read_result(state)


@pytest.mark.asyncio
async def test_extra_output_introduced_during_batch_cleanup_prevents_receipt(measurement_protocol):
    state = measurement_protocol()

    def add_unregistered_output():
        (state.output / "unexpected.json").write_text("{}")

    state.on_cleanup = add_unregistered_output
    with pytest.raises(ValueError, match="output set changed during cleanup"):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
    assert state.closed and state.journal.current.disposition == "CONSUMED"
    assert not (state.output / "measurement.json").exists()
