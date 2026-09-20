"""Disposable journal/ledger custody tests; native issuance is explicitly isolated."""

from __future__ import annotations

import os
from decimal import Decimal

import pytest

from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_publication import measured, prepare_publication
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["bytes", "same_bytes_inode", "symlink", "ancestor", "extra"])
async def test_journal_change_after_capture_cannot_publish_measured_subject(
    measurement_protocol, change
):
    state = prepare_publication(measurement_protocol())
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            captured = state.observations

            def mutate():
                if state.observations != captured + 2:
                    return
                path = state.root / "000.json"
                if change == "bytes":
                    path.write_bytes(path.read_bytes() + b"\n")
                elif change == "same_bytes_inode":
                    replacement = state.root / "replacement.json"
                    replacement.write_bytes(path.read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, path)
                elif change == "symlink":
                    target = state.root / "retained.json"
                    path.rename(target)
                    path.symlink_to(target)
                elif change == "ancestor":
                    moved = state.root.with_name("moved-journal")
                    state.root.rename(moved)
                    state.root.mkdir(mode=0o700)
                    for item in moved.iterdir():
                        item.rename(state.root / item.name)
                else:
                    (state.root / "unregistered.json").write_text("{}")

            state.on_observe = mutate
            with pytest.raises(ValueError):
                measured(state, live)
            state.on_observe = None
    assert state.closed and state.secret.cleared
    assert not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["ledger", "proof", "live_field", "journal_inode"])
async def test_late_native_revalidation_cannot_hide_changed_source(measurement_protocol, change):
    state = prepare_publication(measurement_protocol())
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            captured = state.observations

            def mutate():
                # For a one-candidate numeric refusal: entry require, derive require,
                # refusal recheck, final require. Mutate at that last observation.
                if state.observations != captured + 4:
                    return
                if change == "ledger":
                    charge = state.ledger.reserve("synthetic-late", Decimal("1"))
                    state.ledger.reconcile(charge, Decimal("0.1"))
                elif change == "proof":
                    state.revoke(live.verification)
                elif change == "live_field":
                    object.__setattr__(live, "registration_sha256", "f" * 64)
                else:
                    path = state.root / "000.json"
                    replacement = state.root / "replacement.json"
                    replacement.write_bytes(path.read_bytes())
                    replacement.chmod(0o600)
                    os.replace(replacement, path)

            state.on_observe = mutate
            with pytest.raises(ValueError):
                measured(state, live)
            state.on_observe = None
            # Propagate a failed consumer regardless of the owner's additional cleanup checks.
            raise ValueError("synthetic rejected publication")
    assert state.closed and state.secret.cleared
    assert not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)
