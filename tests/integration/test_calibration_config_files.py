"""Exact C1/C2 handoff under real local journal changes and isolated native custody."""

from __future__ import annotations

import os
from decimal import Decimal

import pytest

from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_authenticated_calibration_config import build_config, prepare_config
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["bytes", "same_bytes_inode", "symlink", "ancestor", "extra"])
async def test_original_journal_custody_survives_between_native_publication_checks(
    measurement_protocol, change
):
    state = prepare_config(measurement_protocol)
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            initial = state.observations

            def mutate():
                # Start of second original publication check, before its fresh local capture.
                if state.observations != initial + 5:
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
                    target = state.root / "moved.json"
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
                build_config(state, live)
            state.on_observe = None
    assert state.closed and state.secret.cleared
    assert not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["config", "policy", "ledger", "proof", "live"])
async def test_same_source_is_required_through_proposal_construction(measurement_protocol, change):
    state = prepare_config(measurement_protocol)
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            original = state.config_namespace["_assemble_proposal"]

            def mutate_after_assembly(*args):
                result = original(*args)
                if change == "config":
                    state.config.reporting.markdown = not state.config.reporting.markdown
                elif change == "policy":
                    state.predecessor.maximum_validity_days -= 1
                elif change == "ledger":
                    reservation = state.ledger.reserve("synthetic-late", Decimal("1"))
                    state.ledger.reconcile(reservation, Decimal("0.1"))
                elif change == "proof":
                    state.revoke(live.verification)
                else:
                    # Equal bytes do not transfer ownership of borrowed object fields.
                    object.__setattr__(
                        live, "registration_sha256", live.registration_sha256.encode().decode()
                    )
                return result

            state.config_namespace["_assemble_proposal"] = mutate_after_assembly
            with pytest.raises(ValueError):
                build_config(state, live)
            raise ValueError("synthetic rejected configuration consumer")
    assert state.closed and state.secret.cleared
    assert not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)
