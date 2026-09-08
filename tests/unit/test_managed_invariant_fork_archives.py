"""Invariant archive preparation is exact input selection, never execution evidence."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest
from pydantic import ValidationError

from mmaudit.orchestration import managed_fork_archives as archives_module
from mmaudit.orchestration import managed_provisioning_runtime as runtime
from mmaudit.orchestration.managed_fork_archives import (
    ManagedForkArchiveError,
    ManagedForkArchiveSource,
)
from tests.managed_invariant_fork_support import (
    prepare_invariant_archives,
    prepared_invariant_archives,
)
from tests.unit.test_managed_offline_fork_consumers import _setup


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: archive preparation cannot execute or open sockets")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_invariant_archives(tmp_path, config_factory)


def test_invariant_archive_is_independent_of_primary_scanner_or_matrix(prepared):
    selected = prepare_invariant_archives(prepared)
    assert not selected.config.reproduction.enabled
    assert selected.reproduction_source_binding is None
    assert not selected.config.scanners.foundry_fork.enabled
    assert selected.state_ids == () and selected.primary_source_binding is None
    assert selected.invariant_source_binding.path == prepared[4].name
    assert selected.source_bindings == (selected.invariant_source_binding,)
    assert selected.config == prepared[1].config
    assert selected.runtime_authority is selected.complete_state is False
    selected.verify(prepared[1].config)
    assert not prepared[2].exists()


@pytest.mark.parametrize("value", ["0" * 64, "a" * 63, "A" * 64, "invalid", True, 1])
def test_invariant_digest_is_strict_nonzero_sha256(tmp_path, value):
    with pytest.raises(ValidationError):
        ManagedForkArchiveSource(archive_root=tmp_path, invariant_archive_sha256=value)


@pytest.mark.parametrize("field", ["expected_chain_id", "pinned_block_number"])
@pytest.mark.parametrize("missing", [False, True])
def test_invariant_archive_requires_exact_final_chain_and_block(prepared, field, missing):
    config = prepared[1].config
    setattr(config.reproduction, field, None if missing else 8)
    with pytest.raises(ManagedForkArchiveError):
        prepare_invariant_archives(prepared, config=config)


@pytest.mark.parametrize(
    "mode", ["invariants", "smart_contracts", "acknowledgement", "execute_generated"]
)
def test_invariant_archive_cannot_enable_disabled_or_unacknowledged_execution(prepared, mode):
    config = prepared[1].config
    if mode == "acknowledgement":
        config.smart_contracts.allow_fork_probing = False
    elif mode == "execute_generated":
        config.invariants.execute_generated = False
    else:
        getattr(config, mode).enabled = False
    with pytest.raises(ManagedForkArchiveError):
        prepare_invariant_archives(prepared, config=config)


def test_invariant_archive_drift_invalidates_retained_selection(prepared):
    selected = prepare_invariant_archives(prepared)
    prepared[4].write_text("{}")
    with pytest.raises(ManagedForkArchiveError):
        selected.verify(prepared[1].config)


def test_primary_and_invariant_roles_remain_separate_and_share_the_read_ceiling(
    prepared, monkeypatch
):
    config = prepared[1].config
    config.scanners.foundry_fork.enabled = True
    source = prepared[3].model_copy(
        update={"primary_archive_sha256": prepared[3].invariant_archive_sha256}
    )
    selected = prepare_invariant_archives(prepared, config=config, source=source)
    assert selected.primary_source_binding == selected.invariant_source_binding
    assert len(selected.source_bindings) == 2 and selected.state_ids == ()
    assert selected.primary_source_binding is not selected.invariant_source_binding
    monkeypatch.setattr(
        archives_module, "_MAX_TOTAL_ARCHIVE_BYTES", 2 * prepared[4].stat().st_size - 1
    )
    with pytest.raises(ManagedForkArchiveError):
        selected.verify(config)
    with pytest.raises(ManagedForkArchiveError):
        prepare_invariant_archives(prepared, config=config, source=source)


@pytest.mark.parametrize(
    "deadline",
    [True, float("nan"), float("inf"), -1, 0, pytest.param(10**1000, id="oversized-integer")],
)
def test_invalid_invariant_deadlines_refuse_before_listening(prepared, deadline):
    selected = prepare_invariant_archives(prepared)
    with pytest.raises(ManagedForkArchiveError):
        selected.start_invariant_attempt(
            repository=prepared[0], output=prepared[2], absolute_deadline=deadline
        )


@pytest.mark.parametrize("remaining", [1, 17, 18, 34])
def test_startup_cannot_shorten_the_original_child_budget(prepared, remaining):
    selected = prepare_invariant_archives(prepared)
    before = selected.config.model_dump_json()
    with pytest.raises(ManagedForkArchiveError):
        selected.start_invariant_attempt(
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + remaining,
        )
    assert selected.config.model_dump_json() == before


def test_maximum_repetition_policy_uses_independent_full_attempt_lifetimes(prepared):
    config = prepared[1].config
    config.reproduction.timeout_seconds = 1800
    config.reproduction.repetitions = 10
    selected = prepare_invariant_archives(prepared, config=config)
    assert selected.invariant_attempt_lifetime_seconds == 1832
    assert selected.config.reproduction.timeout_seconds == 1800
    assert selected.config.reproduction.repetitions == 10


def test_all_three_nonmatrix_roles_keep_their_selection_and_combined_read_bound(
    prepared, monkeypatch
):
    config = prepared[1].config
    config.scanners.foundry_fork.enabled = True
    config.reproduction.enabled = True
    digest = prepared[3].invariant_archive_sha256
    source = prepared[3].model_copy(
        update={"primary_archive_sha256": digest, "reproduction_archive_sha256": digest}
    )
    selected = prepare_invariant_archives(prepared, config=config, source=source)
    bindings = (
        selected.primary_source_binding,
        selected.reproduction_source_binding,
        selected.invariant_source_binding,
    )
    assert selected.state_ids == () and selected.source_bindings == bindings
    assert len({id(binding) for binding in bindings}) == 3
    assert all(binding == bindings[0] for binding in bindings)
    monkeypatch.setattr(
        archives_module, "_MAX_TOTAL_ARCHIVE_BYTES", 3 * prepared[4].stat().st_size - 1
    )
    with pytest.raises(ManagedForkArchiveError):
        selected.verify(config)
    with pytest.raises(ManagedForkArchiveError):
        prepare_invariant_archives(prepared, config=config, source=source)


@pytest.mark.parametrize("failure", ["start", "deadline", "interrupt", "exit"])
def test_invariant_factory_closes_every_acquired_lease_on_startup_failure(
    prepared, monkeypatch, failure
):
    selected = prepare_invariant_archives(prepared)
    calls = []
    sentinel = KeyboardInterrupt() if failure == "interrupt" else SystemExit(2)

    class LifecycleControl:
        def __init__(self, replay, *, lifetime_seconds):
            assert replay.source_binding == selected.invariant_source_binding
            assert lifetime_seconds == 33
            calls.append("construct")

        def start(self):
            calls.append("start")
            if failure in {"interrupt", "exit"}:
                raise sentinel
            if failure == "start":
                raise ValueError("synthetic startup failure")

        def stop(self, *, deadline):
            calls.append(("stop", deadline))

    ticks = iter((10, 10, 40))
    with monkeypatch.context() as patch:
        patch.setattr(archives_module, "OfflineForkRpcLease", LifecycleControl)
        patch.setattr(archives_module.time, "monotonic", lambda: next(ticks))
        with pytest.raises(
            type(sentinel) if failure in {"interrupt", "exit"} else ManagedForkArchiveError
        ):
            selected.start_invariant_attempt(
                repository=prepared[0], output=prepared[2], absolute_deadline=43
            )
    assert calls == ["construct", "start", ("stop", 43)]


@pytest.mark.parametrize("phase", ["prepared", "published"])
@pytest.mark.parametrize("existing", [False, True])
def test_invariant_source_drift_cannot_publish_or_replace_a_setup_receipt(
    prepared, tmp_path, monkeypatch, phase, existing
):
    if existing:
        _setup(prepared, tmp_path)
    output = tmp_path / "managed-setup"
    previous = {path.name: path.read_bytes() for path in output.glob("*receipt-*.json")}
    method = "prepare" if phase == "prepared" else "_publish_or_verify_locked"
    original = getattr(runtime._PrivateOutputCustody, method)

    def drift(self, *args):
        result = original(self, *args)
        prepared[4].write_text("{}")
        return result

    monkeypatch.setattr(runtime._PrivateOutputCustody, method, drift)
    with pytest.raises(ManagedForkArchiveError):
        _setup(prepared, tmp_path)
    assert {path.name: path.read_bytes() for path in output.glob("*receipt-*.json")} == previous
    assert not list(output.glob(".*.tmp"))
