"""Primary reads are explicit frozen data, never an ambient fork or execution authority."""

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
from tests.managed_offline_fork_support import prepared_archives
from tests.unit.test_managed_fork_archives import _prepare
from tests.unit.test_managed_offline_fork_consumers import _setup


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: primary preparation cannot execute, open RPC or discover PATH")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_archives(tmp_path, config_factory, primary=True, matrix=False)


@pytest.mark.parametrize("matrix", [False, True])
def test_primary_archive_is_prepared_independently_of_matrix_selection(
    tmp_path, config_factory, matrix
):
    prepared = prepared_archives(tmp_path, config_factory, primary=True, matrix=matrix)
    selected = _prepare(prepared)
    assert selected.primary_source_binding.path == prepared[4].name
    assert selected.primary_timeout_seconds == 1
    assert selected.state_ids == (("synthetic-offline",) if matrix else ())
    assert len(selected.source_bindings) == (2 if matrix else 1)
    assert selected.config == prepared[1].config
    assert selected.complete_state is selected.runtime_authority is False
    selected.verify(prepared[1].config)
    assert not list(prepared[2].iterdir())


@pytest.mark.parametrize("value", ["0" * 64, "a" * 63, "A" * 64, "not-a-digest", True, 1])
def test_primary_selection_requires_a_strict_nonzero_digest(tmp_path, value):
    with pytest.raises(ValidationError):
        ManagedForkArchiveSource(archive_root=tmp_path, primary_archive_sha256=value)


@pytest.mark.parametrize("field", ["expected_chain_id", "pinned_block_number"])
@pytest.mark.parametrize("missing", [False, True])
def test_primary_archive_requires_exact_declared_chain_and_block(prepared, field, missing):
    config = prepared[1].config
    setattr(config.reproduction, field, None if missing else 8)
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, config=config)


@pytest.mark.parametrize("field", ["scanner", "acknowledgement"])
def test_primary_archive_cannot_enable_disabled_execution(prepared, field):
    config = prepared[1].config
    if field == "scanner":
        config.scanners.foundry_fork.enabled = False
    else:
        config.smart_contracts.allow_fork_probing = False
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, config=config)


def test_no_primary_or_matrix_declaration_cannot_prepare_an_empty_handle(prepared):
    source = ManagedForkArchiveSource(archive_root=prepared[3].archive_root)
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, source=source)


def test_matrix_only_selection_does_not_implicitly_select_a_primary(
    prepared, tmp_path, config_factory
):
    other = tmp_path / "matrix-only"
    other.mkdir()
    matrix = prepared_archives(other, config_factory)
    selected = _prepare(matrix)
    assert selected.primary_source_binding is None
    with pytest.raises(ManagedForkArchiveError):
        selected.start_primary(
            repository=matrix[0], output=matrix[2], absolute_deadline=time.monotonic() + 1
        )


def test_full_primary_policy_cannot_be_shortened_to_fit_the_lease(prepared):
    config = prepared[1].config
    config.execution.scanner_timeout_seconds = 3600
    config.smart_contracts.max_fork_probe_seconds = 3600
    config.smart_contracts.repository_suite.total_timeout_seconds = 3600
    with pytest.raises(ManagedForkArchiveError, match=r"budget|lifetime"):
        _prepare(prepared, config=config)
    assert config.execution.scanner_timeout_seconds == 3600
    assert config.smart_contracts.max_fork_probe_seconds == 3600
    assert config.smart_contracts.repository_suite.total_timeout_seconds == 3600


@pytest.mark.parametrize(
    "deadline",
    [True, float("nan"), float("inf"), -1, 0, pytest.param(10**1000, id="oversized-integer")],
)
def test_invalid_primary_deadlines_refuse_before_any_listener(prepared, deadline):
    selected = _prepare(prepared)
    with pytest.raises(ManagedForkArchiveError):
        selected.start_primary(
            repository=prepared[0], output=prepared[2], absolute_deadline=deadline
        )


def test_primary_source_drift_refuses_before_start(prepared):
    selected = _prepare(prepared)
    prepared[4].write_text("{}")
    with pytest.raises(ManagedForkArchiveError):
        selected.start_primary(
            repository=prepared[0], output=prepared[2], absolute_deadline=time.monotonic() + 1
        )


@pytest.mark.parametrize("phase", ["prepare", "verify"])
def test_primary_and_matrix_share_one_aggregate_read_ceiling(
    tmp_path, config_factory, monkeypatch, phase
):
    prepared = prepared_archives(tmp_path, config_factory, primary=True)
    selected = _prepare(prepared)
    monkeypatch.setattr(
        archives_module, "_MAX_TOTAL_ARCHIVE_BYTES", prepared[4].stat().st_size * 2 - 1
    )
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared) if phase == "prepare" else selected.verify(prepared[1].config)


@pytest.mark.parametrize("failure", ["start", "deadline", "interrupt", "exit"])
def test_primary_factory_closes_acquired_lease_without_changing_child_policy(
    prepared, monkeypatch, failure
):
    selected = _prepare(prepared)
    original_config = selected.config.model_dump_json()
    calls = []
    sentinel = KeyboardInterrupt() if failure == "interrupt" else SystemExit(2)

    class LifecycleControl:
        def __init__(self, replay, *, lifetime_seconds):
            assert replay.source_binding == selected.primary_source_binding
            assert lifetime_seconds == 4.0  # Original one-second policy, shutdown and slack.
            calls.append("construct")

        def start(self):
            calls.append("start")
            if failure in {"interrupt", "exit"}:
                raise sentinel
            if failure == "start":
                raise ValueError("synthetic startup failure")

        def stop(self, *, deadline):
            calls.append(("stop", deadline))

    ticks = iter((10, 10, 12))
    with monkeypatch.context() as patch:
        patch.setattr(archives_module, "OfflineForkRpcLease", LifecycleControl)
        patch.setattr(archives_module.time, "monotonic", lambda: next(ticks))
        error = type(sentinel) if failure in {"interrupt", "exit"} else ManagedForkArchiveError
        with pytest.raises(error):
            selected.start_primary(repository=prepared[0], output=prepared[2], absolute_deadline=11)
    assert calls == ["construct", "start", ("stop", 13.0)]
    assert selected.config.model_dump_json() == original_config


@pytest.mark.parametrize("phase", ["prepared", "published"])
@pytest.mark.parametrize("existing", [False, True])
def test_primary_only_source_drift_cannot_publish_a_new_setup_receipt(
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
