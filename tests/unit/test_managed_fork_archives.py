"""Exact offline-state selection cannot discover URLs, execute tools or grant authority."""

from __future__ import annotations

import copy
import hashlib
import pickle
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import RepositoryPinnedForkMatrixStateConfig
from mmaudit.orchestration import managed_fork_archives as archives_module
from mmaudit.orchestration.managed_fork_archives import (
    ManagedForkArchiveError,
    ManagedForkArchives,
    ManagedForkArchiveSource,
    prepare_managed_fork_archives,
)
from tests.managed_offline_fork_support import prepared_archives


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: offline archive preparation cannot execute, connect or search PATH")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)


@pytest.fixture
def prepared(tmp_path, config_factory):
    return prepared_archives(tmp_path, config_factory)


def _prepare(prepared, **kwargs):
    repository, tools, private, source, _ = prepared
    return prepare_managed_fork_archives(
        kwargs.pop("config", tools.config),
        source=kwargs.pop("source", source),
        repository=kwargs.pop("repository", repository),
        output=kwargs.pop("output", private),
        **kwargs,
    )


def _state(prepared):
    return next(
        state
        for state in prepared[1].config.smart_contracts.repository_suite.fork_matrix_states
        if isinstance(state, RepositoryPinnedForkMatrixStateConfig)
    )


def test_preparation_selects_only_declared_hash_files_without_writing_or_opening_rpc(prepared):
    selected = _prepare(prepared)
    assert type(selected) is ManagedForkArchives
    assert selected.state_ids == ("synthetic-offline",)
    assert selected.config == prepared[1].config
    assert selected.runtime_authority is selected.complete_state is False
    binding = selected.source_bindings[0]
    assert binding.sha256 == hashlib.sha256(prepared[4].read_bytes()).hexdigest()
    assert binding.path == prepared[4].name
    selected.verify(prepared[1].config)
    selected.verify_roots(prepared[0], prepared[2], prepared[1].directory)
    assert list(prepared[3].archive_root.iterdir()) == [prepared[4]]
    assert not list(prepared[2].iterdir())


def test_prepared_configuration_and_bindings_are_detached(prepared):
    selected = _prepare(prepared)
    config = selected.config
    config.smart_contracts.foundry_fuzz_runs += 1
    assert config != selected.config
    assert selected.source_bindings[0] is not selected.source_bindings[0]
    with pytest.raises(ManagedForkArchiveError):
        selected.verify(config)


@pytest.mark.parametrize("value", [None, {}, object(), "archive"])
def test_untyped_sources_cannot_select_managed_state(prepared, value):
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, source=value)


@pytest.mark.parametrize("value", [Path("."), Path("relative"), Path("/safe/../other"), "relative"])
def test_archive_source_root_must_be_an_explicit_absolute_path(value):
    with pytest.raises(ValidationError):
        ManagedForkArchiveSource(archive_root=value)


@pytest.mark.parametrize("mutation", ["missing", "changed", "file_link", "hard_link", "root_link"])
def test_changed_missing_or_linked_archive_inputs_refuse(prepared, mutation):
    path = prepared[4]
    source = prepared[3]
    if mutation == "missing":
        path.rename(path.with_suffix(".not-selected"))
    elif mutation == "changed":
        path.write_text("{}")
    elif mutation == "file_link":
        retained = path.with_suffix(".retained")
        path.rename(retained)
        path.symlink_to(retained)
    elif mutation == "hard_link":
        path.with_suffix(".alias").hardlink_to(path)
    else:
        alias = source.archive_root.parent / "archive-alias"
        alias.symlink_to(source.archive_root, target_is_directory=True)
        source = ManagedForkArchiveSource(archive_root=alias)
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, source=source)


@pytest.mark.parametrize("root_index", [0, 2])
def test_archive_store_cannot_overlap_source_or_writable_output(prepared, root_index):
    source = ManagedForkArchiveSource(archive_root=prepared[root_index])
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, source=source)


def test_extra_directory_content_is_never_discovered_or_read(prepared, monkeypatch):
    selected = _prepare(prepared)

    def forbidden(*args, **kwargs):
        pytest.fail("invariant: managed archive selection must not enumerate ambient files")

    monkeypatch.setattr(Path, "iterdir", forbidden)
    monkeypatch.setattr(Path, "glob", forbidden)
    monkeypatch.setattr(Path, "rglob", forbidden)
    selected.verify(prepared[1].config)
    _prepare(prepared)


@pytest.mark.parametrize("field,value", [("expected_chain_id", 1), ("pinned_block_number", 8)])
def test_archive_chain_and_block_must_join_the_selected_state(prepared, field, value):
    config = prepared[1].config
    for state in config.smart_contracts.repository_suite.fork_matrix_states:
        if isinstance(state, RepositoryPinnedForkMatrixStateConfig):
            setattr(state, field, value)
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared, config=config)


def test_source_drift_after_preparation_refuses_before_a_lease_can_open(prepared):
    selected = _prepare(prepared)
    prepared[4].write_text("{}")
    with pytest.raises(ManagedForkArchiveError):
        selected.verify(prepared[1].config)
    with pytest.raises(ManagedForkArchiveError):
        selected.start(
            _state(prepared),
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + 100,
        )


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), -1, 0, 10**1000])
def test_invalid_or_exhausted_matrix_deadlines_refuse_without_a_listener(prepared, deadline):
    selected = _prepare(prepared)
    with pytest.raises(ManagedForkArchiveError):
        selected.start(
            _state(prepared), repository=prepared[0], output=prepared[2], absolute_deadline=deadline
        )


def test_full_child_timeouts_cannot_be_shrunk_to_fit_the_service(prepared):
    config = prepared[1].config
    config.smart_contracts.repository_suite.total_timeout_seconds = 7200
    with pytest.raises(ManagedForkArchiveError, match=r"budget|lifetime"):
        _prepare(prepared, config=config)
    assert config.smart_contracts.repository_suite.total_timeout_seconds == 7200


@pytest.mark.parametrize("operation", [copy.copy, copy.deepcopy, pickle.dumps])
def test_prepared_runtime_handles_cannot_be_copied_or_serialized(prepared, operation):
    with pytest.raises(TypeError):
        operation(_prepare(prepared))


@pytest.mark.parametrize(
    "field,value", [("state_id", "undeclared"), ("state_source_sha256", "c" * 64)]
)
def test_only_exact_declared_states_can_start(prepared, field, value):
    selected = _prepare(prepared)
    state = _state(prepared)
    setattr(state, field, value)
    with pytest.raises(ManagedForkArchiveError):
        selected.start(
            state,
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + 100,
        )


@pytest.mark.parametrize("remaining", [0, 1, 20, 37])
def test_full_state_budget_is_required_before_startup(prepared, remaining):
    selected = _prepare(prepared)
    config_before = selected.config.model_dump_json()
    with pytest.raises(ManagedForkArchiveError):
        selected.start(
            _state(prepared),
            repository=prepared[0],
            output=prepared[2],
            absolute_deadline=time.monotonic() + remaining,
        )
    assert selected.config.model_dump_json() == config_before


@pytest.mark.parametrize("phase", ["prepare", "verify"])
def test_aggregate_archive_byte_limit_is_enforced_by_the_bounded_reader(
    prepared, monkeypatch, phase
):
    selected = _prepare(prepared)
    maximum = prepared[4].stat().st_size - 1
    monkeypatch.setattr(archives_module, "_MAX_TOTAL_ARCHIVE_BYTES", maximum)
    accesses = []
    original = archives_module.read_file_evidence

    def bounded(**kwargs):
        assert kwargs["max_bytes"] <= maximum
        accesses.append(kwargs["relative_path"])
        return original(**kwargs)

    monkeypatch.setattr(archives_module, "read_file_evidence", bounded)
    with pytest.raises(ManagedForkArchiveError):
        _prepare(prepared) if phase == "prepare" else selected.verify(prepared[1].config)
    assert accesses == ([prepared[4].name] if phase == "prepare" else [])


@pytest.mark.parametrize("failure", ["start", "budget", "interrupt"])
def test_factory_cleans_acquired_lease_on_startup_failure_without_shortening_timeouts(
    prepared, monkeypatch, failure
):
    selected = _prepare(prepared)
    calls = []
    interrupt = KeyboardInterrupt()

    class LifecycleControl:
        def __init__(self, replay, **kwargs):
            assert replay.source_binding == selected.source_bindings[0]
            assert kwargs["lifetime_seconds"] == pytest.approx(37.2)
            calls.append("construct")

        def start(self):
            calls.append("start")
            if failure == "interrupt":
                raise interrupt
            if failure == "start":
                raise ValueError("synthetic startup failure")

        def stop(self, *, deadline):
            calls.append(("stop", deadline))

    ticks = iter((10, 10, 200))
    with monkeypatch.context() as patch:
        patch.setattr(archives_module, "OfflineForkRpcLease", LifecycleControl)
        patch.setattr(archives_module.time, "monotonic", lambda: next(ticks))
        with pytest.raises(
            KeyboardInterrupt if failure == "interrupt" else ManagedForkArchiveError
        ):
            selected.start(
                _state(prepared), repository=prepared[0], output=prepared[2], absolute_deadline=100
            )
    assert calls == ["construct", "start", ("stop", 100)]
