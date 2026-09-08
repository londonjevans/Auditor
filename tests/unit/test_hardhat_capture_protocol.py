"""Capture/source/protocol regressions without any process, socket, Hardhat or container."""

from __future__ import annotations

import hashlib
import shutil
import socket
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from mmaudit.models.schemas import HardhatInventoryPhaseRequest, RepositoryTestExecutionStatus
from mmaudit.scanners import hardhat_protocol as protocol
from mmaudit.scanners.hardhat_supervision import HardhatCaptureOutcome
from tests.hardhat_capture_support import execution_capture, inputs


@pytest.fixture(autouse=True)
def no_execution(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("invariant: protocol consumption cannot execute processes or open sockets")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)


@pytest.fixture
def selected(tmp_path):
    root, config, request, capture = inputs(tmp_path)
    prepared = protocol.prepare_hardhat_test_phase_from_capture(
        request,
        capture,
        root=root,
        smart_contracts=config,
    )
    return root, config, request, capture, prepared


def test_published_schema_pins_are_exact_and_phase_specific():
    root = Path(__file__).parents[2] / "schemas"
    assert (
        hashlib.sha256((root / "hardhat_reporter_inventory.schema.json").read_bytes()).hexdigest()
        == protocol.HARDHAT_INVENTORY_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256((root / "hardhat_reporter_test.schema.json").read_bytes()).hexdigest()
        == protocol.HARDHAT_TEST_SCHEMA_SHA256
    )
    assert protocol.HARDHAT_INVENTORY_SCHEMA_SHA256 != protocol.HARDHAT_TEST_SCHEMA_SHA256


def test_inventory_capture_prepares_exact_source_selection_and_detached_test_request(selected):
    _root, config, request, capture, prepared = selected
    assert prepared.inventory_request is not request
    assert prepared.inventory_capture is not capture
    assert prepared.selection.tests[0].test_name == "preserves accounting"
    assert prepared.test_request.inventory_request_sha256 == request.request_sha256
    assert prepared.test_request.reporter_schema_sha256 == protocol.HARDHAT_TEST_SCHEMA_SHA256
    assert prepared.test_request.configuration_sha256 == config.repository_suite.stable_hash()
    assert prepared.runtime_authority is prepared.execution_credit is False
    assert "preserves accounting" not in repr(prepared)
    request.reporter_version = "changed"
    assert prepared.inventory_request.reporter_version != "changed"


@pytest.mark.parametrize(
    "status,exit_code",
    [
        (RepositoryTestExecutionStatus.PASSED, 0),
        (RepositoryTestExecutionStatus.SKIPPED, 0),
        (RepositoryTestExecutionStatus.FAILED, 7),
        (RepositoryTestExecutionStatus.ASSERTION_FAILED, 1),
        (RepositoryTestExecutionStatus.REVERTED, 255),
    ],
)
def test_consistent_terminal_results_remain_untrusted_and_noncrediting(selected, status, exit_code):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared, status=status, exit_code=exit_code)
    report = protocol.consume_hardhat_test_phase_capture(
        prepared, capture, root=root, smart_contracts=config
    )
    assert report.results[0].status is status
    assert report.execution_credit is report.authorship_claim is report.safety_claim is False
    assert report.provenance == "untrusted_target_process_observation"
    if exit_code:
        assert not capture.complete


@pytest.mark.parametrize(
    "field,value",
    [
        ("outcome", HardhatCaptureOutcome.TIMED_OUT),
        ("outcome", HardhatCaptureOutcome.CLEANUP_FAILED),
        ("outcome", HardhatCaptureOutcome.OUTPUT_LIMIT),
        ("outcome", "EXITED"),
        ("phase", "test"),
        ("process_exit_code", None),
        ("process_exit_code", True),
        ("process_exit_code", -9),
        ("process_exit_code", 1),
        ("duration_seconds", float("nan")),
        ("duration_seconds", float("inf")),
        ("duration_seconds", True),
        ("duration_seconds", -1),
        ("duration_seconds", 10.0),
        ("report", None),
        ("report", b""),
        ("report", bytearray(b"{}")),
        ("stdout", "not bytes"),
        ("stderr", b"x" * 100_000),
        ("request_sha256", "a" * 64),
    ],
)
def test_incomplete_nonexact_or_unbounded_inventory_capture_refuses(tmp_path, field, value):
    root, config, request, capture = inputs(tmp_path)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.prepare_hardhat_test_phase_from_capture(
            request,
            replace(capture, **{field: value}),
            root=root,
            smart_contracts=config,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("reporter_sha256", "a" * 64),
        ("reporter_version", "1.0.1"),
        ("reporter_schema_sha256", protocol.HARDHAT_TEST_SCHEMA_SHA256),
        ("configuration_sha256", "b" * 64),
        ("repository_sha256", "c" * 64),
        ("repository_exclusion_path", "other"),
        ("timeout_seconds", 11),
        ("maximum_output_bytes", 100_001),
        ("fuzz_seed", "0x" + "a" * 64),
    ],
)
def test_resealed_but_unmatched_request_does_not_select_source(tmp_path, field, value):
    root, config, request, capture = inputs(tmp_path)
    values = request.model_dump(exclude={"request_sha256"})
    values[field] = value
    altered = HardhatInventoryPhaseRequest.sealed(**values)
    capture = replace(capture, request_sha256=altered.request_sha256)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.prepare_hardhat_test_phase_from_capture(
            altered, capture, root=root, smart_contracts=config
        )


@pytest.mark.parametrize(
    "report", [b"not json", b"{}{}", b'{"phase":"inventory","phase":"inventory"}', b"\xff"]
)
def test_complete_byte_capture_is_not_semantic_report_validity(tmp_path, report):
    root, config, request, capture = inputs(tmp_path)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.prepare_hardhat_test_phase_from_capture(
            request, replace(capture, report=report), root=root, smart_contracts=config
        )


@pytest.mark.parametrize(
    "status,exit_code",
    [
        (RepositoryTestExecutionStatus.PASSED, 7),
        (RepositoryTestExecutionStatus.SKIPPED, 7),
        (RepositoryTestExecutionStatus.FAILED, 0),
        (RepositoryTestExecutionStatus.REVERTED, 0),
        (RepositoryTestExecutionStatus.PASSED, -9),
        (RepositoryTestExecutionStatus.FAILED, 256),
    ],
)
def test_process_exit_cannot_contradict_reported_test_results(selected, status, exit_code):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared, status=status, exit_code=exit_code)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.consume_hardhat_test_phase_capture(
            prepared, capture, root=root, smart_contracts=config
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "source",
        "config",
        "authority_copy",
        "inventory",
        "selection",
        "request",
        "aggregate_time",
        "aggregate_bytes",
    ],
)
def test_second_phase_revalidates_source_exact_join_and_aggregate_limits(selected, mutation):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared)
    if mutation == "source":
        (root / "test/audit/Vault.ts").write_text("// synthetic changed source\n")
    elif mutation == "config":
        config.repository_suite.max_total_output_bytes += 1
    elif mutation == "authority_copy":
        prepared = replace(prepared, source_authority=replace(prepared.source_authority))
    elif mutation == "inventory":
        prepared.inventory.tests[0].test_name = "changed"
    elif mutation == "selection":
        prepared.selection.selection_sha256 = "1" * 64
    elif mutation == "request":
        prepared.test_request.inventory_request_sha256 = "2" * 64
    elif mutation == "aggregate_time":
        prepared = replace(
            prepared, inventory_capture=replace(prepared.inventory_capture, duration_seconds=6.0)
        )
        capture = replace(capture, duration_seconds=6.0)
    else:
        prepared = replace(
            prepared, inventory_capture=replace(prepared.inventory_capture, stdout=b"x" * 60_000)
        )
        capture = replace(capture, stderr=b"y" * 60_000)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.consume_hardhat_test_phase_capture(
            prepared, capture, root=root, smart_contracts=config
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("request_sha256", "a" * 64),
        ("selection_sha256", "b" * 64),
        ("chain_id", 1),
        ("block_number", 1),
        ("block_hash", "0x" + "c" * 64),
        ("fuzz_seed", "0x" + "d" * 64),
        ("reporter_sha256", "e" * 64),
    ],
)
def test_self_consistent_report_cannot_substitute_phase_or_fork_bindings(selected, field, value):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared)
    original = protocol.HardhatReporterExecution.model_validate_json(capture.report)
    values = original.model_dump()
    values["results"] = original.results
    values[field] = value
    values.pop("report_sha256")
    report = protocol.HardhatReporterExecution.sealed(**values)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.consume_hardhat_test_phase_capture(
            prepared,
            replace(capture, report=report.model_dump_json().encode()),
            root=root,
            smart_contracts=config,
        )


@pytest.mark.parametrize(
    "mutation", ["source", "same_bytes_root_swap", "capture", "selection", "config"]
)
def test_post_parse_custody_change_cannot_return_observations(selected, monkeypatch, mutation):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared)
    original = protocol.parse_hardhat_execution_report

    def changed(*args, **kwargs):
        report = original(*args, **kwargs)
        if mutation == "source":
            (root / "test/audit/Vault.ts").write_text("// synthetic changed source\n")
        elif mutation == "same_bytes_root_swap":
            previous = root.with_name("previous-source")
            root.rename(previous)
            shutil.copytree(previous, root)
        elif mutation == "capture":
            object.__setattr__(capture, "stdout", b"changed")
        elif mutation == "selection":
            prepared.selection.tests[0].test_name = "changed"
        else:
            config.enabled = not config.enabled
        return report

    monkeypatch.setattr(protocol, "parse_hardhat_execution_report", changed)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.consume_hardhat_test_phase_capture(
            prepared, capture, root=root, smart_contracts=config
        )


@pytest.mark.parametrize("mutation", ["request", "config", "capture", "source"])
def test_inventory_post_parse_mutation_refuses(tmp_path, monkeypatch, mutation):
    root, config, request, capture = inputs(tmp_path)
    original = protocol.parse_hardhat_inventory_report

    def changed(*args, **kwargs):
        inventory = original(*args, **kwargs)
        if mutation == "request":
            request.reporter_version = "changed"
        elif mutation == "config":
            config.enabled = not config.enabled
        elif mutation == "capture":
            object.__setattr__(capture, "stderr", b"changed")
        else:
            (root / "test/audit/Vault.ts").write_text("// changed synthetic source\n")
        return inventory

    monkeypatch.setattr(protocol, "parse_hardhat_inventory_report", changed)
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.prepare_hardhat_test_phase_from_capture(
            request, capture, root=root, smart_contracts=config
        )


@pytest.mark.parametrize("mutation", ["phase", "outcome", "capture_type", "prepared_type"])
def test_test_consumption_refuses_wrong_phase_incomplete_or_nonexact_inputs(selected, mutation):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared)
    if mutation == "phase":
        capture = replace(capture, phase="inventory")
    elif mutation == "outcome":
        capture = replace(capture, outcome=HardhatCaptureOutcome.REPORT_UNAVAILABLE)
    elif mutation == "capture_type":
        capture = object()
    else:
        prepared = object()
    with pytest.raises(protocol.HardhatProtocolBindingError):
        protocol.consume_hardhat_test_phase_capture(
            prepared, capture, root=root, smart_contracts=config
        )


def test_parser_interrupt_is_not_translated_into_a_report(selected, monkeypatch):
    root, config, _, _, prepared = selected
    capture = execution_capture(prepared)
    sentinel = KeyboardInterrupt()

    def interrupted(*args, **kwargs):
        raise sentinel

    monkeypatch.setattr(protocol, "parse_hardhat_execution_report", interrupted)
    with pytest.raises(KeyboardInterrupt) as raised:
        protocol.consume_hardhat_test_phase_capture(
            prepared, capture, root=root, smart_contracts=config
        )
    assert raised.value is sentinel
