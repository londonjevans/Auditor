"""Actual local structural proof moves; fixtures never gain AUTHRUNNER REAL origin."""

import copy
import os
import pickle
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import pytest

import mmaudit.models.generation_evidence as generation
from tests.unit.test_generation_evidence import (
    _resolve_trusted_generation,
    _trusted_generation_capability,
)


def test_move_consumes_original_and_preserves_every_attestation_without_granting_origin() -> None:
    original, request, evidence = _trusted_generation_capability()
    retained = original
    successor = generation.transfer_trusted_generation_verification(original, requests=(request,))
    assert successor is not original and type(successor) is type(original)
    assert _resolve_trusted_generation(successor, request) == evidence
    assert not generation._has_authrunner_generation_origin(successor)
    assert not generation._has_authrunner_generation_origin(retained)
    with pytest.raises(ValueError, match="not trusted"):
        _resolve_trusted_generation(retained, request)
    with pytest.raises(ValueError, match="not trusted"):
        generation.transfer_trusted_generation_verification(retained, requests=(request,))
    generation.revoke_trusted_generation_verification(successor)
    with pytest.raises(ValueError, match="not trusted"):
        _resolve_trusted_generation(successor, request)


@pytest.mark.parametrize("kind", ("empty", "list", "duplicate", "excess", "wrong-type"))
def test_invalid_request_inventory_cannot_consume_original(kind: str) -> None:
    original, request, evidence = _trusted_generation_capability()
    requests: Any = {
        "empty": (),
        "list": [request],
        "duplicate": (request, request),
        "excess": (request,) * 513,
        "wrong-type": (object(),),
    }[kind]
    with pytest.raises(ValueError):
        generation.transfer_trusted_generation_verification(original, requests=requests)
    assert _resolve_trusted_generation(original, request) == evidence
    generation.revoke_trusted_generation_verification(original)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("benchmark_report_sha256", "9" * 64),
        ("case_id", "different-case"),
        ("exact_model_id", "other/model"),
        ("canonical_model_id", "other/canonical"),
        ("catalog_identity_binding_sha256", "9" * 64),
        ("discovery_evidence_sha256", "9" * 64),
        ("expected_provider_name", "Other Provider"),
    ),
)
def test_changed_request_binding_never_moves_original(field: str, value: str) -> None:
    original, request, evidence = _trusted_generation_capability()
    altered = copy.copy(request)
    object.__setattr__(altered, field, value)
    with pytest.raises(ValueError):
        generation.transfer_trusted_generation_verification(original, requests=(altered,))
    assert _resolve_trusted_generation(original, request) == evidence
    generation.revoke_trusted_generation_verification(original)


def test_changed_usage_cannot_consume_original() -> None:
    original, request, evidence = _trusted_generation_capability()
    altered = copy.copy(request)
    object.__setattr__(
        altered,
        "usage_record",
        request.usage_record.model_copy(update={"request_id": "different-request"}),
    )
    with pytest.raises(ValueError):
        generation.transfer_trusted_generation_verification(original, requests=(altered,))
    assert _resolve_trusted_generation(original, request) == evidence
    generation.revoke_trusted_generation_verification(original)


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_successor_is_not_copyable_or_serializable(operation: Any) -> None:
    original, request, _ = _trusted_generation_capability()
    successor = generation.transfer_trusted_generation_verification(original, requests=(request,))
    try:
        with pytest.raises(TypeError):
            operation(successor)
    finally:
        generation.revoke_trusted_generation_verification(successor)


def test_forged_generation_proof_cannot_be_moved() -> None:
    original, request, _ = _trusted_generation_capability()
    forged = object.__new__(generation.TrustedGenerationVerification)
    with pytest.raises(ValueError, match="not trusted"):
        generation.transfer_trusted_generation_verification(forged, requests=(request,))
    generation.revoke_trusted_generation_verification(original)


def test_two_concurrent_moves_have_exactly_one_successor() -> None:
    original, request, evidence = _trusted_generation_capability()
    start = threading.Barrier(2)

    def move() -> object:
        start.wait(timeout=5)
        try:
            return generation.transfer_trusted_generation_verification(
                original, requests=(request,)
            )
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(move) for _ in range(2)]
        outcomes = [future.result(timeout=10) for future in futures]
    successors = [
        item for item in outcomes if type(item) is generation.TrustedGenerationVerification
    ]
    assert len(successors) == 1 and sum(isinstance(item, ValueError) for item in outcomes) == 1
    successor = successors[0]
    assert _resolve_trusted_generation(successor, request) == evidence
    assert not generation._has_authrunner_generation_origin(successor)
    generation.revoke_trusted_generation_verification(successor)


def test_source_revocation_wins_during_pristine_transfer_replay() -> None:
    original, request, _ = _trusted_generation_capability()
    started = threading.Event()
    resume = threading.Event()
    reconcile_code = generation._reconcile_generation_evidence.__code__

    def pause(frame: Any, event: str, _argument: Any) -> Any:
        if event == "call" and frame.f_code is reconcile_code:
            started.set()
            if not resume.wait(timeout=5):
                raise AssertionError("synthetic transfer replay did not resume")
        return pause

    def move() -> object:
        sys.settrace(pause)
        try:
            return generation.transfer_trusted_generation_verification(
                original, requests=(request,)
            )
        except ValueError as error:
            return error
        finally:
            sys.settrace(None)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(move)
        try:
            assert started.wait(timeout=5)
            generation.revoke_trusted_generation_verification(original)
        finally:
            resume.set()
        result = future.result(timeout=10)
    assert isinstance(result, ValueError)
    assert not generation._has_authrunner_generation_origin(original)


@pytest.mark.parametrize(
    "binding",
    (
        "_move_trusted_generation_capability",
        "_move_generation_custody_with_origin",
        "_has_authrunner_generation_origin",
        "_snapshot_trusted_generation_capability",
        "transfer_trusted_generation_verification",
    ),
)
def test_binding_retarget_is_refused_before_original_is_consumed(
    monkeypatch: pytest.MonkeyPatch, binding: str
) -> None:
    original, request, evidence = _trusted_generation_capability()
    transfer = generation.transfer_trusted_generation_verification
    with monkeypatch.context() as context:
        context.setattr(generation, binding, lambda *_args, **_kwargs: None)
        with pytest.raises(ValueError, match="not pristine"):
            transfer(original, requests=(request,))
    assert _resolve_trusted_generation(original, request) == evidence
    generation.revoke_trusted_generation_verification(original)


def test_core_move_rejects_replayed_and_wrong_nonce_snapshots() -> None:
    original, request, evidence = _trusted_generation_capability()
    snapshot = generation._snapshot_trusted_generation_capability(original)
    with pytest.raises(ValueError, match="changed or was revoked"):
        generation._move_trusted_generation_capability(original, replace(snapshot, nonce=object()))
    successor = generation._move_trusted_generation_capability(original, snapshot)
    assert _resolve_trusted_generation(successor, request) == evidence
    with pytest.raises(ValueError, match="changed or was revoked"):
        generation._move_trusted_generation_capability(original, snapshot)
    assert not generation._has_authrunner_generation_origin(successor)
    generation.revoke_trusted_generation_verification(successor)


@pytest.mark.parametrize("fault", (ValueError, RuntimeError, KeyboardInterrupt))
def test_postmove_replay_failure_disposes_successor_without_reviving_source(fault: Any) -> None:
    original, request, _ = _trusted_generation_capability()
    retained: list[generation.TrustedGenerationVerification] = []

    def interrupt_successor(frame: Any, event: str, _argument: Any) -> Any:
        if (
            event == "call"
            and frame.f_globals is generation.__dict__
            and frame.f_code.co_name == "replay"
            and frame.f_locals.get("capability") is not original
        ):
            retained.append(frame.f_locals["capability"])
            raise fault("synthetic failure after custody moved")
        return interrupt_successor

    sys.settrace(interrupt_successor)
    try:
        with pytest.raises(fault, match="synthetic failure"):
            generation.transfer_trusted_generation_verification(original, requests=(request,))
    finally:
        sys.settrace(None)
    assert len(retained) == 1
    for capability in (original, retained[0]):
        with pytest.raises(ValueError, match="not trusted"):
            _resolve_trusted_generation(capability, request)
        assert not generation._has_authrunner_generation_origin(capability)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires local POSIX process custody")
def test_generation_transfer_cannot_use_parent_proof_in_a_child_process() -> None:
    original, request, evidence = _trusted_generation_capability()
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            generation.transfer_trusted_generation_verification(original, requests=(request,))
        except generation.GenerationEvidenceValidationError:
            os.write(write_fd, b"refused")
        finally:
            os.close(write_fd)
            os._exit(0)
    os.close(write_fd)
    try:
        assert os.read(read_fd, 32) == b"refused"
    finally:
        os.close(read_fd)
        waited, status = os.waitpid(child, 0)
    assert waited == child and status == 0
    assert _resolve_trusted_generation(original, request) == evidence
    generation.revoke_trusted_generation_verification(original)
