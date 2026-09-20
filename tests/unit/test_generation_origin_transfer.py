"""Isolated origin-row migration, explicitly incapable of native provider attestation.

Only the exact move function AST is copied into a separate namespace. Its origin
registry and successful-origin guard are local stand-ins; the production origin
registry/issuer are never modified. Real core structural leases are used, and every
result must still be rejected by the actual AUTHRUNNER-origin predicate.
"""

import ast
import os
import threading
import weakref
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import mmaudit.models.generation_evidence as generation
from tests.unit.test_generation_evidence import (
    _resolve_trusted_generation,
    _trusted_generation_capability,
)


@pytest.fixture
def isolated_move():
    original, request, evidence = _trusted_generation_capability()
    snapshot = generation._snapshot_trusted_generation_capability(original)
    ledger_marker = object()
    bindings = tuple((*key, value.usage_record_sha256) for key, value in snapshot.bindings.items())
    row = (weakref.ref(original), bindings, ledger_marker, os.getpid())
    registry: dict[int, Any] = {id(original): row}
    observed = []

    def contains(capability, *, atomic_ledger):
        observed.append(capability)
        retained = registry.get(id(capability))
        return bool(
            retained is not None
            and retained[0]() is capability
            and retained[2] is atomic_ledger
            and generation._snapshot_trusted_generation_capability(capability)
        )

    source = Path(generation.__file__)
    factory = next(
        node
        for node in ast.parse(source.read_text()).body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_build_authrunner_generation_origin_authority"
    )
    definition = next(
        node
        for node in factory.body
        if isinstance(node, ast.FunctionDef) and node.name == "move_custody"
    )
    namespace = {
        **vars(generation),
        "registry": registry,
        "lock": threading.RLock(),
        "trusted_recheck": generation._recheck_trusted_generation_capability,
        "trusted_core_move": generation._move_trusted_generation_capability,
        "trusted_core_revoke": generation._revoke_trusted_generation_capability,
        "trusted_usage_sha256": generation._usage_record_sha256,
        "trusted_usage_origin": lambda _record, *, atomic_ledger: atomic_ledger is ledger_marker,
        "contains": contains,
    }
    exec(compile(ast.Module(body=[definition], type_ignores=[]), str(source), "exec"), namespace)
    yield SimpleNamespace(
        original=original,
        request=request,
        evidence=evidence,
        snapshot=snapshot,
        row=row,
        registry=registry,
        observed=observed,
        namespace=namespace,
        move=namespace["move_custody"],
    )
    for capability in {original, *observed}:
        assert generation._has_authrunner_generation_origin(capability) is False
        try:
            generation.revoke_trusted_generation_verification(capability)
        except generation.GenerationEvidenceValidationError as error:
            assert "absent, mismatched, or revoked" in str(error)


def test_isolated_move_preserves_all_origin_row_fields_but_grants_no_native_credit(
    isolated_move,
):
    scope = isolated_move
    successor, had_origin = scope.move(scope.original, scope.snapshot, (scope.request,))
    assert had_origin is True  # True only in this deliberately isolated stand-in registry.
    assert id(scope.original) not in scope.registry
    assert scope.registry[id(successor)][0]() is successor
    assert scope.registry[id(successor)][1:] == scope.row[1:]
    assert _resolve_trusted_generation(successor, scope.request) == scope.evidence
    assert generation._has_authrunner_generation_origin(successor) is False
    with pytest.raises(ValueError, match="not trusted"):
        _resolve_trusted_generation(scope.original, scope.request)


def test_actual_origin_predicate_rejects_the_isolated_synthetic_row_before_move(isolated_move):
    scope = isolated_move
    scope.namespace["contains"] = generation._has_authrunner_generation_origin
    with pytest.raises(ValueError, match="cannot authenticate its original origin"):
        scope.move(scope.original, scope.snapshot, (scope.request,))
    assert scope.registry[id(scope.original)] is scope.row
    assert _resolve_trusted_generation(scope.original, scope.request) == scope.evidence


@pytest.mark.parametrize("kind", ("missing", "extra", "wrong-usage"))
def test_isolated_origin_must_cover_exactly_the_whole_structural_proof(isolated_move, kind: str):
    scope = isolated_move
    row = scope.row
    bindings = row[1]
    altered = {
        "missing": (),
        "extra": (*bindings, bindings[0]),
        "wrong-usage": ((*bindings[0][:3], "f" * 64),),
    }[kind]
    scope.registry[id(scope.original)] = (row[0], altered, row[2], row[3])
    with pytest.raises(ValueError, match="does not cover the complete proof"):
        scope.move(scope.original, scope.snapshot, (scope.request,))
    assert _resolve_trusted_generation(scope.original, scope.request) == scope.evidence


def test_isolated_missing_original_usage_refuses_before_move(isolated_move):
    scope = isolated_move
    scope.namespace["trusted_usage_origin"] = lambda *_args, **_kwargs: False
    with pytest.raises(ValueError, match="every original REAL usage"):
        scope.move(scope.original, scope.snapshot, (scope.request,))
    assert _resolve_trusted_generation(scope.original, scope.request) == scope.evidence


def test_isolated_late_origin_failure_disposes_successor_and_does_not_restore_source(
    isolated_move,
):
    scope = isolated_move

    def refuse_successor(capability, **_kwargs):
        scope.observed.append(capability)
        return capability is scope.original

    scope.namespace["contains"] = refuse_successor
    with pytest.raises(ValueError, match="could not follow"):
        scope.move(scope.original, scope.snapshot, (scope.request,))
    assert scope.registry == {}
    for capability in scope.observed:
        with pytest.raises(ValueError, match="not trusted"):
            _resolve_trusted_generation(capability, scope.request)


@pytest.mark.parametrize("started_with_origin", (False, True))
def test_isolated_reentrant_origin_change_cannot_publish_a_successor(
    isolated_move, started_with_origin: bool
):
    scope = isolated_move
    if not started_with_origin:
        scope.registry.clear()

    def change_origin(capability, snapshot):
        successor = generation._move_trusted_generation_capability(capability, snapshot)
        scope.observed.append(successor)
        if started_with_origin:
            scope.registry.pop(id(capability))
        else:
            scope.registry[id(capability)] = scope.row
        return successor

    scope.namespace["trusted_core_move"] = change_origin
    with pytest.raises(ValueError, match="origin changed during custody transfer"):
        scope.move(scope.original, scope.snapshot, (scope.request,))
    assert scope.registry == {}
    for capability in scope.observed:
        with pytest.raises(ValueError, match="not trusted"):
            _resolve_trusted_generation(capability, scope.request)
