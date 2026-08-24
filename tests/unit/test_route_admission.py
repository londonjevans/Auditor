from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import mmaudit.models.discovery as discovery_module
import mmaudit.models.openrouter as openrouter_module
import mmaudit.models.qualification as qualification_module
import mmaudit.models.route_admission as route_admission_module
import mmaudit.models.route_constraints as route_constraints_module
from mmaudit.config import AuditConfig
from mmaudit.models.qualification import CandidateModel, seal_candidate_registry
from mmaudit.models.route_admission import (
    AuthenticatedRunnerRouteAdmissionError,
    AuthenticatedRunnerRouteArtifacts,
    require_authenticated_runner_route_admission,
    require_authenticated_runner_three_route_admission,
    route_admission_callables_are_pristine,
)
from mmaudit.models.route_constraints import (
    RouteConstraintPurpose,
    RoutePredicateDisposition,
    RoutePredicateId,
    RoutePredicateReason,
    RoutePredicateRequirementError,
    route_constraint_callables_are_pristine,
)
from tests.unit import test_authenticated_runner_execution as execution_fixtures


@pytest.mark.parametrize(
    "function",
    (
        require_authenticated_runner_route_admission,
        require_authenticated_runner_three_route_admission,
    ),
)
def test_route_admission_code_mutation_is_not_pristine(function: Callable[..., object]) -> None:
    original_code = function.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    function.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False
    finally:
        function.__code__ = original_code
    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


def test_route_admission_evaluator_alias_mutation_is_not_pristine(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(
            route_admission_module,
            "evaluate_route_predicates",
            lambda **_kwargs: None,
        )
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False

    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


def test_route_admission_guard_alias_mutation_revokes_captured_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_guard = route_admission_callables_are_pristine

    with monkeypatch.context() as context:
        context.setattr(
            route_admission_module,
            "route_admission_callables_are_pristine",
            lambda: True,
        )
        assert captured_guard() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False

    assert captured_guard() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


def test_route_admission_noncallable_constraint_guard_alias_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(route_admission_module, "route_constraint_callables_are_pristine", object())
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False

    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


def test_registry_authority_sys_alias_mutation_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority_guard = route_admission_module._candidate_registry_validation_surface_is_pristine

    with monkeypatch.context() as context:
        context.setattr(route_admission_module, "sys", object())
        assert authority_guard() is False
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False

    assert authority_guard() is True
    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


@pytest.mark.parametrize(
    "model_type",
    (CandidateModel, qualification_module.CandidateRegistry),
)
def test_registry_authority_model_config_mutation_fails_closed(
    model_type: type[object],
) -> None:
    authority_guard = route_admission_module._candidate_registry_validation_surface_is_pristine
    model_config = model_type.model_config

    model_config["route_guard_probe"] = True
    try:
        assert authority_guard() is False
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False
    finally:
        del model_config["route_guard_probe"]

    assert authority_guard() is True
    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


@pytest.mark.parametrize(
    ("module", "name"),
    (
        (qualification_module, "validate_candidate_registry_discovery"),
        (discovery_module, "_validate_discovery_route_predicate_evidence"),
    ),
)
def test_route_admission_transitive_validator_alias_mutation_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    module: object,
    name: str,
) -> None:
    with monkeypatch.context() as context:
        context.setattr(module, name, lambda *_args, **_kwargs: None)
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False

    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


@pytest.mark.parametrize(
    "function",
    (
        qualification_module.validate_candidate_registry_discovery,
        qualification_module._validate_candidate_route_constraint_custody,
        qualification_module.canonical_sha256,
        discovery_module._validate_discovery_route_predicate_evidence,
    ),
)
def test_route_admission_transitive_validator_code_mutation_fails_closed(
    function: Callable[..., object],
) -> None:
    original_code = function.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    function.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False
    finally:
        function.__code__ = original_code

    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


@pytest.mark.parametrize(
    "cell_name",
    ("issuer_callable_states", "issuer_callable_states_seal"),
)
def test_route_admission_registered_graph_cell_replacement_fails_closed(
    cell_name: str,
) -> None:
    authority_guard = route_admission_module._candidate_registry_validation_surface_is_pristine
    guard_closure = dict(
        zip(
            authority_guard.__code__.co_freevars,
            authority_guard.__closure__ or (),
            strict=True,
        )
    )
    unchecked = guard_closure["pristine_unchecked"].cell_contents
    closure = dict(
        zip(
            unchecked.__code__.co_freevars,
            unchecked.__closure__ or (),
            strict=True,
        )
    )
    cell = closure[cell_name]
    original: tuple[object, ...] = cell.cell_contents
    changed = tuple([*original])
    assert changed is not original

    cell.cell_contents = changed
    try:
        assert authority_guard() is False
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False
    finally:
        cell.cell_contents = original

    assert authority_guard() is True
    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


def test_transitive_route_helper_code_mutation_revokes_provider_boundary() -> None:
    helper = route_constraints_module._unavailable_result
    original_code = helper.__code__

    def changed(*_args: object, **_kwargs: object) -> None:
        return None

    helper.__code__ = changed.__code__.replace(co_freevars=original_code.co_freevars)
    try:
        assert route_constraint_callables_are_pristine() is False
        assert route_admission_callables_are_pristine() is False
        assert openrouter_module._openrouter_client_callables_are_pristine() is False
    finally:
        helper.__code__ = original_code

    assert route_constraint_callables_are_pristine() is True
    assert route_admission_callables_are_pristine() is True
    assert openrouter_module._openrouter_client_callables_are_pristine() is True


@pytest.mark.parametrize(
    "imports",
    (
        (
            "import mmaudit.models.route_admission as r; "
            "import mmaudit.models.qualification; import mmaudit.models.openrouter as o"
        ),
        (
            "import mmaudit.models.openrouter as o; import mmaudit.models.qualification; "
            "import mmaudit.models.route_admission as r"
        ),
        (
            "import mmaudit.models.qualification; import mmaudit.models.route_admission as r; "
            "import mmaudit.models.openrouter as o"
        ),
    ),
)
def test_route_admission_import_orders_install_the_same_pristine_boundary(imports: str) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                f"{imports}; "
                "print(r.route_admission_callables_are_pristine(), "
                "o._openrouter_client_callables_are_pristine())"
            ),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert completed.stdout.strip() == "True True"


def _routes(
    harness: Any,
) -> tuple[
    AuthenticatedRunnerRouteArtifacts,
    AuthenticatedRunnerRouteArtifacts,
    AuthenticatedRunnerRouteArtifacts,
]:
    return (
        (
            harness.registry,
            harness.discovery_manifest,
            harness.discovery_evidence,
        ),
        (
            harness.plans[0].judge_registry,
            harness.plans[0].judge_discovery_manifest,
            harness.plans[0].judge_discovery_evidence,
        ),
        (
            harness.plans[1].judge_registry,
            harness.plans[1].judge_discovery_manifest,
            harness.plans[1].judge_discovery_evidence,
        ),
    )


@pytest.mark.asyncio
async def test_registry_and_noncrediting_admission_preserve_separate_runtime_facts(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(
        tmp_path,
        config_factory,
        constrained_routes=True,
    )
    candidate, primary, replay = _routes(harness)
    ledger = harness.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    registry_reports = require_authenticated_runner_three_route_admission(
        candidate=candidate,
        primary_judge=primary,
        replay_judge=replay,
        purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
    )
    live_reports = require_authenticated_runner_three_route_admission(
        candidate=candidate,
        primary_judge=primary,
        replay_judge=replay,
        purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
        frozen_live_equivalent=True,
        runtime_required_output_tokens=harness.config.effective_reserved_output_tokens,
    )

    for registry_report, live_report in zip(registry_reports, live_reports, strict=True):
        registry_results = {item.predicate_id: item for item in registry_report.results}
        live_results = {item.predicate_id: item for item in live_report.results}
        assert registry_results[RoutePredicateId.FROZEN_LIVE_EQUIVALENCE].disposition is (
            RoutePredicateDisposition.UNAVAILABLE
        )
        assert live_results[RoutePredicateId.FROZEN_LIVE_EQUIVALENCE].disposition is (
            RoutePredicateDisposition.SATISFIED
        )
        for predicate, reason in (
            (
                RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE,
                RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE,
            ),
            (
                RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION,
                RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE,
            ),
        ):
            assert live_results[predicate].disposition is RoutePredicateDisposition.UNAVAILABLE
            assert live_results[predicate].reason is reason
    assert harness.usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
async def test_full_admission_rejects_fixed_unavailable_runtime_predicates(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(
        tmp_path,
        config_factory,
        constrained_routes=True,
    )
    candidate, primary, replay = _routes(harness)

    with pytest.raises(RoutePredicateRequirementError) as captured:
        require_authenticated_runner_three_route_admission(
            candidate=candidate,
            primary_judge=primary,
            replay_judge=replay,
            purpose=RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION,
            runtime_required_output_tokens=harness.config.effective_reserved_output_tokens,
        )

    assert captured.value.purpose is RouteConstraintPurpose.FULL_CAMPAIGN_ADMISSION
    failures = {item.predicate_id: item.reason for item in captured.value.failures}
    assert failures[RoutePredicateId.EMPIRICAL_SCHEMA_CONFORMANCE] is (
        RoutePredicateReason.EMPIRICAL_SCHEMA_EVIDENCE_UNAVAILABLE
    )
    assert failures[RoutePredicateId.TOKEN_DETAIL_REPORTING_CONVENTION] is (
        RoutePredicateReason.TOKEN_DETAIL_CONVENTION_UNAVAILABLE
    )


@pytest.mark.asyncio
async def test_noncrediting_admission_rejects_explicit_live_mismatch(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    harness = await execution_fixtures._harness(
        tmp_path,
        config_factory,
        constrained_routes=True,
    )
    candidate, primary, replay = _routes(harness)

    with pytest.raises(RoutePredicateRequirementError) as captured:
        require_authenticated_runner_three_route_admission(
            candidate=candidate,
            primary_judge=primary,
            replay_judge=replay,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
            frozen_live_equivalent=False,
            runtime_required_output_tokens=harness.config.effective_reserved_output_tokens,
        )

    assert any(
        item.predicate_id is RoutePredicateId.FROZEN_LIVE_EQUIVALENCE
        and item.reason is RoutePredicateReason.LIVE_EQUIVALENCE_MISMATCH
        for item in captured.value.failures
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("delta", (-256, 256))
async def test_noncrediting_admission_rejects_runtime_output_envelope_drift(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    delta: int,
) -> None:
    harness = await execution_fixtures._harness(
        tmp_path,
        config_factory,
        constrained_routes=True,
    )
    candidate, primary, replay = _routes(harness)
    ledger = harness.budget.atomic_ledger
    assert ledger is not None
    before = ledger.snapshot()

    with pytest.raises(RoutePredicateRequirementError) as captured:
        require_authenticated_runner_three_route_admission(
            candidate=candidate,
            primary_judge=primary,
            replay_judge=replay,
            purpose=RouteConstraintPurpose.NONCREDITING_SMOKE_ADMISSION,
            frozen_live_equivalent=True,
            runtime_required_output_tokens=(
                harness.config.effective_reserved_output_tokens + delta
            ),
        )

    assert any(
        item.predicate_id is RoutePredicateId.OUTPUT_CAPACITY_ENVELOPE
        and item.reason is RoutePredicateReason.RUNTIME_OUTPUT_TOKENS_MISMATCH
        for item in captured.value.failures
    )
    assert harness.usage.records == []
    assert ledger.snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("route_index", (0, 1, 2))
async def test_registry_report_hash_custody_rejects_each_exact_role(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    route_index: int,
) -> None:
    harness = await execution_fixtures._harness(
        tmp_path,
        config_factory,
        constrained_routes=True,
    )
    routes = list(_routes(harness))
    registry, manifest, evidence = routes[route_index]
    model = registry.candidates[0]
    tampered = CandidateModel.model_validate(
        {
            **model.model_dump(mode="python"),
            "route_predicate_report_sha256": "0" * 64,
        },
        strict=True,
    )
    routes[route_index] = (
        seal_candidate_registry(
            created_at=registry.created_at,
            discovery_run_sha256=registry.discovery_run_sha256,
            candidates=(tampered,),
        ),
        manifest,
        evidence,
    )
    candidate, primary, replay = routes

    with pytest.raises(
        AuthenticatedRunnerRouteAdmissionError,
        match="registry differs from its discovery",
    ):
        require_authenticated_runner_three_route_admission(
            candidate=candidate,
            primary_judge=primary,
            replay_judge=replay,
            purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
        )
