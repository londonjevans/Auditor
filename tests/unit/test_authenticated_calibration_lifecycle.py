"""Isolated lease-state tests, explicitly incapable of issuing production verification.

The production factory is not exported. Its exact AST is exercised in a separate
namespace with deterministic observer/proposal stand-ins. That registry is never
installed in the product; even its objects are rejected by the real consumer.
These tests establish lifecycle behavior, not REAL transport or campaign evidence.
"""

import ast
import gc
import weakref
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.models.authenticated_calibration as calibration
from tests.authenticated_calibration_support import population
from tests.unit import test_authenticated_runner_durable_bundle as runner_fixtures
from tests.unit.test_authenticated_calibration import measure
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution


@pytest.fixture
def isolated_lease():
    measured = measure(population())
    proposed = calibration._policy_proposal(measured)
    state = {"observations": 0, "proposals": 0, "on_observe": None, "on_policy": None}

    def observe_values(**_kwargs):
        state["observations"] += 1
        if state["on_observe"] is not None:
            state["on_observe"]()
        return state.get("replacement", measured)

    def propose_values(_artifact):
        state["proposals"] += 1
        if state["on_policy"] is not None:
            state["on_policy"]()
        return proposed

    namespace = dict(vars(calibration))
    namespace["_observe_inputs"] = observe_values
    namespace["_policy_proposal"] = propose_values
    source = Path(calibration.__file__)
    definitions = [
        node
        for node in ast.parse(source.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == "_build_calibration_authority"
    ]
    assert len(definitions) == 1 and not hasattr(calibration, "_build_calibration_authority")
    # Deliberately isolated white-box fixture; never modify calibration.__dict__.
    exec(compile(ast.Module(body=definitions, type_ignores=[]), str(source), "exec"), namespace)
    exports = namespace["_build_calibration_authority"]()
    names = (
        "observe_authenticated_model_calibration",
        "derive_authenticated_calibration_policy",
        "_require_verified_authenticated_model_calibration",
        "revoke_verified_authenticated_model_calibration",
    )
    namespace.update(zip(names, exports, strict=True))
    return SimpleNamespace(
        observe=exports[0],
        derive=exports[1],
        require=exports[2],
        revoke=exports[3],
        state=state,
        measured=measured,
        proposed=proposed,
        namespace=namespace,
    )


def issue_only_in_test_registry(scope):
    return scope.observe(
        selected_model_ids=scope.measured.selected_model_ids,
        benchmark_suite=None,
        ground_truth=None,
        inputs=(),
    )


def test_isolated_lease_revalidates_before_and_after_derivation_and_has_no_real_authority(
    isolated_lease,
):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)
    assert scope.derive(calibration=measured, verification=capability) == scope.proposed
    assert scope.state["observations"] == 3 and scope.state["proposals"] == 1
    with pytest.raises(ValueError, match="absent or revoked"):
        capability.require_for(measured)
    with pytest.raises(ValueError, match="absent or revoked"):
        calibration.derive_authenticated_calibration_policy(
            calibration=measured, verification=capability
        )


def test_isolated_revocation_is_one_way_and_prevents_policy_derivation(isolated_lease):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)
    scope.revoke(capability)
    with pytest.raises(ValueError, match="absent or revoked"):
        scope.derive(calibration=measured, verification=capability)
    with pytest.raises(ValueError, match="absent or revoked"):
        scope.revoke(capability)
    assert scope.state["observations"] == 1 and scope.state["proposals"] == 0


@pytest.mark.parametrize("during", ["observation", "proposal"])
def test_isolated_revocation_during_use_cannot_return_a_policy(isolated_lease, during):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)
    scope.state["on_observe" if during == "observation" else "on_policy"] = lambda: scope.revoke(
        capability
    )
    with pytest.raises(ValueError, match=r"revoked during revalidation|absent or revoked"):
        scope.derive(calibration=measured, verification=capability)
    assert scope.state["proposals"] == (0 if during == "observation" else 1)


@pytest.mark.parametrize("invalid_on", [2, 3])
def test_isolated_upstream_custody_loss_before_or_after_projection_is_not_accepted(
    isolated_lease, invalid_on
):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)

    def require_live():
        if scope.state["observations"] == invalid_on:
            raise ValueError("synthetic upstream custody was revoked")

    scope.state["on_observe"] = require_live
    with pytest.raises(ValueError, match="upstream custody was revoked"):
        scope.derive(calibration=measured, verification=capability)
    assert scope.state["proposals"] == invalid_on - 2


def test_isolated_capability_is_bound_to_original_artifact(isolated_lease):
    scope = isolated_lease
    _, capability = issue_only_in_test_registry(scope)
    with pytest.raises(ValueError, match="belongs to other evidence"):
        scope.derive(calibration=measure(population(1)), verification=capability)
    assert scope.state["observations"] == 1 and scope.state["proposals"] == 0


def test_isolated_live_rebuild_must_equal_original_measurements(isolated_lease):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)
    scope.state["replacement"] = measure(population(1))
    with pytest.raises(ValueError, match="changed after observation"):
        scope.derive(calibration=measured, verification=capability)
    assert scope.state["proposals"] == 0


def test_isolated_registry_does_not_keep_abandoned_capability_alive(isolated_lease):
    _, capability = issue_only_in_test_registry(isolated_lease)
    reference = weakref.ref(capability)
    del capability
    gc.collect()
    assert reference() is None


def test_isolated_revocation_remains_permanent_when_rule_drift_is_reported(isolated_lease):
    scope = isolated_lease
    measured, capability = issue_only_in_test_registry(scope)
    original = scope.namespace["read_authenticated_model_calibration"]
    scope.namespace["read_authenticated_model_calibration"] = None
    with pytest.raises(ValueError, match="not pristine"):
        scope.revoke(capability)
    scope.namespace["read_authenticated_model_calibration"] = original
    with pytest.raises(ValueError, match="absent or revoked"):
        scope.derive(calibration=measured, verification=capability)


@pytest.mark.parametrize("lose_earlier_custody", [False, True])
def test_private_observer_consumes_then_rechecks_every_candidate_without_issuing_authority(
    monkeypatch,
    lose_earlier_custody,
):
    """Stub only upstream verification to assay assembly, never the public issuer."""

    live = runner_fixtures._v11_inputs().live
    sources = population(2)
    inputs = []
    lookup = {}
    for source in sources:
        capability = object.__new__(calibration.VerifiedCrossLineageRunnerCustody)
        retained = tuple(
            replace(
                original,
                candidate_campaign_effective_config_sha256=run.effective_config_sha256,
                candidate_campaign_policy_sha256=run.policy_sha256,
                candidate_portfolio=original.candidate_portfolio.model_copy(
                    update={
                        "portfolio_sha256": run.portfolio_sha256,
                        "diagnostics": (run.diagnostic,),
                    }
                ),
            )
            for original, run in zip(live.runs, source.runs, strict=True)
        )
        item = calibration.AuthenticatedCalibrationCandidateInputs(
            runner_custody=capability,
            runner_evidence=source.runner_evidence,
            runs=retained,
        )
        inputs.append(item)
        lookup[capability] = source
    consumed, rechecked = [], []

    def consume(**kwargs):
        capability = kwargs["runner_custody"]
        source = lookup[capability]
        assert kwargs["runner_evidence"] is source.runner_evidence
        assert kwargs["benchmark_suite"] is live.suite
        consumed.append(capability)
        return source.collision_map, tuple(run.decision for run in source.runs)

    def require(capability, *, evidence):
        assert len(consumed) == len(inputs)
        assert evidence is lookup[capability].runner_evidence
        rechecked.append(capability)
        if lose_earlier_custody and capability is inputs[0].runner_custody:
            raise ValueError("earlier synthetic custody was revoked")

    monkeypatch.setattr(calibration, "build_authenticated_evidence_seal_runner_inputs", consume)
    monkeypatch.setattr(calibration, "require_verified_cross_lineage_runner_custody", require)
    kwargs = dict(
        selected_model_ids=tuple(
            source.collision_map.candidate.exact_model_id for source in sources
        ),
        benchmark_suite=live.suite,
        ground_truth=live.ground_truth,
        inputs=tuple(inputs),
    )
    if lose_earlier_custody:
        with pytest.raises(ValueError, match="earlier synthetic custody was revoked"):
            calibration._observe_inputs(**kwargs)
    else:
        assert calibration._observe_inputs(**kwargs) == measure(sources)
        assert rechecked == [item.runner_custody for item in inputs]
    assert consumed == [item.runner_custody for item in inputs]
    with pytest.raises(ValueError, match="not pristine"):
        calibration.observe_authenticated_model_calibration(**kwargs)
