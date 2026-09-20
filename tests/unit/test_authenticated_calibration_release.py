"""Native release joins with test-only successor pins and synthetic source measurements.

Positive cases use the original opaque release-observation registry, but its host
measurement is explicitly stubbed. They do not prove a REAL successor release,
native population origin, external publication, or policy adoption.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.config as config_module
import mmaudit.models.release_attestation as release_module
import mmaudit.orchestration.authenticated_calibration_release as transition
from mmaudit.config import parse_canonical_audit_config
from mmaudit.models.calibration_transition import CalibrationReleaseTransitionArtifact
from mmaudit.models.qualification_workflow import seal_qualification_release_bindings
from mmaudit.models.release_attestation import TrustedReleaseBindingObservation
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_authenticated_calibration_config import proposal_data as proposal_data
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_release_attestation import NOW, _measurement

PIN_NAMES = (
    "MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256",
    "MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION",
    "MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256",
    "MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION",
    "MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256",
)


def bindings_for(config):
    return seal_qualification_release_bindings(
        source_commit="1" * 40,
        source_tree_sha256="2" * 64,
        effective_config_sha256=config.stable_hash(),
        prompt_sha256="3" * 64,
        response_schema_sha256="4" * 64,
        toolchain_sha256="5" * 64,
        isolation_sha256="6" * 64,
        benchmark_corpus_version=config.maximum_assurance.qualification.corpus_version,
        benchmark_ground_truth_version=config.maximum_assurance.qualification.ground_truth_version,
    )


def observe_synthetic(bindings, monkeypatch):
    with monkeypatch.context() as context:
        context.setattr(release_module, "_utc_now", lambda: NOW)
        context.setattr(
            release_module,
            "measure_qualification_release_environment",
            lambda **_: _measurement(bindings),
        )
        return release_module.observe_and_verify_qualification_release(
            release_bindings=bindings,
            source_root=Path("/synthetic-non-executable-release"),
            isolation_backend=object(),
        )


@pytest.fixture
def future_inputs(proposal_data, monkeypatch):
    # This is an isolated future-source simulation, never mutation of the original
    # validator's captured P1 pin or adoption of the synthetic policy.
    monkeypatch.setattr(
        config_module, PIN_NAMES[0], proposal_data.measurement_subject.policy.policy_sha256
    )
    config = parse_canonical_audit_config(proposal_data.successor_effective_config_json)
    bindings = bindings_for(config)
    observation = observe_synthetic(bindings, monkeypatch)
    pins = tuple(getattr(config_module, name) for name in PIN_NAMES)

    def make_validator(release=release_module):
        return isolated_factory(
            transition,
            "_build_native_release_input_validator",
            {"_COMPILED_NATIVE_RELEASE_PINS": pins, "_release": release},
        )[1]

    return SimpleNamespace(
        proposal=proposal_data.model_copy(deep=True),
        config=config,
        bindings=bindings,
        observation=observation,
        validate=make_validator(),
        make_validator=make_validator,
    )


def validate(state, **changes):
    args = {
        "proposal": state.proposal,
        "successor_config": state.config,
        "release_bindings": state.bindings,
        "trusted_release_observation": state.observation,
    }
    return state.validate(**{**args, **changes})


def test_future_source_join_reuses_exact_nonauthorizing_transition(future_inputs):
    state = future_inputs
    result = validate(state)
    proposal = state.proposal
    assert type(result) is CalibrationReleaseTransitionArtifact
    assert result.predecessor_policy_sha256 == proposal.predecessor_policy.policy_sha256
    assert (
        result.predecessor_effective_config_sha256 == proposal.predecessor_effective_config_sha256
    )
    assert (
        result.calibration_artifact_sha256
        == proposal.measurement_subject.calibration.artifact_sha256
    )
    assert result.successor_policy_sha256 == proposal.measurement_subject.policy.policy_sha256
    assert result.successor_effective_config_sha256 == state.config.stable_hash()
    assert result.successor_release_bindings_sha256 == state.bindings.bindings_sha256
    assert result.policy_independent_config_sha256 == proposal.policy_independent_config_sha256
    assert result.production_selection_authority is False
    assert (
        CalibrationReleaseTransitionArtifact.model_validate_json(result.model_dump_json()) == result
    )
    assert not hasattr(result, "require_release_pinned_for")
    assert not hasattr(transition, "_build_native_release_input_validator")
    assert not hasattr(transition, "_COMPILED_NATIVE_RELEASE_PINS")


def test_original_current_source_refuses_p2_even_after_runtime_pin_mutation(future_inputs):
    future_inputs.validate = transition.validate_authenticated_calibration_successor_release_inputs
    with pytest.raises(ValueError, match="source pins changed"):
        validate(future_inputs)


def test_original_current_p1_source_does_not_admit_proposed_p2(proposal_data, monkeypatch):
    config = parse_canonical_audit_config(proposal_data.predecessor_effective_config_json)
    bindings = bindings_for(config)
    with pytest.raises(ValueError, match="not pinned by this source release"):
        transition.validate_authenticated_calibration_successor_release_inputs(
            proposal=proposal_data,
            successor_config=config,
            release_bindings=bindings,
            trusted_release_observation=observe_synthetic(bindings, monkeypatch),
        )


@pytest.mark.parametrize(
    "field", ["proposal", "successor_config", "release_bindings", "trusted_release_observation"]
)
def test_serialized_or_absent_inputs_cannot_recreate_release_join(future_inputs, field):
    with pytest.raises(ValueError, match="exact input types"):
        validate(future_inputs, **{field: {}})


def test_forged_observation_cannot_bypass_original_registry_using_a_patched_method(
    future_inputs, monkeypatch
):
    forged = object.__new__(TrustedReleaseBindingObservation)
    monkeypatch.setattr(TrustedReleaseBindingObservation, "require_for", lambda *_: None)
    with pytest.raises(ValueError, match="not trusted"):
        validate(future_inputs, trusted_release_observation=forged)


@pytest.mark.parametrize("name", PIN_NAMES)
def test_all_five_source_pins_remain_frozen(future_inputs, monkeypatch, name):
    monkeypatch.setattr(config_module, name, "7" * 64)
    with pytest.raises(ValueError, match="source pins changed"):
        validate(future_inputs)


@pytest.mark.parametrize(
    "field",
    [
        "source_commit",
        "source_tree_sha256",
        "effective_config_sha256",
        "prompt_sha256",
        "response_schema_sha256",
        "toolchain_sha256",
        "isolation_sha256",
        "benchmark_corpus_version",
        "benchmark_ground_truth_version",
    ],
)
def test_every_release_binding_field_is_joined_after_coherent_reseal(future_inputs, field):
    values = future_inputs.bindings.model_dump(exclude={"schema_version", "bindings_sha256"})
    values[field] = (
        "2.1" if field.endswith("version") else "8" * (40 if field == "source_commit" else 64)
    )
    changed = seal_qualification_release_bindings(**values)
    with pytest.raises(ValueError, match=r"bindings differ|differs from qualification bindings"):
        validate(future_inputs, release_bindings=changed)


def test_complete_c2_comparison_rejects_non_policy_config_drift(future_inputs):
    data = json.loads(future_inputs.proposal.successor_effective_config_json)
    data["repository"]["include_docs"] = not data["repository"]["include_docs"]
    config = config_module.AuditConfig.model_validate(data).effective()
    with pytest.raises(ValueError, match="complete proposed C2"):
        validate(future_inputs, successor_config=config)


@pytest.mark.parametrize("after_check", [1, 2])
@pytest.mark.parametrize("field", ["proposal", "config", "bindings", "source_pin"])
def test_changes_during_original_release_checks_are_refused(
    future_inputs, monkeypatch, after_check, field
):
    state = future_inputs
    original = release_module._require_trusted_release_observation
    calls = 0

    def checked(observation, bindings):
        nonlocal calls
        original(observation, bindings)
        calls += 1
        if calls == after_check:
            if field == "proposal":
                object.__setattr__(state.proposal, "proposal_sha256", "9" * 64)
            elif field == "config":
                state.config.repository.include_docs = not state.config.repository.include_docs
            elif field == "bindings":
                values = state.bindings.model_dump(exclude={"schema_version", "bindings_sha256"})
                values["prompt_sha256"] = "9" * 64
                replacement = seal_qualification_release_bindings(**values)
                object.__setattr__(state.bindings, "prompt_sha256", replacement.prompt_sha256)
                object.__setattr__(state.bindings, "bindings_sha256", replacement.bindings_sha256)
            else:
                monkeypatch.setattr(config_module, PIN_NAMES[0], "9" * 64)

    state.validate = state.make_validator(
        SimpleNamespace(_require_trusted_release_observation=checked)
    )
    with pytest.raises(ValueError):
        validate(state)
    assert calls >= after_check


@pytest.mark.parametrize("target", ["proposal_reader", "release_require", "config_reader"])
def test_original_dependency_replacement_cannot_supply_a_passing_join(
    future_inputs, monkeypatch, target
):
    module, name = {
        "proposal_reader": (transition._proposal, "read_authenticated_calibration_config_proposal"),
        "release_require": (release_module, "_require_trusted_release_observation"),
        "config_reader": (config_module, "parse_canonical_audit_config"),
    }[target]
    monkeypatch.setattr(module, name, lambda *_: None)
    with pytest.raises(ValueError, match="dependency changed"):
        validate(future_inputs)


@pytest.mark.parametrize("target", ["proposal_reader", "release_require", "config_reader"])
def test_original_dependency_code_mutation_is_refused(future_inputs, monkeypatch, target):
    function = {
        "proposal_reader": transition._proposal.read_authenticated_calibration_config_proposal,
        "release_require": release_module._require_trusted_release_observation,
        "config_reader": config_module.parse_canonical_audit_config,
    }[target]
    monkeypatch.setattr(function, "__code__", function.__code__.replace(co_name="changed"))
    with pytest.raises(ValueError, match="dependency changed"):
        validate(future_inputs)
