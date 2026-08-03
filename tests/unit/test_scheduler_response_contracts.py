from __future__ import annotations

import hashlib
from types import SimpleNamespace
from typing import cast

import pytest
from pydantic import BaseModel, field_validator

import mmaudit.models.scheduler as scheduler_module
from mmaudit.models.openrouter import strict_json_schema
from mmaudit.models.scheduler import (
    SchedulerPassKind,
    SchedulerScope,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    _parse_scheduler_model_payload,
    scheduler_canonical_sha256,
    scheduler_response_schema_model_registry,
    scheduler_response_schema_sha256,
)
from mmaudit.models.schemas import ThreatModel
from mmaudit.orchestration.scheduler_runtime import scheduler_response_schema_registry
from tests.scheduler_support import _synthetic_manifest


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _orientation_task() -> tuple[SchedulerTaskPlan, str]:
    schema_sha256 = scheduler_canonical_sha256(strict_json_schema(ThreatModel))
    task = SchedulerTaskPlan.build(
        manifest=_synthetic_manifest("orientation-contract"),
        pass_kind=SchedulerPassKind.ORIENTATION,
        scope=SchedulerScope.global_scope(),
        task_kind=SchedulerTaskKind.MODEL_REQUEST,
        task_key="threat-model",
        role="threat_model",
        requested_model="synthetic/auditor-v1",
        root_lineage="sha256:" + _sha256("orientation-lineage"),
        input_sha256=_sha256("orientation-input"),
        prompt_sha256=_sha256("orientation-prompt"),
        system_prompt_sha256=_sha256("orientation-system"),
        normalizer_sha256=_sha256("orientation-normalizer"),
        response_schema_sha256=schema_sha256,
    )
    return task, schema_sha256


def test_runtime_schema_inventory_uses_the_single_parser_registry() -> None:
    model_registry = scheduler_response_schema_model_registry()
    runtime_registry = scheduler_response_schema_registry()

    assert {item["schema_sha256"] for item in runtime_registry} == set(model_registry)
    assert {item["model_type"] for item in runtime_registry} == {
        f"{model.__module__}.{model.__qualname__}" for model in model_registry.values()
    }


def test_parser_registry_cache_is_isolated_from_caller_mutation() -> None:
    expected = scheduler_response_schema_model_registry()
    poisoned = scheduler_response_schema_model_registry()
    poisoned.clear()
    poisoned["f" * 64] = ThreatModel

    observed = scheduler_response_schema_model_registry()

    assert observed == expected
    assert observed is not poisoned
    assert set(observed) != {"f" * 64}


def test_registered_response_hash_is_the_exact_strict_schema_contract() -> None:
    expected = scheduler_canonical_sha256(strict_json_schema(ThreatModel))

    assert scheduler_response_schema_sha256(ThreatModel) == expected


def test_parser_rejects_same_class_schema_drift_after_forced_rebuild(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DynamicSchedulerResponse(BaseModel):
        value: str

    task, _schema_sha256 = _orientation_task()
    original_models = scheduler_module._SCHEDULER_RESPONSE_MODELS
    scheduler_module._scheduler_response_schema_model_registry.cache_clear()
    monkeypatch.setattr(
        scheduler_module,
        "_SCHEDULER_RESPONSE_MODELS",
        (DynamicSchedulerResponse,),
    )
    monkeypatch.setattr(
        scheduler_module,
        "_expected_response_model",
        lambda _task: DynamicSchedulerResponse,
    )
    try:
        registry = scheduler_response_schema_model_registry()
        frozen_sha256 = next(iter(registry))
        activation = cast(
            SchedulerTaskActivation,
            SimpleNamespace(response_schema_sha256=frozen_sha256),
        )

        DynamicSchedulerResponse.model_fields["value"].annotation = int
        assert DynamicSchedulerResponse.model_rebuild(force=True) is True
        assert DynamicSchedulerResponse.model_validate({"value": 7}).value == 7

        with pytest.raises(ValueError, match="schema drifted after registry construction"):
            scheduler_response_schema_model_registry()
        with pytest.raises(ValueError, match="schema drifted after registry construction"):
            _parse_scheduler_model_payload(
                task=task,
                activation=activation,
                payload={"value": 7},
            )
    finally:
        scheduler_module._SCHEDULER_RESPONSE_MODELS = original_models
        scheduler_module._scheduler_response_schema_model_registry.cache_clear()


def test_parser_rejects_schema_rebuild_during_model_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rebuild_state = {"complete": False}

    class DynamicSchedulerResponse(BaseModel):
        value: str

        @field_validator("value")
        @classmethod
        def rebuild_during_validation(cls, value: str) -> str:
            if not rebuild_state["complete"]:
                rebuild_state["complete"] = True
                assert cls.model_rebuild(force=True) is True
            return value

    task, _schema_sha256 = _orientation_task()
    original_models = scheduler_module._SCHEDULER_RESPONSE_MODELS
    scheduler_module._scheduler_response_schema_model_registry.cache_clear()
    monkeypatch.setattr(
        scheduler_module,
        "_SCHEDULER_RESPONSE_MODELS",
        (DynamicSchedulerResponse,),
    )
    monkeypatch.setattr(
        scheduler_module,
        "_expected_response_model",
        lambda _task: DynamicSchedulerResponse,
    )
    try:
        frozen_sha256 = next(iter(scheduler_response_schema_model_registry()))
        activation = cast(
            SchedulerTaskActivation,
            SimpleNamespace(response_schema_sha256=frozen_sha256),
        )

        with pytest.raises(ValueError, match="changed response schema during validation"):
            _parse_scheduler_model_payload(
                task=task,
                activation=activation,
                payload={"value": "synthetic"},
            )
    finally:
        scheduler_module._SCHEDULER_RESPONSE_MODELS = original_models
        scheduler_module._scheduler_response_schema_model_registry.cache_clear()


def test_parser_ignores_mutated_model_validate_and_uses_captured_schema_validator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DynamicSchedulerResponse(BaseModel):
        value: str

    task, _schema_sha256 = _orientation_task()
    original_models = scheduler_module._SCHEDULER_RESPONSE_MODELS
    scheduler_module._scheduler_response_schema_model_registry.cache_clear()
    monkeypatch.setattr(
        scheduler_module,
        "_SCHEDULER_RESPONSE_MODELS",
        (DynamicSchedulerResponse,),
    )
    monkeypatch.setattr(
        scheduler_module,
        "_expected_response_model",
        lambda _task: DynamicSchedulerResponse,
    )
    try:
        frozen_sha256 = next(iter(scheduler_response_schema_model_registry()))
        activation = cast(
            SchedulerTaskActivation,
            SimpleNamespace(response_schema_sha256=frozen_sha256),
        )

        def fail_open_model_validate(
            cls: type[DynamicSchedulerResponse],
            _payload: object,
        ) -> DynamicSchedulerResponse:
            return cls.model_construct(value={"unexpected": "nested payload"})

        monkeypatch.setattr(
            DynamicSchedulerResponse,
            "model_validate",
            classmethod(fail_open_model_validate),
        )

        with pytest.raises(ValueError, match="violates its registered response schema"):
            _parse_scheduler_model_payload(
                task=task,
                activation=activation,
                payload={"unexpected": "payload"},
            )

        parsed = _parse_scheduler_model_payload(
            task=task,
            activation=activation,
            payload={"value": "validated by captured schema"},
        )
        assert type(parsed) is DynamicSchedulerResponse
        assert parsed.value == "validated by captured schema"
    finally:
        scheduler_module._SCHEDULER_RESPONSE_MODELS = original_models
        scheduler_module._scheduler_response_schema_model_registry.cache_clear()


def test_orientation_rejects_schema_valid_but_empty_threat_evidence() -> None:
    task, schema_sha256 = _orientation_task()
    activation = cast(
        SchedulerTaskActivation,
        SimpleNamespace(response_schema_sha256=schema_sha256),
    )
    empty = {
        "assets": [],
        "trust_boundaries": [],
        "attacker_controlled_inputs": [],
        "identities_and_roles": [],
        "sensitive_data": [],
        "external_integrations": [],
        "attack_surfaces": [],
        "missing_controls": [],
        "review_targets": [],
    }

    with pytest.raises(ValueError, match="substantive core threat evidence"):
        _parse_scheduler_model_payload(task=task, activation=activation, payload=empty)


def test_orientation_accepts_nonempty_core_threat_evidence() -> None:
    task, schema_sha256 = _orientation_task()
    activation = cast(
        SchedulerTaskActivation,
        SimpleNamespace(response_schema_sha256=schema_sha256),
    )
    parsed = _parse_scheduler_model_payload(
        task=task,
        activation=activation,
        payload={
            "assets": ["synthetic protocol state"],
            "trust_boundaries": [
                {
                    "name": "synthetic boundary",
                    "description": "Only the local synthetic fixture is in scope.",
                    "locations": [],
                }
            ],
            "attacker_controlled_inputs": ["synthetic call data"],
            "identities_and_roles": ["synthetic caller"],
            "sensitive_data": [],
            "external_integrations": [],
            "attack_surfaces": ["synthetic entry point"],
            "missing_controls": [],
            "review_targets": ["synthetic state-transition invariant"],
        },
    )

    assert isinstance(parsed, ThreatModel)
