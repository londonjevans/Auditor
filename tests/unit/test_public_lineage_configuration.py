from __future__ import annotations

import copy
import pickle
from dataclasses import replace
from typing import cast

import pytest

import mmaudit.models.public_lineage_authority as authority_module
import mmaudit.models.public_lineage_configuration as configuration_module
from mmaudit.config import PrivacyConfig
from mmaudit.models.public_lineage_authority import (
    VerifiedPublicModelLineage,
    public_model_lineage_inventory,
    require_independent_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.public_lineage_configuration import (
    PublicModelLineageConfigurationProjection,
    project_public_model_lineage_configuration,
)

_COGITO = "deepcogito/cogito-v2.1-671b"
_DEEPSEEK_V3 = "deepseek/deepseek-v3.2-exp"
_DEEPSEEK_V4 = "deepseek/deepseek-v4-pro-0813"
_KIMI_K2 = "moonshotai/kimi-k2-thinking"
_KIMI_K3 = "moonshotai/kimi-k3"
_META = "meta-llama/llama-4-maverick"
_NEMOTRON = "nvidia/nemotron-3-super-120b-a12b"
_GPT_OSS = "openai/gpt-oss-120b"
_HUNYUAN = "tencent/hunyuan-a13b-instruct"
_TENCENT_HY3 = "tencent/hy3"
_UNCONFIRMED = (
    "mistralai/mistral-small-2603",
    _GPT_OSS,
    _HUNYUAN,
    "z-ai/glm-4.7",
)
_EXPECTED_CONSTRAINT_IDS = (
    "constraint-cogito-deepseek",
    "constraint-deepseek-family",
    "constraint-gemma-gemini",
    "constraint-gpt-oss-gpt-5-6",
    "constraint-kimi-k2-k3",
    "constraint-nemotron-meta",
    "constraint-tencent-hy3-hunyuan",
)
_EXPECTED_CONSTRAINT_MEMBERS = {
    "constraint-cogito-deepseek": (_COGITO, _DEEPSEEK_V3),
    "constraint-deepseek-family": (_COGITO, _DEEPSEEK_V3, _DEEPSEEK_V4),
    "constraint-gemma-gemini": (
        "google/gemini-3.7-flash",
        "google/gemma-4-26b-a4b-it",
    ),
    "constraint-gpt-oss-gpt-5-6": (
        "openai/gpt-5.6-sol",
        "openai/gpt-oss-120b",
    ),
    "constraint-kimi-k2-k3": (_KIMI_K2, _KIMI_K3),
    "constraint-nemotron-meta": (_META, _NEMOTRON),
    "constraint-tencent-hy3-hunyuan": (_HUNYUAN, _TENCENT_HY3),
}

_FALSE_AUTHORITY_FIELDS = (
    "serialized_authority",
    "provider_call_authorized",
    "source_egress_authorized",
    "runner_authority_authorized",
    "model_qualification_authorized",
    "production_selection_authorized",
    "seal_publication_authorized",
    "release_authorized",
    "benchmark_authorized",
)


def test_projection_derives_config_values_only_from_confirmed_capability() -> None:
    capability = resolve_verified_public_model_lineage()
    inventory = public_model_lineage_inventory(capability)

    projection = project_public_model_lineage_configuration(capability)

    assert projection.eligible_exact_candidate_ids == inventory.confirmed_exact_model_ids
    assert (
        projection.excluded_unconfirmed_exact_model_ids
        == inventory.unconfirmed_exact_model_ids
        == inventory.excluded_exact_model_ids
    )
    assert projection.approved_model_lineages == inventory.approved_root_lineages
    assert projection.confirmed_bindings == inventory.confirmed_bindings
    assert tuple(binding.exact_model_id for binding in projection.confirmed_bindings) == (
        projection.eligible_exact_candidate_ids
    )
    assert set(projection.approved_model_lineages) == {
        binding.root_lineage for binding in projection.confirmed_bindings
    }
    assert not (
        set(projection.eligible_exact_candidate_ids)
        & set(projection.excluded_unconfirmed_exact_model_ids)
    )
    assert (
        PrivacyConfig(
            approved_model_lineages=projection.approved_model_lineages
        ).approved_model_lineages
        == projection.approved_model_lineages
    )
    for field in _FALSE_AUTHORITY_FIELDS:
        assert getattr(projection, field) is False


def test_projection_preserves_current_inclusion_and_all_negative_constraints() -> None:
    capability = resolve_verified_public_model_lineage()
    inventory = public_model_lineage_inventory(capability)
    projection = project_public_model_lineage_configuration(capability)

    assert (
        projection.conservative_non_independence_constraints
        == inventory.conservative_non_independence_constraints
    )
    assert (
        tuple(item.constraint_id for item in projection.conservative_non_independence_constraints)
        == _EXPECTED_CONSTRAINT_IDS
    )
    assert len(projection.eligible_exact_candidate_ids) == 11
    assert len(projection.approved_model_lineages) == 10
    assert projection.excluded_unconfirmed_exact_model_ids == _UNCONFIRMED
    assert not set(_UNCONFIRMED) & set(projection.eligible_exact_candidate_ids)
    assert _NEMOTRON in projection.eligible_exact_candidate_ids
    assert {
        item.constraint_id: item.member_exact_model_ids
        for item in projection.conservative_non_independence_constraints
    } == _EXPECTED_CONSTRAINT_MEMBERS
    nemotron_constraint = next(
        item
        for item in projection.conservative_non_independence_constraints
        if item.constraint_id == "constraint-nemotron-meta"
    )
    assert _NEMOTRON in nemotron_constraint.member_exact_model_ids
    assert nemotron_constraint.negative_only is True
    assert nemotron_constraint.positive_root_assignment_authorized is False
    assert all(
        item.negative_only is True and item.positive_root_assignment_authorized is False
        for item in projection.conservative_non_independence_constraints
    )
    with pytest.raises(ValueError, match=r"not independent|conservatively non-independent"):
        require_independent_public_model_lineage(capability, _COGITO, _DEEPSEEK_V3)
    for left, right in (
        (_COGITO, _DEEPSEEK_V4),
        (_DEEPSEEK_V4, _COGITO),
        (_DEEPSEEK_V3, _DEEPSEEK_V4),
        (_DEEPSEEK_V4, _DEEPSEEK_V3),
        (_KIMI_K2, _KIMI_K3),
        (_KIMI_K3, _KIMI_K2),
    ):
        with pytest.raises(ValueError, match="conservatively non-independent"):
            require_independent_public_model_lineage(capability, left, right)
    nemotron_binding = next(
        item for item in projection.confirmed_bindings if item.exact_model_id == _NEMOTRON
    )
    meta_binding = next(
        item for item in projection.confirmed_bindings if item.exact_model_id == _META
    )
    assert nemotron_binding.root_lineage != meta_binding.root_lineage
    with pytest.raises(ValueError, match="conservatively non-independent"):
        require_independent_public_model_lineage(capability, _NEMOTRON, _META)


def test_projection_requires_an_issued_opaque_production_capability() -> None:
    capability = resolve_verified_public_model_lineage()
    with pytest.raises(TypeError, match="cannot be constructed"):
        VerifiedPublicModelLineage()
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"cannot be copied|cannot be serialized"):
            operation(capability)

    forged = object.__new__(VerifiedPublicModelLineage)
    with pytest.raises(ValueError, match="absent"):
        project_public_model_lineage_configuration(forged)
    with pytest.raises((TypeError, ValueError)):
        project_public_model_lineage_configuration(
            cast(VerifiedPublicModelLineage, public_model_lineage_inventory(capability))
        )


def test_projection_replays_fresh_values_and_rejects_api_retargeting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capability = resolve_verified_public_model_lineage()
    expected = project_public_model_lineage_configuration(capability)
    mutated = project_public_model_lineage_configuration(capability)
    object.__setattr__(mutated, "approved_model_lineages", ("sha256:" + "0" * 64,))

    assert project_public_model_lineage_configuration(capability) == expected

    monkeypatch.setattr(
        authority_module,
        "public_model_lineage_inventory",
        lambda _capability: object(),
    )
    with pytest.raises(ValueError, match="resolver binding changed"):
        project_public_model_lineage_configuration(capability)


def test_precaptured_projection_rejects_output_constructor_retargeting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_ref = project_public_model_lineage_configuration
    capability = resolve_verified_public_model_lineage()
    constructor_calls = 0

    def forged_projection(**_values: object) -> object:
        nonlocal constructor_calls
        constructor_calls += 1
        return object()

    monkeypatch.setattr(
        configuration_module,
        "PublicModelLineageConfigurationProjection",
        forged_projection,
    )
    with pytest.raises(ValueError, match="resolver binding changed"):
        project_ref(capability)
    assert constructor_calls == 0


def test_precaptured_projection_rejects_exported_projector_retargeting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_ref = project_public_model_lineage_configuration
    capability = resolve_verified_public_model_lineage()
    monkeypatch.setattr(
        configuration_module,
        "project_public_model_lineage_configuration",
        object(),
    )
    with pytest.raises(ValueError, match="resolver binding changed"):
        project_ref(capability)


def test_projection_is_not_an_audit_config_or_runtime_authority() -> None:
    projection = project_public_model_lineage_configuration(resolve_verified_public_model_lineage())

    assert type(projection) is PublicModelLineageConfigurationProjection
    with pytest.raises(TypeError, match="init=False"):
        replace(projection, source_egress_authorized=True)  # type: ignore[arg-type]
    assert not hasattr(projection, "model_for")
    assert not hasattr(projection, "routing_evidence")
    assert not hasattr(projection, "authorize")
