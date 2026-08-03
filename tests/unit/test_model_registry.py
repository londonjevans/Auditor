from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.config import (
    AuditConfig,
    configured_model_ids,
    validate_model_independence,
)
from mmaudit.models.qualification import (
    VerifiedProductionQualification,
    seal_qualified_reasoning_role_binding,
)
from mmaudit.models.registry import ModelRegistry, ProductionQualificationValidation
from mmaudit.models.schemas import AuditProfile
from tests.conftest import MODEL_IDS, base_config_data, model_registry_entry
from tests.unit import test_model_qualification as qualification_fixtures


def _metadata(config: AuditConfig) -> list[dict[str, Any]]:
    return [
        {
            "id": model_id,
            "supported_parameters": ["response_format"],
        }
        for model_id in configured_model_ids(config, include_fallbacks=True)
    ]


def _verified_production_config_and_capability() -> tuple[
    AuditConfig, VerifiedProductionQualification, datetime
]:
    bundle = qualification_fixtures._bundle()
    observed_at = qualification_fixtures._NOW + timedelta(hours=4)
    results = bundle.artifact.results
    registry = []
    for result in results:
        assert result.root_lineage is not None
        entry = model_registry_entry(
            result.exact_model_id,
            root_lineage=result.root_lineage,
            measured_quality_score=result.overall_score,
            measured_quality_tier="highest",
        )
        entry["measured_quality"]["measurement"] = f"sha256:{result.quality_measurement_sha256}"
        registry.append(entry)
    roles = list(MODEL_IDS)
    role_models: dict[str, Any] = {
        role: {"primary": results[index].exact_model_id, "fallbacks": []}
        for index, role in enumerate(roles)
    }
    role_models["specialists"] = {
        "access_control": {
            "primary": results[6].exact_model_id,
            "fallbacks": [],
        },
        "report_quality": {
            "primary": results[7].exact_model_id,
            "fallbacks": [],
        },
    }
    data = base_config_data()
    data["privacy"]["approved_model_lineages"] = sorted(
        {result.root_lineage for result in results if result.root_lineage is not None}
    )
    data["models"].update(
        {
            "provider_policy": {
                "only": sorted({result.approved_provider_endpoint for result in results}),
                "allow_fallbacks": False,
            },
            "registry": registry,
            **role_models,
        }
    )
    config = AuditConfig.model_validate(data)
    assert bundle.bindings.effective_config_sha256 != config.stable_hash()
    qualification = qualification_fixtures._resolve_for_test(
        bundle,
        production_effective_config_sha256=config.stable_hash(),
    )
    return config, qualification, observed_at


def _reseal_production_validation_payload(payload: dict[str, Any]) -> None:
    unsigned = {key: value for key, value in payload.items() if key != "validation_sha256"}
    payload["validation_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def test_lineage_record_is_immutable(config_factory) -> None:
    lineage = config_factory().models.registry[0]
    with pytest.raises(ValidationError, match="frozen"):
        lineage.root_lineage = "sha256:" + ("f" * 64)


def test_identity_only_lineage_has_no_quality_sentinel() -> None:
    data = base_config_data()
    data["models"]["registry"][0].pop("measured_quality")

    config = AuditConfig.model_validate(data)
    lineage = config.models.registry[0]
    serialized = lineage.model_dump(mode="json")

    assert lineage.measured_quality is None
    assert "measured_quality" not in serialized
    assert "measured_quality_score" not in serialized
    assert "measured_quality_tier" not in serialized
    assert "quality_measurement" not in serialized


def test_identity_only_lineage_rejects_explicit_null_quality() -> None:
    data = base_config_data()
    data["models"]["registry"][0]["measured_quality"] = None

    with pytest.raises(ValidationError, match="must be omitted rather than null"):
        AuditConfig.model_validate(data)


@pytest.mark.parametrize("missing", ["score", "tier", "measurement"])
def test_partial_measured_quality_record_is_rejected(missing: str) -> None:
    data = base_config_data()
    data["models"]["registry"][0]["measured_quality"].pop(missing)

    with pytest.raises(ValidationError, match="Field required"):
        AuditConfig.model_validate(data)


def test_flat_legacy_quality_fields_are_not_silently_promoted() -> None:
    data = base_config_data()
    entry = data["models"]["registry"][0]
    entry.pop("measured_quality")
    entry.update(
        {
            "measured_quality_score": 0.95,
            "measured_quality_tier": "highest",
            "quality_measurement": "sha256:" + ("a" * 64),
        }
    )

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        AuditConfig.model_validate(data)


def test_identity_only_audit_role_fails_preflight_and_registry_validation() -> None:
    data = base_config_data()
    selected = data["models"]["threat_model"]["primary"]
    entry = next(
        item for item in data["models"]["registry"] if item["canonical_model_id"] == selected
    )
    entry.pop("measured_quality")
    config = AuditConfig.model_validate(data)

    independence_errors = validate_model_independence(config)
    registry_errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=False,
    )

    assert any(
        "configured audit models lack benchmark-derived quality measurements" in error
        and selected in error
        for error in independence_errors
    )
    assert any(
        "model lacks benchmark-derived quality measurement" in error and selected in error
        for error in registry_errors
    )


def test_measured_zero_is_distinct_from_unmeasured() -> None:
    data = base_config_data()
    quality = data["models"]["registry"][0]["measured_quality"]
    quality["score"] = 0.0
    quality["tier"] = "standard"
    config = AuditConfig.model_validate(data)

    observed = config.models.registry[0].measured_quality

    assert observed is not None
    assert observed.score == 0.0
    assert not any(
        "lacks benchmark-derived quality measurement" in error
        for error in ModelRegistry.validate(
            config,
            _metadata(config),
            require_verified_qualification=False,
        )
    )


def test_aliases_share_one_independence_slot(config_factory) -> None:
    base = config_factory()
    threat_id = base.models.threat_model.primary
    source_id = base.models.source_audit.primary
    shared = model_registry_entry(
        "synthetic/shared-root",
        aliases=[threat_id, source_id],
    )
    remaining = [
        entry.model_dump(mode="json")
        for entry in base.models.registry
        if entry.canonical_model_id not in {threat_id, source_id}
    ]
    config = config_factory(
        models={
            "minimum_distinct_families": 4,
            "registry": [shared, *remaining],
        }
    )

    errors = validate_model_independence(config)

    assert any("only 3 independent analysis model families" in error for error in errors)


def test_registry_rejects_duplicate_alias_across_lineages() -> None:
    data = base_config_data()
    duplicate = model_registry_entry(
        "synthetic/duplicate-root",
        aliases=[MODEL_IDS["threat_model"]],
    )
    data["models"]["registry"].append(duplicate)

    with pytest.raises(ValidationError, match="globally unique"):
        AuditConfig.model_validate(data)


def test_registry_allows_distinct_exact_models_to_share_one_root_lineage() -> None:
    data = base_config_data()
    shared_root = data["models"]["registry"][0]["root_lineage"]
    data["models"]["registry"][1]["root_lineage"] = shared_root

    config = AuditConfig.model_validate(data)

    assert config.models.registry[0].root_lineage == config.models.registry[1].root_lineage
    assert (
        config.models.registry[0].canonical_model_id != config.models.registry[1].canonical_model_id
    )


def test_source_egress_requires_explicit_root_approval(config_factory) -> None:
    config = config_factory(privacy={"approved_model_lineages": []})

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=False,
        zdr_model_ids=set(configured_model_ids(config, include_fallbacks=True)),
        source_egress_requested=True,
    )

    assert any("root lineage is not approved" in error for error in errors)


def test_source_egress_rejects_retention_above_policy(config_factory) -> None:
    config = config_factory()
    registry = list(config.models.registry)
    registry[0] = registry[0].model_copy(update={"retention_policy": "temporary"})
    config = config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": tuple(registry)}),
        }
    )

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=False,
        zdr_model_ids=set(configured_model_ids(config, include_fallbacks=True)),
        source_egress_requested=True,
    )

    assert any(
        "retention policy temporary exceeds configured maximum zero" in error for error in errors
    )


def test_measured_quality_tier_must_satisfy_role_requirement(config_factory) -> None:
    config = config_factory()
    source = config.models.source_audit.model_copy(update={"quality_tier": "highest"})
    registry = []
    for entry in config.models.registry:
        if entry.canonical_model_id == source.primary:
            assert entry.measured_quality is not None
            entry = entry.model_copy(
                update={
                    "measured_quality": entry.measured_quality.model_copy(
                        update={"score": 0.8, "tier": "high"}
                    )
                }
            )
        registry.append(entry)
    config = config.model_copy(
        update={
            "models": config.models.model_copy(
                update={
                    "source_audit": source,
                    "registry": tuple(registry),
                }
            )
        }
    )

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=False,
    )

    assert any("measured quality tier is below source_audit.primary" in error for error in errors)


def test_measured_quality_tier_rejects_unqualified_score() -> None:
    data = base_config_data()
    data["models"]["registry"][0]["measured_quality"]["score"] = 0.5
    data["models"]["registry"][0]["measured_quality"]["tier"] = "high"

    with pytest.raises(ValidationError, match=r"requires score >= 0\.75"):
        AuditConfig.model_validate(data)


@pytest.mark.parametrize("coercive_score", [True, "0.95"])
def test_measured_quality_score_rejects_coercive_values(coercive_score: object) -> None:
    data = base_config_data()
    data["models"]["registry"][0]["measured_quality"]["score"] = coercive_score

    with pytest.raises(ValidationError, match="valid number"):
        AuditConfig.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("root_lineage", "SHA256:" + ("a" * 64)),
        ("canonical_model_id", " author/model "),
        ("aliases", [" author/alias "]),
    ],
)
def test_lineage_identity_rejects_values_outside_published_schema(
    field: str,
    value: object,
) -> None:
    data = base_config_data()
    data["models"]["registry"][0][field] = value

    with pytest.raises(ValidationError):
        AuditConfig.model_validate(data)


def test_model_metadata_cache_is_source_and_hash_bound(
    config_factory,
    tmp_path: Path,
) -> None:
    path = tmp_path / "openrouter-models.json"
    registry = ModelRegistry(path)
    models = _metadata(config_factory())

    registry.save_cache(models)

    assert registry.load_cache() == models
    assert path.stat().st_mode & 0o077 == 0
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["source_base_url"] == "https://openrouter.ai/api/v1"
    assert len(payload["models_sha256"]) == 64


@pytest.mark.parametrize("mutation", ["future", "hash", "source", "extra"])
def test_model_metadata_cache_rejects_untrusted_envelopes(
    config_factory,
    tmp_path: Path,
    mutation: str,
) -> None:
    path = tmp_path / "openrouter-models.json"
    registry = ModelRegistry(path)
    registry.save_cache(_metadata(config_factory()))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if mutation == "future":
        payload["cached_at"] = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    elif mutation == "hash":
        payload["models_sha256"] = "0" * 64
    elif mutation == "source":
        payload["source_base_url"] = "https://untrusted.invalid/api/v1"
    else:
        payload["untrusted"] = True
    path.write_text(json.dumps(payload), encoding="utf-8")

    assert registry.load_cache() is None


def test_model_metadata_cache_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "openrouter-models.json"
    path.write_text(
        '{"schema_version":"1.0","schema_version":"1.0"}',
        encoding="utf-8",
    )

    assert ModelRegistry(path).load_cache() is None


def test_maximum_assurance_rejects_shape_only_quality_hashes(config_factory) -> None:
    config = config_factory().model_copy(update={"profile": AuditProfile.MAXIMUM_ASSURANCE})

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=True,
    )

    assert (
        "verified production qualification is required; "
        "configured quality hashes are not authorization"
    ) in errors


def test_standard_production_rejects_shape_only_quality_hashes(config_factory) -> None:
    config = config_factory()

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=True,
    )

    assert (
        "verified production qualification is required; "
        "configured quality hashes are not authorization"
    ) in errors


def test_nonproduction_fixture_can_explicitly_disable_qualification_gate(config_factory) -> None:
    config = config_factory().model_copy(update={"profile": AuditProfile.MAXIMUM_ASSURANCE})

    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        require_verified_qualification=False,
    )

    assert not any("verified production qualification" in error for error in errors)


def test_catalog_registry_does_not_globally_filter_non_native_output_models(
    config_factory,
) -> None:
    config = config_factory()
    metadata = [
        {
            "id": model_id,
            "supported_parameters": ["max_tokens", "temperature"],
        }
        for model_id in configured_model_ids(config, include_fallbacks=True)
    ]

    errors = ModelRegistry.validate(
        config,
        metadata,
        require_verified_qualification=False,
    )

    assert not any("structured JSON output" in error for error in errors)


def test_verified_production_selection_resolves_every_exact_model_and_role() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()

    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    errors = ModelRegistry.validate(
        config,
        _metadata(config),
        production_qualification=qualification,
        require_verified_qualification=True,
        qualification_now=observed_at,
    )

    assert evidence.valid
    assert not errors
    assert qualification.bindings.effective_config_sha256 != config.stable_hash()
    assert qualification.production_effective_config_sha256 == config.stable_hash()
    assert evidence.production_effective_config_sha256 == config.stable_hash()
    assert evidence.configured_model_ids == evidence.qualified_model_ids
    assert len(evidence.model_bindings) == 8
    assert all(binding.approved_provider_name for binding in evidence.model_bindings)
    assert {binding.qualification_result_sha256 for binding in evidence.model_bindings} == {
        model.qualification_result_sha256 for model in qualification.models
    }
    assert {binding.endpoint_snapshot_sha256 for binding in evidence.model_bindings} == {
        model.endpoint_snapshot_sha256 for model in qualification.models
    }
    assert {binding.output_capability_sha256 for binding in evidence.model_bindings} == {
        model.output_capability_sha256 for model in qualification.models
    }
    assert {binding.structured_output_mode for binding in evidence.model_bindings} == {
        model.structured_output_mode for model in qualification.models
    }
    assert {binding.model_metadata_snapshot_sha256 for binding in evidence.model_bindings} == {
        model.model_metadata_snapshot_sha256 for model in qualification.models
    }
    assert {binding.pricing_snapshot_sha256 for binding in evidence.model_bindings} == {
        model.pricing_snapshot_sha256 for model in qualification.models
    }
    assert {binding.benchmark_report_sha256 for binding in evidence.model_bindings} == {
        model.benchmark_report_sha256 for model in qualification.models
    }
    assert {binding.benchmark_verification_sha256 for binding in evidence.model_bindings} == {
        model.benchmark_verification_sha256 for model in qualification.models
    }
    assert {binding.fresh_benchmark_evidence_sha256 for binding in evidence.model_bindings} == {
        model.fresh_benchmark_evidence_sha256 for model in qualification.models
    }
    assert {binding.benchmark_case_count for binding in evidence.model_bindings} == {
        model.benchmark_case_count for model in qualification.models
    }
    assert {binding.evaluated_at for binding in evidence.model_bindings} == {
        model.evaluated_at for model in qualification.models
    }
    assert {binding.expires_at for binding in evidence.model_bindings} == {
        model.expires_at for model in qualification.models
    }
    assert ProductionQualificationValidation.from_dict(evidence.as_dict()) == evidence


def test_production_qualification_rejects_unapproved_root_lineage() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    revoked_model = qualification.models[0]
    config = config.model_copy(
        update={
            "privacy": config.privacy.model_copy(
                update={
                    "approved_model_lineages": tuple(
                        lineage
                        for lineage in config.privacy.approved_model_lineages
                        if lineage != revoked_model.root_lineage
                    )
                }
            )
        }
    )

    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert (
        f"verified production root lineage is not approved: {revoked_model.exact_model_id}"
        in evidence.errors
    )


def test_production_selection_rejects_identity_only_registry_entry() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    registry = list(config.models.registry)
    unmeasured_model_id = registry[0].canonical_model_id
    registry[0] = registry[0].model_copy(update={"measured_quality": None})
    changed = config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": tuple(registry)}),
        }
    )

    evidence = ModelRegistry.validate_production_qualification(
        changed,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert (
        f"verified production model lacks configured quality measurement: {unmeasured_model_id}"
        in evidence.errors
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "measurement",
            "sha256:" + ("f" * 64),
            "quality measurement differs",
        ),
        ("score", 0.95, "quality score differs"),
        ("tier", "high", "quality tier differs"),
    ],
)
def test_production_selection_rejects_stale_configured_quality_designations(
    field: str,
    value: object,
    message: str,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    registry = list(config.models.registry)
    assert registry[0].measured_quality is not None
    registry[0] = registry[0].model_copy(
        update={"measured_quality": registry[0].measured_quality.model_copy(update={field: value})}
    )
    changed = config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": tuple(registry)}),
        }
    )

    evidence = ModelRegistry.validate_production_qualification(
        changed,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert any(message in error for error in evidence.errors)


def test_production_selection_rejects_effective_config_binding_mismatch() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    changed = config.model_copy(update={"profile": AuditProfile.MAXIMUM_ASSURANCE})

    evidence = ModelRegistry.validate_production_qualification(
        changed,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert "verified production qualification binds a different effective configuration" in (
        evidence.errors
    )


def test_maximum_assurance_rejects_alternate_self_hashed_quality_inputs() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    maximum = config.model_copy(update={"profile": AuditProfile.MAXIMUM_ASSURANCE})

    evidence = ModelRegistry.validate_production_qualification(
        maximum,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert any("qualification policy differs" in error for error in evidence.errors)
    assert any("benchmark corpus differs" in error for error in evidence.errors)
    assert any("benchmark ground truth differs" in error for error in evidence.errors)


def test_production_selection_rejects_selected_alias_inheritance() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    registry = list(config.models.registry)
    selected_model = registry[0].canonical_model_id
    registry[0] = registry[0].model_copy(
        update={
            "canonical_model_id": "synthetic/unselected-canonical",
            "aliases": (selected_model,),
        }
    )
    changed = config.model_copy(
        update={
            "models": config.models.model_copy(update={"registry": tuple(registry)}),
        }
    )

    evidence = ModelRegistry.validate_production_qualification(
        changed,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert any("must be the canonical lineage record" in error for error in evidence.errors)


def test_production_selection_does_not_inherit_qualification_to_an_alias() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    source = config.models.source_audit.model_copy(update={"primary": "author0/unqualified-alias"})
    registry = list(config.models.registry)
    registry[0] = registry[0].model_copy(
        update={"aliases": (*registry[0].aliases, "author0/unqualified-alias")}
    )
    config = config.model_copy(
        update={
            "models": config.models.model_copy(
                update={
                    "source_audit": source,
                    "registry": tuple(registry),
                }
            )
        }
    )

    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )

    assert not evidence.valid
    assert "exact model lacks verified Tier A qualification: author0/unqualified-alias" in (
        evidence.errors
    )
    assert any("all_eligible_tier_a" in error for error in evidence.errors)


def test_production_qualification_rejects_stale_or_unconfigured_routes() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    config = config.model_copy(
        update={
            "models": config.models.model_copy(
                update={
                    "provider_policy": config.models.provider_policy.model_copy(
                        update={"only": ("unrelated-provider",)}
                    )
                }
            )
        }
    )

    route_evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    stale_evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=qualification.expires_at,
    )

    assert not route_evidence.valid
    assert any("endpoint is not configured" in error for error in route_evidence.errors)
    assert not stale_evidence.valid
    assert "verified production qualification is expired" in stale_evidence.errors


def test_serialized_production_qualification_validation_rejects_tampering() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    payload = evidence.as_dict()
    payload["qualification_artifact_sha256"] = "0" * 64

    with pytest.raises(
        ValidationError,
        match=(
            r"self-hash is inconsistent|"
            "production reasoning qualification differs from its model binding"
        ),
    ):
        ProductionQualificationValidation.from_dict(payload)


def test_serialized_production_qualification_rejects_truncated_reasoning_routes() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    payload = evidence.as_dict()
    payload["model_bindings"][0]["reasoning_bindings"].pop()
    _reseal_production_validation_payload(payload)

    with pytest.raises(
        ValidationError,
        match="reasoning qualification routes differ from approved role inventory",
    ):
        ProductionQualificationValidation.from_dict(payload)


def test_serialized_production_qualification_rejects_extra_reasoning_route() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    model = evidence.model_bindings[0]
    source_route = next(
        route for route in model.reasoning_bindings if route.qualified_role == "source_audit"
    )
    extra_route = seal_qualified_reasoning_role_binding(
        exact_model_id=source_route.exact_model_id,
        approved_provider_endpoint=source_route.approved_provider_endpoint,
        approved_provider_name=source_route.approved_provider_name,
        qualified_role="model_benchmark",
        configured_policy_role="source_audit",
        control_profile=source_route.control_profile,
        reasoning_policy_artifact_sha256=(source_route.reasoning_policy_artifact_sha256),
        reasoning_policy_role_binding_sha256=(source_route.reasoning_policy_role_binding_sha256),
        endpoint_reasoning_capability_sha256=(source_route.endpoint_reasoning_capability_sha256),
        qualification_report_sha256=source_route.qualification_report_sha256,
        qualification_result_sha256=source_route.qualification_result_sha256,
        qualification_verification_sha256=(source_route.qualification_verification_sha256),
    )
    payload = evidence.as_dict()
    routes = payload["model_bindings"][0]["reasoning_bindings"]
    routes.append(extra_route.model_dump(mode="json"))
    routes.sort(
        key=lambda route: (
            route["qualified_role"],
            route["configured_policy_role"],
        )
    )
    _reseal_production_validation_payload(payload)

    with pytest.raises(
        ValidationError,
        match="reasoning qualification routes differ from approved role inventory",
    ):
        ProductionQualificationValidation.from_dict(payload)


def test_serialized_production_qualification_rejects_reasoning_parent_mismatch() -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    source_route = evidence.model_bindings[0].reasoning_bindings[0]
    mismatched_route = seal_qualified_reasoning_role_binding(
        exact_model_id=source_route.exact_model_id,
        approved_provider_endpoint=source_route.approved_provider_endpoint,
        approved_provider_name=source_route.approved_provider_name,
        qualified_role=source_route.qualified_role,
        configured_policy_role=source_route.configured_policy_role,
        control_profile=source_route.control_profile,
        reasoning_policy_artifact_sha256=(source_route.reasoning_policy_artifact_sha256),
        reasoning_policy_role_binding_sha256=(source_route.reasoning_policy_role_binding_sha256),
        endpoint_reasoning_capability_sha256=(source_route.endpoint_reasoning_capability_sha256),
        qualification_report_sha256=source_route.qualification_report_sha256,
        qualification_result_sha256=source_route.qualification_result_sha256,
        qualification_verification_sha256="0" * 64,
    )
    payload = evidence.as_dict()
    payload["model_bindings"][0]["reasoning_bindings"][0] = mismatched_route.model_dump(mode="json")
    _reseal_production_validation_payload(payload)

    with pytest.raises(
        ValidationError,
        match="reasoning qualification verification differs from parent",
    ):
        ProductionQualificationValidation.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("qualification_result_sha256", "a" * 64),
        ("benchmark_report_sha256", "b" * 64),
        ("benchmark_verification_sha256", "c" * 64),
        ("fresh_benchmark_evidence_sha256", "d" * 64),
        ("endpoint_snapshot_sha256", "e" * 64),
        ("output_capability_sha256", "1" * 64),
        ("structured_output_mode", "VALIDATED_TEXT_JSON"),
        ("model_metadata_snapshot_sha256", "f" * 64),
        ("pricing_snapshot_sha256", "0" * 64),
        ("benchmark_case_count", 2),
    ],
)
def test_serialized_production_model_evidence_rejects_tampering(
    field: str,
    value: object,
) -> None:
    config, qualification, observed_at = _verified_production_config_and_capability()
    evidence = ModelRegistry.validate_production_qualification(
        config,
        qualification,
        now=observed_at,
    )
    payload = evidence.as_dict()
    payload["model_bindings"][0][field] = value

    with pytest.raises(
        ValidationError,
        match=(
            r"self-hash is inconsistent|"
            "production reasoning qualification differs from its model binding"
        ),
    ):
        ProductionQualificationValidation.from_dict(payload)
