"""OpenRouter model metadata cache and capability validation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.config import AuditConfig, ModelQualityTier, model_lineage_index
from mmaudit.constants import ALL_MODEL_ROLES, OPENROUTER_DEFAULT_BASE_URL
from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    QualificationBindings,
    QualifiedReasoningRoleBinding,
    VerifiedProductionQualification,
)
from mmaudit.models.reasoning import (
    ReasoningPolicyError,
    reasoning_policy_roles_for_qualified_role,
)
from mmaudit.models.schemas import AuditProfile, StrictModel

_QUALITY_TIER_RANK: dict[str, int] = {
    "standard": 0,
    "high": 1,
    "highest": 2,
}
_RETENTION_RANK: dict[str, int] = {
    "zero": 0,
    "temporary": 1,
    "persistent": 2,
}
_CACHE_SCHEMA_VERSION = "1.0"
_MAX_CACHE_BYTES = 20_000_000


class ModelRegistryError(RuntimeError):
    """Raised when configured models cannot meet audit requirements."""


def _expected_production_reasoning_routes(
    approved_roles: tuple[str, ...],
) -> tuple[tuple[str, str], ...]:
    """Derive the sole complete reasoning-route inventory for approved roles."""

    try:
        return tuple(
            sorted(
                (qualified_role, configured_policy_role)
                for qualified_role in approved_roles
                for configured_policy_role in reasoning_policy_roles_for_qualified_role(
                    qualified_role
                )
            )
        )
    except ReasoningPolicyError as exc:
        raise ValueError("production approved role has no exact reasoning policy route") from exc


class ProductionModelQualificationBinding(StrictModel):
    """One exact, non-secret model binding resolved from verified Tier A evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    exact_model_id: str
    canonical_model_slug: str
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    approved_provider_endpoint: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
    approved_provider_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._:/()&+-]{0,199}$")
    endpoint_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    output_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    structured_output_mode: StructuredOutputMode
    model_metadata_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pricing_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    approved_roles: tuple[str, ...] = Field(min_length=1, max_length=128)
    quality_measurement_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qualification_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    benchmark_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    benchmark_verification_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fresh_benchmark_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reasoning_bindings: tuple[QualifiedReasoningRoleBinding, ...] = Field(
        min_length=1,
        max_length=256,
    )
    benchmark_case_count: int = Field(ge=1)
    evaluated_at: datetime
    expires_at: datetime

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value)

    @field_validator("approved_roles")
    @classmethod
    def roles_are_safe_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            not role
            or len(role) > 128
            or not role[0].islower()
            or any(
                not (character.islower() or character.isdigit() or character in "_:.-")
                for character in role
            )
            for role in value
        ):
            raise ValueError("approved production roles must be safe, unique, and sorted")
        return value

    @field_validator("evaluated_at", "expires_at")
    @classmethod
    def qualification_time_is_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value)

    @model_validator(mode="after")
    def qualification_window_is_valid(self) -> Self:
        if self.expires_at <= self.evaluated_at:
            raise ValueError("production model qualification must expire after evaluation")
        observed_routes = tuple(
            (binding.qualified_role, binding.configured_policy_role)
            for binding in self.reasoning_bindings
        )
        expected_routes = _expected_production_reasoning_routes(self.approved_roles)
        if observed_routes != expected_routes:
            raise ValueError(
                "production reasoning qualification routes differ from approved role inventory"
            )
        if any(
            binding.exact_model_id != self.exact_model_id
            or binding.approved_provider_endpoint != self.approved_provider_endpoint
            or binding.approved_provider_name != self.approved_provider_name
            or binding.qualification_report_sha256 != self.benchmark_report_sha256
            or binding.qualification_result_sha256 != self.qualification_result_sha256
            for binding in self.reasoning_bindings
        ):
            raise ValueError("production reasoning qualification differs from its model binding")
        return self


class ProductionQualificationValidation(StrictModel):
    """Sanitized deterministic evidence for one production-qualification decision."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    observed_at: datetime
    required: bool
    valid: bool
    configured_model_ids: tuple[str, ...]
    qualified_model_ids: tuple[str, ...]
    model_bindings: tuple[ProductionModelQualificationBinding, ...]
    qualification_artifact_sha256: str | None
    qualification_verification_sha256: str | None
    candidate_registry_sha256: str | None
    qualification_policy_sha256: str | None
    qualification_bindings: QualificationBindings | None
    expected_bindings_sha256: str | None
    release_observation_sha256: str | None
    production_effective_config_sha256: str | None
    production_selection_sha256: str | None
    selection_verification_sha256: str | None
    qualification_capability_sha256: str | None
    errors: tuple[str, ...]
    validation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    def as_dict(self) -> dict[str, Any]:
        """Return a stable JSON-compatible representation without model content."""

        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        """Bound and validate an untrusted serialized runtime artifact."""

        try:
            encoded = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("production qualification validation is not JSON-compatible") from exc
        if len(encoded) > 2_000_000:
            raise ValueError("production qualification validation exceeds the byte limit")
        return cls.model_validate(payload)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value)

    @field_validator("configured_model_ids", "qualified_model_ids")
    @classmethod
    def model_ids_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or len(value) > 128:
            raise ValueError("production model IDs must be unique, sorted, and bounded")
        for model_id in value:
            require_exact_openrouter_model_id(model_id)
        return value

    @field_validator(
        "qualification_artifact_sha256",
        "qualification_verification_sha256",
        "candidate_registry_sha256",
        "qualification_policy_sha256",
        "expected_bindings_sha256",
        "release_observation_sha256",
        "production_effective_config_sha256",
        "production_selection_sha256",
        "selection_verification_sha256",
        "qualification_capability_sha256",
    )
    @classmethod
    def optional_hash_is_canonical(cls, value: str | None) -> str | None:
        if value is not None and (
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("qualification validation hashes must be lowercase SHA-256")
        return value

    @field_validator("errors")
    @classmethod
    def errors_are_sorted_unique_and_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if (
            value != tuple(sorted(set(value)))
            or len(value) > 512
            or any(not error or len(error) > 1_000 for error in value)
        ):
            raise ValueError("qualification validation errors must be bounded and sorted")
        return value

    @model_validator(mode="after")
    def bindings_state_and_hash_are_consistent(self) -> Self:
        binding_ids = tuple(binding.exact_model_id for binding in self.model_bindings)
        if binding_ids != self.qualified_model_ids:
            raise ValueError("qualification model bindings differ from qualified model IDs")
        for binding in self.model_bindings:
            observed_routes = tuple(
                (route.qualified_role, route.configured_policy_role)
                for route in binding.reasoning_bindings
            )
            expected_routes = _expected_production_reasoning_routes(binding.approved_roles)
            if observed_routes != expected_routes:
                raise ValueError(
                    "serialized production reasoning routes differ from approved role inventory"
                )
        if any(
            binding.evaluated_at > self.observed_at or binding.expires_at <= self.observed_at
            for binding in self.model_bindings
        ):
            raise ValueError(
                "qualification model bindings must be evaluated and current at observation time"
            )
        expected_valid = not self.errors
        if self.valid is not expected_valid:
            raise ValueError("qualification validation state differs from its errors")
        binding_hashes = (
            self.qualification_artifact_sha256,
            self.qualification_verification_sha256,
            self.candidate_registry_sha256,
            self.qualification_policy_sha256,
            self.expected_bindings_sha256,
            self.release_observation_sha256,
            self.production_effective_config_sha256,
            self.production_selection_sha256,
            self.selection_verification_sha256,
            self.qualification_capability_sha256,
        )
        if self.qualified_model_ids and any(value is None for value in binding_hashes):
            raise ValueError("qualified models require every qualification binding")
        if not self.qualified_model_ids and any(value is not None for value in binding_hashes):
            raise ValueError("empty qualification evidence cannot claim binding hashes")
        if self.qualification_verification_sha256 is not None and any(
            route.qualification_verification_sha256 != self.qualification_verification_sha256
            for binding in self.model_bindings
            for route in binding.reasoning_bindings
        ):
            raise ValueError("production reasoning qualification verification differs from parent")
        if self.qualified_model_ids and self.qualification_bindings is None:
            raise ValueError("qualified models require normalized qualification bindings")
        if not self.qualified_model_ids and self.qualification_bindings is not None:
            raise ValueError("empty qualification evidence cannot claim normalized bindings")
        if self.qualification_bindings is not None and (
            self.expected_bindings_sha256
            != _canonical_sha256(self.qualification_bindings.model_dump(mode="json"))
        ):
            raise ValueError("normalized qualification bindings differ from their hash")
        if self.required and self.valid and not self.qualified_model_ids:
            raise ValueError("required qualification validation cannot pass without models")
        expected_hash = _canonical_sha256(
            self.model_dump(mode="json", exclude={"validation_sha256"})
        )
        if self.validation_sha256 != expected_hash:
            raise ValueError("production qualification validation self-hash is inconsistent")
        return self


class ModelRegistry:
    def __init__(self, cache_path: Path, *, ttl: timedelta = timedelta(hours=6)) -> None:
        self.cache_path = cache_path
        self.ttl = ttl

    def load_cache(self) -> list[dict[str, Any]] | None:
        if self._has_symlink_component():
            return None
        try:
            metadata = self.cache_path.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > _MAX_CACHE_BYTES
            ):
                return None
            raw = json.loads(
                self.cache_path.read_text(encoding="utf-8"),
                object_pairs_hook=_unique_json_object,
            )
            if not isinstance(raw, dict) or set(raw) != {
                "schema_version",
                "source_base_url",
                "cached_at",
                "models_sha256",
                "models",
            }:
                return None
            if (
                raw["schema_version"] != _CACHE_SCHEMA_VERSION
                or raw["source_base_url"] != OPENROUTER_DEFAULT_BASE_URL
            ):
                return None
            cached_at = datetime.fromisoformat(str(raw["cached_at"]))
            now = datetime.now(UTC)
            if (
                cached_at.tzinfo is None
                or cached_at > now + timedelta(minutes=5)
                or now - cached_at > self.ttl
            ):
                return None
            models = raw["models"]
            if (
                not isinstance(models, list)
                or not models
                or any(not isinstance(item, dict) for item in models)
                or raw["models_sha256"] != _canonical_sha256(models)
            ):
                return None
            return list(models)
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def save_cache(self, models: list[dict[str, Any]]) -> None:
        if self._has_symlink_component():
            raise ModelRegistryError("refusing symlinked model metadata cache")
        if not models or any(not isinstance(item, dict) for item in models):
            raise ModelRegistryError("refusing invalid model metadata cache")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": _CACHE_SCHEMA_VERSION,
            "source_base_url": OPENROUTER_DEFAULT_BASE_URL,
            "cached_at": datetime.now(UTC).isoformat(),
            "models_sha256": _canonical_sha256(models),
            "models": models,
        }
        if self.cache_path.exists():
            metadata = self.cache_path.stat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ModelRegistryError("refusing non-file model metadata cache")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_CACHE_BYTES:
            raise ModelRegistryError("refusing oversized model metadata cache")
        descriptor, temporary_name = tempfile.mkstemp(
            dir=self.cache_path.parent,
            prefix=f".{self.cache_path.name}.",
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                os.fchmod(stream.fileno(), stat.S_IRUSR | stat.S_IWUSR)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self.cache_path)
        finally:
            temporary.unlink(missing_ok=True)

    def _has_symlink_component(self) -> bool:
        cursor = self.cache_path.absolute()
        while True:
            if cursor.is_symlink() or cursor.is_junction():
                return True
            if cursor == cursor.parent:
                return False
            cursor = cursor.parent

    @staticmethod
    def validate(
        config: AuditConfig,
        models: list[dict[str, Any]],
        *,
        zdr_model_ids: set[str] | None = None,
        source_egress_requested: bool = False,
        production_qualification: VerifiedProductionQualification | None = None,
        require_verified_qualification: bool | None = None,
        qualification_now: datetime | None = None,
    ) -> list[str]:
        """Validate provider capabilities, source egress, and production qualification."""

        metadata_ids = [str(item.get("id", "")) for item in models]
        by_id = {model_id: item for model_id, item in zip(metadata_ids, models, strict=True)}
        errors: list[str] = []
        qualification_required = (
            config.profile is AuditProfile.MAXIMUM_ASSURANCE
            if require_verified_qualification is None
            else require_verified_qualification
        )
        if qualification_required or production_qualification is not None:
            qualification_validation = ModelRegistry.validate_production_qualification(
                config,
                production_qualification,
                required=qualification_required,
                now=qualification_now,
            )
            errors.extend(qualification_validation.errors)
        duplicate_metadata_ids = sorted(
            model_id
            for model_id in set(metadata_ids)
            if model_id and metadata_ids.count(model_id) > 1
        )
        if duplicate_metadata_ids:
            errors.append("duplicate model metadata IDs: " + ", ".join(duplicate_metadata_ids))

        lineage_by_id = model_lineage_index(config)
        approved_lineages = set(config.privacy.approved_model_lineages)
        maximum_retention = _RETENTION_RANK[config.privacy.maximum_model_retention]
        for role, model_id, required_tier in _configured_model_requirements(config):
            metadata = by_id.get(model_id)
            if metadata is None:
                errors.append(f"model does not exist: {model_id}")
                continue
            lineage = lineage_by_id.get(model_id.lower())
            if lineage is None:
                if source_egress_requested:
                    errors.append(
                        f"source egress blocked: {role} model has no immutable lineage "
                        f"record: {model_id}"
                    )
            else:
                if (
                    not qualification_required
                    and _QUALITY_TIER_RANK[lineage.measured_quality_tier]
                    < _QUALITY_TIER_RANK[required_tier]
                ):
                    errors.append(
                        f"model measured quality tier is below {role} requirement: "
                        f"{model_id} is {lineage.measured_quality_tier}, requires {required_tier}"
                    )
                if source_egress_requested:
                    if lineage.root_lineage not in approved_lineages:
                        errors.append(
                            f"source egress blocked: root lineage is not approved: "
                            f"{lineage.root_lineage}"
                        )
                    if _RETENTION_RANK[lineage.retention_policy] > maximum_retention:
                        errors.append(
                            f"source egress blocked: {model_id} retention policy "
                            f"{lineage.retention_policy} exceeds configured maximum "
                            f"{config.privacy.maximum_model_retention}"
                        )
            if (
                config.privacy.require_zdr
                and zdr_model_ids is not None
                and model_id not in zdr_model_ids
            ):
                errors.append(f"model has no currently advertised ZDR endpoint: {model_id}")
        return list(dict.fromkeys(errors))

    @staticmethod
    def validate_production_qualification(
        config: AuditConfig,
        qualification: VerifiedProductionQualification | None,
        *,
        required: bool = True,
        now: datetime | None = None,
    ) -> ProductionQualificationValidation:
        """Resolve exact configured production models against opaque Tier A evidence."""

        observed_at = _whole_second_utc(now)
        configured_requirements = _configured_primary_model_requirements(config)
        configured_ids = tuple(sorted({model_id for _, model_id in configured_requirements}))
        errors: list[str] = []
        qualified_ids: tuple[str, ...] = ()
        model_bindings: tuple[ProductionModelQualificationBinding, ...] = ()
        artifact_sha256: str | None = None
        qualification_verification_sha256: str | None = None
        candidate_registry_sha256: str | None = None
        qualification_policy_sha256: str | None = None
        qualification_bindings: QualificationBindings | None = None
        expected_bindings_sha256: str | None = None
        release_observation_sha256: str | None = None
        production_effective_config_sha256: str | None = None
        production_selection_sha256: str | None = None
        selection_verification_sha256: str | None = None
        capability_sha256: str | None = None

        if qualification is None:
            if required:
                errors.append(
                    "verified production qualification is required; "
                    "configured quality hashes are not authorization"
                )
        else:
            if type(qualification) is not VerifiedProductionQualification:
                errors.append("production qualification capability has an invalid type")
            else:
                try:
                    qualification = qualification.require_current(now=observed_at)
                except ValueError as exc:
                    errors.append(str(exc))
                else:
                    qualified_ids = tuple(model.exact_model_id for model in qualification.models)
                    model_bindings = tuple(
                        ProductionModelQualificationBinding(
                            exact_model_id=model.exact_model_id,
                            canonical_model_slug=model.canonical_model_slug,
                            root_lineage=model.root_lineage,
                            approved_provider_endpoint=model.approved_provider_endpoint,
                            approved_provider_name=model.approved_provider_name,
                            endpoint_snapshot_sha256=model.endpoint_snapshot_sha256,
                            output_capability_sha256=model.output_capability_sha256,
                            structured_output_mode=model.structured_output_mode,
                            model_metadata_snapshot_sha256=(model.model_metadata_snapshot_sha256),
                            pricing_snapshot_sha256=model.pricing_snapshot_sha256,
                            approved_roles=model.approved_roles,
                            quality_measurement_sha256=model.quality_measurement_sha256,
                            qualification_result_sha256=model.qualification_result_sha256,
                            benchmark_report_sha256=model.benchmark_report_sha256,
                            benchmark_verification_sha256=(model.benchmark_verification_sha256),
                            fresh_benchmark_evidence_sha256=(model.fresh_benchmark_evidence_sha256),
                            reasoning_bindings=model.reasoning_bindings,
                            benchmark_case_count=model.benchmark_case_count,
                            evaluated_at=model.evaluated_at,
                            expires_at=model.expires_at,
                        )
                        for model in qualification.models
                    )
                    artifact_sha256 = qualification.artifact_sha256
                    qualification_verification_sha256 = (
                        qualification.qualification_verification_sha256
                    )
                    candidate_registry_sha256 = qualification.candidate_registry_sha256
                    qualification_policy_sha256 = qualification.policy_sha256
                    qualification_bindings = qualification.bindings
                    expected_bindings_sha256 = qualification.expected_bindings_sha256
                    release_observation_sha256 = qualification.release_observation_sha256
                    production_effective_config_sha256 = (
                        qualification.production_effective_config_sha256
                    )
                    production_selection_sha256 = qualification.production_selection_sha256
                    selection_verification_sha256 = qualification.selection_verification_sha256
                    capability_sha256 = qualification.capability_sha256
                    errors.extend(
                        _validate_configured_production_models(
                            config,
                            configured_requirements=configured_requirements,
                            configured_ids=configured_ids,
                            qualification=qualification,
                            observed_at=observed_at,
                        )
                    )

        errors = sorted(set(errors))
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
            "required": required,
            "valid": not errors,
            "configured_model_ids": list(configured_ids),
            "qualified_model_ids": list(qualified_ids),
            "model_bindings": [binding.model_dump(mode="json") for binding in model_bindings],
            "qualification_artifact_sha256": artifact_sha256,
            "qualification_verification_sha256": qualification_verification_sha256,
            "candidate_registry_sha256": candidate_registry_sha256,
            "qualification_policy_sha256": qualification_policy_sha256,
            "qualification_bindings": (
                qualification_bindings.model_dump(mode="json")
                if qualification_bindings is not None
                else None
            ),
            "expected_bindings_sha256": expected_bindings_sha256,
            "release_observation_sha256": release_observation_sha256,
            "production_effective_config_sha256": production_effective_config_sha256,
            "production_selection_sha256": production_selection_sha256,
            "selection_verification_sha256": selection_verification_sha256,
            "qualification_capability_sha256": capability_sha256,
            "errors": errors,
        }
        return ProductionQualificationValidation.model_validate(
            {
                **payload,
                "validation_sha256": _canonical_sha256(payload),
            }
        )


def extract_zdr_model_ids(payload: Any) -> set[str]:
    """Extract model IDs from documented and legacy ZDR endpoint response shapes."""

    if isinstance(payload, dict):
        candidates = payload.get("data", payload.get("endpoints", []))
    else:
        candidates = payload
    result: set[str] = set()
    if not isinstance(candidates, list):
        return result
    for item in candidates:
        if not isinstance(item, dict):
            continue
        for key in ("model_id", "model", "id"):
            value = item.get(key)
            if isinstance(value, str) and "/" in value:
                result.add(value)
                break
    return result


def _configured_model_requirements(
    config: AuditConfig,
) -> list[tuple[str, str, ModelQualityTier]]:
    requirements: list[tuple[str, str, ModelQualityTier]] = []
    for role in ALL_MODEL_ROLES:
        role_config = config.models.role(role)
        requirements.append((f"{role}.primary", role_config.primary, role_config.quality_tier))
        requirements.extend(
            (
                f"{role}.fallbacks[{index}]",
                model_id,
                role_config.quality_tier,
            )
            for index, model_id in enumerate(role_config.fallbacks)
        )
    for role in sorted(config.models.specialists):
        role_config = config.models.specialists[role]
        requirements.append(
            (
                f"specialists.{role}.primary",
                role_config.primary,
                role_config.quality_tier,
            )
        )
        requirements.extend(
            (
                f"specialists.{role}.fallbacks[{index}]",
                model_id,
                role_config.quality_tier,
            )
            for index, model_id in enumerate(role_config.fallbacks)
        )
    return requirements


def _configured_primary_model_requirements(config: AuditConfig) -> list[tuple[str, str]]:
    requirements = [(role, config.models.role(role).primary) for role in ALL_MODEL_ROLES]
    requirements.extend(
        (role, config.models.specialists[role].primary)
        for role in sorted(config.models.specialists)
    )
    return requirements


def _validate_configured_production_models(
    config: AuditConfig,
    *,
    configured_requirements: list[tuple[str, str]],
    configured_ids: tuple[str, ...],
    qualification: VerifiedProductionQualification,
    observed_at: datetime,
) -> list[str]:
    errors: list[str] = []
    qualified_ids = tuple(model.exact_model_id for model in qualification.models)
    if config.profile is AuditProfile.MAXIMUM_ASSURANCE or config.maximum_assurance.require:
        pins = config.maximum_assurance.qualification
        bindings = qualification.bindings
        if qualification.policy_sha256 != pins.policy_sha256:
            errors.append(
                "verified production qualification policy differs from "
                "the maximum-assurance release pin"
            )
        if (
            bindings.benchmark_corpus_version != pins.corpus_version
            or bindings.benchmark_corpus_sha256 != pins.corpus_sha256
        ):
            errors.append(
                "verified production benchmark corpus differs from "
                "the maximum-assurance release pin"
            )
        if (
            bindings.benchmark_ground_truth_version != pins.ground_truth_version
            or bindings.benchmark_ground_truth_sha256 != pins.ground_truth_sha256
        ):
            errors.append(
                "verified production benchmark ground truth differs from "
                "the maximum-assurance release pin"
            )
    if qualification.production_effective_config_sha256 != config.stable_hash():
        errors.append("verified production qualification binds a different effective configuration")
    if configured_ids != qualified_ids:
        errors.append(
            "configured exact production model set differs from all_eligible_tier_a selection"
        )

    fallback_roles = [
        role
        for role in (*ALL_MODEL_ROLES, *tuple(sorted(config.models.specialists)))
        if config.models.role(role).fallbacks
    ]
    if fallback_roles:
        errors.append(
            "verified production selection forbids configured model fallbacks: "
            + ", ".join(fallback_roles)
        )

    lineage_by_id = model_lineage_index(config)
    approved_lineages = set(config.privacy.approved_model_lineages)
    configured_endpoints = set(config.models.provider_policy.only) | set(
        config.models.provider_policy.order
    )
    for role, model_id in configured_requirements:
        try:
            model = qualification.model_for(model_id, now=observed_at)
        except ValueError:
            errors.append(f"exact model lacks verified Tier A qualification: {model_id}")
            continue
        lineage = lineage_by_id.get(model_id.lower())
        if lineage is None:
            errors.append(f"verified production model lacks an immutable lineage: {model_id}")
        elif lineage.root_lineage != model.root_lineage:
            errors.append(f"verified production root lineage differs: {model_id}")
        elif lineage.canonical_model_id != model.exact_model_id:
            errors.append(
                f"selected production model must be the canonical lineage record: {model_id}"
            )
        elif lineage.quality_measurement != model.quality_measurement:
            errors.append(
                f"configured quality measurement differs from verified qualification "
                f"result: {model_id}"
            )
        elif lineage.measured_quality_score != model.overall_score:
            errors.append(
                f"configured quality score differs from verified qualification result: {model_id}"
            )
        elif lineage.measured_quality_tier != "highest":
            errors.append(
                f"configured quality tier differs from verified Tier A qualification: {model_id}"
            )
        if model.root_lineage not in approved_lineages:
            errors.append(f"verified production root lineage is not approved: {model_id}")
        if role not in model.approved_roles:
            errors.append(f"verified Tier A qualification does not approve {role} role: {model_id}")
        if model.approved_provider_endpoint not in configured_endpoints:
            errors.append(
                f"verified production endpoint is not configured: "
                f"{model_id} requires {model.approved_provider_endpoint}"
            )
    return errors


def _whole_second_utc(value: datetime | None) -> datetime:
    observed_at = datetime.now(UTC).replace(microsecond=0) if value is None else value
    if (
        observed_at.tzinfo is None
        or observed_at.utcoffset() != timedelta(0)
        or observed_at.microsecond != 0
    ):
        raise ValueError("qualification validation time must be a whole-second UTC timestamp")
    return observed_at


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result
