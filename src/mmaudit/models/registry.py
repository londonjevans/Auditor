"""OpenRouter model metadata cache and capability validation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mmaudit.config import AuditConfig, ModelQualityTier, model_lineage_index
from mmaudit.constants import ALL_MODEL_ROLES, OPENROUTER_DEFAULT_BASE_URL

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
    ) -> list[str]:
        """Validate provider capabilities and operator-bound source-egress policy."""

        metadata_ids = [str(item.get("id", "")) for item in models]
        by_id = {model_id: item for model_id, item in zip(metadata_ids, models, strict=True)}
        errors: list[str] = []
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
            parameters = {str(value).lower() for value in metadata.get("supported_parameters", [])}
            if not ({"response_format", "structured_outputs", "json_schema"} & parameters):
                errors.append(f"model lacks structured JSON output support: {model_id}")
            lineage = lineage_by_id.get(model_id.lower())
            if lineage is None:
                if source_egress_requested:
                    errors.append(
                        f"source egress blocked: {role} model has no immutable lineage "
                        f"record: {model_id}"
                    )
            else:
                if (
                    _QUALITY_TIER_RANK[lineage.measured_quality_tier]
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
