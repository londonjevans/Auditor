"""OpenRouter model metadata cache and capability validation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from mmaudit.config import AuditConfig, ModelQualityTier, model_lineage_index
from mmaudit.constants import ALL_MODEL_ROLES

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
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
            cached_at = datetime.fromisoformat(str(raw["cached_at"]))
            if datetime.now(UTC) - cached_at > self.ttl:
                return None
            models = raw["models"]
            if not isinstance(models, list):
                return None
            return [item for item in models if isinstance(item, dict)]
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def save_cache(self, models: list[dict[str, Any]]) -> None:
        if self._has_symlink_component():
            raise ModelRegistryError("refusing symlinked model metadata cache")
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "cached_at": datetime.now(UTC).isoformat(),
            "models": models,
        }
        if self.cache_path.exists():
            if not self.cache_path.is_file():
                raise ModelRegistryError("refusing non-file model metadata cache")
            self.cache_path.unlink()
        self.cache_path.write_text(
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

    def _has_symlink_component(self) -> bool:
        return any(
            path.is_symlink() or path.is_junction()
            for path in (
                self.cache_path,
                self.cache_path.parent,
                self.cache_path.parent.parent,
            )
        )

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
