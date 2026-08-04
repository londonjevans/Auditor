from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mmaudit.config import ModelLineageConfig
from scripts.generate_release_schemas import MODELS, rendered_schema

ROOT = Path(__file__).resolve().parents[2]


def test_release_schemas_are_exact_strict_generated_models() -> None:
    for filename, model in MODELS.items():
        path = ROOT / "schemas" / filename
        observed_text = path.read_text(encoding="utf-8")
        assert observed_text == rendered_schema(filename, model)
        schema = json.loads(observed_text)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == f"https://mmaudit.local/schemas/{filename}"
        assert schema["additionalProperties"] is False


def test_versioned_report_artifacts_bind_language_capability_without_rewriting_legacy() -> None:
    contracts = {
        "findings_artifact.schema.json": (["1.1", "1.2"], ["1.1"]),
        "model_execution_artifact.schema.json": (["1.0", "1.1", "1.2"], ["1.0", "1.1"]),
    }
    for filename, (versions, legacy_versions) in contracts.items():
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"]["enum"] == versions
        assert schema["properties"]["schema_version"]["default"] == "1.2"
        assert schema["allOf"] == [
            {
                "if": {"properties": {"schema_version": {"const": "1.2"}}},
                "then": {
                    "properties": {"language_capability": {"not": {"type": "null"}}},
                    "required": ["language_capability"],
                },
            },
            {
                "if": {
                    "properties": {"schema_version": {"enum": legacy_versions}},
                    "required": ["schema_version"],
                },
                "then": {"not": {"required": ["language_capability"]}},
            },
        ]


def test_models_config_schema_separates_identity_from_optional_measured_quality() -> None:
    schema = json.loads((ROOT / "schemas" / "models_config.schema.json").read_text())
    lineage = schema["$defs"]["ModelLineageConfig"]
    quality = schema["$defs"]["ModelQualityMeasurementConfig"]

    assert "measured_quality" not in lineage["required"]
    assert lineage["properties"]["measured_quality"] == {
        "$ref": "#/$defs/ModelQualityMeasurementConfig"
    }
    assert set(quality["required"]) == {"measurement", "score", "tier"}
    assert quality["additionalProperties"] is False
    assert quality["properties"]["measurement"]["pattern"] == r"^sha256:[0-9a-f]{64}$"
    assert lineage["properties"]["root_lineage"]["pattern"] == r"^sha256:[0-9a-f]{64}$"
    assert lineage["properties"]["canonical_model_id"]["pattern"] == (r"^[^\s/]+/[^\s/]+$")
    assert lineage["properties"]["aliases"]["items"]["pattern"] == r"^[^\s/]+/[^\s/]+$"
    assert lineage["properties"]["aliases"]["uniqueItems"] is True
    assert quality["allOf"] == [
        {
            "if": {"properties": {"tier": {"const": "high"}}, "required": ["tier"]},
            "then": {"properties": {"score": {"minimum": 0.75, "type": "number"}}},
        },
        {
            "if": {"properties": {"tier": {"const": "highest"}}, "required": ["tier"]},
            "then": {"properties": {"score": {"minimum": 0.9, "type": "number"}}},
        },
    ]
    assert "case-insensitively distinct" in lineage["$comment"]
    assert "not expressible" in schema["properties"]["registry"]["$comment"]


def _commented_lineage_example(path: Path, *, measured: bool) -> ModelLineageConfig:
    selected: list[str] = []
    in_example = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "# [[models.registry]]":
            in_example = True
        if not in_example:
            continue
        if line == "# [models.registry.measured_quality]" and not measured:
            break
        if line.startswith(
            (
                "# [[models.registry]]",
                "# [models.registry.measured_quality]",
                "# root_lineage =",
                "# canonical_model_id =",
                "# aliases =",
                "# retention_policy =",
                "# score =",
                "# tier =",
                "# measurement =",
            )
        ):
            selected.append(line.removeprefix("# "))
        if line.startswith("# measurement ="):
            break
    payload = tomllib.loads("\n".join(selected))
    return ModelLineageConfig.model_validate(payload["models"]["registry"][0])


def test_both_templates_expose_valid_identity_only_and_measured_examples() -> None:
    paths = (
        ROOT / "mmaudit.example.toml",
        ROOT / "src" / "mmaudit" / "templates" / "mmaudit.example.toml",
    )
    for path in paths:
        identity = _commented_lineage_example(path, measured=False)
        measured = _commented_lineage_example(path, measured=True)

        assert identity.measured_quality is None
        assert "measured_quality" not in identity.model_dump(mode="json")
        assert measured.aliases == identity.aliases
        assert measured.measured_quality is not None
        assert measured.measured_quality.measurement == "sha256:" + ("0" * 64)


def test_operator_templates_select_the_solidity_evm_capability_explicitly() -> None:
    for path in (
        ROOT / "mmaudit.example.toml",
        ROOT / "src" / "mmaudit" / "templates" / "mmaudit.example.toml",
        ROOT / "config" / "openrouter-qualification.toml",
    ):
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
        assert payload["language_profile"] == "solidity-evm"
