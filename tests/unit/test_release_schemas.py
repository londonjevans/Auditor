from __future__ import annotations

import json
from pathlib import Path

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
