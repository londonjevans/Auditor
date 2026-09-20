"""Conservative future-review serialization bounds, never candidate observations or requests."""

from __future__ import annotations

import json
from typing import Any

from mmaudit.models.development_corpus import DevelopmentCorpusFinding, DevelopmentCorpusResponse
from mmaudit.models.development_corpus_judgment import DevelopmentCorpusJudgmentClaim
from mmaudit.orchestration.manifest import canonical_sha256


def _json(value: Any) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _quoted_bytes(value: Any) -> int:
    # Claims are serialized into the user-message string, which is serialized again on the wire.
    return len(_json(_json(value)).encode("utf-8"))


def _maximum_value(schema: dict[str, Any], definitions: dict[str, Any], depth: int = 0) -> Any:
    """Bound the closed generated finding grammar; pattern/cross-field rules only narrow it."""

    if depth > 16:
        raise ValueError("review bound schema is recursive or too deep")
    if "$ref" in schema:
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            raise ValueError("review bound refuses external schema references")
        target = definitions.get(reference.removeprefix("#/$defs/"))
        if type(target) is not dict:
            raise ValueError("review bound schema reference is missing")
        return _maximum_value(target, definitions, depth + 1)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return max(schema["enum"], key=_quoted_bytes)
    if "anyOf" in schema:
        return max(
            (_maximum_value(s, definitions, depth + 1) for s in schema["anyOf"]),
            key=_quoted_bytes,
        )
    kind = schema.get("type")
    if kind == "object":
        if schema.get("additionalProperties") is not False:
            raise ValueError("review bound requires closed schema objects")
        return {
            key: _maximum_value(value, definitions, depth + 1)
            for key, value in schema["properties"].items()
        }
    if kind == "string":
        maximum = schema.get("maxLength")
        if type(maximum) is not int or not 0 <= maximum <= 10_000:
            raise ValueError("review bound requires bounded schema strings")
        # U+0000 costs six bytes in inner JSON, then seven in the outer JSON string.
        # Quotes/backslashes cost four; valid UTF-8 scalars cost at most four. Using NUL
        # even for a patterned field is a conservative size superset, not a valid finding.
        return "\x00" * maximum
    if kind == "integer":
        low, high = schema.get("minimum"), schema.get("maximum")
        if type(low) is not int or type(high) is not int or not -(10**12) <= low <= high <= 10**12:
            raise ValueError("review bound requires bounded schema integers")
        return max((low, high), key=_quoted_bytes)
    if kind == "null":
        return None
    if kind == "boolean":
        return False
    raise ValueError("review bound schema has an unsupported value domain")


def development_tree_review_claims_bound() -> tuple[str, str]:
    """Return a size-only JSON superset and schema pin; never parse it as a real observation."""

    finding_schema = DevelopmentCorpusFinding.model_json_schema()
    response_schema = DevelopmentCorpusResponse.model_json_schema()
    count = response_schema["properties"]["findings"]["maxItems"]
    if type(count) is not int or not 1 <= count <= 16:
        raise ValueError("review bound refuses a changed candidate claim population")
    claim_schema = DevelopmentCorpusJudgmentClaim.model_json_schema()
    from mmaudit.models.development_corpus import DEVELOPMENT_CORPUS_CLAIM_PATTERN

    if (
        DEVELOPMENT_CORPUS_CLAIM_PATTERN
        != r"^file-(?:00(?:0[1-9]|[1-9][0-9])|01[0-9]{2}|02(?:[0-4][0-9]|5[0-6])):(?:0[1-9]|1[0-6])$"
        or claim_schema.get("type") != "object"
        or claim_schema.get("additionalProperties") is not False
        or claim_schema["properties"]
        != {
            "claim_id": {
                "pattern": DEVELOPMENT_CORPUS_CLAIM_PATTERN,
                "title": "Claim Id",
                "type": "string",
            },
            "finding": {"$ref": "#/$defs/DevelopmentCorpusFinding"},
        }
        or claim_schema["$defs"]["DevelopmentCorpusFinding"]
        != {k: v for k, v in finding_schema.items() if k != "$defs"}
    ):
        raise ValueError("review bound claim identity grammar changed")
    finding = _maximum_value(finding_schema, finding_schema.get("$defs", {}))
    # All allowed file/claim ordinals have the same encoded width.
    claims = [{"claim_id": f"file-0256:{i:02d}", "finding": finding} for i in range(1, count + 1)]
    return _json(claims), canonical_sha256(
        {"claim": claim_schema, "response": response_schema, "finding": finding_schema}
    )
