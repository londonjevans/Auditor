"""Lossless strict JSON omission replay, without removing gaps or weakening typed commitments."""

import json

import pytest

from mmaudit.models.schemas import (
    SolidityGraphFactKind,
    SolidityGraphFactOmission,
    SolidityGraphKind,
    SolidityGraphOmission,
)


def omission(kind):
    cls = SolidityGraphOmission if kind == "edge" else SolidityGraphFactOmission
    return cls.build(
        **(
            {"graph": SolidityGraphKind.INTERNAL_CALL}
            if kind == "edge"
            else {"fact_kind": SolidityGraphFactKind.WARNING}
        ),
        candidate_count=1,
        retained_count=0,
        omitted_count=1,
        omitted_canonical_bytes=128,
        omitted_stream_sha256="a" * 64,
        omitted_sample_sha256s=("b" * 64,),
    )


@pytest.mark.parametrize("kind", ["edge", "fact"])
def test_strict_json_round_trip_preserves_every_omission_byte_and_commitment(kind):
    original = omission(kind)
    raw = original.model_dump_json()
    rebuilt = type(original).model_validate_json(raw, strict=True)
    assert rebuilt == original and rebuilt.model_dump_json() == raw
    assert rebuilt.omitted_count == 1 and rebuilt.omitted_sample_sha256s == ("b" * 64,)


@pytest.mark.parametrize("kind", ["edge", "fact"])
@pytest.mark.parametrize(
    "change",
    ["python-list", "coerced-count", "duplicate-sample", "non-array", "bad-digest", "extra"],
)
def test_replay_does_not_relax_types_bounds_uniqueness_or_hashes(kind, change):
    original = omission(kind)
    if change == "python-list":
        value = original.model_dump()
        value["omitted_sample_sha256s"] = ["b" * 64]
        with pytest.raises(ValueError):
            type(original).model_validate(value, strict=True)
        return
    value = original.model_dump(mode="json")
    if change == "coerced-count":
        value["omitted_count"] = "1"
    elif change == "duplicate-sample":
        value["omitted_sample_sha256s"] *= 2
    elif change == "non-array":
        value["omitted_sample_sha256s"] = {"0": "b" * 64}
    elif change == "bad-digest":
        value["evidence_sha256"] = "c" * 64
    else:
        value["unrecognized"] = True
    with pytest.raises(ValueError):
        type(original).model_validate_json(json.dumps(value), strict=True)
