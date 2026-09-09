"""Actual raw-byte limits and unambiguous JSON for locally predeclared synthetic repeat records."""

import json

import pytest

from mmaudit.models.development_corpus_repeats import (
    MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES,
    MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES,
    read_development_corpus_repeats,
    read_development_corpus_repeats_plan,
)
from mmaudit.orchestration.development_corpus_repeats import _report
from tests.development_corpus_repeats_support import repeat_case
from tests.development_review_support import local_controls


@pytest.fixture
def missing_series(tmp_path):
    prepared = repeat_case()
    ledger, _ = local_controls(tmp_path)
    return _report(prepared, ledger, [None, None], 0, "MOCK_HTTP", "LOCAL_FAILURE", 0.0)


@pytest.mark.parametrize("kind", ["plan", "observation"])
def test_exact_actual_byte_ceiling_accepts_and_one_more_byte_refuses(missing_series, kind):
    model, reader, maximum = (
        (
            missing_series.plan,
            read_development_corpus_repeats_plan,
            MAX_DEVELOPMENT_CORPUS_REPEATS_PLAN_BYTES,
        )
        if kind == "plan"
        else (missing_series, read_development_corpus_repeats, MAX_DEVELOPMENT_CORPUS_REPEATS_BYTES)
    )
    raw = model.model_dump_json().encode()
    padded = raw + b" " * (maximum - len(raw))
    assert len(padded) == maximum and reader(padded) == model
    with pytest.raises(ValueError, match="byte bound"):
        reader(padded + b" ")


@pytest.mark.parametrize("kind", ["plan", "observation"])
@pytest.mark.parametrize(
    "mutation", ["duplicate", "unknown", "coerced", "array", "utf8", "not_bytes"]
)
def test_strict_readers_refuse_ambiguous_or_changed_input(missing_series, kind, mutation):
    model, reader = (
        (missing_series.plan, read_development_corpus_repeats_plan)
        if kind == "plan"
        else (missing_series, read_development_corpus_repeats)
    )
    raw = model.model_dump_json().encode()
    if mutation == "duplicate":
        raw = b'{"schema_version":"1.0",' + raw[1:]
    elif mutation == "unknown":
        raw = b'{"invented_authority":true,' + raw[1:]
    elif mutation == "coerced":
        value = json.loads(raw)
        value["trial_count" if kind == "plan" else "started_trial_count"] = "2"
        raw = json.dumps(value).encode()
    elif mutation == "array":
        raw = b"[]"
    elif mutation == "utf8":
        raw = b"\xff"
    else:
        raw = raw.decode()
    with pytest.raises((ValueError, UnicodeError)):
        reader(raw)
