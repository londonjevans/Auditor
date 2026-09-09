"""Strict self-reproduction and local file identity controls for annotation-independent measurement."""

from __future__ import annotations

import json
import os

import pytest

import mmaudit.benchmark.development_corpus_control_measurement as measurement
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.file_custody import (
    observe_regular_file_custody,
    require_regular_file_custody_unchanged,
)
from tests.development_corpus_control_measurement_support import retained_score


@pytest.mark.parametrize("cumulative", [False, True])
@pytest.mark.parametrize("complete", [False, True])
def test_readers_reproduce_exact_original_or_cumulative_scores_without_hidden_inputs(
    cumulative, complete
):
    old = retained_score(cumulative=cumulative, complete=complete)
    raw = old.model_dump_json().encode()
    assert measurement.read_development_corpus_control_source(raw) == old
    result = measurement.measure_development_corpus_controls(score=old)
    assert (
        measurement.read_development_corpus_control_measurement(result.model_dump_json().encode())
        == result
    )
    assert result.source_score.model_dump_json().encode() == raw
    assert result.summary.unique_root_location_coverage.value == (1 if complete else None)
    if cumulative and not complete:
        assert result.source_score.cumulative_summary.uncertain_accounted_cost_usd > 0


@pytest.mark.parametrize(
    "field",
    [
        "source_score_sha256",
        "source_scope",
        "summary",
        "claims",
        "annotation_policy",
        "origin_policy",
        "precision_denominator",
        "cost_runtime_reference",
        "measurement_sha256",
        "root_independence",
        "audit_complete",
        "findings_validated",
        "qualification_eligible",
        "release_eligible",
        "source_score",
    ],
)
def test_rehashed_changed_measurements_policies_or_authorities_refuse(field):
    result = measurement.measure_development_corpus_controls(score=retained_score())
    data = result.model_dump(mode="json")
    if field == "summary":
        data[field]["located_root_ids"] = []
    elif field == "claims":
        data[field][0]["category_agrees"] = not data[field][0]["category_agrees"]
    elif field == "source_score":
        data[field]["summary"]["total_claim_count"] += 1
    elif field.endswith("eligible") or field in {"audit_complete", "findings_validated"}:
        data[field] = True
    elif field == "source_scope":
        data[field] = "CUMULATIVE_RECORDED_ATTEMPTS"
    else:
        data[field] = "0" * 64
    if field != "measurement_sha256":
        data["measurement_sha256"] = canonical_sha256(
            {k: v for k, v in data.items() if k != "measurement_sha256"}
        )
    with pytest.raises(ValueError):
        measurement.read_development_corpus_control_measurement(json.dumps(data).encode())


@pytest.mark.parametrize(
    "reader",
    [
        measurement.read_development_corpus_control_source,
        measurement.read_development_corpus_control_measurement,
    ],
)
@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"[]",
        b"{}",
        b"{",
        b"\xff",
        b'{"a":1,"a":1}',
        b'{"x":NaN}',
        b"[" * 2000 + b"0" + b"]" * 2000,
        "{}",
        bytearray(b"{}"),
    ],
)
def test_readers_refuse_wrong_types_ambiguous_json_nonfinite_or_deep_shapes(reader, raw):
    with pytest.raises(ValueError):
        reader(raw)


@pytest.mark.parametrize("kind", ["none", "mapping", "subclass", "tampered"])
def test_pure_measurement_rejects_inexact_or_mutated_source_objects(kind):
    old = retained_score()
    if kind == "none":
        candidate = None
    elif kind == "mapping":
        candidate = old.model_dump()
    elif kind == "subclass":
        candidate = type("SyntheticSubclass", (type(old),), {}).model_validate(old.model_dump())
    else:
        candidate = old.model_copy(update={"observation_sha256": "0" * 64})
    with pytest.raises(ValueError):
        measurement.measure_development_corpus_controls(score=candidate)


@pytest.mark.parametrize("opt_in", [False, True])
def test_shared_file_revalidation_defaults_strict_and_only_opt_in_allows_sibling_churn(
    tmp_path, opt_in
):
    target = tmp_path / "synthetic.json"
    target.write_bytes(b"{}")
    expected = observe_regular_file_custody(
        root=tmp_path, relative_path=target.name, label="synthetic", max_bytes=100
    )
    (tmp_path / "unrelated.json").write_bytes(b"{}")
    if opt_in:
        require_regular_file_custody_unchanged(
            expected, label="synthetic", max_bytes=100, allow_directory_entry_metadata_change=True
        )
    else:
        with pytest.raises(ValueError):
            require_regular_file_custody_unchanged(expected, label="synthetic", max_bytes=100)


@pytest.mark.parametrize("value", [None, 0, 1, "true", [], {}])
def test_shared_file_revalidation_requires_an_exact_boolean_opt_in(tmp_path, value):
    (tmp_path / "synthetic.json").write_bytes(b"{}")
    expected = observe_regular_file_custody(
        root=tmp_path, relative_path="synthetic.json", label="synthetic", max_bytes=100
    )
    with pytest.raises(ValueError):
        require_regular_file_custody_unchanged(
            expected, label="synthetic", max_bytes=100, allow_directory_entry_metadata_change=value
        )


@pytest.mark.parametrize(
    "kind", ["bytes", "replace", "mode", "parent", "ancestor", "symlink", "hardlink"]
)
def test_entry_churn_opt_in_still_refuses_every_selected_file_or_ancestor_change(tmp_path, kind):
    parent = tmp_path / "middle" / "inner"
    parent.mkdir(parents=True)
    target = parent / "synthetic.json"
    target.write_bytes(b"{}")
    target.chmod(0o600)
    expected = observe_regular_file_custody(
        root=parent,
        relative_path=target.name,
        label="synthetic",
        max_bytes=100,
        allow_directory_entry_metadata_change=True,
    )
    if kind == "bytes":
        target.write_bytes(b"{} ")
    elif kind == "mode":
        target.chmod(0o644)
    elif kind in {"parent", "ancestor"}:
        changed = parent if kind == "parent" else parent.parent
        changed.rename(changed.with_name("retained-" + changed.name))
        parent.mkdir(parents=True)
        target.write_bytes(b"{}")
        target.chmod(0o600)
    else:
        retained = target.with_suffix(".retained")
        target.rename(retained)
        if kind == "replace":
            target.write_bytes(b"{}")
            target.chmod(0o600)
        elif kind == "symlink":
            target.symlink_to(retained)
        else:
            os.link(retained, target)
    with pytest.raises(ValueError):
        require_regular_file_custody_unchanged(
            expected, label="synthetic", max_bytes=100, allow_directory_entry_metadata_change=True
        )
