"""Exact byte identities and explicit bounds constrain one private pure coverage result."""

from __future__ import annotations

from copy import deepcopy

import pytest

from mmaudit.orchestration import development_tree as module
from tests.unit.test_development_context_sources import partitioned_tree
from tests.unit.test_development_corpus_coverage import candidate


def inputs(tmp_path):
    loaded = partitioned_tree(tmp_path)
    _, observed = candidate(loaded)
    return dict(reference=loaded.material, records=(observed,), partitions=None)


def test_only_one_exact_population_is_retained_and_a_new_instance_recomputes(tmp_path, monkeypatch):
    arguments = inputs(tmp_path)
    compute = module.compute_development_corpus_coverage
    populations = []

    def counted(**kwargs):
        populations.append(len(kwargs["records"]))
        return compute(**kwargs)

    monkeypatch.setattr(module, "compute_development_corpus_coverage", counted)
    replay = module._CoverageReplay()
    first = replay.compute(**arguments)
    assert replay.compute(**deepcopy(arguments)) is first
    assert first.model_dump_json() == compute(**arguments).model_dump_json()
    assert populations == [1]
    replay.compute(**{**arguments, "records": ()})
    assert replay.compute(**arguments) == first
    assert populations == [1, 0, 1]
    assert module._CoverageReplay().compute(**arguments) == first
    assert populations == [1, 0, 1, 1]


@pytest.mark.parametrize("field", ["reference", "record"])
def test_same_declared_digest_never_admits_changed_input_bytes(tmp_path, field):
    arguments = inputs(tmp_path)
    replay = module._CoverageReplay()
    replay.compute(**arguments)
    if field == "reference":
        reference = arguments["reference"]
        first, *rest = reference.sources
        arguments["reference"] = reference.model_copy(
            update={"sources": (first.model_copy(update={"content": first.content + "\n"}), *rest)}
        )
        assert arguments["reference"].manifest.manifest_sha256 == reference.manifest.manifest_sha256
    else:
        record = arguments["records"][0]
        arguments["records"] = (record.model_copy(update={"completed_shard_count": 999}),)
        assert arguments["records"][0].plan.plan_sha256 == record.plan.plan_sha256
    with pytest.raises(ValueError):
        replay.compute(**arguments)
    assert replay._key is replay._coverage is replay._content is None


def test_mutating_a_previously_returned_result_is_refused_before_reuse(tmp_path):
    arguments = inputs(tmp_path)
    replay = module._CoverageReplay()
    result = replay.compute(**arguments)
    assert result.summary.status == "INCOMPLETE"
    object.__setattr__(result.summary, "status", "ALL_PRIMARY_RESPONSES_OBSERVED")
    with pytest.raises(ValueError, match="cached coverage changed"):
        replay.compute(**arguments)


@pytest.mark.parametrize("change", ["records_list", "empty_partitions", "too_many_records"])
def test_warm_replay_still_refuses_invalid_container_types_and_counts(tmp_path, change):
    arguments = inputs(tmp_path)
    replay = module._CoverageReplay()
    replay.compute(**arguments)
    if change == "records_list":
        arguments["records"] = list(arguments["records"])
    elif change == "empty_partitions":
        arguments["partitions"] = ()
    else:
        arguments["records"] *= module.MAX_DEVELOPMENT_COVERAGE_RUNS + 1
    with pytest.raises(ValueError, match="exact bounded inputs"):
        replay.compute(**arguments)


def test_input_byte_limit_is_rechecked_even_for_the_previous_exact_key(tmp_path, monkeypatch):
    arguments = inputs(tmp_path)
    replay = module._CoverageReplay()
    replay.compute(**arguments)
    size = sum(
        len(model.model_dump_json().encode())
        for model in (arguments["reference"], *arguments["records"])
    )
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_COVERAGE_BYTES", size - 1)
    with pytest.raises(ValueError, match="input byte bound"):
        replay.compute(**arguments)


def test_oversized_result_is_never_cached(tmp_path, monkeypatch):
    arguments = inputs(tmp_path)
    size = sum(
        len(model.model_dump_json().encode())
        for model in (arguments["reference"], *arguments["records"])
    )
    result = module.compute_development_corpus_coverage(**arguments)
    assert len(result.model_dump_json().encode()) > size
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_COVERAGE_BYTES", size)
    replay = module._CoverageReplay()
    with pytest.raises(ValueError, match="result byte bound"):
        replay.compute(**arguments)
    assert replay._key is replay._coverage is replay._content is None


def test_result_byte_limit_is_rechecked_on_a_warm_lookup(tmp_path, monkeypatch):
    arguments = inputs(tmp_path)
    replay = module._CoverageReplay()
    result = replay.compute(**arguments)
    monkeypatch.setattr(
        module, "MAX_DEVELOPMENT_COVERAGE_BYTES", len(result.model_dump_json().encode()) - 1
    )
    with pytest.raises(ValueError, match="result byte bound"):
        replay.compute(**arguments)


def test_inputs_changed_during_computation_cannot_poison_the_previous_key(tmp_path, monkeypatch):
    arguments = inputs(tmp_path)
    compute = module.compute_development_corpus_coverage

    def changed(**kwargs):
        result = compute(**kwargs)
        source = kwargs["reference"].sources[0]
        object.__setattr__(source, "content", source.content + "\n")
        return result

    monkeypatch.setattr(module, "compute_development_corpus_coverage", changed)
    replay = module._CoverageReplay()
    with pytest.raises(ValueError, match="inputs changed during computation"):
        replay.compute(**arguments)
    assert replay._key is replay._coverage is replay._content is None
