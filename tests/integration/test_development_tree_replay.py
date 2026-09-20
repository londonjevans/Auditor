"""Invocation-local plan reuse never caches actual filesystem custody or negative route gates."""

from __future__ import annotations

from dataclasses import replace

import pytest

from mmaudit.repository import development_tree_plan as module
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import tree_plan_case

pytestmark = pytest.mark.usefixtures("no_external_execution")


def test_invocation_reuses_only_the_detached_preflight_and_rechecks_actual_inputs(
    tmp_path, monkeypatch
):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    calls = {"plan": 0, "sources": 0, "eligibility": 0}
    original_read = module.read_development_tree_plan
    original_sources = module.revalidate_captured_development_corpus_tree
    original_metadata = module._development_metadata

    def read(content):
        calls["plan"] += 1
        return original_read(content)

    def sources(value):
        calls["sources"] += 1
        return original_sources(value)

    def metadata(value):
        calls["eligibility"] += 1
        return original_metadata(value)

    monkeypatch.setattr(module, "read_development_tree_plan", read)
    monkeypatch.setattr(module, "revalidate_captured_development_corpus_tree", sources)
    monkeypatch.setattr(module, "_development_metadata", metadata)
    replay = module.bind_development_tree_plan_replay(loaded)
    replay()
    replay()
    assert calls == {"plan": 1, "sources": 4, "eligibility": 9}
    # A new invocation must earn its own preflight, not inherit an earlier validation cache.
    module.bind_development_tree_plan_replay(loaded)
    assert calls == {"plan": 2, "sources": 6, "eligibility": 12}


@pytest.mark.parametrize("field", ["plan", "nested_policy", "reference"])
def test_in_memory_changes_cannot_modify_the_private_replayed_selection(tmp_path, field):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    replay = module.bind_development_tree_plan_replay(loaded)
    if field == "plan":
        object.__setattr__(loaded.plan, "maximum_requests", 1)
    elif field == "nested_policy":
        object.__setattr__(loaded.plan.policy, "maximum_total_seconds", 1)
    else:
        object.__setattr__(loaded.reference.material.manifest, "corpus_id", "synthetic-forgery")
    with pytest.raises(ValueError, match="replayed selection"):
        replay()


def test_a_forged_handle_cannot_acquire_a_replay_callback(tmp_path):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    forged = loaded.plan.model_copy(update={"maximum_requests": 1})
    with pytest.raises(ValueError, match="retained plan"):
        module.bind_development_tree_plan_replay(replace(loaded, plan=forged))


@pytest.mark.parametrize(
    "input_name", ["policy_file", "remappings_file", "source", "plan", "manifest"]
)
@pytest.mark.parametrize("replacement", [False, True])
def test_replayed_selection_still_rejects_byte_drift_and_same_byte_file_replacement(
    tmp_path, input_name, replacement
):
    inputs = tree_plan_case(tmp_path)
    loaded = module.write_development_tree_plan(**inputs)
    replay = module.bind_development_tree_plan_replay(loaded)
    path = (
        inputs["corpus_root"] / "src/Controller.sol"
        if input_name == "source"
        else inputs["output_dir"] / (input_name + ".json")
        if input_name in {"plan", "manifest"}
        else inputs[input_name]
    )
    content = path.read_bytes()
    if replacement:
        path.rename(tmp_path / "retained-original-input")
        path.write_bytes(content)
        path.chmod(0o600)
    else:
        path.write_bytes(content + b"\n")
    with pytest.raises(ValueError):
        replay()


def test_original_tree_namespace_is_not_replaced_by_a_matching_cached_manifest(tmp_path):
    inputs = tree_plan_case(tmp_path)
    replay = module.bind_development_tree_plan_replay(module.write_development_tree_plan(**inputs))
    source = inputs["corpus_root"] / "src/Controller.sol"
    (inputs["corpus_root"] / "Unexpected.sol").write_bytes(source.read_bytes())
    with pytest.raises(ValueError):
        replay()


def test_route_eligibility_is_checked_again_during_the_same_invocation(tmp_path, monkeypatch):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    replay = module.bind_development_tree_plan_replay(loaded)

    def revoked(_metadata):
        raise ValueError("synthetic negative eligibility changed")

    monkeypatch.setattr(module, "_development_metadata", revoked)
    with pytest.raises(ValueError, match="negative eligibility"):
        replay()


def test_review_grammar_changes_invalidate_the_bound_preflight(tmp_path, monkeypatch):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    replay = module.bind_development_tree_plan_replay(loaded)
    monkeypatch.setattr(module, "development_tree_review_claims_bound", lambda: ("", "b" * 64))
    with pytest.raises(ValueError, match="grammar changed"):
        replay()


def test_replay_does_not_retain_a_superseded_reader_byte_bound(tmp_path, monkeypatch):
    loaded = module.write_development_tree_plan(**tree_plan_case(tmp_path))
    replay = module.bind_development_tree_plan_replay(loaded)
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_TREE_PLAN_BYTES", 1)
    with pytest.raises(ValueError, match="byte bound"):
        replay()
