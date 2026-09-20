"""Every original source and all three role envelopes must survive automatic preflight."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest

from mmaudit.models import development_tree_plan as module
from mmaudit.models.development_corpus import prepare_development_corpus
from mmaudit.models.development_corpus_partition import validate_development_corpus_partition
from mmaudit.models.development_tree_plan import plan_development_tree, read_development_tree_plan
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.repository.development_corpus_partition import materialize_development_corpus_partition
from tests.development_tree_support import tree_metadata, tree_policy
from tests.unit.test_development_context_sources import partitioned_tree
from tests.unit.test_development_dependency_closure import fixture_sources


@pytest.fixture(scope="module")
def reference(tmp_path_factory):
    return partitioned_tree(tmp_path_factory.mktemp("automatic-tree"), primaries=None)


def test_every_original_source_is_primary_once_with_its_minimal_original_closure(reference):
    plan = plan_development_tree(reference=reference.material, policy=tree_policy())
    assert plan.status == "READY" and plan.headroom_complete
    assert not plan.audit_complete and not plan.qualification_eligible and not plan.release_eligible
    assert tuple(p.primary_filename for p in plan.primaries) == tuple(
        s.filename for s in reference.material.manifest.sources
    )
    closures = reference.material.manifest.dependency_evidence.static_call_closure.primaries
    for primary, closure in zip(plan.primaries, closures, strict=True):
        assert primary.primary_filename == closure.primary
        manifest = primary.partition.manifest
        assert tuple(s.filename for s in manifest.sources) == closure.members
        assert tuple(s.filename for s in manifest.primary_sources) == (closure.primary,)
        assert manifest.dependency_closure == "CALL_CLOSED"
        assert len(primary.candidate.shards) == 1
        assert len(primary.role_envelopes) == 3
        assert not primary.shortfalls
        assert all(not e.shortfalls for e in primary.role_envelopes)
    assert plan.maximum_requests == 15 and plan.reserved_run_seconds == 300
    assert len({p.case_run_id for p in plan.primaries}) == 5
    assert read_development_tree_plan(plan.model_dump_json().encode()) == plan


def test_planned_candidate_equals_the_real_custodied_request(reference, tmp_path):
    policy = tree_policy()
    plan = plan_development_tree(reference=reference.material, policy=policy)
    primary = plan.primaries[0]
    loaded = materialize_development_corpus_partition(
        reference=reference, partition=primary.partition, output_dir=tmp_path / "bundle"
    )
    prepared = prepare_development_corpus(
        policy=policy.cost_policy,
        endpoint_snapshot=policy.role_metadata[0],
        manifest=loaded.material.manifest,
        source_files=loaded.material.source_files,
        source_custody=loaded,
        run_id=primary.candidate.run_id,
        maximum_completion_tokens=policy.maximum_completion_tokens[0],
        maximum_run_seconds=policy.maximum_manifest_seconds,
    )
    assert prepared.plan == primary.candidate
    assert (
        len(prepared.shards[0].request_content)
        == primary.role_envelopes[0].serialized_request_bytes
    )
    assert prepared.shards[0].estimate == primary.role_envelopes[0].estimate


@pytest.mark.parametrize("role", [0, 1, 2])
def test_each_role_reports_every_capacity_failure_without_losing_source_slots(reference, role):
    metadata = list(tree_policy().role_metadata)
    metadata[role] = tree_metadata(role, prompt=100, context=100, completion=10)
    plan = plan_development_tree(
        reference=reference.material, policy=tree_policy(role_metadata=tuple(metadata))
    )
    assert plan.status == "REFUSED" and not plan.headroom_complete
    assert plan.shortfalls == ("UNPLACEABLE_PRIMARY",)
    assert len(plan.primaries) == 5
    for primary in plan.primaries:
        envelope = primary.role_envelopes[role]
        assert envelope.shortfalls == ("PROMPT_LIMIT", "CONTEXT_LIMIT", "COMPLETION_LIMIT")
        assert envelope.estimate is None
        assert "ROLE_ENVELOPE_REFUSED" in primary.shortfalls


def test_whole_run_time_requests_and_cost_fail_together_before_any_dispatch(reference):
    policy = tree_policy()
    policy = tree_policy(
        cost_policy=policy.cost_policy.model_copy(update={"total_budget_usd": Decimal("20")}),
        maximum_requests=14,
        maximum_total_seconds=299,
    )
    plan = plan_development_tree(reference=reference.material, policy=policy)
    assert plan.shortfalls == (
        "WHOLE_COST_ENVELOPE",
        "WHOLE_REQUEST_ENVELOPE",
        "WHOLE_TIME_ENVELOPE",
    )
    assert all(not p.shortfalls for p in plan.primaries)
    assert plan.status == "REFUSED" and plan.headroom_complete


def test_time_shortfall_does_not_hide_reviewer_capacity_failure(reference):
    metadata = (tree_metadata(0), tree_metadata(1, prompt=100), tree_metadata(2))
    plan = plan_development_tree(
        reference=reference.material,
        policy=tree_policy(maximum_manifest_seconds=47, role_metadata=metadata),
    )
    for primary in plan.primaries:
        assert primary.shortfalls == ("MANIFEST_TIME_ENVELOPE", "ROLE_ENVELOPE_REFUSED")
        assert primary.role_envelopes[1].shortfalls == ("PROMPT_LIMIT",)


def test_worst_case_review_cost_can_refuse_when_the_candidate_fits(reference):
    policy = tree_policy()
    plan = plan_development_tree(
        reference=reference.material,
        policy=tree_policy(
            cost_policy=policy.cost_policy.model_copy(
                update={"per_attempt_budget_usd": Decimal("10")}
            )
        ),
    )
    assert plan.status == "REFUSED"
    controller = next(p for p in plan.primaries if p.primary_filename == "src/Controller.sol")
    assert not controller.role_envelopes[0].shortfalls
    assert all(e.shortfalls == ("PER_ATTEMPT_BUDGET",) for e in controller.role_envelopes[1:])
    assert controller.candidate is not None


def test_work_bound_refusal_keeps_every_original_primary_and_original_proof(reference, monkeypatch):
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_TREE_PLAN_BYTES", 200_000)
    # Exercise the work guard without manufacturing a false source witness.
    monkeypatch.setattr(
        module, "_derive_partition_from_replayed_reference", lambda *_: pytest.fail()
    )
    sizes = reference.material.manifest.total_source_bytes
    monkeypatch.setattr(module, "MAX_DEVELOPMENT_TREE_PLAN_BYTES", sizes - 1)
    projection = module._projection(reference.material, tree_policy())
    assert "PLANNING_WORK_BOUND" in projection["shortfalls"]
    assert len(projection["primaries"]) == 5
    assert all(
        p.partition is None and "PLANNING_WORK_BOUND" in p.shortfalls
        for p in projection["primaries"]
    )
    assert not projection["headroom_complete"]


@pytest.mark.parametrize(
    "field",
    ["primaries", "maximum_requests", "reserved_run_seconds", "headroom_complete", "status"],
)
def test_rehashed_plan_cannot_drop_work_or_change_a_computed_envelope(reference, field):
    plan = plan_development_tree(reference=reference.material, policy=tree_policy())
    value = plan.model_dump(mode="json")
    if field == "primaries":
        value[field].pop()
    elif field == "status":
        value[field] = "REFUSED"
    elif field == "headroom_complete":
        value[field] = False
    else:
        value[field] -= 1
    value["plan_sha256"] = canonical_sha256({k: v for k, v in value.items() if k != "plan_sha256"})
    with pytest.raises(ValueError, match="population or resource envelopes"):
        read_development_tree_plan(json.dumps(value).encode())


def test_derived_bundle_cannot_replace_the_original_tree(reference):
    plan = plan_development_tree(reference=reference.material, policy=tree_policy())
    subset = validate_development_corpus_partition(
        reference=reference.material, partition=plan.primaries[0].partition
    )
    with pytest.raises(ValueError, match="complete original"):
        plan_development_tree(reference=subset, policy=tree_policy())


def test_plan_does_not_enable_retries_or_change_existing_role_independence():
    policy = tree_policy()
    with pytest.raises(ValueError, match="retries"):
        tree_policy(cost_policy=policy.cost_policy.model_copy(update={"maximum_attempts": 2}))
    with pytest.raises(ValueError):
        tree_policy(role_metadata=(policy.role_metadata[0],) * 3)


def test_missing_dependency_is_an_exact_unplaceable_slot_not_a_dropped_primary(tmp_path):
    files = tuple((p, b) for p, b in fixture_sources() if p != "lib/Math.sol")
    reference = partitioned_tree(tmp_path, primaries=None, files=files).material
    plan = plan_development_tree(reference=reference, policy=tree_policy())
    assert plan.status == "REFUSED" and "UNPLACEABLE_PRIMARY" in plan.shortfalls
    assert tuple(p.primary_filename for p in plan.primaries) == tuple(p for p, _ in files)
    controller = next(p for p in plan.primaries if p.primary_filename == "src/Controller.sol")
    assert "CALL_CLOSURE_NOT_ESTABLISHED" in controller.shortfalls
    assert controller.partition is None and controller.candidate is None
    assert plan.reference.manifest.dependency_evidence == reference.manifest.dependency_evidence
    assert not plan.headroom_complete
