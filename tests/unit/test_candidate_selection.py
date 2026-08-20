from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.candidate_selection import (
    OBJECTIVE_SHA256,
    CandidateSelectionError,
    CandidateSelectionPlan,
    derive_pending_candidate_registry_from_selection_plan,
    load_candidate_selection_plan,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
    seal_candidate_selection_source_binding,
    validate_candidate_selection_plan_sources,
    validate_candidate_selection_routes,
)
from mmaudit.models.discovery import DiscoveryCandidateRoute
from mmaudit.models.qualification import CandidateBenchmarkStatus, LineageReviewStatus
from mmaudit.privacy import PrivacyProfile
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_candidate_benchmark as fixtures

RANKING_BYTES = b"synthetic operator-staged ranking implementation\n"
REVIEW_BYTES = b"synthetic operator-staged lineage review\n"
MODEL_A = "alpha/atlas-current"
MODEL_B = "beta/beacon-current"
MODEL_C = "gamma/compass-current"
ENDPOINT_A = "provider-alpha"
ENDPOINT_B = "provider-beta/fp8"
ENDPOINT_C = "provider-gamma/global"
ROOT = Path(__file__).parents[2]


def _plan() -> CandidateSelectionPlan:
    sources = (
        seal_candidate_selection_source_binding(
            kind="MODEL_RANKING_IMPLEMENTATION",
            filename="model-ranking.py",
            content=RANKING_BYTES,
        ),
        seal_candidate_selection_source_binding(
            kind="OPERATOR_LINEAGE_REVIEW",
            filename="V3-LINEAGE-001-operator-review.md",
            content=REVIEW_BYTES,
        ),
    )
    entries = (
        seal_candidate_selection_entry(
            exact_model_id=MODEL_C,
            priority_rank=3,
            advisory_lineage_group="Gamma advisory root",
            allowed_provider_endpoints=(ENDPOINT_C,),
        ),
        seal_candidate_selection_entry(
            exact_model_id=MODEL_A,
            priority_rank=1,
            advisory_lineage_group="Alpha advisory root",
            allowed_provider_endpoints=(ENDPOINT_A, "provider-alpha/alternate"),
        ),
        seal_candidate_selection_entry(
            exact_model_id=MODEL_B,
            priority_rank=2,
            advisory_lineage_group="Beta advisory root",
            allowed_provider_endpoints=(ENDPOINT_B,),
        ),
    )
    assignment = seal_authenticated_runner_selection(
        candidate_model_id=MODEL_A,
        primary_judge_model_id=MODEL_B,
        replay_judge_model_id=MODEL_C,
    )
    return seal_candidate_selection_plan(
        source_bindings=sources,
        entries=entries,
        authenticated_runner_selection=assignment,
        unresolved_requirements=(
            "Fresh exact provider metadata is required.",
            "New exact IDs require documentary public-lineage confirmation.",
        ),
    )


def test_selection_plan_is_deterministic_and_strictly_nonauthorizing() -> None:
    first = _plan()
    second = _plan()

    assert first == second
    assert first.objective_sha256 == OBJECTIVE_SHA256
    assert tuple(entry.exact_model_id for entry in first.entries) == tuple(
        sorted((MODEL_A, MODEL_B, MODEL_C))
    )
    assert tuple(entry.priority_rank for entry in first.entries) == (1, 2, 3)
    assert all(entry.approved_roles == () for entry in first.entries)
    payload = first.model_dump(mode="json")
    assert payload["ranking_executed"] is False
    assert payload["provider_metadata_present"] is False
    assert payload["documentary_lineage_identity_authorized"] is False
    assert payload["provider_call_authorized"] is False
    assert payload["source_egress_authorized"] is False
    assert payload["qualification_authorized"] is False
    assert payload["production_selection_authorized"] is False
    assert payload["runner_authority_authorized"] is False
    assert payload["benchmark_authorized"] is False
    assert payload["seal_publication_authorized"] is False
    assert payload["release_authorized"] is False
    assert payload["serialized_authority"] is False
    serialized = stable_json(first)
    assert '"root_lineage"' not in serialized
    assert '"discovery_evidence_sha256"' not in serialized
    assert '"pricing_snapshot_sha256"' not in serialized

    schema = CandidateSelectionPlan.model_json_schema()
    required = set(schema["required"])
    assert {
        "objective_sha256",
        "provider_call_authorized",
        "qualification_authorized",
        "runner_authority_authorized",
        "release_authorized",
        "serialized_authority",
    }.issubset(required)
    assert schema["properties"]["objective_sha256"]["const"] == OBJECTIVE_SHA256
    entry_schema = schema["$defs"]["CandidateSelectionEntry"]
    assert entry_schema["properties"]["exact_model_id"]["pattern"]
    assert "entry_authority" in entry_schema["required"]


def test_committed_selection_plan_is_canonical_and_nonauthorizing() -> None:
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")
    guide = (ROOT / "docs" / "models" / "model_selection.md").read_text(encoding="utf-8")

    assert plan.plan_sha256 == "b365a0ce5056ec1328f3f54722a97104dd25308a1cfab663d4185476165b06a7"
    assert plan.plan_sha256 in guide
    assert len(plan.entries) == 11
    assert plan.authenticated_runner_selection is not None
    assert plan.authenticated_runner_selection.distinct_root_lineages_verified is False
    assert all(entry.availability == "UNVERIFIED" for entry in plan.entries)
    assert all(entry.documentary_lineage == "UNCONFIRMED" for entry in plan.entries)


def test_selection_plan_replays_exact_staged_source_bytes() -> None:
    plan = _plan()
    assert (
        validate_candidate_selection_plan_sources(
            plan,
            ranking_source_bytes=RANKING_BYTES,
            lineage_review_source_bytes=REVIEW_BYTES,
        )
        == plan
    )

    with pytest.raises(CandidateSelectionError, match="differs from its binding"):
        validate_candidate_selection_plan_sources(
            plan,
            ranking_source_bytes=RANKING_BYTES + b"tamper",
            lineage_review_source_bytes=REVIEW_BYTES,
        )


def test_selection_plan_rejects_one_source_relabelled_as_two() -> None:
    ranking = seal_candidate_selection_source_binding(
        kind="MODEL_RANKING_IMPLEMENTATION",
        filename="shared-input.txt",
        content=RANKING_BYTES,
    )
    review = seal_candidate_selection_source_binding(
        kind="OPERATOR_LINEAGE_REVIEW",
        filename="shared-input.txt",
        content=RANKING_BYTES,
    )

    with pytest.raises(CandidateSelectionError, match="plan is invalid"):
        seal_candidate_selection_plan(
            source_bindings=(ranking, review),
            entries=_plan().entries,
        )


def test_selection_routes_are_an_explicit_exact_subset() -> None:
    plan = _plan()
    selected = (
        DiscoveryCandidateRoute(
            exact_model_id=MODEL_B,
            approved_provider_endpoint=ENDPOINT_B,
        ),
    )
    assert validate_candidate_selection_routes(plan, routes=selected) == plan

    with pytest.raises(CandidateSelectionError, match="unlisted endpoint"):
        validate_candidate_selection_routes(
            plan,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id=MODEL_B,
                    approved_provider_endpoint="provider-beta/unlisted",
                ),
            ),
        )
    with pytest.raises(CandidateSelectionError, match="outside the plan"):
        validate_candidate_selection_routes(
            plan,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id="delta/unlisted",
                    approved_provider_endpoint="provider-delta",
                ),
            ),
        )


def test_plan_loader_requires_canonical_regular_bytes(tmp_path: Path) -> None:
    plan = _plan()
    path = tmp_path / "selection-plan.json"
    path.write_text(stable_json(plan), encoding="utf-8")
    assert load_candidate_selection_plan(path) == plan

    noncanonical = tmp_path / "selection-plan-noncanonical.json"
    noncanonical.write_text(
        json.dumps(plan.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )
    with pytest.raises(CandidateSelectionError, match="not canonical JSON"):
        load_candidate_selection_plan(noncanonical)

    linked = tmp_path / "selection-plan-link.json"
    linked.symlink_to(path)
    with pytest.raises(CandidateSelectionError, match="could not be opened"):
        load_candidate_selection_plan(linked)

    hardlink_source = tmp_path / "selection-plan-hardlink-source.json"
    hardlink_source.write_text(stable_json(plan), encoding="utf-8")
    hardlink = tmp_path / "selection-plan-hardlink.json"
    hardlink.hardlink_to(hardlink_source)
    with pytest.raises(CandidateSelectionError, match="not bounded and regular"):
        load_candidate_selection_plan(hardlink)

    fifo = tmp_path / "selection-plan-fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(CandidateSelectionError, match="not bounded and regular"):
        load_candidate_selection_plan(fifo)


def test_fresh_discovery_derives_only_rootless_pending_registry(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    spec = fixtures._CandidateSpec(
        model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        provider_name="Provider Alpha",
        canonical_model_id="alpha/atlas-current-20260820",
    )
    manifest, evidence, _legacy_registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(spec,),
    )

    registry = derive_pending_candidate_registry_from_selection_plan(
        plan=_plan(),
        run_manifest=manifest,
        evidence=evidence,
    )

    assert registry.created_at == manifest.run_provenance.retrieved_at
    assert registry.discovery_run_sha256 == manifest.manifest_sha256
    assert len(registry.candidates) == 1
    candidate = registry.candidates[0]
    discovered = evidence[0]
    assert candidate.exact_model_id == MODEL_A
    assert candidate.canonical_model_slug == discovered.canonical_slug
    assert candidate.root_lineage is None
    assert candidate.lineage_review.status is LineageReviewStatus.PENDING
    assert candidate.benchmark_status is CandidateBenchmarkStatus.PENDING
    assert candidate.approved_roles == ()
    assert candidate.discovery_evidence_sha256 == discovered.discovery_evidence_sha256
    assert candidate.endpoint_snapshot_sha256 == discovered.endpoint_snapshot_sha256
    assert candidate.output_capability_sha256 == discovered.output_capability_sha256
    assert candidate.model_metadata_snapshot_sha256 == discovered.model_metadata_snapshot_sha256
    assert candidate.pricing_snapshot_sha256 == discovered.pricing_snapshot_sha256
    assert _plan().plan_sha256 in candidate.lineage_review.rationale


def test_derivation_rejects_route_not_authorized_by_plan(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    spec = fixtures._CandidateSpec(
        model_id=MODEL_A,
        provider_endpoint="provider-alpha/unlisted",
        provider_name="Provider Alpha",
    )
    manifest, evidence, _legacy_registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(spec,),
    )

    with pytest.raises(CandidateSelectionError, match="unlisted endpoint"):
        derive_pending_candidate_registry_from_selection_plan(
            plan=_plan(),
            run_manifest=manifest,
            evidence=evidence,
        )
