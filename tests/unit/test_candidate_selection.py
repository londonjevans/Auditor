from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.candidate_selection import (
    OBJECTIVE_SHA256,
    CandidateSelectionError,
    CandidateSelectionPlan,
    authenticated_runner_route_constraint,
    derive_pending_candidate_registry_from_selection_plan,
    load_candidate_selection_plan,
    require_candidate_selection_plan_currently_eligible,
    seal_authenticated_runner_route_predicate_profile,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
    seal_candidate_selection_source_binding,
    validate_candidate_selection_plan_sources,
    validate_candidate_selection_routes,
)
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryRunManifest,
    validate_openrouter_constrained_model_discovery,
)
from mmaudit.models.public_lineage_authority import (
    require_independent_public_model_lineage,
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    LineageReviewStatus,
    seal_candidate_registry,
    validate_candidate_registry_discovery,
)
from mmaudit.models.reasoning import (
    CANONICAL_REASONING_POLICY_ROLES,
    ReasoningControlProfile,
    ReasoningEffort,
    ReasoningPolicyArtifact,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    RoutePredicateProfile,
)
from mmaudit.privacy import PrivacyProfile
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_candidate_benchmark as fixtures

RANKING_BYTES = b"synthetic operator-staged ranking implementation\n"
REVIEW_BYTES = b"synthetic operator-staged lineage review\n"
MODEL_A = "alpha/atlas-current"
MODEL_B = "beta/beacon-current"
MODEL_C = "gamma/compass-current"
MODEL_D = "delta/delta-current"
ENDPOINT_A = "provider-alpha"
ENDPOINT_B = "provider-beta/fp8"
ENDPOINT_C = "provider-gamma/global"
ENDPOINT_D = "provider-delta"
ROOT = Path(__file__).parents[2]
HIGH_REASONING_EFFORTS: tuple[ReasoningEffort, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
)
NON_HIGH_REASONING_EFFORTS: tuple[ReasoningEffort, ...] = (
    "none",
    "minimal",
    "low",
    "medium",
    "xhigh",
)


def _reasoning_policy() -> ReasoningPolicyArtifact:
    control = ReasoningControlProfile.build(
        mode="effort",
        effort="high",
        reserved_reasoning_tokens=4_096,
    )
    return ReasoningPolicyArtifact.build(
        controls_by_role={role: control for role in CANONICAL_REASONING_POLICY_ROLES}
    )


def _route_profile_and_constraints() -> tuple[
    RoutePredicateProfile,
    tuple[ExactRouteConstraint, ...],
]:
    profile = seal_authenticated_runner_route_predicate_profile(
        reasoning_policy=_reasoning_policy(),
        minimum_prompt_tokens=65_536,
        required_output_tokens=4_096,
        minimum_context_tokens=73_728,
    )
    constraints = tuple(
        sorted(
            (
                ExactRouteConstraint.build(
                    role=ExactRouteRole.CANDIDATE,
                    exact_model_id=MODEL_A,
                    provider_endpoint=ENDPOINT_A,
                    profile=profile,
                ),
                ExactRouteConstraint.build(
                    role=ExactRouteRole.CANDIDATE,
                    exact_model_id=MODEL_A,
                    provider_endpoint="provider-alpha/alternate",
                    profile=profile,
                ),
                ExactRouteConstraint.build(
                    role=ExactRouteRole.PRIMARY_JUDGE,
                    exact_model_id=MODEL_B,
                    provider_endpoint=ENDPOINT_B,
                    profile=profile,
                ),
                ExactRouteConstraint.build(
                    role=ExactRouteRole.REPLAY_JUDGE,
                    exact_model_id=MODEL_C,
                    provider_endpoint=ENDPOINT_C,
                    profile=profile,
                ),
            ),
            key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
        )
    )
    return profile, constraints


def _constrained_discovery(
    *,
    tmp_path: Path,
    config: AuditConfig,
    plan: CandidateSelectionPlan,
    specs: tuple[fixtures._CandidateSpec, ...],
) -> tuple[OpenRouterModelDiscoveryRunManifest, tuple[OpenRouterModelDiscoveryEvidence, ...]]:
    ordered = tuple(sorted(specs, key=lambda item: item.model_id))
    catalog_payload = {"data": [fixtures._catalog_model(spec) for spec in ordered]}
    zdr_payload = {"data": [fixtures._endpoint(spec) for spec in ordered]}
    payloads = []
    endpoint_payloads: dict[str, dict[str, object]] = {}
    for spec in ordered:
        endpoint_payload: dict[str, object] = {
            "data": {
                "id": spec.model_id,
                "endpoints": [
                    {
                        key: value
                        for key, value in fixtures._endpoint(spec).items()
                        if key != "model_id"
                    }
                ],
            }
        }
        endpoint_payloads[spec.model_id] = endpoint_payload
        profile, constraint = authenticated_runner_route_constraint(
            plan,
            exact_model_id=spec.model_id,
            provider_endpoint=spec.provider_endpoint,
        )
        payloads.append(
            validate_openrouter_constrained_model_discovery(
                exact_model_id=spec.model_id,
                models_payload=catalog_payload,
                single_model_payload={"data": fixtures._catalog_model(spec)},
                configured_provider_endpoints=(spec.provider_endpoint,),
                provider_policy_mode="only",
                endpoint_payload=endpoint_payload,
                require_zdr=config.privacy.require_zdr,
                zdr_payload=zdr_payload,
                route_predicate_profile=profile,
                exact_route_constraint=constraint,
                expected_selection_plan_sha256=plan.plan_sha256,
                reasoning_policy=_reasoning_policy(),
                automatic_fallbacks_allowed=False,
            )
        )
    provenance, evidence = fixtures._issue_real_openrouter_discovery_run(
        run_id="1" * 32,
        retrieved_at=fixtures._NOW,
        client_fingerprint_sha256="a" * 64,
        provider_fingerprint_sha256="b" * 64,
        catalog_snapshot_sha256=fixtures._canonical_hash(catalog_payload),
        zdr_snapshot_sha256=fixtures._canonical_hash(zdr_payload),
        candidate_routes=tuple(
            DiscoveryCandidateRoute(
                exact_model_id=spec.model_id,
                approved_provider_endpoint=spec.provider_endpoint,
            )
            for spec in ordered
        ),
        model_metadata_bindings=tuple(
            fixtures.DiscoveryModelMetadataBinding(
                exact_model_id=payload.exact_model_id,
                canonical_slug=payload.canonical_slug,
                api_query=fixtures.openrouter_model_query(payload.exact_model_id),
                response_snapshot_sha256=fixtures._canonical_hash(
                    {
                        "data": fixtures._catalog_model(
                            next(
                                spec for spec in ordered if spec.model_id == payload.exact_model_id
                            )
                        )
                    }
                ),
                model_metadata_snapshot_sha256=payload.model_metadata_snapshot_sha256,
            )
            for payload in payloads
        ),
        endpoint_metadata_bindings=tuple(
            fixtures.DiscoveryEndpointMetadataBinding(
                exact_model_id=spec.model_id,
                api_query=fixtures.openrouter_endpoint_query(spec.model_id),
                response_snapshot_sha256=fixtures._canonical_hash(endpoint_payloads[spec.model_id]),
            )
            for spec in ordered
        ),
        payloads=tuple(payloads),
        issuer=fixtures._TRUSTED_OPENROUTER_DISCOVERY_ISSUER,
    )
    manifest = fixtures.write_model_discovery_run(tmp_path / "discovery-run", evidence)
    assert manifest.run_provenance == provenance
    return manifest, evidence


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
    profile, constraints = _route_profile_and_constraints()
    assignment = seal_authenticated_runner_selection(
        candidate_model_id=MODEL_A,
        primary_judge_model_id=MODEL_B,
        replay_judge_model_id=MODEL_C,
        route_predicate_profile=profile,
        route_constraints=constraints,
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
    assert schema["properties"]["schema_version"]["const"] == "1.4"
    assignment_schema = schema["$defs"]["AuthenticatedRunnerSelection"]
    assert assignment_schema["properties"]["required_output_mode"]["const"] == (
        "NATIVE_JSON_SCHEMA"
    )
    assert assignment_schema["properties"]["required_supported_parameters"]["minItems"] == 1
    assert assignment_schema["properties"]["required_supported_parameters"]["maxItems"] == 1
    assert assignment_schema["properties"]["required_reasoning_effort"]["const"] == "high"
    assert assignment_schema["properties"]["required_completion_limit_source"]["const"] == (
        "metadata"
    )
    assert "required_completion_limit_source" in assignment_schema["required"]
    assert "route_predicate_profile" in assignment_schema["required"]
    assert "route_constraints" in assignment_schema["required"]
    entry_schema = schema["$defs"]["CandidateSelectionEntry"]
    assert entry_schema["properties"]["exact_model_id"]["pattern"]
    assert "entry_authority" in entry_schema["required"]


def test_committed_selection_plan_is_canonical_and_nonauthorizing() -> None:
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")
    guide = (ROOT / "docs" / "models" / "model_selection.md").read_text(encoding="utf-8")

    assert plan.schema_version == "1.4"
    assert plan.plan_sha256 == "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
    assert plan.plan_sha256 in guide
    assert len(plan.entries) == 12
    assert plan.authenticated_runner_selection is not None
    assert plan.authenticated_runner_selection.distinct_root_lineages_verified is False
    assert plan.authenticated_runner_selection.required_output_mode.value == "NATIVE_JSON_SCHEMA"
    assert plan.authenticated_runner_selection.required_supported_parameters == (
        "structured_outputs",
    )
    assert plan.authenticated_runner_selection.required_reasoning_effort == "high"
    assert plan.authenticated_runner_selection.required_completion_limit_source == "metadata"
    assert plan.authenticated_runner_selection.candidate_model_id == (
        "deepseek/deepseek-v4-pro-0813"
    )
    assert plan.authenticated_runner_selection.primary_judge_model_id == "z-ai/glm-5.2"
    assert plan.authenticated_runner_selection.role_assignment_sha256 == (
        "7d67d43f98484890bf9f184a5bb89fbba25d0408dee65a7174eef5fdf1a75b14"
    )
    assert plan.authenticated_runner_selection.replay_judge_model_id == "moonshotai/kimi-k3"
    assert plan.authenticated_runner_selection.route_predicate_profile.profile_sha256 == (
        "00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82"
    )
    assert len(plan.authenticated_runner_selection.route_predicate_profile.predicate_ids) == 29
    assert len(plan.authenticated_runner_selection.route_constraints) == 4
    assert plan.authenticated_runner_selection.route_predicate_profile.require_singleton_route
    assert not plan.authenticated_runner_selection.route_predicate_profile.allow_automatic_fallbacks
    entries = {entry.exact_model_id: entry for entry in plan.entries}
    assert entries["deepseek/deepseek-v4-pro-0813"].allowed_provider_endpoints == ("parasail/fp8",)
    assert entries["deepseek/deepseek-v4-pro-0813"].entry_sha256 == (
        "da576e8d1835b41be94ea4dab6cd6329ae8c1483b830214d9e05acef44e8617b"
    )
    assert entries["minimax/minimax-m3"].allowed_provider_endpoints == ("coreweave/fp4",)
    assert entries["minimax/minimax-m3"].entry_sha256 == (
        "caf35cf7507cb1f7299dcdcfbc06e405f10d855361f13a4d8dd21c844bc15176"
    )
    assert entries["qwen/qwen3.8-max"].allowed_provider_endpoints == ("alibaba",)
    assert entries["moonshotai/kimi-k3"].allowed_provider_endpoints == (
        "modal/mxfp4",
        "phala",
    )
    assert entries["moonshotai/kimi-k3"].entry_sha256 == (
        "77217b6dca94bc292a13cc5a5ce84c48c68a6bb2e055462db51048013abd3f11"
    )
    assert entries["google/gemma-4-26b-a4b-it"].allowed_provider_endpoints == ("deepinfra/fp8",)
    assert entries["google/gemma-4-26b-a4b-it"].entry_sha256 == (
        "3fd5dce9d53e043546e3b519a82f497f94cc2cd8d34c2d07413f6c0a25ee8a74"
    )
    assert entries["tencent/hy3"].allowed_provider_endpoints == ("novita",)
    assert entries["tencent/hy3"].entry_sha256 == (
        "5ca2c5e02454bf0fed2f25464a9ac5666bba684cb06291437a902b1ddfcb4652"
    )
    assert entries["z-ai/glm-5.2"].allowed_provider_endpoints == ("sail-research/fp8",)
    assert entries["z-ai/glm-5.2"].entry_sha256 == (
        "45f0a3f416a806932e2596ca4f6381e12bbc4901d15c301b22fd5d607a7f55ef"
    )
    assert any("00de61717cb6d61c" in item for item in plan.unresolved_requirements)
    assert any("14ece147138fb5bf" in item for item in plan.unresolved_requirements)
    assert any("5faa33fe1bd5b332" in item for item in plan.unresolved_requirements)
    assert any("5fb3d3091e339b84" in item for item in plan.unresolved_requirements)
    assert all(entry.availability == "UNVERIFIED" for entry in plan.entries)
    assert all(entry.documentary_lineage == "UNCONFIRMED" for entry in plan.entries)


def test_runner_route_constraints_exactly_cover_selected_endpoint_policy() -> None:
    plan = _plan()
    selection = plan.authenticated_runner_selection
    assert selection is not None
    expected = {
        (MODEL_A, ENDPOINT_A),
        (MODEL_A, "provider-alpha/alternate"),
        (MODEL_B, ENDPOINT_B),
        (MODEL_C, ENDPOINT_C),
    }

    observed = {
        (constraint.exact_model_id, constraint.provider_endpoint)
        for constraint in selection.route_constraints
    }
    assert observed == expected
    for model_id, endpoint in expected:
        profile, constraint = authenticated_runner_route_constraint(
            plan,
            exact_model_id=model_id,
            provider_endpoint=endpoint,
        )
        assert profile == selection.route_predicate_profile
        assert constraint.profile_sha256 == profile.profile_sha256

    with pytest.raises(CandidateSelectionError, match="one exact route constraint"):
        authenticated_runner_route_constraint(
            plan,
            exact_model_id=MODEL_A,
            provider_endpoint="provider-alpha/unlisted",
        )


def test_plan_rejects_valid_constraint_outside_selected_endpoint_policy() -> None:
    plan = _plan()
    selection = plan.authenticated_runner_selection
    assert selection is not None
    extra = ExactRouteConstraint.build(
        role=ExactRouteRole.CANDIDATE,
        exact_model_id=MODEL_A,
        provider_endpoint="provider-alpha/unlisted",
        profile=selection.route_predicate_profile,
    )
    changed = seal_authenticated_runner_selection(
        candidate_model_id=selection.candidate_model_id,
        primary_judge_model_id=selection.primary_judge_model_id,
        replay_judge_model_id=selection.replay_judge_model_id,
        route_predicate_profile=selection.route_predicate_profile,
        route_constraints=(*selection.route_constraints, extra),
    )

    with pytest.raises(CandidateSelectionError, match="candidate selection plan is invalid"):
        seal_candidate_selection_plan(
            source_bindings=plan.source_bindings,
            entries=plan.entries,
            authenticated_runner_selection=changed,
            unresolved_requirements=plan.unresolved_requirements,
        )


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


def test_committed_selection_plan_accepts_only_corrected_authrunner_routes() -> None:
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")
    corrected = (
        DiscoveryCandidateRoute(
            exact_model_id="deepseek/deepseek-v4-pro-0813",
            approved_provider_endpoint="parasail/fp8",
        ),
        DiscoveryCandidateRoute(
            exact_model_id="moonshotai/kimi-k3",
            approved_provider_endpoint="modal/mxfp4",
        ),
        DiscoveryCandidateRoute(
            exact_model_id="z-ai/glm-5.2",
            approved_provider_endpoint="sail-research/fp8",
        ),
    )

    assert validate_candidate_selection_routes(plan, routes=corrected) == plan
    assert (
        validate_candidate_selection_routes(
            plan,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id="moonshotai/kimi-k3",
                    approved_provider_endpoint="phala",
                ),
            ),
        )
        == plan
    )
    for model_id, stale_endpoint in (
        ("deepseek/deepseek-v4-pro-0813", "novita/fp8"),
        ("deepseek/deepseek-v4-pro-0813", "novita"),
        ("deepseek/deepseek-v4-pro-0813", "together"),
        ("deepseek/deepseek-v4-pro-0813", "fireworks"),
        ("moonshotai/kimi-k3", "deepinfra/bf16"),
        ("moonshotai/kimi-k3", "together"),
        ("moonshotai/kimi-k3", "wafer"),
        ("z-ai/glm-5.2", "deepinfra/fp4"),
        ("z-ai/glm-5.2", "deepinfra"),
    ):
        with pytest.raises(CandidateSelectionError, match="unlisted endpoint"):
            validate_candidate_selection_routes(
                plan,
                routes=(
                    DiscoveryCandidateRoute(
                        exact_model_id=model_id,
                        approved_provider_endpoint=stale_endpoint,
                    ),
                ),
            )
    assert (
        validate_candidate_selection_routes(
            plan,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id="tencent/hy3",
                    approved_provider_endpoint="novita",
                ),
            ),
        )
        == plan
    )


def test_committed_selection_plan_stays_historical_but_is_revoked_for_current_action() -> None:
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")
    historical_route = (
        DiscoveryCandidateRoute(
            exact_model_id="deepseek/deepseek-v4-pro-0813",
            approved_provider_endpoint="parasail/fp8",
        ),
    )

    assert validate_candidate_selection_routes(plan, routes=historical_route) == plan
    with pytest.raises(CandidateSelectionError, match="candidate selection route is revoked"):
        require_candidate_selection_plan_currently_eligible(plan)


def test_pending_registry_derivation_rejects_revoked_historical_plan(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    manifest, evidence, _template = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id=MODEL_A,
                provider_endpoint=ENDPOINT_A,
                provider_name="Provider Alpha",
            ),
        ),
    )
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")

    with pytest.raises(CandidateSelectionError, match="candidate selection route is revoked"):
        derive_pending_candidate_registry_from_selection_plan(
            plan=plan,
            run_manifest=manifest,
            evidence=evidence,
        )


def test_committed_runner_selection_has_three_documented_independent_roots() -> None:
    plan = load_candidate_selection_plan(ROOT / "config" / "models.selection-plan.json")
    selection = plan.authenticated_runner_selection
    assert selection is not None
    capability = resolve_verified_public_model_lineage()
    selected_ids = (
        selection.candidate_model_id,
        selection.primary_judge_model_id,
        selection.replay_judge_model_id,
    )
    bindings = tuple(
        require_verified_public_model_lineage(capability, exact_model_id)
        for exact_model_id in selected_ids
    )
    assert len({binding.root_lineage for binding in bindings}) == 3
    for left, right in (
        (selected_ids[0], selected_ids[1]),
        (selected_ids[1], selected_ids[0]),
        (selected_ids[0], selected_ids[2]),
        (selected_ids[2], selected_ids[0]),
        (selected_ids[1], selected_ids[2]),
        (selected_ids[2], selected_ids[1]),
    ):
        assert require_independent_public_model_lineage(capability, left, right).independent is True
    assert selection.distinct_root_lineages_verified is False


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
        native_structured_output_parameter="structured_outputs",
        endpoint_reasoning_efforts_published=False,
    )
    plan = _plan()
    manifest, evidence = _constrained_discovery(
        tmp_path=tmp_path,
        config=config,
        plan=plan,
        specs=(spec,),
    )

    registry = derive_pending_candidate_registry_from_selection_plan(
        plan=plan,
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
    assert plan.plan_sha256 in candidate.lineage_review.rationale
    assert candidate.selection_plan_sha256 == plan.plan_sha256
    assert candidate.route_predicate_profile_sha256 == (
        plan.authenticated_runner_selection.route_predicate_profile.profile_sha256
    )
    assert candidate.exact_route_constraint_sha256 is not None
    assert candidate.route_predicate_report_sha256 is not None

    changed_payload = candidate.model_dump(mode="python")
    changed_payload["selection_plan_sha256"] = "f" * 64
    changed_candidate = CandidateModel.model_validate(changed_payload)
    changed_registry = seal_candidate_registry(
        created_at=registry.created_at,
        discovery_run_sha256=registry.discovery_run_sha256,
        candidates=(changed_candidate,),
    )
    with pytest.raises(ValueError, match="route predicate custody"):
        validate_candidate_registry_discovery(
            registry=changed_registry,
            run_manifest=manifest,
            evidence=evidence,
        )


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


@pytest.mark.parametrize(
    "native_parameter",
    (None, "json_schema"),
)
@pytest.mark.parametrize(
    ("model_id", "provider_endpoint"),
    (
        (MODEL_A, ENDPOINT_A),
        (MODEL_B, ENDPOINT_B),
        (MODEL_C, ENDPOINT_C),
    ),
)
def test_selected_runner_route_requires_literal_native_structured_outputs(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    native_parameter: Literal["json_schema"] | None,
    model_id: str,
    provider_endpoint: str,
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        provider_name="Provider Alpha",
        native_structured_output_parameter=native_parameter,
    )
    with pytest.raises(
        ValueError,
        match=r"required structured-output mode|NATIVE_MARKER_MISSING",
    ):
        _constrained_discovery(
            tmp_path=tmp_path,
            config=config,
            plan=_plan(),
            specs=(spec,),
        )


@pytest.mark.parametrize(
    (
        "reasoning_supported",
        "model_reasoning_efforts",
        "endpoint_reasoning_efforts_published",
        "endpoint_reasoning_efforts",
    ),
    (
        (False, None, False, None),
        (True, None, False, None),
        (True, NON_HIGH_REASONING_EFFORTS, False, None),
        (True, HIGH_REASONING_EFFORTS, True, NON_HIGH_REASONING_EFFORTS),
    ),
    ids=(
        "reasoning-parameter-unsupported",
        "effort-inventories-absent",
        "model-inventory-lacks-high",
        "endpoint-inventory-overrides-model-high",
    ),
)
@pytest.mark.parametrize(
    ("model_id", "provider_endpoint"),
    (
        (MODEL_A, ENDPOINT_A),
        (MODEL_B, ENDPOINT_B),
        (MODEL_C, ENDPOINT_C),
    ),
)
def test_selected_runner_route_requires_explicit_high_reasoning_effort(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    reasoning_supported: bool,
    model_reasoning_efforts: tuple[ReasoningEffort, ...] | None,
    endpoint_reasoning_efforts_published: bool,
    endpoint_reasoning_efforts: tuple[ReasoningEffort, ...] | None,
    model_id: str,
    provider_endpoint: str,
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        provider_name="Provider Alpha",
        reasoning_supported=reasoning_supported,
        native_structured_output_parameter="structured_outputs",
        endpoint_reasoning_efforts_published=endpoint_reasoning_efforts_published,
        model_reasoning_efforts=model_reasoning_efforts,
        endpoint_reasoning_efforts=endpoint_reasoning_efforts,
    )
    with pytest.raises(
        ValueError,
        match=(
            r"REASONING_(?:EFFORT|CONTROL)|REASONING_NOT_EMITTED|"
            r"EMITTED_PARAMETER_SUPPORT_MISMATCH"
        ),
    ):
        _constrained_discovery(
            tmp_path=tmp_path,
            config=config,
            plan=_plan(),
            specs=(spec,),
        )


@pytest.mark.parametrize(
    ("model_id", "provider_endpoint"),
    (
        (MODEL_A, ENDPOINT_A),
        (MODEL_B, ENDPOINT_B),
        (MODEL_C, ENDPOINT_C),
    ),
)
def test_selected_runner_route_requires_explicit_metadata_completion_limit(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    model_id: str,
    provider_endpoint: str,
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    spec = fixtures._CandidateSpec(
        model_id=model_id,
        provider_endpoint=provider_endpoint,
        provider_name="Provider Alpha",
        native_structured_output_parameter="structured_outputs",
        endpoint_completion_limit_published=False,
    )
    with pytest.raises(ValueError, match="COMPLETION_CAPACITY_NOT_METADATA"):
        _constrained_discovery(
            tmp_path=tmp_path,
            config=config,
            plan=_plan(),
            specs=(spec,),
        )


def test_non_runner_selection_entry_remains_capability_adaptive(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    base = _plan()
    adaptive_entry = seal_candidate_selection_entry(
        exact_model_id=MODEL_D,
        priority_rank=4,
        advisory_lineage_group="Delta advisory root",
        allowed_provider_endpoints=(ENDPOINT_D,),
    )
    plan = seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=(*base.entries, adaptive_entry),
        authenticated_runner_selection=base.authenticated_runner_selection,
        unresolved_requirements=base.unresolved_requirements,
    )
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    manifest, evidence, _legacy_registry = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id=MODEL_D,
                provider_endpoint=ENDPOINT_D,
                provider_name="Provider Delta",
                reasoning_supported=False,
                endpoint_completion_limit_published=False,
            ),
        ),
    )

    registry = derive_pending_candidate_registry_from_selection_plan(
        plan=plan,
        run_manifest=manifest,
        evidence=evidence,
    )

    assert registry.candidates[0].exact_model_id == MODEL_D
    assert registry.candidates[0].structured_output_supported is True
    assert registry.candidates[0].reasoning_supported is False
    assert registry.candidates[0].output_limit_source == "context_limit"
