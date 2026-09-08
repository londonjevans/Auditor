from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import textwrap
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import pytest

import mmaudit.models.candidate_selection as candidate_selection_module
from mmaudit.config import AuditConfig
from mmaudit.models.candidate_revocation import (
    CandidateSelectionRevocationReason,
    load_candidate_selection_revocation_registry,
    seal_candidate_selection_revocation_entry,
    seal_candidate_selection_revocation_registry,
)
from mmaudit.models.candidate_selection import (
    NO_ACTIVE_CANDIDATE_REQUIREMENT,
    OBJECTIVE_SHA256,
    CandidateSelectionError,
    CandidateSelectionPlan,
    CandidateSelectionUnavailableState,
    authenticated_runner_route_constraint,
    derive_candidate_selection_plan_successor,
    derive_candidate_selection_plan_unavailable_successor,
    derive_pending_candidate_registry_from_selection_plan,
    load_candidate_selection_plan,
    require_candidate_selection_plan_currently_eligible,
    seal_authenticated_runner_route_predicate_profile,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
    seal_candidate_selection_source_binding,
    validate_candidate_selection_discovery_capability,
    validate_candidate_selection_plan_sources,
    validate_candidate_selection_plan_successor,
    validate_candidate_selection_routes,
    write_candidate_selection_plan_successor,
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
    ProviderPriceCapAlgorithm,
    RoutePredicateProfile,
    RoutePriceComponent,
    RoutePriceComponentUnitEnvelope,
)
from mmaudit.orchestration.manifest import canonical_sha256
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
REFRESHED_ENDPOINT_A = "provider-alpha/new-fp8"
ROOT = Path(__file__).parents[2]
ACTIVE_SELECTION_PLAN_PATH = ROOT / "config" / "models.selection-plan.json"
REVOKED_SELECTION_PLAN_PATH = (
    ROOT / "tests" / "fixtures" / "model_selection" / "revoked-active-plan-v1.4.json"
)
REVOKED_SELECTION_PLAN_RAW_SHA256 = (
    "0da03b75dd608efade4c41e87de38139fb735576049f824365889be9c9a3ff24"
)
REVOKED_SELECTION_PLAN_SHA256 = "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
ACTIVE_SELECTION_PLAN_RAW_SHA256 = (
    "4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695"
)
ACTIVE_SELECTION_PLAN_SHA256 = "14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3"
ACTIVE_UNAVAILABLE_STATE_SHA256 = "98941c3253ffe0f1aa88890b1c8b7fafb7d6575ee28ca31cb7724f14e784ceae"
MATCHED_REVOCATION_SET_SHA256 = "7c0118f5c170d46e6d2478bf92cbd83d1be6b426bda36dd57a6fc93e2ffd18c5"
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


def _run_successor_publication_race(script: str) -> None:
    completed = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, (
        f"isolated successor publication regression failed\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
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


def _plan_with_revoked_pinned_candidate() -> CandidateSelectionPlan:
    base = _plan()
    revoked_model_id = "deepseek/deepseek-v4-pro-0813"
    revoked_endpoint = "parasail/fp8"
    entries = (
        *base.entries,
        seal_candidate_selection_entry(
            exact_model_id=revoked_model_id,
            priority_rank=4,
            advisory_lineage_group="Revoked historical advisory root",
            allowed_provider_endpoints=(revoked_endpoint,),
        ),
    )
    selection = base.authenticated_runner_selection
    assert selection is not None
    constraints = tuple(
        sorted(
            (
                ExactRouteConstraint.build(
                    role=ExactRouteRole.CANDIDATE,
                    exact_model_id=revoked_model_id,
                    provider_endpoint=revoked_endpoint,
                    profile=selection.route_predicate_profile,
                ),
                *(
                    constraint
                    for constraint in selection.route_constraints
                    if constraint.role is not ExactRouteRole.CANDIDATE
                ),
            ),
            key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
        )
    )
    assignment = seal_authenticated_runner_selection(
        candidate_model_id=revoked_model_id,
        primary_judge_model_id=selection.primary_judge_model_id,
        replay_judge_model_id=selection.replay_judge_model_id,
        route_predicate_profile=selection.route_predicate_profile,
        route_constraints=constraints,
    )
    return seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=entries,
        authenticated_runner_selection=assignment,
        unresolved_requirements=base.unresolved_requirements,
    )


def _plan_with_candidate_tombstone_identity_for_judge(
    role: ExactRouteRole,
) -> CandidateSelectionPlan:
    assert role in {ExactRouteRole.PRIMARY_JUDGE, ExactRouteRole.REPLAY_JUDGE}
    base = _plan()
    selection = base.authenticated_runner_selection
    assert selection is not None
    model_id = "deepseek/deepseek-v4-pro-0813"
    endpoint = "parasail/fp8"
    constraints = tuple(
        sorted(
            (
                ExactRouteConstraint.build(
                    role=role,
                    exact_model_id=model_id,
                    provider_endpoint=endpoint,
                    profile=selection.route_predicate_profile,
                ),
                *(
                    constraint
                    for constraint in selection.route_constraints
                    if constraint.role is not role
                ),
            ),
            key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
        )
    )
    assignment = seal_authenticated_runner_selection(
        candidate_model_id=selection.candidate_model_id,
        primary_judge_model_id=(
            model_id if role is ExactRouteRole.PRIMARY_JUDGE else selection.primary_judge_model_id
        ),
        replay_judge_model_id=(
            model_id if role is ExactRouteRole.REPLAY_JUDGE else selection.replay_judge_model_id
        ),
        route_predicate_profile=selection.route_predicate_profile,
        route_constraints=constraints,
    )
    return seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=(
            *base.entries,
            seal_candidate_selection_entry(
                exact_model_id=model_id,
                priority_rank=4,
                advisory_lineage_group="Candidate-tombstone identity judge root",
                allowed_provider_endpoints=(endpoint,),
            ),
        ),
        authenticated_runner_selection=assignment,
        unresolved_requirements=base.unresolved_requirements,
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
    assert schema["properties"]["schema_version"]["enum"] == [
        "1.4",
        "1.5",
        "1.6",
        "1.7",
        "1.8",
    ]
    assert "predecessor_plan_sha256" not in required
    assert "endpoint_inventory_refresh" not in required
    assert schema["allOf"] == [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.4"}},
                "required": ["schema_version"],
            },
            "then": {"not": {"required": ["predecessor_plan_sha256"]}},
            "else": {
                "properties": {
                    "predecessor_plan_sha256": {
                        "pattern": r"^[0-9a-f]{64}$",
                        "type": "string",
                    }
                },
                "required": ["predecessor_plan_sha256"],
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.6"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "endpoint_inventory_refresh": {
                        "not": {"type": "null"},
                    }
                },
                "required": ["endpoint_inventory_refresh"],
            },
            "else": {"not": {"required": ["endpoint_inventory_refresh"]}},
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.7"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "authenticated_runner_selection": {"type": "null"},
                    "authenticated_runner_unavailability": {
                        "not": {"type": "null"},
                    },
                },
                "required": ["authenticated_runner_unavailability"],
            },
            "else": {
                "not": {"required": ["authenticated_runner_unavailability"]},
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "1.8"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {
                    "authenticated_runner_selection": {
                        "type": "object",
                        "properties": {
                            "route_predicate_profile": {
                                "type": "object",
                                "properties": {
                                    "schema_version": {"const": "1.0"},
                                    "price_cap_algorithm": {
                                        "const": "MMAUDIT_OPENROUTER_MAX_PRICE_CEILING_V1"
                                    },
                                    "price_component_unit_envelopes": {"type": "null"},
                                },
                                "required": ["schema_version", "price_cap_algorithm"],
                            }
                        },
                        "required": ["route_predicate_profile"],
                    },
                    "ancestry_transition_binding": {"not": {"type": "null"}},
                },
                "required": [
                    "authenticated_runner_selection",
                    "ancestry_transition_binding",
                ],
            },
            "else": {"not": {"required": ["ancestry_transition_binding"]}},
        },
    ]
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
    refresh_schema = schema["$defs"]["CandidateSelectionEndpointInventoryRefresh"]
    assert refresh_schema["properties"]["disposition"]["const"] == ("OPERATOR_STAGED_UNVERIFIED")
    assert refresh_schema["properties"]["constrained_discovery_required"]["const"] is True
    assert refresh_schema["properties"]["provider_metadata_embedded"]["const"] is False
    assert refresh_schema["properties"]["discovery_evidence_embedded"]["const"] is False
    assert refresh_schema["properties"]["endpoint_authority"]["const"] is False
    unavailable_schema = schema["$defs"]["CandidateSelectionUnavailableState"]
    assert unavailable_schema["properties"]["disposition"]["const"] == (
        "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
    )
    assert unavailable_schema["properties"]["price_cap_profile_decision"]["const"] == (
        "PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION"
    )
    assert unavailable_schema["properties"]["candidate_selection_authorized"]["const"] is False
    assert unavailable_schema["properties"]["matched_revocation_set_sha256"]["pattern"] == (
        "^[0-9a-f]{64}$"
    )
    for field_name in (
        "revocation_entry_sha256s",
        "withdrawn_candidate_constraint_sha256s",
    ):
        assert unavailable_schema["properties"][field_name]["items"]["pattern"] == (
            "^[0-9a-f]{64}$"
        )
    ancestry_schema = schema["$defs"]["CandidateSelectionPlanAncestryTransitionBinding"]
    assert ancestry_schema["properties"]["opaque_ancestry_capability_required"]["const"] is True
    assert ancestry_schema["properties"]["endpoint_inventory_refresh_authorized"]["const"] is False
    assert ancestry_schema["properties"]["price_cap_profile_upgrade_authorized"]["const"] is False
    assert ancestry_schema["properties"]["production_selection_authorized"]["const"] is False
    assert ancestry_schema["properties"]["serialized_authority"]["const"] is False


def test_candidate_selection_schema_v16_requires_a_nonnull_endpoint_refresh() -> None:
    schema = CandidateSelectionPlan.model_json_schema()
    refresh_clause = next(
        clause
        for clause in schema["allOf"]
        if clause.get("if", {}).get("properties", {}).get("schema_version", {}).get("const")
        == "1.6"
    )

    assert refresh_clause["then"] == {
        "properties": {
            "endpoint_inventory_refresh": {
                "not": {"type": "null"},
            }
        },
        "required": ["endpoint_inventory_refresh"],
    }
    assert refresh_clause["else"] == {"not": {"required": ["endpoint_inventory_refresh"]}}


def test_candidate_selection_successor_is_deterministic_predecessor_bound_and_nonauthorizing(
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    predecessor_bytes = stable_json(predecessor)
    first = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    second = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )

    assert first == second
    assert first.plan_sha256 == "00708ad6cdfdf4aa8b7e0b6305a94da736a5b31ff4e40cd3b5967e43191e0eb5"
    assert hashlib.sha256(stable_json(first).encode("utf-8")).hexdigest() == (
        "e124c2af7608d8e1284d3b8fa069a9781af2cf49696b3e8538a24008e7febef4"
    )
    assert stable_json(predecessor) == predecessor_bytes
    assert predecessor.schema_version == "1.4"
    assert predecessor.predecessor_plan_sha256 is None
    assert '"predecessor_plan_sha256"' not in predecessor_bytes
    assert first.schema_version == "1.5"
    assert first.predecessor_plan_sha256 == predecessor.plan_sha256
    assert first.plan_sha256 != predecessor.plan_sha256
    assert first.plan_sha256 == canonical_sha256(
        first.model_dump(mode="json", exclude={"plan_sha256"})
    )
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=first,
        )
        == first
    )

    predecessor_selection = predecessor.authenticated_runner_selection
    successor_selection = first.authenticated_runner_selection
    assert predecessor_selection is not None
    assert successor_selection is not None
    assert successor_selection.candidate_model_id == MODEL_A
    assert successor_selection.primary_judge_model_id == (
        predecessor_selection.primary_judge_model_id
    )
    assert successor_selection.replay_judge_model_id == (
        predecessor_selection.replay_judge_model_id
    )
    assert successor_selection.route_predicate_profile == (
        predecessor_selection.route_predicate_profile
    )
    assert tuple(
        constraint
        for constraint in successor_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    ) == tuple(
        constraint
        for constraint in predecessor_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )
    candidate_constraints = tuple(
        constraint
        for constraint in successor_selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    )
    assert len(candidate_constraints) == 1
    assert candidate_constraints[0].exact_model_id == MODEL_A
    assert candidate_constraints[0].provider_endpoint == ENDPOINT_A
    assert candidate_constraints[0].constraint_sha256 == canonical_sha256(
        candidate_constraints[0].model_dump(mode="json", exclude={"constraint_sha256"})
    )
    assert successor_selection.route_predicate_profile.profile_sha256 == canonical_sha256(
        successor_selection.route_predicate_profile.model_dump(
            mode="json",
            exclude={"profile_sha256"},
        )
    )
    successor_entries = {entry.exact_model_id: entry for entry in first.entries}
    assert successor_entries[MODEL_A].allowed_provider_endpoints == (ENDPOINT_A,)
    for entry in first.entries:
        assert entry.entry_sha256 == canonical_sha256(
            entry.model_dump(mode="json", exclude={"entry_sha256"})
        )
    authority_fields = (
        "ranking_executed",
        "cached_ranking_payload_present",
        "provider_metadata_present",
        "discovery_evidence_present",
        "documentary_lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "qualification_authorized",
        "production_selection_authorized",
        "runner_authority_authorized",
        "benchmark_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "serialized_authority",
    )
    assert all(getattr(first, field) is False for field in authority_fields)

    output = tmp_path / "private" / "successor.json"
    written = write_candidate_selection_plan_successor(
        path=output,
        predecessor=predecessor,
        successor=first,
    )
    assert written == first
    assert load_candidate_selection_plan(output) == first
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CandidateSelectionError, match="fresh file"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=first,
        )


def test_successor_explicit_v1_to_v2_rebuilds_profile_and_every_constraint() -> None:
    predecessor = _plan()
    predecessor_bytes = stable_json(predecessor)
    predecessor_selection = predecessor.authenticated_runner_selection
    assert predecessor_selection is not None
    predecessor_profile = predecessor_selection.route_predicate_profile
    predecessor_constraint_hashes = {
        (constraint.role, constraint.exact_model_id, constraint.provider_endpoint): (
            constraint.constraint_sha256
        )
        for constraint in predecessor_selection.route_constraints
    }

    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    repeated = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )

    assert successor == repeated
    assert stable_json(predecessor) == predecessor_bytes
    assert successor.schema_version == "1.5"
    assert successor.predecessor_plan_sha256 == predecessor.plan_sha256
    assert (
        successor.plan_sha256 == "77ed2dd32d89b231af5da1f417f96b162bfbae98d9b899047b275acdd95179db"
    )
    assert hashlib.sha256(stable_json(successor).encode("utf-8")).hexdigest() == (
        "7e2a1d708d41460b81a87edfd2ff62092792b6afebeac89b615bc7f3e9d31920"
    )
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=successor,
        )
        == successor
    )
    selection = successor.authenticated_runner_selection
    assert selection is not None
    profile = selection.route_predicate_profile
    assert predecessor_profile.schema_version == "1.0"
    assert (
        predecessor_profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    )
    assert predecessor_profile.price_component_unit_envelopes is None
    assert profile.schema_version == "1.1"
    assert (
        profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
    )
    assert profile.price_component_unit_envelopes == (
        RoutePriceComponentUnitEnvelope.build_web_search_disabled(),
    )
    envelope = profile.price_component_unit_envelopes[0]
    assert envelope.component is RoutePriceComponent.WEB_SEARCH
    assert envelope.maximum_units == 0
    assert envelope.maximum_cost_usd_exact == "0"
    assert envelope.emitted_request_parameters == (
        "max_tokens",
        "reasoning",
        "response_format",
        "temperature",
    )
    assert envelope.prohibited_request_fields == (
        "plugins",
        "tool_choice",
        "tools",
        "web_search",
        "web_search_options",
    )
    preserved_profile_fields = (
        "reasoning_policy_sha256",
        "reasoning_role_profile_sha256",
        "reasoning_role_binding_sha256",
        "reasoning_control_profile_sha256",
        "reasoning_mode",
        "reasoning_effort",
        "reasoning_max_tokens",
        "reasoning_exclude",
        "reserved_reasoning_tokens",
        "minimum_prompt_tokens",
        "required_output_tokens",
        "required_completion_tokens",
        "minimum_context_tokens",
        "required_completion_limit_source",
    )
    assert all(
        getattr(profile, field) == getattr(predecessor_profile, field)
        for field in preserved_profile_fields
    )
    assert all(
        constraint.profile_sha256 == profile.profile_sha256
        for constraint in selection.route_constraints
    )
    assert all(
        constraint.constraint_sha256
        != predecessor_constraint_hashes[
            (constraint.role, constraint.exact_model_id, constraint.provider_endpoint)
        ]
        for constraint in selection.route_constraints
    )
    assert tuple(
        (constraint.role, constraint.exact_model_id, constraint.provider_endpoint)
        for constraint in selection.route_constraints
    ) == (
        (ExactRouteRole.CANDIDATE, MODEL_A, ENDPOINT_A),
        (ExactRouteRole.PRIMARY_JUDGE, MODEL_B, ENDPOINT_B),
        (ExactRouteRole.REPLAY_JUDGE, MODEL_C, ENDPOINT_C),
    )


def test_successor_v1_to_v2_rebuilds_every_multi_endpoint_judge_constraint() -> None:
    base = _plan_with_revoked_pinned_candidate()
    base_selection = base.authenticated_runner_selection
    assert base_selection is not None
    alternate_judge_endpoint = "provider-beta/alternate"
    predecessor_entries = tuple(
        seal_candidate_selection_entry(
            exact_model_id=entry.exact_model_id,
            priority_rank=entry.priority_rank,
            advisory_lineage_group=entry.advisory_lineage_group,
            allowed_provider_endpoints=(
                (ENDPOINT_B, alternate_judge_endpoint)
                if entry.exact_model_id == MODEL_B
                else entry.allowed_provider_endpoints
            ),
        )
        for entry in base.entries
    )
    predecessor_constraints = (
        *base_selection.route_constraints,
        ExactRouteConstraint.build(
            role=ExactRouteRole.PRIMARY_JUDGE,
            exact_model_id=MODEL_B,
            provider_endpoint=alternate_judge_endpoint,
            profile=base_selection.route_predicate_profile,
        ),
    )
    predecessor = seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=predecessor_entries,
        authenticated_runner_selection=seal_authenticated_runner_selection(
            candidate_model_id=base_selection.candidate_model_id,
            primary_judge_model_id=base_selection.primary_judge_model_id,
            replay_judge_model_id=base_selection.replay_judge_model_id,
            route_predicate_profile=base_selection.route_predicate_profile,
            route_constraints=predecessor_constraints,
        ),
        unresolved_requirements=base.unresolved_requirements,
    )
    predecessor_selection = predecessor.authenticated_runner_selection
    assert predecessor_selection is not None
    predecessor_constraints_by_route = {
        (constraint.role, constraint.exact_model_id, constraint.provider_endpoint): constraint
        for constraint in predecessor_selection.route_constraints
    }

    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )

    selection = successor.authenticated_runner_selection
    assert selection is not None
    profile = selection.route_predicate_profile
    primary_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.PRIMARY_JUDGE
    )
    assert tuple(item.provider_endpoint for item in primary_constraints) == tuple(
        sorted((ENDPOINT_B, alternate_judge_endpoint))
    )
    assert len(selection.route_constraints) == 4
    assert all(
        item.profile_sha256 == profile.profile_sha256 for item in selection.route_constraints
    )
    for constraint in selection.route_constraints:
        predecessor_constraint = predecessor_constraints_by_route.get(
            (constraint.role, constraint.exact_model_id, constraint.provider_endpoint)
        )
        if predecessor_constraint is not None:
            assert constraint.constraint_sha256 != predecessor_constraint.constraint_sha256


def test_successor_explicit_v3_upgrade_fails_closed_without_mutating_v2_predecessor() -> None:
    v1_predecessor = _plan()
    v2_predecessor = derive_candidate_selection_plan_successor(
        predecessor=v1_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    predecessor_bytes = stable_json(v2_predecessor)
    predecessor_selection = v2_predecessor.authenticated_runner_selection
    assert predecessor_selection is not None
    predecessor_profile = predecessor_selection.route_predicate_profile
    assert predecessor_profile.schema_version == "1.1"
    assert (
        predecessor_profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
    )

    for _attempt in range(2):
        with pytest.raises(
            CandidateSelectionError,
            match=(
                "V3 price-cap upgrade is unavailable because provider max_price cannot bind "
                "cache-write pricing"
            ),
        ):
            derive_candidate_selection_plan_successor(
                predecessor=v2_predecessor,
                candidate_model_id=MODEL_A,
                provider_endpoint=ENDPOINT_A,
                upgrade_price_cap_profile_v3=True,
            )

    assert stable_json(v2_predecessor) == predecessor_bytes


@pytest.mark.parametrize("invalid_flag", (0, 1, None, "true"))
def test_successor_rejects_nonboolean_v2_upgrade_flag(invalid_flag: object) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()

    with pytest.raises(CandidateSelectionError, match="wrong exact type"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=invalid_flag,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("invalid_flag", (0, 1, None, "true"))
def test_successor_rejects_nonboolean_v3_upgrade_flag(invalid_flag: object) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()

    with pytest.raises(CandidateSelectionError, match="wrong exact type"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v3=invalid_flag,  # type: ignore[arg-type]
        )


def test_successor_rejects_mutually_exclusive_price_cap_upgrades() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()

    with pytest.raises(CandidateSelectionError, match="mutually exclusive"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=True,
            upgrade_price_cap_profile_v3=True,
        )


def test_successor_v3_derivation_and_validation_are_unconditionally_unavailable() -> None:
    v1_predecessor = _plan_with_revoked_pinned_candidate()
    unavailable = (
        "V3 price-cap upgrade is unavailable because provider max_price cannot bind "
        "cache-write pricing"
    )
    with pytest.raises(CandidateSelectionError, match=unavailable):
        derive_candidate_selection_plan_successor(
            predecessor=v1_predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v3=True,
        )

    v2_predecessor = derive_candidate_selection_plan_successor(
        predecessor=v1_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    v2_selection = v2_predecessor.authenticated_runner_selection
    assert v2_selection is not None
    with pytest.raises(CandidateSelectionError, match=unavailable):
        derive_candidate_selection_plan_successor(
            predecessor=v2_predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v3=True,
        )
    with pytest.raises(CandidateSelectionError, match=unavailable):
        derive_candidate_selection_plan_successor(
            predecessor=v2_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
            upgrade_price_cap_profile_v3=True,
        )

    predecessor_profile = v2_selection.route_predicate_profile
    v3_profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=predecessor_profile.reasoning_policy_sha256,
        reasoning_role_profile_sha256=predecessor_profile.reasoning_role_profile_sha256,
        reasoning_role_binding_sha256=predecessor_profile.reasoning_role_binding_sha256,
        reasoning_control_profile_sha256=predecessor_profile.reasoning_control_profile_sha256,
        reserved_reasoning_tokens=predecessor_profile.reserved_reasoning_tokens,
        minimum_prompt_tokens=predecessor_profile.minimum_prompt_tokens,
        required_output_tokens=predecessor_profile.required_output_tokens,
        minimum_context_tokens=predecessor_profile.minimum_context_tokens,
        price_cap_algorithm=(
            ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_PROMPT_DOMINATED_CACHE_WRITE_V3
        ),
    )
    v3_selection = seal_authenticated_runner_selection(
        candidate_model_id=v2_selection.candidate_model_id,
        primary_judge_model_id=v2_selection.primary_judge_model_id,
        replay_judge_model_id=v2_selection.replay_judge_model_id,
        route_predicate_profile=v3_profile,
        route_constraints=tuple(
            ExactRouteConstraint.build(
                role=constraint.role,
                exact_model_id=constraint.exact_model_id,
                provider_endpoint=constraint.provider_endpoint,
                profile=v3_profile,
            )
            for constraint in v2_selection.route_constraints
        ),
    )
    externally_supplied_v3_successor = candidate_selection_module._seal_candidate_selection_plan(
        source_bindings=v2_predecessor.source_bindings,
        entries=v2_predecessor.entries,
        authenticated_runner_selection=v3_selection,
        authenticated_runner_unavailability=None,
        endpoint_inventory_refresh=None,
        unresolved_requirements=v2_predecessor.unresolved_requirements,
        predecessor_plan_sha256=v2_predecessor.plan_sha256,
    )
    with pytest.raises(CandidateSelectionError, match=unavailable):
        validate_candidate_selection_plan_successor(
            predecessor=v2_predecessor,
            successor=externally_supplied_v3_successor,
        )


def test_successor_rejects_repeat_v2_upgrade_tamper_and_downgrade() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    v2_successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    v2_selection = v2_successor.authenticated_runner_selection
    predecessor_selection = predecessor.authenticated_runner_selection
    assert v2_selection is not None
    assert predecessor_selection is not None

    with pytest.raises(CandidateSelectionError, match="requires an exact V1 predecessor"):
        derive_candidate_selection_plan_successor(
            predecessor=v2_successor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=True,
        )
    with pytest.raises(CandidateSelectionError, match="candidate selection route is revoked"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
            upgrade_price_cap_profile_v2=True,
        )
    predecessor_profile = predecessor_selection.route_predicate_profile
    altered_v2_profile = RoutePredicateProfile.build(
        reasoning_policy_sha256=predecessor_profile.reasoning_policy_sha256,
        reasoning_role_profile_sha256=predecessor_profile.reasoning_role_profile_sha256,
        reasoning_role_binding_sha256=predecessor_profile.reasoning_role_binding_sha256,
        reasoning_control_profile_sha256=predecessor_profile.reasoning_control_profile_sha256,
        reserved_reasoning_tokens=predecessor_profile.reserved_reasoning_tokens,
        minimum_prompt_tokens=predecessor_profile.minimum_prompt_tokens,
        required_output_tokens=predecessor_profile.required_output_tokens,
        minimum_context_tokens=predecessor_profile.minimum_context_tokens + 1,
        price_cap_algorithm=(ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2),
    )

    def rebuild_with_profile(
        plan: CandidateSelectionPlan,
        profile: RoutePredicateProfile,
    ) -> CandidateSelectionPlan:
        selection = plan.authenticated_runner_selection
        assert selection is not None
        rebuilt_selection = seal_authenticated_runner_selection(
            candidate_model_id=selection.candidate_model_id,
            primary_judge_model_id=selection.primary_judge_model_id,
            replay_judge_model_id=selection.replay_judge_model_id,
            route_predicate_profile=profile,
            route_constraints=tuple(
                ExactRouteConstraint.build(
                    role=constraint.role,
                    exact_model_id=constraint.exact_model_id,
                    provider_endpoint=constraint.provider_endpoint,
                    profile=profile,
                )
                for constraint in selection.route_constraints
            ),
        )
        return candidate_selection_module._seal_candidate_selection_plan(
            source_bindings=plan.source_bindings,
            entries=plan.entries,
            authenticated_runner_selection=rebuilt_selection,
            authenticated_runner_unavailability=None,
            endpoint_inventory_refresh=None,
            unresolved_requirements=plan.unresolved_requirements,
            predecessor_plan_sha256=plan.predecessor_plan_sha256,
        )

    altered_v2_successor = rebuild_with_profile(v2_successor, altered_v2_profile)
    with pytest.raises(CandidateSelectionError, match="differs from its derivation"):
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=altered_v2_successor,
        )

    downgraded_successor = rebuild_with_profile(
        candidate_selection_module._seal_candidate_selection_plan(
            source_bindings=v2_successor.source_bindings,
            entries=v2_successor.entries,
            authenticated_runner_selection=v2_selection,
            authenticated_runner_unavailability=None,
            endpoint_inventory_refresh=None,
            unresolved_requirements=v2_successor.unresolved_requirements,
            predecessor_plan_sha256=v2_successor.plan_sha256,
        ),
        predecessor_profile,
    )
    with pytest.raises(CandidateSelectionError, match="profile transition is invalid"):
        validate_candidate_selection_plan_successor(
            predecessor=v2_successor,
            successor=downgraded_successor,
        )


def test_successor_preserves_v2_without_upgrade_during_later_route_change() -> None:
    base = _plan()
    safe_predecessor = seal_candidate_selection_plan(
        source_bindings=base.source_bindings,
        entries=(
            *base.entries,
            seal_candidate_selection_entry(
                exact_model_id=MODEL_D,
                priority_rank=4,
                advisory_lineage_group="Delta advisory root",
                allowed_provider_endpoints=(ENDPOINT_D,),
            ),
        ),
        authenticated_runner_selection=base.authenticated_runner_selection,
        unresolved_requirements=base.unresolved_requirements,
    )
    v2_predecessor = derive_candidate_selection_plan_successor(
        predecessor=safe_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    v2_selection = v2_predecessor.authenticated_runner_selection
    assert v2_selection is not None

    successor = derive_candidate_selection_plan_successor(
        predecessor=v2_predecessor,
        candidate_model_id=MODEL_D,
        provider_endpoint=ENDPOINT_D,
    )

    assert (
        validate_candidate_selection_plan_successor(
            predecessor=v2_predecessor,
            successor=successor,
        )
        == successor
    )
    selection = successor.authenticated_runner_selection
    assert selection is not None
    assert selection.route_predicate_profile == v2_selection.route_predicate_profile
    assert (
        selection.route_predicate_profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
    )
    assert tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    ) == tuple(
        constraint
        for constraint in v2_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )


def test_successor_validation_rejects_predecessor_lookalike_without_method_access() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )

    class PredecessorLookalike:
        model_dump_json_called = False

        def model_dump_json(self) -> str:
            self.model_dump_json_called = True
            raise AssertionError("predecessor lookalike method must not run")

    lookalike = PredecessorLookalike()
    with pytest.raises(CandidateSelectionError, match="predecessor has the wrong exact type"):
        validate_candidate_selection_plan_successor(
            predecessor=lookalike,  # type: ignore[arg-type]
            successor=successor,
        )
    assert lookalike.model_dump_json_called is False


def test_successor_validation_rejects_stateful_exact_predecessor_substitution() -> None:
    supplied_predecessor = derive_candidate_selection_plan_successor(
        predecessor=_plan_with_revoked_pinned_candidate(),
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    substituted_predecessor = derive_candidate_selection_plan_successor(
        predecessor=_plan(),
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    substituted_successor = derive_candidate_selection_plan_successor(
        predecessor=substituted_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
    )
    supplied_json = CandidateSelectionPlan.model_dump_json(supplied_predecessor)
    substituted_json = CandidateSelectionPlan.model_dump_json(substituted_predecessor)
    serializer_calls = 0

    def stateful_model_dump_json(*_args: object, **_kwargs: object) -> str:
        nonlocal serializer_calls
        serializer_calls += 1
        return supplied_json if serializer_calls == 1 else substituted_json

    object.__setattr__(supplied_predecessor, "model_dump_json", stateful_model_dump_json)

    with pytest.raises(CandidateSelectionError, match="differs from its derivation"):
        validate_candidate_selection_plan_successor(
            predecessor=supplied_predecessor,
            successor=substituted_successor,
        )
    assert serializer_calls == 0


def test_candidate_selection_successor_explicitly_stages_unlisted_endpoint_inventory(
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()

    with pytest.raises(CandidateSelectionError, match="uses an unlisted endpoint"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=REFRESHED_ENDPOINT_A,
        )
    with pytest.raises(CandidateSelectionError, match="previously unlisted"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            refresh_endpoint_inventory=True,
        )

    first = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
    )
    second = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
    )
    v2_refreshed = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
        upgrade_price_cap_profile_v2=True,
    )

    assert first == second
    assert v2_refreshed.schema_version == "1.6"
    assert v2_refreshed.endpoint_inventory_refresh is not None
    assert v2_refreshed.authenticated_runner_selection is not None
    assert v2_refreshed.authenticated_runner_selection.route_predicate_profile.schema_version == (
        "1.1"
    )
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=v2_refreshed,
        )
        == v2_refreshed
    )
    assert first.schema_version == "1.6"
    assert first.predecessor_plan_sha256 == predecessor.plan_sha256
    assert first.endpoint_inventory_refresh is not None
    refresh = first.endpoint_inventory_refresh
    predecessor_entry = next(
        entry for entry in predecessor.entries if entry.exact_model_id == MODEL_A
    )
    assert refresh.exact_model_id == MODEL_A
    assert refresh.predecessor_entry_sha256 == predecessor_entry.entry_sha256
    assert (
        refresh.predecessor_allowed_provider_endpoints
        == predecessor_entry.allowed_provider_endpoints
    )
    assert refresh.provider_endpoint == REFRESHED_ENDPOINT_A
    assert refresh.disposition == "OPERATOR_STAGED_UNVERIFIED"
    assert refresh.constrained_discovery_required is True
    assert refresh.provider_metadata_embedded is False
    assert refresh.discovery_evidence_embedded is False
    assert refresh.endpoint_authority is False
    assert refresh.refresh_sha256 == canonical_sha256(
        refresh.model_dump(mode="json", exclude={"refresh_sha256"})
    )
    assert first.plan_sha256 == canonical_sha256(
        first.model_dump(mode="json", exclude={"plan_sha256"})
    )
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=first,
        )
        == first
    )

    predecessor_selection = predecessor.authenticated_runner_selection
    successor_selection = first.authenticated_runner_selection
    assert predecessor_selection is not None
    assert successor_selection is not None
    assert tuple(
        constraint
        for constraint in successor_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    ) == tuple(
        constraint
        for constraint in predecessor_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )
    entries = {entry.exact_model_id: entry for entry in first.entries}
    assert entries[MODEL_A].allowed_provider_endpoints == (REFRESHED_ENDPOINT_A,)
    assert first.source_bindings == predecessor.source_bindings
    authority_fields = (
        "ranking_executed",
        "cached_ranking_payload_present",
        "provider_metadata_present",
        "discovery_evidence_present",
        "documentary_lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "qualification_authorized",
        "production_selection_authorized",
        "runner_authority_authorized",
        "benchmark_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "serialized_authority",
    )
    assert all(getattr(first, field) is False for field in authority_fields)

    output = tmp_path / "private" / "refreshed-successor.json"
    assert (
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=first,
        )
        == first
    )
    assert load_candidate_selection_plan(output) == first


def test_successor_writer_rejects_parent_identity_swap_and_removes_exact_output() -> None:
    _run_successor_publication_race(
        """
        import os
        import sys
        import tempfile
        from pathlib import Path

        from mmaudit.models.candidate_selection import (
            CandidateSelectionError,
            derive_candidate_selection_plan_successor,
            write_candidate_selection_plan_successor,
        )
        from tests.unit.test_candidate_selection import (
            ENDPOINT_A,
            MODEL_A,
            _plan_with_revoked_pinned_candidate,
        )

        predecessor = _plan_with_revoked_pinned_candidate()
        successor = derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
        )
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            root = Path(temporary)
            parent = root / "private-parent"
            parent.mkdir(mode=0o700)
            moved_parent = root / "moved-parent"
            output = parent / "successor.json"
            state = {"fired": False}

            def swap_parent_on_publication(event, _arguments):
                if event != "os.link" or state["fired"]:
                    return
                state["fired"] = True
                parent.rename(moved_parent)
                parent.symlink_to(moved_parent, target_is_directory=True)

            sys.addaudithook(swap_parent_on_publication)
            failure = None
            try:
                write_candidate_selection_plan_successor(
                    path=output,
                    predecessor=predecessor,
                    successor=successor,
                )
            except (CandidateSelectionError, OSError) as exc:
                failure = exc
            else:
                raise AssertionError("parent replacement was accepted")

            assert state["fired"], repr(failure)
            assert not os.path.lexists(output)
            assert not os.path.lexists(moved_parent / output.name)
        """
    )


def test_successor_writer_cleanup_removes_exact_output_when_temp_unlink_is_raced() -> None:
    _run_successor_publication_race(
        """
        import os
        import sys
        import tempfile
        from pathlib import Path

        from mmaudit.models.candidate_selection import (
            CandidateSelectionError,
            derive_candidate_selection_plan_successor,
            write_candidate_selection_plan_successor,
        )
        from tests.unit.test_candidate_selection import (
            ENDPOINT_A,
            MODEL_A,
            _plan_with_revoked_pinned_candidate,
        )

        predecessor = _plan_with_revoked_pinned_candidate()
        successor = derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
        )
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            parent = Path(temporary) / "private-parent"
            parent.mkdir(mode=0o700)
            output = parent / "successor.json"
            state = {"fired": False}

            def replace_temp_on_unlink(event, arguments):
                if event != "os.remove" or state["fired"]:
                    return
                name = os.fsdecode(arguments[0])
                if not name.startswith(".mmaudit-selection-successor-"):
                    return
                state["fired"] = True
                directory_descriptor = arguments[1]
                os.unlink(name, dir_fd=directory_descriptor)
                os.mkdir(name, mode=0o700, dir_fd=directory_descriptor)

            sys.addaudithook(replace_temp_on_unlink)
            failure = None
            try:
                write_candidate_selection_plan_successor(
                    path=output,
                    predecessor=predecessor,
                    successor=successor,
                )
            except (CandidateSelectionError, OSError) as exc:
                failure = exc
            else:
                raise AssertionError("temporary-name replacement was accepted")

            assert state["fired"], repr(failure)
            assert not os.path.lexists(output)
            assert not any(item.is_file() for item in parent.iterdir())
        """
    )


def test_successor_writer_cleanup_continues_after_first_exact_unlink_is_interrupted() -> None:
    _run_successor_publication_race(
        """
        import os
        import sys
        import tempfile
        from pathlib import Path

        from mmaudit.models.candidate_selection import (
            CandidateSelectionError,
            derive_candidate_selection_plan_successor,
            write_candidate_selection_plan_successor,
        )
        from tests.unit.test_candidate_selection import (
            ENDPOINT_A,
            MODEL_A,
            _plan_with_revoked_pinned_candidate,
        )

        predecessor = _plan_with_revoked_pinned_candidate()
        successor = derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
        )
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temporary:
            parent = Path(temporary) / "private-parent"
            parent.mkdir(mode=0o700)
            output = parent / "successor.json"
            state = {"temp_raced": False, "cleanup_interrupted": False}

            def interrupt_first_cleanup(event, arguments):
                if event != "os.remove":
                    return
                name = os.fsdecode(arguments[0])
                directory_descriptor = arguments[1]
                if (
                    name.startswith(".mmaudit-selection-successor-")
                    and not state["temp_raced"]
                ):
                    state["temp_raced"] = True
                    os.unlink(name, dir_fd=directory_descriptor)
                    os.mkdir(name, mode=0o700, dir_fd=directory_descriptor)
                    return
                if name == output.name and not state["cleanup_interrupted"]:
                    state["cleanup_interrupted"] = True
                    raise RuntimeError("synthetic cleanup interruption")

            sys.addaudithook(interrupt_first_cleanup)
            try:
                write_candidate_selection_plan_successor(
                    path=output,
                    predecessor=predecessor,
                    successor=successor,
                )
            except (CandidateSelectionError, OSError):
                pass
            else:
                raise AssertionError("interrupted exact-output cleanup was accepted")

            assert state == {"temp_raced": True, "cleanup_interrupted": True}
            assert not os.path.lexists(output)
            assert not any(item.is_file() for item in parent.iterdir())
        """
    )


def test_successor_writer_rejects_nonprivate_output_parent(tmp_path: Path) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    parent = tmp_path / "shared-parent"
    parent.mkdir()
    parent.chmod(0o770)
    output = parent / "successor.json"

    with pytest.raises(CandidateSelectionError, match="parent must be private and owned"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )

    assert not output.exists()
    assert tuple(parent.iterdir()) == ()


def test_candidate_selection_successor_rejects_revoked_noop_unlisted_and_judge_routes() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    with pytest.raises(CandidateSelectionError, match="must change the candidate route"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    with pytest.raises(CandidateSelectionError, match="unlisted endpoint"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint="provider-alpha/unlisted",
        )
    with pytest.raises(CandidateSelectionError, match="collide with a judge"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_B,
            provider_endpoint=ENDPOINT_B,
        )

    valid = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    with pytest.raises(CandidateSelectionError, match="candidate selection plan is not currently"):
        derive_candidate_selection_plan_successor(
            predecessor=valid,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )


def test_historical_successor_validation_is_separate_from_current_revocation(
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )

    assert (
        validate_candidate_selection_plan_successor(
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
        == historical_revoked_successor
    )
    with pytest.raises(CandidateSelectionError, match="candidate selection plan is not currently"):
        require_candidate_selection_plan_currently_eligible(historical_revoked_successor)
    output = tmp_path / "revoked-successor.json"
    with pytest.raises(CandidateSelectionError, match="candidate selection plan is not currently"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
    assert not output.exists()


def test_successor_derivation_and_write_reject_eligibility_gate_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "require_candidate_selection_plan_currently_eligible",
        lambda plan: plan,
    )

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    output = tmp_path / "revocation-gate-replaced.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
    assert not output.exists()


def test_successor_derivation_and_write_reject_eligibility_gate_code_mutation(
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )

    def bypass_eligibility(plan: CandidateSelectionPlan) -> CandidateSelectionPlan:
        return plan

    eligibility_gate = (
        candidate_selection_module._require_candidate_selection_plan_currently_eligible_checked
    )
    original_code = eligibility_gate.__code__
    eligibility_gate.__code__ = bypass_eligibility.__code__
    try:
        with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
            derive_candidate_selection_plan_successor(
                predecessor=eligible_predecessor,
                candidate_model_id="deepseek/deepseek-v4-pro-0813",
                provider_endpoint="parasail/fp8",
            )
        output = tmp_path / "revocation-gate-code-mutated.json"
        with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
            write_candidate_selection_plan_successor(
                path=output,
                predecessor=eligible_predecessor,
                successor=historical_revoked_successor,
            )
        assert not output.exists()
    finally:
        eligibility_gate.__code__ = original_code


def test_successor_rejects_coherent_derivation_root_and_kwdefault_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )

    def bypass_derivation(**_kwargs: Any) -> CandidateSelectionPlan:
        return historical_revoked_successor

    def bypass_eligibility(plan: CandidateSelectionPlan) -> CandidateSelectionPlan:
        return plan

    successor_pristine = (
        candidate_selection_module._candidate_selection_successor_dependencies_are_pristine
    )
    route_pristine = candidate_selection_module.route_constraint_callables_are_pristine
    replacement_roots = (
        bypass_derivation,
        bypass_derivation.__code__,
        bypass_eligibility,
        bypass_eligibility.__code__,
        successor_pristine,
        successor_pristine.__code__,
        route_pristine,
        route_pristine.__code__,
    )
    derivation_defaults = (
        candidate_selection_module._derive_candidate_selection_plan_successor_checked.__kwdefaults__
    )
    assert derivation_defaults is not None
    monkeypatch.setattr(
        candidate_selection_module,
        "_derive_candidate_selection_plan_successor_unchecked",
        bypass_derivation,
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "_require_candidate_selection_plan_currently_eligible_checked",
        bypass_eligibility,
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "_CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS",
        replacement_roots,
    )
    monkeypatch.setitem(derivation_defaults, "_successor_call_roots", replacement_roots)

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )


def test_successor_rejects_coherent_revocation_root_and_kwdefault_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )

    def bypass_pristine() -> bool:
        return True

    def bypass_revocation(*_args: Any, **_kwargs: Any) -> None:
        return None

    replacement_roots = (bypass_pristine, bypass_revocation, bypass_revocation)
    eligibility_defaults = candidate_selection_module._require_candidate_selection_plan_currently_eligible_checked.__kwdefaults__
    assert eligibility_defaults is not None
    monkeypatch.setattr(
        candidate_selection_module,
        "_CANDIDATE_REVOCATION_CALL_ROOTS",
        replacement_roots,
    )
    monkeypatch.setitem(
        eligibility_defaults,
        "_candidate_revocation_call_roots",
        replacement_roots,
    )
    for module in (
        candidate_selection_module,
        candidate_selection_module.candidate_revocation_module,
    ):
        monkeypatch.setattr(
            module,
            "candidate_revocation_callables_are_pristine",
            bypass_pristine,
        )
        monkeypatch.setattr(
            module,
            "require_candidate_assignment_eligible",
            bypass_revocation,
        )
        monkeypatch.setattr(
            module,
            "require_selection_plan_routes_eligible",
            bypass_revocation,
        )

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        require_candidate_selection_plan_currently_eligible(historical_revoked_successor)
    output = tmp_path / "coherent-revocation-root.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
    assert not output.exists()


def test_successor_writer_has_no_injectable_root_and_rejects_public_gate_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    assert write_candidate_selection_plan_successor.__kwdefaults__ is None
    assert not hasattr(
        candidate_selection_module,
        "_CANDIDATE_SELECTION_SUCCESSOR_WRITE_CALL_ROOTS",
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "validate_candidate_selection_plan_successor",
        lambda **_kwargs: successor,
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "require_candidate_selection_plan_currently_eligible",
        lambda plan: plan,
    )
    monkeypatch.setattr(
        candidate_selection_module,
        "preflight_candidate_selection_plan_successor_output",
        lambda path: path,
    )

    output = tmp_path / "uncreated-parent" / "replaced-public-gates.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.parent.exists()


def test_successor_writer_rejects_private_mode_global_mutation_before_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    monkeypatch.setattr(candidate_selection_module, "_PRIVATE_FILE_MODE", 0o666)
    output = tmp_path / "mode-mutated.json"

    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()
    assert tuple(tmp_path.iterdir()) == ()


def test_successor_writer_rejects_link_guard_replacement_before_symlink_traversal(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    real_target = tmp_path / "real-target"
    real_target.mkdir()
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_target, target_is_directory=True)
    monkeypatch.setattr(
        candidate_selection_module,
        "_reject_candidate_selection_output_links",
        lambda _path: None,
    )
    output = linked_parent / "through-link.json"

    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()
    assert not (real_target / output.name).exists()


def test_successor_writer_rejects_concrete_path_getattribute_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    real_target = tmp_path / "real-path-target"
    real_target.mkdir()
    linked_parent = tmp_path / "path-lookup-link"
    linked_parent.symlink_to(real_target, target_is_directory=True)
    concrete_path_type = type(Path("."))
    original_getattribute = concrete_path_type.__getattribute__

    def hiding_path_getattribute(self: Any, name: str) -> Any:
        if name in {"is_junction", "is_symlink"}:
            return lambda: False
        return original_getattribute(self, name)

    monkeypatch.setattr(
        concrete_path_type,
        "__getattribute__",
        hiding_path_getattribute,
        raising=False,
    )
    output = linked_parent / "through-path-lookup.json"

    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()
    assert not (real_target / output.name).exists()


def test_successor_rejects_inherited_base_model_getattribute_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )
    base_model_type = candidate_selection_module.BaseModel
    original_getattribute = base_model_type.__getattribute__

    def hiding_assignment_getattribute(self: Any, name: str) -> Any:
        if type(self) is CandidateSelectionPlan and name == "authenticated_runner_selection":
            return None
        return original_getattribute(self, name)

    monkeypatch.setattr(
        base_model_type,
        "__getattribute__",
        hiding_assignment_getattribute,
    )

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        require_candidate_selection_plan_currently_eligible(historical_revoked_successor)
    output = tmp_path / "base-model-lookup-mutated.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
    assert not output.exists()


def test_successor_rejects_stateful_candidate_selection_model_dump_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    revoked_predecessor = _plan_with_revoked_pinned_candidate()
    eligible_predecessor = derive_candidate_selection_plan_successor(
        predecessor=revoked_predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    historical_revoked_successor = (
        candidate_selection_module._derive_candidate_selection_plan_successor_unchecked(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    )
    original_model_dump = CandidateSelectionPlan.model_dump
    call_count = 0

    def stateful_model_dump(
        self: CandidateSelectionPlan,
        *args: Any,
        **kwargs: Any,
    ) -> dict[str, Any]:
        nonlocal call_count
        payload = original_model_dump(self, *args, **kwargs)
        call_count += 1
        if call_count == 1:
            payload["authenticated_runner_selection"] = None
            payload["plan_sha256"] = canonical_sha256(
                {key: value for key, value in payload.items() if key != "plan_sha256"}
            )
        return payload

    monkeypatch.setattr(CandidateSelectionPlan, "model_dump", stateful_model_dump)

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=eligible_predecessor,
            candidate_model_id="deepseek/deepseek-v4-pro-0813",
            provider_endpoint="parasail/fp8",
        )
    output = tmp_path / "stateful-model-dump.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=eligible_predecessor,
            successor=historical_revoked_successor,
        )
    assert call_count == 0
    assert not output.exists()


def test_successor_rejects_swapped_judge_sealer_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    original_sealer = candidate_selection_module.seal_authenticated_runner_selection

    def swapped_judge_sealer(
        *,
        candidate_model_id: str,
        primary_judge_model_id: str,
        replay_judge_model_id: str,
        route_predicate_profile: RoutePredicateProfile,
        route_constraints: tuple[ExactRouteConstraint, ...],
    ) -> candidate_selection_module.AuthenticatedRunnerSelection:
        swapped_constraints = tuple(
            ExactRouteConstraint.build(
                role=(
                    ExactRouteRole.REPLAY_JUDGE
                    if constraint.role is ExactRouteRole.PRIMARY_JUDGE
                    else ExactRouteRole.PRIMARY_JUDGE
                    if constraint.role is ExactRouteRole.REPLAY_JUDGE
                    else constraint.role
                ),
                exact_model_id=constraint.exact_model_id,
                provider_endpoint=constraint.provider_endpoint,
                profile=route_predicate_profile,
            )
            for constraint in route_constraints
        )
        return original_sealer(
            candidate_model_id=candidate_model_id,
            primary_judge_model_id=replay_judge_model_id,
            replay_judge_model_id=primary_judge_model_id,
            route_predicate_profile=route_predicate_profile,
            route_constraints=swapped_constraints,
        )

    monkeypatch.setattr(
        candidate_selection_module,
        "seal_authenticated_runner_selection",
        swapped_judge_sealer,
    )

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
        )
    output = tmp_path / "swapped-judges.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()


@pytest.mark.parametrize("guarded_type", (RoutePredicateProfile, ExactRouteConstraint))
def test_successor_rejects_inherited_route_model_serialization_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    guarded_type: type[RoutePredicateProfile] | type[ExactRouteConstraint],
) -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    original_model_dump_json = guarded_type.model_dump_json

    def replacement_model_dump_json(self: Any, *args: Any, **kwargs: Any) -> str:
        return original_model_dump_json(self, *args, **kwargs)

    monkeypatch.setattr(guarded_type, "model_dump_json", replacement_model_dump_json)

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
        )
    output = tmp_path / f"{guarded_type.__name__}-serialization-override.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()


@pytest.mark.parametrize("guarded_type", (RoutePredicateProfile, ExactRouteConstraint))
def test_v2_successor_rejects_route_builder_replacement_before_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    guarded_type: type[RoutePredicateProfile] | type[ExactRouteConstraint],
) -> None:
    predecessor = _plan()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    original_build = guarded_type.build

    def replacement_build(*args: Any, **kwargs: Any) -> Any:
        return original_build(*args, **kwargs)

    monkeypatch.setattr(guarded_type, "build", replacement_build)

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=True,
        )
    output = tmp_path / f"{guarded_type.__name__}-builder-replaced.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()


def test_v2_successor_rejects_price_algorithm_alias_replacement_before_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    monkeypatch.setattr(candidate_selection_module, "ProviderPriceCapAlgorithm", object())

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=True,
        )
    output = tmp_path / "price-algorithm-alias-replaced.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()


@pytest.mark.parametrize(
    "function_name",
    (
        "derive_candidate_selection_plan_successor",
        "_derive_candidate_selection_plan_successor_checked",
        "_derive_candidate_selection_plan_successor_unchecked",
    ),
)
@pytest.mark.parametrize(
    "upgrade_flag",
    ("upgrade_price_cap_profile_v2", "upgrade_price_cap_profile_v3"),
)
def test_successor_rejects_upgrade_default_mutation_before_output(
    function_name: str,
    upgrade_flag: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    predecessor = _plan()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
        upgrade_price_cap_profile_v2=True,
    )
    function = getattr(candidate_selection_module, function_name)
    defaults = function.__kwdefaults__
    assert defaults is not None
    assert defaults[upgrade_flag] is False
    monkeypatch.setitem(defaults, upgrade_flag, True)

    with pytest.raises(CandidateSelectionError, match="successor call boundary changed"):
        derive_candidate_selection_plan_successor(
            predecessor=predecessor,
            candidate_model_id=MODEL_A,
            provider_endpoint=ENDPOINT_A,
            upgrade_price_cap_profile_v2=False,
        )
    output = tmp_path / f"{function_name}-default-mutated.json"
    with pytest.raises(CandidateSelectionError, match="successor write boundary changed"):
        write_candidate_selection_plan_successor(
            path=output,
            predecessor=predecessor,
            successor=successor,
        )
    assert not output.exists()


def test_candidate_selection_successor_rejects_raw_and_coherently_resealed_chain_tamper() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    raw_tamper = successor.model_dump(mode="json")
    raw_tamper["predecessor_plan_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="self-hash"):
        CandidateSelectionPlan.model_validate_json(json.dumps(raw_tamper), strict=True)

    resealed = successor.model_dump(mode="json")
    resealed["predecessor_plan_sha256"] = "f" * 64
    resealed["plan_sha256"] = canonical_sha256(
        {key: value for key, value in resealed.items() if key != "plan_sha256"}
    )
    structurally_valid = CandidateSelectionPlan.model_validate_json(
        json.dumps(resealed),
        strict=True,
    )
    with pytest.raises(CandidateSelectionError, match="differs from its derivation"):
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=structurally_valid,
        )


def test_endpoint_inventory_refresh_rejects_raw_and_coherently_resealed_custody_tamper() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
    )

    raw_tamper = successor.model_dump(mode="json")
    raw_refresh = raw_tamper["endpoint_inventory_refresh"]
    assert isinstance(raw_refresh, dict)
    raw_refresh["predecessor_entry_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="refresh self-hash"):
        CandidateSelectionPlan.model_validate_json(json.dumps(raw_tamper), strict=True)

    resealed = successor.model_dump(mode="json")
    resealed_refresh = resealed["endpoint_inventory_refresh"]
    assert isinstance(resealed_refresh, dict)
    resealed_refresh["predecessor_entry_sha256"] = "f" * 64
    resealed_refresh["predecessor_allowed_provider_endpoints"] = ["provider-alpha/stale"]
    resealed_refresh["refresh_sha256"] = canonical_sha256(
        {key: value for key, value in resealed_refresh.items() if key != "refresh_sha256"}
    )
    resealed["plan_sha256"] = canonical_sha256(
        {key: value for key, value in resealed.items() if key != "plan_sha256"}
    )
    structurally_valid = CandidateSelectionPlan.model_validate_json(
        json.dumps(resealed),
        strict=True,
    )
    with pytest.raises(CandidateSelectionError, match="differs from its derivation"):
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=structurally_valid,
        )


def test_candidate_selection_schema_versions_require_exact_predecessor_custody() -> None:
    predecessor = _plan_with_revoked_pinned_candidate()
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )
    invalid_root = predecessor.model_dump(mode="json")
    invalid_root["predecessor_plan_sha256"] = "f" * 64
    invalid_root["plan_sha256"] = canonical_sha256(
        {key: value for key, value in invalid_root.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="predecessor custody"):
        CandidateSelectionPlan.model_validate_json(json.dumps(invalid_root), strict=True)

    explicit_null_root = predecessor.model_dump(mode="json")
    explicit_null_root["predecessor_plan_sha256"] = None
    with pytest.raises(ValueError, match="predecessor custody"):
        CandidateSelectionPlan.model_validate_json(json.dumps(explicit_null_root), strict=True)

    invalid_successor = successor.model_dump(mode="json")
    invalid_successor.pop("predecessor_plan_sha256")
    invalid_successor["plan_sha256"] = canonical_sha256(
        {key: value for key, value in invalid_successor.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="predecessor custody"):
        CandidateSelectionPlan.model_validate_json(json.dumps(invalid_successor), strict=True)

    refreshed = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=REFRESHED_ENDPOINT_A,
        refresh_endpoint_inventory=True,
    )
    missing_refresh = refreshed.model_dump(mode="json")
    missing_refresh.pop("endpoint_inventory_refresh")
    missing_refresh["plan_sha256"] = canonical_sha256(
        {key: value for key, value in missing_refresh.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="endpoint refresh"):
        CandidateSelectionPlan.model_validate_json(json.dumps(missing_refresh), strict=True)

    refresh_on_v15 = refreshed.model_dump(mode="json")
    refresh_on_v15["schema_version"] = "1.5"
    refresh_on_v15["plan_sha256"] = canonical_sha256(
        {key: value for key, value in refresh_on_v15.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="endpoint refresh"):
        CandidateSelectionPlan.model_validate_json(json.dumps(refresh_on_v15), strict=True)


def test_committed_selection_plan_is_canonical_and_nonauthorizing() -> None:
    plan = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)
    predecessor = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    guide = (ROOT / "docs" / "models" / "model_selection.md").read_text(encoding="utf-8")

    assert plan.schema_version == "1.7"
    assert plan.predecessor_plan_sha256 == REVOKED_SELECTION_PLAN_SHA256
    assert plan.plan_sha256 == ACTIVE_SELECTION_PLAN_SHA256
    assert len(plan.entries) == 12
    assert plan.source_bindings == predecessor.source_bindings
    assert plan.entries == predecessor.entries
    assert plan.authenticated_runner_selection is None
    unavailable = plan.authenticated_runner_unavailability
    predecessor_selection = predecessor.authenticated_runner_selection
    assert type(unavailable) is CandidateSelectionUnavailableState
    assert predecessor_selection is not None
    assert unavailable.disposition == "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
    assert unavailable.price_cap_profile_decision == ("PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION")
    assert unavailable.predecessor_role_assignment_sha256 == (
        "7d67d43f98484890bf9f184a5bb89fbba25d0408dee65a7174eef5fdf1a75b14"
    )
    assert unavailable.matched_revocation_set_sha256 == MATCHED_REVOCATION_SET_SHA256
    assert unavailable.revocation_entry_sha256s == (
        "67eb2be8bb4d51d8223c2893736c0adeea60bd73d7671ee22f39cc6f4dee6ec4",
    )
    assert unavailable.withdrawn_candidate_constraint_sha256s == (
        "126a1553cb4fbc96c642d803edacadd4879f41dbfbd69e53b0e4d19d4674763a",
    )
    assert unavailable.primary_judge_model_id == "z-ai/glm-5.2"
    assert unavailable.replay_judge_model_id == "moonshotai/kimi-k3"
    assert unavailable.route_predicate_profile == predecessor_selection.route_predicate_profile
    assert unavailable.route_predicate_profile.profile_sha256 == (
        "00b33f3eff0ee7ac7710253c34786ce0a041ffe881baa4015dce0ed4f4b7ce82"
    )
    assert unavailable.route_predicate_profile.schema_version == "1.0"
    assert (
        unavailable.route_predicate_profile.price_cap_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
    )
    assert unavailable.route_predicate_profile.price_component_unit_envelopes is None
    assert unavailable.judge_route_constraints == tuple(
        constraint
        for constraint in predecessor_selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )
    assert tuple(
        constraint.constraint_sha256 for constraint in unavailable.judge_route_constraints
    ) == (
        "f0177706981e7cc78994b8fc6d1ed34e170b6ee637e88ad12d1d94976d0ed6ad",
        "ffc54dc13eea0d92c06a1c6f29e0ae679eac5328d05ae8899e8cd7899b1eb199",
        "2a820c3b85936bc24cc1b0d007415d39e8e8bfd3b4eacb072a321e904e8a5912",
    )
    assert len(unavailable.route_predicate_profile.predicate_ids) == 29
    assert unavailable.route_predicate_profile.require_singleton_route
    assert not unavailable.route_predicate_profile.allow_automatic_fallbacks
    assert unavailable.candidate_selection_authorized is False
    assert unavailable.state_sha256 == ACTIVE_UNAVAILABLE_STATE_SHA256
    assert unavailable.state_sha256 == canonical_sha256(
        unavailable.model_dump(mode="json", exclude={"state_sha256"})
    )
    assert NO_ACTIVE_CANDIDATE_REQUIREMENT in plan.unresolved_requirements
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
    assert plan.plan_sha256 == canonical_sha256(
        plan.model_dump(mode="json", exclude={"plan_sha256"})
    )
    for field_name in (
        "ranking_executed",
        "cached_ranking_payload_present",
        "provider_metadata_present",
        "discovery_evidence_present",
        "documentary_lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "qualification_authorized",
        "production_selection_authorized",
        "runner_authority_authorized",
        "benchmark_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "serialized_authority",
    ):
        assert getattr(plan, field_name) is False
    assert plan.plan_sha256 in guide
    assert predecessor.plan_sha256 in guide


def test_unavailable_successor_is_deterministic_and_replays_the_committed_bytes() -> None:
    predecessor_bytes = REVOKED_SELECTION_PLAN_PATH.read_bytes()
    predecessor = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    committed_bytes = ACTIVE_SELECTION_PLAN_PATH.read_bytes()
    committed = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)

    first = derive_candidate_selection_plan_unavailable_successor(predecessor=predecessor)
    second = derive_candidate_selection_plan_unavailable_successor(predecessor=predecessor)

    assert first == second == committed
    assert (
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=first,
        )
        == first
    )
    assert REVOKED_SELECTION_PLAN_PATH.stat().st_size == 14_918
    assert hashlib.sha256(predecessor_bytes).hexdigest() == REVOKED_SELECTION_PLAN_RAW_SHA256
    assert predecessor.plan_sha256 == REVOKED_SELECTION_PLAN_SHA256
    assert stable_json(predecessor).encode("utf-8") == predecessor_bytes
    assert stable_json(first).encode("utf-8") == committed_bytes
    assert len(committed_bytes) == 15_163
    assert hashlib.sha256(committed_bytes).hexdigest() == ACTIVE_SELECTION_PLAN_RAW_SHA256
    assert committed.plan_sha256 == ACTIVE_SELECTION_PLAN_SHA256
    assert predecessor_bytes == REVOKED_SELECTION_PLAN_PATH.read_bytes()


def test_unavailable_successor_requires_complete_exact_revocation_custody() -> None:
    unrevoked = _plan()
    resealed_old_route = _plan_with_revoked_pinned_candidate()

    for predecessor in (unrevoked, resealed_old_route):
        with pytest.raises(
            CandidateSelectionError,
            match="complete exact revocation custody",
        ):
            derive_candidate_selection_plan_unavailable_successor(predecessor=predecessor)


def test_unavailable_state_replay_ignores_unrelated_future_revocation_entries() -> None:
    predecessor = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    selection = predecessor.authenticated_runner_selection
    assert selection is not None
    registry = load_candidate_selection_revocation_registry()
    matching_entry = registry.entries[0]
    unrelated_entry = seal_candidate_selection_revocation_entry(
        selection_plan_sha256="a" * 64,
        role=ExactRouteRole.CANDIDATE,
        exact_model_id="synthetic/unrelated-candidate",
        canonical_model_slug="synthetic/unrelated-candidate",
        provider_endpoint="synthetic-provider",
        exact_route_constraint_sha256="b" * 64,
        effective_at=datetime(2026, 9, 4, tzinfo=UTC),
        reason=CandidateSelectionRevocationReason.EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE,
    )
    expanded_registry = seal_candidate_selection_revocation_registry(
        entries=(*registry.entries, unrelated_entry)
    )

    original = candidate_selection_module._seal_candidate_selection_unavailable_state(
        predecessor_selection=selection,
        revocation_registry=registry,
        revocation_entries=(matching_entry,),
    )
    after_unrelated_append = candidate_selection_module._seal_candidate_selection_unavailable_state(
        predecessor_selection=selection,
        revocation_registry=expanded_registry,
        revocation_entries=(matching_entry,),
    )

    assert expanded_registry.registry_sha256 != registry.registry_sha256
    assert after_unrelated_append == original
    assert original.matched_revocation_set_sha256 == MATCHED_REVOCATION_SET_SHA256


def test_unavailable_successor_rejects_routes_and_cannot_be_used_as_a_profile() -> None:
    plan = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)

    for model_id, provider_endpoint in (
        ("deepseek/deepseek-v4-pro-0813", "parasail/fp8"),
        ("tencent/hy3", "novita"),
        ("z-ai/glm-5.2", "sail-research/fp8"),
    ):
        with pytest.raises(
            CandidateSelectionError,
            match="NO_ACTIVE_CANDIDATE_AFTER_REVOCATION",
        ):
            validate_candidate_selection_routes(
                plan,
                routes=(
                    DiscoveryCandidateRoute(
                        exact_model_id=model_id,
                        approved_provider_endpoint=provider_endpoint,
                    ),
                ),
            )
        with pytest.raises(
            CandidateSelectionError,
            match="NO_ACTIVE_CANDIDATE_AFTER_REVOCATION",
        ):
            authenticated_runner_route_constraint(
                plan,
                exact_model_id=model_id,
                provider_endpoint=provider_endpoint,
            )


def test_unavailable_successor_blocks_discovery_and_registry_derivation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    plan = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    manifest, evidence, _template = fixtures._discovery_and_registry(
        tmp_path=tmp_path,
        config=config,
        specs=(
            fixtures._CandidateSpec(
                model_id="tencent/hy3",
                provider_endpoint="novita",
                provider_name="Synthetic Novita",
            ),
        ),
    )

    with pytest.raises(
        CandidateSelectionError,
        match="NO_ACTIVE_CANDIDATE_AFTER_REVOCATION",
    ):
        validate_candidate_selection_discovery_capability(plan, evidence=evidence[0])
    with pytest.raises(
        CandidateSelectionError,
        match="NO_ACTIVE_CANDIDATE_AFTER_REVOCATION",
    ):
        derive_pending_candidate_registry_from_selection_plan(
            plan=plan,
            run_manifest=manifest,
            evidence=evidence,
        )


def test_unavailable_successor_refuses_reactivation_without_authenticated_ancestry() -> None:
    inactive = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)
    unavailable = inactive.authenticated_runner_unavailability
    assert unavailable is not None
    forged_payload = inactive.model_dump(mode="json")
    forged_unavailable = forged_payload["authenticated_runner_unavailability"]
    assert isinstance(forged_unavailable, dict)
    forged_unavailable["predecessor_role_assignment_sha256"] = "f" * 64
    forged_unavailable["state_sha256"] = canonical_sha256(
        {key: value for key, value in forged_unavailable.items() if key != "state_sha256"}
    )
    forged_payload["plan_sha256"] = canonical_sha256(
        {key: value for key, value in forged_payload.items() if key != "plan_sha256"}
    )
    forged = CandidateSelectionPlan.model_validate_json(
        json.dumps(forged_payload),
        strict=True,
    )

    for predecessor in (inactive, forged):
        for model_id, provider_endpoint in (
            ("tencent/hy3", "novita"),
            ("deepseek/deepseek-v4-pro-0813", "parasail/fp8"),
        ):
            with pytest.raises(
                CandidateSelectionError,
                match="separately authenticated ancestry transition",
            ):
                derive_candidate_selection_plan_successor(
                    predecessor=predecessor,
                    candidate_model_id=model_id,
                    provider_endpoint=provider_endpoint,
                )


def test_selected_private_plan_cannot_claim_unavailable_plan_as_authenticated_predecessor() -> None:
    archived = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    inactive = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)
    selected = derive_candidate_selection_plan_successor(
        predecessor=archived,
        candidate_model_id="tencent/hy3",
        provider_endpoint="novita",
    )
    claimed = selected.model_dump(mode="json")
    claimed["predecessor_plan_sha256"] = inactive.plan_sha256
    claimed["plan_sha256"] = canonical_sha256(
        {key: value for key, value in claimed.items() if key != "plan_sha256"}
    )
    structurally_valid = CandidateSelectionPlan.model_validate_json(
        json.dumps(claimed),
        strict=True,
    )

    assert require_candidate_selection_plan_currently_eligible(structurally_valid) == (
        structurally_valid
    )
    assert (
        validate_candidate_selection_routes(
            structurally_valid,
            routes=(
                DiscoveryCandidateRoute(
                    exact_model_id="tencent/hy3",
                    approved_provider_endpoint="novita",
                ),
            ),
        )
        == structurally_valid
    )
    with pytest.raises(
        CandidateSelectionError,
        match="separately authenticated ancestry transition",
    ):
        validate_candidate_selection_plan_successor(
            predecessor=inactive,
            successor=structurally_valid,
        )


def test_unavailable_successor_rejects_state_tamper_and_candidate_resurrection() -> None:
    predecessor = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    successor = load_candidate_selection_plan(ACTIVE_SELECTION_PLAN_PATH)

    raw_hash_tamper = successor.model_dump(mode="json")
    raw_unavailable = raw_hash_tamper["authenticated_runner_unavailability"]
    assert isinstance(raw_unavailable, dict)
    raw_unavailable["predecessor_role_assignment_sha256"] = "f" * 64
    with pytest.raises(ValueError, match="state self-hash"):
        CandidateSelectionPlan.model_validate_json(json.dumps(raw_hash_tamper), strict=True)

    invalid_matched_set = successor.model_dump(mode="json")
    invalid_matched_unavailable = invalid_matched_set["authenticated_runner_unavailability"]
    assert isinstance(invalid_matched_unavailable, dict)
    invalid_matched_unavailable["matched_revocation_set_sha256"] = "0" * 64
    invalid_matched_unavailable["state_sha256"] = canonical_sha256(
        {key: value for key, value in invalid_matched_unavailable.items() if key != "state_sha256"}
    )
    invalid_matched_set["plan_sha256"] = canonical_sha256(
        {key: value for key, value in invalid_matched_set.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="matched revocation set digest is inconsistent"):
        CandidateSelectionPlan.model_validate_json(json.dumps(invalid_matched_set), strict=True)

    for field_name in (
        "revocation_entry_sha256s",
        "withdrawn_candidate_constraint_sha256s",
    ):
        malformed_hash = successor.model_dump(mode="json")
        malformed_unavailable = malformed_hash["authenticated_runner_unavailability"]
        assert isinstance(malformed_unavailable, dict)
        malformed_unavailable[field_name] = ["not-a-sha256"]
        malformed_unavailable["state_sha256"] = canonical_sha256(
            {key: value for key, value in malformed_unavailable.items() if key != "state_sha256"}
        )
        malformed_hash["plan_sha256"] = canonical_sha256(
            {key: value for key, value in malformed_hash.items() if key != "plan_sha256"}
        )
        with pytest.raises(ValueError, match="String should match pattern"):
            CandidateSelectionPlan.model_validate_json(json.dumps(malformed_hash), strict=True)

    coherent_tamper = successor.model_dump(mode="json")
    coherent_unavailable = coherent_tamper["authenticated_runner_unavailability"]
    assert isinstance(coherent_unavailable, dict)
    coherent_unavailable["predecessor_role_assignment_sha256"] = "f" * 64
    coherent_unavailable["state_sha256"] = canonical_sha256(
        {key: value for key, value in coherent_unavailable.items() if key != "state_sha256"}
    )
    coherent_tamper["plan_sha256"] = canonical_sha256(
        {key: value for key, value in coherent_tamper.items() if key != "plan_sha256"}
    )
    structurally_valid = CandidateSelectionPlan.model_validate_json(
        json.dumps(coherent_tamper),
        strict=True,
    )
    with pytest.raises(CandidateSelectionError, match="differs from its derivation"):
        validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=structurally_valid,
        )

    resurrected_selection = predecessor.authenticated_runner_selection
    assert resurrected_selection is not None
    dual_state = successor.model_dump(mode="json")
    dual_state["authenticated_runner_selection"] = resurrected_selection.model_dump(mode="json")
    dual_state["plan_sha256"] = canonical_sha256(
        {key: value for key, value in dual_state.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="unavailability differs from its schema"):
        CandidateSelectionPlan.model_validate_json(json.dumps(dual_state), strict=True)

    missing_state = successor.model_dump(mode="json")
    missing_state.pop("authenticated_runner_unavailability")
    missing_state["plan_sha256"] = canonical_sha256(
        {key: value for key, value in missing_state.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="unavailability differs from its schema"):
        CandidateSelectionPlan.model_validate_json(json.dumps(missing_state), strict=True)

    relabelled_state = successor.model_dump(mode="json")
    relabelled_state["schema_version"] = "1.5"
    relabelled_state["plan_sha256"] = canonical_sha256(
        {key: value for key, value in relabelled_state.items() if key != "plan_sha256"}
    )
    with pytest.raises(ValueError, match="unavailability differs from its schema"):
        CandidateSelectionPlan.model_validate_json(json.dumps(relabelled_state), strict=True)

    candidate_in_judge_archive = successor.model_dump(mode="json")
    candidate_archive = candidate_in_judge_archive["authenticated_runner_unavailability"]
    assert isinstance(candidate_archive, dict)
    predecessor_payload = predecessor.model_dump(mode="json")
    predecessor_assignment = predecessor_payload["authenticated_runner_selection"]
    assert isinstance(predecessor_assignment, dict)
    predecessor_constraints = predecessor_assignment["route_constraints"]
    assert isinstance(predecessor_constraints, list)
    candidate_constraint = next(
        constraint for constraint in predecessor_constraints if constraint["role"] == "candidate"
    )
    archived_constraints = candidate_archive["judge_route_constraints"]
    assert isinstance(archived_constraints, list)
    candidate_archive["judge_route_constraints"] = sorted(
        (*archived_constraints, candidate_constraint),
        key=lambda item: (item["role"], item["exact_model_id"], item["provider_endpoint"]),
    )
    with pytest.raises(ValueError, match="retain both judge roles only"):
        CandidateSelectionPlan.model_validate_json(
            json.dumps(candidate_in_judge_archive),
            strict=True,
        )


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


def test_archived_selection_plan_accepts_only_its_historical_authrunner_routes() -> None:
    plan = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
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


def test_archived_selection_plan_stays_historical_but_is_revoked_for_current_action() -> None:
    plan = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
    historical_route = (
        DiscoveryCandidateRoute(
            exact_model_id="deepseek/deepseek-v4-pro-0813",
            approved_provider_endpoint="parasail/fp8",
        ),
    )

    assert validate_candidate_selection_routes(plan, routes=historical_route) == plan
    with pytest.raises(CandidateSelectionError, match="candidate selection route is revoked"):
        require_candidate_selection_plan_currently_eligible(plan)


def test_pending_registry_derivation_admits_unrevoked_assignment_from_stale_plan(
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
    plan = _plan_with_revoked_pinned_candidate()

    registry = derive_pending_candidate_registry_from_selection_plan(
        plan=plan,
        run_manifest=manifest,
        evidence=evidence,
    )

    assert tuple(candidate.exact_model_id for candidate in registry.candidates) == (MODEL_A,)
    assert registry.candidates[0].approved_roles == ()


def test_predecessor_constrained_evidence_remains_historical_under_successor(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    predecessor = _plan_with_revoked_pinned_candidate()
    _manifest, evidence = _constrained_discovery(
        tmp_path=tmp_path,
        config=config,
        plan=predecessor,
        specs=(
            fixtures._CandidateSpec(
                model_id="deepseek/deepseek-v4-pro-0813",
                canonical_model_id="deepseek/deepseek-v4-pro-20260813",
                provider_endpoint="parasail/fp8",
                provider_name="Synthetic Parasail",
                native_structured_output_parameter="structured_outputs",
            ),
        ),
    )
    frozen_evidence_bytes = stable_json(evidence[0])
    successor = derive_candidate_selection_plan_successor(
        predecessor=predecessor,
        candidate_model_id=MODEL_A,
        provider_endpoint=ENDPOINT_A,
    )

    assert (
        validate_candidate_selection_discovery_capability(
            predecessor,
            evidence=evidence[0],
        )
        == predecessor
    )
    with pytest.raises(CandidateSelectionError, match="unexpected route custody"):
        validate_candidate_selection_discovery_capability(
            successor,
            evidence=evidence[0],
        )
    assert stable_json(evidence[0]) == frozen_evidence_bytes
    assert (
        evidence[0].endpoint_snapshot.normalized_route_facts.expected_selection_plan_sha256
        == predecessor.plan_sha256
    )


@pytest.mark.parametrize(
    "role",
    (ExactRouteRole.PRIMARY_JUDGE, ExactRouteRole.REPLAY_JUDGE),
)
def test_pending_registry_derivation_preserves_exact_judge_role_isolation(
    tmp_path: Path,
    config_factory: Callable[..., AuditConfig],
    role: ExactRouteRole,
) -> None:
    config = config_factory(privacy={"profile": PrivacyProfile.SYNTHETIC_BENCHMARK})
    plan = _plan_with_candidate_tombstone_identity_for_judge(role)
    manifest, evidence = _constrained_discovery(
        tmp_path=tmp_path / role.value,
        config=config,
        plan=plan,
        specs=(
            fixtures._CandidateSpec(
                model_id="deepseek/deepseek-v4-pro-0813",
                canonical_model_id="deepseek/deepseek-v4-pro-20260813",
                provider_endpoint="parasail/fp8",
                provider_name="Synthetic Parasail",
                native_structured_output_parameter="structured_outputs",
            ),
        ),
    )

    registry = derive_pending_candidate_registry_from_selection_plan(
        plan=plan,
        run_manifest=manifest,
        evidence=evidence,
    )

    assert tuple(item.exact_model_id for item in registry.candidates) == (
        "deepseek/deepseek-v4-pro-0813",
    )


def test_archived_runner_selection_has_three_documented_independent_roots() -> None:
    plan = load_candidate_selection_plan(REVOKED_SELECTION_PLAN_PATH)
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
