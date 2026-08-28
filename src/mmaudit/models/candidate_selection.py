"""Nonauthorizing model-selection seeds for fresh candidate discovery.

This module deliberately cannot construct provider or lineage authority.  A plan only
narrows which exact model/endpoint pairs an operator may ask the existing discovery
transport to observe.  Every registry runtime field is copied from fresh discovery
evidence, and every resulting lineage decision remains rootless and pending.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, field_validator, model_validator

import mmaudit.models.candidate_revocation as candidate_revocation_module
from mmaudit.models.candidate_revocation import (
    CandidateSelectionRevocationError,
    candidate_revocation_callables_are_pristine,
    require_candidate_assignment_eligible,
    require_selection_plan_routes_eligible,
)
from mmaudit.models.discovery import (
    DiscoveryCandidateRoute,
    OpenRouterModelDiscoveryEvidence,
    OpenRouterModelDiscoveryPayload,
    OpenRouterModelDiscoveryRunManifest,
    require_openrouter_constrained_discovery_publication,
)
from mmaudit.models.identifiers import EXACT_MODEL_ID_PATTERN, require_exact_openrouter_model_id
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.models.qualification import (
    CandidateBenchmarkStatus,
    CandidateModel,
    CandidateOperationalStatus,
    CandidateRegistry,
    LineageReviewStatus,
    seal_candidate_registry,
    seal_operator_lineage_review,
    validate_candidate_registry_discovery,
)
from mmaudit.models.reasoning import ReasoningEffort, ReasoningPolicyArtifact
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    RouteConstraintPurpose,
    RoutePredicateProfile,
    bind_registry_route_facts,
    evaluate_route_predicates,
    require_route_predicates,
)
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_SAFE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_ADVISORY_GROUP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,199}$"
_MAX_PLAN_BYTES = 2_000_000
_MAX_SOURCE_BYTES = 2_000_000
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK_FLAG = getattr(os, "O_NONBLOCK", 0)
type _CandidateRevocationCallRoots = tuple[
    Callable[[], bool],
    Callable[..., None],
    Callable[..., None],
]
_CANDIDATE_REVOCATION_CALL_ROOTS: _CandidateRevocationCallRoots = (
    candidate_revocation_callables_are_pristine,
    require_candidate_assignment_eligible,
    require_selection_plan_routes_eligible,
)


class CandidateSelectionError(ValueError):
    """Raised when a nonauthorizing selection seed is invalid."""


class CandidateSelectionSourceBinding(StrictModel):
    """Exact bytes for one operator-staged, explicitly unverified input."""

    kind: Literal["MODEL_RANKING_IMPLEMENTATION", "OPERATOR_LINEAGE_REVIEW"]
    filename: str = Field(pattern=_SAFE_NAME_PATTERN)
    byte_count: int = Field(ge=1, le=_MAX_SOURCE_BYTES)
    content_sha256: str = Field(pattern=_SHA256_PATTERN)
    authenticity: Literal["OPERATOR_STAGED_UNVERIFIED"]
    source_binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def binding_is_self_hashed(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"source_binding_sha256"}))
        if self.source_binding_sha256 != expected:
            raise ValueError("candidate selection source binding self-hash is inconsistent")
        return self


class CandidateSelectionEntry(StrictModel):
    """One exact candidate proposal with no discovery or lineage authority."""

    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    priority_rank: int = Field(ge=1, le=128)
    advisory_lineage_group: str = Field(pattern=_ADVISORY_GROUP_PATTERN)
    lineage_group_seed_sha256: str = Field(pattern=_SHA256_PATTERN)
    allowed_provider_endpoints: tuple[str, ...] = Field(min_length=1, max_length=16)
    approved_roles: tuple[str, ...] = Field(max_length=0)
    availability: Literal["UNVERIFIED"]
    documentary_lineage: Literal["UNCONFIRMED"]
    entry_authority: Literal[False]
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        try:
            require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("candidate selection model ID must be exact") from exc
        return value

    @field_validator("allowed_provider_endpoints")
    @classmethod
    def endpoints_are_exact_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("candidate selection endpoints must be unique and sorted")
        if any(re.fullmatch(_ENDPOINT_PATTERN, endpoint) is None for endpoint in value):
            raise ValueError("candidate selection endpoint is not canonical")
        return value

    @model_validator(mode="after")
    def advisory_hashes_are_consistent(self) -> Self:
        expected_group = canonical_sha256(
            {
                "advisory_lineage_group": self.advisory_lineage_group,
                "authority": False,
            }
        )
        if self.lineage_group_seed_sha256 != expected_group:
            raise ValueError("candidate lineage group seed hash is inconsistent")
        expected_entry = canonical_sha256(self.model_dump(mode="json", exclude={"entry_sha256"}))
        if self.entry_sha256 != expected_entry:
            raise ValueError("candidate selection entry self-hash is inconsistent")
        return self


class AuthenticatedRunnerSelection(StrictModel):
    """Planning-only three-model role assignment; independence is not asserted."""

    candidate_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    primary_judge_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    replay_judge_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    required_output_mode: Literal[StructuredOutputMode.NATIVE_JSON_SCHEMA]
    required_supported_parameters: tuple[Literal["structured_outputs"], ...] = Field(
        min_length=1,
        max_length=1,
    )
    required_reasoning_effort: Literal["high"]
    required_completion_limit_source: Literal["metadata"]
    route_predicate_profile: RoutePredicateProfile
    route_constraints: tuple[ExactRouteConstraint, ...] = Field(min_length=3, max_length=18)
    distinct_root_lineages_verified: Literal[False]
    role_assignment_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "candidate_model_id",
        "primary_judge_model_id",
        "replay_judge_model_id",
    )
    @classmethod
    def role_model_id_is_exact(cls, value: str) -> str:
        try:
            require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("authenticated runner seed model ID must be exact") from exc
        return value

    @model_validator(mode="after")
    def assignment_is_distinct_and_self_hashed(self) -> Self:
        model_ids = (
            self.candidate_model_id,
            self.primary_judge_model_id,
            self.replay_judge_model_id,
        )
        if len(set(model_ids)) != len(model_ids):
            raise ValueError("authenticated runner seed model IDs must be distinct")
        if self.required_supported_parameters != ("structured_outputs",):
            raise ValueError("authenticated runner seed must require native structured outputs")
        if self.required_output_mode is not StructuredOutputMode.NATIVE_JSON_SCHEMA:
            raise ValueError("authenticated runner seed must require native JSON Schema")
        if self.required_reasoning_effort != "high":
            raise ValueError("authenticated runner seed must require reasoning effort=high")
        if self.required_completion_limit_source != "metadata":
            raise ValueError(
                "authenticated runner seed must require an explicit metadata completion limit"
            )
        profile = RoutePredicateProfile.model_validate_json(
            self.route_predicate_profile.model_dump_json(),
            strict=True,
        )
        role_models = {
            ExactRouteRole.CANDIDATE: self.candidate_model_id,
            ExactRouteRole.PRIMARY_JUDGE: self.primary_judge_model_id,
            ExactRouteRole.REPLAY_JUDGE: self.replay_judge_model_id,
        }
        expected_order = tuple(
            sorted(
                self.route_constraints,
                key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
            )
        )
        if self.route_constraints != expected_order:
            raise ValueError("authenticated runner route constraints are not canonically ordered")
        keys = tuple(
            (item.role, item.exact_model_id, item.provider_endpoint)
            for item in self.route_constraints
        )
        if len(keys) != len(set(keys)):
            raise ValueError("authenticated runner route constraints are not unique")
        observed_roles = {item.role for item in self.route_constraints}
        if observed_roles != set(role_models):
            raise ValueError("authenticated runner route constraints do not cover every role")
        if any(
            item.profile_sha256 != profile.profile_sha256
            or item.exact_model_id != role_models[item.role]
            for item in self.route_constraints
        ):
            raise ValueError(
                "authenticated runner route constraint differs from its role or profile"
            )
        if (
            self.required_output_mode is not profile.required_output_mode
            or self.required_supported_parameters != (profile.native_capability_marker,)
            or self.required_reasoning_effort != profile.reasoning_effort
            or self.required_completion_limit_source != profile.required_completion_limit_source
        ):
            raise ValueError("authenticated runner legacy requirements differ from its profile")
        expected = canonical_sha256(
            self.model_dump(mode="json", exclude={"role_assignment_sha256"})
        )
        if self.role_assignment_sha256 != expected:
            raise ValueError("authenticated runner role assignment self-hash is inconsistent")
        return self


class CandidateSelectionPlan(StrictModel):
    """Self-hashed operator-staged seed with only literal-false authority flags."""

    schema_version: Literal["1.4"]
    artifact_kind: Literal["OPERATOR_STAGED_MODEL_SELECTION"]
    status: Literal["NONAUTHORIZING"]
    objective_sha256: Literal["e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"]
    source_bindings: tuple[CandidateSelectionSourceBinding, ...] = Field(
        min_length=2,
        max_length=2,
    )
    entries: tuple[CandidateSelectionEntry, ...] = Field(min_length=1, max_length=64)
    authenticated_runner_selection: AuthenticatedRunnerSelection | None = None
    unresolved_requirements: tuple[str, ...] = Field(max_length=64)
    ranking_executed: Literal[False]
    cached_ranking_payload_present: Literal[False]
    provider_metadata_present: Literal[False]
    discovery_evidence_present: Literal[False]
    documentary_lineage_identity_authorized: Literal[False]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    benchmark_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    serialized_authority: Literal[False]
    plan_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("unresolved_requirements")
    @classmethod
    def unresolved_requirements_are_sorted(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError(
                "candidate selection unresolved requirements must be unique and sorted"
            )
        if any(not item or len(item.encode("utf-8")) > 1_000 for item in value):
            raise ValueError("candidate selection unresolved requirement is not bounded")
        return value

    @model_validator(mode="after")
    def inventory_and_hash_are_consistent(self) -> Self:
        if self.objective_sha256 != OBJECTIVE_SHA256:
            raise ValueError("candidate selection plan binds the wrong objective")
        kinds = tuple(binding.kind for binding in self.source_bindings)
        expected_kinds = ("MODEL_RANKING_IMPLEMENTATION", "OPERATOR_LINEAGE_REVIEW")
        if kinds != expected_kinds:
            raise ValueError("candidate selection sources must be exact and canonically ordered")
        if (
            len({binding.filename for binding in self.source_bindings}) != 2
            or len({binding.content_sha256 for binding in self.source_bindings}) != 2
        ):
            raise ValueError("candidate selection sources must be distinct files and bytes")
        model_ids = tuple(entry.exact_model_id for entry in self.entries)
        if model_ids != tuple(sorted(set(model_ids))):
            raise ValueError("candidate selection entries must be unique and sorted by exact ID")
        ranks = tuple(entry.priority_rank for entry in self.entries)
        if tuple(sorted(ranks)) != tuple(range(1, len(self.entries) + 1)):
            raise ValueError("candidate selection priority ranks must be contiguous and unique")
        if self.authenticated_runner_selection is not None:
            selection = self.authenticated_runner_selection
            selected = {
                selection.candidate_model_id,
                selection.primary_judge_model_id,
                selection.replay_judge_model_id,
            }
            if not selected.issubset(set(model_ids)):
                raise ValueError("authenticated runner seed is outside the candidate selection")
            entries_by_id = {entry.exact_model_id: entry for entry in self.entries}
            constraint_endpoints_by_model: dict[str, set[str]] = {
                model_id: set() for model_id in selected
            }
            for constraint in selection.route_constraints:
                constraint_endpoints_by_model[constraint.exact_model_id].add(
                    constraint.provider_endpoint
                )
            if any(
                constraint_endpoints_by_model[model_id]
                != set(entries_by_id[model_id].allowed_provider_endpoints)
                for model_id in selected
            ):
                raise ValueError(
                    "authenticated runner route constraints differ from selected endpoint policy"
                )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"plan_sha256"}))
        if self.plan_sha256 != expected:
            raise ValueError("candidate selection plan self-hash is inconsistent")
        return self


def seal_candidate_selection_source_binding(
    *,
    kind: Literal["MODEL_RANKING_IMPLEMENTATION", "OPERATOR_LINEAGE_REVIEW"],
    filename: str,
    content: bytes,
) -> CandidateSelectionSourceBinding:
    if not isinstance(content, bytes) or not 1 <= len(content) <= _MAX_SOURCE_BYTES:
        raise CandidateSelectionError("candidate selection source bytes are empty or oversized")
    values: dict[str, object] = {
        "kind": kind,
        "filename": filename,
        "byte_count": len(content),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "authenticity": "OPERATOR_STAGED_UNVERIFIED",
    }
    values["source_binding_sha256"] = canonical_sha256(values)
    try:
        return CandidateSelectionSourceBinding.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection source binding is invalid") from exc


def seal_candidate_selection_entry(
    *,
    exact_model_id: str,
    priority_rank: int,
    advisory_lineage_group: str,
    allowed_provider_endpoints: tuple[str, ...],
) -> CandidateSelectionEntry:
    group_hash = canonical_sha256(
        {"advisory_lineage_group": advisory_lineage_group, "authority": False}
    )
    values: dict[str, object] = {
        "exact_model_id": exact_model_id,
        "priority_rank": priority_rank,
        "advisory_lineage_group": advisory_lineage_group,
        "lineage_group_seed_sha256": group_hash,
        "allowed_provider_endpoints": list(sorted(allowed_provider_endpoints)),
        "approved_roles": [],
        "availability": "UNVERIFIED",
        "documentary_lineage": "UNCONFIRMED",
        "entry_authority": False,
    }
    values["entry_sha256"] = canonical_sha256(values)
    try:
        return CandidateSelectionEntry.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection entry is invalid") from exc


def seal_authenticated_runner_selection(
    *,
    candidate_model_id: str,
    primary_judge_model_id: str,
    replay_judge_model_id: str,
    route_predicate_profile: RoutePredicateProfile,
    route_constraints: tuple[ExactRouteConstraint, ...],
) -> AuthenticatedRunnerSelection:
    profile = RoutePredicateProfile.model_validate_json(
        route_predicate_profile.model_dump_json(),
        strict=True,
    )
    ordered_constraints = tuple(
        sorted(
            (
                ExactRouteConstraint.model_validate_json(item.model_dump_json(), strict=True)
                for item in route_constraints
            ),
            key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
        )
    )
    values: dict[str, object] = {
        "candidate_model_id": candidate_model_id,
        "primary_judge_model_id": primary_judge_model_id,
        "replay_judge_model_id": replay_judge_model_id,
        "required_output_mode": profile.required_output_mode.value,
        "required_supported_parameters": (profile.native_capability_marker,),
        "required_reasoning_effort": profile.reasoning_effort,
        "required_completion_limit_source": profile.required_completion_limit_source,
        "route_predicate_profile": profile,
        "route_constraints": ordered_constraints,
        "distinct_root_lineages_verified": False,
    }
    values["role_assignment_sha256"] = canonical_sha256(
        {
            **values,
            "required_supported_parameters": [profile.native_capability_marker],
            "route_predicate_profile": profile.model_dump(mode="json"),
            "route_constraints": [item.model_dump(mode="json") for item in ordered_constraints],
        }
    )
    try:
        return AuthenticatedRunnerSelection.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("authenticated runner seed assignment is invalid") from exc


def seal_authenticated_runner_route_predicate_profile(
    *,
    reasoning_policy: ReasoningPolicyArtifact,
    minimum_prompt_tokens: int,
    required_output_tokens: int,
    minimum_context_tokens: int,
) -> RoutePredicateProfile:
    """Bind the shared route profile to the exact model-benchmark reasoning policy."""

    if type(reasoning_policy) is not ReasoningPolicyArtifact:
        raise CandidateSelectionError("route predicate profile requires an exact reasoning policy")
    try:
        policy = ReasoningPolicyArtifact.model_validate_json(
            reasoning_policy.model_dump_json(),
            strict=True,
        )
        role_policy = policy.role_policy_for_request("model_benchmark")
        control = role_policy.control
        if (
            control.mode != "effort"
            or control.effort != "high"
            or control.max_tokens is not None
            or control.exclude is not False
            or control.reserved_reasoning_tokens <= 0
        ):
            raise ValueError("model-benchmark reasoning control must be exact effort=high")
        return RoutePredicateProfile.build(
            reasoning_policy_sha256=policy.artifact_sha256,
            reasoning_role_profile_sha256=policy.role_profile.profile_sha256,
            reasoning_role_binding_sha256=role_policy.binding_sha256,
            reasoning_control_profile_sha256=control.profile_sha256,
            reserved_reasoning_tokens=control.reserved_reasoning_tokens,
            minimum_prompt_tokens=minimum_prompt_tokens,
            required_output_tokens=required_output_tokens,
            minimum_context_tokens=minimum_context_tokens,
        )
    except ValueError as exc:
        raise CandidateSelectionError(
            "authenticated runner route predicate profile is invalid"
        ) from exc


def seal_candidate_selection_plan(
    *,
    source_bindings: tuple[CandidateSelectionSourceBinding, ...],
    entries: tuple[CandidateSelectionEntry, ...],
    authenticated_runner_selection: AuthenticatedRunnerSelection | None = None,
    unresolved_requirements: tuple[str, ...] = (),
) -> CandidateSelectionPlan:
    ordered_sources = tuple(sorted(source_bindings, key=lambda item: item.kind))
    ordered_entries = tuple(sorted(entries, key=lambda item: item.exact_model_id))
    values: dict[str, object] = {
        "schema_version": "1.4",
        "artifact_kind": "OPERATOR_STAGED_MODEL_SELECTION",
        "status": "NONAUTHORIZING",
        "objective_sha256": OBJECTIVE_SHA256,
        "source_bindings": [item.model_dump(mode="json") for item in ordered_sources],
        "entries": [item.model_dump(mode="json") for item in ordered_entries],
        "authenticated_runner_selection": authenticated_runner_selection,
        "unresolved_requirements": list(sorted(unresolved_requirements)),
        "ranking_executed": False,
        "cached_ranking_payload_present": False,
        "provider_metadata_present": False,
        "discovery_evidence_present": False,
        "documentary_lineage_identity_authorized": False,
        "provider_call_authorized": False,
        "source_egress_authorized": False,
        "qualification_authorized": False,
        "production_selection_authorized": False,
        "runner_authority_authorized": False,
        "benchmark_authorized": False,
        "seal_publication_authorized": False,
        "release_authorized": False,
        "serialized_authority": False,
    }
    values["plan_sha256"] = canonical_sha256(
        {
            **values,
            "authenticated_runner_selection": (
                None
                if authenticated_runner_selection is None
                else authenticated_runner_selection.model_dump(mode="json")
            ),
        }
    )
    try:
        return CandidateSelectionPlan.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection plan is invalid") from exc


def load_candidate_selection_plan(path: Path) -> CandidateSelectionPlan:
    """Load one bounded regular canonical plan without following a final symlink."""

    content = _read_bounded_regular_file(path, maximum=_MAX_PLAN_BYTES)
    try:
        plan = CandidateSelectionPlan.model_validate_json(content, strict=True)
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection plan is invalid") from exc
    if stable_json(plan).encode("utf-8") != content:
        raise CandidateSelectionError("candidate selection plan is not canonical JSON")
    return plan


def read_candidate_selection_source(path: Path) -> bytes:
    """Read one bounded, regular staged source exactly once for hash validation."""

    return _read_bounded_regular_file(path, maximum=_MAX_SOURCE_BYTES)


def validate_candidate_selection_plan_sources(
    plan: CandidateSelectionPlan,
    *,
    ranking_source_bytes: bytes,
    lineage_review_source_bytes: bytes,
) -> CandidateSelectionPlan:
    canonical = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    supplied: Mapping[str, bytes] = {
        "MODEL_RANKING_IMPLEMENTATION": ranking_source_bytes,
        "OPERATOR_LINEAGE_REVIEW": lineage_review_source_bytes,
    }
    for binding in canonical.source_bindings:
        content = supplied[binding.kind]
        if (
            not isinstance(content, bytes)
            or len(content) != binding.byte_count
            or hashlib.sha256(content).hexdigest() != binding.content_sha256
        ):
            raise CandidateSelectionError("candidate selection source differs from its binding")
    return canonical


def validate_candidate_selection_routes(
    plan: CandidateSelectionPlan,
    *,
    routes: tuple[DiscoveryCandidateRoute, ...],
) -> CandidateSelectionPlan:
    """Require an explicit exact nonempty subset; never select an endpoint automatically."""

    canonical = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    validated_routes = tuple(
        DiscoveryCandidateRoute.model_validate(route.model_dump(mode="python")) for route in routes
    )
    route_keys = tuple(
        (route.exact_model_id, route.approved_provider_endpoint) for route in validated_routes
    )
    if not route_keys or route_keys != tuple(sorted(set(route_keys))):
        raise CandidateSelectionError(
            "candidate selection routes must be nonempty, unique, and sorted"
        )
    if len({route.exact_model_id for route in validated_routes}) != len(validated_routes):
        raise CandidateSelectionError("candidate selection routes repeat one exact model ID")
    entries_by_id = {entry.exact_model_id: entry for entry in canonical.entries}
    for route in validated_routes:
        entry = entries_by_id.get(route.exact_model_id)
        if entry is None:
            raise CandidateSelectionError("candidate selection route is outside the plan")
        if route.approved_provider_endpoint not in entry.allowed_provider_endpoints:
            raise CandidateSelectionError("candidate selection route uses an unlisted endpoint")
        selection = canonical.authenticated_runner_selection
        if selection is not None and route.exact_model_id in {
            selection.candidate_model_id,
            selection.primary_judge_model_id,
            selection.replay_judge_model_id,
        }:
            authenticated_runner_route_constraint(
                canonical,
                exact_model_id=route.exact_model_id,
                provider_endpoint=route.approved_provider_endpoint,
            )
    return canonical


def require_candidate_selection_plan_currently_eligible(
    plan: CandidateSelectionPlan,
    *,
    _candidate_revocation_call_roots: _CandidateRevocationCallRoots = (
        _CANDIDATE_REVOCATION_CALL_ROOTS
    ),
) -> CandidateSelectionPlan:
    """Reject tombstoned runner routes without changing historical plan validity."""

    function_defaults = require_candidate_selection_plan_currently_eligible.__kwdefaults__
    if type(_candidate_revocation_call_roots) is not tuple or len(
        _candidate_revocation_call_roots
    ) != 3:
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    trusted_pristine, trusted_assignment_gate, trusted_plan_gate = (
        _candidate_revocation_call_roots
    )
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_candidate_revocation_call_roots")
        is not _candidate_revocation_call_roots
        or _CANDIDATE_REVOCATION_CALL_ROOTS is not _candidate_revocation_call_roots
        or candidate_revocation_callables_are_pristine is not trusted_pristine
        or require_candidate_assignment_eligible is not trusted_assignment_gate
        or require_selection_plan_routes_eligible is not trusted_plan_gate
        or candidate_revocation_module.candidate_revocation_callables_are_pristine
        is not trusted_pristine
        or candidate_revocation_module.require_candidate_assignment_eligible
        is not trusted_assignment_gate
        or candidate_revocation_module.require_selection_plan_routes_eligible
        is not trusted_plan_gate
        or not trusted_pristine()
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    canonical = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    selection = canonical.authenticated_runner_selection
    if selection is None:
        return canonical
    routes = tuple(
        sorted(
            (
                (
                    constraint.role,
                    constraint.exact_model_id,
                    constraint.provider_endpoint,
                    constraint.constraint_sha256,
                )
                for constraint in selection.route_constraints
            ),
            key=lambda item: (item[0].value, item[1], item[2].casefold(), item[3]),
        )
    )
    try:
        trusted_plan_gate(canonical.plan_sha256, routes)
    except CandidateSelectionRevocationError as exc:
        raise CandidateSelectionError(
            f"candidate selection plan is not currently eligible: {exc}"
        ) from exc
    return canonical


def authenticated_runner_route_constraint(
    plan: CandidateSelectionPlan,
    *,
    exact_model_id: str,
    provider_endpoint: str,
) -> tuple[RoutePredicateProfile, ExactRouteConstraint]:
    """Return the sole exact selected-route constraint without choosing a fallback."""

    canonical = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    selection = canonical.authenticated_runner_selection
    if selection is None:
        raise CandidateSelectionError("candidate selection has no authenticated runner profile")
    matching = tuple(
        item
        for item in selection.route_constraints
        if item.exact_model_id == exact_model_id and item.provider_endpoint == provider_endpoint
    )
    if len(matching) != 1:
        raise CandidateSelectionError("selected route lacks one exact route constraint")
    return selection.route_predicate_profile, matching[0]


def require_authenticated_runner_native_structured_output(
    evidence: OpenRouterModelDiscoveryPayload | OpenRouterModelDiscoveryEvidence,
) -> None:
    """Require the exact native-schema marker on both model and endpoint metadata."""

    if type(evidence) not in {
        OpenRouterModelDiscoveryPayload,
        OpenRouterModelDiscoveryEvidence,
    }:
        raise CandidateSelectionError(
            "authenticated runner structured-output evidence has the wrong exact type"
        )
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    required = {"structured_outputs"}
    if (
        evidence.structured_output_mode is not StructuredOutputMode.NATIVE_JSON_SCHEMA
        or evidence.structured_output_supported is not True
        or not required.issubset(evidence.model_supported_parameters)
        or not required.issubset(endpoint.supported_parameters)
        or not required.issubset(evidence.structured_output_parameters)
        or not required.issubset(endpoint.structured_output_parameters)
    ):
        raise CandidateSelectionError(
            "authenticated runner route lacks required native structured_outputs support"
        )


def require_authenticated_runner_reasoning_effort(
    evidence: OpenRouterModelDiscoveryPayload | OpenRouterModelDiscoveryEvidence,
    *,
    required_effort: ReasoningEffort,
) -> None:
    """Require explicit reasoning support and the endpoint-first configured effort."""

    if type(evidence) not in {
        OpenRouterModelDiscoveryPayload,
        OpenRouterModelDiscoveryEvidence,
    }:
        raise CandidateSelectionError(
            "authenticated runner reasoning evidence has the wrong exact type"
        )
    if required_effort != "high":
        raise CandidateSelectionError(
            "authenticated runner selection has an unsupported reasoning requirement"
        )
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    required_parameters = {"reasoning"}
    effective_efforts = (
        endpoint.supported_reasoning_efforts
        if endpoint.supported_reasoning_efforts is not None
        else evidence.model_supported_reasoning_efforts
    )
    if (
        evidence.reasoning_supported is not True
        or not required_parameters.issubset(evidence.model_supported_parameters)
        or not required_parameters.issubset(endpoint.supported_parameters)
        or not required_parameters.issubset(evidence.reasoning_parameters)
        or evidence.reasoning_capability.reasoning_parameter_support != "supported"
        or effective_efforts is None
        or required_effort not in effective_efforts
    ):
        raise CandidateSelectionError(
            "authenticated runner route lacks required reasoning effort=high support"
        )


def require_authenticated_runner_metadata_completion_limit(
    evidence: OpenRouterModelDiscoveryPayload | OpenRouterModelDiscoveryEvidence,
    *,
    required_source: Literal["metadata"],
) -> None:
    """Require an explicit endpoint completion limit rather than a context fallback."""

    if type(evidence) not in {
        OpenRouterModelDiscoveryPayload,
        OpenRouterModelDiscoveryEvidence,
    }:
        raise CandidateSelectionError(
            "authenticated runner completion-capacity evidence has the wrong exact type"
        )
    if required_source != "metadata":
        raise CandidateSelectionError(
            "authenticated runner selection has an unsupported completion-limit source"
        )
    endpoint = evidence.endpoint_snapshot.endpoint(evidence.approved_provider_endpoint)
    if endpoint.max_completion_tokens_source != required_source:
        raise CandidateSelectionError(
            "authenticated runner route lacks an explicit metadata completion limit"
        )


def validate_candidate_selection_discovery_capability(
    plan: CandidateSelectionPlan,
    *,
    evidence: OpenRouterModelDiscoveryPayload | OpenRouterModelDiscoveryEvidence,
) -> CandidateSelectionPlan:
    """Enforce every selected AUTHRUNNER role capability before registry publication."""

    canonical = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    selection = canonical.authenticated_runner_selection
    if selection is None:
        return canonical
    selected_ids = {
        selection.candidate_model_id,
        selection.primary_judge_model_id,
        selection.replay_judge_model_id,
    }
    if evidence.exact_model_id in selected_ids:
        profile, constraint = authenticated_runner_route_constraint(
            canonical,
            exact_model_id=evidence.exact_model_id,
            provider_endpoint=evidence.approved_provider_endpoint,
        )
        require_openrouter_constrained_discovery_publication(
            evidence,
            route_predicate_profile=profile,
            exact_route_constraint=constraint,
            expected_selection_plan_sha256=canonical.plan_sha256,
        )
    return canonical


def derive_pending_candidate_registry_from_selection_plan(
    *,
    plan: CandidateSelectionPlan,
    run_manifest: OpenRouterModelDiscoveryRunManifest,
    evidence: tuple[OpenRouterModelDiscoveryEvidence, ...],
    _candidate_revocation_call_roots: _CandidateRevocationCallRoots = (
        _CANDIDATE_REVOCATION_CALL_ROOTS
    ),
) -> CandidateRegistry:
    """Build a rootless pending registry using runtime fields only from fresh evidence."""

    function_defaults = derive_pending_candidate_registry_from_selection_plan.__kwdefaults__
    if type(_candidate_revocation_call_roots) is not tuple or len(
        _candidate_revocation_call_roots
    ) != 3:
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    trusted_pristine, trusted_assignment_gate, trusted_plan_gate = (
        _candidate_revocation_call_roots
    )
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_candidate_revocation_call_roots")
        is not _candidate_revocation_call_roots
        or _CANDIDATE_REVOCATION_CALL_ROOTS is not _candidate_revocation_call_roots
        or candidate_revocation_callables_are_pristine is not trusted_pristine
        or require_candidate_assignment_eligible is not trusted_assignment_gate
        or require_selection_plan_routes_eligible is not trusted_plan_gate
        or candidate_revocation_module.candidate_revocation_callables_are_pristine
        is not trusted_pristine
        or candidate_revocation_module.require_candidate_assignment_eligible
        is not trusted_assignment_gate
        or candidate_revocation_module.require_selection_plan_routes_eligible
        is not trusted_plan_gate
        or not trusted_pristine()
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    canonical_plan = require_candidate_selection_plan_currently_eligible(plan)
    selection = canonical_plan.authenticated_runner_selection
    if selection is not None:
        routes = tuple(
            sorted(
                (
                    (
                        constraint.role,
                        constraint.exact_model_id,
                        constraint.provider_endpoint,
                        constraint.constraint_sha256,
                    )
                    for constraint in selection.route_constraints
                ),
                key=lambda item: (item[0].value, item[1], item[2].casefold(), item[3]),
            )
        )
        try:
            trusted_plan_gate(canonical_plan.plan_sha256, routes)
        except CandidateSelectionRevocationError as exc:
            raise CandidateSelectionError(
                f"candidate selection plan is not currently eligible: {exc}"
            ) from exc
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        run_manifest.model_dump(mode="python")
    )
    try:
        for route in manifest.run_provenance.candidate_routes:
            trusted_assignment_gate(
                exact_model_id=route.exact_model_id,
                provider_endpoint=route.approved_provider_endpoint,
            )
    except CandidateSelectionRevocationError as exc:
        raise CandidateSelectionError(
            f"candidate selection discovery route is not currently eligible: {exc}"
        ) from exc
    records = tuple(
        OpenRouterModelDiscoveryEvidence.model_validate(item.model_dump(mode="python"))
        for item in evidence
    )
    try:
        for item in records:
            for model_id in {item.exact_model_id, item.canonical_slug}:
                trusted_assignment_gate(
                    exact_model_id=model_id,
                    provider_endpoint=item.approved_provider_endpoint,
                )
    except CandidateSelectionRevocationError as exc:
        raise CandidateSelectionError(
            f"candidate discovery identity is not currently eligible: {exc}"
        ) from exc
    record_ids = tuple(item.exact_model_id for item in records)
    route_ids = tuple(route.exact_model_id for route in manifest.run_provenance.candidate_routes)
    if record_ids != route_ids or record_ids != tuple(sorted(set(record_ids))):
        raise CandidateSelectionError(
            "fresh candidate evidence does not exactly cover unique discovery routes"
        )
    validate_candidate_selection_routes(
        canonical_plan,
        routes=manifest.run_provenance.candidate_routes,
    )

    candidates: list[CandidateModel] = []
    for item in records:
        validate_candidate_selection_discovery_capability(canonical_plan, evidence=item)
        if item.zdr_eligible is not True or not item.endpoint_snapshot.require_zdr:
            raise CandidateSelectionError(
                "fresh candidate discovery is not bound to exact ZDR eligibility"
            )
        endpoint = item.endpoint_snapshot.endpoint(item.approved_provider_endpoint)
        if (
            item.output_capability_sha256 is None
            or item.structured_output_mode is None
            or endpoint.max_prompt_tokens is None
            or endpoint.max_prompt_tokens_source is None
            or endpoint.max_completion_tokens_source is None
        ):
            raise CandidateSelectionError(
                "fresh candidate discovery lacks exact output capability evidence"
            )
        review = seal_operator_lineage_review(
            status=LineageReviewStatus.PENDING,
            reviewed_model_ids=(item.exact_model_id,),
            rationale=(
                "Pending exact documentary public-lineage confirmation under nonauthorizing "
                f"candidate selection plan {canonical_plan.plan_sha256}."
            ),
        )
        route_custody: dict[str, object] = {}
        selection = canonical_plan.authenticated_runner_selection
        if selection is not None and item.exact_model_id in {
            selection.candidate_model_id,
            selection.primary_judge_model_id,
            selection.replay_judge_model_id,
        }:
            profile, constraint = authenticated_runner_route_constraint(
                canonical_plan,
                exact_model_id=item.exact_model_id,
                provider_endpoint=item.approved_provider_endpoint,
            )
            discovery_facts = item.endpoint_snapshot.normalized_route_facts
            if discovery_facts is None:
                raise CandidateSelectionError(
                    "selected candidate discovery lacks normalized route facts"
                )
            try:
                registry_facts = bind_registry_route_facts(
                    discovery_facts,
                    registry_selection_plan_sha256=canonical_plan.plan_sha256,
                    profile=profile,
                    constraint=constraint,
                )
                registry_report = evaluate_route_predicates(
                    profile=profile,
                    constraint=constraint,
                    facts=registry_facts,
                )
                require_route_predicates(
                    registry_report,
                    purpose=RouteConstraintPurpose.REGISTRY_PUBLICATION,
                )
            except ValueError as exc:
                raise CandidateSelectionError(
                    "selected candidate registry route custody is invalid"
                ) from exc
            route_custody = {
                "selection_plan_sha256": canonical_plan.plan_sha256,
                "route_predicate_profile_sha256": profile.profile_sha256,
                "exact_route_constraint_sha256": constraint.constraint_sha256,
                "route_predicate_report_sha256": registry_report.report_sha256,
            }
        elif item.endpoint_snapshot.route_predicate_report is not None:
            raise CandidateSelectionError(
                "nonselected candidate discovery carries unexpected route custody"
            )
        candidates.append(
            CandidateModel(
                exact_model_id=item.exact_model_id,
                canonical_model_slug=item.canonical_slug,
                root_lineage=None,
                lineage_review=review,
                discovery_evidence_sha256=item.discovery_evidence_sha256,
                approved_provider_endpoint=item.approved_provider_endpoint,
                approved_provider_name=item.provider_name,
                endpoint_snapshot_sha256=item.endpoint_snapshot_sha256,
                output_capability_sha256=item.output_capability_sha256,
                model_metadata_snapshot_sha256=item.model_metadata_snapshot_sha256,
                pricing_snapshot_sha256=item.pricing_snapshot_sha256,
                context_size=item.context_size,
                max_prompt_tokens=endpoint.max_prompt_tokens,
                max_prompt_tokens_source=endpoint.max_prompt_tokens_source,
                output_limit=item.output_limit,
                output_limit_source=endpoint.max_completion_tokens_source,
                structured_output_supported=item.structured_output_supported,
                structured_output_mode=item.structured_output_mode,
                reasoning_supported=item.reasoning_supported,
                zdr_eligible=True,
                data_collection_deny_eligible=item.data_collection_deny_eligible,
                data_collection_deny_request_policy_enforced=(
                    item.data_collection_deny_request_policy_enforced
                ),
                data_collection_deny_evidence_source=item.data_collection_deny_evidence_source,
                data_collection_deny_evidence_sha256=item.data_collection_deny_evidence_sha256,
                data_collection_deny_evidence_expires_at=(
                    item.data_collection_deny_evidence_expires_at
                ),
                operational_status=CandidateOperationalStatus.AVAILABLE,
                benchmark_status=CandidateBenchmarkStatus.PENDING,
                benchmark_artifact_sha256=None,
                qualification_expires_at=None,
                approved_roles=(),
                **route_custody,
            )
        )
    registry = seal_candidate_registry(
        created_at=manifest.run_provenance.retrieved_at,
        discovery_run_sha256=manifest.manifest_sha256,
        candidates=tuple(candidates),
    )
    try:
        validate_candidate_registry_discovery(
            registry=registry,
            run_manifest=manifest,
            evidence=records,
        )
    except ValueError as exc:
        raise CandidateSelectionError(
            "candidate selection registry differs from fresh discovery"
        ) from exc
    return registry


def _read_bounded_regular_file(path: Path, *, maximum: int) -> bytes:
    if not isinstance(path, Path):
        raise CandidateSelectionError("candidate selection path must be explicit")
    try:
        descriptor = os.open(path, os.O_RDONLY | _NOFOLLOW_FLAG | _NONBLOCK_FLAG)
    except OSError as exc:
        raise CandidateSelectionError("candidate selection file could not be opened") from exc
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 1 <= before.st_size <= maximum
        ):
            raise CandidateSelectionError("candidate selection file is not bounded and regular")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_after != identity_before or len(content) != before.st_size:
            raise CandidateSelectionError("candidate selection file changed while reading")
        return content
    finally:
        os.close(descriptor)
