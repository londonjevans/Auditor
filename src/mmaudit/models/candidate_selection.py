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
from types import CellType, CodeType, FunctionType
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import mmaudit.models.candidate_revocation as candidate_revocation_module
import mmaudit.models.route_constraints as route_constraints_module
from mmaudit.models.candidate_revocation import (
    CandidateSelectionRevocationEntry,
    CandidateSelectionRevocationError,
    CandidateSelectionRevocationRegistry,
    candidate_revocation_callables_are_pristine,
    load_candidate_selection_revocation_registry,
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
    ProviderPriceCapAlgorithm,
    RouteConstraintPurpose,
    RoutePredicateProfile,
    bind_registry_route_facts,
    evaluate_route_predicates,
    require_route_predicates,
    route_constraint_callables_are_pristine,
)
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json

OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_SAFE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"
_ADVISORY_GROUP_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,199}$"
_Sha256Value = Annotated[str, Field(pattern=_SHA256_PATTERN)]
_MAX_PLAN_BYTES = 2_000_000
_MAX_SOURCE_BYTES = 2_000_000
_PRIVATE_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR
_NOFOLLOW_FLAG = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK_FLAG = getattr(os, "O_NONBLOCK", 0)
NO_ACTIVE_CANDIDATE_REQUIREMENT = (
    "No active candidate remains after exact revocation reconciliation; a separately authorized "
    "non-revoked successor is required."
)
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


class CandidateSelectionEndpointInventoryRefresh(StrictModel):
    """One explicit, nonauthorizing endpoint inventory transition."""

    schema_version: Literal["1.0"]
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    predecessor_entry_sha256: str = Field(pattern=_SHA256_PATTERN)
    predecessor_allowed_provider_endpoints: tuple[str, ...] = Field(
        min_length=1,
        max_length=16,
    )
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    disposition: Literal["OPERATOR_STAGED_UNVERIFIED"]
    constrained_discovery_required: Literal[True]
    provider_metadata_embedded: Literal[False]
    discovery_evidence_embedded: Literal[False]
    endpoint_authority: Literal[False]
    refresh_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        try:
            require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("endpoint inventory refresh model ID must be exact") from exc
        return value

    @field_validator("predecessor_allowed_provider_endpoints")
    @classmethod
    def predecessor_endpoints_are_exact_sorted_unique(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("endpoint inventory refresh predecessor endpoints are not canonical")
        if any(re.fullmatch(_ENDPOINT_PATTERN, endpoint) is None for endpoint in value):
            raise ValueError("endpoint inventory refresh predecessor endpoint is invalid")
        return value

    @model_validator(mode="after")
    def transition_is_new_and_self_hashed(self) -> Self:
        if self.provider_endpoint in self.predecessor_allowed_provider_endpoints:
            raise ValueError("endpoint inventory refresh must stage a previously unlisted endpoint")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"refresh_sha256"}))
        if self.refresh_sha256 != expected:
            raise ValueError("endpoint inventory refresh self-hash is inconsistent")
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


class CandidateSelectionUnavailableState(StrictModel):
    """Inactive judge custody after every predecessor candidate route was revoked."""

    schema_version: Literal["1.0"]
    disposition: Literal["NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"]
    price_cap_profile_decision: Literal["PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION"]
    predecessor_role_assignment_sha256: str = Field(pattern=_SHA256_PATTERN)
    matched_revocation_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    revocation_entry_sha256s: tuple[_Sha256Value, ...] = Field(min_length=1, max_length=16)
    withdrawn_candidate_constraint_sha256s: tuple[_Sha256Value, ...] = Field(
        min_length=1,
        max_length=16,
    )
    primary_judge_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    replay_judge_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    route_predicate_profile: RoutePredicateProfile
    judge_route_constraints: tuple[ExactRouteConstraint, ...] = Field(
        min_length=2,
        max_length=17,
    )
    candidate_selection_authorized: Literal[False]
    state_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("primary_judge_model_id", "replay_judge_model_id")
    @classmethod
    def judge_model_id_is_exact(cls, value: str) -> str:
        try:
            require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("unavailable candidate judge model ID must be exact") from exc
        return value

    @field_validator(
        "revocation_entry_sha256s",
        "withdrawn_candidate_constraint_sha256s",
    )
    @classmethod
    def hashes_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("unavailable candidate hashes must be unique and sorted")
        return value

    @model_validator(mode="after")
    def inactive_judge_custody_is_exact(self) -> Self:
        if self.primary_judge_model_id == self.replay_judge_model_id:
            raise ValueError("unavailable candidate judge models must remain distinct")
        profile = RoutePredicateProfile.model_validate_json(
            self.route_predicate_profile.model_dump_json(),
            strict=True,
        )
        if (
            profile.schema_version != "1.0"
            or profile.price_cap_algorithm
            is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
            or profile.price_component_unit_envelopes is not None
        ):
            raise ValueError("unavailable candidate state must preserve the predecessor V1 profile")
        expected_order = tuple(
            sorted(
                self.judge_route_constraints,
                key=lambda item: (item.role.value, item.exact_model_id, item.provider_endpoint),
            )
        )
        if self.judge_route_constraints != expected_order:
            raise ValueError("unavailable candidate judge constraints are not canonically ordered")
        keys = tuple(
            (item.role, item.exact_model_id, item.provider_endpoint)
            for item in self.judge_route_constraints
        )
        if len(keys) != len(set(keys)):
            raise ValueError("unavailable candidate judge constraints are not unique")
        role_models = {
            ExactRouteRole.PRIMARY_JUDGE: self.primary_judge_model_id,
            ExactRouteRole.REPLAY_JUDGE: self.replay_judge_model_id,
        }
        if {item.role for item in self.judge_route_constraints} != set(role_models):
            raise ValueError("unavailable candidate state must retain both judge roles only")
        if any(
            item.profile_sha256 != profile.profile_sha256
            or item.exact_model_id != role_models[item.role]
            for item in self.judge_route_constraints
        ):
            raise ValueError(
                "unavailable candidate judge constraint differs from its role or profile"
            )
        expected_revocation_set = canonical_sha256(
            {
                "schema_version": "1.0",
                "artifact_kind": "MATCHED_CANDIDATE_SELECTION_REVOCATIONS",
                "revocation_entry_sha256s": list(self.revocation_entry_sha256s),
            }
        )
        if self.matched_revocation_set_sha256 != expected_revocation_set:
            raise ValueError("unavailable candidate matched revocation set digest is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"state_sha256"}))
        if self.state_sha256 != expected:
            raise ValueError("unavailable candidate state self-hash is inconsistent")
        return self


class CandidateSelectionPlanAncestryTransitionBinding(StrictModel):
    """Nonauthorizing durable binding for one capability-verified reactivation."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["REPOSITORY_PINNED_SELECTION_PLAN_ANCESTRY_TRANSITION"]
    selected_ancestor_raw_sha256: str = Field(pattern=_SHA256_PATTERN)
    selected_ancestor_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    unavailable_predecessor_raw_sha256: str = Field(pattern=_SHA256_PATTERN)
    unavailable_predecessor_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    unavailable_state_sha256: str = Field(pattern=_SHA256_PATTERN)
    matched_revocation_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    ancestry_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    revocation_entry_sha256s: tuple[_Sha256Value, ...] = Field(min_length=1, max_length=16)
    withdrawn_candidate_constraint_sha256s: tuple[_Sha256Value, ...] = Field(
        min_length=1,
        max_length=16,
    )
    selected_ancestor_role_assignment_sha256: str = Field(pattern=_SHA256_PATTERN)
    retained_route_predicate_profile_sha256: str = Field(pattern=_SHA256_PATTERN)
    retained_judge_constraint_sha256s: tuple[_Sha256Value, ...] = Field(
        min_length=2,
        max_length=17,
    )
    replacement_candidate_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    replacement_provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    replacement_candidate_constraint_sha256: str = Field(pattern=_SHA256_PATTERN)
    opaque_ancestry_capability_required: Literal[True]
    endpoint_inventory_refresh_authorized: Literal[False]
    price_cap_profile_upgrade_authorized: Literal[False]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    benchmark_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    serialized_authority: Literal[False]
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("replacement_candidate_model_id")
    @classmethod
    def replacement_model_id_is_exact(cls, value: str) -> str:
        try:
            return require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("ancestry-transition candidate model ID must be exact") from exc

    @field_validator("replacement_provider_endpoint")
    @classmethod
    def replacement_endpoint_is_canonical(cls, value: str) -> str:
        if value != value.casefold():
            raise ValueError("ancestry-transition provider endpoint must be canonical lowercase")
        return value

    @field_validator(
        "revocation_entry_sha256s",
        "withdrawn_candidate_constraint_sha256s",
        "retained_judge_constraint_sha256s",
    )
    @classmethod
    def hashes_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("ancestry-transition hashes must be unique and sorted")
        return value

    @model_validator(mode="after")
    def binding_is_nonauthorizing_and_self_hashed(self) -> Self:
        if self.selected_ancestor_plan_sha256 == self.unavailable_predecessor_plan_sha256:
            raise ValueError("ancestry transition must bind distinct plan generations")
        expected_revocation_set = canonical_sha256(
            {
                "schema_version": "1.0",
                "artifact_kind": "MATCHED_CANDIDATE_SELECTION_REVOCATIONS",
                "revocation_entry_sha256s": list(self.revocation_entry_sha256s),
            }
        )
        if self.matched_revocation_set_sha256 != expected_revocation_set:
            raise ValueError("ancestry-transition matched revocation set is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("ancestry-transition binding self-hash is inconsistent")
        return self


class CandidateSelectionPlan(StrictModel):
    """Self-hashed operator-staged seed with only literal-false authority flags."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"schema_version": {"const": "1.4"}},
                        "required": ["schema_version"],
                    },
                    "then": {
                        "not": {"required": ["predecessor_plan_sha256"]},
                    },
                    "else": {
                        "properties": {
                            "predecessor_plan_sha256": {
                                "pattern": _SHA256_PATTERN,
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
                    "else": {"not": {"required": ["authenticated_runner_unavailability"]}},
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
                                                "const": ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1.value
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
        }
    )

    schema_version: Literal["1.4", "1.5", "1.6", "1.7", "1.8"]
    artifact_kind: Literal["OPERATOR_STAGED_MODEL_SELECTION"]
    status: Literal["NONAUTHORIZING"]
    objective_sha256: Literal["e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"]
    predecessor_plan_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
        exclude_if=lambda value: value is None,
    )
    source_bindings: tuple[CandidateSelectionSourceBinding, ...] = Field(
        min_length=2,
        max_length=2,
    )
    entries: tuple[CandidateSelectionEntry, ...] = Field(min_length=1, max_length=64)
    authenticated_runner_selection: AuthenticatedRunnerSelection | None = None
    authenticated_runner_unavailability: CandidateSelectionUnavailableState | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    endpoint_inventory_refresh: CandidateSelectionEndpointInventoryRefresh | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    ancestry_transition_binding: CandidateSelectionPlanAncestryTransitionBinding | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
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
        predecessor_supplied = "predecessor_plan_sha256" in self.model_fields_set
        refresh_supplied = "endpoint_inventory_refresh" in self.model_fields_set
        unavailability_supplied = "authenticated_runner_unavailability" in self.model_fields_set
        ancestry_supplied = "ancestry_transition_binding" in self.model_fields_set
        if self.schema_version == "1.4":
            predecessor_is_valid = not predecessor_supplied and self.predecessor_plan_sha256 is None
        else:
            predecessor_is_valid = self.predecessor_plan_sha256 is not None
        refresh_is_valid = (
            self.schema_version == "1.6"
            and refresh_supplied
            and self.endpoint_inventory_refresh is not None
        ) or (
            self.schema_version != "1.6"
            and not refresh_supplied
            and self.endpoint_inventory_refresh is None
        )
        if not predecessor_is_valid:
            raise ValueError("candidate selection plan predecessor custody differs from its schema")
        if not refresh_is_valid:
            raise ValueError("candidate selection endpoint refresh differs from its schema")
        unavailability_is_valid = (
            self.schema_version == "1.7"
            and unavailability_supplied
            and self.authenticated_runner_unavailability is not None
            and self.authenticated_runner_selection is None
        ) or (
            self.schema_version != "1.7"
            and not unavailability_supplied
            and self.authenticated_runner_unavailability is None
        )
        if not unavailability_is_valid:
            raise ValueError("candidate selection unavailability differs from its schema")
        ancestry_is_valid = (
            self.schema_version == "1.8"
            and ancestry_supplied
            and self.ancestry_transition_binding is not None
            and self.authenticated_runner_selection is not None
            and self.authenticated_runner_unavailability is None
            and self.endpoint_inventory_refresh is None
        ) or (
            self.schema_version != "1.8"
            and not ancestry_supplied
            and self.ancestry_transition_binding is None
        )
        if not ancestry_is_valid:
            raise ValueError("candidate selection ancestry transition differs from its schema")
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
        if self.endpoint_inventory_refresh is not None:
            refresh = self.endpoint_inventory_refresh
            refresh_selection = self.authenticated_runner_selection
            if refresh_selection is None:
                raise ValueError("endpoint inventory refresh requires a runner assignment")
            candidate_constraints = tuple(
                constraint
                for constraint in refresh_selection.route_constraints
                if constraint.role is ExactRouteRole.CANDIDATE
            )
            entries_by_id = {entry.exact_model_id: entry for entry in self.entries}
            refreshed_entry = entries_by_id.get(refresh.exact_model_id)
            if (
                refresh_selection.candidate_model_id != refresh.exact_model_id
                or refreshed_entry is None
                or refreshed_entry.allowed_provider_endpoints != (refresh.provider_endpoint,)
                or len(candidate_constraints) != 1
                or candidate_constraints[0].exact_model_id != refresh.exact_model_id
                or candidate_constraints[0].provider_endpoint != refresh.provider_endpoint
            ):
                raise ValueError(
                    "endpoint inventory refresh differs from the exact candidate assignment"
                )
        if self.authenticated_runner_unavailability is not None:
            unavailable = self.authenticated_runner_unavailability
            if NO_ACTIVE_CANDIDATE_REQUIREMENT not in self.unresolved_requirements:
                raise ValueError(
                    "unavailable candidate plan lacks its named unresolved requirement"
                )
            entries_by_id = {entry.exact_model_id: entry for entry in self.entries}
            for role, model_id in (
                (ExactRouteRole.PRIMARY_JUDGE, unavailable.primary_judge_model_id),
                (ExactRouteRole.REPLAY_JUDGE, unavailable.replay_judge_model_id),
            ):
                entry = entries_by_id.get(model_id)
                retained_endpoints = {
                    constraint.provider_endpoint
                    for constraint in unavailable.judge_route_constraints
                    if constraint.role is role
                }
                if entry is None or retained_endpoints != set(entry.allowed_provider_endpoints):
                    raise ValueError(
                        "unavailable candidate judge constraints differ from endpoint policy"
                    )
        if self.ancestry_transition_binding is not None:
            transition = self.ancestry_transition_binding
            ancestry_selection = self.authenticated_runner_selection
            if ancestry_selection is None or self.predecessor_plan_sha256 != (
                transition.unavailable_predecessor_plan_sha256
            ):
                raise ValueError("ancestry transition differs from the immediate predecessor")
            candidate_constraints = tuple(
                constraint
                for constraint in ancestry_selection.route_constraints
                if constraint.role is ExactRouteRole.CANDIDATE
            )
            judge_constraint_sha256s = tuple(
                sorted(
                    constraint.constraint_sha256
                    for constraint in ancestry_selection.route_constraints
                    if constraint.role is not ExactRouteRole.CANDIDATE
                )
            )
            if (
                len(candidate_constraints) != 1
                or candidate_constraints[0].exact_model_id
                != transition.replacement_candidate_model_id
                or candidate_constraints[0].provider_endpoint
                != transition.replacement_provider_endpoint
                or candidate_constraints[0].constraint_sha256
                != transition.replacement_candidate_constraint_sha256
                or ancestry_selection.route_predicate_profile.profile_sha256
                != transition.retained_route_predicate_profile_sha256
                or ancestry_selection.route_predicate_profile.schema_version != "1.0"
                or ancestry_selection.route_predicate_profile.price_cap_algorithm
                is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
                or ancestry_selection.route_predicate_profile.price_component_unit_envelopes
                is not None
                or judge_constraint_sha256s != transition.retained_judge_constraint_sha256s
                or NO_ACTIVE_CANDIDATE_REQUIREMENT in self.unresolved_requirements
            ):
                raise ValueError("ancestry transition differs from its reactivated assignment")
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


def _seal_candidate_selection_endpoint_inventory_refresh(
    *,
    predecessor_entry: CandidateSelectionEntry,
    provider_endpoint: str,
) -> CandidateSelectionEndpointInventoryRefresh:
    if type(predecessor_entry) is not CandidateSelectionEntry:
        raise CandidateSelectionError(
            "endpoint inventory refresh predecessor entry has the wrong exact type"
        )
    try:
        entry = CandidateSelectionEntry.model_validate_json(
            predecessor_entry.model_dump_json(),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError(
            "endpoint inventory refresh predecessor entry is invalid"
        ) from exc
    values: dict[str, object] = {
        "schema_version": "1.0",
        "exact_model_id": entry.exact_model_id,
        "predecessor_entry_sha256": entry.entry_sha256,
        "predecessor_allowed_provider_endpoints": entry.allowed_provider_endpoints,
        "provider_endpoint": provider_endpoint,
        "disposition": "OPERATOR_STAGED_UNVERIFIED",
        "constrained_discovery_required": True,
        "provider_metadata_embedded": False,
        "discovery_evidence_embedded": False,
        "endpoint_authority": False,
    }
    values["refresh_sha256"] = canonical_sha256(values)
    try:
        return CandidateSelectionEndpointInventoryRefresh.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("candidate endpoint inventory refresh is invalid") from exc


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


def _seal_candidate_selection_unavailable_state(
    *,
    predecessor_selection: AuthenticatedRunnerSelection,
    revocation_registry: CandidateSelectionRevocationRegistry,
    revocation_entries: tuple[CandidateSelectionRevocationEntry, ...],
) -> CandidateSelectionUnavailableState:
    """Seal inactive judge custody for a fully revoked predecessor candidate assignment."""

    if type(predecessor_selection) is not AuthenticatedRunnerSelection:
        raise CandidateSelectionError(
            "unavailable candidate predecessor selection has the wrong exact type"
        )
    if type(revocation_registry) is not CandidateSelectionRevocationRegistry:
        raise CandidateSelectionError(
            "unavailable candidate revocation registry has the wrong exact type"
        )
    if (
        type(revocation_entries) is not tuple
        or not revocation_entries
        or any(type(entry) is not CandidateSelectionRevocationEntry for entry in revocation_entries)
    ):
        raise CandidateSelectionError("unavailable candidate revocation entries are not exact")
    try:
        selection = AuthenticatedRunnerSelection.model_validate_json(
            predecessor_selection.model_dump_json(),
            strict=True,
        )
        registry = CandidateSelectionRevocationRegistry.model_validate_json(
            revocation_registry.model_dump_json(),
            strict=True,
        )
        entries_by_sha = {entry.entry_sha256: entry for entry in registry.entries}
        canonical_revocations = tuple(
            entries_by_sha[entry.entry_sha256] for entry in revocation_entries
        )
    except (KeyError, ValueError) as exc:
        raise CandidateSelectionError(
            "unavailable candidate revocation custody is invalid"
        ) from exc
    if len(canonical_revocations) != len(set(canonical_revocations)):
        raise CandidateSelectionError("unavailable candidate revocation entries repeat")
    candidate_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    )
    judge_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )
    revocation_entry_sha256s = sorted(entry.entry_sha256 for entry in canonical_revocations)
    values: dict[str, object] = {
        "schema_version": "1.0",
        "disposition": "NO_ACTIVE_CANDIDATE_AFTER_REVOCATION",
        "price_cap_profile_decision": "PRESERVE_PREDECESSOR_V1_NO_V2_ADOPTION",
        "predecessor_role_assignment_sha256": selection.role_assignment_sha256,
        "matched_revocation_set_sha256": canonical_sha256(
            {
                "schema_version": "1.0",
                "artifact_kind": "MATCHED_CANDIDATE_SELECTION_REVOCATIONS",
                "revocation_entry_sha256s": revocation_entry_sha256s,
            }
        ),
        "revocation_entry_sha256s": revocation_entry_sha256s,
        "withdrawn_candidate_constraint_sha256s": sorted(
            constraint.constraint_sha256 for constraint in candidate_constraints
        ),
        "primary_judge_model_id": selection.primary_judge_model_id,
        "replay_judge_model_id": selection.replay_judge_model_id,
        "route_predicate_profile": selection.route_predicate_profile.model_dump(mode="json"),
        "judge_route_constraints": [
            constraint.model_dump(mode="json") for constraint in judge_constraints
        ],
        "candidate_selection_authorized": False,
    }
    values["state_sha256"] = canonical_sha256(values)
    try:
        return CandidateSelectionUnavailableState.model_validate_json(
            stable_json(values),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError("unavailable candidate state is invalid") from exc


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
    """Seal one legacy root plan; successor custody is available only through derivation."""

    return _seal_candidate_selection_plan(
        source_bindings=source_bindings,
        entries=entries,
        authenticated_runner_selection=authenticated_runner_selection,
        authenticated_runner_unavailability=None,
        endpoint_inventory_refresh=None,
        unresolved_requirements=unresolved_requirements,
        predecessor_plan_sha256=None,
    )


def _seal_candidate_selection_plan(
    *,
    source_bindings: tuple[CandidateSelectionSourceBinding, ...],
    entries: tuple[CandidateSelectionEntry, ...],
    authenticated_runner_selection: AuthenticatedRunnerSelection | None,
    authenticated_runner_unavailability: CandidateSelectionUnavailableState | None,
    endpoint_inventory_refresh: CandidateSelectionEndpointInventoryRefresh | None,
    unresolved_requirements: tuple[str, ...],
    predecessor_plan_sha256: str | None,
    ancestry_transition_binding: CandidateSelectionPlanAncestryTransitionBinding | None = None,
) -> CandidateSelectionPlan:
    ordered_sources = tuple(sorted(source_bindings, key=lambda item: item.kind))
    ordered_entries = tuple(sorted(entries, key=lambda item: item.exact_model_id))
    values: dict[str, object] = {
        "schema_version": (
            "1.4"
            if predecessor_plan_sha256 is None
            else (
                "1.8"
                if ancestry_transition_binding is not None
                else (
                    "1.7"
                    if authenticated_runner_unavailability is not None
                    else ("1.6" if endpoint_inventory_refresh is not None else "1.5")
                )
            )
        ),
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
    if predecessor_plan_sha256 is not None:
        values["predecessor_plan_sha256"] = predecessor_plan_sha256
    if authenticated_runner_unavailability is not None:
        values["authenticated_runner_unavailability"] = authenticated_runner_unavailability
    if endpoint_inventory_refresh is not None:
        values["endpoint_inventory_refresh"] = endpoint_inventory_refresh.model_dump(mode="json")
    if ancestry_transition_binding is not None:
        values["ancestry_transition_binding"] = ancestry_transition_binding.model_dump(mode="json")
    values["plan_sha256"] = canonical_sha256(
        {
            **values,
            "authenticated_runner_selection": (
                None
                if authenticated_runner_selection is None
                else authenticated_runner_selection.model_dump(mode="json")
            ),
            **(
                {}
                if authenticated_runner_unavailability is None
                else {
                    "authenticated_runner_unavailability": (
                        authenticated_runner_unavailability.model_dump(mode="json")
                    )
                }
            ),
            **(
                {}
                if ancestry_transition_binding is None
                else {
                    "ancestry_transition_binding": ancestry_transition_binding.model_dump(
                        mode="json"
                    )
                }
            ),
        }
    )
    try:
        return CandidateSelectionPlan.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection plan is invalid") from exc


type _CandidateSelectionFunctionState = tuple[
    FunctionType,
    CodeType,
    tuple[object, ...] | None,
    dict[str, object] | None,
    tuple[tuple[str, object], ...],
    dict[str, Any],
    tuple[CellType, ...] | None,
    tuple[tuple[CellType, object], ...],
    dict[str, Any],
    tuple[tuple[str, object], ...],
]


def _build_candidate_selection_successor_dependency_guard() -> Callable[[], bool]:
    """Seal succession's semantic dependencies against coherent runtime replacement."""

    module_globals = globals()
    empty_cell = object()
    successor_model_types = (
        CandidateSelectionSourceBinding,
        CandidateSelectionEntry,
        CandidateSelectionEndpointInventoryRefresh,
        AuthenticatedRunnerSelection,
        CandidateSelectionUnavailableState,
        CandidateSelectionPlanAncestryTransitionBinding,
        CandidateSelectionPlan,
        RoutePredicateProfile,
        ExactRouteConstraint,
    )
    successor_model_mro_types = tuple(
        dict.fromkeys(
            base
            for model_type in successor_model_types
            for base in model_type.__mro__
            if base is not object
        )
    )
    guarded_metaclasses = tuple(
        dict.fromkeys(
            base
            for guarded_type in (*successor_model_mro_types, ExactRouteRole)
            for base in cast(Any, type(guarded_type)).__mro__
            if base not in {type, object}
        )
    )
    guarded_types = (
        *successor_model_mro_types,
        ExactRouteRole,
        *guarded_metaclasses,
    )
    class_bindings = tuple(
        (guarded_type, tuple(vars(guarded_type).items())) for guarded_type in guarded_types
    )
    mutable_class_bindings = tuple(
        (
            guarded_type,
            name,
            value,
            tuple(value.items()) if type(value) is dict else tuple(value),
        )
        for guarded_type, bindings in class_bindings
        for name, value in bindings
        if type(value) in {dict, list, set}
    )
    base_model_bindings = tuple(
        (name, vars(BaseModel)[name])
        for name in ("model_dump", "model_dump_json", "model_validate", "model_validate_json")
    )
    fixed_globals = (
        ("OBJECTIVE_SHA256", OBJECTIVE_SHA256),
        ("CandidateSelectionSourceBinding", CandidateSelectionSourceBinding),
        ("CandidateSelectionEntry", CandidateSelectionEntry),
        (
            "CandidateSelectionEndpointInventoryRefresh",
            CandidateSelectionEndpointInventoryRefresh,
        ),
        ("AuthenticatedRunnerSelection", AuthenticatedRunnerSelection),
        ("CandidateSelectionUnavailableState", CandidateSelectionUnavailableState),
        (
            "CandidateSelectionPlanAncestryTransitionBinding",
            CandidateSelectionPlanAncestryTransitionBinding,
        ),
        ("CandidateSelectionPlan", CandidateSelectionPlan),
        ("CandidateSelectionError", CandidateSelectionError),
        ("RoutePredicateProfile", RoutePredicateProfile),
        ("ExactRouteConstraint", ExactRouteConstraint),
        ("ExactRouteRole", ExactRouteRole),
        ("ProviderPriceCapAlgorithm", ProviderPriceCapAlgorithm),
        ("NO_ACTIVE_CANDIDATE_REQUIREMENT", NO_ACTIVE_CANDIDATE_REQUIREMENT),
        ("canonical_sha256", canonical_sha256),
        ("stable_json", stable_json),
        ("seal_candidate_selection_entry", seal_candidate_selection_entry),
        (
            "_seal_candidate_selection_endpoint_inventory_refresh",
            _seal_candidate_selection_endpoint_inventory_refresh,
        ),
        ("seal_authenticated_runner_selection", seal_authenticated_runner_selection),
        (
            "_seal_candidate_selection_unavailable_state",
            _seal_candidate_selection_unavailable_state,
        ),
        ("_seal_candidate_selection_plan", _seal_candidate_selection_plan),
        ("route_constraint_callables_are_pristine", route_constraint_callables_are_pristine),
    )

    def snapshot(function: FunctionType) -> _CandidateSelectionFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for cell in closure or ():
            try:
                value = cell.cell_contents
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
            function.__globals__,
            closure,
            tuple(closure_values),
            attributes,
            tuple(sorted(attributes.items())),
        )

    def function_state_is_current(state: _CandidateSelectionFunctionState) -> bool:
        (
            function,
            code,
            defaults,
            kwdefaults,
            kwdefault_items,
            function_globals,
            closure,
            closure_values,
            attributes,
            attribute_items,
        ) = state
        current_kwdefaults = function.__kwdefaults__
        current_attributes = function.__dict__
        if (
            type(function) is not FunctionType
            or type(current_kwdefaults) not in {dict, type(None)}
            or type(current_attributes) is not dict
            or function.__code__ is not code
            or function.__defaults__ is not defaults
            or current_kwdefaults is not kwdefaults
            or function.__globals__ is not function_globals
            or function.__closure__ is not closure
            or current_attributes is not attributes
            or len(current_kwdefaults or {}) != len(kwdefault_items)
            or any(
                (current_kwdefaults or {}).get(name) is not value for name, value in kwdefault_items
            )
            or len(current_attributes) != len(attribute_items)
            or any(current_attributes.get(name) is not value for name, value in attribute_items)
        ):
            return False
        current_closure = function.__closure__ or ()
        if len(current_closure) != len(closure_values):
            return False
        for current_cell, (expected_cell, expected_value) in zip(
            current_closure,
            closure_values,
            strict=True,
        ):
            if current_cell is not expected_cell:
                return False
            try:
                current_value = current_cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if current_value is not expected_value:
                return False
        return True

    descriptor_functions: list[FunctionType] = []
    for _guarded_type, bindings in class_bindings:
        for _name, descriptor in bindings:
            if type(descriptor) is FunctionType:
                descriptor_functions.append(descriptor)
            elif type(descriptor) in {classmethod, staticmethod}:
                descriptor_functions.append(cast(FunctionType, cast(Any, descriptor).__func__))
            elif type(descriptor) is property:
                descriptor_functions.extend(
                    function
                    for function in (descriptor.fget, descriptor.fset, descriptor.fdel)
                    if type(function) is FunctionType
                )
    for _name, descriptor in base_model_bindings:
        if type(descriptor) is FunctionType:
            descriptor_functions.append(descriptor)
        elif type(descriptor) in {classmethod, staticmethod}:
            descriptor_functions.append(cast(FunctionType, cast(Any, descriptor).__func__))
    state_functions = tuple(
        dict.fromkeys(
            (
                seal_candidate_selection_entry,
                _seal_candidate_selection_endpoint_inventory_refresh,
                seal_authenticated_runner_selection,
                _seal_candidate_selection_unavailable_state,
                _seal_candidate_selection_plan,
                canonical_sha256,
                stable_json,
                *descriptor_functions,
            )
        )
    )
    states = tuple(
        snapshot(function) for function in state_functions if type(function) is FunctionType
    )
    base_model_bindings_seal = base_model_bindings
    class_bindings_seal = class_bindings
    fixed_globals_seal = fixed_globals
    module_globals_seal = module_globals
    mutable_class_bindings_seal = mutable_class_bindings
    states_seal = states

    def pristine() -> bool:
        try:
            if (
                base_model_bindings is not base_model_bindings_seal
                or class_bindings is not class_bindings_seal
                or fixed_globals is not fixed_globals_seal
                or module_globals is not module_globals_seal
                or mutable_class_bindings is not mutable_class_bindings_seal
                or states is not states_seal
                or module_globals.get("_candidate_selection_successor_dependencies_are_pristine")
                is not pristine
            ):
                return False
            if any(module_globals.get(name) is not expected for name, expected in fixed_globals):
                return False
            if (
                route_constraints_module.route_constraint_callables_are_pristine
                is not route_constraint_callables_are_pristine
                or not route_constraint_callables_are_pristine()
            ):
                return False
            if any(
                vars(BaseModel).get(name) is not expected for name, expected in base_model_bindings
            ):
                return False
            for guarded_type, expected_bindings in class_bindings:
                current_bindings = vars(guarded_type)
                if len(current_bindings) != len(expected_bindings) or any(
                    current_bindings.get(name) is not expected
                    for name, expected in expected_bindings
                ):
                    return False
            for guarded_type, name, container, expected_items in mutable_class_bindings:
                if vars(guarded_type).get(name) is not container:
                    return False
                if type(container) is dict:
                    current_items = tuple(container.items())
                    if len(current_items) != len(expected_items) or any(
                        not any(
                            current_key is expected_key and current_value is expected_value
                            for current_key, current_value in current_items
                        )
                        for expected_key, expected_value in expected_items
                    ):
                        return False
                elif type(container) in {list, set}:
                    current_values = tuple(cast(list[Any] | set[Any], container))
                    if len(current_values) != len(expected_items) or any(
                        not any(current is expected for current in current_values)
                        for expected in expected_items
                    ):
                        return False
                else:
                    return False
            return all(function_state_is_current(state) for state in states)
        except BaseException:
            return False

    return pristine


_candidate_selection_successor_dependencies_are_pristine = (
    _build_candidate_selection_successor_dependency_guard()
)
del _build_candidate_selection_successor_dependency_guard
if not _candidate_selection_successor_dependencies_are_pristine():
    raise RuntimeError("candidate selection successor dependency boundary failed integrity check")

type _CandidateSelectionSuccessorDependencyCallRoots = tuple[
    Callable[[], bool],
    CodeType,
    Callable[[], bool],
    CodeType,
]
_CANDIDATE_SELECTION_SUCCESSOR_DEPENDENCY_CALL_ROOTS: _CandidateSelectionSuccessorDependencyCallRoots = (
    _candidate_selection_successor_dependencies_are_pristine,
    _candidate_selection_successor_dependencies_are_pristine.__code__,
    route_constraint_callables_are_pristine,
    route_constraint_callables_are_pristine.__code__,
)


def _require_candidate_selection_plan_currently_eligible_checked(
    plan: CandidateSelectionPlan,
    *,
    _candidate_revocation_call_roots: _CandidateRevocationCallRoots = (
        _CANDIDATE_REVOCATION_CALL_ROOTS
    ),
    _successor_dependency_call_roots: _CandidateSelectionSuccessorDependencyCallRoots = (
        _CANDIDATE_SELECTION_SUCCESSOR_DEPENDENCY_CALL_ROOTS
    ),
) -> CandidateSelectionPlan:
    """Reject tombstoned runner routes without changing historical plan validity."""

    function_defaults = _require_candidate_selection_plan_currently_eligible_checked.__kwdefaults__
    if (
        type(_candidate_revocation_call_roots) is not tuple
        or len(_candidate_revocation_call_roots) != 3
        or type(_successor_dependency_call_roots) is not tuple
        or len(_successor_dependency_call_roots) != 4
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    trusted_pristine, trusted_assignment_gate, trusted_plan_gate = _candidate_revocation_call_roots
    (
        trusted_successor_pristine,
        trusted_successor_pristine_code,
        trusted_route_pristine,
        trusted_route_pristine_code,
    ) = _successor_dependency_call_roots
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_candidate_revocation_call_roots")
        is not _candidate_revocation_call_roots
        or function_defaults.get("_successor_dependency_call_roots")
        is not _successor_dependency_call_roots
        or _CANDIDATE_REVOCATION_CALL_ROOTS is not _candidate_revocation_call_roots
        or _CANDIDATE_SELECTION_SUCCESSOR_DEPENDENCY_CALL_ROOTS
        is not _successor_dependency_call_roots
        or _candidate_selection_successor_dependencies_are_pristine
        is not trusted_successor_pristine
        or getattr(trusted_successor_pristine, "__code__", None)
        is not trusted_successor_pristine_code
        or route_constraint_callables_are_pristine is not trusted_route_pristine
        or getattr(trusted_route_pristine, "__code__", None) is not trusted_route_pristine_code
        or route_constraints_module.route_constraint_callables_are_pristine
        is not trusted_route_pristine
        or candidate_revocation_callables_are_pristine is not trusted_pristine
        or require_candidate_assignment_eligible is not trusted_assignment_gate
        or require_selection_plan_routes_eligible is not trusted_plan_gate
        or candidate_revocation_module.candidate_revocation_callables_are_pristine
        is not trusted_pristine
        or candidate_revocation_module.require_candidate_assignment_eligible
        is not trusted_assignment_gate
        or candidate_revocation_module.require_selection_plan_routes_eligible
        is not trusted_plan_gate
        or not trusted_successor_pristine()
        or not trusted_route_pristine()
        or not trusted_pristine()
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    if type(plan) is not CandidateSelectionPlan:
        raise CandidateSelectionError("candidate selection plan has the wrong exact type")
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


type _CandidateSelectionSuccessorDerivationCallRoots = tuple[
    Callable[..., CandidateSelectionPlan],
    CodeType,
    Callable[..., CandidateSelectionPlan],
    CodeType,
    Callable[..., CandidateSelectionPlan],
    CodeType,
    Callable[[], bool],
    CodeType,
    Callable[[], bool],
    CodeType,
]


def _derive_candidate_selection_plan_successor_unchecked(
    *,
    predecessor: CandidateSelectionPlan,
    candidate_model_id: str,
    provider_endpoint: str,
    refresh_endpoint_inventory: bool = False,
    upgrade_price_cap_profile_v2: bool = False,
    upgrade_price_cap_profile_v3: bool = False,
) -> CandidateSelectionPlan:
    """Reproduce one structural successor without reinterpreting current eligibility."""

    function_defaults = _derive_candidate_selection_plan_successor_unchecked.__kwdefaults__
    if (
        type(function_defaults) is not dict
        or len(function_defaults) != 3
        or function_defaults.get("refresh_endpoint_inventory") is not False
        or function_defaults.get("upgrade_price_cap_profile_v2") is not False
        or function_defaults.get("upgrade_price_cap_profile_v3") is not False
    ):
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    if type(predecessor) is not CandidateSelectionPlan:
        raise CandidateSelectionError("candidate selection predecessor has the wrong exact type")
    try:
        canonical_predecessor = CandidateSelectionPlan.model_validate_json(
            CandidateSelectionPlan.model_dump_json(predecessor),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection predecessor is invalid") from exc
    selection = canonical_predecessor.authenticated_runner_selection
    unavailability = canonical_predecessor.authenticated_runner_unavailability
    if unavailability is not None:
        raise CandidateSelectionError(
            "unavailable candidate predecessor requires a separately authenticated "
            "ancestry transition"
        )
    if selection is None:
        raise CandidateSelectionError(
            "candidate selection predecessor has no authenticated runner assignment"
        )
    primary_judge_model_id = selection.primary_judge_model_id
    replay_judge_model_id = selection.replay_judge_model_id
    predecessor_profile = selection.route_predicate_profile
    retained_judge_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is not ExactRouteRole.CANDIDATE
    )
    predecessor_candidate_routes = {
        (constraint.exact_model_id, constraint.provider_endpoint)
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    }
    if (
        type(candidate_model_id) is not str
        or type(provider_endpoint) is not str
        or type(refresh_endpoint_inventory) is not bool
        or type(upgrade_price_cap_profile_v2) is not bool
        or type(upgrade_price_cap_profile_v3) is not bool
    ):
        raise CandidateSelectionError(
            "candidate selection successor route has the wrong exact type"
        )
    if upgrade_price_cap_profile_v2 and upgrade_price_cap_profile_v3:
        raise CandidateSelectionError(
            "candidate selection price-cap profile upgrades are mutually exclusive"
        )
    if upgrade_price_cap_profile_v3:
        raise CandidateSelectionError(
            "candidate selection V3 price-cap upgrade is unavailable because provider "
            "max_price cannot bind cache-write pricing"
        )
    entries_by_id = {entry.exact_model_id: entry for entry in canonical_predecessor.entries}
    selected_entry = entries_by_id.get(candidate_model_id)
    if selected_entry is None:
        raise CandidateSelectionError("candidate selection successor route is outside the plan")
    endpoint_is_listed = provider_endpoint in selected_entry.allowed_provider_endpoints
    if not endpoint_is_listed and not refresh_endpoint_inventory:
        raise CandidateSelectionError(
            "candidate selection successor route uses an unlisted endpoint"
        )
    if endpoint_is_listed and refresh_endpoint_inventory:
        raise CandidateSelectionError(
            "candidate endpoint inventory refresh requires a previously unlisted endpoint"
        )
    if candidate_model_id in {
        primary_judge_model_id,
        replay_judge_model_id,
    }:
        raise CandidateSelectionError("candidate selection successor would collide with a judge")
    if (
        candidate_model_id,
        provider_endpoint,
    ) in predecessor_candidate_routes and not (
        upgrade_price_cap_profile_v2 or upgrade_price_cap_profile_v3
    ):
        raise CandidateSelectionError(
            "candidate selection successor must change the candidate route"
        )

    rebuilt_entries = tuple(
        seal_candidate_selection_entry(
            exact_model_id=entry.exact_model_id,
            priority_rank=entry.priority_rank,
            advisory_lineage_group=entry.advisory_lineage_group,
            allowed_provider_endpoints=(
                (provider_endpoint,)
                if entry.exact_model_id == candidate_model_id
                else entry.allowed_provider_endpoints
            ),
        )
        for entry in canonical_predecessor.entries
    )
    profile = RoutePredicateProfile.model_validate_json(
        predecessor_profile.model_dump_json(),
        strict=True,
    )
    if upgrade_price_cap_profile_v2:
        if (
            profile.schema_version != "1.0"
            or profile.price_cap_algorithm
            is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
            or profile.price_component_unit_envelopes is not None
        ):
            raise CandidateSelectionError(
                "candidate selection V2 price-cap upgrade requires an exact V1 predecessor"
            )
        profile = RoutePredicateProfile.build(
            reasoning_policy_sha256=profile.reasoning_policy_sha256,
            reasoning_role_profile_sha256=profile.reasoning_role_profile_sha256,
            reasoning_role_binding_sha256=profile.reasoning_role_binding_sha256,
            reasoning_control_profile_sha256=profile.reasoning_control_profile_sha256,
            reserved_reasoning_tokens=profile.reserved_reasoning_tokens,
            minimum_prompt_tokens=profile.minimum_prompt_tokens,
            required_output_tokens=profile.required_output_tokens,
            minimum_context_tokens=profile.minimum_context_tokens,
            price_cap_algorithm=(ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2),
        )
    elif upgrade_price_cap_profile_v3:
        if (
            profile.schema_version != "1.1"
            or profile.price_cap_algorithm
            is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
        ):
            raise CandidateSelectionError(
                "candidate selection V3 price-cap upgrade requires an exact V2 predecessor"
            )
        profile = RoutePredicateProfile.build(
            reasoning_policy_sha256=profile.reasoning_policy_sha256,
            reasoning_role_profile_sha256=profile.reasoning_role_profile_sha256,
            reasoning_role_binding_sha256=profile.reasoning_role_binding_sha256,
            reasoning_control_profile_sha256=profile.reasoning_control_profile_sha256,
            reserved_reasoning_tokens=profile.reserved_reasoning_tokens,
            minimum_prompt_tokens=profile.minimum_prompt_tokens,
            required_output_tokens=profile.required_output_tokens,
            minimum_context_tokens=profile.minimum_context_tokens,
            price_cap_algorithm=(
                ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_PROMPT_DOMINATED_CACHE_WRITE_V3
            ),
        )
    if upgrade_price_cap_profile_v2 or upgrade_price_cap_profile_v3:
        judge_constraints = tuple(
            ExactRouteConstraint.build(
                role=constraint.role,
                exact_model_id=constraint.exact_model_id,
                provider_endpoint=constraint.provider_endpoint,
                profile=profile,
            )
            for constraint in retained_judge_constraints
        )
    else:
        judge_constraints = tuple(
            ExactRouteConstraint.model_validate_json(constraint.model_dump_json(), strict=True)
            for constraint in retained_judge_constraints
        )
    successor_selection = seal_authenticated_runner_selection(
        candidate_model_id=candidate_model_id,
        primary_judge_model_id=primary_judge_model_id,
        replay_judge_model_id=replay_judge_model_id,
        route_predicate_profile=profile,
        route_constraints=(
            ExactRouteConstraint.build(
                role=ExactRouteRole.CANDIDATE,
                exact_model_id=candidate_model_id,
                provider_endpoint=provider_endpoint,
                profile=profile,
            ),
            *judge_constraints,
        ),
    )
    successor = _seal_candidate_selection_plan(
        source_bindings=canonical_predecessor.source_bindings,
        entries=rebuilt_entries,
        authenticated_runner_selection=successor_selection,
        authenticated_runner_unavailability=None,
        endpoint_inventory_refresh=(
            _seal_candidate_selection_endpoint_inventory_refresh(
                predecessor_entry=selected_entry,
                provider_endpoint=provider_endpoint,
            )
            if refresh_endpoint_inventory
            else None
        ),
        unresolved_requirements=tuple(
            item
            for item in canonical_predecessor.unresolved_requirements
            if item != NO_ACTIVE_CANDIDATE_REQUIREMENT
        ),
        predecessor_plan_sha256=canonical_predecessor.plan_sha256,
    )
    return successor


def _derive_candidate_selection_plan_unavailable_successor_unchecked(
    *,
    predecessor: CandidateSelectionPlan,
    _revocation_registry_loader: Callable[[], CandidateSelectionRevocationRegistry] = (
        load_candidate_selection_revocation_registry
    ),
) -> CandidateSelectionPlan:
    """Derive one inactive successor only when every predecessor candidate route is tombstoned."""

    function_defaults = (
        _derive_candidate_selection_plan_unavailable_successor_unchecked.__kwdefaults__
    )
    if (
        type(function_defaults) is not dict
        or len(function_defaults) != 1
        or function_defaults.get("_revocation_registry_loader") is not _revocation_registry_loader
        or load_candidate_selection_revocation_registry is not _revocation_registry_loader
        or candidate_revocation_module.load_candidate_selection_revocation_registry
        is not _revocation_registry_loader
        or not candidate_revocation_callables_are_pristine()
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    if type(predecessor) is not CandidateSelectionPlan:
        raise CandidateSelectionError("candidate selection predecessor has the wrong exact type")
    try:
        canonical_predecessor = CandidateSelectionPlan.model_validate_json(
            CandidateSelectionPlan.model_dump_json(predecessor),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection predecessor is invalid") from exc
    selection = canonical_predecessor.authenticated_runner_selection
    if selection is None or canonical_predecessor.authenticated_runner_unavailability is not None:
        raise CandidateSelectionError(
            "candidate selection predecessor lacks one active runner assignment"
        )
    profile = selection.route_predicate_profile
    if (
        profile.schema_version != "1.0"
        or profile.price_cap_algorithm
        is not ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
        or profile.price_component_unit_envelopes is not None
    ):
        raise CandidateSelectionError(
            "candidate selection unavailable successor must preserve an exact V1 predecessor"
        )
    candidate_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    )
    if not candidate_constraints:
        raise CandidateSelectionError("candidate selection predecessor has no candidate route")
    registry = _revocation_registry_loader()
    matches: list[CandidateSelectionRevocationEntry] = []
    for constraint in candidate_constraints:
        exact_matches = tuple(
            entry
            for entry in registry.entries
            if entry.selection_plan_sha256 == canonical_predecessor.plan_sha256
            and entry.role is ExactRouteRole.CANDIDATE
            and entry.exact_model_id == constraint.exact_model_id
            and entry.provider_endpoint.casefold() == constraint.provider_endpoint.casefold()
            and entry.exact_route_constraint_sha256 == constraint.constraint_sha256
        )
        if len(exact_matches) != 1:
            raise CandidateSelectionError(
                "candidate selection predecessor does not have complete exact revocation custody"
            )
        matches.append(exact_matches[0])
    unavailable = _seal_candidate_selection_unavailable_state(
        predecessor_selection=selection,
        revocation_registry=registry,
        revocation_entries=tuple(matches),
    )
    return _seal_candidate_selection_plan(
        source_bindings=canonical_predecessor.source_bindings,
        entries=canonical_predecessor.entries,
        authenticated_runner_selection=None,
        authenticated_runner_unavailability=unavailable,
        endpoint_inventory_refresh=None,
        unresolved_requirements=tuple(
            sorted(
                {
                    *canonical_predecessor.unresolved_requirements,
                    NO_ACTIVE_CANDIDATE_REQUIREMENT,
                }
            )
        ),
        predecessor_plan_sha256=canonical_predecessor.plan_sha256,
    )


_CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS: _CandidateSelectionSuccessorDerivationCallRoots = (
    _derive_candidate_selection_plan_successor_unchecked,
    _derive_candidate_selection_plan_successor_unchecked.__code__,
    _derive_candidate_selection_plan_unavailable_successor_unchecked,
    _derive_candidate_selection_plan_unavailable_successor_unchecked.__code__,
    _require_candidate_selection_plan_currently_eligible_checked,
    _require_candidate_selection_plan_currently_eligible_checked.__code__,
    _candidate_selection_successor_dependencies_are_pristine,
    _candidate_selection_successor_dependencies_are_pristine.__code__,
    route_constraint_callables_are_pristine,
    route_constraint_callables_are_pristine.__code__,
)


def _derive_candidate_selection_plan_successor_checked(
    *,
    predecessor: CandidateSelectionPlan,
    candidate_model_id: str,
    provider_endpoint: str,
    refresh_endpoint_inventory: bool = False,
    upgrade_price_cap_profile_v2: bool = False,
    upgrade_price_cap_profile_v3: bool = False,
    _successor_call_roots: _CandidateSelectionSuccessorDerivationCallRoots = (
        _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS
    ),
) -> CandidateSelectionPlan:
    """Derive one currently eligible, nonauthorizing candidate-route successor."""

    function_defaults = _derive_candidate_selection_plan_successor_checked.__kwdefaults__
    if type(_successor_call_roots) is not tuple or len(_successor_call_roots) != 10:
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    (
        trusted_derivation,
        trusted_derivation_code,
        trusted_unavailability_derivation,
        trusted_unavailability_derivation_code,
        trusted_eligibility,
        trusted_eligibility_code,
        trusted_successor_pristine,
        trusted_successor_pristine_code,
        trusted_route_pristine,
        trusted_route_pristine_code,
    ) = _successor_call_roots
    if (
        type(function_defaults) is not dict
        or len(function_defaults) != 4
        or function_defaults.get("refresh_endpoint_inventory") is not False
        or function_defaults.get("upgrade_price_cap_profile_v2") is not False
        or function_defaults.get("upgrade_price_cap_profile_v3") is not False
        or function_defaults.get("_successor_call_roots") is not _successor_call_roots
        or _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS is not _successor_call_roots
        or _derive_candidate_selection_plan_successor_unchecked is not trusted_derivation
        or getattr(trusted_derivation, "__code__", None) is not trusted_derivation_code
        or _derive_candidate_selection_plan_unavailable_successor_unchecked
        is not trusted_unavailability_derivation
        or getattr(trusted_unavailability_derivation, "__code__", None)
        is not trusted_unavailability_derivation_code
        or _require_candidate_selection_plan_currently_eligible_checked is not trusted_eligibility
        or getattr(trusted_eligibility, "__code__", None) is not trusted_eligibility_code
        or _candidate_selection_successor_dependencies_are_pristine
        is not trusted_successor_pristine
        or getattr(trusted_successor_pristine, "__code__", None)
        is not trusted_successor_pristine_code
        or route_constraint_callables_are_pristine is not trusted_route_pristine
        or getattr(trusted_route_pristine, "__code__", None) is not trusted_route_pristine_code
        or route_constraints_module.route_constraint_callables_are_pristine
        is not trusted_route_pristine
        or not trusted_successor_pristine()
        or not trusted_route_pristine()
    ):
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    successor = trusted_derivation(
        predecessor=predecessor,
        candidate_model_id=candidate_model_id,
        provider_endpoint=provider_endpoint,
        refresh_endpoint_inventory=refresh_endpoint_inventory,
        upgrade_price_cap_profile_v2=upgrade_price_cap_profile_v2,
        upgrade_price_cap_profile_v3=upgrade_price_cap_profile_v3,
    )
    eligible = trusted_eligibility(successor)
    if type(eligible) is not CandidateSelectionPlan or eligible != successor:
        raise CandidateSelectionError("candidate selection successor eligibility result changed")
    return eligible


def _derive_candidate_selection_plan_unavailable_successor_checked(
    *,
    predecessor: CandidateSelectionPlan,
    _successor_call_roots: _CandidateSelectionSuccessorDerivationCallRoots = (
        _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS
    ),
) -> CandidateSelectionPlan:
    """Derive one currently eligible, nonauthorizing unavailable-candidate successor."""

    function_defaults = (
        _derive_candidate_selection_plan_unavailable_successor_checked.__kwdefaults__
    )
    if type(_successor_call_roots) is not tuple or len(_successor_call_roots) != 10:
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    (
        trusted_derivation,
        trusted_derivation_code,
        trusted_unavailability_derivation,
        trusted_unavailability_derivation_code,
        trusted_eligibility,
        trusted_eligibility_code,
        trusted_successor_pristine,
        trusted_successor_pristine_code,
        trusted_route_pristine,
        trusted_route_pristine_code,
    ) = _successor_call_roots
    if (
        type(function_defaults) is not dict
        or len(function_defaults) != 1
        or function_defaults.get("_successor_call_roots") is not _successor_call_roots
        or _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS is not _successor_call_roots
        or _derive_candidate_selection_plan_successor_unchecked is not trusted_derivation
        or getattr(trusted_derivation, "__code__", None) is not trusted_derivation_code
        or _derive_candidate_selection_plan_unavailable_successor_unchecked
        is not trusted_unavailability_derivation
        or getattr(trusted_unavailability_derivation, "__code__", None)
        is not trusted_unavailability_derivation_code
        or _require_candidate_selection_plan_currently_eligible_checked is not trusted_eligibility
        or getattr(trusted_eligibility, "__code__", None) is not trusted_eligibility_code
        or _candidate_selection_successor_dependencies_are_pristine
        is not trusted_successor_pristine
        or getattr(trusted_successor_pristine, "__code__", None)
        is not trusted_successor_pristine_code
        or route_constraint_callables_are_pristine is not trusted_route_pristine
        or getattr(trusted_route_pristine, "__code__", None) is not trusted_route_pristine_code
        or route_constraints_module.route_constraint_callables_are_pristine
        is not trusted_route_pristine
        or not trusted_successor_pristine()
        or not trusted_route_pristine()
    ):
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    successor = trusted_unavailability_derivation(predecessor=predecessor)
    eligible = trusted_eligibility(successor)
    if type(eligible) is not CandidateSelectionPlan or eligible != successor:
        raise CandidateSelectionError("candidate selection successor eligibility result changed")
    return eligible


def _validate_candidate_selection_plan_successor_checked(
    *,
    predecessor: CandidateSelectionPlan,
    successor: CandidateSelectionPlan,
    _successor_call_roots: _CandidateSelectionSuccessorDerivationCallRoots = (
        _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS
    ),
) -> CandidateSelectionPlan:
    """Reproduce and validate one exact immediate successor against its predecessor."""

    function_defaults = _validate_candidate_selection_plan_successor_checked.__kwdefaults__
    if type(_successor_call_roots) is not tuple or len(_successor_call_roots) != 10:
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    (
        trusted_derivation,
        trusted_derivation_code,
        trusted_unavailability_derivation,
        trusted_unavailability_derivation_code,
        trusted_eligibility,
        trusted_eligibility_code,
        trusted_successor_pristine,
        trusted_successor_pristine_code,
        trusted_route_pristine,
        trusted_route_pristine_code,
    ) = _successor_call_roots
    if (
        type(function_defaults) is not dict
        or function_defaults.get("_successor_call_roots") is not _successor_call_roots
        or _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS is not _successor_call_roots
        or _derive_candidate_selection_plan_successor_unchecked is not trusted_derivation
        or getattr(trusted_derivation, "__code__", None) is not trusted_derivation_code
        or _derive_candidate_selection_plan_unavailable_successor_unchecked
        is not trusted_unavailability_derivation
        or getattr(trusted_unavailability_derivation, "__code__", None)
        is not trusted_unavailability_derivation_code
        or _require_candidate_selection_plan_currently_eligible_checked is not trusted_eligibility
        or getattr(trusted_eligibility, "__code__", None) is not trusted_eligibility_code
        or _candidate_selection_successor_dependencies_are_pristine
        is not trusted_successor_pristine
        or getattr(trusted_successor_pristine, "__code__", None)
        is not trusted_successor_pristine_code
        or route_constraint_callables_are_pristine is not trusted_route_pristine
        or getattr(trusted_route_pristine, "__code__", None) is not trusted_route_pristine_code
        or route_constraints_module.route_constraint_callables_are_pristine
        is not trusted_route_pristine
        or not trusted_successor_pristine()
        or not trusted_route_pristine()
    ):
        raise CandidateSelectionError("candidate selection successor call boundary changed")
    if type(successor) is not CandidateSelectionPlan:
        raise CandidateSelectionError("candidate selection successor has the wrong exact type")
    if type(predecessor) is not CandidateSelectionPlan:
        raise CandidateSelectionError("candidate selection predecessor has the wrong exact type")
    try:
        canonical_successor = CandidateSelectionPlan.model_validate_json(
            CandidateSelectionPlan.model_dump_json(successor),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection successor is invalid") from exc
    selection = canonical_successor.authenticated_runner_selection
    if canonical_successor.authenticated_runner_unavailability is not None:
        expected_unavailable = trusted_unavailability_derivation(predecessor=predecessor)
        if canonical_successor != expected_unavailable:
            raise CandidateSelectionError(
                "candidate selection unavailable successor differs from its derivation"
            )
        return canonical_successor
    if selection is None:
        raise CandidateSelectionError(
            "candidate selection successor has no authenticated runner assignment"
        )
    candidate_constraints = tuple(
        constraint
        for constraint in selection.route_constraints
        if constraint.role is ExactRouteRole.CANDIDATE
    )
    if len(candidate_constraints) != 1:
        raise CandidateSelectionError(
            "candidate selection successor must bind one exact candidate route"
        )
    candidate_constraint = candidate_constraints[0]
    try:
        canonical_predecessor = CandidateSelectionPlan.model_validate_json(
            CandidateSelectionPlan.model_dump_json(predecessor),
            strict=True,
        )
    except ValueError as exc:
        raise CandidateSelectionError("candidate selection predecessor is invalid") from exc
    predecessor_selection = canonical_predecessor.authenticated_runner_selection
    predecessor_unavailability = canonical_predecessor.authenticated_runner_unavailability
    if predecessor_unavailability is not None:
        raise CandidateSelectionError(
            "unavailable candidate predecessor requires a separately authenticated "
            "ancestry transition"
        )
    if predecessor_selection is None:
        raise CandidateSelectionError(
            "candidate selection predecessor has no authenticated runner assignment"
        )
    predecessor_profile = predecessor_selection.route_predicate_profile
    predecessor_algorithm = predecessor_profile.price_cap_algorithm
    successor_algorithm = selection.route_predicate_profile.price_cap_algorithm
    if predecessor_algorithm is successor_algorithm:
        upgrade_price_cap_profile_v2 = False
        upgrade_price_cap_profile_v3 = False
    elif (
        predecessor_algorithm is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1
        and successor_algorithm is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
    ):
        upgrade_price_cap_profile_v2 = True
        upgrade_price_cap_profile_v3 = False
    elif (
        predecessor_algorithm is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_REQUEST_UNITS_V2
        and successor_algorithm
        is ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_PROMPT_DOMINATED_CACHE_WRITE_V3
    ):
        upgrade_price_cap_profile_v2 = False
        upgrade_price_cap_profile_v3 = True
    else:
        raise CandidateSelectionError(
            "candidate selection successor price-cap profile transition is invalid"
        )
    expected = trusted_derivation(
        predecessor=canonical_predecessor,
        candidate_model_id=candidate_constraint.exact_model_id,
        provider_endpoint=candidate_constraint.provider_endpoint,
        refresh_endpoint_inventory=canonical_successor.endpoint_inventory_refresh is not None,
        upgrade_price_cap_profile_v2=upgrade_price_cap_profile_v2,
        upgrade_price_cap_profile_v3=upgrade_price_cap_profile_v3,
    )
    if canonical_successor != expected:
        raise CandidateSelectionError("candidate selection successor differs from its derivation")
    return canonical_successor


def _read_open_candidate_selection_descriptor(descriptor: int, *, maximum: int) -> bytes:
    os.lseek(descriptor, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    value = b"".join(chunks)
    if len(value) > maximum:
        raise CandidateSelectionError("candidate selection successor readback is oversized")
    return value


def _reject_candidate_selection_output_links(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.is_symlink() or candidate.is_junction():
            raise CandidateSelectionError(
                "candidate selection successor path may not traverse filesystem links"
            )


def _unlink_exact_candidate_selection_output(
    path: Path,
    *,
    created_identity: tuple[int, int] | None,
) -> None:
    if created_identity is None:
        return
    try:
        metadata = os.lstat(path)
    except OSError:
        return
    if (metadata.st_dev, metadata.st_ino) == created_identity and stat.S_ISREG(metadata.st_mode):
        path.unlink(missing_ok=True)


def _preflight_candidate_selection_plan_successor_output_checked(path: Path) -> Path:
    """Validate one fresh private successor-plan destination."""

    if not isinstance(path, Path):
        raise CandidateSelectionError("candidate selection successor output path must be explicit")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute.suffix.casefold() != ".json":
        raise CandidateSelectionError("candidate selection successor output must use .json")
    _reject_candidate_selection_output_links(absolute)
    if absolute.exists() or absolute.is_symlink() or absolute.is_junction():
        raise CandidateSelectionError("candidate selection successor output must be a fresh file")
    return absolute


class _CandidateSelectionEligibility(Protocol):
    def __call__(self, plan: CandidateSelectionPlan) -> CandidateSelectionPlan: ...


class _CandidateSelectionSuccessorDeriver(Protocol):
    def __call__(
        self,
        *,
        predecessor: CandidateSelectionPlan,
        candidate_model_id: str,
        provider_endpoint: str,
        refresh_endpoint_inventory: bool = False,
        upgrade_price_cap_profile_v2: bool = False,
        upgrade_price_cap_profile_v3: bool = False,
    ) -> CandidateSelectionPlan: ...


class _CandidateSelectionUnavailableSuccessorDeriver(Protocol):
    def __call__(
        self,
        *,
        predecessor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan: ...


class _CandidateSelectionSuccessorValidator(Protocol):
    def __call__(
        self,
        *,
        predecessor: CandidateSelectionPlan,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan: ...


class _CandidateSelectionSuccessorPreflight(Protocol):
    def __call__(self, path: Path) -> Path: ...


class _CandidateSelectionSuccessorWriter(Protocol):
    def __call__(
        self,
        *,
        path: Path,
        predecessor: CandidateSelectionPlan,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan: ...


def _build_candidate_selection_successor_callable_boundary() -> tuple[
    Callable[[], bool],
    _CandidateSelectionEligibility,
    _CandidateSelectionSuccessorDeriver,
    _CandidateSelectionUnavailableSuccessorDeriver,
    _CandidateSelectionSuccessorValidator,
    _CandidateSelectionSuccessorPreflight,
    _CandidateSelectionSuccessorWriter,
]:
    """Seal successor derivation and publication against coherent runtime replacement."""

    module_globals = globals()
    empty_cell = object()
    error_type = CandidateSelectionError
    plan_type = CandidateSelectionPlan
    eligibility_implementation = _require_candidate_selection_plan_currently_eligible_checked
    derivation_implementation = _derive_candidate_selection_plan_successor_checked
    unavailability_derivation_implementation = (
        _derive_candidate_selection_plan_unavailable_successor_checked
    )
    validation_implementation = _validate_candidate_selection_plan_successor_checked
    preflight_implementation = _preflight_candidate_selection_plan_successor_output_checked
    reject_links_implementation = _reject_candidate_selection_output_links
    readback_implementation = _read_open_candidate_selection_descriptor
    unlink_implementation = _unlink_exact_candidate_selection_output
    stable_json_implementation = stable_json
    successor_pristine = _candidate_selection_successor_dependencies_are_pristine
    route_pristine = route_constraint_callables_are_pristine
    revocation_pristine = candidate_revocation_callables_are_pristine
    derivation_call_roots = _CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS
    revocation_call_roots = _CANDIDATE_REVOCATION_CALL_ROOTS
    maximum_plan_bytes = _MAX_PLAN_BYTES
    private_file_mode = 0o600
    nofollow_flag = _NOFOLLOW_FLAG
    nonblock_flag = _NONBLOCK_FLAG
    readonly_flag = os.O_RDONLY
    readwrite_flag = os.O_RDWR
    create_flag = os.O_CREAT
    exclusive_flag = os.O_EXCL
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    close_on_exec_flag = getattr(os, "O_CLOEXEC", 0)
    seek_start = os.SEEK_SET
    path_type = Path
    concrete_path_type = type(Path("."))

    chmod_descriptor = os.fchmod
    write_descriptor = os.write
    sync_descriptor = os.fsync
    stat_descriptor = os.fstat
    close_descriptor = os.close
    link_path = os.link
    open_path = os.open
    seek_descriptor = os.lseek
    read_descriptor = os.read
    stat_path = os.lstat
    stat_path_at = os.stat
    unlink_path_at = os.unlink
    make_directory_at = os.mkdir
    path_module = os.path
    absolute_path = os.path.abspath
    filesystem_path = os.fspath
    get_effective_uid = os.geteuid
    effective_uid = get_effective_uid()
    is_regular = stat.S_ISREG
    is_directory = stat.S_ISDIR
    file_mode = stat.S_IMODE
    unsafe_directory_write_bits = stat.S_IWGRP | stat.S_IWOTH

    external_bindings = (
        (os, "fchmod", chmod_descriptor),
        (os, "write", write_descriptor),
        (os, "fsync", sync_descriptor),
        (os, "fstat", stat_descriptor),
        (os, "close", close_descriptor),
        (os, "link", link_path),
        (os, "open", open_path),
        (os, "lseek", seek_descriptor),
        (os, "read", read_descriptor),
        (os, "lstat", stat_path),
        (os, "stat", stat_path_at),
        (os, "unlink", unlink_path_at),
        (os, "mkdir", make_directory_at),
        (os, "path", path_module),
        (os.path, "abspath", absolute_path),
        (os, "fspath", filesystem_path),
        (os, "geteuid", get_effective_uid),
        (os, "O_RDONLY", readonly_flag),
        (os, "O_RDWR", readwrite_flag),
        (os, "O_CREAT", create_flag),
        (os, "O_EXCL", exclusive_flag),
        (os, "SEEK_SET", seek_start),
        (stat, "S_ISREG", is_regular),
        (stat, "S_ISDIR", is_directory),
        (stat, "S_IMODE", file_mode),
        (stat, "S_IWGRP", stat.S_IWGRP),
        (stat, "S_IWOTH", stat.S_IWOTH),
        (
            candidate_revocation_module,
            "candidate_revocation_callables_are_pristine",
            revocation_pristine,
        ),
        (
            candidate_revocation_module,
            "require_candidate_assignment_eligible",
            require_candidate_assignment_eligible,
        ),
        (
            candidate_revocation_module,
            "require_selection_plan_routes_eligible",
            require_selection_plan_routes_eligible,
        ),
        (
            candidate_revocation_module,
            "load_candidate_selection_revocation_registry",
            load_candidate_selection_revocation_registry,
        ),
        (
            route_constraints_module,
            "route_constraint_callables_are_pristine",
            route_pristine,
        ),
    )
    effective_path_owners = (
        (path_type,) if concrete_path_type is path_type else (path_type, concrete_path_type)
    )
    path_owners = tuple(owner for owner in concrete_path_type.__mro__ if owner is not object)
    path_class_bindings = tuple((owner, tuple(vars(owner).items())) for owner in path_owners)
    mutable_path_class_bindings = tuple(
        (
            owner,
            name,
            value,
            tuple(value.items()) if type(value) is dict else tuple(value),
        )
        for owner, bindings in path_class_bindings
        for name, value in bindings
        if type(value) in {dict, list, set}
    )
    path_bindings = tuple(
        (owner, name, getattr(owner, name))
        for owner in effective_path_owners
        for name in (
            "exists",
            "is_dir",
            "is_junction",
            "is_symlink",
            "mkdir",
            "name",
            "parent",
            "parents",
            "suffix",
            "unlink",
        )
    )

    def open_directory_chain(
        directory: Path,
        *,
        create: bool,
    ) -> tuple[int, tuple[int, int]]:
        if (
            type(directory) is not concrete_path_type
            or not directory.is_absolute()
            or not directory.anchor
            or not directory_flag
            or not nofollow_flag
        ):
            raise error_type(
                "candidate selection successor output directory custody is unavailable"
            )
        flags = readonly_flag | directory_flag | nofollow_flag | nonblock_flag | close_on_exec_flag
        descriptor = -1
        try:
            descriptor = open_path(directory.anchor, flags)
            metadata = stat_descriptor(descriptor)
            if not is_directory(metadata.st_mode):
                raise error_type("candidate selection successor output ancestor is not a directory")
            for component in directory.parts[1:]:
                if component in {"", ".", ".."}:
                    raise error_type("candidate selection successor output path is not canonical")
                try:
                    child_descriptor = open_path(
                        component,
                        flags,
                        dir_fd=descriptor,
                    )
                except FileNotFoundError:
                    if not create:
                        raise
                    try:
                        make_directory_at(
                            component,
                            0o700,
                            dir_fd=descriptor,
                        )
                    except FileExistsError:
                        child_descriptor = open_path(
                            component,
                            flags,
                            dir_fd=descriptor,
                        )
                    else:
                        child_descriptor = open_path(
                            component,
                            flags,
                            dir_fd=descriptor,
                        )
                try:
                    child_metadata = stat_descriptor(child_descriptor)
                    if not is_directory(child_metadata.st_mode):
                        raise error_type(
                            "candidate selection successor output ancestor is not a directory"
                        )
                except BaseException:
                    close_descriptor(child_descriptor)
                    raise
                close_descriptor(descriptor)
                descriptor = child_descriptor
            final_metadata = stat_descriptor(descriptor)
            if (
                final_metadata.st_uid != effective_uid
                or file_mode(final_metadata.st_mode) & unsafe_directory_write_bits
            ):
                raise error_type(
                    "candidate selection successor output parent must be private and owned"
                )
            identity = (final_metadata.st_dev, final_metadata.st_ino)
            retained_descriptor = descriptor
            descriptor = -1
            return retained_descriptor, identity
        finally:
            if descriptor >= 0:
                close_descriptor(descriptor)

    def unlink_exact_output_at(
        parent_descriptor: int,
        name: str,
        *,
        created_identity: tuple[int, int] | None,
    ) -> None:
        if created_identity is None:
            return
        try:
            metadata = stat_path_at(
                name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except BaseException:
            return
        if (metadata.st_dev, metadata.st_ino) == created_identity and is_regular(metadata.st_mode):
            try:
                unlink_path_at(name, dir_fd=parent_descriptor)
            except BaseException:
                return

    def close_quietly(descriptor: int) -> None:
        try:
            close_descriptor(descriptor)
        except BaseException:
            return

    def snapshot(function: FunctionType) -> _CandidateSelectionFunctionState:
        closure = function.__closure__
        closure_values: list[tuple[CellType, object]] = []
        for cell in closure or ():
            try:
                value = cell.cell_contents
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        attributes = function.__dict__
        return (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple(sorted((function.__kwdefaults__ or {}).items())),
            function.__globals__,
            closure,
            tuple(closure_values),
            attributes,
            tuple(sorted(attributes.items())),
        )

    def function_state_is_current(state: _CandidateSelectionFunctionState) -> bool:
        (
            function,
            code,
            defaults,
            kwdefaults,
            kwdefault_items,
            function_globals,
            closure,
            closure_values,
            attributes,
            attribute_items,
        ) = state
        current_kwdefaults = function.__kwdefaults__
        current_attributes = function.__dict__
        if (
            type(function) is not FunctionType
            or type(current_kwdefaults) not in {dict, type(None)}
            or type(current_attributes) is not dict
            or function.__code__ is not code
            or function.__defaults__ is not defaults
            or current_kwdefaults is not kwdefaults
            or function.__globals__ is not function_globals
            or function.__closure__ is not closure
            or current_attributes is not attributes
            or len(current_kwdefaults or {}) != len(kwdefault_items)
            or any(
                (current_kwdefaults or {}).get(name) is not value for name, value in kwdefault_items
            )
            or len(current_attributes) != len(attribute_items)
            or any(current_attributes.get(name) is not value for name, value in attribute_items)
        ):
            return False
        current_closure = function.__closure__ or ()
        if len(current_closure) != len(closure_values):
            return False
        for current_cell, (expected_cell, expected_value) in zip(
            current_closure,
            closure_values,
            strict=True,
        ):
            if current_cell is not expected_cell:
                return False
            try:
                current_value = current_cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if current_value is not expected_value:
                return False
        return True

    def pristine() -> bool:
        try:
            if (
                aliases is not aliases_seal
                or derivation_call_roots is not derivation_call_roots_seal
                or external_bindings is not external_bindings_seal
                or fixed_globals is not fixed_globals_seal
                or module_globals is not module_globals_seal
                or mutable_path_class_bindings is not mutable_path_class_bindings_seal
                or path_bindings is not path_bindings_seal
                or path_class_bindings is not path_class_bindings_seal
                or revocation_call_roots is not revocation_call_roots_seal
                or states is not states_seal
                or module_globals.get("_candidate_selection_successor_callables_are_pristine")
                is not pristine
            ):
                return False
            if any(module_globals.get(name) is not expected for name, expected in aliases):
                return False
            if any(module_globals.get(name) is not expected for name, expected in fixed_globals):
                return False
            if (
                type(module_globals.get("_MAX_PLAN_BYTES")) is not int
                or module_globals.get("_MAX_PLAN_BYTES") != maximum_plan_bytes
                or type(module_globals.get("_PRIVATE_FILE_MODE")) is not int
                or module_globals.get("_PRIVATE_FILE_MODE") != private_file_mode
                or type(module_globals.get("_NOFOLLOW_FLAG")) is not int
                or module_globals.get("_NOFOLLOW_FLAG") != nofollow_flag
                or type(module_globals.get("_NONBLOCK_FLAG")) is not int
                or module_globals.get("_NONBLOCK_FLAG") != nonblock_flag
                or getattr(os, "O_DIRECTORY", 0) != directory_flag
                or module_globals.get("_CANDIDATE_REVOCATION_CALL_ROOTS")
                is not revocation_call_roots
                or module_globals.get("_CANDIDATE_SELECTION_SUCCESSOR_DERIVATION_CALL_ROOTS")
                is not derivation_call_roots
            ):
                return False
            if any(
                getattr(owner, name, None) is not expected
                for owner, name, expected in external_bindings
            ):
                return False
            if any(
                getattr(owner, name, None) is not expected
                for owner, name, expected in path_bindings
            ):
                return False
            for owner, expected_bindings in path_class_bindings:
                current_bindings = vars(owner)
                if len(current_bindings) != len(expected_bindings) or any(
                    current_bindings.get(name) is not expected
                    for name, expected in expected_bindings
                ):
                    return False
            for owner, name, container, expected_items in mutable_path_class_bindings:
                if vars(owner).get(name) is not container:
                    return False
                if type(container) is dict:
                    current_items = tuple(container.items())
                    if len(current_items) != len(expected_items) or any(
                        not any(
                            current_key is expected_key and current_value is expected_value
                            for current_key, current_value in current_items
                        )
                        for expected_key, expected_value in expected_items
                    ):
                        return False
                elif type(container) in {list, set}:
                    current_values = tuple(cast(list[Any] | set[Any], container))
                    if len(current_values) != len(expected_items) or any(
                        not any(current is expected for current in current_values)
                        for expected in expected_items
                    ):
                        return False
                else:
                    return False
            if (
                getattr(successor_pristine, "__code__", None) is not successor_pristine_code
                or getattr(route_pristine, "__code__", None) is not route_pristine_code
                or not successor_pristine()
                or not route_pristine()
                or not revocation_pristine()
            ):
                return False
            return all(function_state_is_current(state) for state in states)
        except BaseException:
            return False

    pristine_code = pristine.__code__
    successor_pristine_code = successor_pristine.__code__
    route_pristine_code = route_pristine.__code__

    def require_candidate_selection_plan_currently_eligible(
        plan: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Reject tombstoned routes through the sealed successor boundary."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor call boundary changed")
        return eligibility_implementation(plan)

    def derive_candidate_selection_plan_successor(
        *,
        predecessor: CandidateSelectionPlan,
        candidate_model_id: str,
        provider_endpoint: str,
        refresh_endpoint_inventory: bool = False,
        upgrade_price_cap_profile_v2: bool = False,
        upgrade_price_cap_profile_v3: bool = False,
    ) -> CandidateSelectionPlan:
        """Derive one currently eligible, nonauthorizing candidate-route successor."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor call boundary changed")
        return derivation_implementation(
            predecessor=predecessor,
            candidate_model_id=candidate_model_id,
            provider_endpoint=provider_endpoint,
            refresh_endpoint_inventory=refresh_endpoint_inventory,
            upgrade_price_cap_profile_v2=upgrade_price_cap_profile_v2,
            upgrade_price_cap_profile_v3=upgrade_price_cap_profile_v3,
        )

    def derive_candidate_selection_plan_unavailable_successor(
        *,
        predecessor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Derive one inactive successor after complete exact candidate revocation."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor call boundary changed")
        return unavailability_derivation_implementation(predecessor=predecessor)

    def validate_candidate_selection_plan_successor(
        *,
        predecessor: CandidateSelectionPlan,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Validate one exact immediate successor through the sealed boundary."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor call boundary changed")
        return validation_implementation(predecessor=predecessor, successor=successor)

    def preflight_candidate_selection_plan_successor_output(path: Path) -> Path:
        """Validate one fresh private destination through the sealed boundary."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor write boundary changed")
        if type(path) is not concrete_path_type:
            raise error_type("candidate selection successor output path must be explicit")
        absolute = preflight_implementation(path)
        parent_descriptor = -1
        try:
            parent_descriptor, _parent_identity = open_directory_chain(
                absolute.parent,
                create=True,
            )
            try:
                stat_path_at(
                    absolute.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise error_type("candidate selection successor output must be a fresh file")
        finally:
            if parent_descriptor >= 0:
                close_descriptor(parent_descriptor)
        return absolute

    def write_candidate_selection_plan_successor(
        *,
        path: Path,
        predecessor: CandidateSelectionPlan,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Atomically publish one fresh, canonical, mode-0600 successor plan."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate selection successor write boundary changed")
        canonical = validate_candidate_selection_plan_successor(
            predecessor=predecessor,
            successor=successor,
        )
        eligible = require_candidate_selection_plan_currently_eligible(canonical)
        if type(eligible) is not plan_type or eligible != canonical:
            raise error_type("candidate selection successor eligibility result changed")
        canonical = eligible
        serialized = stable_json_implementation(canonical).encode("utf-8")
        if not serialized or len(serialized) > maximum_plan_bytes:
            raise error_type("candidate selection successor exceeds its byte bound")
        absolute = preflight_candidate_selection_plan_successor_output(path)
        parent_descriptor = -1
        parent_identity: tuple[int, int] | None = None
        descriptor = -1
        temporary_name = ""
        published = False
        created_identity: tuple[int, int] | None = None
        try:
            parent_descriptor, parent_identity = open_directory_chain(
                absolute.parent,
                create=False,
            )
            creation_flags = (
                readwrite_flag
                | create_flag
                | exclusive_flag
                | nofollow_flag
                | nonblock_flag
                | close_on_exec_flag
            )
            for ordinal in range(256):
                candidate_name = f".mmaudit-selection-successor-{ordinal:03d}.tmp"
                try:
                    descriptor = open_path(
                        candidate_name,
                        creation_flags,
                        private_file_mode,
                        dir_fd=parent_descriptor,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate_name
                break
            if descriptor < 0 or not temporary_name:
                raise error_type("candidate selection successor temporary namespace is exhausted")
            opened_metadata = stat_descriptor(descriptor)
            created_identity = (opened_metadata.st_dev, opened_metadata.st_ino)
            if (
                not is_regular(opened_metadata.st_mode)
                or opened_metadata.st_nlink != 1
                or opened_metadata.st_size != 0
            ):
                raise OSError("candidate selection successor temporary artifact is not fresh")
            chmod_descriptor(descriptor, private_file_mode)
            view = memoryview(serialized)
            while view:
                written = write_descriptor(descriptor, view)
                if written <= 0:
                    raise OSError("candidate selection successor write made no progress")
                view = view[written:]
            sync_descriptor(descriptor)
            metadata = stat_descriptor(descriptor)
            if (
                created_identity != (metadata.st_dev, metadata.st_ino)
                or not is_regular(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size != len(serialized)
                or file_mode(metadata.st_mode) != private_file_mode
            ):
                raise OSError("candidate selection successor temporary artifact is not exact")

            reject_links_implementation(absolute.parent)
            try:
                link_path(
                    temporary_name,
                    absolute.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise error_type(
                    "candidate selection successor output must remain a fresh file"
                ) from exc
            unlink_path_at(temporary_name, dir_fd=parent_descriptor)

            final_descriptor = open_path(
                absolute.name,
                readonly_flag | nofollow_flag | nonblock_flag | close_on_exec_flag,
                dir_fd=parent_descriptor,
            )
            try:
                final_metadata = stat_descriptor(final_descriptor)
                if (
                    created_identity != (final_metadata.st_dev, final_metadata.st_ino)
                    or not is_regular(final_metadata.st_mode)
                    or final_metadata.st_nlink != 1
                    or final_metadata.st_size != len(serialized)
                    or file_mode(final_metadata.st_mode) != private_file_mode
                ):
                    raise OSError("published candidate selection successor is not exact")
                readback = readback_implementation(
                    final_descriptor,
                    maximum=len(serialized),
                )
            finally:
                close_descriptor(final_descriptor)
            if readback != serialized:
                raise OSError("published candidate selection successor bytes changed")
            parsed = plan_type.model_validate_json(readback, strict=True)
            if (
                parsed != canonical
                or stable_json_implementation(parsed).encode("utf-8") != readback
            ):
                raise error_type("published candidate selection successor is not canonical")
            final_path_metadata = stat_path_at(
                absolute.name,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if (
                created_identity != (final_path_metadata.st_dev, final_path_metadata.st_ino)
                or not is_regular(final_path_metadata.st_mode)
                or final_path_metadata.st_nlink != 1
                or final_path_metadata.st_size != len(serialized)
                or file_mode(final_path_metadata.st_mode) != private_file_mode
            ):
                raise OSError("published candidate selection successor path changed")
            sync_descriptor(parent_descriptor)
            verification_descriptor = -1
            verification_final_descriptor = -1
            try:
                verification_descriptor, verification_identity = open_directory_chain(
                    absolute.parent,
                    create=False,
                )
                if verification_identity != parent_identity:
                    raise OSError("candidate selection successor output parent identity changed")
                verification_final_descriptor = open_path(
                    absolute.name,
                    readonly_flag | nofollow_flag | nonblock_flag | close_on_exec_flag,
                    dir_fd=verification_descriptor,
                )
                verification_metadata = stat_descriptor(verification_final_descriptor)
                if (
                    created_identity != (verification_metadata.st_dev, verification_metadata.st_ino)
                    or not is_regular(verification_metadata.st_mode)
                    or verification_metadata.st_nlink != 1
                    or verification_metadata.st_size != len(serialized)
                    or file_mode(verification_metadata.st_mode) != private_file_mode
                    or readback_implementation(
                        verification_final_descriptor,
                        maximum=len(serialized),
                    )
                    != serialized
                ):
                    raise OSError("candidate selection successor output path changed")
            finally:
                if verification_final_descriptor >= 0:
                    close_quietly(verification_final_descriptor)
                if verification_descriptor >= 0:
                    close_quietly(verification_descriptor)
            published = True
            return parsed
        finally:
            cleanup_error: CandidateSelectionError | None = None
            cleanup_identity = created_identity
            if not published and parent_descriptor >= 0 and descriptor >= 0:
                if cleanup_identity is None:
                    try:
                        cleanup_metadata = stat_descriptor(descriptor)
                    except BaseException:
                        cleanup_error = error_type(
                            "candidate selection successor cleanup identity is unavailable"
                        )
                    else:
                        if is_regular(cleanup_metadata.st_mode):
                            cleanup_identity = (
                                cleanup_metadata.st_dev,
                                cleanup_metadata.st_ino,
                            )
                        else:
                            cleanup_error = error_type(
                                "candidate selection successor cleanup identity is invalid"
                            )
                for _attempt in range(2):
                    try:
                        unlink_exact_output_at(
                            parent_descriptor,
                            absolute.name,
                            created_identity=cleanup_identity,
                        )
                    except BaseException:
                        cleanup_error = error_type(
                            "candidate selection successor exact-output cleanup was interrupted"
                        )
                    try:
                        unlink_exact_output_at(
                            parent_descriptor,
                            temporary_name,
                            created_identity=cleanup_identity,
                        )
                    except BaseException:
                        cleanup_error = error_type(
                            "candidate selection successor temporary cleanup was interrupted"
                        )
                try:
                    cleanup_metadata = stat_descriptor(descriptor)
                except BaseException:
                    cleanup_error = error_type(
                        "candidate selection successor cleanup could not attest the exact artifact"
                    )
                else:
                    if cleanup_metadata.st_nlink == 0:
                        cleanup_error = None
                    else:
                        cleanup_error = error_type(
                            "candidate selection successor cleanup did not remove the exact artifact"
                        )
            if descriptor >= 0:
                close_quietly(descriptor)
            if parent_descriptor >= 0:
                close_quietly(parent_descriptor)
            if cleanup_error is not None:
                raise cleanup_error

    aliases = (
        (
            "_require_candidate_selection_plan_currently_eligible_checked",
            eligibility_implementation,
        ),
        ("_derive_candidate_selection_plan_successor_checked", derivation_implementation),
        (
            "_derive_candidate_selection_plan_unavailable_successor_checked",
            unavailability_derivation_implementation,
        ),
        ("_validate_candidate_selection_plan_successor_checked", validation_implementation),
        (
            "_preflight_candidate_selection_plan_successor_output_checked",
            preflight_implementation,
        ),
        ("_reject_candidate_selection_output_links", reject_links_implementation),
        ("_read_open_candidate_selection_descriptor", readback_implementation),
        ("_unlink_exact_candidate_selection_output", unlink_implementation),
        (
            "_candidate_selection_successor_callables_are_pristine",
            pristine,
        ),
        (
            "require_candidate_selection_plan_currently_eligible",
            require_candidate_selection_plan_currently_eligible,
        ),
        ("derive_candidate_selection_plan_successor", derive_candidate_selection_plan_successor),
        (
            "derive_candidate_selection_plan_unavailable_successor",
            derive_candidate_selection_plan_unavailable_successor,
        ),
        (
            "validate_candidate_selection_plan_successor",
            validate_candidate_selection_plan_successor,
        ),
        (
            "preflight_candidate_selection_plan_successor_output",
            preflight_candidate_selection_plan_successor_output,
        ),
        ("write_candidate_selection_plan_successor", write_candidate_selection_plan_successor),
    )
    fixed_globals = (
        ("CandidateSelectionError", error_type),
        ("CandidateSelectionPlan", plan_type),
        ("Path", path_type),
        ("candidate_revocation_module", candidate_revocation_module),
        (
            "candidate_revocation_callables_are_pristine",
            revocation_pristine,
        ),
        (
            "require_candidate_assignment_eligible",
            require_candidate_assignment_eligible,
        ),
        (
            "require_selection_plan_routes_eligible",
            require_selection_plan_routes_eligible,
        ),
        (
            "load_candidate_selection_revocation_registry",
            load_candidate_selection_revocation_registry,
        ),
        ("route_constraints_module", route_constraints_module),
        ("route_constraint_callables_are_pristine", route_pristine),
        (
            "_candidate_selection_successor_dependencies_are_pristine",
            successor_pristine,
        ),
        (
            "_derive_candidate_selection_plan_successor_unchecked",
            _derive_candidate_selection_plan_successor_unchecked,
        ),
        (
            "_derive_candidate_selection_plan_unavailable_successor_unchecked",
            _derive_candidate_selection_plan_unavailable_successor_unchecked,
        ),
        ("stable_json", stable_json_implementation),
        ("os", os),
        ("stat", stat),
    )
    path_descriptor_functions: list[FunctionType] = []
    for _path_owner, bindings in path_class_bindings:
        for _name, descriptor in bindings:
            if type(descriptor) is FunctionType:
                path_descriptor_functions.append(descriptor)
            elif type(descriptor) in {classmethod, staticmethod}:
                path_descriptor_functions.append(cast(FunctionType, cast(Any, descriptor).__func__))
            elif type(descriptor) is property:
                path_descriptor_functions.extend(
                    function
                    for function in (descriptor.fget, descriptor.fset, descriptor.fdel)
                    if type(function) is FunctionType
                )
    function_roots = tuple(
        dict.fromkeys(
            (
                eligibility_implementation,
                _derive_candidate_selection_plan_successor_unchecked,
                _derive_candidate_selection_plan_unavailable_successor_unchecked,
                derivation_implementation,
                unavailability_derivation_implementation,
                validation_implementation,
                preflight_implementation,
                reject_links_implementation,
                readback_implementation,
                unlink_implementation,
                stable_json_implementation,
                successor_pristine,
                route_pristine,
                revocation_pristine,
                require_candidate_assignment_eligible,
                require_selection_plan_routes_eligible,
                load_candidate_selection_revocation_registry,
                require_candidate_selection_plan_currently_eligible,
                derive_candidate_selection_plan_successor,
                derive_candidate_selection_plan_unavailable_successor,
                validate_candidate_selection_plan_successor,
                preflight_candidate_selection_plan_successor_output,
                write_candidate_selection_plan_successor,
                open_directory_chain,
                unlink_exact_output_at,
                close_quietly,
                *path_descriptor_functions,
                *(expected for _owner, _name, expected in external_bindings),
                *(expected for _owner, _name, expected in path_bindings),
            )
        )
    )
    states = tuple(
        snapshot(function) for function in function_roots if type(function) is FunctionType
    )
    aliases_seal = aliases
    derivation_call_roots_seal = derivation_call_roots
    external_bindings_seal = external_bindings
    fixed_globals_seal = fixed_globals
    module_globals_seal = module_globals
    mutable_path_class_bindings_seal = mutable_path_class_bindings
    path_bindings_seal = path_bindings
    path_class_bindings_seal = path_class_bindings
    revocation_call_roots_seal = revocation_call_roots
    states_seal = states
    return (
        pristine,
        require_candidate_selection_plan_currently_eligible,
        derive_candidate_selection_plan_successor,
        derive_candidate_selection_plan_unavailable_successor,
        validate_candidate_selection_plan_successor,
        preflight_candidate_selection_plan_successor_output,
        write_candidate_selection_plan_successor,
    )


(
    _candidate_selection_successor_callables_are_pristine,
    require_candidate_selection_plan_currently_eligible,
    derive_candidate_selection_plan_successor,
    derive_candidate_selection_plan_unavailable_successor,
    validate_candidate_selection_plan_successor,
    preflight_candidate_selection_plan_successor_output,
    write_candidate_selection_plan_successor,
) = _build_candidate_selection_successor_callable_boundary()
del _build_candidate_selection_successor_callable_boundary
if not _candidate_selection_successor_callables_are_pristine():
    raise RuntimeError("candidate selection successor callable boundary failed integrity check")


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
    if canonical.authenticated_runner_unavailability is not None:
        raise CandidateSelectionError(
            "candidate selection has no active candidate: NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
        )
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
        if canonical.authenticated_runner_unavailability is not None:
            raise CandidateSelectionError(
                "candidate selection has no active candidate: NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
            )
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
    if type(evidence) not in {
        OpenRouterModelDiscoveryPayload,
        OpenRouterModelDiscoveryEvidence,
    }:
        raise CandidateSelectionError("candidate selection discovery has the wrong exact type")
    route_custody = (
        evidence.endpoint_snapshot.route_predicate_profile,
        evidence.endpoint_snapshot.exact_route_constraint,
        evidence.endpoint_snapshot.normalized_route_facts,
        evidence.endpoint_snapshot.route_predicate_report,
    )
    selection = canonical.authenticated_runner_selection
    if selection is None:
        if canonical.authenticated_runner_unavailability is not None:
            raise CandidateSelectionError(
                "candidate selection has no active candidate: NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
            )
        if any(item is not None for item in route_custody):
            raise CandidateSelectionError(
                "unselected candidate discovery carries unexpected route custody"
            )
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
    elif any(item is not None for item in route_custody):
        raise CandidateSelectionError(
            "nonselected candidate discovery carries unexpected route custody"
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
    if (
        type(_candidate_revocation_call_roots) is not tuple
        or len(_candidate_revocation_call_roots) != 3
    ):
        raise CandidateSelectionError("candidate selection revocation boundary changed")
    trusted_pristine, trusted_assignment_gate, trusted_plan_gate = _candidate_revocation_call_roots
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
    canonical_plan = CandidateSelectionPlan.model_validate(plan.model_dump(mode="python"))
    if canonical_plan.authenticated_runner_unavailability is not None:
        raise CandidateSelectionError(
            "candidate selection has no active candidate: NO_ACTIVE_CANDIDATE_AFTER_REVOCATION"
        )
    manifest = OpenRouterModelDiscoveryRunManifest.model_validate(
        run_manifest.model_dump(mode="python")
    )
    selected_constraints = (
        ()
        if canonical_plan.authenticated_runner_selection is None
        else canonical_plan.authenticated_runner_selection.route_constraints
    )

    def assignment_role(
        *,
        exact_model_id: str,
        provider_endpoint: str,
    ) -> ExactRouteRole:
        matching = tuple(
            constraint.role
            for constraint in selected_constraints
            if constraint.exact_model_id == exact_model_id
            and constraint.provider_endpoint == provider_endpoint
        )
        if len(matching) > 1:
            raise CandidateSelectionError("candidate discovery route repeats selected role custody")
        return matching[0] if matching else ExactRouteRole.CANDIDATE

    try:
        for route in manifest.run_provenance.candidate_routes:
            trusted_assignment_gate(
                role=assignment_role(
                    exact_model_id=route.exact_model_id,
                    provider_endpoint=route.approved_provider_endpoint,
                ),
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
            role = assignment_role(
                exact_model_id=item.exact_model_id,
                provider_endpoint=item.approved_provider_endpoint,
            )
            for model_id in {item.exact_model_id, item.canonical_slug}:
                trusted_assignment_gate(
                    role=role,
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
