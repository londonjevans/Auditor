"""Repository-pinned ancestry custody for unavailable candidate-selection plans.

The active schema-v1.7 plan intentionally has no candidate assignment.  This module
authenticates its exact repository ancestry before a distinct, private schema-v1.8
reactivation plan can be derived.  The opaque capability and every serialized plan
remain nonauthorizing: no provider, adoption, qualification, runner, or release
authority is created here.
"""

from __future__ import annotations

import hashlib
import os
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import CellType, CodeType, FunctionType, ModuleType
from typing import Any, Literal, Never, SupportsIndex, cast

import mmaudit.models.candidate_revocation as candidate_revocation_module
import mmaudit.models.candidate_selection as candidate_selection_module
import mmaudit.release_io as release_io_module
from mmaudit.models.candidate_revocation import (
    CandidateSelectionRevocationError,
    candidate_revocation_callables_are_pristine,
    require_candidate_assignment_eligible,
)
from mmaudit.models.candidate_selection import (
    NO_ACTIVE_CANDIDATE_REQUIREMENT,
    CandidateSelectionError,
    CandidateSelectionPlan,
    CandidateSelectionPlanAncestryTransitionBinding,
    load_candidate_selection_plan,
    preflight_candidate_selection_plan_successor_output,
    require_candidate_selection_plan_currently_eligible,
    seal_authenticated_runner_selection,
    seal_candidate_selection_entry,
    validate_candidate_selection_plan_successor,
)
from mmaudit.models.route_constraints import (
    ExactRouteConstraint,
    ExactRouteRole,
    ProviderPriceCapAlgorithm,
    RoutePredicateProfile,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, write_json_evidence
from mmaudit.reporting.json_report import stable_json

_MAX_PLAN_BYTES = 2_000_000
_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_SELECTED_ANCESTOR_RELATIVE_PATH = "tests/fixtures/model_selection/revoked-active-plan-v1.4.json"
_UNAVAILABLE_PREDECESSOR_RELATIVE_PATH = "config/models.selection-plan.json"

SELECTED_ANCESTOR_RAW_SHA256 = "0da03b75dd608efade4c41e87de38139fb735576049f824365889be9c9a3ff24"
SELECTED_ANCESTOR_PLAN_SHA256 = "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
UNAVAILABLE_PREDECESSOR_RAW_SHA256 = (
    "4e7fff76ffb126a1cdf044cdfc889d79def96a29076aa11e3b42c7ef0ff9a695"
)
UNAVAILABLE_PREDECESSOR_PLAN_SHA256 = (
    "14566de1f7da5e4a769502bdd6a7e1ec6c0f193ed126c8fc85236f0851586fd3"
)
UNAVAILABLE_STATE_SHA256 = "98941c3253ffe0f1aa88890b1c8b7fafb7d6575ee28ca31cb7724f14e784ceae"
MATCHED_REVOCATION_SET_SHA256 = "7c0118f5c170d46e6d2478bf92cbd83d1be6b426bda36dd57a6fc93e2ffd18c5"


class CandidateSelectionPlanAncestryError(ValueError):
    """Raised when exact repository selection-plan ancestry cannot be replayed."""


@dataclass(frozen=True, slots=True)
class CandidateSelectionPlanAncestryProjection:
    """Fresh nonauthorizing projection from the opaque exact-ancestry capability."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["REPOSITORY_PINNED_SELECTION_PLAN_ANCESTRY"]
    status: Literal["VERIFIED_NONAUTHORIZING"]
    selected_ancestor_raw_sha256: str
    selected_ancestor_byte_count: int
    selected_ancestor_plan_sha256: str
    unavailable_predecessor_raw_sha256: str
    unavailable_predecessor_byte_count: int
    unavailable_predecessor_plan_sha256: str
    unavailable_state_sha256: str
    matched_revocation_set_sha256: str
    revocation_entry_sha256s: tuple[str, ...]
    withdrawn_candidate_constraint_sha256s: tuple[str, ...]
    selected_ancestor_role_assignment_sha256: str
    retained_route_predicate_profile_sha256: str
    retained_judge_constraint_sha256s: tuple[str, ...]
    exact_successor_replay_verified: Literal[True]
    candidate_reactivation_authorized: Literal[False]
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    benchmark_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    serialized_authority: Literal[False]
    projection_sha256: str


class VerifiedCandidateSelectionPlanAncestry:
    """PID-local opaque custody for the exact selected-to-unavailable plan chain."""

    __slots__ = ("__weakref__",)

    def __new__(
        cls,
        *_args: object,
        **_kwargs: object,
    ) -> VerifiedCandidateSelectionPlanAncestry:
        del cls
        raise TypeError("verified candidate-selection plan ancestry cannot be constructed directly")

    def __init_subclass__(cls, **_kwargs: object) -> Never:
        del cls
        raise TypeError("verified candidate-selection plan ancestry cannot be subclassed")

    def __copy__(self) -> Never:
        raise TypeError("verified candidate-selection plan ancestry cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified candidate-selection plan ancestry cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified candidate-selection plan ancestry cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified candidate-selection plan ancestry cannot be serialized")


@dataclass(frozen=True, slots=True)
class _ObservedCandidateSelectionPlanAncestry:
    selected_ancestor: CandidateSelectionPlan
    unavailable_predecessor: CandidateSelectionPlan
    projection: CandidateSelectionPlanAncestryProjection


@dataclass(frozen=True, slots=True)
class _VerifiedCandidateSelectionPlanAncestryState:
    process_id: int
    projection_sha256: str


type _AncestryFunctionState = tuple[
    FunctionType,
    CodeType,
    tuple[object, ...] | None,
    dict[str, Any] | None,
    tuple[tuple[str, object], ...],
    dict[str, Any],
    tuple[CellType, ...] | None,
    tuple[tuple[CellType, object], ...],
    dict[str, Any],
    tuple[tuple[str, object], ...],
]


def _projection_values(
    *,
    selected_ancestor: CandidateSelectionPlan,
    selected_ancestor_raw_sha256: str,
    selected_ancestor_byte_count: int,
    unavailable_predecessor: CandidateSelectionPlan,
    unavailable_predecessor_raw_sha256: str,
    unavailable_predecessor_byte_count: int,
) -> dict[str, object]:
    ancestor_selection = selected_ancestor.authenticated_runner_selection
    unavailable = unavailable_predecessor.authenticated_runner_unavailability
    if ancestor_selection is None or unavailable is None:
        raise CandidateSelectionPlanAncestryError(
            "candidate-selection ancestry lacks its selected or unavailable state"
        )
    return {
        "schema_version": "1.0",
        "artifact_kind": "REPOSITORY_PINNED_SELECTION_PLAN_ANCESTRY",
        "status": "VERIFIED_NONAUTHORIZING",
        "selected_ancestor_raw_sha256": selected_ancestor_raw_sha256,
        "selected_ancestor_byte_count": selected_ancestor_byte_count,
        "selected_ancestor_plan_sha256": selected_ancestor.plan_sha256,
        "unavailable_predecessor_raw_sha256": unavailable_predecessor_raw_sha256,
        "unavailable_predecessor_byte_count": unavailable_predecessor_byte_count,
        "unavailable_predecessor_plan_sha256": unavailable_predecessor.plan_sha256,
        "unavailable_state_sha256": unavailable.state_sha256,
        "matched_revocation_set_sha256": unavailable.matched_revocation_set_sha256,
        "revocation_entry_sha256s": unavailable.revocation_entry_sha256s,
        "withdrawn_candidate_constraint_sha256s": (
            unavailable.withdrawn_candidate_constraint_sha256s
        ),
        "selected_ancestor_role_assignment_sha256": ancestor_selection.role_assignment_sha256,
        "retained_route_predicate_profile_sha256": (
            unavailable.route_predicate_profile.profile_sha256
        ),
        "retained_judge_constraint_sha256s": tuple(
            sorted(item.constraint_sha256 for item in unavailable.judge_route_constraints)
        ),
        "exact_successor_replay_verified": True,
        "candidate_reactivation_authorized": False,
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


def _build_candidate_selection_plan_ancestry_runtime() -> tuple[
    Callable[[], VerifiedCandidateSelectionPlanAncestry],
    Callable[
        [VerifiedCandidateSelectionPlanAncestry],
        CandidateSelectionPlanAncestryProjection,
    ],
    Callable[..., CandidateSelectionPlan],
    Callable[..., CandidateSelectionPlan],
    Callable[..., CandidateSelectionPlan],
    Callable[..., CandidateSelectionPlanAncestryProjection],
]:
    """Seal exact ancestry verification and reactivation behind one runtime boundary."""

    namespace = globals()
    error_type = CandidateSelectionPlanAncestryError
    plan_error_type = CandidateSelectionError
    revocation_error_type = CandidateSelectionRevocationError
    plan_type = CandidateSelectionPlan
    binding_type = CandidateSelectionPlanAncestryTransitionBinding
    projection_type = CandidateSelectionPlanAncestryProjection
    capability_type = VerifiedCandidateSelectionPlanAncestry
    observed_type = _ObservedCandidateSelectionPlanAncestry
    state_type = _VerifiedCandidateSelectionPlanAncestryState
    route_constraint_type = ExactRouteConstraint
    route_profile_type = RoutePredicateProfile
    candidate_role = ExactRouteRole.CANDIDATE
    v1_price_algorithm = ProviderPriceCapAlgorithm.OPENROUTER_MAX_PRICE_CEILING_V1

    repository_root = _REPOSITORY_ROOT
    ancestor_relative_path = _SELECTED_ANCESTOR_RELATIVE_PATH
    unavailable_relative_path = _UNAVAILABLE_PREDECESSOR_RELATIVE_PATH
    ancestor_raw_sha256 = SELECTED_ANCESTOR_RAW_SHA256
    ancestor_plan_sha256 = SELECTED_ANCESTOR_PLAN_SHA256
    unavailable_raw_sha256 = UNAVAILABLE_PREDECESSOR_RAW_SHA256
    unavailable_plan_sha256 = UNAVAILABLE_PREDECESSOR_PLAN_SHA256
    unavailable_state_sha256 = UNAVAILABLE_STATE_SHA256
    matched_revocation_set_sha256 = MATCHED_REVOCATION_SET_SHA256
    maximum_plan_bytes = _MAX_PLAN_BYTES
    no_candidate_requirement = NO_ACTIVE_CANDIDATE_REQUIREMENT

    trusted_read = read_file_evidence
    trusted_write = write_json_evidence
    trusted_load = load_candidate_selection_plan
    trusted_preflight = preflight_candidate_selection_plan_successor_output
    trusted_validate_successor = validate_candidate_selection_plan_successor
    trusted_require_eligible = require_candidate_selection_plan_currently_eligible
    trusted_seal_selection = seal_authenticated_runner_selection
    trusted_seal_entry = seal_candidate_selection_entry
    trusted_seal_plan = candidate_selection_module._seal_candidate_selection_plan
    trusted_assignment_gate = require_candidate_assignment_eligible
    trusted_candidate_pristine = (
        candidate_selection_module._candidate_selection_successor_callables_are_pristine
    )
    trusted_revocation_pristine = candidate_revocation_callables_are_pristine
    trusted_canonical_sha256 = canonical_sha256
    trusted_stable_json = stable_json
    trusted_projection_values = _projection_values
    trusted_sha256 = hashlib.sha256
    trusted_getpid = os.getpid
    trusted_object_new = object.__new__
    trusted_weakref = weakref.ref
    trusted_identity = id

    lock = threading.RLock()
    # WeakKeyDictionary delegates to the referent's equality/hash implementation.
    # A caller must hold the exact issued instance, never an equal-looking object.
    states: dict[
        int,
        tuple[
            weakref.ReferenceType[VerifiedCandidateSelectionPlanAncestry],
            _VerifiedCandidateSelectionPlanAncestryState,
        ],
    ] = {}
    public_bindings: tuple[tuple[str, object], ...] = ()
    class_bindings = tuple(
        (guarded_type, tuple(vars(guarded_type).items()))
        for guarded_type in (
            capability_type,
            state_type,
            observed_type,
            projection_type,
            release_io_module._RootHandle,
            release_io_module._FileObservation,
            release_io_module.FileEvidenceObservation,
            ManifestFileBinding,
        )
    )
    mutable_class_bindings = tuple(
        (guarded_type, name, value, tuple(value.items()))
        for guarded_type, bindings in class_bindings
        for name, value in bindings
        if type(value) is dict
    )
    empty_cell = object()
    function_states: tuple[_AncestryFunctionState, ...] = ()
    function_states_seal = function_states

    def snapshot_function(function: FunctionType) -> _AncestryFunctionState:
        closure_values: list[tuple[CellType, object]] = []
        for name, cell in zip(
            function.__code__.co_freevars, function.__closure__ or (), strict=True
        ):
            # Self-referential verifier metadata is sealed separately by identity.
            if function is require_pristine and name in {"function_states", "function_states_seal"}:
                continue
            try:
                value = cell.cell_contents
            except ValueError:
                value = empty_cell
            closure_values.append((cell, value))
        return (
            function,
            function.__code__,
            function.__defaults__,
            function.__kwdefaults__,
            tuple((function.__kwdefaults__ or {}).items()),
            function.__globals__,
            function.__closure__,
            tuple(closure_values),
            function.__dict__,
            tuple(function.__dict__.items()),
        )

    def function_state_is_current(state: _AncestryFunctionState) -> bool:
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
        if (
            function.__code__ is not code
            or function.__defaults__ is not defaults
            or function.__kwdefaults__ is not kwdefaults
            or function.__globals__ is not function_globals
            or function.__closure__ is not closure
            or function.__dict__ is not attributes
            or len(function.__kwdefaults__ or {}) != len(kwdefault_items)
            or any(
                (function.__kwdefaults__ or {}).get(name) is not value
                for name, value in kwdefault_items
            )
            or len(function.__dict__) != len(attribute_items)
            or any(function.__dict__.get(name) is not value for name, value in attribute_items)
        ):
            return False
        for cell, expected_value in closure_values:
            try:
                current_value = cell.cell_contents
            except ValueError:
                current_value = empty_cell
            if current_value is not expected_value:
                return False
        return True

    snapshot_code = snapshot_function.__code__
    state_check_code = function_state_is_current.__code__
    class_bindings_seal = class_bindings
    mutable_class_bindings_seal = mutable_class_bindings

    fixed_globals = tuple(
        {
            "_REPOSITORY_ROOT": repository_root,
            "_SELECTED_ANCESTOR_RELATIVE_PATH": ancestor_relative_path,
            "_UNAVAILABLE_PREDECESSOR_RELATIVE_PATH": unavailable_relative_path,
            "SELECTED_ANCESTOR_RAW_SHA256": ancestor_raw_sha256,
            "SELECTED_ANCESTOR_PLAN_SHA256": ancestor_plan_sha256,
            "UNAVAILABLE_PREDECESSOR_RAW_SHA256": unavailable_raw_sha256,
            "UNAVAILABLE_PREDECESSOR_PLAN_SHA256": unavailable_plan_sha256,
            "UNAVAILABLE_STATE_SHA256": unavailable_state_sha256,
            "MATCHED_REVOCATION_SET_SHA256": matched_revocation_set_sha256,
            "CandidateSelectionPlan": plan_type,
            "CandidateSelectionPlanAncestryTransitionBinding": binding_type,
            "CandidateSelectionPlanAncestryProjection": projection_type,
            "VerifiedCandidateSelectionPlanAncestry": capability_type,
            "CandidateSelectionPlanAncestryError": error_type,
            "_projection_values": trusted_projection_values,
            "candidate_selection_module": candidate_selection_module,
            "candidate_revocation_module": candidate_revocation_module,
            "release_io_module": release_io_module,
        }.items()
    )
    external_bindings = (
        (candidate_selection_module, "seal_candidate_selection_entry", trusted_seal_entry),
        (candidate_selection_module, "_seal_candidate_selection_plan", trusted_seal_plan),
        (
            candidate_selection_module,
            "_candidate_selection_successor_callables_are_pristine",
            trusted_candidate_pristine,
        ),
        (
            candidate_selection_module,
            "validate_candidate_selection_plan_successor",
            trusted_validate_successor,
        ),
        (
            candidate_selection_module,
            "require_candidate_selection_plan_currently_eligible",
            trusted_require_eligible,
        ),
        (
            candidate_selection_module,
            "preflight_candidate_selection_plan_successor_output",
            trusted_preflight,
        ),
        (candidate_selection_module, "load_candidate_selection_plan", trusted_load),
        (
            candidate_revocation_module,
            "candidate_revocation_callables_are_pristine",
            trusted_revocation_pristine,
        ),
        (
            candidate_revocation_module,
            "require_candidate_assignment_eligible",
            trusted_assignment_gate,
        ),
        (release_io_module, "read_file_evidence", trusted_read),
        (release_io_module, "write_json_evidence", trusted_write),
    )
    # Follow the repository-owned I/O call graph, including globals referenced by
    # nested code. Pin direct platform bindings without claiming a Python sandbox.
    # Attribute identity alone would miss in-place helper-code/default mutation.
    io_functions: dict[FunctionType, None] = {}
    io_globals: dict[tuple[int, str], tuple[dict[str, Any], str, object]] = {}
    io_attributes: dict[tuple[ModuleType, str], tuple[ModuleType, str, object]] = {}
    missing_io_global = object()
    pending_io_functions = [cast(FunctionType, trusted_read), cast(FunctionType, trusted_write)]
    visited_io_functions: set[FunctionType] = set()
    while pending_io_functions:
        io_function = pending_io_functions.pop()
        if io_function in visited_io_functions:
            continue
        visited_io_functions.add(io_function)
        io_functions[io_function] = None
        pending_codes = [io_function.__code__]
        global_names: set[str] = set()
        attribute_names: set[str] = set()
        while pending_codes:
            code = pending_codes.pop()
            global_names.update(code.co_names)
            attribute_names.update(code.co_names)
            for constant in code.co_consts:
                if type(constant) is CodeType:
                    pending_codes.append(constant)
                elif type(constant) is str and constant.isidentifier():
                    attribute_names.add(constant)
        pending_modules: list[ModuleType] = []
        dependencies: list[object] = []
        builtins_mapping = cast(dict[str, Any], cast(Any, io_function).__builtins__)
        for name in sorted(global_names):
            mapping = io_function.__globals__
            value = mapping.get(name, missing_io_global)
            io_globals[(id(mapping), name)] = (mapping, name, value)
            dependencies.append(value)
            if value is missing_io_global and name in builtins_mapping:
                io_globals[(id(builtins_mapping), name)] = (
                    builtins_mapping,
                    name,
                    builtins_mapping[name],
                )
            if type(value) is ModuleType:
                pending_modules.append(value)
        visited_modules: set[ModuleType] = set()
        while pending_modules:
            owner = pending_modules.pop()
            if owner in visited_modules:
                continue
            visited_modules.add(owner)
            for name in sorted(attribute_names):
                if name not in vars(owner):
                    continue
                value = vars(owner)[name]
                io_attributes[(owner, name)] = (owner, name, value)
                dependencies.append(value)
                if type(value) is ModuleType:
                    pending_modules.append(value)
        for dependency in dependencies:
            if type(dependency) is FunctionType:
                io_functions[dependency] = None
                if dependency.__module__.startswith("mmaudit."):
                    pending_io_functions.append(dependency)
    io_global_bindings = tuple(io_globals.values())
    io_external_bindings = tuple(io_attributes.values())
    io_dependency_functions = tuple(io_functions)
    function_codes: tuple[tuple[object, object], ...] = (
        (trusted_seal_entry, trusted_seal_entry.__code__),
        (trusted_candidate_pristine, getattr(trusted_candidate_pristine, "__code__", None)),
        (trusted_revocation_pristine, getattr(trusted_revocation_pristine, "__code__", None)),
        (trusted_validate_successor, getattr(trusted_validate_successor, "__code__", None)),
        (trusted_require_eligible, getattr(trusted_require_eligible, "__code__", None)),
        (trusted_preflight, getattr(trusted_preflight, "__code__", None)),
        (trusted_load, getattr(trusted_load, "__code__", None)),
        (trusted_read, getattr(trusted_read, "__code__", None)),
        (trusted_write, getattr(trusted_write, "__code__", None)),
        (trusted_assignment_gate, getattr(trusted_assignment_gate, "__code__", None)),
        (trusted_stable_json, getattr(trusted_stable_json, "__code__", None)),
        (trusted_canonical_sha256, getattr(trusted_canonical_sha256, "__code__", None)),
        (trusted_projection_values, trusted_projection_values.__code__),
    )

    def require_pristine() -> None:
        if (
            function_states is not function_states_seal
            or class_bindings is not class_bindings_seal
            or mutable_class_bindings is not mutable_class_bindings_seal
            or snapshot_function.__code__ is not snapshot_code
            or function_state_is_current.__code__ is not state_check_code
            or any(namespace.get(name) is not value for name, value in fixed_globals)
            or any(
                getattr(owner, name, None) is not value for owner, name, value in external_bindings
            )
            or any(
                mapping.get(name, missing_io_global) is not value
                for mapping, name, value in io_global_bindings
            )
            or any(
                vars(owner).get(name, missing_io_global) is not value
                for owner, name, value in io_external_bindings
            )
            or any(
                getattr(function, "__code__", None) is not code for function, code in function_codes
            )
            or hashlib.sha256 is not trusted_sha256
            or os.getpid is not trusted_getpid
            or weakref.ref is not trusted_weakref
            or any(
                len(vars(guarded_type)) != len(bindings)
                or any(vars(guarded_type).get(name) is not value for name, value in bindings)
                for guarded_type, bindings in class_bindings
            )
            or any(
                vars(guarded_type).get(name) is not container
                or len(container) != len(items)
                or any(container.get(key) is not value for key, value in items)
                for guarded_type, name, container, items in mutable_class_bindings
            )
            or not all(function_state_is_current(state) for state in function_states)
            or not trusted_candidate_pristine()
            or not trusted_revocation_pristine()
            or any(namespace.get(name) is not value for name, value in public_bindings)
        ):
            raise error_type("candidate-selection ancestry runtime boundary changed")

    pristine_code = require_pristine.__code__

    def load_exact_plan(
        *,
        root: Path,
        relative_path: str,
        expected_raw_sha256: str,
        expected_plan_sha256: str,
        expected_schema_version: str,
    ) -> tuple[CandidateSelectionPlan, int]:
        try:
            observation = trusted_read(
                evidence_root=root,
                relative_path=relative_path,
                max_bytes=maximum_plan_bytes,
            )
            if observation.binding.sha256 != expected_raw_sha256:
                raise error_type("candidate-selection ancestry raw byte identity changed")
            plan = plan_type.model_validate_json(observation.content, strict=True)
            if (
                type(plan) is not plan_type
                or plan.schema_version != expected_schema_version
                or plan.plan_sha256 != expected_plan_sha256
                or trusted_stable_json(plan).encode("utf-8") != observation.content
            ):
                raise error_type("candidate-selection ancestry plan identity changed")
            return plan, len(observation.content)
        except error_type:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise error_type("candidate-selection ancestry plan could not be read safely") from exc

    def observe_once(
        *,
        root: Path,
        selected_relative_path: str,
        unavailable_relative_path_value: str,
        expected_selected_raw_sha256: str,
        expected_selected_plan_sha256: str,
        expected_unavailable_raw_sha256: str,
        expected_unavailable_plan_sha256: str,
        expected_unavailable_state_sha256: str,
        expected_matched_revocation_set_sha256: str,
    ) -> _ObservedCandidateSelectionPlanAncestry:
        selected, selected_size = load_exact_plan(
            root=root,
            relative_path=selected_relative_path,
            expected_raw_sha256=expected_selected_raw_sha256,
            expected_plan_sha256=expected_selected_plan_sha256,
            expected_schema_version="1.4",
        )
        unavailable, unavailable_size = load_exact_plan(
            root=root,
            relative_path=unavailable_relative_path_value,
            expected_raw_sha256=expected_unavailable_raw_sha256,
            expected_plan_sha256=expected_unavailable_plan_sha256,
            expected_schema_version="1.7",
        )
        selected_assignment = selected.authenticated_runner_selection
        unavailable_state = unavailable.authenticated_runner_unavailability
        if (
            selected_assignment is None
            or unavailable.authenticated_runner_selection is not None
            or unavailable_state is None
            or unavailable.predecessor_plan_sha256 != selected.plan_sha256
            or unavailable_state.state_sha256 != expected_unavailable_state_sha256
            or unavailable_state.matched_revocation_set_sha256
            != expected_matched_revocation_set_sha256
            or unavailable_state.predecessor_role_assignment_sha256
            != selected_assignment.role_assignment_sha256
            or unavailable_state.route_predicate_profile
            != selected_assignment.route_predicate_profile
            or unavailable_state.judge_route_constraints
            != tuple(
                item
                for item in selected_assignment.route_constraints
                if item.role is not candidate_role
            )
        ):
            raise error_type("candidate-selection ancestry custody differs from its compiled chain")
        profile = unavailable_state.route_predicate_profile
        if (
            profile.schema_version != "1.0"
            or profile.price_cap_algorithm is not v1_price_algorithm
            or profile.price_component_unit_envelopes is not None
        ):
            raise error_type("candidate-selection ancestry does not retain the exact V1 profile")
        try:
            replayed = trusted_validate_successor(predecessor=selected, successor=unavailable)
        except (plan_error_type, ValueError) as exc:
            raise error_type("candidate-selection ancestry exact successor replay failed") from exc
        if type(replayed) is not plan_type or replayed != unavailable:
            raise error_type("candidate-selection ancestry successor replay result changed")
        values = trusted_projection_values(
            selected_ancestor=selected,
            selected_ancestor_raw_sha256=expected_selected_raw_sha256,
            selected_ancestor_byte_count=selected_size,
            unavailable_predecessor=unavailable,
            unavailable_predecessor_raw_sha256=expected_unavailable_raw_sha256,
            unavailable_predecessor_byte_count=unavailable_size,
        )
        projection = projection_type(
            **cast(dict[str, Any], values),
            projection_sha256=trusted_canonical_sha256(values),
        )
        return observed_type(
            selected_ancestor=selected,
            unavailable_predecessor=unavailable,
            projection=projection,
        )

    def observe_pair(
        *,
        root: Path = repository_root,
        selected_relative_path: str = ancestor_relative_path,
        unavailable_relative_path_value: str = unavailable_relative_path,
        expected_selected_raw_sha256: str = ancestor_raw_sha256,
        expected_selected_plan_sha256: str = ancestor_plan_sha256,
        expected_unavailable_raw_sha256: str = unavailable_raw_sha256,
        expected_unavailable_plan_sha256: str = unavailable_plan_sha256,
        expected_unavailable_state_sha256: str = unavailable_state_sha256,
        expected_matched_revocation_set_sha256: str = matched_revocation_set_sha256,
        between_reads: Callable[[], None] | None = None,
    ) -> _ObservedCandidateSelectionPlanAncestry:
        first = observe_once(
            root=root,
            selected_relative_path=selected_relative_path,
            unavailable_relative_path_value=unavailable_relative_path_value,
            expected_selected_raw_sha256=expected_selected_raw_sha256,
            expected_selected_plan_sha256=expected_selected_plan_sha256,
            expected_unavailable_raw_sha256=expected_unavailable_raw_sha256,
            expected_unavailable_plan_sha256=expected_unavailable_plan_sha256,
            expected_unavailable_state_sha256=expected_unavailable_state_sha256,
            expected_matched_revocation_set_sha256=expected_matched_revocation_set_sha256,
        )
        if between_reads is not None:
            between_reads()
        second = observe_once(
            root=root,
            selected_relative_path=selected_relative_path,
            unavailable_relative_path_value=unavailable_relative_path_value,
            expected_selected_raw_sha256=expected_selected_raw_sha256,
            expected_selected_plan_sha256=expected_selected_plan_sha256,
            expected_unavailable_raw_sha256=expected_unavailable_raw_sha256,
            expected_unavailable_plan_sha256=expected_unavailable_plan_sha256,
            expected_unavailable_state_sha256=expected_unavailable_state_sha256,
            expected_matched_revocation_set_sha256=expected_matched_revocation_set_sha256,
        )
        if first != second:
            raise error_type("candidate-selection ancestry changed during verification")
        return second

    def replay(
        capability: VerifiedCandidateSelectionPlanAncestry,
    ) -> _ObservedCandidateSelectionPlanAncestry:
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        if type(capability) is not capability_type:
            raise TypeError("candidate-selection ancestry capability has the wrong exact type")
        with lock:
            entry = states.get(trusted_identity(capability))
        if (
            entry is None
            or entry[0]() is not capability
            or type(entry[1]) is not state_type
            or entry[1].process_id != trusted_getpid()
        ):
            raise error_type("candidate-selection ancestry capability is absent or fork-inherited")
        state = entry[1]
        observed = observe_pair()
        if observed.projection.projection_sha256 != state.projection_sha256:
            raise error_type("candidate-selection ancestry changed after capability issuance")
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return observed

    def resolve_verified_candidate_selection_plan_ancestry() -> (
        VerifiedCandidateSelectionPlanAncestry
    ):
        """Issue opaque ancestry custody only for the compiled repository plan pair."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        observed = observe_pair()
        capability = trusted_object_new(capability_type)
        state = state_type(
            process_id=trusted_getpid(),
            projection_sha256=observed.projection.projection_sha256,
        )
        capability_id = trusted_identity(capability)

        def retire(
            reference: weakref.ReferenceType[VerifiedCandidateSelectionPlanAncestry],
        ) -> None:
            with lock:
                entry = states.get(capability_id)
                if entry is not None and entry[0] is reference:
                    del states[capability_id]

        with lock:
            states[capability_id] = (trusted_weakref(capability, retire), state)
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return capability

    def candidate_selection_plan_ancestry_projection(
        capability: VerifiedCandidateSelectionPlanAncestry,
    ) -> CandidateSelectionPlanAncestryProjection:
        """Return a fresh nonauthorizing projection after exact current replay."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        result = replay(capability).projection
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return result

    def derive_impl(
        capability: VerifiedCandidateSelectionPlanAncestry,
        *,
        candidate_model_id: str,
        provider_endpoint: str,
    ) -> CandidateSelectionPlan:
        observed = replay(capability)
        predecessor = observed.unavailable_predecessor
        projection = observed.projection
        unavailable = predecessor.authenticated_runner_unavailability
        if unavailable is None:
            raise error_type("candidate-selection ancestry predecessor is not unavailable")
        if type(candidate_model_id) is not str or type(provider_endpoint) is not str:
            raise error_type("candidate-selection reactivation route has the wrong exact type")
        if provider_endpoint != provider_endpoint.casefold():
            raise error_type(
                "candidate-selection reactivation endpoint must be canonical lowercase"
            )
        entries_by_id = {item.exact_model_id: item for item in predecessor.entries}
        entry = entries_by_id.get(candidate_model_id)
        if entry is None:
            raise error_type("candidate-selection reactivation route is outside the plan")
        if provider_endpoint not in entry.allowed_provider_endpoints:
            raise error_type("candidate-selection reactivation route uses an unlisted endpoint")
        if candidate_model_id in {
            unavailable.primary_judge_model_id,
            unavailable.replay_judge_model_id,
        }:
            raise error_type("candidate-selection reactivation would collide with a judge")
        try:
            trusted_assignment_gate(
                role=candidate_role,
                exact_model_id=candidate_model_id,
                provider_endpoint=provider_endpoint,
            )
        except revocation_error_type as exc:
            raise error_type(f"candidate-selection reactivation route is revoked: {exc}") from exc
        profile = route_profile_type.model_validate_json(
            unavailable.route_predicate_profile.model_dump_json(),
            strict=True,
        )
        candidate_constraint = route_constraint_type.build(
            role=candidate_role,
            exact_model_id=candidate_model_id,
            provider_endpoint=provider_endpoint,
            profile=profile,
        )
        judge_constraints = tuple(
            route_constraint_type.model_validate_json(item.model_dump_json(), strict=True)
            for item in unavailable.judge_route_constraints
        )
        selection = trusted_seal_selection(
            candidate_model_id=candidate_model_id,
            primary_judge_model_id=unavailable.primary_judge_model_id,
            replay_judge_model_id=unavailable.replay_judge_model_id,
            route_predicate_profile=profile,
            route_constraints=(candidate_constraint, *judge_constraints),
        )
        binding_values: dict[str, object] = {
            "schema_version": "1.0",
            "artifact_kind": "REPOSITORY_PINNED_SELECTION_PLAN_ANCESTRY_TRANSITION",
            "selected_ancestor_raw_sha256": projection.selected_ancestor_raw_sha256,
            "selected_ancestor_plan_sha256": projection.selected_ancestor_plan_sha256,
            "unavailable_predecessor_raw_sha256": (projection.unavailable_predecessor_raw_sha256),
            "unavailable_predecessor_plan_sha256": (projection.unavailable_predecessor_plan_sha256),
            "unavailable_state_sha256": projection.unavailable_state_sha256,
            "matched_revocation_set_sha256": projection.matched_revocation_set_sha256,
            "ancestry_evidence_sha256": projection.projection_sha256,
            "revocation_entry_sha256s": projection.revocation_entry_sha256s,
            "withdrawn_candidate_constraint_sha256s": (
                projection.withdrawn_candidate_constraint_sha256s
            ),
            "selected_ancestor_role_assignment_sha256": (
                projection.selected_ancestor_role_assignment_sha256
            ),
            "retained_route_predicate_profile_sha256": (
                projection.retained_route_predicate_profile_sha256
            ),
            "retained_judge_constraint_sha256s": (projection.retained_judge_constraint_sha256s),
            "replacement_candidate_model_id": candidate_model_id,
            "replacement_provider_endpoint": provider_endpoint,
            "replacement_candidate_constraint_sha256": candidate_constraint.constraint_sha256,
            "opaque_ancestry_capability_required": True,
            "endpoint_inventory_refresh_authorized": False,
            "price_cap_profile_upgrade_authorized": False,
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
        binding = binding_type.model_validate(
            {
                **binding_values,
                "binding_sha256": trusted_canonical_sha256(binding_values),
            },
            strict=True,
        )
        successor = trusted_seal_plan(
            source_bindings=predecessor.source_bindings,
            entries=tuple(
                trusted_seal_entry(
                    exact_model_id=item.exact_model_id,
                    priority_rank=item.priority_rank,
                    advisory_lineage_group=item.advisory_lineage_group,
                    allowed_provider_endpoints=(provider_endpoint,),
                )
                if item.exact_model_id == candidate_model_id
                else item
                for item in predecessor.entries
            ),
            authenticated_runner_selection=selection,
            authenticated_runner_unavailability=None,
            endpoint_inventory_refresh=None,
            unresolved_requirements=tuple(
                item
                for item in predecessor.unresolved_requirements
                if item != no_candidate_requirement
            ),
            predecessor_plan_sha256=predecessor.plan_sha256,
            ancestry_transition_binding=binding,
        )
        eligible = trusted_require_eligible(successor)
        if (
            type(eligible) is not plan_type
            or eligible != successor
            or successor.schema_version != "1.8"
        ):
            raise error_type("candidate-selection reactivation eligibility result changed")
        return eligible

    def derive_candidate_selection_plan_reactivation(
        capability: VerifiedCandidateSelectionPlanAncestry,
        *,
        candidate_model_id: str,
        provider_endpoint: str,
    ) -> CandidateSelectionPlan:
        """Derive one private nonauthorizing v1.8 plan from exact opaque ancestry."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        result = derive_impl(
            capability,
            candidate_model_id=candidate_model_id,
            provider_endpoint=provider_endpoint,
        )
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return result

    def validate_impl(
        capability: VerifiedCandidateSelectionPlanAncestry,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        if type(successor) is not plan_type:
            raise error_type("candidate-selection reactivation successor has the wrong exact type")
        try:
            canonical = plan_type.model_validate_json(successor.model_dump_json(), strict=True)
        except ValueError as exc:
            raise error_type("candidate-selection reactivation successor is invalid") from exc
        binding = canonical.ancestry_transition_binding
        selection = canonical.authenticated_runner_selection
        if canonical.schema_version != "1.8" or binding is None or selection is None:
            raise error_type("candidate-selection reactivation successor lacks ancestry custody")
        candidate_constraints = tuple(
            item for item in selection.route_constraints if item.role is candidate_role
        )
        if len(candidate_constraints) != 1:
            raise error_type("candidate-selection reactivation lacks one candidate constraint")
        expected = derive_impl(
            capability,
            candidate_model_id=candidate_constraints[0].exact_model_id,
            provider_endpoint=candidate_constraints[0].provider_endpoint,
        )
        if canonical != expected:
            raise error_type("candidate-selection reactivation differs from exact derivation")
        return canonical

    def validate_candidate_selection_plan_reactivation(
        capability: VerifiedCandidateSelectionPlanAncestry,
        *,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Replay exact repository ancestry and validate one v1.8 successor."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        result = validate_impl(capability, successor)
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return result

    def write_candidate_selection_plan_reactivation(
        capability: VerifiedCandidateSelectionPlanAncestry,
        *,
        path: Path,
        successor: CandidateSelectionPlan,
    ) -> CandidateSelectionPlan:
        """Publish one fresh private v1.8 plan after immediate ancestry replay."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        canonical = validate_impl(capability, successor)
        try:
            absolute = trusted_preflight(path)
        except (plan_error_type, OSError, TypeError, ValueError) as exc:
            raise error_type(
                "candidate-selection reactivation could not be published safely"
            ) from exc
        canonical = validate_impl(capability, canonical)

        def validate_published(content: bytes) -> None:
            if require_pristine.__code__ is not pristine_code:
                raise error_type("candidate-selection ancestry runtime boundary changed")
            require_pristine()
            if trusted_sha256(content).hexdigest() != canonical_sha256_bytes(
                trusted_stable_json(canonical)
            ):
                raise error_type("candidate-selection reactivation publication hash changed")
            loaded = plan_type.model_validate_json(content, strict=True)
            if loaded != canonical or validate_impl(capability, loaded) != canonical:
                raise error_type("candidate-selection reactivation readback changed")
            if require_pristine.__code__ is not pristine_code:
                raise error_type("candidate-selection ancestry runtime boundary changed")
            require_pristine()

        try:
            trusted_write(
                evidence_root=absolute.parent,
                relative_path=absolute.name,
                value=canonical,
                max_bytes=maximum_plan_bytes,
                validate_content=validate_published,
                require_private_parent=True,
            )
        except error_type:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise error_type(
                "candidate-selection reactivation could not be published safely"
            ) from exc
        # All fallible ancestry validation occurs while the release writer still
        # owns its output descriptors and can remove exactly its newly created file.
        return canonical

    def verify_candidate_selection_plan_ancestry_for_test(
        *,
        root: Path,
        selected_relative_path: str,
        unavailable_relative_path_value: str,
        expected_selected_raw_sha256: str,
        expected_selected_plan_sha256: str,
        expected_unavailable_raw_sha256: str,
        expected_unavailable_plan_sha256: str,
        expected_unavailable_state_sha256: str,
        expected_matched_revocation_set_sha256: str,
        between_reads: Callable[[], None] | None = None,
    ) -> CandidateSelectionPlanAncestryProjection:
        """Replay local test files without issuing an opaque production capability."""

        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        observed = observe_pair(
            root=root,
            selected_relative_path=selected_relative_path,
            unavailable_relative_path_value=unavailable_relative_path_value,
            expected_selected_raw_sha256=expected_selected_raw_sha256,
            expected_selected_plan_sha256=expected_selected_plan_sha256,
            expected_unavailable_raw_sha256=expected_unavailable_raw_sha256,
            expected_unavailable_plan_sha256=expected_unavailable_plan_sha256,
            expected_unavailable_state_sha256=expected_unavailable_state_sha256,
            expected_matched_revocation_set_sha256=expected_matched_revocation_set_sha256,
            between_reads=between_reads,
        )
        if require_pristine.__code__ is not pristine_code:
            raise error_type("candidate-selection ancestry runtime boundary changed")
        require_pristine()
        return observed.projection

    def canonical_sha256_bytes(value: str) -> str:
        # The release writer returns the raw byte hash, not the model's semantic hash.
        return trusted_sha256(value.encode("utf-8")).hexdigest()

    public_bindings = tuple(
        {
            "resolve_verified_candidate_selection_plan_ancestry": (
                resolve_verified_candidate_selection_plan_ancestry
            ),
            "candidate_selection_plan_ancestry_projection": (
                candidate_selection_plan_ancestry_projection
            ),
            "derive_candidate_selection_plan_reactivation": (
                derive_candidate_selection_plan_reactivation
            ),
            "validate_candidate_selection_plan_reactivation": (
                validate_candidate_selection_plan_reactivation
            ),
            "write_candidate_selection_plan_reactivation": (
                write_candidate_selection_plan_reactivation
            ),
            "_verify_candidate_selection_plan_ancestry_for_test": (
                verify_candidate_selection_plan_ancestry_for_test
            ),
        }.items()
    )
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
    guarded_functions = (
        snapshot_function,
        function_state_is_current,
        require_pristine,
        load_exact_plan,
        observe_once,
        observe_pair,
        replay,
        derive_impl,
        validate_impl,
        canonical_sha256_bytes,
        *(function for _name, function in public_bindings),
        *(function for function, _code in function_codes),
        *io_dependency_functions,
        *descriptor_functions,
    )
    function_states = tuple(
        snapshot_function(function)
        for function in dict.fromkeys(guarded_functions)
        if type(function) is FunctionType
    )
    function_states_seal = function_states
    return (
        resolve_verified_candidate_selection_plan_ancestry,
        candidate_selection_plan_ancestry_projection,
        derive_candidate_selection_plan_reactivation,
        validate_candidate_selection_plan_reactivation,
        write_candidate_selection_plan_reactivation,
        verify_candidate_selection_plan_ancestry_for_test,
    )


(
    resolve_verified_candidate_selection_plan_ancestry,
    candidate_selection_plan_ancestry_projection,
    derive_candidate_selection_plan_reactivation,
    validate_candidate_selection_plan_reactivation,
    write_candidate_selection_plan_reactivation,
    _verify_candidate_selection_plan_ancestry_for_test,
) = _build_candidate_selection_plan_ancestry_runtime()
del _build_candidate_selection_plan_ancestry_runtime
