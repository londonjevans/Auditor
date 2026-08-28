"""Negative-only execution vetoes for empirically rejected model candidates.

The committed selection plan remains immutable historical evidence.  This module
loads a separately pinned tombstone registry and can only refuse a candidate; it
cannot select a replacement or create provider, benchmark, qualification, or
release authority.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from importlib.resources import files
from json import dumps
from re import fullmatch
from types import CellType, CodeType, FunctionType
from typing import Any, Literal, Protocol, Self, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import EXACT_MODEL_ID_PATTERN, require_exact_openrouter_model_id
from mmaudit.models.route_constraints import ExactRouteRole
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_ENDPOINT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$"
_MAX_RESOURCE_BYTES = 1_000_000
_MAX_REVOCATIONS = 256

CANDIDATE_SELECTION_REVOCATION_RESOURCE = "resources/candidate-selection-revocations.json"
CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256 = (
    "8c0448ba238dc98d1d76eea13ad9a09e442a1d13f0bff38548efbaa2f92fba42"
)
OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256 = (
    "f3569e3eac39391a9b09566ccc5a2b83a5eed6e963fb8ce417c03c850166e617"
)

type CandidateSelectionRouteKey = tuple[ExactRouteRole, str, str, str]
type _CandidateSelectionRevocationProjectionEntry = tuple[str, str, str, str, str, str]
CANDIDATE_SELECTION_REVOCATION_PROJECTION: tuple[
    _CandidateSelectionRevocationProjectionEntry, ...
] = (
    (
        "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f",
        "candidate",
        "deepseek/deepseek-v4-pro-0813",
        "deepseek/deepseek-v4-pro-20260813",
        "parasail/fp8",
        "126a1553cb4fbc96c642d803edacadd4879f41dbfbd69e53b0e4d19d4674763a",
    ),
)
type _FunctionState = tuple[
    FunctionType,
    CodeType,
    tuple[Any, ...] | None,
    dict[str, Any] | None,
    tuple[tuple[str, Any], ...],
    dict[str, Any],
    tuple[CellType, ...] | None,
    tuple[tuple[CellType, object], ...],
    dict[str, Any],
    tuple[tuple[str, Any], ...],
]


class CandidateSelectionRevocationError(ValueError):
    """Raised when revocation custody is invalid or an assignment is tombstoned."""


class CandidateSelectionRevocationReason(StrEnum):
    """Closed reasons that can only narrow candidate execution eligibility."""

    EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE = "EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE"


class _StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class CandidateSelectionRevocationEntry(_StrictFrozenModel):
    """One exact negative-only candidate assignment tombstone."""

    schema_version: Literal["1.0"]
    selection_plan_sha256: str = Field(pattern=_SHA256_PATTERN)
    role: ExactRouteRole
    exact_model_id: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    canonical_model_slug: str = Field(pattern=EXACT_MODEL_ID_PATTERN)
    provider_endpoint: str = Field(pattern=_ENDPOINT_PATTERN)
    exact_route_constraint_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_at: datetime
    reason: CandidateSelectionRevocationReason
    disposition: Literal["REVOKED"]
    entry_authority: Literal[False]
    entry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id", "canonical_model_slug")
    @classmethod
    def model_id_is_exact(cls, value: str) -> str:
        try:
            return require_exact_openrouter_model_id(value)
        except ValueError as exc:
            raise ValueError("candidate revocation model identity must be exact") from exc

    @field_validator("provider_endpoint")
    @classmethod
    def provider_endpoint_is_canonical(cls, value: str) -> str:
        if value != value.casefold():
            raise ValueError("candidate revocation endpoint must use canonical lowercase text")
        return value

    @field_validator("effective_at")
    @classmethod
    def effective_time_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond != 0:
            raise ValueError("candidate revocation effective time must be whole-second UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def entry_is_negative_only_and_self_hashed(self) -> Self:
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"entry_sha256"}))
        if self.entry_sha256 != expected:
            raise ValueError("candidate revocation entry self-hash is inconsistent")
        return self

    @property
    def key(self) -> tuple[str, str, str, str, str]:
        """Return the exact canonical assignment key bound by this tombstone."""

        return (
            self.selection_plan_sha256,
            self.role.value,
            self.exact_model_id,
            self.provider_endpoint,
            self.exact_route_constraint_sha256,
        )

    def matches_model_identity(self, exact_model_id: str) -> bool:
        """Match the requested ID or its explicitly bound canonical alias."""

        return exact_model_id in {self.exact_model_id, self.canonical_model_slug}


class CandidateSelectionRevocationRegistry(_StrictFrozenModel):
    """Pinned, self-hashed registry that can only revoke candidate execution."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["CANDIDATE_SELECTION_REVOCATION_REGISTRY"]
    status: Literal["NONAUTHORIZING_NEGATIVE_ONLY"]
    operator_evidence_sha256: Literal[
        "f3569e3eac39391a9b09566ccc5a2b83a5eed6e963fb8ce417c03c850166e617"
    ]
    operator_evidence_authenticity: Literal["OPERATOR_SUPPLIED_UNVERIFIED"]
    operator_evidence_authority: Literal[False]
    entries: tuple[CandidateSelectionRevocationEntry, ...] = Field(
        min_length=1,
        max_length=_MAX_REVOCATIONS,
    )
    provider_call_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    benchmark_authorized: Literal[False]
    seal_publication_authorized: Literal[False]
    release_authorized: Literal[False]
    serialized_authority: Literal[False]
    registry_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def registry_is_canonical_negative_only_and_self_hashed(self) -> Self:
        keys = tuple(entry.key for entry in self.entries)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("candidate revocations must be unique and canonically ordered")
        alias_keys = tuple(
            (
                entry.selection_plan_sha256,
                entry.role.value,
                model_id,
                entry.provider_endpoint.casefold(),
                entry.exact_route_constraint_sha256,
            )
            for entry in self.entries
            for model_id in {entry.exact_model_id, entry.canonical_model_slug}
        )
        if len(alias_keys) != len(set(alias_keys)):
            raise ValueError("candidate revocation aliases overlap")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"registry_sha256"}))
        if self.registry_sha256 != expected:
            raise ValueError("candidate revocation registry self-hash is inconsistent")
        return self


def seal_candidate_selection_revocation_entry(
    *,
    selection_plan_sha256: str,
    role: ExactRouteRole,
    exact_model_id: str,
    canonical_model_slug: str,
    provider_endpoint: str,
    exact_route_constraint_sha256: str,
    effective_at: datetime,
    reason: CandidateSelectionRevocationReason,
) -> CandidateSelectionRevocationEntry:
    """Build one deterministic negative-only revocation entry."""

    values: dict[str, Any] = {
        "schema_version": "1.0",
        "selection_plan_sha256": selection_plan_sha256,
        "role": role,
        "exact_model_id": exact_model_id,
        "canonical_model_slug": canonical_model_slug,
        "provider_endpoint": provider_endpoint,
        "exact_route_constraint_sha256": exact_route_constraint_sha256,
        "effective_at": effective_at,
        "reason": reason,
        "disposition": "REVOKED",
        "entry_authority": False,
    }
    values["entry_sha256"] = _canonical_sha256(_json_ready(values))
    try:
        return CandidateSelectionRevocationEntry.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionRevocationError("candidate revocation entry is invalid") from exc


def seal_candidate_selection_revocation_registry(
    *,
    entries: tuple[CandidateSelectionRevocationEntry, ...],
) -> CandidateSelectionRevocationRegistry:
    """Build one deterministic registry without creating positive authority."""

    ordered = tuple(sorted(entries, key=lambda entry: entry.key))
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "artifact_kind": "CANDIDATE_SELECTION_REVOCATION_REGISTRY",
        "status": "NONAUTHORIZING_NEGATIVE_ONLY",
        "operator_evidence_sha256": OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256,
        "operator_evidence_authenticity": "OPERATOR_SUPPLIED_UNVERIFIED",
        "operator_evidence_authority": False,
        "entries": ordered,
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
    values["registry_sha256"] = _canonical_sha256(_json_ready(values))
    try:
        return CandidateSelectionRevocationRegistry.model_validate(values)
    except ValueError as exc:
        raise CandidateSelectionRevocationError("candidate revocation registry is invalid") from exc


def _read_candidate_selection_revocation_resource_unchecked() -> bytes:
    """Read the exact package resource after its immutable byte pin is proven."""

    resource = files("mmaudit").joinpath(*CANDIDATE_SELECTION_REVOCATION_RESOURCE.split("/"))
    try:
        content = resource.read_bytes()
    except OSError as exc:
        raise CandidateSelectionRevocationError(
            "candidate revocation resource could not be read"
        ) from exc
    if not 1 <= len(content) <= _MAX_RESOURCE_BYTES:
        raise CandidateSelectionRevocationError("candidate revocation resource is not bounded")
    if sha256(content).hexdigest() != CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256:
        raise CandidateSelectionRevocationError("candidate revocation resource identity changed")
    return content


def _load_candidate_selection_revocation_registry_unchecked() -> (
    CandidateSelectionRevocationRegistry
):
    """Load the exact pinned package tombstones without caller-selected bytes."""

    content = _read_candidate_selection_revocation_resource_unchecked()
    try:
        registry = CandidateSelectionRevocationRegistry.model_validate_json(content, strict=True)
    except ValueError as exc:
        raise CandidateSelectionRevocationError("candidate revocation resource is invalid") from exc
    if type(registry) is not CandidateSelectionRevocationRegistry or any(
        type(entry) is not CandidateSelectionRevocationEntry for entry in registry.entries
    ):
        raise CandidateSelectionRevocationError(
            "candidate revocation resource has an invalid model type"
        )
    model_projection = tuple(
        (
            entry.selection_plan_sha256,
            entry.role.value,
            entry.exact_model_id,
            entry.canonical_model_slug,
            entry.provider_endpoint,
            entry.exact_route_constraint_sha256,
        )
        for entry in registry.entries
    )
    if model_projection != CANDIDATE_SELECTION_REVOCATION_PROJECTION:
        raise CandidateSelectionRevocationError(
            "candidate revocation model projection differs from pinned bytes"
        )
    if stable_json(registry).encode("utf-8") != content:
        raise CandidateSelectionRevocationError(
            "candidate revocation resource is not canonical JSON"
        )
    return registry


def _require_candidate_assignment_eligible_unchecked(
    *,
    exact_model_id: str,
    provider_endpoint: str | None,
    selection_plan_sha256: str | None = None,
    exact_route_constraint_sha256: str | None = None,
) -> None:
    """Refuse a revoked requested/canonical model before a new execution.

    Qualified runtime capabilities may no longer retain selection-plan custody, so
    model and endpoint are sufficient for a fail-closed negative match.  When plan
    custody is available, both hashes must be supplied together and are validated.
    This negative gate never establishes positive discovery or execution authority.
    """

    _validate_assignment_fields(
        exact_model_id=exact_model_id,
        provider_endpoint=provider_endpoint,
        selection_plan_sha256=selection_plan_sha256,
        exact_route_constraint_sha256=exact_route_constraint_sha256,
    )
    active_alias_entries = tuple(
        entry
        for entry in CANDIDATE_SELECTION_REVOCATION_PROJECTION
        if exact_model_id in {entry[2], entry[3]}
    )
    if active_alias_entries and provider_endpoint is None:
        raise CandidateSelectionRevocationError(
            "candidate selection model endpoint is unpinned and cannot exclude its revocation"
        )
    if provider_endpoint is None:
        return
    for entry in active_alias_entries:
        if provider_endpoint.casefold() == entry[4].casefold():
            raise CandidateSelectionRevocationError("candidate selection assignment is revoked")


def _require_candidate_route_eligible_unchecked(
    *,
    selection_plan_sha256: str,
    role: ExactRouteRole,
    exact_model_id: str,
    provider_endpoint: str,
    exact_route_constraint_sha256: str,
) -> None:
    """Refuse one exact new plan/role/route assignment when tombstoned."""

    _require_selection_plan_routes_eligible_unchecked(
        selection_plan_sha256,
        ((role, exact_model_id, provider_endpoint, exact_route_constraint_sha256),),
    )


def _require_selection_plan_routes_eligible_unchecked(
    selection_plan_sha256: str,
    routes: tuple[CandidateSelectionRouteKey, ...],
) -> None:
    """Refuse any tombstoned candidate role in a canonical exact route inventory."""

    _require_sha256(selection_plan_sha256, label="candidate selection plan hash")
    if type(routes) is not tuple or not routes:
        raise CandidateSelectionRevocationError(
            "candidate selection routes must be a nonempty exact tuple"
        )
    canonical_keys: list[tuple[str, str, str, str]] = []
    validated_routes: list[CandidateSelectionRouteKey] = []
    for route in routes:
        if type(route) is not tuple or len(route) != 4:
            raise CandidateSelectionRevocationError(
                "candidate selection route has the wrong exact shape"
            )
        role, exact_model_id, provider_endpoint, constraint_sha256 = route
        if type(role) is not ExactRouteRole:
            raise CandidateSelectionRevocationError(
                "candidate selection route role has the wrong exact type"
            )
        _validate_assignment_fields(
            exact_model_id=exact_model_id,
            provider_endpoint=provider_endpoint,
            selection_plan_sha256=selection_plan_sha256,
            exact_route_constraint_sha256=constraint_sha256,
        )
        canonical_keys.append(
            (role.value, exact_model_id, provider_endpoint.casefold(), constraint_sha256)
        )
        validated_routes.append(route)
    if tuple(canonical_keys) != tuple(sorted(set(canonical_keys))):
        raise CandidateSelectionRevocationError(
            "candidate selection routes must be unique and canonically ordered"
        )

    for role, exact_model_id, provider_endpoint, _constraint_sha256 in validated_routes:
        for entry in CANDIDATE_SELECTION_REVOCATION_PROJECTION:
            if (
                role.value == entry[1]
                and exact_model_id in {entry[2], entry[3]}
                and provider_endpoint.casefold() == entry[4].casefold()
            ):
                raise CandidateSelectionRevocationError("candidate selection route is revoked")


def _validate_assignment_fields(
    *,
    exact_model_id: str,
    provider_endpoint: str | None,
    selection_plan_sha256: str | None,
    exact_route_constraint_sha256: str | None,
) -> None:
    if type(exact_model_id) is not str:
        raise CandidateSelectionRevocationError(
            "candidate selection assignment model ID has the wrong exact type"
        )
    try:
        require_exact_openrouter_model_id(exact_model_id)
    except (TypeError, ValueError) as exc:
        raise CandidateSelectionRevocationError(
            "candidate selection assignment model ID is not exact"
        ) from exc
    if provider_endpoint is not None and (
        type(provider_endpoint) is not str
        or fullmatch(_ENDPOINT_PATTERN, provider_endpoint) is None
    ):
        raise CandidateSelectionRevocationError(
            "candidate selection assignment endpoint is not exact"
        )
    if (selection_plan_sha256 is None) != (exact_route_constraint_sha256 is None):
        raise CandidateSelectionRevocationError(
            "candidate selection assignment route custody must be complete or absent"
        )
    if selection_plan_sha256 is not None:
        _require_sha256(selection_plan_sha256, label="candidate selection plan hash")
        assert exact_route_constraint_sha256 is not None
        _require_sha256(
            exact_route_constraint_sha256,
            label="candidate selection route constraint hash",
        )


def _require_sha256(value: object, *, label: str) -> str:
    if type(value) is not str or fullmatch(_SHA256_PATTERN, value) is None:
        raise CandidateSelectionRevocationError(f"{label} is not canonical")
    return value


def _json_ready(value: object) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: _json_ready(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_ready(item) for item in value]
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, datetime):
        canonical = value.astimezone(UTC)
        return canonical.isoformat().replace("+00:00", "Z")
    return value


def _canonical_sha256(value: object) -> str:
    encoded = dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


class _CandidateRevocationPristine(Protocol):
    def __call__(self) -> bool: ...


class _CandidateRevocationLoader(Protocol):
    def __call__(self) -> CandidateSelectionRevocationRegistry: ...


class _CandidateAssignmentEligibilityGate(Protocol):
    def __call__(
        self,
        *,
        exact_model_id: str,
        provider_endpoint: str | None,
        selection_plan_sha256: str | None = None,
        exact_route_constraint_sha256: str | None = None,
    ) -> None: ...


class _CandidateRouteEligibilityGate(Protocol):
    def __call__(
        self,
        *,
        selection_plan_sha256: str,
        role: ExactRouteRole,
        exact_model_id: str,
        provider_endpoint: str,
        exact_route_constraint_sha256: str,
    ) -> None: ...


class _SelectionPlanRoutesEligibilityGate(Protocol):
    def __call__(
        self,
        selection_plan_sha256: str,
        routes: tuple[CandidateSelectionRouteKey, ...],
    ) -> None: ...


def _build_candidate_revocation_callable_boundary() -> tuple[
    _CandidateRevocationPristine,
    _CandidateRevocationLoader,
    _CandidateAssignmentEligibilityGate,
    _CandidateRouteEligibilityGate,
    _SelectionPlanRoutesEligibilityGate,
]:
    """Seal the provider-free veto boundary against module-level replacement."""

    module_globals = globals()
    empty_cell = object()
    error_type = CandidateSelectionRevocationError
    read_implementation = _read_candidate_selection_revocation_resource_unchecked
    loader_implementation = _load_candidate_selection_revocation_registry_unchecked
    assignment_implementation = _require_candidate_assignment_eligible_unchecked
    route_implementation = _require_candidate_route_eligible_unchecked
    plan_routes_implementation = _require_selection_plan_routes_eligible_unchecked
    class_bindings = tuple(
        (guarded_type, tuple(vars(guarded_type).items()))
        for guarded_type in (
            CandidateSelectionRevocationEntry,
            CandidateSelectionRevocationRegistry,
        )
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
        ("CANDIDATE_SELECTION_REVOCATION_RESOURCE", CANDIDATE_SELECTION_REVOCATION_RESOURCE),
        (
            "CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256",
            CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256,
        ),
        (
            "OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256",
            OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256,
        ),
        (
            "CANDIDATE_SELECTION_REVOCATION_PROJECTION",
            CANDIDATE_SELECTION_REVOCATION_PROJECTION,
        ),
        ("CandidateSelectionRevocationEntry", CandidateSelectionRevocationEntry),
        ("CandidateSelectionRevocationRegistry", CandidateSelectionRevocationRegistry),
        ("CandidateSelectionRevocationError", error_type),
        ("BaseModel", BaseModel),
        ("ExactRouteRole", ExactRouteRole),
        ("_ENDPOINT_PATTERN", _ENDPOINT_PATTERN),
        ("_MAX_RESOURCE_BYTES", _MAX_RESOURCE_BYTES),
        ("_SHA256_PATTERN", _SHA256_PATTERN),
        ("UTC", UTC),
        ("datetime", datetime),
        ("files", files),
        ("fullmatch", fullmatch),
        ("require_exact_openrouter_model_id", require_exact_openrouter_model_id),
        ("sha256", sha256),
        ("stable_json", stable_json),
    )

    def snapshot(function: FunctionType) -> _FunctionState:
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

    def function_state_is_current(state: _FunctionState) -> bool:
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
                or base_model_bindings is not base_model_bindings_seal
                or class_bindings is not class_bindings_seal
                or fixed_globals is not fixed_globals_seal
                or module_globals is not module_globals_seal
                or mutable_class_bindings is not mutable_class_bindings_seal
                or states is not states_seal
                or module_globals.get("candidate_revocation_callables_are_pristine") is not pristine
            ):
                return False
            if any(module_globals.get(name) is not expected for name, expected in aliases):
                return False
            if any(module_globals.get(name) is not expected for name, expected in fixed_globals):
                return False
            if any(
                vars(BaseModel).get(name) is not expected
                for name, expected in base_model_bindings
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

    pristine_code = pristine.__code__

    def load_candidate_selection_revocation_registry() -> CandidateSelectionRevocationRegistry:
        """Load the exact pinned package tombstones after an integrity check."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate revocation callable boundary is not pristine")
        return loader_implementation()

    def require_candidate_assignment_eligible(
        *,
        exact_model_id: str,
        provider_endpoint: str | None,
        selection_plan_sha256: str | None = None,
        exact_route_constraint_sha256: str | None = None,
    ) -> None:
        """Fail closed before using a tombstoned candidate assignment."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate revocation callable boundary is not pristine")
        assignment_implementation(
            exact_model_id=exact_model_id,
            provider_endpoint=provider_endpoint,
            selection_plan_sha256=selection_plan_sha256,
            exact_route_constraint_sha256=exact_route_constraint_sha256,
        )

    def require_candidate_route_eligible(
        *,
        selection_plan_sha256: str,
        role: ExactRouteRole,
        exact_model_id: str,
        provider_endpoint: str,
        exact_route_constraint_sha256: str,
    ) -> None:
        """Fail closed before using one tombstoned plan route."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate revocation callable boundary is not pristine")
        route_implementation(
            selection_plan_sha256=selection_plan_sha256,
            role=role,
            exact_model_id=exact_model_id,
            provider_endpoint=provider_endpoint,
            exact_route_constraint_sha256=exact_route_constraint_sha256,
        )

    def require_selection_plan_routes_eligible(
        selection_plan_sha256: str,
        routes: tuple[CandidateSelectionRouteKey, ...],
    ) -> None:
        """Fail closed before using any tombstoned route from an exact plan."""

        if pristine.__code__ is not pristine_code or not pristine():
            raise error_type("candidate revocation callable boundary is not pristine")
        plan_routes_implementation(selection_plan_sha256, routes)

    aliases = (
        ("_read_candidate_selection_revocation_resource_unchecked", read_implementation),
        ("_load_candidate_selection_revocation_registry_unchecked", loader_implementation),
        ("_require_candidate_assignment_eligible_unchecked", assignment_implementation),
        ("_require_candidate_route_eligible_unchecked", route_implementation),
        ("_require_selection_plan_routes_eligible_unchecked", plan_routes_implementation),
        ("_validate_assignment_fields", _validate_assignment_fields),
        ("_require_sha256", _require_sha256),
        ("_json_ready", _json_ready),
        ("_canonical_sha256", _canonical_sha256),
        (
            "load_candidate_selection_revocation_registry",
            load_candidate_selection_revocation_registry,
        ),
        ("require_candidate_assignment_eligible", require_candidate_assignment_eligible),
        ("require_candidate_route_eligible", require_candidate_route_eligible),
        ("require_selection_plan_routes_eligible", require_selection_plan_routes_eligible),
    )
    external_functions: tuple[FunctionType, ...] = tuple(
        value
        for value in (files, fullmatch, require_exact_openrouter_model_id, stable_json)
        if type(value) is FunctionType
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
    for _name, descriptor in base_model_bindings:
        if type(descriptor) is FunctionType:
            descriptor_functions.append(descriptor)
        elif type(descriptor) in {classmethod, staticmethod}:
            descriptor_functions.append(cast(FunctionType, cast(Any, descriptor).__func__))
    state_functions = (
        read_implementation,
        loader_implementation,
        assignment_implementation,
        route_implementation,
        plan_routes_implementation,
        _validate_assignment_fields,
        _require_sha256,
        _json_ready,
        _canonical_sha256,
        load_candidate_selection_revocation_registry,
        require_candidate_assignment_eligible,
        require_candidate_route_eligible,
        require_selection_plan_routes_eligible,
        *tuple(dict.fromkeys(descriptor_functions)),
        *external_functions,
    )
    states = tuple(snapshot(cast(FunctionType, function)) for function in state_functions)
    aliases_seal = aliases
    base_model_bindings_seal = base_model_bindings
    class_bindings_seal = class_bindings
    fixed_globals_seal = fixed_globals
    module_globals_seal = module_globals
    mutable_class_bindings_seal = mutable_class_bindings
    states_seal = states
    return (
        pristine,
        load_candidate_selection_revocation_registry,
        require_candidate_assignment_eligible,
        require_candidate_route_eligible,
        require_selection_plan_routes_eligible,
    )


(
    candidate_revocation_callables_are_pristine,
    load_candidate_selection_revocation_registry,
    require_candidate_assignment_eligible,
    require_candidate_route_eligible,
    require_selection_plan_routes_eligible,
) = _build_candidate_revocation_callable_boundary()
del _build_candidate_revocation_callable_boundary
if not candidate_revocation_callables_are_pristine():
    raise RuntimeError("candidate revocation callable boundary failed its initial integrity check")
