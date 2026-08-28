from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from importlib.resources import files
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.models.candidate_revocation as candidate_revocation_module
from mmaudit.models.candidate_revocation import (
    CANDIDATE_SELECTION_REVOCATION_RESOURCE,
    CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256,
    OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256,
    CandidateSelectionRevocationEntry,
    CandidateSelectionRevocationError,
    CandidateSelectionRevocationReason,
    CandidateSelectionRevocationRegistry,
    candidate_revocation_callables_are_pristine,
    load_candidate_selection_revocation_registry,
    require_candidate_assignment_eligible,
    require_candidate_route_eligible,
    require_selection_plan_routes_eligible,
    seal_candidate_selection_revocation_entry,
    seal_candidate_selection_revocation_registry,
)
from mmaudit.models.candidate_selection import load_candidate_selection_plan
from mmaudit.models.route_constraints import ExactRouteRole
from mmaudit.reporting.json_report import stable_json
from scripts.generate_release_schemas import MODELS, rendered_schema

ROOT = Path(__file__).resolve().parents[2]
PLAN_SHA256 = "bb3d60c3ff75ed2062b1ee68fe7b2011cf37ce860461b7d37eb10cd5faf7650f"
CONSTRAINT_SHA256 = "126a1553cb4fbc96c642d803edacadd4879f41dbfbd69e53b0e4d19d4674763a"
REQUESTED_MODEL = "deepseek/deepseek-v4-pro-0813"
CANONICAL_MODEL = "deepseek/deepseek-v4-pro-20260813"
ENDPOINT = "parasail/fp8"
EFFECTIVE_AT = datetime(2026, 8, 27, 17, 22, tzinfo=UTC)
SCHEMA_FILENAME = "candidate_selection_revocation_registry.schema.json"


def _entry(
    *,
    selection_plan_sha256: str = PLAN_SHA256,
    role: ExactRouteRole = ExactRouteRole.CANDIDATE,
    exact_model_id: str = REQUESTED_MODEL,
    canonical_model_slug: str = CANONICAL_MODEL,
    provider_endpoint: str = ENDPOINT,
    exact_route_constraint_sha256: str = CONSTRAINT_SHA256,
    effective_at: datetime = EFFECTIVE_AT,
) -> CandidateSelectionRevocationEntry:
    return seal_candidate_selection_revocation_entry(
        selection_plan_sha256=selection_plan_sha256,
        role=role,
        exact_model_id=exact_model_id,
        canonical_model_slug=canonical_model_slug,
        provider_endpoint=provider_endpoint,
        exact_route_constraint_sha256=exact_route_constraint_sha256,
        effective_at=effective_at,
        reason=(CandidateSelectionRevocationReason.EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE),
    )


def test_pinned_resource_is_exact_canonical_negative_only_evidence() -> None:
    resource = files("mmaudit").joinpath(*CANDIDATE_SELECTION_REVOCATION_RESOURCE.split("/"))
    content = resource.read_bytes()
    assert hashlib.sha256(content).hexdigest() == (CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256)

    registry = load_candidate_selection_revocation_registry()
    assert stable_json(registry).encode("utf-8") == content
    assert registry.operator_evidence_sha256 == OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256
    assert registry.operator_evidence_authenticity == "OPERATOR_SUPPLIED_UNVERIFIED"
    assert registry.status == "NONAUTHORIZING_NEGATIVE_ONLY"
    assert len(registry.entries) == 1
    entry = registry.entries[0]
    assert entry.key == (
        PLAN_SHA256,
        "candidate",
        REQUESTED_MODEL,
        ENDPOINT,
        CONSTRAINT_SHA256,
    )
    assert entry.canonical_model_slug == CANONICAL_MODEL
    assert entry.effective_at == EFFECTIVE_AT
    assert entry.reason is (
        CandidateSelectionRevocationReason.EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE
    )
    assert entry.disposition == "REVOKED"
    for field_name in (
        "operator_evidence_authority",
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
        assert getattr(registry, field_name) is False
    assert entry.entry_authority is False


def test_historical_selection_plan_remains_parseable_evidence_but_is_not_runnable() -> None:
    plan = load_candidate_selection_plan(ROOT / "config/models.selection-plan.json")
    assert plan.plan_sha256 == PLAN_SHA256
    assert plan.status == "NONAUTHORIZING"
    assert plan.provider_call_authorized is False
    assert plan.production_selection_authorized is False
    assert plan.authenticated_runner_selection is not None
    routes = tuple(
        (
            constraint.role,
            constraint.exact_model_id,
            constraint.provider_endpoint,
            constraint.constraint_sha256,
        )
        for constraint in plan.authenticated_runner_selection.route_constraints
    )
    with pytest.raises(CandidateSelectionRevocationError, match="route is revoked"):
        require_selection_plan_routes_eligible(plan.plan_sha256, routes)


def test_entry_and_registry_self_hash_tampering_is_rejected() -> None:
    resource = files("mmaudit").joinpath(*CANDIDATE_SELECTION_REVOCATION_RESOURCE.split("/"))
    payload = json.loads(resource.read_text(encoding="utf-8"))
    payload["entries"][0]["entry_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="entry self-hash is inconsistent"):
        CandidateSelectionRevocationRegistry.model_validate_json(
            json.dumps(payload),
            strict=True,
        )

    payload = json.loads(resource.read_text(encoding="utf-8"))
    payload["registry_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="registry self-hash is inconsistent"):
        CandidateSelectionRevocationRegistry.model_validate_json(
            json.dumps(payload),
            strict=True,
        )


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("provider_call_authorized",), True),
        (("operator_evidence_authority",), True),
        (("entries", 0, "entry_authority"), True),
        (("schema_version",), 1.0),
    ),
)
def test_registry_is_strict_and_cannot_create_authority(
    path: tuple[str | int, ...],
    value: object,
) -> None:
    resource = files("mmaudit").joinpath(*CANDIDATE_SELECTION_REVOCATION_RESOURCE.split("/"))
    payload: object = json.loads(resource.read_text(encoding="utf-8"))
    target = payload
    for component in path[:-1]:
        assert isinstance(target, dict | list)
        target = target[component]
    assert isinstance(target, dict | list)
    target[path[-1]] = value
    with pytest.raises(ValidationError):
        CandidateSelectionRevocationRegistry.model_validate_json(
            json.dumps(payload),
            strict=True,
        )


def test_registry_entries_are_sorted_unique_and_alias_disjoint() -> None:
    first = _entry()
    second = _entry(
        exact_model_id="zeta/zenith-20260827",
        canonical_model_slug="zeta/zenith-20260827-canonical",
        exact_route_constraint_sha256="e" * 64,
    )
    registry = seal_candidate_selection_revocation_registry(entries=(second, first))
    assert registry.entries == (first, second)

    with pytest.raises(CandidateSelectionRevocationError, match="registry is invalid"):
        seal_candidate_selection_revocation_registry(entries=(first, first))

    overlapping_alias = _entry(
        exact_model_id=CANONICAL_MODEL,
        canonical_model_slug=REQUESTED_MODEL,
    )
    with pytest.raises(CandidateSelectionRevocationError, match="registry is invalid"):
        seal_candidate_selection_revocation_registry(entries=(first, overlapping_alias))


def test_entry_requires_canonical_endpoint_and_whole_second_utc() -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="entry is invalid"):
        _entry(provider_endpoint="PARASAIL/FP8")
    with pytest.raises(CandidateSelectionRevocationError, match="entry is invalid"):
        _entry(effective_at=EFFECTIVE_AT.replace(microsecond=1))


@pytest.mark.parametrize(
    ("model_id", "endpoint"),
    (
        (REQUESTED_MODEL, ENDPOINT),
        (CANONICAL_MODEL, ENDPOINT),
        (REQUESTED_MODEL, "PARASAIL/FP8"),
        (CANONICAL_MODEL, "PARASAIL/FP8"),
    ),
)
def test_assignment_gate_rejects_requested_and_canonical_alias_case_insensitively(
    model_id: str,
    endpoint: str,
) -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="assignment is revoked"):
        require_candidate_assignment_eligible(
            exact_model_id=model_id,
            provider_endpoint=endpoint,
        )


@pytest.mark.parametrize("model_id", (REQUESTED_MODEL, CANONICAL_MODEL))
def test_assignment_gate_fails_closed_for_unpinned_tombstoned_endpoint(
    model_id: str,
) -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="endpoint is unpinned"):
        require_candidate_assignment_eligible(
            exact_model_id=model_id,
            provider_endpoint=None,
        )


@pytest.mark.parametrize("model_id", (REQUESTED_MODEL, CANONICAL_MODEL))
def test_new_plan_or_constraint_hash_cannot_resurrect_revoked_endpoint(
    model_id: str,
) -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="assignment is revoked"):
        require_candidate_assignment_eligible(
            exact_model_id=model_id,
            provider_endpoint=ENDPOINT,
            selection_plan_sha256="a" * 64,
            exact_route_constraint_sha256="b" * 64,
        )


@pytest.mark.parametrize("model_id", (REQUESTED_MODEL, CANONICAL_MODEL))
def test_explicit_adjacent_endpoint_remains_discoverable_but_not_authorized(
    model_id: str,
) -> None:
    require_candidate_assignment_eligible(
        exact_model_id=model_id,
        provider_endpoint="parasail/bf16",
        selection_plan_sha256="a" * 64,
        exact_route_constraint_sha256="b" * 64,
    )
    require_candidate_assignment_eligible(
        exact_model_id="adjacent/model-20260827",
        provider_endpoint=ENDPOINT,
    )


def test_assignment_gate_requires_complete_optional_route_custody() -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="custody"):
        require_candidate_assignment_eligible(
            exact_model_id="adjacent/model-20260827",
            provider_endpoint="adjacent/provider",
            selection_plan_sha256="a" * 64,
        )


def test_assignment_gate_rejects_hostile_string_subclasses_before_alias_matching() -> None:
    class DeceptiveModelId(str):
        def __hash__(self) -> int:
            return hash("adjacent/not-revoked")

        def __eq__(self, other: object) -> bool:
            del other
            return False

    with pytest.raises(CandidateSelectionRevocationError, match="wrong exact type"):
        require_candidate_assignment_eligible(
            exact_model_id=DeceptiveModelId(REQUESTED_MODEL),
            provider_endpoint=ENDPOINT,
        )


@pytest.mark.parametrize("model_id", (REQUESTED_MODEL, CANONICAL_MODEL))
def test_plan_route_gate_rejects_alias_under_new_provenance(model_id: str) -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="route is revoked"):
        require_selection_plan_routes_eligible(
            "a" * 64,
            (
                (
                    ExactRouteRole.CANDIDATE,
                    model_id,
                    "PARASAIL/FP8",
                    "b" * 64,
                ),
            ),
        )


def test_plan_route_gate_is_exact_to_role_model_and_endpoint() -> None:
    require_selection_plan_routes_eligible(
        PLAN_SHA256,
        (
            (
                ExactRouteRole.CANDIDATE,
                REQUESTED_MODEL,
                "parasail/bf16",
                CONSTRAINT_SHA256,
            ),
        ),
    )
    require_selection_plan_routes_eligible(
        PLAN_SHA256,
        (
            (
                ExactRouteRole.PRIMARY_JUDGE,
                REQUESTED_MODEL,
                ENDPOINT,
                CONSTRAINT_SHA256,
            ),
        ),
    )
    require_selection_plan_routes_eligible(
        PLAN_SHA256,
        (
            (
                ExactRouteRole.CANDIDATE,
                "adjacent/model-20260827",
                ENDPOINT,
                CONSTRAINT_SHA256,
            ),
        ),
    )


def test_single_route_helper_rejects_exact_tombstone() -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="route is revoked"):
        require_candidate_route_eligible(
            selection_plan_sha256=PLAN_SHA256,
            role=ExactRouteRole.CANDIDATE,
            exact_model_id=REQUESTED_MODEL,
            provider_endpoint=ENDPOINT,
            exact_route_constraint_sha256=CONSTRAINT_SHA256,
        )


def test_plan_route_inventory_requires_canonical_nonempty_unique_tuples() -> None:
    with pytest.raises(CandidateSelectionRevocationError, match="nonempty exact tuple"):
        require_selection_plan_routes_eligible(PLAN_SHA256, ())
    duplicate = (
        ExactRouteRole.CANDIDATE,
        "adjacent/model-20260827",
        "adjacent/provider",
        "d" * 64,
    )
    with pytest.raises(CandidateSelectionRevocationError, match="unique and canonically ordered"):
        require_selection_plan_routes_eligible(PLAN_SHA256, (duplicate, duplicate))


def test_callable_boundary_rejects_loader_alias_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert candidate_revocation_callables_are_pristine()
    with monkeypatch.context() as mutation:
        mutation.setattr(
            candidate_revocation_module,
            "_load_candidate_selection_revocation_registry_unchecked",
            lambda: None,
        )
        assert candidate_revocation_callables_are_pristine() is False
        with pytest.raises(CandidateSelectionRevocationError, match="not pristine"):
            require_candidate_assignment_eligible(
                exact_model_id="adjacent/model-20260827",
                provider_endpoint="adjacent/provider",
            )
    assert candidate_revocation_callables_are_pristine()


def test_callable_boundary_binds_resource_identity_constant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as mutation:
        mutation.setattr(
            candidate_revocation_module,
            "CANDIDATE_SELECTION_REVOCATION_RESOURCE_SHA256",
            "0" * 64,
        )
        assert candidate_revocation_callables_are_pristine() is False
        with pytest.raises(CandidateSelectionRevocationError, match="not pristine"):
            load_candidate_selection_revocation_registry()
    assert candidate_revocation_callables_are_pristine()


@pytest.mark.parametrize(
    ("target", "name", "replacement"),
    (
        (
            CandidateSelectionRevocationEntry,
            "matches_model_identity",
            lambda _self, _model_id: False,
        ),
        (
            CandidateSelectionRevocationRegistry,
            "model_validate_json",
            classmethod(lambda _cls, _content, **_kwargs: object()),
        ),
    ),
)
def test_callable_boundary_rejects_guarded_model_class_surface_mutation(
    monkeypatch: pytest.MonkeyPatch,
    target: type[object],
    name: str,
    replacement: object,
) -> None:
    with monkeypatch.context() as mutation:
        mutation.setattr(target, name, replacement)
        assert candidate_revocation_callables_are_pristine() is False
        with pytest.raises(CandidateSelectionRevocationError, match="not pristine"):
            require_candidate_assignment_eligible(
                exact_model_id=REQUESTED_MODEL,
                provider_endpoint=ENDPOINT,
            )
    assert candidate_revocation_callables_are_pristine()


def test_callable_boundary_binds_immutable_revocation_projection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as mutation:
        mutation.setattr(
            candidate_revocation_module,
            "CANDIDATE_SELECTION_REVOCATION_PROJECTION",
            (
                (
                    "a" * 64,
                    "candidate",
                    "adjacent/model",
                    "adjacent/model",
                    "adjacent/provider",
                    "b" * 64,
                ),
            ),
        )
        assert candidate_revocation_callables_are_pristine() is False
        with pytest.raises(CandidateSelectionRevocationError, match="not pristine"):
            require_candidate_assignment_eligible(
                exact_model_id=REQUESTED_MODEL,
                provider_endpoint=ENDPOINT,
            )
    assert candidate_revocation_callables_are_pristine()


def test_published_schema_is_exact_closed_bounded_and_negative_only() -> None:
    assert MODELS[SCHEMA_FILENAME] is CandidateSelectionRevocationRegistry
    observed = (ROOT / "schemas" / SCHEMA_FILENAME).read_text(encoding="utf-8")
    assert observed == rendered_schema(
        SCHEMA_FILENAME,
        CandidateSelectionRevocationRegistry,
    )
    schema = json.loads(observed)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["entries"]["minItems"] == 1
    assert schema["properties"]["entries"]["maxItems"] == 256
    assert schema["properties"]["operator_evidence_sha256"]["const"] == (
        OPERATOR_RESULTS_REVOCATION_EVIDENCE_SHA256
    )
    entry = schema["$defs"]["CandidateSelectionRevocationEntry"]
    assert entry["additionalProperties"] is False
    assert set(entry["required"]) == set(entry["properties"])
    assert entry["properties"]["disposition"]["const"] == "REVOKED"
    assert entry["properties"]["entry_authority"]["const"] is False
    assert schema["$defs"]["CandidateSelectionRevocationReason"]["enum"] == [
        "EMPIRICAL_STRUCTURED_OUTPUT_NONCONFORMANCE"
    ]
    for field_name in (
        "operator_evidence_authority",
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
        assert schema["properties"][field_name]["const"] is False
