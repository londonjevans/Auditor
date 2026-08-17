"""Provider-free daily refresh projection for policy re-determination signals.

This module joins exact authenticated catalogue evidence to operator-supplied
policy evidence without making a legal decision.  A projection can retain the
absence of a review signal or require re-determination; it can never mark a route
eligible or grant selection, qualification, source-egress, or production authority.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.policy_eligibility import (
    ModelPolicyEligibilityArtifact,
    PolicyEligibilityRoute,
    PolicyReviewReason,
    PolicyReviewSignal,
    policy_eligibility_candidate_routes_sha256,
    policy_review_signal,
)
from mmaudit.models.policy_eligibility_authority import (
    PolicyEligibilitySourceObservation,
    build_policy_eligibility_source_commitment,
    build_policy_eligibility_source_observation,
)
from mmaudit.models.refresh import ModelRefreshSnapshot
from mmaudit.release_io import read_json_evidence
from mmaudit.reporting.json_report import stable_json

POLICY_ELIGIBILITY_REFRESH_FILENAME = "model-policy-eligibility-refresh.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_ROUTES = 128
_MAX_POLICY_EVIDENCE_BYTES = 20_000_000
_DAILY_REFRESH_MAX_AGE = timedelta(hours=24)


class ModelPolicyEligibilityRefreshError(ValueError):
    """Raised when an exact non-authorizing refresh projection cannot be built."""


class PolicyEligibilityRefreshRouteDisposition(StrEnum):
    """Refresh-only route states; deliberately contains no eligibility state."""

    NO_REVIEW_SIGNAL = "NO_REVIEW_SIGNAL"
    REDETERMINATION_REQUIRED = "REDETERMINATION_REQUIRED"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PolicyEligibilityRefreshRouteRecord(_FrozenModel):
    """Exact classification of one checked route in one refresh projection."""

    schema_version: Literal["1.0"] = "1.0"
    route: PolicyEligibilityRoute
    refresh_route_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commitment_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    disposition: PolicyEligibilityRefreshRouteDisposition
    review_reasons: tuple[PolicyReviewReason, ...] = Field(max_length=4)
    review_signal_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    redetermination_required: bool
    automated_eligibility_inference: Literal[False] = False
    policy_selection_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    record_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("review_reasons")
    @classmethod
    def reasons_are_canonical(
        cls,
        value: tuple[PolicyReviewReason, ...],
    ) -> tuple[PolicyReviewReason, ...]:
        if value != tuple(sorted(set(value), key=lambda item: item.value)):
            raise ValueError("policy refresh review reasons must be unique and sorted")
        return value

    @field_validator(
        "automated_eligibility_inference",
        "policy_selection_authorized",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_booleans(cls, value: object) -> object:
        return _require_literal_bool(value, label="policy refresh route authority flag")

    @model_validator(mode="after")
    def record_is_canonical_non_authorizing_and_self_hashed(self) -> Self:
        if self.disposition is PolicyEligibilityRefreshRouteDisposition.NO_REVIEW_SIGNAL:
            if (
                self.redetermination_required
                or self.review_reasons
                or self.review_signal_sha256 is not None
            ):
                raise ValueError("no-review-signal route cannot retain re-determination evidence")
        elif (
            not self.redetermination_required
            or not self.review_reasons
            or self.review_signal_sha256 is None
        ):
            raise ValueError("re-determination route requires exact review-signal evidence")
        missing = PolicyReviewReason.MISSING in self.review_reasons
        if missing is not (self.source_commitment_sha256 is None):
            raise ValueError(
                "missing determination state must exactly match absent source commitment"
            )
        _require_self_hash(self, "record_sha256", label="policy refresh route record")
        return self


class ModelPolicyEligibilityRefreshArtifact(_FrozenModel):
    """Self-hashed daily review-signal projection with no positive authority."""

    schema_version: Literal["1.0"] = "1.0"
    projection_kind: Literal["POLICY_REDETERMINATION_SIGNAL_ONLY"] = (
        "POLICY_REDETERMINATION_SIGNAL_ONLY"
    )
    observed_at: datetime
    refresh_retrieved_at: datetime
    daily_refresh_max_age_hours: Literal[24] = 24
    evidence_fresh_until: datetime
    refresh_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_source_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_semantic_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_catalog_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_zdr_snapshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    refresh_candidate_registry_sha256: str = Field(pattern=_SHA256_PATTERN)
    policy_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_observation: PolicyEligibilitySourceObservation
    checked_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    checked_routes: tuple[PolicyEligibilityRoute, ...] = Field(
        min_length=1,
        max_length=_MAX_ROUTES,
    )
    refresh_route_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    route_records: tuple[PolicyEligibilityRefreshRouteRecord, ...] = Field(
        min_length=1,
        max_length=_MAX_ROUTES,
    )
    route_record_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    review_signals: tuple[PolicyReviewSignal, ...] = Field(max_length=_MAX_ROUTES)
    review_signal_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    redetermination_required: bool
    automated_eligibility_inference: Literal[False] = False
    policy_selection_authorized: Literal[False] = False
    qualification_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    artifact_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at", "refresh_retrieved_at", "evidence_fresh_until")
    @classmethod
    def times_are_whole_second_utc(cls, value: datetime) -> datetime:
        return _whole_second_utc(value, label="policy refresh projection time")

    @field_validator(
        "automated_eligibility_inference",
        "policy_selection_authorized",
        "qualification_authorized",
        "source_egress_authorized",
        "production_selection_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_booleans(cls, value: object) -> object:
        return _require_literal_bool(value, label="policy refresh artifact authority flag")

    @model_validator(mode="after")
    def artifact_is_exact_non_authorizing_and_self_hashed(self) -> Self:
        _require_canonical_routes(self.checked_routes, label="checked policy refresh routes")
        if self.refresh_retrieved_at != self.observed_at:
            raise ValueError("policy refresh snapshot and projection times must be identical")
        if self.source_observation.artifact_sha256 != self.policy_artifact_sha256:
            raise ValueError("policy refresh source observation differs from its policy artifact")
        source_age = self.refresh_retrieved_at - self.source_observation.observed_at
        if (
            source_age < timedelta(0)
            or source_age > _DAILY_REFRESH_MAX_AGE
            or self.refresh_retrieved_at >= self.source_observation.expires_at
        ):
            raise ValueError("policy refresh source observation is future-dated, stale, or expired")
        try:
            refresh_deadline = self.refresh_retrieved_at + _DAILY_REFRESH_MAX_AGE
        except OverflowError as exc:
            raise ValueError("policy refresh freshness deadline is outside supported time") from exc
        expected_fresh_until = min(self.source_observation.expires_at, refresh_deadline)
        if (
            self.evidence_fresh_until != expected_fresh_until
            or self.evidence_fresh_until <= self.observed_at
        ):
            raise ValueError("policy refresh evidence freshness binding is inconsistent")
        if self.checked_route_set_sha256 != policy_eligibility_candidate_routes_sha256(
            self.checked_routes
        ):
            raise ValueError("policy refresh checked route-set hash is inconsistent")

        record_routes = tuple(record.route for record in self.route_records)
        if record_routes != self.checked_routes:
            raise ValueError("policy refresh must classify every checked route exactly once")
        expected_refresh_route_set = _canonical_sha256(
            [record.refresh_route_sha256 for record in self.route_records]
        )
        if (
            len({record.refresh_route_sha256 for record in self.route_records})
            != len(self.route_records)
            or self.refresh_route_set_sha256 != expected_refresh_route_set
        ):
            raise ValueError("policy refresh exact snapshot-route binding is inconsistent")
        expected_record_set = _canonical_sha256(
            [record.model_dump(mode="json") for record in self.route_records]
        )
        if self.route_record_set_sha256 != expected_record_set:
            raise ValueError("policy refresh route-record set hash is inconsistent")

        signal_routes = tuple(signal.route for signal in self.review_signals)
        _require_canonical_routes(signal_routes, label="policy refresh signal routes")
        expected_signal_routes = tuple(
            record.route for record in self.route_records if record.redetermination_required
        )
        if signal_routes != expected_signal_routes:
            raise ValueError("policy refresh signals differ from classified routes")
        expected_signal_set = _canonical_sha256(
            [signal.model_dump(mode="json") for signal in self.review_signals]
        )
        if self.review_signal_set_sha256 != expected_signal_set:
            raise ValueError("policy refresh review-signal set hash is inconsistent")

        commitments_by_route = {
            commitment.route.identity: commitment
            for commitment in self.source_observation.source_commitments
        }
        signals_by_route = {signal.route.identity: signal for signal in self.review_signals}
        expected_commitment_routes: list[PolicyEligibilityRoute] = []
        for record in self.route_records:
            commitment = commitments_by_route.get(record.route.identity)
            signal = signals_by_route.get(record.route.identity)
            if record.source_commitment_sha256 != (
                None if commitment is None else commitment.commitment_sha256
            ):
                raise ValueError("policy refresh route differs from its source commitment")
            if record.review_signal_sha256 != (None if signal is None else signal.signal_sha256):
                raise ValueError("policy refresh route differs from its review signal")
            if signal is None:
                if record.review_reasons:
                    raise ValueError("policy refresh route reasons lack a review signal")
            else:
                if (
                    signal.artifact_sha256 != self.policy_artifact_sha256
                    or signal.observed_at != self.observed_at
                    or signal.route != record.route
                    or signal.reasons != record.review_reasons
                ):
                    raise ValueError("policy refresh signal differs from its exact route evidence")
                if commitment is None:
                    if (
                        signal.reasons != (PolicyReviewReason.MISSING,)
                        or signal.determination_sha256 is not None
                        or signal.source_reference_observations is not None
                    ):
                        raise ValueError("missing policy refresh signal is inconsistent")
                elif (
                    signal.determination_sha256 != commitment.determination_sha256
                    or signal.source_reference_observations
                    != commitment.source_reference_observations
                ):
                    raise ValueError(
                        "policy refresh signal differs from source-reference observations"
                    )
            if commitment is not None:
                expected_commitment_routes.append(record.route)

        observed_commitment_routes = tuple(
            commitment.route for commitment in self.source_observation.source_commitments
        )
        if observed_commitment_routes != tuple(expected_commitment_routes):
            raise ValueError(
                "policy refresh observation must cover every non-missing route exactly"
            )
        if self.redetermination_required is not any(
            record.redetermination_required for record in self.route_records
        ):
            raise ValueError("policy refresh aggregate re-determination state is inconsistent")
        _require_self_hash(self, "artifact_sha256", label="policy refresh artifact")
        return self


def build_model_policy_eligibility_refresh_artifact(
    *,
    refresh_snapshot: ModelRefreshSnapshot,
    policy_artifact: ModelPolicyEligibilityArtifact,
    source_observation: PolicyEligibilitySourceObservation,
    checked_routes: tuple[PolicyEligibilityRoute, ...],
) -> ModelPolicyEligibilityRefreshArtifact:
    """Build one exact daily projection by replaying every route review signal."""

    snapshot = _validated_exact(
        ModelRefreshSnapshot,
        refresh_snapshot,
        label="model refresh snapshot",
    )
    policy, observation, routes = _validated_policy_refresh_inputs(
        policy_artifact=policy_artifact,
        source_observation=source_observation,
        checked_routes=checked_routes,
        refresh_retrieved_at=snapshot.retrieved_at,
    )

    refresh_routes: dict[tuple[str, str, str], str] = {}
    for model in snapshot.models:
        for refresh_route in model.routes:
            identity = (
                model.exact_model_id,
                refresh_route.provider_name,
                refresh_route.provider_endpoint,
            )
            if identity in refresh_routes:
                raise ModelPolicyEligibilityRefreshError(
                    "refresh snapshot repeats an exact policy route"
                )
            refresh_routes[identity] = refresh_route.route_sha256
    missing_snapshot_routes = tuple(
        route for route in routes if route.identity not in refresh_routes
    )
    if missing_snapshot_routes:
        raise ModelPolicyEligibilityRefreshError(
            "checked policy route is absent from the exact refresh snapshot"
        )

    commitments_by_route = {
        commitment.route.identity: commitment for commitment in observation.source_commitments
    }
    records: list[PolicyEligibilityRefreshRouteRecord] = []
    signals: list[PolicyReviewSignal] = []
    for policy_route in routes:
        commitment = commitments_by_route.get(policy_route.identity)
        if commitment is not None:
            try:
                rebuilt_commitment = build_policy_eligibility_source_commitment(
                    artifact=policy,
                    route=policy_route,
                    source_reference_observations=(commitment.source_reference_observations),
                )
            except ValueError as exc:
                raise ModelPolicyEligibilityRefreshError(
                    "policy source commitment is not canonical for its route"
                ) from exc
            if rebuilt_commitment != commitment:
                raise ModelPolicyEligibilityRefreshError(
                    "policy source commitment differs from deterministic replay"
                )
        signal = policy_review_signal(
            artifact=policy,
            route=policy_route,
            observed_at=snapshot.retrieved_at,
            source_reference_observations=(
                None if commitment is None else commitment.source_reference_observations
            ),
        )
        if signal is not None:
            signals.append(signal)
        disposition = (
            PolicyEligibilityRefreshRouteDisposition.NO_REVIEW_SIGNAL
            if signal is None
            else PolicyEligibilityRefreshRouteDisposition.REDETERMINATION_REQUIRED
        )
        record_values: dict[str, Any] = {
            "schema_version": "1.0",
            "route": policy_route,
            "refresh_route_sha256": refresh_routes[policy_route.identity],
            "source_commitment_sha256": (
                None if commitment is None else commitment.commitment_sha256
            ),
            "disposition": disposition,
            "review_reasons": () if signal is None else signal.reasons,
            "review_signal_sha256": None if signal is None else signal.signal_sha256,
            "redetermination_required": signal is not None,
            "automated_eligibility_inference": False,
            "policy_selection_authorized": False,
            "production_selection_authorized": False,
        }
        record_values["record_sha256"] = _canonical_sha256(record_values)
        records.append(PolicyEligibilityRefreshRouteRecord.model_validate(record_values))

    record_tuple = tuple(records)
    signal_tuple = tuple(signals)
    try:
        evidence_fresh_until = min(
            observation.expires_at,
            snapshot.retrieved_at + _DAILY_REFRESH_MAX_AGE,
        )
    except OverflowError as exc:
        raise ModelPolicyEligibilityRefreshError(
            "policy refresh freshness deadline is outside supported time"
        ) from exc
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "projection_kind": "POLICY_REDETERMINATION_SIGNAL_ONLY",
        "observed_at": snapshot.retrieved_at,
        "refresh_retrieved_at": snapshot.retrieved_at,
        "daily_refresh_max_age_hours": 24,
        "evidence_fresh_until": evidence_fresh_until,
        "refresh_snapshot_sha256": snapshot.snapshot_sha256,
        "refresh_source_evidence_sha256": snapshot.source_evidence_sha256,
        "refresh_semantic_sha256": snapshot.semantic_sha256,
        "refresh_catalog_snapshot_sha256": snapshot.catalog_snapshot_sha256,
        "refresh_zdr_snapshot_sha256": snapshot.zdr_snapshot_sha256,
        "refresh_candidate_registry_sha256": snapshot.candidate_registry_sha256,
        "policy_artifact_sha256": policy.artifact_sha256,
        "source_observation": observation,
        "checked_route_set_sha256": policy_eligibility_candidate_routes_sha256(routes),
        "checked_routes": routes,
        "refresh_route_set_sha256": _canonical_sha256(
            [record.refresh_route_sha256 for record in record_tuple]
        ),
        "route_records": record_tuple,
        "route_record_set_sha256": _canonical_sha256(
            [record.model_dump(mode="json") for record in record_tuple]
        ),
        "review_signals": signal_tuple,
        "review_signal_set_sha256": _canonical_sha256(
            [signal.model_dump(mode="json") for signal in signal_tuple]
        ),
        "redetermination_required": any(record.redetermination_required for record in record_tuple),
        "automated_eligibility_inference": False,
        "policy_selection_authorized": False,
        "qualification_authorized": False,
        "source_egress_authorized": False,
        "production_selection_authorized": False,
    }
    values["artifact_sha256"] = _canonical_sha256(values)
    return ModelPolicyEligibilityRefreshArtifact.model_validate(values)


def validate_model_policy_eligibility_refresh_inputs(
    *,
    policy_artifact: ModelPolicyEligibilityArtifact,
    source_observation: PolicyEligibilitySourceObservation,
    checked_routes: tuple[PolicyEligibilityRoute, ...],
    refresh_retrieved_at: datetime,
) -> None:
    """Fail closed on explicit policy inputs before any provider access."""

    _validated_policy_refresh_inputs(
        policy_artifact=policy_artifact,
        source_observation=source_observation,
        checked_routes=checked_routes,
        refresh_retrieved_at=refresh_retrieved_at,
    )


def verify_model_policy_eligibility_refresh_artifact(
    *,
    artifact: ModelPolicyEligibilityRefreshArtifact,
    refresh_snapshot: ModelRefreshSnapshot,
    policy_artifact: ModelPolicyEligibilityArtifact,
    source_observation: PolicyEligibilitySourceObservation,
    checked_routes: tuple[PolicyEligibilityRoute, ...],
    used_at: datetime,
) -> None:
    """Rebuild one projection from exact evidence and require it to remain fresh."""

    validated = _validated_exact(
        ModelPolicyEligibilityRefreshArtifact,
        artifact,
        label="policy refresh artifact",
    )
    rebuilt = build_model_policy_eligibility_refresh_artifact(
        refresh_snapshot=refresh_snapshot,
        policy_artifact=policy_artifact,
        source_observation=source_observation,
        checked_routes=checked_routes,
    )
    if rebuilt != validated:
        raise ModelPolicyEligibilityRefreshError(
            "policy refresh artifact differs from exact source evidence"
        )
    used = _whole_second_utc(used_at, label="policy refresh evidence use time")
    if used < validated.observed_at or used >= validated.evidence_fresh_until:
        raise ModelPolicyEligibilityRefreshError("policy refresh artifact is future-dated or stale")


def load_model_policy_eligibility_artifact(path: Path) -> ModelPolicyEligibilityArtifact:
    """Load one explicit canonical operator/legal artifact without source access."""

    return _load_exact_json_model(
        path,
        ModelPolicyEligibilityArtifact,
        label="policy eligibility artifact",
    )


def load_policy_eligibility_source_observation(
    path: Path,
) -> PolicyEligibilitySourceObservation:
    """Load one explicit canonical current-source observation without fetching sources."""

    return _load_exact_json_model(
        path,
        PolicyEligibilitySourceObservation,
        label="policy source observation",
    )


def load_policy_eligibility_checked_routes(
    path: Path,
) -> tuple[PolicyEligibilityRoute, ...]:
    """Load a canonical JSON array of exact checked routes from an explicit path."""

    try:
        observation = read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=_MAX_POLICY_EVIDENCE_BYTES,
        )
        if not isinstance(observation.value, list):
            raise ValueError("checked routes must be a JSON array")
        routes = tuple(
            PolicyEligibilityRoute.model_validate(item, strict=True) for item in observation.value
        )
        if not routes:
            raise ValueError("checked routes must not be empty")
        _require_canonical_routes(routes, label="checked policy refresh routes")
        expected = stable_json([route.model_dump(mode="json") for route in routes]).encode("utf-8")
        if observation.content != expected:
            raise ValueError("checked routes are not canonically serialized")
    except ValueError as exc:
        raise ModelPolicyEligibilityRefreshError(
            "checked policy refresh routes are invalid"
        ) from exc
    return routes


def load_model_policy_eligibility_refresh_artifact(
    path: Path,
) -> ModelPolicyEligibilityRefreshArtifact:
    """Load one exact canonical non-authorizing projection."""

    return _load_exact_json_model(
        path,
        ModelPolicyEligibilityRefreshArtifact,
        label="policy eligibility refresh artifact",
    )


def _require_canonical_routes(
    routes: tuple[PolicyEligibilityRoute, ...],
    *,
    label: str,
) -> None:
    identities = tuple(route.identity for route in routes)
    if identities != tuple(sorted(set(identities))):
        raise ModelPolicyEligibilityRefreshError(f"{label} must be exact, unique, and sorted")


def _validated_policy_refresh_inputs(
    *,
    policy_artifact: ModelPolicyEligibilityArtifact,
    source_observation: PolicyEligibilitySourceObservation,
    checked_routes: tuple[PolicyEligibilityRoute, ...],
    refresh_retrieved_at: datetime,
) -> tuple[
    ModelPolicyEligibilityArtifact,
    PolicyEligibilitySourceObservation,
    tuple[PolicyEligibilityRoute, ...],
]:
    policy = _validated_exact(
        ModelPolicyEligibilityArtifact,
        policy_artifact,
        label="model policy eligibility artifact",
    )
    observation = _validated_exact(
        PolicyEligibilitySourceObservation,
        source_observation,
        label="policy source observation",
    )
    routes = tuple(
        _validated_exact(PolicyEligibilityRoute, route, label="checked policy route")
        for route in checked_routes
    )
    if not routes:
        raise ModelPolicyEligibilityRefreshError("policy refresh requires checked routes")
    _require_canonical_routes(routes, label="checked policy refresh routes")
    refreshed_at = _whole_second_utc(
        refresh_retrieved_at,
        label="policy refresh retrieval time",
    )
    source_age = refreshed_at - observation.observed_at
    if (
        source_age < timedelta(0)
        or source_age > _DAILY_REFRESH_MAX_AGE
        or refreshed_at >= observation.expires_at
    ):
        raise ModelPolicyEligibilityRefreshError(
            "policy source observation is future-dated, stale, or expired for the refresh"
        )
    if observation.artifact_sha256 != policy.artifact_sha256:
        raise ModelPolicyEligibilityRefreshError(
            "policy source observation differs from its policy artifact"
        )
    try:
        rebuilt_observation = build_policy_eligibility_source_observation(
            artifact=policy,
            observed_at=observation.observed_at,
            expires_at=observation.expires_at,
            source_commitments=observation.source_commitments,
        )
    except ValueError as exc:
        raise ModelPolicyEligibilityRefreshError(
            "policy source observation is not canonical for its artifact"
        ) from exc
    if rebuilt_observation != observation:
        raise ModelPolicyEligibilityRefreshError(
            "policy source observation differs from deterministic replay"
        )
    determinations_by_route = {
        determination.route.identity: determination for determination in policy.determinations
    }
    expected_observed_routes = tuple(
        route for route in routes if route.identity in determinations_by_route
    )
    observed_routes = tuple(commitment.route for commitment in observation.source_commitments)
    if observed_routes != expected_observed_routes:
        raise ModelPolicyEligibilityRefreshError(
            "policy source observation must exactly cover determined checked routes"
        )
    return policy, observation, routes


def _validated_exact[ModelT: BaseModel](
    model_type: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    if type(value) is not model_type:
        raise ModelPolicyEligibilityRefreshError(f"{label} must be exact and typed")
    try:
        return model_type.model_validate_json(value.model_dump_json(), strict=True)
    except ValueError as exc:
        raise ModelPolicyEligibilityRefreshError(f"{label} is invalid") from exc


def _load_exact_json_model[ModelT: BaseModel](
    path: Path,
    model_type: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        observation = read_json_evidence(
            evidence_root=path.parent,
            relative_path=path.name,
            max_bytes=_MAX_POLICY_EVIDENCE_BYTES,
        )
        value = model_type.model_validate_json(observation.content, strict=True)
        if observation.content != stable_json(value).encode("utf-8"):
            raise ValueError(f"{label} is not canonically serialized")
    except ValueError as exc:
        raise ModelPolicyEligibilityRefreshError(f"{label} is invalid") from exc
    return value


def _whole_second_utc(value: datetime, *, label: str) -> datetime:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
        or value.microsecond != 0
    ):
        raise ModelPolicyEligibilityRefreshError(f"{label} must be a whole-second UTC timestamp")
    return value.astimezone(UTC)


def _require_literal_bool(value: object, *, label: str) -> object:
    if type(value) is not bool:
        raise ValueError(f"{label} must be a literal boolean")
    return value


def _require_self_hash(model: BaseModel, field: str, *, label: str) -> None:
    expected = _canonical_sha256(model.model_dump(mode="json", exclude={field}))
    if getattr(model, field) != expected:
        raise ValueError(f"{label} self-hash is inconsistent")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            _canonical_json_value(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _canonical_json_value(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonical_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_json_value(item) for item in value]
    return value


__all__ = [
    "POLICY_ELIGIBILITY_REFRESH_FILENAME",
    "ModelPolicyEligibilityRefreshArtifact",
    "ModelPolicyEligibilityRefreshError",
    "PolicyEligibilityRefreshRouteDisposition",
    "PolicyEligibilityRefreshRouteRecord",
    "build_model_policy_eligibility_refresh_artifact",
    "load_model_policy_eligibility_artifact",
    "load_model_policy_eligibility_refresh_artifact",
    "load_policy_eligibility_checked_routes",
    "load_policy_eligibility_source_observation",
    "validate_model_policy_eligibility_refresh_inputs",
    "verify_model_policy_eligibility_refresh_artifact",
]
