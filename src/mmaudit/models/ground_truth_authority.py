"""Provider-free custody for frozen, non-model-authored benchmark ground truth.

The durable models in this module are evidence only.  They deliberately carry no
scoring, qualification, egress, selection, or authority-issuance permission.  A
process-local :class:`VerifiedFrozenGroundTruth` is issued only after an exact
benchmark suite is rebuilt against verifier-compiled frozen pins.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Never, Self, SupportsIndex
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.benchmark.models import (
    ModelBenchmarkClassification,
    ModelBenchmarkSuite,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_json_evidence

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_REVISION_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_CASE_ID_PATTERN = r"^case-[0-9a-f]{16}$"
_MAX_PROVENANCE_BYTES = 10_000_000
_MAX_CASES = 10_000

# These pins are intentionally compiled into the verifier instead of accepted from
# the artifact or its caller.  Changing the frozen corpus is therefore a reviewed
# code-and-schema change, never a runtime reseal operation.
FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256 = (
    "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
)
FROZEN_GROUND_TRUTH_PROVENANCE_SHA256 = (
    "2a5aefecae5de53f2a390cefc1ee7bfe86922e41b51298e212c50f05d56e6ae9"
)
FROZEN_GROUND_TRUTH_SOURCE_REVISION = "f794db0ba0e16e8cd1f028ac623b0486ce86c879"
FROZEN_GROUND_TRUTH_CORPUS_SHA256 = (
    "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
)
FROZEN_GROUND_TRUTH_ANSWER_KEY_SHA256 = (
    "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
)
FROZEN_GROUND_TRUTH_MANIFEST_FILE_SHA256 = (
    "f0b4cee796501d2209048c65c3cf11926a1ed42bf1a9756d392505d12686cfb3"
)
FROZEN_GROUND_TRUTH_ANSWER_KEY_FILE_SHA256 = (
    "bf007f7ee39d374b82e2c04d4af619a713e7bd6c319ce2a109141a2874ebec49"
)
FROZEN_GROUND_TRUTH_REGRESSION_CONTRACT_FILE_SHA256 = (
    "ae28d1c5773cd56d6e73cd96b6f62797aad09c38f2d6ec7380419fb85b961287"
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GroundTruthOriginKind(StrEnum):
    """Non-model origin that fixes one benchmark answer key."""

    SYNTHETIC_PLANTED = "SYNTHETIC_PLANTED"
    PUBLIC_ESTABLISHED = "PUBLIC_ESTABLISHED"


class GroundTruthDisposition(StrEnum):
    """Canonical case outcome independently joined to benchmark truth."""

    VULNERABILITY = "VULNERABILITY"
    SAFE = "SAFE"
    INSUFFICIENT_CONTEXT = "INSUFFICIENT_CONTEXT"


class SyntheticPlantedGroundTruthOrigin(_FrozenModel):
    """Precommitted synthetic construction and its deterministic regression contract."""

    origin_kind: Literal[GroundTruthOriginKind.SYNTHETIC_PLANTED] = (
        GroundTruthOriginKind.SYNTHETIC_PLANTED
    )
    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    authored_by_evaluated_process: Literal[False] = False
    construction_basis: Literal["PRECOMMITTED_NON_MODEL_FIXTURE"] = "PRECOMMITTED_NON_MODEL_FIXTURE"
    construction_source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    construction_manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_ground_truth_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    regression_contract_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    origin_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("authored_by_evaluated_process", mode="before")
    @classmethod
    def authorship_flag_is_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="synthetic ground-truth authorship")

    @model_validator(mode="after")
    def origin_hash_is_exact(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"origin_sha256"}))
        if self.origin_sha256 != expected:
            raise ValueError("synthetic ground-truth origin hash is inconsistent")
        return self


class PublicEstablishedGroundTruthOrigin(_FrozenModel):
    """Externally published finding bound to an immutable affected source revision."""

    origin_kind: Literal[GroundTruthOriginKind.PUBLIC_ESTABLISHED] = (
        GroundTruthOriginKind.PUBLIC_ESTABLISHED
    )
    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    authored_by_evaluated_process: Literal[False] = False
    public_finding_id: str = Field(
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$",
    )
    publication_uri: str = Field(min_length=9, max_length=2_000)
    published_at: datetime
    publication_artifact_sha256: str = Field(pattern=_SHA256_PATTERN)
    publication_proof_kind: Literal["EXTERNAL_TRANSPARENCY_INCLUSION"] = (
        "EXTERNAL_TRANSPARENCY_INCLUSION"
    )
    publication_proof_sha256: str = Field(pattern=_SHA256_PATTERN)
    upstream_source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    upstream_source_sha256: str = Field(pattern=_SHA256_PATTERN)
    origin_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("authored_by_evaluated_process", mode="before")
    @classmethod
    def authorship_flag_is_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="public ground-truth authorship")

    @field_validator("publication_uri")
    @classmethod
    def publication_uri_is_canonical_https(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.hostname is None
            or parsed.port is not None
            or parsed.query
            or parsed.fragment
            or parsed.netloc != parsed.hostname
            or parsed.path in {"", "/"}
            or "//" in parsed.path
            or any(part in {"", ".", ".."} for part in parsed.path.split("/")[1:])
        ):
            raise ValueError("public ground-truth publication URI must be canonical HTTPS")
        return value

    @field_validator("published_at")
    @classmethod
    def published_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("public ground-truth publication time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def origin_hash_is_exact(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"origin_sha256"}))
        if self.origin_sha256 != expected:
            raise ValueError("public ground-truth origin hash is inconsistent")
        return self


GroundTruthOrigin = Annotated[
    SyntheticPlantedGroundTruthOrigin | PublicEstablishedGroundTruthOrigin,
    Field(discriminator="origin_kind"),
]


class FrozenGroundTruthCaseBinding(_FrozenModel):
    """Exact corpus, answer-key, source-excerpt, and origin join for one case."""

    case_id: str = Field(pattern=_CASE_ID_PATTERN)
    disposition: GroundTruthDisposition
    corpus_case_sha256: str = Field(pattern=_SHA256_PATTERN)
    ground_truth_case_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_excerpt_sha256: str = Field(pattern=_SHA256_PATTERN)
    origin: GroundTruthOrigin
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def case_and_hash_are_exact(self) -> Self:
        if self.origin.case_id != self.case_id:
            raise ValueError("ground-truth origin belongs to a different case")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("frozen ground-truth case binding hash is inconsistent")
        return self


class FrozenGroundTruthProvenance(_FrozenModel):
    """Non-authorizing exact provenance overlay for one frozen benchmark suite."""

    schema_version: Literal["1.0"] = "1.0"
    objective_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    benchmark_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_ground_truth_sha256: str = Field(pattern=_SHA256_PATTERN)
    case_bindings: tuple[FrozenGroundTruthCaseBinding, ...] = Field(
        min_length=1,
        max_length=_MAX_CASES,
    )
    case_binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    authored_by_evaluated_process: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    benchmark_scoring_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    provenance_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "authored_by_evaluated_process",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "authority_issuance_authorized",
        mode="before",
    )
    @classmethod
    def durable_authority_flags_are_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="durable ground-truth authority")

    @model_validator(mode="after")
    def exact_sets_flags_and_hash_are_consistent(self) -> Self:
        case_ids = tuple(binding.case_id for binding in self.case_bindings)
        if case_ids != tuple(sorted(set(case_ids))):
            raise ValueError("frozen ground-truth case bindings must be unique and sorted")
        expected_set = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.case_bindings]
        )
        if self.case_binding_set_sha256 != expected_set:
            raise ValueError("frozen ground-truth case-binding set hash is inconsistent")
        for binding in self.case_bindings:
            origin_revision = (
                binding.origin.construction_source_revision
                if isinstance(binding.origin, SyntheticPlantedGroundTruthOrigin)
                else binding.origin.upstream_source_revision
            )
            if origin_revision != self.source_revision:
                raise ValueError("ground-truth origin differs from the frozen source revision")
        synthetic = [
            binding.origin
            for binding in self.case_bindings
            if isinstance(binding.origin, SyntheticPlantedGroundTruthOrigin)
        ]
        if synthetic and any(
            len({getattr(origin, field) for origin in synthetic}) != 1
            for field in (
                "construction_manifest_file_sha256",
                "construction_ground_truth_file_sha256",
                "regression_contract_file_sha256",
            )
        ):
            raise ValueError("synthetic ground-truth origins use inconsistent construction files")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"provenance_sha256"}))
        if self.provenance_sha256 != expected:
            raise ValueError("frozen ground-truth provenance hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedFrozenGroundTruthProjection:
    """Non-authorizing values exposed after live process-local verification."""

    objective_sha256: str
    provenance_sha256: str
    source_revision: str
    benchmark_corpus_sha256: str
    benchmark_ground_truth_sha256: str
    case_binding_set_sha256: str
    case_count: int
    origin_kinds: tuple[GroundTruthOriginKind, ...]


class VerifiedFrozenGroundTruth:
    """Opaque process-local proof of exact external pins and rebuilt case joins."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedFrozenGroundTruth:
        del cls
        raise TypeError("verified frozen ground truth cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def require_for(
        self,
        *,
        objective_sha256: str,
        provenance_sha256: str,
        source_revision: str,
        benchmark_corpus_sha256: str,
        benchmark_ground_truth_sha256: str,
    ) -> VerifiedFrozenGroundTruthProjection:
        """Require the exact external pins and benchmark identities used at issuance."""

        return _require_verified_frozen_ground_truth(
            self,
            objective_sha256,
            provenance_sha256,
            source_revision,
            benchmark_corpus_sha256,
            benchmark_ground_truth_sha256,
        )

    def __copy__(self) -> Never:
        raise TypeError("verified frozen ground truth cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified frozen ground truth cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified frozen ground truth cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified frozen ground truth cannot be serialized")


@dataclass(frozen=True, slots=True)
class _VerifiedState:
    provenance: FrozenGroundTruthProvenance
    provenance_content_sha256: str
    projection_values: tuple[object, ...]


def _build_frozen_ground_truth_runtime_authority() -> tuple[
    Callable[..., VerifiedFrozenGroundTruth],
    Callable[..., VerifiedFrozenGroundTruthProjection],
]:
    registry: dict[
        int,
        tuple[weakref.ReferenceType[VerifiedFrozenGroundTruth], _VerifiedState],
    ] = {}
    lock = threading.RLock()
    compiled_objective_sha256 = FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256
    compiled_provenance_sha256 = FROZEN_GROUND_TRUTH_PROVENANCE_SHA256
    compiled_source_revision = FROZEN_GROUND_TRUTH_SOURCE_REVISION
    compiled_corpus_sha256 = FROZEN_GROUND_TRUTH_CORPUS_SHA256
    compiled_answer_key_sha256 = FROZEN_GROUND_TRUTH_ANSWER_KEY_SHA256
    compiled_manifest_file_sha256 = FROZEN_GROUND_TRUTH_MANIFEST_FILE_SHA256
    compiled_answer_key_file_sha256 = FROZEN_GROUND_TRUTH_ANSWER_KEY_FILE_SHA256
    compiled_regression_contract_file_sha256 = FROZEN_GROUND_TRUTH_REGRESSION_CONTRACT_FILE_SHA256

    def resolve(
        *,
        provenance: FrozenGroundTruthProvenance,
        benchmark_suite: ModelBenchmarkSuite,
    ) -> VerifiedFrozenGroundTruth:
        if type(provenance) is not FrozenGroundTruthProvenance:
            raise ValueError("frozen ground-truth provenance must be exact and typed")
        if type(benchmark_suite) is not ModelBenchmarkSuite:
            raise ValueError("frozen ground-truth benchmark suite must be exact and typed")
        try:
            validated = FrozenGroundTruthProvenance.model_validate_json(
                provenance.model_dump_json(),
                strict=True,
            )
            suite = ModelBenchmarkSuite.model_validate_json(
                benchmark_suite.model_dump_json(),
                strict=True,
            )
        except Exception:
            raise ValueError("frozen ground-truth inputs are structurally invalid") from None
        if validated != provenance or suite != benchmark_suite:
            raise ValueError("frozen ground-truth inputs changed during validation")
        if (
            validated.objective_sha256 != compiled_objective_sha256
            or validated.provenance_sha256 != compiled_provenance_sha256
            or validated.source_revision != compiled_source_revision
            or validated.benchmark_corpus_sha256 != compiled_corpus_sha256
            or validated.benchmark_ground_truth_sha256 != compiled_answer_key_sha256
        ):
            raise ValueError("frozen ground-truth provenance differs from compiled frozen pins")
        if (
            validated.benchmark_corpus_sha256 != suite.corpus_sha256
            or validated.benchmark_ground_truth_sha256 != suite.ground_truth_sha256
        ):
            raise ValueError("frozen ground-truth provenance differs from the benchmark suite")
        expected_bindings = tuple(
            _rebuilt_case_binding(binding, suite) for binding in validated.case_bindings
        )
        if expected_bindings != validated.case_bindings:
            raise ValueError("frozen ground-truth case provenance differs from benchmark truth")
        suite_case_ids = tuple(case.case_id for case in suite.cases)
        if tuple(binding.case_id for binding in expected_bindings) != suite_case_ids:
            raise ValueError("frozen ground-truth provenance does not exactly cover the suite")
        for binding in validated.case_bindings:
            if not isinstance(binding.origin, SyntheticPlantedGroundTruthOrigin):
                raise ValueError(
                    "public ground truth requires an independently verified publication capability"
                )
            if (
                binding.origin.construction_source_revision != compiled_source_revision
                or binding.origin.construction_manifest_file_sha256 != compiled_manifest_file_sha256
                or binding.origin.construction_ground_truth_file_sha256
                != compiled_answer_key_file_sha256
                or binding.origin.regression_contract_file_sha256
                != compiled_regression_contract_file_sha256
            ):
                raise ValueError("synthetic ground truth differs from compiled construction pins")

        projection = VerifiedFrozenGroundTruthProjection(
            objective_sha256=validated.objective_sha256,
            provenance_sha256=validated.provenance_sha256,
            source_revision=validated.source_revision,
            benchmark_corpus_sha256=validated.benchmark_corpus_sha256,
            benchmark_ground_truth_sha256=validated.benchmark_ground_truth_sha256,
            case_binding_set_sha256=validated.case_binding_set_sha256,
            case_count=len(validated.case_bindings),
            origin_kinds=tuple(
                sorted(
                    {binding.origin.origin_kind for binding in validated.case_bindings},
                    key=lambda item: item.value,
                )
            ),
        )
        capability = object.__new__(VerifiedFrozenGroundTruth)
        key = id(capability)
        state = _VerifiedState(
            provenance=validated,
            provenance_content_sha256=_model_content_sha256(validated),
            projection_values=_ground_truth_projection_values(projection),
        )

        def discard(reference: weakref.ReferenceType[VerifiedFrozenGroundTruth]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return capability

    def require(
        capability: VerifiedFrozenGroundTruth,
        objective_sha256: str,
        provenance_sha256: str,
        source_revision: str,
        benchmark_corpus_sha256: str,
        benchmark_ground_truth_sha256: str,
    ) -> VerifiedFrozenGroundTruthProjection:
        _require_sha256(objective_sha256, label="required objective")
        _require_sha256(provenance_sha256, label="required provenance")
        _require_source_revision(source_revision, label="required source revision")
        _require_sha256(benchmark_corpus_sha256, label="required benchmark corpus")
        _require_sha256(benchmark_ground_truth_sha256, label="required benchmark ground truth")
        with lock:
            registered = registry.get(id(capability))
        state = (
            registered[1]
            if type(capability) is VerifiedFrozenGroundTruth
            and registered is not None
            and registered[0]() is capability
            else None
        )
        if state is None:
            raise ValueError("verified frozen ground-truth authority is absent")
        try:
            current = FrozenGroundTruthProvenance.model_validate_json(
                state.provenance.model_dump_json(),
                strict=True,
            )
        except Exception:
            raise ValueError("verified frozen ground-truth authority became inconsistent") from None
        projection = VerifiedFrozenGroundTruthProjection(
            objective_sha256=current.objective_sha256,
            provenance_sha256=current.provenance_sha256,
            source_revision=current.source_revision,
            benchmark_corpus_sha256=current.benchmark_corpus_sha256,
            benchmark_ground_truth_sha256=current.benchmark_ground_truth_sha256,
            case_binding_set_sha256=current.case_binding_set_sha256,
            case_count=len(current.case_bindings),
            origin_kinds=tuple(
                sorted(
                    {binding.origin.origin_kind for binding in current.case_bindings},
                    key=lambda item: item.value,
                )
            ),
        )
        if (
            current != state.provenance
            or _model_content_sha256(current) != state.provenance_content_sha256
            or _ground_truth_projection_values(projection) != state.projection_values
            or projection.objective_sha256 != objective_sha256
            or projection.provenance_sha256 != provenance_sha256
            or projection.source_revision != source_revision
            or projection.benchmark_corpus_sha256 != benchmark_corpus_sha256
            or projection.benchmark_ground_truth_sha256 != benchmark_ground_truth_sha256
        ):
            raise ValueError("verified frozen ground-truth authority is mismatched")
        return projection

    return resolve, require


(
    resolve_verified_frozen_ground_truth,
    _require_verified_frozen_ground_truth,
) = _build_frozen_ground_truth_runtime_authority()
del _build_frozen_ground_truth_runtime_authority


def load_frozen_ground_truth_provenance(path: Path) -> FrozenGroundTruthProvenance:
    """Descriptor-safely load one bounded, duplicate-key-free provenance artifact."""

    observation = read_json_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        max_bytes=_MAX_PROVENANCE_BYTES,
    )
    if not isinstance(observation.value, dict):
        raise ValueError("frozen ground-truth provenance must be a JSON object")
    try:
        return FrozenGroundTruthProvenance.model_validate_json(
            observation.content,
            strict=True,
        )
    except ValueError as exc:
        raise ValueError("frozen ground-truth provenance is invalid") from exc


def _rebuilt_case_binding(
    supplied: FrozenGroundTruthCaseBinding,
    suite: ModelBenchmarkSuite,
) -> FrozenGroundTruthCaseBinding:
    corpus_by_id = {case.case_id: case for case in suite.cases}
    truth_by_id = {case.case_id: case for case in suite.ground_truth.cases}
    corpus_case = corpus_by_id.get(supplied.case_id)
    truth_case = truth_by_id.get(supplied.case_id)
    if corpus_case is None or truth_case is None:
        raise ValueError("frozen ground-truth case is absent from the benchmark suite")
    expected_disposition = _classification_disposition(truth_case.expectation.classification)
    if supplied.disposition is not expected_disposition:
        raise ValueError("frozen ground-truth disposition differs from benchmark truth")
    values = supplied.model_dump(mode="json", exclude={"binding_sha256"})
    values.update(
        {
            "corpus_case_sha256": canonical_sha256(corpus_case.model_dump(mode="json")),
            "ground_truth_case_sha256": canonical_sha256(truth_case.model_dump(mode="json")),
            "source_excerpt_sha256": hashlib.sha256(
                corpus_case.source_excerpt.encode("utf-8")
            ).hexdigest(),
        }
    )
    values["binding_sha256"] = canonical_sha256(values)
    return FrozenGroundTruthCaseBinding.model_validate_json(
        json.dumps(values, sort_keys=True, separators=(",", ":")),
        strict=True,
    )


def _classification_disposition(
    classification: ModelBenchmarkClassification,
) -> GroundTruthDisposition:
    return {
        ModelBenchmarkClassification.VULNERABILITY: GroundTruthDisposition.VULNERABILITY,
        ModelBenchmarkClassification.SAFE: GroundTruthDisposition.SAFE,
        ModelBenchmarkClassification.INSUFFICIENT_CONTEXT: (
            GroundTruthDisposition.INSUFFICIENT_CONTEXT
        ),
    }[classification]


def _require_literal_false(value: object, *, label: str) -> object:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label} flag must be literal false")
    return value


def _require_sha256(value: str, *, label: str) -> None:
    if type(value) is not str or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError(f"{label} SHA-256 is invalid")


def _require_source_revision(value: str, *, label: str) -> None:
    if type(value) is not str or re.fullmatch(_SOURCE_REVISION_PATTERN, value) is None:
        raise ValueError(f"{label} is not a full immutable source revision")


def _model_content_sha256(value: BaseModel) -> str:
    return canonical_sha256(value.model_dump(mode="json"))


def _ground_truth_projection_values(
    value: VerifiedFrozenGroundTruthProjection,
) -> tuple[object, ...]:
    return (
        value.objective_sha256,
        value.provenance_sha256,
        value.source_revision,
        value.benchmark_corpus_sha256,
        value.benchmark_ground_truth_sha256,
        value.case_binding_set_sha256,
        value.case_count,
        value.origin_kinds,
    )
