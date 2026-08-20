"""Provider-free custody for constructed synthetic model-lineage identities.

The durable models in this module are non-authorizing evidence.  Runtime lineage
custody is represented only by :class:`VerifiedFrozenModelLineage`, an opaque,
PID-bound capability issued after descriptor-safe reads match verifier-compiled
fixture bytes and all model-to-root joins are rebuilt.

Only the reserved, non-provider ``synthetic-lineage:`` namespace can issue today.
Public lineage provenance is modeled for a future externally verified publication
capability, but this resolver deliberately rejects it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Never, Protocol, Self, SupportsIndex, cast
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.models.identifiers import require_exact_openrouter_model_id
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import read_file_evidence, read_json_evidence
from mmaudit.reporting.json_report import stable_json

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_REVISION_PATTERN = r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
_SYNTHETIC_MODEL_ID_PATTERN = r"^synthetic-lineage:[a-z][a-z0-9_-]{0,31}/[a-z][a-z0-9._-]{0,63}$"
_CONSTRUCTION_GROUP_PATTERN = r"^constructed-root-[a-z][a-z0-9-]{0,47}$"
_MAX_MODELS = 128
_MAX_GROUP_MODELS = 32
_MAX_ARTIFACT_BYTES = 1_000_000
_MAX_SOURCE_BYTES = 100_000
_MAX_REGRESSION_BYTES = 100_000
_SYNTHETIC_NAMESPACE: Literal["MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1"] = (
    "MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1"
)
_SOURCE_HEADER = "MMAUDIT_SYNTHETIC_MODEL_LINEAGE_SOURCE_V1"
_ROOT_DOMAIN = b"mmaudit-synthetic-model-lineage-root-v1\0"
_CONCRETE_PATH_TYPE = type(Path())

FROZEN_MODEL_LINEAGE_OBJECTIVE_SHA256 = (
    "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
)
FROZEN_MODEL_LINEAGE_PROVENANCE_FILENAME = "provenance.json"
FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILENAME = "manifest.json"
FROZEN_MODEL_LINEAGE_SOURCE_FILENAME = "source.txt"
FROZEN_MODEL_LINEAGE_REGRESSION_FILENAME = "regression_contract.txt"

# Filled from the exact committed demonstration-only fixture bytes.  These are
# verifier constants, never values accepted from a runtime caller or artifact.
FROZEN_MODEL_LINEAGE_PROVENANCE_FILE_SHA256 = (
    "44a916b74457b51b486ca98954fc0a1280e45187e4e20c2c048b7f597fa9bf98"
)
FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILE_SHA256 = (
    "0f57e7c224e8e7178ab1baf33678c89c91b424383655e0e5f3b3078a56aa356a"
)
FROZEN_MODEL_LINEAGE_SOURCE_FILE_SHA256 = (
    "af58892d44968df4a3c2ffaa9e4aa239fb2d7762546770f54004bcadbef6bd41"
)
FROZEN_MODEL_LINEAGE_REGRESSION_FILE_SHA256 = (
    "65ca78292f7465045f58cc7676cee41708ab362dea3595756f640cf127a051e9"
)
FROZEN_MODEL_LINEAGE_PROVENANCE_SHA256 = (
    "7b36005d5ee33f31db8edf056b5d2dbe035c901de70eaa7c940153e69d9acbb5"
)
FROZEN_MODEL_LINEAGE_CONSTRUCTION_SHA256 = (
    "83e3001667782029981fc0ac1ae0f8e5acfe75bde892877e2f1300cd6cce6b63"
)
FROZEN_MODEL_LINEAGE_SOURCE_REVISION = (
    "af58892d44968df4a3c2ffaa9e4aa239fb2d7762546770f54004bcadbef6bd41"
)


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _HexDigest(Protocol):
    def hexdigest(self) -> str: ...


class ModelLineageOriginKind(StrEnum):
    """Structurally represented provenance kinds; neither grants authority alone."""

    SYNTHETIC_CONSTRUCTED = "SYNTHETIC_CONSTRUCTED"
    PUBLIC_ESTABLISHED = "PUBLIC_ESTABLISHED"


class SyntheticConstructedModelLineageOrigin(_FrozenModel):
    """One identity planted in the reserved non-provider construction domain."""

    origin_kind: Literal[ModelLineageOriginKind.SYNTHETIC_CONSTRUCTED] = (
        ModelLineageOriginKind.SYNTHETIC_CONSTRUCTED
    )
    exact_model_id: str = Field(pattern=_SYNTHETIC_MODEL_ID_PATTERN)
    model_identity_domain: Literal["MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1"] = (
        _SYNTHETIC_NAMESPACE
    )
    provenance_class: Literal["SYNTHETIC_CONSTRUCTED_TEST_FIXTURE"] = (
        "SYNTHETIC_CONSTRUCTED_TEST_FIXTURE"
    )
    non_model_authorship_verified: Literal[False] = False
    external_provenance_verified: Literal[False] = False
    real_provider_model_applicable: Literal[False] = False
    construction_group_id: str = Field(pattern=_CONSTRUCTION_GROUP_PATTERN)
    construction_group_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_group_model_ids: tuple[str, ...] = Field(
        min_length=1,
        max_length=_MAX_GROUP_MODELS,
    )
    construction_source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    construction_manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_source_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    regression_contract_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    origin_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "non_model_authorship_verified",
        "external_provenance_verified",
        "real_provider_model_applicable",
        mode="before",
    )
    @classmethod
    def provenance_flags_are_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="synthetic lineage provenance")

    @model_validator(mode="after")
    def exact_domain_and_hash_are_consistent(self) -> Self:
        _require_synthetic_model_id(self.exact_model_id)
        for model_id in self.construction_group_model_ids:
            _require_synthetic_model_id(model_id)
        if self.construction_group_model_ids != tuple(
            sorted(set(self.construction_group_model_ids))
        ):
            raise ValueError("synthetic lineage group inventory must be unique and sorted")
        if self.exact_model_id not in self.construction_group_model_ids:
            raise ValueError("synthetic lineage origin is absent from its group inventory")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"origin_sha256"}))
        if self.origin_sha256 != expected:
            raise ValueError("synthetic model-lineage origin hash is inconsistent")
        return self


class PublicEstablishedModelLineageOrigin(_FrozenModel):
    """Structurally representable public ancestry with no current issuer."""

    origin_kind: Literal[ModelLineageOriginKind.PUBLIC_ESTABLISHED] = (
        ModelLineageOriginKind.PUBLIC_ESTABLISHED
    )
    exact_model_id: str
    non_model_authorship_verified: Literal[False] = False
    external_provenance_verified: Literal[False] = False
    public_lineage_id: str = Field(
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
    origin_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("exact_model_id")
    @classmethod
    def model_id_is_exact_provider_identity(cls, value: str) -> str:
        return require_exact_openrouter_model_id(value, label="public lineage model ID")

    @field_validator(
        "non_model_authorship_verified",
        "external_provenance_verified",
        mode="before",
    )
    @classmethod
    def provenance_flags_are_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="public lineage provenance")

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
            raise ValueError("public lineage publication URI must be canonical HTTPS")
        return value

    @field_validator("published_at")
    @classmethod
    def published_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("public lineage publication time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def origin_hash_is_consistent(self) -> Self:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"origin_sha256"}))
        if self.origin_sha256 != expected:
            raise ValueError("public model-lineage origin hash is inconsistent")
        return self


ModelLineageOrigin = Annotated[
    SyntheticConstructedModelLineageOrigin | PublicEstablishedModelLineageOrigin,
    Field(discriminator="origin_kind"),
]


class FrozenModelLineageBinding(_FrozenModel):
    """One durable exact-model, canonical-model, root, and origin join."""

    exact_model_id: str = Field(min_length=3, max_length=300)
    canonical_model_id: str = Field(min_length=3, max_length=300)
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    origin: ModelLineageOrigin
    binding_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def identity_root_and_hash_are_consistent(self) -> Self:
        if self.origin.exact_model_id != self.exact_model_id:
            raise ValueError("model-lineage origin belongs to another exact model")
        if isinstance(self.origin, SyntheticConstructedModelLineageOrigin):
            _require_synthetic_model_id(self.exact_model_id)
            _require_synthetic_model_id(self.canonical_model_id)
            if self.canonical_model_id not in self.origin.construction_group_model_ids:
                raise ValueError("synthetic canonical model is absent from its group inventory")
            expected_root = _synthetic_root_lineage(self.origin.construction_group_model_ids)
            if self.root_lineage != expected_root:
                raise ValueError(
                    "synthetic root lineage is not derived from its construction group"
                )
        else:
            require_exact_openrouter_model_id(
                self.exact_model_id,
                label="public lineage exact model ID",
            )
            require_exact_openrouter_model_id(
                self.canonical_model_id,
                label="public lineage canonical model ID",
            )
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"binding_sha256"}))
        if self.binding_sha256 != expected:
            raise ValueError("frozen model-lineage binding hash is inconsistent")
        return self


class SyntheticModelLineageGroup(_FrozenModel):
    """One planted root and its exact reserved-domain alias closure."""

    group_id: str = Field(pattern=_CONSTRUCTION_GROUP_PATTERN)
    canonical_model_id: str = Field(pattern=_SYNTHETIC_MODEL_ID_PATTERN)
    model_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_GROUP_MODELS)
    group_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("model_ids")
    @classmethod
    def model_ids_are_reserved_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for model_id in value:
            _require_synthetic_model_id(model_id)
        if value != tuple(sorted(set(value))):
            raise ValueError("synthetic lineage model IDs must be unique and sorted")
        return value

    @model_validator(mode="after")
    def canonical_member_and_hash_are_consistent(self) -> Self:
        _require_synthetic_model_id(self.canonical_model_id)
        if self.canonical_model_id not in self.model_ids:
            raise ValueError("synthetic lineage canonical model must belong to its group")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"group_sha256"}))
        if self.group_sha256 != expected:
            raise ValueError("synthetic model-lineage group hash is inconsistent")
        return self


class SyntheticModelLineageConstruction(_FrozenModel):
    """Complete demonstration-only group construction parsed from exact source bytes."""

    schema_version: Literal["1.0"] = "1.0"
    model_identity_domain: Literal["MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1"] = (
        _SYNTHETIC_NAMESPACE
    )
    deployable: Literal[False] = False
    groups: tuple[SyntheticModelLineageGroup, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    construction_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("deployable", mode="before")
    @classmethod
    def deployable_is_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="synthetic lineage deployability")

    @model_validator(mode="after")
    def groups_and_hash_are_consistent(self) -> Self:
        group_ids = tuple(group.group_id for group in self.groups)
        if group_ids != tuple(sorted(set(group_ids))):
            raise ValueError("synthetic lineage groups must be unique and sorted")
        model_ids = tuple(model_id for group in self.groups for model_id in group.model_ids)
        if len(model_ids) > _MAX_MODELS:
            raise ValueError("synthetic lineage construction exceeds the total model bound")
        if len({model_id.casefold() for model_id in model_ids}) != len(model_ids):
            raise ValueError("synthetic lineage groups overlap an exact model identity")
        canonical_ids = tuple(group.canonical_model_id for group in self.groups)
        if len({model_id.casefold() for model_id in canonical_ids}) != len(canonical_ids):
            raise ValueError("synthetic lineage groups split a canonical model identity")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"construction_sha256"}))
        if self.construction_sha256 != expected:
            raise ValueError("synthetic model-lineage construction hash is inconsistent")
        return self


class FrozenModelLineageProvenance(_FrozenModel):
    """Strict durable evidence over exact constructed lineage source bytes."""

    schema_version: Literal["1.0"] = "1.0"
    authority_basis: Literal["MECHANISM_ONLY"] = "MECHANISM_ONLY"
    projection_scope: Literal["LOCAL_SYNTHETIC_MECHANISM_TEST"] = "LOCAL_SYNTHETIC_MECHANISM_TEST"
    objective_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_revision: str = Field(pattern=_SOURCE_REVISION_PATTERN)
    construction_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_manifest_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    construction_source_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    regression_contract_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    bindings: tuple[FrozenModelLineageBinding, ...] = Field(min_length=1, max_length=_MAX_MODELS)
    binding_set_sha256: str = Field(pattern=_SHA256_PATTERN)
    completion_eligible: Literal[False] = False
    non_model_authorship_verified: Literal[False] = False
    external_provenance_verified: Literal[False] = False
    real_provider_model_applicable: Literal[False] = False
    lineage_identity_authorized: Literal[False] = False
    provider_lineage_authorized: Literal[False] = False
    runner_authority_authorized: Literal[False] = False
    authority_issuance_authorized: Literal[False] = False
    model_qualification_authorized: Literal[False] = False
    production_selection_authorized: Literal[False] = False
    release_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    provider_access_authorized: Literal[False] = False
    provenance_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator(
        "completion_eligible",
        "non_model_authorship_verified",
        "external_provenance_verified",
        "real_provider_model_applicable",
        "lineage_identity_authorized",
        "provider_lineage_authorized",
        "runner_authority_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "release_authorized",
        "source_egress_authorized",
        "provider_access_authorized",
        mode="before",
    )
    @classmethod
    def authority_flags_are_literal_false(cls, value: object) -> object:
        return _require_literal_false(value, label="durable model-lineage authority")

    @model_validator(mode="after")
    def exact_sets_sources_and_hash_are_consistent(self) -> Self:
        model_ids = tuple(binding.exact_model_id for binding in self.bindings)
        if model_ids != tuple(sorted(set(model_ids))):
            raise ValueError("frozen model-lineage bindings must be unique and sorted")
        folded_exact_ids = {model_id.casefold() for model_id in model_ids}
        if len(folded_exact_ids) != len(model_ids):
            raise ValueError("frozen model-lineage exact IDs collide case-insensitively")
        roots_by_identity: dict[str, set[str]] = {}
        canonical_ids_by_root: dict[str, set[str]] = {}
        for binding in self.bindings:
            canonical_key = binding.canonical_model_id.casefold()
            if canonical_key not in folded_exact_ids:
                raise ValueError("frozen model-lineage canonical ID lacks an exact binding")
            for identity in (binding.exact_model_id, binding.canonical_model_id):
                roots_by_identity.setdefault(identity.casefold(), set()).add(binding.root_lineage)
            canonical_ids_by_root.setdefault(binding.root_lineage, set()).add(canonical_key)
        if any(len(roots) != 1 for roots in roots_by_identity.values()):
            raise ValueError("frozen model-lineage identity is split across roots")
        if any(len(canonical_ids) != 1 for canonical_ids in canonical_ids_by_root.values()):
            raise ValueError("frozen model-lineage root has conflicting canonical identities")
        expected_set = canonical_sha256(
            [binding.model_dump(mode="json") for binding in self.bindings]
        )
        if self.binding_set_sha256 != expected_set:
            raise ValueError("frozen model-lineage binding-set hash is inconsistent")
        for binding in self.bindings:
            origin = binding.origin
            if isinstance(origin, SyntheticConstructedModelLineageOrigin) and (
                origin.construction_source_revision != self.source_revision
                or origin.construction_manifest_file_sha256
                != self.construction_manifest_file_sha256
                or origin.construction_source_file_sha256 != self.construction_source_file_sha256
                or origin.regression_contract_file_sha256 != self.regression_contract_file_sha256
            ):
                raise ValueError("synthetic lineage origin differs from provenance source bytes")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"provenance_sha256"}))
        if self.provenance_sha256 != expected:
            raise ValueError("frozen model-lineage provenance hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class VerifiedFrozenModelLineageProjection:
    """Fresh non-authorizing values derived from an opaque verified capability."""

    authority_basis: Literal["MECHANISM_ONLY"]
    projection_scope: Literal["LOCAL_SYNTHETIC_MECHANISM_TEST"]
    completion_eligible: Literal[False]
    non_model_authorship_verified: Literal[False]
    external_provenance_verified: Literal[False]
    real_provider_model_applicable: Literal[False]
    lineage_identity_authorized: Literal[False]
    provider_lineage_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    authority_issuance_authorized: Literal[False]
    model_qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    release_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    provider_access_authorized: Literal[False]
    objective_sha256: str
    provenance_sha256: str
    provenance_file_sha256: str
    source_revision: str
    construction_sha256: str
    construction_file_sha256: str
    construction_source_file_sha256: str
    regression_contract_file_sha256: str
    binding_set_sha256: str
    exact_model_id: str
    canonical_model_id: str
    root_lineage: str
    binding_sha256: str
    origin_kind: ModelLineageOriginKind


@dataclass(frozen=True, slots=True)
class VerifiedFrozenModelLineagePairProjection:
    """Fresh same-root predicate derived from one opaque registry state."""

    authority_basis: Literal["MECHANISM_ONLY"]
    projection_scope: Literal["LOCAL_SYNTHETIC_MECHANISM_TEST"]
    completion_eligible: Literal[False]
    non_model_authorship_verified: Literal[False]
    external_provenance_verified: Literal[False]
    real_provider_model_applicable: Literal[False]
    lineage_identity_authorized: Literal[False]
    provider_lineage_authorized: Literal[False]
    runner_authority_authorized: Literal[False]
    authority_issuance_authorized: Literal[False]
    model_qualification_authorized: Literal[False]
    production_selection_authorized: Literal[False]
    release_authorized: Literal[False]
    source_egress_authorized: Literal[False]
    provider_access_authorized: Literal[False]
    candidate_exact_model_id: str
    candidate_root_lineage: str
    runner_exact_model_id: str
    runner_root_lineage: str
    same_root: Literal[False]
    provenance_sha256: str
    binding_set_sha256: str
    pair_sha256: str


class VerifiedFrozenModelLineage:
    """PID-local custody token for exact compiled synthetic construction bytes.

    The interpreter and imported verifier code are trusted.  The token rejects
    caller bytes, labels, serialization, copying, and fork inheritance, but pure
    Python cannot defend against hostile same-interpreter reflection or arbitrary
    mutation of closure cells.  Stronger custody requires a separate verifier
    process or a native non-reflective boundary.
    """

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> VerifiedFrozenModelLineage:
        del cls
        raise TypeError("verified frozen model lineage cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    def __copy__(self) -> Never:
        raise TypeError("verified frozen model lineage cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("verified frozen model lineage cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("verified frozen model lineage cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("verified frozen model lineage cannot be serialized")


@dataclass(frozen=True, slots=True)
class _VerifiedLineageBindingState:
    exact_model_id: str
    canonical_model_id: str
    root_lineage: str
    binding_sha256: str
    origin_kind: ModelLineageOriginKind


@dataclass(frozen=True, slots=True)
class _VerifiedLineageState:
    process_id: int
    objective_sha256: str
    provenance_sha256: str
    provenance_content_sha256: str
    source_revision: str
    construction_sha256: str
    construction_file_sha256: str
    construction_source_file_sha256: str
    regression_contract_file_sha256: str
    binding_set_sha256: str
    bindings: tuple[_VerifiedLineageBindingState, ...]


@dataclass(frozen=True, slots=True)
class _CompiledFixturePins:
    objective_sha256: str
    provenance_filename: str
    construction_filename: str
    source_filename: str
    regression_filename: str
    provenance_file_sha256: str
    construction_file_sha256: str
    source_file_sha256: str
    regression_file_sha256: str
    provenance_sha256: str
    construction_sha256: str
    source_revision: str
    identity_domain: str
    source_header: str
    root_domain: bytes
    max_artifact_bytes: int
    max_source_bytes: int
    max_regression_bytes: int
    max_models: int
    concrete_path_type: type[Path]


@dataclass(frozen=True, slots=True)
class _VerifiedFixtureDigests:
    provenance_file_sha256: str
    construction_file_sha256: str
    source_file_sha256: str
    regression_file_sha256: str


def _build_frozen_model_lineage_runtime_authority() -> tuple[
    Callable[[Path], VerifiedFrozenModelLineage],
    Callable[[VerifiedFrozenModelLineage, str], VerifiedFrozenModelLineageProjection],
    Callable[
        [VerifiedFrozenModelLineage, str, str],
        VerifiedFrozenModelLineagePairProjection,
    ],
]:
    """Capture the verifier surface and invalidate inherited capabilities after fork."""

    # These bindings deliberately occur once, after every helper is defined.  Ordinary
    # reassignment of module globals cannot retarget the issuer.  Arbitrary reflection
    # into Python closure cells remains outside the documented trusted-interpreter
    # boundary of this mechanism-only fixture.
    read_json = read_json_evidence
    read_file = read_file_evidence
    parse_construction_source = _parse_construction_source
    rebuild_synthetic_bindings = _rebuild_synthetic_bindings
    derive_synthetic_root = _synthetic_root_lineage
    require_synthetic_model_id = _require_synthetic_model_id
    canonical_hash = canonical_sha256
    render_stable_json = stable_json
    dump_json = json.dumps
    load_json = json.loads
    sha256_hex = _sha256_hex
    sha256_constructor = hashlib.sha256
    current_process_id = os.getpid
    owner_process_id = current_process_id()
    public_origin_type = PublicEstablishedModelLineageOrigin
    capability_type = VerifiedFrozenModelLineage
    binding_state_type = _VerifiedLineageBindingState
    verified_state_type = _VerifiedLineageState
    fixture_digests_type = _VerifiedFixtureDigests
    projection_type = VerifiedFrozenModelLineageProjection
    pair_projection_type = VerifiedFrozenModelLineagePairProjection
    synthetic_origin_kind = ModelLineageOriginKind.SYNTHETIC_CONSTRUCTED
    make_weakref = weakref.ref
    provenance_validator = FrozenModelLineageProvenance.__pydantic_validator__.validate_json
    construction_validator = SyntheticModelLineageConstruction.__pydantic_validator__.validate_json
    group_validator = SyntheticModelLineageGroup.__pydantic_validator__.validate_json
    origin_validator = SyntheticConstructedModelLineageOrigin.__pydantic_validator__.validate_json
    binding_validator = FrozenModelLineageBinding.__pydantic_validator__.validate_json
    pins = _CompiledFixturePins(
        objective_sha256=FROZEN_MODEL_LINEAGE_OBJECTIVE_SHA256,
        provenance_filename=FROZEN_MODEL_LINEAGE_PROVENANCE_FILENAME,
        construction_filename=FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILENAME,
        source_filename=FROZEN_MODEL_LINEAGE_SOURCE_FILENAME,
        regression_filename=FROZEN_MODEL_LINEAGE_REGRESSION_FILENAME,
        provenance_file_sha256=FROZEN_MODEL_LINEAGE_PROVENANCE_FILE_SHA256,
        construction_file_sha256=FROZEN_MODEL_LINEAGE_CONSTRUCTION_FILE_SHA256,
        source_file_sha256=FROZEN_MODEL_LINEAGE_SOURCE_FILE_SHA256,
        regression_file_sha256=FROZEN_MODEL_LINEAGE_REGRESSION_FILE_SHA256,
        provenance_sha256=FROZEN_MODEL_LINEAGE_PROVENANCE_SHA256,
        construction_sha256=FROZEN_MODEL_LINEAGE_CONSTRUCTION_SHA256,
        source_revision=FROZEN_MODEL_LINEAGE_SOURCE_REVISION,
        identity_domain=_SYNTHETIC_NAMESPACE,
        source_header=_SOURCE_HEADER,
        root_domain=_ROOT_DOMAIN,
        max_artifact_bytes=_MAX_ARTIFACT_BYTES,
        max_source_bytes=_MAX_SOURCE_BYTES,
        max_regression_bytes=_MAX_REGRESSION_BYTES,
        max_models=_MAX_MODELS,
        concrete_path_type=_CONCRETE_PATH_TYPE,
    )
    registry: dict[
        int,
        tuple[weakref.ReferenceType[VerifiedFrozenModelLineage], _VerifiedLineageState],
    ] = {}
    lock = threading.RLock()

    def group_from_payload(payload: dict[str, object]) -> SyntheticModelLineageGroup:
        return cast(
            SyntheticModelLineageGroup,
            group_validator(
                dump_json(payload, sort_keys=True, separators=(",", ":")),
                strict=True,
            ),
        )

    def construction_from_payload(
        payload: dict[str, object],
    ) -> SyntheticModelLineageConstruction:
        return cast(
            SyntheticModelLineageConstruction,
            construction_validator(
                dump_json(payload, sort_keys=True, separators=(",", ":")),
                strict=True,
            ),
        )

    def origin_from_payload(
        payload: dict[str, object],
    ) -> SyntheticConstructedModelLineageOrigin:
        return cast(
            SyntheticConstructedModelLineageOrigin,
            origin_validator(
                dump_json(payload, sort_keys=True, separators=(",", ":")),
                strict=True,
            ),
        )

    def binding_from_payload(payload: dict[str, object]) -> FrozenModelLineageBinding:
        return cast(
            FrozenModelLineageBinding,
            binding_validator(
                dump_json(payload, sort_keys=True, separators=(",", ":")),
                strict=True,
            ),
        )

    def trusted_root(model_ids: tuple[str, ...]) -> str:
        return derive_synthetic_root(
            model_ids,
            identity_domain=pins.identity_domain,
            root_domain=pins.root_domain,
            model_id_validator=require_synthetic_model_id,
            sha256_constructor=sha256_constructor,
        )

    def public_claim_is_present(content: bytes) -> bool:
        try:
            parsed: object = load_json(content)
        except (UnicodeDecodeError, ValueError):
            return False
        if not isinstance(parsed, dict):
            return False
        bindings = parsed.get("bindings")
        if not isinstance(bindings, list):
            return False
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            origin = binding.get("origin")
            if isinstance(origin, dict) and origin.get("origin_kind") == "PUBLIC_ESTABLISHED":
                return True
        return False

    def verify_fixture(
        fixture_root: Path,
    ) -> tuple[
        FrozenModelLineageProvenance,
        SyntheticModelLineageConstruction,
        tuple[FrozenModelLineageBinding, ...],
        _VerifiedFixtureDigests,
    ]:
        if type(fixture_root) is not pins.concrete_path_type:
            raise ValueError("frozen model-lineage fixture root must be a concrete Path")
        provenance_observation = read_json(
            evidence_root=fixture_root,
            relative_path=pins.provenance_filename,
            max_bytes=pins.max_artifact_bytes,
        )
        construction_observation = read_json(
            evidence_root=fixture_root,
            relative_path=pins.construction_filename,
            max_bytes=pins.max_artifact_bytes,
        )
        source_observation = read_file(
            evidence_root=fixture_root,
            relative_path=pins.source_filename,
            max_bytes=pins.max_source_bytes,
        )
        regression_observation = read_file(
            evidence_root=fixture_root,
            relative_path=pins.regression_filename,
            max_bytes=pins.max_regression_bytes,
        )
        if public_claim_is_present(provenance_observation.content):
            raise ValueError(
                "public model lineage requires an independent publication verification capability"
            )
        actual_hashes = (
            sha256_hex(provenance_observation.content),
            sha256_hex(construction_observation.content),
            sha256_hex(source_observation.content),
            sha256_hex(regression_observation.content),
        )
        if actual_hashes != (
            pins.provenance_file_sha256,
            pins.construction_file_sha256,
            pins.source_file_sha256,
            pins.regression_file_sha256,
        ):
            raise ValueError("frozen model-lineage fixture bytes differ from compiled pins")

        # Core-schema validator callables were captured before caller code can
        # replace module parsers or model factories.  They parse the exact bytes
        # whose four raw digests were just compared to private compiled pins.
        provenance = cast(
            FrozenModelLineageProvenance,
            provenance_validator(provenance_observation.content, strict=True),
        )
        construction = cast(
            SyntheticModelLineageConstruction,
            construction_validator(construction_observation.content, strict=True),
        )
        if provenance_observation.content != render_stable_json(provenance).encode(
            "utf-8"
        ) or construction_observation.content != render_stable_json(construction).encode("utf-8"):
            raise ValueError("frozen model-lineage JSON fixture is not canonically serialized")
        if (
            provenance.objective_sha256 != pins.objective_sha256
            or provenance.provenance_sha256 != pins.provenance_sha256
            or provenance.source_revision != pins.source_revision
            or construction.construction_sha256 != pins.construction_sha256
            or provenance.construction_sha256 != construction.construction_sha256
            or provenance.construction_manifest_file_sha256 != actual_hashes[1]
            or provenance.construction_source_file_sha256 != actual_hashes[2]
            or provenance.regression_contract_file_sha256 != actual_hashes[3]
            or provenance.source_revision != actual_hashes[2]
        ):
            raise ValueError("frozen model-lineage evidence differs from compiled semantic pins")
        expected_groups = parse_construction_source(
            source_observation.content,
            pins=pins,
            canonical_hash=canonical_hash,
            group_from_payload=group_from_payload,
            construction_from_payload=construction_from_payload,
        )
        if construction.groups != expected_groups:
            raise ValueError("synthetic lineage manifest differs from exact construction source")
        expected_bindings = rebuild_synthetic_bindings(
            construction,
            pins=pins,
            derive_root=trusted_root,
            canonical_hash=canonical_hash,
            origin_kind_value=synthetic_origin_kind.value,
            origin_from_payload=origin_from_payload,
            binding_from_payload=binding_from_payload,
        )
        if provenance.bindings != expected_bindings:
            raise ValueError("frozen model-lineage provenance differs from its construction")
        return (
            provenance,
            construction,
            expected_bindings,
            fixture_digests_type(
                provenance_file_sha256=actual_hashes[0],
                construction_file_sha256=actual_hashes[1],
                source_file_sha256=actual_hashes[2],
                regression_file_sha256=actual_hashes[3],
            ),
        )

    def resolve(fixture_root: Path) -> VerifiedFrozenModelLineage:
        if current_process_id() != owner_process_id:
            raise ValueError("frozen model-lineage resolver cannot cross a process fork")
        provenance, construction, expected_bindings, digests = verify_fixture(fixture_root)
        if any(isinstance(binding.origin, public_origin_type) for binding in expected_bindings):
            raise ValueError(
                "public model lineage requires an independent publication verification capability"
            )

        bindings = tuple(
            binding_state_type(
                exact_model_id=model_id,
                canonical_model_id=group.canonical_model_id,
                root_lineage=trusted_root(group.model_ids),
                binding_sha256=next(
                    binding.binding_sha256
                    for binding in expected_bindings
                    if binding.exact_model_id == model_id
                ),
                origin_kind=synthetic_origin_kind,
            )
            for group in construction.groups
            for model_id in group.model_ids
        )
        capability = object.__new__(capability_type)
        state = verified_state_type(
            process_id=current_process_id(),
            objective_sha256=provenance.objective_sha256,
            provenance_sha256=provenance.provenance_sha256,
            provenance_content_sha256=digests.provenance_file_sha256,
            source_revision=provenance.source_revision,
            construction_sha256=construction.construction_sha256,
            construction_file_sha256=digests.construction_file_sha256,
            construction_source_file_sha256=digests.source_file_sha256,
            regression_contract_file_sha256=digests.regression_file_sha256,
            binding_set_sha256=provenance.binding_set_sha256,
            bindings=tuple(sorted(bindings, key=lambda item: item.exact_model_id)),
        )
        key = id(capability)

        def discard(reference: weakref.ReferenceType[VerifiedFrozenModelLineage]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = make_weakref(capability, discard)
        with lock:
            registry[key] = (reference, state)
        return capability

    def state_for(capability: VerifiedFrozenModelLineage) -> _VerifiedLineageState:
        process_id = current_process_id()
        if process_id != owner_process_id:
            raise ValueError("verified frozen model-lineage authority cannot cross a process fork")
        with lock:
            registered = registry.get(id(capability))
        state = (
            registered[1]
            if type(capability) is capability_type
            and registered is not None
            and registered[0]() is capability
            else None
        )
        if state is None:
            raise ValueError("verified frozen model-lineage authority is absent")
        if state.process_id != process_id:
            raise ValueError("verified frozen model-lineage authority cannot cross a process fork")
        return state

    def project(
        state: _VerifiedLineageState,
        exact_model_id: str,
    ) -> VerifiedFrozenModelLineageProjection:
        model_id = require_synthetic_model_id(exact_model_id)
        matches = tuple(binding for binding in state.bindings if binding.exact_model_id == model_id)
        if len(matches) != 1:
            raise ValueError("exact model is absent from verified frozen model lineage")
        binding = matches[0]
        return projection_type(
            authority_basis="MECHANISM_ONLY",
            projection_scope="LOCAL_SYNTHETIC_MECHANISM_TEST",
            completion_eligible=False,
            non_model_authorship_verified=False,
            external_provenance_verified=False,
            real_provider_model_applicable=False,
            lineage_identity_authorized=False,
            provider_lineage_authorized=False,
            runner_authority_authorized=False,
            authority_issuance_authorized=False,
            model_qualification_authorized=False,
            production_selection_authorized=False,
            release_authorized=False,
            source_egress_authorized=False,
            provider_access_authorized=False,
            objective_sha256=state.objective_sha256,
            provenance_sha256=state.provenance_sha256,
            provenance_file_sha256=state.provenance_content_sha256,
            source_revision=state.source_revision,
            construction_sha256=state.construction_sha256,
            construction_file_sha256=state.construction_file_sha256,
            construction_source_file_sha256=state.construction_source_file_sha256,
            regression_contract_file_sha256=state.regression_contract_file_sha256,
            binding_set_sha256=state.binding_set_sha256,
            exact_model_id=binding.exact_model_id,
            canonical_model_id=binding.canonical_model_id,
            root_lineage=binding.root_lineage,
            binding_sha256=binding.binding_sha256,
            origin_kind=binding.origin_kind,
        )

    def require(
        capability: VerifiedFrozenModelLineage,
        exact_model_id: str,
    ) -> VerifiedFrozenModelLineageProjection:
        # Return a fresh value object; canonical and root values are never accepted
        # from the caller or retained in a mutable projection instance.
        return project(state_for(capability), exact_model_id)

    def require_independent(
        capability: VerifiedFrozenModelLineage,
        candidate_exact_model_id: str,
        runner_exact_model_id: str,
    ) -> VerifiedFrozenModelLineagePairProjection:
        state = state_for(capability)
        candidate = project(state, candidate_exact_model_id)
        runner = project(state, runner_exact_model_id)
        if candidate.exact_model_id == runner.exact_model_id:
            raise ValueError("candidate and runner require distinct exact model identities")
        if candidate.root_lineage == runner.root_lineage:
            raise ValueError("same-root candidate and runner are not lineage-independent")
        payload = {
            "authority_basis": "MECHANISM_ONLY",
            "projection_scope": "LOCAL_SYNTHETIC_MECHANISM_TEST",
            "completion_eligible": False,
            "non_model_authorship_verified": False,
            "external_provenance_verified": False,
            "real_provider_model_applicable": False,
            "lineage_identity_authorized": False,
            "provider_lineage_authorized": False,
            "runner_authority_authorized": False,
            "authority_issuance_authorized": False,
            "model_qualification_authorized": False,
            "production_selection_authorized": False,
            "release_authorized": False,
            "source_egress_authorized": False,
            "provider_access_authorized": False,
            "candidate_exact_model_id": candidate.exact_model_id,
            "candidate_root_lineage": candidate.root_lineage,
            "runner_exact_model_id": runner.exact_model_id,
            "runner_root_lineage": runner.root_lineage,
            "same_root": False,
            "provenance_sha256": candidate.provenance_sha256,
            "binding_set_sha256": candidate.binding_set_sha256,
        }
        return pair_projection_type(
            authority_basis="MECHANISM_ONLY",
            projection_scope="LOCAL_SYNTHETIC_MECHANISM_TEST",
            completion_eligible=False,
            non_model_authorship_verified=False,
            external_provenance_verified=False,
            real_provider_model_applicable=False,
            lineage_identity_authorized=False,
            provider_lineage_authorized=False,
            runner_authority_authorized=False,
            authority_issuance_authorized=False,
            model_qualification_authorized=False,
            production_selection_authorized=False,
            release_authorized=False,
            source_egress_authorized=False,
            provider_access_authorized=False,
            candidate_exact_model_id=candidate.exact_model_id,
            candidate_root_lineage=candidate.root_lineage,
            runner_exact_model_id=runner.exact_model_id,
            runner_root_lineage=runner.root_lineage,
            same_root=False,
            provenance_sha256=candidate.provenance_sha256,
            binding_set_sha256=candidate.binding_set_sha256,
            pair_sha256=canonical_hash(payload),
        )

    return resolve, require, require_independent


def load_frozen_model_lineage_provenance(path: Path) -> FrozenModelLineageProvenance:
    """Descriptor-safely load one bounded durable provenance artifact."""

    if type(path) is not _CONCRETE_PATH_TYPE:
        raise ValueError("frozen model-lineage provenance path must be a Path")
    observation = read_json_evidence(
        evidence_root=path.parent,
        relative_path=path.name,
        max_bytes=_MAX_ARTIFACT_BYTES,
    )
    provenance = _parse_json_model(
        observation.content,
        FrozenModelLineageProvenance,
        label="frozen model-lineage provenance",
    )
    if observation.content != stable_json(provenance).encode("utf-8"):
        raise ValueError("frozen model-lineage provenance is not canonically serialized")
    return provenance


def _parse_construction_source(
    content: bytes,
    *,
    pins: _CompiledFixturePins,
    canonical_hash: Callable[[object], str],
    group_from_payload: Callable[[dict[str, object]], SyntheticModelLineageGroup],
    construction_from_payload: Callable[
        [dict[str, object]],
        SyntheticModelLineageConstruction,
    ],
) -> tuple[SyntheticModelLineageGroup, ...]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("synthetic lineage source must be UTF-8") from exc
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        raise ValueError("synthetic lineage source must be canonical newline-delimited text")
    lines = text[:-1].split("\n")
    if (
        not lines
        or lines[0] != pins.source_header
        or len(lines) < 2
        or len(lines) > pins.max_models + 1
    ):
        raise ValueError("synthetic lineage source header or group count is invalid")
    groups: list[SyntheticModelLineageGroup] = []
    for line in lines[1:]:
        if any(ord(character) < 32 or ord(character) > 126 for character in line):
            raise ValueError("synthetic lineage source contains unsupported characters")
        parts = line.split("|")
        if len(parts) != 3:
            raise ValueError("synthetic lineage source row is malformed")
        group_id, canonical_model_id, model_text = parts
        model_ids = tuple(model_text.split(","))
        group_payload = {
            "group_id": group_id,
            "canonical_model_id": canonical_model_id,
            "model_ids": list(model_ids),
        }
        groups.append(
            group_from_payload({**group_payload, "group_sha256": canonical_hash(group_payload)})
        )
    result = tuple(groups)
    # Construction-level validation catches group order, overlap, and canonical splits.
    construction_payload: dict[str, object] = {
        "schema_version": "1.0",
        "model_identity_domain": pins.identity_domain,
        "deployable": False,
        "groups": [group.model_dump(mode="json") for group in result],
    }
    construction_from_payload(
        {
            **construction_payload,
            "construction_sha256": canonical_hash(construction_payload),
        },
    )
    return result


def _rebuild_synthetic_bindings(
    construction: SyntheticModelLineageConstruction,
    *,
    pins: _CompiledFixturePins,
    derive_root: Callable[[tuple[str, ...]], str],
    canonical_hash: Callable[[object], str],
    origin_kind_value: str,
    origin_from_payload: Callable[
        [dict[str, object]],
        SyntheticConstructedModelLineageOrigin,
    ],
    binding_from_payload: Callable[[dict[str, object]], FrozenModelLineageBinding],
) -> tuple[FrozenModelLineageBinding, ...]:
    bindings: list[FrozenModelLineageBinding] = []
    for group in construction.groups:
        root_lineage = derive_root(group.model_ids)
        for model_id in group.model_ids:
            origin_payload = {
                "origin_kind": origin_kind_value,
                "exact_model_id": model_id,
                "model_identity_domain": pins.identity_domain,
                "provenance_class": "SYNTHETIC_CONSTRUCTED_TEST_FIXTURE",
                "non_model_authorship_verified": False,
                "external_provenance_verified": False,
                "real_provider_model_applicable": False,
                "construction_group_id": group.group_id,
                "construction_group_sha256": group.group_sha256,
                "construction_group_model_ids": list(group.model_ids),
                "construction_source_revision": pins.source_revision,
                "construction_manifest_file_sha256": pins.construction_file_sha256,
                "construction_source_file_sha256": pins.source_file_sha256,
                "regression_contract_file_sha256": pins.regression_file_sha256,
            }
            origin = origin_from_payload(
                {**origin_payload, "origin_sha256": canonical_hash(origin_payload)}
            )
            binding_payload = {
                "exact_model_id": model_id,
                "canonical_model_id": group.canonical_model_id,
                "root_lineage": root_lineage,
                "origin": origin.model_dump(mode="json"),
            }
            bindings.append(
                binding_from_payload(
                    {
                        **binding_payload,
                        "binding_sha256": canonical_hash(binding_payload),
                    }
                )
            )
    return tuple(sorted(bindings, key=lambda item: item.exact_model_id))


def _synthetic_root_lineage(
    model_ids: tuple[str, ...],
    *,
    identity_domain: str = _SYNTHETIC_NAMESPACE,
    root_domain: bytes = _ROOT_DOMAIN,
    model_id_validator: Callable[[object], str] | None = None,
    sha256_constructor: Callable[[bytes], _HexDigest] = hashlib.sha256,
) -> str:
    """Derive genealogy only from its domain and complete sorted member inventory."""

    if model_ids != tuple(sorted(set(model_ids))) or not model_ids:
        raise ValueError("synthetic lineage root inventory must be non-empty, unique, and sorted")
    validator = _require_synthetic_model_id if model_id_validator is None else model_id_validator
    framed_inventory = bytearray()
    for model_id in model_ids:
        encoded = validator(model_id).encode("ascii")
        framed_inventory.extend(len(encoded).to_bytes(4, "big"))
        framed_inventory.extend(encoded)
    return (
        "sha256:"
        + sha256_constructor(
            root_domain + identity_domain.encode("ascii") + b"\0" + framed_inventory
        ).hexdigest()
    )


def _require_synthetic_model_id(value: object) -> str:
    if type(value) is not str or re.fullmatch(_SYNTHETIC_MODEL_ID_PATTERN, value) is None:
        raise ValueError("model ID is outside the reserved synthetic-lineage namespace")
    # The reserved colon in the author segment must remain invalid as a provider ID.
    try:
        require_exact_openrouter_model_id(value)
    except ValueError:
        return value
    raise ValueError("reserved synthetic lineage ID unexpectedly overlaps provider model syntax")


def _require_literal_false(value: object, *, label: str) -> object:
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label} flag must be literal false")
    return value


def _parse_json_model[ModelT: BaseModel](
    content: bytes,
    model: type[ModelT],
    *,
    label: str,
) -> ModelT:
    try:
        parsed = model.model_validate_json(content, strict=True)
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    # A second canonical-value round trip makes subtype/model_construct inputs irrelevant.
    try:
        copied = model.model_validate_json(
            json.dumps(
                parsed.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ),
            strict=True,
        )
    except ValueError as exc:
        raise ValueError(f"{label} is invalid") from exc
    if copied != parsed:
        raise ValueError(f"{label} changed during validation")
    return copied


def _sha256_hex(
    content: bytes,
    _sha256: Callable[[bytes], _HexDigest] = hashlib.sha256,
) -> str:
    digest = _sha256(content)
    value = digest.hexdigest()
    if type(value) is not str or re.fullmatch(_SHA256_PATTERN, value) is None:
        raise ValueError("SHA-256 implementation returned an invalid digest")
    return value


# Instantiate only after every verification helper exists so the issuer captures
# pristine callable objects and compiled primitive pins rather than resolving
# mutable module globals at issuance time.
(
    resolve_verified_frozen_model_lineage,
    require_verified_frozen_model_lineage,
    require_independent_frozen_model_lineage,
) = _build_frozen_model_lineage_runtime_authority()
del _build_frozen_model_lineage_runtime_authority
