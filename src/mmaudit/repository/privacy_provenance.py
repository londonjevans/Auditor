"""Fail-closed provenance for source classifications that permit benchmark egress."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import threading
import weakref
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal, Self, SupportsIndex, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import mmaudit
from mmaudit.models.provider_smoke import (
    REAL_PROVIDER_SMOKE_ROLE as _TRUSTED_PROVIDER_SMOKE_ROLE,
)
from mmaudit.models.provider_smoke import (
    REAL_PROVIDER_SMOKE_SCHEMA_NAME as _TRUSTED_PROVIDER_SMOKE_SCHEMA_NAME,
)
from mmaudit.models.provider_smoke import (
    SyntheticProviderSmokeResponse as _TRUSTED_PROVIDER_SMOKE_RESPONSE,
)
from mmaudit.models.provider_smoke import (
    build_provider_smoke_user_prompt as _TRUSTED_BUILD_PROVIDER_SMOKE_USER_PROMPT,
)
from mmaudit.models.provider_smoke import (
    provider_smoke_request_commitment as _TRUSTED_PROVIDER_SMOKE_REQUEST_COMMITMENT,
)
from mmaudit.models.provider_smoke import (
    provider_smoke_system_prompt as _TRUSTED_PROVIDER_SMOKE_SYSTEM_PROMPT,
)
from mmaudit.repository.discovery import DiscoveryResult
from mmaudit.repository.ignore import normalize_relative_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_OBJECT_PATTERN = re.compile(r"^[0-9a-f]{40,64}$")
_MAX_GIT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_PROVENANCE_FILE_BYTES = 8 * 1024 * 1024
_MAX_PROVENANCE_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_PROVENANCE_FILES = 20_000
_SYNTHETIC_DECLARATION_RELATIVE_PATH = "src/mmaudit/resources/privacy-synthetic-sources.json"
_PACKAGE_SYNTHETIC_DECLARATION_RELATIVE_PATH = "resources/privacy-synthetic-sources.json"
_TRUSTED_SYNTHETIC_DECLARATION_SHA256 = (
    "7bca2ce44d14f9844f61a8434277f88b443c0992a8df5d811db6794513a9fb6b"
)


def _build_release_pinned_model_benchmark_validator() -> Callable[
    [tuple[str, str, str, str]],
    tuple[str, str, str, str],
]:
    from mmaudit.config import (
        MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
        MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
        MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
        MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
    )

    compiled_pins = (
        MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_VERSION,
        MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256,
        MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_VERSION,
        MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256,
    )

    def require_exact(
        observed: tuple[str, str, str, str],
    ) -> tuple[str, str, str, str]:
        if observed != compiled_pins:
            raise ValueError(
                "model benchmark corpus and ground truth differ from the release-pinned "
                "synthetic prequalification source"
            )
        return compiled_pins

    return require_exact


_TRUSTED_REQUIRE_RELEASE_PINNED_MODEL_BENCHMARK = _build_release_pinned_model_benchmark_validator()
del _build_release_pinned_model_benchmark_validator

PrivacySourceClassificationValue = Literal[
    "PRIVATE_OPERATOR_SOURCE",
    "SYNTHETIC_COMMITTED",
    "PUBLIC_BENCHMARK",
]


class _SyntheticDeclarationFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str = Field(min_length=1, max_length=1_024)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0, le=_MAX_PROVENANCE_FILE_BYTES)

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized != value or normalized in {"", "."}:
            raise ValueError("synthetic declaration file path must be normalized")
        return value


class _SyntheticDeclarationEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scope: str = Field(min_length=1, max_length=1_024)
    purpose: str = Field(min_length=1, max_length=1_000)
    files: tuple[_SyntheticDeclarationFile, ...] = Field(
        min_length=1,
        max_length=_MAX_PROVENANCE_FILES,
    )

    @field_validator("scope")
    @classmethod
    def scope_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if normalized != value or normalized in {"", "."}:
            raise ValueError("synthetic declaration scope must be normalized")
        return value

    @field_validator("purpose")
    @classmethod
    def purpose_is_bounded_printable_text(cls, value: str) -> str:
        if value != value.strip() or any(not character.isprintable() for character in value):
            raise ValueError("synthetic declaration purpose must be canonical printable text")
        return value

    @field_validator("files")
    @classmethod
    def files_are_sorted_and_unique(
        cls,
        value: tuple[_SyntheticDeclarationFile, ...],
    ) -> tuple[_SyntheticDeclarationFile, ...]:
        paths = tuple(item.path for item in value)
        if paths != tuple(sorted(set(paths))):
            raise ValueError("synthetic declaration files must be unique and sorted")
        return value


class _SyntheticSourceDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"]
    entries: tuple[_SyntheticDeclarationEntry, ...] = Field(min_length=1, max_length=1_000)

    @field_validator("entries")
    @classmethod
    def entries_are_sorted_and_unique(
        cls,
        value: tuple[_SyntheticDeclarationEntry, ...],
    ) -> tuple[_SyntheticDeclarationEntry, ...]:
        scopes = tuple(item.scope for item in value)
        if scopes != tuple(sorted(set(scopes))):
            raise ValueError("synthetic declaration entries must be unique and sorted")
        return value


class PrivacySourceProvenanceEvidence(BaseModel):
    """Self-hashed evidence supporting the effective source classification."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source_classification: PrivacySourceClassificationValue
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    proof_kind: Literal[
        "PRIVATE_DEFAULT",
        "DISTRIBUTION_COMMITTED_SYNTHETIC",
        "PACKAGE_PINNED_SYNTHETIC",
        "RELEASE_PINNED_MODEL_BENCHMARK",
        "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
    ]
    distribution_commit: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{40,64}$",
    )
    distribution_scope: str | None = Field(default=None, min_length=1, max_length=1_024)
    committed_file_count: int = Field(ge=0, le=_MAX_PROVENANCE_FILES)
    committed_file_inventory_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    synthetic_declaration_path: str | None = Field(
        default=None,
        min_length=1,
        max_length=1_024,
    )
    synthetic_declaration_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    synthetic_declaration_entry_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    release_pin_set_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    provider_visible_case_count: int = Field(default=0, ge=0, le=10_000)
    provider_visible_case_inventory_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    adjudication_prepared_run_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    adjudication_candidate_report_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    adjudication_ground_truth_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    observed_at: datetime
    limitations: tuple[str, ...] = Field(min_length=1, max_length=8)
    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("source provenance time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def evidence_is_coherent_and_self_hashed(self) -> Self:
        committed_synthetic = self.proof_kind in {
            "DISTRIBUTION_COMMITTED_SYNTHETIC",
            "PACKAGE_PINNED_SYNTHETIC",
        }
        committed_synthetic_values = (
            self.distribution_scope,
            self.committed_file_inventory_sha256,
            self.synthetic_declaration_path,
            self.synthetic_declaration_sha256,
            self.synthetic_declaration_entry_sha256,
        )
        release_pinned_benchmark = self.proof_kind == "RELEASE_PINNED_MODEL_BENCHMARK"
        release_values = (
            self.release_pin_set_sha256,
            self.provider_visible_case_inventory_sha256,
        )
        adjudication_values = (
            self.adjudication_prepared_run_sha256,
            self.adjudication_candidate_report_sha256,
            self.adjudication_ground_truth_sha256,
        )
        release_pinned_adjudication = self.proof_kind == "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
        smoke_pinned_benchmark = self.proof_kind == "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"
        smoke_pinned_adjudication = (
            self.proof_kind == "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"
        )
        if committed_synthetic:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or any(value is None for value in committed_synthetic_values)
                or self.committed_file_count < 1
                or any(value is not None for value in release_values)
                or any(value is not None for value in adjudication_values)
                or self.provider_visible_case_count
            ):
                raise ValueError("synthetic source provenance is incomplete")
            if (
                self.proof_kind == "DISTRIBUTION_COMMITTED_SYNTHETIC"
                and self.distribution_commit is None
            ):
                raise ValueError("committed synthetic provenance requires a commit")
            if (
                self.proof_kind == "PACKAGE_PINNED_SYNTHETIC"
                and self.distribution_commit is not None
            ):
                raise ValueError("package-pinned synthetic provenance cannot claim a commit")
        elif release_pinned_benchmark:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or self.distribution_commit is not None
                or self.distribution_scope != "benchmarks/model_corpus"
                or self.committed_file_count
                or self.committed_file_inventory_sha256 is not None
                or self.synthetic_declaration_path is not None
                or self.synthetic_declaration_sha256 is not None
                or self.synthetic_declaration_entry_sha256 is not None
                or any(value is None for value in release_values)
                or any(value is not None for value in adjudication_values)
                or self.provider_visible_case_count < 1
            ):
                raise ValueError("release-pinned model benchmark provenance is incomplete")
        elif release_pinned_adjudication:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or self.distribution_commit is not None
                or self.distribution_scope != "benchmarks/model_corpus"
                or self.committed_file_count
                or self.committed_file_inventory_sha256 is not None
                or self.synthetic_declaration_path is not None
                or self.synthetic_declaration_sha256 is not None
                or self.synthetic_declaration_entry_sha256 is not None
                or any(value is None for value in release_values)
                or any(value is None for value in adjudication_values)
                or self.provider_visible_case_count < 1
            ):
                raise ValueError("release-pinned cross-lineage provenance is incomplete")
        elif smoke_pinned_benchmark:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or self.distribution_commit is not None
                or self.distribution_scope != "benchmarks/model_corpus_smoke"
                or self.committed_file_count
                or self.committed_file_inventory_sha256 is not None
                or self.synthetic_declaration_path is not None
                or self.synthetic_declaration_sha256 is not None
                or self.synthetic_declaration_entry_sha256 is not None
                or any(value is None for value in release_values)
                or any(value is not None for value in adjudication_values)
                or self.provider_visible_case_count != 1
            ):
                raise ValueError("pinned noncrediting smoke benchmark provenance is incomplete")
        elif smoke_pinned_adjudication:
            if (
                self.source_classification != "SYNTHETIC_COMMITTED"
                or self.distribution_commit is not None
                or self.distribution_scope != "benchmarks/model_corpus_smoke"
                or self.committed_file_count
                or self.committed_file_inventory_sha256 is not None
                or self.synthetic_declaration_path is not None
                or self.synthetic_declaration_sha256 is not None
                or self.synthetic_declaration_entry_sha256 is not None
                or any(value is None for value in release_values)
                or any(value is None for value in adjudication_values)
                or self.provider_visible_case_count != 1
            ):
                raise ValueError("pinned noncrediting smoke cross-lineage provenance is incomplete")
        elif (
            self.source_classification != "PRIVATE_OPERATOR_SOURCE"
            or self.distribution_commit is not None
            or any(value is not None for value in committed_synthetic_values)
            or self.committed_file_count
            or any(value is not None for value in release_values)
            or any(value is not None for value in adjudication_values)
            or self.provider_visible_case_count
        ):
            raise ValueError("private source provenance cannot claim committed benchmark proof")
        if self.limitations != tuple(sorted(set(self.limitations))):
            raise ValueError("source provenance limitations must be unique and sorted")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("source provenance hash is inconsistent")
        return self


class PrivacySourceProvenanceObservation:
    """Opaque live observation issued only by the trusted provenance prover."""

    __slots__ = ("__weakref__",)

    def __new__(cls, *_args: object, **_kwargs: object) -> PrivacySourceProvenanceObservation:
        del cls
        raise TypeError("source provenance observation cannot be constructed directly")

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        del self, _args, _kwargs

    @property
    def evidence(self) -> PrivacySourceProvenanceEvidence:
        """Return the immutable non-secret evidence behind this live observation."""

        return _privacy_source_provenance_observation_evidence(self)

    def __copy__(self) -> PrivacySourceProvenanceObservation:
        raise TypeError("source provenance observations cannot be copied")

    def __deepcopy__(self, memo: dict[int, Any]) -> PrivacySourceProvenanceObservation:
        del memo
        raise TypeError("source provenance observations cannot be copied")

    def __reduce__(self) -> Any:
        raise TypeError("source provenance observations cannot be serialized")

    def __reduce_ex__(self, protocol: SupportsIndex) -> Any:
        del protocol
        raise TypeError("source provenance observations cannot be serialized")


def _build_privacy_source_classification_evidence(
    discovery: DiscoveryResult,
    *,
    requested_classification: str,
    source_sha256: str,
    now: datetime,
    _smoke_user_prompt: Callable[..., str] = _TRUSTED_BUILD_PROVIDER_SMOKE_USER_PROMPT,
    _smoke_request_commitment: Callable[..., str] = (_TRUSTED_PROVIDER_SMOKE_REQUEST_COMMITMENT),
    _smoke_system_prompt: Callable[[], str] = _TRUSTED_PROVIDER_SMOKE_SYSTEM_PROMPT,
    _smoke_response_model: type[BaseModel] = _TRUSTED_PROVIDER_SMOKE_RESPONSE,
    _smoke_role: str = _TRUSTED_PROVIDER_SMOKE_ROLE,
    _smoke_schema_name: str = _TRUSTED_PROVIDER_SMOKE_SCHEMA_NAME,
) -> tuple[PrivacySourceProvenanceEvidence, frozenset[str]]:
    """Prove a safe effective classification for the exact provider-visible scope."""

    classification = _classification_value(requested_classification)
    if type(discovery) is not DiscoveryResult:
        raise ValueError("privacy source discovery must be typed")
    if classification is None:
        raise ValueError("privacy source classification must be typed")
    if re.fullmatch(_SHA256_PATTERN, source_sha256) is None:
        raise ValueError("privacy source inventory hash is invalid")
    observed_at = _whole_second_utc(now)
    expected_source_sha256 = _canonical_sha256(
        [
            {
                "path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
            }
            for item in sorted(discovery.files, key=lambda candidate: candidate.relative_path)
        ]
    )
    if expected_source_sha256 != source_sha256:
        raise ValueError("privacy source provenance binds a different source inventory")

    if classification == "PRIVATE_OPERATOR_SOURCE":
        return (
            _seal(
                {
                    "schema_version": "1.0",
                    "source_classification": classification,
                    "source_sha256": source_sha256,
                    "proof_kind": "PRIVATE_DEFAULT",
                    "distribution_commit": None,
                    "distribution_scope": None,
                    "committed_file_count": 0,
                    "committed_file_inventory_sha256": None,
                    "synthetic_declaration_path": None,
                    "synthetic_declaration_sha256": None,
                    "synthetic_declaration_entry_sha256": None,
                    "release_pin_set_sha256": None,
                    "provider_visible_case_count": 0,
                    "provider_visible_case_inventory_sha256": None,
                    "observed_at": observed_at,
                    "limitations": (
                        "Private is the fail-closed default; no public or synthetic provenance is claimed.",
                    ),
                }
            ),
            frozenset(),
        )
    if classification == "PUBLIC_BENCHMARK":
        raise ValueError(
            "PUBLIC_BENCHMARK requires independent publication provenance, which is unavailable"
        )
    if not discovery.files:
        raise ValueError("synthetic benchmark provenance requires a non-empty source scope")

    distribution_root = _distribution_root()
    target_root = discovery.root.resolve(strict=True)
    package_mode = _is_packaged_distribution(distribution_root)
    allowed_candidates = (
        (distribution_root / "resources" / "synthetic",)
        if package_mode
        else (
            distribution_root / "tests" / "fixtures",
            distribution_root / "benchmarks",
            distribution_root / "src" / "mmaudit" / "resources" / "synthetic",
        )
    )
    allowed_roots = tuple(
        candidate.resolve(strict=True)
        for candidate in allowed_candidates
        if candidate.is_dir() and not candidate.is_symlink()
    )
    if not any(target_root == root or target_root.is_relative_to(root) for root in allowed_roots):
        raise ValueError(
            "SYNTHETIC_COMMITTED requires a distribution-owned fixture or benchmark scope"
        )
    physical_scope = normalize_relative_path(target_root.relative_to(distribution_root))
    scope = f"src/mmaudit/{physical_scope}" if package_mode else physical_scope
    declaration_relative_path = (
        _PACKAGE_SYNTHETIC_DECLARATION_RELATIVE_PATH
        if package_mode
        else _SYNTHETIC_DECLARATION_RELATIVE_PATH
    )
    declaration_bytes = _read_bound_regular_file(
        distribution_root,
        declaration_relative_path,
        max_bytes=262_144,
    )
    declaration_sha256 = hashlib.sha256(declaration_bytes).hexdigest()
    if declaration_sha256 != _TRUSTED_SYNTHETIC_DECLARATION_SHA256:
        raise ValueError("trusted synthetic source declaration differs from its code-pinned hash")

    git: Path | None = None
    commit: str | None = None
    tree: dict[str, str] = {}
    if not package_mode:
        git = _trusted_git_executable()
        observed_top = Path(
            _decode_line(
                _run_git(git, distribution_root, ("rev-parse", "--show-toplevel")),
                label="Git worktree root",
            )
        ).resolve(strict=True)
        if observed_top != distribution_root:
            raise ValueError("synthetic benchmark provenance is not distribution-root bound")
        commit = _decode_line(
            _run_git(git, distribution_root, ("rev-parse", "--verify", "HEAD^{commit}")),
            label="Git commit",
        )
        if _GIT_OBJECT_PATTERN.fullmatch(commit) is None:
            raise ValueError("synthetic benchmark commit identity is malformed")
        if _run_git(
            git,
            distribution_root,
            (
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignore-submodules=all",
                "--",
                scope,
                _SYNTHETIC_DECLARATION_RELATIVE_PATH,
            ),
        ):
            raise ValueError("synthetic benchmark scope or declaration differs from committed HEAD")
        tree = _parse_tree(
            _run_git(
                git,
                distribution_root,
                (
                    "ls-tree",
                    "-r",
                    "-z",
                    "--full-tree",
                    commit,
                    "--",
                    scope,
                    _SYNTHETIC_DECLARATION_RELATIVE_PATH,
                ),
            )
        )
        declaration_object = tree.get(_SYNTHETIC_DECLARATION_RELATIVE_PATH)
        if declaration_object is None:
            raise ValueError("trusted synthetic source declaration is not committed")
        if (
            _read_git_blob(
                git,
                distribution_root,
                declaration_object,
                max_bytes=262_144,
            )
            != declaration_bytes
        ):
            raise ValueError("trusted synthetic source declaration differs from committed HEAD")
    try:
        declaration = _SyntheticSourceDeclaration.model_validate_json(
            declaration_bytes,
            strict=True,
        )
    except Exception:
        raise ValueError("trusted synthetic source declaration is invalid") from None
    declared_entry = next((entry for entry in declaration.entries if entry.scope == scope), None)
    if declared_entry is None:
        raise ValueError("synthetic benchmark scope is not explicitly approved")
    declared_by_path = {item.path: item for item in declared_entry.files}
    discovered_paths = tuple(
        sorted(normalize_relative_path(item.relative_path) for item in discovery.files)
    )
    if discovered_paths != tuple(declared_by_path):
        raise ValueError("provider-visible synthetic source differs from its approved declaration")

    records: list[dict[str, str | int]] = []
    observed_total_bytes = 0
    for item in sorted(discovery.files, key=lambda candidate: candidate.relative_path):
        relative_path = normalize_relative_path(item.relative_path)
        if relative_path != item.relative_path or relative_path in {"", "."}:
            raise ValueError("provider-visible synthetic source path is not canonical")
        expected_absolute_path = target_root / relative_path
        if Path(os.path.abspath(item.absolute_path)) != expected_absolute_path:
            raise ValueError("provider-visible synthetic source path binding is inconsistent")
        data = _read_bound_regular_file(
            target_root,
            relative_path,
            max_bytes=_MAX_PROVENANCE_FILE_BYTES,
        )
        observed_total_bytes += len(data)
        if observed_total_bytes > _MAX_PROVENANCE_TOTAL_BYTES:
            raise ValueError("synthetic benchmark source exceeds its aggregate byte bound")
        current_sha256 = hashlib.sha256(data).hexdigest()
        expected_content = data.decode("utf-8", errors="replace")
        if (
            item.size != len(data)
            or item.sha256 != current_sha256
            or item.content != expected_content
        ):
            raise ValueError("provider-visible synthetic source inventory is inconsistent")
        declared_file = declared_by_path[relative_path]
        if declared_file.size != len(data) or declared_file.sha256 != current_sha256:
            raise ValueError("provider-visible synthetic source violates its approved declaration")
        distribution_path = normalize_relative_path(
            expected_absolute_path.relative_to(distribution_root)
        )
        logical_distribution_path = (
            f"src/mmaudit/{distribution_path}" if package_mode else distribution_path
        )
        if git is None:
            expected_object = f"package-sha256:{current_sha256}"
        else:
            tree_object = tree.get(distribution_path)
            if tree_object is None:
                raise ValueError("provider-visible synthetic source is not committed")
            expected_object = tree_object
            committed_data = _read_git_blob(
                git,
                distribution_root,
                expected_object,
                max_bytes=_MAX_PROVENANCE_FILE_BYTES,
            )
            if committed_data != data:
                raise ValueError("provider-visible synthetic source differs from committed HEAD")
        records.append(
            {
                "path": logical_distribution_path,
                "sha256": current_sha256,
                "size": len(data),
                "git_object": expected_object,
            }
        )
    proof_kind = "PACKAGE_PINNED_SYNTHETIC" if package_mode else "DISTRIBUTION_COMMITTED_SYNTHETIC"
    provider_visible_request_commitment_sha256s: frozenset[str] = frozenset()
    provider_smoke_scopes = {
        "tests/fixtures/solidity/provider_smoke",
        "src/mmaudit/resources/synthetic/provider_smoke",
    }
    if scope in provider_smoke_scopes:
        from mmaudit.models.output_modes import StructuredOutputMode

        if len(discovery.files) != 1 or len(records) != 1:
            raise ValueError("provider smoke provenance requires one exact committed source")
        smoke_file = discovery.files[0]
        smoke_path = records[0]["path"]
        if type(smoke_path) is not str:
            raise ValueError("provider smoke provenance path is invalid")
        user_prompt = _smoke_user_prompt(
            fixture_path=smoke_path,
            fixture_sha256=smoke_file.sha256,
            fixture_source=smoke_file.content,
        )
        provider_visible_request_commitment_sha256s = frozenset(
            {
                _smoke_request_commitment(
                    request_role=_smoke_role,
                    system_prompt=_smoke_system_prompt(),
                    user_prompt=user_prompt,
                    response_model=_smoke_response_model,
                    schema_name=_smoke_schema_name,
                    structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
                    context_package=None,
                )
            }
        )
    limitations = (
        (
            "Package-pinned provenance proves exact reviewed bytes, but no runtime Git commit is available."
        )
        if package_mode
        else "Committed distribution provenance proves fixture custody, not real-world publication."
    )
    return (
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": classification,
                "source_sha256": source_sha256,
                "proof_kind": proof_kind,
                "distribution_commit": commit,
                "distribution_scope": scope,
                "committed_file_count": len(records),
                "committed_file_inventory_sha256": _canonical_sha256(records),
                "synthetic_declaration_path": _SYNTHETIC_DECLARATION_RELATIVE_PATH,
                "synthetic_declaration_sha256": declaration_sha256,
                "synthetic_declaration_entry_sha256": _canonical_sha256(
                    declared_entry.model_dump(mode="json")
                ),
                "release_pin_set_sha256": None,
                "provider_visible_case_count": 0,
                "provider_visible_case_inventory_sha256": None,
                "observed_at": observed_at,
                "limitations": (limitations,),
            }
        ),
        provider_visible_request_commitment_sha256s,
    )


def _build_release_pinned_model_benchmark_evidence(
    benchmark_suite: object,
    *,
    now: datetime,
    _require_exact_pins: Callable[
        [tuple[str, str, str, str]],
        tuple[str, str, str, str],
    ] = _TRUSTED_REQUIRE_RELEASE_PINNED_MODEL_BENCHMARK,
) -> tuple[PrivacySourceProvenanceEvidence, frozenset[str]]:
    """Prove the exact release-pinned semantic corpus used for provider-visible benchmarking."""

    from mmaudit.benchmark.models import (
        MODEL_BENCHMARK_SCHEMA_NAME,
        ModelBenchmarkResponse,
        ModelBenchmarkSuite,
        blinded_model_benchmark_request,
        model_benchmark_provider_request_commitment,
        model_benchmark_system_prompt,
    )
    from mmaudit.models.output_modes import StructuredOutputMode

    if type(benchmark_suite) is not ModelBenchmarkSuite:
        raise ValueError("release-pinned model benchmark source must be a typed suite")
    try:
        canonical_suite = ModelBenchmarkSuite.model_validate_json(
            benchmark_suite.model_dump_json(),
            strict=True,
        )
    except Exception:
        raise ValueError("release-pinned model benchmark source is structurally invalid") from None
    if canonical_suite != benchmark_suite:
        raise ValueError("release-pinned model benchmark source changed during validation")

    observed_pins = (
        canonical_suite.corpus.schema_version,
        canonical_suite.corpus_sha256,
        canonical_suite.ground_truth.schema_version,
        canonical_suite.ground_truth_sha256,
    )
    expected_pins = _require_exact_pins(
        observed_pins,
    )

    provider_visible_cases = []
    provider_visible_case_commitment_sha256s: set[str] = set()
    for case in canonical_suite.cases:
        user_prompt = blinded_model_benchmark_request(case)
        request_bytes = user_prompt.encode("utf-8")
        case_commitment_sha256, _request_commitment_sha256 = (
            model_benchmark_provider_request_commitment(
                request_role="model_benchmark",
                system_prompt=model_benchmark_system_prompt(),
                user_prompt=user_prompt,
                response_model=ModelBenchmarkResponse,
                schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
                structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
                context_package=None,
            )
        )
        provider_visible_case_commitment_sha256s.add(case_commitment_sha256)
        provider_visible_cases.append(
            {
                "case_id": case.case_id,
                "source_path": case.source_path,
                "case_commitment_sha256": case_commitment_sha256,
                "request_size": len(request_bytes),
            }
        )
    if len(provider_visible_case_commitment_sha256s) != len(provider_visible_cases):
        raise ValueError("release-pinned benchmark provider requests are not unique")
    provider_visible_inventory_sha256 = _canonical_sha256(provider_visible_cases)
    release_pin_set_sha256 = _canonical_sha256(
        {
            "schema_version": "1.0",
            "benchmark_corpus_version": expected_pins[0],
            "benchmark_corpus_sha256": expected_pins[1],
            "benchmark_ground_truth_version": expected_pins[2],
            "benchmark_ground_truth_sha256": expected_pins[3],
        }
    )
    observed_at = _whole_second_utc(now)
    return (
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": "SYNTHETIC_COMMITTED",
                "source_sha256": canonical_suite.corpus_sha256,
                "proof_kind": "RELEASE_PINNED_MODEL_BENCHMARK",
                "distribution_commit": None,
                "distribution_scope": "benchmarks/model_corpus",
                "committed_file_count": 0,
                "committed_file_inventory_sha256": None,
                "synthetic_declaration_path": None,
                "synthetic_declaration_sha256": None,
                "synthetic_declaration_entry_sha256": None,
                "release_pin_set_sha256": release_pin_set_sha256,
                "provider_visible_case_count": len(provider_visible_cases),
                "provider_visible_case_inventory_sha256": (provider_visible_inventory_sha256),
                "observed_at": observed_at,
                "limitations": (
                    "Release pins prove this reviewed semantic benchmark suite, not arbitrary custom corpus data.",
                    "The provider-visible inventory binds blinded requests; ground truth remains local.",
                ),
            }
        ),
        frozenset(provider_visible_case_commitment_sha256s),
    )


def _build_release_pinned_cross_lineage_adjudication_evidence(
    prepared_run: object,
    benchmark_suite: object,
    candidate_report: object,
    *,
    now: datetime,
    _release_builder: Callable[..., tuple[PrivacySourceProvenanceEvidence, frozenset[str]]] = (
        _build_release_pinned_model_benchmark_evidence
    ),
) -> tuple[PrivacySourceProvenanceEvidence, frozenset[str]]:
    """Prove one exact prepared judge-request inventory over the release benchmark."""

    from mmaudit.benchmark.cross_lineage_adjudication import (
        CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        CrossLineageAdjudicationPreparedRun,
        CrossLineageAdjudicationWireResponse,
        build_cross_lineage_adjudication_prompt,
        cross_lineage_adjudication_provider_request_commitment,
        cross_lineage_adjudication_source_sha256,
        cross_lineage_adjudication_system_prompt,
    )
    from mmaudit.benchmark.models import ModelBenchmarkReport, ModelBenchmarkSuite

    if type(prepared_run) is not CrossLineageAdjudicationPreparedRun:
        raise ValueError("cross-lineage source requires an exact prepared run")
    if type(benchmark_suite) is not ModelBenchmarkSuite:
        raise ValueError("cross-lineage source requires an exact benchmark suite")
    if type(candidate_report) is not ModelBenchmarkReport:
        raise ValueError("cross-lineage source requires an exact candidate report")
    try:
        prepared = CrossLineageAdjudicationPreparedRun.model_validate(
            prepared_run.model_dump(mode="python"),
            strict=True,
        )
        suite = ModelBenchmarkSuite.model_validate(
            benchmark_suite.model_dump(mode="python"),
            strict=True,
        )
        report = ModelBenchmarkReport.model_validate(
            candidate_report.model_dump(mode="python"),
            strict=True,
        )
    except Exception:
        raise ValueError("cross-lineage source inputs failed detached validation") from None
    if prepared != prepared_run or suite != benchmark_suite or report != candidate_report:
        raise ValueError("cross-lineage source inputs changed during detached validation")
    if (
        prepared.corpus_name != suite.name
        or prepared.corpus_sha256 != suite.corpus_sha256
        or prepared.ground_truth_sha256 != suite.ground_truth_sha256
        or prepared.candidate_report_sha256 != report.report_sha256
    ):
        raise ValueError("cross-lineage prepared run differs from its sealed source inputs")

    release_evidence, _release_commitments = _release_builder(suite, now=now)
    if (
        release_evidence.proof_kind != "RELEASE_PINNED_MODEL_BENCHMARK"
        or release_evidence.release_pin_set_sha256 is None
    ):
        raise ValueError("cross-lineage source lacks release-pinned benchmark custody")
    output_mode = prepared.target.judge_structured_output_mode
    request_commitments: set[str] = set()
    inventory: list[dict[str, object]] = []
    for request in prepared.requests:
        prompt = build_cross_lineage_adjudication_prompt(
            request=request,
            suite=suite,
            candidate_report=report,
        )
        commitment = cross_lineage_adjudication_provider_request_commitment(
            request_role="model_benchmark",
            system_prompt=cross_lineage_adjudication_system_prompt(),
            user_prompt=prompt,
            response_model=CrossLineageAdjudicationWireResponse,
            schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
            structured_output_mode=output_mode,
            context_package=None,
        )
        request_commitments.add(commitment)
        inventory.append(
            {
                "case_id": request.case_id,
                "request_sha256": request.request_sha256,
                "provider_visible_payload_sha256": request.provider_visible_payload_sha256,
                "provider_request_commitment_sha256": commitment,
                "request_size": len(prompt.encode("utf-8")),
            }
        )
    if len(request_commitments) != len(prepared.requests):
        raise ValueError("cross-lineage provider request commitments are not unique")
    observed_at = _whole_second_utc(now)
    return (
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": "SYNTHETIC_COMMITTED",
                "source_sha256": cross_lineage_adjudication_source_sha256(prepared),
                "proof_kind": "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
                "distribution_commit": None,
                "distribution_scope": "benchmarks/model_corpus",
                "committed_file_count": 0,
                "committed_file_inventory_sha256": None,
                "synthetic_declaration_path": None,
                "synthetic_declaration_sha256": None,
                "synthetic_declaration_entry_sha256": None,
                "release_pin_set_sha256": release_evidence.release_pin_set_sha256,
                "provider_visible_case_count": len(inventory),
                "provider_visible_case_inventory_sha256": _canonical_sha256(inventory),
                "adjudication_prepared_run_sha256": prepared.prepared_run_sha256,
                "adjudication_candidate_report_sha256": report.report_sha256,
                "adjudication_ground_truth_sha256": suite.ground_truth_sha256,
                "observed_at": observed_at,
                "limitations": tuple(
                    sorted(
                        {
                            "Adjudication source custody covers only this exact prepared request inventory.",
                            "Release pins prove the synthetic corpus; candidate responses remain separately REAL-evidence bound.",
                        }
                    )
                ),
            }
        ),
        frozenset(request_commitments),
    )


def _validated_authenticated_runner_smoke_bundle(value: object) -> Any:
    """Detach one code-pinned singleton smoke bundle before deriving egress proof."""

    from mmaudit.models.authenticated_runner_smoke_corpus import (
        AUTHENTICATED_RUNNER_SMOKE_CASE_ID,
        AuthenticatedRunnerSmokeCorpusBundle,
    )

    if type(value) is not AuthenticatedRunnerSmokeCorpusBundle:
        raise ValueError("noncrediting smoke source requires the exact pinned bundle type")
    try:
        bundle = AuthenticatedRunnerSmokeCorpusBundle.model_validate_json(
            value.model_dump_json(),
            strict=True,
        )
    except Exception:
        raise ValueError("noncrediting smoke source bundle failed detached validation") from None
    if (
        bundle != value
        or bundle.case.case_id != AUTHENTICATED_RUNNER_SMOKE_CASE_ID
        or bundle.ground_truth_case.case_id != AUTHENTICATED_RUNNER_SMOKE_CASE_ID
        or bundle.case_binding.case_id != AUTHENTICATED_RUNNER_SMOKE_CASE_ID
    ):
        raise ValueError("noncrediting smoke source differs from its exact singleton pin")
    return bundle


def _build_pinned_noncrediting_smoke_model_benchmark_evidence(
    smoke_bundle: object,
    *,
    now: datetime,
    _validate_bundle: Callable[[object], Any] = _validated_authenticated_runner_smoke_bundle,
) -> tuple[PrivacySourceProvenanceEvidence, frozenset[str]]:
    """Prove only the exact singleton candidate prompt pinned by the smoke bundle."""

    from mmaudit.benchmark.models import (
        MODEL_BENCHMARK_SCHEMA_NAME,
        ModelBenchmarkResponse,
        blinded_model_benchmark_request,
        model_benchmark_provider_request_commitment,
        model_benchmark_system_prompt,
    )
    from mmaudit.models.output_modes import StructuredOutputMode

    bundle = _validate_bundle(smoke_bundle)
    case = bundle.case
    user_prompt = blinded_model_benchmark_request(case)
    case_commitment_sha256, _closed_request_commitment_sha256 = (
        model_benchmark_provider_request_commitment(
            request_role="model_benchmark",
            system_prompt=model_benchmark_system_prompt(),
            user_prompt=user_prompt,
            response_model=ModelBenchmarkResponse,
            schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
            structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
            context_package=None,
        )
    )
    case_sha256 = _canonical_sha256(case.model_dump(mode="json"))
    inventory = (
        {
            "case_id": case.case_id,
            "source_path": case.source_path,
            "case_sha256": case_sha256,
            "case_commitment_sha256": case_commitment_sha256,
            "request_size": len(user_prompt.encode("utf-8")),
        },
    )
    observed_at = _whole_second_utc(now)
    return (
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": "SYNTHETIC_COMMITTED",
                "source_sha256": bundle.source_sha256,
                "proof_kind": "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
                "distribution_commit": None,
                "distribution_scope": "benchmarks/model_corpus_smoke",
                "committed_file_count": 0,
                "committed_file_inventory_sha256": None,
                "synthetic_declaration_path": None,
                "synthetic_declaration_sha256": None,
                "synthetic_declaration_entry_sha256": None,
                "release_pin_set_sha256": bundle.bundle_sha256,
                "provider_visible_case_count": 1,
                "provider_visible_case_inventory_sha256": _canonical_sha256(inventory),
                "observed_at": observed_at,
                "limitations": tuple(
                    sorted(
                        {
                            "This proof admits one pinned transport-smoke candidate prompt only.",
                            "Smoke source custody grants no benchmark, qualification, seal, audit, or release credit.",
                        }
                    )
                ),
            }
        ),
        frozenset({case_commitment_sha256}),
    )


def _build_pinned_noncrediting_smoke_cross_lineage_adjudication_evidence(
    smoke_bundle: object,
    candidate_result: object,
    prepared_run: object,
    *,
    now: datetime,
    _validate_bundle: Callable[[object], Any] = _validated_authenticated_runner_smoke_bundle,
) -> tuple[PrivacySourceProvenanceEvidence, frozenset[str]]:
    """Prove one exact smoke judge prompt over the pinned case and candidate result."""

    from mmaudit.benchmark.cross_lineage_adjudication import (
        CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        CrossLineageAdjudicationPreparedRun,
        CrossLineageAdjudicationWireResponse,
        cross_lineage_adjudication_provider_request_commitment,
        cross_lineage_adjudication_source_sha256,
        cross_lineage_adjudication_system_prompt,
    )
    from mmaudit.benchmark.models import ModelBenchmarkCaseResult

    bundle = _validate_bundle(smoke_bundle)
    if type(candidate_result) is not ModelBenchmarkCaseResult:
        raise ValueError("noncrediting smoke adjudication requires one exact candidate result")
    if type(prepared_run) is not CrossLineageAdjudicationPreparedRun:
        raise ValueError("noncrediting smoke adjudication requires one exact prepared run")
    try:
        result = ModelBenchmarkCaseResult.model_validate(
            candidate_result.model_dump(mode="python"),
            strict=True,
        )
        prepared = CrossLineageAdjudicationPreparedRun.model_validate(
            prepared_run.model_dump(mode="python"),
            strict=True,
        )
    except Exception:
        raise ValueError(
            "noncrediting smoke adjudication inputs failed detached validation"
        ) from None
    if result != candidate_result or prepared != prepared_run:
        raise ValueError("noncrediting smoke adjudication inputs changed at the boundary")
    case = bundle.case
    truth = bundle.ground_truth_case
    response = result.normalized_response
    usage = result.usage_record
    generation = result.generation_evidence
    if (
        prepared.case_ids != (case.case_id,)
        or len(prepared.requests) != 1
        or prepared.corpus_sha256 != bundle.manifest.parent.corpus_sha256
        or prepared.ground_truth_sha256 != bundle.manifest.parent.ground_truth_sha256
        or result.case_id != case.case_id
        or result.error_kind is not None
        or response is None
        or usage is None
        or generation is None
    ):
        raise ValueError("noncrediting smoke adjudication is not an exact successful singleton")
    request = prepared.requests[0]
    case_sha256 = _canonical_sha256(case.model_dump(mode="json"))
    truth_sha256 = _canonical_sha256(truth.model_dump(mode="json"))
    result_sha256 = _canonical_sha256(result.model_dump(mode="json"))
    usage_sha256 = _canonical_sha256(usage.model_dump(mode="json"))
    dimension_sha256s = tuple(
        _canonical_sha256(item.model_dump(mode="json")) for item in result.dimensions
    )
    try:
        prompt_envelope = json.loads(request.provider_visible_user_prompt)
        prompt_payload = prompt_envelope["case_payload"]
    except (KeyError, TypeError, ValueError):
        raise ValueError("noncrediting smoke adjudication prompt is malformed") from None
    if (
        request.case_id != case.case_id
        or request.corpus_sha256 != bundle.manifest.parent.corpus_sha256
        or request.ground_truth_sha256 != bundle.manifest.parent.ground_truth_sha256
        or request.corpus_case_sha256 != case_sha256
        or request.ground_truth_case_sha256 != truth_sha256
        or request.candidate_case_result_sha256 != result_sha256
        or request.candidate_validated_response_sha256 != result.validated_response_sha256
        or request.candidate_request_body_sha256 != usage.request_body_sha256
        or request.candidate_usage_record_sha256 != usage_sha256
        or request.candidate_generation_evidence_sha256 != generation.evidence_sha256
        or request.candidate_dimension_result_sha256s != dimension_sha256s
        or prompt_payload.get("case") != case.model_dump(mode="json")
        or prompt_payload.get("ground_truth") != truth.model_dump(mode="json")
        or prompt_payload.get("candidate_response") != response.model_dump(mode="json")
        or prompt_payload.get("dimensions") != [item.dimension.value for item in result.dimensions]
    ):
        raise ValueError(
            "noncrediting smoke adjudication prompt differs from the pinned singleton source"
        )
    output_mode = prepared.target.judge_structured_output_mode
    request_commitment_sha256 = cross_lineage_adjudication_provider_request_commitment(
        request_role="model_benchmark",
        system_prompt=cross_lineage_adjudication_system_prompt(),
        user_prompt=request.provider_visible_user_prompt,
        response_model=CrossLineageAdjudicationWireResponse,
        schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        structured_output_mode=output_mode,
        context_package=None,
    )
    inventory = (
        {
            "case_id": request.case_id,
            "request_sha256": request.request_sha256,
            "provider_visible_payload_sha256": request.provider_visible_payload_sha256,
            "provider_request_commitment_sha256": request_commitment_sha256,
            "request_size": len(request.provider_visible_user_prompt.encode("utf-8")),
        },
    )
    observed_at = _whole_second_utc(now)
    return (
        _seal(
            {
                "schema_version": "1.0",
                "source_classification": "SYNTHETIC_COMMITTED",
                "source_sha256": cross_lineage_adjudication_source_sha256(prepared),
                "proof_kind": ("PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION"),
                "distribution_commit": None,
                "distribution_scope": "benchmarks/model_corpus_smoke",
                "committed_file_count": 0,
                "committed_file_inventory_sha256": None,
                "synthetic_declaration_path": None,
                "synthetic_declaration_sha256": None,
                "synthetic_declaration_entry_sha256": None,
                "release_pin_set_sha256": bundle.bundle_sha256,
                "provider_visible_case_count": 1,
                "provider_visible_case_inventory_sha256": _canonical_sha256(inventory),
                "adjudication_prepared_run_sha256": prepared.prepared_run_sha256,
                "adjudication_candidate_report_sha256": prepared.candidate_report_sha256,
                "adjudication_ground_truth_sha256": prepared.ground_truth_sha256,
                "observed_at": observed_at,
                "limitations": tuple(
                    sorted(
                        {
                            "This proof admits one exact pinned transport-smoke judge prompt only.",
                            "Smoke adjudication grants no benchmark, qualification, seal, audit, or release credit.",
                        }
                    )
                ),
            }
        ),
        frozenset({request_commitment_sha256}),
    )


def _build_privacy_source_provenance_authority(
    source_builder: Callable[..., tuple[PrivacySourceProvenanceEvidence, frozenset[str]]],
    release_builder: Callable[..., tuple[PrivacySourceProvenanceEvidence, frozenset[str]]],
    adjudication_builder: Callable[
        ...,
        tuple[PrivacySourceProvenanceEvidence, frozenset[str]],
    ],
    smoke_benchmark_builder: Callable[
        ...,
        tuple[PrivacySourceProvenanceEvidence, frozenset[str]],
    ],
    smoke_adjudication_builder: Callable[
        ...,
        tuple[PrivacySourceProvenanceEvidence, frozenset[str]],
    ],
    smoke_request_commitment: Callable[..., str],
) -> tuple[
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceObservation],
    Callable[..., PrivacySourceProvenanceEvidence],
    Callable[..., PrivacySourceProvenanceEvidence],
    Callable[[PrivacySourceProvenanceObservation], PrivacySourceProvenanceEvidence],
]:
    """Keep provenance issuance state unreachable behind validated proof operations."""

    @dataclass(frozen=True, slots=True)
    class Binding:
        evidence: PrivacySourceProvenanceEvidence
        evidence_sha256: str
        evidence_content_sha256: str
        provider_visible_case_commitment_sha256s: frozenset[str]

    registry: dict[
        int,
        tuple[weakref.ReferenceType[PrivacySourceProvenanceObservation], Binding],
    ] = {}
    lock = threading.RLock()
    classification_value = _classification_value
    model_content_sha256 = _model_content_sha256

    def state_for(observation: PrivacySourceProvenanceObservation) -> Binding:
        if type(observation) is not PrivacySourceProvenanceObservation:
            raise ValueError("privacy source provenance observation is not trusted")
        with lock:
            registered = registry.get(id(observation))
        if registered is None or registered[0]() is not observation:
            raise ValueError("privacy source provenance observation was not issued in this process")
        return registered[1]

    def issue(
        evidence: PrivacySourceProvenanceEvidence,
        provider_visible_case_commitment_sha256s: frozenset[str],
    ) -> PrivacySourceProvenanceObservation:
        validated = PrivacySourceProvenanceEvidence.model_validate(
            evidence.model_dump(mode="python"),
            strict=True,
        )
        observation = object.__new__(PrivacySourceProvenanceObservation)
        key = id(observation)
        state = Binding(
            evidence=validated,
            evidence_sha256=validated.evidence_sha256,
            evidence_content_sha256=model_content_sha256(validated),
            provider_visible_case_commitment_sha256s=(provider_visible_case_commitment_sha256s),
        )

        def discard(reference: weakref.ReferenceType[PrivacySourceProvenanceObservation]) -> None:
            with lock:
                current = registry.get(key)
                if current is not None and current[0] is reference:
                    registry.pop(key, None)

        reference = weakref.ref(observation, discard)
        with lock:
            registry[key] = (reference, state)
        return observation

    def prove_source(
        discovery: DiscoveryResult,
        *,
        requested_classification: str,
        source_sha256: str,
        now: datetime,
    ) -> PrivacySourceProvenanceObservation:
        evidence, request_sha256s = source_builder(
            discovery,
            requested_classification=requested_classification,
            source_sha256=source_sha256,
            now=now,
        )
        return issue(evidence, request_sha256s)

    def prove_release(
        benchmark_suite: object,
        *,
        now: datetime,
    ) -> PrivacySourceProvenanceObservation:
        evidence, request_sha256s = release_builder(benchmark_suite, now=now)
        return issue(evidence, request_sha256s)

    def prove_adjudication(
        prepared_run: object,
        benchmark_suite: object,
        candidate_report: object,
        *,
        now: datetime,
    ) -> PrivacySourceProvenanceObservation:
        evidence, request_sha256s = adjudication_builder(
            prepared_run,
            benchmark_suite,
            candidate_report,
            now=now,
        )
        return issue(evidence, request_sha256s)

    def prove_smoke_benchmark(
        smoke_bundle: object,
        *,
        now: datetime,
    ) -> PrivacySourceProvenanceObservation:
        evidence, request_sha256s = smoke_benchmark_builder(smoke_bundle, now=now)
        return issue(evidence, request_sha256s)

    def prove_smoke_adjudication(
        smoke_bundle: object,
        candidate_result: object,
        prepared_run: object,
        *,
        now: datetime,
    ) -> PrivacySourceProvenanceObservation:
        evidence, request_sha256s = smoke_adjudication_builder(
            smoke_bundle,
            candidate_result,
            prepared_run,
            now=now,
        )
        return issue(evidence, request_sha256s)

    def reobserve_retained(
        current_observation: PrivacySourceProvenanceObservation,
        retained_evidence: PrivacySourceProvenanceEvidence,
    ) -> PrivacySourceProvenanceObservation:
        """Reissue exact retained evidence only from a matching current live observation."""

        current_binding = state_for(current_observation)
        if type(retained_evidence) is not PrivacySourceProvenanceEvidence:
            raise ValueError("retained source provenance evidence must be exact and typed")
        try:
            current = PrivacySourceProvenanceEvidence.model_validate(
                current_binding.evidence.model_dump(mode="python"),
                strict=True,
            )
            retained = PrivacySourceProvenanceEvidence.model_validate(
                retained_evidence.model_dump(mode="python"),
                strict=True,
            )
        except Exception:
            raise ValueError("retained source provenance evidence is invalid") from None
        if (
            current.evidence_sha256 != current_binding.evidence_sha256
            or model_content_sha256(current) != current_binding.evidence_content_sha256
        ):
            raise ValueError("current source provenance observation binding is inconsistent")
        projection_exclusions = {"observed_at", "evidence_sha256"}
        if (
            retained != retained_evidence
            or retained.observed_at > current.observed_at
            or retained.model_dump(mode="json", exclude=projection_exclusions)
            != current.model_dump(mode="json", exclude=projection_exclusions)
        ):
            raise ValueError("retained source provenance differs from the current live observation")
        return issue(
            retained,
            current_binding.provider_visible_case_commitment_sha256s,
        )

    def validate(
        observation: PrivacySourceProvenanceObservation,
        *,
        source_sha256: str,
        source_classification: str,
    ) -> PrivacySourceProvenanceEvidence:
        classification = classification_value(source_classification)
        if classification is None:
            raise ValueError("privacy source classification must be typed")
        if re.fullmatch(_SHA256_PATTERN, source_sha256) is None:
            raise ValueError("privacy source inventory hash is invalid")
        binding = state_for(observation)
        try:
            validated = PrivacySourceProvenanceEvidence.model_validate(
                binding.evidence.model_dump(mode="python"),
                strict=True,
            )
        except Exception:
            raise ValueError(
                "privacy source provenance observation binding is inconsistent"
            ) from None
        if (
            validated.evidence_sha256 != binding.evidence_sha256
            or model_content_sha256(validated) != binding.evidence_content_sha256
            or validated.source_sha256 != source_sha256
            or validated.source_classification != classification
        ):
            raise ValueError("privacy source provenance observation binding is inconsistent")
        return validated

    def validate_request(
        observation: PrivacySourceProvenanceObservation,
        *,
        request_role: str,
        system_prompt: str,
        user_prompt: str,
        response_model: type[BaseModel],
        schema_name: str,
        structured_output_mode: object,
        context_package: object | None,
    ) -> PrivacySourceProvenanceEvidence:
        from mmaudit.models.output_modes import StructuredOutputMode
        from mmaudit.privacy import PrivacySourceClassification

        binding = state_for(observation)
        evidence = validate(
            observation,
            source_sha256=binding.evidence.source_sha256,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        )
        if type(structured_output_mode) is not StructuredOutputMode:
            raise ValueError("release-pinned benchmark structured-output mode is invalid")
        if evidence.proof_kind == "RELEASE_PINNED_MODEL_BENCHMARK":
            from mmaudit.benchmark.models import model_benchmark_provider_request_commitment

            request_commitment_sha256, _closed_request_commitment_sha256 = (
                model_benchmark_provider_request_commitment(
                    request_role=request_role,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                )
            )
            expected_count = evidence.provider_visible_case_count
        elif evidence.proof_kind == "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION":
            from mmaudit.benchmark.cross_lineage_adjudication import (
                cross_lineage_adjudication_provider_request_commitment,
            )

            request_commitment_sha256 = cross_lineage_adjudication_provider_request_commitment(
                request_role=request_role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
            expected_count = evidence.provider_visible_case_count
        elif evidence.proof_kind == "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK":
            from mmaudit.benchmark.models import model_benchmark_provider_request_commitment

            request_commitment_sha256, _closed_request_commitment_sha256 = (
                model_benchmark_provider_request_commitment(
                    request_role=request_role,
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_model=response_model,
                    schema_name=schema_name,
                    structured_output_mode=structured_output_mode,
                    context_package=context_package,
                )
            )
            expected_count = 1
        elif evidence.proof_kind == "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION":
            from mmaudit.benchmark.cross_lineage_adjudication import (
                cross_lineage_adjudication_provider_request_commitment,
            )

            request_commitment_sha256 = cross_lineage_adjudication_provider_request_commitment(
                request_role=request_role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
            expected_count = 1
        elif evidence.proof_kind in {
            "DISTRIBUTION_COMMITTED_SYNTHETIC",
            "PACKAGE_PINNED_SYNTHETIC",
        }:
            request_commitment_sha256 = smoke_request_commitment(
                request_role=request_role,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_model=response_model,
                schema_name=schema_name,
                structured_output_mode=structured_output_mode,
                context_package=context_package,
            )
            expected_count = 1
        else:
            raise ValueError("source provenance does not authorize a provider request")
        if (
            len(binding.provider_visible_case_commitment_sha256s) != expected_count
            or request_commitment_sha256 not in binding.provider_visible_case_commitment_sha256s
        ):
            if evidence.proof_kind in {
                "RELEASE_PINNED_MODEL_BENCHMARK",
                "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION",
            }:
                raise ValueError(
                    "request is absent from the live release-pinned provider-visible "
                    "benchmark inventory"
                )
            if evidence.proof_kind in {
                "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
                "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            }:
                raise ValueError(
                    "request is absent from the live pinned noncrediting smoke inventory"
                )
            raise ValueError("request is absent from the live provider-visible source inventory")
        return evidence

    def evidence_for(
        observation: PrivacySourceProvenanceObservation,
    ) -> PrivacySourceProvenanceEvidence:
        return state_for(observation).evidence

    return (
        prove_source,
        prove_release,
        prove_adjudication,
        prove_smoke_benchmark,
        prove_smoke_adjudication,
        reobserve_retained,
        validate,
        validate_request,
        evidence_for,
    )


def _classification_value(value: object) -> PrivacySourceClassificationValue | None:
    from mmaudit.privacy import PrivacySourceClassification

    if type(value) is not PrivacySourceClassification:
        return None
    normalized = value.value
    if normalized not in {
        "PRIVATE_OPERATOR_SOURCE",
        "SYNTHETIC_COMMITTED",
        "PUBLIC_BENCHMARK",
    }:
        return None
    return cast(PrivacySourceClassificationValue, normalized)


def _read_bound_regular_file(root: Path, relative_path: str, *, max_bytes: int) -> bytes:
    """Read a regular single-link file beneath root without following links."""

    normalized = normalize_relative_path(relative_path)
    if normalized != relative_path or normalized in {"", "."}:
        raise ValueError("source provenance file path is not canonical")
    parts = Path(normalized).parts
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    opened_directories: list[int] = []
    try:
        descriptor = os.open(root, directory_flags | nofollow)
        opened_directories.append(descriptor)
        for part in parts[:-1]:
            descriptor = os.open(part, directory_flags | nofollow, dir_fd=descriptor)
            opened_directories.append(descriptor)
        file_descriptor = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow,
            dir_fd=descriptor,
        )
    except (OSError, ValueError):
        for opened in reversed(opened_directories):
            os.close(opened)
        raise ValueError("source provenance file could not be opened safely") from None
    try:
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size < 0
            or before.st_size > max_bytes
        ):
            raise ValueError("source provenance file metadata is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(file_descriptor, min(remaining, 65_536))
            if not chunk:
                raise ValueError("source provenance file changed while it was read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(file_descriptor, 1):
            raise ValueError("source provenance file exceeds its declared byte size")
        after = os.fstat(file_descriptor)
        if _stat_identity(before) != _stat_identity(after):
            raise ValueError("source provenance file changed while it was read")
        return b"".join(chunks)
    except OSError:
        raise ValueError("source provenance file could not be read safely") from None
    finally:
        os.close(file_descriptor)
        for opened in reversed(opened_directories):
            os.close(opened)


def _stat_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _distribution_root() -> Path:
    package_path = mmaudit.__file__
    if package_path is None:
        raise ValueError("executing mmaudit distribution is unavailable")
    try:
        package_root = Path(package_path).resolve(strict=True).parent
    except (IndexError, OSError):
        raise ValueError("executing mmaudit distribution is unavailable") from None
    source_root = package_root.parents[1] if len(package_root.parents) >= 2 else None
    source_package = source_root / "src" / "mmaudit" if source_root is not None else None
    root = (
        source_root
        if source_root is not None
        and source_package is not None
        and source_package.is_dir()
        and source_package.resolve(strict=True) == package_root
        and (source_root / ".git").exists()
        else package_root
    )
    if root.is_symlink() or not root.is_dir():
        raise ValueError("executing mmaudit distribution root is unsafe")
    return root


def _is_packaged_distribution(root: Path) -> bool:
    return (root / "resources").is_dir() and not (root / "src" / "mmaudit").is_dir()


def _trusted_git_executable() -> Path:
    for candidate in (Path("/usr/bin/git"), Path("/bin/git")):
        try:
            declared = candidate.lstat()
            resolved = candidate.resolve(strict=True)
            observed = resolved.stat()
        except OSError:
            continue
        if (
            not stat.S_ISLNK(declared.st_mode)
            and stat.S_ISREG(observed.st_mode)
            and observed.st_uid == 0
            and not stat.S_IMODE(observed.st_mode) & 0o022
        ):
            return resolved
    raise ValueError("fixed trusted Git executable is unavailable")


def _run_git(git: Path, root: Path, arguments: tuple[str, ...]) -> bytes:
    try:
        result = subprocess.run(
            [
                str(git),
                "--no-replace-objects",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "protocol.allow=never",
                "-c",
                "submodule.recurse=false",
                "-C",
                str(root),
                *arguments,
            ],
            check=False,
            capture_output=True,
            timeout=30,
            env={
                "PATH": "/usr/bin:/bin",
                "LANG": "C",
                "LC_ALL": "C",
                "TMPDIR": "/tmp",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
            },
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("trusted Git source provenance observation failed") from None
    if (
        result.returncode
        or result.stderr
        or len(result.stdout) > _MAX_GIT_OUTPUT_BYTES
        or len(result.stderr) > _MAX_GIT_OUTPUT_BYTES
    ):
        raise ValueError("trusted Git source provenance observation was rejected")
    return result.stdout


def _read_git_blob(
    git: Path,
    root: Path,
    object_id: str,
    *,
    max_bytes: int,
) -> bytes:
    if _GIT_OBJECT_PATTERN.fullmatch(object_id) is None:
        raise ValueError("trusted Git blob identity is malformed")
    raw_size = _decode_line(
        _run_git(git, root, ("cat-file", "-s", object_id)),
        label="Git blob size",
    )
    try:
        size = int(raw_size)
    except ValueError:
        raise ValueError("trusted Git blob size is malformed") from None
    if size < 0 or size > max_bytes:
        raise ValueError("trusted Git blob exceeds its byte bound")
    content = _run_git(git, root, ("cat-file", "blob", object_id))
    if len(content) != size:
        raise ValueError("trusted Git blob size is inconsistent")
    return content


def _parse_tree(value: bytes) -> dict[str, str]:
    if not value or not value.endswith(b"\0") or b"\0\0" in value:
        raise ValueError("synthetic benchmark Git tree is empty or malformed")
    records = value[:-1].split(b"\0")
    if len(records) > _MAX_PROVENANCE_FILES:
        raise ValueError("synthetic benchmark Git tree exceeds its file bound")
    result: dict[str, str] = {}
    for record in records:
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = header.decode("ascii", errors="strict").split(" ")
            path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            raise ValueError("synthetic benchmark Git tree is malformed") from None
        normalized = normalize_relative_path(path)
        if (
            kind != "blob"
            or mode not in {"100644", "100755"}
            or _GIT_OBJECT_PATTERN.fullmatch(object_id) is None
            or normalized != path
            or path in result
        ):
            raise ValueError("synthetic benchmark Git tree contains an unsafe entry")
        result[path] = object_id
    return result


def _decode_line(value: bytes, *, label: str) -> str:
    try:
        decoded = value.decode("ascii", errors="strict")
    except UnicodeError:
        raise ValueError(f"{label} output is malformed") from None
    if not decoded.endswith("\n") or decoded.count("\n") != 1:
        raise ValueError(f"{label} output is malformed")
    return decoded[:-1]


def _whole_second_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
        raise ValueError("source provenance time must be whole-second UTC")
    return value


def _seal(payload: dict[str, object]) -> PrivacySourceProvenanceEvidence:
    normalized = {
        "adjudication_prepared_run_sha256": None,
        "adjudication_candidate_report_sha256": None,
        "adjudication_ground_truth_sha256": None,
        **payload,
    }
    return PrivacySourceProvenanceEvidence.model_validate(
        {**normalized, "evidence_sha256": _canonical_sha256(normalized)}
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=_json_default,
        ).encode("utf-8")
    ).hexdigest()


def _json_default(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def _model_content_sha256(value: BaseModel) -> str:
    return _canonical_sha256(value.model_dump(mode="json"))


(
    prove_privacy_source_classification,
    prove_release_pinned_model_benchmark_source,
    prove_release_pinned_cross_lineage_adjudication_source,
    prove_pinned_noncrediting_smoke_model_benchmark_source,
    prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source,
    reobserve_retained_privacy_source_provenance,
    validate_privacy_source_provenance_observation,
    validate_provider_visible_source_request,
    _privacy_source_provenance_observation_evidence,
) = _build_privacy_source_provenance_authority(
    _build_privacy_source_classification_evidence,
    _build_release_pinned_model_benchmark_evidence,
    _build_release_pinned_cross_lineage_adjudication_evidence,
    _build_pinned_noncrediting_smoke_model_benchmark_evidence,
    _build_pinned_noncrediting_smoke_cross_lineage_adjudication_evidence,
    _TRUSTED_PROVIDER_SMOKE_REQUEST_COMMITMENT,
)
del _build_privacy_source_provenance_authority
del _build_privacy_source_classification_evidence
del _build_release_pinned_model_benchmark_evidence
del _build_release_pinned_cross_lineage_adjudication_evidence
del _build_pinned_noncrediting_smoke_model_benchmark_evidence
del _build_pinned_noncrediting_smoke_cross_lineage_adjudication_evidence
del _validated_authenticated_runner_smoke_bundle
del _TRUSTED_REQUIRE_RELEASE_PINNED_MODEL_BENCHMARK
del _TRUSTED_BUILD_PROVIDER_SMOKE_USER_PROMPT
del _TRUSTED_PROVIDER_SMOKE_REQUEST_COMMITMENT
del _TRUSTED_PROVIDER_SMOKE_RESPONSE
del _TRUSTED_PROVIDER_SMOKE_ROLE
del _TRUSTED_PROVIDER_SMOKE_SCHEMA_NAME
del _TRUSTED_PROVIDER_SMOKE_SYSTEM_PROMPT

# Compatibility name for callers whose request is specifically the release benchmark.
validate_release_pinned_model_benchmark_request = validate_provider_visible_source_request
