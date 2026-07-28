"""Deterministic, provider-free validation of committed release inputs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.adversarial_acceptance import load_adversarial_acceptance_manifest
from mmaudit.benchmark.engine import load_manifest, validate_benchmark_ground_truth
from mmaudit.benchmark.models import load_model_benchmark_corpus
from mmaudit.economic_acceptance import load_economic_acceptance_manifest
from mmaudit.full_protocol_acceptance import load_full_protocol_acceptance_manifest
from mmaudit.models.schemas import StrictModel
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_candidate import (
    ReleaseCandidateObservation,
    observe_release_candidate,
)
from mmaudit.snapshots.compare import (
    SnapshotComparisonStatus,
    compare_deployment_snapshot,
    load_compiler_contract_artifacts,
)
from mmaudit.snapshots.schema import load_deployment_snapshot

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_STATIC_FILE_BYTES = 100_000_000
_MAX_SCHEMAS = 1_000


class StaticReleaseEvidencePayload(StrictModel):
    """Hash-linked result of validating immutable local release inputs."""

    schema_version: Literal["1.0"]
    generated_by: Literal["mmaudit"]
    candidate_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    candidate_observation_sha256: str = Field(pattern=_SHA256_PATTERN)
    observed_at: datetime
    schemas: list[ManifestFileBinding] = Field(min_length=1, max_length=_MAX_SCHEMAS)
    schema_inventory_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_source_bindings: int = Field(ge=1)
    benchmark_evidence_sha256: str = Field(pattern=_SHA256_PATTERN)
    model_cases: int = Field(ge=1)
    model_corpus_sha256: str = Field(pattern=_SHA256_PATTERN)
    economic_cases: int = Field(ge=1)
    economic_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    adversarial_cases: int = Field(ge=1)
    adversarial_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    full_protocol_files: int = Field(ge=1)
    full_protocol_manifest_sha256: str = Field(pattern=_SHA256_PATTERN)
    snapshot_comparison_sha256: str = Field(pattern=_SHA256_PATTERN)
    foundry_ast_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def observed_at_is_whole_second_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0) or value.microsecond:
            raise ValueError("static release evidence time must be whole-second UTC")
        return value

    @model_validator(mode="after")
    def inventory_is_consistent(self) -> StaticReleaseEvidencePayload:
        paths = [item.path for item in self.schemas]
        if paths != sorted(set(paths)):
            raise ValueError("release schema inventory must be unique and sorted")
        expected = canonical_sha256([item.model_dump(mode="json") for item in self.schemas])
        if self.schema_inventory_sha256 != expected:
            raise ValueError("release schema inventory hash is inconsistent")
        return self


class StaticReleaseEvidence(StaticReleaseEvidencePayload):
    """Self-hashed static release validation evidence."""

    evidence_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def evidence_hash_is_consistent(self) -> StaticReleaseEvidence:
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"evidence_sha256"}))
        if self.evidence_sha256 != expected:
            raise ValueError("static release evidence hash is inconsistent")
        return self


def collect_static_release_evidence(
    repository_root: Path,
    *,
    candidate: ReleaseCandidateObservation,
) -> StaticReleaseEvidence:
    """Validate and hash the local schemas and synthetic acceptance inputs."""

    root = _require_directory(repository_root)
    supplied_candidate = ReleaseCandidateObservation.model_validate(
        candidate.model_dump(mode="json")
    )
    observed_candidate_before = observe_release_candidate(root)
    if _candidate_identity(observed_candidate_before) != _candidate_identity(supplied_candidate):
        raise ValueError("static release inputs are not bound to the supplied candidate")
    schema_root = root / "schemas"
    schema_paths = sorted(schema_root.glob("*.json"))
    if not schema_paths or len(schema_paths) > _MAX_SCHEMAS:
        raise ValueError("release validation found no bounded published schema inventory")
    schema_bindings: list[ManifestFileBinding] = []
    for path in schema_paths:
        data = _read_unique_file(path, label=f"release schema {path.name}")
        schema = _decode_json_object(data, label=f"release schema {path.name}")
        if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            raise ValueError(f"release schema does not declare draft 2020-12: {path.name}")
        if schema.get("additionalProperties") is not False:
            raise ValueError(f"release schema root is not strict: {path.name}")
        schema_bindings.append(
            ManifestFileBinding(
                path=f"schemas/{path.name}",
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
            )
        )

    benchmark = load_manifest(root / "benchmarks" / "corpus" / "manifest.json")
    ground_truth = validate_benchmark_ground_truth(benchmark, workspace_root=root)
    model_corpus = load_model_benchmark_corpus(
        root / "benchmarks" / "model_corpus" / "manifest.json"
    )
    economic = load_economic_acceptance_manifest(
        root / "tests" / "fixtures" / "solidity" / "maximum_assurance_economic" / "manifest.json",
        repository_root=root,
    )
    adversarial = load_adversarial_acceptance_manifest(
        root / "tests" / "fixtures" / "adversarial_repository" / "cases.json"
    )
    full_root = root / "tests" / "fixtures" / "full_protocol_offline"
    full_protocol = load_full_protocol_acceptance_manifest(full_root / "manifest.json")

    snapshot = load_deployment_snapshot(full_root / full_protocol.expectations.snapshot_path)
    compiler_artifacts = load_compiler_contract_artifacts(
        full_root,
        [Path(full_protocol.expectations.compiler_artifact_path)],
    )
    comparison = compare_deployment_snapshot(snapshot, compiler_artifacts)
    if comparison.status is not SnapshotComparisonStatus.MATCHED:
        raise ValueError("release full-protocol compiler artifact does not match the snapshot")

    foundry_ast = (
        root / "tests" / "fixtures" / "solidity" / "foundry" / "out" / "Vault.sol" / "Vault.json"
    )
    foundry_bytes = _read_unique_file(foundry_ast, label="release compiler AST fixture")
    foundry_payload = _decode_json_object(
        foundry_bytes,
        label="release compiler AST fixture",
    )
    if not isinstance(foundry_payload.get("ast"), dict):
        raise ValueError("release compiler AST fixture has no normalized AST")

    observed_candidate_after = observe_release_candidate(root)
    if _candidate_identity(observed_candidate_after) != _candidate_identity(
        observed_candidate_before
    ):
        raise ValueError("release candidate changed during static evidence collection")

    payload = StaticReleaseEvidencePayload(
        schema_version="1.0",
        generated_by="mmaudit",
        candidate_commit=supplied_candidate.candidate_commit,
        candidate_observation_sha256=supplied_candidate.observation_sha256,
        observed_at=datetime.now(UTC).replace(microsecond=0),
        schemas=schema_bindings,
        schema_inventory_sha256=canonical_sha256(
            [item.model_dump(mode="json") for item in schema_bindings]
        ),
        benchmark_source_bindings=len(ground_truth),
        benchmark_evidence_sha256=canonical_sha256(
            {
                "manifest": benchmark.model_dump(mode="json"),
                "ground_truth": [
                    item.model_dump(mode="json")
                    for item in sorted(
                        ground_truth,
                        key=lambda item: item.path,
                    )
                ],
            }
        ),
        model_cases=len(model_corpus.cases),
        model_corpus_sha256=canonical_sha256(model_corpus.model_dump(mode="json")),
        economic_cases=len(economic.cases),
        economic_manifest_sha256=canonical_sha256(economic.model_dump(mode="json")),
        adversarial_cases=len(adversarial.cases),
        adversarial_manifest_sha256=canonical_sha256(adversarial.model_dump(mode="json")),
        full_protocol_files=len(full_protocol.fixture_files),
        full_protocol_manifest_sha256=full_protocol.manifest_sha256,
        snapshot_comparison_sha256=canonical_sha256(comparison.model_dump(mode="json")),
        foundry_ast_sha256=hashlib.sha256(foundry_bytes).hexdigest(),
    )
    serialized = payload.model_dump(mode="json")
    return StaticReleaseEvidence.model_validate(
        {
            **serialized,
            "evidence_sha256": canonical_sha256(serialized),
        }
    )


def _candidate_identity(candidate: ReleaseCandidateObservation) -> str:
    return canonical_sha256(
        candidate.model_dump(
            mode="json",
            exclude={"observed_at", "observation_sha256"},
        )
    )


def _require_directory(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current /= part
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or current.is_junction():
                raise ValueError("release repository path may not traverse a link")
        metadata = absolute.lstat()
    except OSError as exc:
        raise ValueError("release repository root is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("release repository root must be a directory")
    return absolute.resolve(strict=True)


def _read_unique_file(path: Path, *, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} is missing") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > _MAX_STATIC_FILE_BYTES
    ):
        raise ValueError(f"{label} must be a bounded unshared regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} could not be opened safely") from exc
    try:
        data = bytearray()
        opened = os.fstat(descriptor)
        while len(data) <= _MAX_STATIC_FILE_BYTES:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, _MAX_STATIC_FILE_BYTES + 1 - len(data)),
            )
            if not chunk:
                break
            data.extend(chunk)
        finished = os.fstat(descriptor)
    except OSError as exc:
        raise ValueError(f"{label} could not be read safely") from exc
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} changed while being read") from exc
    identities = {
        _stat_identity(before),
        _stat_identity(opened),
        _stat_identity(finished),
        _stat_identity(after),
    }
    if len(data) > _MAX_STATIC_FILE_BYTES or len(identities) != 1:
        raise ValueError(f"{label} changed or exceeded its bound while being read")
    return bytes(data)


def _stat_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _decode_json_object(data: bytes, *, label: str) -> dict[str, Any]:
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    def reject_nonfinite(value: str) -> None:
        raise ValueError(f"{label} contains non-finite value: {value}")

    def finite_float(value: str) -> float:
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError(f"{label} contains an out-of-range number")
        return parsed

    try:
        value = json.loads(
            data,
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
            parse_float=finite_float,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain one JSON object")
    return value
