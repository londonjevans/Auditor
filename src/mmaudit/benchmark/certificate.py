"""Deterministic component bindings for benchmark certificates."""

from __future__ import annotations

import hashlib
import re
import stat
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.benchmark.engine import (
    BenchmarkManifest,
    BenchmarkReport,
    require_benchmark_report_matches_manifest,
    require_certifiable_benchmark_report,
)
from mmaudit.models.schemas import AuditProfile, StrictModel
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name, is_sensitive_workspace_path

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_GIT_COMMIT_PATTERN = r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$"
_MAX_CERTIFICATE_BYTES = 20_000_000
_MAX_CERTIFICATE_INPUT_BYTES = 2_000_000
_MAX_COMPONENT_FILE_BYTES = 100_000_000
_MAX_BINDINGS_PER_CATEGORY = 100_000


class CertificateComponentSource(StrEnum):
    """Whether a binding hashes a local file or a typed in-memory projection."""

    FILE = "file"
    PROJECTION = "projection"


class CertificateComponentBinding(StrictModel):
    """One named, hash-bound benchmark input or result component."""

    identifier: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@#-]*$",
    )
    source: CertificateComponentSource
    sha256: str = Field(pattern=_SHA256_PATTERN)
    path: str | None = Field(default=None, min_length=1, max_length=4_096)
    size: int | None = Field(default=None, ge=0, le=_MAX_COMPONENT_FILE_BYTES)
    details: dict[str, str] = Field(default_factory=dict, max_length=50)

    @field_validator("path")
    @classmethod
    def path_is_normalized_and_non_sensitive(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _normalized_component_path(value)

    @field_validator("details")
    @classmethod
    def details_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        for key, detail in value.items():
            if (
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", key) is None
                or len(detail) > 2_000
                or any(ord(character) < 32 or ord(character) == 127 for character in detail)
            ):
                raise ValueError("certificate component details are not bounded")
        return value

    @model_validator(mode="after")
    def source_metadata_is_consistent(self) -> CertificateComponentBinding:
        has_file_metadata = self.path is not None and self.size is not None
        if self.source is CertificateComponentSource.FILE and not has_file_metadata:
            raise ValueError("file bindings require a normalized path and size")
        if self.source is CertificateComponentSource.PROJECTION and (
            self.path is not None or self.size is not None
        ):
            raise ValueError("projection bindings may not claim file metadata")
        return self


class BenchmarkCertificateBindingSet(StrictModel):
    """Every component category required by the BENCH-001 contract."""

    configuration: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    prompts: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    models: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    tools: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    compilers: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    corpus: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    ground_truth: list[CertificateComponentBinding] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )

    @model_validator(mode="after")
    def categories_are_sorted_and_unique(self) -> BenchmarkCertificateBindingSet:
        for category, bindings in _binding_categories(self):
            identifiers = [binding.identifier for binding in bindings]
            if identifiers != sorted(set(identifiers)):
                raise ValueError(f"certificate {category} bindings must be unique and sorted")
        return self


class BenchmarkCertificateFileInputs(StrictModel):
    """Complete local file list used by the certification CLI."""

    configuration: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    prompts: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    models: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    tools: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    compilers: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    corpus: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    ground_truth: list[str] = Field(
        min_length=1,
        max_length=_MAX_BINDINGS_PER_CATEGORY,
    )
    benchmark_report: str

    @field_validator(
        "configuration",
        "prompts",
        "models",
        "tools",
        "compilers",
        "corpus",
        "ground_truth",
    )
    @classmethod
    def paths_are_normalized_sorted_and_unique(cls, value: list[str]) -> list[str]:
        normalized = [_normalized_component_path(path) for path in value]
        if normalized != sorted(set(normalized)):
            raise ValueError("certificate input paths must be unique and sorted")
        return normalized

    @field_validator("benchmark_report")
    @classmethod
    def report_path_is_normalized(cls, value: str) -> str:
        return _normalized_component_path(value)


class BenchmarkCertificatePayload(StrictModel):
    """Validated certificate contents before deterministic sealing."""

    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    certificate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    benchmark_name: str = Field(min_length=1, max_length=500)
    profile: AuditProfile
    repository_git_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    bindings: BenchmarkCertificateBindingSet
    benchmark_report: CertificateComponentBinding


class BenchmarkCertificate(BenchmarkCertificatePayload):
    """Canonical self-hashed certificate over every benchmark component."""

    bindings_sha256: str = Field(pattern=_SHA256_PATTERN)
    certificate_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def hashes_match_contents(self) -> BenchmarkCertificate:
        expected_bindings = _bound_components_sha256(
            self.repository_git_commit,
            self.bindings,
            self.benchmark_report,
        )
        if self.bindings_sha256 != expected_bindings:
            raise ValueError("benchmark certificate component hash is inconsistent")
        expected_certificate = canonical_sha256(
            self.model_dump(mode="json", exclude={"certificate_sha256"})
        )
        if self.certificate_sha256 != expected_certificate:
            raise ValueError("benchmark certificate self-hash is inconsistent")
        return self


class CertificateVerificationStatus(StrEnum):
    """Whether every observed component still matches the sealed certificate."""

    CURRENT = "current"
    STALE = "stale"


class CertificateVerificationOrigin(StrEnum):
    """Trusted boundary that produced one verification record."""

    IN_MEMORY = "in_memory"
    FILE_BACKED = "file_backed"


class CertificateMismatchKind(StrEnum):
    """A deterministic reason that a certificate binding is stale."""

    GIT_COMMIT = "git_commit"
    MISSING = "missing"
    UNEXPECTED = "unexpected"
    CHANGED = "changed"


class CertificateBindingMismatch(StrictModel):
    """Sanitized evidence for one changed component binding."""

    category: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    identifier: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@#-]*$",
    )
    kind: CertificateMismatchKind
    expected_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )
    observed_binding_sha256: str | None = Field(
        default=None,
        pattern=_SHA256_PATTERN,
    )

    @model_validator(mode="after")
    def digests_match_mismatch_kind(self) -> CertificateBindingMismatch:
        if self.kind is CertificateMismatchKind.MISSING and (
            self.expected_binding_sha256 is None or self.observed_binding_sha256 is not None
        ):
            raise ValueError("missing certificate components require only an expected hash")
        if self.kind is CertificateMismatchKind.UNEXPECTED and (
            self.expected_binding_sha256 is not None or self.observed_binding_sha256 is None
        ):
            raise ValueError("unexpected certificate components require only an observed hash")
        if self.kind in {
            CertificateMismatchKind.CHANGED,
            CertificateMismatchKind.GIT_COMMIT,
        } and (self.expected_binding_sha256 is None or self.observed_binding_sha256 is None):
            raise ValueError("changed certificate components require both hashes")
        return self


class FileBackedBenchmarkVerificationEvidence(StrictModel):
    """Bounded proof that a certificate and complete non-empty passed report were loaded."""

    certificate_loaded: Literal[True]
    certificate_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_report_loaded: Literal[True]
    benchmark_report_file_sha256: str = Field(pattern=_SHA256_PATTERN)
    benchmark_name: str = Field(min_length=1, max_length=500)
    benchmark_profile: AuditProfile
    benchmark_report_status: Literal["passed"]
    benchmark_report_gate_count: int = Field(ge=1, le=_MAX_BINDINGS_PER_CATEGORY)
    benchmark_reports_expected: int = Field(ge=1, le=_MAX_BINDINGS_PER_CATEGORY)
    benchmark_reports_loaded: int = Field(ge=1, le=_MAX_BINDINGS_PER_CATEGORY)

    @model_validator(mode="after")
    def all_expected_reports_were_loaded(self) -> FileBackedBenchmarkVerificationEvidence:
        if self.benchmark_reports_loaded != self.benchmark_reports_expected:
            raise ValueError("file-backed benchmark evidence requires every expected report")
        return self


class BenchmarkCertificateVerification(StrictModel):
    """Self-hashed, deterministic current-versus-sealed comparison evidence."""

    schema_version: Literal["1.0"] = "1.0"
    certificate_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: CertificateVerificationStatus
    observed_repository_git_commit: str = Field(pattern=_GIT_COMMIT_PATTERN)
    observed_bindings_sha256: str = Field(pattern=_SHA256_PATTERN)
    mismatches: list[CertificateBindingMismatch] = Field(
        max_length=3 + (14 * _MAX_BINDINGS_PER_CATEGORY)
    )
    origin: CertificateVerificationOrigin = CertificateVerificationOrigin.IN_MEMORY
    file_backed_evidence: FileBackedBenchmarkVerificationEvidence | None = None
    verification_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def status_order_and_hash_are_consistent(self) -> BenchmarkCertificateVerification:
        if (self.origin is CertificateVerificationOrigin.FILE_BACKED) != (
            self.file_backed_evidence is not None
        ):
            raise ValueError(
                "file-backed certificate verification requires exact loaded-file evidence"
            )
        mismatch_keys = [
            (item.category, item.identifier, item.kind.value) for item in self.mismatches
        ]
        if mismatch_keys != sorted(set(mismatch_keys)):
            raise ValueError("certificate mismatches must be unique and sorted")
        expected_status = (
            CertificateVerificationStatus.STALE
            if self.mismatches
            else CertificateVerificationStatus.CURRENT
        )
        if self.status is not expected_status:
            raise ValueError("certificate verification status is inconsistent")
        expected_hash = canonical_sha256(
            self.model_dump(mode="json", exclude={"verification_sha256"})
        )
        if self.verification_sha256 == expected_hash:
            return self
        provenance_fields = {"origin", "file_backed_evidence"}
        legacy_compatible = (
            self.origin is CertificateVerificationOrigin.IN_MEMORY
            and self.file_backed_evidence is None
        )
        legacy_hash = canonical_sha256(
            self.model_dump(
                mode="json",
                exclude={"verification_sha256", *provenance_fields},
            )
        )
        if not legacy_compatible or self.verification_sha256 != legacy_hash:
            raise ValueError("certificate verification self-hash is inconsistent")
        return self


def bind_certificate_file(
    root: Path,
    relative_path: str | Path,
    *,
    identifier: str,
    details: dict[str, str] | None = None,
) -> CertificateComponentBinding:
    """Hash one unique regular file beneath a non-link caller-selected root."""

    if not root.is_dir() or root.is_symlink() or root.is_junction():
        raise ValueError("certificate component root must be a regular non-link directory")
    resolved_root = root.resolve(strict=True)
    normalized = CertificateComponentBinding(
        identifier=identifier,
        source=CertificateComponentSource.FILE,
        sha256="0" * 64,
        path=str(relative_path),
        size=0,
        details=details or {},
    ).path
    if normalized is None:
        raise ValueError("certificate file binding requires a path")
    candidate = resolved_root.joinpath(*PurePosixPath(normalized).parts)
    current = resolved_root
    for part in PurePosixPath(normalized).parts:
        current /= part
        if current.is_symlink() or current.is_junction():
            raise ValueError("certificate component paths may not contain links")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(resolved_root)
        metadata = resolved.lstat()
    except (OSError, ValueError) as exc:
        raise ValueError("certificate component must remain inside its root") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > _MAX_COMPONENT_FILE_BYTES
    ):
        raise ValueError("certificate components must be bounded unique regular files")
    return CertificateComponentBinding(
        identifier=identifier,
        source=CertificateComponentSource.FILE,
        sha256=_file_sha256(resolved),
        path=normalized,
        size=metadata.st_size,
        details=details or {},
    )


def bind_certificate_projection(
    identifier: str,
    value: Any,
    *,
    details: dict[str, str] | None = None,
) -> CertificateComponentBinding:
    """Hash one JSON-compatible typed projection without retaining its contents."""

    return CertificateComponentBinding(
        identifier=identifier,
        source=CertificateComponentSource.PROJECTION,
        sha256=canonical_sha256(value),
        path=None,
        size=None,
        details=details or {},
    )


def load_benchmark_certificate_file_inputs(
    path: Path,
) -> BenchmarkCertificateFileInputs:
    """Load a bounded local component-path manifest without following links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive certificate input filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("certificate inputs must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_CERTIFICATE_INPUT_BYTES:
        raise ValueError("certificate inputs must be a bounded unshared file")
    return BenchmarkCertificateFileInputs.model_validate_json(path.read_text(encoding="utf-8"))


def build_file_backed_benchmark_certificate(
    *,
    component_root: Path,
    inputs: BenchmarkCertificateFileInputs,
    repository_git_commit: str,
    certificate_id: str,
) -> BenchmarkCertificate:
    """Certify one passed report and a complete set of observed local files."""

    benchmark_report = _load_passed_benchmark_report(
        component_root,
        inputs.benchmark_report,
    )
    _load_matching_corpus_manifest(
        component_root,
        inputs.corpus,
        benchmark_report,
    )
    bindings = BenchmarkCertificateBindingSet(
        configuration=_bind_file_category(
            component_root,
            inputs.configuration,
            "configuration",
        ),
        prompts=_bind_file_category(component_root, inputs.prompts, "prompts"),
        models=_bind_file_category(component_root, inputs.models, "models"),
        tools=_bind_file_category(component_root, inputs.tools, "tools"),
        compilers=_bind_file_category(component_root, inputs.compilers, "compilers"),
        corpus=_bind_file_category(component_root, inputs.corpus, "corpus"),
        ground_truth=_bind_file_category(
            component_root,
            inputs.ground_truth,
            "ground_truth",
        ),
    )
    report_binding = bind_certificate_file(
        component_root,
        inputs.benchmark_report,
        identifier="benchmark-report",
        details={
            "corpus": benchmark_report.corpus_name[:2_000],
            "profile": benchmark_report.profile.value,
            "status": benchmark_report.status.value,
        },
    )
    return seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id=certificate_id,
            benchmark_name=benchmark_report.corpus_name,
            profile=benchmark_report.profile,
            repository_git_commit=repository_git_commit,
            bindings=bindings,
            benchmark_report=report_binding,
        )
    )


def observe_file_backed_certificate(
    certificate: BenchmarkCertificate,
    *,
    component_root: Path,
) -> tuple[BenchmarkCertificateBindingSet, CertificateComponentBinding]:
    """Re-hash every file path recorded by a CLI-issued certificate."""

    observed: dict[str, list[CertificateComponentBinding]] = {}
    for category, expected_bindings in _binding_categories(certificate.bindings):
        observed[category] = [
            _rebind_expected_file(component_root, binding) for binding in expected_bindings
        ]
    report = _rebind_expected_file(component_root, certificate.benchmark_report)
    return (
        BenchmarkCertificateBindingSet(
            configuration=observed["configuration"],
            prompts=observed["prompts"],
            models=observed["models"],
            tools=observed["tools"],
            compilers=observed["compilers"],
            corpus=observed["corpus"],
            ground_truth=observed["ground_truth"],
        ),
        report,
    )


def seal_benchmark_certificate(
    payload: BenchmarkCertificatePayload,
) -> BenchmarkCertificate:
    """Attach component and certificate hashes to validated contents."""

    serialized = payload.model_dump(mode="json")
    serialized["bindings_sha256"] = _bound_components_sha256(
        payload.repository_git_commit,
        payload.bindings,
        payload.benchmark_report,
    )
    serialized["certificate_sha256"] = canonical_sha256(serialized)
    return BenchmarkCertificate.model_validate(serialized)


def verify_benchmark_certificate(
    certificate: BenchmarkCertificate,
    *,
    repository_git_commit: str,
    bindings: BenchmarkCertificateBindingSet,
    benchmark_report: CertificateComponentBinding,
) -> BenchmarkCertificateVerification:
    """Compare every sealed component with a complete observed binding set."""

    if re.fullmatch(_GIT_COMMIT_PATTERN, repository_git_commit) is None:
        raise ValueError("observed benchmark commit is not a full lowercase Git hash")
    mismatches: list[CertificateBindingMismatch] = []
    if repository_git_commit != certificate.repository_git_commit:
        mismatches.append(
            CertificateBindingMismatch(
                category="repository",
                identifier="git-commit",
                kind=CertificateMismatchKind.GIT_COMMIT,
                expected_binding_sha256=canonical_sha256(certificate.repository_git_commit),
                observed_binding_sha256=canonical_sha256(repository_git_commit),
            )
        )
    expected_categories = {
        **dict(_binding_categories(certificate.bindings)),
        "benchmark_report": [certificate.benchmark_report],
    }
    observed_categories = {
        **dict(_binding_categories(bindings)),
        "benchmark_report": [benchmark_report],
    }
    for category in sorted(expected_categories):
        expected = {item.identifier: item for item in expected_categories[category]}
        observed = {item.identifier: item for item in observed_categories[category]}
        for identifier in sorted(set(expected) | set(observed)):
            expected_item = expected.get(identifier)
            observed_item = observed.get(identifier)
            if expected_item is None and observed_item is not None:
                mismatches.append(
                    _binding_mismatch(
                        category,
                        identifier,
                        CertificateMismatchKind.UNEXPECTED,
                        None,
                        observed_item,
                    )
                )
            elif expected_item is not None and observed_item is None:
                mismatches.append(
                    _binding_mismatch(
                        category,
                        identifier,
                        CertificateMismatchKind.MISSING,
                        expected_item,
                        None,
                    )
                )
            elif (
                expected_item is not None
                and observed_item is not None
                and expected_item != observed_item
            ):
                mismatches.append(
                    _binding_mismatch(
                        category,
                        identifier,
                        CertificateMismatchKind.CHANGED,
                        expected_item,
                        observed_item,
                    )
                )
    mismatches.sort(key=lambda item: (item.category, item.identifier, item.kind.value))
    observed_bindings_sha256 = _bound_components_sha256(
        repository_git_commit,
        bindings,
        benchmark_report,
    )
    verification_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "certificate_sha256": certificate.certificate_sha256,
        "status": (
            CertificateVerificationStatus.STALE
            if mismatches
            else CertificateVerificationStatus.CURRENT
        ),
        "observed_repository_git_commit": repository_git_commit,
        "observed_bindings_sha256": observed_bindings_sha256,
        "mismatches": [item.model_dump(mode="json") for item in mismatches],
        "origin": CertificateVerificationOrigin.IN_MEMORY,
        "file_backed_evidence": None,
    }
    verification_payload["verification_sha256"] = canonical_sha256(verification_payload)
    return BenchmarkCertificateVerification.model_validate(verification_payload)


def verify_file_backed_benchmark_certificate(
    certificate_path: Path,
    *,
    component_root: Path,
    repository_git_commit: str,
) -> BenchmarkCertificateVerification:
    """Load, re-observe, and validate one CLI-issued certificate without execution."""

    certificate, certificate_file_sha256 = _load_benchmark_certificate_with_hash(certificate_path)
    observed_bindings, observed_report = observe_file_backed_certificate(
        certificate,
        component_root=component_root,
    )
    if certificate.benchmark_report.path is None:
        raise ValueError("file-backed certificate does not bind a local benchmark report")
    report, loaded_report_binding = _load_passed_benchmark_report_with_binding(
        component_root,
        certificate.benchmark_report.path,
    )
    if (
        loaded_report_binding.path != observed_report.path
        or loaded_report_binding.size != observed_report.size
        or loaded_report_binding.sha256 != observed_report.sha256
    ):
        raise ValueError("benchmark report changed while file-backed verification was loading")
    if (
        report.corpus_name != certificate.benchmark_name
        or report.profile is not certificate.profile
    ):
        raise ValueError("benchmark report identity does not match the certificate")
    corpus_paths = [
        binding.path for binding in certificate.bindings.corpus if binding.path is not None
    ]
    if len(corpus_paths) != len(certificate.bindings.corpus):
        raise ValueError("file-backed certificate corpus bindings must retain local paths")
    _load_matching_corpus_manifest(component_root, corpus_paths, report)
    verification = verify_benchmark_certificate(
        certificate,
        repository_git_commit=repository_git_commit,
        bindings=observed_bindings,
        benchmark_report=observed_report,
    )
    payload = verification.model_dump(mode="json", exclude={"verification_sha256"})
    payload.update(
        {
            "origin": CertificateVerificationOrigin.FILE_BACKED,
            "file_backed_evidence": FileBackedBenchmarkVerificationEvidence(
                certificate_loaded=True,
                certificate_file_sha256=certificate_file_sha256,
                benchmark_report_loaded=True,
                benchmark_report_file_sha256=loaded_report_binding.sha256,
                benchmark_name=certificate.benchmark_name,
                benchmark_profile=certificate.profile,
                benchmark_report_status=report.status.value,
                benchmark_report_gate_count=len(report.gates),
                benchmark_reports_expected=report.reports_expected,
                benchmark_reports_loaded=report.reports_loaded,
            ).model_dump(mode="json"),
        }
    )
    payload["verification_sha256"] = canonical_sha256(payload)
    return BenchmarkCertificateVerification.model_validate(payload)


def load_benchmark_certificate(path: Path) -> BenchmarkCertificate:
    """Load one bounded certificate without following links or shared hardlinks."""

    certificate, _file_sha256 = _load_benchmark_certificate_with_hash(path)
    return certificate


def _load_benchmark_certificate_with_hash(
    path: Path,
) -> tuple[BenchmarkCertificate, str]:
    """Load and hash the exact bounded bytes used to validate one certificate."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive benchmark certificate filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("benchmark certificate must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_CERTIFICATE_BYTES:
        raise ValueError("benchmark certificate must be a bounded unshared file")
    contents = path.read_bytes()
    if len(contents) != metadata.st_size or len(contents) > _MAX_CERTIFICATE_BYTES:
        raise ValueError("benchmark certificate changed while it was being loaded")
    return (
        BenchmarkCertificate.model_validate_json(contents),
        hashlib.sha256(contents).hexdigest(),
    )


def write_benchmark_certificate(
    path: Path,
    certificate: BenchmarkCertificate,
) -> None:
    """Write a canonical certificate without following a link or shared hardlink."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive benchmark certificate filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("benchmark certificate destination may not be a link")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("benchmark certificate destination must be an unshared file")
    write_json(path, certificate)


def write_benchmark_certificate_verification(
    path: Path,
    verification: BenchmarkCertificateVerification,
) -> None:
    """Write sanitized verification evidence without following shared links."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to write a sensitive verification filename")
    if path.is_symlink() or path.is_junction():
        raise ValueError("certificate verification destination may not be a link")
    if path.exists() and (not path.is_file() or path.stat().st_nlink != 1):
        raise ValueError("certificate verification destination must be an unshared file")
    write_json(path, verification)


def _binding_categories(
    bindings: BenchmarkCertificateBindingSet,
) -> tuple[tuple[str, list[CertificateComponentBinding]], ...]:
    return (
        ("configuration", bindings.configuration),
        ("prompts", bindings.prompts),
        ("models", bindings.models),
        ("tools", bindings.tools),
        ("compilers", bindings.compilers),
        ("corpus", bindings.corpus),
        ("ground_truth", bindings.ground_truth),
    )


def _bind_file_category(
    component_root: Path,
    paths: list[str],
    category: str,
) -> list[CertificateComponentBinding]:
    return [
        bind_certificate_file(
            component_root,
            path,
            identifier=f"{category}/{index:05d}",
        )
        for index, path in enumerate(paths)
    ]


def _load_passed_benchmark_report(
    component_root: Path,
    relative_path: str,
) -> BenchmarkReport:
    report, _binding = _load_passed_benchmark_report_with_binding(
        component_root,
        relative_path,
    )
    return report


def _load_passed_benchmark_report_with_binding(
    component_root: Path,
    relative_path: str,
) -> tuple[BenchmarkReport, CertificateComponentBinding]:
    """Load exact report bytes after binding them to a bounded local file."""

    binding = bind_certificate_file(
        component_root,
        relative_path,
        identifier="benchmark-report-validation",
    )
    if binding.path is None:
        raise ValueError("benchmark report binding did not retain its local path")
    report_path = component_root.resolve(strict=True).joinpath(*PurePosixPath(binding.path).parts)
    contents = report_path.read_bytes()
    if len(contents) != binding.size or hashlib.sha256(contents).hexdigest() != binding.sha256:
        raise ValueError("benchmark report changed while it was being loaded")
    report = BenchmarkReport.model_validate_json(contents)
    require_certifiable_benchmark_report(report)
    return report, binding


def _load_matching_corpus_manifest(
    component_root: Path,
    relative_paths: list[str],
    report: BenchmarkReport,
) -> BenchmarkManifest:
    """Load exactly one bound typed corpus whose inventory matches the report."""

    candidates: list[BenchmarkManifest] = []
    resolved_root = component_root.resolve(strict=True)
    for index, relative_path in enumerate(relative_paths):
        binding = bind_certificate_file(
            component_root,
            relative_path,
            identifier=f"corpus-validation/{index:05d}",
        )
        if binding.path is None:
            raise ValueError("corpus binding did not retain its local path")
        path = resolved_root.joinpath(*PurePosixPath(binding.path).parts)
        try:
            manifest = BenchmarkManifest.model_validate_json(path.read_bytes())
        except ValueError:
            continue
        candidates.append(manifest)
    matching = [
        manifest
        for manifest in candidates
        if manifest.name == report.corpus_name and manifest.corpus_sha256 == report.corpus_sha256
    ]
    if len(matching) != 1:
        raise ValueError(
            "certificate corpus inputs require exactly one typed manifest matching the report"
        )
    require_benchmark_report_matches_manifest(report, matching[0])
    return matching[0]


def _rebind_expected_file(
    component_root: Path,
    expected: CertificateComponentBinding,
) -> CertificateComponentBinding:
    if expected.source is not CertificateComponentSource.FILE or expected.path is None:
        raise ValueError("CLI verification requires file-backed certificate bindings")
    return bind_certificate_file(
        component_root,
        expected.path,
        identifier=expected.identifier,
        details=expected.details,
    )


def _bound_components_sha256(
    repository_git_commit: str,
    bindings: BenchmarkCertificateBindingSet,
    benchmark_report: CertificateComponentBinding,
) -> str:
    return canonical_sha256(
        {
            "repository_git_commit": repository_git_commit,
            "bindings": bindings.model_dump(mode="json"),
            "benchmark_report": benchmark_report.model_dump(mode="json"),
        }
    )


def _binding_mismatch(
    category: str,
    identifier: str,
    kind: CertificateMismatchKind,
    expected: CertificateComponentBinding | None,
    observed: CertificateComponentBinding | None,
) -> CertificateBindingMismatch:
    return CertificateBindingMismatch(
        category=category,
        identifier=identifier,
        kind=kind,
        expected_binding_sha256=(
            canonical_sha256(expected.model_dump(mode="json")) if expected is not None else None
        ),
        observed_binding_sha256=(
            canonical_sha256(observed.model_dump(mode="json")) if observed is not None else None
        ),
    )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_component_path(value: str) -> str:
    normalized = normalize_relative_path(value)
    parts = PurePosixPath(normalized).parts
    if normalized in {"", "."} or not parts or is_sensitive_workspace_path(normalized):
        raise ValueError("certificate component path is empty or sensitive")
    return normalized
