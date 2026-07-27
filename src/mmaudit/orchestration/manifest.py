"""Deterministic hash-linked evidence manifests for completed local runs."""

from __future__ import annotations

import hashlib
import json
import stat
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from mmaudit.config import AuditConfig
from mmaudit.constants import ALL_MODEL_ROLES, VERSION
from mmaudit.models.schemas import AuditReport, StrictModel
from mmaudit.reporting.json_report import write_json
from mmaudit.repository.ignore import normalize_relative_path
from mmaudit.repository.secrets import is_sensitive_workspace_name

_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_MANIFEST_FILES = 100_000
_MAX_MANIFEST_BYTES = 4 * 1024**3
_MAX_JSON_ARTIFACT_BYTES = 100_000_000


class ManifestFileBinding(StrictModel):
    """Hash and size for one normalized source or run-artifact path."""

    path: str = Field(min_length=1, max_length=4_096)
    sha256: str = Field(pattern=_SHA256_PATTERN)
    size: int = Field(ge=0)

    @field_validator("path")
    @classmethod
    def path_is_normalized(cls, value: str) -> str:
        normalized = normalize_relative_path(value)
        if (
            not normalized
            or normalized == "."
            or any(is_sensitive_workspace_name(part) for part in PurePosixPath(normalized).parts)
        ):
            raise ValueError("manifest file path must identify a file")
        return normalized


class ManifestHashBinding(StrictModel):
    """Named digest for one normalized security-relevant evidence projection."""

    identifier: str = Field(
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@#-]*$",
    )
    sha256: str = Field(pattern=_SHA256_PATTERN)
    details: dict[str, str] = Field(default_factory=dict, max_length=50)

    @field_validator("details")
    @classmethod
    def details_are_bounded(cls, value: dict[str, str]) -> dict[str, str]:
        if any(
            not key
            or len(key) > 100
            or len(detail) > 2_000
            or any(ord(character) < 32 or ord(character) == 127 for character in key)
            for key, detail in value.items()
        ):
            raise ValueError("manifest binding details are not bounded")
        return value


class ManifestBindingSet(StrictModel):
    """Required binding categories from the MAN-001 acceptance contract."""

    configuration: list[ManifestHashBinding] = Field(min_length=1, max_length=100)
    prompts: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    models: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    tools: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    compilers: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    isolation: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    seeds: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    corpora: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)
    harnesses: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    reproductions: list[ManifestHashBinding] = Field(min_length=1, max_length=100_000)
    coverage: list[ManifestHashBinding] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def categories_are_sorted_and_unique(self) -> ManifestBindingSet:
        for field_name in self.__class__.model_fields:
            bindings = getattr(self, field_name)
            identifiers = [binding.identifier for binding in bindings]
            if identifiers != sorted(set(identifiers)):
                raise ValueError(f"manifest {field_name} bindings must be unique and sorted")
        return self


class RunEvidenceManifest(StrictModel):
    """Self-hashed manifest over source, run evidence projections, and artifacts."""

    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    tool_version: str = Field(min_length=1, max_length=100)
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository_root_name: str = Field(min_length=1, max_length=500)
    git_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    sources: list[ManifestFileBinding] = Field(max_length=_MAX_MANIFEST_FILES)
    source_tree_sha256: str = Field(pattern=_SHA256_PATTERN)
    bindings: ManifestBindingSet
    artifacts: list[ManifestFileBinding] = Field(min_length=1, max_length=_MAX_MANIFEST_FILES)
    manifest_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def hashes_and_paths_are_consistent(self) -> RunEvidenceManifest:
        source_paths = [binding.path for binding in self.sources]
        if source_paths != sorted(set(source_paths)):
            raise ValueError("manifest source paths must be unique and sorted")
        artifact_paths = [binding.path for binding in self.artifacts]
        if artifact_paths != sorted(set(artifact_paths)):
            raise ValueError("manifest artifact paths must be unique and sorted")
        if "run-evidence-manifest.json" in artifact_paths:
            raise ValueError("manifest cannot include itself as an artifact")
        expected_source = canonical_sha256(
            [source.model_dump(mode="json") for source in self.sources]
        )
        if self.source_tree_sha256 != expected_source:
            raise ValueError("manifest source-tree hash does not match source bindings")
        expected_manifest = canonical_sha256(
            self.model_dump(mode="json", exclude={"manifest_sha256"})
        )
        if self.manifest_sha256 != expected_manifest:
            raise ValueError("manifest self-hash does not match its canonical contents")
        return self


def canonical_sha256(value: Any) -> str:
    """Hash a JSON-compatible value using a single canonical encoding."""

    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def seal_run_evidence_manifest(
    *,
    run_id: str,
    repository_root_name: str,
    git_commit: str | None,
    sources: list[ManifestFileBinding],
    bindings: ManifestBindingSet,
    artifacts: list[ManifestFileBinding],
    tool_version: str = VERSION,
) -> RunEvidenceManifest:
    """Sort and self-hash an otherwise complete manifest payload."""

    ordered_sources = sorted(sources, key=lambda item: item.path)
    ordered_artifacts = sorted(artifacts, key=lambda item: item.path)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "tool_version": tool_version,
        "run_id": run_id,
        "repository_root_name": repository_root_name,
        "git_commit": git_commit,
        "sources": [item.model_dump(mode="json") for item in ordered_sources],
        "source_tree_sha256": canonical_sha256(
            [item.model_dump(mode="json") for item in ordered_sources]
        ),
        "bindings": bindings.model_dump(mode="json"),
        "artifacts": [item.model_dump(mode="json") for item in ordered_artifacts],
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    return RunEvidenceManifest.model_validate(payload)


def build_run_evidence_manifest(
    *,
    run_dir: Path,
    report: AuditReport,
    config: AuditConfig,
) -> RunEvidenceManifest:
    """Build all MAN-001 projections from typed runtime state and emitted artifacts."""

    root = run_dir.resolve(strict=True)
    sources = sorted(
        (
            ManifestFileBinding(
                path=source.path,
                sha256=source.sha256,
                size=source.size,
            )
            for source in report.repository.files
        ),
        key=lambda item: item.path,
    )
    compilation = _read_json_artifact(root, "solidity-compilation.json")
    harness_plan = _read_json_artifact(root, "invariant-harness-plan.json")
    property_corpus = _read_json_artifact(root, "property-corpus.json")
    invariant_results = _read_json_artifact(root, "invariant-execution-results.json")
    formal_results = _read_json_artifact(root, "formal-results.json")
    reproduction_results = _read_json_artifact(root, "reproduction-results.json")
    solidity_coverage = _read_json_artifact(root, "solidity-coverage.json")
    model_coverage = _read_json_artifact(root, "model-review-coverage.json")
    scope_assessment = _read_json_artifact(root, "scope-assessment.json")

    bindings = ManifestBindingSet(
        configuration=_configuration_bindings(config),
        prompts=_prompt_bindings(report),
        models=_model_bindings(config, report),
        tools=_tool_bindings(config, report),
        compilers=_compiler_bindings(config, compilation),
        isolation=_isolation_bindings(config, report, compilation),
        seeds=_seed_bindings(
            property_corpus,
            harness_plan,
            invariant_results,
            formal_results,
            reproduction_results,
        ),
        corpora=_corpus_bindings(property_corpus),
        harnesses=_harness_bindings(harness_plan, invariant_results, reproduction_results),
        reproductions=_reproduction_bindings(reproduction_results),
        coverage=_coverage_bindings(
            report,
            solidity_coverage,
            model_coverage,
            scope_assessment,
        ),
    )
    return seal_run_evidence_manifest(
        run_id=report.run_id,
        repository_root_name=report.repository.root_name,
        git_commit=report.repository.git_commit,
        sources=sources,
        bindings=bindings,
        artifacts=_collect_artifacts(root),
    )


def write_run_evidence_manifest(path: Path, manifest: RunEvidenceManifest) -> None:
    """Write the sealed manifest without following an existing link."""

    if path.is_symlink() or path.is_junction():
        raise ValueError("run evidence manifest destination may not be a link")
    write_json(path, manifest)


def load_run_evidence_manifest(path: Path) -> RunEvidenceManifest:
    """Load a bounded, unique, non-link manifest and verify its canonical hash."""

    if is_sensitive_workspace_name(path.name):
        raise ValueError("refusing to read a sensitive run-manifest filename")
    if path.is_symlink() or path.is_junction() or not path.is_file():
        raise ValueError("run evidence manifest must be a regular non-link file")
    metadata = path.stat()
    if metadata.st_nlink != 1 or metadata.st_size > _MAX_JSON_ARTIFACT_BYTES:
        raise ValueError("run evidence manifest must be a bounded unshared file")
    return RunEvidenceManifest.model_validate_json(path.read_text(encoding="utf-8"))


def collect_run_artifacts(run_dir: Path) -> list[ManifestFileBinding]:
    """Observe the bounded run artifact set without executing any artifact."""

    return _collect_artifacts(run_dir.resolve(strict=True))


def validate_manifest_artifacts(
    manifest: RunEvidenceManifest,
    run_dir: Path,
) -> None:
    """Verify every run file is listed and unchanged without executing target code."""

    root = run_dir.resolve(strict=True)
    expected = {binding.path: binding for binding in manifest.artifacts}
    actual = {binding.path: binding for binding in collect_run_artifacts(root)}
    if set(actual) != set(expected):
        raise ValueError("run artifact set does not match the evidence manifest")
    for path, binding in expected.items():
        observed = actual[path]
        if observed.size != binding.size or observed.sha256 != binding.sha256:
            raise ValueError(f"run artifact hash mismatch: {path}")


def _configuration_bindings(config: AuditConfig) -> list[ManifestHashBinding]:
    return [
        ManifestHashBinding(
            identifier="config/full",
            sha256=config.stable_hash(),
            details={"version": str(config.version), "profile": config.profile.value},
        ),
        ManifestHashBinding(
            identifier="config/models",
            sha256=config.model_hash(),
            details={"configured_roles": str(6 + len(config.models.specialists))},
        ),
    ]


def _prompt_bindings(report: AuditReport) -> list[ManifestHashBinding]:
    bindings: list[ManifestHashBinding] = []
    prompt_root = files("mmaudit.prompts")
    for prompt in sorted(prompt_root.iterdir(), key=lambda item: item.name):
        if prompt.is_file() and prompt.name.endswith(".md"):
            bindings.append(
                ManifestHashBinding(
                    identifier=f"template/{prompt.name}",
                    sha256=hashlib.sha256(prompt.read_bytes()).hexdigest(),
                    details={"kind": "system_template"},
                )
            )
    for index, usage in enumerate(report.usage):
        bindings.append(
            ManifestHashBinding(
                identifier=f"request/{index:05d}",
                sha256=usage.prompt_sha256,
                details={
                    "role": _detail(usage.role),
                    "requested_model": _detail(usage.requested_model),
                    "status": _detail(usage.status),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _model_bindings(
    config: AuditConfig,
    report: AuditReport,
) -> list[ManifestHashBinding]:
    roles = [*ALL_MODEL_ROLES, *sorted(config.models.specialists)]
    registry = {
        model_id.lower(): entry
        for entry in config.models.registry
        for model_id in entry.model_ids()
    }
    bindings = []
    for role in roles:
        role_config = config.models.role(role)
        lineage = registry.get(role_config.primary.lower())
        projection = {
            "role": role,
            "configuration": role_config.model_dump(mode="json"),
            "lineage": lineage.model_dump(mode="json") if lineage is not None else None,
        }
        bindings.append(
            _binding(
                f"configured/{role}",
                projection,
                {
                    "primary": _detail(role_config.primary),
                    "root_lineage": lineage.root_lineage if lineage is not None else "unresolved",
                },
            )
        )
    for index, usage in enumerate(report.usage):
        bindings.append(
            _binding(
                f"execution/{index:05d}",
                usage.model_dump(mode="json"),
                {
                    "role": _detail(usage.role),
                    "requested": _detail(usage.requested_model),
                    "returned": _detail(usage.returned_model or "not_reported"),
                    "status": _detail(usage.status),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _tool_bindings(
    config: AuditConfig,
    report: AuditReport,
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "configured/scanners",
            config.scanners.model_dump(mode="json"),
            {"kind": "scanner_configuration"},
        )
    ]
    for index, scanner in enumerate(report.scanner_runs):
        bindings.append(
            _binding(
                f"scanner/{index:05d}",
                scanner.model_dump(mode="json"),
                {
                    "name": _detail(scanner.scanner),
                    "status": scanner.status.value,
                    "version": _detail(scanner.version or "unavailable"),
                    "executable_sha256": _detail(
                        scanner.executable_sha256
                        or (
                            "bound_by_isolation_image"
                            if scanner.repository_code_execution.value == "isolated"
                            else "not_recorded"
                        )
                    ),
                },
            )
        )
    for index, run in enumerate(report.formal_runs):
        bindings.append(
            _binding(
                f"formal/{index:05d}",
                run.model_dump(mode="json"),
                {
                    "name": _detail(run.tool),
                    "status": run.status.value,
                    "version": _detail(run.version or "unavailable"),
                    "executable_sha256": _detail(run.executable_sha256 or "unavailable"),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _compiler_bindings(
    config: AuditConfig,
    compilation: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "configured/solidity",
            config.smart_contracts.model_dump(mode="json"),
            {
                "compile": str(config.smart_contracts.compile).lower(),
                "framework": config.smart_contracts.framework,
            },
        )
    ]
    for index, result in enumerate(_object_list(compilation, "results")):
        bindings.append(
            _binding(
                f"result/{index:05d}",
                result,
                {
                    "framework": _detail(result.get("framework")),
                    "project_root": _detail(result.get("project_root")),
                    "status": _detail(result.get("status")),
                    "executable_sha256": _detail(
                        result.get("executable_sha256")
                        or (
                            "bound_by_isolation_image"
                            if result.get("repository_code_execution") == "isolated"
                            else "not_recorded"
                        )
                    ),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _isolation_bindings(
    config: AuditConfig,
    report: AuditReport,
    compilation: dict[str, Any],
) -> list[ManifestHashBinding]:
    configured = {
        "backend": config.reproduction.isolation_backend,
        "runtime": config.reproduction.rootless_container_runtime,
        "image": config.reproduction.rootless_container_image,
        "require_hardened": config.reproduction.require_hardened_isolation,
    }
    observed = [
        {
            "kind": "scanner",
            "name": run.scanner,
            "backend": run.isolation_backend,
            "repository_code_execution": run.repository_code_execution.value,
        }
        for run in report.scanner_runs
    ]
    observed.extend(
        {
            "kind": "compiler",
            "name": str(result.get("framework", "unknown")),
            "backend": result.get("isolation_backend"),
            "repository_code_execution": result.get("repository_code_execution"),
        }
        for result in _object_list(compilation, "results")
    )
    observed.extend(
        {
            "kind": "invariant",
            "name": result.harness_name,
            "backend": result.isolation_backend,
        }
        for result in report.invariant_executions
    )
    observed.extend(
        {
            "kind": "reproduction",
            "name": result.test_name,
            "backend": result.isolation_backend,
        }
        for result in report.reproductions
    )
    observed.extend(
        {
            "kind": "formal",
            "name": result.tool,
            "backend": result.isolation_backend,
        }
        for result in report.formal_runs
    )
    return [
        _binding(
            "configured/boundary",
            configured,
            {
                "backend": config.reproduction.isolation_backend,
                "image": _detail(config.reproduction.rootless_container_image or "not_configured"),
            },
        ),
        _binding(
            "observed/boundaries",
            observed,
            {"records": str(len(observed))},
        ),
    ]


def _seed_bindings(*artifacts: dict[str, Any]) -> list[ManifestHashBinding]:
    extracted: list[tuple[str, int | str]] = []
    for artifact_index, artifact in enumerate(artifacts):
        _extract_seed_values(
            artifact,
            path=f"artifact-{artifact_index}",
            output=extracted,
        )
    bindings = [
        _binding(
            "seed-set",
            extracted,
            {"count": str(len(extracted))},
        )
    ]
    for index, (path, value) in enumerate(extracted):
        bindings.append(
            _binding(
                f"seed/{index:05d}",
                {"path": path, "value": value},
                {"field": _detail(path), "value": _detail(value)},
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _corpus_bindings(property_corpus: dict[str, Any]) -> list[ManifestHashBinding]:
    corpus = property_corpus.get("corpus")
    corpus_object = corpus if isinstance(corpus, dict) else {}
    corpus_hash = corpus_object.get("corpus_hash")
    digest = (
        corpus_hash
        if isinstance(corpus_hash, str)
        and len(corpus_hash) == 64
        and all(character in "0123456789abcdef" for character in corpus_hash)
        else canonical_sha256(corpus_object)
    )
    properties = corpus_object.get("properties", [])
    return sorted(
        [
            ManifestHashBinding(
                identifier="property-corpus/content",
                sha256=digest,
                details={
                    "properties": str(len(properties) if isinstance(properties, list) else 0),
                },
            ),
            _binding(
                "property-corpus/artifact",
                property_corpus,
                {"artifact": "property-corpus.json"},
            ),
        ],
        key=lambda item: item.identifier,
    )


def _harness_bindings(
    harness_plan: dict[str, Any],
    invariant_results: dict[str, Any],
    reproduction_results: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "invariant-plan/artifact",
            harness_plan,
            {"artifact": "invariant-harness-plan.json"},
        ),
        _binding(
            "invariant-results/artifact",
            invariant_results,
            {"artifact": "invariant-execution-results.json"},
        ),
        _binding(
            "reproduction-specifications/artifact",
            reproduction_results.get("test_specifications", []),
            {"artifact": "reproduction-results.json"},
        ),
    ]
    for index, harness in enumerate(_object_list(harness_plan, "harnesses")):
        bindings.append(
            _binding(
                f"invariant/{index:05d}",
                harness,
                {
                    "name": _detail(harness.get("name")),
                    "invariant_id": _detail(harness.get("invariant_id")),
                },
            )
        )
    for index, specification in enumerate(
        _object_list(reproduction_results, "test_specifications")
    ):
        bindings.append(
            _binding(
                f"reproduction/{index:05d}",
                specification,
                {"name": _detail(specification.get("name"))},
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _reproduction_bindings(
    reproduction_results: dict[str, Any],
) -> list[ManifestHashBinding]:
    bindings = [
        _binding(
            "results/artifact",
            reproduction_results,
            {"artifact": "reproduction-results.json"},
        )
    ]
    for index, result in enumerate(_object_list(reproduction_results, "results")):
        bindings.append(
            _binding(
                f"result/{index:05d}",
                result,
                {
                    "candidate_id": _detail(result.get("candidate_id")),
                    "state": _detail(result.get("state")),
                    "specification_sha256": _detail(result.get("specification_sha256")),
                    "generated_test_sha256": _detail(
                        result.get("generated_test_sha256") or "not_generated"
                    ),
                },
            )
        )
    return sorted(bindings, key=lambda item: item.identifier)


def _coverage_bindings(
    report: AuditReport,
    solidity_coverage: dict[str, Any],
    model_coverage: dict[str, Any],
    scope_assessment: dict[str, Any],
) -> list[ManifestHashBinding]:
    return [
        _binding(
            "model-review/artifact",
            model_coverage,
            {"artifact": "model-review-coverage.json"},
        ),
        _binding(
            "quality-gates/report",
            [gate.model_dump(mode="json") for gate in report.quality_gates],
            {"gates": str(len(report.quality_gates))},
        ),
        _binding(
            "scope/artifact",
            scope_assessment,
            {"artifact": "scope-assessment.json"},
        ),
        _binding(
            "solidity/artifact",
            solidity_coverage,
            {"artifact": "solidity-coverage.json"},
        ),
    ]


def _binding(
    identifier: str,
    payload: Any,
    details: dict[str, str],
) -> ManifestHashBinding:
    return ManifestHashBinding(
        identifier=identifier,
        sha256=canonical_sha256(payload),
        details=details,
    )


def _extract_seed_values(
    value: Any,
    *,
    path: str,
    output: list[tuple[str, int | str]],
) -> None:
    if isinstance(value, dict):
        for key in sorted(value):
            child = value[key]
            child_path = f"{path}/{key}"
            if key in {"seed", "campaign_seed"} and isinstance(child, (int, str)):
                output.append((child_path, child))
            _extract_seed_values(child, path=child_path, output=output)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _extract_seed_values(child, path=f"{path}/{index}", output=output)


def _collect_artifacts(run_dir: Path) -> list[ManifestFileBinding]:
    artifacts: list[ManifestFileBinding] = []
    total_bytes = 0
    for candidate in sorted(run_dir.rglob("*"), key=lambda path: path.as_posix()):
        relative = normalize_relative_path(candidate.relative_to(run_dir))
        if relative == "run-evidence-manifest.json":
            continue
        if any(is_sensitive_workspace_name(part) for part in PurePosixPath(relative).parts):
            raise ValueError("run artifacts may not include sensitive filenames")
        if candidate.is_symlink() or candidate.is_junction():
            raise ValueError("run artifacts may not contain links")
        if candidate.is_dir():
            continue
        metadata = candidate.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("run artifacts must be unique regular files")
        total_bytes += metadata.st_size
        if len(artifacts) + 1 > _MAX_MANIFEST_FILES or total_bytes > _MAX_MANIFEST_BYTES:
            raise ValueError("run artifact manifest limits were exceeded")
        artifacts.append(
            ManifestFileBinding(
                path=relative,
                sha256=_file_sha256(candidate),
                size=metadata.st_size,
            )
        )
    if not artifacts:
        raise ValueError("run evidence manifest requires at least one artifact")
    return artifacts


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json_artifact(run_dir: Path, name: str) -> dict[str, Any]:
    normalized = normalize_relative_path(name)
    path = run_dir / normalized
    if path.is_symlink() or path.is_junction():
        raise ValueError(f"run JSON artifact may not be a link: {name}")
    resolved = path.resolve(strict=True)
    resolved.relative_to(run_dir)
    if not resolved.is_file() or resolved.stat().st_nlink != 1:
        raise ValueError(f"run JSON artifact is not a unique regular file: {name}")
    if resolved.stat().st_size > _MAX_JSON_ARTIFACT_BYTES:
        raise ValueError(f"run JSON artifact exceeds its byte limit: {name}")
    payload = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"run JSON artifact must contain an object: {name}")
    return payload


def _object_list(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key, [])
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _detail(value: object) -> str:
    rendered = "none" if value is None else str(value)
    sanitized = "".join(
        character if ord(character) >= 32 and ord(character) != 127 else "\ufffd"
        for character in rendered
    )
    return sanitized[:2_000]
