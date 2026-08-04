"""Machine-verifiable maximum-assurance requirements traceability.

The matrix is deliberately conservative: a capability is only marked implemented
when executable code, an automated test, and a runtime artifact are all named and
validated.  Documentation-only and planning-only work cannot pass validation.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from mmaudit.models.schemas import StrictModel


class ImplementationStatus(StrEnum):
    IMPLEMENTED = "implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    UNAVAILABLE = "unavailable"
    UNIMPLEMENTED = "unimplemented"


class TraceabilityRequirement(StrictModel):
    requirement_id: str = Field(pattern=r"^MA-[A-Z0-9-]{3,48}$")
    description: str
    implementation_status: ImplementationStatus
    implementation_paths: list[str] = Field(default_factory=list)
    unit_tests: list[str] = Field(default_factory=list)
    real_integration_tests: list[str] = Field(default_factory=list)
    runtime_artifacts: list[str] = Field(default_factory=list)
    required_for_complete: bool
    downgrade_reason: str | None = None
    last_verified_commit: str

    @model_validator(mode="after")
    def implemented_has_three_forms_of_evidence(self) -> TraceabilityRequirement:
        if self.implementation_status is ImplementationStatus.IMPLEMENTED:
            if not self.implementation_paths:
                raise ValueError("implemented requirement lacks executable implementation paths")
            if not self.unit_tests and not self.real_integration_tests:
                raise ValueError("implemented requirement lacks automated tests")
            if not self.runtime_artifacts:
                raise ValueError("implemented requirement lacks runtime artifacts")
            if self.downgrade_reason:
                raise ValueError("implemented requirement cannot have a downgrade reason")
        elif self.required_for_complete and not self.downgrade_reason:
            raise ValueError("incomplete required requirement must state its downgrade reason")
        return self


class MaximumAssuranceTraceability(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    generated_by: Literal["mmaudit"] = "mmaudit"
    last_verified_commit: str
    requirements: list[TraceabilityRequirement]

    @model_validator(mode="after")
    def identifiers_are_unique(self) -> MaximumAssuranceTraceability:
        identifiers = [item.requirement_id for item in self.requirements]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("traceability requirement IDs must be unique")
        return self


def build_traceability_matrix(commit: str | None) -> MaximumAssuranceTraceability:
    """Build the honest current capability ledger.

    The status values are intentionally maintained alongside executable code.  CI
    validates every implemented row against the repository and emitted artifacts.
    """

    verified = commit or "UNCOMMITTED-WORKTREE"
    rows = [
        _row(
            "MA-TRACE-001",
            "Machine-validated requirement traceability is emitted for every audit run.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=["src/mmaudit/traceability.py"],
            unit_tests=["tests/unit/test_traceability.py"],
            real_integration_tests=["tests/integration/test_traceability_artifact.py"],
            runtime_artifacts=["maximum_assurance_traceability.json"],
        ),
        _row(
            "MA-ASSURANCE-CONTRACT",
            "Maximum-assurance status is capped by every required traceability row.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/orchestration/assurance.py",
                "src/mmaudit/orchestration/pipeline.py",
            ],
            unit_tests=["tests/unit/test_assurance.py"],
            real_integration_tests=[
                "tests/integration/test_financial_settlement_foundry.py",
                "tests/integration/test_pipeline.py",
            ],
            runtime_artifacts=["final-findings.json"],
        ),
        _row(
            "MA-SOLIDITY-DISCOVERY",
            "Foundry, Hardhat, mixed, plain, and monorepo Solidity projects are detected.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=["src/mmaudit/solidity/projects.py"],
            unit_tests=["tests/unit/test_solidity.py"],
            runtime_artifacts=["solidity-projects.json"],
        ),
        _row(
            "MA-SCOPE-CONTROL",
            "Requested audit scope is filtered, measured, and failed closed when required evidence is missing.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/full_protocol_acceptance_report.schema.json",
                "src/mmaudit/config.py",
                "src/mmaudit/full_protocol_acceptance.py",
                "src/mmaudit/orchestration/scope.py",
                "src/mmaudit/orchestration/pipeline.py",
            ],
            unit_tests=[
                "tests/unit/test_full_protocol_acceptance.py",
                "tests/unit/test_scope.py",
            ],
            real_integration_tests=[
                "tests/integration/test_full_protocol_offline_acceptance.py",
                "tests/integration/test_pipeline.py",
            ],
            runtime_artifacts=[
                "scope-assessment.json",
                "final-findings.json",
            ],
        ),
        _row(
            "MA-LANGUAGE-CAPABILITY",
            (
                "The requested language profile is source-bound, explicitly configured, "
                "fail-closed in assurance, and propagated through report and release evidence "
                "without overclaiming the Solidity/EVM portfolio."
            ),
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/language_capability.schema.json",
                "schemas/release_bound_gate_result.schema.json",
                "schemas/release_gate_report.schema.json",
                "schemas/release_run_binding.schema.json",
                "schemas/run_evidence_manifest.schema.json",
                "schemas/run_terminal_report_authority.schema.json",
                "scripts/generate_release_schemas.py",
                "src/mmaudit/cli.py",
                "src/mmaudit/config.py",
                "src/mmaudit/language_plugins.py",
                "src/mmaudit/models/schemas.py",
                "src/mmaudit/orchestration/assurance.py",
                "src/mmaudit/orchestration/manifest.py",
                "src/mmaudit/orchestration/pipeline.py",
                "src/mmaudit/orchestration/verification.py",
                "src/mmaudit/release_observations.py",
                "src/mmaudit/release_report.py",
                "src/mmaudit/release_run.py",
                "src/mmaudit/release_validation.py",
                "src/mmaudit/release_verification.py",
                "src/mmaudit/reporting/client.py",
                "src/mmaudit/reporting/markdown.py",
                "src/mmaudit/reporting/run_authority.py",
                "src/mmaudit/reporting/sarif.py",
                "src/mmaudit/repository/discovery.py",
            ],
            unit_tests=[
                "tests/unit/test_assurance.py",
                "tests/unit/test_cli.py",
                "tests/unit/test_config.py",
                "tests/unit/test_language_plugins.py",
                "tests/unit/test_manifest.py",
                "tests/unit/test_openrouter_qualification_config.py",
                "tests/unit/test_release_artifacts.py",
                "tests/unit/test_release_observations.py",
                "tests/unit/test_release_report.py",
                "tests/unit/test_release_run.py",
                "tests/unit/test_release_schemas.py",
                "tests/unit/test_release_validation.py",
                "tests/unit/test_release_verification.py",
                "tests/unit/test_report_status_projection.py",
                "tests/unit/test_run_status.py",
                "tests/unit/test_scanners_reporting.py",
            ],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=[
                "audit-results.sarif",
                "client-report.md",
                "final-findings.json",
                "forensic-report.md",
                "language-capability.json",
                "run-evidence-manifest.json",
            ],
        ),
        _row(
            "MA-PRIOR-AUDIT",
            "Historical findings are withheld from blind discovery and compared afterward.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/full_protocol_acceptance_manifest.schema.json",
                "schemas/full_protocol_acceptance_report.schema.json",
                "schemas/prior_audit.schema.json",
                "src/mmaudit/full_protocol_acceptance.py",
                "src/mmaudit/orchestration/prior_audit.py",
                "src/mmaudit/orchestration/pipeline.py",
                "src/mmaudit/reporting/markdown.py",
            ],
            unit_tests=[
                "tests/unit/test_full_protocol_acceptance.py",
                "tests/unit/test_prior_audit.py",
            ],
            real_integration_tests=[
                "tests/integration/test_full_protocol_offline_acceptance.py",
                "tests/integration/test_pipeline.py",
            ],
            runtime_artifacts=[
                "prior-audit-comparison.json",
                "final-findings.json",
            ],
        ),
        _row(
            "MA-SEMANTIC-GRAPHS",
            "Compiler-backed semantic graphs cover all required protocol relationships.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/solidity/index.py",
                "src/mmaudit/solidity/graphs.py",
            ],
            unit_tests=["tests/unit/test_solidity.py"],
            runtime_artifacts=["solidity-graphs.json"],
            downgrade_reason=(
                "Many graph kinds exist, but complete compiler-backed branch, cross-chain, "
                "off-chain dependency, and upgrade-compatibility validation is not proven."
            ),
        ),
        _row(
            "MA-ECONOMIC-PORTFOLIO",
            "Every applicable economic template has a typed, compiled, executed harness.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/economic_acceptance_manifest.schema.json",
                "schemas/economic_acceptance_report.schema.json",
                "src/mmaudit/economic_acceptance.py",
                "src/mmaudit/solidity/economics.py",
                "src/mmaudit/solidity/invariant_templates.py",
                "src/mmaudit/solidity/invariant_execution.py",
            ],
            unit_tests=[
                "tests/unit/test_economic_acceptance.py",
                "tests/unit/test_economics.py",
                "tests/unit/test_invariant_execution.py",
            ],
            real_integration_tests=[
                "tests/integration/test_economic_acceptance_foundry.py",
                "tests/integration/test_economic_erc4626_fixture.py",
            ],
            runtime_artifacts=[
                "economic-simulation-plan.json",
                "invariant-execution-results.json",
            ],
        ),
        _row(
            "MA-EXPLOIT-REALISM",
            "Reproduction separates setup from attack and enforces realistic capabilities.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/solidity/reproduction.py",
                "src/mmaudit/solidity/reproduction_integrity.py",
            ],
            unit_tests=[
                "tests/unit/test_reproduction.py",
                "tests/unit/test_reproduction_integrity.py",
            ],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=["reproduction-results.json"],
            downgrade_reason=(
                "Capabilities, phase separation, source-cited reachability, repository identity, "
                "clean replay, assertions, minimized steps, and arithmetically reconciled "
                "single-asset financial settlement are deterministic; audited-source/deployed-"
                "bytecode equivalence remains incomplete."
            ),
        ),
        _row(
            "MA-FORMAL-PORTFOLIO",
            "Independent fuzz, symbolic, and formal engines execute applicable properties.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/benchmark/engine.py",
                "src/mmaudit/benchmark/mutations.py",
                "src/mmaudit/solidity/formal.py",
            ],
            unit_tests=[
                "tests/unit/test_benchmark.py",
                "tests/unit/test_formal.py",
            ],
            runtime_artifacts=["formal-results.json", "benchmark-results.json"],
            downgrade_reason=(
                "Tool adapters normalize bounded results and per-property mutation gates fail "
                "closed, but real cross-engine fixture execution remains incomplete."
            ),
        ),
        _row(
            "MA-MODEL-ENSEMBLE",
            "All approved Tier A models execute the required specialist review coverage.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/models/openrouter.py",
                "src/mmaudit/models/qualification.py",
                "src/mmaudit/models/registry.py",
                "src/mmaudit/agents/specialists.py",
                "src/mmaudit/orchestration/assurance.py",
                "src/mmaudit/orchestration/model_coverage.py",
            ],
            unit_tests=[
                "tests/unit/test_openrouter.py",
                "tests/unit/test_model_qualification.py",
                "tests/unit/test_model_registry.py",
                "tests/unit/test_assurance.py",
                "tests/unit/test_model_coverage.py",
            ],
            runtime_artifacts=[
                "model-validation.json",
                "model-qualification-runtime.json",
                "model-review-coverage.json",
                "final-findings.json",
            ],
            downgrade_reason=(
                "Qualification and response-backed specialist routing fail closed, but no frozen "
                "real production benchmark currently proves and executes every selected Tier A "
                "model and required independent lineage."
            ),
        ),
        _row(
            "MA-BENCHMARK-CERTIFICATE",
            "mmaudit run verifies a current component-bound benchmark certificate.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/benchmark/certificate.py",
                "src/mmaudit/cli.py",
                "src/mmaudit/orchestration/assurance.py",
                "src/mmaudit/orchestration/pipeline.py",
            ],
            unit_tests=[
                "tests/unit/test_benchmark_certificate.py",
                "tests/unit/test_cli.py",
                "tests/unit/test_assurance.py",
            ],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=["final-findings.json"],
        ),
        _row(
            "MA-OS-ISOLATION",
            "All untrusted dynamic execution uses a rootless, pinned OS isolation boundary.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/adversarial_acceptance_manifest.schema.json",
                "schemas/adversarial_acceptance_report.schema.json",
                "src/mmaudit/adversarial_acceptance.py",
                "src/mmaudit/isolation/container.py",
                "src/mmaudit/repository/workspace.py",
                "src/mmaudit/solidity/reproduction.py",
                "Dockerfile",
            ],
            unit_tests=[
                "tests/unit/test_adversarial_acceptance.py",
                "tests/unit/test_adversarial_repository.py",
                "tests/unit/test_isolation.py",
                "tests/unit/test_reproduction.py",
            ],
            real_integration_tests=[
                "tests/integration/test_adversarial_acceptance_fail_closed.py",
                "tests/integration/test_adversarial_repository_isolation.py",
                "tests/integration/test_rootless_container.py",
            ],
            runtime_artifacts=["metadata.json", "reproduction-results.json"],
            downgrade_reason=(
                "A digest-pinned rootless container backend now enforces read-only mounts, "
                "no network, syscall/resource limits, shared bounded workspace validation, and "
                "verified cleanup. The source-bound adversarial acceptance portfolio passes "
                "deterministic rejection and fail-closed coverage without host execution, but "
                "broader dynamic tool paths still support platform-specific isolation and real "
                "rootless integration is environment-bound."
            ),
        ),
        _row(
            "MA-HARDHAT-ISOLATION",
            "Hardhat configuration and plugins never execute in a host audit process.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/isolation/container.py",
                "src/mmaudit/isolation/repository_code.py",
                "src/mmaudit/scanners/base.py",
                "src/mmaudit/solidity/compile.py",
            ],
            unit_tests=[
                "tests/unit/test_isolation.py",
                "tests/unit/test_scanners_reporting.py",
                "tests/unit/test_solidity.py",
            ],
            real_integration_tests=["tests/integration/test_rootless_container.py"],
            runtime_artifacts=[
                "scanner-results.json",
                "solidity-compilation.json",
            ],
        ),
        _row(
            "MA-DEPENDENCY-PREPARATION",
            "Hardhat dependencies are prepared from a checksum-bound offline snapshot without lifecycle execution.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/dependency_snapshot.schema.json",
                "schemas/dependency_sbom.schema.json",
                "src/mmaudit/config.py",
                "src/mmaudit/isolation/dependencies.py",
                "src/mmaudit/orchestration/pipeline.py",
                "src/mmaudit/solidity/compile.py",
            ],
            unit_tests=["tests/unit/test_dependencies.py"],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=[
                "dependency-preparation.json",
                "dependency-sbom.json",
            ],
        ),
        _row(
            "MA-REPORT-BUNDLE",
            "Every audit emits a concise branded client report and a separately hash-bound "
            "complete forensic evidence bundle.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/coverage_artifact.schema.json",
                "schemas/findings_artifact.schema.json",
                "schemas/forensic_delivery_descriptor.schema.json",
                "schemas/model_execution_artifact.schema.json",
                "schemas/run_evidence_manifest.schema.json",
                "src/mmaudit/cli.py",
                "src/mmaudit/forensic_export.py",
                "src/mmaudit/release_io.py",
                "src/mmaudit/reporting/bundle.py",
                "src/mmaudit/reporting/client.py",
                "src/mmaudit/reporting/markdown.py",
                "src/mmaudit/orchestration/manifest.py",
                "src/mmaudit/orchestration/pipeline.py",
            ],
            unit_tests=[
                "tests/unit/test_client_forensic_reporting.py",
                "tests/unit/test_client_forensic_reporting_adversarial.py",
                "tests/unit/test_forensic_cost_ledger.py",
                "tests/unit/test_forensic_export.py",
                "tests/unit/test_manifest.py",
                "tests/unit/test_release_io.py",
                "tests/unit/test_release_artifacts.py",
            ],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=[
                "client-report.md",
                "forensic-report.md",
                "audit-report.md",
                "findings.json",
                "audit-results.sarif",
                "coverage.json",
                "model-execution.json",
                "run-evidence-manifest.json",
            ],
        ),
        _row(
            "MA-EVIDENCE-MANIFEST",
            "Every run emits a deterministic hash-linked manifest of its effective "
            "configuration, safe override provenance, inputs, and artifacts.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/run_evidence_manifest.schema.json",
                "src/mmaudit/config.py",
                "src/mmaudit/orchestration/manifest.py",
                "src/mmaudit/orchestration/pipeline.py",
            ],
            unit_tests=[
                "tests/unit/test_config.py",
                "tests/unit/test_manifest.py",
            ],
            real_integration_tests=["tests/integration/test_pipeline.py"],
            runtime_artifacts=["run-evidence-manifest.json"],
        ),
        _row(
            "MA-REPLAY-MANIFEST",
            "Hash-linked run manifests support deterministic verification and replay.",
            ImplementationStatus.IMPLEMENTED,
            verified,
            implementation_paths=[
                "schemas/offline_replay.schema.json",
                "schemas/run_verification.schema.json",
                "src/mmaudit/cli.py",
                "src/mmaudit/orchestration/certification.py",
                "src/mmaudit/orchestration/manifest.py",
                "src/mmaudit/orchestration/replay.py",
                "src/mmaudit/orchestration/verification.py",
            ],
            unit_tests=[
                "tests/unit/test_certification.py",
                "tests/unit/test_manifest.py",
                "tests/unit/test_replay.py",
            ],
            real_integration_tests=["tests/integration/test_offline_replay.py"],
            runtime_artifacts=["run-evidence-manifest.json"],
            required=True,
        ),
        _row(
            "MA-BLIND-SUPERIORITY",
            "Blind head-to-head evidence demonstrates superiority to professional auditors.",
            ImplementationStatus.PARTIALLY_IMPLEMENTED,
            verified,
            implementation_paths=[
                "src/mmaudit/benchmark/claims.py",
                "src/mmaudit/benchmark/engine.py",
            ],
            unit_tests=["tests/unit/test_benchmark_claims.py"],
            runtime_artifacts=["benchmark-results.json"],
            required=False,
            downgrade_reason=(
                "The three-state claim gate defaults to NOT_EVALUATED and validates blinded "
                "comparability, independent adjudication, and 95% precision/recall support, "
                "but no qualifying human-comparison corpus has been executed."
            ),
        ),
    ]
    return MaximumAssuranceTraceability(
        last_verified_commit=verified,
        requirements=rows,
    )


def validate_traceability_evidence(
    matrix: MaximumAssuranceTraceability,
    *,
    repository_root: Path | None,
    runtime_artifacts: set[str],
) -> None:
    """Fail when an implemented row cannot prove code, tests, and artifacts."""

    root = repository_root.resolve(strict=True) if repository_root is not None else None
    for requirement in matrix.requirements:
        if requirement.implementation_status is not ImplementationStatus.IMPLEMENTED:
            continue
        for relative in requirement.implementation_paths:
            normalized = _evidence_path(relative)
            if normalized.suffix not in {".py", ".sh", ".toml", ".json", ".yml", ".yaml"}:
                raise ValueError(
                    f"{requirement.requirement_id} implementation evidence is not executable "
                    f"code or machine configuration: {relative}"
                )
            if normalized.parts[0] in {"docs", "tests"}:
                raise ValueError(
                    f"{requirement.requirement_id} implementation evidence cannot be "
                    f"documentation or a test: {relative}"
                )
        for relative in [*requirement.unit_tests, *requirement.real_integration_tests]:
            normalized = _evidence_path(relative)
            if (
                normalized.parts[0] != "tests"
                or normalized.suffix != ".py"
                or not normalized.name.startswith("test_")
            ):
                raise ValueError(
                    f"{requirement.requirement_id} test evidence is not a pytest file: {relative}"
                )
        for artifact in requirement.runtime_artifacts:
            normalized = _evidence_path(artifact)
            if len(normalized.parts) != 1:
                raise ValueError(
                    f"{requirement.requirement_id} runtime artifact must be a run-directory "
                    f"filename: {artifact}"
                )
        if root is not None:
            for relative in [
                *requirement.implementation_paths,
                *requirement.unit_tests,
                *requirement.real_integration_tests,
            ]:
                _validate_repository_evidence_file(
                    root,
                    relative,
                    requirement_id=requirement.requirement_id,
                )
        missing_artifacts = set(requirement.runtime_artifacts) - runtime_artifacts
        if missing_artifacts:
            raise ValueError(
                f"{requirement.requirement_id} lacks runtime artifacts: "
                + ", ".join(sorted(missing_artifacts))
            )


def _evidence_path(value: str) -> PurePosixPath:
    if not value or "\\" in value:
        raise ValueError(f"traceability evidence path is not normalized: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"traceability evidence path is unsafe: {value!r}")
    return path


def _validate_repository_evidence_file(
    root: Path,
    relative: str,
    *,
    requirement_id: str,
) -> None:
    path = _evidence_path(relative)
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError(f"{requirement_id} evidence traverses a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError(
            f"{requirement_id} evidence is outside or missing from the repository: {relative}"
        ) from exc
    if not resolved.is_file():
        raise ValueError(f"{requirement_id} evidence is not a regular repository file: {relative}")


def write_traceability_artifact(
    path: Path,
    matrix: MaximumAssuranceTraceability,
) -> None:
    """Write stable traceability JSON without following symlink destinations."""

    if path.is_symlink():
        raise ValueError("traceability artifact destination may not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(matrix.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _row(
    requirement_id: str,
    description: str,
    status: ImplementationStatus,
    commit: str,
    *,
    implementation_paths: list[str] | None = None,
    unit_tests: list[str] | None = None,
    real_integration_tests: list[str] | None = None,
    runtime_artifacts: list[str] | None = None,
    required: bool = True,
    downgrade_reason: str | None = None,
) -> TraceabilityRequirement:
    return TraceabilityRequirement(
        requirement_id=requirement_id,
        description=description,
        implementation_status=status,
        implementation_paths=implementation_paths or [],
        unit_tests=unit_tests or [],
        real_integration_tests=real_integration_tests or [],
        runtime_artifacts=runtime_artifacts or [],
        required_for_complete=required,
        downgrade_reason=downgrade_reason,
        last_verified_commit=commit,
    )
