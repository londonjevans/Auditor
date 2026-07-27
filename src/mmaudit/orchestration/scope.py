"""Deterministic requested-versus-achieved audit-scope accounting."""

from __future__ import annotations

from pathlib import PurePosixPath

from mmaudit.config import ScopeConfig
from mmaudit.models.schemas import (
    AnalysisState,
    AuditScope,
    AuditScopeAssessment,
    QualityGateResult,
    ScopeComponent,
    ScopeComponentEvidence,
    ScopeEvidenceStatus,
    SolidityProjectMetadata,
    scope_components_for,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult

_DOCUMENT_EXTENSIONS = frozenset({".md", ".rst", ".adoc", ".txt"})
_OFFCHAIN_LANGUAGES = frozenset(
    {
        "C",
        "C#",
        "C++",
        "C/C++ Header",
        "Go",
        "HTML",
        "Java",
        "JavaScript",
        "Kotlin",
        "PHP",
        "Python",
        "Ruby",
        "Rust",
        "Shell",
        "SQL",
        "Template",
        "Terraform",
        "TypeScript",
        "XML",
        "YAML",
    }
)
_DEPLOYMENT_SEGMENTS = frozenset(
    {
        "broadcast",
        "deploy",
        "deployments",
        "migration",
        "migrations",
        "script",
        "scripts",
    }
)
_TEST_SEGMENTS = frozenset({"test", "tests", "spec", "specs"})
_GLOBAL_OMISSION_PREFIXES = (
    "repository: max_files reached",
    "repository: max_walk_entries reached",
)


def assess_audit_scope(
    discovery: DiscoveryResult,
    projects: list[SolidityProjectMetadata],
    config: ScopeConfig,
    *,
    include_docs: bool,
    include_tests: bool,
) -> AuditScopeAssessment:
    """Classify bounded discovery evidence and calculate the highest achieved scope."""

    required = scope_components_for(config.mode)
    analyzed: dict[ScopeComponent, set[str]] = {component: set() for component in ScopeComponent}
    omissions: dict[ScopeComponent, set[str]] = {component: set() for component in ScopeComponent}
    deployment_roots = {
        path.rstrip("/")
        for project in projects
        for path in [*project.script_directories, *project.deployment_directories]
    }
    for item in discovery.files:
        component = _classify_file(item, deployment_roots)
        if component is None:
            continue
        if item.size > 0 and not item.content:
            omissions[component].add(f"{item.relative_path}: content omitted by bounded discovery")
        else:
            analyzed[component].add(item.relative_path)
    for omission in discovery.omitted:
        if omission.startswith(_GLOBAL_OMISSION_PREFIXES):
            for component in required:
                omissions[component].add(omission)
            continue
        path = omission.split(": ", 1)[0]
        component = _classify_path(path, deployment_roots)
        if component is not None:
            omissions[component].add(omission)
    if ScopeComponent.DOCUMENTATION in required and not include_docs:
        omissions[ScopeComponent.DOCUMENTATION].add(
            "repository.include_docs=false excluded documentation evidence"
        )
    if ScopeComponent.TESTS in required and not include_tests:
        omissions[ScopeComponent.TESTS].add("repository.include_tests=false excluded test evidence")
    evidence = [
        _component_evidence(
            component,
            required=component in required,
            analyzed_paths=analyzed[component],
            omissions=omissions[component],
        )
        for component in ScopeComponent
    ]
    complete_components = {
        item.component for item in evidence if item.status is ScopeEvidenceStatus.ANALYZED
    }
    achieved = _achieved_scope(complete_components)
    missing = sorted(required - complete_components, key=lambda item: item.value)
    limitations = [
        "ignore rules may intentionally exclude paths that bounded discovery does not enumerate"
    ]
    return AuditScopeAssessment(
        requested=config.mode,
        achieved=achieved,
        gate_required=config.require_complete,
        complete=not missing,
        components=sorted(evidence, key=lambda item: item.component.value),
        missing_required_components=missing,
        limitations=limitations,
    )


def filter_discovery_for_scope(
    discovery: DiscoveryResult,
    projects: list[SolidityProjectMetadata],
    scope: AuditScope,
) -> DiscoveryResult:
    """Return the bounded file set authorized by the requested scope mode."""

    if scope is AuditScope.FULL_PROTOCOL:
        return discovery
    deployment_roots = {
        path.rstrip("/")
        for project in projects
        for path in [*project.script_directories, *project.deployment_directories]
    }
    support_paths = {
        path
        for project in projects
        for path in [
            *project.dependency_files,
            *project.framework_config_files,
        ]
    }
    allowed_components = {
        AuditScope.CONTRACTS_ONLY: {
            ScopeComponent.CONTRACTS,
            ScopeComponent.TESTS,
        },
        AuditScope.CONTRACTS_AND_DEPLOYMENT: {
            ScopeComponent.CONTRACTS,
            ScopeComponent.DEPLOYMENT,
            ScopeComponent.TESTS,
        },
    }[scope]
    retained: list[DiscoveredFile] = []
    for item in discovery.files:
        component = _classify_file(item, deployment_roots)
        if item.relative_path in support_paths or (
            component in allowed_components
            and (component is not ScopeComponent.TESTS or item.language == "Solidity")
        ):
            retained.append(item)
    files = tuple(retained)
    retained_paths = {item.relative_path for item in files}
    return DiscoveryResult(
        root=discovery.root,
        files=files,
        omitted=discovery.omitted,
        changed_paths=frozenset(discovery.changed_paths & retained_paths),
        git_commit=discovery.git_commit,
    )


def scope_quality_gate(assessment: AuditScopeAssessment | None) -> QualityGateResult:
    """Convert the typed scope assessment into one explicit quality gate."""

    if assessment is None:
        return QualityGateResult(
            gate="requested_audit_scope",
            required=False,
            passed=False,
            detail="audit-scope assessment was not produced",
            state=AnalysisState.NOT_ANALYZED,
        )
    achieved = assessment.achieved.value if assessment.achieved is not None else "none"
    missing = ", ".join(item.value for item in assessment.missing_required_components)
    required_omission = any(
        item.required and item.status is ScopeEvidenceStatus.OMITTED
        for item in assessment.components
    )
    return QualityGateResult(
        gate="requested_audit_scope",
        required=assessment.gate_required,
        passed=assessment.complete,
        detail=(
            f"requested={assessment.requested.value}; achieved={achieved}"
            + (f"; missing or omitted={missing}" if missing else "")
        ),
        state=(
            AnalysisState.DETERMINISTIC
            if assessment.complete
            else (
                AnalysisState.ATTEMPTED_FAILED if required_omission else AnalysisState.NOT_ANALYZED
            )
        ),
        artifacts=["scope-assessment.json"],
    )


def _component_evidence(
    component: ScopeComponent,
    *,
    required: bool,
    analyzed_paths: set[str],
    omissions: set[str],
) -> ScopeComponentEvidence:
    paths = sorted(analyzed_paths)
    normalized_omissions = sorted(omissions)
    status = (
        ScopeEvidenceStatus.OMITTED
        if normalized_omissions
        else ScopeEvidenceStatus.ANALYZED
        if paths
        else ScopeEvidenceStatus.MISSING
    )
    return ScopeComponentEvidence(
        component=component,
        required=required,
        status=status,
        analyzed_paths=paths,
        omissions=normalized_omissions,
        detail=(f"{len(paths)} analyzed path(s); {len(normalized_omissions)} known omission(s)"),
    )


def _achieved_scope(complete_components: set[ScopeComponent]) -> AuditScope | None:
    for scope in (
        AuditScope.FULL_PROTOCOL,
        AuditScope.CONTRACTS_AND_DEPLOYMENT,
        AuditScope.CONTRACTS_ONLY,
    ):
        if scope_components_for(scope) <= complete_components:
            return scope
    return None


def _classify_file(
    item: DiscoveredFile,
    deployment_roots: set[str],
) -> ScopeComponent | None:
    path_component = _classify_path(item.relative_path, deployment_roots)
    if path_component is not None:
        return path_component
    if item.language == "Solidity":
        return ScopeComponent.CONTRACTS
    if item.language in _OFFCHAIN_LANGUAGES:
        return ScopeComponent.OFFCHAIN
    return None


def _classify_path(
    path: str,
    deployment_roots: set[str],
) -> ScopeComponent | None:
    normalized = path.replace("\\", "/").strip("/")
    if not normalized or normalized == "repository":
        return None
    pure = PurePosixPath(normalized)
    lower_parts = tuple(part.lower() for part in pure.parts)
    lower_name = pure.name.lower()
    suffixes = "".join(pure.suffixes).lower()
    if set(lower_parts) & _TEST_SEGMENTS or lower_name.endswith((".t.sol", ".spec.sol")):
        return ScopeComponent.TESTS
    if (
        set(lower_parts) & _DEPLOYMENT_SEGMENTS
        or any(normalized == root or normalized.startswith(f"{root}/") for root in deployment_roots)
        or lower_name.startswith(("deploy", "migrate"))
        or lower_name.endswith(".s.sol")
    ):
        return ScopeComponent.DEPLOYMENT
    if pure.suffix.lower() in _DOCUMENT_EXTENSIONS:
        return ScopeComponent.DOCUMENTATION
    if pure.suffix.lower() == ".sol" or suffixes.endswith(".sol"):
        return ScopeComponent.CONTRACTS
    if pure.suffix.lower() in {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".go",
        ".h",
        ".hpp",
        ".html",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".mjs",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".tf",
        ".ts",
        ".tsx",
        ".xml",
        ".yaml",
        ".yml",
    }:
        return ScopeComponent.OFFCHAIN
    return None
