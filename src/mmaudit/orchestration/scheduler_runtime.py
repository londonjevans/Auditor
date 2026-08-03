"""Production bindings and task/result joins for the seven-pass scheduler."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mmaudit.config import AuditConfig, AuditRunOptions
from mmaudit.isolation.dependencies import DependencyPreparationRun
from mmaudit.models.openrouter import (
    DeliveredSourceDescriptor,
    ModelRequestPrivacyBinding,
    OpenRouterSchemaError,
    OpenRouterTruncatedResponseError,
    OpenRouterUnboundIdentityError,
)
from mmaudit.models.qualification import VerifiedProductionQualification
from mmaudit.models.scheduler import (
    ABSENT_COST_LEDGER_BASELINE_SHA256,
    ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256,
    ABSENT_QUALIFICATION_SHA256,
    ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256,
    SCHEDULER_PASS_ORDER,
    SchedulerAbsenceReason,
    SchedulerAnalysisInputDescriptor,
    SchedulerAnalysisInputInventory,
    SchedulerArtifact,
    SchedulerBindings,
    SchedulerCandidateWorkset,
    SchedulerConditionalAbsence,
    SchedulerCostLedgerBaseline,
    SchedulerCostLedgerBaselineEntry,
    SchedulerPassDependency,
    SchedulerPassKind,
    SchedulerPassPlan,
    SchedulerPassResult,
    SchedulerPrivacyEvidenceCustody,
    SchedulerProviderAttemptEvidence,
    SchedulerReportBinding,
    SchedulerScope,
    SchedulerShardDescriptor,
    SchedulerShardInventory,
    SchedulerSourceDescriptor,
    SchedulerTaskActivation,
    SchedulerTaskKind,
    SchedulerTaskPlan,
    SchedulerTaskResult,
    SchedulerTerminalStatus,
    scheduler_canonical_sha256,
    scheduler_response_schema_model_registry,
)
from mmaudit.models.schemas import (
    AuditScopeAssessment,
    CandidateFinding,
    EconomicSimulationPlan,
    FormalToolRun,
    FoundryInvariantHarnessSpec,
    InvariantExecutionResult,
    InvariantSuite,
    LocationValidation,
    ModelSurfaceReviewArtifact,
    ModelSurfaceReviewRequest,
    PropertyCorpus,
    RepositoryMap,
    RepositorySuiteDifferentialRun,
    ScannerRun,
    SolidityCompilationResult,
    SolidityCoverage,
    SolidityGraphSet,
    SolidityProjectMetadata,
    SoliditySymbolIndex,
    SpecialistAcceptedOutcome,
    UsageRecord,
)
from mmaudit.models.sharding import SolidityShardInventory
from mmaudit.models.usage import is_accountable_usage_record, is_creditable_usage_record
from mmaudit.orchestration.budgets import (
    BudgetExhaustedError,
    _issue_trusted_request_limit_scope,
    _TrustedRequestLimitScope,
)
from mmaudit.orchestration.cost_ledger import (
    AtomicCostLedger,
    cost_entry_sha256,
    cost_ledger_snapshot_sha256,
)
from mmaudit.orchestration.execution_candidates import ExecutionCandidateBuildResult
from mmaudit.orchestration.scheduler import (
    SchedulerJournal,
    create_scheduler_journal,
    resume_scheduler_journal,
)
from mmaudit.repository.discovery import DiscoveryResult

_HOST_PROMPT_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.host-computation-prompt.v1"}
)
_HOST_RESPONSE_SCHEMA_SHA256 = scheduler_canonical_sha256(
    {"domain": "mmaudit.scheduler.host-computation-response.v1"}
)

# Analysis-input commitments describe the security-relevant observation, not the
# disposable process which happened to produce it.  These exclusions are closed
# and type-specific so a future runtime field is retained by default.  Derived
# self-hashes are excluded only where their preimage contains one of the listed
# incidental fields; the independently useful content/tool hashes remain bound.
_SEMANTIC_FIELD_EXCLUSIONS: dict[str, frozenset[str]] = {
    "DependencyPreparationResult": frozenset({"prepared_path"}),
    "FormalEvidence": frozenset(),
    "FormalToolRun": frozenset(
        {
            "duration_seconds",
            "execution_observation_sha256",
            "stdout_path",
            "stderr_path",
            "result_path",
        }
    ),
    "InvariantExecutionAttemptEvidence": frozenset({"stdout_path", "stderr_path"}),
    "InvariantExecutionResult": frozenset(
        {
            "duration_seconds",
            "execution_observation_sha256",
            "stdout_path",
            "stderr_path",
        }
    ),
    "LocationValidation": frozenset({"validated_at"}),
    "RepositoryCleanStateAttestationEvidence": frozenset(
        {
            "startup_duration_seconds",
            "termination_duration_seconds",
            "process_attestation_sha256",
            "attestation_sha256",
        }
    ),
    "RepositorySuiteDifferentialMatrix": frozenset({"matrix_sha256"}),
    "RepositorySuiteDifferentialRun": frozenset({"result_sha256"}),
    "RepositorySuiteExecutionStateEvidence": frozenset({"state_sha256"}),
    "RepositorySuiteStateAttempt": frozenset(
        {
            "workspace_identity_sha256",
            "workspace_freshness_attestation_sha256",
            "attempt_sha256",
        }
    ),
    "RepositorySuiteStateWorkspaceCleanupEvidence": frozenset(
        {
            "attempt_cleanup_sequence_lifecycle_sha256s",
            "attempt_cumulative_removal_duration_seconds",
            "removal_duration_seconds",
            "aggregate_evidence_sha256",
        }
    ),
    "RepositorySuiteTestComparison": frozenset(
        {
            "clean_state_sha256",
            "pinned_state_sha256",
            "clean_consensus_sha256",
            "pinned_consensus_sha256",
            "comparison_sha256",
        }
    ),
    "RepositorySuiteTestStateConsensus": frozenset({"attempt_sha256s", "consensus_sha256"}),
    "RepositorySuiteWorkspaceCopyEvidence": frozenset(
        {
            "attempt_binding_sha256",
            "source_root_device_before",
            "source_root_inode_before",
            "source_root_device_after",
            "source_root_inode_after",
            "workspace_root_device_before",
            "workspace_root_inode_before",
            "workspace_root_device_after",
            "workspace_root_inode_after",
            "workspace_parent_device",
            "workspace_parent_inode",
            "copy_evidence_sha256",
        }
    ),
    "RepositorySuiteWorkspaceLifecycleEvidence": frozenset(
        {
            "attempt_binding_sha256",
            "workspace_copy_evidence_sha256",
            "scanner_execution_observation_sha256",
            "freshness_attestation_sha256",
            "attempt_root_device",
            "attempt_root_inode",
            "removal_duration_seconds",
            "lifecycle_evidence_sha256",
        }
    ),
    "RepositoryTestExecution": frozenset({"duration_seconds", "execution_sha256"}),
    "RepositoryTestForkRpcScopeEvidence": frozenset(
        {
            "attempt_binding_sha256",
            "bridge_scope_snapshot_sha256",
            "evidence_sha256",
        }
    ),
    "ForkRpcReadOnlyEgressEvidence": frozenset(
        {
            "selected_test_scope_snapshot_sha256s",
            "bridge_snapshot_sha256",
            "evidence_sha256",
        }
    ),
    "ScannerRun": frozenset(
        {
            "started_at",
            "finished_at",
            "duration_seconds",
            "raw_output_path",
            "execution_observation_sha256",
        }
    ),
    "SolidityCompilationResult": frozenset({"duration_seconds", "stdout_path", "stderr_path"}),
}

_COMMAND_MODEL_TYPES = frozenset(
    {"FormalToolRun", "InvariantExecutionResult", "ScannerRun", "SolidityCompilationResult"}
)
_PROJECT_ROOT_MODEL_TYPES = frozenset(
    {
        "DependencyPreparationResult",
        "DependencySbom",
        "SolidityCompilationResult",
        "SolidityProjectMetadata",
    }
)
_DIAGNOSTIC_FIELDS = frozenset({"error", "errors", "failure_reason", "limitations", "warnings"})


@dataclass(frozen=True)
class _AnalysisProjectionRoots:
    audited_repository_root: Path
    disposable_roots: tuple[Path, ...]


def scheduler_prompt_template_inventory() -> tuple[dict[str, Any], ...]:
    """Return the exact trusted prompt-template inventory available to a campaign."""

    root = files("mmaudit.prompts")
    records: list[dict[str, Any]] = []
    for prompt in sorted(root.iterdir(), key=lambda item: item.name):
        if not prompt.is_file() or not prompt.name.endswith(".md"):
            continue
        content = prompt.read_bytes()
        records.append(
            {
                "name": prompt.name,
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "utf8_bytes": len(content),
            }
        )
    if not records:
        raise ValueError("scheduler prompt-template inventory is empty")
    return tuple(records)


def scheduler_prompt_template_set_sha256() -> str:
    """Hash the immutable trusted prompt-template inventory."""

    return scheduler_canonical_sha256(scheduler_prompt_template_inventory())


@cache
def _cached_scheduler_response_schema_registry_items() -> tuple[tuple[str, str], ...]:
    """Return immutable model-type/schema-hash pairs for the closed registry."""

    model_registry = scheduler_response_schema_model_registry()
    records = tuple(
        sorted(
            (
                (f"{model.__module__}.{model.__qualname__}", schema_sha256)
                for schema_sha256, model in model_registry.items()
            ),
            key=lambda item: item[0],
        )
    )
    if len({model_type for model_type, _schema_sha256 in records}) != len(records):
        raise ValueError("scheduler response-schema registry contains a duplicate type")
    return records


def _scheduler_response_schema_registry_items() -> tuple[tuple[str, str], ...]:
    """Return cached records only after checking every live parser contract."""

    scheduler_response_schema_model_registry()
    return _cached_scheduler_response_schema_registry_items()


def scheduler_response_schema_registry() -> tuple[dict[str, str], ...]:
    """Return mutation-isolated records derived from the immutable registry cache."""

    return tuple(
        {"model_type": model_type, "schema_sha256": schema_sha256}
        for model_type, schema_sha256 in _scheduler_response_schema_registry_items()
    )


@cache
def _cached_scheduler_response_schema_set_sha256() -> str:
    """Hash the closed pre-execution response-schema registry."""

    return scheduler_canonical_sha256(
        tuple(
            {"model_type": model_type, "schema_sha256": schema_sha256}
            for model_type, schema_sha256 in _scheduler_response_schema_registry_items()
        )
    )


def scheduler_response_schema_set_sha256() -> str:
    """Return the set hash only while the live parser registry remains exact."""

    scheduler_response_schema_model_registry()
    return _cached_scheduler_response_schema_set_sha256()


@cache
def _cached_scheduler_response_schema_hashes() -> frozenset[str]:
    """Return the exact response hashes permitted in model task plans."""

    return frozenset(
        schema_sha256 for _model_type, schema_sha256 in _scheduler_response_schema_registry_items()
    )


def scheduler_response_schema_hashes() -> frozenset[str]:
    """Return permitted hashes only while every live parser contract remains exact."""

    scheduler_response_schema_model_registry()
    return _cached_scheduler_response_schema_hashes()


@cache
def _cached_scheduler_response_normalizer_sha256(response_schema_sha256: str) -> str:
    """Bind the canonical JSON/Pydantic normalization used by scheduler outputs."""

    return scheduler_canonical_sha256(
        {
            "domain": "mmaudit.scheduler.model-output-normalizer.v1",
            "response_schema_sha256": response_schema_sha256,
            "json_encoding": "sorted-keys,compact,ascii,no-nan",
        }
    )


def scheduler_response_normalizer_sha256(response_schema_sha256: str) -> str:
    """Bind normalization only for a currently exact registered response schema."""

    if response_schema_sha256 not in scheduler_response_schema_hashes():
        raise ValueError("scheduler normalizer requires a registered response schema")
    return _cached_scheduler_response_normalizer_sha256(response_schema_sha256)


def scheduler_tool_policy_projection(config: AuditConfig) -> dict[str, Any]:
    """Project only pre-execution local-engine and isolation policy."""

    effective = config.effective()
    return {
        "dependency_preparation": effective.dependency_preparation.model_dump(mode="json"),
        "execution_limits": {
            "concurrency": effective.execution.concurrency,
            "request_timeout_seconds": effective.execution.request_timeout_seconds,
            "scanner_timeout_seconds": effective.execution.scanner_timeout_seconds,
        },
        "formal": effective.formal.model_dump(mode="json"),
        "invariants": effective.invariants.model_dump(mode="json"),
        "maximum_assurance": effective.maximum_assurance.model_dump(mode="json"),
        "reproduction": effective.reproduction.model_dump(mode="json"),
        "scanners": effective.scanners.model_dump(mode="json"),
        "smart_contracts": effective.smart_contracts.model_dump(mode="json"),
    }


def scheduler_tool_policy_sha256(config: AuditConfig) -> str:
    """Hash the exact effective local-engine and isolation policy."""

    return scheduler_canonical_sha256(scheduler_tool_policy_projection(config))


def scheduler_qualification_sha256(
    qualification: VerifiedProductionQualification | None,
) -> str:
    """Return the exact qualification artifact hash or a typed absence commitment."""

    return (
        qualification.artifact_sha256 if qualification is not None else ABSENT_QUALIFICATION_SHA256
    )


def build_scheduler_shard_inventory(
    repository: RepositoryMap,
    solidity_inventory: SolidityShardInventory | None,
) -> SchedulerShardInventory:
    """Bind every audited source exactly once to a scheduler shard.

    Solidity source units retain their semantic shard identities. All remaining
    audited source is assigned to one deterministic repository pseudo-shard so a
    mixed-language audit cannot silently disappear from the blind-review barrier.
    """

    sources_by_path = {
        item.path: SchedulerSourceDescriptor.build(
            path=item.path,
            sha256=item.sha256,
            size=item.size,
        )
        for item in repository.files
    }
    if not sources_by_path:
        raise ValueError("scheduler requires a non-empty audited source inventory")
    if len(sources_by_path) != len(repository.files):
        raise ValueError("scheduler source inventory contains duplicate paths")

    descriptors: list[SchedulerShardDescriptor] = []
    semantic_paths: set[str] = set()
    semantic_inventory_sha256 = ABSENT_SEMANTIC_SHARD_INVENTORY_SHA256
    if solidity_inventory is not None:
        semantic_inventory_sha256 = solidity_inventory.inventory_sha256
        for shard in solidity_inventory.shards:
            source = sources_by_path.get(shard.source_path)
            if source is None or source.sha256 != shard.source_content_sha256:
                raise ValueError(
                    "semantic scheduler shard differs from the audited source inventory"
                )
            semantic_paths.add(shard.source_path)
            descriptors.append(
                SchedulerShardDescriptor.semantic(
                    shard_id=shard.shard_id,
                    semantic_shard_sha256=shard.shard_sha256,
                    sources=(source,),
                )
            )

    remaining = tuple(
        source for path, source in sorted(sources_by_path.items()) if path not in semantic_paths
    )
    if remaining:
        descriptors.append(SchedulerShardDescriptor.repository_pseudo(sources=remaining))
    return SchedulerShardInventory.build(
        semantic_inventory_sha256=semantic_inventory_sha256,
        shards=descriptors,
    )


def build_scheduler_bindings(
    *,
    config: AuditConfig,
    shard_inventory: SchedulerShardInventory,
    qualification: VerifiedProductionQualification | None,
    analysis_input_sha256: str,
    cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    privacy_evidence_custody: SchedulerPrivacyEvidenceCustody | None = None,
) -> SchedulerBindings:
    """Build independently reproducible immutable campaign bindings."""

    effective = config.effective()
    return SchedulerBindings.build(
        source_sha256=shard_inventory.source_tree_sha256,
        analysis_input_sha256=analysis_input_sha256,
        effective_config_sha256=effective.stable_hash(),
        shard_inventory_sha256=shard_inventory.inventory_sha256,
        model_selection_sha256=effective.model_hash(),
        qualification_sha256=scheduler_qualification_sha256(qualification),
        prompt_set_sha256=scheduler_prompt_template_set_sha256(),
        schema_set_sha256=scheduler_response_schema_set_sha256(),
        tool_policy_sha256=scheduler_tool_policy_sha256(effective),
        cost_ledger_baseline_sha256=(
            cost_ledger_baseline.baseline_sha256
            if cost_ledger_baseline is not None
            else ABSENT_COST_LEDGER_BASELINE_SHA256
        ),
        privacy_evidence_custody_sha256=(
            privacy_evidence_custody.custody_sha256
            if privacy_evidence_custody is not None
            else ABSENT_PRIVACY_EVIDENCE_CUSTODY_SHA256
        ),
    )


def scheduler_analysis_semantic_projection(
    value: object,
    *,
    audited_repository_root: Path,
    disposable_roots: Iterable[Path] = (),
    audited_exclusion_roots: Iterable[Path] = (),
    audited_source_paths: Iterable[str] = (),
) -> object:
    """Project one typed input to deterministic, security-relevant scheduler evidence.

    Runtime timing, process identity, and disposable output locations cannot
    influence task planning or model context.  Status, normalized outcomes,
    compiler/tool identity, source/configuration hashes, coverage, failures, and
    limitations remain committed.  Unknown model types and fields are retained by
    default so schema growth fails toward a stricter binding.
    """

    roots = _validated_projection_roots(
        audited_repository_root=audited_repository_root,
        disposable_roots=disposable_roots,
        audited_exclusion_roots=audited_exclusion_roots,
        audited_source_paths=audited_source_paths,
    )
    return _scheduler_analysis_semantic_projection(value, roots)


def _scheduler_analysis_semantic_projection(
    value: object,
    roots: _AnalysisProjectionRoots,
) -> object:
    if isinstance(value, BaseModel):
        type_name = type(value).__name__
        excluded = _SEMANTIC_FIELD_EXCLUSIONS.get(type_name, frozenset())
        projection: dict[str, object] = {}
        for field_name in type(value).model_fields:
            if field_name in excluded:
                continue
            field_value = getattr(value, field_name)
            if field_name == "command" and type_name in _COMMAND_MODEL_TYPES:
                projection[field_name] = _semantic_command(
                    field_value,
                    executable_sha256=getattr(value, "executable_sha256", None),
                    roots=roots,
                )
            elif field_name == "project_root" and type_name in _PROJECT_ROOT_MODEL_TYPES:
                projection[field_name] = _semantic_bound_path(field_value, roots)
            elif (
                type_name == "RepositorySuiteExecutionStateEvidence"
                and field_name == "state_source_sha256"
                and getattr(value, "clean_state_attestation", None) is not None
            ):
                # Clean-local state identity is reproduced by its semantic chain
                # and launcher projection; the original self-hash includes process
                # timing and cannot identify an equivalent fresh run.
                continue
            elif type_name == "ScannerFinding" and field_name == "metadata":
                projection[field_name] = _scanner_finding_metadata_projection(
                    field_value,
                    roots,
                )
            elif field_name in _DIAGNOSTIC_FIELDS:
                projection[field_name] = _semantic_diagnostic(field_value, roots)
            elif field_name in {
                "artifact_paths",
                "artifacts",
                "assumption_artifacts",
                "source_path",
                "specification_artifacts",
                "vacuity_artifacts",
            }:
                projection[field_name] = _semantic_paths(field_value, roots)
            else:
                projection[field_name] = _scheduler_analysis_semantic_projection(
                    field_value,
                    roots,
                )
        return projection
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {
            _semantic_mapping_key(key): _scheduler_analysis_semantic_projection(item, roots)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scheduler_analysis_semantic_projection(item, roots) for item in value]
    if isinstance(value, (set, frozenset)):
        projected = [_scheduler_analysis_semantic_projection(item, roots) for item in value]
        return sorted(projected, key=scheduler_canonical_sha256)
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported scheduler analysis-input value type: {type(value).__name__}")


def _semantic_mapping_key(value: object) -> str:
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, str):
        return value
    raise TypeError("scheduler analysis-input mappings require string or enum keys")


def _validated_projection_roots(
    *,
    audited_repository_root: Path,
    disposable_roots: Iterable[Path],
    audited_exclusion_roots: Iterable[Path] = (),
    audited_source_paths: Iterable[str] = (),
) -> _AnalysisProjectionRoots:
    audited = _validated_projection_root(audited_repository_root, "audited repository")
    source_paths = tuple(sorted(set(audited_source_paths)))
    exclusions = tuple(
        sorted(
            {
                _validated_projection_root(root, "audited exclusion")
                for root in audited_exclusion_roots
            },
            key=lambda item: (-len(item.parts), item.as_posix()),
        )
    )
    for exclusion in exclusions:
        try:
            relative = exclusion.relative_to(audited)
        except ValueError:
            raise ValueError(
                "scheduler audited exclusion roots must be inside the audited repository"
            ) from None
        if relative == Path(".") or any(
            _relative_path_is_within(source_path, relative) for source_path in source_paths
        ):
            raise ValueError("scheduler audited exclusion root overlaps audited source evidence")
    disposable = tuple(
        sorted(
            {_validated_projection_root(root, "disposable analysis") for root in disposable_roots},
            key=lambda item: (-len(item.parts), item.as_posix()),
        )
    )
    for root in disposable:
        if root == audited:
            raise ValueError("scheduler disposable roots cannot equal the audited repository")
        if audited in root.parents and not any(
            root == exclusion or exclusion in root.parents for exclusion in exclusions
        ):
            raise ValueError(
                "scheduler in-repository disposable root lacks exact exclusion authority"
            )
    return _AnalysisProjectionRoots(
        audited_repository_root=audited,
        disposable_roots=disposable,
    )


def _relative_path_is_within(source_path: str, root: Path) -> bool:
    normalized = Path(source_path.replace("\\", "/"))
    return normalized == root or root in normalized.parents


def _validated_projection_root(value: Path, label: str) -> Path:
    supplied = Path(os.path.abspath(value))
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"scheduler {label} root is unavailable") from exc
    if supplied != resolved or not resolved.is_dir() or resolved.is_symlink():
        raise ValueError(f"scheduler {label} root must be a direct existing directory")
    return resolved


def _semantic_command(
    value: object,
    *,
    executable_sha256: object,
    roots: _AnalysisProjectionRoots,
) -> object:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        raise TypeError("scheduler engine commands must be string argument arrays")
    normalized: list[str] = []
    for index, argument in enumerate(value):
        if index == 0 and _is_absolute_command_path(argument):
            if isinstance(executable_sha256, str) and re.fullmatch(
                r"[0-9a-f]{64}", executable_sha256
            ):
                normalized.append(f"<trusted-executable>/{Path(argument).name}")
                continue
            normalized.append(argument)
            continue
        normalized_argument = _semantic_bound_path(argument, roots)
        if normalized_argument != argument:
            if not isinstance(normalized_argument, str):
                raise TypeError("scheduler command path normalization must produce text")
            normalized.append(normalized_argument)
            continue
        option, separator, option_value = argument.partition("=")
        normalized_option_value = _semantic_bound_path(option_value, roots)
        if separator and normalized_option_value != option_value:
            normalized.append(f"{option}={normalized_option_value}")
            continue
        normalized.append(argument)
    return normalized


def _is_absolute_command_path(value: str) -> bool:
    return value.startswith(("/", "\\")) or bool(re.match(r"^[A-Za-z]:[\\/]", value))


def _semantic_bound_path(value: object, roots: _AnalysisProjectionRoots) -> object:
    if not isinstance(value, str) or not _is_absolute_command_path(value):
        return _scheduler_analysis_semantic_projection(value, roots)
    candidate = Path(value)
    labelled_roots = (
        *(("disposable-root", root) for root in roots.disposable_roots),
        ("audited-source", roots.audited_repository_root),
    )
    for label, root in labelled_roots:
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            continue
        suffix = relative.as_posix()
        return f"<{label}>/{suffix}" if suffix != "." else f"<{label}>"
    return value


def _semantic_paths(value: object, roots: _AnalysisProjectionRoots) -> object:
    if isinstance(value, str):
        return _semantic_bound_path(value, roots)
    if isinstance(value, (list, tuple)):
        return [_semantic_paths(item, roots) for item in value]
    return _scheduler_analysis_semantic_projection(value, roots)


def _semantic_diagnostic(value: object, roots: _AnalysisProjectionRoots) -> object:
    if isinstance(value, str):
        normalized = value
        labelled_roots = (
            *(("disposable-root", root) for root in roots.disposable_roots),
            ("audited-source", roots.audited_repository_root),
        )
        for label, root in labelled_roots:
            normalized = normalized.replace(str(root), f"<{label}>")
        return normalized
    if isinstance(value, (list, tuple)):
        return [_semantic_diagnostic(item, roots) for item in value]
    return _scheduler_analysis_semantic_projection(value, roots)


def _scanner_finding_metadata_projection(
    value: object,
    roots: _AnalysisProjectionRoots,
) -> object:
    if not isinstance(value, dict):
        return _scheduler_analysis_semantic_projection(value, roots)
    projection: dict[str, object] = {}
    for key, item in value.items():
        if key == "repository_test_execution_sha256":
            continue
        normalized_key = _semantic_mapping_key(key)
        if key == "location_validation":
            if not isinstance(item, list):
                raise ValueError("scanner location-validation metadata must be a typed list")
            projection[normalized_key] = [
                _scheduler_analysis_semantic_projection(
                    LocationValidation.model_validate(entry),
                    roots,
                )
                for entry in item
            ]
        else:
            projection[normalized_key] = _scheduler_analysis_semantic_projection(item, roots)
    return projection


def build_scheduler_analysis_input_inventory(
    *,
    run_options: AuditRunOptions,
    discovery: DiscoveryResult,
    repository_map: RepositoryMap,
    repository_execution_sha256: str | None,
    scanner_source_sha256: str | None,
    dependency_preparation: DependencyPreparationRun,
    scope_assessment: AuditScopeAssessment | None,
    projects: list[SolidityProjectMetadata],
    compilations: list[SolidityCompilationResult],
    index: SoliditySymbolIndex | None,
    graphs: SolidityGraphSet | None,
    semantic_shards: SolidityShardInventory | None,
    invariants: InvariantSuite | None,
    invariant_harnesses: list[FoundryInvariantHarnessSpec],
    invariant_executions: list[InvariantExecutionResult],
    property_corpus: PropertyCorpus,
    economic_simulations: list[EconomicSimulationPlan],
    formal_runs: list[FormalToolRun],
    scanner_runs: list[ScannerRun],
    repository_suite_differential: RepositorySuiteDifferentialRun | None,
    solidity_coverage: SolidityCoverage | None,
    execution_candidate_build: ExecutionCandidateBuildResult,
    model_surface_requests: list[ModelSurfaceReviewRequest],
    model_surface_review_assignments: dict[str, list[ModelSurfaceReviewRequest]],
    disposable_roots: Iterable[Path] = (),
    audited_exclusion_roots: Iterable[Path] = (),
) -> SchedulerAnalysisInputInventory:
    """Commit every deterministic pre-scheduler input without private paths or source text."""

    _require_optional_sha256(repository_execution_sha256, "repository_execution_sha256")
    _require_optional_sha256(scanner_source_sha256, "scanner_source_sha256")
    projection_roots = _validated_projection_roots(
        audited_repository_root=discovery.root,
        disposable_roots=disposable_roots,
        audited_exclusion_roots=audited_exclusion_roots,
        audited_source_paths=(item.relative_path for item in discovery.files),
    )
    discovery_projection = {
        "files": [
            {
                "relative_path": item.relative_path,
                "sha256": item.sha256,
                "size": item.size,
                "lines": item.lines,
                "language": item.language,
                "categories": list(item.categories),
            }
            for item in sorted(discovery.files, key=lambda item: item.relative_path)
        ],
        "omitted": sorted(discovery.omitted),
        "changed_paths": sorted(discovery.changed_paths),
        "git_commit": discovery.git_commit,
    }
    dependency_projection = {
        "results": [
            _scheduler_analysis_semantic_projection(item, projection_roots)
            for item in dependency_preparation.results
        ],
        "sboms": [
            _scheduler_analysis_semantic_projection(item, projection_roots)
            for item in dependency_preparation.sboms
        ],
        "prepared_root_keys": sorted(dependency_preparation.prepared_roots),
    }
    execution_projection = {
        "candidates": [
            _scheduler_analysis_semantic_projection(item, projection_roots)
            for item in execution_candidate_build.candidates
        ],
        "dispositions": [
            _scheduler_analysis_semantic_projection(item, projection_roots)
            for item in execution_candidate_build.dispositions
        ],
        "rejected_counterexample_count": (execution_candidate_build.rejected_counterexample_count),
        "limitations": list(execution_candidate_build.limitations),
    }
    assignments_projection = {
        role: [_scheduler_analysis_semantic_projection(item, projection_roots) for item in requests]
        for role, requests in sorted(model_surface_review_assignments.items())
    }
    typed_values: tuple[tuple[str, str, object], ...] = (
        (
            "run_options",
            "AuditRunOptions",
            _scheduler_analysis_semantic_projection(run_options, projection_roots),
        ),
        ("discovery", "DiscoveryResultProjection", discovery_projection),
        (
            "repository_map",
            "RepositoryMap",
            _scheduler_analysis_semantic_projection(repository_map, projection_roots),
        ),
        ("repository_execution_sha256", "str|None", repository_execution_sha256),
        ("scanner_source_sha256", "str|None", scanner_source_sha256),
        ("dependency_preparation", "DependencyPreparationRunProjection", dependency_projection),
        (
            "scope_assessment",
            "AuditScopeAssessment|None",
            _optional_semantic_projection(scope_assessment, projection_roots),
        ),
        (
            "projects",
            "list[SolidityProjectMetadata]",
            _semantic_model_list(projects, projection_roots),
        ),
        (
            "compilations",
            "list[SolidityCompilationResult]",
            _semantic_model_list(compilations, projection_roots),
        ),
        (
            "index",
            "SoliditySymbolIndex|None",
            _optional_semantic_projection(index, projection_roots),
        ),
        (
            "graphs",
            "SolidityGraphSet|None",
            _optional_semantic_projection(graphs, projection_roots),
        ),
        (
            "semantic_shards",
            "SolidityShardInventory|None",
            _optional_semantic_projection(semantic_shards, projection_roots),
        ),
        (
            "invariants",
            "InvariantSuite|None",
            _optional_semantic_projection(invariants, projection_roots),
        ),
        (
            "invariant_harnesses",
            "list[FoundryInvariantHarnessSpec]",
            _semantic_model_list(invariant_harnesses, projection_roots),
        ),
        (
            "invariant_executions",
            "list[InvariantExecutionResult]",
            _semantic_model_list(invariant_executions, projection_roots),
        ),
        (
            "property_corpus",
            "PropertyCorpus",
            _scheduler_analysis_semantic_projection(property_corpus, projection_roots),
        ),
        (
            "economic_simulations",
            "list[EconomicSimulationPlan]",
            _semantic_model_list(economic_simulations, projection_roots),
        ),
        (
            "formal_runs",
            "list[FormalToolRun]",
            _semantic_model_list(formal_runs, projection_roots),
        ),
        (
            "scanner_runs",
            "list[ScannerRun]",
            _semantic_model_list(scanner_runs, projection_roots),
        ),
        (
            "repository_suite_differential",
            "RepositorySuiteDifferentialRun|None",
            _optional_semantic_projection(repository_suite_differential, projection_roots),
        ),
        (
            "solidity_coverage",
            "SolidityCoverage|None",
            _optional_semantic_projection(solidity_coverage, projection_roots),
        ),
        (
            "execution_candidate_build",
            "ExecutionCandidateBuildResultProjection",
            execution_projection,
        ),
        (
            "model_surface_requests",
            "list[ModelSurfaceReviewRequest]",
            _semantic_model_list(model_surface_requests, projection_roots),
        ),
        (
            "model_surface_review_assignments",
            "dict[str,list[ModelSurfaceReviewRequest]]",
            assignments_projection,
        ),
    )
    return SchedulerAnalysisInputInventory.build(
        SchedulerAnalysisInputDescriptor.build(
            label=label,
            type_name=type_name,
            value=value,
        )
        for label, type_name, value in typed_values
    )


def _optional_semantic_projection(
    value: BaseModel | None,
    roots: _AnalysisProjectionRoots,
) -> object:
    return _scheduler_analysis_semantic_projection(value, roots) if value is not None else None


def _semantic_model_list(
    values: Iterable[BaseModel],
    roots: _AnalysisProjectionRoots,
) -> list[object]:
    return [_scheduler_analysis_semantic_projection(item, roots) for item in values]


def _require_optional_sha256(value: str | None, label: str) -> None:
    if value is None:
        return
    if len(value) != 64 or value.lower() != value:
        raise ValueError(f"scheduler {label} must be an exact lowercase SHA-256")
    try:
        bytes.fromhex(value)
    except ValueError:
        raise ValueError(f"scheduler {label} must be an exact lowercase SHA-256") from None


def build_scheduler_cost_ledger_baseline(
    atomic_ledger: AtomicCostLedger,
) -> SchedulerCostLedgerBaseline:
    """Freeze the exact terminal ledger head before a scheduler campaign starts."""

    snapshot = atomic_ledger.snapshot()
    return SchedulerCostLedgerBaseline.build(
        cap_usd_exact=format(snapshot.cap_usd, "f"),
        spent_usd_exact=format(snapshot.spent_usd, "f"),
        active_reserved_usd_exact=format(snapshot.active_reserved_usd, "f"),
        entries=(
            SchedulerCostLedgerBaselineEntry.build(
                request_id=entry.request_id,
                ledger_entry_sha256=cost_entry_sha256(entry),
            )
            for entry in snapshot.entries
        ),
        ledger_identity_sha256=atomic_ledger.identity_sha256,
        ledger_snapshot_sha256=cost_ledger_snapshot_sha256(snapshot),
    )


class PipelineScheduler:
    """Small production controller joining work to one descriptor-safe journal."""

    def __init__(self, journal: SchedulerJournal) -> None:
        self.journal = journal
        self._active_plan: SchedulerPassPlan | None = (
            journal.plans[-1] if len(journal.plans) > len(journal.pass_results) else None
        )
        self._activations: dict[str, SchedulerTaskActivation] = {
            item.task_id: item for item in journal.activations
        }
        self._upstream_results: dict[str, tuple[str, ...]] = {}

    @classmethod
    def create(
        cls,
        path: Path,
        *,
        bindings: SchedulerBindings,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        shard_inventory: SchedulerShardInventory,
        privacy_evidence_custody: SchedulerPrivacyEvidenceCustody,
        cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
    ) -> PipelineScheduler:
        return cls(
            create_scheduler_journal(
                path,
                bindings=bindings,
                analysis_input_inventory=analysis_input_inventory,
                shard_inventory=shard_inventory,
                cost_ledger_baseline=cost_ledger_baseline,
                privacy_evidence_custody=privacy_evidence_custody,
            )
        )

    @classmethod
    def resume(
        cls,
        path: Path,
        *,
        bindings: SchedulerBindings,
        analysis_input_inventory: SchedulerAnalysisInputInventory,
        shard_inventory: SchedulerShardInventory,
        cost_ledger_baseline: SchedulerCostLedgerBaseline | None = None,
        atomic_ledger: AtomicCostLedger | None = None,
    ) -> PipelineScheduler:
        """Resume only an exact campaign; dispatched work remains non-retriable."""

        return cls(
            resume_scheduler_journal(
                path,
                expected_bindings=bindings,
                expected_analysis_input_inventory=analysis_input_inventory,
                expected_shard_inventory=shard_inventory,
                expected_cost_ledger_baseline=cost_ledger_baseline,
                atomic_ledger=atomic_ledger,
            )
        )

    @property
    def manifest(self):  # type: ignore[no-untyped-def]
        return self.journal.manifest

    @property
    def active_plan(self) -> SchedulerPassPlan:
        if self._active_plan is None:
            raise ValueError("scheduler has no active sealed pass")
        return self._active_plan

    def model_task(
        self,
        *,
        pass_kind: SchedulerPassKind,
        scope: SchedulerScope,
        task_key: str,
        role: str,
        requested_model: str,
        root_lineage: str,
        system_prompt_sha256: str,
        response_schema_sha256: str,
        candidate_ids: Iterable[str] = (),
    ) -> SchedulerTaskPlan:
        if self.journal.manifest.privacy_evidence_custody is None:
            raise ValueError("scheduled model task lacks exact pre-dispatch privacy custody")
        if response_schema_sha256 not in scheduler_response_schema_hashes():
            raise ValueError("scheduled model task uses an unregistered response schema")
        input_recipe_sha256 = scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.model-input-recipe.v1",
                "pass_kind": pass_kind,
                "scope_sha256": scope.scope_sha256,
                "task_key": task_key,
                "role": role,
            }
        )
        prompt_recipe_sha256 = scheduler_canonical_sha256(
            {
                "domain": "mmaudit.scheduler.model-prompt-recipe.v1",
                "prompt_set_sha256": self.journal.manifest.bindings.prompt_set_sha256,
                "task_key": task_key,
                "role": role,
            }
        )
        return SchedulerTaskPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            scope=scope,
            task_kind=SchedulerTaskKind.MODEL_REQUEST,
            task_key=task_key,
            role=role,
            requested_model=requested_model,
            root_lineage=root_lineage,
            candidate_ids=candidate_ids,
            input_sha256=input_recipe_sha256,
            prompt_sha256=prompt_recipe_sha256,
            system_prompt_sha256=system_prompt_sha256,
            normalizer_sha256=scheduler_response_normalizer_sha256(response_schema_sha256),
            response_schema_sha256=response_schema_sha256,
        )

    def host_task(
        self,
        *,
        pass_kind: SchedulerPassKind,
        scope: SchedulerScope,
        task_key: str,
        role: str,
    ) -> SchedulerTaskPlan:
        return SchedulerTaskPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            scope=scope,
            task_kind=SchedulerTaskKind.HOST_COMPUTATION,
            task_key=task_key,
            role=role,
            input_sha256=scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.host-input-recipe.v1",
                    "pass_kind": pass_kind,
                    "scope_sha256": scope.scope_sha256,
                    "task_key": task_key,
                    "role": role,
                }
            ),
            prompt_sha256=_HOST_PROMPT_SHA256,
            response_schema_sha256=_HOST_RESPONSE_SCHEMA_SHA256,
        )

    def empty_task(
        self,
        *,
        pass_kind: SchedulerPassKind,
        scope: SchedulerScope,
        task_key: str,
        role: str,
        reason: str,
    ) -> SchedulerTaskPlan:
        return SchedulerTaskPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            scope=scope,
            task_kind=SchedulerTaskKind.EMPTY_COMPLETION,
            task_key=task_key,
            role=role,
            input_sha256=scheduler_canonical_sha256(
                {
                    "domain": "mmaudit.scheduler.conditional-absence-recipe.v1",
                    "pass_kind": pass_kind,
                    "scope_sha256": scope.scope_sha256,
                    "task_key": task_key,
                    "reason": reason,
                }
            ),
            prompt_sha256=_HOST_PROMPT_SHA256,
            response_schema_sha256=_HOST_RESPONSE_SCHEMA_SHA256,
        )

    def conditional_absence(
        self,
        *,
        reason: SchedulerAbsenceReason,
        candidate_workset: SchedulerCandidateWorkset,
    ) -> SchedulerConditionalAbsence:
        """Bind no-work only to a persisted empty pass-four candidate inventory."""

        return SchedulerConditionalAbsence.build(
            reason=reason,
            candidate_workset=candidate_workset,
        )

    def candidate_workset(
        self,
        pass_kind: SchedulerPassKind,
    ) -> SchedulerCandidateWorkset:
        """Project pass-five/six work from the exact retained pass-four host output."""

        matching_passes = tuple(
            result
            for result in self.journal.pass_results
            if result.plan.pass_kind is SchedulerPassKind.CROSS_SHARD_INTEGRATION
        )
        if len(matching_passes) != 1:
            raise ValueError("scheduler candidate workset lacks one exact pass-four result")
        source_pass = matching_passes[0]
        matching_results = tuple(
            result
            for result in source_pass.task_results
            if next(task for task in source_pass.plan.tasks if task.task_id == result.task_id).role
            == "host:cross_shard_integrator"
        )
        if len(matching_results) != 1:
            raise ValueError("scheduler candidate workset lacks one integration host result")
        source_result = matching_results[0]
        matching_outputs = tuple(
            output
            for output in self.journal.outputs
            if output.task_id == source_result.task_id
            and output.output_artifact_sha256 == source_result.output_artifact_sha256
        )
        if len(matching_outputs) != 1:
            raise ValueError("scheduler candidate workset lacks exact persisted integration output")
        return SchedulerCandidateWorkset.build(
            pass_kind=pass_kind,
            source_pass_result=source_pass,
            source_result=source_result,
            source_output=matching_outputs[0],
        )

    def seal_pass(
        self,
        pass_kind: SchedulerPassKind,
        tasks: Iterable[SchedulerTaskPlan],
        *,
        candidate_workset: SchedulerCandidateWorkset | None = None,
        conditional_absence: SchedulerConditionalAbsence | None = None,
    ) -> SchedulerPassPlan:
        if self._active_plan is not None:
            raise ValueError("scheduler already has an active pass")
        plan = SchedulerPassPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            dependencies=self.journal.next_dependencies,
            tasks=tasks,
            candidate_workset=candidate_workset,
            conditional_absence=conditional_absence,
        )
        self._active_plan = self.journal.seal_pass_plan(plan)
        return self._active_plan

    def prepare_pass(
        self,
        pass_kind: SchedulerPassKind,
        tasks: Iterable[SchedulerTaskPlan],
        *,
        candidate_workset: SchedulerCandidateWorkset | None = None,
        conditional_absence: SchedulerConditionalAbsence | None = None,
    ) -> SchedulerPassPlan:
        """Seal a fresh pass or adopt the byte-exact active plan after resume."""

        expected = SchedulerPassPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            dependencies=self.journal.next_dependencies,
            tasks=tasks,
            candidate_workset=candidate_workset,
            conditional_absence=conditional_absence,
        )
        if self._active_plan is None:
            self._active_plan = self.journal.seal_pass_plan(expected)
        elif self._active_plan != expected:
            raise ValueError("resumed scheduler pass differs from the exact prepared plan")
        return self._active_plan

    def completed_pass_result(
        self,
        pass_kind: SchedulerPassKind,
        tasks: Iterable[SchedulerTaskPlan],
        *,
        candidate_workset: SchedulerCandidateWorkset | None = None,
        conditional_absence: SchedulerConditionalAbsence | None = None,
    ) -> SchedulerPassResult | None:
        """Adopt one byte-exact completed pass without reopening it for dispatch."""

        ordinal = SCHEDULER_PASS_ORDER.index(pass_kind)
        completed = self.journal.pass_results
        if ordinal >= len(completed):
            return None
        result = completed[ordinal]
        expected = SchedulerPassPlan.build(
            manifest=self.journal.manifest,
            pass_kind=pass_kind,
            dependencies=tuple(
                SchedulerPassDependency.from_result(item) for item in completed[:ordinal]
            ),
            tasks=tasks,
            candidate_workset=candidate_workset,
            conditional_absence=conditional_absence,
        )
        if result.plan != expected:
            raise ValueError(
                "resumed completed scheduler pass differs from the exact prepared plan"
            )
        return result

    def completed_result_for_task(
        self,
        pass_result: SchedulerPassResult,
        task: SchedulerTaskPlan,
    ) -> SchedulerTaskResult:
        """Return one exact task result from an adopted completed pass."""

        if pass_result not in self.journal.pass_results or task not in pass_result.plan.tasks:
            raise ValueError("completed scheduler task is outside its durable pass result")
        matches = tuple(item for item in pass_result.task_results if item.task_id == task.task_id)
        if len(matches) != 1 or matches[0].task_plan_sha256 != task.task_plan_sha256:
            raise ValueError("completed scheduler task lacks one exact durable result")
        return matches[0]

    def completed_output_for_task[OutputT: BaseModel](
        self,
        pass_result: SchedulerPassResult,
        task: SchedulerTaskPlan,
        output_type: type[OutputT],
    ) -> OutputT:
        """Strictly reconstruct one adopted completed task's retained typed output."""

        result = self.completed_result_for_task(pass_result, task)
        if result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
            raise ValueError("completed scheduler task lacks a successful retained output")
        return self.journal.reconstruct_output(task.task_id, output_type)

    @property
    def resumable_tasks(self) -> tuple[SchedulerTaskPlan, ...]:
        """Return exact active-plan tasks that were never durably dispatched."""

        resumable = set(self.journal.resumable_task_ids)
        return tuple(task for task in self.active_plan.tasks if task.task_id in resumable)

    @property
    def terminal_results(self) -> tuple[SchedulerTaskResult, ...]:
        """Return exact terminal results belonging to the active plan."""

        active = {task.task_id for task in self.active_plan.tasks}
        return tuple(result for result in self.journal.task_results if result.task_id in active)

    def result_for_task(self, task: SchedulerTaskPlan) -> SchedulerTaskResult | None:
        """Return the exact credited terminal result, if this task already completed."""

        self._require_active_task(task)
        matches = tuple(
            result for result in self.terminal_results if result.task_id == task.task_id
        )
        if len(matches) > 1:
            raise ValueError("scheduler task has ambiguous credited terminal results")
        return matches[0] if matches else None

    def output_for_task[OutputT: BaseModel](
        self,
        task: SchedulerTaskPlan,
        output_type: type[OutputT],
    ) -> OutputT:
        """Strictly reconstruct a completed task's typed retained output."""

        result = self.result_for_task(task)
        if result is None or result.terminal_status is not SchedulerTerminalStatus.SUCCEEDED:
            raise ValueError("scheduler task lacks a successful retained output")
        return self.journal.reconstruct_output(task.task_id, output_type)

    def set_upstream_results(
        self,
        task: SchedulerTaskPlan,
        results: Iterable[SchedulerTaskResult],
    ) -> None:
        """Bind same-pass predecessor results before a task is activated."""

        self._require_active_task(task)
        values = tuple(sorted({item.result_sha256 for item in results}))
        existing = self._activations.get(task.task_id)
        if existing is not None:
            if existing.upstream_task_result_sha256s != values:
                raise ValueError("resumed task upstream results differ from durable activation")
            return
        self._upstream_results[task.task_id] = values

    def request_ready(
        self,
        *,
        logical_request_id: str,
        role: str,
        requested_model: str,
        prompt_sha256: str,
        system_prompt_sha256: str,
        user_prompt_sha256: str,
        schema_sha256: str,
        delivered_sources: tuple[DeliveredSourceDescriptor, ...],
        privacy_binding: ModelRequestPrivacyBinding | None,
    ) -> _TrustedRequestLimitScope | None:
        """Persist the exact provider request material before transport."""

        matches = [
            task for task in self.active_plan.tasks if task.logical_request_id == logical_request_id
        ]
        if len(matches) != 1:
            raise OpenRouterSchemaError(
                "provider request lacks one exact active scheduler task identity"
            )
        task = matches[0]
        custody = self.journal.manifest.privacy_evidence_custody
        if (
            custody is None
            or privacy_binding is None
            or privacy_binding.source_sha256 != custody.source_sha256
            or privacy_binding.effective_policy_sha256 != custody.effective_policy_evidence_sha256
            or privacy_binding.source_provenance_sha256 != custody.source_provenance_evidence_sha256
        ):
            raise OpenRouterSchemaError(
                "provider request privacy authority differs from scheduler custody"
            )
        if (
            task.task_kind is not SchedulerTaskKind.MODEL_REQUEST
            or task.role != role
            or task.requested_model != requested_model
            or task.system_prompt_sha256 != system_prompt_sha256
            or task.response_schema_sha256 != schema_sha256
            or schema_sha256 not in scheduler_response_schema_hashes()
        ):
            raise OpenRouterSchemaError(
                "provider request differs from its exact active scheduler task"
            )
        upstream = self._upstream_results.get(task.task_id, ())
        if delivered_sources != tuple(sorted(set(delivered_sources))):
            raise OpenRouterSchemaError(
                "provider delivered source descriptors are not unique and sorted"
            )
        sources_by_path = {
            source.path: source
            for shard in self.journal.manifest.shard_inventory.shards
            for source in shard.sources
        }
        if any(
            (source := sources_by_path.get(delivered.path)) is None
            or source.sha256 != delivered.sha256
            or source.size != delivered.size
            for delivered in delivered_sources
        ):
            raise OpenRouterSchemaError(
                "provider delivered source descriptor differs from audited source bytes"
            )
        delivered_source_descriptor_sha256s = tuple(
            sources_by_path[delivered.path].source_descriptor_sha256
            for delivered in delivered_sources
        )
        existing = self._activations.get(task.task_id)
        if existing is None:
            activation = self.journal.activate_task(
                task.task_id,
                actual_input_sha256=user_prompt_sha256,
                system_prompt_sha256=system_prompt_sha256,
                user_prompt_sha256=user_prompt_sha256,
                provider_prompt_sha256=prompt_sha256,
                response_schema_sha256=schema_sha256,
                delivered_source_descriptor_sha256s=(delivered_source_descriptor_sha256s),
                upstream_task_result_sha256s=upstream,
            )
            self._activations[task.task_id] = activation
        else:
            expected = SchedulerTaskActivation.build(
                plan=self.active_plan,
                task=task,
                actual_input_sha256=user_prompt_sha256,
                system_prompt_sha256=system_prompt_sha256,
                user_prompt_sha256=user_prompt_sha256,
                provider_prompt_sha256=prompt_sha256,
                response_schema_sha256=schema_sha256,
                delivered_source_descriptor_sha256s=(delivered_source_descriptor_sha256s),
                upstream_task_result_sha256s=existing.upstream_task_result_sha256s,
            )
            if (
                task.task_id not in self.journal.dispatchable_task_ids
                or existing != expected
                or (upstream and upstream != existing.upstream_task_result_sha256s)
            ):
                raise OpenRouterSchemaError(
                    "resumed provider request differs from its durable activation"
                )
        return _issue_trusted_request_limit_scope(logical_request_id)

    def request_dispatched(self, *, logical_request_id: str) -> None:
        """Persist provider dispatch before the HTTP transport is entered."""

        matches = [
            task for task in self.active_plan.tasks if task.logical_request_id == logical_request_id
        ]
        if len(matches) != 1:
            raise OpenRouterSchemaError(
                "provider dispatch lacks one exact active scheduler task identity"
            )
        self.journal.mark_dispatched(matches[0].task_id)

    def activate_host(
        self,
        task: SchedulerTaskPlan,
        *,
        input_value: Any,
        upstream_results: Iterable[SchedulerTaskResult] = (),
    ) -> SchedulerTaskActivation:
        """Durably activate and dispatch one trusted host computation."""

        self._require_active_task(task)
        if task.task_kind is SchedulerTaskKind.MODEL_REQUEST:
            raise ValueError("model requests must activate through the provider lifecycle")
        upstream = tuple(sorted({item.result_sha256 for item in upstream_results}))
        if task.task_kind is SchedulerTaskKind.EMPTY_COMPLETION:
            workset = self.active_plan.candidate_workset
            if workset is None:
                raise ValueError("explicit-empty task lacks a bound candidate workset")
            required_upstream = (workset.source_result_sha256,)
            if upstream and upstream != required_upstream:
                raise ValueError("explicit-empty activation differs from pass-four source result")
            upstream = required_upstream
        actual_input_sha256 = scheduler_canonical_sha256(input_value)
        activation = self._activations.get(task.task_id)
        if activation is None:
            activation = self.journal.activate_task(
                task.task_id,
                actual_input_sha256=actual_input_sha256,
                upstream_task_result_sha256s=upstream,
            )
            self._activations[task.task_id] = activation
        else:
            expected = SchedulerTaskActivation.build(
                plan=self.active_plan,
                task=task,
                actual_input_sha256=actual_input_sha256,
                upstream_task_result_sha256s=upstream,
            )
            if activation != expected or task.task_id not in self.journal.dispatchable_task_ids:
                raise ValueError("resumed host task differs from its durable activation")
        self.journal.mark_dispatched(task.task_id)
        return activation

    def record_model_success(
        self,
        task: SchedulerTaskPlan,
        *,
        output_value: Any,
        usage_records: list[UsageRecord],
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        model_surface_review_requests: Iterable[ModelSurfaceReviewRequest] = (),
        model_surface_review_artifact: ModelSurfaceReviewArtifact | None = None,
        accepted_candidates: Iterable[CandidateFinding] = (),
    ) -> SchedulerTaskResult:
        self._require_active_task(task)
        activation = self._activation(task)
        exact = [record for record in usage_records if record.request_id == task.logical_request_id]
        privacy_custody = self.journal.manifest.privacy_evidence_custody
        valid = [
            record
            for record in exact
            if is_creditable_usage_record(record)
            and privacy_custody is not None
            and record.routing.get("privacy_source_sha256") == privacy_custody.source_sha256
            and record.routing.get("effective_privacy_policy_sha256")
            == privacy_custody.effective_policy_evidence_sha256
            and record.routing.get("privacy_source_provenance_sha256")
            == privacy_custody.source_provenance_evidence_sha256
            and record.role == task.role
            and record.requested_model == task.requested_model
            and record.returned_model == task.requested_model
            and record.actual_model == task.requested_model
            and not record.fallback_used
            and not record.substitution_detected
            and record.prompt_sha256 == activation.provider_prompt_sha256
            and record.user_prompt_sha256 == activation.user_prompt_sha256
            and record.schema_sha256 == activation.response_schema_sha256
            and record.validated_response_sha256 is not None
        ]
        if len(exact) != 1 or len(valid) != 1:
            attempt = self._persist_accountable_provider_attempt(task, exact)
            return self._record_result(
                task,
                terminal_status=SchedulerTerminalStatus.UNBOUND,
                terminal_evidence_sha256=(
                    attempt.attempt_evidence_sha256
                    if attempt is not None
                    else scheduler_canonical_sha256(
                        {
                            "classification": "model_result_not_exactly_bound",
                            "exact_usage_records": len(exact),
                            "valid_usage_records": len(valid),
                        }
                    )
                ),
            )
        usage = valid[0]
        assert usage.validated_response_sha256 is not None
        try:
            return self._record_result(
                task,
                terminal_status=SchedulerTerminalStatus.SUCCEEDED,
                terminal_evidence_sha256=usage.validated_response_sha256,
                output_value=output_value,
                usage_record=usage,
                specialist_accepted_outcome=specialist_accepted_outcome,
                model_surface_review_requests=model_surface_review_requests,
                model_surface_review_artifact=model_surface_review_artifact,
                accepted_candidates=accepted_candidates,
            )
        except ValueError:
            attempt = self._persist_accountable_provider_attempt(task, (usage,))
            return self._record_result(
                task,
                terminal_status=SchedulerTerminalStatus.INVALID,
                terminal_evidence_sha256=(
                    attempt.attempt_evidence_sha256
                    if attempt is not None
                    else scheduler_canonical_sha256(
                        {
                            "classification": "model_output_not_substantively_creditable",
                            "validated_response_sha256": usage.validated_response_sha256,
                            "response_schema_sha256": usage.schema_sha256,
                        }
                    )
                ),
            )

    def record_failure(
        self,
        task: SchedulerTaskPlan,
        error: BaseException,
        *,
        usage_records: Iterable[UsageRecord] = (),
    ) -> SchedulerTaskResult:
        self._require_active_task(task)
        if isinstance(error, OpenRouterTruncatedResponseError):
            status = SchedulerTerminalStatus.TRUNCATED
        elif isinstance(error, OpenRouterUnboundIdentityError):
            status = SchedulerTerminalStatus.UNBOUND
        elif isinstance(error, OpenRouterSchemaError):
            status = SchedulerTerminalStatus.INVALID
        elif isinstance(error, BudgetExhaustedError):
            status = SchedulerTerminalStatus.INCONCLUSIVE
        else:
            status = SchedulerTerminalStatus.FAILED
        evidence_sha256 = scheduler_canonical_sha256(
            {
                "classification": "scheduled_task_exception",
                "exception_type": f"{type(error).__module__}.{type(error).__qualname__}",
            }
        )
        if task.task_id not in self._activations:
            result = SchedulerTaskResult.build_preflight_failure(
                plan=self.active_plan,
                task=task,
                terminal_status=status,
                terminal_evidence_sha256=evidence_sha256,
            )
            self.journal.record_preflight_failure(result)
            return result
        if task.task_id in self.journal.dispatchable_task_ids:
            result = SchedulerTaskResult.build(
                plan=self.active_plan,
                task=task,
                activation=self._activation(task),
                terminal_status=status,
                terminal_evidence_sha256=evidence_sha256,
            )
            self.journal.record_activated_preflight_failure(result)
            return result
        attempt = self._persist_accountable_provider_attempt(task, usage_records)
        if attempt is not None:
            evidence_sha256 = attempt.attempt_evidence_sha256
        return self._record_result(
            task,
            terminal_status=status,
            terminal_evidence_sha256=evidence_sha256,
        )

    def record_host_success(
        self,
        task: SchedulerTaskPlan,
        *,
        output_value: Any,
    ) -> SchedulerTaskResult:
        self._require_active_task(task)
        return self._record_result(
            task,
            terminal_status=SchedulerTerminalStatus.SUCCEEDED,
            terminal_evidence_sha256=scheduler_canonical_sha256(
                {
                    "classification": "host_computation_completed",
                    "output_sha256": scheduler_canonical_sha256(output_value),
                }
            ),
            output_value=output_value,
        )

    def record_empty(self, task: SchedulerTaskPlan) -> SchedulerTaskResult:
        self._require_active_task(task)
        if task.task_kind is not SchedulerTaskKind.EMPTY_COMPLETION:
            raise ValueError("only an explicit-empty task may record empty completion")
        return self._record_result(
            task,
            terminal_status=SchedulerTerminalStatus.EXPLICIT_EMPTY,
            terminal_evidence_sha256=task.input_sha256,
        )

    def seal_pass_result(self) -> SchedulerPassResult:
        plan = self.active_plan
        result = self.journal.seal_pass_result(plan.pass_kind)
        self._active_plan = None
        return result

    def artifact(self) -> SchedulerArtifact:
        return self.journal.artifact()

    def report_binding(self) -> SchedulerReportBinding:
        return SchedulerReportBinding.from_artifact(self.artifact())

    def require_complete(self) -> None:
        self.journal.require_complete()

    def close(self) -> None:
        self.journal.close()

    def _record_result(
        self,
        task: SchedulerTaskPlan,
        *,
        terminal_status: SchedulerTerminalStatus,
        terminal_evidence_sha256: str,
        output_value: Any | None = None,
        usage_record: UsageRecord | None = None,
        specialist_accepted_outcome: SpecialistAcceptedOutcome | None = None,
        model_surface_review_requests: Iterable[ModelSurfaceReviewRequest] = (),
        model_surface_review_artifact: ModelSurfaceReviewArtifact | None = None,
        accepted_candidates: Iterable[CandidateFinding] = (),
    ) -> SchedulerTaskResult:
        output = (
            self.journal.persist_output(
                task.task_id,
                output_value,
                usage_record=usage_record,
                specialist_accepted_outcome=specialist_accepted_outcome,
                model_surface_review_requests=model_surface_review_requests,
                model_surface_review_artifact=model_surface_review_artifact,
                accepted_candidates=accepted_candidates,
            )
            if terminal_status is SchedulerTerminalStatus.SUCCEEDED
            else None
        )
        result = SchedulerTaskResult.build(
            plan=self.active_plan,
            task=task,
            activation=self._activation(task),
            terminal_status=terminal_status,
            terminal_evidence_sha256=terminal_evidence_sha256,
            output=output,
        )
        self.journal.record_terminal(result)
        return result

    def _persist_accountable_provider_attempt(
        self,
        task: SchedulerTaskPlan,
        records: Iterable[UsageRecord],
    ) -> SchedulerProviderAttemptEvidence | None:
        """Retain one exact paid attempt without granting successful-review credit."""

        if task.task_id in self.journal.dispatchable_task_ids:
            return None
        exact = tuple(record for record in records if record.request_id == task.logical_request_id)
        if len(exact) != 1 or not is_accountable_usage_record(exact[0]):
            return None
        return self.journal.persist_provider_attempt(task.task_id, exact[0])

    def _require_active_task(self, task: SchedulerTaskPlan) -> None:
        if task not in self.active_plan.tasks:
            raise ValueError("scheduler task is outside the active sealed pass")

    def _activation(self, task: SchedulerTaskPlan) -> SchedulerTaskActivation:
        self._require_active_task(task)
        activation = self._activations.get(task.task_id)
        if activation is None:
            raise ValueError("scheduler task lacks exact activation evidence")
        return activation


def scheduler_input_sha256(value: Any) -> str:
    """Expose the canonical scheduler input commitment for pipeline call sites."""

    return scheduler_canonical_sha256(value)
