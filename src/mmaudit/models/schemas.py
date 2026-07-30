"""Strict schemas shared by scanners, model roles, and reporters."""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from itertools import pairwise
from typing import Any, Literal, Self

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
)

from mmaudit.constants import (
    ANALYSIS_ROLES,
    SPECIALIST_INVESTIGATOR_ROLES,
)
from mmaudit.models.identity import OpenRouterIdentityStrength
from mmaudit.models.output_modes import (
    STRUCTURED_OUTPUT_PROTOCOL_VERSION,
    StructuredOutputMode,
    mode_for_supported_parameters,
    output_mode_request_parameters,
)
from mmaudit.models.structured_output import StructuredOutputRepairEvidence
from mmaudit.models.token_planning import (
    CONTEXT_OMISSION_GROUP_CAP,
    UTF8_BYTES_PER_ESTIMATED_TOKEN,
    ContextOmissionItem,
    ContextOmissionNoticeLevel,
)


class StrictModel(BaseModel):
    """Base model that rejects unknown fields in security-sensitive data."""

    model_config = ConfigDict(extra="forbid")


class StructuredOutputResponseFormat(StrEnum):
    """Exact provider request encoding used for one structured response."""

    JSON_SCHEMA = "json_schema"
    JSON_OBJECT = "json_object"
    OMITTED = "omitted"


class StructuredOutputEvidence(StrictModel):
    """Self-hashed output negotiation and validation evidence.

    The record contains hashes and routing metadata only. Raw provider content is
    deliberately excluded. A syntactically repaired response may be retained as
    non-creditable evidence, but repair can never satisfy review credit.
    """

    schema_version: Literal["1.0"] = "1.0"
    requested_mode: StructuredOutputMode
    achieved_mode: StructuredOutputMode
    configured_provider_endpoints: tuple[str, ...] = Field(max_length=100)
    selected_provider_endpoint: str = Field(min_length=1, max_length=500)
    endpoint_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint_structured_output_parameters: tuple[str, ...] = Field(max_length=3)
    output_capability_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_body_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    provider_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    decoded_response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    validated_response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_format: StructuredOutputResponseFormat
    required_provider_parameters: tuple[str, ...] = Field(max_length=16)
    provider_require_parameters: bool
    reasoning_request_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    request_shape_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    strict_protocol_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    strict_parser: Literal["MMAUDIT_STRICT_JSON_V1"] = "MMAUDIT_STRICT_JSON_V1"
    truncated: Literal[False] = False
    repair_evidence: StructuredOutputRepairEvidence | None = None
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("configured_provider_endpoints")
    @classmethod
    def provider_endpoints_are_unique_and_safe(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if (
            not value
            or len(value) != len(set(value))
            or any(
                not endpoint
                or len(endpoint) > 500
                or any(ord(character) < 33 or ord(character) == 127 for character in endpoint)
                for endpoint in value
            )
        ):
            raise ValueError("structured-output provider endpoints must be non-empty and unique")
        return value

    @field_validator("endpoint_structured_output_parameters")
    @classmethod
    def capability_parameters_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        allowed = {"json_schema", "response_format", "structured_outputs"}
        if value != tuple(sorted(set(value))) or not set(value).issubset(allowed):
            raise ValueError("structured-output capability parameters are not canonical")
        return value

    @field_validator("required_provider_parameters")
    @classmethod
    def required_provider_parameters_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        allowed = {"reasoning", "response_format"}
        if value != tuple(sorted(set(value))) or not set(value).issubset(allowed):
            raise ValueError("required provider parameters are not canonical")
        return value

    @model_validator(mode="after")
    def negotiation_and_hashes_are_consistent(self) -> StructuredOutputEvidence:
        if self.selected_provider_endpoint not in self.configured_provider_endpoints:
            raise ValueError("selected structured-output endpoint was not configured")
        if self.requested_mode is not self.achieved_mode:
            raise ValueError("achieved structured-output mode differs from the requested mode")
        if self.requested_mode is not mode_for_supported_parameters(
            self.endpoint_structured_output_parameters
        ):
            raise ValueError("structured-output mode differs from endpoint capability evidence")

        if self.requested_mode is StructuredOutputMode.NATIVE_JSON_SCHEMA:
            expected_format = StructuredOutputResponseFormat.JSON_SCHEMA
            protocol_required = False
        elif self.requested_mode is StructuredOutputMode.JSON_OBJECT:
            expected_format = StructuredOutputResponseFormat.JSON_OBJECT
            protocol_required = True
        else:
            expected_format = StructuredOutputResponseFormat.OMITTED
            protocol_required = True
        required_parameters = set(self.required_provider_parameters)
        expected_output_parameters = set(output_mode_request_parameters(self.requested_mode))
        if required_parameters.intersection({"response_format"}) != expected_output_parameters or (
            "reasoning" in required_parameters
        ) is not (self.reasoning_request_sha256 is not None):
            raise ValueError("structured-output request parameters differ from its emitted request")
        if (
            self.response_format is not expected_format
            or self.provider_require_parameters is not bool(required_parameters)
            or (self.strict_protocol_sha256 is not None) is not protocol_required
        ):
            raise ValueError("structured-output request encoding differs from its mode")
        if self.request_shape_sha256 != structured_output_request_shape_sha256(
            mode=self.requested_mode,
            schema_sha256=self.schema_sha256,
            required_provider_parameters=self.required_provider_parameters,
            reasoning_request_sha256=self.reasoning_request_sha256,
            strict_protocol_sha256=self.strict_protocol_sha256,
        ):
            raise ValueError("structured-output request-shape hash is inconsistent")

        repair = self.repair_evidence
        if repair is None:
            if self.original_response_sha256 != self.decoded_response_sha256:
                raise ValueError("unrepaired structured output changed before validation")
        elif (
            repair.original_response_sha256 != self.original_response_sha256
            or repair.repaired_response_sha256 != self.decoded_response_sha256
        ):
            raise ValueError("structured-output repair evidence does not bind response hashes")

        expected_evidence = _canonical_model_sha256(
            self.model_dump(mode="json", exclude={"evidence_sha256"})
        )
        if self.evidence_sha256 != expected_evidence:
            raise ValueError("structured-output evidence hash is inconsistent")
        return self

    @property
    def repair_used(self) -> bool:
        """Return whether local syntax-envelope repair was required."""

        return self.repair_evidence is not None


def seal_structured_output_evidence(
    *,
    requested_mode: StructuredOutputMode,
    achieved_mode: StructuredOutputMode,
    configured_provider_endpoints: tuple[str, ...],
    selected_provider_endpoint: str,
    endpoint_snapshot_sha256: str,
    output_capability_sha256: str,
    endpoint_structured_output_parameters: tuple[str, ...],
    prompt_sha256: str,
    request_body_sha256: str,
    provider_policy_sha256: str,
    schema_sha256: str,
    original_response_sha256: str,
    decoded_response_sha256: str,
    validated_response_sha256: str,
    response_format: StructuredOutputResponseFormat,
    required_provider_parameters: tuple[str, ...],
    provider_require_parameters: bool,
    reasoning_request_sha256: str | None,
    request_shape_sha256: str,
    strict_protocol_sha256: str | None,
    repair_evidence: StructuredOutputRepairEvidence | None,
) -> StructuredOutputEvidence:
    """Seal hash-only structured-output evidence after local schema validation."""

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "requested_mode": requested_mode.value,
        "achieved_mode": achieved_mode.value,
        "configured_provider_endpoints": list(configured_provider_endpoints),
        "selected_provider_endpoint": selected_provider_endpoint,
        "endpoint_snapshot_sha256": endpoint_snapshot_sha256,
        "endpoint_structured_output_parameters": list(endpoint_structured_output_parameters),
        "output_capability_sha256": output_capability_sha256,
        "prompt_sha256": prompt_sha256,
        "request_body_sha256": request_body_sha256,
        "provider_policy_sha256": provider_policy_sha256,
        "schema_sha256": schema_sha256,
        "original_response_sha256": original_response_sha256,
        "decoded_response_sha256": decoded_response_sha256,
        "validated_response_sha256": validated_response_sha256,
        "response_format": response_format.value,
        "required_provider_parameters": list(required_provider_parameters),
        "provider_require_parameters": provider_require_parameters,
        "reasoning_request_sha256": reasoning_request_sha256,
        "request_shape_sha256": request_shape_sha256,
        "strict_protocol_sha256": strict_protocol_sha256,
        "strict_parser": "MMAUDIT_STRICT_JSON_V1",
        "truncated": False,
        "repair_evidence": (
            repair_evidence.model_dump(mode="json") if repair_evidence is not None else None
        ),
    }
    payload["evidence_sha256"] = _canonical_model_sha256(payload)
    return StructuredOutputEvidence.model_validate(payload)


def structured_output_request_shape_sha256(
    *,
    mode: StructuredOutputMode,
    schema_sha256: str,
    required_provider_parameters: tuple[str, ...],
    reasoning_request_sha256: str | None,
    strict_protocol_sha256: str | None,
) -> str:
    """Hash the exact special-parameter shape without retaining a raw schema."""

    response_format = (
        StructuredOutputResponseFormat.JSON_SCHEMA.value
        if mode is StructuredOutputMode.NATIVE_JSON_SCHEMA
        else (
            StructuredOutputResponseFormat.JSON_OBJECT.value
            if mode is StructuredOutputMode.JSON_OBJECT
            else None
        )
    )
    return _canonical_model_sha256(
        {
            "mode": mode.value,
            "protocol": STRUCTURED_OUTPUT_PROTOCOL_VERSION,
            "reasoning_request_sha256": reasoning_request_sha256,
            "required_provider_parameters": list(required_provider_parameters),
            "require_parameters": bool(required_provider_parameters),
            "response_format": response_format,
            "schema_sha256": schema_sha256,
            "strict_protocol_sha256": strict_protocol_sha256,
        }
    )


def _canonical_model_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256 = _canonical_model_sha256(
    {
        "domain": "mmaudit.repository-suite-workspace-copy-policy.v3",
        "bounded_no_follow_inventory": True,
        "direct_child_workspace": True,
        "exclusive_creation": True,
        "source_descriptor_custody": True,
        "workspace_descriptor_custody": True,
        "workspace_parent_descriptor_custody": True,
        "workspace_parent_attempt_identity_join": True,
        "pre_post_root_identity_validation": True,
        "pre_post_inventory_validation": True,
    }
)
REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT = 250_000
REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT = 128
REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS = 5.0
REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_ENTRY_MINIMUM = 2
REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_DEPTH_MINIMUM = 1
REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256 = _canonical_model_sha256(
    {
        "domain": "mmaudit.repository-suite-workspace-disposal-policy.v3",
        "descriptor_relative_no_follow_removal": True,
        "aggregate_lifecycle_budget": True,
        "entry_limit": REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT,
        "depth_limit": REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT,
        "monotonic_timeout_seconds": REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
        "validated_minimum_removed_entries": (
            REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_ENTRY_MINIMUM
        ),
        "validated_minimum_removed_depth": (
            REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_DEPTH_MINIMUM
        ),
        "exact_root_identity_required": True,
        "descriptor_close_required": True,
        "workspace_absence_required": True,
        "attempt_root_absence_required": True,
        "private_path_retention_prohibited": True,
        "rpc_endpoint_retention_prohibited": True,
    }
)


class Severity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(StrEnum):
    CONFIRMED = "confirmed"
    STRONGLY_SUPPORTED = "strongly_supported"
    HIGH_CONFIDENCE = "high_confidence"
    PLAUSIBLE = "plausible"
    NEEDS_REVIEW = "needs_review"
    INFORMATIONAL = "informational"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    UNSUPPORTED = "unsupported"
    REJECTED = "rejected"


class CandidateOriginKind(StrEnum):
    """Trusted origin of a candidate before consensus and adjudication."""

    MODEL_REVIEW = "model_review"
    DETERMINISTIC_EXECUTION = "deterministic_execution"


class FindingOriginKind(StrEnum):
    """Trusted discovery origin retained on a normalized finding."""

    MODEL_REVIEW = "model_review"
    DETERMINISTIC_EXECUTION = "deterministic_execution"
    STATIC_ANALYZER = "static_analyzer"


class AuditProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    MAXIMUM_ASSURANCE = "maximum-assurance"


class AuditScope(StrEnum):
    CONTRACTS_ONLY = "contracts-only"
    CONTRACTS_AND_DEPLOYMENT = "contracts-and-deployment"
    FULL_PROTOCOL = "full-protocol"


class ScopeComponent(StrEnum):
    CONTRACTS = "contracts"
    DEPLOYMENT = "deployment"
    DOCUMENTATION = "documentation"
    OFFCHAIN = "offchain"
    TESTS = "tests"


class ScopeEvidenceStatus(StrEnum):
    ANALYZED = "analyzed"
    MISSING = "missing"
    OMITTED = "omitted"


class PriorAuditPreviousState(StrEnum):
    OPEN = "open"
    REMEDIATED = "remediated"


class PriorAuditDiscoveryStatus(StrEnum):
    REDISCOVERED = "rediscovered"
    MISSED = "missed"
    INCONCLUSIVE = "inconclusive"


class PriorAuditRemediationStatus(StrEnum):
    UNRESOLVED = "unresolved"
    REMEDIATED = "remediated"
    REGRESSED = "regressed"
    CHANGED_UNVERIFIED = "changed_unverified"
    INCONCLUSIVE = "inconclusive"


class AuditQualityStatus(StrEnum):
    COMPLETED = "completed"
    COMPLETED_WITH_LIMITATIONS = "completed_with_limitations"
    INCOMPLETE = "incomplete"
    FAILED = "failed"
    ENVIRONMENT_UNSAFE = "environment_unsafe"
    TARGET_UNSUPPORTED = "target_unsupported"


class AuditRunStatus(StrEnum):
    """Evidence-derived terminal state for an audit run."""

    COMPLETE = "COMPLETE"
    DEGRADED = "DEGRADED"
    INCOMPLETE = "INCOMPLETE"
    FAILED = "FAILED"


class MaximumAssuranceStatus(StrEnum):
    """Public status for the maximum-assurance contract."""

    NOT_REQUESTED = "NOT_REQUESTED"
    COMPLETE = "COMPLETE"
    DOWNGRADED = "DOWNGRADED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalysisState(StrEnum):
    """Evidence-aware state used by engines and coverage reports."""

    NOT_ANALYZED = "not_analyzed"
    ATTEMPTED_FAILED = "attempted_but_failed"
    FALLBACK_PARSER = "analyzed_with_fallback_parser"
    MODEL_ONLY = "model_only"
    SCANNER_SUPPORTED = "scanner_supported"
    DETERMINISTIC = "deterministic"
    REPRODUCED = "reproduced"
    FORMALLY_PROVEN = "formally_proven"


class EvidenceStrength(StrEnum):
    NONE = "none"
    MODEL_INFERENCE = "model_inference"
    INDEPENDENT_MODEL_SUPPORT = "independent_model_support"
    VALIDATED_ATTACK_PATH = "validated_attack_path"
    DETERMINISTIC_ANALYZER = "deterministic_analyzer"
    DETERMINISTIC_EXECUTION_COUNTEREXAMPLE = "deterministic_execution_counterexample"
    LOCAL_FORK_REPRODUCTION = "local_fork_reproduction"
    MINIMIZED_LOCAL_FORK_REPRODUCTION = "minimized_local_fork_reproduction"
    FORMAL_COUNTEREXAMPLE = "formal_counterexample"


class ReproductionState(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    GENERATION_FAILED = "generation_failed"
    COMPILE_FAILED = "compile_failed"
    ENVIRONMENT_BLOCKED = "environment_blocked"
    NOT_REPRODUCED = "not_reproduced"
    PARTIALLY_REPRODUCED = "partially_reproduced"
    REPRODUCED = "reproduced"
    REPRODUCED_AND_MINIMIZED = "reproduced_and_minimized"
    FORMALLY_PROVEN = "formally_proven"
    DISPROVEN = "disproven"


class ReproductionResolutionKind(StrEnum):
    """Typed terminal adjudication for one high/critical candidate."""

    REPRODUCED = "reproduced"
    INCONCLUSIVE = "inconclusive"


class VerificationVerdict(StrEnum):
    VERIFIED = "verified"
    PLAUSIBLE = "plausible"
    REJECTED = "rejected"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class ScannerStatus(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"


class RepositoryTestExecutionStatus(StrEnum):
    """Terminal observation for one selected repository-owned test."""

    PASSED = "passed"
    FAILED = "failed"
    REVERTED = "reverted"
    ASSERTION_FAILED = "assertion_failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"
    INVALID_OUTPUT = "invalid_output"


class RepositoryExecutionStateKind(StrEnum):
    """Configured execution state in a repository-suite differential matrix."""

    CLEAN_LOCAL = "clean_local"
    PINNED_FORK = "pinned_fork"


class RepositoryExecutionStateObservationStatus(StrEnum):
    """Whether one configured state acquired a complete runtime identity."""

    OBSERVED = "observed"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


class RepositoryCleanListenerOwnershipKind(StrEnum):
    """Platform-specific proof that the clean-chain process owns its listener."""

    LINUX_PROC_SOCKET_INODE = "linux_proc_socket_inode"
    DARWIN_ROOT_OWNED_LSOF = "darwin_root_owned_lsof"


class RepositoryCleanRuntimeExecutableIdentityKind(StrEnum):
    """Platform-specific runtime executable identity proof."""

    LINUX_PROC_PID_EXE = "linux_proc_pid_exe"
    DARWIN_PROC_PIDPATH = "darwin_proc_pidpath"


class RepositoryCleanExecPathBindingKind(StrEnum):
    """Platform-specific binding between the trusted copy and executed image."""

    LINUX_INHERITED_FD = "linux_inherited_fd"
    DARWIN_PRIVATE_PATH_POST_SPAWN_HASH = "darwin_private_path_post_spawn_hash"


class RepositoryForkEgressStatus(StrEnum):
    """Fail-closed status of the trusted read-only fork RPC boundary."""

    ENFORCED = "enforced"
    VIOLATION = "violation"
    UNVERIFIED = "unverified"


class RepositoryTestForkRpcScopeStatus(StrEnum):
    """Per-test disposition from one drained read-only RPC bridge scope."""

    VALIDATED = "validated"
    NOT_OBSERVED = "not_observed"
    VIOLATION = "violation"


class RepositorySuiteWorkspaceLifecycleStatus(StrEnum):
    """Whether one removed attempt workspace has complete creditable evidence."""

    VALIDATED = "validated"
    DISPOSED_UNCREDITED = "disposed_uncredited"


class RepositoryStateConsensusStatus(StrEnum):
    """Repeated-execution consensus for one test in one state."""

    CONSISTENT_PASS = "consistent_pass"
    CONSISTENT_FAILURE = "consistent_failure"
    INCONCLUSIVE = "inconclusive"


class RepositoryDifferentialClassification(StrEnum):
    """Typed clean-versus-pinned result for one selected repository test."""

    CONSISTENT_PASS = "consistent_pass"
    CONSISTENT_FAILURE = "consistent_failure"
    DIVERGED = "diverged"
    INCONCLUSIVE = "inconclusive"


class RepositoryDifferentialRunStatus(StrEnum):
    """Overall execution disposition for a configured differential matrix."""

    COMPLETE = "complete"
    INCONCLUSIVE = "inconclusive"
    FAILED = "failed"


class RepositoryDivergenceDirection(StrEnum):
    """Observed direction of a repeated semantic result divergence."""

    CLEAN_PASS_PINNED_FAILURE = "clean_pass_pinned_failure"
    CLEAN_FAILURE_PINNED_PASS = "clean_failure_pinned_pass"
    SEMANTIC_RESULT_CHANGED = "semantic_result_changed"


class RepositoryStateInconclusiveReason(StrEnum):
    """Typed reason repeated state execution cannot support a conclusion."""

    STATE_UNOBSERVED = "state_unobserved"
    SINGLE_OBSERVATION = "single_observation"
    ATTEMPT_UNAVAILABLE = "attempt_unavailable"
    NON_REAL_EVIDENCE = "non_real_evidence"
    UNISOLATED_EXECUTION = "unisolated_execution"
    EGRESS_UNENFORCED = "egress_unenforced"
    STATE_READ_UNPROVEN = "state_read_unproven"
    WORKSPACE_LIFECYCLE_UNPROVEN = "workspace_lifecycle_unproven"
    ATTEMPT_DISAGREEMENT = "attempt_disagreement"
    IDENTITY_MISMATCH = "identity_mismatch"
    INVALID_MACHINE_OUTPUT = "invalid_machine_output"


class ExecutionEvidenceKind(StrEnum):
    """Whether a runtime record came from a real process or a test double."""

    REAL = "real"
    MOCK = "mock"
    UNVERIFIED = "unverified"


class ModelRequestValidationStatus(StrEnum):
    """Fail-closed terminal validation state for one provider request."""

    NOT_VALIDATED = "not_validated"
    VALID = "valid"
    INVALID_RESPONSE = "invalid_response"
    TRUNCATED = "truncated"
    MODEL_MISMATCH = "model_mismatch"
    PROVIDER_MISMATCH = "provider_mismatch"
    PROVIDER_ERROR = "provider_error"


ModelIdentityStrength = OpenRouterIdentityStrength


class SolidityProjectType(StrEnum):
    FOUNDRY = "foundry"
    HARDHAT = "hardhat"
    MIXED = "mixed"
    PLAIN = "plain"


class RepositorySuiteFramework(StrEnum):
    """Supported repository-owned suite framework."""

    FOUNDRY = "foundry"
    HARDHAT = "hardhat"


class RepositorySuiteInventoryKind(StrEnum):
    """How a repository-owned test inventory was established."""

    STATIC_SOURCE = "static_source"
    ISOLATED_FOUNDRY_BUILD_INFO = "isolated_foundry_build_info"


class RepositorySuiteInventoryPhase(StrEnum):
    """When an isolated repository-suite inventory was observed."""

    PRE_EXECUTION = "pre_execution"
    POST_EXECUTION = "post_execution"


class RepositoryTestKind(StrEnum):
    """Machine-classified Foundry test campaign kind."""

    UNIT = "unit"
    FUZZ = "fuzz"
    INVARIANT = "invariant"


class CompilationStatus(StrEnum):
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    UNAVAILABLE = "unavailable"


class DependencyPreparationStatus(StrEnum):
    DISABLED = "disabled"
    NOT_APPLICABLE = "not_applicable"
    PREPARED = "prepared"
    REJECTED = "rejected"
    FAILED = "failed"


class DependencyScanStatus(StrEnum):
    NOT_RUN = "not_run"
    PASSED = "passed"
    FAILED = "failed"


class RepositoryCodeExecutionState(StrEnum):
    """Whether potentially executable repository configuration crossed isolation."""

    NOT_APPLICABLE = "not_applicable"
    DISABLED = "disabled"
    BLOCKED = "blocked"
    ISOLATED = "isolated"


class SolidityProvenance(StrEnum):
    COMPILER = "compiler"
    FALLBACK = "fallback"
    STATIC_TOOL = "static_tool"
    HEURISTIC = "heuristic"
    MODEL_SUGGESTED = "model_suggested"


class CoverageProvenance(StrEnum):
    """Origin of a coverage count, exclusion, or failure observation."""

    DISCOVERY = "discovery"
    CONFIGURATION = "configuration"
    COMPILER = "compiler"
    SYMBOL_INDEX = "symbol_index"
    SEMANTIC_GRAPH = "semantic_graph"
    STATIC_TOOL = "static_tool"
    MODEL_CONTEXT = "model_context"
    MODEL_REVIEW = "model_review"
    INVARIANT_EXECUTION = "invariant_execution"
    FORMAL_ENGINE = "formal_engine"
    RUNTIME = "runtime"


class SolidityGraphKind(StrEnum):
    INHERITANCE = "inheritance"
    MODIFIER = "modifier"
    INTERNAL_CALL = "internal_call"
    EXTERNAL_CALL = "external_call"
    LOW_LEVEL_CALL = "low_level_call"
    DELEGATECALL = "delegatecall"
    CONTRACT_CREATION = "contract_creation"
    STATE_READ = "state_read"
    STATE_WRITE = "state_write"
    STATE_DEPENDENCY = "state_dependency"
    ASSET_FLOW = "asset_flow"
    PRIVILEGE = "privilege"
    GOVERNANCE = "governance"
    DEPENDENCY = "dependency"
    PROXY = "proxy"
    STORAGE_LAYOUT = "storage_layout"
    UPGRADE_COMPATIBILITY = "upgrade_compatibility"
    INITIALIZER = "initializer"
    ORACLE_DEPENDENCY = "oracle_dependency"
    EVENT_STATE = "event_state"
    EVENT_FLOW = "event_flow"
    CROSS_CHAIN = "cross_chain"
    OFFCHAIN_DEPENDENCY = "offchain_dependency"
    SIGNATURE_REPLAY = "signature_replay"
    REENTRANCY = "reentrancy"
    STATE_GROWTH = "state_growth"
    SENSITIVE_REACHABILITY = "sensitive_reachability"


class SolidityGraphNodeKind(StrEnum):
    ENTITY = "entity"
    EXTERNAL_TARGET = "external_target"
    STATE_VARIABLE = "state_variable"
    ROLE = "role"
    ASSET = "asset"
    STORAGE_SLOT = "storage_slot"
    PROXY = "proxy"
    ORACLE = "oracle"
    GOVERNANCE = "governance"
    MESSAGE = "message"
    OFFCHAIN_ACTOR = "offchain_actor"
    SIGNATURE_DOMAIN = "signature_domain"
    UNKNOWN = "unknown"


class SolidityEntityKind(StrEnum):
    CONTRACT = "contract"
    INTERFACE = "interface"
    LIBRARY = "library"
    FUNCTION = "function"
    CONSTRUCTOR = "constructor"
    MODIFIER = "modifier"
    EVENT = "event"
    ERROR = "error"
    STRUCT = "struct"
    ENUM = "enum"
    STATE_VARIABLE = "state_variable"
    IMMUTABLE = "immutable"
    CONSTANT = "constant"


class ModelReviewSurfaceKind(StrEnum):
    """Deterministic Solidity surface categories tracked across model contexts."""

    CONTRACT = "contract"
    ENTRY_POINT = "entry_point"
    PRIVILEGE_FUNCTION = "privilege_function"
    ASSET_FUNCTION = "asset_function"
    CALL = "call"
    STATE = "state"
    INVARIANT = "invariant"
    TEMPLATE = "template"


class InvariantCategory(StrEnum):
    ACCOUNTING = "accounting"
    AUTHORIZATION = "authorization"
    TOKEN_STANDARD = "token_standard"
    STATE_MACHINE = "state_machine"
    ECONOMIC = "economic"


class InvariantTemplate(StrEnum):
    CONSERVATION_OF_BALANCES = "conservation_of_balances"
    OBSERVED_ASSET_ACCOUNTING = "observed_asset_accounting"
    NO_FREE_MINT = "no_free_mint"
    CLAIM_ONCE = "claim_once"
    REWARD_INDEX_MONOTONIC = "reward_index_monotonic"
    DEBT_COLLATERAL_CONSISTENCY = "debt_collateral_consistency"
    AUTHORIZED_UPGRADE = "authorized_upgrade"
    AUTHORIZED_ADMIN_CHANGE = "authorized_admin_change"
    PAUSE_ENFORCEMENT = "pause_enforcement"
    INITIALIZE_ONCE = "initialize_once"
    ERC20_SUPPLY_BALANCE = "erc20_supply_balance"
    ERC4626_CONVERSION_SANITY = "erc4626_conversion_sanity"
    PERMIT_REPLAY_PROTECTION = "permit_replay_protection"
    FEE_BOUNDS = "fee_bounds"
    ROUNDING_BOUNDS = "rounding_bounds"
    ORACLE_MANIPULATION_RESISTANCE = "oracle_manipulation_resistance"
    ORACLE_GUARD_SANITY = "oracle_guard_sanity"
    GOVERNANCE_DELAY_SANITY = "governance_delay_sanity"
    UPGRADE_INITIALIZER_SANITY = "upgrade_initializer_sanity"
    MESSAGE_CONSUMPTION_ONCE = "message_consumption_once"
    CALLBACK_STATE_CONSISTENCY = "callback_state_consistency"
    STATE_GROWTH_BOUND = "state_growth_bound"
    ERC20_RETURN_HANDLING = "erc20_return_handling"
    DONATION_INFLATION_RESISTANCE = "donation_inflation_resistance"
    ORDERING_VALUE_BOUND = "ordering_value_bound"
    MULTI_STEP_STATE_CONSISTENCY = "multi_step_state_consistency"


class InvariantReviewVerdict(StrEnum):
    """Non-authoritative model review of a source-derived invariant."""

    SUPPORTED = "supported"
    NEEDS_REFINEMENT = "needs_refinement"
    UNSUPPORTED = "unsupported"
    INSUFFICIENT_CONTEXT = "insufficient_context"


class HarnessArgumentSource(StrEnum):
    CONSTANT = "constant"
    FUZZ_UINT = "fuzz_uint"
    ACTOR = "actor"


class InvariantRelation(StrEnum):
    EQ = "eq"
    GTE = "gte"
    LTE = "lte"


class InvariantExecutionStatus(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    GENERATION_FAILED = "generation_failed"
    ENVIRONMENT_BLOCKED = "environment_blocked"
    COMPILE_FAILED = "compile_failed"
    EXECUTION_FAILED = "execution_failed"
    TIMED_OUT = "timed_out"
    PASSED = "passed"
    COUNTEREXAMPLE = "counterexample"


class EconomicSimulationKind(StrEnum):
    ERC4626_DONATION = "erc4626_donation_inflation"
    REWARD_INDEX = "reward_index_manipulation"
    FLASH_ORACLE = "flash_loan_oracle_manipulation"
    ORACLE_GUARDS = "oracle_freshness_scale_availability"
    AMM_RESERVES = "amm_reserve_manipulation"
    LIQUIDATION = "liquidation_edge_cases"
    SHARE_PRICE = "share_price_exchange_rate"
    NON_STANDARD_TOKEN = "fee_on_transfer_rebasing_accounting"
    ROUNDING = "rounding_exploitation"
    GOVERNANCE_RACE = "governance_timelock_race"
    UPGRADE_INITIALIZER = "upgrade_initializer_misuse"
    CROSS_CHAIN_REPLAY = "cross_chain_duplicate_ordering"
    CALLBACK_REENTRANCY = "callback_receiver_reentrancy"
    BOUNDED_STATE_GROWTH = "bounded_state_growth"
    STATE_ORDERING = "multi_transaction_state_ordering"
    SANDWICH = "sandwich_sensitive_flow"
    SIGNATURE_REPLAY = "signature_nonce_domain_replay"


_SUPPORTED_ABI_TYPE = r"(?:uint256|int256|address|bool|bytes32|bytes|string)"


def _signature_argument_kinds(value: str) -> list[ForkArgumentKind]:
    match = re.fullmatch(
        rf"[A-Za-z_][A-Za-z0-9_]*\((?P<arguments>{_SUPPORTED_ABI_TYPE}"
        rf"(?:,{_SUPPORTED_ABI_TYPE})*)?\)",
        value,
    )
    if match is None:
        raise ValueError("function signature must use supported canonical ABI types")
    raw = match.group("arguments")
    return [] if not raw else [ForkArgumentKind(item) for item in raw.split(",")]


def _validation_argument_value(kind: ForkArgumentKind) -> str:
    return {
        ForkArgumentKind.UINT256: "0",
        ForkArgumentKind.INT256: "0",
        ForkArgumentKind.ADDRESS: "0x0000000000000000000000000000000000000001",
        ForkArgumentKind.BOOL: "false",
        ForkArgumentKind.BYTES32: "0x" + "00" * 32,
        ForkArgumentKind.BYTES: "0x",
        ForkArgumentKind.STRING: "",
    }[kind]


class FormalToolStatus(StrEnum):
    SUCCESS = "success"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    INCONCLUSIVE = "inconclusive"
    SKIPPED = "skipped"


class FormalResultKind(StrEnum):
    PROOF = "proof"
    COUNTEREXAMPLE = "counterexample"
    UNKNOWN = "unknown"
    NONE = "none"


class DynamicPropertyOutcome(StrEnum):
    COUNTEREXAMPLE = "counterexample"
    NO_COUNTEREXAMPLE = "no_counterexample_within_bounds"
    INCONCLUSIVE = "inconclusive"
    NOT_EXECUTED = "not_executed"


class Location(StrictModel):
    path: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str | None = None
    content_hash: str | None = None

    @model_validator(mode="after")
    def lines_are_ordered(self) -> Location:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class SourceSink(StrictModel):
    description: str = Field(min_length=1)
    path: str
    line: int = Field(ge=1)


class Evidence(StrictModel):
    type: Literal["model", "scanner", "execution", "reproduction", "formal", "repository"]
    source: str
    description: str = Field(min_length=1)
    rule_id: str | None = None
    fingerprint: str | None = None


class VerificationTest(StrictModel):
    type: Literal["local"] = "local"
    description: str = Field(min_length=1)
    safe: bool = True

    @field_validator("safe")
    @classmethod
    def must_be_safe(cls, value: bool) -> bool:
        if not value:
            raise ValueError("verification tests must be safe and local")
        return value


class InvariantExecutionCandidateProvenance(StrictModel):
    """Self-hashed origin evidence for one replayed deterministic counterexample."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    producer: Literal["foundry_invariant"] = "foundry_invariant"
    execution_evidence: Literal[ExecutionEvidenceKind.REAL] = ExecutionEvidenceKind.REAL
    invariant_id: str = Field(min_length=1, max_length=160)
    invariant_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    harness_name: str = Field(min_length=1, max_length=240)
    harness_spec_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    property_corpus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    property_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    property_hashes: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    execution_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1, max_length=1_000)
    compiler_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_backend: str = Field(min_length=1, max_length=160)
    isolation_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    replay_confirmed: Literal[True] = True
    attempts: int = Field(ge=2, le=10)
    successful_attempts: int = Field(ge=2, le=10)
    minimized: bool
    source_locations: tuple[Location, ...] = Field(min_length=1, max_length=100)
    provenance_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> InvariantExecutionCandidateProvenance:
        """Validate and self-hash one execution-origin candidate record."""

        if "provenance_sha256" in values:
            raise ValueError("provenance_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, provenance_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"provenance_sha256"})
        return cls.model_validate(
            {
                **payload,
                "provenance_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def execution_origin_is_canonical_and_hash_linked(
        self,
    ) -> InvariantExecutionCandidateProvenance:
        if self.property_ids != tuple(sorted(set(self.property_ids))):
            raise ValueError("execution provenance property IDs must be unique and sorted")
        if self.property_hashes != tuple(sorted(set(self.property_hashes))) or any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None for value in self.property_hashes
        ):
            raise ValueError("execution provenance property hashes must be unique and sorted")
        if len(self.property_ids) != len(self.property_hashes):
            raise ValueError("execution provenance property IDs and hashes must have equal length")
        if any(
            property_id != f"prop-{property_hash[:24]}"
            for property_id, property_hash in zip(
                self.property_ids,
                self.property_hashes,
                strict=True,
            )
        ):
            raise ValueError("execution provenance property IDs must derive from their hashes")
        if self.attempts != self.successful_attempts:
            raise ValueError("execution provenance requires every replay attempt to succeed")
        location_keys = [
            (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol or "",
                location.content_hash or "",
            )
            for location in self.source_locations
        ]
        if location_keys != sorted(set(location_keys)) or any(
            location.content_hash is None
            or re.fullmatch(r"[0-9a-f]{64}", location.content_hash) is None
            for location in self.source_locations
        ):
            raise ValueError(
                "execution provenance source locations must be unique, sorted, and content-hashed"
            )
        if self.provenance_sha256 != self.expected_provenance_sha256():
            raise ValueError("execution provenance hash does not match its typed contents")
        return self

    def expected_provenance_sha256(self) -> str:
        """Return the canonical hash of every non-derived provenance field."""

        payload = self.model_dump(mode="json", exclude={"provenance_sha256"})
        return _canonical_model_sha256(payload)


class ForkTestType(StrEnum):
    UNIT_EXPLOIT = "unit_exploit"
    BOUNDARY_VALUE = "boundary_value"
    AUTHORIZATION_MATRIX = "authorization_matrix"
    TRANSACTION_SEQUENCE = "transaction_sequence"
    ACCOUNTING_INVARIANT = "accounting_invariant"


class ForkArgumentKind(StrEnum):
    UINT256 = "uint256"
    INT256 = "int256"
    ADDRESS = "address"
    BOOL = "bool"
    BYTES32 = "bytes32"
    BYTES = "bytes"
    STRING = "string"


class ForkArgument(StrictModel):
    kind: ForkArgumentKind
    value: str = Field(min_length=1, max_length=4_096)


class AttackerCapability(StrEnum):
    STARTING_CAPITAL = "starting_capital"
    FLASH_LIQUIDITY = "flash_liquidity"
    TOKEN_APPROVAL = "token_approval"
    TIMING = "timing"
    TRANSACTION_ORDERING = "transaction_ordering"
    ORACLE_INFLUENCE = "oracle_influence"
    GOVERNANCE_RIGHTS = "governance_rights"
    PRIVILEGED_ROLE = "privileged_role"
    CROSS_CHAIN_MESSAGE = "cross_chain_message"


class TransactionOrderingCapability(StrEnum):
    NONE = "none"
    SAME_BLOCK = "same_block"
    MULTI_TRANSACTION = "multi_transaction"


class OracleInfluenceCapability(StrEnum):
    NONE = "none"
    BOUNDED_MARKET = "bounded_market"
    FIXTURE_CONFIGURED = "fixture_configured"


class CrossChainMessageCapability(StrEnum):
    NONE = "none"
    VALID_MESSAGE = "valid_message"
    REORDER_VALID_MESSAGES = "reorder_valid_messages"


class AttackerCapabilityPolicy(StrictModel):
    """Explicit capability envelope for the attack phase of a reproduction."""

    attacker_controlled_actors: list[str] = Field(min_length=1, max_length=16)
    attacker_controlled_contracts: list[str] = Field(default_factory=list, max_length=16)
    starting_native_capital_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    flash_liquidity_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    token_approval_targets: list[str] = Field(default_factory=list, max_length=32)
    max_time_shift_seconds: int = Field(default=0, ge=0, le=31_536_000)
    max_block_advance: int = Field(default=0, ge=0, le=10_000_000)
    transaction_ordering: TransactionOrderingCapability = TransactionOrderingCapability.NONE
    oracle_influence: OracleInfluenceCapability = OracleInfluenceCapability.NONE
    governance_rights: bool = False
    privileged_roles: list[str] = Field(default_factory=list, max_length=16)
    cross_chain_messages: CrossChainMessageCapability = CrossChainMessageCapability.NONE
    capability_justifications: dict[AttackerCapability, str] = Field(
        default_factory=dict,
        max_length=9,
    )

    @field_validator(
        "attacker_controlled_actors",
        "attacker_controlled_contracts",
        "token_approval_targets",
        "privileged_roles",
    )
    @classmethod
    def identifiers_are_safe_and_unique(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("capability policy identifiers must be unique")
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", item) for item in value):
            raise ValueError("capability policy identifiers must be safe names")
        return value

    @field_validator("capability_justifications")
    @classmethod
    def justifications_are_bounded(
        cls,
        value: dict[AttackerCapability, str],
    ) -> dict[AttackerCapability, str]:
        if any(not text.strip() or len(text) > 1_000 for text in value.values()):
            raise ValueError("capability justifications must contain 1-1000 characters")
        return value

    @model_validator(mode="after")
    def active_capabilities_are_justified(self) -> AttackerCapabilityPolicy:
        active = self.enabled_capabilities()
        declared = set(self.capability_justifications)
        missing = active - declared
        unused = declared - active
        if missing:
            raise ValueError(
                "active attacker capabilities lack justification: "
                + ", ".join(sorted(item.value for item in missing))
            )
        if unused:
            raise ValueError(
                "capability justifications were supplied for inactive capabilities: "
                + ", ".join(sorted(item.value for item in unused))
            )
        return self

    def enabled_capabilities(self) -> set[AttackerCapability]:
        """Return capabilities granted by this declarative policy."""

        enabled: set[AttackerCapability] = set()
        if self.starting_native_capital_wei:
            enabled.add(AttackerCapability.STARTING_CAPITAL)
        if self.flash_liquidity_wei:
            enabled.add(AttackerCapability.FLASH_LIQUIDITY)
        if self.token_approval_targets:
            enabled.add(AttackerCapability.TOKEN_APPROVAL)
        if self.max_time_shift_seconds or self.max_block_advance:
            enabled.add(AttackerCapability.TIMING)
        if self.transaction_ordering is not TransactionOrderingCapability.NONE:
            enabled.add(AttackerCapability.TRANSACTION_ORDERING)
        if self.oracle_influence is not OracleInfluenceCapability.NONE:
            enabled.add(AttackerCapability.ORACLE_INFLUENCE)
        if self.governance_rights:
            enabled.add(AttackerCapability.GOVERNANCE_RIGHTS)
        if self.privileged_roles:
            enabled.add(AttackerCapability.PRIVILEGED_ROLE)
        if self.cross_chain_messages is not CrossChainMessageCapability.NONE:
            enabled.add(AttackerCapability.CROSS_CHAIN_MESSAGE)
        return enabled


class ForkActor(StrictModel):
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    address: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    initial_native_balance_wei: int = Field(default=0, ge=0, le=2**256 - 1)


class ForkExternalCallStep(StrictModel):
    """Fixed-shape external call shared by setup and attacker-reachable phases."""

    step_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    actor: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    target: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    function_signature: str = Field(min_length=3, max_length=256)
    arguments: list[ForkArgument] = Field(default_factory=list, max_length=24)
    value_wei: int = Field(default=0, ge=0, le=2**256 - 1)

    @field_validator("function_signature")
    @classmethod
    def signature_is_declarative(cls, value: str) -> str:
        if not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*\((?:(?:uint256|int256|address|bool|bytes32|bytes|string)"
            r"(?:,(?:uint256|int256|address|bool|bytes32|bytes|string))*)?\)",
            value,
        ):
            raise ValueError("function_signature must use the supported canonical ABI types")
        return value

    @model_validator(mode="after")
    def argument_types_match_signature(self) -> ForkExternalCallStep:
        raw_types = self.function_signature.split("(", 1)[1][:-1]
        expected = [] if not raw_types else raw_types.split(",")
        actual = [argument.kind.value for argument in self.arguments]
        if expected != actual:
            raise ValueError("arguments must exactly match function_signature ABI types")
        return self


class ForkSetupCallStep(ForkExternalCallStep):
    """Explicit setup-only external call; no arbitrary state mutation is representable."""


class ForkCallStep(ForkExternalCallStep):
    """Attacker-reachable external call constrained by the capability policy."""

    required_capabilities: list[AttackerCapability] = Field(
        default_factory=list,
        max_length=9,
    )

    @model_validator(mode="after")
    def capabilities_are_unique(self) -> ForkCallStep:
        if len(self.required_capabilities) != len(set(self.required_capabilities)):
            raise ValueError("required call capabilities must be unique")
        return self


class TokenBalanceSeed(StrictModel):
    """Deterministic ERC token balance seeding for isolated fork harness setup."""

    token: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    actor: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    amount: int = Field(gt=0, le=2**256 - 1)


class ForkAssertionKind(StrEnum):
    CALL_SUCCEEDS = "call_succeeds"
    CALL_REVERTS = "call_reverts"
    RETURN_UINT_GTE = "return_uint_gte"
    RETURN_BOOL_EQUALS = "return_bool_equals"
    NATIVE_BALANCE_GAIN_GTE = "native_balance_gain_gte"
    NATIVE_BALANCE_LOSS_GTE = "native_balance_loss_gte"


class ForkAssertion(StrictModel):
    kind: ForkAssertionKind
    step_id: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    address: str | None = Field(default=None, pattern=r"^0x[0-9a-fA-F]{40}$")
    expected_uint: int | None = Field(default=None, ge=0, le=2**256 - 1)
    expected_bool: bool | None = None

    @model_validator(mode="after")
    def required_operand_is_present(self) -> ForkAssertion:
        if (
            self.kind
            in {
                ForkAssertionKind.CALL_SUCCEEDS,
                ForkAssertionKind.CALL_REVERTS,
                ForkAssertionKind.RETURN_UINT_GTE,
                ForkAssertionKind.RETURN_BOOL_EQUALS,
            }
            and self.step_id is None
        ):
            raise ValueError(f"{self.kind.value} requires step_id")
        if (
            self.kind
            in {
                ForkAssertionKind.RETURN_UINT_GTE,
                ForkAssertionKind.NATIVE_BALANCE_GAIN_GTE,
                ForkAssertionKind.NATIVE_BALANCE_LOSS_GTE,
            }
            and self.expected_uint is None
        ):
            raise ValueError(f"{self.kind.value} requires expected_uint")
        if self.kind is ForkAssertionKind.RETURN_BOOL_EQUALS and self.expected_bool is None:
            raise ValueError("return_bool_equals requires expected_bool")
        if (
            self.kind
            in {
                ForkAssertionKind.NATIVE_BALANCE_GAIN_GTE,
                ForkAssertionKind.NATIVE_BALANCE_LOSS_GTE,
            }
            and self.address is None
        ):
            raise ValueError(f"{self.kind.value} requires address")
        return self


class FinancialAssetKind(StrEnum):
    NATIVE = "native"
    ERC20 = "erc20"


class FinancialSettlementEvidence(StrictModel):
    """Single-asset settled cashflow with exact base-unit arithmetic."""

    actor: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    asset_kind: FinancialAssetKind
    asset_target: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$",
    )
    unit: Literal["base_units"] = "base_units"
    starting_assets: int = Field(ge=0, le=2**256 - 1)
    borrowed_assets: int = Field(ge=0, le=2**256 - 1)
    repaid_assets: int = Field(ge=0, le=2**256 - 1)
    gross_assets_received: int = Field(ge=0, le=2**256 - 1)
    fees_paid: int = Field(ge=0, le=2**256 - 1)
    slippage_loss: int = Field(ge=0, le=2**256 - 1)
    ending_assets: int = Field(ge=0, le=2**256 - 1)
    net_impact: int = Field(ge=-(2**255), le=2**255 - 1)

    @model_validator(mode="after")
    def cashflow_is_settled_and_balanced(self) -> FinancialSettlementEvidence:
        if self.asset_kind is FinancialAssetKind.NATIVE and self.asset_target is not None:
            raise ValueError("native-asset settlement cannot declare an ERC20 target")
        if self.asset_kind is FinancialAssetKind.ERC20 and self.asset_target is None:
            raise ValueError("ERC20 settlement requires a configured asset target")
        if self.repaid_assets != self.borrowed_assets:
            raise ValueError("settled financial evidence requires full principal repayment")
        expected_ending = (
            self.starting_assets
            + self.borrowed_assets
            + self.gross_assets_received
            - self.repaid_assets
            - self.fees_paid
            - self.slippage_loss
        )
        if expected_ending < 0 or expected_ending >= 2**256:
            raise ValueError("financial settlement arithmetic is outside uint256 bounds")
        if self.ending_assets != expected_ending:
            raise ValueError("ending assets do not reconcile with the declared cashflow")
        if self.net_impact != self.ending_assets - self.starting_assets:
            raise ValueError("net impact must equal ending assets minus starting assets")
        return self


class LendingBoundaryEvidence(StrictModel):
    """Same-unit debt and collateral evidence for one healthy-position boundary."""

    unit: Literal["base_units"] = "base_units"
    debt_before: int = Field(ge=0, le=2**256 - 1)
    collateral_before: int = Field(ge=0, le=2**256 - 1)
    debt_after: int = Field(ge=0, le=2**256 - 1)
    collateral_after: int = Field(ge=0, le=2**256 - 1)
    collateral_seized: int = Field(ge=0, le=2**256 - 1)
    bad_debt_after: int = Field(ge=0, le=2**256 - 1)

    @model_validator(mode="after")
    def healthy_boundary_arithmetic_is_consistent(self) -> LendingBoundaryEvidence:
        if self.collateral_before < self.debt_before:
            raise ValueError("lending boundary evidence requires a healthy starting position")
        if self.debt_after > self.debt_before:
            raise ValueError("liquidation boundary cannot increase position debt")
        if self.collateral_after > self.collateral_before:
            raise ValueError("liquidation boundary cannot increase position collateral")
        if self.collateral_seized != self.collateral_before - self.collateral_after:
            raise ValueError("collateral seized does not match the observed position transition")
        expected_bad_debt = max(self.debt_after - self.collateral_after, 0)
        if self.bad_debt_after != expected_bad_debt:
            raise ValueError("bad debt does not match observed debt and collateral")
        return self


class SharePriceBoundaryEvidence(StrictModel):
    """Deterministic share-rate evidence that isolates legitimate yield."""

    unit: Literal["base_units"] = "base_units"
    rate_scale: int = Field(ge=1, le=2**256 - 1)
    total_assets_before: int = Field(ge=0, le=2**256 - 1)
    total_shares_before: int = Field(ge=1, le=2**256 - 1)
    legitimate_yield: int = Field(ge=0, le=2**256 - 1)
    expected_rate_after_yield: int = Field(ge=0, le=2**256 - 1)
    observed_rate_after: int = Field(ge=0, le=2**256 - 1)
    shares_redeemed: int = Field(ge=1, le=2**256 - 1)
    assets_redeemed: int = Field(ge=0, le=2**256 - 1)
    excess_assets: int = Field(ge=0, le=2**256 - 1)

    @model_validator(mode="after")
    def rate_and_redemption_arithmetic_is_consistent(self) -> SharePriceBoundaryEvidence:
        assets_after_yield = self.total_assets_before + self.legitimate_yield
        if assets_after_yield >= 2**256:
            raise ValueError("share-price yield arithmetic is outside uint256 bounds")
        expected_rate = assets_after_yield * self.rate_scale // self.total_shares_before
        if expected_rate != self.expected_rate_after_yield:
            raise ValueError("yield-adjusted share rate does not reconcile")
        expected_assets = self.shares_redeemed * self.expected_rate_after_yield // self.rate_scale
        observed_assets = self.shares_redeemed * self.observed_rate_after // self.rate_scale
        if observed_assets != self.assets_redeemed:
            raise ValueError("observed share redemption does not reconcile")
        if self.excess_assets != max(self.assets_redeemed - expected_assets, 0):
            raise ValueError("excess share redemption does not reconcile")
        return self


class GeneratedFoundryTestSpec(StrictModel):
    """Constrained model output translated deterministically into Solidity."""

    candidate_id: str = Field(min_length=1, max_length=160)
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    test_type: ForkTestType
    rationale: str = Field(min_length=1, max_length=4_000)
    actors: list[ForkActor] = Field(min_length=1, max_length=16)
    attacker_policy: AttackerCapabilityPolicy
    setup_calls: list[ForkSetupCallStep] = Field(default_factory=list, max_length=40)
    attack_calls: list[ForkCallStep] = Field(min_length=1, max_length=40)
    assertions: list[ForkAssertion] = Field(min_length=1, max_length=40)
    financial_settlement: FinancialSettlementEvidence | None = None
    assumptions: list[str] = Field(default_factory=list, max_length=40)
    required_block_number: int | None = Field(default=None, ge=0)
    expected_chain_id: int | None = Field(default=None, ge=1)
    generator_role: str = ""
    generator_model_family: str = ""

    @model_validator(mode="after")
    def references_are_internal(self) -> GeneratedFoundryTestSpec:
        actor_names = [actor.name for actor in self.actors]
        setup_step_ids = [step.step_id for step in self.setup_calls]
        attack_step_ids = [step.step_id for step in self.attack_calls]
        step_ids = [*setup_step_ids, *attack_step_ids]
        if len(actor_names) != len(set(actor_names)):
            raise ValueError("actor names must be unique")
        if len(step_ids) != len(set(step_ids)):
            raise ValueError("call step IDs must be unique")
        if any(
            step.actor not in set(actor_names) for step in [*self.setup_calls, *self.attack_calls]
        ):
            raise ValueError("every call must reference a declared actor")
        controlled = set(self.attacker_policy.attacker_controlled_actors)
        if not controlled <= set(actor_names):
            raise ValueError("attacker policy references undeclared actors")
        if any(step.actor not in controlled for step in self.attack_calls):
            raise ValueError("every attack call must use an attacker-controlled actor")
        granted = self.attacker_policy.enabled_capabilities()
        required = {
            capability for step in self.attack_calls for capability in step.required_capabilities
        }
        undeclared = required - granted
        if undeclared:
            raise ValueError(
                "attack calls require undeclared capabilities: "
                + ", ".join(sorted(item.value for item in undeclared))
            )
        actor_capital = sum(
            actor.initial_native_balance_wei for actor in self.actors if actor.name in controlled
        )
        if actor_capital > self.attacker_policy.starting_native_capital_wei:
            raise ValueError("attacker actor balances exceed declared starting capital")
        call_value = sum(step.value_wei for step in self.attack_calls)
        available = (
            self.attacker_policy.starting_native_capital_wei
            + self.attacker_policy.flash_liquidity_wei
        )
        if call_value > available:
            raise ValueError("attack call value exceeds declared capital and liquidity")
        if any(
            assertion.step_id is not None and assertion.step_id not in set(attack_step_ids)
            for assertion in self.assertions
        ):
            raise ValueError("assertions must reference attacker-reachable call steps")
        financial_capabilities = {
            AttackerCapability.STARTING_CAPITAL,
            AttackerCapability.FLASH_LIQUIDITY,
        }
        financial_reproduction = (
            bool(required & financial_capabilities)
            or any(step.value_wei for step in self.attack_calls)
            or any(
                assertion.kind
                in {
                    ForkAssertionKind.NATIVE_BALANCE_GAIN_GTE,
                    ForkAssertionKind.NATIVE_BALANCE_LOSS_GTE,
                }
                for assertion in self.assertions
            )
        )
        if financial_reproduction and self.financial_settlement is None:
            raise ValueError(
                "financial reproduction requires arithmetically settled impact evidence"
            )
        if self.financial_settlement is not None:
            settlement = self.financial_settlement
            if settlement.actor not in controlled:
                raise ValueError("financial settlement actor must be attacker-controlled")
            if (
                settlement.asset_kind is FinancialAssetKind.NATIVE
                and AttackerCapability.FLASH_LIQUIDITY in required
                and not (0 < settlement.borrowed_assets <= self.attacker_policy.flash_liquidity_wei)
            ):
                raise ValueError(
                    "native borrowed assets must fit the declared flash-liquidity capability"
                )
        return self


class GeneratedFoundryTestBatch(StrictModel):
    tests: list[GeneratedFoundryTestSpec] = Field(default_factory=list, max_length=100)


class FalsificationVerdict(StrEnum):
    ACCEPTED = "accepted"
    FALSIFIED = "falsified"
    INCONCLUSIVE = "inconclusive"
    UNSAFE = "unsafe"


class FalsificationDecision(StrictModel):
    candidate_id: str
    test_name: str
    verdict: FalsificationVerdict
    test_matches_claim: bool
    assumptions_validated: bool
    rationale: str
    contradictions: list[str] = Field(default_factory=list)


class FalsificationBatch(StrictModel):
    decisions: list[FalsificationDecision] = Field(default_factory=list)


class CandidateCrossExaminationVerdict(StrEnum):
    SUPPORTED = "supported"
    DISPUTED = "disputed"
    INCONCLUSIVE = "inconclusive"


class CandidateCrossExaminationResponseDecision(StrictModel):
    """An anonymized reviewer decision before local candidate-ID restoration."""

    candidate_ref: str = Field(pattern=r"^candidate-[0-9]{4}$")
    verdict: CandidateCrossExaminationVerdict
    rationale: str = Field(min_length=1, max_length=8_000)
    contradictions: list[str] = Field(default_factory=list, max_length=50)
    missing_evidence: list[str] = Field(default_factory=list, max_length=50)


class CandidateCrossExaminationResponse(StrictModel):
    decisions: list[CandidateCrossExaminationResponseDecision] = Field(
        default_factory=list,
        max_length=200,
    )


class CandidateCrossExaminationDecision(StrictModel):
    """Normalized multi-lineage dissent retained in the audit report."""

    candidate_id: str = Field(min_length=1)
    request_id: str = Field(min_length=1)
    reviewer_index: int = Field(ge=1, le=2)
    requested_model: str = Field(min_length=1)
    returned_model: str | None = None
    root_lineage: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    verdict: CandidateCrossExaminationVerdict
    rationale: str = Field(min_length=1, max_length=8_000)
    contradictions: list[str] = Field(default_factory=list, max_length=50)
    missing_evidence: list[str] = Field(default_factory=list, max_length=50)


class ReproductionIntegrityStatus(StrEnum):
    VERIFIED = "verified"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class ReproductionIntegrityCheckKind(StrEnum):
    TARGET_IDENTITY = "target_identity"
    CITED_REACHABILITY = "cited_reachability"
    CLEAN_REPLAY = "clean_replay"
    REPOSITORY_HASH = "repository_hash"
    SETTLEMENT = "settlement"
    MINIMIZATION = "minimization"


class ReproductionAttemptEvidence(StrictModel):
    """Deterministic evidence for one isolated execution from a fresh copy."""

    attempt: int = Field(ge=1, le=10)
    state: ReproductionState
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    generated_test_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fresh_workspace: bool
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReproductionMinimizationTrial(StrictModel):
    removed_step_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    attempted_step_ids: list[str] = Field(max_length=39)
    state: ReproductionState
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def attempted_steps_are_unique(self) -> ReproductionMinimizationTrial:
        if len(self.attempted_step_ids) != len(set(self.attempted_step_ids)):
            raise ValueError("minimization trial step IDs must be unique")
        if self.removed_step_id in self.attempted_step_ids:
            raise ValueError("removed minimization step cannot remain in its trial")
        return self


class ReproductionMinimizationEvidence(StrictModel):
    """Bounded proof metadata for a claimed minimized attacker sequence."""

    original_step_ids: list[str] = Field(min_length=1, max_length=40)
    retained_step_ids: list[str] = Field(min_length=1, max_length=40)
    removal_trials: list[ReproductionMinimizationTrial] = Field(
        default_factory=list,
        max_length=40,
    )
    strategy: Literal["single_step_trivial", "bounded_step_deletion", "not_attempted"]
    proven_minimal: bool

    @model_validator(mode="after")
    def step_sets_are_consistent(self) -> ReproductionMinimizationEvidence:
        if len(self.original_step_ids) != len(set(self.original_step_ids)):
            raise ValueError("original minimization step IDs must be unique")
        if len(self.retained_step_ids) != len(set(self.retained_step_ids)):
            raise ValueError("retained minimization step IDs must be unique")
        if not set(self.retained_step_ids) <= set(self.original_step_ids):
            raise ValueError("retained minimization steps must come from the original sequence")
        if any(
            trial.removed_step_id not in set(self.original_step_ids)
            or not set(trial.attempted_step_ids) <= set(self.original_step_ids)
            for trial in self.removal_trials
        ):
            raise ValueError("minimization trials must reference original step IDs")
        if self.strategy == "single_step_trivial" and (
            len(self.original_step_ids) != 1
            or self.retained_step_ids != self.original_step_ids
            or self.removal_trials
            or not self.proven_minimal
        ):
            raise ValueError("single-step minimization evidence is inconsistent")
        if self.strategy == "not_attempted" and self.proven_minimal:
            raise ValueError("unattempted minimization cannot be proven")
        return self


class ReproductionTargetIdentity(StrictModel):
    """Exact chain/block/address/source-name identity used by a reproduction."""

    alias: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    contract_name: str = Field(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    address: str = Field(pattern=r"^0x[0-9a-fA-F]{40}$")
    chain_id: int = Field(ge=1)
    block_number: int = Field(ge=0)
    binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def identity_hash_matches_fields(self) -> ReproductionTargetIdentity:
        payload = {
            "alias": self.alias,
            "contract_name": self.contract_name,
            "address": self.address.lower(),
            "chain_id": self.chain_id,
            "block_number": self.block_number,
        }
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.binding_sha256 != expected:
            raise ValueError("reproduction target identity hash does not match its fields")
        return self


class ReproductionReachabilityEvidence(StrictModel):
    """Source-index evidence linking one declared call to a cited entry point."""

    step_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    target: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    function_signature: str = Field(min_length=3, max_length=256)
    entity_id: str = Field(min_length=1, max_length=1_000)
    location: Location
    provenance: SolidityProvenance

    @model_validator(mode="after")
    def source_hash_is_present(self) -> ReproductionReachabilityEvidence:
        if self.location.content_hash is None or not re.fullmatch(
            r"[0-9a-f]{64}",
            self.location.content_hash,
        ):
            raise ValueError("reproduction reachability requires an exact source hash")
        return self


class ReproductionSettlementStatus(StrEnum):
    ASSERTIONS_SATISFIED = "assertions_satisfied"
    CLAIM_NOT_REPRODUCED = "claim_not_reproduced"
    NOT_EXECUTED = "not_executed"


class ReproductionSettlementEvidence(StrictModel):
    """Execution state for the specification's declared end-state assertions."""

    status: ReproductionSettlementStatus
    assertions_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assertion_count: int = Field(ge=1, le=40)
    verified_attempts: int = Field(ge=0, le=10)
    financial_settlement_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    financial_settlement_verified: bool = False

    @model_validator(mode="after")
    def financial_evidence_matches_status(self) -> ReproductionSettlementEvidence:
        if self.financial_settlement_verified and (
            self.financial_settlement_sha256 is None
            or self.status is not ReproductionSettlementStatus.ASSERTIONS_SATISFIED
        ):
            raise ValueError(
                "verified financial settlement requires satisfied assertions and a digest"
            )
        return self


class ReproductionIntegrityCheck(StrictModel):
    check: ReproductionIntegrityCheckKind
    passed: bool
    detail: str = Field(min_length=1, max_length=2_000)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ReproductionIntegrityAssessment(StrictModel):
    """Hash-linked decision over every REAL-003 integrity requirement."""

    schema_version: Literal["1.0"] = "1.0"
    status: ReproductionIntegrityStatus
    repository_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    targets: list[ReproductionTargetIdentity] = Field(default_factory=list, max_length=40)
    reachability: list[ReproductionReachabilityEvidence] = Field(
        default_factory=list,
        max_length=40,
    )
    settlement: ReproductionSettlementEvidence
    minimization: ReproductionMinimizationEvidence
    checks: list[ReproductionIntegrityCheck] = Field(min_length=6, max_length=6)
    integrity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def assessment_is_canonical_and_hash_linked(self) -> ReproductionIntegrityAssessment:
        expected_checks = list(ReproductionIntegrityCheckKind)
        if [item.check for item in self.checks] != expected_checks:
            raise ValueError("reproduction integrity checks must use canonical complete order")
        if self.status is ReproductionIntegrityStatus.VERIFIED and not all(
            item.passed for item in self.checks
        ):
            raise ValueError("verified reproduction integrity requires every check to pass")
        payload = self.model_dump(mode="json", exclude={"integrity_sha256"})
        expected_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        if self.integrity_sha256 != expected_hash:
            raise ValueError("reproduction integrity hash does not match its typed contents")
        return self


class ReproductionResult(StrictModel):
    candidate_id: str
    test_name: str
    state: ReproductionState
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    specification_sha256: str
    generated_test_sha256: str | None = None
    generated_test_path: str | None = None
    regression_test_path: str | None = None
    command: list[str] = Field(default_factory=list)
    attempts: int = Field(default=0, ge=0)
    successful_attempts: int = Field(default=0, ge=0)
    original_steps: int = Field(default=0, ge=0)
    minimized_steps: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0, ge=0)
    required_block_number: int | None = Field(default=None, ge=0)
    expected_chain_id: int | None = Field(default=None, ge=1)
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    stdout_path: str | None = None
    stderr_path: str | None = None
    isolation_backend: str | None = None
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    repository_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    attempt_evidence: list[ReproductionAttemptEvidence] = Field(
        default_factory=list,
        max_length=10,
    )
    minimization_evidence: ReproductionMinimizationEvidence | None = None
    financial_settlement: FinancialSettlementEvidence | None = None
    financial_settlement_verified: bool = False
    integrity: ReproductionIntegrityAssessment | None = None

    @model_validator(mode="after")
    def execution_evidence_matches_summary(self) -> ReproductionResult:
        if self.attempt_evidence:
            if [item.attempt for item in self.attempt_evidence] != list(
                range(1, len(self.attempt_evidence) + 1)
            ):
                raise ValueError("reproduction attempt evidence must be contiguous and ordered")
            if self.attempts != len(self.attempt_evidence):
                raise ValueError("reproduction attempt count does not match its evidence")
            reproduced = sum(
                item.state is ReproductionState.REPRODUCED for item in self.attempt_evidence
            )
            if self.successful_attempts != reproduced:
                raise ValueError("successful reproduction count does not match attempt evidence")
        positive_states = {
            ReproductionState.REPRODUCED,
            ReproductionState.REPRODUCED_AND_MINIMIZED,
        }
        if self.financial_settlement_verified and (
            self.financial_settlement is None
            or self.state not in positive_states
            or not self.attempts
            or self.successful_attempts != self.attempts
        ):
            raise ValueError(
                "verified financial settlement requires complete successful replay evidence"
            )
        if (
            self.financial_settlement is not None
            and self.state in positive_states
            and not self.financial_settlement_verified
        ):
            raise ValueError("positive financial reproduction requires verified settlement")
        return self


class CandidateReproductionResolution(StrictModel):
    """Evidence references supporting the terminal state of one candidate."""

    candidate_id: str = Field(min_length=1, max_length=160)
    kind: ReproductionResolutionKind
    evidence_refs: list[str] = Field(default_factory=list, max_length=100)
    detail: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def evidence_is_canonical_and_present_for_qualifying_outcomes(
        self,
    ) -> CandidateReproductionResolution:
        if self.evidence_refs != sorted(set(self.evidence_refs)):
            raise ValueError("candidate resolution evidence references must be unique and sorted")
        if any(
            not reference
            or len(reference) > 500
            or any(ord(character) < 32 or ord(character) == 127 for character in reference)
            for reference in self.evidence_refs
        ):
            raise ValueError("candidate resolution evidence references must be bounded text")
        if self.kind is not ReproductionResolutionKind.INCONCLUSIVE and not self.evidence_refs:
            raise ValueError("a qualifying candidate resolution requires evidence references")
        return self


class QualityGateResult(StrictModel):
    gate: str
    required: bool
    passed: bool
    detail: str
    state: AnalysisState = AnalysisState.NOT_ANALYZED
    artifacts: list[str] = Field(default_factory=list)


class ScopeComponentEvidence(StrictModel):
    """Bounded discovery evidence for one requested audit-scope component."""

    component: ScopeComponent
    required: bool
    status: ScopeEvidenceStatus
    analyzed_paths: list[str] = Field(default_factory=list, max_length=2_000)
    omissions: list[str] = Field(default_factory=list, max_length=2_000)
    detail: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def evidence_state_is_consistent(self) -> ScopeComponentEvidence:
        if self.analyzed_paths != sorted(set(self.analyzed_paths)):
            raise ValueError("scope analyzed paths must be unique and sorted")
        if self.omissions != sorted(set(self.omissions)):
            raise ValueError("scope omissions must be unique and sorted")
        expected = (
            ScopeEvidenceStatus.OMITTED
            if self.omissions
            else (
                ScopeEvidenceStatus.ANALYZED if self.analyzed_paths else ScopeEvidenceStatus.MISSING
            )
        )
        if self.status is not expected:
            raise ValueError("scope evidence status does not match paths and omissions")
        return self


class AuditScopeAssessment(StrictModel):
    """Requested-versus-achieved scope with fail-closed component evidence."""

    requested: AuditScope
    achieved: AuditScope | None = None
    gate_required: bool
    complete: bool
    components: list[ScopeComponentEvidence]
    missing_required_components: list[ScopeComponent] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def scope_hierarchy_is_consistent(self) -> AuditScopeAssessment:
        if self.components != sorted(
            self.components,
            key=lambda item: item.component.value,
        ):
            raise ValueError("scope component evidence must be sorted")
        component_names = [item.component for item in self.components]
        if len(component_names) != len(set(component_names)):
            raise ValueError("scope component evidence must be unique")
        if set(component_names) != set(ScopeComponent):
            raise ValueError("scope assessment must include every component class")
        requested_components = scope_components_for(self.requested)
        if any(
            item.required != (item.component in requested_components) for item in self.components
        ):
            raise ValueError("scope required flags do not match the requested mode")
        complete_components = {
            item.component
            for item in self.components
            if item.status is ScopeEvidenceStatus.ANALYZED
        }
        achieved = None
        for candidate in (
            AuditScope.FULL_PROTOCOL,
            AuditScope.CONTRACTS_AND_DEPLOYMENT,
            AuditScope.CONTRACTS_ONLY,
        ):
            if scope_components_for(candidate) <= complete_components:
                achieved = candidate
                break
        if self.achieved is not achieved:
            raise ValueError("achieved scope does not match component evidence")
        missing = sorted(
            requested_components - complete_components,
            key=lambda item: item.value,
        )
        if self.missing_required_components != missing:
            raise ValueError("missing scope components do not match component evidence")
        if self.complete != (not missing):
            raise ValueError("scope completeness does not match required components")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("scope limitations must be unique and sorted")
        return self


class PriorAuditLocation(StrictModel):
    """Historical source range and hashes needed for local remediation comparison."""

    path: str = Field(min_length=1, max_length=500)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str | None = Field(default=None, max_length=200)
    historical_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    remediated_content_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    @field_validator("path")
    @classmethod
    def source_path_is_normalized_and_relative(cls, value: str) -> str:
        if (
            "\\" in value
            or value.startswith(("/", "-"))
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("prior-audit source path must be normalized and relative")
        return value

    @model_validator(mode="after")
    def historical_location_is_consistent(self) -> PriorAuditLocation:
        if self.end_line < self.start_line:
            raise ValueError("prior-audit end_line must not precede start_line")
        if (
            self.remediated_content_sha256 is not None
            and self.remediated_content_sha256 == self.historical_content_sha256
        ):
            raise ValueError("historical and remediated hashes must differ")
        return self


class PriorAuditFinding(StrictModel):
    prior_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,159}$")
    title: str = Field(min_length=1, max_length=500)
    severity: Severity
    cwe: list[str] = Field(default_factory=list, max_length=100)
    previous_state: PriorAuditPreviousState
    locations: list[PriorAuditLocation] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def remediated_claim_has_expected_hashes(self) -> PriorAuditFinding:
        if self.previous_state is PriorAuditPreviousState.REMEDIATED and any(
            location.remediated_content_sha256 is None for location in self.locations
        ):
            raise ValueError("a prior remediated claim requires an expected hash per location")
        keys = [
            (location.path, location.start_line, location.end_line) for location in self.locations
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("prior-audit finding locations must be unique")
        return self


class PriorAuditCorpus(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    findings: list[PriorAuditFinding] = Field(default_factory=list, max_length=2_000)

    @model_validator(mode="after")
    def finding_ids_are_unique(self) -> PriorAuditCorpus:
        prior_ids = [finding.prior_id for finding in self.findings]
        if len(prior_ids) != len(set(prior_ids)):
            raise ValueError("prior-audit finding IDs must be unique")
        return self


class PriorAuditComparisonItem(StrictModel):
    prior_id: str
    title: str
    discovery_status: PriorAuditDiscoveryStatus
    remediation_status: PriorAuditRemediationStatus
    source_valid: bool
    current_content_sha256: list[str] = Field(default_factory=list, max_length=100)
    matched_candidate_ids: list[str] = Field(default_factory=list, max_length=2_000)
    matched_finding_ids: list[str] = Field(default_factory=list, max_length=2_000)
    validation_errors: list[str] = Field(default_factory=list, max_length=500)

    @model_validator(mode="after")
    def comparison_evidence_is_normalized(self) -> PriorAuditComparisonItem:
        for values, label in (
            (self.current_content_sha256, "current content hashes"),
            (self.matched_candidate_ids, "matched candidate IDs"),
            (self.matched_finding_ids, "matched finding IDs"),
            (self.validation_errors, "validation errors"),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"prior-audit {label} must be unique and sorted")
        if any(
            re.fullmatch(r"[0-9a-f]{64}", value) is None for value in self.current_content_sha256
        ):
            raise ValueError("current prior-audit comparison hashes must be sha256")
        if self.source_valid != (not self.validation_errors):
            raise ValueError("prior-audit source validity must match validation errors")
        if (self.discovery_status is PriorAuditDiscoveryStatus.REDISCOVERED) != bool(
            self.matched_candidate_ids or self.matched_finding_ids
        ):
            raise ValueError("rediscovered status must match finding evidence")
        if (self.discovery_status is PriorAuditDiscoveryStatus.INCONCLUSIVE) != (
            not self.source_valid
        ):
            raise ValueError("inconclusive discovery status must match invalid source evidence")
        if (self.remediation_status is PriorAuditRemediationStatus.INCONCLUSIVE) != (
            not self.source_valid
        ):
            raise ValueError("inconclusive remediation status must match invalid source evidence")
        return self


class PriorAuditComparison(StrictModel):
    configured: bool
    required: bool
    loaded: bool
    source_path: str | None = None
    source_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    prior_material_withheld_from_discovery: bool
    blind_discovery_completed_before_load: bool
    independent_candidate_count: int = Field(default=0, ge=0)
    model_request_count_before_load: int = Field(default=0, ge=0)
    items: list[PriorAuditComparisonItem] = Field(default_factory=list, max_length=2_000)
    errors: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def load_state_is_consistent(self) -> PriorAuditComparison:
        if self.items != sorted(self.items, key=lambda item: item.prior_id):
            raise ValueError("prior-audit comparisons must be sorted by prior ID")
        prior_ids = [item.prior_id for item in self.items]
        if len(prior_ids) != len(set(prior_ids)):
            raise ValueError("prior-audit comparison IDs must be unique")
        if self.errors != sorted(set(self.errors)):
            raise ValueError("prior-audit comparison errors must be unique and sorted")
        if self.configured:
            if self.source_path is None:
                raise ValueError("configured prior audit requires a source path")
            if self.loaded:
                if self.source_sha256 is None or self.errors:
                    raise ValueError("loaded prior audit requires a source hash and no errors")
                if not self.prior_material_withheld_from_discovery:
                    raise ValueError("loaded prior audit must be withheld from discovery")
                if not self.blind_discovery_completed_before_load:
                    raise ValueError("loaded prior audit must be parsed after blind discovery")
            elif not self.errors:
                raise ValueError("failed prior-audit loading requires explicit errors")
        elif any(
            (
                self.loaded,
                self.source_path is not None,
                self.source_sha256 is not None,
                self.prior_material_withheld_from_discovery,
                self.blind_discovery_completed_before_load,
                bool(self.items),
                bool(self.errors),
            )
        ):
            raise ValueError("unconfigured prior audit cannot contain load evidence")
        return self


def scope_components_for(scope: AuditScope) -> set[ScopeComponent]:
    """Return the fixed evidence classes required by one scope mode."""

    return {
        AuditScope.CONTRACTS_ONLY: {
            ScopeComponent.CONTRACTS,
        },
        AuditScope.CONTRACTS_AND_DEPLOYMENT: {
            ScopeComponent.CONTRACTS,
            ScopeComponent.DEPLOYMENT,
        },
        AuditScope.FULL_PROTOCOL: set(ScopeComponent),
    }[scope]


class MaximumAssuranceRequirement(StrictModel):
    """One auditable clause in the maximum-assurance contract."""

    engine: str
    required: bool
    passed: bool
    blocking: bool
    state: AnalysisState
    detail: str
    artifacts: list[str] = Field(default_factory=list)


class MaximumAssuranceAssessment(StrictModel):
    """Machine-readable result of applying the maximum-assurance contract."""

    contract_version: Literal["1.0"] = "1.0"
    requested: bool
    required: bool
    downgrade_allowed: bool
    downgraded: bool
    status: MaximumAssuranceStatus
    requirements: list[MaximumAssuranceRequirement] = Field(default_factory=list)
    downgrade_reasons: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def complete_requires_every_clause(self) -> MaximumAssuranceAssessment:
        engines = [requirement.engine for requirement in self.requirements]
        if engines != list(dict.fromkeys(engines)):
            raise ValueError("maximum-assurance requirement engines must be unique")
        if self.status is MaximumAssuranceStatus.COMPLETE and (
            not self.requested
            or not self.requirements
            or not any(requirement.required for requirement in self.requirements)
            or self.downgraded
            or any(
                requirement.required and (not requirement.passed or requirement.blocking)
                for requirement in self.requirements
            )
        ):
            raise ValueError(
                "maximum-assurance COMPLETE requires a non-empty passing required clause inventory"
            )
        if self.downgraded and self.status is not MaximumAssuranceStatus.DOWNGRADED:
            raise ValueError("downgraded maximum-assurance runs must use DOWNGRADED status")
        return self


class ModelVote(StrictModel):
    role: str
    requested_model: str
    returned_model: str | None = None
    family: str
    verdict: str
    rationale: str = ""


class LocationValidation(StrictModel):
    valid: bool
    content_hash: str | None = None
    errors: list[str] = Field(default_factory=list)
    validated_at: datetime | None = None


class CandidateFinding(StrictModel):
    """Finding proposed by an analysis role before independent verification."""

    candidate_id: str = Field(min_length=1)
    origin_kind: CandidateOriginKind = CandidateOriginKind.MODEL_REVIEW
    execution_provenance: InvariantExecutionCandidateProvenance | None = None
    title: str = Field(min_length=1)
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    summary: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    preconditions: list[str] = Field(min_length=1)
    locations: list[Location] = Field(min_length=1)
    source: SourceSink | None = None
    sink: SourceSink | None = None
    attack_path: list[str] = Field(min_length=1)
    evidence: list[Evidence] = Field(min_length=1)
    compensating_controls: list[str] = Field(default_factory=list)
    false_positive_conditions: list[str] = Field(min_length=1)
    recommendation: str = Field(min_length=1)
    verification_test: VerificationTest
    role: str | None
    model_family: str | None
    model_votes: list[ModelVote] = Field(default_factory=list)

    @model_validator(mode="after")
    def origin_fields_are_exact(self) -> CandidateFinding:
        if self.origin_kind is CandidateOriginKind.MODEL_REVIEW:
            if self.execution_provenance is not None:
                raise ValueError("model-review candidates cannot claim execution provenance")
            if not self.role or not self.role.strip() or not self.model_family:
                raise ValueError("model-review candidates require a non-empty role and family")
            if not self.model_family.strip():
                raise ValueError("model-review candidates require a non-empty role and family")
            return self

        provenance = self.execution_provenance
        if provenance is None:
            raise ValueError("execution-origin candidates require typed provenance")
        provenance = InvariantExecutionCandidateProvenance.model_validate(
            provenance.model_dump(mode="python")
        )
        if self.role is not None or self.model_family is not None:
            raise ValueError("execution-origin candidates cannot claim a model role or family")
        expected_id = f"exec-{provenance.provenance_sha256[:24]}"
        if self.candidate_id != expected_id:
            raise ValueError("execution-origin candidate ID must derive from provenance")
        if tuple(self.locations) != provenance.source_locations:
            raise ValueError("execution-origin candidate locations must exactly match provenance")
        execution_evidence = [item for item in self.evidence if item.type == "execution"]
        if len(execution_evidence) != 1:
            raise ValueError("execution-origin candidates require exactly one execution evidence")
        bound_evidence = execution_evidence[0]
        if (
            bound_evidence.source != "mmaudit-foundry-invariant"
            or bound_evidence.rule_id != provenance.invariant_id
            or bound_evidence.fingerprint != provenance.provenance_sha256
        ):
            raise ValueError("execution evidence must bind the exact provenance record")
        if any(item.type == "model" for item in self.evidence):
            raise ValueError("execution-origin candidates cannot contain model evidence")
        return self


class CandidateFindingArtifact(StrictModel):
    """Versioned candidate inventory emitted before final consensus reporting."""

    schema_version: Literal["1.0", "1.1"]
    findings: list[CandidateFinding] = Field(default_factory=list, max_length=100_000)

    @model_validator(mode="before")
    @classmethod
    def version_declares_origin_semantics(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        version = value.get("schema_version")
        raw_findings = value.get("findings")
        if not isinstance(raw_findings, list):
            return value
        if version == "1.1" and any(
            not isinstance(item, dict) or "origin_kind" not in item for item in raw_findings
        ):
            raise ValueError("candidate artifact 1.1 requires explicit origin on every candidate")
        if version == "1.0" and any(
            isinstance(item, dict)
            and item.get("origin_kind") == CandidateOriginKind.DETERMINISTIC_EXECUTION.value
            for item in raw_findings
        ):
            raise ValueError("candidate artifact 1.0 cannot claim deterministic execution origin")
        return value

    @model_validator(mode="after")
    def candidates_are_unique(self) -> CandidateFindingArtifact:
        identifiers = [item.candidate_id for item in self.findings]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("saved candidates must be unique")
        return self


class Finding(StrictModel):
    id: str = Field(min_length=1)
    group_id: str | None = None
    origin_kind: FindingOriginKind = FindingOriginKind.MODEL_REVIEW
    execution_provenance: tuple[InvariantExecutionCandidateProvenance, ...] = Field(
        default_factory=tuple,
        max_length=100,
    )
    title: str = Field(min_length=1)
    status: FindingStatus
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    summary: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    preconditions: list[str] = Field(default_factory=list)
    locations: list[Location] = Field(default_factory=list)
    source: SourceSink | None = None
    sink: SourceSink | None = None
    attack_path: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    compensating_controls: list[str] = Field(default_factory=list)
    false_positive_conditions: list[str] = Field(default_factory=list)
    recommendation: str = ""
    verification_test: VerificationTest | None = None
    model_votes: list[ModelVote] = Field(default_factory=list)
    location_validation: LocationValidation
    disagreement: str = ""
    contributing_candidate_ids: list[str] = Field(default_factory=list)
    evidence_strength: EvidenceStrength = EvidenceStrength.NONE
    reproduction_state: ReproductionState = ReproductionState.NOT_ATTEMPTED

    @model_validator(mode="after")
    def accepted_findings_are_complete(self) -> Finding:
        self._validate_origin_fields()
        if self.status is FindingStatus.REJECTED:
            return self
        required_collections = (
            self.preconditions,
            self.locations,
            self.attack_path,
            self.evidence,
            self.false_positive_conditions,
        )
        if any(not value for value in required_collections):
            raise ValueError("non-rejected findings require complete evidence fields")
        if not self.impact or not self.recommendation or self.verification_test is None:
            raise ValueError("non-rejected findings require impact, remediation, and a test")
        return self

    def _validate_origin_fields(self) -> None:
        if self.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION:
            if self.execution_provenance:
                raise ValueError("non-execution findings cannot claim execution provenance")
            return
        if self.group_id is None or not self.group_id.strip():
            raise ValueError("execution-origin findings require a non-empty group ID")
        if not self.execution_provenance:
            raise ValueError("execution-origin findings require typed provenance")
        provenance = tuple(
            InvariantExecutionCandidateProvenance.model_validate(item.model_dump(mode="python"))
            for item in self.execution_provenance
        )
        provenance_hashes = tuple(item.provenance_sha256 for item in provenance)
        if provenance_hashes != tuple(sorted(set(provenance_hashes))):
            raise ValueError("execution finding provenance must be unique and sorted")
        if len(self.contributing_candidate_ids) != len(set(self.contributing_candidate_ids)):
            raise ValueError("execution finding contributing candidate IDs must be unique")
        expected_candidate_ids = {f"exec-{item.provenance_sha256[:24]}" for item in provenance}
        if not expected_candidate_ids <= set(self.contributing_candidate_ids):
            raise ValueError("execution finding must retain every provenance-derived candidate ID")
        locations_by_key = {
            (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol or "",
                location.content_hash or "",
            ): location
            for item in provenance
            for location in item.source_locations
        }
        expected_locations = tuple(locations_by_key[key] for key in sorted(locations_by_key))
        if tuple(self.locations) != expected_locations:
            raise ValueError("execution finding locations must exactly match its provenance")


class ThreatBoundary(StrictModel):
    name: str
    description: str
    locations: list[Location] = Field(default_factory=list)


class ThreatModel(StrictModel):
    assets: list[str]
    trust_boundaries: list[ThreatBoundary]
    attacker_controlled_inputs: list[str]
    identities_and_roles: list[str]
    sensitive_data: list[str]
    external_integrations: list[str]
    attack_surfaces: list[str]
    missing_controls: list[str]
    review_targets: list[str]


class CandidateBatch(StrictModel):
    findings: list[CandidateFinding]


class ModelSurfaceReviewRequest(StrictModel):
    """One deterministic surface that a model is explicitly asked to review."""

    surface_id: str = Field(pattern=r"^model-surface:[0-9a-f]{64}$")
    kind: ModelReviewSurfaceKind
    subject_id: str = Field(min_length=1, max_length=500)
    contract: str = Field(min_length=1, max_length=500)
    function_or_state_surface: str = Field(min_length=1, max_length=500)
    critical: bool
    allowed_locations: tuple[Location, ...] = Field(default_factory=tuple, max_length=100)
    allowed_symbols: tuple[str, ...] = Field(default_factory=tuple, max_length=100)
    invariant_considered: str = Field(min_length=1, max_length=1_000)

    @staticmethod
    def calculate_surface_id(kind: ModelReviewSurfaceKind, subject_id: str) -> str:
        """Return the stable ID shared with the deterministic surface inventory."""

        digest = hashlib.sha256(f"{kind.value}\0{subject_id}".encode()).hexdigest()
        return f"model-surface:{digest}"

    @field_validator(
        "subject_id",
        "contract",
        "function_or_state_surface",
        "invariant_considered",
    )
    @classmethod
    def descriptor_text_is_bounded_plain_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface review request text must be bounded plain text")
        return normalized

    @field_validator("allowed_locations")
    @classmethod
    def allowed_locations_are_canonical(
        cls,
        value: tuple[Location, ...],
    ) -> tuple[Location, ...]:
        keys = [
            (
                location.path,
                location.start_line,
                location.end_line,
                location.symbol or "",
                location.content_hash or "",
            )
            for location in value
        ]
        if keys != sorted(set(keys)):
            raise ValueError("model surface review allowed locations must be unique and sorted")
        return value

    @field_validator("allowed_symbols")
    @classmethod
    def allowed_symbols_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(symbol.strip() for symbol in value)
        if any(
            not symbol
            or len(symbol) > 500
            or any(ord(character) < 32 or ord(character) == 127 for character in symbol)
            for symbol in normalized
        ) or normalized != tuple(sorted(set(normalized))):
            raise ValueError(
                "model surface review allowed symbols must be bounded, unique, and sorted"
            )
        return normalized

    @model_validator(mode="after")
    def identity_and_evidence_are_explicit(self) -> ModelSurfaceReviewRequest:
        expected_surface_id = self.calculate_surface_id(self.kind, self.subject_id)
        if self.surface_id != expected_surface_id:
            raise ValueError("model surface review request has an inconsistent stable ID")
        if not self.allowed_locations and not self.allowed_symbols:
            raise ValueError("model surface review request requires an allowed location or symbol")
        return self


class ModelSurfaceReviewStatus(StrEnum):
    """Explicit outcome for one requested deterministic review surface."""

    REVIEWED_NO_ISSUE = "REVIEWED_NO_ISSUE"
    CANDIDATE = "CANDIDATE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_REVIEWED = "NOT_REVIEWED"


class ModelSurfaceReviewCitation(StrictModel):
    """A source location or symbol that can be validated outside model output."""

    location: Location | None = None
    symbol: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("symbol")
    @classmethod
    def symbol_is_bounded_plain_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface review symbol must be bounded plain text")
        return normalized

    @model_validator(mode="after")
    def location_or_symbol_is_explicit(self) -> ModelSurfaceReviewCitation:
        if self.location is None and self.symbol is None:
            raise ValueError("model surface review requires a source location or symbol")
        if self.location is not None:
            if self.location.end_line < self.location.start_line:
                raise ValueError("model surface review location range is reversed")
            if (
                self.location.symbol is not None
                and self.symbol is not None
                and self.location.symbol != self.symbol
            ):
                raise ValueError("model surface review citation symbols disagree")
        return self


class ModelSurfaceReviewEvidenceObservation(StrictModel):
    """One source-anchored observation supporting a substantive surface review."""

    citation: ModelSurfaceReviewCitation
    observed_behavior: str = Field(min_length=12, max_length=1_000)
    security_relevance: str = Field(min_length=12, max_length=1_000)

    @field_validator("observed_behavior", "security_relevance")
    @classmethod
    def observation_fields_are_bounded_plain_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface evidence must be bounded plain text")
        return normalized


class ModelSurfaceReviewReachability(StrictModel):
    """Structured path evidence connecting an entry point to the reviewed surface."""

    entry_point: ModelSurfaceReviewCitation
    path: tuple[ModelSurfaceReviewCitation, ...] = Field(min_length=1, max_length=50)
    actor_or_caller: str = Field(min_length=1, max_length=500)
    preconditions: tuple[str, ...] = Field(max_length=50)

    @field_validator("actor_or_caller")
    @classmethod
    def actor_or_caller_is_bounded_plain_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface reachability actor must be bounded plain text")
        return normalized

    @field_validator("preconditions")
    @classmethod
    def preconditions_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip() for item in value)
        if any(
            not item
            or len(item) > 500
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in normalized
        ) or normalized != tuple(sorted(set(normalized))):
            raise ValueError(
                "model surface reachability preconditions must be bounded, unique, and sorted"
            )
        return normalized

    @model_validator(mode="after")
    def entry_point_starts_path(self) -> ModelSurfaceReviewReachability:
        if self.path[0] != self.entry_point:
            raise ValueError("model surface reachability path must begin at its entry point")
        return self


class ModelSurfaceReviewRecord(StrictModel):
    """One model-authored, surface-specific review statement."""

    surface_id: str = Field(pattern=r"^model-surface:[0-9a-f]{64}$")
    contract: str = Field(min_length=1, max_length=500)
    function_or_state_surface: str = Field(min_length=1, max_length=500)
    review_role: str = Field(pattern=r"^[a-z][a-z0-9_:.-]{0,127}$")
    status: ModelSurfaceReviewStatus
    rationale: str = Field(min_length=8, max_length=2_000)
    citation: ModelSurfaceReviewCitation
    invariant_considered: str = Field(min_length=1, max_length=1_000)
    evidence_observations: tuple[ModelSurfaceReviewEvidenceObservation, ...] = Field(max_length=20)
    reachability: ModelSurfaceReviewReachability | None
    assumptions: tuple[str, ...] = Field(max_length=50)
    confidence: float = Field(ge=0, le=1)

    @field_validator(
        "contract",
        "function_or_state_surface",
        "rationale",
        "invariant_considered",
    )
    @classmethod
    def narrative_fields_are_bounded_plain_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface review text must be bounded plain text")
        return normalized

    @field_validator("assumptions")
    @classmethod
    def assumptions_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip() for item in value)
        if any(
            not item
            or len(item) > 500
            or any(ord(character) < 32 or ord(character) == 127 for character in item)
            for item in normalized
        ) or normalized != tuple(sorted(set(normalized))):
            raise ValueError("model surface review assumptions must be bounded, unique, and sorted")
        return normalized

    @model_validator(mode="after")
    def creditable_review_has_surface_bound_evidence(self) -> ModelSurfaceReviewRecord:
        if self.status not in {
            ModelSurfaceReviewStatus.CANDIDATE,
            ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        }:
            return self
        if not self.evidence_observations or self.reachability is None:
            raise ValueError(
                "creditable model surface review requires explicit evidence and reachability"
            )
        if any(observation.citation != self.citation for observation in self.evidence_observations):
            raise ValueError("model surface evidence observations must cite the reviewed surface")
        if self.reachability.path[-1] != self.citation:
            raise ValueError(
                "model surface reachability path must terminate at the reviewed surface"
            )
        return self


class CandidateReviewBatch(StrictModel):
    """Provider response with candidates and an explicit record for each supplied surface."""

    findings: list[CandidateFinding]
    surface_reviews: tuple[ModelSurfaceReviewRecord, ...] = Field(max_length=10_000)

    @field_validator("surface_reviews")
    @classmethod
    def surface_reviews_are_unique_and_sorted(
        cls,
        value: tuple[ModelSurfaceReviewRecord, ...],
    ) -> tuple[ModelSurfaceReviewRecord, ...]:
        surface_ids = tuple(record.surface_id for record in value)
        if surface_ids != tuple(sorted(set(surface_ids))):
            raise ValueError("candidate surface reviews must be unique and sorted by surface ID")
        return value

    def require_exact_surface_set(
        self,
        requested_surface_ids: Sequence[str],
    ) -> CandidateReviewBatch:
        """Reject a response that omitted or invented any requested surface record."""

        expected = tuple(requested_surface_ids)
        if expected != tuple(sorted(set(expected))) or any(
            re.fullmatch(r"model-surface:[0-9a-f]{64}", surface_id) is None
            for surface_id in expected
        ):
            raise ValueError("requested surface IDs must be valid, unique, and sorted")
        actual = tuple(record.surface_id for record in self.surface_reviews)
        if actual != expected:
            raise ValueError(
                "candidate surface reviews must exactly cover the requested surface set"
            )
        return self


class ModelSurfaceReviewArtifact(StrictModel):
    """Hash-linked normalized response for one exact requested surface set."""

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1, max_length=500)
    review_role: str = Field(pattern=r"^[a-z][a-z0-9_:.-]{0,127}$")
    requested_surface_ids: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    requested_surface_ids_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_surface_manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    rendered_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    validated_response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    records: tuple[ModelSurfaceReviewRecord, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @staticmethod
    def calculate_artifact_sha256(payload: dict[str, Any]) -> str:
        """Hash a JSON-compatible artifact payload without its digest field."""

        canonical = {key: value for key, value in payload.items() if key != "artifact_sha256"}
        return hashlib.sha256(
            json.dumps(
                canonical,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @staticmethod
    def calculate_requested_surface_manifest_sha256(
        requests: Sequence[ModelSurfaceReviewRequest],
    ) -> str:
        """Hash the exact ordered deterministic request descriptors."""

        payload = [request.model_dump(mode="json") for request in requests]
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @field_validator("request_id")
    @classmethod
    def request_id_is_bounded_plain_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(
            ord(character) < 32 or ord(character) == 127 for character in normalized
        ):
            raise ValueError("model surface review request ID must be bounded plain text")
        return normalized

    @field_validator("requested_surface_ids")
    @classmethod
    def requested_surface_ids_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(r"model-surface:[0-9a-f]{64}", surface_id) is None for surface_id in value
        ):
            raise ValueError("requested model surface IDs must be valid, unique, and sorted")
        return value

    @model_validator(mode="after")
    def exact_surface_set_role_and_hashes_are_consistent(
        self,
    ) -> ModelSurfaceReviewArtifact:
        record_ids = tuple(record.surface_id for record in self.records)
        if record_ids != self.requested_surface_ids:
            raise ValueError(
                "model surface review records must exactly cover the requested surface set"
            )
        if any(record.review_role != self.review_role for record in self.records):
            raise ValueError("model surface review record role differs from its request")
        expected_surface_ids_hash = hashlib.sha256(
            json.dumps(
                list(self.requested_surface_ids),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()
        if self.requested_surface_ids_sha256 != expected_surface_ids_hash:
            raise ValueError("requested model surface ID hash is inconsistent")
        expected_artifact_hash = self.calculate_artifact_sha256(self.model_dump(mode="json"))
        if self.artifact_sha256 != expected_artifact_hash:
            raise ValueError("model surface review artifact hash is inconsistent")
        return self

    def require_exact_requested_surface_manifest(
        self,
        requests: Sequence[ModelSurfaceReviewRequest],
    ) -> ModelSurfaceReviewArtifact:
        """Verify that this artifact is bound to the supplied ordered descriptors."""

        requested_surface_ids = tuple(request.surface_id for request in requests)
        if requested_surface_ids != self.requested_surface_ids:
            raise ValueError(
                "model surface review artifact does not match the requested surface IDs"
            )
        expected_manifest_hash = self.calculate_requested_surface_manifest_sha256(requests)
        if self.requested_surface_manifest_sha256 != expected_manifest_hash:
            raise ValueError(
                "model surface review artifact does not match the requested surface manifest"
            )
        return self


class VerificationDecision(StrictModel):
    candidate_id: str
    verdict: VerificationVerdict
    rationale: str
    source_to_sink: str
    reachability: str
    authentication: str
    privilege_requirements: str
    environmental_assumptions: list[str]
    guards_and_controls: list[str]
    false_positive_conditions: list[str]
    safe_verification_test: VerificationTest
    confidence: float = Field(ge=0, le=1)


class VerificationBatch(StrictModel):
    decisions: list[VerificationDecision]


class JudgeBatch(StrictModel):
    findings: list[Finding]


class JudgeDecision(StrictModel):
    group_id: str
    status: FindingStatus
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    rationale: str


class JudgeDecisionBatch(StrictModel):
    decisions: list[JudgeDecision]


class ReportQualityReview(StrictModel):
    """Non-authoritative review of report completeness and claim calibration."""

    passed: bool
    missing_sections: list[str] = Field(default_factory=list, max_length=100)
    unsupported_claims: list[str] = Field(default_factory=list, max_length=100)
    coverage_caveats: list[str] = Field(default_factory=list, max_length=100)
    contradictions: list[str] = Field(default_factory=list, max_length=100)
    rationale: str = Field(min_length=1, max_length=8_000)


class ScannerFinding(StrictModel):
    scanner: str
    rule_id: str
    title: str
    severity: Severity
    message: str
    locations: list[Location]
    cwe: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    evidence_strength: EvidenceStrength = EvidenceStrength.NONE
    fingerprint: str


def _repository_suite_path_is_safe(value: str, *, allow_root: bool) -> bool:
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    sensitive_parts = {".git", ".ssh", ".aws", ".azure", "credentials", "mnemonics"}
    if allow_root and value == ".":
        return True
    return not (
        not value
        or value != value.strip()
        or normalized != value
        or len(value) > 1_000
        or value.startswith(("/", "-"))
        or re.match(r"^[A-Za-z]:/", value)
        or any(part in {"", ".", ".."} for part in parts)
        or any(character in "*?[]{}" for character in value)
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
        or any(
            part.casefold() in sensitive_parts or part.casefold().startswith(".env")
            for part in parts
        )
    )


def _repository_suite_text_is_safe(value: str) -> bool:
    return (
        bool(value)
        and value == value.strip()
        and unicodedata.normalize("NFC", value) == value
        and not any(unicodedata.category(character).startswith("C") for character in value)
    )


class RepositorySuiteInventoryArtifact(StrictModel):
    """Hash-only identity for one private compiler inventory artifact."""

    name: str = Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bytes: int = Field(ge=1, le=100_000_000)


class RepositorySuiteInventoryRecord(StrictModel):
    """Compiler-bound execution and declaration identity for one runnable test."""

    project_root: str = Field(min_length=1, max_length=1_000)
    execution_path: str = Field(min_length=1, max_length=1_000)
    execution_suite_name: str = Field(min_length=1, max_length=1_000)
    test_name: str = Field(min_length=1, max_length=1_000)
    execution_signature: str = Field(min_length=1, max_length=1_000)
    execution_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_start_line: int = Field(ge=1)
    execution_end_line: int = Field(ge=1)
    execution_contract_ast_id: int = Field(ge=0)
    declaration_path: str = Field(min_length=1, max_length=1_000)
    declaration_suite_name: str = Field(min_length=1, max_length=1_000)
    declaration_signature: str = Field(min_length=3, max_length=1_000)
    declaration_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    declaration_start_line: int = Field(ge=1)
    declaration_end_line: int = Field(ge=1)
    declaration_contract_ast_id: int = Field(ge=0)
    declaration_function_ast_id: int = Field(ge=0)
    build_info_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteInventoryRecord:
        """Validate and self-hash one compiler-reconciled inventory record."""

        if "record_sha256" in values:
            raise ValueError("record_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, record_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"record_sha256"})
        return cls.model_validate(
            {
                **payload,
                "record_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("project_root")
    @classmethod
    def project_root_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=True):
            raise ValueError("repository inventory project root must be repository-relative")
        return value

    @field_validator("execution_path", "declaration_path")
    @classmethod
    def source_paths_are_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=False):
            raise ValueError("repository inventory source path must be repository-relative")
        return value

    @field_validator(
        "execution_suite_name",
        "test_name",
        "execution_signature",
        "declaration_suite_name",
        "declaration_signature",
    )
    @classmethod
    def names_are_bounded_printable_text(cls, value: str) -> str:
        if not _repository_suite_text_is_safe(value):
            raise ValueError("repository inventory names must be bounded printable text")
        return value

    @model_validator(mode="after")
    def paths_ranges_signature_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteInventoryRecord:
        if self.project_root != ".":
            prefix = f"{self.project_root}/"
            if not self.execution_path.startswith(prefix) or not self.declaration_path.startswith(
                prefix
            ):
                raise ValueError("repository inventory source lies outside its project root")
        if self.execution_end_line < self.execution_start_line:
            raise ValueError("repository inventory execution range is reversed")
        if self.declaration_end_line < self.declaration_start_line:
            raise ValueError("repository inventory declaration range is reversed")
        if not self.declaration_signature.startswith(f"{self.test_name}("):
            raise ValueError("repository inventory signature differs from its test name")
        if self.execution_signature.partition("(")[0] != self.test_name:
            raise ValueError("repository inventory execution signature differs from test name")
        if self.record_sha256 != self.expected_record_sha256():
            raise ValueError("repository suite inventory record hash does not match")
        return self

    @property
    def canonical_key(self) -> tuple[str, str, str, str]:
        return (
            self.project_root,
            self.execution_path,
            self.execution_suite_name,
            self.test_name,
        )

    def expected_record_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"record_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteProjectInventoryEvidence(StrictModel):
    """One isolated Forge inventory invocation for a canonical project root."""

    project_root: str = Field(min_length=1, max_length=1_000)
    command_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    process_exit_code: Literal[0] = 0
    machine_output_validated: Literal[True] = True
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_bytes: int = Field(ge=2, le=100_000_000)
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_bytes: int = Field(ge=0, le=100_000_000)
    build_info_artifacts: tuple[RepositorySuiteInventoryArtifact, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    build_info_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_build_info_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    parser_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    records: tuple[RepositorySuiteInventoryRecord, ...] = Field(
        min_length=1,
        max_length=10_000,
    )
    normalized_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    project_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteProjectInventoryEvidence:
        """Validate and self-hash one project inventory."""

        if "project_inventory_sha256" in values:
            raise ValueError(
                "project_inventory_sha256 is derived and cannot be supplied to sealed()"
            )
        provisional = cls.model_construct(**values, project_inventory_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"project_inventory_sha256"})
        return cls.model_validate(
            {
                **payload,
                "project_inventory_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("project_root")
    @classmethod
    def project_root_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=True):
            raise ValueError("repository inventory project root must be repository-relative")
        return value

    @model_validator(mode="after")
    def artifacts_records_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteProjectInventoryEvidence:
        artifacts = tuple(
            (
                artifact.name,
                artifact.sha256,
                artifact.normalized_sha256,
                artifact.bytes,
            )
            for artifact in self.build_info_artifacts
        )
        if artifacts != tuple(sorted(set(artifacts))):
            raise ValueError("repository suite inventory artifacts must be unique and sorted")
        if self.build_info_bundle_sha256 != _canonical_model_sha256(
            [artifact.model_dump(mode="json") for artifact in self.build_info_artifacts]
        ):
            raise ValueError("repository suite build-info bundle hash does not match")
        normalized_artifact_hashes = tuple(
            artifact.normalized_sha256 for artifact in self.build_info_artifacts
        )
        if len(normalized_artifact_hashes) != len(set(normalized_artifact_hashes)):
            raise ValueError("repository suite normalized build-info artifacts must be unique")
        if self.normalized_build_info_bundle_sha256 != _canonical_model_sha256(
            sorted(normalized_artifact_hashes)
        ):
            raise ValueError("repository suite normalized build-info bundle hash does not match")
        artifact_hashes = set(normalized_artifact_hashes)
        if any(record.build_info_sha256 not in artifact_hashes for record in self.records):
            raise ValueError("repository suite inventory record lacks its build-info artifact")
        record_keys = tuple(record.canonical_key for record in self.records)
        record_hashes = tuple(record.record_sha256 for record in self.records)
        if record_keys != tuple(sorted(set(record_keys))) or len(record_hashes) != len(
            set(record_hashes)
        ):
            raise ValueError("repository suite inventory records must be unique and sorted")
        if any(record.project_root != self.project_root for record in self.records):
            raise ValueError("repository suite inventory record has the wrong project root")
        if self.normalized_inventory_sha256 != _canonical_model_sha256(sorted(record_hashes)):
            raise ValueError("repository suite normalized inventory hash does not match")
        if self.project_inventory_sha256 != self.expected_project_inventory_sha256():
            raise ValueError("repository suite project inventory hash does not match")
        return self

    def expected_project_inventory_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"project_inventory_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteInventoryEvidence(StrictModel):
    """Self-hashed proof of isolated Forge list/build-info inventories."""

    schema_version: Literal["1.0"] = "1.0"
    phase: RepositorySuiteInventoryPhase
    framework: Literal[RepositorySuiteFramework.FOUNDRY] = RepositorySuiteFramework.FOUNDRY
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_version: str = Field(min_length=1, max_length=1_000)
    tool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1, max_length=1_000)
    compiler_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_backend: str = Field(min_length=1, max_length=200)
    isolation_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    execution_evidence: ExecutionEvidenceKind
    repository_code_execution: Literal[RepositoryCodeExecutionState.ISOLATED] = (
        RepositoryCodeExecutionState.ISOLATED
    )
    projects: tuple[RepositorySuiteProjectInventoryEvidence, ...] = Field(
        min_length=1,
        max_length=1_000,
    )
    project_bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_record_count: int = Field(ge=1, le=10_000)
    safety_claim: Literal[False] = False
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteInventoryEvidence:
        """Validate and self-hash one terminal isolated inventory."""

        if "inventory_sha256" in values:
            raise ValueError("inventory_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, inventory_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"inventory_sha256"})
        return cls.model_validate(
            {
                **payload,
                "inventory_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def projects_records_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteInventoryEvidence:
        project_keys = tuple(project.project_root for project in self.projects)
        project_hashes = tuple(project.project_inventory_sha256 for project in self.projects)
        if project_keys != tuple(sorted(set(project_keys))):
            raise ValueError("repository suite project inventories must be unique and sorted")
        if self.project_bundle_sha256 != _canonical_model_sha256(list(project_hashes)):
            raise ValueError("repository suite project inventory bundle hash does not match")
        records = tuple(record for project in self.projects for record in project.records)
        record_hashes = tuple(sorted(record.record_sha256 for record in records))
        if len(record_hashes) != len(set(record_hashes)):
            raise ValueError("repository suite inventory contains duplicate record hashes")
        if self.inventory_record_count != len(record_hashes):
            raise ValueError("repository suite inventory record count does not match")
        if self.normalized_inventory_sha256 != _canonical_model_sha256(list(record_hashes)):
            raise ValueError("repository suite normalized inventory hash does not match")
        if self.execution_evidence is ExecutionEvidenceKind.REAL and (
            not self.isolation_backend or not self.isolation_attestation_sha256
        ):
            raise ValueError("real repository inventory requires isolation attestation")
        if self.inventory_sha256 != self.expected_inventory_sha256():
            raise ValueError("repository suite inventory evidence hash does not match")
        return self

    def expected_inventory_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"inventory_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteTestDescriptor(StrictModel):
    """Canonical source-bound identity for one selected repository-owned test."""

    framework: RepositorySuiteFramework
    project_root: str = Field(min_length=1, max_length=1_000)
    path: str = Field(min_length=1, max_length=1_000)
    suite_name: str = Field(min_length=1, max_length=1_000)
    test_name: str = Field(min_length=1, max_length=1_000)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    inventory_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    inventory_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    execution_contract_ast_id: int | None = Field(default=None, ge=0)
    declaration_path: str | None = Field(default=None, min_length=1, max_length=1_000)
    declaration_suite_name: str | None = Field(default=None, min_length=1, max_length=1_000)
    declaration_signature: str | None = Field(default=None, min_length=3, max_length=1_000)
    declaration_source_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    declaration_start_line: int | None = Field(default=None, ge=1)
    declaration_end_line: int | None = Field(default=None, ge=1)
    declaration_contract_ast_id: int | None = Field(default=None, ge=0)
    declaration_function_ast_id: int | None = Field(default=None, ge=0)
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteTestDescriptor:
        """Validate and self-hash a newly discovered descriptor."""

        if "descriptor_sha256" in values:
            raise ValueError("descriptor_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, descriptor_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"descriptor_sha256"})
        return cls.model_validate(
            {
                **payload,
                "descriptor_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("project_root")
    @classmethod
    def project_root_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=True):
            raise ValueError("repository suite project root must be repository-relative")
        return value

    @field_validator("path", "declaration_path")
    @classmethod
    def path_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _repository_suite_path_is_safe(value, allow_root=False):
            raise ValueError("repository suite test path must be repository-relative")
        return value

    @field_validator(
        "suite_name",
        "test_name",
        "declaration_suite_name",
        "declaration_signature",
    )
    @classmethod
    def names_are_bounded_printable_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not _repository_suite_text_is_safe(value):
            raise ValueError("repository suite and test names must be bounded printable text")
        return value

    @model_validator(mode="after")
    def source_range_and_hash_are_consistent(self) -> RepositorySuiteTestDescriptor:
        if self.end_line < self.start_line:
            raise ValueError("repository suite descriptor end line precedes its start line")
        if self.path != self.project_relative_path:
            raise ValueError("repository suite test path must reside under its project root")
        inventory_fields = (
            self.inventory_sha256,
            self.inventory_record_sha256,
            self.execution_contract_ast_id,
            self.declaration_path,
            self.declaration_suite_name,
            self.declaration_signature,
            self.declaration_source_sha256,
            self.declaration_start_line,
            self.declaration_end_line,
            self.declaration_contract_ast_id,
            self.declaration_function_ast_id,
        )
        populated = tuple(value is not None for value in inventory_fields)
        if any(populated) and not all(populated):
            raise ValueError("repository suite inventory descriptor fields must be all-or-none")
        if all(populated):
            if self.framework is not RepositorySuiteFramework.FOUNDRY:
                raise ValueError("only Foundry descriptors may carry compiler inventory")
            assert self.declaration_path is not None
            assert self.declaration_signature is not None
            assert self.declaration_start_line is not None
            assert self.declaration_end_line is not None
            if self.project_root != "." and not self.declaration_path.startswith(
                f"{self.project_root}/"
            ):
                raise ValueError(
                    "repository suite declaration path must reside under its project root"
                )
            if self.declaration_end_line < self.declaration_start_line:
                raise ValueError("repository suite declaration range is reversed")
            if not self.declaration_signature.startswith(f"{self.test_name}("):
                raise ValueError("repository suite declaration signature differs from test name")
        if self.descriptor_sha256 != self.expected_descriptor_sha256():
            raise ValueError("repository suite descriptor hash does not match its fields")
        return self

    @property
    def project_relative_path(self) -> str:
        if self.project_root == ".":
            return self.path
        prefix = f"{self.project_root}/"
        if not self.path.startswith(prefix):
            return ""
        return self.path

    @property
    def canonical_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.framework.value,
            self.project_root,
            self.path,
            self.suite_name,
            self.test_name,
        )

    @property
    def collision_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.framework.value.casefold(),
            self.project_root.casefold(),
            self.path.casefold(),
            self.suite_name.casefold(),
            self.test_name.casefold(),
        )

    @property
    def inventory_bound(self) -> bool:
        """Return whether compiler evidence binds execution to its declaration."""

        return self.inventory_sha256 is not None

    @property
    def finding_path(self) -> str:
        """Return the effective declaration path used for finding evidence."""

        return self.declaration_path or self.path

    @property
    def finding_source_sha256(self) -> str:
        """Return the effective declaration source hash."""

        return self.declaration_source_sha256 or self.source_sha256

    @property
    def finding_start_line(self) -> int:
        """Return the effective declaration start line."""

        return self.declaration_start_line or self.start_line

    @property
    def finding_end_line(self) -> int:
        """Return the effective declaration end line."""

        return self.declaration_end_line or self.end_line

    def expected_descriptor_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"descriptor_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteSelection(StrictModel):
    """Hash-bound result of bounded repository-suite selection."""

    schema_version: Literal["1.0"] = "1.0"
    profile: Literal["legacy_audit", "explicit"]
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_exclusion_path: str = Field(min_length=1, max_length=1_000)
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_file_count: int = Field(ge=0)
    candidate_test_count: int = Field(ge=0)
    selected_file_count: int = Field(ge=0)
    selected_test_count: int = Field(ge=0)
    omitted_file_count: int = Field(ge=0)
    omitted_test_count: int = Field(ge=0)
    limit_reached: bool
    inventory_kind: RepositorySuiteInventoryKind = RepositorySuiteInventoryKind.STATIC_SOURCE
    inventory_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    tests: tuple[RepositorySuiteTestDescriptor, ...] = Field(max_length=10_000)
    safety_claim: Literal[False] = False
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteSelection:
        """Validate and self-hash a completed bounded selection."""

        if "selection_sha256" in values:
            raise ValueError("selection_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, selection_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"selection_sha256"})
        return cls.model_validate(
            {
                **payload,
                "selection_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("repository_exclusion_path")
    @classmethod
    def repository_exclusion_path_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=False):
            raise ValueError(
                "repository suite exclusion path must be normalized and repository-relative"
            )
        return value

    @model_validator(mode="after")
    def counts_order_and_hash_are_consistent(self) -> RepositorySuiteSelection:
        keys = tuple(test.canonical_key for test in self.tests)
        collision_keys = tuple(test.collision_key for test in self.tests)
        descriptor_hashes = tuple(test.descriptor_sha256 for test in self.tests)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("repository suite descriptors must be unique and canonically sorted")
        if len(descriptor_hashes) != len(set(descriptor_hashes)):
            raise ValueError("repository suite descriptor hashes must be unique")
        if len(collision_keys) != len(set(collision_keys)):
            raise ValueError("repository suite descriptors have a case-insensitive collision")
        selected_files = {
            (test.framework.value, test.project_root, test.path) for test in self.tests
        }
        if self.selected_file_count != len(selected_files) or self.selected_test_count != len(
            self.tests
        ):
            raise ValueError("repository suite selected counts do not match its descriptors")
        if (
            self.candidate_file_count != self.selected_file_count + self.omitted_file_count
            or self.candidate_test_count != self.selected_test_count + self.omitted_test_count
        ):
            raise ValueError("repository suite candidate and omission counts are inconsistent")
        if self.limit_reached:
            raise ValueError("repository suite selection must fail instead of truncating at limits")
        if self.inventory_kind is RepositorySuiteInventoryKind.STATIC_SOURCE:
            if self.inventory_sha256 is not None or any(
                descriptor.inventory_bound for descriptor in self.tests
            ):
                raise ValueError("static repository selection cannot claim compiler inventory")
        else:
            if self.inventory_sha256 is None:
                raise ValueError("compiler-backed repository selection requires inventory hash")
            if any(
                descriptor.inventory_sha256 != self.inventory_sha256 for descriptor in self.tests
            ):
                raise ValueError("compiler-backed descriptors must bind the selection inventory")
        if self.selection_sha256 != self.expected_selection_sha256():
            raise ValueError("repository suite selection hash does not match its fields")
        return self

    def expected_selection_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"selection_sha256"})
        return _canonical_model_sha256(payload)


class HardhatReporterInventory(StrictModel):
    """Strict, self-hashed inventory emitted only by the trusted image reporter."""

    schema_version: Literal["1.0"] = "1.0"
    reporter_name: Literal["mmaudit-hardhat-reporter"] = "mmaudit-hardhat-reporter"
    reporter_version: str = Field(min_length=1, max_length=200)
    reporter_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tests: tuple[RepositorySuiteTestDescriptor, ...] = Field(max_length=10_000)
    completed: Literal[True] = True
    safety_claim: Literal[False] = False
    inventory_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> HardhatReporterInventory:
        """Validate and self-hash one complete reporter inventory."""

        if "inventory_sha256" in values:
            raise ValueError("inventory_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, inventory_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"inventory_sha256"})
        return cls.model_validate(
            {
                **payload,
                "inventory_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def framework_order_and_hash_are_consistent(self) -> HardhatReporterInventory:
        keys = tuple(test.canonical_key for test in self.tests)
        collision_keys = tuple(test.collision_key for test in self.tests)
        if any(
            test.framework is not RepositorySuiteFramework.HARDHAT or test.inventory_bound
            for test in self.tests
        ):
            raise ValueError("Hardhat reporter inventory must contain static Hardhat descriptors")
        if keys != tuple(sorted(set(keys))):
            raise ValueError(
                "Hardhat reporter inventory descriptors must be unique and canonically sorted"
            )
        if len(collision_keys) != len(set(collision_keys)):
            raise ValueError(
                "Hardhat reporter inventory has a case-insensitive descriptor collision"
            )
        if self.inventory_sha256 != self.expected_inventory_sha256():
            raise ValueError("Hardhat reporter inventory hash does not match its fields")
        return self

    def expected_inventory_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"inventory_sha256"})
        return _canonical_model_sha256(payload)


class HardhatReporterTestResult(StrictModel):
    """One bounded terminal test record from the trusted Hardhat reporter."""

    schema_version: Literal["1.0"] = "1.0"
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    path: str = Field(min_length=1, max_length=1_000)
    suite_name: str = Field(min_length=1, max_length=1_000)
    test_name: str = Field(min_length=1, max_length=1_000)
    status: RepositoryTestExecutionStatus
    terminal_detail: str | None = Field(default=None, max_length=8_000)
    duration_seconds: float = Field(ge=0, le=1_800)
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> HardhatReporterTestResult:
        """Validate and self-hash one trusted reporter result."""

        if "result_sha256" in values:
            raise ValueError("result_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, result_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"result_sha256"})
        return cls.model_validate(
            {
                **payload,
                "result_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=False):
            raise ValueError("Hardhat reporter result path must be repository-relative")
        return value

    @field_validator("suite_name", "test_name")
    @classmethod
    def names_are_bounded_printable_text(cls, value: str) -> str:
        if not _repository_suite_text_is_safe(value):
            raise ValueError("Hardhat reporter result names must be bounded printable text")
        return value

    @field_validator("terminal_detail")
    @classmethod
    def detail_is_bounded_printable_text(cls, value: str | None) -> str | None:
        if value is not None and not _repository_suite_text_is_safe(value):
            raise ValueError("Hardhat reporter result detail must be bounded printable text")
        return value

    @model_validator(mode="after")
    def outcome_and_hash_are_consistent(self) -> HardhatReporterTestResult:
        classified_statuses = {
            RepositoryTestExecutionStatus.PASSED,
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
            RepositoryTestExecutionStatus.SKIPPED,
        }
        if self.status not in classified_statuses:
            raise ValueError("Hardhat reporter result is not a classified terminal outcome")
        failure_statuses = {
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        }
        if self.status in failure_statuses and self.terminal_detail is None:
            raise ValueError("failing Hardhat reporter result requires terminal detail")
        if self.status not in failure_statuses and self.terminal_detail is not None:
            raise ValueError("non-failing Hardhat reporter result cannot carry failure detail")
        if self.result_sha256 != self.expected_result_sha256():
            raise ValueError("Hardhat reporter result hash does not match its fields")
        return self

    def expected_result_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"result_sha256"})
        return _canonical_model_sha256(payload)


class HardhatReporterExecution(StrictModel):
    """Complete self-hashed reporter output bound to one explicit suite selection."""

    schema_version: Literal["1.0"] = "1.0"
    reporter_name: Literal["mmaudit-hardhat-reporter"] = "mmaudit-hardhat-reporter"
    reporter_version: str = Field(min_length=1, max_length=200)
    reporter_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    chain_id: int = Field(ge=1)
    block_number: int = Field(ge=0)
    block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    fuzz_seed: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    results: tuple[HardhatReporterTestResult, ...] = Field(max_length=10_000)
    completed: Literal[True] = True
    safety_claim: Literal[False] = False
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> HardhatReporterExecution:
        """Validate and self-hash one complete reporter execution."""

        if "report_sha256" in values:
            raise ValueError("report_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, report_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"report_sha256"})
        return cls.model_validate(
            {
                **payload,
                "report_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def result_order_and_hash_are_consistent(self) -> HardhatReporterExecution:
        descriptor_hashes = tuple(result.descriptor_sha256 for result in self.results)
        if descriptor_hashes != tuple(sorted(set(descriptor_hashes))):
            raise ValueError(
                "Hardhat reporter results must be unique and ordered by descriptor hash"
            )
        if self.report_sha256 != self.expected_report_sha256():
            raise ValueError("Hardhat reporter execution hash does not match its fields")
        return self

    def expected_report_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"report_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteExecutionPolicy(StrictModel):
    """Typed, self-hashed policy that independently binds repository-suite execution."""

    schema_version: Literal["1.0"] = "1.0"
    framework: Literal[RepositorySuiteFramework.FOUNDRY] = RepositorySuiteFramework.FOUNDRY
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    chain_id: int = Field(ge=1)
    block_number: int = Field(ge=0)
    block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    tool_name: Literal["forge"] = "forge"
    tool_version: str = Field(min_length=1, max_length=1_000)
    tool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    compiler_version: str = Field(min_length=1, max_length=1_000)
    compiler_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    isolation_backend: str = Field(min_length=1, max_length=200)
    isolation_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fuzz_seed: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    fuzz_runs: int = Field(ge=1, le=1_000_000)
    invariant_runs: int = Field(ge=1, le=100_000)
    per_test_timeout_seconds: float = Field(gt=0, le=1_800)
    total_timeout_seconds: float = Field(gt=0, le=7_200)
    max_output_bytes_per_test: int = Field(ge=1_024, le=10_000_000)
    max_total_output_bytes: int = Field(ge=1_024, le=100_000_000)
    ffi_enabled: Literal[False] = False
    fs_permissions: Literal["[]"] = "[]"
    foundry_profile: Literal["default"] = "default"
    offline: Literal[True] = True
    storage_caching: Literal[False] = False
    threads: Literal[1] = 1
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteExecutionPolicy:
        """Validate and self-hash a canonical execution policy."""

        if "policy_sha256" in values:
            raise ValueError("policy_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, policy_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"policy_sha256"})
        return cls.model_validate(
            {
                **payload,
                "policy_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def limits_and_hash_are_consistent(self) -> RepositorySuiteExecutionPolicy:
        if self.total_timeout_seconds < self.per_test_timeout_seconds:
            raise ValueError("repository execution total timeout is below its per-test timeout")
        if self.max_total_output_bytes < self.max_output_bytes_per_test:
            raise ValueError(
                "repository execution total output is below its per-test output ceiling"
            )
        if self.policy_sha256 != self.expected_policy_sha256():
            raise ValueError("repository suite execution policy hash does not match its fields")
        return self

    def expected_policy_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"policy_sha256"})
        return _canonical_model_sha256(payload)


class RepositoryTestExecution(StrictModel):
    """Terminal, hash-bound execution evidence for one selected repository test."""

    schema_version: Literal["1.0"] = "1.0"
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    inventory_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    post_inventory_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    inventory_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    framework: RepositorySuiteFramework
    project_root: str = Field(min_length=1, max_length=1_000)
    path: str = Field(min_length=1, max_length=1_000)
    suite_name: str = Field(min_length=1, max_length=1_000)
    test_name: str = Field(min_length=1, max_length=1_000)
    chain_id: int | None = Field(default=None, ge=1)
    block_number: int | None = Field(default=None, ge=0)
    block_hash: str | None = Field(default=None, pattern=r"^0x[0-9a-f]{64}$")
    fuzz_seed: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    test_kind: RepositoryTestKind | None = None
    fuzz_cases: int = Field(default=0, ge=0, le=2**63 - 1)
    invariant_runs: int = Field(default=0, ge=0, le=2**63 - 1)
    invariant_calls: int = Field(default=0, ge=0, le=2**63 - 1)
    status: RepositoryTestExecutionStatus
    terminal_detail: str | None = Field(default=None, max_length=8_000)
    duration_seconds: float = Field(ge=0, le=7_200)
    command_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    output_bytes: int = Field(default=0, ge=0, le=100_000_000)
    machine_result_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    process_exit_code: int | None = None
    machine_output_validated: bool = False
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    repository_code_execution: RepositoryCodeExecutionState = (
        RepositoryCodeExecutionState.NOT_APPLICABLE
    )
    isolation_backend: str | None = Field(default=None, min_length=1, max_length=200)
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    compiler_version: str | None = Field(default=None, min_length=1, max_length=1_000)
    compiler_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    execution_policy_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    safety_claim: Literal[False] = False
    execution_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositoryTestExecution:
        """Validate and self-hash one terminal execution observation."""

        if "execution_sha256" in values:
            raise ValueError("execution_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, execution_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"execution_sha256"})
        return cls.model_validate(
            {
                **payload,
                "execution_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("project_root")
    @classmethod
    def project_root_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=True):
            raise ValueError("repository test execution project root must be repository-relative")
        return value

    @field_validator("path")
    @classmethod
    def path_is_safe(cls, value: str) -> str:
        if not _repository_suite_path_is_safe(value, allow_root=False):
            raise ValueError("repository test execution path must be repository-relative")
        return value

    @field_validator("suite_name", "test_name")
    @classmethod
    def names_are_bounded_printable_text(cls, value: str) -> str:
        if not _repository_suite_text_is_safe(value):
            raise ValueError("repository execution names must be bounded printable text")
        return value

    @field_validator("terminal_detail")
    @classmethod
    def terminal_detail_is_printable(cls, value: str | None) -> str | None:
        if value is not None and (not _repository_suite_text_is_safe(value)):
            raise ValueError("repository execution detail must be bounded printable text")
        return value

    @model_validator(mode="after")
    def terminal_evidence_and_hash_are_consistent(self) -> RepositoryTestExecution:
        if self.project_root != "." and not self.path.startswith(f"{self.project_root}/"):
            raise ValueError("repository test execution path must reside under its project root")
        attempted = {
            RepositoryTestExecutionStatus.PASSED,
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
            RepositoryTestExecutionStatus.TIMED_OUT,
            RepositoryTestExecutionStatus.INVALID_OUTPUT,
        }
        machine_validated = {
            RepositoryTestExecutionStatus.PASSED,
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        }
        detail_required = set(RepositoryTestExecutionStatus) - {
            RepositoryTestExecutionStatus.PASSED
        }
        if self.status in attempted:
            if self.chain_id is None or self.block_number is None or self.block_hash is None:
                raise ValueError("attempted repository test requires pinned fork chain and block")
            if self.command_sha256 is None or self.output_sha256 is None:
                raise ValueError("attempted repository test requires command and output hashes")
            if self.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED:
                raise ValueError("attempted repository test requires isolated repository code")
            if self.isolation_backend is None or self.isolation_attestation_sha256 is None:
                raise ValueError("attempted repository test requires isolation evidence")
            if (
                self.compiler_version is None
                or self.compiler_sha256 is None
                or self.execution_policy_sha256 is None
            ):
                raise ValueError(
                    "attempted repository test requires compiler and execution-policy evidence"
                )
        if self.status in machine_validated and not self.machine_output_validated:
            raise ValueError("classified repository test outcome requires validated machine output")
        if self.status not in machine_validated and self.machine_output_validated:
            raise ValueError("non-classified repository test cannot claim validated machine output")
        if self.status in machine_validated and self.machine_result_sha256 is None:
            raise ValueError(
                "classified repository test outcome requires a normalized machine-result hash"
            )
        if self.status not in machine_validated and self.machine_result_sha256 is not None:
            raise ValueError(
                "unclassified repository test cannot claim a normalized machine-result hash"
            )
        if self.status in detail_required and self.terminal_detail is None:
            raise ValueError("non-passing repository test requires terminal detail")
        if self.status is RepositoryTestExecutionStatus.PASSED:
            if self.terminal_detail is not None or self.process_exit_code != 0:
                raise ValueError("passing repository test requires exit zero and no failure detail")
        elif self.status in {
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        } and self.process_exit_code in {None, 0}:
            raise ValueError("failed repository test requires a nonzero process exit code")
        if self.status in machine_validated and self.test_kind is None:
            raise ValueError("classified repository test requires a typed campaign kind")
        if self.status not in machine_validated and self.test_kind is not None:
            raise ValueError("unclassified repository test cannot claim a campaign kind")
        if self.test_kind is RepositoryTestKind.UNIT and (
            self.fuzz_cases or self.invariant_runs or self.invariant_calls
        ):
            raise ValueError("unit repository test cannot claim fuzz or invariant campaigns")
        if self.test_kind is RepositoryTestKind.FUZZ and (
            self.fuzz_cases < 1 or self.invariant_runs or self.invariant_calls
        ):
            raise ValueError("fuzz repository test requires only a nonzero fuzz campaign")
        if self.test_kind is RepositoryTestKind.INVARIANT and (
            self.fuzz_cases or self.invariant_runs < 1 or self.invariant_calls < 1
        ):
            raise ValueError("invariant repository test requires nonzero invariant runs and calls")
        if self.test_kind is None and (
            self.fuzz_cases or self.invariant_runs or self.invariant_calls
        ):
            raise ValueError("unclassified repository test cannot claim campaign counts")
        if self.output_sha256 is None and self.output_bytes:
            raise ValueError("repository test output bytes require an output hash")
        inventory_fields = (
            self.inventory_sha256,
            self.post_inventory_sha256,
            self.inventory_record_sha256,
        )
        if any(value is not None for value in inventory_fields) and not all(
            value is not None for value in inventory_fields
        ):
            raise ValueError("repository test inventory bindings must be all-or-none")
        if self.execution_sha256 != self.expected_execution_sha256():
            raise ValueError("repository test execution hash does not match its fields")
        return self

    @property
    def canonical_key(self) -> tuple[str, str, str, str, str]:
        return (
            self.framework.value,
            self.project_root,
            self.path,
            self.suite_name,
            self.test_name,
        )

    def expected_execution_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"execution_sha256"})
        return _canonical_model_sha256(payload)


_TRUSTED_READ_ONLY_FORK_RPC_METHODS = frozenset(
    {
        "eth_blockNumber",
        "eth_call",
        "eth_chainId",
        "eth_gasPrice",
        "eth_getAccountInfo",
        "eth_getBalance",
        "eth_getBlockByHash",
        "eth_getBlockByNumber",
        "eth_getBlockReceipts",
        "eth_getBlockTransactionCountByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getCode",
        "eth_getLogs",
        "eth_getStorageAt",
        "eth_getTransactionByBlockHashAndIndex",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionCount",
        "eth_getUncleByBlockHashAndIndex",
        "eth_getUncleByBlockNumberAndIndex",
        "eth_getUncleCountByBlockHash",
        "eth_getUncleCountByBlockNumber",
        "net_version",
    }
)


class ForkRpcMethodCount(StrictModel):
    """Permitted-method accounting from a trusted local RPC bridge snapshot."""

    method: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
    count: int = Field(ge=1, le=1_000_000)

    @field_validator("count", mode="before")
    @classmethod
    def count_is_an_exact_integer(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("fork RPC method count requires an exact integer")
        return value


class RepositoryTestForkRpcScopeEvidence(StrictModel):
    """Self-hashed per-test accounting from one drained read-only RPC scope."""

    schema_version: Literal["1.0"] = "1.0"
    attempt_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sequence_index: int = Field(ge=1, le=10_000)
    bridge_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_chain_id: int = Field(ge=1, lt=2**64)
    pinned_block_number: int = Field(ge=0, lt=2**64)
    pinned_block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    status: RepositoryTestForkRpcScopeStatus
    http_request_count: int = Field(ge=0, le=1_000_000)
    permitted_rpc_call_count: int = Field(ge=0, le=1_000_000)
    origin_attempted_rpc_call_count: int = Field(ge=0, le=1_000_000)
    origin_validated_rpc_call_count: int = Field(ge=0, le=1_000_000)
    synthetic_rpc_call_count: int = Field(ge=0, le=1_000_000)
    denied_request_count: int = Field(ge=0, le=1_000_000)
    malformed_request_count: int = Field(ge=0, le=1_000_000)
    limit_exceeded_request_count: int = Field(ge=0, le=1_000_000)
    upstream_error_request_count: int = Field(ge=0, le=1_000_000)
    allowed_method_counts: tuple[ForkRpcMethodCount, ...] = Field(max_length=512)
    method_log_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    boundary_drained: Literal[True]
    transaction_capable_request_forwarded: Literal[False]
    credentials_forwarded: Literal[False]
    raw_payloads_retained: Literal[False]
    rpc_endpoint_recorded: Literal[False]
    bridge_scope_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositoryTestForkRpcScopeEvidence:
        """Validate and self-hash one bridge-emitted per-test scope."""

        if "evidence_sha256" in values:
            raise ValueError("evidence_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("allowed_method_counts")
    @classmethod
    def method_counts_are_canonical(
        cls,
        value: tuple[ForkRpcMethodCount, ...],
    ) -> tuple[ForkRpcMethodCount, ...]:
        methods = tuple(item.method for item in value)
        if methods != tuple(sorted(set(methods))):
            raise ValueError(
                "per-test fork RPC method counts must be unique and canonically sorted"
            )
        if any(method not in _TRUSTED_READ_ONLY_FORK_RPC_METHODS for method in methods):
            raise ValueError("per-test fork RPC method is outside the trusted read-only vocabulary")
        return value

    @field_validator(
        "sequence_index",
        "expected_chain_id",
        "pinned_block_number",
        "http_request_count",
        "permitted_rpc_call_count",
        "origin_attempted_rpc_call_count",
        "origin_validated_rpc_call_count",
        "synthetic_rpc_call_count",
        "denied_request_count",
        "malformed_request_count",
        "limit_exceeded_request_count",
        "upstream_error_request_count",
        mode="before",
    )
    @classmethod
    def integer_evidence_is_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("per-test fork RPC counters and identities require exact integers")
        return value

    @field_validator(
        "boundary_drained",
        "transaction_capable_request_forwarded",
        "credentials_forwarded",
        "raw_payloads_retained",
        "rpc_endpoint_recorded",
        mode="before",
    )
    @classmethod
    def boundary_facts_are_exact_booleans(cls, value: object) -> object:
        if not isinstance(value, bool):
            raise ValueError("per-test fork RPC boundary facts require exact booleans")
        return value

    @model_validator(mode="after")
    def accounting_status_and_hash_are_consistent(
        self,
    ) -> RepositoryTestForkRpcScopeEvidence:
        if (
            self.origin_attempted_rpc_call_count + self.synthetic_rpc_call_count
            != self.permitted_rpc_call_count
            or self.origin_validated_rpc_call_count > self.origin_attempted_rpc_call_count
            or (self.origin_validated_rpc_call_count == self.origin_attempted_rpc_call_count)
            != (self.upstream_error_request_count == 0)
            or sum(item.count for item in self.allowed_method_counts)
            != self.permitted_rpc_call_count
        ):
            raise ValueError(
                "per-test fork RPC permitted-call accounting does not match scope counters"
            )
        rejection_or_error_count = (
            self.denied_request_count
            + self.malformed_request_count
            + self.limit_exceeded_request_count
            + self.upstream_error_request_count
        )
        if rejection_or_error_count > self.http_request_count:
            raise ValueError("per-test fork RPC rejection/error count exceeds HTTP request count")
        if rejection_or_error_count:
            if self.status is not RepositoryTestForkRpcScopeStatus.VIOLATION:
                raise ValueError(
                    "per-test fork RPC rejection or upstream error requires violation status"
                )
        elif self.status is RepositoryTestForkRpcScopeStatus.VIOLATION:
            raise ValueError("per-test fork RPC violation requires a rejection or upstream error")
        if (
            self.origin_attempted_rpc_call_count == 0
            and rejection_or_error_count == 0
            and self.status is not RepositoryTestForkRpcScopeStatus.NOT_OBSERVED
        ):
            raise ValueError("per-test fork RPC zero origin requires not-observed status")
        if self.status is RepositoryTestForkRpcScopeStatus.VALIDATED and (
            self.origin_validated_rpc_call_count == 0
            or self.origin_attempted_rpc_call_count != self.origin_validated_rpc_call_count
            or rejection_or_error_count
        ):
            raise ValueError(
                "validated per-test fork RPC evidence requires nonempty fully validated origin reads"
            )
        if self.status is RepositoryTestForkRpcScopeStatus.NOT_OBSERVED and (
            self.origin_attempted_rpc_call_count != 0
            or self.origin_validated_rpc_call_count != 0
            or rejection_or_error_count
        ):
            raise ValueError(
                "not-observed per-test fork RPC evidence requires zero origin and no errors"
            )
        if self.bridge_scope_snapshot_sha256 != self.expected_bridge_scope_snapshot_sha256():
            raise ValueError(
                "per-test fork RPC bridge scope snapshot hash does not match its fields"
            )
        if self.evidence_sha256 != self.expected_evidence_sha256():
            raise ValueError("per-test fork RPC evidence hash does not match its fields")
        return self

    @staticmethod
    def calculate_bridge_scope_snapshot_sha256(values: dict[str, Any]) -> str:
        """Hash the exact canonical primitive projection emitted by one bridge scope."""

        raw_method_counts = values["allowed_method_counts"]
        method_counts = [
            (
                item.model_dump(mode="json")
                if isinstance(item, ForkRpcMethodCount)
                else {"method": item["method"], "count": item["count"]}
            )
            for item in raw_method_counts
        ]
        status = values["status"]
        if isinstance(status, RepositoryTestForkRpcScopeStatus):
            status = status.value
        payload = {
            "schema_version": values["schema_version"],
            "attempt_binding_sha256": values["attempt_binding_sha256"],
            "selection_sha256": values["selection_sha256"],
            "descriptor_sha256": values["descriptor_sha256"],
            "sequence_index": values["sequence_index"],
            "policy_sha256": values["bridge_policy_sha256"],
            "expected_chain_id": values["expected_chain_id"],
            "pinned_block_number": values["pinned_block_number"],
            "pinned_block_hash": values["pinned_block_hash"],
            "status": status,
            "http_request_count": values["http_request_count"],
            "permitted_rpc_call_count": values["permitted_rpc_call_count"],
            "origin_attempted_rpc_call_count": values["origin_attempted_rpc_call_count"],
            "origin_validated_rpc_call_count": values["origin_validated_rpc_call_count"],
            "synthetic_rpc_call_count": values["synthetic_rpc_call_count"],
            "denied_request_count": values["denied_request_count"],
            "malformed_request_count": values["malformed_request_count"],
            "limit_exceeded_request_count": values["limit_exceeded_request_count"],
            "upstream_error_request_count": values["upstream_error_request_count"],
            "allowed_method_counts": method_counts,
            "method_log_sha256": values["method_log_sha256"],
            "boundary_drained": values["boundary_drained"],
        }
        return _canonical_model_sha256(payload)

    def expected_bridge_scope_snapshot_sha256(self) -> str:
        """Recompute the trusted per-test bridge-scope snapshot binding."""

        return self.calculate_bridge_scope_snapshot_sha256(self.model_dump(mode="python"))

    def expected_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        return _canonical_model_sha256(payload)


class ForkRpcReadOnlyEgressEvidence(StrictModel):
    """Self-hashed, endpoint-free evidence from the trusted read-only RPC boundary."""

    schema_version: Literal["2.0"] = "2.0"
    status: RepositoryForkEgressStatus
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    state_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_chain_id: int = Field(ge=1, lt=2**64)
    pinned_block_number: int = Field(ge=0, lt=2**64)
    pinned_block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    boundary_kind: Literal["trusted_read_only_loopback_bridge"] = (
        "trusted_read_only_loopback_bridge"
    )
    network_scope: Literal["single_loopback_origin"] = "single_loopback_origin"
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    method_log_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selected_test_scope_snapshot_sha256s: tuple[str, ...] = Field(
        default=(),
        max_length=10_000,
        exclude_if=lambda value: not value,
    )
    preflight_origin_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    postflight_origin_observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    origin_state_stable: Literal[True] = True
    http_request_count: int = Field(ge=0, le=1_000_000)
    permitted_rpc_call_count: int = Field(ge=0, le=1_000_000)
    origin_attempted_rpc_call_count: int = Field(ge=0, le=1_000_000)
    origin_validated_rpc_call_count: int = Field(ge=0, le=1_000_000)
    synthetic_rpc_call_count: int = Field(ge=0, le=1_000_000)
    denied_request_count: int = Field(ge=0, le=1_000_000)
    malformed_request_count: int = Field(ge=0, le=1_000_000)
    limit_exceeded_request_count: int = Field(ge=0, le=1_000_000)
    upstream_error_request_count: int = Field(ge=0, le=1_000_000)
    allowed_method_counts: tuple[ForkRpcMethodCount, ...] = Field(max_length=512)
    stopped_cleanly: Literal[True] = True
    transaction_capable_request_forwarded: Literal[False] = False
    credentials_forwarded: Literal[False] = False
    raw_payloads_retained: Literal[False] = False
    rpc_endpoint_recorded: Literal[False] = False
    bridge_snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> ForkRpcReadOnlyEgressEvidence:
        """Validate and self-hash one endpoint-free bridge snapshot."""

        if "evidence_sha256" in values:
            raise ValueError("evidence_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        if not payload.get("selected_test_scope_snapshot_sha256s"):
            payload.pop("selected_test_scope_snapshot_sha256s", None)
        return cls.model_validate(
            {
                **payload,
                "evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("allowed_method_counts")
    @classmethod
    def method_counts_are_canonical(
        cls,
        value: tuple[ForkRpcMethodCount, ...],
    ) -> tuple[ForkRpcMethodCount, ...]:
        methods = tuple(item.method for item in value)
        if methods != tuple(sorted(set(methods))):
            raise ValueError("fork RPC method counts must be unique and canonically sorted")
        if any(method not in _TRUSTED_READ_ONLY_FORK_RPC_METHODS for method in methods):
            raise ValueError("fork RPC method is outside the trusted read-only bridge vocabulary")
        return value

    @field_validator("selected_test_scope_snapshot_sha256s")
    @classmethod
    def selected_test_scope_hashes_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in value):
            raise ValueError("selected-test scope ledger requires SHA-256 values")
        if len(value) != len(set(value)):
            raise ValueError("selected-test scope ledger hashes must be unique")
        return value

    @field_validator(
        "expected_chain_id",
        "pinned_block_number",
        "http_request_count",
        "permitted_rpc_call_count",
        "origin_attempted_rpc_call_count",
        "origin_validated_rpc_call_count",
        "synthetic_rpc_call_count",
        "denied_request_count",
        "malformed_request_count",
        "limit_exceeded_request_count",
        "upstream_error_request_count",
        mode="before",
    )
    @classmethod
    def integer_evidence_is_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("fork RPC counters and state identity require exact integers")
        return value

    @staticmethod
    def calculate_origin_observation_sha256(
        *,
        expected_chain_id: int,
        pinned_block_number: int,
        pinned_block_hash: str,
    ) -> str:
        """Hash the exact canonical identity emitted by a pinned-origin observation."""

        if (
            isinstance(expected_chain_id, bool)
            or not isinstance(expected_chain_id, int)
            or not 1 <= expected_chain_id < 2**64
            or isinstance(pinned_block_number, bool)
            or not isinstance(pinned_block_number, int)
            or not 0 <= pinned_block_number < 2**64
            or re.fullmatch(r"0x[0-9a-f]{64}", pinned_block_hash) is None
        ):
            raise ValueError("canonical pinned observation identity is invalid")
        return _canonical_model_sha256(
            {
                "schema_version": "1.0",
                "chain_id": expected_chain_id,
                "block_number": pinned_block_number,
                "block_hash": pinned_block_hash,
            }
        )

    @model_validator(mode="after")
    def accounting_status_and_hash_are_consistent(self) -> ForkRpcReadOnlyEgressEvidence:
        if (
            self.origin_attempted_rpc_call_count + self.synthetic_rpc_call_count
            != self.permitted_rpc_call_count
            or self.origin_validated_rpc_call_count > self.origin_attempted_rpc_call_count
            or sum(item.count for item in self.allowed_method_counts)
            != self.permitted_rpc_call_count
        ):
            raise ValueError("fork RPC permitted-call accounting does not match bridge counters")
        rejection_or_error_count = (
            self.denied_request_count
            + self.malformed_request_count
            + self.limit_exceeded_request_count
            + self.upstream_error_request_count
        )
        if rejection_or_error_count > self.http_request_count:
            raise ValueError("fork RPC rejection/error count exceeds HTTP request count")
        if self.status is RepositoryForkEgressStatus.ENFORCED and (
            rejection_or_error_count
            or self.permitted_rpc_call_count == 0
            or self.origin_validated_rpc_call_count == 0
            or self.origin_validated_rpc_call_count != self.origin_attempted_rpc_call_count
        ):
            raise ValueError(
                "enforced fork RPC evidence requires nonempty fully validated read accounting"
            )
        if self.status is RepositoryForkEgressStatus.VIOLATION and rejection_or_error_count == 0:
            raise ValueError("fork RPC violation requires a rejection or upstream error")
        if self.status is RepositoryForkEgressStatus.UNVERIFIED:
            raise ValueError("serialized fork RPC evidence must bind a stopped bridge snapshot")
        expected_observation_sha256 = self.calculate_origin_observation_sha256(
            expected_chain_id=self.expected_chain_id,
            pinned_block_number=self.pinned_block_number,
            pinned_block_hash=self.pinned_block_hash,
        )
        if (
            self.preflight_origin_observation_sha256 != expected_observation_sha256
            or self.postflight_origin_observation_sha256 != expected_observation_sha256
        ):
            raise ValueError("fork RPC observations must bind the canonical pinned observation")
        if self.bridge_snapshot_sha256 != self.expected_bridge_snapshot_sha256():
            raise ValueError("fork RPC bridge snapshot hash does not match its fields")
        if self.evidence_sha256 != self.expected_evidence_sha256():
            raise ValueError("fork RPC egress evidence hash does not match its fields")
        return self

    @staticmethod
    def calculate_bridge_snapshot_sha256(values: dict[str, Any]) -> str:
        """Hash exactly the canonical primitive projection emitted by the bridge."""

        expected_observation_sha256 = (
            ForkRpcReadOnlyEgressEvidence.calculate_origin_observation_sha256(
                expected_chain_id=values["expected_chain_id"],
                pinned_block_number=values["pinned_block_number"],
                pinned_block_hash=values["pinned_block_hash"],
            )
        )
        if (
            values["preflight_origin_observation_sha256"] != expected_observation_sha256
            or values["postflight_origin_observation_sha256"] != expected_observation_sha256
        ):
            raise ValueError(
                "bridge snapshot observations differ from the canonical pinned observation"
            )
        raw_method_counts = values["allowed_method_counts"]
        method_counts = [
            (
                item.model_dump(mode="json")
                if isinstance(item, ForkRpcMethodCount)
                else {"method": item["method"], "count": item["count"]}
            )
            for item in raw_method_counts
        ]
        status = values["status"]
        if isinstance(status, RepositoryForkEgressStatus):
            status = status.value
        payload = {
            "schema_version": values["schema_version"],
            "status": status,
            "policy_sha256": values["policy_sha256"],
            "expected_chain_id": values["expected_chain_id"],
            "pinned_block_number": values["pinned_block_number"],
            "pinned_block_hash": values["pinned_block_hash"],
            "preflight_origin_observation_sha256": values["preflight_origin_observation_sha256"],
            "postflight_origin_observation_sha256": values["postflight_origin_observation_sha256"],
            "origin_state_stable": values["origin_state_stable"],
            "http_request_count": values["http_request_count"],
            "permitted_rpc_call_count": values["permitted_rpc_call_count"],
            "origin_attempted_rpc_call_count": values["origin_attempted_rpc_call_count"],
            "origin_validated_rpc_call_count": values["origin_validated_rpc_call_count"],
            "synthetic_rpc_call_count": values["synthetic_rpc_call_count"],
            "denied_request_count": values["denied_request_count"],
            "malformed_request_count": values["malformed_request_count"],
            "limit_exceeded_request_count": values["limit_exceeded_request_count"],
            "upstream_error_request_count": values["upstream_error_request_count"],
            "allowed_method_counts": method_counts,
            "method_log_sha256": values["method_log_sha256"],
            "stopped_cleanly": values["stopped_cleanly"],
        }
        scope_hashes = tuple(values.get("selected_test_scope_snapshot_sha256s", ()))
        if scope_hashes:
            payload["selected_test_scope_snapshot_sha256s"] = list(scope_hashes)
        return _canonical_model_sha256(payload)

    def expected_bridge_snapshot_sha256(self) -> str:
        """Recompute the trusted bridge snapshot binding."""

        return self.calculate_bridge_snapshot_sha256(self.model_dump(mode="python"))

    def expected_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        if not self.selected_test_scope_snapshot_sha256s:
            payload.pop("selected_test_scope_snapshot_sha256s", None)
        return _canonical_model_sha256(payload)


class RepositoryCleanStateAttestationEvidence(StrictModel):
    """Inspectable process evidence for one internally launched clean chain."""

    schema_version: Literal["2.0"] = "2.0"
    launcher_kind: Literal["trusted_internal_anvil"] = "trusted_internal_anvil"
    launcher_policy_version: Literal["2.0"] = "2.0"
    execution_evidence: Literal[ExecutionEvidenceKind.REAL] = ExecutionEvidenceKind.REAL
    configured_tool_version: str = Field(min_length=1, max_length=160)
    observed_tool_version: str = Field(min_length=1, max_length=160)
    configured_tool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_tool_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trust_pin_validated: Literal[True] = True
    launch_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    environment_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    process_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_arguments_inherited: Literal[False] = False
    target_environment_inherited: Literal[False] = False
    fork_or_state_arguments_present: Literal[False] = False
    target_state_input_present: Literal[False] = False
    listener_scope: Literal["numeric_loopback"] = "numeric_loopback"
    listener_ownership_kind: RepositoryCleanListenerOwnershipKind
    listener_owner_pid_bound: Literal[True]
    runtime_executable_identity_kind: RepositoryCleanRuntimeExecutableIdentityKind
    runtime_executable_matches_pinned_copy: Literal[True]
    exec_path_binding_kind: RepositoryCleanExecPathBindingKind
    version_probe_process_group_absent: Literal[True]
    outbound_network_isolation: Literal["not_attested"] = "not_attested"
    expected_chain_id: int = Field(ge=1)
    observed_chain_id: int = Field(ge=1)
    genesis_block_number: Literal[0]
    genesis_block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    initial_head_block_number: Literal[0]
    initial_head_block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    initial_head_state_root: str | None = Field(pattern=r"^0x[0-9a-f]{64}$")
    final_head_block_number: Literal[0]
    final_head_block_hash: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    final_head_state_root: str | None = Field(pattern=r"^0x[0-9a-f]{64}$")
    pristine_head_pre_post_match: Literal[True]
    startup_completed: Literal[True] = True
    startup_duration_seconds: float = Field(ge=0, le=15)
    termination_method: Literal["term", "kill"]
    termination_duration_seconds: float = Field(ge=0, le=10)
    process_group_absent: Literal[True] = True
    collector_threads_closed: Literal[True]
    executable_descriptor_closed: Literal[True]
    private_workspace_removed: Literal[True]
    ancestor_config_absent: Literal[True]
    no_upstream_fork_configuration: Literal[True] = True
    endpoint_retained: Literal[False] = False
    executable_path_retained: Literal[False] = False
    port_retained: Literal[False] = False
    process_id_retained: Literal[False] = False
    raw_output_retained: Literal[False] = False
    attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositoryCleanStateAttestationEvidence:
        """Validate and self-hash trusted clean-chain process evidence."""

        if "attestation_sha256" in values:
            raise ValueError("attestation_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, attestation_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"attestation_sha256"})
        return cls.model_validate(
            {
                **payload,
                "attestation_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("configured_tool_version", "observed_tool_version")
    @classmethod
    def tool_version_is_bounded_printable_text(cls, value: str) -> str:
        if not _repository_suite_text_is_safe(value):
            raise ValueError("clean-state tool version must be bounded printable text")
        return value

    @field_validator(
        "expected_chain_id",
        "observed_chain_id",
        "genesis_block_number",
        "initial_head_block_number",
        "final_head_block_number",
        mode="before",
    )
    @classmethod
    def integer_identity_is_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("clean-state chain identity requires exact integers")
        return value

    @model_validator(mode="after")
    def trust_identity_and_hash_are_consistent(
        self,
    ) -> RepositoryCleanStateAttestationEvidence:
        if (
            self.configured_tool_version != self.observed_tool_version
            or self.configured_tool_sha256 != self.observed_tool_sha256
        ):
            raise ValueError("clean-state observed tool does not match its configured trust pin")
        if self.expected_chain_id != self.observed_chain_id:
            raise ValueError("clean-state observed chain differs from its configured identity")
        platform_bundle = (
            self.listener_ownership_kind,
            self.runtime_executable_identity_kind,
            self.exec_path_binding_kind,
        )
        valid_platform_bundles = {
            (
                RepositoryCleanListenerOwnershipKind.LINUX_PROC_SOCKET_INODE,
                RepositoryCleanRuntimeExecutableIdentityKind.LINUX_PROC_PID_EXE,
                RepositoryCleanExecPathBindingKind.LINUX_INHERITED_FD,
            ),
            (
                RepositoryCleanListenerOwnershipKind.DARWIN_ROOT_OWNED_LSOF,
                RepositoryCleanRuntimeExecutableIdentityKind.DARWIN_PROC_PIDPATH,
                RepositoryCleanExecPathBindingKind.DARWIN_PRIVATE_PATH_POST_SPAWN_HASH,
            ),
        }
        if platform_bundle not in valid_platform_bundles:
            raise ValueError("clean-state process identity proofs must use one platform bundle")
        if (
            self.genesis_block_number != 0
            or self.initial_head_block_number != 0
            or self.final_head_block_number != 0
            or self.initial_head_block_hash != self.genesis_block_hash
            or self.final_head_block_hash != self.genesis_block_hash
        ):
            raise ValueError("clean-state initial and final head must remain at genesis")
        if (self.initial_head_state_root is None) != (self.final_head_state_root is None):
            raise ValueError("clean-state head state roots must be supplied together")
        if (
            self.initial_head_state_root is not None
            and self.initial_head_state_root != self.final_head_state_root
        ):
            raise ValueError("clean-state initial and final head state roots must match")
        if self.attestation_sha256 != self.expected_attestation_sha256():
            raise ValueError("clean-state attestation hash does not match its fields")
        return self

    def expected_attestation_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"attestation_sha256"})
        return _canonical_model_sha256(payload)

    def expected_state_source_sha256(self) -> str:
        """Derive the reusable clean-state identity from inspectable trusted facts."""

        return _canonical_model_sha256(
            {
                "domain": "mmaudit.repository-clean-state-source.v2",
                "attestation": self.model_dump(
                    mode="json",
                    exclude={"attestation_sha256"},
                ),
            }
        )


class RepositorySuiteExecutionStateEvidence(StrictModel):
    """Configured and optionally observed identity for one differential execution state."""

    schema_version: Literal["1.0"] = "1.0"
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    kind: RepositoryExecutionStateKind
    rpc_url_env: str | None = Field(default=None, pattern=r"^[A-Z_][A-Z0-9_]{0,127}$")
    state_source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_chain_id: int = Field(ge=1)
    pinned_block_number: int = Field(ge=0)
    observation_status: RepositoryExecutionStateObservationStatus
    observed_chain_id: int | None = Field(default=None, ge=1)
    observed_block_number: int | None = Field(default=None, ge=0)
    observed_block_hash: str | None = Field(default=None, pattern=r"^0x[0-9a-f]{64}$")
    clean_state_attestation: RepositoryCleanStateAttestationEvidence | None = None
    observation_detail: str | None = Field(default=None, max_length=2_000)
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteExecutionStateEvidence:
        """Validate and self-hash a configured state and its runtime observation."""

        if "state_sha256" in values:
            raise ValueError("state_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, state_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"state_sha256"})
        return cls.model_validate(
            {
                **payload,
                "state_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("observation_detail")
    @classmethod
    def observation_detail_is_bounded_printable(
        cls,
        value: str | None,
    ) -> str | None:
        if value is not None and not _repository_suite_text_is_safe(value):
            raise ValueError("state observation detail must be bounded printable text")
        return value

    @field_validator(
        "expected_chain_id",
        "pinned_block_number",
        "observed_chain_id",
        "observed_block_number",
        mode="before",
    )
    @classmethod
    def integer_identity_is_exact(cls, value: object) -> object:
        if value is not None and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError("repository execution state identity requires exact integers")
        return value

    @model_validator(mode="after")
    def identity_observation_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteExecutionStateEvidence:
        observed_fields = (
            self.observed_chain_id,
            self.observed_block_number,
            self.observed_block_hash,
        )
        if self.observation_status is RepositoryExecutionStateObservationStatus.OBSERVED:
            if not all(value is not None for value in observed_fields):
                raise ValueError(
                    "observed execution state requires complete chain and block identity"
                )
            if (
                self.observed_chain_id != self.expected_chain_id
                or self.observed_block_number != self.pinned_block_number
            ):
                raise ValueError("observed execution state differs from its configured pin")
            if self.observation_detail is not None:
                raise ValueError("observed execution state cannot carry an unavailable detail")
        else:
            if any(value is not None for value in observed_fields):
                raise ValueError("unobserved execution state cannot claim runtime chain identity")
            if self.observation_detail is None:
                raise ValueError("unobserved execution state requires a bounded detail")
        if self.kind is RepositoryExecutionStateKind.CLEAN_LOCAL:
            if self.rpc_url_env is not None:
                raise ValueError("clean execution state cannot serialize an external RPC variable")
            if self.pinned_block_number != 0:
                raise ValueError("clean execution state must pin its genesis block")
            if self.observation_status is RepositoryExecutionStateObservationStatus.OBSERVED:
                if self.clean_state_attestation is None:
                    raise ValueError(
                        "observed clean state requires trusted no-fork attestation evidence"
                    )
                if (
                    self.clean_state_attestation.expected_chain_id != self.expected_chain_id
                    or self.clean_state_attestation.observed_chain_id != self.observed_chain_id
                    or self.clean_state_attestation.genesis_block_number
                    != self.observed_block_number
                    or self.clean_state_attestation.genesis_block_hash != self.observed_block_hash
                    or self.state_source_sha256
                    != self.clean_state_attestation.expected_state_source_sha256()
                ):
                    raise ValueError(
                        "clean execution state source identity differs from its process attestation"
                    )
            elif self.clean_state_attestation is not None:
                raise ValueError("unobserved clean state cannot claim a no-fork attestation")
        else:
            if self.rpc_url_env is None:
                raise ValueError("pinned fork state requires its configured RPC variable name")
            if self.clean_state_attestation is not None:
                raise ValueError("pinned fork state cannot carry clean-state attestation evidence")
        if self.state_sha256 != self.expected_state_sha256():
            raise ValueError("repository execution state hash does not match its fields")
        return self

    def expected_state_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"state_sha256"})
        return _canonical_model_sha256(payload)


class FoundryTestExecutionSummary(StrictModel):
    """Observed unit, fuzz/property, and invariant coverage from one Forge suite."""

    unit_tests: int = Field(ge=0)
    fuzz_tests: int = Field(ge=0)
    invariant_tests: int = Field(ge=0)
    passed_tests: int = Field(ge=0)
    failed_tests: int = Field(ge=0)
    skipped_tests: int = Field(ge=0)
    fuzz_cases: int = Field(ge=0)
    invariant_runs: int = Field(ge=0)
    invariant_calls: int = Field(ge=0)

    @model_validator(mode="after")
    def outcome_count_matches_classified_tests(self) -> FoundryTestExecutionSummary:
        classified = self.unit_tests + self.fuzz_tests + self.invariant_tests
        outcomes = self.passed_tests + self.failed_tests + self.skipped_tests
        if classified != outcomes:
            raise ValueError("Foundry classified test count must match observed outcomes")
        return self


class RepositorySuiteWorkspaceCopyEvidence(StrictModel):
    """Path-free proof that one exclusive audited-source copy stayed identity-stable."""

    schema_version: Literal["1.0"] = "1.0"
    attempt_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copy_policy_sha256: str = Field(
        REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256,
        pattern=r"^[0-9a-f]{64}$",
    )
    source_inventory_sha256_before: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_inventory_sha256_after: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_inventory_sha256_after_copy: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_inventory_sha256_after_execution: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_root_device_before: int = Field(ge=0)
    source_root_inode_before: int = Field(ge=1)
    source_root_device_after: int = Field(ge=0)
    source_root_inode_after: int = Field(ge=1)
    workspace_root_device_before: int = Field(ge=0)
    workspace_root_inode_before: int = Field(ge=1)
    workspace_root_device_after: int = Field(ge=0)
    workspace_root_inode_after: int = Field(ge=1)
    workspace_parent_device: int = Field(ge=0)
    workspace_parent_inode: int = Field(ge=1)
    workspace_created_exclusively: Literal[True] = True
    workspace_direct_child: Literal[True] = True
    audited_inventory_symlink_free: Literal[True] = True
    source_descriptor_custody_validated: Literal[True] = True
    workspace_descriptor_custody_validated: Literal[True] = True
    workspace_parent_descriptor_custody_validated: Literal[True] = True
    copy_matches_source: Literal[True] = True
    source_identity_stable: Literal[True] = True
    workspace_identity_stable: Literal[True] = True
    workspace_removed: Literal[False] = False
    copy_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteWorkspaceCopyEvidence:
        """Validate and self-hash one scanner-owned source-copy observation."""

        if "copy_evidence_sha256" in values:
            raise ValueError("copy_evidence_sha256 is derived and cannot be supplied to sealed()")
        identity_fields = (
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
        )
        if any(
            isinstance(values.get(name), bool) or not isinstance(values.get(name), int)
            for name in identity_fields
        ):
            raise ValueError("workspace copy root identity requires exact integers")
        provisional = cls.model_construct(**values, copy_evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"copy_evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "copy_evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator(
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
        mode="before",
    )
    @classmethod
    def root_identity_numbers_are_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("workspace copy root identity requires exact integers")
        return value

    @model_validator(mode="after")
    def inventory_identity_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteWorkspaceCopyEvidence:
        if self.attempt_binding_sha256 == "0" * 64:
            raise ValueError("workspace copy requires a nonzero attempt binding")
        if self.copy_policy_sha256 != REPOSITORY_SUITE_WORKSPACE_COPY_POLICY_SHA256:
            raise ValueError("workspace copy policy hash differs from the exact v3 policy")
        inventories = (
            self.source_inventory_sha256_before,
            self.source_inventory_sha256_after,
            self.workspace_inventory_sha256_after_copy,
            self.workspace_inventory_sha256_after_execution,
        )
        if any(value != self.repository_sha256 for value in inventories):
            raise ValueError(
                "workspace copy audited inventory must match the bound repository pre/post"
            )
        if (
            self.source_root_device_before,
            self.source_root_inode_before,
        ) != (
            self.source_root_device_after,
            self.source_root_inode_after,
        ) or (
            self.workspace_root_device_before,
            self.workspace_root_inode_before,
        ) != (
            self.workspace_root_device_after,
            self.workspace_root_inode_after,
        ):
            raise ValueError("workspace copy pre/post root identity must remain stable")
        if self.copy_evidence_sha256 != self.expected_copy_evidence_sha256():
            raise ValueError("workspace copy evidence hash does not match its fields")
        return self

    def expected_copy_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"copy_evidence_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteWorkspaceLifecycleEvidence(StrictModel):
    """Path-free, self-hashed disposal evidence for one matrix attempt root."""

    schema_version: Literal["1.0"] = "1.0"
    status: RepositorySuiteWorkspaceLifecycleStatus
    attempt_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_copy_evidence_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    scanner_execution_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    freshness_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposal_policy_sha256: str = Field(
        REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256,
        pattern=r"^[0-9a-f]{64}$",
    )
    attempt_root_device: int = Field(ge=0)
    attempt_root_inode: int = Field(ge=1)
    attempt_root_created_exclusively: Literal[True] = True
    attempt_root_direct_child: Literal[True] = True
    removal_entry_limit: int = Field(ge=1, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT)
    removed_entry_count: int = Field(
        ge=0,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT,
    )
    removal_depth_limit: int = Field(ge=1, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT)
    maximum_removed_depth: int = Field(ge=0, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT)
    removal_timeout_seconds: float = Field(
        gt=0,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    )
    removal_duration_seconds: float = Field(
        ge=0,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    )
    attempt_descriptor_closed: Literal[True] = True
    workspace_path_absent: Literal[True] = True
    attempt_path_absent: Literal[True] = True
    private_path_retained: Literal[False] = False
    rpc_endpoint_retained: Literal[False] = False
    lifecycle_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteWorkspaceLifecycleEvidence:
        """Validate and self-hash one matrix-owned removal observation."""

        if "lifecycle_evidence_sha256" in values:
            raise ValueError(
                "lifecycle_evidence_sha256 is derived and cannot be supplied to sealed()"
            )
        integer_fields = (
            "attempt_root_device",
            "attempt_root_inode",
            "removal_entry_limit",
            "removed_entry_count",
            "removal_depth_limit",
            "maximum_removed_depth",
        )
        if any(
            isinstance(values.get(name), bool) or not isinstance(values.get(name), int)
            for name in integer_fields
        ):
            raise ValueError("workspace lifecycle counters and identity require exact integers")
        duration_fields = ("removal_timeout_seconds", "removal_duration_seconds")
        durations = tuple(values.get(name) for name in duration_fields)
        if any(
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
            for value in durations
        ):
            raise ValueError("workspace lifecycle durations require exact finite numbers")
        provisional = cls.model_construct(**values, lifecycle_evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"lifecycle_evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "lifecycle_evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator(
        "attempt_root_device",
        "attempt_root_inode",
        "removal_entry_limit",
        "removed_entry_count",
        "removal_depth_limit",
        "maximum_removed_depth",
        mode="before",
    )
    @classmethod
    def lifecycle_integers_are_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("workspace lifecycle counters and identity require exact integers")
        return value

    @field_validator(
        "removal_timeout_seconds",
        "removal_duration_seconds",
        mode="before",
    )
    @classmethod
    def lifecycle_durations_are_finite_numbers(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("workspace lifecycle durations require exact finite numbers")
        numeric = float(value)
        if not math.isfinite(numeric):
            raise ValueError("workspace lifecycle durations require exact finite numbers")
        return numeric

    @model_validator(mode="after")
    def removal_bounds_status_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteWorkspaceLifecycleEvidence:
        if self.attempt_binding_sha256 == "0" * 64:
            raise ValueError("workspace lifecycle requires a nonzero attempt binding")
        if self.disposal_policy_sha256 != REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256:
            raise ValueError("workspace disposal policy hash differs from the exact v3 policy")
        if self.removed_entry_count > self.removal_entry_limit:
            raise ValueError("workspace removal exceeded its entry limit")
        if self.maximum_removed_depth > self.removal_depth_limit:
            raise ValueError("workspace removal exceeded its depth limit")
        if self.removal_duration_seconds > self.removal_timeout_seconds:
            raise ValueError("workspace removal exceeded its timeout")
        if (
            self.removal_entry_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT
            or self.removal_depth_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT
            or self.removal_timeout_seconds != REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
        ):
            raise ValueError("workspace removal bounds differ from the exact v3 policy")
        if self.status is RepositorySuiteWorkspaceLifecycleStatus.VALIDATED and (
            self.workspace_copy_evidence_sha256 is None
            or self.scanner_execution_observation_sha256 is None
        ):
            raise ValueError("validated lifecycle requires copy and scanner observation bindings")
        if self.status is RepositorySuiteWorkspaceLifecycleStatus.VALIDATED and (
            self.removed_entry_count < REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_ENTRY_MINIMUM
            or self.maximum_removed_depth
            < REPOSITORY_SUITE_VALIDATED_WORKSPACE_REMOVAL_DEPTH_MINIMUM
        ):
            raise ValueError(
                "validated lifecycle removal lacks the attempt root and copied workspace minimum"
            )
        if self.freshness_attestation_sha256 != (self.expected_freshness_attestation_sha256()):
            raise ValueError("workspace lifecycle freshness attestation does not match")
        if self.lifecycle_evidence_sha256 != self.expected_lifecycle_evidence_sha256():
            raise ValueError("workspace lifecycle evidence hash does not match its fields")
        return self

    def expected_freshness_attestation_sha256(self) -> str:
        """Recompute the historical freshness binding from inspectable root facts."""

        return _canonical_model_sha256(
            {
                "workspace_identity_sha256": self.attempt_binding_sha256,
                "created_with_exist_ok_false": True,
                "device": self.attempt_root_device,
                "inode": self.attempt_root_inode,
            }
        )

    def expected_lifecycle_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"lifecycle_evidence_sha256"})
        return _canonical_model_sha256(payload)


class ScannerRun(StrictModel):
    scanner: str
    status: ScannerStatus
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    version: str | None = None
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    command: list[str] = Field(default_factory=list)
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = Field(ge=0)
    findings: list[ScannerFinding] = Field(default_factory=list)
    error: str | None = None
    raw_output_path: str | None = None
    raw_output_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    raw_output_bytes: int = Field(default=0, ge=0)
    process_exit_code: int | None = None
    isolation_backend: str | None = None
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    machine_output_validated: bool = False
    foundry_summary: FoundryTestExecutionSummary | None = None
    repository_suite_selection: RepositorySuiteSelection | None = None
    repository_suite_inventory: RepositorySuiteInventoryEvidence | None = None
    repository_suite_post_inventory: RepositorySuiteInventoryEvidence | None = None
    repository_suite_execution_policy: RepositorySuiteExecutionPolicy | None = None
    repository_suite_workspace_copy: RepositorySuiteWorkspaceCopyEvidence | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    fork_rpc_egress: ForkRpcReadOnlyEgressEvidence | None = None
    repository_test_fork_rpc_scopes: list[RepositoryTestForkRpcScopeEvidence] = Field(
        default_factory=list,
        max_length=10_000,
        exclude_if=lambda value: not value,
    )
    repository_test_executions: list[RepositoryTestExecution] = Field(
        default_factory=list,
        max_length=10_000,
    )
    execution_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    repository_code_execution: RepositoryCodeExecutionState = (
        RepositoryCodeExecutionState.NOT_APPLICABLE
    )

    def expected_execution_observation_sha256(self) -> str:
        """Bind every scanner observation except the digest itself."""

        payload = self.model_dump(
            mode="json",
            exclude={"execution_observation_sha256"},
        )
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    def expected_legacy_execution_observation_sha256(self) -> str:
        """Recompute the pre-scope digest for an empty-scope historical run."""

        if self.repository_test_fork_rpc_scopes or self.repository_suite_workspace_copy is not None:
            raise ValueError(
                "scoped scanner runs and workspace-attested runs do not have a legacy "
                "observation digest"
            )
        payload = self.model_dump(
            mode="json",
            exclude={
                "execution_observation_sha256",
                "repository_test_fork_rpc_scopes",
                "repository_suite_workspace_copy",
            },
        )
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    def execution_observation_sha256_is_valid(self) -> bool:
        """Accept current evidence, or the exact empty-scope historical projection."""

        if self.execution_observation_sha256 is None:
            return False
        if self.execution_observation_sha256 == self.expected_execution_observation_sha256():
            return True
        return (
            not self.repository_test_fork_rpc_scopes
            and self.repository_suite_workspace_copy is None
            and self.execution_observation_sha256
            == self.expected_legacy_execution_observation_sha256()
        )

    @model_validator(mode="after")
    def repository_code_isolation_evidence_is_consistent(self) -> ScannerRun:
        if (
            self.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
            and self.isolation_backend is None
        ):
            raise ValueError("isolated repository code requires an isolation backend")
        if (
            self.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
            and self.status is ScannerStatus.SUCCESS
        ):
            raise ValueError("blocked repository code cannot have a successful scanner result")
        if self.raw_output_sha256 is None and self.raw_output_bytes:
            raise ValueError("scanner output bytes require a SHA-256 binding")
        if self.repository_test_executions and self.repository_suite_selection is None:
            raise ValueError("repository test executions require their selection evidence")
        if (
            self.repository_suite_inventory is not None
            or self.repository_suite_post_inventory is not None
        ) and self.repository_suite_selection is None:
            raise ValueError("repository inventory evidence requires its suite selection")
        if (
            self.repository_suite_execution_policy is not None
            and self.repository_suite_selection is None
        ):
            raise ValueError("repository execution policy requires its suite selection")
        workspace_copy = self.repository_suite_workspace_copy
        if workspace_copy is not None:
            selection = self.repository_suite_selection
            if self.scanner != "foundry_fork":
                raise ValueError("workspace copy evidence requires the Foundry fork scanner")
            if selection is None:
                raise ValueError("workspace copy evidence requires its repository selection")
            if (
                workspace_copy.selection_sha256 != selection.selection_sha256
                or workspace_copy.repository_sha256 != selection.repository_sha256
            ):
                raise ValueError("workspace copy evidence differs from its repository selection")
        if self.repository_test_fork_rpc_scopes:
            selection = self.repository_suite_selection
            execution_policy = self.repository_suite_execution_policy
            if selection is None or execution_policy is None:
                raise ValueError(
                    "per-test fork RPC scopes require repository selection and execution policy"
                )
            if self.scanner != "foundry_fork":
                raise ValueError("per-test fork RPC scopes require the Foundry fork scanner")
            scopes = self.repository_test_fork_rpc_scopes
            scope_evidence_hashes = tuple(scope.evidence_sha256 for scope in scopes)
            scope_snapshot_hashes = tuple(scope.bridge_scope_snapshot_sha256 for scope in scopes)
            if len(scope_evidence_hashes) != len(set(scope_evidence_hashes)) or len(
                scope_snapshot_hashes
            ) != len(set(scope_snapshot_hashes)):
                raise ValueError("per-test fork RPC scopes contain duplicate hashes")
            attempt_bindings = {scope.attempt_binding_sha256 for scope in scopes}
            if len(attempt_bindings) != 1 or "0" * 64 in attempt_bindings:
                raise ValueError(
                    "per-test fork RPC scopes require one common nonzero attempt binding"
                )
            if (
                workspace_copy is not None
                and workspace_copy.attempt_binding_sha256 not in attempt_bindings
            ):
                raise ValueError(
                    "workspace copy attempt binding differs from per-test fork RPC scopes"
                )
            if self.status is ScannerStatus.SUCCESS and workspace_copy is None:
                raise ValueError(
                    "successful scoped repository suite requires workspace copy evidence"
                )
            if len({scope.bridge_policy_sha256 for scope in scopes}) != 1:
                raise ValueError("per-test fork RPC scopes require one common bridge policy")
            expected_prefix = tuple(
                (index, descriptor.descriptor_sha256)
                for index, descriptor in enumerate(
                    selection.tests[: len(scopes)],
                    start=1,
                )
            )
            observed_sequence = tuple(
                (scope.sequence_index, scope.descriptor_sha256) for scope in scopes
            )
            if observed_sequence != expected_prefix:
                raise ValueError(
                    "per-test fork RPC scopes must be a canonical 1-based prefix of selected "
                    "descriptor order"
                )
            if self.status is ScannerStatus.SUCCESS and len(scopes) != len(selection.tests):
                raise ValueError(
                    "successful repository suite requires full per-test fork RPC scope coverage"
                )
            if self.status not in {
                ScannerStatus.SUCCESS,
                ScannerStatus.FAILED,
                ScannerStatus.TIMED_OUT,
                ScannerStatus.UNAVAILABLE,
            }:
                raise ValueError(
                    "per-test fork RPC scopes require a successful or interrupted scanner status"
                )
            if any(scope.selection_sha256 != selection.selection_sha256 for scope in scopes):
                raise ValueError("per-test fork RPC scope selection identity differs")
            if any(
                scope.expected_chain_id != execution_policy.chain_id
                or scope.pinned_block_number != execution_policy.block_number
                or scope.pinned_block_hash != execution_policy.block_hash
                for scope in scopes
            ):
                raise ValueError("per-test fork RPC scope execution state identity differs")
        if self.fork_rpc_egress is not None:
            if self.scanner != "foundry_fork":
                raise ValueError("fork RPC egress evidence requires the Foundry fork scanner")
            execution_policy = self.repository_suite_execution_policy
            if execution_policy is None:
                raise ValueError("fork RPC egress evidence requires an execution policy")
            if (
                self.fork_rpc_egress.expected_chain_id != execution_policy.chain_id
                or self.fork_rpc_egress.pinned_block_number != execution_policy.block_number
                or self.fork_rpc_egress.pinned_block_hash != execution_policy.block_hash
            ):
                raise ValueError("fork RPC egress identity differs from its execution policy")
        if self.repository_suite_selection is not None:
            selection = self.repository_suite_selection
            if not selection.tests and self.status is ScannerStatus.SUCCESS:
                raise ValueError("an empty repository suite selection cannot be successful")
            executions = self.repository_test_executions
            execution_policy = self.repository_suite_execution_policy
            inventory = self.repository_suite_inventory
            post_inventory = self.repository_suite_post_inventory
            inventories_stable = False
            expected_framework = {
                "foundry_fork": RepositorySuiteFramework.FOUNDRY,
                "hardhat_fork": RepositorySuiteFramework.HARDHAT,
            }.get(self.scanner)
            if expected_framework is None:
                raise ValueError(
                    "repository suite evidence requires the Foundry or Hardhat fork scanner"
                )
            if any(test.framework is not expected_framework for test in selection.tests):
                raise ValueError("repository suite descriptor framework differs from its scanner")
            if selection.inventory_kind is RepositorySuiteInventoryKind.STATIC_SOURCE:
                if inventory is not None or post_inventory is not None:
                    raise ValueError("static repository selection cannot carry runtime inventory")
            else:
                if inventory is None:
                    raise ValueError(
                        "compiler-backed repository selection requires pre-execution inventory"
                    )
                if inventory.phase is not RepositorySuiteInventoryPhase.PRE_EXECUTION:
                    raise ValueError("repository pre-execution inventory phase is invalid")
                if self.status is ScannerStatus.SUCCESS and post_inventory is None:
                    raise ValueError(
                        "successful compiler-backed repository suite requires post inventory"
                    )
                if (
                    post_inventory is not None
                    and post_inventory.phase is not RepositorySuiteInventoryPhase.POST_EXECUTION
                ):
                    raise ValueError("repository post-execution inventory phase is invalid")
                if selection.inventory_sha256 != inventory.normalized_inventory_sha256:
                    raise ValueError(
                        "repository selection differs from its pre-execution inventory"
                    )
                stable_inventory_fields = (
                    "framework",
                    "repository_sha256",
                    "configuration_sha256",
                    "tool_version",
                    "tool_sha256",
                    "compiler_version",
                    "compiler_sha256",
                    "isolation_backend",
                    "isolation_attestation_sha256",
                    "execution_evidence",
                    "repository_code_execution",
                    "safety_claim",
                )
                pre_records = {
                    record.record_sha256: record
                    for project in inventory.projects
                    for record in project.records
                }
                if post_inventory is not None:
                    if any(
                        getattr(inventory, field) != getattr(post_inventory, field)
                        for field in stable_inventory_fields
                    ):
                        raise ValueError("pre/post repository inventory identity differs")
                    post_records = {
                        record.record_sha256: record
                        for project in post_inventory.projects
                        for record in project.records
                    }
                    pre_project_semantics = tuple(
                        (
                            project.project_root,
                            project.build_info_bundle_sha256,
                            project.normalized_build_info_bundle_sha256,
                            project.parser_inventory_sha256,
                            project.normalized_inventory_sha256,
                        )
                        for project in inventory.projects
                    )
                    post_project_semantics = tuple(
                        (
                            project.project_root,
                            project.build_info_bundle_sha256,
                            project.normalized_build_info_bundle_sha256,
                            project.parser_inventory_sha256,
                            project.normalized_inventory_sha256,
                        )
                        for project in post_inventory.projects
                    )
                    inventories_stable = (
                        inventory.normalized_inventory_sha256
                        == post_inventory.normalized_inventory_sha256
                        and inventory.inventory_record_count
                        == post_inventory.inventory_record_count
                        and pre_records == post_records
                        and pre_project_semantics == post_project_semantics
                    )
                    if self.status is ScannerStatus.SUCCESS and not inventories_stable:
                        raise ValueError("successful repository suite inventory evidence drifted")
                if inventory.repository_sha256 != selection.repository_sha256:
                    raise ValueError("repository inventory differs from selected repository")
                if inventory.configuration_sha256 != selection.configuration_sha256:
                    raise ValueError("repository inventory differs from selection configuration")
                if inventory.framework is not expected_framework:
                    raise ValueError("repository inventory framework differs from scanner")
                if inventory.tool_version != self.version or inventory.tool_sha256 != (
                    self.executable_sha256
                ):
                    raise ValueError("repository inventory tool identity differs from scanner")
                if (
                    inventory.isolation_backend != self.isolation_backend
                    or inventory.isolation_attestation_sha256 != self.isolation_attestation_sha256
                    or inventory.repository_code_execution is not self.repository_code_execution
                ):
                    raise ValueError("repository inventory provenance differs from scanner")
                if (
                    self.status is ScannerStatus.SUCCESS
                    and inventory.execution_evidence is not self.execution_evidence
                ):
                    raise ValueError(
                        "successful repository inventory evidence differs from scanner"
                    )
                for descriptor in selection.tests:
                    if descriptor.inventory_record_sha256 not in pre_records:
                        raise ValueError("repository descriptor is absent from compiler inventory")
                    record = pre_records[descriptor.inventory_record_sha256]
                    descriptor_record = (
                        descriptor.project_root,
                        descriptor.path,
                        descriptor.suite_name,
                        descriptor.test_name,
                        descriptor.source_sha256,
                        descriptor.start_line,
                        descriptor.end_line,
                        descriptor.execution_contract_ast_id,
                        descriptor.declaration_path,
                        descriptor.declaration_suite_name,
                        descriptor.declaration_signature,
                        descriptor.declaration_source_sha256,
                        descriptor.declaration_start_line,
                        descriptor.declaration_end_line,
                        descriptor.declaration_contract_ast_id,
                        descriptor.declaration_function_ast_id,
                    )
                    inventory_record = (
                        record.project_root,
                        record.execution_path,
                        record.execution_suite_name,
                        record.test_name,
                        record.execution_source_sha256,
                        record.execution_start_line,
                        record.execution_end_line,
                        record.execution_contract_ast_id,
                        record.declaration_path,
                        record.declaration_suite_name,
                        record.declaration_signature,
                        record.declaration_source_sha256,
                        record.declaration_start_line,
                        record.declaration_end_line,
                        record.declaration_contract_ast_id,
                        record.declaration_function_ast_id,
                    )
                    if descriptor_record != inventory_record:
                        raise ValueError(
                            "repository descriptor differs from compiler inventory record"
                        )
            execution_keys = tuple(execution.canonical_key for execution in executions)
            execution_hashes = tuple(execution.execution_sha256 for execution in executions)
            if execution_keys != tuple(sorted(set(execution_keys))):
                raise ValueError("repository test executions must be unique and canonically sorted")
            if len(execution_hashes) != len(set(execution_hashes)):
                raise ValueError("repository test execution hashes must be unique")
            selected_by_hash = {
                descriptor.descriptor_sha256: descriptor for descriptor in selection.tests
            }
            if set(selected_by_hash) != {execution.descriptor_sha256 for execution in executions}:
                raise ValueError(
                    "repository test executions must exactly cover the selected descriptors"
                )
            for execution in executions:
                descriptor = selected_by_hash[execution.descriptor_sha256]
                if execution.selection_sha256 != selection.selection_sha256:
                    raise ValueError("repository test execution does not bind its suite selection")
                if selection.inventory_kind is RepositorySuiteInventoryKind.STATIC_SOURCE:
                    if (
                        execution.inventory_sha256 is not None
                        or execution.post_inventory_sha256 is not None
                        or execution.inventory_record_sha256 is not None
                    ):
                        raise ValueError("static repository execution cannot claim inventory")
                else:
                    assert inventory is not None
                    if post_inventory is None:
                        if (
                            execution.inventory_sha256 is not None
                            or execution.post_inventory_sha256 is not None
                            or execution.inventory_record_sha256 is not None
                        ):
                            raise ValueError(
                                "repository execution cannot claim incomplete inventories"
                            )
                    elif inventories_stable:
                        if (
                            execution.inventory_sha256 != inventory.inventory_sha256
                            or execution.post_inventory_sha256 != post_inventory.inventory_sha256
                            or execution.inventory_record_sha256
                            != descriptor.inventory_record_sha256
                        ):
                            raise ValueError(
                                "repository test execution differs from compiler inventories"
                            )
                    elif (
                        execution.inventory_sha256 is not None
                        or execution.post_inventory_sha256 is not None
                        or execution.inventory_record_sha256 is not None
                    ):
                        raise ValueError("repository execution cannot claim drifting inventories")
                if execution.canonical_key != descriptor.canonical_key:
                    raise ValueError(
                        "repository test execution identity differs from its descriptor"
                    )
                if execution.execution_evidence is not self.execution_evidence:
                    raise ValueError(
                        "repository test execution evidence differs from its scanner run"
                    )
                if execution.repository_code_execution is not self.repository_code_execution:
                    raise ValueError("repository test isolation state differs from its scanner run")
                if execution.isolation_backend != self.isolation_backend:
                    raise ValueError(
                        "repository test isolation backend differs from its scanner run"
                    )
                if execution.isolation_attestation_sha256 != self.isolation_attestation_sha256:
                    raise ValueError(
                        "repository test isolation attestation differs from its scanner run"
                    )
                if execution.status in {
                    RepositoryTestExecutionStatus.PASSED,
                    RepositoryTestExecutionStatus.FAILED,
                    RepositoryTestExecutionStatus.REVERTED,
                    RepositoryTestExecutionStatus.ASSERTION_FAILED,
                }:
                    if execution_policy is None:
                        raise ValueError(
                            "classified repository suite requires its typed execution policy"
                        )
                    if execution.execution_policy_sha256 != execution_policy.policy_sha256:
                        raise ValueError(
                            "repository test execution policy differs from its typed policy"
                        )
                    if (
                        execution.chain_id != execution_policy.chain_id
                        or execution.block_number != execution_policy.block_number
                        or execution.block_hash != execution_policy.block_hash
                        or execution.fuzz_seed != execution_policy.fuzz_seed
                        or execution.compiler_version != execution_policy.compiler_version
                        or execution.compiler_sha256 != execution_policy.compiler_sha256
                    ):
                        raise ValueError(
                            "repository test evidence differs from its typed execution policy"
                        )

            if execution_policy is not None:
                if expected_framework is not RepositorySuiteFramework.FOUNDRY:
                    raise ValueError("only Foundry repository suites support this execution policy")
                if execution_policy.selection_sha256 != selection.selection_sha256:
                    raise ValueError("repository execution policy differs from its selection")
                if (
                    execution_policy.selection_configuration_sha256
                    != selection.configuration_sha256
                ):
                    raise ValueError(
                        "repository execution policy configuration differs from its selection"
                    )
                if execution_policy.tool_version != self.version:
                    raise ValueError("repository execution policy tool version differs")
                if execution_policy.tool_sha256 != self.executable_sha256:
                    raise ValueError("repository execution policy tool hash differs")
                if execution_policy.isolation_backend != self.isolation_backend:
                    raise ValueError("repository execution policy isolation backend differs")
                if (
                    execution_policy.isolation_attestation_sha256
                    != self.isolation_attestation_sha256
                ):
                    raise ValueError("repository execution policy isolation attestation differs")

            failure_statuses = {
                RepositoryTestExecutionStatus.FAILED,
                RepositoryTestExecutionStatus.REVERTED,
                RepositoryTestExecutionStatus.ASSERTION_FAILED,
            }
            classified_statuses = {
                RepositoryTestExecutionStatus.PASSED,
                *failure_statuses,
            }
            if self.status is ScannerStatus.SUCCESS and any(
                execution.status not in classified_statuses for execution in executions
            ):
                raise ValueError(
                    "successful repository suite requires every selected test to have a "
                    "classified machine result"
                )
            fork_states = {
                (
                    execution.chain_id,
                    execution.block_number,
                    execution.block_hash,
                    execution.fuzz_seed,
                )
                for execution in executions
                if execution.status in classified_statuses
            }
            if len(fork_states) > 1:
                raise ValueError(
                    "repository suite executions do not share one pinned fork state and seed"
                )
            execution_policies = {
                (
                    execution.compiler_version,
                    execution.compiler_sha256,
                    execution.execution_policy_sha256,
                )
                for execution in executions
                if execution.status in classified_statuses
            }
            if len(execution_policies) > 1:
                raise ValueError(
                    "repository suite executions do not share one compiler and execution policy"
                )
            failing_hashes = {
                execution.execution_sha256
                for execution in executions
                if execution.status in failure_statuses
            }
            executions_by_hash = {execution.execution_sha256: execution for execution in executions}
            finding_hashes: list[str] = []
            for finding in self.findings:
                reference = finding.metadata.get("repository_test_execution_sha256")
                if reference is None:
                    raise ValueError("repository suite finding lacks its test execution reference")
                if finding.scanner != self.scanner:
                    raise ValueError(
                        "repository suite finding scanner differs from its scanner run"
                    )
                if not isinstance(reference, str) or not re.fullmatch(r"[0-9a-f]{64}", reference):
                    raise ValueError("repository test finding has an invalid execution reference")
                if reference not in failing_hashes:
                    raise ValueError(
                        "repository test finding does not reference a failing execution"
                    )
                execution = executions_by_hash[reference]
                expected_strength = (
                    EvidenceStrength.DETERMINISTIC_ANALYZER
                    if execution.execution_evidence is ExecutionEvidenceKind.REAL
                    else EvidenceStrength.NONE
                )
                if finding.evidence_strength is not expected_strength:
                    raise ValueError(
                        "repository suite finding evidence strength differs from its "
                        "execution provenance"
                    )
                descriptor = selected_by_hash[execution.descriptor_sha256]
                if not any(
                    location.path == descriptor.finding_path
                    and location.start_line >= descriptor.finding_start_line
                    and location.end_line <= descriptor.finding_end_line
                    for location in finding.locations
                ):
                    raise ValueError(
                        "repository suite finding location differs from its test descriptor"
                    )
                finding_hashes.append(reference)
            if set(finding_hashes) != failing_hashes:
                raise ValueError(
                    "every failing repository test must have hash-bound finding evidence"
                )

            if (
                expected_framework is RepositorySuiteFramework.FOUNDRY
                and self.status is ScannerStatus.SUCCESS
                and self.foundry_summary is None
            ):
                raise ValueError("successful Foundry repository suite requires its summary")
            if (
                expected_framework is RepositorySuiteFramework.HARDHAT
                and self.foundry_summary is not None
            ):
                raise ValueError("Hardhat repository suite cannot carry a Foundry summary")
            if self.foundry_summary is not None:
                foundry_executions = [
                    execution
                    for execution in executions
                    if execution.framework is RepositorySuiteFramework.FOUNDRY
                ]
                passed = sum(
                    execution.status is RepositoryTestExecutionStatus.PASSED
                    for execution in foundry_executions
                )
                failed = sum(
                    execution.status in failure_statuses for execution in foundry_executions
                )
                skipped = sum(
                    execution.status is RepositoryTestExecutionStatus.SKIPPED
                    for execution in foundry_executions
                )
                unit_tests = sum(
                    execution.test_kind is RepositoryTestKind.UNIT
                    for execution in foundry_executions
                )
                fuzz_tests = sum(
                    execution.test_kind is RepositoryTestKind.FUZZ
                    for execution in foundry_executions
                )
                invariant_tests = sum(
                    execution.test_kind is RepositoryTestKind.INVARIANT
                    for execution in foundry_executions
                )
                if (
                    self.foundry_summary.passed_tests != passed
                    or self.foundry_summary.failed_tests != failed
                    or self.foundry_summary.skipped_tests != skipped
                    or passed + failed + skipped != len(foundry_executions)
                    or self.foundry_summary.unit_tests != unit_tests
                    or self.foundry_summary.fuzz_tests != fuzz_tests
                    or self.foundry_summary.invariant_tests != invariant_tests
                    or self.foundry_summary.fuzz_cases
                    != sum(execution.fuzz_cases for execution in foundry_executions)
                    or self.foundry_summary.invariant_runs
                    != sum(execution.invariant_runs for execution in foundry_executions)
                    or self.foundry_summary.invariant_calls
                    != sum(execution.invariant_calls for execution in foundry_executions)
                ):
                    raise ValueError("Foundry summary does not match repository test executions")
        if (
            self.execution_observation_sha256 is not None
            and not self.execution_observation_sha256_is_valid()
        ):
            raise ValueError("scanner execution observation hash does not match its fields")
        return self


class RepositorySuiteStateAttempt(StrictModel):
    """One fresh-workspace execution attempt bound to a configured state."""

    schema_version: Literal["1.0"] = "1.0"
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    attempt_index: int = Field(ge=1, le=10)
    workspace_kind: Literal["fresh_disposable_copy"] = "fresh_disposable_copy"
    workspace_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_freshness_attestation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_disposal_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_lifecycle: RepositorySuiteWorkspaceLifecycleEvidence
    fork_rpc_egress_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    scanner_run: ScannerRun
    attempt_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteStateAttempt:
        """Validate and self-hash one differential execution attempt."""

        if "attempt_sha256" in values:
            raise ValueError("attempt_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, attempt_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"attempt_sha256"})
        return cls.model_validate(
            {
                **payload,
                "attempt_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("attempt_index", mode="before")
    @classmethod
    def attempt_index_is_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("repository state attempt index requires an exact integer")
        return value

    @model_validator(mode="after")
    def nested_egress_command_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteStateAttempt:
        lifecycle = self.workspace_lifecycle
        if (
            lifecycle.attempt_binding_sha256 != self.workspace_identity_sha256
            or lifecycle.freshness_attestation_sha256 != self.workspace_freshness_attestation_sha256
            or lifecycle.disposal_policy_sha256 != self.workspace_disposal_policy_sha256
        ):
            raise ValueError("state attempt workspace lifecycle identity or policy binding differs")
        selection = self.scanner_run.repository_suite_selection
        workspace_copy = self.scanner_run.repository_suite_workspace_copy
        scanner_observation_sha256 = self.scanner_run.execution_observation_sha256
        if workspace_copy is not None and (
            workspace_copy.workspace_parent_device,
            workspace_copy.workspace_parent_inode,
        ) != (
            lifecycle.attempt_root_device,
            lifecycle.attempt_root_inode,
        ):
            raise ValueError(
                "state attempt workspace lifecycle lacks full cross-layer joins: "
                "copy-parent identity differs"
            )
        if lifecycle.status is RepositorySuiteWorkspaceLifecycleStatus.VALIDATED:
            if (
                self.scanner_run.status is not ScannerStatus.SUCCESS
                or selection is None
                or workspace_copy is None
                or scanner_observation_sha256 is None
                or lifecycle.selection_sha256 != selection.selection_sha256
                or lifecycle.repository_sha256 != selection.repository_sha256
                or lifecycle.workspace_copy_evidence_sha256 != workspace_copy.copy_evidence_sha256
                or lifecycle.scanner_execution_observation_sha256 != scanner_observation_sha256
                or workspace_copy.attempt_binding_sha256 != self.workspace_identity_sha256
            ):
                raise ValueError(
                    "validated state attempt workspace lifecycle lacks full cross-layer joins"
                )
        else:
            if lifecycle.workspace_copy_evidence_sha256 is not None and (
                workspace_copy is None
                or lifecycle.workspace_copy_evidence_sha256 != workspace_copy.copy_evidence_sha256
            ):
                raise ValueError(
                    "uncredited workspace lifecycle copy binding differs from its scanner run"
                )
            if (
                lifecycle.scanner_execution_observation_sha256 is not None
                and lifecycle.scanner_execution_observation_sha256 != scanner_observation_sha256
            ):
                raise ValueError(
                    "uncredited workspace lifecycle observation differs from its scanner run"
                )
        egress = self.scanner_run.fork_rpc_egress
        if (egress is None) != (self.fork_rpc_egress_sha256 is None):
            raise ValueError("state attempt egress reference must be all-or-none")
        if egress is not None and self.fork_rpc_egress_sha256 != egress.evidence_sha256:
            raise ValueError("state attempt egress hash differs from its scanner run")
        scopes = tuple(self.scanner_run.repository_test_fork_rpc_scopes)
        if egress is not None and scopes:
            counter_fields = (
                "http_request_count",
                "permitted_rpc_call_count",
                "origin_attempted_rpc_call_count",
                "origin_validated_rpc_call_count",
                "synthetic_rpc_call_count",
                "denied_request_count",
                "malformed_request_count",
                "limit_exceeded_request_count",
                "upstream_error_request_count",
            )
            if any(
                sum(getattr(scope, field) for scope in scopes) > getattr(egress, field)
                for field in counter_fields
            ):
                raise ValueError(
                    "state attempt per-test fork RPC counters exceed aggregate bridge evidence"
                )
            aggregate_method_counts = {
                item.method: item.count for item in egress.allowed_method_counts
            }
            scoped_method_counts: dict[str, int] = {}
            for scope in scopes:
                for item in scope.allowed_method_counts:
                    scoped_method_counts[item.method] = (
                        scoped_method_counts.get(item.method, 0) + item.count
                    )
            if any(
                count > aggregate_method_counts.get(method, 0)
                for method, count in scoped_method_counts.items()
            ):
                raise ValueError(
                    "state attempt per-test fork RPC methods exceed aggregate bridge evidence"
                )
        endpoint_markers = ("http://", "https://", "ws://", "wss://", "localhost", "127.0.0.1")
        if any(
            any(marker in token.casefold() for marker in endpoint_markers)
            for token in self.scanner_run.command
        ):
            raise ValueError("state attempt command cannot serialize an RPC endpoint")
        if self.attempt_sha256 != self.expected_attempt_sha256():
            raise ValueError("repository state attempt hash does not match its fields")
        return self

    def expected_attempt_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"attempt_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteTestStateConsensus(StrictModel):
    """Declared repeated-execution consensus for one test in one state."""

    schema_version: Literal["1.0"] = "1.0"
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: RepositoryStateConsensusStatus
    attempt_sha256s: tuple[str, ...] = Field(min_length=1, max_length=10)
    observed_status: RepositoryTestExecutionStatus | None = None
    machine_result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    inconclusive_reasons: tuple[RepositoryStateInconclusiveReason, ...] = Field(max_length=16)
    consensus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteTestStateConsensus:
        """Validate and self-hash one declared state consensus."""

        if "consensus_sha256" in values:
            raise ValueError("consensus_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, consensus_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"consensus_sha256"})
        return cls.model_validate(
            {
                **payload,
                "consensus_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def declaration_and_hash_are_consistent(self) -> RepositorySuiteTestStateConsensus:
        if self.attempt_sha256s != tuple(sorted(set(self.attempt_sha256s))):
            raise ValueError("state consensus attempt hashes must be unique and sorted")
        reason_values = tuple(reason.value for reason in self.inconclusive_reasons)
        if reason_values != tuple(sorted(set(reason_values))):
            raise ValueError("state inconclusive reasons must be unique and sorted")
        failure_statuses = {
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        }
        if self.status is RepositoryStateConsensusStatus.INCONCLUSIVE:
            if (
                self.observed_status is not None
                or self.machine_result_sha256 is not None
                or not self.inconclusive_reasons
            ):
                raise ValueError(
                    "inconclusive state consensus requires reasons and no credited outcome"
                )
        else:
            if (
                len(self.attempt_sha256s) < 2
                or self.machine_result_sha256 is None
                or self.inconclusive_reasons
            ):
                raise ValueError(
                    "conclusive state consensus requires two agreeing attempts and a result"
                )
            if (
                self.status is RepositoryStateConsensusStatus.CONSISTENT_PASS
                and self.observed_status is not RepositoryTestExecutionStatus.PASSED
            ):
                raise ValueError("consistent-pass consensus requires a passing observation")
            if (
                self.status is RepositoryStateConsensusStatus.CONSISTENT_FAILURE
                and self.observed_status not in failure_statuses
            ):
                raise ValueError("consistent-failure consensus requires a failing observation")
        if self.consensus_sha256 != self.expected_consensus_sha256():
            raise ValueError("repository state consensus hash does not match its fields")
        return self

    def expected_consensus_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"consensus_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteTestComparison(StrictModel):
    """Self-hashed comparison of clean and pinned consensus for one test."""

    schema_version: Literal["1.0"] = "1.0"
    clean_state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    clean_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pinned_state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    pinned_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    clean_consensus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pinned_consensus_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    classification: RepositoryDifferentialClassification
    direction: RepositoryDivergenceDirection | None = None
    comparison_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteTestComparison:
        """Validate and self-hash one clean-versus-pinned comparison."""

        if "comparison_sha256" in values:
            raise ValueError("comparison_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, comparison_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"comparison_sha256"})
        return cls.model_validate(
            {
                **payload,
                "comparison_sha256": _canonical_model_sha256(payload),
            }
        )

    @model_validator(mode="after")
    def direction_and_hash_are_consistent(self) -> RepositorySuiteTestComparison:
        if (
            self.clean_state_id == self.pinned_state_id
            or self.clean_state_sha256 == self.pinned_state_sha256
        ):
            raise ValueError("differential comparison requires distinct clean and pinned states")
        if self.classification is RepositoryDifferentialClassification.DIVERGED:
            if self.direction is None:
                raise ValueError("diverged comparison requires a typed direction")
        elif self.direction is not None:
            raise ValueError("non-diverged comparison cannot carry a divergence direction")
        if self.comparison_sha256 != self.expected_comparison_sha256():
            raise ValueError("repository suite comparison hash does not match its fields")
        return self

    def expected_comparison_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"comparison_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteStateWorkspaceCleanupEvidence(StrictModel):
    """Sealed proof that one state's owned directories shared one removal budget."""

    schema_version: Literal["1.0"] = "1.0"
    state_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    disposal_policy_sha256: str = Field(
        REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256,
        pattern=r"^[0-9a-f]{64}$",
    )
    attempt_cleanup_sequence_lifecycle_sha256s: tuple[str, ...] = Field(
        min_length=2,
        max_length=10,
    )
    attempt_cumulative_removed_entry_counts: tuple[int, ...] = Field(
        min_length=2,
        max_length=10,
    )
    attempt_cumulative_removal_duration_seconds: tuple[float, ...] = Field(
        min_length=2,
        max_length=10,
    )
    owned_directory_count: int = Field(ge=2, le=11)
    auxiliary_directory_count: int = Field(ge=0, le=1)
    removal_entry_limit: int = Field(ge=1, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT)
    removed_entry_count: int = Field(
        ge=1,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT,
    )
    removal_depth_limit: int = Field(ge=1, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT)
    maximum_removed_depth: int = Field(ge=0, le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT)
    removal_timeout_seconds: float = Field(
        gt=0,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    )
    removal_duration_seconds: float = Field(
        ge=0,
        le=REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS,
    )
    all_owned_descriptors_closed: Literal[True] = True
    all_owned_paths_absent: Literal[True] = True
    private_path_retained: Literal[False] = False
    rpc_endpoint_retained: Literal[False] = False
    aggregate_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteStateWorkspaceCleanupEvidence:
        """Validate and self-hash one shared per-state disposal budget."""

        if "aggregate_evidence_sha256" in values:
            raise ValueError(
                "aggregate_evidence_sha256 is derived and cannot be supplied to sealed()"
            )
        provisional = cls.model_construct(**values, aggregate_evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"aggregate_evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "aggregate_evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator(
        "owned_directory_count",
        "auxiliary_directory_count",
        "removal_entry_limit",
        "removed_entry_count",
        "removal_depth_limit",
        "maximum_removed_depth",
        mode="before",
    )
    @classmethod
    def aggregate_integers_are_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("state workspace cleanup counters require exact integers")
        return value

    @field_validator("attempt_cumulative_removed_entry_counts", mode="before")
    @classmethod
    def cumulative_entry_counts_are_exact(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)) or any(
            isinstance(item, bool) or not isinstance(item, int) for item in value
        ):
            raise ValueError("state workspace cleanup cumulative entries require exact integers")
        return value

    @field_validator(
        "attempt_cumulative_removal_duration_seconds",
        mode="before",
    )
    @classmethod
    def cumulative_durations_are_finite(cls, value: object) -> object:
        if not isinstance(value, (list, tuple)) or any(
            isinstance(item, bool)
            or not isinstance(item, (int, float))
            or not math.isfinite(float(item))
            for item in value
        ):
            raise ValueError("state workspace cleanup durations require finite numbers")
        return value

    @field_validator(
        "removal_timeout_seconds",
        "removal_duration_seconds",
        mode="before",
    )
    @classmethod
    def aggregate_durations_are_finite(cls, value: object) -> object:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(float(value))
        ):
            raise ValueError("state workspace cleanup durations require finite numbers")
        return value

    @model_validator(mode="after")
    def shared_budget_sequence_bounds_and_hash_are_consistent(
        self,
    ) -> RepositorySuiteStateWorkspaceCleanupEvidence:
        sequence_count = len(self.attempt_cleanup_sequence_lifecycle_sha256s)
        if sequence_count != len(
            self.attempt_cumulative_removed_entry_counts
        ) or sequence_count != len(self.attempt_cumulative_removal_duration_seconds):
            raise ValueError("state workspace cleanup sequence and cumulative counters differ")
        if len(set(self.attempt_cleanup_sequence_lifecycle_sha256s)) != sequence_count:
            raise ValueError("state workspace cleanup attempt lifecycle sequence is not unique")
        if self.owned_directory_count != sequence_count + self.auxiliary_directory_count:
            raise ValueError("state workspace cleanup owned-directory count is inconsistent")
        if self.disposal_policy_sha256 != REPOSITORY_SUITE_WORKSPACE_DISPOSAL_POLICY_SHA256:
            raise ValueError("state workspace cleanup policy differs from the exact v3 policy")
        if (
            self.removal_entry_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_ENTRY_LIMIT
            or self.removal_depth_limit != REPOSITORY_SUITE_WORKSPACE_REMOVAL_DEPTH_LIMIT
            or self.removal_timeout_seconds != REPOSITORY_SUITE_WORKSPACE_REMOVAL_TIMEOUT_SECONDS
        ):
            raise ValueError("state workspace cleanup bounds differ from the exact v3 policy")
        cumulative_entries = self.attempt_cumulative_removed_entry_counts
        if any(current <= previous for previous, current in pairwise(cumulative_entries)):
            raise ValueError("state workspace cleanup cumulative entries are not increasing")
        cumulative_durations = self.attempt_cumulative_removal_duration_seconds
        if any(current < previous for previous, current in pairwise(cumulative_durations)):
            raise ValueError("state workspace cleanup cumulative durations regressed")
        if (
            cumulative_entries[-1] + self.auxiliary_directory_count > self.removed_entry_count
            or cumulative_durations[-1] > self.removal_duration_seconds
            or self.owned_directory_count > self.removed_entry_count
        ):
            raise ValueError("state workspace cleanup aggregate is below its cumulative evidence")
        if self.aggregate_evidence_sha256 != self.expected_aggregate_evidence_sha256():
            raise ValueError("state workspace cleanup evidence hash does not match its fields")
        return self

    def expected_aggregate_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"aggregate_evidence_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteDifferentialMatrix(StrictModel):
    """Canonical repeated-state matrix kept separate from qualifying scanner runs."""

    schema_version: Literal["1.0"] = "1.0"
    repository_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    selection_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    descriptor_sha256s: tuple[str, ...] = Field(min_length=1, max_length=10_000)
    required_repetitions: int = Field(ge=2, le=10)
    fuzz_seed: str = Field(pattern=r"^0x[0-9a-f]{64}$")
    execution_configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fork_rpc_policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    states: tuple[RepositorySuiteExecutionStateEvidence, ...] = Field(
        min_length=2,
        max_length=8,
    )
    attempts: tuple[RepositorySuiteStateAttempt, ...] = Field(
        min_length=4,
        max_length=80,
    )
    state_workspace_cleanups: tuple[RepositorySuiteStateWorkspaceCleanupEvidence, ...] = Field(
        min_length=2,
        max_length=8,
    )
    state_consensuses: tuple[RepositorySuiteTestStateConsensus, ...] = Field(
        min_length=2,
        max_length=80_000,
    )
    comparisons: tuple[RepositorySuiteTestComparison, ...] = Field(
        min_length=1,
        max_length=70_000,
    )
    safety_claim: Literal[False] = False
    matrix_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteDifferentialMatrix:
        """Validate and self-hash a complete repeated-state matrix."""

        if "matrix_sha256" in values:
            raise ValueError("matrix_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, matrix_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"matrix_sha256"})
        return cls.model_validate(
            {
                **payload,
                "matrix_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("required_repetitions", mode="before")
    @classmethod
    def required_repetitions_are_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("repository differential repetitions require an exact integer")
        return value

    @staticmethod
    def calculate_matrix_sha256(payload: dict[str, Any]) -> str:
        """Calculate the canonical digest of a serialized matrix payload."""

        canonical = {key: value for key, value in payload.items() if key != "matrix_sha256"}
        return _canonical_model_sha256(canonical)

    @staticmethod
    def execution_configuration_sha256_for_policy(
        policy: RepositorySuiteExecutionPolicy,
    ) -> str:
        """Hash execution controls while excluding the deliberately varying state pin."""

        payload = policy.model_dump(
            mode="json",
            exclude={"chain_id", "block_number", "block_hash", "policy_sha256"},
        )
        return _canonical_model_sha256(payload)

    @model_validator(mode="after")
    def cartesian_evidence_and_classifications_are_consistent(
        self,
    ) -> RepositorySuiteDifferentialMatrix:
        self._validate_canonical_sets()
        states_by_id = {state.state_id: state for state in self.states}
        attempts_by_state = {
            state_id: tuple(attempt for attempt in self.attempts if attempt.state_id == state_id)
            for state_id in states_by_id
        }
        consensuses_by_key = {
            (consensus.state_id, consensus.descriptor_sha256): consensus
            for consensus in self.state_consensuses
        }
        for key, consensus in consensuses_by_key.items():
            state = states_by_id[key[0]]
            attempts = attempts_by_state[key[0]]
            expected = self._expected_consensus(state, attempts, key[1])
            actual = (
                consensus.status,
                consensus.observed_status,
                consensus.machine_result_sha256,
                consensus.inconclusive_reasons,
            )
            if actual != expected:
                expected_status = expected[0].value
                reason_suffix = (
                    ": " + ", ".join(reason.value for reason in expected[3]) if expected[3] else ""
                )
                raise ValueError(
                    "state consensus must be "
                    f"{expected_status} for its runtime evidence{reason_suffix}"
                )
            expected_attempt_hashes = tuple(sorted(attempt.attempt_sha256 for attempt in attempts))
            if consensus.attempt_sha256s != expected_attempt_hashes:
                raise ValueError("state consensus does not bind every configured attempt")
            if consensus.state_sha256 != state.state_sha256:
                raise ValueError("state consensus identity differs from its state evidence")

        clean = next(
            state for state in self.states if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL
        )
        for comparison in self.comparisons:
            pinned = states_by_id[comparison.pinned_state_id]
            clean_consensus = consensuses_by_key[(clean.state_id, comparison.descriptor_sha256)]
            pinned_consensus = consensuses_by_key[(pinned.state_id, comparison.descriptor_sha256)]
            expected_classification, expected_direction = self._expected_comparison(
                clean_consensus,
                pinned_consensus,
            )
            if (
                comparison.classification is not expected_classification
                or comparison.direction is not expected_direction
            ):
                raise ValueError("differential comparison classification is inconsistent")
            if (
                comparison.clean_state_id != clean.state_id
                or comparison.clean_state_sha256 != clean.state_sha256
                or comparison.pinned_state_sha256 != pinned.state_sha256
                or comparison.clean_consensus_sha256 != clean_consensus.consensus_sha256
                or comparison.pinned_consensus_sha256 != pinned_consensus.consensus_sha256
            ):
                raise ValueError("differential comparison does not bind its state consensuses")
        if self.matrix_sha256 != self.expected_matrix_sha256():
            raise ValueError("repository differential matrix hash does not match its fields")
        return self

    def _validate_canonical_sets(self) -> None:
        state_ids = tuple(state.state_id for state in self.states)
        if state_ids != tuple(sorted(set(state_ids))):
            raise ValueError("matrix states must have unique canonically sorted IDs")
        if len({state.state_sha256 for state in self.states}) != len(self.states):
            raise ValueError("matrix state hashes must be unique")
        clean_states = [
            state for state in self.states if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL
        ]
        pinned_states = [
            state for state in self.states if state.kind is RepositoryExecutionStateKind.PINNED_FORK
        ]
        if len(clean_states) != 1 or not pinned_states:
            raise ValueError(
                "matrix requires exactly one clean state and at least one pinned state"
            )
        if self.descriptor_sha256s != tuple(sorted(set(self.descriptor_sha256s))):
            raise ValueError("matrix descriptor hashes must be unique and sorted")
        attempt_keys = tuple((attempt.state_id, attempt.attempt_index) for attempt in self.attempts)
        expected_attempt_keys = tuple(
            (state.state_id, index)
            for state in self.states
            for index in range(1, self.required_repetitions + 1)
        )
        if attempt_keys != expected_attempt_keys:
            raise ValueError("matrix attempts must exactly cover every state and repetition")
        if len({attempt.attempt_sha256 for attempt in self.attempts}) != len(self.attempts):
            raise ValueError("matrix attempt hashes must be unique")
        if len({attempt.workspace_identity_sha256 for attempt in self.attempts}) != len(
            self.attempts
        ):
            raise ValueError("matrix attempts require distinct fresh workspace identities")
        if any(
            attempt.workspace_lifecycle.repository_sha256 != self.repository_sha256
            or attempt.workspace_lifecycle.selection_sha256 != self.selection_sha256
            for attempt in self.attempts
        ):
            raise ValueError("matrix attempt workspace lifecycle differs from repository selection")
        if len(
            {attempt.workspace_lifecycle.lifecycle_evidence_sha256 for attempt in self.attempts}
        ) != len(self.attempts):
            raise ValueError("matrix attempts require distinct workspace lifecycle evidence")
        states_by_id = {state.state_id: state for state in self.states}
        if any(
            attempt.state_sha256 != states_by_id[attempt.state_id].state_sha256
            for attempt in self.attempts
            if attempt.state_id in states_by_id
        ) or any(attempt.state_id not in states_by_id for attempt in self.attempts):
            raise ValueError("matrix attempt state identity is unknown or inconsistent")
        cleanup_state_ids = tuple(cleanup.state_id for cleanup in self.state_workspace_cleanups)
        if cleanup_state_ids != state_ids:
            raise ValueError("matrix state workspace cleanups must canonically cover every state")
        cleanups_by_state = {cleanup.state_id: cleanup for cleanup in self.state_workspace_cleanups}
        for state_id, state in states_by_id.items():
            cleanup = cleanups_by_state[state_id]
            state_attempts = tuple(
                attempt for attempt in self.attempts if attempt.state_id == state_id
            )
            cleanup_order = tuple(reversed(state_attempts))
            expected_lifecycle_sequence = tuple(
                attempt.workspace_lifecycle.lifecycle_evidence_sha256 for attempt in cleanup_order
            )
            cumulative_entries: list[int] = []
            entry_total = 0
            minimum_cumulative_duration = 0.0
            for index, attempt in enumerate(cleanup_order):
                lifecycle = attempt.workspace_lifecycle
                entry_total += lifecycle.removed_entry_count
                cumulative_entries.append(entry_total)
                minimum_cumulative_duration = math.fsum(
                    (
                        minimum_cumulative_duration,
                        lifecycle.removal_duration_seconds,
                    )
                )
                if (
                    cleanup.attempt_cumulative_removal_duration_seconds[index] + 1e-9
                    < minimum_cumulative_duration
                ):
                    raise ValueError(
                        "matrix state cleanup cumulative duration omits an attempt removal"
                    )
            expected_auxiliary_count = (
                1 if state.kind is RepositoryExecutionStateKind.CLEAN_LOCAL else 0
            )
            if (
                cleanup.state_sha256 != state.state_sha256
                or cleanup.attempt_cleanup_sequence_lifecycle_sha256s != expected_lifecycle_sequence
                or cleanup.attempt_cumulative_removed_entry_counts != tuple(cumulative_entries)
                or cleanup.auxiliary_directory_count != expected_auxiliary_count
                or cleanup.owned_directory_count != len(state_attempts) + expected_auxiliary_count
                or cleanup.maximum_removed_depth
                < max(
                    attempt.workspace_lifecycle.maximum_removed_depth for attempt in state_attempts
                )
                or (
                    expected_auxiliary_count == 0
                    and cleanup.removed_entry_count != cumulative_entries[-1]
                )
            ):
                raise ValueError(
                    "matrix state workspace cleanup lacks exact runtime-to-attempt joins"
                )
        consensus_keys = tuple(
            (consensus.state_id, consensus.descriptor_sha256)
            for consensus in self.state_consensuses
        )
        expected_consensus_keys = tuple(
            (state.state_id, descriptor_sha256)
            for state in self.states
            for descriptor_sha256 in self.descriptor_sha256s
        )
        if consensus_keys != expected_consensus_keys:
            raise ValueError("matrix consensus must exactly cover every state and descriptor")
        if len({item.consensus_sha256 for item in self.state_consensuses}) != len(
            self.state_consensuses
        ):
            raise ValueError("matrix consensus hashes must be unique")
        clean = clean_states[0]
        comparison_keys = tuple(
            (comparison.pinned_state_id, comparison.descriptor_sha256)
            for comparison in self.comparisons
        )
        expected_comparison_keys = tuple(
            (state.state_id, descriptor_sha256)
            for state in pinned_states
            for descriptor_sha256 in self.descriptor_sha256s
        )
        if comparison_keys != expected_comparison_keys:
            raise ValueError(
                "matrix comparison must exactly cover the clean-pinned descriptor Cartesian set"
            )
        if any(
            comparison.clean_state_id != clean.state_id
            or comparison.pinned_state_id not in states_by_id
            for comparison in self.comparisons
        ):
            raise ValueError("matrix comparison references an unknown execution state")
        if len({item.comparison_sha256 for item in self.comparisons}) != len(self.comparisons):
            raise ValueError("matrix comparison hashes must be unique")

    def _expected_consensus(
        self,
        state: RepositorySuiteExecutionStateEvidence,
        attempts: tuple[RepositorySuiteStateAttempt, ...],
        descriptor_sha256: str,
    ) -> tuple[
        RepositoryStateConsensusStatus,
        RepositoryTestExecutionStatus | None,
        str | None,
        tuple[RepositoryStateInconclusiveReason, ...],
    ]:
        if state.observation_status is not RepositoryExecutionStateObservationStatus.OBSERVED:
            return (
                RepositoryStateConsensusStatus.INCONCLUSIVE,
                None,
                None,
                (RepositoryStateInconclusiveReason.STATE_UNOBSERVED,),
            )
        reasons: set[RepositoryStateInconclusiveReason] = set()
        observations: list[RepositoryTestExecution] = []
        for attempt in attempts:
            run = attempt.scanner_run
            if (
                attempt.workspace_lifecycle.status
                is not RepositorySuiteWorkspaceLifecycleStatus.VALIDATED
            ):
                reasons.add(RepositoryStateInconclusiveReason.WORKSPACE_LIFECYCLE_UNPROVEN)
            egress = run.fork_rpc_egress
            if (
                egress is None
                or egress.status is not RepositoryForkEgressStatus.ENFORCED
                or egress.policy_sha256 != self.fork_rpc_policy_sha256
                or egress.state_id != state.state_id
                or egress.state_source_sha256 != state.state_source_sha256
                or attempt.fork_rpc_egress_sha256 != egress.evidence_sha256
            ):
                reasons.add(RepositoryStateInconclusiveReason.EGRESS_UNENFORCED)
            scopes = tuple(run.repository_test_fork_rpc_scopes)
            matching_scopes = tuple(
                scope for scope in scopes if scope.descriptor_sha256 == descriptor_sha256
            )
            scope_ledger_valid = egress is not None
            if egress is not None:
                scope_ledger_valid = (
                    tuple(
                        scope.bridge_scope_snapshot_sha256
                        for scope in run.repository_test_fork_rpc_scopes
                    )
                    == egress.selected_test_scope_snapshot_sha256s
                )
                counter_fields = (
                    "http_request_count",
                    "permitted_rpc_call_count",
                    "origin_attempted_rpc_call_count",
                    "origin_validated_rpc_call_count",
                    "synthetic_rpc_call_count",
                    "denied_request_count",
                    "malformed_request_count",
                    "limit_exceeded_request_count",
                    "upstream_error_request_count",
                )
                scope_ledger_valid = scope_ledger_valid and all(
                    sum(getattr(scope, field) for scope in scopes) <= getattr(egress, field)
                    for field in counter_fields
                )
                aggregate_method_counts = {
                    item.method: item.count for item in egress.allowed_method_counts
                }
                scoped_method_counts: dict[str, int] = {}
                for scope in scopes:
                    for item in scope.allowed_method_counts:
                        scoped_method_counts[item.method] = (
                            scoped_method_counts.get(item.method, 0) + item.count
                        )
                scope_ledger_valid = scope_ledger_valid and all(
                    count <= aggregate_method_counts.get(method, 0)
                    for method, count in scoped_method_counts.items()
                )
                scope_ledger_valid = scope_ledger_valid and all(
                    scope.attempt_binding_sha256 == attempt.workspace_identity_sha256
                    and scope.bridge_policy_sha256 == egress.policy_sha256
                    and scope.expected_chain_id == egress.expected_chain_id
                    and scope.pinned_block_number == egress.pinned_block_number
                    and scope.pinned_block_hash == egress.pinned_block_hash
                    for scope in scopes
                )
            if (
                not scope_ledger_valid
                or len(matching_scopes) != 1
                or matching_scopes[0].status is not RepositoryTestForkRpcScopeStatus.VALIDATED
                or matching_scopes[0].origin_validated_rpc_call_count == 0
            ):
                reasons.add(RepositoryStateInconclusiveReason.STATE_READ_UNPROVEN)
            if run.status is not ScannerStatus.SUCCESS:
                reasons.add(RepositoryStateInconclusiveReason.ATTEMPT_UNAVAILABLE)
                continue
            if run.execution_evidence is not ExecutionEvidenceKind.REAL:
                reasons.add(RepositoryStateInconclusiveReason.NON_REAL_EVIDENCE)
            if (
                run.repository_code_execution is not RepositoryCodeExecutionState.ISOLATED
                or run.isolation_backend is None
                or run.isolation_attestation_sha256 is None
            ):
                reasons.add(RepositoryStateInconclusiveReason.UNISOLATED_EXECUTION)
            selection = run.repository_suite_selection
            policy = run.repository_suite_execution_policy
            if (
                selection is None
                or policy is None
                or selection.repository_sha256 != self.repository_sha256
                or selection.selection_sha256 != self.selection_sha256
                or selection.configuration_sha256 != self.selection_configuration_sha256
                or run.version != policy.tool_version
                or run.executable_sha256 != policy.tool_sha256
                or run.isolation_backend != policy.isolation_backend
                or run.isolation_attestation_sha256 != policy.isolation_attestation_sha256
                or policy.chain_id != state.expected_chain_id
                or policy.block_number != state.pinned_block_number
                or policy.block_hash != state.observed_block_hash
                or policy.fuzz_seed != self.fuzz_seed
                or self.execution_configuration_sha256_for_policy(policy)
                != self.execution_configuration_sha256
            ):
                reasons.add(RepositoryStateInconclusiveReason.IDENTITY_MISMATCH)
            if not run.machine_output_validated or run.execution_observation_sha256 is None:
                reasons.add(RepositoryStateInconclusiveReason.INVALID_MACHINE_OUTPUT)
            matches = [
                execution
                for execution in run.repository_test_executions
                if execution.descriptor_sha256 == descriptor_sha256
            ]
            if len(matches) != 1:
                reasons.add(RepositoryStateInconclusiveReason.INVALID_MACHINE_OUTPUT)
            else:
                observations.append(matches[0])
        if len(observations) < 2:
            reasons.add(RepositoryStateInconclusiveReason.SINGLE_OBSERVATION)
        statuses = {observation.status for observation in observations}
        result_hashes = {observation.machine_result_sha256 for observation in observations}
        if len(statuses) != 1 or len(result_hashes) != 1 or None in result_hashes:
            reasons.add(RepositoryStateInconclusiveReason.ATTEMPT_DISAGREEMENT)
        if reasons:
            return (
                RepositoryStateConsensusStatus.INCONCLUSIVE,
                None,
                None,
                tuple(sorted(reasons, key=lambda reason: reason.value)),
            )
        observed_status = observations[0].status
        machine_result_sha256 = observations[0].machine_result_sha256
        assert machine_result_sha256 is not None
        if observed_status is RepositoryTestExecutionStatus.PASSED:
            consensus_status = RepositoryStateConsensusStatus.CONSISTENT_PASS
        elif observed_status in {
            RepositoryTestExecutionStatus.FAILED,
            RepositoryTestExecutionStatus.REVERTED,
            RepositoryTestExecutionStatus.ASSERTION_FAILED,
        }:
            consensus_status = RepositoryStateConsensusStatus.CONSISTENT_FAILURE
        else:
            return (
                RepositoryStateConsensusStatus.INCONCLUSIVE,
                None,
                None,
                (RepositoryStateInconclusiveReason.INVALID_MACHINE_OUTPUT,),
            )
        return consensus_status, observed_status, machine_result_sha256, ()

    @staticmethod
    def _expected_comparison(
        clean: RepositorySuiteTestStateConsensus,
        pinned: RepositorySuiteTestStateConsensus,
    ) -> tuple[
        RepositoryDifferentialClassification,
        RepositoryDivergenceDirection | None,
    ]:
        if (
            clean.status is RepositoryStateConsensusStatus.INCONCLUSIVE
            or pinned.status is RepositoryStateConsensusStatus.INCONCLUSIVE
        ):
            return RepositoryDifferentialClassification.INCONCLUSIVE, None
        if (
            clean.status is RepositoryStateConsensusStatus.CONSISTENT_PASS
            and pinned.status is RepositoryStateConsensusStatus.CONSISTENT_FAILURE
        ):
            return (
                RepositoryDifferentialClassification.DIVERGED,
                RepositoryDivergenceDirection.CLEAN_PASS_PINNED_FAILURE,
            )
        if (
            clean.status is RepositoryStateConsensusStatus.CONSISTENT_FAILURE
            and pinned.status is RepositoryStateConsensusStatus.CONSISTENT_PASS
        ):
            return (
                RepositoryDifferentialClassification.DIVERGED,
                RepositoryDivergenceDirection.CLEAN_FAILURE_PINNED_PASS,
            )
        if (
            clean.observed_status == pinned.observed_status
            and clean.machine_result_sha256 == pinned.machine_result_sha256
        ):
            classification = (
                RepositoryDifferentialClassification.CONSISTENT_PASS
                if clean.status is RepositoryStateConsensusStatus.CONSISTENT_PASS
                else RepositoryDifferentialClassification.CONSISTENT_FAILURE
            )
            return classification, None
        return (
            RepositoryDifferentialClassification.DIVERGED,
            RepositoryDivergenceDirection.SEMANTIC_RESULT_CHANGED,
        )

    def expected_matrix_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"matrix_sha256"})
        return _canonical_model_sha256(payload)


class RepositorySuiteDifferentialRun(StrictModel):
    """Self-hashed configured matrix result, including fail-closed non-results."""

    schema_version: Literal["1.0"] = "1.0"
    status: RepositoryDifferentialRunStatus
    configuration_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_state_ids: tuple[str, ...] = Field(min_length=2, max_length=8)
    required_repetitions: int = Field(ge=2, le=10)
    matrix: RepositorySuiteDifferentialMatrix | None = None
    limitations: tuple[str, ...] = Field(max_length=32)
    result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def sealed(cls, **values: Any) -> RepositorySuiteDifferentialRun:
        """Validate and self-hash a configured differential result."""

        if "result_sha256" in values:
            raise ValueError("result_sha256 is derived and cannot be supplied to sealed()")
        provisional = cls.model_construct(**values, result_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"result_sha256"})
        return cls.model_validate(
            {
                **payload,
                "result_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator("requested_state_ids")
    @classmethod
    def state_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", item) is None for item in value
        ):
            raise ValueError("differential requested state IDs must be unique and sorted")
        return value

    @field_validator("required_repetitions", mode="before")
    @classmethod
    def required_repetitions_are_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("repository differential repetitions require an exact integer")
        return value

    @field_validator("limitations")
    @classmethod
    def limitations_are_bounded(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(dict.fromkeys(value)) or any(
            not item or len(item) > 2_000 or not _repository_suite_text_is_safe(item)
            for item in value
        ):
            raise ValueError("differential limitations must be unique bounded printable text")
        return value

    @model_validator(mode="after")
    def status_matrix_and_hash_are_consistent(self) -> RepositorySuiteDifferentialRun:
        if self.matrix is not None:
            if (
                self.requested_state_ids != tuple(state.state_id for state in self.matrix.states)
                or self.required_repetitions != self.matrix.required_repetitions
            ):
                raise ValueError("differential result configuration differs from its matrix")
            has_inconclusive = any(
                comparison.classification is RepositoryDifferentialClassification.INCONCLUSIVE
                for comparison in self.matrix.comparisons
            )
        else:
            has_inconclusive = True
        if self.status is RepositoryDifferentialRunStatus.COMPLETE:
            if (
                self.matrix is None
                or has_inconclusive
                or self.limitations
                or self.configuration_sha256 != self.matrix.selection_configuration_sha256
            ):
                raise ValueError(
                    "complete differential result requires a conclusive matrix, "
                    "configuration binding, and no limitations"
                )
        elif not self.limitations:
            raise ValueError("non-complete differential result requires a prominent limitation")
        if self.status is RepositoryDifferentialRunStatus.INCONCLUSIVE and not has_inconclusive:
            raise ValueError("inconclusive differential result requires incomplete matrix evidence")
        if self.status is RepositoryDifferentialRunStatus.FAILED and self.matrix is not None:
            raise ValueError("failed differential result cannot claim a completed matrix")
        if self.result_sha256 != self.expected_result_sha256():
            raise ValueError("repository differential result hash does not match its fields")
        return self

    def expected_result_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"result_sha256"})
        return _canonical_model_sha256(payload)


class RepositoryForkRpcPrivacyEvidence(StrictModel):
    """Endpoint-free privacy projection of one configured fork-matrix run."""

    schema_version: Literal["1.0"] = "1.0"
    status: RepositoryForkEgressStatus
    differential_result_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    boundary_kind: Literal["trusted_read_only_loopback_bridge"] = (
        "trusted_read_only_loopback_bridge"
    )
    network_scope: Literal["single_loopback_origin"] = "single_loopback_origin"
    state_ids: tuple[str, ...] = Field(min_length=2, max_length=8)
    configured_policy_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    observed_policy_sha256s: tuple[str, ...] = Field(max_length=8)
    attempt_count: int = Field(ge=0, le=80)
    egress_evidence_count: int = Field(ge=0, le=80)
    egress_evidence_sha256s: tuple[str, ...] = Field(max_length=80)
    http_request_count: int = Field(ge=0, le=80_000_000)
    permitted_rpc_call_count: int = Field(ge=0, le=80_000_000)
    origin_attempted_rpc_call_count: int = Field(ge=0, le=80_000_000)
    origin_validated_rpc_call_count: int = Field(ge=0, le=80_000_000)
    synthetic_rpc_call_count: int = Field(ge=0, le=80_000_000)
    denied_request_count: int = Field(ge=0, le=80_000_000)
    malformed_request_count: int = Field(ge=0, le=80_000_000)
    limit_exceeded_request_count: int = Field(ge=0, le=80_000_000)
    upstream_error_request_count: int = Field(ge=0, le=80_000_000)
    transaction_capable_request_forwarded: Literal[False] = False
    credentials_forwarded: Literal[False] = False
    raw_payloads_retained: Literal[False] = False
    rpc_endpoint_recorded: Literal[False] = False
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def from_differential(
        cls,
        result: RepositorySuiteDifferentialRun,
    ) -> RepositoryForkRpcPrivacyEvidence:
        """Project only endpoint-free bridge accounting from a typed matrix result."""

        matrix = result.matrix
        if matrix is None:
            egress: tuple[ForkRpcReadOnlyEgressEvidence, ...] = ()
            configured_policy_sha256 = None
        else:
            egress = tuple(
                item
                for attempt in matrix.attempts
                if (item := attempt.scanner_run.fork_rpc_egress) is not None
            )
            configured_policy_sha256 = matrix.fork_rpc_policy_sha256
        violation = any(item.status is RepositoryForkEgressStatus.VIOLATION for item in egress)
        fully_enforced = (
            matrix is not None
            and len(egress) == len(matrix.attempts)
            and bool(egress)
            and all(
                item.status is RepositoryForkEgressStatus.ENFORCED
                and item.policy_sha256 == matrix.fork_rpc_policy_sha256
                for item in egress
            )
        )
        status = (
            RepositoryForkEgressStatus.VIOLATION
            if violation
            else (
                RepositoryForkEgressStatus.ENFORCED
                if fully_enforced
                else RepositoryForkEgressStatus.UNVERIFIED
            )
        )
        values: dict[str, Any] = {
            "status": status,
            "differential_result_sha256": result.result_sha256,
            "state_ids": result.requested_state_ids,
            "configured_policy_sha256": configured_policy_sha256,
            "observed_policy_sha256s": tuple(sorted({item.policy_sha256 for item in egress})),
            "attempt_count": len(matrix.attempts) if matrix is not None else 0,
            "egress_evidence_count": len(egress),
            "egress_evidence_sha256s": tuple(item.evidence_sha256 for item in egress),
        }
        for field in (
            "http_request_count",
            "permitted_rpc_call_count",
            "origin_attempted_rpc_call_count",
            "origin_validated_rpc_call_count",
            "synthetic_rpc_call_count",
            "denied_request_count",
            "malformed_request_count",
            "limit_exceeded_request_count",
            "upstream_error_request_count",
        ):
            values[field] = sum(getattr(item, field) for item in egress)
        provisional = cls.model_construct(**values, evidence_sha256="0" * 64)
        payload = provisional.model_dump(mode="json", exclude={"evidence_sha256"})
        return cls.model_validate(
            {
                **payload,
                "evidence_sha256": _canonical_model_sha256(payload),
            }
        )

    @field_validator(
        "attempt_count",
        "egress_evidence_count",
        "http_request_count",
        "permitted_rpc_call_count",
        "origin_attempted_rpc_call_count",
        "origin_validated_rpc_call_count",
        "synthetic_rpc_call_count",
        "denied_request_count",
        "malformed_request_count",
        "limit_exceeded_request_count",
        "upstream_error_request_count",
        mode="before",
    )
    @classmethod
    def integer_evidence_is_exact(cls, value: object) -> object:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("fork RPC privacy accounting requires exact integers")
        return value

    @field_validator("state_ids")
    @classmethod
    def state_ids_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", item) is None for item in value
        ):
            raise ValueError("fork RPC privacy state IDs must be unique and sorted")
        return value

    @field_validator("observed_policy_sha256s")
    @classmethod
    def policy_hashes_are_canonical(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))) or any(
            re.fullmatch(r"[0-9a-f]{64}", item) is None for item in value
        ):
            raise ValueError("fork RPC privacy policy hashes must be unique and sorted")
        return value

    @field_validator("egress_evidence_sha256s")
    @classmethod
    def egress_hashes_are_valid(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(re.fullmatch(r"[0-9a-f]{64}", item) is None for item in value):
            raise ValueError("fork RPC privacy egress references must be SHA-256 values")
        return value

    @model_validator(mode="after")
    def accounting_status_and_hash_are_consistent(
        self,
    ) -> RepositoryForkRpcPrivacyEvidence:
        if self.egress_evidence_count != len(self.egress_evidence_sha256s):
            raise ValueError("fork RPC privacy evidence count differs from its hashes")
        if self.egress_evidence_count > self.attempt_count:
            raise ValueError("fork RPC privacy evidence count exceeds matrix attempts")
        if (
            self.origin_attempted_rpc_call_count + self.synthetic_rpc_call_count
            != self.permitted_rpc_call_count
            or self.origin_validated_rpc_call_count > self.origin_attempted_rpc_call_count
        ):
            raise ValueError("fork RPC privacy call accounting is inconsistent")
        rejection_or_error_count = (
            self.denied_request_count
            + self.malformed_request_count
            + self.limit_exceeded_request_count
            + self.upstream_error_request_count
        )
        if self.status is RepositoryForkEgressStatus.ENFORCED:
            if (
                self.attempt_count == 0
                or self.egress_evidence_count != self.attempt_count
                or self.permitted_rpc_call_count == 0
                or self.origin_validated_rpc_call_count != self.origin_attempted_rpc_call_count
                or rejection_or_error_count
                or self.configured_policy_sha256 is None
                or self.observed_policy_sha256s != (self.configured_policy_sha256,)
            ):
                raise ValueError(
                    "enforced fork RPC privacy evidence requires complete validated accounting"
                )
        elif self.status is RepositoryForkEgressStatus.VIOLATION:
            if rejection_or_error_count == 0:
                raise ValueError("fork RPC privacy violation requires rejection/error evidence")
        elif (
            self.attempt_count
            and self.egress_evidence_count == self.attempt_count
            and rejection_or_error_count == 0
            and self.configured_policy_sha256 is not None
            and self.observed_policy_sha256s == (self.configured_policy_sha256,)
            and self.permitted_rpc_call_count > 0
            and self.origin_validated_rpc_call_count == self.origin_attempted_rpc_call_count
        ):
            raise ValueError("fully enforced fork RPC privacy evidence cannot be unverified")
        if self.evidence_sha256 != self.expected_evidence_sha256():
            raise ValueError("fork RPC privacy evidence hash does not match its fields")
        return self

    def expected_evidence_sha256(self) -> str:
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        return _canonical_model_sha256(payload)


class DependencyPackageEvidence(StrictModel):
    ecosystem: Literal["npm"] = "npm"
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    lock_path: str = Field(min_length=1, max_length=1_000)
    integrity: str = Field(
        pattern=r"^sha512-[A-Za-z0-9+/]+={0,2}$",
        max_length=256,
    )
    tree_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purl: str = Field(min_length=1, max_length=1_000)
    file_count: int = Field(ge=1)
    total_bytes: int = Field(ge=1)


class DependencyAdvisoryFinding(StrictModel):
    advisory_id: str = Field(min_length=1, max_length=200)
    package_name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    severity: Severity
    summary: str = Field(min_length=1, max_length=2_000)


class DependencyPreparationResult(StrictModel):
    status: DependencyPreparationStatus
    project_root: str
    lockfile_path: str | None = None
    lockfile_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    packages: list[DependencyPackageEvidence] = Field(default_factory=list)
    scan_status: DependencyScanStatus = DependencyScanStatus.NOT_RUN
    scan_findings: list[DependencyAdvisoryFinding] = Field(default_factory=list)
    checks: dict[str, bool] = Field(default_factory=dict)
    copied_files: int = Field(default=0, ge=0)
    copied_bytes: int = Field(default=0, ge=0)
    prepared_path: str | None = None
    errors: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def prepared_result_has_complete_evidence(self) -> DependencyPreparationResult:
        if self.status is DependencyPreparationStatus.PREPARED and (
            self.lockfile_path is None
            or self.lockfile_sha256 is None
            or self.snapshot_sha256 is None
            or not self.packages
            or self.scan_status is not DependencyScanStatus.PASSED
            or self.scan_findings
            or not self.checks
            or not all(self.checks.values())
            or self.copied_files != sum(package.file_count for package in self.packages)
            or self.copied_bytes != sum(package.total_bytes for package in self.packages)
            or self.prepared_path is None
            or self.errors
        ):
            raise ValueError("prepared dependencies require complete validated evidence")
        if (
            self.status
            in {
                DependencyPreparationStatus.DISABLED,
                DependencyPreparationStatus.NOT_APPLICABLE,
                DependencyPreparationStatus.REJECTED,
                DependencyPreparationStatus.FAILED,
            }
            and self.prepared_path is not None
        ):
            raise ValueError("unprepared dependency result cannot expose a prepared path")
        if self.scan_findings and self.scan_status is not DependencyScanStatus.FAILED:
            raise ValueError("dependency scan findings require a failed scan status")
        return self


class DependencySbomComponent(StrictModel):
    type: Literal["library"] = "library"
    bom_ref: str = Field(
        min_length=1,
        max_length=1_000,
        validation_alias=AliasChoices("bom_ref", "bom-ref"),
        serialization_alias="bom-ref",
    )
    name: str = Field(min_length=1, max_length=214)
    version: str = Field(min_length=1, max_length=128)
    purl: str = Field(min_length=1, max_length=1_000)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    integrity: str = Field(
        pattern=r"^sha512-[A-Za-z0-9+/]+={0,2}$",
        max_length=256,
    )


class DependencySbom(StrictModel):
    bom_format: Literal["CycloneDX"] = Field(
        default="CycloneDX",
        validation_alias=AliasChoices("bom_format", "bomFormat"),
        serialization_alias="bomFormat",
    )
    spec_version: Literal["1.5"] = Field(
        default="1.5",
        validation_alias=AliasChoices("spec_version", "specVersion"),
        serialization_alias="specVersion",
    )
    serial_number: str = Field(
        pattern=r"^urn:uuid:[0-9a-f-]{36}$",
        validation_alias=AliasChoices("serial_number", "serialNumber"),
        serialization_alias="serialNumber",
    )
    version: Literal[1] = 1
    project_root: str
    lockfile_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    components: list[DependencySbomComponent] = Field(min_length=1)

    @model_validator(mode="after")
    def components_are_unique_and_sorted(self) -> DependencySbom:
        references = [component.bom_ref for component in self.components]
        if references != sorted(set(references)):
            raise ValueError("SBOM component references must be unique and sorted")
        return self


class SolidityProjectMetadata(StrictModel):
    project_type: SolidityProjectType
    project_root: str
    source_directories: list[str] = Field(default_factory=list)
    test_directories: list[str] = Field(default_factory=list)
    script_directories: list[str] = Field(default_factory=list)
    deployment_directories: list[str] = Field(default_factory=list)
    dependency_files: list[str] = Field(default_factory=list)
    compiler_versions: list[str] = Field(default_factory=list)
    optimizer_enabled: bool | None = None
    optimizer_runs: int | None = None
    evm_version: str | None = None
    remappings: list[str] = Field(default_factory=list)
    build_command: list[str] = Field(default_factory=list)
    test_command: list[str] = Field(default_factory=list)
    framework_config_files: list[str] = Field(default_factory=list)
    artifact_paths: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    discovery_warnings: list[str] = Field(default_factory=list)


class SolidityCompilationResult(StrictModel):
    status: CompilationStatus
    framework: SolidityProjectType
    project_root: str
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    command: list[str] = Field(default_factory=list)
    compiler_versions: list[str] = Field(default_factory=list)
    contracts_compiled: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    source_maps_available: bool = False
    ast_available: bool = False
    duration_seconds: float = Field(default=0, ge=0)
    tool_versions: dict[str, str] = Field(default_factory=dict)
    stdout_path: str | None = None
    stderr_path: str | None = None
    isolation_backend: str | None = None
    repository_code_execution: RepositoryCodeExecutionState = (
        RepositoryCodeExecutionState.NOT_APPLICABLE
    )

    @model_validator(mode="after")
    def repository_code_isolation_evidence_is_consistent(
        self,
    ) -> SolidityCompilationResult:
        if (
            self.repository_code_execution is RepositoryCodeExecutionState.ISOLATED
            and self.isolation_backend is None
        ):
            raise ValueError("isolated repository code requires an isolation backend")
        if (
            self.repository_code_execution is RepositoryCodeExecutionState.BLOCKED
            and self.status is CompilationStatus.SUCCESS
        ):
            raise ValueError("blocked repository code cannot have a successful compilation")
        return self


class SolidityEntity(StrictModel):
    id: str
    kind: SolidityEntityKind
    name: str
    contract_name: str | None = None
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    byte_start: int = Field(ge=0)
    byte_end: int = Field(ge=0)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=200)
    visibility: str | None = None
    mutability: str | None = None
    payable: bool = False
    signature: str | None = None
    selector: str | None = None
    return_types: list[str] = Field(default_factory=list)
    documentation: str | None = None

    @model_validator(mode="after")
    def entity_lines_are_ordered(self) -> SolidityEntity:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.byte_end < self.byte_start:
            raise ValueError("byte_end must not precede byte_start")
        if self.provenance is SolidityProvenance.FALLBACK and self.confidence >= 0.8:
            raise ValueError("fallback entity confidence must remain below compiler confidence")
        return self


class SoliditySymbolIndex(StrictModel):
    projects: list[SolidityProjectMetadata]
    entities: list[SolidityEntity]
    ast_sources: list[str] = Field(default_factory=list)
    fallback_sources: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class SolidityStorageEntry(StrictModel):
    """Compiler-derived or explicitly lower-confidence storage layout entry."""

    id: str
    contract_name: str
    declaring_contract_name: str | None = None
    variable_name: str
    type_name: str
    slot: str
    offset: int = Field(ge=0)
    byte_size: int | None = Field(default=None, ge=0)
    ast_id: int | None = None
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def storage_provenance_is_exact(self) -> SolidityStorageEntry:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.provenance is SolidityProvenance.FALLBACK and self.confidence >= 0.8:
            raise ValueError("fallback storage confidence must remain below compiler confidence")
        return self


class SolidityGraphNode(StrictModel):
    id: str
    kind: SolidityGraphNodeKind
    label: str
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def graph_node_provenance_is_exact(self) -> SolidityGraphNode:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.provenance is SolidityProvenance.FALLBACK and self.confidence >= 0.8:
            raise ValueError("fallback graph-node confidence must remain below compiler confidence")
        return self


class SolidityGraphEdge(StrictModel):
    graph: SolidityGraphKind
    source_id: str
    target_id: str
    label: str
    provenance: SolidityProvenance
    path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def graph_edge_provenance_is_exact(self) -> SolidityGraphEdge:
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if self.provenance is SolidityProvenance.FALLBACK and self.confidence >= 0.8:
            raise ValueError("fallback graph-edge confidence must remain below compiler confidence")
        return self


class SolidityGraphSet(StrictModel):
    nodes: list[SolidityGraphNode] = Field(default_factory=list)
    edges: list[SolidityGraphEdge]
    storage_layout: list[SolidityStorageEntry] = Field(default_factory=list)
    analyzed_graphs: list[SolidityGraphKind] = Field(default_factory=list)
    coverage: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class InvariantSpec(StrictModel):
    id: str
    title: str
    category: InvariantCategory
    description: str
    template: InvariantTemplate | None = None
    locations: list[Location] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    state_variables: list[str] = Field(default_factory=list)
    functions: list[str] = Field(default_factory=list)
    protocol_profiles: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    template_available: bool = False
    executable: bool = False
    analysis_state: AnalysisState = AnalysisState.DETERMINISTIC
    evidence_hash: str


class InvariantSuite(StrictModel):
    invariants: list[InvariantSpec] = Field(default_factory=list)
    protocol_profiles: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    templates_available_count: int = Field(default=0, ge=0)
    executable_count: int = Field(default=0, ge=0)


class InvariantReviewDecision(StrictModel):
    """A model opinion about an existing invariant, never deterministic evidence."""

    invariant_id: str = Field(min_length=1, max_length=160)
    verdict: InvariantReviewVerdict
    rationale: str = Field(min_length=1, max_length=8_000)
    missing_context: list[str] = Field(default_factory=list, max_length=50)
    assumptions_to_validate: list[str] = Field(default_factory=list, max_length=50)


class ModelInvariantProposal(StrictModel):
    """A bounded invariant hypothesis proposed by the dedicated model role."""

    title: str = Field(min_length=1, max_length=240)
    category: InvariantCategory
    description: str = Field(min_length=1, max_length=8_000)
    template: InvariantTemplate | None = None
    locations: list[Location] = Field(min_length=1, max_length=12)
    entity_ids: list[str] = Field(default_factory=list, max_length=50)
    state_variables: list[str] = Field(default_factory=list, max_length=50)
    functions: list[str] = Field(default_factory=list, max_length=50)
    protocol_profiles: list[str] = Field(default_factory=list, max_length=20)
    assumptions: list[str] = Field(default_factory=list, max_length=50)
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(min_length=1, max_length=8_000)


class InvariantReviewBatch(StrictModel):
    """Raw structured output accepted from the invariant-review model."""

    decisions: list[InvariantReviewDecision] = Field(default_factory=list, max_length=1_000)
    proposals: list[ModelInvariantProposal] = Field(default_factory=list, max_length=200)


class InvariantProposalRejection(StrictModel):
    """Deterministic reason a model proposal was excluded from audit evidence."""

    title: str
    errors: list[str] = Field(min_length=1)


class InvariantReviewResult(StrictModel):
    """Validated, non-finding result of the dedicated invariant-review stage."""

    decisions: list[InvariantReviewDecision] = Field(default_factory=list)
    accepted_proposals: list[InvariantSpec] = Field(default_factory=list)
    rejected_proposals: list[InvariantProposalRejection] = Field(default_factory=list)
    analysis_state: AnalysisState = AnalysisState.MODEL_ONLY
    warning: str = (
        "Model invariant review is a hypothesis-generation aid. It does not create findings, "
        "deterministic evidence, or executable properties."
    )

    @model_validator(mode="after")
    def proposals_remain_model_only(self) -> InvariantReviewResult:
        for proposal in self.accepted_proposals:
            if (
                proposal.provenance is not SolidityProvenance.MODEL_SUGGESTED
                or proposal.analysis_state is not AnalysisState.MODEL_ONLY
                or proposal.executable
                or proposal.template_available
            ):
                raise ValueError(
                    "accepted model invariants must remain non-executable model claims"
                )
        return self


class HarnessArgument(StrictModel):
    kind: ForkArgumentKind
    source: HarnessArgumentSource
    value: str | None = Field(default=None, max_length=4_096)
    minimum: int | None = Field(default=None, ge=0, le=2**256 - 1)
    maximum: int | None = Field(default=None, ge=0, le=2**256 - 1)
    fuzz_slot: int | None = Field(default=None, ge=0, le=7)

    @model_validator(mode="after")
    def source_fields_are_consistent(self) -> HarnessArgument:
        if self.source is HarnessArgumentSource.CONSTANT:
            if self.value is None:
                raise ValueError("constant harness arguments require value")
            ForkArgument(kind=self.kind, value=self.value)
        elif self.source is HarnessArgumentSource.FUZZ_UINT:
            if self.kind is not ForkArgumentKind.UINT256:
                raise ValueError("fuzz_uint supports uint256 arguments only")
            if self.fuzz_slot is None:
                raise ValueError("fuzz_uint requires fuzz_slot")
            if self.minimum is None or self.maximum is None:
                raise ValueError("fuzz_uint requires minimum and maximum")
            if self.maximum < self.minimum:
                raise ValueError("fuzz_uint maximum must not precede minimum")
        elif self.source is HarnessArgumentSource.ACTOR:
            if self.kind is not ForkArgumentKind.ADDRESS:
                raise ValueError("actor arguments must have address ABI type")
            if self.fuzz_slot is None:
                raise ValueError("actor arguments require fuzz_slot")
        return self


class StatefulActionSpec(StrictModel):
    action_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    target: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    function_signature: str = Field(min_length=3, max_length=256)
    actor_names: list[str] = Field(min_length=1, max_length=16)
    actor_fuzz_slot: int | None = Field(default=None, ge=0, le=7)
    arguments: list[HarnessArgument] = Field(default_factory=list, max_length=24)
    value_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    time_shift_seconds_before: int = Field(default=0, ge=0, le=31_536_000)

    @field_validator("function_signature")
    @classmethod
    def action_signature_is_declarative(cls, value: str) -> str:
        ForkCallStep(
            step_id="validate",
            actor="validate",
            target="Validate",
            function_signature=value,
            arguments=[
                ForkArgument(kind=kind, value=_validation_argument_value(kind))
                for kind in _signature_argument_kinds(value)
            ],
        )
        return value

    @model_validator(mode="after")
    def argument_types_match_signature(self) -> StatefulActionSpec:
        expected = _signature_argument_kinds(self.function_signature)
        if expected != [argument.kind for argument in self.arguments]:
            raise ValueError("harness arguments must exactly match function_signature ABI types")
        if len(self.actor_names) != len(set(self.actor_names)):
            raise ValueError("actor_names must be unique")
        argument_slots = {
            argument.fuzz_slot for argument in self.arguments if argument.fuzz_slot is not None
        }
        if self.actor_fuzz_slot is not None and self.actor_fuzz_slot in argument_slots:
            raise ValueError("actor_fuzz_slot must be distinct from argument fuzz slots")
        return self


class InvariantProbe(StrictModel):
    target: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    function_signature: str = Field(min_length=3, max_length=256)
    arguments: list[ForkArgument] = Field(default_factory=list, max_length=24)

    @model_validator(mode="after")
    def probe_signature_matches_arguments(self) -> InvariantProbe:
        expected = _signature_argument_kinds(self.function_signature)
        if expected != [argument.kind for argument in self.arguments]:
            raise ValueError("probe arguments must exactly match function_signature ABI types")
        return self


class InvariantPropertySpec(StrictModel):
    property_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    left: InvariantProbe
    relation: InvariantRelation
    right: InvariantProbe | None = None
    expected_uint: int | None = Field(default=None, ge=0, le=2**256 - 1)
    compare_to_initial: bool = False
    required_action_ids: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def has_exactly_one_comparison_operand(self) -> InvariantPropertySpec:
        operands = sum(
            (
                self.right is not None,
                self.expected_uint is not None,
                self.compare_to_initial,
            )
        )
        if operands != 1:
            raise ValueError(
                "property requires exactly one of right, expected_uint, or compare_to_initial"
            )
        if len(self.required_action_ids) != len(set(self.required_action_ids)):
            raise ValueError("property required action IDs must be unique")
        return self


class LocalInvariantDeploymentArgument(StrictModel):
    """One constructor dependency for a synthetic local invariant target."""

    target_alias: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    cast_contract: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$",
    )


class LocalInvariantDeployment(StrictModel):
    """Bounded source-local deployment used only inside an isolated generated test."""

    target_alias: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    contract_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    source_path: str = Field(min_length=1, max_length=500)
    constructor_arguments: list[LocalInvariantDeploymentArgument] = Field(
        default_factory=list,
        max_length=8,
    )
    token_seed_function_signature: Literal["mint(address,uint256)"] | None = None

    @field_validator("source_path")
    @classmethod
    def source_path_is_project_relative_solidity(cls, value: str) -> str:
        if (
            "\\" in value
            or value.startswith(("/", "-"))
            or not value.endswith(".sol")
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError(
                "local invariant deployment source_path must be a normalized "
                "project-relative Solidity path"
            )
        return value


class FinancialSettlementProbeSpec(StrictModel):
    """Typed uint256 probes used to validate one settled invariant action."""

    actor: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    asset_kind: FinancialAssetKind
    asset_target: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$",
    )
    action_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    starting_assets: InvariantProbe
    borrowed_assets: InvariantProbe
    repaid_assets: InvariantProbe
    gross_assets_received: InvariantProbe
    fees_paid: InvariantProbe
    slippage_loss: InvariantProbe
    ending_assets: InvariantProbe
    net_impact: InvariantProbe

    @model_validator(mode="after")
    def asset_and_probes_are_bounded(self) -> FinancialSettlementProbeSpec:
        if self.asset_kind is FinancialAssetKind.NATIVE and self.asset_target is not None:
            raise ValueError("native financial probes cannot declare an ERC20 target")
        if self.asset_kind is FinancialAssetKind.ERC20 and self.asset_target is None:
            raise ValueError("ERC20 financial probes require an asset target")
        probes = (
            self.starting_assets,
            self.borrowed_assets,
            self.repaid_assets,
            self.gross_assets_received,
            self.fees_paid,
            self.slippage_loss,
            self.ending_assets,
            self.net_impact,
        )
        if any(probe.arguments for probe in probes):
            raise ValueError("financial settlement probes must use zero-argument uint getters")
        return self


class LendingBoundaryProbeSpec(StrictModel):
    """Typed uint256 probes for one settled healthy-position liquidation boundary."""

    action_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    debt_before: InvariantProbe
    collateral_before: InvariantProbe
    debt_after: InvariantProbe
    collateral_after: InvariantProbe
    collateral_seized: InvariantProbe
    bad_debt_after: InvariantProbe

    @model_validator(mode="after")
    def probes_are_zero_argument_getters(self) -> LendingBoundaryProbeSpec:
        probes = (
            self.debt_before,
            self.collateral_before,
            self.debt_after,
            self.collateral_after,
            self.collateral_seized,
            self.bad_debt_after,
        )
        if any(probe.arguments for probe in probes):
            raise ValueError("lending boundary probes must use zero-argument uint getters")
        return self


class SharePriceBoundaryProbeSpec(StrictModel):
    """Typed uint256 probes for one settled share-price boundary transition."""

    action_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    rate_scale: InvariantProbe
    total_assets_before: InvariantProbe
    total_shares_before: InvariantProbe
    legitimate_yield: InvariantProbe
    expected_rate_after_yield: InvariantProbe
    observed_rate_after: InvariantProbe
    shares_redeemed: InvariantProbe
    assets_redeemed: InvariantProbe
    excess_assets: InvariantProbe

    @model_validator(mode="after")
    def probes_are_zero_argument_getters(self) -> SharePriceBoundaryProbeSpec:
        probes = (
            self.rate_scale,
            self.total_assets_before,
            self.total_shares_before,
            self.legitimate_yield,
            self.expected_rate_after_yield,
            self.observed_rate_after,
            self.shares_redeemed,
            self.assets_redeemed,
            self.excess_assets,
        )
        if any(probe.arguments for probe in probes):
            raise ValueError("share-price boundary probes must use zero-argument uint getters")
        return self


class FoundryInvariantHarnessSpec(StrictModel):
    """Operator/model-neutral declarative stateful invariant harness."""

    invariant_id: str = Field(min_length=1, max_length=160)
    name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    actors: list[ForkActor] = Field(min_length=1, max_length=16)
    setup_calls: list[ForkCallStep] = Field(default_factory=list, max_length=32)
    token_balance_seeds: list[TokenBalanceSeed] = Field(default_factory=list, max_length=16)
    local_deployments: list[LocalInvariantDeployment] = Field(
        default_factory=list,
        max_length=16,
    )
    actions: list[StatefulActionSpec] = Field(default_factory=list, max_length=32)
    required_action_sequence: list[str] = Field(default_factory=list, max_length=8)
    properties: list[InvariantPropertySpec] = Field(min_length=1, max_length=16)
    runs: int = Field(default=256, ge=1, le=100_000)
    depth: int = Field(default=64, ge=1, le=10_000)
    seed: int = Field(default=1, ge=0, le=2**256 - 1)
    economic_template: EconomicSimulationKind | None = None
    required_transaction_ordering: TransactionOrderingCapability = (
        TransactionOrderingCapability.NONE
    )
    capability_policy: AttackerCapabilityPolicy | None = None
    financial_settlement: FinancialSettlementProbeSpec | None = None
    lending_boundary: LendingBoundaryProbeSpec | None = None
    share_price_boundary: SharePriceBoundaryProbeSpec | None = None
    assumptions: list[str] = Field(default_factory=list, max_length=40)

    def specification_sha256(self) -> str:
        """Return the canonical identity of this complete typed harness."""

        return hashlib.sha256(
            json.dumps(
                self.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @model_validator(mode="after")
    def references_declared_actors(self) -> FoundryInvariantHarnessSpec:
        actor_names = [actor.name for actor in self.actors]
        if len(actor_names) != len(set(actor_names)):
            raise ValueError("actor names must be unique")
        declared = set(actor_names)
        if not self.actions and not self.setup_calls:
            raise ValueError("harness requires at least one setup call or stateful action")
        if any(call.actor not in declared for call in self.setup_calls):
            raise ValueError("every setup call actor must be declared")
        if any(seed.actor not in declared for seed in self.token_balance_seeds):
            raise ValueError("every token balance seed actor must be declared")
        if any(not set(action.actor_names) <= declared for action in self.actions):
            raise ValueError("every action actor must be declared")
        setup_ids = [call.step_id for call in self.setup_calls]
        if len(setup_ids) != len(set(setup_ids)):
            raise ValueError("setup call IDs must be unique")
        seed_pairs = [(seed.token, seed.actor) for seed in self.token_balance_seeds]
        if len(seed_pairs) != len(set(seed_pairs)):
            raise ValueError("token balance seed pairs must be unique")
        referenced_targets = {
            *(call.target for call in self.setup_calls),
            *(seed.token for seed in self.token_balance_seeds),
            *(action.target for action in self.actions),
            *(property_spec.left.target for property_spec in self.properties),
            *(
                property_spec.right.target
                for property_spec in self.properties
                if property_spec.right is not None
            ),
            *(
                _financial_probe_targets(self.financial_settlement)
                if self.financial_settlement is not None
                else set()
            ),
            *(
                _lending_probe_targets(self.lending_boundary)
                if self.lending_boundary is not None
                else set()
            ),
            *(
                _share_price_probe_targets(self.share_price_boundary)
                if self.share_price_boundary is not None
                else set()
            ),
        }
        deployment_targets = [deployment.target_alias for deployment in self.local_deployments]
        if len(deployment_targets) != len(set(deployment_targets)):
            raise ValueError("local invariant deployment targets must be unique")
        if self.local_deployments and set(deployment_targets) != referenced_targets:
            raise ValueError(
                "local invariant deployments must exactly cover every referenced target alias"
            )
        deployed: set[str] = set()
        for deployment in self.local_deployments:
            constructor_targets = {
                argument.target_alias for argument in deployment.constructor_arguments
            }
            if not constructor_targets <= deployed:
                raise ValueError(
                    "local invariant constructor dependencies must reference earlier deployments"
                )
            deployed.add(deployment.target_alias)
        seeded_tokens = {seed.token for seed in self.token_balance_seeds}
        local_seed_hooks = {
            deployment.target_alias
            for deployment in self.local_deployments
            if deployment.token_seed_function_signature is not None
        }
        if self.local_deployments and not seeded_tokens <= local_seed_hooks:
            raise ValueError("locally deployed seeded tokens require a fixed token seed function")
        action_ids = [action.action_id for action in self.actions]
        property_ids = [property_spec.property_id for property_spec in self.properties]
        if len(action_ids) != len(set(action_ids)):
            raise ValueError("action IDs must be unique")
        declared_action_ids = set(action_ids)
        if not set(self.required_action_sequence) <= declared_action_ids:
            raise ValueError("required action sequence must reference declared action IDs")
        if any(
            not set(property_spec.required_action_ids) <= declared_action_ids
            for property_spec in self.properties
        ):
            raise ValueError("property action guards must reference declared action IDs")
        if len(property_ids) != len(set(property_ids)):
            raise ValueError("property IDs must be unique")
        if self.economic_template is EconomicSimulationKind.SANDWICH and (
            self.required_transaction_ordering is not TransactionOrderingCapability.SAME_BLOCK
        ):
            raise ValueError("ordering-sensitive harnesses must declare same_block ordering")
        if self.economic_template is EconomicSimulationKind.STATE_ORDERING and (
            self.required_transaction_ordering
            is not TransactionOrderingCapability.MULTI_TRANSACTION
        ):
            raise ValueError("multi-step state harnesses must declare multi_transaction ordering")
        if (
            self.economic_template
            not in {
                EconomicSimulationKind.SANDWICH,
                EconomicSimulationKind.STATE_ORDERING,
            }
            and self.required_transaction_ordering is not TransactionOrderingCapability.NONE
        ):
            raise ValueError(
                "transaction ordering is supported only by declared ordering templates"
            )
        if self.economic_template is EconomicSimulationKind.STATE_ORDERING:
            if (
                len(self.actions) != 2
                or self.depth != 2
                or self.required_action_sequence != action_ids
                or len(set(self.required_action_sequence)) != 2
            ):
                raise ValueError(
                    "multi-step state harnesses require two distinct ordered actions at depth two"
                )
            if self.runs > 32:
                raise ValueError("multi-step state harnesses require at most 32 bounded runs")
            if (
                self.capability_policy is None
                or self.capability_policy.transaction_ordering
                is not TransactionOrderingCapability.MULTI_TRANSACTION
            ):
                raise ValueError(
                    "multi-step state harnesses require a multi-transaction caller policy"
                )
            required_ids = set(self.required_action_sequence)
            if any(
                set(property_spec.required_action_ids) != required_ids
                for property_spec in self.properties
            ):
                raise ValueError("multi-step state properties must require both ordered actions")
        elif self.required_action_sequence:
            raise ValueError(
                "required action sequences are supported only by multi-step state harnesses"
            )
        time_shift_per_depth = max(
            (action.time_shift_seconds_before for action in self.actions),
            default=0,
        )
        if time_shift_per_depth:
            if self.capability_policy is None:
                raise ValueError("time-shifting actions require a declared capability policy")
            if time_shift_per_depth * self.depth > self.capability_policy.max_time_shift_seconds:
                raise ValueError("stateful time shifts exceed the declared bounded capability")
        if self.capability_policy is not None:
            controlled = set(self.capability_policy.attacker_controlled_actors)
            if not controlled <= declared:
                raise ValueError("capability-policy actors must be declared harness actors")
        if self.financial_settlement is not None:
            if self.financial_settlement.actor not in declared:
                raise ValueError("financial settlement actor must be declared")
            if self.financial_settlement.action_id not in declared_action_ids:
                raise ValueError("financial settlement action must reference a declared action")
        if (
            self.lending_boundary is not None
            and self.lending_boundary.action_id not in declared_action_ids
        ):
            raise ValueError("lending boundary action must reference a declared action")
        if (
            self.share_price_boundary is not None
            and self.share_price_boundary.action_id not in declared_action_ids
        ):
            raise ValueError("share-price boundary action must reference a declared action")
        if self.economic_template is EconomicSimulationKind.FLASH_ORACLE:
            if self.financial_settlement is None:
                raise ValueError(
                    "temporary-liquidity oracle harnesses require financial settlement probes"
                )
            if (
                self.capability_policy is None
                or self.capability_policy.flash_liquidity_wei == 0
                or self.capability_policy.oracle_influence is OracleInfluenceCapability.NONE
            ):
                raise ValueError(
                    "temporary-liquidity oracle harnesses require bounded liquidity "
                    "and oracle-influence capabilities"
                )
            if self.depth != 1 or len(self.actions) != 1:
                raise ValueError(
                    "temporary-liquidity oracle harnesses require exactly one bounded action"
                )
        if self.economic_template is EconomicSimulationKind.AMM_RESERVES:
            if self.financial_settlement is None:
                raise ValueError("AMM reserve harnesses require financial settlement probes")
            if (
                self.capability_policy is None
                or self.capability_policy.oracle_influence
                is not OracleInfluenceCapability.FIXTURE_CONFIGURED
                or self.capability_policy.flash_liquidity_wei != 0
            ):
                raise ValueError(
                    "AMM reserve harnesses require fixture-configured reserve influence "
                    "without temporary borrowing"
                )
            if self.depth != 1 or len(self.actions) != 1:
                raise ValueError("AMM reserve harnesses require exactly one bounded action")
        if self.economic_template is EconomicSimulationKind.LIQUIDATION:
            if self.financial_settlement is None or self.lending_boundary is None:
                raise ValueError(
                    "liquidation harnesses require financial settlement and lending boundary probes"
                )
            if self.financial_settlement.action_id != self.lending_boundary.action_id:
                raise ValueError("liquidation settlement and boundary probes must share one action")
            if self.capability_policy is None:
                raise ValueError("liquidation harnesses require a declared caller policy")
            if self.depth != 1 or len(self.actions) != 1:
                raise ValueError("liquidation harnesses require exactly one bounded action")
        if self.economic_template is EconomicSimulationKind.SHARE_PRICE:
            if self.financial_settlement is None or self.share_price_boundary is None:
                raise ValueError(
                    "share-price harnesses require financial settlement and rate boundary probes"
                )
            if self.financial_settlement.action_id != self.share_price_boundary.action_id:
                raise ValueError("share-price settlement and boundary probes must share one action")
            if self.capability_policy is None:
                raise ValueError("share-price harnesses require a declared caller policy")
            if self.depth != 1 or len(self.actions) != 1:
                raise ValueError("share-price harnesses require exactly one bounded action")
        if self.economic_template is EconomicSimulationKind.GOVERNANCE_RACE:
            if self.capability_policy is None or not self.capability_policy.governance_rights:
                raise ValueError(
                    "governance harnesses require explicitly declared governance rights"
                )
            controlled = set(self.capability_policy.attacker_controlled_actors)
            used_actors = {
                *(call.actor for call in self.setup_calls),
                *(actor for action in self.actions for actor in action.actor_names),
            }
            if not used_actors <= controlled:
                raise ValueError(
                    "governance harness calls must use only declared governance actors"
                )
        if self.economic_template is EconomicSimulationKind.CROSS_CHAIN_REPLAY:
            if (
                self.capability_policy is None
                or self.capability_policy.cross_chain_messages is CrossChainMessageCapability.NONE
            ):
                raise ValueError(
                    "cross-chain harnesses require an explicitly declared message capability"
                )
            controlled = set(self.capability_policy.attacker_controlled_actors)
            used_actors = {
                *(call.actor for call in self.setup_calls),
                *(actor for action in self.actions for actor in action.actor_names),
            }
            if not used_actors <= controlled:
                raise ValueError(
                    "cross-chain harness calls must use only declared synthetic message actors"
                )
        if self.economic_template is EconomicSimulationKind.CALLBACK_REENTRANCY:
            if self.capability_policy is None or not (
                self.capability_policy.attacker_controlled_contracts
            ):
                raise ValueError(
                    "callback harnesses require an explicitly declared controlled receiver"
                )
            controlled = set(self.capability_policy.attacker_controlled_actors)
            used_actors = {
                *(call.actor for call in self.setup_calls),
                *(actor for action in self.actions for actor in action.actor_names),
            }
            if not used_actors <= controlled:
                raise ValueError(
                    "callback harness calls must use only declared callback-trigger actors"
                )
        if self.economic_template is EconomicSimulationKind.BOUNDED_STATE_GROWTH:
            if self.depth != 1 or self.runs > 8:
                raise ValueError(
                    "state-growth harnesses require at most 8 runs and exactly one action depth"
                )
            if len(self.setup_calls) > 16 or len(self.actions) != 1:
                raise ValueError(
                    "state-growth harnesses require one bounded action and at most 16 setup calls"
                )
            if not any(
                property_spec.right is not None
                and property_spec.right.function_signature == "growthThreshold()"
                for property_spec in self.properties
            ):
                raise ValueError(
                    "state-growth harnesses require a source-exposed growthThreshold() probe"
                )
        return self


def _financial_probe_targets(
    settlement: FinancialSettlementProbeSpec,
) -> set[str]:
    return {
        *((settlement.asset_target,) if settlement.asset_target is not None else ()),
        settlement.starting_assets.target,
        settlement.borrowed_assets.target,
        settlement.repaid_assets.target,
        settlement.gross_assets_received.target,
        settlement.fees_paid.target,
        settlement.slippage_loss.target,
        settlement.ending_assets.target,
        settlement.net_impact.target,
    }


def _lending_probe_targets(
    boundary: LendingBoundaryProbeSpec,
) -> set[str]:
    return {
        boundary.debt_before.target,
        boundary.collateral_before.target,
        boundary.debt_after.target,
        boundary.collateral_after.target,
        boundary.collateral_seized.target,
        boundary.bad_debt_after.target,
    }


def _share_price_probe_targets(
    boundary: SharePriceBoundaryProbeSpec,
) -> set[str]:
    return {
        boundary.rate_scale.target,
        boundary.total_assets_before.target,
        boundary.total_shares_before.target,
        boundary.legitimate_yield.target,
        boundary.expected_rate_after_yield.target,
        boundary.observed_rate_after.target,
        boundary.shares_redeemed.target,
        boundary.assets_redeemed.target,
        boundary.excess_assets.target,
    }


class PropertyFuzzInputBound(StrictModel):
    """One engine-neutral fuzz slot and its stable campaign bounds."""

    slot: int = Field(ge=0, le=7)
    kind: ForkArgumentKind
    minimum: int | None = Field(default=None, ge=0, le=2**256 - 1)
    maximum: int | None = Field(default=None, ge=0, le=2**256 - 1)
    sources: list[str] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def bound_shape_matches_kind(self) -> PropertyFuzzInputBound:
        if self.kind is ForkArgumentKind.UINT256:
            if self.minimum is None or self.maximum is None:
                raise ValueError("uint256 property fuzz bounds require minimum and maximum")
            if self.maximum < self.minimum:
                raise ValueError("property fuzz maximum must not precede minimum")
        elif self.kind is ForkArgumentKind.ADDRESS:
            if self.minimum is not None or self.maximum is not None:
                raise ValueError("address property fuzz slots cannot declare numeric bounds")
        else:
            raise ValueError("property corpus supports only uint256 and address fuzz slots")
        if self.sources != sorted(set(self.sources)):
            raise ValueError("property fuzz-bound sources must be unique and sorted")
        return self


class PropertyCampaignBounds(StrictModel):
    """Deterministic limits shared by every dynamic-engine translation."""

    seed: int = Field(ge=0, le=2**256 - 1)
    runs: int = Field(ge=1, le=100_000)
    depth: int = Field(ge=1, le=10_000)
    fuzz_inputs: list[PropertyFuzzInputBound] = Field(default_factory=list, max_length=8)
    maximum_time_shift_seconds: int = Field(default=0, ge=0, le=31_536_000)
    maximum_call_value_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    maximum_actor_initial_balance_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    maximum_token_seed_amount: int = Field(default=0, ge=0, le=2**256 - 1)
    transaction_ordering: TransactionOrderingCapability = TransactionOrderingCapability.NONE

    @model_validator(mode="after")
    def fuzz_slots_are_unique_and_sorted(self) -> PropertyCampaignBounds:
        slots = [item.slot for item in self.fuzz_inputs]
        if slots != sorted(set(slots)):
            raise ValueError("property fuzz slots must be unique and sorted")
        return self


class PropertySourceEvidence(StrictModel):
    """Exact source lineage retained by an engine-neutral property."""

    entity_id: str = Field(min_length=1, max_length=1_000)
    location: Location
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    transformation: str = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def location_retains_exact_source_hash(self) -> PropertySourceEvidence:
        if self.location.content_hash is None:
            raise ValueError("property source evidence requires a content hash")
        if not re.fullmatch(r"[0-9a-f]{64}", self.location.content_hash):
            raise ValueError("property source evidence requires a SHA-256 content hash")
        if self.provenance is SolidityProvenance.FALLBACK and self.confidence >= 0.8:
            raise ValueError("fallback property evidence confidence must remain below 0.8")
        return self


class DynamicPropertySpec(StrictModel):
    """One shared property with enough typed context for deterministic translation."""

    id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    invariant_id: str = Field(min_length=1, max_length=160)
    harness_name: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
    property_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=8_000)
    category: InvariantCategory
    template: InvariantTemplate | None = None
    predicate: InvariantPropertySpec
    actors: list[ForkActor] = Field(min_length=1, max_length=16)
    setup_calls: list[ForkCallStep] = Field(default_factory=list, max_length=32)
    token_balance_seeds: list[TokenBalanceSeed] = Field(default_factory=list, max_length=16)
    actions: list[StatefulActionSpec] = Field(default_factory=list, max_length=32)
    target_aliases: list[str] = Field(min_length=1, max_length=64)
    source_evidence: list[PropertySourceEvidence] = Field(min_length=1, max_length=100)
    covered_entity_ids: list[str] = Field(min_length=1, max_length=100)
    covered_functions: list[str] = Field(default_factory=list, max_length=100)
    covered_state_variables: list[str] = Field(default_factory=list, max_length=100)
    assumptions: list[str] = Field(default_factory=list, max_length=100)
    provenance: SolidityProvenance
    confidence: float = Field(ge=0, le=1)
    analysis_state: AnalysisState
    campaign: PropertyCampaignBounds
    capability_policy: AttackerCapabilityPolicy | None = None
    invariant_evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    property_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @staticmethod
    def calculate_hash(payload: dict[str, Any]) -> str:
        """Hash the JSON-safe property payload excluding its derived identifiers."""

        canonical = {
            key: value for key, value in payload.items() if key not in {"id", "property_hash"}
        }
        return hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    @model_validator(mode="after")
    def shared_property_is_self_consistent(self) -> DynamicPropertySpec:
        expected_hash = self.calculate_hash(self.model_dump(mode="json"))
        if self.property_hash != expected_hash:
            raise ValueError("property hash does not match its typed contents")
        if self.id != f"prop-{self.property_hash[:24]}":
            raise ValueError("property ID must be derived from property_hash")
        if self.property_id != self.predicate.property_id:
            raise ValueError("property_id must match the typed predicate")
        evidence_ids = [item.entity_id for item in self.source_evidence]
        if evidence_ids != sorted(set(evidence_ids)):
            raise ValueError("property source evidence must be unique and sorted by entity ID")
        if self.covered_entity_ids != evidence_ids:
            raise ValueError("covered entity IDs must exactly match source-evidence entity IDs")
        for values, label in (
            (self.target_aliases, "target aliases"),
            (self.covered_functions, "covered functions"),
            (self.covered_state_variables, "covered state variables"),
            (self.assumptions, "property assumptions"),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"{label} must be unique and sorted")
        if self.confidence > min(item.confidence for item in self.source_evidence):
            raise ValueError("property confidence cannot exceed its source evidence")
        if self.provenance is SolidityProvenance.MODEL_SUGGESTED:
            raise ValueError("model-suggested hypotheses cannot enter the executable corpus")
        if self.analysis_state not in {
            AnalysisState.DETERMINISTIC,
            AnalysisState.FALLBACK_PARSER,
        }:
            raise ValueError("executable properties require deterministic or fallback analysis")
        return self


class PropertyCorpus(StrictModel):
    """Deterministically ordered property input shared by dynamic engines."""

    schema_version: Literal["1.0"] = "1.0"
    properties: list[DynamicPropertySpec] = Field(default_factory=list, max_length=10_000)
    limitations: list[str] = Field(default_factory=list, max_length=10_000)
    corpus_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def corpus_is_stable_and_hash_linked(self) -> PropertyCorpus:
        identifiers = [item.id for item in self.properties]
        if identifiers != sorted(set(identifiers)):
            raise ValueError("property corpus entries must be unique and sorted by ID")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("property corpus limitations must be unique and sorted")
        payload = {
            "schema_version": self.schema_version,
            "property_hashes": [item.property_hash for item in self.properties],
            "limitations": self.limitations,
        }
        expected = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        if self.corpus_hash != expected:
            raise ValueError("property corpus hash does not match its ordered contents")
        return self


class InvariantExecutionAttemptEvidence(StrictModel):
    """Normalized evidence for one generated invariant campaign in a fresh copy."""

    attempt: int = Field(ge=1, le=10)
    status: InvariantExecutionStatus
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fresh_workspace: bool
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stdout_path: str = Field(min_length=1, max_length=500)
    stderr_path: str = Field(min_length=1, max_length=500)
    process_exit_code: int | None = None
    machine_output_validated: bool = False
    campaign_runs: int = Field(default=0, ge=0)
    campaign_calls: int = Field(default=0, ge=0)


class InvariantExecutionRemovalTrial(StrictModel):
    """One clean bounded campaign with a candidate sequence action removed."""

    removed_action_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,47}$")
    retained_action_ids: list[str] = Field(min_length=1, max_length=31)
    status: InvariantExecutionStatus
    replay_confirmed: bool
    seed: int = Field(ge=0, le=2**256 - 1)

    @model_validator(mode="after")
    def passing_trial_replays_cleanly(self) -> InvariantExecutionRemovalTrial:
        if self.status is not InvariantExecutionStatus.PASSED or not self.replay_confirmed:
            raise ValueError("minimization removal trials must pass on clean replay")
        return self


class InvariantExecutionMinimizationEvidence(StrictModel):
    """Bounded proof metadata for a minimized invariant action sequence."""

    original_action_ids: list[str] = Field(min_length=1, max_length=32)
    retained_action_ids: list[str] = Field(min_length=1, max_length=32)
    strategy: Literal[
        "single_action_trivial",
        "bounded_action_removal",
        "not_attempted",
    ]
    proven_minimal: bool
    foundry_original_sequence_length: int | None = Field(default=None, ge=1, le=10_000)
    foundry_shrunk_sequence_length: int | None = Field(default=None, ge=1, le=10_000)
    removal_trials: list[InvariantExecutionRemovalTrial] = Field(
        default_factory=list,
        max_length=32,
    )

    @model_validator(mode="after")
    def action_sets_are_consistent(self) -> InvariantExecutionMinimizationEvidence:
        if len(self.original_action_ids) != len(set(self.original_action_ids)):
            raise ValueError("original invariant action IDs must be unique")
        if len(self.retained_action_ids) != len(set(self.retained_action_ids)):
            raise ValueError("retained invariant action IDs must be unique")
        if not set(self.retained_action_ids) <= set(self.original_action_ids):
            raise ValueError("retained invariant actions must come from the original sequence")
        if self.strategy == "single_action_trivial" and (
            len(self.original_action_ids) != 1
            or self.retained_action_ids != self.original_action_ids
            or not self.proven_minimal
            or self.removal_trials
        ):
            raise ValueError("single-action invariant minimization evidence is inconsistent")
        if self.strategy == "bounded_action_removal":
            if (
                len(self.original_action_ids) < 2
                or self.retained_action_ids != self.original_action_ids
                or not self.proven_minimal
                or self.foundry_original_sequence_length is None
                or self.foundry_shrunk_sequence_length != len(self.retained_action_ids)
                or self.foundry_original_sequence_length < self.foundry_shrunk_sequence_length
            ):
                raise ValueError("bounded invariant minimization evidence is inconsistent")
            removed = [trial.removed_action_id for trial in self.removal_trials]
            if sorted(removed) != sorted(self.original_action_ids):
                raise ValueError("bounded minimization must remove every action exactly once")
            for trial in self.removal_trials:
                expected = [
                    action_id
                    for action_id in self.original_action_ids
                    if action_id != trial.removed_action_id
                ]
                if trial.retained_action_ids != expected:
                    raise ValueError("minimization trial retained sequence is inconsistent")
        if self.strategy == "not_attempted" and (self.proven_minimal or self.removal_trials):
            raise ValueError("unattempted invariant minimization cannot be proven")
        return self


class InvariantCampaignCoverage(StrictModel):
    """Separate observed function, state-property, and sequence campaign evidence."""

    declared_action_functions: list[str] = Field(default_factory=list, max_length=32)
    observed_action_functions: list[str] = Field(default_factory=list, max_length=32)
    declared_state_properties: list[str] = Field(default_factory=list, max_length=16)
    observed_state_properties: list[str] = Field(default_factory=list, max_length=16)
    sequence_depth_bound: int = Field(ge=1, le=10_000)
    observed_sequence_lengths: list[int] = Field(default_factory=list, max_length=32)
    minimized_sequence_action_ids: list[str] = Field(default_factory=list, max_length=32)
    attempts_consistent: bool
    observed_campaign_runs: int = Field(default=0, ge=0)
    observed_campaign_calls: int = Field(default=0, ge=0)

    @model_validator(mode="after")
    def dimensions_are_separate_and_consistent(self) -> InvariantCampaignCoverage:
        for values in (
            self.declared_action_functions,
            self.observed_action_functions,
            self.declared_state_properties,
            self.observed_state_properties,
        ):
            if values != sorted(set(values)):
                raise ValueError("campaign coverage dimensions must be unique and sorted")
        if self.observed_sequence_lengths != sorted(set(self.observed_sequence_lengths)):
            raise ValueError("campaign coverage dimensions must be unique and sorted")
        if not set(self.observed_action_functions) <= set(self.declared_action_functions):
            raise ValueError("observed action functions must be declared by the harness")
        if not set(self.observed_state_properties) <= set(self.declared_state_properties):
            raise ValueError("observed state properties must be declared by the harness")
        if any(
            length < 1 or length > self.sequence_depth_bound
            for length in self.observed_sequence_lengths
        ):
            raise ValueError("observed sequence lengths must respect the campaign depth")
        if self.minimized_sequence_action_ids and (
            len(self.minimized_sequence_action_ids) not in self.observed_sequence_lengths
        ):
            raise ValueError("minimized sequence length requires observed sequence evidence")
        return self


class InvariantExecutionResult(StrictModel):
    invariant_id: str
    harness_name: str
    harness_spec_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: InvariantExecutionStatus
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_sha256: str | None = None
    compiler_version: str | None = Field(default=None, min_length=1, max_length=1_000)
    compiler_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    command: list[str] = Field(default_factory=list)
    runs: int = Field(default=0, ge=0)
    depth: int = Field(default=0, ge=0)
    seed: int = Field(default=0, ge=0)
    economic_template: EconomicSimulationKind | None = None
    required_transaction_ordering: TransactionOrderingCapability = (
        TransactionOrderingCapability.NONE
    )
    capability_policy: AttackerCapabilityPolicy | None = None
    economic_metrics: EconomicMetrics | None = None
    attempts: int = Field(default=0, ge=0, le=10)
    successful_attempts: int = Field(default=0, ge=0, le=10)
    replay_confirmed: bool = False
    attempt_evidence: list[InvariantExecutionAttemptEvidence] = Field(
        default_factory=list,
        max_length=10,
    )
    minimization_evidence: InvariantExecutionMinimizationEvidence | None = None
    campaign_coverage: InvariantCampaignCoverage | None = None
    duration_seconds: float = Field(default=0, ge=0)
    limitations: list[str] = Field(default_factory=list)
    counterexample_summary: str | None = None
    source_path: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    isolation_backend: str | None = None
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    execution_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    def expected_execution_observation_sha256(self) -> str:
        """Bind the normalized campaign result to every retained execution attempt."""

        payload = {
            "invariant_id": self.invariant_id,
            "harness_name": self.harness_name,
            "harness_spec_sha256": self.harness_spec_sha256,
            "status": self.status.value,
            "execution_evidence": self.execution_evidence.value,
            "executable_sha256": self.executable_sha256,
            "source_sha256": self.source_sha256,
            "compiler_version": self.compiler_version,
            "compiler_sha256": self.compiler_sha256,
            "command": self.command,
            "runs": self.runs,
            "depth": self.depth,
            "seed": self.seed,
            "economic_template": (
                self.economic_template.value if self.economic_template is not None else None
            ),
            "required_transaction_ordering": self.required_transaction_ordering.value,
            "capability_policy": (
                self.capability_policy.model_dump(mode="json")
                if self.capability_policy is not None
                else None
            ),
            "economic_metrics": (
                self.economic_metrics.model_dump(mode="json")
                if self.economic_metrics is not None
                else None
            ),
            "attempts": self.attempts,
            "successful_attempts": self.successful_attempts,
            "replay_confirmed": self.replay_confirmed,
            "attempt_evidence": [item.model_dump(mode="json") for item in self.attempt_evidence],
            "minimization_evidence": (
                self.minimization_evidence.model_dump(mode="json")
                if self.minimization_evidence is not None
                else None
            ),
            "campaign_coverage": (
                self.campaign_coverage.model_dump(mode="json")
                if self.campaign_coverage is not None
                else None
            ),
            "limitations": self.limitations,
            "counterexample_summary": self.counterexample_summary,
            "source_path": self.source_path,
            "stdout_path": self.stdout_path,
            "stderr_path": self.stderr_path,
            "isolation_backend": self.isolation_backend,
            "isolation_attestation_sha256": self.isolation_attestation_sha256,
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @model_validator(mode="after")
    def replay_and_minimization_are_consistent(self) -> InvariantExecutionResult:
        if self.attempts != len(self.attempt_evidence):
            raise ValueError("invariant attempt count must match attempt evidence")
        completed = {
            InvariantExecutionStatus.PASSED,
            InvariantExecutionStatus.COUNTEREXAMPLE,
        }
        successful = sum(item.status in completed for item in self.attempt_evidence)
        if self.successful_attempts != successful:
            raise ValueError("successful invariant attempt count does not match evidence")
        if self.replay_confirmed:
            if self.attempts < 2 or self.status not in completed:
                raise ValueError("confirmed invariant replay requires two completed attempts")
            if any(item.status is not self.status for item in self.attempt_evidence):
                raise ValueError("confirmed invariant replay requires identical attempt outcomes")
        if (
            self.minimization_evidence is not None
            and self.status is not InvariantExecutionStatus.COUNTEREXAMPLE
        ):
            raise ValueError("invariant minimization evidence requires a counterexample")
        if (
            self.execution_observation_sha256 is not None
            and self.execution_observation_sha256 != self.expected_execution_observation_sha256()
        ):
            raise ValueError("invariant execution observation hash does not match its fields")
        return self


class EconomicSimulationTemplate(StrictModel):
    kind: EconomicSimulationKind
    title: str
    protocol_profiles: list[str]
    required_fixtures: list[str]
    attacker_capabilities: list[str]
    preconditions: list[str]
    expected_invariant_violation: str
    bounded_parameters: dict[str, int]
    measured_outputs: list[str]


class EconomicSimulationPlan(StrictModel):
    kind: EconomicSimulationKind
    applicable: bool
    rationale: str
    invariant_ids: list[str] = Field(default_factory=list)
    source_locations: list[Location] = Field(default_factory=list)
    typed_harness_available: bool = False
    execution_required: bool = False
    required_transaction_ordering: TransactionOrderingCapability = (
        TransactionOrderingCapability.NONE
    )
    limitations: list[str] = Field(default_factory=list)


class EconomicMetrics(StrictModel):
    required_initial_capital: int | None = Field(default=None, ge=0)
    borrowed_capital: int | None = Field(default=None, ge=0)
    gross_extraction: int | None = Field(default=None, ge=0)
    fees: int | None = Field(default=None, ge=0)
    gas_used: int | None = Field(default=None, ge=0)
    net_profit_or_loss: int | None = None
    maximum_victim_loss: int | None = Field(default=None, ge=0)
    protocol_insolvency: int | None = Field(default=None, ge=0)
    repeatable: bool | None = None
    resource_threshold: int | None = Field(default=None, ge=1)
    bounded_actions: int | None = Field(default=None, ge=1)
    required_privileges: list[str] = Field(default_factory=list)
    market_assumptions: list[str] = Field(default_factory=list)
    financial_settlement: FinancialSettlementEvidence | None = None
    lending_boundary: LendingBoundaryEvidence | None = None
    share_price_boundary: SharePriceBoundaryEvidence | None = None


class FormalEvidence(StrictModel):
    tool: str
    property_id: str
    property_description: str
    status: FormalToolStatus
    result_kind: FormalResultKind
    assumptions: list[str] = Field(default_factory=list)
    path_constraints: list[str] = Field(default_factory=list)
    counterexample: dict[str, Any] = Field(default_factory=dict)
    locations: list[Location] = Field(default_factory=list)
    confidence: float = Field(default=0, ge=0, le=1)
    artifact_paths: list[str] = Field(default_factory=list)


class FormalDependencyProvenance(StrictModel):
    """One exact executable dependency used by a formal engine."""

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    version: str | None = Field(default=None, max_length=200)
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FormalCampaignBounds(StrictModel):
    """Configured campaign limits; these are not runtime observations."""

    runs: int = Field(ge=1)
    depth: int = Field(ge=1)


class FormalCampaignObservation(StrictModel):
    """Campaign statistics explicitly emitted by validated engine output."""

    runs: int | None = Field(default=None, ge=0)
    calls: int | None = Field(default=None, ge=0)
    depth: int | None = Field(default=None, ge=0)
    iterations: int | None = Field(default=None, ge=0)
    paths: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def at_least_one_statistic_was_observed(self) -> FormalCampaignObservation:
        if all(
            value is None
            for value in (self.runs, self.calls, self.depth, self.iterations, self.paths)
        ):
            raise ValueError("formal campaign observation requires an emitted statistic")
        return self


class FormalPropertyBinding(StrictModel):
    """Typed identity link from one generated engine property to the shared corpus."""

    generated_property_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
    corpus_property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    property_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def corpus_identifier_matches_property_hash(self) -> FormalPropertyBinding:
        if self.corpus_property_id != f"prop-{self.property_hash[:24]}":
            raise ValueError("formal property binding ID must derive from its property hash")
        return self


class FormalToolRun(StrictModel):
    tool: str
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    version: str | None = None
    executable_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    isolation_backend: str | None = None
    isolation_attestation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    dependencies: list[FormalDependencyProvenance] = Field(default_factory=list)
    status: FormalToolStatus
    command: list[str] = Field(default_factory=list)
    duration_seconds: float = Field(default=0, ge=0)
    evidence: list[FormalEvidence] = Field(default_factory=list)
    coverage: dict[str, Any] = Field(default_factory=dict)
    property_corpus_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    property_corpus_property_ids: list[str] = Field(default_factory=list)
    translated_property_bindings: list[FormalPropertyBinding] = Field(default_factory=list)
    campaign_seed: int | None = Field(default=None, ge=0, le=2**256 - 1)
    configured_campaign: FormalCampaignBounds | None = None
    observed_campaign: FormalCampaignObservation | None = None
    translated_properties: int = Field(default=0, ge=0)
    executed_property_ids: list[str] = Field(default_factory=list)
    observed_property_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    translation_limitations: list[str] = Field(default_factory=list)
    specification_artifacts: list[str] = Field(default_factory=list)
    assumption_artifacts: list[str] = Field(default_factory=list)
    vacuity_artifacts: list[str] = Field(default_factory=list)
    failure_reason: str | None = None
    stdout_path: str | None = None
    stderr_path: str | None = None
    result_path: str | None = None
    process_exit_code: int | None = None
    stdout_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    stdout_bytes: int = Field(default=0, ge=0)
    stderr_bytes: int = Field(default=0, ge=0)
    result_bytes: int = Field(default=0, ge=0)
    machine_output_validated: bool = False
    execution_observation_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )

    def expected_execution_observation_sha256(self) -> str:
        """Bind normalized outcomes and campaign coverage to retained process evidence."""

        payload = {
            "tool": self.tool,
            "execution_evidence": self.execution_evidence.value,
            "version": self.version,
            "executable_sha256": self.executable_sha256,
            "isolation_backend": self.isolation_backend,
            "isolation_attestation_sha256": self.isolation_attestation_sha256,
            "dependencies": [
                dependency.model_dump(mode="json") for dependency in self.dependencies
            ],
            "status": self.status.value,
            "command": self.command,
            "process_exit_code": self.process_exit_code,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "result_sha256": self.result_sha256,
            "stdout_bytes": self.stdout_bytes,
            "stderr_bytes": self.stderr_bytes,
            "result_bytes": self.result_bytes,
            "machine_output_validated": self.machine_output_validated,
            "property_corpus_hash": self.property_corpus_hash,
            "property_corpus_property_ids": self.property_corpus_property_ids,
            "translated_property_bindings": [
                binding.model_dump(mode="json") for binding in self.translated_property_bindings
            ],
            "campaign_seed": self.campaign_seed,
            "configured_campaign": (
                self.configured_campaign.model_dump(mode="json")
                if self.configured_campaign is not None
                else None
            ),
            "observed_campaign": (
                self.observed_campaign.model_dump(mode="json")
                if self.observed_campaign is not None
                else None
            ),
            "translated_properties": self.translated_properties,
            "executed_property_ids": self.executed_property_ids,
            "observed_property_ids": self.observed_property_ids,
            "evidence": [item.model_dump(mode="json") for item in self.evidence],
            "coverage": self.coverage,
            "assumptions": self.assumptions,
            "translation_limitations": self.translation_limitations,
            "specification_artifacts": self.specification_artifacts,
            "assumption_artifacts": self.assumption_artifacts,
            "vacuity_artifacts": self.vacuity_artifacts,
            "failure_reason": self.failure_reason,
        }
        return hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @model_validator(mode="after")
    def translated_run_retains_corpus_identity(self) -> FormalToolRun:
        if self.translated_properties and self.property_corpus_hash is None:
            raise ValueError("translated formal runs require a corpus hash")
        if self.property_corpus_property_ids != sorted(set(self.property_corpus_property_ids)):
            raise ValueError("formal corpus property IDs must be unique and sorted")
        if any(
            re.fullmatch(r"prop-[0-9a-f]{24}", property_id) is None
            for property_id in self.property_corpus_property_ids
        ):
            raise ValueError("formal corpus property IDs must be canonical")
        if self.property_corpus_hash is None and self.property_corpus_property_ids:
            raise ValueError("formal corpus property IDs require a corpus hash")
        generated_property_ids = [
            binding.generated_property_id for binding in self.translated_property_bindings
        ]
        if generated_property_ids != sorted(set(generated_property_ids)):
            raise ValueError("formal property bindings must be unique and sorted")
        bound_corpus_ids = [
            binding.corpus_property_id for binding in self.translated_property_bindings
        ]
        if len(bound_corpus_ids) != len(set(bound_corpus_ids)):
            raise ValueError("formal property bindings must not duplicate corpus property IDs")
        if not set(bound_corpus_ids) <= set(self.property_corpus_property_ids):
            raise ValueError("formal property bindings must reference the recorded corpus")
        if self.translated_property_bindings and (
            len(self.translated_property_bindings) != self.translated_properties
            or sorted(bound_corpus_ids) != self.executed_property_ids
        ):
            raise ValueError("formal property bindings must exactly identify translated properties")
        if self.execution_observation_sha256 is not None and self.translated_properties:
            if not self.property_corpus_property_ids:
                raise ValueError("observed translated runs require complete corpus property IDs")
            if len(self.translated_property_bindings) != self.translated_properties:
                raise ValueError("observed translated runs require typed property bindings")
        if (
            self.translated_properties
            and self.tool in {"echidna", "medusa"}
            and self.campaign_seed is None
        ):
            raise ValueError("translated fuzz-engine runs require a campaign seed")
        dependency_names = [dependency.name for dependency in self.dependencies]
        if dependency_names != sorted(set(dependency_names)):
            raise ValueError("formal dependencies must be unique and sorted by name")
        if self.assumptions != sorted(set(self.assumptions)):
            raise ValueError("formal assumptions must be unique and sorted")
        if self.translation_limitations != sorted(set(self.translation_limitations)):
            raise ValueError("formal translation limitations must be unique and sorted")
        for artifacts in (
            self.specification_artifacts,
            self.assumption_artifacts,
            self.vacuity_artifacts,
        ):
            if artifacts != sorted(set(artifacts)):
                raise ValueError("formal artifact paths must be unique and sorted")
            for path in artifacts:
                normalized = path.removeprefix("workspace/")
                if (
                    not normalized
                    or normalized.startswith(("/", "-"))
                    or "\\" in normalized
                    or any(part in {"", ".", ".."} for part in normalized.split("/"))
                ):
                    raise ValueError("formal artifact paths must be normalized")
        if self.executed_property_ids != sorted(set(self.executed_property_ids)):
            raise ValueError("executed formal property IDs must be unique and sorted")
        if any(
            re.fullmatch(r"prop-[0-9a-f]{24}", property_id) is None
            for property_id in self.executed_property_ids
        ):
            raise ValueError("executed formal property IDs must be canonical")
        if len(self.executed_property_ids) != self.translated_properties:
            raise ValueError("executed property IDs must match the translated property count")
        if self.observed_property_ids != sorted(set(self.observed_property_ids)):
            raise ValueError("observed formal property IDs must be unique and sorted")
        if any(
            re.fullmatch(r"prop-[0-9a-f]{24}", property_id) is None
            for property_id in self.observed_property_ids
        ):
            raise ValueError("observed formal property IDs must be canonical")
        if not set(self.observed_property_ids) <= set(self.executed_property_ids):
            raise ValueError("observed formal property IDs must have been translated")
        if (
            self.execution_observation_sha256 is not None
            and self.execution_observation_sha256 != self.expected_execution_observation_sha256()
        ):
            raise ValueError("formal execution observation hash does not match its fields")
        return self


class DynamicEngineComparison(StrictModel):
    property_id: str = Field(pattern=r"^prop-[0-9a-f]{24}$")
    outcomes: dict[str, DynamicPropertyOutcome] = Field(min_length=1)
    disagreement: bool

    @model_validator(mode="after")
    def comparison_is_deterministic(self) -> DynamicEngineComparison:
        if list(self.outcomes) != sorted(set(self.outcomes)):
            raise ValueError("dynamic engine outcomes must be unique and sorted by engine")
        if self.disagreement != (len(set(self.outcomes.values())) > 1):
            raise ValueError("dynamic engine disagreement must match the recorded outcomes")
        return self


class CoverageExclusion(StrictModel):
    """One explicitly evidenced member removed from a coverage denominator."""

    subject: str = Field(min_length=1, max_length=500)
    reason: str = Field(min_length=1, max_length=1_000)
    provenance: CoverageProvenance


class CoverageMetric(StrictModel):
    """One independently auditable coverage dimension; never a context-free score."""

    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    population: int = Field(ge=0)
    percentage: float | None = Field(default=None, ge=0, le=100)
    exclusions: list[CoverageExclusion]
    not_applicable_evidence: list[str]
    confidence: float = Field(ge=0, le=1)
    provenance: list[CoverageProvenance] = Field(min_length=1)
    failures: list[str]
    state: AnalysisState
    detail: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def ratio_is_consistent(self) -> CoverageMetric:
        if self.numerator > self.denominator:
            raise ValueError("coverage numerator cannot exceed denominator")
        if self.population != self.denominator + len(self.exclusions):
            raise ValueError("coverage population must equal denominator plus explicit exclusions")
        expected = round((self.numerator / self.denominator) * 100, 4) if self.denominator else None
        if self.percentage != expected:
            raise ValueError("coverage percentage must match its numerator and denominator")
        exclusion_subjects = [exclusion.subject for exclusion in self.exclusions]
        if len(exclusion_subjects) != len(set(exclusion_subjects)):
            raise ValueError("coverage exclusions must identify distinct population members")
        if len(self.provenance) != len(set(self.provenance)):
            raise ValueError("coverage provenance entries must be unique")
        if self.denominator:
            if self.not_applicable_evidence:
                raise ValueError("not-applicable evidence is only valid for an empty denominator")
            if self.numerator < self.denominator and not self.failures:
                raise ValueError("incomplete coverage requires explicit failure evidence")
        elif bool(self.not_applicable_evidence) == bool(self.failures):
            raise ValueError(
                "an empty coverage denominator requires exactly one of "
                "not-applicable evidence or failure evidence"
            )
        return self


class ModelReviewEvidenceReference(StrictModel):
    """One normalized decision about whether a response record earns surface credit."""

    surface_id: str = Field(pattern=r"^model-surface:[0-9a-f]{64}$")
    request_id: str = Field(min_length=1, max_length=500)
    artifact_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_model: str | None = Field(default=None, pattern=r"^[^\s/]+/[^\s/]+$")
    model: str | None = Field(default=None, pattern=r"^[^\s/]+/[^\s/]+$")
    review_role: str = Field(pattern=r"^[a-z][a-z0-9_:.-]{0,127}$")
    status: ModelSurfaceReviewStatus
    root_lineage: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    credited: bool
    reason: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def credited_reference_is_substantive_and_registered(
        self,
    ) -> ModelReviewEvidenceReference:
        if self.credited and self.status not in {
            ModelSurfaceReviewStatus.CANDIDATE,
            ModelSurfaceReviewStatus.REVIEWED_NO_ISSUE,
        }:
            raise ValueError("only candidate or reviewed-no-issue records may earn review credit")
        if self.credited and (
            self.requested_model is None or self.model is None or self.root_lineage is None
        ):
            raise ValueError("credited model-review evidence requires exact model and lineage")
        return self


class ModelReviewSurface(StrictModel):
    """One deterministic surface and its explicit model-authored review evidence."""

    surface_id: str = Field(pattern=r"^model-surface:[0-9a-f]{64}$")
    kind: ModelReviewSurfaceKind
    subject_id: str = Field(min_length=1, max_length=500)
    label: str = Field(min_length=1, max_length=500)
    critical: bool
    locations: list[Location] = Field(default_factory=list, max_length=100)
    reviewer_roles: list[str] = Field(default_factory=list, max_length=100)
    root_lineages: list[str] = Field(default_factory=list, max_length=100)
    reviewed: bool = False
    evidence_references: list[ModelReviewEvidenceReference] = Field(
        default_factory=list,
        max_length=10_000,
    )

    @model_validator(mode="before")
    @classmethod
    def derive_review_summary_from_credited_references(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        references = [
            ModelReviewEvidenceReference.model_validate(item)
            for item in value.get("evidence_references", [])
        ]
        credited = [reference for reference in references if reference.credited]
        derived_roles = sorted({reference.review_role for reference in credited})
        derived_lineages = sorted(
            {reference.root_lineage for reference in credited if reference.root_lineage is not None}
        )
        derived_reviewed = bool(credited)
        for field, derived in (
            ("reviewer_roles", derived_roles),
            ("root_lineages", derived_lineages),
            ("reviewed", derived_reviewed),
        ):
            if field in value and value[field] != derived:
                raise ValueError(f"{field} must be derived from credited evidence references")
        return {
            **value,
            "reviewer_roles": derived_roles,
            "root_lineages": derived_lineages,
            "reviewed": derived_reviewed,
        }

    @model_validator(mode="after")
    def review_evidence_is_normalized(self) -> ModelReviewSurface:
        if self.reviewer_roles != sorted(set(self.reviewer_roles)):
            raise ValueError("model-review roles must be unique and sorted")
        if self.root_lineages != sorted(set(self.root_lineages)):
            raise ValueError("model-review root lineages must be unique and sorted")
        if any(re.fullmatch(r"sha256:[0-9a-f]{64}", item) is None for item in self.root_lineages):
            raise ValueError("model-review root lineages must be immutable sha256 identifiers")
        if self.locations != sorted(
            self.locations,
            key=lambda item: (
                item.path,
                item.start_line,
                item.end_line,
                item.symbol or "",
                item.content_hash or "",
            ),
        ):
            raise ValueError("model-review locations must be sorted")
        evidence_keys = [
            (
                item.request_id,
                item.artifact_sha256,
                item.surface_id,
                item.review_role,
                item.status.value,
            )
            for item in self.evidence_references
        ]
        if evidence_keys != sorted(set(evidence_keys)):
            raise ValueError("model-review evidence references must be unique and sorted")
        if any(item.surface_id != self.surface_id for item in self.evidence_references):
            raise ValueError("model-review evidence references must identify their surface")
        if self.reviewed != bool(self.reviewer_roles and self.root_lineages):
            raise ValueError("reviewed must require both a successful role and registered lineage")
        return self


class ModelReviewCoverage(StrictModel):
    """Per-surface response evidence with an independent critical-surface gate."""

    schema_version: Literal["1.0"] = "1.0"
    applicable: bool
    minimum_critical_root_lineages: int = Field(default=3, ge=2, le=16)
    surfaces: list[ModelReviewSurface] = Field(default_factory=list)
    overall: CoverageMetric
    by_kind: dict[ModelReviewSurfaceKind, CoverageMetric]
    critical: CoverageMetric
    critical_gate_passed: bool
    limitations: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def surface_metrics_are_consistent(self) -> ModelReviewCoverage:
        if self.surfaces != sorted(self.surfaces, key=lambda item: item.surface_id):
            raise ValueError("model-review surfaces must be sorted by stable ID")
        surface_ids = [surface.surface_id for surface in self.surfaces]
        if len(surface_ids) != len(set(surface_ids)):
            raise ValueError("model-review surface IDs must be unique")
        if set(self.by_kind) != set(ModelReviewSurfaceKind):
            raise ValueError("model-review coverage must include every surface kind")
        reviewed = sum(surface.reviewed for surface in self.surfaces)
        if (self.overall.numerator, self.overall.denominator) != (
            reviewed,
            len(self.surfaces),
        ):
            raise ValueError("overall model-review numerator/denominator do not match surfaces")
        for kind in ModelReviewSurfaceKind:
            kind_surfaces = [surface for surface in self.surfaces if surface.kind is kind]
            metric = self.by_kind[kind]
            if (metric.numerator, metric.denominator) != (
                sum(surface.reviewed for surface in kind_surfaces),
                len(kind_surfaces),
            ):
                raise ValueError(f"{kind.value} model-review metric does not match surfaces")
        critical_surfaces = [surface for surface in self.surfaces if surface.critical]
        critical_reviewed = sum(
            surface.reviewed and len(surface.root_lineages) >= self.minimum_critical_root_lineages
            for surface in critical_surfaces
        )
        if (self.critical.numerator, self.critical.denominator) != (
            critical_reviewed,
            len(critical_surfaces),
        ):
            raise ValueError("critical model-review metric does not match surfaces")
        expected_gate = self.critical.numerator == self.critical.denominator
        if self.critical_gate_passed != expected_gate:
            raise ValueError("critical model-review gate does not match per-surface evidence")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("model-review limitations must be unique and sorted")
        return self


class EconomicTemplateExecutionCoverage(StrictModel):
    """Per-template generated-harness lifecycle evidence."""

    kind: EconomicSimulationKind
    applicable: bool
    execution_required: bool
    typed_harness_available: bool
    harnesses_generated: int = Field(ge=0)
    harnesses_compiled: int = Field(ge=0)
    harnesses_executed: int = Field(ge=0)
    harnesses_replayed: int = Field(ge=0)
    counterexamples: int = Field(ge=0)
    counterexamples_minimized: int = Field(ge=0)
    statuses: dict[InvariantExecutionStatus, int] = Field(default_factory=dict)
    source_sha256s: list[str] = Field(default_factory=list)
    compiler_sha256s: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def lifecycle_counts_are_consistent(self) -> EconomicTemplateExecutionCoverage:
        if sum(self.statuses.values()) != self.harnesses_generated:
            raise ValueError("economic template status counts must match generated harnesses")
        if any(count < 0 for count in self.statuses.values()):
            raise ValueError("economic template status counts must be non-negative")
        if not (
            self.harnesses_replayed
            <= self.harnesses_executed
            <= self.harnesses_compiled
            <= self.harnesses_generated
        ):
            raise ValueError("economic template lifecycle counts are not monotonic")
        if self.counterexamples > self.harnesses_executed:
            raise ValueError("economic counterexamples cannot exceed executed harnesses")
        if self.counterexamples_minimized > self.counterexamples:
            raise ValueError("minimized counterexamples cannot exceed counterexamples")
        if not self.applicable and self.harnesses_generated:
            raise ValueError("non-applicable economic templates cannot have generated harnesses")
        if not self.typed_harness_available and self.harnesses_generated:
            raise ValueError("generated economic harnesses require typed-harness availability")
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in self.source_sha256s):
            raise ValueError("economic template source hashes must be SHA-256 digests")
        if any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in self.compiler_sha256s):
            raise ValueError("economic template compiler hashes must be SHA-256 digests")
        if self.source_sha256s != sorted(set(self.source_sha256s)):
            raise ValueError("economic template source hashes must be unique and sorted")
        if self.compiler_sha256s != sorted(set(self.compiler_sha256s)):
            raise ValueError("economic template compiler hashes must be unique and sorted")
        if self.limitations != sorted(set(self.limitations)):
            raise ValueError("economic template limitations must be unique and sorted")
        return self


class SolidityCoverage(StrictModel):
    projects_discovered: int = 0
    project_types: list[str] = Field(default_factory=list)
    files_discovered: int = 0
    solidity_files_analyzed: int = 0
    contracts_indexed: int = 0
    functions_indexed: int = 0
    modifiers_indexed: int = 0
    state_variables_indexed: int = 0
    ast_backed_files: int = 0
    fallback_parser_files: int = 0
    graph_edge_counts: dict[str, int] = Field(default_factory=dict)
    graph_node_counts: dict[str, int] = Field(default_factory=dict)
    asset_flow_operation_counts: dict[str, int] = Field(default_factory=dict)
    asset_flow_direction_counts: dict[str, int] = Field(default_factory=dict)
    control_resolution_counts: dict[str, int] = Field(default_factory=dict)
    governance_stage_counts: dict[str, int] = Field(default_factory=dict)
    dependency_resolution_counts: dict[str, int] = Field(default_factory=dict)
    oracle_freshness_counts: dict[str, int] = Field(default_factory=dict)
    graph_analysis_state: AnalysisState = AnalysisState.NOT_ANALYZED
    invariants_discovered: int = 0
    executable_invariants: int = 0
    invariants_executed: int = 0
    invariant_campaign_functions_declared: int = 0
    invariant_campaign_functions_observed: int = 0
    invariant_campaign_state_properties_declared: int = 0
    invariant_campaign_state_properties_observed: int = 0
    invariant_counterexample_sequences_observed: int = 0
    invariant_counterexample_sequences_minimized: int = 0
    model_invariants_proposed: int = 0
    model_invariants_validated: int = 0
    economic_simulations_planned: int = 0
    economic_simulations_executed: int = 0
    economic_template_execution: dict[
        EconomicSimulationKind,
        EconomicTemplateExecutionCoverage,
    ] = Field(default_factory=dict)
    formal_tools_available: list[str] = Field(default_factory=list)
    formal_tools_unavailable: list[str] = Field(default_factory=list)
    formal_tools_failed: list[str] = Field(default_factory=list)
    functions_reviewed_by_models: int = 0
    functions_covered_by_static_tools: int = 0
    contracts_failed_compilation: list[str] = Field(default_factory=list)
    unsupported_files: list[str] = Field(default_factory=list)
    missing_dependencies: list[str] = Field(default_factory=list)
    unresolved_imports: list[str] = Field(default_factory=list)
    graph_warnings: list[str] = Field(default_factory=list)
    tools_executed: list[str] = Field(default_factory=list)
    tools_unavailable: list[str] = Field(default_factory=list)
    tools_failed: list[str] = Field(default_factory=list)
    tests_executed: int = 0
    tests_failed: int = 0
    reproduction_attempts: int = 0
    quality_metrics: dict[str, CoverageMetric] = Field(default_factory=dict)
    context_limitations: list[str] = Field(default_factory=list)
    excluded_paths: list[str] = Field(default_factory=list)
    project_configuration_assumptions: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def economic_template_keys_match_evidence(self) -> SolidityCoverage:
        if any(
            kind != evidence.kind for kind, evidence in self.economic_template_execution.items()
        ):
            raise ValueError("economic template coverage keys must match their evidence kind")
        return self


class SpecialistExecutionStatus(StrEnum):
    NOT_CONFIGURED = "not_configured"
    NOT_SCHEDULED = "not_scheduled"
    FAILED = "failed"
    PARTIAL = "partial"
    COMPLETED = "completed"


class ContextRequestRelationship(StrEnum):
    """Host-controlled relationship between one request role and its context role."""

    EXACT = "exact"
    EXPLOIT_TEST = "exploit_test"
    FALSIFIER_FALLBACK = "falsifier_fallback"
    CANDIDATE_CROSS_EXAMINATION = "candidate_cross_examination"
    WHOLE_PROTOCOL_INDEXED = "whole_protocol_indexed"


_BASE_CONTEXT_ROLE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SPECIALIST_CONTEXT_ROLE = re.compile(r"^specialist:[a-z][a-z0-9_]{0,63}$")
_CANDIDATE_FALSIFIER_REQUEST_ROLE = re.compile(r"^candidate_falsifier:[0-9a-f]{64}:reviewer_[12]$")
_WHOLE_PROTOCOL_INDEXED_REQUEST_ROLE = re.compile(r"^whole_protocol_review:(?:0|[1-9][0-9]{0,3})$")


def _context_request_relationship(
    request_role: str,
    context_role: str,
) -> ContextRequestRelationship:
    """Resolve only the request/context relationships emitted by host orchestration."""

    exact_context_role = bool(
        _BASE_CONTEXT_ROLE.fullmatch(context_role)
        or _SPECIALIST_CONTEXT_ROLE.fullmatch(context_role)
    )
    if request_role == context_role and exact_context_role:
        return ContextRequestRelationship.EXACT
    if exact_context_role and request_role == (
        f"{context_role}:exploit_test"
        if context_role.startswith("specialist:")
        else f"specialist:{context_role}:exploit_test"
    ):
        return ContextRequestRelationship.EXPLOIT_TEST
    if request_role == "falsifier" and context_role == "verifier":
        return ContextRequestRelationship.FALSIFIER_FALLBACK
    if (
        context_role == "candidate_cross_examination"
        and _CANDIDATE_FALSIFIER_REQUEST_ROLE.fullmatch(request_role)
    ):
        return ContextRequestRelationship.CANDIDATE_CROSS_EXAMINATION
    if context_role == "whole_protocol_review" and _WHOLE_PROTOCOL_INDEXED_REQUEST_ROLE.fullmatch(
        request_role
    ):
        return ContextRequestRelationship.WHOLE_PROTOCOL_INDEXED
    raise ValueError("request role is not valid for the supplied context-package role")


class ContextExecutionEvidence(StrictModel):
    """Exact bounded byte evidence for one materialized context package."""

    context_role: str = Field(min_length=1, max_length=200)
    byte_budget: StrictInt = Field(ge=0)
    declared_bytes_used: StrictInt = Field(ge=0)
    rendered_bytes: StrictInt = Field(ge=0)
    source_bytes: StrictInt = Field(ge=0)
    configured_maximum_source_tokens_per_request: StrictInt = Field(gt=0)
    effective_source_byte_ceiling: StrictInt = Field(ge=0)
    rendered_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def bytes_are_exact_and_bounded(self) -> ContextExecutionEvidence:
        if self.declared_bytes_used != self.rendered_bytes:
            raise ValueError("declared context bytes differ from its rendered UTF-8 bytes")
        if self.rendered_bytes > self.byte_budget:
            raise ValueError("rendered context bytes exceed the package budget")
        configured_source_bytes = min(
            2**31 - 1,
            self.configured_maximum_source_tokens_per_request * UTF8_BYTES_PER_ESTIMATED_TOKEN,
        )
        if self.effective_source_byte_ceiling > min(
            self.byte_budget,
            configured_source_bytes,
        ):
            raise ValueError("effective context source ceiling exceeds its governing limit")
        if self.source_bytes > self.effective_source_byte_ceiling:
            raise ValueError("context source bytes exceed the package source ceiling")
        return self

    def context_binding(self) -> tuple[str, int, int, int, int, int, int, str]:
        """Return every field that binds provider evidence to retained context bytes."""

        return (
            self.context_role,
            self.byte_budget,
            self.declared_bytes_used,
            self.rendered_bytes,
            self.source_bytes,
            self.configured_maximum_source_tokens_per_request,
            self.effective_source_byte_ceiling,
            self.rendered_sha256,
        )


class ContextRequestEvidence(ContextExecutionEvidence):
    """Self-hashed request-to-context binding retained with provider usage evidence."""

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1, max_length=200)
    request_role: str = Field(min_length=1, max_length=200)
    relationship: ContextRequestRelationship
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        request_role: str,
        context_role: str,
        byte_budget: int,
        declared_bytes_used: int,
        rendered_bytes: int,
        source_bytes: int,
        configured_maximum_source_tokens_per_request: int,
        effective_source_byte_ceiling: int,
        rendered_sha256: str,
    ) -> ContextRequestEvidence:
        relationship = _context_request_relationship(request_role, context_role)
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_id": request_id,
            "request_role": request_role,
            "context_role": context_role,
            "relationship": relationship.value,
            "byte_budget": byte_budget,
            "declared_bytes_used": declared_bytes_used,
            "rendered_bytes": rendered_bytes,
            "source_bytes": source_bytes,
            "configured_maximum_source_tokens_per_request": (
                configured_maximum_source_tokens_per_request
            ),
            "effective_source_byte_ceiling": effective_source_byte_ceiling,
            "rendered_sha256": rendered_sha256,
        }
        evidence_sha256 = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return cls.model_validate({**payload, "evidence_sha256": evidence_sha256})

    @model_validator(mode="after")
    def relationship_and_hash_are_exact(self) -> ContextRequestEvidence:
        expected_relationship = _context_request_relationship(
            self.request_role,
            self.context_role,
        )
        if self.relationship is not expected_relationship:
            raise ValueError("request/context relationship label is inconsistent")
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        expected_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if self.evidence_sha256 != expected_hash:
            raise ValueError("request/context evidence hash is inconsistent")
        return self


class SpecialistAcceptedOutcomeKind(StrEnum):
    """Host-validated specialist workflow result eligible for execution credit."""

    CANDIDATE_REVIEW = "candidate_review"
    INVARIANT_REVIEW = "invariant_review"
    TEST_GENERATION = "test_generation"
    FALSIFICATION = "falsification"
    REPORT_QUALITY = "report_quality"


class SpecialistAcceptedOutcome(StrictModel):
    """Self-hashed proof that host-side role validation accepted one response."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    request_id: str = Field(min_length=1, max_length=200)
    specialist_role: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    request_role: str = Field(min_length=1, max_length=200)
    outcome_kind: SpecialistAcceptedOutcomeKind
    validated_response_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_request_evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    requested_surface_count: StrictInt = Field(default=0, ge=0, le=10_000)
    surface_review_artifact_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @classmethod
    def build(
        cls,
        *,
        request_id: str,
        specialist_role: str,
        request_role: str,
        outcome_kind: SpecialistAcceptedOutcomeKind,
        validated_response_sha256: str,
        context_request_evidence_sha256: str,
        requested_surface_count: int = 0,
        surface_review_artifact_sha256: str | None = None,
    ) -> SpecialistAcceptedOutcome:
        payload: dict[str, Any] = {
            "schema_version": "1.0",
            "request_id": request_id,
            "specialist_role": specialist_role,
            "request_role": request_role,
            "outcome_kind": outcome_kind.value,
            "validated_response_sha256": validated_response_sha256,
            "context_request_evidence_sha256": context_request_evidence_sha256,
            "requested_surface_count": requested_surface_count,
            "surface_review_artifact_sha256": surface_review_artifact_sha256,
        }
        evidence_sha256 = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        return cls.model_validate({**payload, "evidence_sha256": evidence_sha256})

    @model_validator(mode="after")
    def role_shape_and_hash_are_exact(self) -> SpecialistAcceptedOutcome:
        expected_request_role: str
        if self.outcome_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW:
            if self.specialist_role not in SPECIALIST_INVESTIGATOR_ROLES:
                raise ValueError("candidate-review outcome requires an investigator role")
            expected_request_role = f"specialist:{self.specialist_role}"
            if self.requested_surface_count > 0 and self.surface_review_artifact_sha256 is None:
                raise ValueError("requested candidate surfaces require an accepted review artifact")
            if (
                self.requested_surface_count == 0
                and self.surface_review_artifact_sha256 is not None
            ):
                raise ValueError(
                    "surface-review artifact cannot be declared without requested surfaces"
                )
        elif self.outcome_kind is SpecialistAcceptedOutcomeKind.INVARIANT_REVIEW:
            if self.specialist_role != "invariant_review":
                raise ValueError("invariant-review outcome has an inconsistent specialist role")
            expected_request_role = "specialist:invariant_review"
        elif self.outcome_kind is SpecialistAcceptedOutcomeKind.TEST_GENERATION:
            if self.specialist_role not in {
                "test_generation",
                "exploit_reproduction_planner",
            }:
                raise ValueError("test-generation outcome has an inconsistent specialist role")
            expected_request_role = f"specialist:{self.specialist_role}:exploit_test"
        elif self.outcome_kind is SpecialistAcceptedOutcomeKind.FALSIFICATION:
            if self.specialist_role != "falsifier":
                raise ValueError("falsification outcome has an inconsistent specialist role")
            expected_request_role = "specialist:falsifier"
        else:
            if self.specialist_role != "report_quality":
                raise ValueError("report-quality outcome has an inconsistent specialist role")
            expected_request_role = "specialist:report_quality"
        if self.request_role != expected_request_role:
            raise ValueError("accepted specialist outcome has an inconsistent request role")
        if self.outcome_kind is not SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW and (
            self.requested_surface_count != 0 or self.surface_review_artifact_sha256 is not None
        ):
            raise ValueError("non-investigator outcome cannot claim model-surface review")
        payload = self.model_dump(mode="json", exclude={"evidence_sha256"})
        expected_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        if self.evidence_sha256 != expected_hash:
            raise ValueError("accepted specialist outcome hash is inconsistent")
        return self


class SpecialistExecutionRecord(StrictModel):
    """Normalized evidence for one bounded specialist responsibility."""

    role: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    role_kind: Literal["investigator", "auxiliary"]
    responsibility: str = Field(min_length=1, max_length=1_000)
    response_schema: str = Field(min_length=1, max_length=100)
    schema_name: str = Field(pattern=r"^[a-z][a-z0-9_]{0,127}$")
    configured: bool
    context_limit_bytes: int = Field(ge=1)
    context_budget_bytes: int | None = Field(default=None, ge=1)
    context_bytes_used: int | None = Field(default=None, ge=0)
    contexts: tuple[ContextExecutionEvidence, ...] = Field(default=(), max_length=4_096)
    request_contexts: tuple[ContextRequestEvidence, ...] = Field(
        default=(),
        max_length=4_096,
    )
    accepted_outcomes: tuple[SpecialistAcceptedOutcome, ...] = Field(
        default=(),
        max_length=4_096,
    )
    request_roles: list[str] = Field(default_factory=list, max_length=4_096)
    successful_request_ids: tuple[str, ...] = Field(default=(), max_length=4_096)
    failed_request_ids: tuple[str, ...] = Field(default=(), max_length=4_096)
    successful_requests: StrictInt = Field(default=0, ge=0)
    failed_requests: StrictInt = Field(default=0, ge=0)
    source_review_creditable_requests: StrictInt = Field(default=0, ge=0)
    status: SpecialistExecutionStatus

    @field_validator("successful_request_ids", "failed_request_ids")
    @classmethod
    def request_ids_are_canonical(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if any(not request_id or len(request_id) > 200 for request_id in value):
            raise ValueError("specialist request IDs must be non-empty and bounded")
        if value != tuple(sorted(set(value))):
            raise ValueError("specialist request IDs must be unique and canonically sorted")
        return value

    def derived_source_review_creditable_requests(self) -> int:
        """Recompute source-backed successes without trusting the serialized counter."""

        successful_ids = set(self.successful_request_ids)
        retained_bindings = {context.context_binding() for context in self.contexts}
        expected_context_role = f"specialist:{self.role}"
        request_contexts_by_id = {context.request_id: context for context in self.request_contexts}
        accepted_candidate_ids = {
            outcome.request_id
            for outcome in self.accepted_outcomes
            if outcome.outcome_kind is SpecialistAcceptedOutcomeKind.CANDIDATE_REVIEW
            and outcome.request_role == expected_context_role
            and outcome.requested_surface_count > 0
            and outcome.surface_review_artifact_sha256 is not None
            and ((request_context := request_contexts_by_id.get(outcome.request_id)) is not None)
            and outcome.context_request_evidence_sha256 == request_context.evidence_sha256
        }
        return len(
            {
                request_context.request_id
                for request_context in self.request_contexts
                if request_context.request_id in successful_ids
                and request_context.request_id in accepted_candidate_ids
                and request_context.context_role == expected_context_role
                and request_context.request_role == expected_context_role
                and request_context.context_binding() in retained_bindings
                and request_context.source_bytes > 0
            }
        )

    @model_validator(mode="after")
    def execution_state_is_consistent(self) -> SpecialistExecutionRecord:
        if (self.context_budget_bytes is None) != (self.context_bytes_used is None):
            raise ValueError("specialist context budget and usage must be recorded together")
        if self.context_budget_bytes is not None:
            assert self.context_bytes_used is not None
            if self.context_budget_bytes > self.context_limit_bytes:
                raise ValueError("specialist context budget exceeds its role limit")
            if self.context_bytes_used > self.context_budget_bytes:
                raise ValueError("specialist context usage exceeds its allocated budget")
        if len(self.contexts) == 1:
            context = self.contexts[0]
            if (
                self.context_budget_bytes != context.byte_budget
                or self.context_bytes_used != context.rendered_bytes
            ):
                raise ValueError("single-context specialist summary differs from its inventory")
        elif self.context_budget_bytes is not None or self.context_bytes_used is not None:
            raise ValueError("singular context summary is valid only for one actual context")
        if any(context.byte_budget > self.context_limit_bytes for context in self.contexts):
            raise ValueError("specialist context budget exceeds its configured package limit")
        expected_context_role = f"specialist:{self.role}"
        if any(context.context_role != expected_context_role for context in self.contexts):
            raise ValueError("retained specialist context has an inconsistent role")
        retained_bindings = {context.context_binding() for context in self.contexts}
        request_context_ids = [context.request_id for context in self.request_contexts]
        if len(request_context_ids) != len(set(request_context_ids)):
            raise ValueError("specialist request-context evidence IDs must be unique")
        allowed_request_roles = (
            {f"{expected_context_role}:exploit_test"}
            if self.role in {"test_generation", "exploit_reproduction_planner"}
            else {expected_context_role}
        )
        if self.request_roles != sorted(set(self.request_roles)) or any(
            request_role not in allowed_request_roles for request_role in self.request_roles
        ):
            raise ValueError("specialist request roles must be unique, canonical, and role-bound")
        request_context_roles = {context.request_role for context in self.request_contexts}
        if not request_context_roles.issubset(self.request_roles):
            raise ValueError("specialist request-role summary omits request-context evidence")
        if any(
            context.context_role != expected_context_role
            or context.request_role not in allowed_request_roles
            or context.context_binding() not in retained_bindings
            for context in self.request_contexts
        ):
            raise ValueError("request context does not match a retained specialist context")
        successful_ids = set(self.successful_request_ids)
        failed_ids = set(self.failed_request_ids)
        outcome_ids = [outcome.request_id for outcome in self.accepted_outcomes]
        if len(outcome_ids) != len(set(outcome_ids)):
            raise ValueError("accepted specialist outcome request IDs must be unique")
        if any(
            outcome.specialist_role != self.role
            or outcome.request_role not in allowed_request_roles
            for outcome in self.accepted_outcomes
        ):
            raise ValueError("accepted specialist outcome is not bound to its responsibility")
        request_contexts_by_id = {context.request_id: context for context in self.request_contexts}
        if any(
            (request_context := request_contexts_by_id.get(outcome.request_id)) is None
            or outcome.context_request_evidence_sha256 != request_context.evidence_sha256
            for outcome in self.accepted_outcomes
        ):
            raise ValueError("accepted specialist outcome context evidence digest is inconsistent")
        if successful_ids & failed_ids:
            raise ValueError("specialist successful and failed request IDs must be disjoint")
        if self.successful_requests != len(successful_ids):
            raise ValueError("successful specialist request count differs from its ID inventory")
        if self.failed_requests != len(failed_ids):
            raise ValueError("failed specialist request count differs from its ID inventory")
        accounted_ids = successful_ids | failed_ids
        if accounted_ids and not self.request_roles:
            raise ValueError("specialist request accounting requires a request-role summary")
        if any(request_id not in accounted_ids for request_id in request_context_ids):
            raise ValueError("request-context evidence is absent from specialist accounting")
        if successful_ids - set(request_context_ids):
            raise ValueError("successful request lacks bound context evidence")
        if successful_ids != set(outcome_ids):
            raise ValueError("successful request inventory differs from accepted role outcomes")
        derived_credit = self.derived_source_review_creditable_requests()
        if self.source_review_creditable_requests != derived_credit:
            raise ValueError("source-review credit differs from source-backed request evidence")
        if not self.configured and self.status is not SpecialistExecutionStatus.NOT_CONFIGURED:
            raise ValueError("unconfigured specialist must remain not_configured")
        if self.status is SpecialistExecutionStatus.COMPLETED and (
            self.successful_requests == 0 or self.failed_requests > 0
        ):
            raise ValueError("completed specialist requires success without failed requests")
        if self.status is SpecialistExecutionStatus.COMPLETED and not self.contexts:
            raise ValueError("completed specialist requires bounded context evidence")
        if self.status is SpecialistExecutionStatus.FAILED and (
            self.failed_requests == 0 or self.successful_requests > 0
        ):
            raise ValueError("failed specialist requires failures and no successful request")
        if self.status is SpecialistExecutionStatus.PARTIAL and (
            self.failed_requests == 0 or self.successful_requests == 0
        ):
            raise ValueError("partial specialist requires successful and failed requests")
        if self.status is SpecialistExecutionStatus.NOT_SCHEDULED and (
            not self.configured or self.successful_requests or self.failed_requests
        ):
            raise ValueError("not_scheduled specialist must be configured without requests")
        return self


class UsageRecord(StrictModel):
    request_id: str
    role: str
    execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.UNVERIFIED
    requested_model: str
    returned_model: str | None = None
    actual_model: str | None = None
    provider: str | None = None
    model_family: str
    timestamp: datetime
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    reported_cost_usd: float | None = Field(default=None, ge=0)
    accounted_cost_usd: float = Field(default=0, ge=0)
    routing: dict[str, Any] = Field(default_factory=dict)
    prompt_sha256: str
    user_prompt_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    response_sha256: str | None = None
    validated_response_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    request_body_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    schema_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    openrouter_generation_id: str | None = Field(default=None, max_length=500)
    configured_provider_endpoints: list[str] = Field(default_factory=list, max_length=100)
    actual_provider_endpoint: str | None = Field(default=None, max_length=500)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    latency_ms: int | None = Field(default=None, ge=0)
    finish_reason: str | None = Field(default=None, max_length=100)
    reasoning_tokens: int = Field(default=0, ge=0)
    cached_tokens: int = Field(default=0, ge=0)
    retry_count: int | None = Field(default=None, ge=0)
    provider_error_classification: str | None = Field(default=None, max_length=100)
    validation_status: ModelRequestValidationStatus = ModelRequestValidationStatus.NOT_VALIDATED
    identity_strength: ModelIdentityStrength = ModelIdentityStrength.UNBOUND
    fallback_used: bool = False
    substitution_detected: bool = False
    status: str
    attempts: int = Field(ge=1)

    @model_validator(mode="after")
    def request_evidence_is_consistent(self) -> UsageRecord:
        if (
            self.ended_at is not None
            and self.started_at is not None
            and self.ended_at < self.started_at
        ):
            raise ValueError("provider request end time precedes its start time")
        if self.retry_count is not None and self.retry_count != self.attempts - 1:
            raise ValueError("provider retry count must equal attempts minus one")
        if len(self.configured_provider_endpoints) != len(set(self.configured_provider_endpoints)):
            raise ValueError("configured provider endpoints must be unique")
        if self.validation_status is ModelRequestValidationStatus.VALID:
            required = (
                self.actual_model,
                self.response_sha256,
                self.validated_response_sha256,
                self.request_body_sha256,
                self.schema_sha256,
                self.openrouter_generation_id,
                self.started_at,
                self.ended_at,
                self.latency_ms,
                self.finish_reason,
                self.retry_count,
            )
            if any(value is None for value in required):
                raise ValueError("validated provider request evidence is incomplete")
            if self.status != "success":
                raise ValueError("validated provider request must have success status")
        if (
            self.identity_strength is not ModelIdentityStrength.UNBOUND
            and self.validation_status is not ModelRequestValidationStatus.VALID
        ):
            raise ValueError("bound model identity requires a validated provider response")
        return self


class RepositoryFile(StrictModel):
    path: str
    size: int = Field(ge=0)
    lines: int = Field(ge=0)
    sha256: str
    language: str
    categories: list[str] = Field(default_factory=list)


class RepositoryMap(StrictModel):
    root_name: str
    git_commit: str | None = None
    changed_since: str | None = None
    languages: dict[str, int]
    frameworks: list[str]
    manifests: list[str]
    entry_points: list[str]
    api_surfaces: list[str]
    auth_components: list[str]
    data_layers: list[str]
    network_clients: list[str]
    file_handlers: list[str]
    configuration_files: list[str]
    sensitive_processing: list[str]
    security_tests: list[str]
    files: list[RepositoryFile]
    omitted_files: list[str] = Field(default_factory=list)


class ContextExcerpt(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    start_line: int
    end_line: int
    content_hash: str
    content: str
    categories: tuple[str, ...] = ()
    omitted_before: bool = False
    omitted_after: bool = False

    @model_validator(mode="after")
    def content_hash_is_exact(self) -> ContextExcerpt:
        if self.content_hash != hashlib.sha256(self.content.encode("utf-8")).hexdigest():
            raise ValueError("context excerpt hash differs from its source bytes")
        return self


class ContextPackage(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: str
    byte_budget: StrictInt = Field(ge=0)
    bytes_used: StrictInt = Field(ge=0)
    configured_maximum_source_tokens_per_request: StrictInt = Field(gt=0)
    effective_source_byte_ceiling: StrictInt = Field(ge=0)
    repository_map: RepositoryMap
    scanner_findings: tuple[ScannerFinding, ...]
    excerpts: tuple[ContextExcerpt, ...]
    requested_model_surfaces: tuple[ModelSurfaceReviewRequest, ...] = ()
    threat_model: ThreatModel | None = None
    solidity_projects: tuple[SolidityProjectMetadata, ...] = ()
    solidity_compilations: tuple[SolidityCompilationResult, ...] = ()
    solidity_index: SoliditySymbolIndex | None = None
    solidity_graphs: SolidityGraphSet | None = None
    solidity_invariants: InvariantSuite | None = None
    invariant_executions: tuple[InvariantExecutionResult, ...] = ()
    economic_simulations: tuple[EconomicSimulationPlan, ...] = ()
    formal_runs: tuple[FormalToolRun, ...] = ()
    solidity_coverage: SolidityCoverage | None = None
    omission_notice_level: ContextOmissionNoticeLevel = ContextOmissionNoticeLevel.MANIFEST_ONLY
    omissions: tuple[ContextOmissionItem, ...] = Field(
        default=(),
        max_length=CONTEXT_OMISSION_GROUP_CAP,
    )

    @field_validator("requested_model_surfaces")
    @classmethod
    def requested_model_surfaces_are_canonical(
        cls,
        value: tuple[ModelSurfaceReviewRequest, ...],
    ) -> tuple[ModelSurfaceReviewRequest, ...]:
        surface_ids = [request.surface_id for request in value]
        if surface_ids != sorted(set(surface_ids)):
            raise ValueError("requested model surfaces must be unique and sorted by surface ID")
        return value

    @field_validator("omissions")
    @classmethod
    def omissions_are_typed_unique_and_canonical(
        cls,
        value: tuple[ContextOmissionItem, ...],
    ) -> tuple[ContextOmissionItem, ...]:
        canonical = tuple(
            sorted(
                value,
                key=lambda item: (
                    item.category.value,
                    item.reason.value,
                    item.omitted_item_sha256,
                ),
            )
        )
        groups = [(item.category, item.reason) for item in canonical]
        if value != canonical or len(groups) != len(set(groups)):
            raise ValueError(
                "context-package omission groups must be unique and canonically sorted"
            )
        return value

    @model_validator(mode="after")
    def source_ceiling_is_explicit_and_package_bound(self) -> ContextPackage:
        if self.bytes_used > self.byte_budget:
            raise ValueError("declared context-package bytes exceed its byte budget")
        configured = self.configured_maximum_source_tokens_per_request
        effective = self.effective_source_byte_ceiling
        configured_bytes = min(
            2**31 - 1,
            configured * UTF8_BYTES_PER_ESTIMATED_TOKEN,
        )
        if effective > configured_bytes or effective > self.byte_budget:
            raise ValueError("effective context-package source ceiling exceeds its governing limit")
        delivered_source_bytes = sum(
            len(excerpt.content.encode("utf-8")) for excerpt in self.excerpts
        )
        if delivered_source_bytes > effective:
            raise ValueError("context-package source content exceeds its effective source ceiling")
        return self

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Copy through validation so bounded immutable omission tuples cannot be bypassed."""

        payload = self.model_dump(mode="python")
        if update is not None:
            payload.update(update)
        return type(self).model_validate(payload)


class MinimumAnalysisFloor(StrictModel):
    """Normalized evidence supporting the audit run's minimum analysis floor."""

    schema_version: Literal["1.0"] = "1.0"
    run_status: AuditRunStatus
    source_files_ingested: int = Field(ge=0)
    source_ingestion_succeeded: bool
    solidity_applicable: bool
    compilation_statuses: dict[CompilationStatus, int] = Field(default_factory=dict)
    qualifying_compilations: int = Field(ge=0)
    compilation_satisfied: bool
    static_analysis_applicable: bool
    qualifying_real_static_scanners: list[str] = Field(default_factory=list, max_length=100)
    static_analysis_satisfied: bool
    model_review_required: bool
    scanner_only: bool
    explicit_downgrade_reason: str | None = Field(default=None, max_length=2_000)
    required_model_roles: list[str] = Field(default_factory=list, max_length=1_000)
    completed_real_model_roles: list[str] = Field(default_factory=list, max_length=1_000)
    model_review_satisfied: bool
    coverage_metric_ids: list[str] = Field(default_factory=list, max_length=1_000)
    coverage_denominators_valid: bool
    surface_analysis_feasible: bool
    orchestration_failures: list[str] = Field(default_factory=list, max_length=100)
    minimum_floor_met: bool
    limitations: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def evidence_and_status_are_consistent(self) -> MinimumAnalysisFloor:
        canonical_lists = (
            ("qualifying real static scanners", self.qualifying_real_static_scanners),
            ("required model roles", self.required_model_roles),
            ("completed real model roles", self.completed_real_model_roles),
            ("coverage metric IDs", self.coverage_metric_ids),
            ("orchestration failures", self.orchestration_failures),
            ("minimum-floor limitations", self.limitations),
        )
        for label, values in canonical_lists:
            if values != sorted(set(values)):
                raise ValueError(f"{label} must be unique and sorted")
            if any(
                not value.strip()
                or value != value.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
                for value in values
            ):
                raise ValueError(f"{label} must contain bounded printable text")
        if list(self.compilation_statuses) != sorted(
            self.compilation_statuses,
            key=lambda status: status.value,
        ):
            raise ValueError("compilation status counts must be canonically ordered")
        if any(count <= 0 for count in self.compilation_statuses.values()):
            raise ValueError("compilation status counts must be positive")
        if self.qualifying_compilations > self.compilation_statuses.get(
            CompilationStatus.SUCCESS,
            0,
        ):
            raise ValueError("qualifying compilation count exceeds successful compilations")
        if self.source_ingestion_succeeded != (self.source_files_ingested > 0):
            raise ValueError("source-ingestion state does not match ingested source evidence")

        compilation_attempts = sum(self.compilation_statuses.values())
        expected_compilation = not self.solidity_applicable or (
            compilation_attempts > 0 and self.qualifying_compilations == compilation_attempts
        )
        if self.compilation_satisfied != expected_compilation:
            raise ValueError("compilation state does not match compilation evidence")
        if not self.solidity_applicable and (
            self.compilation_statuses or self.qualifying_compilations
        ):
            raise ValueError("non-applicable Solidity compilation cannot retain run evidence")

        expected_static = not self.static_analysis_applicable or bool(
            self.qualifying_real_static_scanners
        )
        if self.static_analysis_satisfied != expected_static:
            raise ValueError("static-analysis state does not match REAL scanner evidence")
        if not self.static_analysis_applicable and self.qualifying_real_static_scanners:
            raise ValueError("non-applicable static analysis cannot retain scanner credit")

        if self.explicit_downgrade_reason is not None and (
            not self.explicit_downgrade_reason.strip()
            or self.explicit_downgrade_reason != self.explicit_downgrade_reason.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.explicit_downgrade_reason
            )
        ):
            raise ValueError("explicit downgrade reason must be bounded printable text")
        if self.scanner_only and self.model_review_required:
            raise ValueError("scanner-only analysis cannot simultaneously require model review")
        expected_model_review = not self.model_review_required or (
            bool(self.required_model_roles)
            and set(self.required_model_roles) <= set(self.completed_real_model_roles)
        )
        if self.model_review_satisfied != expected_model_review:
            raise ValueError("model-review state does not match completed REAL role evidence")

        qualifying_real_analysis = bool(
            self.qualifying_real_static_scanners or self.completed_real_model_roles
        )
        hard_failure = (
            not self.source_ingestion_succeeded
            or (bool(self.orchestration_failures) and not qualifying_real_analysis)
            or any(
                status in {CompilationStatus.FAILED, CompilationStatus.TIMED_OUT}
                for status in self.compilation_statuses
            )
        )
        complete_floor = (
            qualifying_real_analysis
            and self.source_ingestion_succeeded
            and self.compilation_satisfied
            and self.static_analysis_satisfied
            and self.model_review_satisfied
            and self.coverage_denominators_valid
            and bool(self.coverage_metric_ids)
            and self.surface_analysis_feasible
            and not self.orchestration_failures
            and not self.scanner_only
            and self.explicit_downgrade_reason is None
        )
        degraded_floor = (
            self.explicit_downgrade_reason is not None
            and qualifying_real_analysis
            and self.source_ingestion_succeeded
            and self.compilation_satisfied
            and self.coverage_denominators_valid
            and bool(self.coverage_metric_ids)
            and self.surface_analysis_feasible
            and not self.orchestration_failures
            and (
                not self.scanner_only
                or (self.static_analysis_applicable and bool(self.qualifying_real_static_scanners))
            )
        )
        expected_status = (
            AuditRunStatus.FAILED
            if hard_failure
            else (
                AuditRunStatus.COMPLETE
                if complete_floor
                else (AuditRunStatus.DEGRADED if degraded_floor else AuditRunStatus.INCOMPLETE)
            )
        )
        if self.run_status is not expected_status:
            raise ValueError("run status does not match minimum-floor evidence")
        if self.minimum_floor_met != (expected_status is AuditRunStatus.COMPLETE):
            raise ValueError("minimum-floor result does not match the run status")
        if (expected_status is AuditRunStatus.COMPLETE) == bool(self.limitations):
            raise ValueError("only non-complete minimum-floor evidence requires limitations")
        return self


class AuditReport(StrictModel):
    schema_version: Literal["1.0", "1.1", "1.2"]
    run_id: str
    generated_at: datetime
    completed: bool
    incomplete_reasons: list[str]
    repository: RepositoryMap
    configuration_hash: str
    model_configuration_hash: str
    privacy: dict[str, Any]
    scanner_runs: list[ScannerRun]
    repository_suite_differential: RepositorySuiteDifferentialRun | None = None
    usage: list[UsageRecord]
    budget_usd: float
    accounted_cost_usd: float
    findings: list[Finding]
    rejected_findings: list[Finding]
    audit_profile: AuditProfile = AuditProfile.STANDARD
    quality_status: AuditQualityStatus = AuditQualityStatus.COMPLETED
    run_status: AuditRunStatus | None = None
    minimum_analysis_floor: MinimumAnalysisFloor | None = None
    quality_gates: list[QualityGateResult] = Field(default_factory=list)
    scope_assessment: AuditScopeAssessment | None = None
    prior_audit_comparison: PriorAuditComparison | None = None
    maximum_assurance: MaximumAssuranceAssessment | None = None
    verification_decisions: list[VerificationDecision] = Field(default_factory=list)
    cross_examination_decisions: list[CandidateCrossExaminationDecision] = Field(
        default_factory=list
    )
    falsification_decisions: list[FalsificationDecision] = Field(default_factory=list)
    reproductions: list[ReproductionResult] = Field(default_factory=list)
    invariants: InvariantSuite | None = None
    invariant_review: InvariantReviewResult | None = None
    invariant_executions: list[InvariantExecutionResult] = Field(default_factory=list)
    economic_simulations: list[EconomicSimulationPlan] = Field(default_factory=list)
    formal_runs: list[FormalToolRun] = Field(default_factory=list)
    solidity_coverage: SolidityCoverage | None = None
    model_review_coverage: ModelReviewCoverage | None = None
    report_quality_review: ReportQualityReview | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def run_status_matches_minimum_analysis_floor(self) -> AuditReport:
        self._validate_execution_origin_bindings()
        if self.schema_version != "1.2":
            if self.run_status is not None or self.minimum_analysis_floor is not None:
                raise ValueError("typed minimum-floor evidence requires report schema 1.2")
            return self
        if self.run_status is None or self.minimum_analysis_floor is None:
            raise ValueError("report schema 1.2 requires typed minimum-floor evidence")
        if self.run_status is not self.minimum_analysis_floor.run_status:
            raise ValueError("report run status conflicts with minimum analysis floor")
        if self.completed != (self.run_status is AuditRunStatus.COMPLETE):
            raise ValueError("report completion must be true only for a COMPLETE run")
        expected_quality = {
            AuditRunStatus.COMPLETE: AuditQualityStatus.COMPLETED,
            AuditRunStatus.DEGRADED: AuditQualityStatus.COMPLETED_WITH_LIMITATIONS,
            AuditRunStatus.INCOMPLETE: AuditQualityStatus.INCOMPLETE,
            AuditRunStatus.FAILED: AuditQualityStatus.FAILED,
        }[self.run_status]
        if self.quality_status is not expected_quality:
            raise ValueError("report quality status conflicts with evidence-derived run status")
        if self.run_status is AuditRunStatus.COMPLETE and self.incomplete_reasons:
            raise ValueError("COMPLETE report cannot retain incomplete reasons")
        if self.run_status is not AuditRunStatus.COMPLETE and not self.incomplete_reasons:
            raise ValueError("non-complete report requires a prominent incomplete reason")
        if not set(self.minimum_analysis_floor.orchestration_failures) <= set(
            self.incomplete_reasons
        ):
            raise ValueError("minimum-floor orchestration failures are absent from the report")
        floor_gates = [gate for gate in self.quality_gates if gate.gate == "minimum_analysis_floor"]
        if (
            len(floor_gates) != 1
            or not floor_gates[0].required
            or floor_gates[0].passed != (self.run_status is AuditRunStatus.COMPLETE)
        ):
            raise ValueError("report minimum-floor gate conflicts with typed run status")
        if self.run_status is AuditRunStatus.COMPLETE and any(
            gate.required and not gate.passed for gate in self.quality_gates
        ):
            raise ValueError("COMPLETE report contains a failed required quality gate")
        if self.audit_profile is AuditProfile.MAXIMUM_ASSURANCE and (
            self.maximum_assurance is None or not self.maximum_assurance.requested
        ):
            raise ValueError("maximum-assurance profile requires a requested assurance assessment")
        if self.maximum_assurance is not None:
            assessment_complete = self.maximum_assurance.status is MaximumAssuranceStatus.COMPLETE
            if assessment_complete != (self.run_status is AuditRunStatus.COMPLETE) and (
                self.audit_profile is AuditProfile.MAXIMUM_ASSURANCE
                or self.maximum_assurance.required
            ):
                raise ValueError(
                    "run completion conflicts with the required maximum-assurance assessment"
                )
        self._validate_minimum_floor_runtime_bindings(self.minimum_analysis_floor)
        return self

    def _validate_execution_origin_bindings(self) -> None:
        """Bind execution-origin findings to exact serialized runtime evidence."""

        execution_keys = [
            (result.invariant_id, result.harness_name) for result in self.invariant_executions
        ]
        if len(execution_keys) != len(set(execution_keys)):
            raise ValueError("report invariant execution identities must be unique")
        execution_results = {
            (result.invariant_id, result.harness_name): result
            for result in self.invariant_executions
        }
        invariant_by_id = {
            invariant.id: invariant
            for invariant in (self.invariants.invariants if self.invariants is not None else [])
        }
        observed_provenance: set[str] = set()
        for finding in [*self.findings, *self.rejected_findings]:
            if finding.origin_kind is not FindingOriginKind.DETERMINISTIC_EXECUTION:
                continue
            for provenance in finding.execution_provenance:
                if provenance.provenance_sha256 in observed_provenance:
                    raise ValueError(
                        "execution provenance cannot appear in more than one finding group"
                    )
                observed_provenance.add(provenance.provenance_sha256)
                result = execution_results.get((provenance.invariant_id, provenance.harness_name))
                invariant = invariant_by_id.get(provenance.invariant_id)
                result_minimized = bool(
                    result is not None
                    and result.minimization_evidence is not None
                    and result.minimization_evidence.proven_minimal
                )
                invariant_location_keys = (
                    sorted(
                        (
                            location.path,
                            location.start_line,
                            location.end_line,
                            location.symbol or "",
                            location.content_hash or "",
                        )
                        for location in invariant.locations
                    )
                    if invariant is not None
                    else []
                )
                provenance_location_keys = [
                    (
                        location.path,
                        location.start_line,
                        location.end_line,
                        location.symbol or "",
                        location.content_hash or "",
                    )
                    for location in provenance.source_locations
                ]
                if (
                    result is None
                    or invariant is None
                    or result.status is not InvariantExecutionStatus.COUNTEREXAMPLE
                    or result.execution_evidence is not ExecutionEvidenceKind.REAL
                    or result.harness_spec_sha256 != provenance.harness_spec_sha256
                    or result.execution_observation_sha256
                    != provenance.execution_observation_sha256
                    or _canonical_model_sha256(result.model_dump(mode="json"))
                    != provenance.execution_result_sha256
                    or invariant.evidence_hash != provenance.invariant_evidence_sha256
                    or provenance.executable_sha256 != result.executable_sha256
                    or provenance.source_sha256 != result.source_sha256
                    or provenance.compiler_version != result.compiler_version
                    or provenance.compiler_sha256 != result.compiler_sha256
                    or provenance.isolation_backend != result.isolation_backend
                    or provenance.isolation_attestation_sha256
                    != result.isolation_attestation_sha256
                    or provenance.attempts != result.attempts
                    or provenance.successful_attempts != result.successful_attempts
                    or provenance.replay_confirmed != result.replay_confirmed
                    or provenance.minimized != result_minimized
                    or provenance_location_keys != invariant_location_keys
                ):
                    raise ValueError(
                        "execution-origin finding differs from its serialized invariant evidence"
                    )

    def _validate_minimum_floor_runtime_bindings(self, floor: MinimumAnalysisFloor) -> None:
        """Bind serialized floor claims back to the report's normalized runtime evidence."""

        from mmaudit.models.usage import is_structurally_creditable_usage_record
        from mmaudit.orchestration.assurance import is_qualifying_real_scanner_run
        from mmaudit.orchestration.run_status import DEFAULT_STATIC_SCANNER_NAMES

        scanner_only = self.metadata.get("scanner_only")
        if not isinstance(scanner_only, bool) or scanner_only != floor.scanner_only:
            raise ValueError("minimum-floor scanner-only state conflicts with report metadata")

        solidity = self.metadata.get("solidity")
        if not isinstance(solidity, dict):
            raise ValueError("report schema 1.2 requires typed Solidity runtime metadata")
        raw_projects = solidity.get("projects")
        raw_compilations = solidity.get("compilation")
        if not isinstance(raw_projects, list) or not isinstance(raw_compilations, list):
            raise ValueError("Solidity runtime metadata omits projects or compilation evidence")
        projects = [SolidityProjectMetadata.model_validate(item) for item in raw_projects]
        compilations = [SolidityCompilationResult.model_validate(item) for item in raw_compilations]
        solidity_applicable = bool(projects)
        if floor.solidity_applicable != solidity_applicable:
            raise ValueError("minimum-floor Solidity applicability conflicts with runtime evidence")

        source_files_ingested = sum(
            (file.language.casefold() == "solidity" or file.path.casefold().endswith(".sol"))
            if solidity_applicable
            else bool(file.path and file.language)
            for file in self.repository.files
        )
        if floor.source_files_ingested != source_files_ingested:
            raise ValueError("minimum-floor source count conflicts with repository evidence")

        compilation_statuses: dict[CompilationStatus, int] = {}
        for compilation in compilations:
            compilation_statuses[compilation.status] = (
                compilation_statuses.get(compilation.status, 0) + 1
            )
        qualifying_compilations = sum(
            compilation.status is CompilationStatus.SUCCESS
            and compilation.ast_available
            and bool(compilation.contracts_compiled)
            for compilation in compilations
        )
        if (
            floor.compilation_statuses != compilation_statuses
            or floor.qualifying_compilations != qualifying_compilations
        ):
            raise ValueError("minimum-floor compilation claims conflict with runtime evidence")

        expected_static_applicability = solidity_applicable or scanner_only
        if floor.static_analysis_applicable != expected_static_applicability:
            raise ValueError("minimum-floor static applicability conflicts with runtime evidence")
        qualifying_scanners = sorted(
            {
                run.scanner
                for run in self.scanner_runs
                if (
                    expected_static_applicability
                    and run.scanner in DEFAULT_STATIC_SCANNER_NAMES
                    and is_qualifying_real_scanner_run(run)
                )
            }
        )
        if floor.qualifying_real_static_scanners != qualifying_scanners:
            raise ValueError("minimum-floor scanner claims conflict with report scanner evidence")

        completed_real_roles = sorted(
            {
                record.role
                for record in self.usage
                if is_structurally_creditable_usage_record(record, require_real=True)
            }
        )
        if floor.completed_real_model_roles != completed_real_roles:
            raise ValueError("minimum-floor model claims conflict with report usage evidence")
        expected_model_review_required = not scanner_only
        expected_required_roles = sorted(ANALYSIS_ROLES) if expected_model_review_required else []
        if (
            floor.model_review_required != expected_model_review_required
            or floor.required_model_roles != expected_required_roles
        ):
            raise ValueError("minimum-floor required model roles conflict with run mode")

        coverage = self.effective_solidity_coverage()
        coverage_metrics = coverage.quality_metrics if coverage is not None else {}
        coverage_ids = sorted(coverage_metrics)
        coverage_valid = bool(coverage_ids) and all(
            not metric.failures and (metric.denominator > 0 or bool(metric.not_applicable_evidence))
            for metric in coverage_metrics.values()
        )
        if (
            floor.coverage_metric_ids != coverage_ids
            or floor.coverage_denominators_valid != coverage_valid
        ):
            raise ValueError("minimum-floor coverage claims conflict with report coverage evidence")

    @model_validator(mode="after")
    def solidity_coverage_sources_are_consistent(self) -> AuditReport:
        legacy_coverage = self._legacy_solidity_coverage()
        if legacy_coverage is None or self.solidity_coverage is None:
            return self
        if legacy_coverage != self.solidity_coverage:
            raise ValueError(
                "typed solidity_coverage conflicts with legacy metadata.solidity.coverage"
            )
        return self

    @model_validator(mode="after")
    def privacy_runtime_evidence_is_typed(self) -> AuditReport:
        """Reject malformed serialized privacy evidence embedded in a report."""

        effective = self.privacy.get("effective_policy")
        provenance = self.privacy.get("source_provenance")
        if effective is not None:
            from mmaudit.privacy import EffectivePrivacyPolicyEvidence

            EffectivePrivacyPolicyEvidence.model_validate(effective)
        if provenance is not None:
            from mmaudit.repository.privacy_provenance import (
                PrivacySourceProvenanceEvidence,
            )

            PrivacySourceProvenanceEvidence.model_validate(provenance)
        fork_rpc = self.privacy.get("fork_rpc_egress")
        if self.repository_suite_differential is None:
            if fork_rpc is not None:
                raise ValueError(
                    "fork RPC privacy evidence requires a typed repository differential result"
                )
        else:
            if fork_rpc is None:
                raise ValueError(
                    "repository differential result requires explicit fork RPC privacy evidence"
                )
            observed = RepositoryForkRpcPrivacyEvidence.model_validate(fork_rpc)
            expected = RepositoryForkRpcPrivacyEvidence.from_differential(
                self.repository_suite_differential
            )
            if observed != expected:
                raise ValueError(
                    "fork RPC privacy evidence differs from the repository differential result"
                )
        return self

    def effective_solidity_coverage(self) -> SolidityCoverage | None:
        """Prefer typed coverage while retaining validated legacy-report compatibility."""

        if self.solidity_coverage is not None:
            return self.solidity_coverage
        return self._legacy_solidity_coverage()

    def _legacy_solidity_coverage(self) -> SolidityCoverage | None:
        solidity = self.metadata.get("solidity")
        if not isinstance(solidity, dict):
            return None
        coverage = solidity.get("coverage")
        if coverage is None:
            return None
        return SolidityCoverage.model_validate(coverage)
