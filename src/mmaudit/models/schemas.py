"""Strict schemas shared by scanners, model roles, and reporters."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from mmaudit.models.identity import OpenRouterIdentityStrength
from mmaudit.models.output_modes import (
    STRUCTURED_OUTPUT_PROTOCOL_VERSION,
    StructuredOutputMode,
    mode_for_supported_parameters,
    output_mode_request_parameters,
)
from mmaudit.models.structured_output import StructuredOutputRepairEvidence


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
    type: Literal["model", "scanner", "reproduction", "formal", "repository"]
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
    role: str
    model_family: str
    model_votes: list[ModelVote] = Field(default_factory=list)


class Finding(StrictModel):
    id: str = Field(min_length=1)
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
    fingerprint: str


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
        if (
            self.execution_observation_sha256 is not None
            and self.execution_observation_sha256 != self.expected_execution_observation_sha256()
        ):
            raise ValueError("scanner execution observation hash does not match its fields")
        return self


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
    COMPLETED = "completed"


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
    request_roles: list[str] = Field(default_factory=list, max_length=100)
    successful_requests: int = Field(default=0, ge=0)
    failed_requests: int = Field(default=0, ge=0)
    status: SpecialistExecutionStatus

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
        if not self.configured and self.status is not SpecialistExecutionStatus.NOT_CONFIGURED:
            raise ValueError("unconfigured specialist must remain not_configured")
        if self.status is SpecialistExecutionStatus.COMPLETED and self.successful_requests == 0:
            raise ValueError("completed specialist requires a successful request")
        if self.status is SpecialistExecutionStatus.COMPLETED and self.context_budget_bytes is None:
            raise ValueError("completed specialist requires bounded context evidence")
        if self.status is SpecialistExecutionStatus.FAILED and (
            self.failed_requests == 0 or self.successful_requests > 0
        ):
            raise ValueError("failed specialist requires failures and no successful request")
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
    path: str
    start_line: int
    end_line: int
    content_hash: str
    content: str
    categories: list[str] = Field(default_factory=list)
    omitted_before: bool = False
    omitted_after: bool = False


class ContextPackage(StrictModel):
    role: str
    byte_budget: int
    bytes_used: int
    repository_map: RepositoryMap
    scanner_findings: list[ScannerFinding]
    excerpts: list[ContextExcerpt]
    requested_model_surfaces: list[ModelSurfaceReviewRequest] = Field(default_factory=list)
    threat_model: ThreatModel | None = None
    solidity_projects: list[SolidityProjectMetadata] = Field(default_factory=list)
    solidity_compilations: list[SolidityCompilationResult] = Field(default_factory=list)
    solidity_index: SoliditySymbolIndex | None = None
    solidity_graphs: SolidityGraphSet | None = None
    solidity_invariants: InvariantSuite | None = None
    invariant_executions: list[InvariantExecutionResult] = Field(default_factory=list)
    economic_simulations: list[EconomicSimulationPlan] = Field(default_factory=list)
    formal_runs: list[FormalToolRun] = Field(default_factory=list)
    solidity_coverage: SolidityCoverage | None = None
    omissions: list[str] = Field(default_factory=list)

    @field_validator("requested_model_surfaces")
    @classmethod
    def requested_model_surfaces_are_canonical(
        cls,
        value: list[ModelSurfaceReviewRequest],
    ) -> list[ModelSurfaceReviewRequest]:
        surface_ids = [request.surface_id for request in value]
        if surface_ids != sorted(set(surface_ids)):
            raise ValueError("requested model surfaces must be unique and sorted by surface ID")
        return value


class AuditReport(StrictModel):
    schema_version: Literal["1.0", "1.1"]
    run_id: str
    generated_at: datetime
    completed: bool
    incomplete_reasons: list[str]
    repository: RepositoryMap
    configuration_hash: str
    model_configuration_hash: str
    privacy: dict[str, Any]
    scanner_runs: list[ScannerRun]
    usage: list[UsageRecord]
    budget_usd: float
    accounted_cost_usd: float
    findings: list[Finding]
    rejected_findings: list[Finding]
    audit_profile: AuditProfile = AuditProfile.STANDARD
    quality_status: AuditQualityStatus = AuditQualityStatus.COMPLETED
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
