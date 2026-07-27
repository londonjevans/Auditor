"""Configuration loading, validation, and deterministic hashing."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mmaudit.constants import (
    ALL_MODEL_ROLES,
    ALL_SPECIALIST_ROLES,
    DEFAULT_CONFIG_NAME,
    DEFAULT_IGNORE_NAME,
)
from mmaudit.models.schemas import (
    AuditProfile,
    AuditScope,
    CrossChainMessageCapability,
    FoundryInvariantHarnessSpec,
    LocalInvariantDeployment,
    OracleInfluenceCapability,
    TransactionOrderingCapability,
)
from mmaudit.operator_secrets import (
    COST_LEDGER_PATH_VARIABLE,
    RESERVED_OPERATOR_CONTROL_PLANE_NAMES,
)


class ConfigError(ValueError):
    """Raised when an audit configuration is missing or unsafe."""


class ConfigModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class RepositoryConfig(ConfigModel):
    root: str = "."
    ignore_file: str = DEFAULT_IGNORE_NAME
    include_tests: bool = True
    include_docs: bool = False
    max_files: int = Field(default=2_000, ge=1)
    max_walk_entries: int = Field(default=50_000, ge=1)
    max_file_bytes: int = Field(default=250_000, ge=1)
    max_discovery_bytes: int = Field(default=50_000_000, ge=1)
    max_total_context_bytes: int = Field(default=2_000_000, ge=1)
    follow_symlinks: bool = False


class ScopeConfig(ConfigModel):
    """Requested audit boundary and whether incomplete evidence blocks completion."""

    mode: AuditScope = AuditScope.FULL_PROTOCOL
    require_complete: bool = False


class PriorAuditConfig(ConfigModel):
    """Bounded local input for blind-first historical remediation comparison."""

    path: str | None = None
    required: bool = False
    fail_on_missed: bool = False
    max_bytes: int = Field(default=2_000_000, ge=1_024, le=20_000_000)
    max_findings: int = Field(default=2_000, ge=1, le=2_000)

    @field_validator("path")
    @classmethod
    def path_is_repository_relative_json(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().replace("\\", "/")
        if (
            not value
            or value.startswith(("/", "-", ".env"))
            or re.match(r"^[A-Za-z]:/", value)
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
            or not value.lower().endswith(".json")
        ):
            raise ValueError("prior-audit path must be a safe repository-relative JSON path")
        return value

    @model_validator(mode="after")
    def required_input_has_path(self) -> PriorAuditConfig:
        if (self.required or self.fail_on_missed) and self.path is None:
            raise ValueError("required prior-audit comparison requires a configured path")
        return self


class PrivacyConfig(ConfigModel):
    allow_code_egress: bool = False
    require_zdr: bool = True
    redact_secrets: bool = True
    fail_on_detected_secret: bool = True
    store_raw_prompts: bool = False
    store_raw_responses: bool = False
    maximum_model_retention: Literal["zero", "temporary", "persistent"] = "zero"
    approved_model_lineages: tuple[str, ...] = ()

    @field_validator("approved_model_lineages")
    @classmethod
    def approved_lineages_are_immutable_identifiers(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("approved model lineages must be unique")
        if any(not re.fullmatch(r"sha256:[0-9a-f]{64}", lineage) for lineage in value):
            raise ValueError("approved model lineages must be lowercase sha256 identifiers")
        return value


class ExecutionConfig(ConfigModel):
    concurrency: int = Field(default=3, ge=1, le=16)
    request_timeout_seconds: float = Field(default=180, gt=0, le=900)
    scanner_timeout_seconds: float = Field(default=900, gt=0, le=3_600)
    max_model_retries: int = Field(default=2, ge=0, le=5)
    max_json_repair_attempts: int = Field(default=0, ge=0, le=1)
    budget_usd: float = Field(default=20.0, gt=0, le=250.0)
    cost_ledger_path: str | None = None
    max_request_bytes: int = Field(default=4_000_000, ge=1_024)
    max_output_tokens_per_request: int = Field(default=4_096, ge=256, le=65_536)
    max_requests_per_agent: int = Field(default=2, ge=1, le=512)
    conservative_usd_per_million_tokens: float = Field(default=60.0, gt=0)

    @field_validator("cost_ledger_path")
    @classmethod
    def cost_ledger_is_an_explicit_absolute_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        path = Path(value)
        if (
            not value
            or "\x00" in value
            or len(value) > 4_096
            or not path.is_absolute()
            or path.name in {"", ".", ".."}
        ):
            raise ValueError("execution cost ledger path must be an absolute file path")
        return value


class DependencyPreparationConfig(ConfigModel):
    """Explicit local-only input for dependency material used by isolated builds."""

    enabled: bool = False
    required: bool = False
    offline_snapshot_path: str | None = None
    offline_snapshot_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    max_snapshot_bytes: int = Field(default=5_000_000, ge=1_024, le=20_000_000)
    max_projects: int = Field(default=50, ge=1, le=200)
    max_packages: int = Field(default=2_000, ge=1, le=10_000)
    max_files: int = Field(default=100_000, ge=1, le=500_000)
    max_file_bytes: int = Field(default=10_000_000, ge=1_024, le=100_000_000)
    max_total_bytes: int = Field(default=1_000_000_000, ge=1_024, le=4_000_000_000)

    @field_validator("offline_snapshot_path")
    @classmethod
    def snapshot_path_is_dedicated_repository_relative_json(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        normalized = value.strip().replace("\\", "/")
        parts = normalized.split("/")
        if (
            not normalized
            or normalized.startswith(("/", "-", ".env"))
            or re.match(r"^[A-Za-z]:/", normalized)
            or len(parts) < 2
            or any(part in {"", ".", ".."} for part in parts)
            or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
            or not normalized.lower().endswith(".json")
            or parts[0].lower() in {".git", ".ssh", ".aws", ".azure"}
        ):
            raise ValueError(
                "offline dependency snapshot must be a safe JSON file in a dedicated "
                "repository-relative directory"
            )
        return normalized

    @model_validator(mode="after")
    def enabled_preparation_has_pinned_snapshot(self) -> DependencyPreparationConfig:
        if self.required and not self.enabled:
            raise ValueError("required dependency preparation must be enabled")
        if self.enabled and (
            self.offline_snapshot_path is None or self.offline_snapshot_sha256 is None
        ):
            raise ValueError(
                "enabled dependency preparation requires a checksum-pinned offline snapshot"
            )
        return self


class SmartContractsConfig(ConfigModel):
    """Fork-only EVM probing controls.

    The configured environment variable name is reportable. Its value is never stored.
    """

    enabled: bool = True
    compile: bool = False
    solc_version: str | None = Field(default=None, min_length=1, max_length=200)
    solc_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    allow_network: bool = False
    framework: Literal["auto", "foundry", "hardhat", "mixed", "plain"] = "auto"
    project_root: str | None = None
    compilation_timeout_seconds: float = Field(default=600, gt=0, le=3_600)
    keep_artifacts: bool = False
    fork_only: Literal[True] = True
    allow_fork_probing: bool = False
    fork_rpc_url_env: str = "MMAUDIT_FORK_RPC_URL"
    require_local_fork_rpc: bool = True
    foundry_match_path: str = "test/audit/*.t.sol"
    foundry_match_test: str | None = None
    foundry_fuzz_runs: int = Field(default=256, ge=1, le=1_000_000)
    foundry_invariant_runs: int = Field(default=64, ge=1, le=100_000)
    max_fork_probe_seconds: float = Field(default=900, gt=0, le=3_600)
    fail_on_fork_test_failure: bool = False

    @model_validator(mode="after")
    def solc_trust_pin_is_complete(self) -> SmartContractsConfig:
        if (self.solc_version is None) != (self.solc_sha256 is None):
            raise ValueError("solc_version and solc_sha256 must be configured together")
        return self

    @field_validator("project_root")
    @classmethod
    def project_root_is_repository_relative(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if (
            value.startswith(("/", "\\", "-"))
            or ".." in value.replace("\\", "/").split("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("project_root must be a safe repository-relative path")
        return value.rstrip("/") or "."

    @field_validator("fork_rpc_url_env")
    @classmethod
    def env_name_is_safe(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,127}", value):
            raise ValueError("fork_rpc_url_env must be an uppercase environment variable name")
        if value in RESERVED_OPERATOR_CONTROL_PLANE_NAMES:
            raise ValueError("fork_rpc_url_env cannot select an operator control-plane variable")
        return value

    @field_validator("foundry_match_path")
    @classmethod
    def match_path_is_repository_relative(cls, value: str) -> str:
        value = value.strip()
        if (
            not value
            or value.startswith(("/", "\\", "-"))
            or ".." in value.replace("\\", "/").split("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("foundry_match_path must be a safe repository-relative glob")
        return value

    @field_validator("foundry_match_test")
    @classmethod
    def match_test_is_safe(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if value.startswith("-") or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("foundry_match_test must be a safe Foundry test selector")
        return value


class ReproductionConfig(ConfigModel):
    """Candidate-specific fork reproduction controls."""

    enabled: bool = True
    required_for_solidity: bool = True
    require_hardened_isolation: bool = True
    isolation_backend: Literal[
        "auto",
        "rootless-container",
        "sandbox-exec",
        "bubblewrap",
    ] = "auto"
    rootless_container_image: str | None = Field(default=None, max_length=512)
    rootless_container_runtime: Literal["auto", "docker", "podman"] = "auto"
    max_candidates: int = Field(default=20, ge=1, le=200)
    max_tests_per_candidate: int = Field(default=3, ge=1, le=10)
    max_total_tests: int = Field(default=40, ge=1, le=500)
    repetitions: int = Field(default=2, ge=1, le=10)
    timeout_seconds: float = Field(default=180, gt=0, le=1_800)
    max_output_bytes: int = Field(default=10_000_000, ge=10_000, le=100_000_000)
    minimize: bool = True
    pinned_block_number: int | None = Field(default=None, ge=0)
    expected_chain_id: int | None = Field(default=None, ge=1)
    targets: dict[str, str] = Field(default_factory=dict)
    max_attacker_controlled_actors: int = Field(default=4, ge=1, le=16)
    max_attacker_controlled_contracts: int = Field(default=4, ge=0, le=16)
    max_starting_native_capital_wei: int = Field(default=10**24, ge=0, le=2**256 - 1)
    max_flash_liquidity_wei: int = Field(default=0, ge=0, le=2**256 - 1)
    allowed_token_approval_targets: list[str] = Field(default_factory=list)
    max_time_shift_seconds: int = Field(default=0, ge=0, le=31_536_000)
    max_block_advance: int = Field(default=0, ge=0, le=10_000_000)
    allowed_transaction_ordering: TransactionOrderingCapability = TransactionOrderingCapability.NONE
    allowed_oracle_influence: OracleInfluenceCapability = OracleInfluenceCapability.NONE
    allow_governance_rights: bool = False
    allowed_privileged_roles: list[str] = Field(default_factory=list)
    allowed_cross_chain_messages: CrossChainMessageCapability = CrossChainMessageCapability.NONE
    max_attack_transactions: int = Field(default=40, ge=1, le=40)

    @field_validator("targets")
    @classmethod
    def targets_are_named_addresses(cls, value: dict[str, str]) -> dict[str, str]:
        for name, address in value.items():
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", name):
                raise ValueError("reproduction target names must be safe identifiers")
            if not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
                raise ValueError("reproduction targets must be literal EVM addresses")
        return value

    @field_validator("allowed_privileged_roles", "allowed_token_approval_targets")
    @classmethod
    def capability_names_are_safe(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("allowed capability names must be unique")
        if any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,47}", item) for item in value):
            raise ValueError("allowed capability names must be safe identifiers")
        return value

    @model_validator(mode="after")
    def rootless_container_configuration_is_pinned(self) -> ReproductionConfig:
        if self.rootless_container_image is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/-]*@sha256:[0-9a-f]{64}",
            self.rootless_container_image,
        ):
            raise ValueError("rootless_container_image must be pinned by lowercase sha256")
        if self.isolation_backend == "rootless-container" and self.rootless_container_image is None:
            raise ValueError(
                "rootless-container isolation requires a digest-pinned container image"
            )
        return self


class QualityGateConfig(ConfigModel):
    """Machine-enforced completion gates for high-assurance profiles."""

    require_compilation: bool = False
    require_slither: bool = False
    require_fork_baseline: bool = False
    require_candidate_reproduction: bool = True
    require_all_model_roles: bool = True
    min_indexed_contract_fraction: float = Field(default=0.95, ge=0, le=1)
    min_reviewed_entry_point_fraction: float = Field(default=0.90, ge=0, le=1)
    min_reviewed_privileged_entry_point_fraction: float = Field(default=1.0, ge=0, le=1)
    min_reviewed_state_writing_function_fraction: float = Field(default=0.90, ge=0, le=1)
    min_reviewed_high_value_path_fraction: float = Field(default=1.0, ge=0, le=1)
    min_classified_external_call_fraction: float = Field(default=1.0, ge=0, le=1)
    min_classified_asset_flow_fraction: float = Field(default=1.0, ge=0, le=1)
    min_modelled_storage_variable_fraction: float = Field(default=0.90, ge=0, le=1)
    min_reproduction_attempt_fraction: float = Field(default=1.0, ge=0, le=1)
    min_invariant_execution_fraction: float = Field(default=0.80, ge=0, le=1)
    min_scanner_completion_fraction: float = Field(default=1.0, ge=0, le=1)
    min_model_role_completion_fraction: float = Field(default=1.0, ge=0, le=1)
    min_economic_template_execution_fraction: float = Field(default=1.0, ge=0, le=1)
    min_dependency_resolution_fraction: float = Field(default=1.0, ge=0, le=1)


class MaximumAssuranceConfig(ConfigModel):
    """Non-negotiable contract controls for maximum-assurance runs."""

    require: bool = False
    allow_downgrade: bool = False
    minimum_model_families: int = Field(default=5, ge=3, le=32)
    minimum_specialist_agents: int = Field(default=8, ge=1, le=64)
    require_reproduction_for_critical: bool = True
    require_formal_or_reproduction_for_confirmed_critical: bool = True
    benchmark_gate: bool = False
    ci_mode: bool = False


class InvariantConfig(ConfigModel):
    enabled: bool = True
    required: bool = False
    generate_foundry_templates: bool = True
    execute_generated: bool = False
    harnesses: list[FoundryInvariantHarnessSpec] = Field(default_factory=list)
    local_deployments: list[LocalInvariantDeployment] = Field(
        default_factory=list,
        max_length=16,
    )
    max_invariants: int = Field(default=100, ge=1, le=1_000)
    minimum_confidence: float = Field(default=0.45, ge=0, le=1)

    @field_validator("harnesses")
    @classmethod
    def harness_names_are_unique(
        cls,
        value: list[FoundryInvariantHarnessSpec],
    ) -> list[FoundryInvariantHarnessSpec]:
        names = [harness.name for harness in value]
        if len(names) != len(set(names)):
            raise ValueError("invariant harness names must be unique")
        return value

    @field_validator("local_deployments")
    @classmethod
    def local_deployments_are_ordered_and_unique(
        cls,
        value: list[LocalInvariantDeployment],
    ) -> list[LocalInvariantDeployment]:
        targets = [deployment.target_alias for deployment in value]
        if len(targets) != len(set(targets)):
            raise ValueError("local invariant deployment targets must be unique")
        deployed: set[str] = set()
        for deployment in value:
            dependencies = {argument.target_alias for argument in deployment.constructor_arguments}
            if not dependencies <= deployed:
                raise ValueError(
                    "local invariant constructor dependencies must reference earlier deployments"
                )
            deployed.add(deployment.target_alias)
        return value


class CertoraConfig(ConfigModel):
    """Explicit operator-owned configuration for remote Certora verification."""

    enabled: bool = False
    cli_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    cli_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source: str | None = None
    contract: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    specification: str | None = None
    rule: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
    assumptions: list[str] = Field(default_factory=list, max_length=100)
    vacuity_check: Literal["basic", "advanced"] = "basic"
    api_key_env_var: str = Field(
        default="CERTORAKEY",
        pattern=r"^[A-Z][A-Z0-9_]{0,63}$",
    )

    @field_validator("api_key_env_var")
    @classmethod
    def api_key_cannot_select_openrouter_control_plane_secret(cls, value: str) -> str:
        if value in RESERVED_OPERATOR_CONTROL_PLANE_NAMES:
            raise ValueError("Certora cannot use an operator control-plane variable")
        return value

    @field_validator("source")
    @classmethod
    def source_is_repository_relative_solidity(cls, value: str | None) -> str | None:
        return _configured_formal_path(value, suffix=".sol", label="Certora source")

    @field_validator("specification")
    @classmethod
    def specification_is_repository_relative_spec(cls, value: str | None) -> str | None:
        return _configured_formal_path(value, suffix=".spec", label="Certora specification")

    @field_validator("assumptions")
    @classmethod
    def assumptions_are_bounded_unique_and_sorted(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(
            not item or len(item) > 500 or "\x00" in item for item in normalized
        ) or normalized != sorted(set(normalized)):
            raise ValueError("Certora assumptions must be bounded, unique, and sorted")
        return normalized

    @model_validator(mode="after")
    def enabled_configuration_is_complete(self) -> CertoraConfig:
        if self.enabled and any(
            value is None
            for value in (
                self.cli_version,
                self.cli_sha256,
                self.source,
                self.contract,
                self.specification,
            )
        ):
            raise ValueError(
                "enabled Certora execution requires CLI trust pins, source, contract, "
                "and specification"
            )
        return self


def _configured_formal_path(
    value: str | None,
    *,
    suffix: str,
    label: str,
) -> str | None:
    if value is None:
        return None
    normalized = value.strip().replace("\\", "/")
    parts = normalized.split("/")
    if (
        not normalized
        or normalized.startswith(("/", "-", ".env"))
        or re.match(r"^[A-Za-z]:/", normalized)
        or any(part in {"", ".", ".."} for part in parts)
        or any(ord(character) < 32 or ord(character) == 127 for character in normalized)
        or not normalized.endswith(suffix)
    ):
        raise ValueError(f"{label} must be a safe repository-relative {suffix} path")
    return normalized


class FormalConfig(ConfigModel):
    enabled: bool = False
    timeout_seconds: float = Field(default=300, gt=0, le=3_600)
    max_output_bytes: int = Field(default=5_000_000, ge=10_000, le=100_000_000)
    required_tools: list[
        Literal[
            "solc-smtchecker",
            "mythril",
            "echidna",
            "medusa",
            "foundry-invariant",
            "halmos",
            "certora",
            "kontrol",
        ]
    ] = Field(default_factory=list)
    run_smtchecker: bool = True
    run_mythril: bool = True
    run_echidna: bool = True
    echidna_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    echidna_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    run_medusa: bool = True
    medusa_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    medusa_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    run_halmos: bool = True
    halmos_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    halmos_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    halmos_solver_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    halmos_solver_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    halmos_max_invariant_depth: int = Field(default=4, ge=1, le=32)
    halmos_loop_bound: int = Field(default=2, ge=1, le=32)
    halmos_max_width: int = Field(default=256, ge=1, le=10_000)
    halmos_max_path_depth: int = Field(default=512, ge=1, le=100_000)
    halmos_solver_timeout_seconds: float = Field(default=10, gt=0, le=300)
    halmos_solver_max_memory_mb: int = Field(default=2_048, ge=64, le=16_384)
    certora: CertoraConfig = Field(default_factory=CertoraConfig)
    run_kontrol: bool = True
    kontrol_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    kontrol_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    kontrol_max_depth: int = Field(default=1_000, ge=1, le=100_000)
    kontrol_max_iterations: int = Field(default=1_000, ge=1, le=100_000)

    @model_validator(mode="after")
    def executable_trust_pins_are_paired(self) -> FormalConfig:
        for label, version, sha256 in (
            ("Echidna", self.echidna_version, self.echidna_sha256),
            ("Medusa", self.medusa_version, self.medusa_sha256),
            ("Halmos", self.halmos_version, self.halmos_sha256),
            ("Halmos solver", self.halmos_solver_version, self.halmos_solver_sha256),
            ("Kontrol", self.kontrol_version, self.kontrol_sha256),
        ):
            if (version is None) != (sha256 is None):
                raise ValueError(f"{label} version and SHA-256 trust pins must be paired")
        return self


ModelQualityTier = Literal["standard", "high", "highest"]
ModelRetentionPolicy = Literal["zero", "temporary", "persistent"]

_MODEL_QUALITY_MINIMUM_SCORE: dict[str, float] = {
    "standard": 0.0,
    "high": 0.75,
    "highest": 0.9,
}
_MODEL_IDENTIFIER = re.compile(r"[^\s/]+/[^\s/]+")
_SHA256_IDENTIFIER = re.compile(r"sha256:[0-9a-f]{64}")
_PROVIDER_ENDPOINT_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")


class ModelLineageConfig(ConfigModel):
    """Immutable operator-reviewed identity, quality, and retention metadata."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    root_lineage: str
    canonical_model_id: str
    aliases: tuple[str, ...] = ()
    measured_quality_score: float = Field(ge=0, le=1)
    measured_quality_tier: ModelQualityTier
    quality_measurement: str
    retention_policy: ModelRetentionPolicy

    @field_validator("root_lineage", "quality_measurement")
    @classmethod
    def hashes_are_immutable_identifiers(cls, value: str) -> str:
        if not _SHA256_IDENTIFIER.fullmatch(value):
            raise ValueError(
                "lineage and quality measurements must be lowercase sha256 identifiers"
            )
        return value

    @field_validator("canonical_model_id")
    @classmethod
    def canonical_model_has_provider(cls, value: str) -> str:
        value = value.strip()
        if not _MODEL_IDENTIFIER.fullmatch(value):
            raise ValueError("canonical model IDs must use provider/model form")
        return value

    @field_validator("aliases")
    @classmethod
    def aliases_are_distinct_model_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        cleaned = tuple(value.strip() for value in values)
        lowered = [value.lower() for value in cleaned]
        if any(not _MODEL_IDENTIFIER.fullmatch(value) for value in cleaned):
            raise ValueError("model aliases must use provider/model form")
        if len(lowered) != len(set(lowered)):
            raise ValueError("model aliases must be unique")
        return cleaned

    @model_validator(mode="after")
    def measured_tier_matches_score(self) -> ModelLineageConfig:
        if self.canonical_model_id.lower() in {alias.lower() for alias in self.aliases}:
            raise ValueError("canonical model ID cannot also be an alias")
        minimum = _MODEL_QUALITY_MINIMUM_SCORE[self.measured_quality_tier]
        if self.measured_quality_score < minimum:
            raise ValueError(
                f"measured quality tier {self.measured_quality_tier} requires score >= {minimum}"
            )
        return self

    def model_ids(self) -> tuple[str, ...]:
        return (self.canonical_model_id, *self.aliases)


class ModelRoleConfig(ConfigModel):
    primary: str
    fallbacks: list[str] = Field(default_factory=list)
    quality_tier: ModelQualityTier = "standard"
    capabilities: list[
        Literal[
            "structured_json",
            "long_context",
            "security_reasoning",
            "solidity",
            "test_generation",
            "formal_reasoning",
        ]
    ] = ["structured_json"]

    @field_validator("primary")
    @classmethod
    def model_has_provider(cls, value: str) -> str:
        value = value.strip()
        if not value or "/" not in value:
            raise ValueError("model IDs must use OpenRouter's provider/model form")
        return value

    @field_validator("fallbacks")
    @classmethod
    def fallbacks_have_provider(cls, values: list[str]) -> list[str]:
        if any("/" not in value for value in values):
            raise ValueError("fallback model IDs must use provider/model form")
        return values


class ModelProviderPolicyConfig(ConfigModel):
    """Explicit OpenRouter endpoint routing policy with no implicit fallback."""

    only: tuple[str, ...] = ()
    order: tuple[str, ...] = ()
    allow_fallbacks: bool = False

    @field_validator("only", "order")
    @classmethod
    def provider_endpoints_are_exact_and_unique(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        cleaned = tuple(value.strip() for value in values)
        if any(not _PROVIDER_ENDPOINT_IDENTIFIER.fullmatch(value) for value in cleaned) or len(
            cleaned
        ) != len(set(cleaned)):
            raise ValueError("provider endpoint slugs must be exact, safe, and unique")
        return cleaned

    @model_validator(mode="after")
    def routing_modes_are_unambiguous(self) -> ModelProviderPolicyConfig:
        if self.only and self.order:
            raise ValueError("provider routing may configure only or order, not both")
        return self


class ModelReasoningConfig(ConfigModel):
    """Bounded provider reasoning controls applied only when configured."""

    effort: Literal["minimal", "low", "medium", "high", "xhigh"] | None = None
    max_tokens: int | None = Field(default=None, ge=1, le=65_536)
    exclude: bool = False

    @model_validator(mode="after")
    def reasoning_budget_mode_is_unambiguous(self) -> ModelReasoningConfig:
        if self.effort is not None and self.max_tokens is not None:
            raise ValueError("reasoning effort and max_tokens are mutually exclusive")
        return self


class ModelsConfig(ConfigModel):
    minimum_distinct_families: int = Field(default=3, ge=3)
    minimum_high_quality_slots: int = Field(default=0, ge=0, le=64)
    allow_non_independent_models: bool = False
    provider_policy: ModelProviderPolicyConfig = Field(default_factory=ModelProviderPolicyConfig)
    reasoning: ModelReasoningConfig = Field(default_factory=ModelReasoningConfig)
    registry: tuple[ModelLineageConfig, ...] = ()
    threat_model: ModelRoleConfig
    source_audit: ModelRoleConfig
    business_logic: ModelRoleConfig
    configuration: ModelRoleConfig
    verifier: ModelRoleConfig
    judge: ModelRoleConfig
    specialists: dict[str, ModelRoleConfig] = Field(default_factory=dict)

    @field_validator("registry")
    @classmethod
    def registry_has_unique_lineages_and_model_ids(
        cls,
        value: tuple[ModelLineageConfig, ...],
    ) -> tuple[ModelLineageConfig, ...]:
        roots = [entry.root_lineage for entry in value]
        if len(roots) != len(set(roots)):
            raise ValueError("model registry root lineages must be unique")
        model_ids = [model_id.lower() for entry in value for model_id in entry.model_ids()]
        if len(model_ids) != len(set(model_ids)):
            raise ValueError("model registry IDs and aliases must be globally unique")
        return value

    @field_validator("specialists")
    @classmethod
    def specialist_names_are_known(
        cls,
        value: dict[str, ModelRoleConfig],
    ) -> dict[str, ModelRoleConfig]:
        unknown = set(value) - set(ALL_SPECIALIST_ROLES)
        if unknown:
            raise ValueError("unknown specialist model roles: " + ", ".join(sorted(unknown)))
        return value

    def role(self, name: str) -> ModelRoleConfig:
        if name in ALL_MODEL_ROLES:
            value = getattr(self, name)
        elif name in self.specialists:
            value = self.specialists[name]
        else:
            raise KeyError(name)
        if not isinstance(value, ModelRoleConfig):
            raise TypeError(f"invalid model role {name}")
        return value


class ScannerConfig(ConfigModel):
    enabled: bool = True
    required: bool = False
    version: str | None = Field(
        default=None,
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def trust_pins_are_paired(self) -> ScannerConfig:
        if (self.version is None) != (self.sha256 is None):
            raise ValueError("scanner version and SHA-256 trust pins must be configured together")
        return self


class CodeQLConfig(ScannerConfig):
    enabled: bool = False
    database_path: str | None = None
    query_suite: str | None = None


class ScannersConfig(ConfigModel):
    semgrep: ScannerConfig = Field(default_factory=ScannerConfig)
    gitleaks: ScannerConfig = Field(default_factory=ScannerConfig)
    trivy: ScannerConfig = Field(default_factory=ScannerConfig)
    osv: ScannerConfig = Field(default_factory=ScannerConfig)
    codeql: CodeQLConfig = Field(default_factory=CodeQLConfig)
    slither: ScannerConfig = Field(default_factory=lambda: ScannerConfig(enabled=False))
    foundry_fork: ScannerConfig = Field(default_factory=lambda: ScannerConfig(enabled=False))


class ReportingConfig(ConfigModel):
    markdown: bool = True
    json_report: bool = Field(default=True, alias="json", serialization_alias="json")
    sarif: bool = True


class AuditConfig(ConfigModel):
    version: Literal[1] = 1
    profile: AuditProfile = AuditProfile.STANDARD
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    prior_audit: PriorAuditConfig = Field(default_factory=PriorAuditConfig)
    repository: RepositoryConfig = Field(default_factory=RepositoryConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    dependency_preparation: DependencyPreparationConfig = Field(
        default_factory=DependencyPreparationConfig
    )
    smart_contracts: SmartContractsConfig = Field(default_factory=SmartContractsConfig)
    reproduction: ReproductionConfig = Field(default_factory=ReproductionConfig)
    quality_gates: QualityGateConfig = Field(default_factory=QualityGateConfig)
    maximum_assurance: MaximumAssuranceConfig = Field(default_factory=MaximumAssuranceConfig)
    invariants: InvariantConfig = Field(default_factory=InvariantConfig)
    formal: FormalConfig = Field(default_factory=FormalConfig)
    models: ModelsConfig
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    def effective(self) -> AuditConfig:
        """Apply non-downgradable profile requirements to a validated config."""

        if self.profile is not AuditProfile.MAXIMUM_ASSURANCE:
            return self
        privacy = self.privacy.model_copy(update={"require_zdr": True})
        execution = self.execution.model_copy(update={"max_json_repair_attempts": 0})
        smart_contracts = self.smart_contracts.model_copy(
            update={
                "enabled": True,
                "compile": True,
                "fork_only": True,
            }
        )
        scope = self.scope.model_copy(
            update={
                "mode": AuditScope.FULL_PROTOCOL,
                "require_complete": True,
            }
        )
        reproduction = self.reproduction.model_copy(
            update={
                "enabled": True,
                "required_for_solidity": True,
                "require_hardened_isolation": True,
                "repetitions": max(3, self.reproduction.repetitions),
                "minimize": True,
            }
        )
        quality_gates = self.quality_gates.model_copy(
            update={
                "require_compilation": True,
                "require_slither": True,
                "require_fork_baseline": True,
                "require_candidate_reproduction": True,
                "require_all_model_roles": True,
                "min_indexed_contract_fraction": max(
                    0.95,
                    self.quality_gates.min_indexed_contract_fraction,
                ),
                "min_reviewed_entry_point_fraction": max(
                    0.90,
                    self.quality_gates.min_reviewed_entry_point_fraction,
                ),
                "min_reviewed_privileged_entry_point_fraction": 1.0,
                "min_reviewed_state_writing_function_fraction": max(
                    0.90,
                    self.quality_gates.min_reviewed_state_writing_function_fraction,
                ),
                "min_reviewed_high_value_path_fraction": 1.0,
                "min_classified_external_call_fraction": 1.0,
                "min_classified_asset_flow_fraction": 1.0,
                "min_modelled_storage_variable_fraction": max(
                    0.90,
                    self.quality_gates.min_modelled_storage_variable_fraction,
                ),
                "min_reproduction_attempt_fraction": 1.0,
                "min_invariant_execution_fraction": max(
                    0.80,
                    self.quality_gates.min_invariant_execution_fraction,
                ),
                "min_scanner_completion_fraction": 1.0,
                "min_model_role_completion_fraction": 1.0,
                "min_economic_template_execution_fraction": 1.0,
                "min_dependency_resolution_fraction": 1.0,
            }
        )
        maximum_assurance = self.maximum_assurance.model_copy(
            update={
                "minimum_model_families": max(
                    5,
                    self.maximum_assurance.minimum_model_families,
                ),
                "minimum_specialist_agents": max(
                    8,
                    self.maximum_assurance.minimum_specialist_agents,
                ),
                "require_reproduction_for_critical": True,
                "require_formal_or_reproduction_for_confirmed_critical": True,
                "benchmark_gate": True,
            }
        )
        invariants = self.invariants.model_copy(
            update={
                "enabled": True,
                "required": True,
                "execute_generated": True,
            }
        )
        formal = self.formal.model_copy(
            update={
                "enabled": True,
                "required_tools": sorted(
                    {
                        *self.formal.required_tools,
                        "echidna",
                        "medusa",
                        "halmos",
                    }
                ),
            }
        )
        models = self.models.model_copy(
            update={
                "minimum_distinct_families": (
                    self.models.minimum_distinct_families
                    if maximum_assurance.allow_downgrade
                    else max(5, self.models.minimum_distinct_families)
                ),
                "minimum_high_quality_slots": (
                    self.models.minimum_high_quality_slots
                    if maximum_assurance.allow_downgrade
                    else max(8, self.models.minimum_high_quality_slots)
                ),
                "provider_policy": self.models.provider_policy.model_copy(
                    update={"allow_fallbacks": False}
                ),
            }
        )
        scanners = self.scanners.model_copy(
            update={
                "slither": self.scanners.slither.model_copy(
                    update={
                        "enabled": True,
                        "required": (
                            self.scanners.slither.required or not maximum_assurance.allow_downgrade
                        ),
                    }
                ),
                "foundry_fork": self.scanners.foundry_fork.model_copy(
                    update={
                        "enabled": True,
                        "required": True,
                    }
                ),
            }
        )
        return self.model_copy(
            update={
                "scope": scope,
                "privacy": privacy,
                "execution": execution,
                "smart_contracts": smart_contracts,
                "reproduction": reproduction,
                "quality_gates": quality_gates,
                "maximum_assurance": maximum_assurance,
                "invariants": invariants,
                "formal": formal,
                "models": models,
                "scanners": scanners,
            }
        )

    def stable_hash(self) -> str:
        payload = self.model_dump(mode="json", by_alias=True)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()

    def model_hash(self) -> str:
        payload = self.models.model_dump(mode="json")
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


_PLACEHOLDER = re.compile(r"(provider|model[_-]?id|replace|example|your[_-])", re.IGNORECASE)


def model_family(model_id: str) -> str:
    """Return a conservative provider/lineage family for independence checks."""

    provider, model = model_id.lower().split("/", 1)
    model = re.sub(r"[:@].*$", "", model)
    tokens = [token for token in re.split(r"[-_.]", model) if token]
    lineage: list[str] = []
    for token in tokens:
        if token.isdigit() or re.fullmatch(r"v?\d+(?:\d+)?", token):
            break
        if re.fullmatch(r"\d{4,8}", token):
            break
        lineage.append(token)
        if len(lineage) == 2:
            break
    return f"{provider}/{'-'.join(lineage) if lineage else model}"


def configured_model_ids(config: AuditConfig, *, include_fallbacks: bool = False) -> list[str]:
    identifiers: list[str] = []
    for role in ALL_MODEL_ROLES:
        role_config = config.models.role(role)
        identifiers.append(role_config.primary)
        if include_fallbacks:
            identifiers.extend(role_config.fallbacks)
    for role in sorted(config.models.specialists):
        role_config = config.models.specialists[role]
        identifiers.append(role_config.primary)
        if include_fallbacks:
            identifiers.extend(role_config.fallbacks)
    return identifiers


def model_lineage_index(config: AuditConfig) -> dict[str, ModelLineageConfig]:
    """Map every canonical ID and alias to its immutable root-lineage record."""

    return {
        model_id.lower(): entry
        for entry in config.models.registry
        for model_id in entry.model_ids()
    }


def validate_model_independence(config: AuditConfig) -> list[str]:
    """Return validation errors for duplicates, placeholders, and model families."""

    errors: list[str] = []
    role_ids = {role: config.models.role(role).primary for role in ALL_MODEL_ROLES}
    placeholder_roles = [
        label
        for role in ALL_MODEL_ROLES
        for label, model in [
            (f"{role}.primary", config.models.role(role).primary),
            *[
                (f"{role}.fallbacks[{index}]", fallback)
                for index, fallback in enumerate(config.models.role(role).fallbacks)
            ],
        ]
        if _PLACEHOLDER.search(model)
    ]
    if placeholder_roles:
        errors.append(f"placeholder model IDs remain for: {', '.join(placeholder_roles)}")
    specialist_placeholders = [
        label
        for role, role_config in config.models.specialists.items()
        for label, model in [
            (f"specialists.{role}.primary", role_config.primary),
            *[
                (f"specialists.{role}.fallbacks[{index}]", fallback)
                for index, fallback in enumerate(role_config.fallbacks)
            ],
        ]
        if _PLACEHOLDER.search(model)
    ]
    if specialist_placeholders:
        errors.append(
            "placeholder specialist model IDs remain for: " + ", ".join(specialist_placeholders)
        )

    duplicates: dict[str, list[str]] = {}
    for role in ALL_MODEL_ROLES:
        role_config = config.models.role(role)
        duplicates.setdefault(role_config.primary.lower(), []).append(f"{role}.primary")
        for index, identifier in enumerate(role_config.fallbacks):
            duplicates.setdefault(identifier.lower(), []).append(f"{role}.fallbacks[{index}]")
    for role, role_config in config.models.specialists.items():
        duplicates.setdefault(role_config.primary.lower(), []).append(f"specialists.{role}.primary")
        for index, identifier in enumerate(role_config.fallbacks):
            duplicates.setdefault(identifier.lower(), []).append(
                f"specialists.{role}.fallbacks[{index}]"
            )
    repeated = [roles for roles in duplicates.values() if len(roles) > 1]
    if repeated and not config.models.allow_non_independent_models:
        errors.append(
            "duplicate configured model IDs are not allowed: "
            + "; ".join(", ".join(roles) for roles in repeated)
        )

    lineage_by_id = model_lineage_index(config)

    def root_lineage(model_id: str) -> str:
        entry = lineage_by_id.get(model_id.lower())
        if entry is not None:
            return entry.root_lineage
        return f"heuristic:{model_family(model_id)}"

    analysis_families = {
        root_lineage(role_ids[role])
        for role in ("threat_model", "source_audit", "business_logic", "configuration")
    } | {
        root_lineage(config.models.specialists[role].primary)
        for role in config.models.specialists
        if role in ALL_SPECIALIST_ROLES
    }
    required_families = config.models.minimum_distinct_families
    if (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        and not config.maximum_assurance.allow_downgrade
    ):
        required_families = max(
            required_families,
            config.maximum_assurance.minimum_model_families,
        )
    if (
        len(analysis_families) < required_families
        and not config.models.allow_non_independent_models
    ):
        errors.append(
            f"only {len(analysis_families)} independent analysis model families configured; "
            f"{required_families} required"
        )
    if (
        config.profile is AuditProfile.MAXIMUM_ASSURANCE
        and not config.maximum_assurance.allow_downgrade
    ):
        missing_specialists = set(ALL_SPECIALIST_ROLES) - set(config.models.specialists)
        if missing_specialists:
            errors.append(
                "maximum-assurance specialist roles are missing: "
                + ", ".join(sorted(missing_specialists))
            )
        high_quality_lineages = {
            root_lineage(role_config.primary)
            for role_config in [
                *(config.models.role(role) for role in ALL_MODEL_ROLES),
                *config.models.specialists.values(),
            ]
            if role_config.quality_tier in {"high", "highest"}
        }
        required_slots = max(
            config.models.minimum_high_quality_slots,
            config.maximum_assurance.minimum_specialist_agents,
        )
        if len(high_quality_lineages) < required_slots:
            errors.append(
                f"only {len(high_quality_lineages)} unique high-quality model slots "
                f"(root lineages) configured; {required_slots} required"
            )
    return errors


def _set_nested(data: dict[str, Any], path: tuple[str, ...], value: Any) -> None:
    current = data
    for part in path[:-1]:
        current = current.setdefault(part, {})
    current[path[-1]] = value


def _environment_overrides(data: dict[str, Any], environ: Mapping[str, str]) -> None:
    mappings: dict[str, tuple[tuple[str, ...], type[Any]]] = {
        "MMAUDIT_BUDGET_USD": (("execution", "budget_usd"), float),
        COST_LEDGER_PATH_VARIABLE: (("execution", "cost_ledger_path"), str),
        "MMAUDIT_CONCURRENCY": (("execution", "concurrency"), int),
        "MMAUDIT_MAX_REQUEST_BYTES": (("execution", "max_request_bytes"), int),
        "MMAUDIT_MAX_FILES": (("repository", "max_files"), int),
        "MMAUDIT_MAX_WALK_ENTRIES": (("repository", "max_walk_entries"), int),
        "MMAUDIT_MAX_FILE_BYTES": (("repository", "max_file_bytes"), int),
        "MMAUDIT_MAX_DISCOVERY_BYTES": (
            ("repository", "max_discovery_bytes"),
            int,
        ),
        "MMAUDIT_MAX_CONTEXT_BYTES": (
            ("repository", "max_total_context_bytes"),
            int,
        ),
        "MMAUDIT_ALLOW_CODE_EGRESS": (("privacy", "allow_code_egress"), bool),
        "MMAUDIT_REQUIRE_ZDR": (("privacy", "require_zdr"), bool),
        "MMAUDIT_ALLOW_FORK_PROBING": (("smart_contracts", "allow_fork_probing"), bool),
        "MMAUDIT_FORK_RPC_URL_ENV": (("smart_contracts", "fork_rpc_url_env"), str),
        "MMAUDIT_FOUNDRY_MATCH_PATH": (("smart_contracts", "foundry_match_path"), str),
        "MMAUDIT_SOLIDITY_COMPILE": (("smart_contracts", "compile"), bool),
        "MMAUDIT_SOLIDITY_ALLOW_NETWORK": (("smart_contracts", "allow_network"), bool),
        "MMAUDIT_SOLIDITY_PROJECT_ROOT": (("smart_contracts", "project_root"), str),
        "MMAUDIT_PROFILE": (("profile",), str),
        "MMAUDIT_SCOPE": (("scope", "mode"), str),
        "MMAUDIT_REQUIRE_COMPLETE_SCOPE": (("scope", "require_complete"), bool),
        "MMAUDIT_PRIOR_AUDIT_PATH": (("prior_audit", "path"), str),
        "MMAUDIT_REQUIRE_PRIOR_AUDIT": (("prior_audit", "required"), bool),
        "MMAUDIT_FAIL_ON_MISSED_PRIOR": (("prior_audit", "fail_on_missed"), bool),
        "MMAUDIT_FORK_BLOCK_NUMBER": (("reproduction", "pinned_block_number"), int),
        "MMAUDIT_FORK_CHAIN_ID": (("reproduction", "expected_chain_id"), int),
        "MMAUDIT_ROOTLESS_CONTAINER_IMAGE": (
            ("reproduction", "rootless_container_image"),
            str,
        ),
        "MMAUDIT_ROOTLESS_CONTAINER_RUNTIME": (
            ("reproduction", "rootless_container_runtime"),
            str,
        ),
    }
    for name, (path, kind) in mappings.items():
        if name not in environ:
            continue
        raw = environ[name]
        if kind is bool:
            lowered = raw.lower()
            if lowered not in {"true", "false", "1", "0", "yes", "no"}:
                raise ConfigError(f"{name} must be a boolean")
            parsed: Any = lowered in {"true", "1", "yes"}
        else:
            try:
                parsed = kind(raw)
            except ValueError as exc:
                raise ConfigError(f"invalid value for {name}") from exc
        _set_nested(data, path, parsed)


def load_config(
    path: Path | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> AuditConfig:
    """Load TOML configuration and documented environment overrides."""

    config_path = (path or Path(DEFAULT_CONFIG_NAME)).resolve()
    if not config_path.is_file():
        raise ConfigError(f"configuration file not found: {config_path}")
    try:
        with config_path.open("rb") as handle:
            raw: dict[str, Any] = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read configuration: {exc}") from exc
    _environment_overrides(raw, os.environ if environ is None else environ)
    try:
        return AuditConfig.model_validate(raw).effective()
    except ValidationError as exc:
        errors = []
        for error in exc.errors(include_url=False, include_context=False, include_input=False):
            location = ".".join(str(part) for part in error.get("loc", ())) or "configuration"
            errors.append(f"{location}: {error.get('msg', 'invalid value')}")
        raise ConfigError("invalid configuration: " + "; ".join(errors)) from exc
