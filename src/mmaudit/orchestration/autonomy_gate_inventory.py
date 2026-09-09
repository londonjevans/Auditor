"""Deterministic, nonauthorizing inventory of managed-run completion inputs.

Phase 0 does not automate any gate.  It discovers the closed configuration and
execution boundary, records the desired nonhuman disposition separately from the
current implementation state, and makes drift from the committed inventory fail
closed.  Discovery is local-only: it imports Python objects, inspects annotations,
AST, package resources, and packaging entrypoints, and reads the frozen public objective.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import textwrap
import tomllib
import types
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, get_args, get_origin

from pydantic import BaseModel, Field, TypeAdapter, field_validator, model_validator
from pydantic.fields import FieldInfo

from mmaudit.config import (
    _AUDIT_OVERRIDE_VALUE_TYPES,
    _ENVIRONMENT_OVERRIDE_MAPPINGS,
    AuditConfig,
    AuditRunOptions,
)
from mmaudit.models.schemas import StrictModel

AUTONOMY_INVENTORY_SCHEMA_VERSION = "1.0"
AUTONOMY_OBJECTIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
AUTONOMY_OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
AUTONOMY_INVENTORY_PATH = "docs/remediation/v3/autonomy_gate_inventory.json"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SOURCE_ID_PATTERN = r"^[a-z][a-z0-9_.:*\[\]-]{0,299}$"
_GATE_ID_PATTERN = r"^gate-[a-z0-9][a-z0-9-]{0,98}$"
_MAX_SOURCES = 8_192
_MAX_GATES = 128
_FROZEN_AUDIT_CONFIG_PATHS_SHA256 = (
    "9d419244ecac1ec4833d030836573f8269bf533a4946b3d243d3a0a6d4e1e759"
)
_FROZEN_AUDIT_RUN_OPTION_PATHS_SHA256 = (
    "f38d9261cd2d800e74e2ebeb73819e2d8bbcc0010ebd627a4a751aa68abf658a"
)
_FROZEN_AUDIT_OVERRIDE_PATHS_SHA256 = (
    "b15da15083f0e7fae393a05aabae3f1bee3bf408fda66a86ce2d6088c9abd3c7"
)
_FROZEN_ENVIRONMENT_OVERRIDE_PAIRS_SHA256 = (
    "9f4ff8a30f85a148c52b097ea7550a55efb8ee04815ef7563879c7a6281f8d23"
)
_FROZEN_CLI_RUN_PARAMETERS_SHA256 = (
    "cef83d47a117042e0edae8e40e0701d69114c221bc6d3e68288cb9a9835ba4cf"
)
_FROZEN_PIPELINE_INIT_PARAMETERS_SHA256 = (
    "4d68421ce51e4d2e429f3be0ea46d2f5cfe84eba2bfc33ea692fc14eb2b67277"
)
_FROZEN_PIPELINE_RUN_PARAMETERS_SHA256 = (
    "55123fbc974864c8cae44eef98ac34c9c46bb625ea6784420290870367fe4748"
)
_FROZEN_COMPLETION_ENTRYPOINT_PARAMETERS_SHA256 = (
    "d2480ffff787e69bdad9bb0ce39127beaada77cf84e971d9dd43cd586a2808c4"
)
_FROZEN_AUDITED_MODULE_PATHS_SHA256 = (
    "e7984ebb1875396cb25bbc7263f830edd7e506ce9eab0b36b2af31b8b9960211"
)
_FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256 = (
    "9cb8b25140d5e2d4da60801b6e51ada6fa931631f8db0f69a2d9a8f08e08da14"
)
_FROZEN_PROJECT_SCRIPTS_SHA256 = "9c597fa232065af210cc6b85424e2571d49c6b1ef941c5470602e916ab98c452"
_FROZEN_FILESYSTEM_INPUT_LOCI_SHA256 = (
    "96b3b5f33dd47ccdc8e19cd20597e34d606d2a308f68907da2482fe527198715"
)
_FROZEN_INTERACTIVE_INPUT_LOCI_SHA256 = (
    "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
)
_FROZEN_ENTROPY_INPUT_LOCI_SHA256 = (
    "2c6625ea6c47281deb350151cb369c8e2f08e0eee853fca319ff8bbcaef5a9fd"
)


class AutonomyInventoryError(ValueError):
    """Raised when the closed completion-input inventory cannot be proved."""


class CompletionInputSourceKind(StrEnum):
    """Closed authoritative source families scanned by Phase 0.

    ``DIRECT_ENVIRONMENT_INPUT`` retains the ticket vocabulary but covers the full
    ambient runtime boundary: process variables, executable resolution, home/cwd/temp
    roots, host/platform/process identity, Python runtime identity, and clock
    observations. ``ENTROPY_INPUT`` is the separately frozen finite set of random-value
    loci reviewed for completion-visible authority, resume, ledger, and replay effects.
    """

    AUDIT_CONFIG_LEAF = "AUDIT_CONFIG_LEAF"
    AUDIT_RUN_OPTION_LEAF = "AUDIT_RUN_OPTION_LEAF"
    AUDIT_OVERRIDE_PATH = "AUDIT_OVERRIDE_PATH"
    ENVIRONMENT_OVERRIDE = "ENVIRONMENT_OVERRIDE"
    CLI_RUN_PARAMETER = "CLI_RUN_PARAMETER"
    PIPELINE_INIT_PARAMETER = "PIPELINE_INIT_PARAMETER"
    PIPELINE_RUN_PARAMETER = "PIPELINE_RUN_PARAMETER"
    COMPLETION_ENTRYPOINT_PARAMETER = "COMPLETION_ENTRYPOINT_PARAMETER"
    DIRECT_ENVIRONMENT_INPUT = "DIRECT_ENVIRONMENT_INPUT"
    ENTROPY_INPUT = "ENTROPY_INPUT"
    AUDITED_MODULE_UNIVERSE = "AUDITED_MODULE_UNIVERSE"
    EXPLICIT_NON_FIELD_GATE = "EXPLICIT_NON_FIELD_GATE"
    REQUIRED_MISSING_GATE = "REQUIRED_MISSING_GATE"


class SourceCoverageClassification(StrEnum):
    """Why one discovered source is or is not a completion gate."""

    GATE = "GATE"
    NON_GATING_CONTROL = "NON_GATING_CONTROL"


class AutonomousGateDisposition(StrEnum):
    """The only objective-compatible desired dispositions."""

    AUTONOMOUS_EVIDENCE_SUBSTITUTE = "AUTONOMOUS_EVIDENCE_SUBSTITUTE"
    PREPROVISIONED_NONHUMAN_INPUT = "PREPROVISIONED_NONHUMAN_INPUT"
    PRERUN_CLIENT_DECISION = "PRERUN_CLIENT_DECISION"
    OBJECTIVE_OUT_OF_SCOPE = "OBJECTIVE_OUT_OF_SCOPE"


class GateImplementationState(StrEnum):
    """Current state, deliberately separate from desired disposition."""

    SATISFIED_AUTONOMOUS = "SATISFIED_AUTONOMOUS"
    SATISFIED_PREPROVISIONED = "SATISFIED_PREPROVISIONED"
    PARTIAL = "PARTIAL"
    CURRENT_MANUAL_INPUT = "CURRENT_MANUAL_INPUT"
    MISSING = "MISSING"
    OBJECTIVE_OUT_OF_SCOPE = "OBJECTIVE_OUT_OF_SCOPE"


_UNSATISFIED_STATES = frozenset(
    {
        GateImplementationState.PARTIAL,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        GateImplementationState.MISSING,
    }
)


class CompletionInputSourceCoverage(StrictModel):
    """One exact discovered input source and its exhaustive classification."""

    source_id: str = Field(pattern=_SOURCE_ID_PATTERN)
    source_kind: CompletionInputSourceKind
    source_path: str = Field(min_length=1, max_length=500)
    source_semantics_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_occurrence_count: int = Field(ge=1, le=32)
    classification: SourceCoverageClassification
    logical_gate_id: str | None = Field(default=None, pattern=_GATE_ID_PATTERN)

    @model_validator(mode="after")
    def gate_join_is_exact(self) -> CompletionInputSourceCoverage:
        if (self.classification is SourceCoverageClassification.GATE) != (
            self.logical_gate_id is not None
        ):
            raise ValueError("only GATE sources must name exactly one logical gate")
        return self


class AutonomousLogicalGate(StrictModel):
    """One logical gate with desired disposition and honest current state."""

    gate_id: str = Field(pattern=_GATE_ID_PATTERN)
    name: str = Field(min_length=1, max_length=200)
    integrity_property: str = Field(min_length=1, max_length=1_000)
    objective_citation: str = Field(min_length=1, max_length=200)
    desired_disposition: AutonomousGateDisposition
    implementation_state: GateImplementationState
    implementation_detail: str = Field(min_length=1, max_length=1_500)
    source_ids: tuple[str, ...] = Field(min_length=1, max_length=_MAX_SOURCES)

    @field_validator("source_ids")
    @classmethod
    def sources_are_sorted_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("logical-gate sources must be unique and sorted")
        return value

    @model_validator(mode="after")
    def out_of_scope_state_matches_disposition(self) -> AutonomousLogicalGate:
        expected = self.desired_disposition is AutonomousGateDisposition.OBJECTIVE_OUT_OF_SCOPE
        observed = self.implementation_state is GateImplementationState.OBJECTIVE_OUT_OF_SCOPE
        if expected != observed:
            raise ValueError("objective-out-of-scope disposition and state must agree")
        return self


class AutonomyGateInventory(StrictModel):
    """Self-hashed Phase-0 inventory; serialized bytes never grant authority."""

    schema_version: Literal["1.0"]
    artifact_kind: Literal["AUTONOMY_COMPLETION_INPUT_GATE_INVENTORY"]
    phase: Literal["PHASE_0_INVENTORY_ONLY"]
    status: Literal["PARTIAL_NONAUTHORIZING"]
    objective_path: Literal["docs/remediation/v3/product_completion_goal.txt"]
    objective_sha256: Literal["e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"]
    completion_scope: Literal["SYNTHETIC_PUBLIC_ONLY"]
    discovery_scope: Literal[
        "TYPED_BOUNDARIES_REGISTERED_ENTRYPOINTS_RUNTIME_PACKAGE_RESOURCES_"
        "UNSEALED_ENV_HOST_WALL_CLOCK_AUTHORITY_ENTROPY_FILESYSTEM_INTERACTIVE_"
        "OPAQUE_AUTHORITIES_"
        "EXPLICIT_MISSING_OBJECTIVE_BOUNDARIES"
    ]
    private_repository_completion_in_scope: Literal[False]
    source_discovery_semantics_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_universe_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_coverage: tuple[CompletionInputSourceCoverage, ...] = Field(
        min_length=1,
        max_length=_MAX_SOURCES,
    )
    logical_gates: tuple[AutonomousLogicalGate, ...] = Field(
        min_length=1,
        max_length=_MAX_GATES,
    )
    source_count: int = Field(ge=1, le=_MAX_SOURCES)
    source_occurrence_count: int = Field(ge=1, le=_MAX_SOURCES)
    audit_config_leaf_locator_count: Literal[513]
    audit_config_leaf_occurrence_count: Literal[516]
    audit_config_shared_locator_count: Literal[3]
    audit_run_option_leaf_count: Literal[16]
    audit_override_path_count: Literal[51]
    environment_override_count: Literal[28]
    cli_run_parameter_count: Literal[53]
    pipeline_init_parameter_count: Literal[29]
    pipeline_run_parameter_count: Literal[16]
    completion_entrypoint_parameter_count: Literal[355]
    source_kind_counts: dict[CompletionInputSourceKind, int] = Field(
        min_length=len(CompletionInputSourceKind),
        max_length=len(CompletionInputSourceKind),
    )
    gate_source_count: int = Field(ge=1, le=_MAX_SOURCES)
    logical_gate_count: int = Field(ge=1, le=_MAX_GATES)
    unsatisfied_gate_count: int = Field(ge=1, le=_MAX_GATES)
    current_manual_gate_count: int = Field(ge=1, le=_MAX_GATES)
    provider_or_network_accessed: Literal[False]
    secret_material_read: Literal[False]
    runtime_authority: Literal[False]
    managed_run_ready: Literal[False]
    inventory_sha256: str = Field(pattern=_SHA256_PATTERN)

    @field_validator("source_coverage")
    @classmethod
    def source_coverage_is_canonical(
        cls,
        value: tuple[CompletionInputSourceCoverage, ...],
    ) -> tuple[CompletionInputSourceCoverage, ...]:
        source_ids = tuple(item.source_id for item in value)
        if source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("source coverage must be unique and sorted")
        return value

    @field_validator("logical_gates")
    @classmethod
    def logical_gates_are_canonical(
        cls,
        value: tuple[AutonomousLogicalGate, ...],
    ) -> tuple[AutonomousLogicalGate, ...]:
        gate_ids = tuple(item.gate_id for item in value)
        if gate_ids != tuple(sorted(set(gate_ids))):
            raise ValueError("logical gates must be unique and sorted")
        return value

    @model_validator(mode="after")
    def joins_counts_and_hashes_are_exact(self) -> AutonomyGateInventory:
        sources = {item.source_id: item for item in self.source_coverage}
        gates = {item.gate_id: item for item in self.logical_gates}
        if self.source_count != len(sources):
            raise ValueError("source count is inconsistent")
        if self.source_occurrence_count != sum(
            item.source_occurrence_count for item in self.source_coverage
        ):
            raise ValueError("source occurrence count is inconsistent")
        expected_kind_counts = {
            kind: sum(item.source_kind is kind for item in self.source_coverage)
            for kind in CompletionInputSourceKind
        }
        if self.source_kind_counts != expected_kind_counts:
            raise ValueError("source-kind counts are inconsistent or incomplete")
        if (
            self.audit_config_leaf_locator_count
            != expected_kind_counts[CompletionInputSourceKind.AUDIT_CONFIG_LEAF]
        ):
            raise ValueError("AuditConfig leaf-locator count is inconsistent")
        config_occurrences = sum(
            item.source_occurrence_count
            for item in self.source_coverage
            if item.source_kind is CompletionInputSourceKind.AUDIT_CONFIG_LEAF
        )
        if self.audit_config_leaf_occurrence_count != config_occurrences:
            raise ValueError("AuditConfig leaf-occurrence count is inconsistent")
        if self.audit_config_shared_locator_count != sum(
            item.source_occurrence_count > 1
            for item in self.source_coverage
            if item.source_kind is CompletionInputSourceKind.AUDIT_CONFIG_LEAF
        ):
            raise ValueError("AuditConfig shared-locator count is inconsistent")
        declared_fixed_kind_counts = {
            CompletionInputSourceKind.AUDIT_RUN_OPTION_LEAF: self.audit_run_option_leaf_count,
            CompletionInputSourceKind.AUDIT_OVERRIDE_PATH: self.audit_override_path_count,
            CompletionInputSourceKind.ENVIRONMENT_OVERRIDE: self.environment_override_count,
            CompletionInputSourceKind.CLI_RUN_PARAMETER: self.cli_run_parameter_count,
            CompletionInputSourceKind.PIPELINE_INIT_PARAMETER: (self.pipeline_init_parameter_count),
            CompletionInputSourceKind.PIPELINE_RUN_PARAMETER: self.pipeline_run_parameter_count,
            CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER: (
                self.completion_entrypoint_parameter_count
            ),
        }
        for kind, declared_count in declared_fixed_kind_counts.items():
            if declared_count != expected_kind_counts[kind]:
                raise ValueError(f"{kind.value} count is inconsistent")
        gate_sources = {
            item.source_id
            for item in self.source_coverage
            if item.classification is SourceCoverageClassification.GATE
        }
        if self.gate_source_count != len(gate_sources):
            raise ValueError("gate-source count is inconsistent")
        if self.logical_gate_count != len(gates):
            raise ValueError("logical-gate count is inconsistent")
        if {gate.desired_disposition for gate in self.logical_gates} != set(
            AutonomousGateDisposition
        ):
            raise ValueError("the exact four desired dispositions must all be represented")
        assigned: list[str] = []
        for gate in self.logical_gates:
            for source_id in gate.source_ids:
                source = sources.get(source_id)
                if source is None:
                    raise ValueError("logical gate references an unknown source")
                if source.classification is not SourceCoverageClassification.GATE:
                    raise ValueError("logical gate references a non-gate source")
                if source.logical_gate_id != gate.gate_id:
                    raise ValueError("source and logical-gate joins disagree")
                assigned.append(source_id)
        if len(assigned) != len(set(assigned)):
            raise ValueError("a gate source has multiple logical-gate assignments")
        if set(assigned) != gate_sources:
            raise ValueError("a gate source is unclassified")
        unsatisfied = sum(
            gate.implementation_state in _UNSATISFIED_STATES for gate in self.logical_gates
        )
        if self.unsatisfied_gate_count != unsatisfied or unsatisfied == 0:
            raise ValueError("unsatisfied gate count is inconsistent or falsely zero")
        current_manual = sum(
            gate.implementation_state is GateImplementationState.CURRENT_MANUAL_INPUT
            for gate in self.logical_gates
        )
        if self.current_manual_gate_count != current_manual or current_manual == 0:
            raise ValueError("current manual gate count is inconsistent or falsely zero")
        expected_universe = _canonical_sha256(
            [
                {
                    "source_id": item.source_id,
                    "source_kind": item.source_kind.value,
                    "source_path": item.source_path,
                    "source_semantics_sha256": item.source_semantics_sha256,
                    "source_occurrence_count": item.source_occurrence_count,
                }
                for item in self.source_coverage
            ]
        )
        if self.source_universe_sha256 != expected_universe:
            raise ValueError("source-universe hash is inconsistent")
        current_discovery_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        if self.source_discovery_semantics_sha256 != current_discovery_hash:
            raise ValueError("source-discovery semantics differ from this implementation")
        expected_inventory = _canonical_sha256(
            self.model_dump(mode="json", exclude={"inventory_sha256"})
        )
        if self.inventory_sha256 != expected_inventory:
            raise ValueError("autonomy inventory self-hash is inconsistent")
        return self


class _GateSpec(StrictModel):
    gate_id: str
    name: str
    integrity_property: str
    objective_citation: str
    desired_disposition: AutonomousGateDisposition
    implementation_state: GateImplementationState
    implementation_detail: str


class _SourceDraft(StrictModel):
    source_id: str
    source_kind: CompletionInputSourceKind
    source_path: str
    source_semantics_sha256: str
    source_occurrence_count: int = 1
    classification: SourceCoverageClassification
    logical_gate_id: str | None = None


def _gate(
    gate_id: str,
    name: str,
    integrity_property: str,
    objective_citation: str,
    disposition: AutonomousGateDisposition,
    state: GateImplementationState,
    detail: str,
) -> _GateSpec:
    return _GateSpec(
        gate_id=gate_id,
        name=name,
        integrity_property=integrity_property,
        objective_citation=objective_citation,
        desired_disposition=disposition,
        implementation_state=state,
        implementation_detail=detail,
    )


_GATE_SPECS = (
    _gate(
        "gate-authenticated-real-campaign",
        "Authenticated synthetic/public model campaign",
        "REAL campaign inputs, route evidence, spend, and outputs must be exact and replayable.",
        "objective:4,5,6(L,S)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "The authenticated runner remains a separately launched operator workflow; no managed run "
        "entry point owns the complete campaign.",
    ),
    _gate(
        "gate-autonomous-model-authority",
        "Evidence-sealed model lineage, qualification, and selection",
        "No model self-qualifies and same-root judging cannot authorize completion.",
        "objective:2,3,7",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.PARTIAL,
        "Provider-free lineage and authority mechanisms exist, but externally anchored REAL "
        "qualification and runtime authority are not complete.",
    ),
    _gate(
        "gate-benchmark-evidence-authority",
        "Frozen benchmark and superiority evidence",
        "Benchmark credit must bind frozen truth, exact reports, and cross-lineage adjudication.",
        "objective:2,3,6(R)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Benchmark evaluation, certification, and verification remain separate explicit commands.",
    ),
    _gate(
        "gate-budget-ceiling",
        "Autonomous USD and token ceilings",
        "Spend must stop below the frozen ceiling and every provider call must reconcile.",
        "objective:5,6(M)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.SATISFIED_AUTONOMOUS,
        "Bounded budgets and fail-closed reconciliation are implemented; managed provisioning is "
        "tracked separately.",
    ),
    _gate(
        "gate-client-audit-scope",
        "Purchase-bound audit scope and authorization",
        "The audited source, language, requested depth, and deployment boundary must be explicit.",
        "objective:1,4,8",
        AutonomousGateDisposition.PRERUN_CLIENT_DECISION,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Scope is currently supplied through files and command options rather than a purchase-bound "
        "client intake record.",
    ),
    _gate(
        "gate-client-privacy-consent",
        "Purchase-bound privacy, egress, and retention decision",
        "Egress and retention posture must be explicit, immutable, and bound to the audit.",
        "objective:4",
        AutonomousGateDisposition.PRERUN_CLIENT_DECISION,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "The CLI still accepts per-run acknowledgements and an operator-authored consent file.",
    ),
    _gate(
        "gate-codeql-provisioning",
        "Prebuilt CodeQL database and query suite",
        "CodeQL analysis must use the intended database and reviewed query suite or fail closed.",
        "objective:1,6(J/K)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Database and query-suite paths remain operator-configured inputs.",
    ),
    _gate(
        "gate-cost-ledger-provisioning",
        "Existing cumulative cost ledger",
        "A one-time initialized, private, exact ledger must exist before any paid request.",
        "objective:5",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Ledger enforcement exists, but initialization and selection are separate operator actions.",
    ),
    _gate(
        "gate-dependency-snapshot",
        "Reviewed dependency snapshot",
        "Dependency preparation must consume a hash-bound, bounded, offline snapshot.",
        "objective:1,6(J/K)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Local archive construction, automatic config handoff and private receipt verification exist; "
        "archive/advisory distribution, feed assurance and full managed execution remain external.",
    ),
    _gate(
        "gate-forensic-export-consent",
        "Sensitive forensic evidence delivery consent",
        "Private or sensitive evidence cannot be exported without the bound client's decision.",
        "objective:4,6(V)",
        AutonomousGateDisposition.PRERUN_CLIENT_DECISION,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Forensic export and verification still require a per-command acknowledgement.",
    ),
    _gate(
        "gate-external-transparency-seal",
        "Externally anchored append-only authority seal",
        "Authority requires external append-only publication plus independently verifiable "
        "inclusion and consistency evidence; a local digest or checkpoint is insufficient.",
        "objective:2,6(U,V)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.MISSING,
        "No externally published transparency receipt or inclusion/consistency proof can "
        "currently authorize runtime completion.",
    ),
    _gate(
        "gate-formal-analysis",
        "Required formal-engine execution",
        "Every required formal engine and check must run or create an explicit incomplete result.",
        "objective:1,6(J/K,S)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.PARTIAL,
        "Typed formal controls exist, but managed engines and all required execution evidence are "
        "not provisioned end to end.",
    ),
    _gate(
        "gate-fork-environment",
        "Pinned local fork environment",
        "Fork probing must use a local endpoint, exact chain and block, and explicit capability.",
        "objective:1,6(J/K,S)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Declared offline primary Foundry, reproduction, invariant and matrix reads have managed "
        "preparation and owned leases; Hardhat consumers, supported local-RPC isolation and source "
        "authority remain external.",
    ),
    _gate(
        "gate-full-quality-analysis",
        "Maximum-assurance full-analysis floor",
        "No required scanner, role, suite, reproduction, invariant, or coverage floor may be skipped.",
        "objective:1,6(S,U),7",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.PARTIAL,
        "Many fail-closed floors exist, but the managed profile and all REAL prerequisites do not.",
    ),
    _gate(
        "gate-human-signoff-boundary",
        "Human signature and sign-off boundary",
        "Human approval cannot become a completion prerequisite.",
        "objective:2,8",
        AutonomousGateDisposition.OBJECTIVE_OUT_OF_SCOPE,
        GateImplementationState.OBJECTIVE_OUT_OF_SCOPE,
        "The frozen objective explicitly replaces signer authority and excludes human sign-off.",
    ),
    _gate(
        "gate-invariant-template-library",
        "Hash-pinned invariant template library",
        "Only template-derived, pre-reviewed typed harnesses may execute without human review.",
        "objective:1,6(J/K,S),7",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.MISSING,
        "Typed harness validation exists, but a reviewed versioned template library and derivation "
        "proof do not.",
    ),
    _gate(
        "gate-managed-completion-entrypoint",
        "Zero-operator completion workflow",
        "One managed workflow must own campaign, audit, benchmark, seal, validation, and release.",
        "objective:1,6(U,V)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.MISSING,
        "Objective-required commands remain separate and no zero-input managed orchestration path "
        "exists.",
    ),
    _gate(
        "gate-managed-output-provisioning",
        "Private output and resume-state provisioning",
        "Fresh output, durable state, and resume inputs must be safely prepared and verified.",
        "objective:1,6(U,V)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Output parents and any resume state are still supplied externally for each command.",
    ),
    _gate(
        "gate-managed-profile",
        "Immutable managed configuration profile",
        "Completion inputs must resolve from one versioned profile without per-run overrides.",
        "objective:1,6(U)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.MISSING,
        "Configuration provenance is strict, but no immutable managed profile bundles every input.",
    ),
    _gate(
        "gate-managed-provisioning",
        "Idempotent auditable provisioning",
        "Every pre-run dependency must be provisioned and verified before spend.",
        "objective:1,5,6(U)",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.PARTIAL,
        "Typed local setup binds the bounded audited-workspace content inventory, creates or "
        "reopens the exact cumulative ledger, preserves portfolio holds, and prepares explicit "
        "offline dependency material. Its API can also materialize pinned direct host files and "
        "hand verified paths and a shared derived config to existing consumers. Fork, CodeQL, "
        "complete installed dependency/image closure, independent trust and a managed audit "
        "remain unverified; provisioning and managed-run authority stay false.",
    ),
    _gate(
        "gate-managed-toolchain-bundle",
        "Versioned managed toolchain bundle",
        "Every executable and image must retain exact identity and per-run verification.",
        "objective:1,6(J/K/S),7",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.PARTIAL,
        "A nonauthorizing catalog/config projection binds 28 managed roles. Bounded offline setup "
        "materializes pinned direct host files with exact repeat verification and shared derived "
        "config. Scanner paths, runtime clones and explicit Slither/Foundry compilers retain pins "
        "without ambient fallback. Built-in launchers use bounded identity observations through "
        "mandatory probes and identity-bound process-local seals. Matching-Linux construction "
        "selects pinned Bubblewrap and exposes only reverified material read-only. Compiler, formal, "
        "local-invariant and reproduction consumers accept prepared paths, fixed commands, isolated "
        "version checks and retained identities. Reproduction still requires acknowledgment, "
        "chain/block pins and compatible loopback isolation. Pipeline composition shares material "
        "and one backend, with config/tool/consumer drift guards. Local controls prove no real "
        "engine, fork or Linux execution. Doctor, unattended provisioning and fork-matrix "
        "handoffs remain incomplete; operating-system probe helpers remain unmodeled. External "
        "production pins, independent bundle trust, "
        "architecture, transitive dependency/image closure, atomic execution custody and full "
        "installed-process verification remain unverified; managed readiness stays false.",
    ),
    _gate(
        "gate-private-repository-boundary",
        "Private-repository completion boundary",
        "Private source must not be required or silently egressed for objective completion.",
        "objective:4,8",
        AutonomousGateDisposition.OBJECTIVE_OUT_OF_SCOPE,
        GateImplementationState.OBJECTIVE_OUT_OF_SCOPE,
        "Private-repository auditing is explicitly opt-in and outside completion.",
    ),
    _gate(
        "gate-provider-secret-transport",
        "Provider secret transport",
        "Provider credentials must be pre-supplied without entering artifacts or inventory reads.",
        "objective:4",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "The safe secrets-env-file transport exists, but each external launch still supplies it.",
    ),
    _gate(
        "gate-release-evidence-pipeline",
        "Evidence-sealed validation and release",
        "Release must bind complete verified evidence with no human sign-off.",
        "objective:2,6(T,U,V)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Verification, certification, export, and release observations remain separate commands.",
    ),
    _gate(
        "gate-runtime-package-integrity",
        "Hash-bound runtime package code and resources",
        "Every installed executable module, prompt, rule, reporter, template, and runtime resource "
        "must match the reviewed package payload used for completion.",
        "objective:1,2,6(J,K,S,U,V),7",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.PARTIAL,
        "Phase 0 binds the complete source-package payload, but the installed distribution is not "
        "yet independently measured and enforced by a managed run.",
    ),
    _gate(
        "gate-report-delivery",
        "Required client and machine-readable reports",
        "A managed run must publish every required bounded deliverable or remain incomplete.",
        "objective:6(U,V)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.SATISFIED_AUTONOMOUS,
        "Typed report and manifest completeness gates exist; managed orchestration is separate.",
    ),
    _gate(
        "gate-reproduction-capability-policy",
        "Bounded reproduction capability policy",
        "Dynamic validation may use only declared, bounded, local defensive capabilities.",
        "objective:1,6(J/K/S),7",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Capability validation is implemented, while deployment-specific allowlists remain authored "
        "in each configuration.",
    ),
    _gate(
        "gate-reproduction-target-derivation",
        "Deterministic reproduction targets",
        "Target aliases must derive from declared deployment evidence or audited source.",
        "objective:1,6(J/K/S)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.MISSING,
        "Targets are literal configuration values; no complete deterministic derivation exists.",
    ),
    _gate(
        "gate-saas-liability-boundary",
        "SaaS and liability claim boundary",
        "Claims beyond the conservative CLI-release ADR cannot gate completion.",
        "objective:6(T),8",
        AutonomousGateDisposition.OBJECTIVE_OUT_OF_SCOPE,
        GateImplementationState.OBJECTIVE_OUT_OF_SCOPE,
        "The frozen objective explicitly excludes broader SaaS and liability claims.",
    ),
    _gate(
        "gate-secret-redaction-policy",
        "Secret detection, redaction, and raw-storage policy",
        "Detected secret material and raw provider content must not leak into deliverables.",
        "objective:4,7",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.SATISFIED_AUTONOMOUS,
        "Fail-closed secret detection and explicit raw-storage controls are implemented.",
    ),
    _gate(
        "gate-snapshot-intake-consent",
        "Read-only deployment snapshot intake",
        "Snapshot observation must remain authorized, allowlisted, read-only, and locally bounded.",
        "objective:1,4,6(J/K)",
        AutonomousGateDisposition.PRERUN_CLIENT_DECISION,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "Snapshot import still requires an explicit per-command acknowledgement.",
    ),
    _gate(
        "gate-synthetic-public-scope",
        "Synthetic/public completion-source boundary",
        "Completion evidence must use only synthetic or public sources and never private egress.",
        "objective:4,6,8",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.PARTIAL,
        "Typed source classifications exist, but the stock run defaults to private operator source "
        "and no managed completion profile fixes the objective scope end to end.",
    ),
    _gate(
        "gate-trivy-database-provisioning",
        "Offline Trivy vulnerability database",
        "Trivy must use a prepared offline vulnerability database and must never download one "
        "inside the audit path.",
        "objective:1,6(J/K/S),7",
        AutonomousGateDisposition.PREPROVISIONED_NONHUMAN_INPUT,
        GateImplementationState.CURRENT_MANUAL_INPUT,
        "The scanner fails closed and names an operator preparation step, but no managed "
        "provisioning-state proof supplies the offline database.",
    ),
    _gate(
        "gate-trusted-time-independent-replay",
        "Trusted-time independent exact replay",
        "Authority must bind an external trusted-time basis and an independently operated exact "
        "rerun whose custody is not controlled by the audited run.",
        "objective:2,3,6(U,V)",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.MISSING,
        "No trusted clock observation or independently operated exact rerun can currently grant "
        "runtime completion authority.",
    ),
    _gate(
        "gate-unresolved-finding-disposition",
        "Autonomous terminal finding disposition",
        "A COMPLETE run cannot retain an ordinary finding that explicitly requires human resolution.",
        "objective:1,3,6(N,S,U,V),8",
        AutonomousGateDisposition.AUTONOMOUS_EVIDENCE_SUBSTITUTE,
        GateImplementationState.MISSING,
        "Consensus can emit NEEDS_REVIEW and reports request human resolution; no general COMPLETE "
        "validator forces autonomous terminal resolution or an incomplete run.",
    ),
)
_GATE_SPEC_BY_ID = {item.gate_id: item for item in _GATE_SPECS}
if len(_GATE_SPEC_BY_ID) != len(_GATE_SPECS):  # pragma: no cover - import-time invariant
    raise RuntimeError("autonomy logical-gate IDs are not unique")


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _assert_frozen_source_shape(
    *,
    label: str,
    observed: object,
    expected_sha256: str,
) -> None:
    if _canonical_sha256(observed) != expected_sha256:
        raise AutonomyInventoryError(f"{label} source shape drifted from the closed inventory")


def _normalized_ast(value: Any) -> str:
    """Return location-free AST for a callable/class, with a deterministic fallback."""

    try:
        source = inspect.getsource(value)
    except (OSError, TypeError):
        return repr(value)
    parsed = ast.parse(textwrap.dedent(source))
    return ast.dump(parsed, annotate_fields=True, include_attributes=False)


def _qualified_name(value: object) -> str:
    module = getattr(value, "__module__", type(value).__module__)
    qualname = getattr(value, "__qualname__", type(value).__qualname__)
    return f"{module}.{qualname}"


def _canonical_default(value: object, *, repository_root: Path | None = None) -> object:
    if value is inspect.Parameter.empty:
        return {"kind": "NO_DEFAULT"}
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, Path):
        if repository_root is not None and value.is_absolute():
            try:
                repository_path = value.relative_to(repository_root)
            except ValueError:
                pass
            else:
                return {"repository_path": repository_path.as_posix()}
        return {"path": value.as_posix()}
    if isinstance(value, StrEnum):
        return {"enum": _qualified_name(type(value)), "value": value.value}
    if isinstance(value, tuple):
        return [_canonical_default(item, repository_root=repository_root) for item in value]
    if isinstance(value, frozenset):
        return sorted(
            (_canonical_default(item, repository_root=repository_root) for item in value),
            key=_canonical_json,
        )
    return {"type": _qualified_name(value), "repr": repr(value)}


def _annotation_descriptor(annotation: object) -> object:
    origin = get_origin(annotation)
    if origin is Annotated:
        base, *metadata = get_args(annotation)
        return {
            "origin": "typing.Annotated",
            "base": _annotation_descriptor(base),
            "metadata": [_metadata_descriptor(item) for item in metadata],
        }
    if origin is not None:
        return {
            "origin": _qualified_name(origin),
            "args": [_annotation_descriptor(item) for item in get_args(annotation)],
        }
    if annotation is None:
        return "None"
    if isinstance(annotation, type):
        return _qualified_name(annotation)
    return repr(annotation)


def _metadata_descriptor(value: object) -> object:
    attributes: dict[str, object] = {}
    for name in (
        "param_decls",
        "min",
        "max",
        "help",
        "hidden",
        "case_sensitive",
        "show_default",
    ):
        candidate = getattr(value, name, None)
        if candidate is None or type(candidate) not in {bool, int, float, str, tuple, list}:
            continue
        attributes[name] = _canonical_default(
            tuple(candidate) if isinstance(candidate, list) else candidate
        )
    return {"type": _qualified_name(value), "attributes": attributes}


def _field_descriptor(field: FieldInfo, owner: type[BaseModel]) -> dict[str, object]:
    try:
        validation_schema: object = TypeAdapter(field.rebuild_annotation()).json_schema()
    except (TypeError, ValueError):
        validation_schema = _annotation_descriptor(field.rebuild_annotation())
    default_factory = field.default_factory
    if field.is_required():
        default: object = {"kind": "REQUIRED"}
    elif default_factory is not None:
        default = {"kind": "FACTORY", "callable": _qualified_name(default_factory)}
    else:
        default = _canonical_default(field.default)
    return {
        "owner": _qualified_name(owner),
        "owner_semantics_sha256": hashlib.sha256(_normalized_ast(owner).encode()).hexdigest(),
        "validation_schema": validation_schema,
        "default": default,
    }


def _nested_model_paths(annotation: object) -> tuple[tuple[str, type[BaseModel]], ...]:
    """Return normalized container markers and every nested Pydantic model branch."""

    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return (("", annotation),)
    origin = get_origin(annotation)
    args = get_args(annotation)
    if origin in {types.UnionType, None}:
        if origin is None:
            return ()
        nested: list[tuple[str, type[BaseModel]]] = []
        for argument in args:
            nested.extend(_nested_model_paths(argument))
        return tuple(dict.fromkeys(nested))
    if origin in {list, tuple, set, frozenset, Sequence}:
        nested = []
        for argument in args:
            if argument is Ellipsis:
                continue
            nested.extend((f"[]{marker}", model) for marker, model in _nested_model_paths(argument))
        return tuple(dict.fromkeys(nested))
    if origin in {dict, Mapping} and len(args) == 2:
        return tuple((f".*{marker}", model) for marker, model in _nested_model_paths(args[1]))
    nested = []
    for argument in args:
        nested.extend(_nested_model_paths(argument))
    return tuple(dict.fromkeys(nested))


def _discover_model_leaf_details(
    model: type[BaseModel],
) -> tuple[tuple[str, str, int], ...]:
    """Recursively discover exact leaf paths, semantics, and union occurrences."""

    leaves: list[tuple[str, str]] = []

    def walk(
        current: type[BaseModel],
        prefix: str,
        ancestry: tuple[dict[str, object], ...],
        active: tuple[type[BaseModel], ...],
    ) -> None:
        if current in active:
            raise AutonomyInventoryError("recursive AuditConfig model is unsupported")
        for field_name, field in current.model_fields.items():
            base_path = f"{prefix}.{field_name}" if prefix else field_name
            descriptor = _field_descriptor(field, current)
            nested = _nested_model_paths(field.annotation)
            if nested:
                for marker, child in nested:
                    walk(child, f"{base_path}{marker}", (*ancestry, descriptor), (*active, current))
                continue
            semantics = _canonical_sha256(
                {
                    "path": base_path,
                    "ancestry": [*ancestry, descriptor],
                }
            )
            leaves.append((base_path, semantics))

    walk(model, "", (), ())
    occurrences: dict[str, list[str]] = {}
    for path, semantics in leaves:
        occurrences.setdefault(path, []).append(semantics)
    # Discriminated-union branches intentionally share three public locators.  Preserve
    # every branch's semantics while exposing one canonical configurable path.
    return tuple(
        (
            path,
            values[0]
            if len(values) == 1
            else _canonical_sha256(
                {
                    "path": path,
                    "union_branch_semantics_sha256s": sorted(values),
                }
            ),
            len(values),
        )
        for path, values in sorted(occurrences.items())
    )


def discover_audit_config_leaves(
    model: type[BaseModel] = AuditConfig,
) -> tuple[tuple[str, str], ...]:
    """Recursively discover exact leaf paths and semantics across unions/containers."""

    return tuple((path, semantics) for path, semantics, _ in _discover_model_leaf_details(model))


def _callable_parameter_sources(
    value: Callable[..., object],
    *,
    source_kind: CompletionInputSourceKind,
    prefix: str,
    repository_root: Path | None = None,
) -> tuple[tuple[str, str, str], ...]:
    callable_hash = hashlib.sha256(_normalized_ast(value).encode("utf-8")).hexdigest()
    result: list[tuple[str, str, str]] = []
    for parameter in inspect.signature(value).parameters.values():
        if parameter.name in {"self", "cls"}:
            continue
        source_path = f"{_qualified_name(value)}:{parameter.name}"
        semantics = _canonical_sha256(
            {
                "callable": _qualified_name(value),
                "callable_semantics_sha256": callable_hash,
                "parameter": parameter.name,
                "kind": parameter.kind.name,
                "annotation": _annotation_descriptor(parameter.annotation),
                "default": _canonical_default(
                    parameter.default,
                    repository_root=repository_root,
                ),
            }
        )
        result.append((f"{prefix}:{parameter.name}", source_path, semantics))
    ordered = tuple(sorted(result))
    if len(ordered) != len({item[0] for item in ordered}):
        raise AutonomyInventoryError(f"duplicate {source_kind.value} parameter source")
    return ordered


def _callable_parameter_names(value: Callable[..., object]) -> tuple[str, ...]:
    return tuple(
        sorted(
            parameter.name
            for parameter in inspect.signature(value).parameters.values()
            if parameter.name not in {"self", "cls"}
        )
    )


def _audit_gate_for_path(path: str) -> str | None:
    """Map one AuditConfig leaf to at most one logical gate."""

    if path == "profile":
        return "gate-full-quality-analysis"
    if path == "language_profile":
        return "gate-client-audit-scope"
    if path.startswith("scope."):
        return "gate-client-audit-scope"
    if path == "prior_audit.path":
        return "gate-client-audit-scope"
    if path.startswith("prior_audit."):
        return "gate-full-quality-analysis"
    if path == "actor_model.path":
        return "gate-client-audit-scope"
    if path.startswith("actor_model."):
        return "gate-full-quality-analysis"
    if path.startswith("repository."):
        if path in {
            "repository.root",
            "repository.ignore_file",
            "repository.include_tests",
            "repository.include_docs",
            "repository.follow_symlinks",
        }:
            return "gate-client-audit-scope"
        return "gate-full-quality-analysis"
    if path == "privacy.approved_model_lineages":
        return "gate-autonomous-model-authority"
    if path in {
        "privacy.redact_secrets",
        "privacy.fail_on_detected_secret",
        "privacy.store_raw_prompts",
        "privacy.store_raw_responses",
    }:
        return "gate-secret-redaction-policy"
    if path.startswith("privacy."):
        return "gate-client-privacy-consent"
    if path in {
        "execution.budget_usd",
        "execution.conservative_usd_per_million_tokens",
    } or path.startswith("token_budgets."):
        return "gate-budget-ceiling"
    if path == "execution.cost_ledger_path":
        return "gate-cost-ledger-provisioning"
    if path.startswith("execution."):
        return "gate-full-quality-analysis"
    if path.startswith("dependency_preparation."):
        return "gate-dependency-snapshot"
    if path.startswith("smart_contracts.repository_suite.fork_matrix_states[]."):
        if path.endswith((".anvil_version", ".anvil_sha256", ".anvil_executable_env")):
            return "gate-managed-toolchain-bundle"
        if path.endswith(
            (
                ".rpc_url_env",
                ".expected_chain_id",
                ".pinned_block_number",
                ".state_source_sha256",
            )
        ):
            return "gate-fork-environment"
        return "gate-full-quality-analysis"
    if path.startswith("smart_contracts.repository_suite."):
        return "gate-full-quality-analysis"
    if path in {
        "smart_contracts.solc_version",
        "smart_contracts.solc_sha256",
        "smart_contracts.solc_executable_env",
    }:
        return "gate-managed-toolchain-bundle"
    if path == "smart_contracts.allow_network":
        return "gate-dependency-snapshot"
    if path == "smart_contracts.project_root":
        return "gate-client-audit-scope"
    if path in {
        "smart_contracts.allow_fork_probing",
        "smart_contracts.fork_rpc_url_env",
        "smart_contracts.require_local_fork_rpc",
    }:
        return "gate-fork-environment"
    if path in {
        "smart_contracts.enabled",
        "smart_contracts.compile",
        "smart_contracts.framework",
    }:
        return "gate-full-quality-analysis"
    if path.startswith("smart_contracts."):
        return "gate-full-quality-analysis"
    if path in {
        "reproduction.require_hardened_isolation",
        "reproduction.isolation_backend",
        "reproduction.rootless_container_image",
        "reproduction.rootless_container_runtime",
    }:
        return "gate-managed-toolchain-bundle"
    if path in {"reproduction.pinned_block_number", "reproduction.expected_chain_id"}:
        return "gate-fork-environment"
    if path == "reproduction.targets":
        return "gate-reproduction-target-derivation"
    if path.startswith("reproduction.allowed_") or path.startswith("reproduction.max_attacker_"):
        return "gate-reproduction-capability-policy"
    if path in {
        "reproduction.max_starting_native_capital_wei",
        "reproduction.max_flash_liquidity_wei",
        "reproduction.max_time_shift_seconds",
        "reproduction.max_block_advance",
        "reproduction.allow_governance_rights",
        "reproduction.max_attack_transactions",
    }:
        return "gate-reproduction-capability-policy"
    if path in {
        "reproduction.enabled",
        "reproduction.required_for_solidity",
        "reproduction.minimize",
    }:
        return "gate-full-quality-analysis"
    if path.startswith("reproduction."):
        return "gate-full-quality-analysis"
    if path.startswith("quality_gates.") or path.startswith("maximum_assurance."):
        if path == "maximum_assurance.benchmark_gate":
            return "gate-benchmark-evidence-authority"
        if path.startswith("maximum_assurance.qualification."):
            return "gate-autonomous-model-authority"
        return "gate-full-quality-analysis"
    if path.startswith("invariants.harnesses") or path.startswith("invariants.local_deployments"):
        return "gate-invariant-template-library"
    if path in {
        "invariants.generate_foundry_templates",
        "invariants.execute_generated",
    }:
        return "gate-invariant-template-library"
    if path in {
        "invariants.enabled",
        "invariants.required",
        "invariants.max_invariants",
        "invariants.minimum_confidence",
    }:
        return "gate-full-quality-analysis"
    if path.startswith("invariants."):
        return "gate-invariant-template-library"
    if path.startswith("formal."):
        if (
            path.endswith("_sha256")
            or path.endswith("_version")
            or path
            in {
                "formal.certora.cli_sha256",
                "formal.certora.cli_version",
            }
        ):
            return "gate-managed-toolchain-bundle"
        if path == "formal.certora.api_key_env_var":
            return "gate-provider-secret-transport"
        return "gate-formal-analysis"
    if path in {
        "models.catalog_refresh.automatic_benchmark_daily_budget_usd",
        "models.catalog_refresh.automatic_benchmark_per_model_budget_usd",
    }:
        return "gate-budget-ceiling"
    if path.startswith("models."):
        return "gate-autonomous-model-authority"
    if path.startswith("scanners.codeql.database_path") or path.startswith(
        "scanners.codeql.query_suite"
    ):
        return "gate-codeql-provisioning"
    if path.startswith("scanners."):
        if path.endswith(".version") or path.endswith(".sha256"):
            return "gate-managed-toolchain-bundle"
        if path.endswith(".enabled") or path.endswith(".required"):
            return "gate-full-quality-analysis"
        return "gate-full-quality-analysis"
    if path.startswith("reporting."):
        return "gate-report-delivery"
    if path == "version":
        return "gate-managed-profile"
    return None


_CLI_GATE_IDS: dict[str, str] = {
    "accepted_quote": "gate-budget-ceiling",
    "config_path": "gate-managed-profile",
    "secrets_env_file": "gate-provider-secret-transport",
    "repo": "gate-client-audit-scope",
    "output": "gate-managed-output-provisioning",
    "budget_usd": "gate-budget-ceiling",
    "cost_ledger": "gate-cost-ledger-provisioning",
    "model_qualification_bundle": "gate-autonomous-model-authority",
    "model_qualification_policy": "gate-autonomous-model-authority",
    "model_qualification_release_bindings": "gate-autonomous-model-authority",
    "model_qualification_release_source_root": "gate-autonomous-model-authority",
    "model_qualification_corpus": "gate-autonomous-model-authority",
    "model_qualification_ground_truth": "gate-autonomous-model-authority",
    "max_files": "gate-full-quality-analysis",
    "max_file_bytes": "gate-full-quality-analysis",
    "max_context_bytes": "gate-full-quality-analysis",
    "concurrency": "gate-full-quality-analysis",
    "schema_validation_retries": "gate-full-quality-analysis",
    "severity_threshold": "gate-client-audit-scope",
    "fail_on": "gate-client-audit-scope",
    "scanner_only": "gate-full-quality-analysis",
    "skip_codeql": "gate-full-quality-analysis",
    "allow_code_egress": "gate-client-privacy-consent",
    "require_zdr": "gate-client-privacy-consent",
    "privacy_profile": "gate-client-privacy-consent",
    "retention_consent": "gate-client-privacy-consent",
    "privacy_source_classification": "gate-synthetic-public-scope",
    "learning_tenant_scope_id": "gate-client-audit-scope",
    "profile": "gate-full-quality-analysis",
    "language_profile": "gate-client-audit-scope",
    "scope": "gate-client-audit-scope",
    "require_complete_scope": "gate-full-quality-analysis",
    "require_maximum_assurance": "gate-full-quality-analysis",
    "allow_maximum_assurance_downgrade": "gate-full-quality-analysis",
    "min_model_families": "gate-full-quality-analysis",
    "min_specialist_agents": "gate-full-quality-analysis",
    "require_reproduction_for_critical": "gate-full-quality-analysis",
    "require_formal_or_reproduction_for_confirmed_critical": "gate-full-quality-analysis",
    "benchmark_gate": "gate-benchmark-evidence-authority",
    "benchmark_certificate": "gate-benchmark-evidence-authority",
    "benchmark_component_root": "gate-benchmark-evidence-authority",
    "benchmark_repository_commit": "gate-benchmark-evidence-authority",
    "solidity": "gate-full-quality-analysis",
    "compile_solidity": "gate-full-quality-analysis",
    "run_slither": "gate-full-quality-analysis",
    "allow_network": "gate-dependency-snapshot",
    "framework": "gate-full-quality-analysis",
    "project_root": "gate-client-audit-scope",
    "allow_fork_probing": "gate-fork-environment",
    "fork_rpc_url_env": "gate-fork-environment",
    "changed_since": "gate-client-audit-scope",
}
_CLI_NON_GATING = frozenset(
    {
        "verbose",
        "no_color",
    }
)

_AUDIT_RUN_OPTION_GATE_IDS: dict[str, str] = {
    "scanner_only": "gate-full-quality-analysis",
    "allow_code_egress": "gate-client-privacy-consent",
    "skip_codeql": "gate-full-quality-analysis",
    "changed_since": "gate-client-audit-scope",
    "severity_threshold": "gate-client-audit-scope",
    "fail_on": "gate-client-audit-scope",
    "refresh_models": "gate-autonomous-model-authority",
    "allow_fork_probing": "gate-fork-environment",
    "require_maximum_assurance": "gate-full-quality-analysis",
    "allow_maximum_assurance_downgrade": "gate-full-quality-analysis",
    "benchmark_repository_git_commit": "gate-benchmark-evidence-authority",
    "privacy_source_classification": "gate-synthetic-public-scope",
    "retention_consent_file_sha256": "gate-client-privacy-consent",
    "learning_capture_scope.input_kind": "gate-client-audit-scope",
    "learning_capture_scope.schema_version": "gate-client-audit-scope",
    "learning_capture_scope.tenant_scope_id": "gate-client-audit-scope",
}

_PIPELINE_INIT_GATE_IDS: dict[str, str] = {
    "accepted_prepurchase_quote": "gate-budget-ceiling",
    "config": "gate-managed-profile",
    "repo": "gate-client-audit-scope",
    "output": "gate-managed-output-provisioning",
    "configuration_root": "gate-managed-profile",
    "file_config": "gate-managed-profile",
    "environment_overrides": "gate-managed-profile",
    "cli_overrides": "gate-managed-profile",
    "cost_ledger": "gate-cost-ledger-provisioning",
    "api_key": "gate-provider-secret-transport",
    "production_qualification": "gate-autonomous-model-authority",
    "audit_model_selection_evidence": "gate-autonomous-model-authority",
    "verified_audit_model_selection": "gate-autonomous-model-authority",
    "audit_model_refresh_evidence": "gate-autonomous-model-authority",
    "audit_model_refresh_guard": "gate-autonomous-model-authority",
    "audit_model_refresh_pricing_evidence": "gate-autonomous-model-authority",
    "audit_model_refresh_pricing_authority": "gate-autonomous-model-authority",
    "privacy_consent_observation": "gate-client-privacy-consent",
    "privacy_source_classification": "gate-synthetic-public-scope",
    "scanner_runner": "gate-full-quality-analysis",
    "client": "gate-authenticated-real-campaign",
    "logger": "gate-secret-redaction-policy",
    "reproduction_runner": "gate-full-quality-analysis",
    "invariant_runner": "gate-invariant-template-library",
    "formal_runner": "gate-formal-analysis",
    "repository_fork_matrix_runner": "gate-fork-environment",
    "host_tools": "gate-managed-toolchain-bundle",
    "managed_backend": "gate-reproduction-capability-policy",
    "offline_forks": "gate-fork-environment",
}

_PIPELINE_RUN_GATE_IDS: dict[str, str] = {
    "resume_run_dir": "gate-managed-output-provisioning",
    "scanner_only": "gate-full-quality-analysis",
    "allow_code_egress": "gate-client-privacy-consent",
    "skip_codeql": "gate-full-quality-analysis",
    "refresh_models": "gate-autonomous-model-authority",
    "allow_fork_probing": "gate-fork-environment",
    "require_maximum_assurance": "gate-full-quality-analysis",
    "allow_maximum_assurance_downgrade": "gate-full-quality-analysis",
    "benchmark_verification": "gate-benchmark-evidence-authority",
    "benchmark_repository_git_commit": "gate-benchmark-evidence-authority",
    "learning_capture_scope": "gate-client-audit-scope",
    "changed_since": "gate-client-audit-scope",
    "severity_threshold": "gate-client-audit-scope",
    "fail_on": "gate-client-audit-scope",
    "ci_mode": "gate-release-evidence-pipeline",
    "ci_baseline": "gate-release-evidence-pipeline",
}


def _classified_source(
    *,
    source_id: str,
    source_kind: CompletionInputSourceKind,
    source_path: str,
    semantics: str,
    source_occurrence_count: int = 1,
    gate_id: str | None = None,
    classification: SourceCoverageClassification | None = None,
) -> _SourceDraft:
    if gate_id is not None:
        if gate_id not in _GATE_SPEC_BY_ID:
            raise AutonomyInventoryError(f"unknown logical gate: {gate_id}")
        resolved = SourceCoverageClassification.GATE
    elif classification is not None:
        resolved = classification
    else:
        raise AutonomyInventoryError("source classification must be explicit")
    return _SourceDraft(
        source_id=source_id,
        source_kind=source_kind,
        source_path=source_path,
        source_semantics_sha256=semantics,
        source_occurrence_count=source_occurrence_count,
        classification=resolved,
        logical_gate_id=gate_id,
    )


def _discover_config_sources(model: type[BaseModel]) -> list[_SourceDraft]:
    details = _discover_model_leaf_details(model)
    _assert_frozen_source_shape(
        label="AuditConfig leaves",
        observed=[path for path, _, _ in details],
        expected_sha256=_FROZEN_AUDIT_CONFIG_PATHS_SHA256,
    )
    drafts: list[_SourceDraft] = []
    for path, semantics, occurrence_count in details:
        gate_id = _audit_gate_for_path(path)
        if gate_id is None:
            raise AutonomyInventoryError(f"unclassified AuditConfig leaf: {path}")
        drafts.append(
            _classified_source(
                source_id=f"audit-config:{path}",
                source_kind=CompletionInputSourceKind.AUDIT_CONFIG_LEAF,
                source_path=f"mmaudit.config.AuditConfig:{path}",
                semantics=semantics,
                gate_id=gate_id,
                source_occurrence_count=occurrence_count,
            )
        )
    return drafts


def _discover_audit_run_option_sources(
    model: type[BaseModel] = AuditRunOptions,
) -> list[_SourceDraft]:
    details = _discover_model_leaf_details(model)
    _assert_frozen_source_shape(
        label="AuditRunOptions leaves",
        observed=[path for path, _, _ in details],
        expected_sha256=_FROZEN_AUDIT_RUN_OPTION_PATHS_SHA256,
    )
    drafts: list[_SourceDraft] = []
    for path, semantics, occurrence_count in details:
        gate_id = _AUDIT_RUN_OPTION_GATE_IDS.get(path)
        if gate_id is None:
            raise AutonomyInventoryError(f"unclassified AuditRunOptions leaf: {path}")
        drafts.append(
            _classified_source(
                source_id=f"audit-run-option:{path}",
                source_kind=CompletionInputSourceKind.AUDIT_RUN_OPTION_LEAF,
                source_path=f"mmaudit.config.AuditRunOptions:{path}",
                semantics=semantics,
                gate_id=gate_id,
                source_occurrence_count=occurrence_count,
            )
        )
    return drafts


def _discover_override_sources(
    mapping: Mapping[str, tuple[type[object], ...]],
) -> list[_SourceDraft]:
    from mmaudit.config import AuditConfigOverride, AuditConfigOverrides, audit_config_overrides

    _assert_frozen_source_shape(
        label="audit override allowlist",
        observed=sorted(mapping),
        expected_sha256=_FROZEN_AUDIT_OVERRIDE_PATHS_SHA256,
    )
    function_semantics = _canonical_sha256(
        {
            "single_override": _normalized_ast(AuditConfigOverride),
            "override_set": _normalized_ast(AuditConfigOverrides),
            "constructor": _normalized_ast(audit_config_overrides),
        }
    )
    drafts: list[_SourceDraft] = []
    for path, types_allowed in sorted(mapping.items()):
        semantics = _canonical_sha256(
            {
                "path": path,
                "types": [_qualified_name(item) for item in types_allowed],
                "override_model_semantics_sha256": function_semantics,
            }
        )
        gate_id = _audit_gate_for_path(path)
        if gate_id is None:
            raise AutonomyInventoryError(f"unclassified audit override path: {path}")
        drafts.append(
            _classified_source(
                source_id=f"audit-override:{path}",
                source_kind=CompletionInputSourceKind.AUDIT_OVERRIDE_PATH,
                source_path=f"mmaudit.config._AUDIT_OVERRIDE_VALUE_TYPES:{path}",
                semantics=semantics,
                gate_id=gate_id,
            )
        )
    return drafts


def _discover_environment_sources(
    mapping: Mapping[str, tuple[str, type[Any]]],
) -> list[_SourceDraft]:
    from mmaudit.config import _environment_overrides

    _assert_frozen_source_shape(
        label="environment override allowlist",
        observed=sorted((name, value[0]) for name, value in mapping.items()),
        expected_sha256=_FROZEN_ENVIRONMENT_OVERRIDE_PAIRS_SHA256,
    )

    function_hash = hashlib.sha256(_normalized_ast(_environment_overrides).encode()).hexdigest()
    drafts: list[_SourceDraft] = []
    for variable, (path, kind) in sorted(mapping.items()):
        semantics = _canonical_sha256(
            {
                "variable": variable,
                "path": path,
                "kind": _qualified_name(kind),
                "parser_semantics_sha256": function_hash,
            }
        )
        gate_id = _audit_gate_for_path(path)
        if gate_id is None:
            raise AutonomyInventoryError(f"unclassified environment override path: {path}")
        drafts.append(
            _classified_source(
                source_id=f"environment-override:{variable.lower()}",
                source_kind=CompletionInputSourceKind.ENVIRONMENT_OVERRIDE,
                source_path=f"mmaudit.config._ENVIRONMENT_OVERRIDE_MAPPINGS:{variable}->{path}",
                semantics=semantics,
                gate_id=gate_id,
            )
        )
    return drafts


def _discover_cli_sources(
    value: Callable[..., object], *, repository_root: Path | None = None
) -> list[_SourceDraft]:
    _assert_frozen_source_shape(
        label="run_command parameters",
        observed=list(_callable_parameter_names(value)),
        expected_sha256=_FROZEN_CLI_RUN_PARAMETERS_SHA256,
    )
    drafts: list[_SourceDraft] = []
    for source_id, source_path, semantics in _callable_parameter_sources(
        value,
        source_kind=CompletionInputSourceKind.CLI_RUN_PARAMETER,
        prefix="cli-run",
        repository_root=repository_root,
    ):
        name = source_id.removeprefix("cli-run:")
        if name in _CLI_GATE_IDS:
            drafts.append(
                _classified_source(
                    source_id=source_id,
                    source_kind=CompletionInputSourceKind.CLI_RUN_PARAMETER,
                    source_path=source_path,
                    semantics=semantics,
                    gate_id=_CLI_GATE_IDS[name],
                )
            )
        elif name in _CLI_NON_GATING:
            drafts.append(
                _classified_source(
                    source_id=source_id,
                    source_kind=CompletionInputSourceKind.CLI_RUN_PARAMETER,
                    source_path=source_path,
                    semantics=semantics,
                    classification=SourceCoverageClassification.NON_GATING_CONTROL,
                )
            )
        else:
            raise AutonomyInventoryError(f"unclassified run_command parameter: {name}")
    return drafts


_CAMPAIGN_COMMANDS = frozenset({"models_authenticated_runner", "models_authenticated_runner_smoke"})


def _registered_cli_commands() -> tuple[tuple[str, Callable[..., object]], ...]:
    """Discover every Typer command/callback from the complete registered CLI module."""

    import mmaudit.cli as cli_module

    try:
        module_source = inspect.getsource(cli_module)
        tree = ast.parse(module_source)
    except (OSError, TypeError, SyntaxError) as exc:
        raise AutonomyInventoryError("registered CLI source cannot be inspected") from exc
    names: list[str] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        registered = False
        for decorator in node.decorator_list:
            expression = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(expression, ast.Attribute) and expression.attr in {"command", "callback"}:
                registered = True
                break
        if registered:
            names.append(node.name)
    if names != list(dict.fromkeys(names)):
        raise AutonomyInventoryError("registered CLI command names are duplicated")
    commands: list[tuple[str, Callable[..., object]]] = []
    for name in sorted(names):
        value = getattr(cli_module, name, None)
        if value is None or not callable(value):
            raise AutonomyInventoryError(f"registered CLI command is unavailable: {name}")
        commands.append((name, value))
    return tuple(commands)


def _command_parameter_classification(
    command_name: str,
    parameter_name: str,
) -> tuple[SourceCoverageClassification, str | None]:
    """Classify one exact auxiliary command parameter without a permissive fallback."""

    if parameter_name in {"no_color", "verbose", "ctx"}:
        return SourceCoverageClassification.NON_GATING_CONTROL, None
    if (command_name, parameter_name) == ("models_list_endpoints", "json_output"):
        return SourceCoverageClassification.NON_GATING_CONTROL, None
    if (command_name, parameter_name) in {
        ("explain_command", "finding_id"),
        ("main", "version"),
    }:
        return SourceCoverageClassification.NON_GATING_CONTROL, None
    if (command_name, parameter_name) == ("init_command", "force"):
        return SourceCoverageClassification.GATE, "gate-managed-provisioning"
    if command_name == "managed_provision" and parameter_name == "verify_only":
        return SourceCoverageClassification.GATE, "gate-managed-provisioning"
    if command_name == "managed_provision" and parameter_name in {
        "archive_root",
        "advisory_path",
        "advisory_sha256",
    }:
        return SourceCoverageClassification.GATE, "gate-dependency-snapshot"
    if command_name == "managed_build_dependency_snapshot" and parameter_name in {
        "repo",
        "archive_root",
        "advisory_path",
        "advisory_sha256",
        "verify_only",
    }:
        return SourceCoverageClassification.GATE, "gate-dependency-snapshot"
    if (command_name, parameter_name) == ("scan_command", "framework"):
        return SourceCoverageClassification.GATE, "gate-full-quality-analysis"
    if command_name in {"quote_accept", "quote_reconcile"} and parameter_name in {
        "acceptance_path",
        "quote_path",
    }:
        return SourceCoverageClassification.GATE, "gate-budget-ceiling"
    if command_name == "quote_create" and parameter_name == "portfolio_preflight":
        return SourceCoverageClassification.GATE, "gate-budget-ceiling"
    if command_name == "quote_create" and parameter_name == "campaign_manifest":
        return SourceCoverageClassification.GATE, "gate-authenticated-real-campaign"
    if command_name == "quote_create" and parameter_name == "solidity_shards":
        return SourceCoverageClassification.GATE, "gate-full-quality-analysis"
    if command_name == "quote_reconcile" and parameter_name == "cost_ledger_evidence":
        return SourceCoverageClassification.GATE, "gate-cost-ledger-provisioning"
    if command_name == "quote_reconcile" and parameter_name == "model_execution":
        return SourceCoverageClassification.GATE, "gate-release-evidence-pipeline"
    if command_name == "models_discover" and parameter_name in {
        "candidate",
        "candidate_registry_template",
        "candidate_selection_lineage_review_source",
        "candidate_selection_plan",
        "candidate_selection_ranking_source",
    }:
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if command_name == "models_emit_selection_plan_successor" and parameter_name in {
        "candidate",
        "predecessor_plan",
        "refresh_endpoint_inventory",
        "upgrade_price_cap_profile_v2",
        "upgrade_price_cap_profile_v3",
    }:
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if command_name == "models_emit_selection_plan_reactivation" and parameter_name == "candidate":
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if command_name == "models_list_endpoints" and parameter_name == "model_id":
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if command_name == "models_refresh" and parameter_name in {
        "hard_max_age_hours",
        "policy_checked_routes",
        "policy_eligibility_artifact",
        "policy_source_observation",
        "previous_candidate_registry",
        "previous_snapshot",
        "previous_source_evidence",
        "pricing_tolerance_fraction",
        "selected_route",
        "soft_max_age_hours",
    }:
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if command_name in _CAMPAIGN_COMMANDS and parameter_name in {
        "preflight_only",
        "live_route_preflight_only",
    }:
        return SourceCoverageClassification.GATE, "gate-authenticated-real-campaign"
    if command_name == "models_authenticated_runner_smoke" and parameter_name == "smoke_run_index":
        return SourceCoverageClassification.GATE, "gate-authenticated-real-campaign"
    if (
        command_name
        in {
            "models_authenticated_runner_smoke",
            "models_verify_authenticated_runner_smoke",
        }
        and parameter_name == "smoke_corpus"
    ):
        return SourceCoverageClassification.GATE, "gate-authenticated-real-campaign"
    if command_name == "models_benchmark" and parameter_name in {
        "lineage_review_bundle",
        "lineage_trust_anchor",
    }:
        return SourceCoverageClassification.GATE, "gate-human-signoff-boundary"
    if command_name == "benchmark_command" and parameter_name == "profile":
        return SourceCoverageClassification.GATE, "gate-benchmark-evidence-authority"
    if parameter_name == "human_comparison":
        return SourceCoverageClassification.GATE, "gate-human-signoff-boundary"
    if parameter_name == "acknowledge_sensitive_evidence":
        return SourceCoverageClassification.GATE, "gate-forensic-export-consent"
    if parameter_name == "allow_read_only_import":
        return SourceCoverageClassification.GATE, "gate-snapshot-intake-consent"
    if parameter_name in {"rpc_url", "fork_rpc_url_env", "allow_fork_probing"}:
        return SourceCoverageClassification.GATE, "gate-fork-environment"
    if parameter_name == "allow_network":
        return SourceCoverageClassification.GATE, "gate-dependency-snapshot"
    if parameter_name in {
        "allow_code_egress",
        "allow_metadata_egress",
        "require_zdr",
        "privacy_profile",
        "retention_consent",
    }:
        return SourceCoverageClassification.GATE, "gate-client-privacy-consent"
    if parameter_name == "privacy_source_classification":
        return SourceCoverageClassification.GATE, "gate-synthetic-public-scope"
    if "secret" in parameter_name or "api_key" in parameter_name:
        return SourceCoverageClassification.GATE, "gate-provider-secret-transport"
    if parameter_name == "cost_ledger":
        return SourceCoverageClassification.GATE, "gate-cost-ledger-provisioning"
    if any(token in parameter_name for token in ("budget", "cost_cap", "cost_tripwire")):
        return SourceCoverageClassification.GATE, "gate-budget-ceiling"
    if parameter_name in {"config_path", "configuration_root", "retry_continuity_config"}:
        return SourceCoverageClassification.GATE, "gate-managed-profile"
    if parameter_name in {
        "repo",
        "repository",
        "project_root",
        "scope",
        "changed_since",
        "severity_threshold",
        "fail_on",
        "language_profile",
    }:
        return SourceCoverageClassification.GATE, "gate-client-audit-scope"
    if parameter_name in {
        "scanner_only",
        "skip_codeql",
        "profile",
        "require_complete_scope",
        "require_maximum_assurance",
        "allow_maximum_assurance_downgrade",
        "min_model_families",
        "min_specialist_agents",
        "require_reproduction_for_critical",
        "require_formal_or_reproduction_for_confirmed_critical",
        "solidity",
        "compile_solidity",
        "run_slither",
        "ci_mode",
        "ci_baseline_run",
        "schema_validation_retries",
    }:
        return SourceCoverageClassification.GATE, "gate-full-quality-analysis"
    if parameter_name in {
        "max_files",
        "max_file_bytes",
        "max_context_bytes",
        "concurrency",
    }:
        return SourceCoverageClassification.GATE, "gate-full-quality-analysis"
    if parameter_name in {
        "directory",
        "destination",
        "output",
        "output_dir",
        "output_json",
        "work_dir",
        "candidate_registry_output",
    }:
        return SourceCoverageClassification.GATE, "gate-managed-output-provisioning"
    if parameter_name in {
        "benchmark_gate",
        "benchmark_certificate",
        "benchmark_component_root",
        "benchmark_repository_commit",
    }:
        return SourceCoverageClassification.GATE, "gate-benchmark-evidence-authority"
    if parameter_name in {
        "smoke_corpus",
        "corpus",
        "ground_truth",
        "ground_truth_root",
        "ground_truth_provenance",
        "reports",
        "mutation_scorecard",
        "campaign_journal",
        "primary_campaign_journal",
        "replay_campaign_journal",
        "primary_portfolio",
        "replay_portfolio",
        "portfolio",
        "calibration_output",
        "calibrated_policy_output",
        "benchmark_certificate",
        "benchmark_component_root",
        "benchmark_repository_commit",
        "repository_commit",
    }:
        return SourceCoverageClassification.GATE, "gate-benchmark-evidence-authority"
    if parameter_name in {
        "candidate_registry",
        "candidate_discovery_run",
        "primary_judge_registry",
        "primary_judge_discovery_run",
        "replay_judge_registry",
        "replay_judge_discovery_run",
        "runtime_evidence_smoke_bundle",
        "qualification_policy",
        "policy",
        "discovery_run",
        "model",
        "release_bindings",
        "release_source_root",
        "qualification_expires_at",
        "model_qualification_bundle",
        "model_qualification_policy",
        "model_qualification_release_bindings",
        "model_qualification_release_source_root",
        "model_qualification_corpus",
        "model_qualification_ground_truth",
    }:
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    if parameter_name in {
        "baseline_run",
        "bundle_path",
        "bundle",
        "manifest",
        "run_dir",
        "replay",
        "certificate_path",
        "component_root",
        "inputs",
        "certificate_id",
    }:
        return SourceCoverageClassification.GATE, "gate-release-evidence-pipeline"
    if parameter_name == "plan":
        return SourceCoverageClassification.GATE, "gate-snapshot-intake-consent"
    if parameter_name == "resume_campaign":
        return SourceCoverageClassification.GATE, "gate-benchmark-evidence-authority"
    if parameter_name == "refresh":
        return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
    raise AutonomyInventoryError(
        f"unclassified completion command parameter: {command_name}.{parameter_name}"
    )


def _discover_completion_entrypoint_sources(
    *, repository_root: Path | None = None
) -> list[_SourceDraft]:
    from mmaudit.cli import _execute_audit

    commands = [
        (name, value) for name, value in _registered_cli_commands() if name != "run_command"
    ]
    commands.append(("_execute_audit", _execute_audit))
    _assert_frozen_source_shape(
        label="completion entrypoint parameters",
        observed=[(name, list(_callable_parameter_names(value))) for name, value in commands],
        expected_sha256=_FROZEN_COMPLETION_ENTRYPOINT_PARAMETERS_SHA256,
    )
    # The private bridge is part of the stock completion boundary and therefore
    # uses the same explicit per-parameter policy as the public run command.
    drafts: list[_SourceDraft] = []
    for command_name, value in sorted(commands):
        parameters = _callable_parameter_sources(
            value,
            source_kind=CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER,
            prefix=f"completion-entrypoint:{command_name}",
            repository_root=repository_root,
        )
        for source_id, source_path, semantics in parameters:
            parameter_name = source_id.rsplit(":", 1)[-1]
            if command_name == "_execute_audit":
                if parameter_name in _CLI_GATE_IDS:
                    classification = SourceCoverageClassification.GATE
                    gate_id = _CLI_GATE_IDS[parameter_name]
                elif parameter_name in _CLI_NON_GATING:
                    classification = SourceCoverageClassification.NON_GATING_CONTROL
                    gate_id = None
                elif parameter_name in {"ci_mode", "ci_baseline_run"}:
                    classification = SourceCoverageClassification.GATE
                    gate_id = "gate-release-evidence-pipeline"
                else:
                    raise AutonomyInventoryError(
                        f"unclassified _execute_audit parameter: {parameter_name}"
                    )
            else:
                classification, gate_id = _command_parameter_classification(
                    command_name,
                    parameter_name,
                )
            if classification is SourceCoverageClassification.GATE and gate_id is None:
                raise AutonomyInventoryError(
                    f"gate-classified command parameter lacks a gate: "
                    f"{command_name}.{parameter_name}"
                )
            drafts.append(
                _classified_source(
                    source_id=source_id,
                    source_kind=CompletionInputSourceKind.COMPLETION_ENTRYPOINT_PARAMETER,
                    source_path=source_path,
                    semantics=semantics,
                    gate_id=gate_id,
                    classification=classification,
                )
            )
    return drafts


def _discover_pipeline_init_sources(
    value: Callable[..., object], *, repository_root: Path | None = None
) -> list[_SourceDraft]:
    _assert_frozen_source_shape(
        label="AuditPipeline.__init__ parameters",
        observed=list(_callable_parameter_names(value)),
        expected_sha256=_FROZEN_PIPELINE_INIT_PARAMETERS_SHA256,
    )
    drafts: list[_SourceDraft] = []
    for source_id, source_path, semantics in _callable_parameter_sources(
        value,
        source_kind=CompletionInputSourceKind.PIPELINE_INIT_PARAMETER,
        prefix="pipeline-init",
        repository_root=repository_root,
    ):
        name = source_id.removeprefix("pipeline-init:")
        if name not in _PIPELINE_INIT_GATE_IDS:
            raise AutonomyInventoryError(f"unclassified AuditPipeline.__init__ parameter: {name}")
        classification = SourceCoverageClassification.GATE
        gate_id = _PIPELINE_INIT_GATE_IDS[name]
        drafts.append(
            _classified_source(
                source_id=source_id,
                source_kind=CompletionInputSourceKind.PIPELINE_INIT_PARAMETER,
                source_path=source_path,
                semantics=semantics,
                gate_id=gate_id,
                classification=classification,
            )
        )
    return drafts


def _discover_pipeline_run_sources(
    value: Callable[..., object], *, repository_root: Path | None = None
) -> list[_SourceDraft]:
    _assert_frozen_source_shape(
        label="AuditPipeline.run parameters",
        observed=list(_callable_parameter_names(value)),
        expected_sha256=_FROZEN_PIPELINE_RUN_PARAMETERS_SHA256,
    )
    drafts: list[_SourceDraft] = []
    for source_id, source_path, semantics in _callable_parameter_sources(
        value,
        source_kind=CompletionInputSourceKind.PIPELINE_RUN_PARAMETER,
        prefix="pipeline-run",
        repository_root=repository_root,
    ):
        name = source_id.removeprefix("pipeline-run:")
        if name not in _PIPELINE_RUN_GATE_IDS:
            raise AutonomyInventoryError(f"unclassified AuditPipeline.run parameter: {name}")
        classification = SourceCoverageClassification.GATE
        gate_id = _PIPELINE_RUN_GATE_IDS[name]
        drafts.append(
            _classified_source(
                source_id=source_id,
                source_kind=CompletionInputSourceKind.PIPELINE_RUN_PARAMETER,
                source_path=source_path,
                semantics=semantics,
                gate_id=gate_id,
                classification=classification,
            )
        )
    return drafts


def _python_source_paths(source_root: Path) -> tuple[Path, ...]:
    try:
        paths = tuple(sorted(path for path in source_root.rglob("*.py") if path.is_file()))
    except OSError as exc:
        raise AutonomyInventoryError("audited Python module universe is unavailable") from exc
    if not paths:
        raise AutonomyInventoryError("audited Python module universe is empty")
    return paths


def _runtime_package_paths(source_root: Path) -> tuple[Path, ...]:
    """Return every regular runtime package file without following filesystem aliases."""

    paths: list[Path] = []
    try:
        candidates = tuple(sorted(source_root.rglob("*")))
    except OSError as exc:
        raise AutonomyInventoryError("audited runtime package universe is unavailable") from exc
    for path in candidates:
        relative = path.relative_to(source_root)
        if "__pycache__" in relative.parts or path.suffix in {".pyc", ".pyo"}:
            continue
        if path.is_symlink():
            raise AutonomyInventoryError(
                f"audited runtime package contains a symbolic link: {relative.as_posix()}"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise AutonomyInventoryError(
                f"audited runtime package contains a special file: {relative.as_posix()}"
            )
        paths.append(path)
    if not paths:
        raise AutonomyInventoryError("audited runtime package universe is empty")
    return tuple(paths)


def _read_normalized_module_ast(path: Path) -> str:
    try:
        source = path.read_text(encoding="utf-8")
        parsed = ast.parse(source, filename=path.as_posix())
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise AutonomyInventoryError(
            f"audited Python module cannot be parsed: {path.name}"
        ) from exc
    return ast.dump(parsed, annotate_fields=True, include_attributes=False)


def _module_source_id(relative_path: str) -> str:
    dotted = relative_path.removesuffix(".py").replace("/", ".").lower()
    return f"audited-module:{dotted}"


def _discover_audited_module_sources(source_root: Path) -> list[_SourceDraft]:
    """Bind every runtime package file so opaque gates and resources cannot evade drift."""

    paths = _runtime_package_paths(source_root)
    relative_paths = [path.relative_to(source_root).as_posix() for path in paths]
    _assert_frozen_source_shape(
        label="audited runtime package paths",
        observed=relative_paths,
        expected_sha256=_FROZEN_AUDITED_MODULE_PATHS_SHA256,
    )
    return [
        _classified_source(
            source_id=_module_source_id(relative_path),
            source_kind=CompletionInputSourceKind.AUDITED_MODULE_UNIVERSE,
            source_path=f"src/mmaudit/{relative_path}",
            semantics=_canonical_sha256(
                {
                    "relative_path": relative_path,
                    "kind": "PYTHON_NORMALIZED_AST",
                    "normalized_ast": _read_normalized_module_ast(path),
                }
                if path.suffix == ".py"
                else {
                    "relative_path": relative_path,
                    "kind": "RUNTIME_RESOURCE_BYTES",
                    "size": path.stat().st_size,
                    "content_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            ),
            gate_id="gate-runtime-package-integrity",
        )
        for path, relative_path in zip(paths, relative_paths, strict=True)
    ]


def _is_attribute(node: ast.AST, *parts: str) -> bool:
    current: ast.AST = node
    for part in reversed(parts[1:]):
        if not isinstance(current, ast.Attribute) or current.attr != part:
            return False
        current = current.value
    return isinstance(current, ast.Name) and current.id == parts[0]


_BOUNDARY_ALIAS_TARGETS = frozenset(
    {
        "builtins.input",
        "builtins.open",
        "click.confirm",
        "click.prompt",
        "datetime.date.today",
        "datetime.datetime.now",
        "datetime.datetime.utcnow",
        "getpass.getpass",
        "glob.glob",
        "glob.iglob",
        "io.open",
        "json.load",
        "os.access",
        "os.environ",
        "os.fstat",
        "os.getegid",
        "os.geteuid",
        "os.getgid",
        "os.getenv",
        "os.getpid",
        "os.getppid",
        "os.getuid",
        "os.listdir",
        "os.lstat",
        "os.open",
        "os.path.abspath",
        "os.path.lexists",
        "os.readlink",
        "os.scandir",
        "os.stat",
        "os.walk",
        "pathlib.Path.cwd",
        "pathlib.Path.absolute",
        "pathlib.Path.exists",
        "pathlib.Path.glob",
        "pathlib.Path.home",
        "pathlib.Path.is_dir",
        "pathlib.Path.is_file",
        "pathlib.Path.is_junction",
        "pathlib.Path.is_symlink",
        "pathlib.Path.iterdir",
        "pathlib.Path.lstat",
        "pathlib.Path.open",
        "pathlib.Path.read_bytes",
        "pathlib.Path.read_text",
        "pathlib.Path.readlink",
        "pathlib.Path.resolve",
        "pathlib.Path.rglob",
        "pathlib.Path.samefile",
        "pathlib.Path.stat",
        "platform.python_implementation",
        "platform.python_version",
        "platform.machine",
        "platform.system",
        "rich.prompt.Confirm.ask",
        "rich.prompt.Prompt.ask",
        "shutil.copy",
        "shutil.copy2",
        "shutil.copyfile",
        "shutil.copytree",
        "shutil.which",
        "tempfile.NamedTemporaryFile",
        "tempfile.TemporaryDirectory",
        "tempfile.gettempdir",
        "tempfile.mkdtemp",
        "tempfile.mkstemp",
        "time.time",
        "time.time_ns",
        "tomllib.load",
        "typer.confirm",
        "typer.prompt",
        "uuid.uuid4",
        "yaml.load",
        "yaml.safe_load",
        "secrets.token_hex",
    }
)


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Return only builtins; lexical imports are applied in source order by visitors."""

    del tree
    return {
        "getattr": "builtins.getattr",
        "input": "builtins.input",
        "open": "builtins.open",
    }


class _ScopedBoundaryVisitor(ast.NodeVisitor):
    """Resolve imports and simple boundary aliases without leaking across lexical scopes."""

    def __init__(self, aliases: Mapping[str, str]) -> None:
        self._alias_frames: list[dict[str, str]] = [dict(aliases)]
        self.scope: list[str] = []

    def _qualified_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            for frame in reversed(self._alias_frames):
                if node.id in frame:
                    return frame[node.id]
            return node.id
        if isinstance(node, ast.Attribute):
            owner = self._qualified_name(node.value)
            return f"{owner}.{node.attr}" if owner is not None else None
        return None

    @staticmethod
    def _target_names(node: ast.AST) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, (ast.Tuple, ast.List)):
            return tuple(
                name for item in node.elts for name in _ScopedBoundaryVisitor._target_names(item)
            )
        return ()

    def _bind(self, name: str, resolved: str | None) -> None:
        self._alias_frames[-1][name] = resolved if resolved in _BOUNDARY_ALIAS_TARGETS else name

    def _binding_resolution(self, value: ast.AST) -> str | None:
        resolved = self._qualified_name(value)
        literal_getattr = self._literal_getattr(value)
        if literal_getattr is not None:
            owner, attribute = literal_getattr
            candidate = f"{owner}.{attribute}"
            if candidate in _BOUNDARY_ALIAS_TARGETS:
                return candidate
        if (
            isinstance(value, ast.Attribute)
            and value.attr in {"getpid", "getppid"}
            and self._qualified_name(value.value) == "trusted_os"
        ):
            return f"os.{value.attr}"
        return resolved

    def _literal_getattr(self, node: ast.AST) -> tuple[str, str] | None:
        if (
            not isinstance(node, ast.Call)
            or self._qualified_name(node.func) != "builtins.getattr"
            or len(node.args) < 2
            or not isinstance(node.args[1], ast.Constant)
            or not isinstance(node.args[1].value, str)
        ):
            return None
        owner = self._qualified_name(node.args[0]) or "<dynamic>"
        return owner, node.args[1].value

    def _observe_assignment(self, node: ast.AST, resolved: str | None) -> None:
        del node, resolved

    def visit_Import(self, node: ast.Import) -> None:
        for imported in node.names:
            local = imported.asname or imported.name.split(".", 1)[0]
            self._alias_frames[-1][local] = imported.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        for imported in node.names:
            if imported.name == "*":
                continue
            local = imported.asname or imported.name
            self._alias_frames[-1][local] = f"{node.module}.{imported.name}"

    def visit_Assign(self, node: ast.Assign) -> None:
        resolved = self._binding_resolution(node.value)
        self._observe_assignment(node, resolved)
        self.visit(node.value)
        for target in node.targets:
            for name in self._target_names(target):
                self._bind(name, resolved)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            resolved = self._binding_resolution(node.value)
            self._observe_assignment(node, resolved)
            self.visit(node.value)
        else:
            resolved = None
        for name in self._target_names(node.target):
            self._bind(name, resolved)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        resolved = self._binding_resolution(node.value)
        self._observe_assignment(node, resolved)
        self.visit(node.value)
        for name in self._target_names(node.target):
            self._bind(name, resolved)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        self.scope.append(node.name)
        parameter_names = {
            argument.arg
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
        }
        if node.args.vararg is not None:
            parameter_names.add(node.args.vararg.arg)
        if node.args.kwarg is not None:
            parameter_names.add(node.args.kwarg.arg)
        self._alias_frames.append({name: name for name in parameter_names})
        for statement in node.body:
            self.visit(statement)
        self._alias_frames.pop()
        self.scope.pop()
        self._bind(node.name, None)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self.scope.append(node.name)
        self._alias_frames.append({})
        for statement in node.body:
            self.visit(statement)
        self._alias_frames.pop()
        self.scope.pop()
        self._bind(node.name, None)


class _EnvironmentAuthorityVisitor(_ScopedBoundaryVisitor):
    """Collect direct process-environment and PATH-resolution authority loci."""

    def __init__(self, aliases: Mapping[str, str]) -> None:
        super().__init__(aliases)
        self.occurrences: list[tuple[str, str, str]] = []

    def _record(self, kind: str, node: ast.AST) -> None:
        scope = ".".join(self.scope) if self.scope else "module"
        self.occurrences.append(
            (
                scope,
                kind,
                ast.dump(node, annotate_fields=True, include_attributes=False),
            )
        )

    def _observe_assignment(self, node: ast.AST, resolved: str | None) -> None:
        if resolved in {"os.getpid", "os.getppid"}:
            self._record("process-identity-binding", node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._qualified_name(node.func) or self._binding_resolution(node.func)
        if call_name == "shutil.which":
            self._record("path-resolution", node)
        if call_name == "pathlib.Path.home":
            self._record("home-resolution", node)
        if call_name in {"pathlib.Path.cwd", "os.getcwd"}:
            self._record("working-directory", node)
        if call_name in {"os.path.abspath", "pathlib.Path.absolute"} or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "absolute"
        ):
            self._record("working-directory", node)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "expanduser":
            self._record("home-expansion", node)
        if call_name in {
            "platform.machine",
            "platform.system",
            "platform.python_implementation",
            "platform.python_version",
        }:
            self._record("host-platform", node)
        if call_name in {
            "datetime.datetime.now",
            "datetime.datetime.utcnow",
            "datetime.date.today",
            "time.time",
            "time.time_ns",
        }:
            self._record("wall-clock", node)
        if call_name in {"os.getuid", "os.geteuid", "os.getgid", "os.getegid"}:
            self._record("host-identity", node)
        if call_name in {"os.getpid", "os.getppid"}:
            self._record("process-identity", node)
        if (
            call_name in {"getattr", "builtins.getattr"}
            and len(node.args) >= 2
            and self._qualified_name(node.args[0]) == "sys"
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value == "_base_executable"
        ):
            self._record("python-runtime", node)
        if call_name in {
            "tempfile.gettempdir",
            "mkdtemp",
            "mkstemp",
            "NamedTemporaryFile",
            "TemporaryDirectory",
            "tempfile.mkdtemp",
            "tempfile.mkstemp",
            "tempfile.NamedTemporaryFile",
            "tempfile.TemporaryDirectory",
        } and not any(keyword.arg == "dir" for keyword in node.keywords):
            self._record("temporary-root", node)
        if call_name == "os.getenv" or (
            call_name is not None and call_name.startswith("os.environ.")
        ):
            self._record("environment-call", node)
            for argument in node.args:
                self.visit(argument)
            for keyword in node.keywords:
                self.visit(keyword.value)
            return
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self._qualified_name(node.value) == "os.environ":
            self._record("environment-subscript", node)
            self.visit(node.slice)
            return
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        qualified = self._qualified_name(node)
        if qualified == "os.environ":
            self._record("environment-mapping", node)
            return
        if qualified in {"os.name", "sys.platform"}:
            self._record("host-platform", node)
            return
        if qualified in {
            "sys._base_executable",
            "sys.executable",
            "sys.implementation.cache_tag",
            "sys.prefix",
            "sys.version_info",
        }:
            self._record("python-runtime", node)
            return
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if self._qualified_name(node) == "os.environ":
            self._record("environment-mapping", node)


def _direct_environment_occurrences(
    source_root: Path,
) -> tuple[tuple[str, str, str, str], ...]:
    result: list[tuple[str, str, str, str]] = []
    for path in _python_source_paths(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        try:
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise AutonomyInventoryError(
                f"environment-authority module cannot be parsed: {relative_path}"
            ) from exc
        visitor = _EnvironmentAuthorityVisitor(_import_aliases(parsed))
        visitor.visit(parsed)
        result.extend(
            (relative_path, scope, kind, expression)
            for scope, kind, expression in visitor.occurrences
        )
    return tuple(result)


def _direct_environment_gate(
    relative_path: str,
    scope: str,
    kind: str,
    expression: str,
) -> str:
    searchable = f"{relative_path}:{scope}:{expression}".lower()
    if (
        relative_path
        in {
            "models/lineage_authority.py",
            "models/policy_eligibility_authority.py",
        }
        and scope == "_verify_sshsig"
    ):
        return "gate-human-signoff-boundary"
    if kind == "wall-clock":
        return "gate-trusted-time-independent-replay"
    if kind in {"process-identity", "process-identity-binding"}:
        if relative_path in {
            "benchmark/foundry_mutation_executor.py",
            "benchmark/model_portfolio.py",
            "benchmark/mutations.py",
        }:
            return "gate-benchmark-evidence-authority"
        if relative_path == "orchestration/budgets.py":
            return "gate-cost-ledger-provisioning"
        if relative_path in {
            "models/openrouter.py",
            "models/route_runtime_evidence.py",
            "models/usage.py",
        }:
            return "gate-authenticated-real-campaign"
        if relative_path.startswith("models/authenticated_runner"):
            return "gate-authenticated-real-campaign"
        if relative_path in {
            "models/candidate_plan_ancestry.py",
            "models/frozen_lineage_authority.py",
            "models/generation_evidence.py",
            "models/public_lineage_authority.py",
        }:
            return "gate-autonomous-model-authority"
        if relative_path == "orchestration/scheduler.py":
            if "privacy_evidence_custody" in scope:
                return "gate-client-privacy-consent"
            return "gate-release-evidence-pipeline"
        if relative_path == "orchestration/truncation_recovery_evidence.py":
            return "gate-release-evidence-pipeline"
        if relative_path == "isolation/container.py":
            return "gate-reproduction-capability-policy"
        if relative_path == "scanners/base.py":
            return "gate-full-quality-analysis"
        raise AutonomyInventoryError(
            f"unclassified process identity authority: {relative_path}:{scope}:{kind}"
        )
    if kind == "working-directory":
        if relative_path == "cli.py":
            if "authenticated_runner" in scope:
                return "gate-managed-output-provisioning"
            if any(token in scope for token in ("benchmark", "calibrat")):
                return "gate-benchmark-evidence-authority"
            if any(
                token in scope
                for token in ("model_discovery", "models_discover", "release_bindings")
            ):
                return "gate-autonomous-model-authority"
            raise AutonomyInventoryError(f"unclassified CLI working-directory authority: {scope}")
        return _filesystem_input_gate(relative_path, scope, expression)
    if relative_path.startswith("benchmark/"):
        return "gate-benchmark-evidence-authority"
    if relative_path == "orchestration/cost_ledger.py":
        return "gate-cost-ledger-provisioning"
    if relative_path == "cli.py" and "authenticated_runner" in searchable:
        return "gate-managed-output-provisioning"
    if relative_path.startswith("models/authenticated_runner"):
        return "gate-managed-output-provisioning"
    if relative_path == "models/release_attestation.py":
        return "gate-autonomous-model-authority"
    if relative_path.startswith("release"):
        return "gate-release-evidence-pipeline"
    if relative_path == "orchestration/pipeline.py" and kind == "host-platform":
        return "gate-report-delivery"
    if kind == "host-identity":
        if relative_path == "isolation/container_cleanup.py":
            return "gate-managed-output-provisioning"
        if relative_path == "isolation/dependency_snapshot.py":
            return "gate-dependency-snapshot"
        if relative_path == "orchestration/managed_host_tools.py":
            return "gate-managed-toolchain-bundle"
        if relative_path == "models/candidate_selection.py":
            return "gate-autonomous-model-authority"
        if relative_path == "isolation/container.py":
            return "gate-reproduction-capability-policy"
        if relative_path == "isolation/hardhat_loopback_relay.py":
            return "gate-fork-environment"
        if relative_path == "scanners/read_only_rpc.py":
            return "gate-fork-environment"
        if relative_path in {"scanners/fork_matrix.py", "scanners/runner.py"}:
            return "gate-managed-output-provisioning"
        if relative_path == "solidity/reproduction.py":
            return "gate-reproduction-capability-policy"
    if kind == "path-resolution":
        return "gate-managed-toolchain-bundle"
    if kind in {"host-platform", "host-identity", "python-runtime"}:
        return "gate-managed-toolchain-bundle"
    if kind == "temporary-root":
        return "gate-managed-output-provisioning"
    if kind in {"home-resolution", "home-expansion"}:
        if relative_path == "operator_secrets.py":
            return "gate-provider-secret-transport"
        if relative_path == "repository/discovery.py":
            return "gate-client-audit-scope"
        return "gate-managed-toolchain-bundle"
    if relative_path == "operator_secrets.py":
        return "gate-provider-secret-transport"
    if relative_path == "config.py":
        return "gate-managed-profile"
    if "api_key_env_var" in searchable or "certoraadapter" in searchable:
        return "gate-provider-secret-transport"
    if any(token in searchable for token in ("fork_rpc", "rpc_url_env", "fork_matrix")):
        return "gate-fork-environment"
    if relative_path in {
        "repository/discovery.py",
        "scanners/base.py",
        "scanners/clean_chain.py",
        "scanners/foundry.py",
        "scanners/slither.py",
        "isolation/container.py",
    }:
        return "gate-managed-toolchain-bundle"
    raise AutonomyInventoryError(
        f"unclassified direct environment authority: {relative_path}:{scope}:{kind}"
    )


def _discover_direct_environment_sources(source_root: Path) -> list[_SourceDraft]:
    occurrences = _direct_environment_occurrences(source_root)
    shape = [list(item) for item in occurrences]
    _assert_frozen_source_shape(
        label="direct environment and PATH-resolution loci",
        observed=shape,
        expected_sha256=_FROZEN_DIRECT_ENVIRONMENT_LOCI_SHA256,
    )
    per_scope_counts: dict[tuple[str, str, str], int] = {}
    drafts: list[_SourceDraft] = []
    for relative_path, scope, kind, expression in occurrences:
        key = (relative_path, scope, kind)
        ordinal = per_scope_counts.get(key, 0) + 1
        per_scope_counts[key] = ordinal
        module = relative_path.removesuffix(".py").replace("/", ".").lower()
        scope_id = scope.lower().replace("<", "").replace(">", "")
        source_id = f"direct-env-ast:{module}:{scope_id}:{kind}:{ordinal}"
        gate_id = _direct_environment_gate(relative_path, scope, kind, expression)
        drafts.append(
            _classified_source(
                source_id=source_id,
                source_kind=CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT,
                source_path=f"src/mmaudit/{relative_path}:{scope}:{kind}:{ordinal}",
                semantics=_canonical_sha256(
                    {
                        "relative_path": relative_path,
                        "scope": scope,
                        "kind": kind,
                        "expression": expression,
                    }
                ),
                gate_id=gate_id,
            )
        )
    return drafts


class _EntropyBoundaryVisitor(_ScopedBoundaryVisitor):
    """Collect the finite random-value family reviewed for authority visibility."""

    def __init__(self, aliases: Mapping[str, str]) -> None:
        super().__init__(aliases)
        self.occurrences: list[tuple[str, str, str]] = []

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._qualified_name(node.func) or self._binding_resolution(node.func)
        if call_name in {"secrets.token_hex", "uuid.uuid4"}:
            scope = ".".join(self.scope) if self.scope else "module"
            self.occurrences.append(
                (
                    scope,
                    call_name,
                    ast.dump(node, annotate_fields=True, include_attributes=False),
                )
            )
        self.generic_visit(node)


def _entropy_input_occurrences(
    source_root: Path,
) -> tuple[tuple[str, str, str, str], ...]:
    result: list[tuple[str, str, str, str]] = []
    for path in _python_source_paths(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        try:
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise AutonomyInventoryError(
                f"entropy-input module cannot be parsed: {relative_path}"
            ) from exc
        visitor = _EntropyBoundaryVisitor(_import_aliases(parsed))
        visitor.visit(parsed)
        result.extend(
            (relative_path, scope, kind, expression)
            for scope, kind, expression in visitor.occurrences
        )
    return tuple(result)


def _entropy_input_classification(
    relative_path: str,
    scope: str,
) -> tuple[SourceCoverageClassification, str | None]:
    if relative_path == "orchestration/cost_ledger.py":
        return SourceCoverageClassification.GATE, "gate-cost-ledger-provisioning"
    if relative_path == "models/openrouter.py":
        return SourceCoverageClassification.GATE, "gate-authenticated-real-campaign"
    if relative_path == "isolation/container.py":
        return SourceCoverageClassification.GATE, "gate-fork-environment"
    if relative_path == "orchestration/pipeline.py":
        if scope == "AuditPipeline._validate_models":
            return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
        if scope == "AuditPipeline._create_run_dir":
            return SourceCoverageClassification.GATE, "gate-managed-output-provisioning"
    if relative_path == "scanners/fork_matrix.py":
        return SourceCoverageClassification.GATE, "gate-fork-environment"
    if relative_path == "scanners/read_only_rpc.py":
        return SourceCoverageClassification.GATE, "gate-fork-environment"
    if relative_path in {
        "models/authenticated_runner_execution.py",
        "models/calibration.py",
        "models/refresh_staging.py",
        "orchestration/context_manifest.py",
    }:
        return SourceCoverageClassification.NON_GATING_CONTROL, None
    if relative_path == "cli.py":
        if scope in {"models_discover.execute", "models_authenticated_runner.execute"}:
            return SourceCoverageClassification.GATE, "gate-autonomous-model-authority"
        if scope == "models_benchmark.execute":
            return SourceCoverageClassification.GATE, "gate-benchmark-evidence-authority"
        if scope in {
            "_preflight_authenticated_runner_output",
            "_write_authenticated_runner_output_fresh",
            "_write_authenticated_runner_smoke_output_fresh",
            "doctor_command",
        }:
            return SourceCoverageClassification.NON_GATING_CONTROL, None
    raise AutonomyInventoryError(f"unclassified entropy input authority: {relative_path}:{scope}")


def _discover_entropy_input_sources(source_root: Path) -> list[_SourceDraft]:
    occurrences = _entropy_input_occurrences(source_root)
    _assert_frozen_source_shape(
        label="authority-visible entropy loci",
        observed=[list(item) for item in occurrences],
        expected_sha256=_FROZEN_ENTROPY_INPUT_LOCI_SHA256,
    )
    per_scope_counts: dict[tuple[str, str, str], int] = {}
    drafts: list[_SourceDraft] = []
    for relative_path, scope, kind, expression in occurrences:
        key = (relative_path, scope, kind)
        ordinal = per_scope_counts.get(key, 0) + 1
        per_scope_counts[key] = ordinal
        classification, gate_id = _entropy_input_classification(relative_path, scope)
        module = relative_path.removesuffix(".py").replace("/", ".").lower()
        scope_id = scope.lower().replace("<", "").replace(">", "")
        drafts.append(
            _classified_source(
                source_id=f"entropy-ast:{module}:{scope_id}:{kind.replace('.', '-')}:{ordinal}",
                source_kind=CompletionInputSourceKind.ENTROPY_INPUT,
                source_path=f"src/mmaudit/{relative_path}:{scope}:{kind}:{ordinal}",
                semantics=_canonical_sha256(
                    {
                        "relative_path": relative_path,
                        "scope": scope,
                        "kind": kind,
                        "expression": expression,
                        "authority_crossing": gate_id is not None,
                    }
                ),
                gate_id=gate_id,
                classification=classification if gate_id is None else None,
            )
        )
    return drafts


class _ExternalInputBoundaryVisitor(_ScopedBoundaryVisitor):
    """Collect filesystem-backed and interactive operator input loci."""

    def __init__(self, aliases: Mapping[str, str]) -> None:
        super().__init__(aliases)
        self.filesystem: list[tuple[str, str, str]] = []
        self.interactive: list[tuple[str, str]] = []

    def _scope(self) -> str:
        return ".".join(self.scope) if self.scope else "module"

    def _open_observation_kind(self, node: ast.Call, call_name: str | None) -> str | None:
        if call_name == "os.open":
            flags = node.args[1] if len(node.args) > 1 else None
            for keyword in node.keywords:
                if keyword.arg == "flags":
                    flags = keyword.value
            flag_names = (
                {
                    qualified.rsplit(".", 1)[-1]
                    for item in ast.walk(flags)
                    if isinstance(item, (ast.Attribute, ast.Name))
                    and (qualified := self._qualified_name(item)) is not None
                }
                if flags is not None
                else set()
            )
            if "O_RDWR" in flag_names:
                return "content-read"
            if "O_WRONLY" in flag_names:
                return "metadata-observation" if "O_EXCL" in flag_names else None
            return "content-read"
        positional_index = (
            1 if call_name in {"builtins.open", "io.open", "pathlib.Path.open"} else 0
        )
        mode: ast.AST | None = (
            node.args[positional_index] if len(node.args) > positional_index else None
        )
        for keyword in node.keywords:
            if keyword.arg == "mode":
                mode = keyword.value
        if not isinstance(mode, ast.Constant) or not isinstance(mode.value, str):
            return "content-read"
        if "+" in mode.value or mode.value[:1] not in {"w", "a", "x"}:
            return "content-read"
        return "metadata-observation" if mode.value.startswith("x") else None

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self._qualified_name(node.func) or self._binding_resolution(node.func)
        filesystem_kind: str | None = None
        if call_name in {"builtins.open", "io.open", "os.open"}:
            filesystem_kind = self._open_observation_kind(node, call_name)
        elif call_name in {
            "pathlib.Path.read_bytes",
            "pathlib.Path.read_text",
            "shutil.copy",
            "shutil.copy2",
            "shutil.copyfile",
            "shutil.copytree",
        } or (
            isinstance(node.func, ast.Attribute) and node.func.attr in {"read_text", "read_bytes"}
        ):
            filesystem_kind = "content-read"
        elif call_name == "pathlib.Path.open" or (
            isinstance(node.func, ast.Attribute) and node.func.attr == "open"
        ):
            filesystem_kind = self._open_observation_kind(node, call_name)
        elif call_name in {"json.load", "tomllib.load", "yaml.safe_load", "yaml.load"}:
            filesystem_kind = "content-read"
        elif (literal_getattr := self._literal_getattr(node.func)) is not None and literal_getattr[
            1
        ] == "is_junction":
            filesystem_kind = "metadata-observation"
        elif call_name in {
            "glob.glob",
            "glob.iglob",
            "os.listdir",
            "os.scandir",
            "os.walk",
            "pathlib.Path.glob",
            "pathlib.Path.iterdir",
            "pathlib.Path.rglob",
        } or (
            isinstance(node.func, ast.Attribute) and node.func.attr in {"glob", "rglob", "iterdir"}
        ):
            filesystem_kind = "directory-enumeration"
        elif (
            call_name
            in {
                "pathlib.Path.exists",
                "pathlib.Path.is_dir",
                "pathlib.Path.is_file",
                "pathlib.Path.is_junction",
                "pathlib.Path.is_symlink",
                "pathlib.Path.lstat",
                "pathlib.Path.readlink",
                "pathlib.Path.resolve",
                "pathlib.Path.samefile",
                "pathlib.Path.stat",
            }
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr
                in {
                    "stat",
                    "lstat",
                    "exists",
                    "is_file",
                    "is_dir",
                    "is_junction",
                    "is_symlink",
                    "resolve",
                    "samefile",
                    "readlink",
                }
            )
            or call_name
            in {
                "os.stat",
                "os.fstat",
                "os.lstat",
                "os.access",
                "os.readlink",
                "os.path.exists",
                "os.path.isfile",
                "os.path.isdir",
                "os.path.islink",
                "os.path.lexists",
                "os.path.realpath",
                "os.path.samefile",
            }
        ):
            filesystem_kind = "metadata-observation"
        if filesystem_kind is not None:
            self.filesystem.append(
                (
                    self._scope(),
                    filesystem_kind,
                    ast.dump(node, annotate_fields=True, include_attributes=False),
                )
            )
        interactive = call_name in {
            "builtins.input",
            "getpass.getpass",
            "typer.confirm",
            "typer.prompt",
            "click.confirm",
            "click.prompt",
            "rich.prompt.Confirm.ask",
            "rich.prompt.Prompt.ask",
        }
        if interactive:
            self.interactive.append(
                (
                    self._scope(),
                    ast.dump(node, annotate_fields=True, include_attributes=False),
                )
            )
        self.generic_visit(node)


def _external_input_occurrences(
    source_root: Path,
) -> tuple[tuple[tuple[str, str, str, str], ...], tuple[tuple[str, str, str], ...]]:
    filesystem: list[tuple[str, str, str, str]] = []
    interactive: list[tuple[str, str, str]] = []
    for path in _python_source_paths(source_root):
        relative_path = path.relative_to(source_root).as_posix()
        try:
            parsed = ast.parse(path.read_text(encoding="utf-8"), filename=relative_path)
        except (OSError, UnicodeError, SyntaxError) as exc:
            raise AutonomyInventoryError(
                f"external-input module cannot be parsed: {relative_path}"
            ) from exc
        visitor = _ExternalInputBoundaryVisitor(_import_aliases(parsed))
        visitor.visit(parsed)
        filesystem.extend(
            (relative_path, scope, kind, expression)
            for scope, kind, expression in visitor.filesystem
        )
        interactive.extend(
            (relative_path, scope, expression) for scope, expression in visitor.interactive
        )
    return tuple(filesystem), tuple(interactive)


_FILESYSTEM_MODULE_GATE_IDS: dict[str, str] = {
    "orchestration/development_corpus_ensemble.py": "gate-release-evidence-pipeline",
    "adversarial_acceptance.py": "gate-release-evidence-pipeline",
    "agents/base.py": "gate-runtime-package-integrity",
    "benchmark/certificate.py": "gate-benchmark-evidence-authority",
    "benchmark/claims.py": "gate-benchmark-evidence-authority",
    "benchmark/engine.py": "gate-benchmark-evidence-authority",
    "benchmark/foundry_mutation_executor.py": "gate-benchmark-evidence-authority",
    "benchmark/model_portfolio.py": "gate-benchmark-evidence-authority",
    "benchmark/models.py": "gate-benchmark-evidence-authority",
    "benchmark/mutations.py": "gate-benchmark-evidence-authority",
    "config.py": "gate-managed-profile",
    "economic_acceptance.py": "gate-release-evidence-pipeline",
    "forensic_export.py": "gate-release-evidence-pipeline",
    "full_protocol_acceptance.py": "gate-release-evidence-pipeline",
    "isolation/container.py": "gate-reproduction-capability-policy",
    "isolation/dependencies.py": "gate-dependency-snapshot",
    "isolation/dependency_snapshot.py": "gate-dependency-snapshot",
    "isolation/hardhat_loopback_relay.py": "gate-managed-toolchain-bundle",
    "isolation/provenance.py": "gate-managed-toolchain-bundle",
    "isolation/repository_code.py": "gate-reproduction-capability-policy",
    "logging.py": "gate-secret-redaction-policy",
    "models/authenticated_runner_durable_bundle.py": "gate-managed-output-provisioning",
    "models/authenticated_runner_execution.py": "gate-managed-output-provisioning",
    "models/authenticated_runner_smoke_corpus.py": "gate-authenticated-real-campaign",
    "models/actor_model.py": "gate-full-quality-analysis",
    "models/calibration.py": "gate-benchmark-evidence-authority",
    "models/candidate_plan_ancestry.py": "gate-autonomous-model-authority",
    "models/candidate_registry_bridge.py": "gate-autonomous-model-authority",
    "models/candidate_revocation.py": "gate-autonomous-model-authority",
    "models/candidate_selection.py": "gate-autonomous-model-authority",
    "models/discovery.py": "gate-autonomous-model-authority",
    "models/lineage_authority.py": "gate-human-signoff-boundary",
    "models/policy_eligibility_authority.py": "gate-human-signoff-boundary",
    "models/public_lineage_authority.py": "gate-autonomous-model-authority",
    "models/qualification.py": "gate-autonomous-model-authority",
    "models/qualification_workflow.py": "gate-autonomous-model-authority",
    "models/refresh.py": "gate-autonomous-model-authority",
    "models/refresh_staging.py": "gate-autonomous-model-authority",
    "models/registry.py": "gate-autonomous-model-authority",
    "models/release_attestation.py": "gate-autonomous-model-authority",
    "models/retry_continuity.py": "gate-managed-profile",
    "operator_secrets.py": "gate-provider-secret-transport",
    "orchestration/autonomy_gate_inventory.py": "gate-runtime-package-integrity",
    "orchestration/actor_model.py": "gate-client-audit-scope",
    "orchestration/certification.py": "gate-release-evidence-pipeline",
    "orchestration/ci.py": "gate-release-evidence-pipeline",
    "orchestration/context_manifest.py": "gate-full-quality-analysis",
    "orchestration/cost_ledger.py": "gate-cost-ledger-provisioning",
    "orchestration/learning.py": "gate-managed-output-provisioning",
    "orchestration/manifest.py": "gate-release-evidence-pipeline",
    "orchestration/managed_host_tools.py": "gate-managed-toolchain-bundle",
    "orchestration/managed_image_files.py": "gate-managed-toolchain-bundle",
    "orchestration/managed_fork_matrix.py": "gate-managed-toolchain-bundle",
    "orchestration/managed_fork_archives.py": "gate-fork-environment",
    "orchestration/managed_pipeline.py": "gate-managed-toolchain-bundle",
    "orchestration/managed_provisioning.py": "gate-managed-provisioning",
    "orchestration/managed_provisioning_runtime.py": "gate-managed-provisioning",
    "orchestration/managed_toolchain.py": "gate-managed-toolchain-bundle",
    "orchestration/pipeline.py": "gate-full-quality-analysis",
    "orchestration/prior_audit.py": "gate-full-quality-analysis",
    "orchestration/replay.py": "gate-release-evidence-pipeline",
    "orchestration/scheduler.py": "gate-managed-output-provisioning",
    "orchestration/scheduler_runtime.py": "gate-runtime-package-integrity",
    "orchestration/verification.py": "gate-release-evidence-pipeline",
    "privacy.py": "gate-client-privacy-consent",
    "release_artifacts.py": "gate-release-evidence-pipeline",
    "release_candidate.py": "gate-release-evidence-pipeline",
    "release_collection.py": "gate-release-evidence-pipeline",
    "release_gates.py": "gate-release-evidence-pipeline",
    "release_io.py": "gate-release-evidence-pipeline",
    "release_observations.py": "gate-release-evidence-pipeline",
    "release_run.py": "gate-release-evidence-pipeline",
    "release_runtime.py": "gate-release-evidence-pipeline",
    "release_static.py": "gate-release-evidence-pipeline",
    "release_validation.py": "gate-release-evidence-pipeline",
    "release_verification.py": "gate-release-evidence-pipeline",
    "reporting/json_report.py": "gate-report-delivery",
    "repository/configuration_custody.py": "gate-managed-profile",
    "repository/directory_custody.py": "gate-release-evidence-pipeline",
    "repository/discovery.py": "gate-client-audit-scope",
    "repository/file_custody.py": "gate-release-evidence-pipeline",
    "repository/ignore.py": "gate-client-audit-scope",
    "repository/locations.py": "gate-client-audit-scope",
    "repository/privacy_provenance.py": "gate-synthetic-public-scope",
    "repository/workspace.py": "gate-client-audit-scope",
    "scanners/base.py": "gate-full-quality-analysis",
    "scanners/clean_chain.py": "gate-managed-toolchain-bundle",
    "scanners/codeql.py": "gate-codeql-provisioning",
    "scanners/fork_matrix.py": "gate-managed-output-provisioning",
    "scanners/foundry.py": "gate-full-quality-analysis",
    "scanners/foundry_inventory_runner.py": "gate-full-quality-analysis",
    "scanners/hardhat.py": "gate-full-quality-analysis",
    "scanners/hardhat_finalization.py": "gate-full-quality-analysis",
    "scanners/hardhat_source.py": "gate-full-quality-analysis",
    "scanners/hardhat_supervision.py": "gate-full-quality-analysis",
    "scanners/normalization.py": "gate-full-quality-analysis",
    "scanners/read_only_rpc.py": "gate-fork-environment",
    "scanners/repository_suite.py": "gate-full-quality-analysis",
    "scanners/runner.py": "gate-full-quality-analysis",
    "scanners/slither.py": "gate-managed-toolchain-bundle",
    "scanners/trusted_inputs.py": "gate-managed-toolchain-bundle",
    "snapshots/compare.py": "gate-snapshot-intake-consent",
    "snapshots/importer.py": "gate-snapshot-intake-consent",
    "snapshots/schema.py": "gate-snapshot-intake-consent",
    "solidity/compile.py": "gate-full-quality-analysis",
    "solidity/engines/certora.py": "gate-formal-analysis",
    "solidity/engines/halmos.py": "gate-formal-analysis",
    "solidity/engines/kontrol.py": "gate-formal-analysis",
    "solidity/formal.py": "gate-formal-analysis",
    "solidity/index.py": "gate-full-quality-analysis",
    "solidity/invariant_execution.py": "gate-invariant-template-library",
    "solidity/projects.py": "gate-full-quality-analysis",
    "solidity/reproduction.py": "gate-full-quality-analysis",
    "solidity/reproduction_integrity.py": "gate-full-quality-analysis",
    "solidity/taxonomy.py": "gate-full-quality-analysis",
    "traceability.py": "gate-release-evidence-pipeline",
}


def _filesystem_input_gate(relative_path: str, scope: str, expression: str = "") -> str:
    searchable = f"{scope}:{expression}".lower()
    if relative_path == "isolation/container_cleanup.py":
        if scope in {"_runtime_identity", "_control_environment", "_run_control_command"}:
            return "gate-managed-toolchain-bundle"
        return "gate-managed-output-provisioning"
    if relative_path == "benchmark/claims.py" and "human_comparison" in scope:
        return "gate-human-signoff-boundary"
    if relative_path == "cli.py":
        if "cost_ledger" in expression:
            return "gate-cost-ledger-provisioning"
        if (
            scope
            in {
                "_audit_config_overrides",
                "_cache_path",
                "_verification_configuration_root",
            }
            or "config_path" in expression
        ):
            return "gate-managed-profile"
        if "authenticated_runner" in scope:
            return "gate-managed-output-provisioning"
        if scope in {
            "_preflight_calibrated_policy_output",
            "_preflight_model_benchmark_output",
            "_preflight_model_benchmark_portfolio_output",
            "_preflight_model_calibration_output",
            "benchmark_certify_command",
            "benchmark_command",
            "models_benchmark.execute",
            "verify_certificate_command",
        }:
            return "gate-benchmark-evidence-authority"
        if scope in {
            "_preflight_model_discovery_output_dir",
            "models_discover.execute",
            "models_observe_release_bindings",
        }:
            return "gate-autonomous-model-authority"
        if scope == "_repo_path":
            return "gate-client-audit-scope"
        if scope in {"doctor_command", "init_command"}:
            return "gate-managed-provisioning"
        if scope == "explain_command":
            return "gate-report-delivery"
        if scope in {
            "certify_run_command",
            "replay_command",
            "verify_forensic_export_command",
            "verify_run_command",
        }:
            return "gate-release-evidence-pipeline"
        if scope == "export_forensic_command":
            return "gate-forensic-export-consent"
        if scope == "snapshot_import_command":
            return "gate-snapshot-intake-consent"
        if scope == "module":
            return "gate-runtime-package-integrity"
        raise AutonomyInventoryError(f"unclassified CLI filesystem input authority: {scope}")
    if relative_path == "isolation/container.py":
        if scope == "discover_rootless_container_backend":
            return "gate-managed-toolchain-bundle"
        if (
            scope.startswith("SingleLoopbackHardhatBackend.")
            or scope == "_hardhat_phase_workspace_identity"
        ):
            return "gate-fork-environment"
        if scope == "_hardhat_private_directory_identity":
            return "gate-managed-output-provisioning"
        return "gate-reproduction-capability-policy"
    if relative_path == "isolation/provenance.py" and scope in {
        "_attestation_still_valid",
        "_run_builtin_preflight",
        "_seal_builtin_isolation_backend",
    }:
        return "gate-reproduction-capability-policy"
    if relative_path == "orchestration/pipeline.py":
        if scope == "AuditPipeline.__init__":
            return "gate-managed-profile"
        if scope == "AuditPipeline._run_with_provider":
            if "repo_input" in expression:
                return "gate-client-audit-scope"
            if "output" in expression:
                return "gate-managed-output-provisioning"
        if scope in {
            "AuditPipeline._write_artifacts",
            "_refresh_latest_artifacts",
            "_refresh_latest_artifact",
            "_resolve_scheduler_resume_journal",
            "_safe_output_directory",
            "resolve_safe_output_root",
        }:
            return "gate-managed-output-provisioning"
        if scope == "_load_exact_resume_privacy_evidence":
            return "gate-client-privacy-consent"
        if scope == "_repository_unchanged":
            return "gate-client-audit-scope"
    if relative_path == "orchestration/scheduler_runtime.py" and scope == (
        "_validated_projection_root"
    ):
        return "gate-managed-output-provisioning"
    if relative_path == "scanners/base.py" and scope in {
        "_observe_scanner_executable",
        "scanner_executable_candidate",
    }:
        return "gate-managed-toolchain-bundle"
    if relative_path == "scanners/foundry.py":
        if scope in {
            "_foundry_private_generated_root",
            "_open_private_artifact_directory",
            "_open_private_artifact_tree",
            "_private_artifact_file_sha256",
            "_private_artifact_live_file_size",
            "_private_artifact_usage.walk_directory",
            "_validate_private_artifact_directory",
        }:
            return "gate-managed-output-provisioning"
        if scope == "_resolve_pinned_solidity_compiler" or "compiler" in searchable:
            return "gate-managed-toolchain-bundle"
    if relative_path == "scanners/hardhat.py" and scope == "verified_hardhat_reporter_source":
        return "gate-managed-toolchain-bundle"
    if relative_path == "scanners/runner.py":
        if scope in {
            "_prepare_private_preflight_root",
            "_require_private_directory",
            "_require_trusted_output_ancestors",
            "_require_trusted_output_directory",
        }:
            return "gate-managed-output-provisioning"
        if scope in {"_resolved_executable", "preflight_configured_scanner_tools"}:
            return "gate-managed-toolchain-bundle"
        if scope == "_preflight_without_isolation":
            return "gate-reproduction-capability-policy"
    if relative_path == "solidity/compile.py":
        if scope == "_copy_prepared_dependencies":
            return "gate-dependency-snapshot"
        if scope in {"_compile_one", "_file_sha256", "_managed_compilation_selection"}:
            return "gate-managed-toolchain-bundle"
    if relative_path == "solidity/formal.py" and scope in {
        "FormalAdapter.available",
        "HalmosAdapter.build_command_with_dependencies",
        "HalmosAdapter.dependencies",
        "HalmosAdapter.prepare_workspace",
        "KontrolAdapter.prepare_workspace",
        "_ManagedFormalSelection.verify_roots",
        "_file_sha256",
    }:
        return "gate-managed-toolchain-bundle"
    if relative_path == "solidity/invariant_execution.py":
        if scope in {
            "_file_sha256",
            "_validated_external_executable",
            "_ManagedInvariantSelection.verify_roots",
        } or (scope == "FoundryInvariantRunner.run" and "copyfile" in expression):
            return "gate-managed-toolchain-bundle"
        return "gate-full-quality-analysis"
    if relative_path == "solidity/reproduction.py":
        if scope in {
            "_ManagedReproductionSelection.verify_roots",
            "_external_executable",
            "_file_sha256",
            "_macos_shebang_interpreter",
            "_validated_macos_executable_aliases",
            "_validated_macos_toolchain_root",
            "_validated_macos_venv_toolchain_root",
            "_validated_regular_file_aliases",
        }:
            return "gate-managed-toolchain-bundle"
        if scope in {
            "BubblewrapBackend._wrap",
            "MacOSSandboxBackend._wrap",
            "default_isolation_backend",
        }:
            return "gate-reproduction-capability-policy"
    gate_id = _FILESYSTEM_MODULE_GATE_IDS.get(relative_path)
    if gate_id is None:
        raise AutonomyInventoryError(
            f"unclassified filesystem input authority: {relative_path}:{scope}"
        )
    return gate_id


def _discover_external_input_sources(source_root: Path) -> list[_SourceDraft]:
    filesystem, interactive = _external_input_occurrences(source_root)
    _assert_frozen_source_shape(
        label="interactive operator input loci",
        observed=[list(item) for item in interactive],
        expected_sha256=_FROZEN_INTERACTIVE_INPUT_LOCI_SHA256,
    )
    if interactive:
        raise AutonomyInventoryError("interactive operator input lacks an autonomous disposition")
    _assert_frozen_source_shape(
        label="filesystem input loci",
        observed=[list(item) for item in filesystem],
        expected_sha256=_FROZEN_FILESYSTEM_INPUT_LOCI_SHA256,
    )
    per_scope_counts: dict[tuple[str, str], int] = {}
    drafts: list[_SourceDraft] = []
    for relative_path, scope, kind, expression in filesystem:
        key = (relative_path, scope)
        ordinal = per_scope_counts.get(key, 0) + 1
        per_scope_counts[key] = ordinal
        module = relative_path.removesuffix(".py").replace("/", ".").lower()
        scope_id = scope.lower()
        drafts.append(
            _classified_source(
                source_id=f"filesystem-input:{module}:{scope_id}:{ordinal}",
                source_kind=CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
                source_path=f"src/mmaudit/{relative_path}:{scope}:{kind}:{ordinal}",
                semantics=_canonical_sha256(
                    {
                        "relative_path": relative_path,
                        "scope": scope,
                        "kind": kind,
                        "expression": expression,
                    }
                ),
                gate_id=_filesystem_input_gate(relative_path, scope, expression),
            )
        )
    return drafts


def _discover_packaging_entrypoint_sources(repository_root: Path) -> list[_SourceDraft]:
    path = repository_root / "pyproject.toml"
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
        project = document["project"]
        scripts = project["scripts"]
    except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError) as exc:
        raise AutonomyInventoryError("project script entrypoints cannot be inspected") from exc
    if not isinstance(scripts, dict) or any(
        not isinstance(name, str) or not isinstance(target, str) for name, target in scripts.items()
    ):
        raise AutonomyInventoryError("project script entrypoints are not a string mapping")
    observed = sorted((name, target) for name, target in scripts.items())
    _assert_frozen_source_shape(
        label="project script entrypoints",
        observed=observed,
        expected_sha256=_FROZEN_PROJECT_SCRIPTS_SHA256,
    )
    gates = {
        "mmaudit": "gate-managed-completion-entrypoint",
        "mmaudit-hardhat-loopback": "gate-managed-toolchain-bundle",
    }
    if set(scripts) != set(gates):
        raise AutonomyInventoryError("project script entrypoint classification is incomplete")
    return [
        _classified_source(
            source_id=f"explicit:packaging-entrypoint-{name}",
            source_kind=CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
            source_path=f"pyproject.toml:[project.scripts].{name}",
            semantics=_canonical_sha256({"name": name, "target": target}),
            gate_id=gates[name],
        )
        for name, target in observed
    ]


def _explicit_anchor(
    source_id: str,
    value: object,
    gate_id: str,
    *,
    source_path: str | None = None,
) -> _SourceDraft:
    return _classified_source(
        source_id=f"explicit:{source_id}",
        source_kind=CompletionInputSourceKind.EXPLICIT_NON_FIELD_GATE,
        source_path=source_path or _qualified_name(value),
        semantics=_canonical_sha256(
            {
                "anchor": _qualified_name(value),
                "normalized_ast": _normalized_ast(value),
                "gate_id": gate_id,
            }
        ),
        gate_id=gate_id,
    )


def _explicit_environment_source(
    source_id: str,
    variable: str,
    anchors: Sequence[object],
    gate_id: str,
    *,
    source_path: str,
) -> _SourceDraft:
    """Bind one direct or dynamically selected process-environment input."""

    return _classified_source(
        source_id=f"direct-env:{source_id}",
        source_kind=CompletionInputSourceKind.DIRECT_ENVIRONMENT_INPUT,
        source_path=source_path,
        semantics=_canonical_sha256(
            {
                "environment_input": variable,
                "anchors": [
                    {
                        "qualified_name": _qualified_name(anchor),
                        "normalized_ast": _normalized_ast(anchor),
                    }
                    for anchor in anchors
                ],
                "gate_id": gate_id,
            }
        ),
        gate_id=gate_id,
    )


def _default_explicit_sources() -> list[_SourceDraft]:
    from mmaudit.benchmark.development import (
        bind_development_benchmark,
        read_development_benchmark_truth,
        score_development_audit,
        score_development_judgment,
    )
    from mmaudit.benchmark.development_comparison import compare_development_scores
    from mmaudit.benchmark.development_corpus import (
        bind_development_corpus_benchmark,
        read_development_corpus_truth,
        score_development_corpus,
    )
    from mmaudit.benchmark.development_corpus_ensemble import score_development_corpus_ensemble
    from mmaudit.benchmark.development_ensemble import score_development_ensemble
    from mmaudit.development_cli import ensemble_development_manifest_command
    from mmaudit.isolation.container import (
        SingleLoopbackHardhatBackend,
        rootless_runtime_environment,
    )
    from mmaudit.isolation.container_cleanup import cleanup_rootless_container
    from mmaudit.isolation.dependencies import prepare_dependencies
    from mmaudit.models.development_audit import prepare_development_audit
    from mmaudit.models.development_corpus import (
        freeze_development_corpus,
        prepare_development_corpus,
    )
    from mmaudit.models.development_corpus_ensemble import prepare_development_corpus_ensemble
    from mmaudit.models.development_corpus_judgment import (
        prepare_development_corpus_judgment,
        require_development_corpus_judgment_candidate,
    )
    from mmaudit.models.development_diagnostics import project_development_completion_telemetry
    from mmaudit.models.development_ensemble import prepare_development_ensemble
    from mmaudit.models.development_judgment import (
        prepare_development_judgment,
        validate_development_accounting_entries,
        validate_development_candidate_accounting,
    )
    from mmaudit.models.development_routing import observe_development_routing
    from mmaudit.models.development_transport import (
        development_request_timeout_seconds,
        review_development_audit_shard,
        review_development_corpus_judgment_shard,
        review_development_corpus_shard,
        review_development_judgment_shard,
    )
    from mmaudit.models.schemas import AuditReport
    from mmaudit.operator_secrets import load_operator_secrets, select_operator_secret_file
    from mmaudit.orchestration.consensus import preliminary_status
    from mmaudit.orchestration.cost_ledger import AtomicCostLedger
    from mmaudit.orchestration.development_audit import run_development_audit
    from mmaudit.orchestration.development_budget import development_uncertain_reservations
    from mmaudit.orchestration.development_comparison import compare_development_score_files
    from mmaudit.orchestration.development_corpus import _report as corpus_accounting_report
    from mmaudit.orchestration.development_corpus import (
        require_development_corpus_upstream as require_candidate_upstream,
    )
    from mmaudit.orchestration.development_corpus import run_development_corpus
    from mmaudit.orchestration.development_corpus_ensemble import (
        _report as corpus_ensemble_accounting_report,
    )
    from mmaudit.orchestration.development_corpus_ensemble import run_development_corpus_ensemble
    from mmaudit.orchestration.development_corpus_judgment import (
        _report as corpus_judgment_accounting_report,
    )
    from mmaudit.orchestration.development_corpus_judgment import (
        require_development_corpus_upstream,
        run_development_corpus_judgment,
    )
    from mmaudit.orchestration.development_ensemble import _report as ensemble_accounting_report
    from mmaudit.orchestration.development_ensemble import run_development_ensemble
    from mmaudit.orchestration.development_judgment import run_development_judgment
    from mmaudit.orchestration.managed_fork_archives import (
        ManagedForkArchives,
        ManagedForkArchiveSource,
        _invariant_state,
        _reproduction_state,
        prepare_managed_fork_archives,
    )
    from mmaudit.orchestration.managed_image_files import verify_managed_image_files
    from mmaudit.orchestration.managed_image_layers import verify_managed_image_layers
    from mmaudit.orchestration.managed_image_metadata import read_managed_image_metadata
    from mmaudit.orchestration.pipeline import (
        AuditPipeline,
        _enforce_post_judge_execution_severity_accounting,
    )
    from mmaudit.privacy import load_privacy_retention_consent
    from mmaudit.release_io import (
        revalidate_composed_evidence_file_binding,
        stream_file_evidence,
        write_composed_json_evidence,
    )
    from mmaudit.reporting.client import _finding_detail
    from mmaudit.reporting.markdown import _status_qualification
    from mmaudit.repository.development_corpus import load_development_corpus
    from mmaudit.repository.directory_custody import prepare_owned_empty_directory
    from mmaudit.scanners.base import sanitized_scanner_environment
    from mmaudit.scanners.clean_chain import TrustedCleanAnvilLauncher
    from mmaudit.scanners.codeql import CodeQLScanner
    from mmaudit.scanners.fork_matrix import RepositoryForkMatrixRunner
    from mmaudit.scanners.foundry import FoundryForkScanner, _resolve_pinned_solidity_compiler
    from mmaudit.scanners.hardhat import _fork_rpc_value
    from mmaudit.scanners.hardhat_execution import capture_hardhat_two_phase_execution
    from mmaudit.scanners.hardhat_finalization import finalize_hardhat_phase
    from mmaudit.scanners.hardhat_protocol import (
        consume_hardhat_test_phase_capture,
        prepare_hardhat_test_phase_from_capture,
    )
    from mmaudit.scanners.hardhat_supervision import supervise_hardhat_phase_process
    from mmaudit.scanners.offline_fork_rpc import load_offline_fork_rpc_archive
    from mmaudit.scanners.offline_fork_service import OfflineForkRpcLease
    from mmaudit.scanners.trivy import TrivyScanner
    from mmaudit.solidity.formal import FormalRunner
    from mmaudit.solidity.invariant_execution import FoundryInvariantRunner
    from mmaudit.solidity.reproduction import ForkReproductionRunner

    sources = [
        _explicit_anchor(
            "development-benchmark-truth",
            read_development_benchmark_truth,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-benchmark-plan-binding",
            bind_development_benchmark,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-benchmark-score",
            score_development_audit,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-benchmark-comparison",
            compare_development_scores,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-comparison-files",
            compare_development_score_files,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-routing-observation",
            observe_development_routing,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-completion-telemetry",
            project_development_completion_telemetry,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-audit-frozen-plan", prepare_development_audit, "gate-client-audit-scope"
        ),
        _explicit_anchor(
            "development-audit-shard-transport",
            review_development_audit_shard,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-audit-sequential-run", run_development_audit, "gate-full-quality-analysis"
        ),
        _explicit_anchor(
            "development-judgment-frozen-plan",
            prepare_development_judgment,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-judgment-shard-transport",
            review_development_judgment_shard,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-judgment-sequential-run",
            run_development_judgment,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "development-judgment-candidate-accounting",
            validate_development_candidate_accounting,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-judgment-impact",
            score_development_judgment,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-ensemble-frozen-plan",
            prepare_development_ensemble,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-ensemble-sequential-run",
            run_development_ensemble,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "development-ensemble-accounting",
            ensemble_accounting_report,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-ensemble-impact",
            score_development_ensemble,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-corpus-frozen-manifest",
            freeze_development_corpus,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-selected-source-loader",
            load_development_corpus,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-frozen-plan",
            prepare_development_corpus,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-shard-transport",
            review_development_corpus_shard,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-selected-request-deadline",
            development_request_timeout_seconds,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-corpus-sequential-run",
            run_development_corpus,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "development-corpus-accounting",
            corpus_accounting_report,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-corpus-judgment-retained-candidate",
            require_development_corpus_judgment_candidate,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-pinned-label-reader",
            read_development_corpus_truth,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-benchmark-binding",
            bind_development_corpus_benchmark,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-candidate-measurement",
            score_development_corpus,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-corpus-judgment-frozen-plan",
            prepare_development_corpus_judgment,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-judgment-shard-transport",
            review_development_corpus_judgment_shard,
            "gate-provider-secret-transport",
        ),
        _explicit_anchor(
            "development-corpus-judgment-sequential-run",
            run_development_corpus_judgment,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "development-corpus-judgment-accounting",
            corpus_judgment_accounting_report,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-corpus-ensemble-frozen-plan",
            prepare_development_corpus_ensemble,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-ensemble-sequential-run",
            run_development_corpus_ensemble,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "development-corpus-ensemble-accounting",
            corpus_ensemble_accounting_report,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-corpus-ensemble-original-measurement",
            score_development_corpus_ensemble,
            "gate-benchmark-evidence-authority",
        ),
        _explicit_anchor(
            "development-corpus-ensemble-cli",
            ensemble_development_manifest_command,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-corpus-candidate-upstream-custody",
            require_candidate_upstream,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "precreated-private-directory-custody",
            prepare_owned_empty_directory,
            "gate-managed-output-provisioning",
        ),
        _explicit_anchor(
            "bounded-composed-json-writer",
            write_composed_json_evidence,
            "gate-release-evidence-pipeline",
        ),
        _explicit_anchor(
            "composed-evidence-original-size-custody",
            revalidate_composed_evidence_file_binding,
            "gate-release-evidence-pipeline",
        ),
        _explicit_anchor(
            "development-corpus-judgment-upstream-custody",
            require_development_corpus_upstream,
            "gate-client-audit-scope",
        ),
        _explicit_anchor(
            "development-prior-stage-accounting",
            validate_development_accounting_entries,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "managed-image-file-membership",
            verify_managed_image_files,
            "gate-managed-toolchain-bundle",
        ),
        _explicit_anchor(
            "managed-image-layer-bytes",
            verify_managed_image_layers,
            "gate-managed-toolchain-bundle",
        ),
        _explicit_anchor(
            "bound-read-only-evidence-stream",
            stream_file_evidence,
            "gate-release-evidence-pipeline",
        ),
        _explicit_anchor(
            "managed-image-metadata-chain",
            read_managed_image_metadata,
            "gate-managed-toolchain-bundle",
        ),
        _explicit_anchor(
            "hardhat-phase-finalization", finalize_hardhat_phase, "gate-full-quality-analysis"
        ),
        _explicit_anchor(
            "rootless-exact-container-cleanup",
            cleanup_rootless_container,
            "gate-managed-output-provisioning",
        ),
        _explicit_anchor(
            "hardhat-owned-two-phase-execution",
            capture_hardhat_two_phase_execution,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "hardhat-phase-container-layout",
            SingleLoopbackHardhatBackend.wrap_hardhat_phase,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "hardhat-captured-inventory-preparation",
            prepare_hardhat_test_phase_from_capture,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "hardhat-captured-test-consumption",
            consume_hardhat_test_phase_capture,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "hardhat-phase-output-supervision",
            supervise_hardhat_phase_process,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "managed-invariant-archive-selection",
            _invariant_state,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "managed-reproduction-archive-selection",
            _reproduction_state,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "managed-offline-primary-archive-selection",
            ManagedForkArchiveSource,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "managed-primary-foundry-consumption",
            FoundryForkScanner,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "managed-offline-fork-archive-preparation",
            prepare_managed_fork_archives,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "managed-offline-fork-archive-consumption",
            ManagedForkArchives,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "offline-fork-read-lease",
            OfflineForkRpcLease,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "offline-fork-read-archive",
            load_offline_fork_rpc_archive,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "cost-ledger-existing-state-contract",
            AtomicCostLedger,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "development-uncertain-estimate-carry",
            development_uncertain_reservations,
            "gate-cost-ledger-provisioning",
        ),
        _explicit_anchor(
            "privacy-consent-loader",
            load_privacy_retention_consent,
            "gate-client-privacy-consent",
        ),
        _explicit_anchor(
            "dependency-snapshot-verifier",
            prepare_dependencies,
            "gate-dependency-snapshot",
        ),
        _explicit_anchor(
            "codeql-database-loader",
            CodeQLScanner,
            "gate-codeql-provisioning",
        ),
        _explicit_anchor(
            "trivy-offline-database-requirement",
            TrivyScanner,
            "gate-trivy-database-provisioning",
        ),
        _explicit_anchor(
            "fork-reproduction-runner",
            ForkReproductionRunner,
            "gate-fork-environment",
        ),
        _explicit_anchor(
            "typed-invariant-runner",
            FoundryInvariantRunner,
            "gate-invariant-template-library",
        ),
        _explicit_anchor(
            "pipeline-completion-body",
            AuditPipeline._run_with_provider,
            "gate-full-quality-analysis",
        ),
        _explicit_anchor(
            "post-judge-manual-review-incomplete-branch",
            _enforce_post_judge_execution_severity_accounting,
            "gate-unresolved-finding-disposition",
        ),
        _explicit_anchor(
            "consensus-needs-review-status",
            preliminary_status,
            "gate-unresolved-finding-disposition",
        ),
        _explicit_anchor(
            "audit-report-complete-validator",
            AuditReport,
            "gate-unresolved-finding-disposition",
        ),
        _explicit_anchor(
            "client-report-human-resolution",
            _finding_detail,
            "gate-unresolved-finding-disposition",
        ),
        _explicit_anchor(
            "markdown-needs-human-review",
            _status_qualification,
            "gate-unresolved-finding-disposition",
        ),
    ]
    sources.extend(
        [
            _explicit_environment_source(
                "dynamic-fork-rpc-environment-selector",
                "config.smart_contracts.fork_rpc_url_env",
                (_fork_rpc_value, ForkReproductionRunner, FoundryInvariantRunner),
                "gate-fork-environment",
                source_path="dynamic environment variable selected by smart_contracts.fork_rpc_url_env",
            ),
            _explicit_environment_source(
                "dynamic-solc-executable-environment-selector",
                "config.smart_contracts.solc_executable_env",
                (_resolve_pinned_solidity_compiler,),
                "gate-managed-toolchain-bundle",
                source_path="dynamic environment variable selected by smart_contracts.solc_executable_env",
            ),
            _explicit_environment_source(
                "dynamic-anvil-executable-environment-selector",
                "config.smart_contracts.repository_suite.fork_matrix_states[].anvil_executable_env",
                (TrustedCleanAnvilLauncher,),
                "gate-managed-toolchain-bundle",
                source_path="dynamic environment variable selected by fork_matrix_states[].anvil_executable_env",
            ),
            _explicit_environment_source(
                "dynamic-pinned-state-rpc-environment-selector",
                "config.smart_contracts.repository_suite.fork_matrix_states[].rpc_url_env",
                (RepositoryForkMatrixRunner,),
                "gate-fork-environment",
                source_path="dynamic environment variable selected by fork_matrix_states[].rpc_url_env",
            ),
            _explicit_environment_source(
                "dynamic-certora-key-environment-selector",
                "config.formal.certora.api_key_env_var",
                (FormalRunner,),
                "gate-provider-secret-transport",
                source_path="dynamic environment variable selected by formal.certora.api_key_env_var",
            ),
            _explicit_environment_source(
                "operator-secrets-env-file-selector",
                "MMAUDIT_SECRETS_ENV_FILE",
                (select_operator_secret_file,),
                "gate-provider-secret-transport",
                source_path="mmaudit.operator_secrets.MMAUDIT_SECRETS_ENV_FILE",
            ),
            _explicit_environment_source(
                "operator-secret-file-content",
                "OPENROUTER_API_KEY in selected bounded secret file",
                (load_operator_secrets,),
                "gate-provider-secret-transport",
                source_path="mmaudit.operator_secrets.load_operator_secrets:selected file content",
            ),
        ]
    )
    for variable in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT", "WINDIR", "PATHEXT"):
        sources.append(
            _explicit_environment_source(
                f"scanner-process-environment-{variable.lower()}",
                variable,
                (sanitized_scanner_environment,),
                "gate-managed-toolchain-bundle",
                source_path=f"mmaudit.scanners.base.sanitized_scanner_environment:{variable}",
            )
        )
    for variable in (
        "PATH",
        "LANG",
        "LC_ALL",
        "XDG_RUNTIME_DIR",
        "DOCKER_HOST",
        "CONTAINER_HOST",
    ):
        sources.append(
            _explicit_environment_source(
                f"rootless-runtime-environment-{variable.lower()}",
                variable,
                (rootless_runtime_environment,),
                "gate-managed-toolchain-bundle",
                source_path=f"mmaudit.isolation.container.rootless_runtime_environment:{variable}",
            )
        )
    return sources


_REQUIRED_MISSING_SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "autonomous-external-lineage-and-seal",
        "Externally anchored ground truth and cross-lineage REAL judging must issue runtime "
        "authority without a signer.",
        "gate-autonomous-model-authority",
    ),
    (
        "autonomous-unresolved-finding-terminal-resolution",
        "Every retained NEEDS_REVIEW or INCONCLUSIVE finding must reach an autonomous terminal "
        "disposition or force the run to a non-COMPLETE status.",
        "gate-unresolved-finding-disposition",
    ),
    (
        "deterministic-reproduction-target-derivation",
        "Reproduction targets must derive from declared deployment material or audited source.",
        "gate-reproduction-target-derivation",
    ),
    (
        "external-transparency-publication",
        "Authority must bind external append-only publication and inclusion/consistency proof.",
        "gate-external-transparency-seal",
    ),
    (
        "idempotent-managed-provisioning-command",
        "One idempotent auditable setup command must provision and verify every pre-run input.",
        "gate-managed-provisioning",
    ),
    (
        "managed-completion-entrypoint",
        "One zero-operator workflow must complete campaign, audits, benchmarks, validation, seal, "
        "and release or fail closed.",
        "gate-managed-completion-entrypoint",
    ),
    (
        "managed-toolchain-bundle",
        "One versioned bundle must bind and provision every executable, image, and reporter pin.",
        "gate-managed-toolchain-bundle",
    ),
    (
        "trusted-time-independent-exact-replay",
        "Authority must bind a trusted time basis and independently operated exact rerun custody.",
        "gate-trusted-time-independent-replay",
    ),
    (
        "purchase-bound-client-intake",
        "Scope, authorization, egress, retention, and snapshot decisions must bind at purchase.",
        "gate-client-audit-scope",
    ),
    (
        "reviewed-invariant-template-library",
        "A versioned hash-pinned reviewed template library must prove each executable harness is "
        "pre-approved by construction.",
        "gate-invariant-template-library",
    ),
    (
        "zero-input-managed-profile",
        "The managed profile must resolve every completion input without a per-run override.",
        "gate-managed-profile",
    ),
)

_OBJECTIVE_BOUNDARY_SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "human-signature-signoff",
        "Human signature and sign-off are not completion prerequisites.",
        "gate-human-signoff-boundary",
    ),
    (
        "private-repository-audit",
        "Private-repository auditing is opt-in and outside objective completion.",
        "gate-private-repository-boundary",
    ),
    (
        "saas-liability-claims",
        "SaaS and liability claims beyond the conservative CLI-release ADR are out of scope.",
        "gate-saas-liability-boundary",
    ),
)


def _required_sources() -> list[_SourceDraft]:
    result: list[_SourceDraft] = []
    for source_id, requirement, gate_id in (
        *_REQUIRED_MISSING_SOURCES,
        *_OBJECTIVE_BOUNDARY_SOURCES,
    ):
        result.append(
            _classified_source(
                source_id=f"required:{source_id}",
                source_kind=CompletionInputSourceKind.REQUIRED_MISSING_GATE,
                source_path=f"{AUTONOMY_OBJECTIVE_PATH}:{source_id}",
                semantics=_canonical_sha256(
                    {
                        "objective_sha256": AUTONOMY_OBJECTIVE_SHA256,
                        "requirement": requirement,
                        "gate_id": gate_id,
                    }
                ),
                gate_id=gate_id,
            )
        )
    return result


def _assert_frozen_objective(repository_root: Path) -> None:
    objective = repository_root / AUTONOMY_OBJECTIVE_PATH
    try:
        content = objective.read_bytes()
    except OSError as exc:
        raise AutonomyInventoryError("frozen autonomy objective is unavailable") from exc
    if hashlib.sha256(content).hexdigest() != AUTONOMY_OBJECTIVE_SHA256:
        raise AutonomyInventoryError("frozen autonomy objective bytes drifted")


def build_autonomy_gate_inventory(
    *,
    repository_root: Path | None = None,
    audit_config_model: type[BaseModel] = AuditConfig,
    audit_run_options_model: type[BaseModel] = AuditRunOptions,
    audit_override_value_types: Mapping[str, tuple[type[object], ...]] = (
        _AUDIT_OVERRIDE_VALUE_TYPES
    ),
    environment_override_mappings: Mapping[str, tuple[str, type[Any]]] = (
        _ENVIRONMENT_OVERRIDE_MAPPINGS
    ),
    cli_run_command: Callable[..., object] | None = None,
    pipeline_init: Callable[..., object] | None = None,
    pipeline_run: Callable[..., object] | None = None,
    explicit_sources: Sequence[_SourceDraft] | None = None,
) -> AutonomyGateInventory:
    """Discover, classify, and self-hash the provider-free Phase-0 inventory."""

    from mmaudit.cli import run_command
    from mmaudit.orchestration.pipeline import AuditPipeline

    root = repository_root or Path(__file__).resolve().parents[3]
    _assert_frozen_objective(root)
    drafts = [
        *_discover_config_sources(audit_config_model),
        *_discover_audit_run_option_sources(audit_run_options_model),
        *_discover_override_sources(audit_override_value_types),
        *_discover_environment_sources(environment_override_mappings),
        *_discover_cli_sources(cli_run_command or run_command, repository_root=root),
        *_discover_pipeline_init_sources(
            pipeline_init or AuditPipeline.__init__, repository_root=root
        ),
        *_discover_pipeline_run_sources(pipeline_run or AuditPipeline.run, repository_root=root),
        *_discover_completion_entrypoint_sources(repository_root=root),
        *_discover_audited_module_sources(root / "src" / "mmaudit"),
        *_discover_direct_environment_sources(root / "src" / "mmaudit"),
        *_discover_entropy_input_sources(root / "src" / "mmaudit"),
        *_discover_external_input_sources(root / "src" / "mmaudit"),
        *_discover_packaging_entrypoint_sources(root),
        *(list(explicit_sources) if explicit_sources is not None else _default_explicit_sources()),
        *_required_sources(),
    ]
    ordered_drafts = tuple(sorted(drafts, key=lambda item: item.source_id))
    source_ids = tuple(item.source_id for item in ordered_drafts)
    if len(source_ids) != len(set(source_ids)):
        raise AutonomyInventoryError("completion-input discovery produced duplicate source IDs")
    source_coverage = tuple(
        CompletionInputSourceCoverage.model_validate(item.model_dump(mode="json"))
        for item in ordered_drafts
    )
    by_gate: dict[str, list[str]] = {gate_id: [] for gate_id in _GATE_SPEC_BY_ID}
    for source in source_coverage:
        if source.logical_gate_id is not None:
            by_gate[source.logical_gate_id].append(source.source_id)
    missing_gate_sources = sorted(gate_id for gate_id, values in by_gate.items() if not values)
    if missing_gate_sources:
        raise AutonomyInventoryError(
            "logical gates lack source coverage: " + ", ".join(missing_gate_sources)
        )
    logical_gates = tuple(
        AutonomousLogicalGate(
            **spec.model_dump(mode="python"),
            source_ids=tuple(sorted(by_gate[spec.gate_id])),
        )
        for spec in sorted(_GATE_SPECS, key=lambda item: item.gate_id)
    )
    universe_payload = [
        {
            "source_id": item.source_id,
            "source_kind": item.source_kind.value,
            "source_path": item.source_path,
            "source_semantics_sha256": item.source_semantics_sha256,
            "source_occurrence_count": item.source_occurrence_count,
        }
        for item in source_coverage
    ]
    values: dict[str, object] = {
        "schema_version": AUTONOMY_INVENTORY_SCHEMA_VERSION,
        "artifact_kind": "AUTONOMY_COMPLETION_INPUT_GATE_INVENTORY",
        "phase": "PHASE_0_INVENTORY_ONLY",
        "status": "PARTIAL_NONAUTHORIZING",
        "objective_path": AUTONOMY_OBJECTIVE_PATH,
        "objective_sha256": AUTONOMY_OBJECTIVE_SHA256,
        "completion_scope": "SYNTHETIC_PUBLIC_ONLY",
        "discovery_scope": (
            "TYPED_BOUNDARIES_REGISTERED_ENTRYPOINTS_RUNTIME_PACKAGE_RESOURCES_"
            "UNSEALED_ENV_HOST_WALL_CLOCK_AUTHORITY_ENTROPY_FILESYSTEM_INTERACTIVE_"
            "OPAQUE_AUTHORITIES_"
            "EXPLICIT_MISSING_OBJECTIVE_BOUNDARIES"
        ),
        "private_repository_completion_in_scope": False,
        "source_discovery_semantics_sha256": hashlib.sha256(
            Path(__file__).read_bytes()
        ).hexdigest(),
        "source_universe_sha256": _canonical_sha256(universe_payload),
        "source_coverage": [item.model_dump(mode="json") for item in source_coverage],
        "logical_gates": [item.model_dump(mode="json") for item in logical_gates],
        "source_count": len(source_coverage),
        "source_occurrence_count": sum(item.source_occurrence_count for item in source_coverage),
        "audit_config_leaf_locator_count": 513,
        "audit_config_leaf_occurrence_count": 516,
        "audit_config_shared_locator_count": 3,
        "audit_run_option_leaf_count": 16,
        "audit_override_path_count": 51,
        "environment_override_count": 28,
        "cli_run_parameter_count": 53,
        "pipeline_init_parameter_count": 29,
        "pipeline_run_parameter_count": 16,
        "completion_entrypoint_parameter_count": 355,
        "source_kind_counts": {
            kind.value: sum(item.source_kind is kind for item in source_coverage)
            for kind in CompletionInputSourceKind
        },
        "gate_source_count": sum(
            item.classification is SourceCoverageClassification.GATE for item in source_coverage
        ),
        "logical_gate_count": len(logical_gates),
        "unsatisfied_gate_count": sum(
            item.implementation_state in _UNSATISFIED_STATES for item in logical_gates
        ),
        "current_manual_gate_count": sum(
            item.implementation_state is GateImplementationState.CURRENT_MANUAL_INPUT
            for item in logical_gates
        ),
        "provider_or_network_accessed": False,
        "secret_material_read": False,
        "runtime_authority": False,
        "managed_run_ready": False,
    }
    values["inventory_sha256"] = _canonical_sha256(values)
    try:
        return AutonomyGateInventory.model_validate(values)
    except ValueError as exc:
        raise AutonomyInventoryError("generated autonomy gate inventory is invalid") from exc


def render_autonomy_gate_inventory(*, repository_root: Path | None = None) -> str:
    """Return deterministic canonical committed artifact bytes."""

    inventory = build_autonomy_gate_inventory(repository_root=repository_root)
    return (
        json.dumps(
            inventory.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def load_autonomy_gate_inventory(path: Path) -> AutonomyGateInventory:
    """Load a bounded canonical inventory without treating it as runtime authority."""

    try:
        content = path.read_bytes()
    except OSError as exc:
        raise AutonomyInventoryError("autonomy gate inventory is unavailable") from exc
    if not content or len(content) > 4_000_000:
        raise AutonomyInventoryError("autonomy gate inventory is empty or oversized")
    try:
        inventory = AutonomyGateInventory.model_validate_json(content, strict=True)
    except ValueError as exc:
        raise AutonomyInventoryError("autonomy gate inventory is invalid") from exc
    expected = (
        json.dumps(
            inventory.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if content != expected:
        raise AutonomyInventoryError("autonomy gate inventory bytes are not canonical")
    return inventory
