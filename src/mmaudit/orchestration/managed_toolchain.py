"""Typed, nonauthorizing contract for the managed toolchain bundle.

The resolver, sealer, and config projection deliberately perform no filesystem,
environment, PATH, subprocess, network, or secret access.  The fixed package-resource
loader is the sole filesystem boundary.  Installed binary verification, image-side
attestation, provisioning, and runtime authority belong to later fail-closed phases.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from mmaudit.config import (
    AuditConfig,
    RepositoryCleanForkMatrixStateConfig,
    ScannerConfig,
)
from mmaudit.models.schemas import AuditProfile, LanguageCapabilityProfile, StrictModel
from mmaudit.scanners.hardhat import (
    HARDHAT_REPORTER_SHA256 as MANAGED_TOOLCHAIN_REPORTER_SHA256,
)
from mmaudit.scanners.hardhat import (
    HARDHAT_REPORTER_VERSION as MANAGED_TOOLCHAIN_REPORTER_VERSION,
)

MANAGED_TOOLCHAIN_SCHEMA_VERSION = "1.0"
MANAGED_TOOLCHAIN_OBJECTIVE_SHA256 = (
    "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
)
MANAGED_TOOLCHAIN_BUNDLE_RESOURCE = "resources/managed_toolchain_bundle.json"
MANAGED_TOOLCHAIN_REPORTER_INVENTORY_SCHEMA_SHA256 = (
    "c5eb7d2e536b8a34d2b6bfdef31b83a67b28f411468056aa833b873a53423a27"
)
MANAGED_TOOLCHAIN_REPORTER_TEST_SCHEMA_SHA256 = (
    "82938fe228ae9f4ba9bf64b284ec9cbbab6af0b0ce1a9e13f4cc8b7c63e77bc8"
)
# Updated only after deterministic generation and review of the fixed package resource.
_MANAGED_TOOLCHAIN_BUNDLE_RAW_SHA256 = (
    "6d427e698d1074be2d20747211bcdd53816509e0e71b4225dff0401c32d6561a"
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_VERSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._+:/ -]{0,199}$"
_SAFE_LOCATOR_PATTERN = r"^[A-Za-z0-9/][A-Za-z0-9._+:/@-]{0,511}$"
_DIGEST_IMAGE_PATTERN = (
    r"^[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*"
    r"@sha256:[0-9a-f]{64}$"
)
MANAGED_TOOLCHAIN_DECLARATION_LIMITATIONS = (
    "Config projection is not installed or executed process identity evidence.",
    "Generic rootless execution is refused until every image-side executable is modeled.",
    "Image-side executable and relay identities remain unattested until provisioning.",
    "Fixed operating-system probe helpers remain unmodeled and lack exact identity verification.",
    "Single-file hashes do not verify transitive dependency closures.",
)


class ManagedToolchainError(ValueError):
    """Raised when a bundle cannot safely project onto one audit config."""


class ManagedToolchainRole(StrEnum):
    """Closed first-class managed identities covered by this declaration."""

    SOLC = "solc"
    ANVIL = "anvil"
    SEMGREP = "semgrep"
    GITLEAKS = "gitleaks"
    TRIVY = "trivy"
    OSV_SCANNER = "osv-scanner"
    CODEQL = "codeql"
    SLITHER = "slither"
    FORGE = "forge"
    MYTHRIL = "mythril"
    ECHIDNA = "echidna"
    MEDUSA = "medusa"
    HALMOS = "halmos"
    HALMOS_Z3 = "halmos-z3"
    CERTORA_CLI = "certora-cli"
    KONTROL = "kontrol"
    PYTHON_RUNTIME = "python-runtime"
    GIT = "git"
    SANDBOX_EXEC = "sandbox-exec"
    BUBBLEWRAP = "bubblewrap"
    CONTAINER_RUNTIME = "container-runtime"
    ROOTLESS_TOOLCHAIN_IMAGE = "rootless-toolchain-image"
    HARDHAT_IMAGE_HARDHAT = "hardhat-image-hardhat"
    HARDHAT_IMAGE_NODE = "hardhat-image-node"
    HARDHAT_IMAGE_LOOPBACK = "hardhat-image-loopback"
    HARDHAT_REPORTER = "hardhat-reporter"
    HARDHAT_REPORTER_INVENTORY_SCHEMA = "hardhat-reporter-inventory-schema"
    HARDHAT_REPORTER_TEST_SCHEMA = "hardhat-reporter-test-schema"


class ManagedToolchainMemberKind(StrEnum):
    """Identity representation used by one closed role."""

    HOST_EXECUTABLE = "HOST_EXECUTABLE"
    OCI_IMAGE = "OCI_IMAGE"
    IMAGE_EXECUTABLE = "IMAGE_EXECUTABLE"
    PACKAGE_RESOURCE = "PACKAGE_RESOURCE"
    GENERATED_SCHEMA = "GENERATED_SCHEMA"


class ManagedToolchainDisposition(StrEnum):
    """Honest identity availability within a declaration."""

    PINNED = "PINNED"
    UNRESOLVED = "UNRESOLVED"
    DISABLED = "DISABLED"


class ManagedToolchainBundleStatus(StrEnum):
    """A bundle status that never grants runtime authority."""

    PARTIAL_NONAUTHORIZING = "PARTIAL_NONAUTHORIZING"
    PINNED_NONAUTHORIZING = "PINNED_NONAUTHORIZING"


class ManagedToolchainConsumer(StrEnum):
    """Closed consumers for the first-class managed identity constraints."""

    SOLIDITY_COMPILATION = "solidity-compilation"
    FORMAL_SMTCHECKER = "formal-smtchecker"
    GENERATED_INVARIANT_EXECUTION = "generated-invariant-execution"
    CLEAN_FORK_MATRIX = "clean-fork-matrix"
    SCANNER_SEMGREP = "scanner-semgrep"
    SCANNER_GITLEAKS = "scanner-gitleaks"
    SCANNER_TRIVY = "scanner-trivy"
    SCANNER_OSV = "scanner-osv"
    SCANNER_CODEQL = "scanner-codeql"
    SCANNER_SLITHER = "scanner-slither"
    SCANNER_SLITHER_COMPILER = "scanner-slither-compiler"
    SCANNER_FOUNDRY_FORK = "scanner-foundry-fork"
    SCANNER_FOUNDRY_COMPILER = "scanner-foundry-compiler"
    SCANNER_HARDHAT_FORK = "scanner-hardhat-fork"
    SOLIDITY_REPRODUCTION = "solidity-reproduction"
    FORMAL_MYTHRIL = "formal-mythril"
    FORMAL_ECHIDNA = "formal-echidna"
    FORMAL_MEDUSA = "formal-medusa"
    FORMAL_FOUNDRY_INVARIANT = "formal-foundry-invariant"
    FORMAL_HALMOS = "formal-halmos"
    FORMAL_HALMOS_SOLVER = "formal-halmos-solver"
    FORMAL_CERTORA = "formal-certora"
    FORMAL_KONTROL = "formal-kontrol"
    MMAUDIT_RUNTIME = "mmaudit-runtime"
    REPOSITORY_DISCOVERY = "repository-discovery"
    HARDENED_HOST_ISOLATION = "hardened-host-isolation"
    ROOTLESS_CONTAINER = "rootless-container"


_ROOTLESS_IMAGE_SIDE_UNREPRESENTED_ROLES = frozenset(
    {
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.SEMGREP,
        ManagedToolchainRole.GITLEAKS,
        ManagedToolchainRole.TRIVY,
        ManagedToolchainRole.OSV_SCANNER,
        ManagedToolchainRole.CODEQL,
        ManagedToolchainRole.SLITHER,
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.MYTHRIL,
        ManagedToolchainRole.ECHIDNA,
        ManagedToolchainRole.MEDUSA,
        ManagedToolchainRole.HALMOS,
        ManagedToolchainRole.HALMOS_Z3,
        ManagedToolchainRole.CERTORA_CLI,
        ManagedToolchainRole.KONTROL,
    }
)


class _ValidatedFrozenManagedModel(StrictModel):
    """Frozen contract base whose copy path cannot bypass validation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Rebuild through validators; ``deep`` is implicit in reconstruction."""

        del deep
        payload = self.model_dump(mode="python")
        if update is not None:
            payload.update(update)
        return type(self).model_validate(payload)


class ManagedToolchainRoleSpec(_ValidatedFrozenManagedModel):
    """Compiled role, representation, and exact consumer set."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: ManagedToolchainRole
    kind: ManagedToolchainMemberKind
    allowed_locators: tuple[str, ...] = Field(min_length=1, max_length=4)
    consumers: tuple[ManagedToolchainConsumer, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def values_are_canonical(self) -> Self:
        if self.allowed_locators != tuple(sorted(set(self.allowed_locators))):
            raise ValueError("managed toolchain locators must be unique and sorted")
        if self.consumers != tuple(sorted(set(self.consumers), key=str)):
            raise ValueError("managed toolchain consumers must be unique and sorted")
        return self


class ManagedToolchainMember(_ValidatedFrozenManagedModel):
    """One declared identity or explicit unavailable disposition."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: ManagedToolchainRole
    kind: ManagedToolchainMemberKind
    disposition: ManagedToolchainDisposition
    locator: str | None = Field(default=None, max_length=512)
    version: str | None = Field(default=None, max_length=200)
    sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    platform: Literal["linux-amd64", "linux-arm64"] | None = None
    platform_manifest_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    parent_image_role: ManagedToolchainRole | None = None
    parent_image_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    parent_platform_manifest_sha256: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    consumers: tuple[ManagedToolchainConsumer, ...] = Field(min_length=1, max_length=8)
    limitation: str | None = Field(default=None, min_length=1, max_length=500)

    @field_validator("locator")
    @classmethod
    def locator_is_bounded_public_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if re.fullmatch(_SAFE_LOCATOR_PATTERN, value) is None:
            raise ValueError("managed toolchain locator is not a safe public identifier")
        return value

    @field_validator("version")
    @classmethod
    def version_is_bounded_public_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if re.fullmatch(_VERSION_PATTERN, value) is None:
            raise ValueError("managed toolchain version is not bounded public text")
        return value

    @field_validator("limitation")
    @classmethod
    def limitation_is_printable(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("managed toolchain limitation must be bounded printable text")
        return value

    @model_validator(mode="after")
    def disposition_fields_are_fail_closed(self) -> Self:
        pin_fields = (self.locator, self.version, self.sha256)
        if self.disposition is ManagedToolchainDisposition.PINNED:
            if any(value is None for value in pin_fields) or self.limitation is not None:
                raise ValueError("a pinned managed toolchain member requires only exact pin fields")
            if self.sha256 == "0" * 64:
                raise ValueError("a managed toolchain member cannot use the zero SHA-256")
        elif any(value is not None for value in pin_fields) or self.limitation is None:
            raise ValueError(
                "an unresolved or disabled managed toolchain member requires only a limitation"
            )
        if (
            self.kind is ManagedToolchainMemberKind.OCI_IMAGE
            and self.disposition is ManagedToolchainDisposition.PINNED
        ):
            if self.platform is None or self.platform_manifest_sha256 in {None, "0" * 64}:
                raise ValueError("a pinned OCI image requires an exact platform child manifest")
        elif self.platform is not None or self.platform_manifest_sha256 is not None:
            raise ValueError("only a pinned OCI image may carry platform manifest identity")
        parent_fields = (
            self.parent_image_role,
            self.parent_image_sha256,
            self.parent_platform_manifest_sha256,
        )
        if (
            self.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE
            and self.disposition is ManagedToolchainDisposition.PINNED
        ):
            if (
                self.parent_image_role is not ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
                or self.parent_image_sha256 in {None, "0" * 64}
                or self.parent_platform_manifest_sha256 in {None, "0" * 64}
            ):
                raise ValueError(
                    "a pinned image executable requires exact parent image and platform identity"
                )
        elif any(value is not None for value in parent_fields):
            raise ValueError("only a pinned image executable may carry parent image identity")
        return self


class ManagedToolchainBundle(_ValidatedFrozenManagedModel):
    """Self-consistent declaration with no trust or execution authority."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    artifact_kind: Literal["managed-toolchain-bundle"] = "managed-toolchain-bundle"
    objective_sha256: Literal[
        "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
    ] = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
    target_platform: Literal["unresolved", "linux-amd64", "linux-arm64"]
    members: tuple[ManagedToolchainMember, ...] = Field(min_length=28, max_length=28)
    status: ManagedToolchainBundleStatus
    self_consistent: Literal[True] = True
    independently_trusted: Literal[False] = False
    installed_members_verified: Literal[False] = False
    transitive_dependency_closure_verified: Literal[False] = False
    image_side_attestation_verified: Literal[False] = False
    provisioning_state_verified: Literal[False] = False
    execution_evidence_verified: Literal[False] = False
    runtime_authority: Literal[False] = False
    managed_run_ready: Literal[False] = False
    limitations: tuple[str, ...] = Field(min_length=5, max_length=5)
    bundle_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def catalog_status_and_hash_are_exact(self) -> Self:
        expected_roles = tuple(spec.role for spec in MANAGED_TOOLCHAIN_ROLE_SPECS)
        observed_roles = tuple(member.role for member in self.members)
        if observed_roles != expected_roles:
            raise ValueError("managed toolchain members must match the closed ordered role catalog")
        for member, spec in zip(self.members, MANAGED_TOOLCHAIN_ROLE_SPECS, strict=True):
            if member.kind is not spec.kind or member.consumers != spec.consumers:
                raise ValueError("managed toolchain member differs from its compiled role contract")
            _require_member_locator(member, spec)
            if (
                member.kind is ManagedToolchainMemberKind.OCI_IMAGE
                and member.disposition is ManagedToolchainDisposition.PINNED
                and member.platform != self.target_platform
            ):
                raise ValueError("managed OCI platform differs from the bundle target platform")
        parent_image = next(
            member
            for member in self.members
            if member.role is ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
        )
        for member in self.members:
            if (
                member.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE
                and member.disposition is ManagedToolchainDisposition.PINNED
            ):
                if parent_image.disposition is not ManagedToolchainDisposition.PINNED:
                    raise ValueError("pinned image executable requires a pinned parent image")
                if member.parent_image_sha256 != parent_image.sha256:
                    raise ValueError("image executable parent image identity differs")
                if member.parent_platform_manifest_sha256 != parent_image.platform_manifest_sha256:
                    raise ValueError("image executable parent platform identity differs")
        expected_status = (
            ManagedToolchainBundleStatus.PINNED_NONAUTHORIZING
            if all(
                member.disposition is ManagedToolchainDisposition.PINNED for member in self.members
            )
            else ManagedToolchainBundleStatus.PARTIAL_NONAUTHORIZING
        )
        if self.status is not expected_status:
            raise ValueError("managed toolchain bundle status differs from member dispositions")
        if self.limitations != MANAGED_TOOLCHAIN_DECLARATION_LIMITATIONS:
            raise ValueError("managed toolchain declaration limitations are incomplete")
        expected_hash = _canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected_hash:
            raise ValueError("managed toolchain bundle hash is inconsistent")
        return self


class ManagedToolchainPinProjection(_ValidatedFrozenManagedModel):
    """Pure config projection; it is not installed or execution evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    source_bundle_sha256: str = Field(pattern=_SHA256_PATTERN)
    effective_config_sha256: str = Field(pattern=_SHA256_PATTERN)
    required_roles: tuple[ManagedToolchainRole, ...]
    members: tuple[ManagedToolchainMember, ...]
    resolved_isolation_backend: (
        Literal["rootless-container", "sandbox-exec", "bubblewrap"] | None
    ) = None
    resolved_container_runtime: Literal["docker", "podman"] | None = None
    resolved_rootless_image: str | None = Field(default=None, max_length=512)
    status: Literal["CONFIG_PROJECTED_NONAUTHORIZING"] = "CONFIG_PROJECTED_NONAUTHORIZING"
    bundle_trusted: Literal[False] = False
    installed_members_verified: Literal[False] = False
    transitive_dependency_closure_verified: Literal[False] = False
    image_side_attestation_verified: Literal[False] = False
    provisioning_state_verified: Literal[False] = False
    execution_evidence_verified: Literal[False] = False
    runtime_authority: Literal[False] = False
    managed_run_ready: Literal[False] = False
    projection_sha256: str = Field(pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def projection_is_ordered_pinned_and_self_hashed(self) -> Self:
        if self.required_roles != tuple(sorted(set(self.required_roles), key=str)):
            raise ValueError("managed toolchain required roles must be unique and sorted")
        if tuple(member.role for member in self.members) != self.required_roles:
            raise ValueError("managed toolchain projected members differ from required roles")
        if any(
            member.disposition is not ManagedToolchainDisposition.PINNED for member in self.members
        ):
            raise ValueError("managed toolchain projection may contain only pinned members")
        selected = {member.role: member for member in self.members}
        selected_host_backends = {
            role
            for role in (ManagedToolchainRole.SANDBOX_EXEC, ManagedToolchainRole.BUBBLEWRAP)
            if role in selected
        }
        runtime = selected.get(ManagedToolchainRole.CONTAINER_RUNTIME)
        image = selected.get(ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
        expected_host_backends: set[ManagedToolchainRole] = set()
        if self.resolved_isolation_backend == "sandbox-exec":
            expected_host_backends.add(ManagedToolchainRole.SANDBOX_EXEC)
        elif self.resolved_isolation_backend == "bubblewrap":
            expected_host_backends.add(ManagedToolchainRole.BUBBLEWRAP)
        elif self.resolved_isolation_backend == "rootless-container" and (
            runtime is None or image is None
        ):
            raise ValueError("managed rootless isolation requires runtime and image members")
        if runtime is not None and self.resolved_isolation_backend != "rootless-container":
            raise ValueError("managed container runtime lacks a rootless isolation selection")
        if (
            self.resolved_isolation_backend in {"sandbox-exec", "bubblewrap"}
            and runtime is not None
        ):
            raise ValueError("managed host isolation cannot also select a container runtime")
        if selected_host_backends != expected_host_backends:
            raise ValueError("managed host isolation selection differs from projected member")
        if (runtime is None) != (self.resolved_container_runtime is None) or (
            runtime is not None and runtime.locator != self.resolved_container_runtime
        ):
            raise ValueError("managed toolchain runtime selection differs from projected member")
        if (image is None) != (self.resolved_rootless_image is None) or (
            image is not None and image.locator != self.resolved_rootless_image
        ):
            raise ValueError("managed toolchain image selection differs from projected member")
        expected = _canonical_sha256(self.model_dump(mode="json", exclude={"projection_sha256"}))
        if self.projection_sha256 != expected:
            raise ValueError("managed toolchain projection hash is inconsistent")
        return self


def seal_managed_toolchain_bundle(
    *,
    members: tuple[ManagedToolchainMember, ...],
    target_platform: str,
) -> ManagedToolchainBundle:
    """Seal a complete declaration without assigning trust or runtime authority."""

    status = (
        ManagedToolchainBundleStatus.PINNED_NONAUTHORIZING
        if all(member.disposition is ManagedToolchainDisposition.PINNED for member in members)
        else ManagedToolchainBundleStatus.PARTIAL_NONAUTHORIZING
    )
    payload: dict[str, Any] = {
        "schema_version": MANAGED_TOOLCHAIN_SCHEMA_VERSION,
        "artifact_kind": "managed-toolchain-bundle",
        "objective_sha256": MANAGED_TOOLCHAIN_OBJECTIVE_SHA256,
        "target_platform": target_platform,
        "members": [member.model_dump(mode="json") for member in members],
        "status": status.value,
        "self_consistent": True,
        "independently_trusted": False,
        "installed_members_verified": False,
        "transitive_dependency_closure_verified": False,
        "image_side_attestation_verified": False,
        "provisioning_state_verified": False,
        "execution_evidence_verified": False,
        "runtime_authority": False,
        "managed_run_ready": False,
        "limitations": list(MANAGED_TOOLCHAIN_DECLARATION_LIMITATIONS),
    }
    payload["bundle_sha256"] = _canonical_sha256(payload)
    return ManagedToolchainBundle.model_validate(payload)


def required_managed_toolchain_roles(config: AuditConfig) -> tuple[ManagedToolchainRole, ...]:
    """Derive every enabled or explicitly pinned identity role from effective config."""

    effective = _snapshot_effective_audit_config(config)
    return _required_managed_toolchain_roles_from_effective(effective)


def _required_managed_toolchain_roles_from_effective(
    effective: AuditConfig,
) -> tuple[ManagedToolchainRole, ...]:
    """Derive required roles from one private, already-effective config snapshot."""

    required: set[ManagedToolchainRole] = {
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainRole.GIT,
    }
    solidity_language = effective.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
    solidity_applicable = solidity_language and effective.smart_contracts.enabled

    scanner_roles = {
        "semgrep": ManagedToolchainRole.SEMGREP,
        "gitleaks": ManagedToolchainRole.GITLEAKS,
        "trivy": ManagedToolchainRole.TRIVY,
        "osv": ManagedToolchainRole.OSV_SCANNER,
        "codeql": ManagedToolchainRole.CODEQL,
        "slither": ManagedToolchainRole.SLITHER,
        "foundry_fork": ManagedToolchainRole.FORGE,
        "hardhat_fork": ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
    }
    for name, role in scanner_roles.items():
        scanner = getattr(effective.scanners, name)
        if not isinstance(scanner, ScannerConfig):
            raise ManagedToolchainError(f"invalid scanner config for {name}")
        if scanner.required and not scanner.enabled:
            raise ManagedToolchainError(f"required scanner {name} cannot be disabled")
        scanner_applicable = (
            (name == "slither" and solidity_language)
            or (name in {"foundry_fork", "hardhat_fork"} and solidity_applicable)
            or name not in {"slither", "foundry_fork", "hardhat_fork"}
        )
        if (
            (scanner.enabled and scanner_applicable)
            or scanner.version is not None
            or scanner.sha256 is not None
        ):
            required.add(role)

    framework = effective.smart_contracts.framework
    hardhat_fork_selected = _hardhat_fork_selected(effective)
    hardhat_compilation_selected = _hardhat_compilation_selected(effective)
    if (
        solidity_applicable
        and effective.smart_contracts.compile
        and framework in {"auto", "foundry", "mixed"}
    ):
        required.update({ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC})
    if (
        (solidity_language and effective.scanners.slither.enabled)
        or (solidity_applicable and effective.scanners.foundry_fork.enabled)
        or effective.smart_contracts.solc_version is not None
        or effective.smart_contracts.solc_sha256 is not None
    ):
        required.add(ManagedToolchainRole.SOLC)
    clean_states = tuple(
        state
        for state in effective.smart_contracts.repository_suite.fork_matrix_states
        if isinstance(state, RepositoryCleanForkMatrixStateConfig)
    )
    if clean_states:
        required.add(ManagedToolchainRole.ANVIL)

    generated_invariants_selected = (
        solidity_applicable
        and effective.invariants.enabled
        and effective.invariants.execute_generated
    )
    if generated_invariants_selected:
        required.update({ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC})

    explicit_formal_pins = {
        ManagedToolchainRole.ECHIDNA: (
            effective.formal.echidna_version,
            effective.formal.echidna_sha256,
        ),
        ManagedToolchainRole.MEDUSA: (
            effective.formal.medusa_version,
            effective.formal.medusa_sha256,
        ),
        ManagedToolchainRole.HALMOS: (
            effective.formal.halmos_version,
            effective.formal.halmos_sha256,
        ),
        ManagedToolchainRole.HALMOS_Z3: (
            effective.formal.halmos_solver_version,
            effective.formal.halmos_solver_sha256,
        ),
        ManagedToolchainRole.CERTORA_CLI: (
            effective.formal.certora.cli_version,
            effective.formal.certora.cli_sha256,
        ),
        ManagedToolchainRole.KONTROL: (
            effective.formal.kontrol_version,
            effective.formal.kontrol_sha256,
        ),
    }
    required.update(
        role
        for role, pin in explicit_formal_pins.items()
        if any(value is not None for value in pin)
    )

    if solidity_applicable and effective.formal.enabled:
        required.update({ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC})
        formal_flags = {
            ManagedToolchainRole.SOLC: effective.formal.run_smtchecker,
            ManagedToolchainRole.MYTHRIL: effective.formal.run_mythril,
            ManagedToolchainRole.ECHIDNA: effective.formal.run_echidna,
            ManagedToolchainRole.MEDUSA: effective.formal.run_medusa,
            ManagedToolchainRole.HALMOS: effective.formal.run_halmos,
            ManagedToolchainRole.HALMOS_Z3: effective.formal.run_halmos,
            ManagedToolchainRole.CERTORA_CLI: effective.formal.certora.enabled,
            ManagedToolchainRole.KONTROL: effective.formal.run_kontrol,
        }
        required.update(role for role, enabled in formal_flags.items() if enabled)
    required_tools = {
        "solc-smtchecker": (ManagedToolchainRole.SOLC,),
        "mythril": (ManagedToolchainRole.MYTHRIL,),
        "echidna": (ManagedToolchainRole.ECHIDNA,),
        "medusa": (ManagedToolchainRole.MEDUSA,),
        "foundry-invariant": (ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC),
        "halmos": (ManagedToolchainRole.HALMOS, ManagedToolchainRole.HALMOS_Z3),
        "certora": (ManagedToolchainRole.CERTORA_CLI,),
        "kontrol": (ManagedToolchainRole.KONTROL,),
    }
    if solidity_applicable:
        for tool in effective.formal.required_tools:
            required.update(required_tools[tool])

    if solidity_applicable and effective.reproduction.enabled:
        required.update({ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC})

    rootless_selected = _rootless_execution_selected(effective)
    if rootless_selected:
        required.add(ManagedToolchainRole.CONTAINER_RUNTIME)
    if rootless_selected or effective.reproduction.rootless_container_image is not None:
        required.add(ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    host_isolation_role = _host_isolation_role(effective)
    if host_isolation_role is not None:
        required.add(host_isolation_role)
    if hardhat_compilation_selected:
        required.update(
            {
                ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
                ManagedToolchainRole.HARDHAT_IMAGE_NODE,
            }
        )
    if hardhat_fork_selected:
        required.update(
            {
                ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
                ManagedToolchainRole.HARDHAT_IMAGE_NODE,
                ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
                ManagedToolchainRole.HARDHAT_REPORTER,
                ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
                ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
            }
        )
    return tuple(sorted(required, key=str))


def resolve_managed_toolchain_config(
    bundle: ManagedToolchainBundle,
    config: AuditConfig,
) -> ManagedToolchainPinProjection:
    """Fail closed and project declared pins without examining installed tools."""

    if type(bundle) is not ManagedToolchainBundle:
        raise ManagedToolchainError("managed toolchain bundle must be the exact compiled type")
    validated_bundle = ManagedToolchainBundle.model_validate_json(
        bundle.model_dump_json(), strict=True
    )
    effective = _snapshot_effective_audit_config(config)
    if (
        effective.profile is AuditProfile.MAXIMUM_ASSURANCE
        and effective.maximum_assurance.allow_downgrade
    ):
        raise ManagedToolchainError("managed maximum-assurance config cannot allow downgrade")
    required_roles = _required_managed_toolchain_roles_from_effective(effective)
    if _rootless_execution_selected(effective):
        unsupported_rootless_roles = set(required_roles).intersection(
            _ROOTLESS_IMAGE_SIDE_UNREPRESENTED_ROLES
        )
        if unsupported_rootless_roles:
            names = ", ".join(sorted(role.value for role in unsupported_rootless_roles))
            raise ManagedToolchainError(
                "managed rootless execution has unrepresented image-side identities: " + names
            )
    by_role = {member.role: member for member in validated_bundle.members}
    selected: list[ManagedToolchainMember] = []
    for role in required_roles:
        member = by_role[role]
        if member.disposition is not ManagedToolchainDisposition.PINNED:
            raise ManagedToolchainError(
                f"required managed toolchain role {role.value} is {member.disposition.value}"
            )
        selected.append(member)

    _require_configured_pin_compatibility(effective, by_role, required_roles)
    runtime_member = by_role.get(ManagedToolchainRole.CONTAINER_RUNTIME)
    image_member = by_role.get(ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    resolved_runtime = (
        runtime_member.locator
        if ManagedToolchainRole.CONTAINER_RUNTIME in required_roles and runtime_member is not None
        else None
    )
    if resolved_runtime not in {None, "docker", "podman"}:
        raise ManagedToolchainError("managed toolchain runtime locator is invalid")
    resolved_image = (
        image_member.locator
        if ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE in required_roles
        and image_member is not None
        else None
    )
    payload: dict[str, Any] = {
        "schema_version": MANAGED_TOOLCHAIN_SCHEMA_VERSION,
        "source_bundle_sha256": validated_bundle.bundle_sha256,
        "effective_config_sha256": effective.stable_hash(),
        "required_roles": [role.value for role in required_roles],
        "members": [member.model_dump(mode="json") for member in selected],
        "resolved_isolation_backend": _resolved_isolation_backend(effective),
        "resolved_container_runtime": resolved_runtime,
        "resolved_rootless_image": resolved_image,
        "status": "CONFIG_PROJECTED_NONAUTHORIZING",
        "bundle_trusted": False,
        "installed_members_verified": False,
        "transitive_dependency_closure_verified": False,
        "image_side_attestation_verified": False,
        "provisioning_state_verified": False,
        "execution_evidence_verified": False,
        "runtime_authority": False,
        "managed_run_ready": False,
    }
    payload["projection_sha256"] = _canonical_sha256(payload)
    return ManagedToolchainPinProjection.model_validate(payload)


def _snapshot_effective_audit_config(config: AuditConfig) -> AuditConfig:
    """Create one exact validated effective snapshot without subclass dispatch."""

    if type(config) is not AuditConfig:
        raise ManagedToolchainError("managed toolchain config must be the exact AuditConfig type")
    try:
        snapshot = AuditConfig.model_validate_json(config.model_dump_json(), strict=True)
        effective = AuditConfig.effective(snapshot)
        return AuditConfig.model_validate_json(effective.model_dump_json(), strict=True)
    except ValueError as exc:
        raise ManagedToolchainError("managed toolchain config snapshot is invalid") from exc


def _rootless_execution_selected(config: AuditConfig) -> bool:
    hardhat_selected = _hardhat_fork_selected(config) or _hardhat_compilation_selected(config)
    backend = config.reproduction.isolation_backend
    if hardhat_selected and backend not in {"auto", "rootless-container"}:
        raise ManagedToolchainError(
            "Hardhat execution requires auto or rootless-container isolation"
        )
    return backend == "rootless-container" or (
        backend == "auto"
        and (config.reproduction.rootless_container_image is not None or hardhat_selected)
    )


def _host_isolation_role(config: AuditConfig) -> ManagedToolchainRole | None:
    if _rootless_execution_selected(config) or not _host_tool_execution_selected(config):
        return None
    backend = config.reproduction.isolation_backend
    if backend == "auto":
        raise ManagedToolchainError(
            "managed host isolation backend auto requires an explicit deterministic selection"
        )
    if backend == "sandbox-exec":
        return ManagedToolchainRole.SANDBOX_EXEC
    if backend == "bubblewrap":
        return ManagedToolchainRole.BUBBLEWRAP
    raise ManagedToolchainError("managed host execution lacks a compatible isolation backend")


def _host_tool_execution_selected(config: AuditConfig) -> bool:
    solidity_language = config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
    solidity_applicable = solidity_language and config.smart_contracts.enabled
    scanner_names = ("semgrep", "gitleaks", "trivy", "osv", "codeql")
    generic_scanner_selected = any(getattr(config.scanners, name).enabled for name in scanner_names)
    solidity_scanner_selected = (solidity_language and config.scanners.slither.enabled) or (
        solidity_applicable and config.scanners.foundry_fork.enabled
    )
    foundry_compilation_selected = (
        solidity_applicable
        and config.smart_contracts.compile
        and config.smart_contracts.framework in {"foundry", "mixed"}
    )
    generated_invariants_selected = (
        solidity_applicable and config.invariants.enabled and config.invariants.execute_generated
    )
    formal_selected = solidity_applicable and config.formal.enabled
    reproduction_selected = solidity_applicable and config.reproduction.enabled
    return any(
        (
            generic_scanner_selected,
            solidity_scanner_selected,
            foundry_compilation_selected,
            generated_invariants_selected,
            formal_selected,
            reproduction_selected,
        )
    )


def _resolved_isolation_backend(
    config: AuditConfig,
) -> Literal["rootless-container", "sandbox-exec", "bubblewrap"] | None:
    if _rootless_execution_selected(config):
        return "rootless-container"
    role = _host_isolation_role(config)
    if role is ManagedToolchainRole.SANDBOX_EXEC:
        return "sandbox-exec"
    if role is ManagedToolchainRole.BUBBLEWRAP:
        return "bubblewrap"
    return None


def _hardhat_fork_selected(config: AuditConfig) -> bool:
    return (
        config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
        and config.smart_contracts.enabled
        and config.scanners.hardhat_fork.enabled
    )


def _hardhat_compilation_selected(config: AuditConfig) -> bool:
    return (
        config.language_profile is LanguageCapabilityProfile.SOLIDITY_EVM
        and config.smart_contracts.enabled
        and config.smart_contracts.compile
        and config.smart_contracts.framework in {"auto", "hardhat"}
    )


def unresolved_managed_toolchain_members(
    limitation: str,
) -> tuple[ManagedToolchainMember, ...]:
    """Build an exact closed catalog with every role explicitly unresolved."""

    return tuple(
        ManagedToolchainMember(
            role=spec.role,
            kind=spec.kind,
            disposition=ManagedToolchainDisposition.UNRESOLVED,
            locator=None,
            version=None,
            sha256=None,
            platform=None,
            platform_manifest_sha256=None,
            parent_image_role=None,
            parent_image_sha256=None,
            parent_platform_manifest_sha256=None,
            consumers=spec.consumers,
            limitation=limitation,
        )
        for spec in MANAGED_TOOLCHAIN_ROLE_SPECS
    )


def default_managed_toolchain_bundle() -> ManagedToolchainBundle:
    """Return the honest packaged declaration without inspecting the host."""

    members = list(
        unresolved_managed_toolchain_members(
            "External production identity is not independently pinned or provisioned."
        )
    )
    packaged_pins = {
        ManagedToolchainRole.HARDHAT_REPORTER: (
            MANAGED_TOOLCHAIN_REPORTER_VERSION,
            MANAGED_TOOLCHAIN_REPORTER_SHA256,
        ),
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA: (
            "1.0",
            MANAGED_TOOLCHAIN_REPORTER_INVENTORY_SCHEMA_SHA256,
        ),
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA: (
            "1.0",
            MANAGED_TOOLCHAIN_REPORTER_TEST_SCHEMA_SHA256,
        ),
    }
    for index, spec in enumerate(MANAGED_TOOLCHAIN_ROLE_SPECS):
        pin = packaged_pins.get(spec.role)
        if pin is None:
            members[index] = members[index].model_copy(
                update={
                    "limitation": (
                        f"Production {spec.role.value} identity is not independently pinned or "
                        "provisioned."
                    )
                }
            )
            continue
        version, sha256 = pin
        members[index] = ManagedToolchainMember(
            role=spec.role,
            kind=spec.kind,
            disposition=ManagedToolchainDisposition.PINNED,
            locator=spec.allowed_locators[0],
            version=version,
            sha256=sha256,
            consumers=spec.consumers,
            limitation=None,
        )
    return seal_managed_toolchain_bundle(
        members=tuple(members),
        target_platform="unresolved",
    )


def render_managed_toolchain_bundle(bundle: ManagedToolchainBundle) -> str:
    """Render deterministic canonical declaration bytes."""

    validated = ManagedToolchainBundle.model_validate(bundle.model_dump(mode="json"))
    return (
        json.dumps(
            validated.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_default_managed_toolchain_bundle() -> str:
    """Render the exact fixed package declaration."""

    return render_managed_toolchain_bundle(default_managed_toolchain_bundle())


def load_packaged_managed_toolchain_bundle() -> ManagedToolchainBundle:
    """Load only the compiled package resource with descriptor-bound custody."""

    package_root = Path(__file__).absolute().parents[1]
    resource_path = package_root / MANAGED_TOOLCHAIN_BUNDLE_RESOURCE
    return _load_managed_toolchain_bundle_path(
        resource_path,
        package_root=package_root,
        expected_raw_sha256=_MANAGED_TOOLCHAIN_BUNDLE_RAW_SHA256,
    )


def _load_managed_toolchain_bundle_path(
    resource_path: Path,
    *,
    package_root: Path,
    expected_raw_sha256: str,
) -> ManagedToolchainBundle:
    """Descriptor-bound implementation retained as a directly testable boundary."""

    if re.fullmatch(_SHA256_PATTERN, expected_raw_sha256) is None:
        raise ManagedToolchainError("managed toolchain expected resource hash is invalid")
    _require_safe_resource_parents(package_root, resource_path.parent)
    try:
        named_before = resource_path.lstat()
    except OSError as exc:
        raise ManagedToolchainError("managed toolchain package resource is unavailable") from exc
    _require_safe_resource_file(named_before)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resource_path, flags)
    except OSError as exc:
        raise ManagedToolchainError("managed toolchain package resource cannot be opened") from exc
    try:
        opened_before = os.fstat(descriptor)
        _require_safe_resource_file(opened_before)
        if _resource_identity(named_before) != _resource_identity(opened_before):
            raise ManagedToolchainError("managed toolchain package resource changed before read")
        chunks: list[bytes] = []
        observed_size = 0
        while True:
            chunk = os.read(descriptor, 65_536)
            if not chunk:
                break
            observed_size += len(chunk)
            if observed_size > 250_000:
                raise ManagedToolchainError("managed toolchain package resource is oversized")
            chunks.append(chunk)
        opened_after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    try:
        named_after = resource_path.lstat()
    except OSError as exc:
        raise ManagedToolchainError("managed toolchain package resource disappeared") from exc
    identity = _resource_identity(opened_before)
    if identity != _resource_identity(opened_after) or identity != _resource_identity(named_after):
        raise ManagedToolchainError("managed toolchain package resource changed during read")
    content = b"".join(chunks)
    if not content or hashlib.sha256(content).hexdigest() != expected_raw_sha256:
        raise ManagedToolchainError("managed toolchain package resource hash is untrusted")
    _strict_json_object(content)
    try:
        bundle = ManagedToolchainBundle.model_validate_json(content, strict=True)
    except ValueError as exc:
        raise ManagedToolchainError("managed toolchain package resource is invalid") from exc
    expected = render_default_managed_toolchain_bundle().encode("utf-8")
    if content != expected:
        raise ManagedToolchainError("managed toolchain package resource bytes are not canonical")
    return bundle


def _require_configured_pin_compatibility(
    config: AuditConfig,
    members: dict[ManagedToolchainRole, ManagedToolchainMember],
    required_roles: tuple[ManagedToolchainRole, ...],
) -> None:
    paired: tuple[tuple[ManagedToolchainRole, str | None, str | None], ...] = (
        (
            ManagedToolchainRole.SOLC,
            config.smart_contracts.solc_version,
            config.smart_contracts.solc_sha256,
        ),
        (
            ManagedToolchainRole.SEMGREP,
            config.scanners.semgrep.version,
            config.scanners.semgrep.sha256,
        ),
        (
            ManagedToolchainRole.GITLEAKS,
            config.scanners.gitleaks.version,
            config.scanners.gitleaks.sha256,
        ),
        (ManagedToolchainRole.TRIVY, config.scanners.trivy.version, config.scanners.trivy.sha256),
        (ManagedToolchainRole.OSV_SCANNER, config.scanners.osv.version, config.scanners.osv.sha256),
        (
            ManagedToolchainRole.CODEQL,
            config.scanners.codeql.version,
            config.scanners.codeql.sha256,
        ),
        (
            ManagedToolchainRole.SLITHER,
            config.scanners.slither.version,
            config.scanners.slither.sha256,
        ),
        (
            ManagedToolchainRole.FORGE,
            config.scanners.foundry_fork.version,
            config.scanners.foundry_fork.sha256,
        ),
        (
            ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
            config.scanners.hardhat_fork.version,
            config.scanners.hardhat_fork.sha256,
        ),
        (ManagedToolchainRole.ECHIDNA, config.formal.echidna_version, config.formal.echidna_sha256),
        (ManagedToolchainRole.MEDUSA, config.formal.medusa_version, config.formal.medusa_sha256),
        (ManagedToolchainRole.HALMOS, config.formal.halmos_version, config.formal.halmos_sha256),
        (
            ManagedToolchainRole.HALMOS_Z3,
            config.formal.halmos_solver_version,
            config.formal.halmos_solver_sha256,
        ),
        (
            ManagedToolchainRole.CERTORA_CLI,
            config.formal.certora.cli_version,
            config.formal.certora.cli_sha256,
        ),
        (ManagedToolchainRole.KONTROL, config.formal.kontrol_version, config.formal.kontrol_sha256),
    )
    for role, version, sha256 in paired:
        if version is None and sha256 is None:
            continue
        member = members[role]
        if (
            member.disposition is not ManagedToolchainDisposition.PINNED
            or member.version != version
            or member.sha256 != sha256
        ):
            raise ManagedToolchainError(
                f"per-run {role.value} trust pins conflict with the managed bundle"
            )

    clean_states = tuple(
        state
        for state in config.smart_contracts.repository_suite.fork_matrix_states
        if isinstance(state, RepositoryCleanForkMatrixStateConfig)
    )
    if clean_states:
        anvil = members[ManagedToolchainRole.ANVIL]
        for state in clean_states:
            if anvil.version != state.anvil_version or anvil.sha256 != state.anvil_sha256:
                raise ManagedToolchainError(
                    "clean-fork Anvil pins conflict with the managed bundle"
                )

    image = config.reproduction.rootless_container_image
    image_member = members[ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE]
    if image is not None and image_member.locator != image:
        raise ManagedToolchainError("rootless container image conflicts with the managed bundle")
    runtime = config.reproduction.rootless_container_runtime
    runtime_member = members[ManagedToolchainRole.CONTAINER_RUNTIME]
    if (
        ManagedToolchainRole.CONTAINER_RUNTIME in required_roles
        and runtime != "auto"
        and runtime_member.locator != runtime
    ):
        raise ManagedToolchainError("rootless container runtime conflicts with the managed bundle")


def _require_member_locator(
    member: ManagedToolchainMember,
    spec: ManagedToolchainRoleSpec,
) -> None:
    if member.disposition is not ManagedToolchainDisposition.PINNED:
        return
    assert member.locator is not None
    assert member.sha256 is not None
    if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE:
        if re.fullmatch(
            _DIGEST_IMAGE_PATTERN, member.locator
        ) is None or not member.locator.endswith(f"@sha256:{member.sha256}"):
            raise ValueError("OCI image locator and declared digest differ")
    elif member.locator not in spec.allowed_locators:
        raise ValueError("managed toolchain member locator differs from its compiled role")


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _strict_json_object(content: bytes) -> dict[str, object]:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ManagedToolchainError("managed toolchain JSON contains a duplicate key")
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise ManagedToolchainError(f"managed toolchain JSON contains non-finite value {value}")

    try:
        decoded = content.decode("utf-8", errors="strict")
        payload = json.loads(
            decoded,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManagedToolchainError(
            "managed toolchain package resource is not strict JSON"
        ) from exc
    if not isinstance(payload, dict):
        raise ManagedToolchainError("managed toolchain package resource must be one JSON object")
    return payload


def _require_safe_resource_parents(package_root: Path, resource_parent: Path) -> None:
    try:
        relative = resource_parent.relative_to(package_root)
    except ValueError as exc:
        raise ManagedToolchainError("managed toolchain resource escaped its package") from exc
    candidates = [package_root]
    current = package_root
    for component in relative.parts:
        current /= component
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ManagedToolchainError("managed toolchain resource parent is unavailable") from exc
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ManagedToolchainError("managed toolchain resource parent is not a real directory")
        if metadata.st_mode & 0o022:
            raise ManagedToolchainError(
                "managed toolchain resource parent is group- or world-writable"
            )


def _require_safe_resource_file(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ManagedToolchainError("managed toolchain package resource is not a regular file")
    if metadata.st_nlink != 1:
        raise ManagedToolchainError("managed toolchain package resource has multiple hard links")
    if metadata.st_mode & 0o022:
        raise ManagedToolchainError(
            "managed toolchain package resource is group- or world-writable"
        )
    if not 0 < metadata.st_size <= 250_000:
        raise ManagedToolchainError("managed toolchain package resource is empty or oversized")


def _resource_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _spec(
    role: ManagedToolchainRole,
    kind: ManagedToolchainMemberKind,
    locators: tuple[str, ...],
    consumers: tuple[ManagedToolchainConsumer, ...],
) -> ManagedToolchainRoleSpec:
    return ManagedToolchainRoleSpec(
        role=role,
        kind=kind,
        allowed_locators=tuple(sorted(locators)),
        consumers=tuple(sorted(consumers, key=str)),
    )


MANAGED_TOOLCHAIN_ROLE_SPECS: tuple[ManagedToolchainRoleSpec, ...] = (
    _spec(
        ManagedToolchainRole.SOLC,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("solc",),
        (
            ManagedToolchainConsumer.FORMAL_FOUNDRY_INVARIANT,
            ManagedToolchainConsumer.FORMAL_SMTCHECKER,
            ManagedToolchainConsumer.GENERATED_INVARIANT_EXECUTION,
            ManagedToolchainConsumer.SCANNER_FOUNDRY_COMPILER,
            ManagedToolchainConsumer.SCANNER_SLITHER_COMPILER,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
            ManagedToolchainConsumer.SOLIDITY_REPRODUCTION,
        ),
    ),
    _spec(
        ManagedToolchainRole.ANVIL,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("anvil",),
        (ManagedToolchainConsumer.CLEAN_FORK_MATRIX,),
    ),
    _spec(
        ManagedToolchainRole.SEMGREP,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("semgrep",),
        (ManagedToolchainConsumer.SCANNER_SEMGREP,),
    ),
    _spec(
        ManagedToolchainRole.GITLEAKS,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("gitleaks",),
        (ManagedToolchainConsumer.SCANNER_GITLEAKS,),
    ),
    _spec(
        ManagedToolchainRole.TRIVY,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("trivy",),
        (ManagedToolchainConsumer.SCANNER_TRIVY,),
    ),
    _spec(
        ManagedToolchainRole.OSV_SCANNER,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("osv-scanner",),
        (ManagedToolchainConsumer.SCANNER_OSV,),
    ),
    _spec(
        ManagedToolchainRole.CODEQL,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("codeql",),
        (ManagedToolchainConsumer.SCANNER_CODEQL,),
    ),
    _spec(
        ManagedToolchainRole.SLITHER,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("slither",),
        (ManagedToolchainConsumer.SCANNER_SLITHER,),
    ),
    _spec(
        ManagedToolchainRole.FORGE,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("forge",),
        (
            ManagedToolchainConsumer.FORMAL_FOUNDRY_INVARIANT,
            ManagedToolchainConsumer.GENERATED_INVARIANT_EXECUTION,
            ManagedToolchainConsumer.SCANNER_FOUNDRY_FORK,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
            ManagedToolchainConsumer.SOLIDITY_REPRODUCTION,
        ),
    ),
    _spec(
        ManagedToolchainRole.MYTHRIL,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("myth",),
        (ManagedToolchainConsumer.FORMAL_MYTHRIL,),
    ),
    _spec(
        ManagedToolchainRole.ECHIDNA,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("echidna",),
        (ManagedToolchainConsumer.FORMAL_ECHIDNA,),
    ),
    _spec(
        ManagedToolchainRole.MEDUSA,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("medusa",),
        (ManagedToolchainConsumer.FORMAL_MEDUSA,),
    ),
    _spec(
        ManagedToolchainRole.HALMOS,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("halmos",),
        (ManagedToolchainConsumer.FORMAL_HALMOS,),
    ),
    _spec(
        ManagedToolchainRole.HALMOS_Z3,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("z3",),
        (ManagedToolchainConsumer.FORMAL_HALMOS_SOLVER,),
    ),
    _spec(
        ManagedToolchainRole.CERTORA_CLI,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("certoraRun",),
        (ManagedToolchainConsumer.FORMAL_CERTORA,),
    ),
    _spec(
        ManagedToolchainRole.KONTROL,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("kontrol",),
        (ManagedToolchainConsumer.FORMAL_KONTROL,),
    ),
    _spec(
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("python3",),
        (ManagedToolchainConsumer.MMAUDIT_RUNTIME,),
    ),
    _spec(
        ManagedToolchainRole.GIT,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("git",),
        (ManagedToolchainConsumer.REPOSITORY_DISCOVERY,),
    ),
    _spec(
        ManagedToolchainRole.SANDBOX_EXEC,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("sandbox-exec",),
        (ManagedToolchainConsumer.HARDENED_HOST_ISOLATION,),
    ),
    _spec(
        ManagedToolchainRole.BUBBLEWRAP,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("bwrap",),
        (ManagedToolchainConsumer.HARDENED_HOST_ISOLATION,),
    ),
    _spec(
        ManagedToolchainRole.CONTAINER_RUNTIME,
        ManagedToolchainMemberKind.HOST_EXECUTABLE,
        ("docker", "podman"),
        (
            ManagedToolchainConsumer.ROOTLESS_CONTAINER,
            ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ),
    ),
    _spec(
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainMemberKind.OCI_IMAGE,
        ("digest-pinned-image",),
        (
            ManagedToolchainConsumer.ROOTLESS_CONTAINER,
            ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainMemberKind.IMAGE_EXECUTABLE,
        ("/usr/local/bin/hardhat",),
        (
            ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
        ManagedToolchainMemberKind.IMAGE_EXECUTABLE,
        ("/usr/local/bin/node",),
        (
            ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,
            ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
        ManagedToolchainMemberKind.IMAGE_EXECUTABLE,
        ("/usr/local/bin/mmaudit-hardhat-loopback",),
        (ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainMemberKind.PACKAGE_RESOURCE,
        ("src/mmaudit/scanners/hardhat_reporter.cjs",),
        (ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainMemberKind.GENERATED_SCHEMA,
        ("schemas/hardhat_reporter_inventory.schema.json",),
        (ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,),
    ),
    _spec(
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
        ManagedToolchainMemberKind.GENERATED_SCHEMA,
        ("schemas/hardhat_reporter_test.schema.json",),
        (ManagedToolchainConsumer.SCANNER_HARDHAT_FORK,),
    ),
)
