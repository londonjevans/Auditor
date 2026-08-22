from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.orchestration.managed_toolchain as managed_toolchain_module
from mmaudit.config import AuditConfig
from mmaudit.orchestration.managed_toolchain import (
    MANAGED_TOOLCHAIN_BUNDLE_RESOURCE,
    MANAGED_TOOLCHAIN_DECLARATION_LIMITATIONS,
    MANAGED_TOOLCHAIN_REPORTER_INVENTORY_SCHEMA_SHA256,
    MANAGED_TOOLCHAIN_REPORTER_SHA256,
    MANAGED_TOOLCHAIN_REPORTER_TEST_SCHEMA_SHA256,
    MANAGED_TOOLCHAIN_ROLE_SPECS,
    ManagedToolchainBundle,
    ManagedToolchainBundleStatus,
    ManagedToolchainConsumer,
    ManagedToolchainDisposition,
    ManagedToolchainError,
    ManagedToolchainMember,
    ManagedToolchainMemberKind,
    ManagedToolchainRole,
    default_managed_toolchain_bundle,
    load_packaged_managed_toolchain_bundle,
    required_managed_toolchain_roles,
    resolve_managed_toolchain_config,
    seal_managed_toolchain_bundle,
    unresolved_managed_toolchain_members,
)
from mmaudit.scanners.hardhat import HARDHAT_REPORTER_SHA256, HARDHAT_REPORTER_VERSION

ROOT = Path(__file__).resolve().parents[2]


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _pinned_members() -> tuple[ManagedToolchainMember, ...]:
    members: list[ManagedToolchainMember] = []
    parent_image_sha256 = _digest(ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE.value)
    parent_platform_manifest_sha256 = _digest(
        f"platform:{ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE.value}"
    )
    for spec in MANAGED_TOOLCHAIN_ROLE_SPECS:
        digest = _digest(spec.role.value)
        locator = spec.allowed_locators[0]
        if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE:
            locator = f"registry.example/mmaudit-toolchain@sha256:{digest}"
        members.append(
            ManagedToolchainMember(
                role=spec.role,
                kind=spec.kind,
                disposition=ManagedToolchainDisposition.PINNED,
                locator=locator,
                version="1.2.3",
                sha256=digest,
                platform=(
                    "linux-amd64" if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE else None
                ),
                platform_manifest_sha256=(
                    _digest(f"platform:{spec.role.value}")
                    if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE
                    else None
                ),
                parent_image_role=(
                    ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
                    if spec.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE
                    else None
                ),
                parent_image_sha256=(
                    parent_image_sha256
                    if spec.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE
                    else None
                ),
                parent_platform_manifest_sha256=(
                    parent_platform_manifest_sha256
                    if spec.kind is ManagedToolchainMemberKind.IMAGE_EXECUTABLE
                    else None
                ),
                consumers=spec.consumers,
                limitation=None,
            )
        )
    return tuple(members)


def _pinned_bundle() -> ManagedToolchainBundle:
    return seal_managed_toolchain_bundle(
        members=_pinned_members(),
        target_platform="linux-amd64",
    )


def _member(
    members: tuple[ManagedToolchainMember, ...],
    role: ManagedToolchainRole,
) -> ManagedToolchainMember:
    return next(item for item in members if item.role is role)


def _updated_config(config: AuditConfig, **sections: object) -> AuditConfig:
    payload = config.model_dump(mode="json")
    for section, value in sections.items():
        if isinstance(value, dict) and isinstance(payload.get(section), dict):
            payload[section].update(value)
        else:
            payload[section] = value
    return AuditConfig.model_validate(payload)


def _disabled_scanners() -> dict[str, dict[str, object]]:
    return {
        name: {"enabled": False, "required": False}
        for name in (
            "semgrep",
            "gitleaks",
            "trivy",
            "osv",
            "codeql",
            "slither",
            "foundry_fork",
            "hardhat_fork",
        )
    }


def _clean_fork_suite(
    config: AuditConfig,
    *,
    anvil_version: str = "anvil Version: 1.3.2-stable",
    anvil_sha256: str = "a" * 64,
) -> dict[str, object]:
    suite = config.smart_contracts.repository_suite.model_dump(mode="json")
    suite["fork_matrix_states"] = [
        {
            "state_id": "clean-local",
            "kind": "clean_local",
            "expected_chain_id": 31_337,
            "anvil_executable_env": "MMAUDIT_ANVIL_EXECUTABLE",
            "anvil_version": anvil_version,
            "anvil_sha256": anvil_sha256,
            "hardfork": "cancun",
            "genesis_timestamp": 1,
            "startup_timeout_seconds": 5,
            "shutdown_timeout_seconds": 5,
        },
        {
            "state_id": "pinned-state",
            "kind": "pinned_fork",
            "rpc_url_env": "MMAUDIT_PINNED_FORK_RPC_URL",
            "expected_chain_id": 1,
            "pinned_block_number": 20_000_000,
            "state_source_sha256": "b" * 64,
        },
    ]
    return suite


def test_closed_role_catalog_covers_shared_and_image_side_consumers() -> None:
    assert tuple(spec.role for spec in MANAGED_TOOLCHAIN_ROLE_SPECS) == tuple(ManagedToolchainRole)
    assert len(MANAGED_TOOLCHAIN_ROLE_SPECS) == 28
    forge = next(
        spec for spec in MANAGED_TOOLCHAIN_ROLE_SPECS if spec.role is ManagedToolchainRole.FORGE
    )
    assert forge.consumers == (
        ManagedToolchainConsumer.FORMAL_FOUNDRY_INVARIANT,
        ManagedToolchainConsumer.GENERATED_INVARIANT_EXECUTION,
        ManagedToolchainConsumer.SCANNER_FOUNDRY_FORK,
        ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ManagedToolchainConsumer.SOLIDITY_REPRODUCTION,
    )
    solc = next(
        spec for spec in MANAGED_TOOLCHAIN_ROLE_SPECS if spec.role is ManagedToolchainRole.SOLC
    )
    assert solc.consumers == (
        ManagedToolchainConsumer.FORMAL_FOUNDRY_INVARIANT,
        ManagedToolchainConsumer.FORMAL_SMTCHECKER,
        ManagedToolchainConsumer.GENERATED_INVARIANT_EXECUTION,
        ManagedToolchainConsumer.SCANNER_FOUNDRY_COMPILER,
        ManagedToolchainConsumer.SCANNER_SLITHER_COMPILER,
        ManagedToolchainConsumer.SOLIDITY_COMPILATION,
        ManagedToolchainConsumer.SOLIDITY_REPRODUCTION,
    )
    hardhat_roles = {
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
        ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
    }
    assert hardhat_roles <= {spec.role for spec in MANAGED_TOOLCHAIN_ROLE_SPECS}
    hardhat_consumer_roles = {
        spec.role
        for spec in MANAGED_TOOLCHAIN_ROLE_SPECS
        if ManagedToolchainConsumer.SCANNER_HARDHAT_FORK in spec.consumers
    }
    assert {
        ManagedToolchainRole.CONTAINER_RUNTIME,
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
        ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
    } == hardhat_consumer_roles
    assert {
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.SANDBOX_EXEC,
        ManagedToolchainRole.BUBBLEWRAP,
    } <= {spec.role for spec in MANAGED_TOOLCHAIN_ROLE_SPECS}
    assert {
        consumer for spec in MANAGED_TOOLCHAIN_ROLE_SPECS for consumer in spec.consumers
    } == set(ManagedToolchainConsumer)
    compilation_roles = {
        spec.role
        for spec in MANAGED_TOOLCHAIN_ROLE_SPECS
        if ManagedToolchainConsumer.SOLIDITY_COMPILATION in spec.consumers
    }
    assert compilation_roles == {
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.CONTAINER_RUNTIME,
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
    }


def test_unresolved_catalog_is_complete_partial_and_nonauthorizing() -> None:
    bundle = seal_managed_toolchain_bundle(
        members=unresolved_managed_toolchain_members(
            "External production identity has not been independently pinned."
        ),
        target_platform="unresolved",
    )

    assert bundle.status is ManagedToolchainBundleStatus.PARTIAL_NONAUTHORIZING
    assert tuple(member.role for member in bundle.members) == tuple(ManagedToolchainRole)
    assert bundle.self_consistent is True
    assert bundle.independently_trusted is False
    assert bundle.installed_members_verified is False
    assert bundle.execution_evidence_verified is False
    assert bundle.runtime_authority is False
    assert bundle.managed_run_ready is False


def test_bundle_rejects_hash_tampering() -> None:
    payload = _pinned_bundle().model_dump(mode="json")
    payload["bundle_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        ManagedToolchainBundle.model_validate(payload)

    payload = _pinned_bundle().model_dump(mode="json")
    payload["objective_sha256"] = "f" * 64
    with pytest.raises(ValidationError, match="literal_error"):
        ManagedToolchainBundle.model_validate(payload)


def test_bundle_rejects_missing_reordered_and_role_retargeted_members() -> None:
    members = list(_pinned_members())
    with pytest.raises(ValidationError, match="at least 28"):
        seal_managed_toolchain_bundle(
            members=tuple(members[:-1]),
            target_platform="linux-amd64",
        )
    with pytest.raises(ValidationError, match="closed ordered role catalog"):
        seal_managed_toolchain_bundle(
            members=(members[1], members[0], *members[2:]),
            target_platform="linux-amd64",
        )

    forged = members[0].model_copy(update={"role": ManagedToolchainRole.ANVIL})
    with pytest.raises(ValidationError, match="closed ordered role catalog"):
        seal_managed_toolchain_bundle(
            members=(forged, *members[1:]),
            target_platform="linux-amd64",
        )


def test_bundle_rejects_kind_consumer_locator_and_image_digest_retargeting() -> None:
    members = list(_pinned_members())
    semgrep_index = next(
        index for index, item in enumerate(members) if item.role is ManagedToolchainRole.SEMGREP
    )
    for updates, message in (
        ({"kind": ManagedToolchainMemberKind.GENERATED_SCHEMA}, "compiled role contract"),
        (
            {"consumers": (ManagedToolchainConsumer.SCANNER_TRIVY,)},
            "compiled role contract",
        ),
        ({"locator": "different-tool"}, "locator differs"),
    ):
        changed = list(members)
        changed[semgrep_index] = changed[semgrep_index].model_copy(update=updates)
        with pytest.raises(ValidationError, match=message):
            seal_managed_toolchain_bundle(
                members=tuple(changed),
                target_platform="linux-amd64",
            )

    image_index = next(
        index
        for index, item in enumerate(members)
        if item.role is ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE
    )
    changed = list(members)
    changed[image_index] = changed[image_index].model_copy(update={"sha256": "a" * 64})
    with pytest.raises(ValidationError, match="locator and declared digest differ"):
        seal_managed_toolchain_bundle(
            members=tuple(changed),
            target_platform="linux-amd64",
        )

    image = members[image_index]
    tagged = list(members)
    tagged[image_index] = image.model_copy(
        update={"locator": (f"registry.example/mmaudit-toolchain:latest@sha256:{image.sha256}")}
    )
    with pytest.raises(ValidationError, match="locator and declared digest differ"):
        seal_managed_toolchain_bundle(
            members=tuple(tagged),
            target_platform="linux-amd64",
        )
    with pytest.raises(ValidationError, match="platform differs"):
        seal_managed_toolchain_bundle(
            members=tuple(members),
            target_platform="linux-arm64",
        )

    swapped_parent = list(members)
    new_parent_sha256 = "b" * 64
    swapped_parent[image_index] = image.model_copy(
        update={
            "locator": f"registry.example/mmaudit-toolchain@sha256:{new_parent_sha256}",
            "sha256": new_parent_sha256,
        }
    )
    with pytest.raises(ValidationError, match="parent image identity differs"):
        seal_managed_toolchain_bundle(
            members=tuple(swapped_parent),
            target_platform="linux-amd64",
        )

    swapped_platform = list(members)
    swapped_platform[image_index] = image.model_copy(update={"platform_manifest_sha256": "c" * 64})
    with pytest.raises(ValidationError, match="parent platform identity differs"):
        seal_managed_toolchain_bundle(
            members=tuple(swapped_platform),
            target_platform="linux-amd64",
        )


def test_member_disposition_rejects_partial_pins_zero_hash_and_false_availability() -> None:
    spec = MANAGED_TOOLCHAIN_ROLE_SPECS[0]
    common: dict[str, Any] = {
        "role": spec.role,
        "kind": spec.kind,
        "consumers": spec.consumers,
    }
    with pytest.raises(ValidationError, match="requires only exact pin fields"):
        ManagedToolchainMember(
            **common,
            disposition=ManagedToolchainDisposition.PINNED,
            locator="solc",
            version="1.2.3",
            sha256=None,
            limitation=None,
        )
    with pytest.raises(ValidationError, match="zero SHA-256"):
        ManagedToolchainMember(
            **common,
            disposition=ManagedToolchainDisposition.PINNED,
            locator="solc",
            version="1.2.3",
            sha256="0" * 64,
            limitation=None,
        )
    with pytest.raises(ValidationError, match="requires only a limitation"):
        ManagedToolchainMember(
            **common,
            disposition=ManagedToolchainDisposition.UNRESOLVED,
            locator="solc",
            version=None,
            sha256=None,
            limitation="Not yet pinned.",
        )


def test_empty_effective_surface_projects_without_runtime_authority(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        reproduction={"rootless_container_runtime": "podman"},
    )
    projection = resolve_managed_toolchain_config(_pinned_bundle(), config)

    assert set(projection.required_roles) == {
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.PYTHON_RUNTIME,
    }
    assert {member.role for member in projection.members} == set(projection.required_roles)
    assert projection.resolved_isolation_backend is None
    assert projection.resolved_container_runtime is None
    assert projection.resolved_rootless_image is None
    assert projection.bundle_trusted is False
    assert projection.installed_members_verified is False
    assert projection.execution_evidence_verified is False
    assert projection.runtime_authority is False
    assert projection.managed_run_ready is False


def test_enabled_scanner_requires_a_pinned_member_and_matching_per_run_pins(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    semgrep = _member(bundle.members, ManagedToolchainRole.SEMGREP)
    config = _updated_config(
        config_factory(),
        scanners={
            "semgrep": {
                "enabled": True,
                "required": True,
                "version": semgrep.version,
                "sha256": semgrep.sha256,
            }
        },
        reproduction={"isolation_backend": "bubblewrap"},
    )
    projection = resolve_managed_toolchain_config(bundle, config)
    assert set(projection.required_roles) == {
        ManagedToolchainRole.BUBBLEWRAP,
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainRole.SEMGREP,
    }
    assert projection.resolved_isolation_backend == "bubblewrap"

    conflict = _updated_config(
        config,
        scanners={
            **config.scanners.model_dump(mode="json"),
            "semgrep": {
                "enabled": True,
                "required": True,
                "version": "9.9.9",
                "sha256": "9" * 64,
            },
        },
    )
    with pytest.raises(ManagedToolchainError, match="trust pins conflict"):
        resolve_managed_toolchain_config(bundle, conflict)

    unresolved_members = list(bundle.members)
    index = next(
        index
        for index, item in enumerate(unresolved_members)
        if item.role is ManagedToolchainRole.SEMGREP
    )
    unresolved_members[index] = ManagedToolchainMember(
        role=MANAGED_TOOLCHAIN_ROLE_SPECS[index].role,
        kind=MANAGED_TOOLCHAIN_ROLE_SPECS[index].kind,
        disposition=ManagedToolchainDisposition.UNRESOLVED,
        consumers=MANAGED_TOOLCHAIN_ROLE_SPECS[index].consumers,
        limitation="No production Semgrep identity is pinned.",
    )
    partial = seal_managed_toolchain_bundle(
        members=tuple(unresolved_members),
        target_platform="linux-amd64",
    )
    with pytest.raises(ManagedToolchainError, match="semgrep is UNRESOLVED"):
        resolve_managed_toolchain_config(partial, config)


def test_host_execution_refuses_ambient_auto_isolation_selection(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        scanners={"semgrep": {"enabled": True, "required": True}},
        reproduction={"isolation_backend": "auto", "rootless_container_image": None},
    )

    with pytest.raises(
        ManagedToolchainError,
        match="host isolation backend auto requires an explicit deterministic selection",
    ):
        resolve_managed_toolchain_config(_pinned_bundle(), config)


def test_required_but_disabled_scanner_and_maximum_downgrade_are_refused(
    config_factory: Callable[..., AuditConfig],
) -> None:
    disabled_required = _updated_config(
        config_factory(),
        scanners={"semgrep": {"enabled": False, "required": True}},
    )
    with pytest.raises(ManagedToolchainError, match="required scanner semgrep"):
        required_managed_toolchain_roles(disabled_required)

    downgradable = _updated_config(
        config_factory(),
        profile="maximum-assurance",
        maximum_assurance={"allow_downgrade": True},
    )
    with pytest.raises(ManagedToolchainError, match="cannot allow downgrade"):
        resolve_managed_toolchain_config(_pinned_bundle(), downgradable)


def test_maximum_assurance_requires_forge_z3_and_all_enabled_formal_engines(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        profile="maximum-assurance",
        language_profile="solidity-evm",
    )
    required = set(required_managed_toolchain_roles(config))

    assert {
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.SLITHER,
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.MYTHRIL,
        ManagedToolchainRole.ECHIDNA,
        ManagedToolchainRole.MEDUSA,
        ManagedToolchainRole.HALMOS,
        ManagedToolchainRole.HALMOS_Z3,
        ManagedToolchainRole.KONTROL,
    } <= required


def test_formal_foundry_and_mixed_framework_compilation_cannot_escape_the_catalog(
    config_factory: Callable[..., AuditConfig],
) -> None:
    formal = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        formal={
            "enabled": True,
            "run_smtchecker": False,
            "run_mythril": False,
            "run_echidna": False,
            "run_medusa": False,
            "run_halmos": False,
            "run_kontrol": False,
        },
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )
    assert ManagedToolchainRole.FORGE in required_managed_toolchain_roles(formal)

    compiling = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )
    required = set(required_managed_toolchain_roles(compiling))
    assert {ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC} <= required

    mixed = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "mixed"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )
    mixed_projection = resolve_managed_toolchain_config(_pinned_bundle(), mixed)
    assert {ManagedToolchainRole.FORGE, ManagedToolchainRole.SOLC} <= set(
        mixed_projection.required_roles
    )
    assert ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT not in mixed_projection.required_roles

    auto = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "auto"},
    )
    assert {
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
    } <= set(required_managed_toolchain_roles(auto))
    with pytest.raises(ManagedToolchainError, match="unrepresented image-side identities"):
        resolve_managed_toolchain_config(_pinned_bundle(), auto)


@pytest.mark.parametrize("framework", ["foundry", "mixed", "hardhat"])
def test_disabled_solidity_portfolio_does_not_project_inert_compile_or_scanner_tools(
    config_factory: Callable[..., AuditConfig],
    framework: str,
) -> None:
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners={
            "slither": {"enabled": True, "required": False},
            "foundry_fork": {"enabled": True, "required": False},
            "hardhat_fork": {"enabled": True, "required": False},
        },
        smart_contracts={"enabled": False, "compile": True, "framework": framework},
        formal={"enabled": True},
        reproduction={"enabled": True, "isolation_backend": "bubblewrap"},
    )

    assert set(required_managed_toolchain_roles(config)) == {
        ManagedToolchainRole.BUBBLEWRAP,
        ManagedToolchainRole.GIT,
        ManagedToolchainRole.PYTHON_RUNTIME,
        ManagedToolchainRole.SLITHER,
        ManagedToolchainRole.SOLC,
    }


def test_slither_requires_a_managed_compiler_and_matching_config_pin(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    solc = _member(bundle.members, ManagedToolchainRole.SOLC)
    scanners = _disabled_scanners()
    scanners["slither"] = {"enabled": True, "required": True}
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners=scanners,
        smart_contracts={
            "enabled": False,
            "compile": False,
            "solc_version": solc.version,
            "solc_sha256": solc.sha256,
        },
        formal={"enabled": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )

    projection = resolve_managed_toolchain_config(bundle, config)
    assert {
        ManagedToolchainRole.SLITHER,
        ManagedToolchainRole.SOLC,
    } <= set(projection.required_roles)

    members = list(bundle.members)
    solc_index = next(
        index for index, member in enumerate(members) if member.role is ManagedToolchainRole.SOLC
    )
    members[solc_index] = ManagedToolchainMember(
        role=ManagedToolchainRole.SOLC,
        kind=ManagedToolchainMemberKind.HOST_EXECUTABLE,
        disposition=ManagedToolchainDisposition.UNRESOLVED,
        consumers=MANAGED_TOOLCHAIN_ROLE_SPECS[solc_index].consumers,
        limitation="No production Solidity compiler identity is pinned.",
    )
    partial = seal_managed_toolchain_bundle(
        members=tuple(members),
        target_platform="linux-amd64",
    )
    with pytest.raises(ManagedToolchainError, match="required managed toolchain role solc"):
        resolve_managed_toolchain_config(partial, config)

    conflict = _updated_config(
        config,
        smart_contracts={"solc_version": "9.9.9", "solc_sha256": "9" * 64},
    )
    with pytest.raises(ManagedToolchainError, match="solc trust pins conflict"):
        resolve_managed_toolchain_config(bundle, conflict)


def test_foundry_compilation_refuses_an_unresolved_solidity_compiler(
    config_factory: Callable[..., AuditConfig],
) -> None:
    members = list(_pinned_members())
    solc_index = next(
        index for index, member in enumerate(members) if member.role is ManagedToolchainRole.SOLC
    )
    members[solc_index] = ManagedToolchainMember(
        role=ManagedToolchainRole.SOLC,
        kind=ManagedToolchainMemberKind.HOST_EXECUTABLE,
        disposition=ManagedToolchainDisposition.UNRESOLVED,
        consumers=MANAGED_TOOLCHAIN_ROLE_SPECS[solc_index].consumers,
        limitation="The exact Solidity compiler is unavailable.",
    )
    bundle = seal_managed_toolchain_bundle(
        members=tuple(members),
        target_platform="linux-amd64",
    )
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        smart_contracts={"compile": True, "framework": "foundry"},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
    )
    with pytest.raises(ManagedToolchainError, match="required managed toolchain role solc"):
        resolve_managed_toolchain_config(bundle, config)


def test_generated_invariant_execution_requires_forge_and_local_compiler(
    config_factory: Callable[..., AuditConfig],
) -> None:
    generated = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        invariants={"enabled": True, "execute_generated": True},
        smart_contracts={"compile": False},
        formal={"enabled": False},
        reproduction={"enabled": False, "isolation_backend": "bubblewrap"},
        scanners={"foundry_fork": {"enabled": False, "required": False}},
    )
    assert {
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.SOLC,
    } <= set(required_managed_toolchain_roles(generated))

    local = _updated_config(
        generated,
        invariants={
            "enabled": True,
            "execute_generated": True,
            "local_deployments": [
                {
                    "target_alias": "Vault",
                    "contract_name": "Vault",
                    "source_path": "src/Vault.sol",
                }
            ],
        },
    )
    assert ManagedToolchainRole.SOLC in required_managed_toolchain_roles(local)


def test_explicit_formal_pins_are_projected_even_when_formal_execution_is_disabled(
    config_factory: Callable[..., AuditConfig],
) -> None:
    digest = "a" * 64
    config = _updated_config(
        config_factory(),
        formal={
            "enabled": False,
            "echidna_version": "1.0.0",
            "echidna_sha256": digest,
            "medusa_version": "1.0.0",
            "medusa_sha256": digest,
            "halmos_version": "1.0.0",
            "halmos_sha256": digest,
            "halmos_solver_version": "1.0.0",
            "halmos_solver_sha256": digest,
            "kontrol_version": "1.0.0",
            "kontrol_sha256": digest,
            "certora": {
                "enabled": False,
                "cli_version": "1.0.0",
                "cli_sha256": digest,
            },
        },
    )

    assert {
        ManagedToolchainRole.ECHIDNA,
        ManagedToolchainRole.MEDUSA,
        ManagedToolchainRole.HALMOS,
        ManagedToolchainRole.HALMOS_Z3,
        ManagedToolchainRole.CERTORA_CLI,
        ManagedToolchainRole.KONTROL,
    } <= set(required_managed_toolchain_roles(config))


def test_hardhat_requires_image_runtime_image_side_tools_reporter_and_both_schemas(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    image = _member(bundle.members, ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    hardhat = _member(bundle.members, ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT)
    scanners = _disabled_scanners()
    scanners["hardhat_fork"] = {
        "enabled": True,
        "required": True,
        "version": hardhat.version,
        "sha256": hardhat.sha256,
    }
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners=scanners,
        smart_contracts={"compile": False},
        formal={"enabled": False},
        reproduction={
            "enabled": False,
            "isolation_backend": "rootless-container",
            "rootless_container_runtime": "docker",
            "rootless_container_image": image.locator,
        },
    )
    required = set(required_managed_toolchain_roles(config))
    assert {
        ManagedToolchainRole.CONTAINER_RUNTIME,
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
        ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
    } <= required
    projection = resolve_managed_toolchain_config(bundle, config)
    assert set(projection.required_roles) == required
    assert projection.resolved_isolation_backend == "rootless-container"

    auto_runtime = _updated_config(
        config,
        reproduction={
            **config.reproduction.model_dump(mode="json"),
            "rootless_container_runtime": "auto",
        },
    )
    auto_projection = resolve_managed_toolchain_config(bundle, auto_runtime)
    assert auto_projection.resolved_isolation_backend == "rootless-container"
    assert auto_projection.resolved_container_runtime == "docker"
    assert auto_projection.resolved_rootless_image == image.locator


def test_hardhat_compilation_projects_only_its_actual_image_chain(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    image = _member(bundle.members, ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners=_disabled_scanners(),
        smart_contracts={"compile": True, "framework": "hardhat"},
        formal={"enabled": False},
        reproduction={
            "enabled": False,
            "isolation_backend": "rootless-container",
            "rootless_container_runtime": "docker",
            "rootless_container_image": image.locator,
        },
    )

    projection = resolve_managed_toolchain_config(bundle, config)
    roles = set(projection.required_roles)
    assert projection.resolved_isolation_backend == "rootless-container"
    assert {
        ManagedToolchainRole.CONTAINER_RUNTIME,
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.HARDHAT_IMAGE_NODE,
    } <= roles
    assert {
        ManagedToolchainRole.HARDHAT_IMAGE_LOOPBACK,
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
    }.isdisjoint(roles)


def test_inert_rootless_image_pin_does_not_override_an_explicit_host_backend(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    image = _member(bundle.members, ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners=_disabled_scanners(),
        smart_contracts={"compile": True, "framework": "foundry"},
        formal={"enabled": False},
        reproduction={
            "enabled": False,
            "isolation_backend": "sandbox-exec",
            "rootless_container_runtime": "auto",
            "rootless_container_image": image.locator,
        },
    )

    projection = resolve_managed_toolchain_config(bundle, config)
    assert {
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE,
    } <= set(projection.required_roles)
    assert ManagedToolchainRole.CONTAINER_RUNTIME not in projection.required_roles
    assert ManagedToolchainRole.SANDBOX_EXEC in projection.required_roles
    assert projection.resolved_isolation_backend == "sandbox-exec"
    assert projection.resolved_container_runtime is None
    assert projection.resolved_rootless_image == image.locator


@pytest.mark.parametrize("backend", ["sandbox-exec", "bubblewrap"])
@pytest.mark.parametrize("hardhat_mode", ["compile", "fork"])
def test_hardhat_refuses_an_explicit_non_rootless_backend(
    config_factory: Callable[..., AuditConfig],
    backend: str,
    hardhat_mode: str,
) -> None:
    scanners = _disabled_scanners()
    smart_contracts: dict[str, object] = {"compile": False}
    if hardhat_mode == "compile":
        smart_contracts = {"compile": True, "framework": "hardhat"}
    else:
        scanners["hardhat_fork"] = {"enabled": True, "required": True}
    config = _updated_config(
        config_factory(),
        language_profile="solidity-evm",
        scanners=scanners,
        smart_contracts=smart_contracts,
        formal={"enabled": False},
        reproduction={
            "enabled": False,
            "isolation_backend": backend,
            "rootless_container_runtime": "auto",
            "rootless_container_image": None,
        },
    )

    with pytest.raises(
        ManagedToolchainError,
        match="Hardhat execution requires auto or rootless-container isolation",
    ):
        required_managed_toolchain_roles(config)


def test_rootless_hardhat_does_not_misclassify_host_side_clean_anvil(
    config_factory: Callable[..., AuditConfig],
) -> None:
    members = list(_pinned_members())
    anvil_index = next(
        index for index, member in enumerate(members) if member.role is ManagedToolchainRole.ANVIL
    )
    anvil_version = "anvil Version: 1.3.2-stable"
    anvil_sha256 = "a" * 64
    members[anvil_index] = members[anvil_index].model_copy(
        update={"version": anvil_version, "sha256": anvil_sha256}
    )
    bundle = seal_managed_toolchain_bundle(
        members=tuple(members),
        target_platform="linux-amd64",
    )
    image = _member(bundle.members, ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE)
    hardhat = _member(bundle.members, ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT)
    scanners = _disabled_scanners()
    scanners["hardhat_fork"] = {
        "enabled": True,
        "required": True,
        "version": hardhat.version,
        "sha256": hardhat.sha256,
    }
    base = config_factory()
    config = _updated_config(
        base,
        language_profile="solidity-evm",
        scanners=scanners,
        smart_contracts={
            "compile": False,
            "repository_suite": _clean_fork_suite(
                base,
                anvil_version=anvil_version,
                anvil_sha256=anvil_sha256,
            ),
        },
        formal={"enabled": False},
        reproduction={
            "enabled": False,
            "isolation_backend": "rootless-container",
            "rootless_container_runtime": "auto",
            "rootless_container_image": image.locator,
        },
    )

    projection = resolve_managed_toolchain_config(bundle, config)
    assert ManagedToolchainRole.ANVIL in projection.required_roles
    assert projection.resolved_isolation_backend == "rootless-container"
    assert projection.resolved_container_runtime == "docker"


def test_config_projection_does_not_touch_host_process_network_or_environment(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pure managed toolchain projection accessed an ambient boundary")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)

    projection = resolve_managed_toolchain_config(_pinned_bundle(), config_factory())
    assert projection.managed_run_ready is False


def test_projection_snapshots_one_exact_validated_config_and_rejects_subclasses(
    config_factory: Callable[..., AuditConfig],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_effective = AuditConfig.effective
    effective_calls = 0

    def counted_effective(config: AuditConfig) -> AuditConfig:
        nonlocal effective_calls
        effective_calls += 1
        return original_effective(config)

    monkeypatch.setattr(AuditConfig, "effective", counted_effective)
    resolve_managed_toolchain_config(_pinned_bundle(), config_factory())
    assert effective_calls == 1

    class DerivedAuditConfig(AuditConfig):
        pass

    derived = DerivedAuditConfig.model_validate(config_factory().model_dump(mode="json"))
    with pytest.raises(ManagedToolchainError, match="exact AuditConfig type"):
        resolve_managed_toolchain_config(_pinned_bundle(), derived)


def test_projection_rejects_post_validation_config_mutation_and_bundle_subclasses(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    config.scanners.semgrep.enabled = "not-a-boolean"  # type: ignore[assignment]
    with (
        pytest.warns(UserWarning, match="Pydantic serializer warnings"),
        pytest.raises(ManagedToolchainError, match="config snapshot is invalid"),
    ):
        resolve_managed_toolchain_config(_pinned_bundle(), config)

    class DerivedBundle(ManagedToolchainBundle):
        pass

    derived_bundle = DerivedBundle.model_validate(_pinned_bundle().model_dump(mode="json"))
    with pytest.raises(ManagedToolchainError, match="exact compiled type"):
        resolve_managed_toolchain_config(derived_bundle, config_factory())


def test_generic_profile_does_not_project_inapplicable_solidity_tools(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = _updated_config(
        config_factory(),
        profile="maximum-assurance",
        language_profile="generic-source-review",
    )

    required = set(required_managed_toolchain_roles(config))
    assert {
        ManagedToolchainRole.SOLC,
        ManagedToolchainRole.ANVIL,
        ManagedToolchainRole.SLITHER,
        ManagedToolchainRole.FORGE,
        ManagedToolchainRole.HARDHAT_IMAGE_HARDHAT,
        ManagedToolchainRole.MYTHRIL,
        ManagedToolchainRole.ECHIDNA,
        ManagedToolchainRole.MEDUSA,
        ManagedToolchainRole.HALMOS,
        ManagedToolchainRole.HALMOS_Z3,
        ManagedToolchainRole.KONTROL,
    }.isdisjoint(required)


def test_generic_profile_still_projects_explicit_clean_chain_anvil_identity(
    config_factory: Callable[..., AuditConfig],
) -> None:
    config = config_factory()
    configured = _updated_config(
        config,
        language_profile="generic-source-review",
        smart_contracts={"repository_suite": _clean_fork_suite(config)},
    )

    assert ManagedToolchainRole.ANVIL in required_managed_toolchain_roles(configured)


def test_contract_models_are_frozen(
    config_factory: Callable[..., AuditConfig],
) -> None:
    bundle = _pinned_bundle()
    projection = resolve_managed_toolchain_config(bundle, config_factory())
    with pytest.raises(ValidationError, match="frozen"):
        bundle.runtime_authority = True  # type: ignore[misc]
    with pytest.raises(ValidationError, match="frozen"):
        bundle.members[0].version = "9.9.9"  # type: ignore[misc]
    with pytest.raises(ValidationError, match="frozen"):
        projection.managed_run_ready = True  # type: ignore[misc]
    with pytest.raises(ValidationError, match="literal_error"):
        bundle.model_copy(update={"runtime_authority": True})
    with pytest.raises(ValidationError, match="hash is inconsistent"):
        bundle.model_copy(update={"bundle_sha256": "f" * 64})
    with pytest.raises(ValidationError, match="literal_error"):
        projection.model_copy(update={"bundle_trusted": True})
    with pytest.raises(ValidationError, match="literal_error"):
        projection.model_copy(update={"managed_run_ready": True})
    with pytest.raises(ValidationError, match="host isolation selection differs"):
        projection.model_copy(update={"resolved_isolation_backend": "bubblewrap"})
    with pytest.raises(ValidationError, match="zero SHA-256"):
        bundle.members[0].model_copy(update={"sha256": "0" * 64})


def test_packaged_declaration_pins_only_the_three_reviewed_package_resources() -> None:
    bundle = default_managed_toolchain_bundle()
    pinned = {
        member.role: member
        for member in bundle.members
        if member.disposition is ManagedToolchainDisposition.PINNED
    }
    assert set(pinned) == {
        ManagedToolchainRole.HARDHAT_REPORTER,
        ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA,
        ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA,
    }
    assert pinned[ManagedToolchainRole.HARDHAT_REPORTER].sha256 == (
        MANAGED_TOOLCHAIN_REPORTER_SHA256
    )
    assert MANAGED_TOOLCHAIN_REPORTER_SHA256 == HARDHAT_REPORTER_SHA256
    assert pinned[ManagedToolchainRole.HARDHAT_REPORTER].version == HARDHAT_REPORTER_VERSION
    assert pinned[ManagedToolchainRole.HARDHAT_REPORTER_INVENTORY_SCHEMA].sha256 == (
        MANAGED_TOOLCHAIN_REPORTER_INVENTORY_SCHEMA_SHA256
    )
    assert pinned[ManagedToolchainRole.HARDHAT_REPORTER_TEST_SCHEMA].sha256 == (
        MANAGED_TOOLCHAIN_REPORTER_TEST_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256(
            (ROOT / "src/mmaudit/scanners/hardhat_reporter.cjs").read_bytes()
        ).hexdigest()
        == MANAGED_TOOLCHAIN_REPORTER_SHA256
    )
    assert (
        hashlib.sha256(
            (ROOT / "schemas/hardhat_reporter_inventory.schema.json").read_bytes()
        ).hexdigest()
        == MANAGED_TOOLCHAIN_REPORTER_INVENTORY_SCHEMA_SHA256
    )
    assert (
        hashlib.sha256(
            (ROOT / "schemas/hardhat_reporter_test.schema.json").read_bytes()
        ).hexdigest()
        == MANAGED_TOOLCHAIN_REPORTER_TEST_SCHEMA_SHA256
    )


def test_packaged_partial_declaration_cannot_resolve_even_an_empty_run(
    config_factory: Callable[..., AuditConfig],
) -> None:
    with pytest.raises(ManagedToolchainError, match="required managed toolchain role git"):
        resolve_managed_toolchain_config(default_managed_toolchain_bundle(), config_factory())


def test_packaged_loader_is_fixed_canonical_and_independently_hash_bound() -> None:
    bundle = load_packaged_managed_toolchain_bundle()
    resource = ROOT / "src" / "mmaudit" / MANAGED_TOOLCHAIN_BUNDLE_RESOURCE
    assert bundle == default_managed_toolchain_bundle()
    assert hashlib.sha256(resource.read_bytes()).hexdigest() == (
        managed_toolchain_module._MANAGED_TOOLCHAIN_BUNDLE_RAW_SHA256
    )
    assert bundle.independently_trusted is False
    assert bundle.transitive_dependency_closure_verified is False
    assert bundle.image_side_attestation_verified is False
    assert bundle.provisioning_state_verified is False
    assert bundle.managed_run_ready is False
    assert bundle.limitations == MANAGED_TOOLCHAIN_DECLARATION_LIMITATIONS
    with pytest.raises(ValidationError, match="literal_error"):
        bundle.model_copy(update={"managed_run_ready": True})


def _copy_package_resource(tmp_path: Path) -> tuple[Path, Path, bytes]:
    package_root = tmp_path / "mmaudit"
    resource_parent = package_root / "resources"
    resource_parent.mkdir(parents=True)
    package_root.chmod(0o755)
    resource_parent.chmod(0o755)
    content = (ROOT / "src" / "mmaudit" / MANAGED_TOOLCHAIN_BUNDLE_RESOURCE).read_bytes()
    resource = resource_parent / "managed_toolchain_bundle.json"
    resource.write_bytes(content)
    resource.chmod(0o644)
    return package_root, resource, content


def _load_test_resource(
    package_root: Path, resource: Path, content: bytes
) -> ManagedToolchainBundle:
    return managed_toolchain_module._load_managed_toolchain_bundle_path(
        resource,
        package_root=package_root,
        expected_raw_sha256=hashlib.sha256(content).hexdigest(),
    )


def test_loader_rejects_symlink_hardlink_and_writable_parent(
    tmp_path: Path,
) -> None:
    package_root, resource, content = _copy_package_resource(tmp_path / "symlink")
    target = resource.with_name("target.json")
    resource.rename(target)
    resource.symlink_to(target.name)
    with pytest.raises(ManagedToolchainError, match="not a regular file"):
        _load_test_resource(package_root, resource, content)

    package_root, resource, content = _copy_package_resource(tmp_path / "hardlink")
    os.link(resource, resource.with_name("second-link.json"))
    with pytest.raises(ManagedToolchainError, match="multiple hard links"):
        _load_test_resource(package_root, resource, content)

    package_root, resource, content = _copy_package_resource(tmp_path / "writable")
    resource.parent.chmod(0o775)
    with pytest.raises(ManagedToolchainError, match="group- or world-writable"):
        _load_test_resource(package_root, resource, content)


def test_loader_rejects_resource_replacement_during_descriptor_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root, resource, content = _copy_package_resource(tmp_path)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor: int, count: int) -> bytes:
        nonlocal replaced
        chunk = original_read(descriptor, count)
        if chunk and not replaced:
            replacement = resource.with_name("replacement.json")
            replacement.write_bytes(content)
            replacement.chmod(0o644)
            replacement.replace(resource)
            replaced = True
        return chunk

    monkeypatch.setattr(managed_toolchain_module.os, "read", replace_after_read)
    with pytest.raises(ManagedToolchainError, match="changed during read"):
        _load_test_resource(package_root, resource, content)


def test_loader_rejects_duplicate_nonfinite_and_correctly_resealed_retarget(
    tmp_path: Path,
) -> None:
    with pytest.raises(ManagedToolchainError, match="duplicate key"):
        managed_toolchain_module._strict_json_object(b'{"a":1,"a":2}')
    with pytest.raises(ManagedToolchainError, match="non-finite"):
        managed_toolchain_module._strict_json_object(b'{"a":NaN}')

    package_root, resource, _content = _copy_package_resource(tmp_path)
    retargeted = _pinned_bundle()
    content = (
        json.dumps(
            retargeted.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    resource.write_bytes(content)
    resource.chmod(0o644)
    with pytest.raises(ManagedToolchainError, match="bytes are not canonical"):
        _load_test_resource(package_root, resource, content)


def test_packaged_load_does_not_touch_environment_process_or_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("packaged bundle load crossed a forbidden ambient boundary")

    monkeypatch.setattr(os, "getenv", forbidden)
    monkeypatch.setattr(shutil, "which", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)

    assert load_packaged_managed_toolchain_bundle().runtime_authority is False
