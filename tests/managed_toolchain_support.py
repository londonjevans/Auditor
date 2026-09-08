"""Synthetic tool identities only; these declarations never represent installed tools."""

from __future__ import annotations

import hashlib

from mmaudit.orchestration.managed_toolchain import (
    MANAGED_TOOLCHAIN_ROLE_SPECS,
    ManagedToolchainBundle,
    ManagedToolchainDisposition,
    ManagedToolchainMember,
    ManagedToolchainMemberKind,
    ManagedToolchainRole,
    seal_managed_toolchain_bundle,
)


def synthetic_pinned_members() -> tuple[ManagedToolchainMember, ...]:
    def digest(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    members: list[ManagedToolchainMember] = []
    parent_image_sha256 = digest(ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE.value)
    parent_platform_manifest_sha256 = digest(
        f"platform:{ManagedToolchainRole.ROOTLESS_TOOLCHAIN_IMAGE.value}"
    )
    for spec in MANAGED_TOOLCHAIN_ROLE_SPECS:
        member_digest = digest(spec.role.value)
        locator = spec.allowed_locators[0]
        if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE:
            locator = f"registry.example/mmaudit-toolchain@sha256:{member_digest}"
        members.append(
            ManagedToolchainMember(
                role=spec.role,
                kind=spec.kind,
                disposition=ManagedToolchainDisposition.PINNED,
                locator=locator,
                version="1.2.3",
                sha256=member_digest,
                platform=(
                    "linux-amd64" if spec.kind is ManagedToolchainMemberKind.OCI_IMAGE else None
                ),
                platform_manifest_sha256=(
                    digest(f"platform:{spec.role.value}")
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


def synthetic_pinned_bundle() -> ManagedToolchainBundle:
    return seal_managed_toolchain_bundle(
        members=synthetic_pinned_members(), target_platform="linux-amd64"
    )
