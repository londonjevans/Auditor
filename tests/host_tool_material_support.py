"""Inert synthetic blob stores for local tool-material provisioning regressions."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from mmaudit.config import AuditConfig
from mmaudit.orchestration.managed_toolchain import (
    ManagedToolchainBundle,
    ManagedToolchainMemberKind,
    required_managed_toolchain_roles,
    seal_managed_toolchain_bundle,
)
from tests.managed_toolchain_support import synthetic_pinned_members

_FIXTURES = Path(__file__).parent / "fixtures"


def setup_host_material_inputs(
    tmp_path: Path, config: AuditConfig
) -> tuple[Path, Path, Path, ManagedToolchainBundle]:
    repository = tmp_path / "repository"
    repository.mkdir()
    shutil.copyfile(
        _FIXTURES / "solidity" / "development_review" / "ControlB.sol",
        repository / "ControlB.sol",
    )
    store = tmp_path / "host-blobs"
    output = tmp_path / "host-output"
    for directory in (store, output):
        directory.mkdir(mode=0o700)
        directory.chmod(0o700)
    required = set(required_managed_toolchain_roles(config))
    inert = (_FIXTURES / "scanners" / "identity-inert.txt").read_bytes()
    members = []
    for member in synthetic_pinned_members():
        if member.kind is ManagedToolchainMemberKind.HOST_EXECUTABLE:
            content = inert + f"Synthetic role: {member.role.value}\n".encode()
            digest = hashlib.sha256(content).hexdigest()
            member = member.model_copy(update={"sha256": digest})
            if member.role in required:
                path = store / f"{digest}.blob"
                path.write_bytes(content)
                path.chmod(0o600)
        members.append(member)
    return (
        repository,
        store,
        output,
        seal_managed_toolchain_bundle(members=tuple(members), target_platform="linux-amd64"),
    )
