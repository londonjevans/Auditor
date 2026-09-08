"""Prepared inert tools and synthetic frozen reads for the ControlB negative regression."""

from __future__ import annotations

import hashlib
import shutil
from pathlib import Path

from mmaudit.orchestration.managed_fork_archives import (
    ManagedForkArchives,
    ManagedForkArchiveSource,
    prepare_managed_fork_archives,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_reproduction_support import (
    SYNTHETIC_RPC,
    SYNTHETIC_TARGET,
    managed_reproduction_inputs,
)


def reproduction_archive_source(tmp_path):
    archive_root = tmp_path / "fork-archives"
    archive_root.mkdir(mode=0o700, exist_ok=True)
    fixture = Path(__file__).parent / "fixtures/offline_fork_rpc/reads.json"
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    archive = archive_root / (digest + ".json")
    if not archive.exists():
        shutil.copyfile(fixture, archive)
    return ManagedForkArchiveSource(
        archive_root=archive_root.resolve(strict=True), reproduction_archive_sha256=digest
    ), archive


def prepare_tool_control_archives(material, repository, private):
    config = material.config
    if (
        not config.reproduction.enabled
        or not config.smart_contracts.enabled
        or not config.smart_contracts.allow_fork_probing
        or config.reproduction.expected_chain_id is None
        or config.reproduction.pinned_block_number is None
    ):
        return None
    source, _ = reproduction_archive_source(repository.parent)
    return prepare_managed_fork_archives(
        config, source=source, repository=repository, output=private
    )


def install_no_network_reproduction_lease_control(monkeypatch):
    """Supply only endpoint/lifecycle shape to old tool controls, never real transport credit."""

    leases = []

    class LeaseControl:
        endpoint = SYNTHETIC_RPC
        stopped_cleanly = False

        def stop(self, deadline=None):
            assert deadline is not None
            self.stopped_cleanly = True

    def start(self, *, repository, output, absolute_deadline):
        self.verify(self.config)
        self.verify_roots(repository, output)
        self.verify_reproduction_execution_budget(absolute_deadline)
        lease = LeaseControl()
        leases.append(lease)
        return lease

    monkeypatch.setattr(ManagedForkArchives, "start_reproduction_attempt", start)
    return leases


def prepared_reproduction_archives(tmp_path, config_factory, candidate_factory):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False, "allow_fork_probing": True},
        reproduction={
            "enabled": True,
            "isolation_backend": "bubblewrap",
            "targets": {"ControlB": SYNTHETIC_TARGET},
            "pinned_block_number": 7,
            "expected_chain_id": 31337,
            "timeout_seconds": 1,
        },
        invariants={"enabled": False},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    source, archive = reproduction_archive_source(tmp_path)
    private = tmp_path / "reproduction-private"
    project, specification = managed_reproduction_inputs()
    candidate = candidate_factory(
        candidate_id=specification.candidate_id,
        path="ControlB.sol",
        title="Synthetic administrator invariant",
    )
    return repository, material, private, source, archive, project, specification, candidate


def prepare_reproduction_archives(prepared, **kwargs):
    return prepare_managed_fork_archives(
        kwargs.pop("config", prepared[1].config),
        source=kwargs.pop("source", prepared[3]),
        repository=prepared[0],
        output=prepared[2],
        **kwargs,
    )
