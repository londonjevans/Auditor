"""Synthetic state-machine archive inputs; no Solidity or isolation evidence."""

from __future__ import annotations

from mmaudit.orchestration.managed_fork_archives import (
    ManagedForkArchiveSource,
    prepare_managed_fork_archives,
)
from mmaudit.orchestration.managed_host_tools import (
    ManagedHostToolSource,
    materialize_managed_host_tools,
)
from tests.host_tool_material_support import setup_host_material_inputs
from tests.managed_invariant_support import local_invariant_inputs
from tests.managed_reproduction_fork_support import reproduction_archive_source


def invariant_archive_source(tmp_path):
    source, archive = reproduction_archive_source(tmp_path)
    return ManagedForkArchiveSource(
        archive_root=source.archive_root,
        invariant_archive_sha256=source.reproduction_archive_sha256,
    ), archive


def prepared_invariant_archives(tmp_path, config_factory):
    config = config_factory(
        language_profile="solidity-evm",
        smart_contracts={"compile": False, "framework": "foundry", "allow_fork_probing": True},
        reproduction={
            "enabled": False,
            "isolation_backend": "bubblewrap",
            "targets": {"FixtureMachine": "0x1111111111111111111111111111111111111111"},
            "pinned_block_number": 7,
            "expected_chain_id": 31337,
            "timeout_seconds": 1,
        },
        invariants={"enabled": True, "execute_generated": True},
        formal={"enabled": False},
    )
    repository, store, output, bundle = setup_host_material_inputs(tmp_path, config)
    project, local_specification = local_invariant_inputs(repository)
    material = materialize_managed_host_tools(
        bundle=bundle,
        config=config,
        repository=repository,
        output_root=output,
        source=ManagedHostToolSource(blob_root=store),
    )
    source, archive = invariant_archive_source(tmp_path)
    specification = local_specification.model_copy(update={"local_deployments": []})
    return (
        repository,
        material,
        tmp_path / "invariant-private",
        source,
        archive,
        project,
        specification,
        local_specification,
    )


def prepare_invariant_archives(prepared, **kwargs):
    return prepare_managed_fork_archives(
        kwargs.pop("config", prepared[1].config),
        source=kwargs.pop("source", prepared[3]),
        repository=prepared[0],
        output=prepared[2],
        **kwargs,
    )
