"""Actual capacity inputs reach the real tree planner; no reduced caps or fabricated custody."""

from __future__ import annotations

import pytest

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILES,
)
from mmaudit.repository import development_tree_plan as tree_repository
from mmaudit.repository.development_tree_plan import (
    revalidate_loaded_development_tree_plan,
    write_development_tree_plan,
)
from mmaudit.solidity.dependency_closure import LEGACY_DEPENDENCY_GRAPH_BYTES
from tests.development_tree_capacity_support import capacity_inputs, capacity_source
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import reopen

pytestmark = pytest.mark.usefixtures("no_external_execution")


def assert_complete_catalog(loaded, files):
    plan = loaded.plan
    assert plan.status == "READY", (plan.shortfalls, [p.shortfalls for p in plan.primaries])
    assert plan.reference.source_files == files
    assert tuple(p.primary_filename for p in plan.primaries) == tuple(p for p, _ in files)
    assert plan.maximum_requests == 3 * len(files)
    assert plan.headroom_complete and all(not p.shortfalls for p in plan.primaries)
    assert all(p.partition.manifest.dependency_closure == "CALL_CLOSED" for p in plan.primaries)
    assert not plan.audit_complete and not plan.qualification_eligible and not plan.release_eligible


@pytest.mark.parametrize("size", [189_779, MAX_DEVELOPMENT_CORPUS_FILE_BYTES])
def test_actual_large_source_has_a_complete_plan_without_reducing_the_source(tmp_path, size):
    files = (("Source.sol", capacity_source(0, size)),)
    inputs = capacity_inputs(tmp_path, files)
    loaded = write_development_tree_plan(**inputs)
    assert_complete_catalog(loaded, files)
    assert loaded.plan.reference.manifest.total_source_bytes == size
    assert reopen(inputs).plan == loaded.plan


def test_actual_maximum_file_population_retains_every_primary(tmp_path):
    assert MAX_DEVELOPMENT_CORPUS_FILES == 256
    files = tuple((f"Source{i:03d}.sol", capacity_source(i)) for i in range(256))
    loaded = write_development_tree_plan(**capacity_inputs(tmp_path, files))
    assert_complete_catalog(loaded, files)
    assert len({p.case_run_id for p in loaded.plan.primaries}) == 256


def test_actual_maximum_aggregate_tree_retains_every_source_byte(tmp_path):
    assert MAX_DEVELOPMENT_CORPUS_BYTES == 8_388_608
    files = tuple((f"Source{i:03d}.sol", capacity_source(i, 262_144)) for i in range(32))
    loaded = write_development_tree_plan(**capacity_inputs(tmp_path, files))
    assert_complete_catalog(loaded, files)
    assert loaded.plan.reference.manifest.total_source_bytes == 8_388_608


@pytest.mark.parametrize("overflow", ["file", "tree", "population"])
def test_actual_ingestion_overflow_refuses_without_a_plan_or_provider_work(tmp_path, overflow):
    if overflow == "file":
        files = (("Source.sol", capacity_source(0, 262_145)),)
    elif overflow == "population":
        files = tuple((f"Source{i:03d}.sol", capacity_source(i)) for i in range(257))
    else:
        files = tuple((f"Source{i:03d}.sol", capacity_source(i, 262_144)) for i in range(33))
    from tests.development_tree_capacity_support import capacity_policy

    inputs = capacity_inputs(tmp_path, files, policy=capacity_policy(256))
    with pytest.raises(ValueError, match="tree exceeds source bounds"):
        write_development_tree_plan(**inputs)
    assert not inputs["output_dir"].exists()


def test_actual_import_cycle_retains_both_closures_and_both_original_primaries(tmp_path):
    files = (
        ("A.sol", capacity_source(0, imports=("./B.sol",))),
        ("B.sol", capacity_source(1, imports=("./A.sol",))),
    )
    loaded = write_development_tree_plan(**capacity_inputs(tmp_path, files))
    assert_complete_catalog(loaded, files)
    for primary in loaded.plan.primaries:
        manifest = primary.partition.manifest
        assert tuple(s.filename for s in manifest.sources) == ("A.sol", "B.sol")
        assert tuple(s.filename for s in manifest.primary_sources) == (primary.primary_filename,)


@pytest.mark.parametrize("drift", ["byte", "replacement", "symlink"])
def test_empty_remappings_keep_exact_content_and_file_identity_custody(tmp_path, drift):
    files = (("Source.sol", capacity_source(0)),)
    inputs = capacity_inputs(tmp_path, files)
    loaded = write_development_tree_plan(**inputs)
    assert loaded.remappings_file.binding.size == 0
    assert reopen(inputs).plan == loaded.plan
    mapping = inputs["remappings_file"]
    if drift == "byte":
        mapping.write_bytes(b"\n")
    else:
        mapping.rename(tmp_path / "retained-empty-remappings")
        if drift == "replacement":
            mapping.write_bytes(b"")
        else:
            mapping.symlink_to(tmp_path / "retained-empty-remappings")
    with pytest.raises(ValueError):
        revalidate_loaded_development_tree_plan(loaded)


def test_reopen_preserves_a_plan_made_with_the_original_smaller_graph_budget(tmp_path, monkeypatch):
    files = (("Source.sol", capacity_source(0)),)
    inputs = capacity_inputs(tmp_path, files)
    with monkeypatch.context() as scoped:
        scoped.setattr(tree_repository, "MAX_DEPENDENCY_GRAPH_BYTES", LEGACY_DEPENDENCY_GRAPH_BYTES)
        loaded = write_development_tree_plan(**inputs)
    assert loaded.plan.reference.manifest.dependency_evidence.graph_artifact_byte_limit == 393_216
    assert tree_repository.MAX_DEPENDENCY_GRAPH_BYTES == 2_097_152
    assert reopen(inputs).plan == loaded.plan
    assert reopen(inputs).plan.primaries[0].candidate == loaded.plan.primaries[0].candidate
