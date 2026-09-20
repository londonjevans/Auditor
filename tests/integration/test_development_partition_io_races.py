"""Original/source/recipe drift during bundle I/O never produces accepted coverage."""

from __future__ import annotations

import pytest

from mmaudit.models.development_corpus_partition import derive_development_corpus_partition
from mmaudit.orchestration import development_corpus_coverage as coverage_io
from mmaudit.repository import development_corpus_partition as bundle_io
from tests.integration.test_development_partition_custody import bundle
from tests.integration.test_development_partition_custody import (
    no_external_execution as no_external_execution,
)
from tests.unit.test_development_context_sources import partitioned_tree
from tests.unit.test_development_corpus_coverage import candidate


@pytest.mark.parametrize("changed", ["original", "selected", "output_directory"])
def test_materializer_rechecks_original_and_created_objects_after_every_write(
    tmp_path, monkeypatch, changed
):
    reference = partitioned_tree(tmp_path / "original")
    recipe = derive_development_corpus_partition(
        reference=reference.material, primary_filenames=("src/IReserve.sol",)
    )
    output = tmp_path / "bundle"
    original_write = bundle_io.write_file_evidence

    def mutate_after_write(**kwargs):
        binding = original_write(**kwargs)
        if changed == "output_directory":
            output.rename(tmp_path / "moved-bundle")
            output.mkdir(mode=0o700)
        else:
            path = (
                reference.corpus_root / "src/Controller.sol"
                if changed == "original"
                else kwargs["evidence_root"] / kwargs["relative_path"]
            )
            path.write_bytes(path.read_bytes() + b"\n")
        return binding

    monkeypatch.setattr(bundle_io, "write_file_evidence", mutate_after_write)
    with pytest.raises(ValueError):
        bundle_io.materialize_development_corpus_partition(
            reference=reference, partition=recipe, output_dir=output
        )
    assert not (output / "manifest.json").exists()
    assert not (output / "partition.json").exists()


@pytest.mark.parametrize("changed", ["original", "recipe_bytes", "recipe_inode"])
def test_coverage_rechecks_original_and_recipe_after_projection_before_output(
    tmp_path, monkeypatch, changed
):
    reference, _, loaded = bundle(tmp_path)
    _, observed = candidate(loaded)
    record = tmp_path / "observed.json"
    record.write_text(observed.model_dump_json())
    original_record = record.read_bytes()
    recipe_path = tmp_path / "bundle/partition.json"
    original_compute = coverage_io.compute_development_corpus_coverage

    def mutate_after_projection(**kwargs):
        result = original_compute(**kwargs)
        if changed == "original":
            path = reference.corpus_root / "src/Controller.sol"
            path.write_bytes(path.read_bytes() + b"\n")
        elif changed == "recipe_bytes":
            recipe_path.write_bytes(recipe_path.read_bytes() + b"\n")
        else:
            content = recipe_path.read_bytes()
            recipe_path.rename(recipe_path.with_name("original-partition.json"))
            recipe_path.write_bytes(content)
        return result

    monkeypatch.setattr(coverage_io, "compute_development_corpus_coverage", mutate_after_projection)
    with pytest.raises(ValueError):
        coverage_io.measure_development_corpus_coverage_files(
            manifest_file=reference.manifest_file,
            corpus_root=reference.corpus_root,
            record_files=(record,),
            partition_files=(recipe_path,),
            output_dir=tmp_path / "coverage",
        )
    assert not (tmp_path / "coverage").exists()
    assert record.read_bytes() == original_record
