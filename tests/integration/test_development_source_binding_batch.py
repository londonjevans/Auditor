"""Original-tree source custody stays live at every derived-corpus boundary."""

from __future__ import annotations

import pytest

from mmaudit import release_io
from mmaudit.repository import development_corpus as module
from tests.integration.test_development_partition_custody import bundle
from tests.integration.test_development_partition_custody import (
    no_external_execution as no_external_execution,
)

pytestmark = pytest.mark.usefixtures("no_external_execution")


def test_derived_custody_keeps_all_four_original_source_batches_and_double_reads(
    tmp_path, monkeypatch
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    original_batch = module.revalidate_evidence_file_bindings
    original_read = release_io._read_file_at_root
    batches, reads = [], []

    def batch(**kwargs):
        if kwargs["evidence_root"] == reference.corpus_root:
            batches.append(tuple(b.path for b in kwargs["bindings"]))
        return original_batch(**kwargs)

    def read(**kwargs):
        if kwargs["root"].path == reference.corpus_root:
            reads.append(kwargs["relative_path"])
        return original_read(**kwargs)

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", batch)
    monkeypatch.setattr(release_io, "_read_file_at_root", read)
    expected = tuple(b.path for b in reference.source_bindings)
    for _ in range(2):
        batches.clear()
        reads.clear()
        module.revalidate_loaded_development_corpus(loaded)
        assert batches == [expected] * 4
        assert reads == [path for path in expected for _ in range(2)] * 4


@pytest.mark.parametrize("hit", [1, 2, 3, 4])
@pytest.mark.parametrize("kind", ["source_bytes", "source_inode", "added_entry", "root_mode"])
def test_original_namespace_guard_still_runs_after_each_source_batch(
    tmp_path, monkeypatch, hit, kind
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    original = module.revalidate_evidence_file_bindings
    batches = 0

    def batch(**kwargs):
        nonlocal batches
        result = original(**kwargs)
        if kwargs["evidence_root"] == reference.corpus_root:
            batches += 1
            if batches == hit:
                path = reference.corpus_root / "src/Controller.sol"
                if kind == "source_bytes":
                    path.write_bytes(path.read_bytes() + b"\n")
                elif kind == "source_inode":
                    content = path.read_bytes()
                    path.rename(tmp_path / "retained-original-source.sol")
                    path.write_bytes(content)
                elif kind == "added_entry":
                    (reference.corpus_root / "added.txt").write_text("synthetic drift")
                else:
                    reference.corpus_root.chmod(0o700)
        return result

    monkeypatch.setattr(module, "revalidate_evidence_file_bindings", batch)
    with pytest.raises(ValueError):
        module.revalidate_loaded_development_corpus(loaded)
    assert batches == hit
