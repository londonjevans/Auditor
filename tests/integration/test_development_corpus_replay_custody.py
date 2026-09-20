"""Pure replay reuse must still refuse original-root or recipe drift at later live boundaries."""

from __future__ import annotations

import pytest

from mmaudit.repository import development_corpus as module
from tests.integration.test_development_partition_custody import bundle
from tests.integration.test_development_partition_custody import (
    no_external_execution as no_external_execution,
)

pytestmark = pytest.mark.usefixtures("no_external_execution")


@pytest.mark.parametrize("hit", [1, 2, 3, 4])
@pytest.mark.parametrize("changed", ["manifest", "source_bytes", "source_inode", "manifest_memory"])
def test_pure_manifest_reuse_preserves_every_original_live_boundary(
    tmp_path, monkeypatch, hit, changed
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    original = module.read_json_evidence
    calls = 0
    mutated = False

    def read(**kwargs):
        nonlocal calls, mutated
        if kwargs["evidence_root"] == reference.manifest_file.parent:
            calls += 1
            if calls == hit:
                mutated = True
                if changed == "manifest_memory":
                    object.__setattr__(
                        reference.material,
                        "manifest",
                        reference.material.manifest.model_copy(
                            update={"corpus_id": "changed-synthetic-corpus"}
                        ),
                    )
                else:
                    path = (
                        reference.manifest_file
                        if changed == "manifest"
                        else reference.corpus_root / "src/Controller.sol"
                    )
                    content = path.read_bytes()
                    if changed == "source_inode":
                        path.rename(tmp_path / "retained-original-source.sol")
                        path.write_bytes(content)
                    else:
                        path.write_bytes(content + b"\n")
        return original(**kwargs)

    monkeypatch.setattr(module, "read_json_evidence", read)
    with pytest.raises(ValueError):
        module.revalidate_loaded_development_corpus(loaded)
    assert mutated and calls == hit


@pytest.mark.parametrize("hit", [2, 3, 5, 6])
@pytest.mark.parametrize(
    "changed", ["original_bytes", "original_inode", "manifest", "recipe", "reference_material"]
)
def test_reused_material_never_caches_a_live_original_or_recipe_verdict(
    tmp_path, monkeypatch, hit, changed
):
    reference, _, loaded = bundle(tmp_path, ("src/IReserve.sol",))
    original = module._replay_material
    calls = 0
    mutated = False

    def mutate_after_pure_replay(material, replayed):
        nonlocal calls, mutated
        result = original(material, replayed)
        if material.manifest.source_origin is None:
            calls += 1
            if calls == hit:
                mutated = True
                if changed == "reference_material":
                    first, *rest = reference.material.sources
                    altered = reference.material.model_copy(
                        update={
                            "sources": (
                                first.model_copy(update={"content": first.content + "\n"}),
                                *rest,
                            )
                        }
                    )
                    object.__setattr__(reference, "material", altered)
                else:
                    path = (
                        reference.manifest_file
                        if changed == "manifest"
                        else tmp_path / "bundle/partition.json"
                        if changed == "recipe"
                        else reference.corpus_root / "src/Controller.sol"
                    )
                    content = path.read_bytes()
                    if changed == "original_inode":
                        path.rename(tmp_path / "retained-original-source.sol")
                        path.write_bytes(content)
                    else:
                        path.write_bytes(content + b"\n")
        return result

    monkeypatch.setattr(module, "_replay_material", mutate_after_pure_replay)
    with pytest.raises(ValueError):
        module.revalidate_loaded_development_corpus(loaded)
    assert mutated
