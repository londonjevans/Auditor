"""Tree enumeration receipts remain bounded, source-bound and explicitly replay-required."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator, ValidationError

from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusTreeDirectory,
    DevelopmentCorpusTreeEvidence,
    freeze_development_corpus,
    render_development_corpus_sources,
    validate_development_corpus_sources,
)
from mmaudit.orchestration.manifest import canonical_sha256
from tests.unit.test_development_dependency_targets import target_manifest, target_sources


def seal_tree(values):
    values = dict(values)
    values["tree_sha256"] = canonical_sha256(
        {k: v for k, v in values.items() if k != "tree_sha256"}
    )
    return DevelopmentCorpusTreeEvidence.model_validate_json(json.dumps(values), strict=True)


def tree_receipt(manifest=None):
    manifest = target_manifest() if manifest is None else manifest
    children = {".": {}}
    for source in manifest.sources:
        parts = source.filename.split("/")
        for index, part in enumerate(parts):
            parent = "/".join(parts[:index]) or "."
            kind = "REGULAR_FILE" if index == len(parts) - 1 else "DIRECTORY"
            children.setdefault(parent, {})[part] = kind
    return seal_tree(
        {
            "policy": "ALL_RECURSIVE_SOLIDITY_NO_EXCLUSIONS_V1",
            "source_inventory_sha256": canonical_sha256(
                [s.model_dump(mode="json") for s in manifest.sources]
            ),
            "solidity_file_count": len(manifest.sources),
            "non_source_file_count": 0,
            "directories": [
                {
                    "path": path,
                    "entry_count": len(entries),
                    "entries_sha256": canonical_sha256(sorted(entries.items())),
                }
                for path, entries in sorted(children.items())
            ],
            "root_replay_required": True,
        }
    )


def tree_manifest():
    return freeze_development_corpus(
        corpus_id="synthetic-tree",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=target_sources(),
        dependency_remapping_text="@local/=lib/\n",
        dependency_target_context=True,
        source_tree_evidence=tree_receipt(),
    )


def test_tree_manifest_binds_exact_source_snapshot_and_requires_actual_root_replay():
    manifest = tree_manifest()
    assert manifest.schema_version == "1.3"
    assert manifest.inventory_scope == "LOCAL_TREE_SNAPSHOT_REQUIRES_ROOT_REPLAY"
    assert manifest.source_tree_evidence.root_replay_required is True
    assert manifest.dependency_evidence.schema_version == "1.1"
    assert manifest.dependency_evidence.target_context.complete_static_resolution is False
    validate_development_corpus_sources(manifest, target_sources())
    assert not manifest.audit_complete and not manifest.qualification_eligible
    prompt = render_development_corpus_sources(manifest, target_sources(), "src/Controller.sol")
    assert manifest.source_tree_evidence.model_dump_json() in prompt
    assert "requires actual local-root replay" in prompt
    assert "Non-source file contents are not included" in prompt


@pytest.mark.parametrize("value", [False, 0, 1, "true", None])
def test_tree_receipt_cannot_waive_root_replay(value):
    data = tree_receipt().model_dump(mode="json")
    data["root_replay_required"] = value
    with pytest.raises(ValueError, match="replay"):
        seal_tree(data)


@pytest.mark.parametrize(
    "change", ["count", "missing_parent", "duplicate", "order", "bytes", "digest"]
)
def test_tree_receipt_rejects_bad_namespace_shape_or_source_binding(change):
    manifest = tree_manifest()
    data = manifest.source_tree_evidence.model_dump(mode="json")
    if change == "count":
        data["non_source_file_count"] += 1
    elif change == "missing_parent":
        data["directories"][-1]["path"] = "missing/src"
    elif change == "duplicate":
        data["directories"].append(data["directories"][-1])
    elif change == "order":
        data["directories"].reverse()
    elif change == "bytes":
        data["source_inventory_sha256"] = "0" * 64
        forged = seal_tree(data)
        with pytest.raises(ValueError, match="tree evidence"):
            freeze_development_corpus(
                corpus_id="synthetic-tree",
                source_scope="OPERATOR_SUPPLIED_PROTOCOL",
                source_files=target_sources(),
                dependency_remapping_text="@local/=lib/\n",
                dependency_target_context=True,
                source_tree_evidence=forged,
            )
        return
    else:
        data["tree_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="digest"):
            DevelopmentCorpusTreeEvidence.model_validate_json(json.dumps(data), strict=True)
        return
    with pytest.raises(ValueError):
        seal_tree(data)


@pytest.mark.parametrize(
    "path", ["../outside", "/absolute", ".git", "src/.env", "src\\other", "a/" * 33 + "b"]
)
def test_tree_directory_never_selects_traversal_control_plane_or_unbounded_depth(path):
    with pytest.raises(ValueError):
        DevelopmentCorpusTreeDirectory(path=path, entry_count=0, entries_sha256="0" * 64)


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2"])
def test_tree_evidence_cannot_be_smuggled_into_old_manifest_versions(version):
    data = tree_manifest().model_dump(mode="json")
    data["schema_version"] = version
    data["manifest_sha256"] = canonical_sha256(
        {k: v for k, v in data.items() if k != "manifest_sha256"}
    )
    with pytest.raises(ValueError, match="legacy"):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(data), strict=True)


def test_tree_evidence_requires_target_context_and_prior_versions_omit_it():
    with pytest.raises(ValueError, match="computed target context"):
        freeze_development_corpus(
            corpus_id="synthetic-tree",
            source_scope="OPERATOR_SUPPLIED_PROTOCOL",
            source_files=target_sources(),
            source_tree_evidence=tree_receipt(),
        )
    prior = target_manifest()
    assert prior.schema_version == "1.2" and "source_tree_evidence" not in prior.model_dump_json()
    assert "Recorded supplied-root" not in render_development_corpus_sources(
        prior, target_sources(), "src/Controller.sol"
    )


@pytest.mark.parametrize("change", ["version", "missing", "null", "scope", "replay"])
def test_generated_tree_schema_requires_versioned_scope_and_evidence(change):
    from scripts.generate_release_schemas import rendered_schema

    validator = Draft202012Validator(
        json.loads(
            rendered_schema("development_corpus_manifest.schema.json", DevelopmentCorpusManifest)
        )
    )
    data = tree_manifest().model_dump(mode="json")
    validator.validate(data)
    if change == "version":
        data["schema_version"] = "1.2"
    elif change == "missing":
        del data["source_tree_evidence"]
    elif change == "null":
        data["source_tree_evidence"] = None
    elif change == "scope":
        data["inventory_scope"] = "EXPLICIT_MANIFEST_ONLY"
    else:
        data["source_tree_evidence"]["root_replay_required"] = 1
    with pytest.raises(ValidationError):
        validator.validate(data)
