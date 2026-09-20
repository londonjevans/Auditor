"""Generated contracts require new source roles without promoting any legacy manifest."""

from __future__ import annotations

import json

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_corpus import DevelopmentCorpusManifest
from mmaudit.models.development_corpus_coverage import (
    DevelopmentCorpusCoverage,
    compute_development_corpus_coverage,
)
from scripts.generate_release_schemas import rendered_schema
from tests.unit.test_development_context_sources import partitioned_tree


@pytest.mark.parametrize("kind", ["manifest", "material", "coverage"])
def test_versioned_source_partition_validates_in_generated_enclosing_artifacts(tmp_path, kind):
    loaded = partitioned_tree(tmp_path)
    artifact = (
        loaded.material.manifest
        if kind == "manifest"
        else loaded.material
        if kind == "material"
        else compute_development_corpus_coverage(reference=loaded.material, records=())
    )
    schema = json.loads(rendered_schema(f"development_corpus_{kind}.schema.json", type(artifact)))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "null",
        "empty",
        "duplicate_primary",
        "duplicate_context",
        "path",
        "tree",
        "witness",
        "import_only",
        "legacy_1_0",
        "legacy_1_1",
        "legacy_1_2",
        "legacy_1_3",
        "legacy_1_4",
        "legacy_1_5",
        "legacy_1_6",
        "legacy_1_7",
        "legacy_1_8",
        "legacy_1_9",
    ],
)
def test_schema_refuses_unversioned_missing_or_invalid_source_partition_evidence(tmp_path, kind):
    data = partitioned_tree(tmp_path).material.manifest.model_dump(mode="json")
    if kind.startswith("legacy_"):
        data["schema_version"] = kind.removeprefix("legacy_").replace("_", ".")
    elif kind == "missing":
        data.pop("source_partition")
    elif kind == "null":
        data["source_partition"] = None
    elif kind == "empty":
        data["source_partition"]["primary_filenames"] = []
    elif kind.startswith("duplicate_"):
        field = "primary_filenames" if kind == "duplicate_primary" else "context_filenames"
        data["source_partition"][field] *= 2
    elif kind == "path":
        data["source_partition"]["primary_filenames"] = ["../outside.sol"]
    elif kind == "tree":
        data.pop("source_tree_evidence")
    elif kind == "witness":
        data["dependency_evidence"]["schema_version"] = "1.6"
    else:
        data["dependency_closure"] = "IMPORT_CLOSED"
    schema = json.loads(
        rendered_schema("development_corpus_manifest.schema.json", DevelopmentCorpusManifest)
    )
    assert list(Draft202012Validator(schema).iter_errors(data)), kind


def test_enclosing_schema_rejects_context_authority_and_root_replay_waiver(tmp_path):
    coverage = compute_development_corpus_coverage(
        reference=partitioned_tree(tmp_path).material, records=()
    )
    schema = json.loads(
        rendered_schema("development_corpus_coverage.schema.json", DevelopmentCorpusCoverage)
    )
    for field in (
        "audit_complete",
        "findings_validated",
        "qualification_eligible",
        "release_eligible",
        "root_replay_required",
    ):
        data = coverage.model_dump(mode="json")
        data[field] = not data[field]
        assert list(Draft202012Validator(schema).iter_errors(data)), field
