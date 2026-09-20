"""Generated contracts cannot turn derived sources into unbound legacy manifests."""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_corpus_coverage import compute_development_corpus_coverage
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.integration.test_development_partition_custody import bundle
from tests.unit.test_development_corpus_coverage import candidate


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    reference, recipe, loaded = bundle(tmp_path_factory.mktemp("partition-schema"))
    _, observed = candidate(loaded)
    covered = compute_development_corpus_coverage(
        reference=reference.material, records=(observed,), partitions=(recipe,)
    )
    return {"manifest": recipe.manifest, "partition": recipe, "coverage": covered}


@pytest.mark.parametrize("kind", ["manifest", "partition", "coverage"])
def test_generated_contract_accepts_current_origin_bound_artifacts(artifacts, kind):
    artifact = artifacts[kind]
    schema = json.loads(rendered_schema(f"development_corpus_{kind}.schema.json", type(artifact)))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(artifact.model_dump(mode="json"))


@pytest.mark.parametrize(
    "change",
    [
        "missing_origin",
        "null_origin",
        "missing_roles",
        "missing_tree",
        "origin_replay",
        "witness",
        "legacy_1.0",
        "legacy_1.9",
        "legacy_1.10",
    ],
)
def test_every_manifest_embedding_requires_the_versioned_origin_and_prior_proof(artifacts, change):
    data = copy.deepcopy(artifacts["manifest"].model_dump(mode="json"))
    if change.startswith("legacy_"):
        data["schema_version"] = change.removeprefix("legacy_")
    elif change == "null_origin":
        data["source_origin"] = None
    elif change == "origin_replay":
        data["source_origin"]["reference_replay_required"] = False
    elif change == "witness":
        data["dependency_evidence"]["schema_version"] = "1.6"
    else:
        data.pop(
            {
                "missing_origin": "source_origin",
                "missing_roles": "source_partition",
                "missing_tree": "source_tree_evidence",
            }[change]
        )
    count = 0
    for name, model in MODELS.items():
        if not name.startswith("development_corpus_"):
            continue
        schema = json.loads(rendered_schema(name, model))
        if name == "development_corpus_manifest.schema.json":
            validator = Draft202012Validator(schema)
        elif "DevelopmentCorpusManifest" in schema.get("$defs", {}):
            validator = Draft202012Validator(
                {"$defs": schema["$defs"], "$ref": "#/$defs/DevelopmentCorpusManifest"}
            )
        else:
            continue
        assert list(validator.iter_errors(data)), name
        count += 1
    assert count == 24


@pytest.mark.parametrize("change", ["missing", "null", "empty", "legacy_version"])
def test_coverage_schema_does_not_make_selected_partition_evidence_optional(artifacts, change):
    data = artifacts["coverage"].model_dump(mode="json")
    if change == "missing":
        data.pop("partitions")
    elif change == "null":
        data["partitions"] = None
    elif change == "empty":
        data["partitions"] = []
    else:
        data["schema_version"] = "1.0"
    schema = json.loads(
        rendered_schema("development_corpus_coverage.schema.json", type(artifacts["coverage"]))
    )
    assert list(Draft202012Validator(schema).iter_errors(data))
