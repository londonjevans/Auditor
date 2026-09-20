"""Versioned generated contracts cannot promote legacy artifacts or omit closure evidence."""

from __future__ import annotations

import copy
import json

import pytest
from jsonschema import Draft202012Validator, ValidationError

from mmaudit.models.development_corpus import freeze_development_corpus
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.integration.test_development_call_closure_custody import frozen_load
from tests.unit.test_development_dependency_closure import fixture_sources
from tests.unit.test_development_static_call_closure import LEGACY, computed

_CORPUS_SCHEMA_NAMES = {
    f"development_corpus_{name}.schema.json"
    for name in (
        "benchmark_binding",
        "benchmark_score",
        "control_measurement",
        "coverage",
        "ensemble_observation",
        "ensemble_plan",
        "ensemble_score",
        "judgment_observation",
        "judgment_plan",
        "judgment_shard_observation",
        "manifest",
        "material",
        "observation",
        "partition",
        "plan",
        "repeats_observation",
        "repeats_plan",
        "resume_attempt",
        "resume_benchmark_score",
        "resume_history",
        "resume_plan",
        "shard_observation",
        "stability",
        "truth",
    )
} | {"development_tree_plan.schema.json"}


@pytest.fixture(scope="module")
def contracts(tmp_path_factory):
    _, loaded = frozen_load(tmp_path_factory.mktemp("static-closure-schemas"))
    schemas = {}
    for filename, model in MODELS.items():
        if filename.startswith("development_corpus_") or filename in {
            "development_dependency_closure.schema.json",
            "development_static_call_closure.schema.json",
            "development_tree_plan.schema.json",
        }:
            schema = json.loads(rendered_schema(filename, model))
            if schema.get("title") in {
                "DevelopmentCorpusManifest",
                "DevelopmentDependencyClosure",
                "DevelopmentStaticCallClosure",
            } or "DevelopmentCorpusManifest" in schema.get("$defs", {}):
                schemas[filename] = schema
    return loaded.material.manifest.model_dump(mode="json"), schemas


def test_every_emitting_schema_accepts_the_versioned_composition_with_its_tree_receipt(contracts):
    manifest, schemas = contracts
    assert set(schemas) == _CORPUS_SCHEMA_NAMES | {
        "development_dependency_closure.schema.json",
        "development_static_call_closure.schema.json",
    }
    for filename, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        if filename == "development_dependency_closure.schema.json":
            value = manifest["dependency_evidence"]
        elif filename == "development_static_call_closure.schema.json":
            value = manifest["dependency_evidence"]["static_call_closure"]
        else:
            value = manifest
            if filename != "development_corpus_manifest.schema.json":
                schema = {"$defs": schema["$defs"], "$ref": "#/$defs/DevelopmentCorpusManifest"}
        Draft202012Validator(schema).validate(value)


@pytest.mark.parametrize(
    "change",
    [
        "tree_missing",
        "tree_null",
        "selected_only",
        "proof_missing",
        "proof_null",
        "legacy_manifest",
        "legacy_witness",
        "old_call_policy",
        "old_syntax_policy",
        "old_scope_policy",
        "members_missing",
        "member_status",
        "proof_status",
        "policy_floor",
        "authority",
        "manifest_status",
        "witness_status",
    ],
)
def test_every_manifest_schema_refuses_missing_proof_custody_or_legacy_promotion(contracts, change):
    manifest, schemas = contracts
    bad = copy.deepcopy(manifest)
    witness = bad["dependency_evidence"]
    proof = witness["static_call_closure"]
    if change == "tree_missing":
        del bad["source_tree_evidence"]
    elif change == "tree_null":
        bad["source_tree_evidence"] = None
    elif change == "selected_only":
        bad["inventory_scope"] = "EXPLICIT_MANIFEST_ONLY"
    elif change == "proof_missing":
        del witness["static_call_closure"]
    elif change == "proof_null":
        witness["static_call_closure"] = None
    elif change == "legacy_manifest":
        bad["schema_version"] = "1.8"
    elif change == "legacy_witness":
        witness["schema_version"] = "1.6"
    elif change.startswith("old_"):
        field, policy = {
            "old_call_policy": ("call_context", "SOURCE_ARGUMENT_RETURN_CALL_RESOLUTION_V1"),
            "old_syntax_policy": ("syntax_context", "SOURCE_GRAMMAR_AND_TYPED_CALL_CENSUS_V1"),
            "old_scope_policy": ("scoped_context", "MODERN_LEXICAL_VALUES_AND_NOMINAL_MEMBERS_V1"),
        }[change]
        witness[field]["policy"] = policy
    elif change == "members_missing":
        del witness["primaries"][0]["call_members"]
    elif change == "member_status":
        proof["primaries"][0]["call_closure"] = "NOT_ESTABLISHED"
    elif change == "proof_status":
        proof["call_closure"] = "NOT_ESTABLISHED"
    elif change == "policy_floor":
        proof["minimum_original_graph_confidence"] = 0.8
    elif change == "manifest_status":
        bad["dependency_closure"] = "IMPORT_CLOSED"
    elif change == "witness_status":
        witness["dependency_closure"] = "NOT_ESTABLISHED"
    else:
        proof["runtime_authority"] = True
    count = 0
    for filename, schema in schemas.items():
        if filename not in _CORPUS_SCHEMA_NAMES:
            continue
        if filename != "development_corpus_manifest.schema.json":
            schema = {"$defs": schema["$defs"], "$ref": "#/$defs/DevelopmentCorpusManifest"}
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(bad)
        count += 1
    assert count == len(_CORPUS_SCHEMA_NAMES) == 25


@pytest.mark.parametrize(
    "case", json.loads(LEGACY.read_text())["cases"], ids=lambda c: c["schema_version"]
)
def test_generated_schema_preserves_legacy_manifests_but_not_new_claims(contracts, case):
    _, schemas = contracts
    validator = Draft202012Validator(schemas["development_corpus_manifest.schema.json"])
    manifest = freeze_development_corpus(
        corpus_id="synthetic-static-closure-legacy",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=fixture_sources(),
        **case["options"],
    ).model_dump(mode="json")
    validator.validate(manifest)
    if manifest.get("dependency_evidence") is not None:
        manifest["dependency_evidence"]["static_call_closure"] = (
            computed().static_call_closure.model_dump(mode="json")
        )
    manifest["dependency_closure"] = "CALL_CLOSED"
    with pytest.raises(ValidationError):
        validator.validate(manifest)
