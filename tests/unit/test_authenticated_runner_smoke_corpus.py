from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from mmaudit.benchmark.models import ModelBenchmarkSuite, load_model_benchmark_corpus
from mmaudit.models.authenticated_runner_smoke_corpus import (
    AUTHENTICATED_RUNNER_SMOKE_CASE_ID,
    AuthenticatedRunnerSmokeCorpusBundle,
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.ground_truth_authority import (
    FrozenGroundTruthProvenance,
    load_frozen_ground_truth_provenance,
)
from scripts.generate_release_schemas import MODELS

ROOT = Path(__file__).resolve().parents[2]
SMOKE_ROOT = ROOT / "benchmarks" / "model_corpus_smoke"
PARENT_ROOT = ROOT / "benchmarks" / "model_corpus"

_FALSE_FLAGS = {
    "audit_evidence_authorized",
    "authseal_input_authorized",
    "authority_issuance_authorized",
    "benchmark_credit_authorized",
    "benchmark_scoring_authorized",
    "calibration_authorized",
    "grants_completion_credit",
    "grants_review_credit",
    "model_qualification_authorized",
    "production_selection_authorized",
    "provider_access_authorized",
    "provider_transport_authorized",
    "release_authorized",
    "runner_custody_authorized",
    "source_egress_authorized",
}


def _copy_bundle(tmp_path: Path) -> Path:
    destination = tmp_path / "smoke"
    shutil.copytree(SMOKE_ROOT, destination)
    return destination


def test_committed_smoke_bundle_is_exact_noncrediting_parent_projection() -> None:
    bundle = load_authenticated_runner_smoke_corpus_bundle(SMOKE_ROOT)
    parent_suite = load_model_benchmark_corpus(PARENT_ROOT / "manifest.json")
    parent_provenance = load_frozen_ground_truth_provenance(PARENT_ROOT / "provenance.json")
    parent_case = next(
        case for case in parent_suite.cases if case.case_id == AUTHENTICATED_RUNNER_SMOKE_CASE_ID
    )
    parent_truth = parent_suite.ground_truth_case(AUTHENTICATED_RUNNER_SMOKE_CASE_ID)
    parent_binding = next(
        binding
        for binding in parent_provenance.case_bindings
        if binding.case_id == AUTHENTICATED_RUNNER_SMOKE_CASE_ID
    )

    assert isinstance(bundle, AuthenticatedRunnerSmokeCorpusBundle)
    assert not isinstance(bundle, ModelBenchmarkSuite | FrozenGroundTruthProvenance)
    assert bundle.case == parent_case
    assert bundle.ground_truth_case == parent_truth
    assert bundle.case_binding == parent_binding
    assert bundle.source_sha256 == (
        "2530063df1ec8b0c7911a1aeb2a4e17d6ed59c6dd72829b0fc52a7bf785eef0e"
    )
    assert bundle.corpus_sha256 == (
        "9d9f60375880430c419d23324ec720cdb9bcbe124e8f7a1b30fe639ff8117967"
    )
    assert bundle.ground_truth_sha256 == (
        "0680c7d694c26be1875f0aecaa3869105ae77e6f36206e9bc5ec14aaebef1027"
    )
    assert bundle.provenance_sha256 == (
        "8ec4b3c73180f2dce0831eb953d5419b9e74741a527901ceae7cc41b2d0a7817"
    )
    assert bundle.bundle_sha256 == (
        "721f058726cf9509c07cb2aae662fb6ac23b5c30a363db40229faf8895034497"
    )
    assert [(item.path, item.sha256, item.size) for item in bundle.artifact_bindings] == [
        (
            "manifest.json",
            "aa453f655a4d09adf19498387c9cd2b48939119f1494e9517182dbb2b3ee685c",
            2486,
        ),
        (
            "ground_truth.json",
            "e5e2baef1b986c77ae448fad1eb96052f061a8db1daae1b6f4122f61cbce8765",
            3094,
        ),
        (
            "provenance.json",
            "d3f9e13733949f660ae4f3eeac8c3576a8b8b620e37adb4f1fc268e45163d46c",
            3420,
        ),
        (
            "verdict_policy.json",
            "79b1aee6b28fc90f64887fff189b9f404114bd7671a7363bdb437e19d258d68f",
            3344,
        ),
    ]
    assert tuple(bundle.verdict_policy.artifact_bindings) == tuple(bundle.artifact_bindings[:3])
    assert bundle.verdict_policy.candidate_run_kinds == ("PRIMARY", "REPLAY")
    assert bundle.verdict_policy.judge_run_kinds == ("PRIMARY", "REPLAY")
    assert bundle.verdict_policy.logical_request_count == 4
    assert bundle.verdict_policy.maximum_provider_attempts == 8
    for artifact in (
        bundle.manifest,
        bundle.ground_truth,
        bundle.provenance,
        bundle.verdict_policy,
    ):
        assert artifact.purpose == "NONCREDITING_SMOKE"
        for field_name in _FALSE_FLAGS:
            assert getattr(artifact, field_name) is False
    assert bundle.verdict_policy.semantic_scores_creditable is False
    assert bundle.verdict_policy.representative_for_calibration is False
    assert bundle.verdict_policy.smoke_success_authorizes_full_launch is False


@pytest.mark.parametrize("mutation", ["missing", "extra", "directory_symlink"])
def test_smoke_loader_requires_one_exact_unlinked_directory_inventory(
    tmp_path: Path,
    mutation: str,
) -> None:
    bundle_root = _copy_bundle(tmp_path)
    load_path = bundle_root
    if mutation == "missing":
        (bundle_root / "provenance.json").unlink()
    elif mutation == "extra":
        (bundle_root / "unexpected.json").write_text("{}\n", encoding="utf-8")
    else:
        linked = tmp_path / "linked"
        linked.symlink_to(bundle_root, target_is_directory=True)
        load_path = linked

    with pytest.raises(ValueError):
        load_authenticated_runner_smoke_corpus_bundle(load_path)


@pytest.mark.parametrize("mutation", ["symlink", "hardlink", "duplicate_key", "noncanonical"])
def test_smoke_loader_rejects_ambiguous_or_rewritten_artifact_bytes(
    tmp_path: Path,
    mutation: str,
) -> None:
    bundle_root = _copy_bundle(tmp_path)
    manifest = bundle_root / "manifest.json"
    original = manifest.read_bytes()
    if mutation in {"symlink", "hardlink"}:
        outside = tmp_path / "outside.json"
        outside.write_bytes(original)
        manifest.unlink()
        if mutation == "symlink":
            manifest.symlink_to(outside)
        else:
            os.link(outside, manifest)
    elif mutation == "duplicate_key":
        manifest.write_bytes(original.replace(b"{\n", b'{\n  "artifact_kind": "duplicate",\n', 1))
    else:
        manifest.write_bytes(original + b" ")

    with pytest.raises(ValueError):
        load_authenticated_runner_smoke_corpus_bundle(bundle_root)


def test_smoke_loader_rejects_authority_flag_even_when_json_false_is_coerced() -> None:
    payload = json.loads((SMOKE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    payload["release_authorized"] = 0
    with pytest.raises(ValueError, match="literal false"):
        type(load_authenticated_runner_smoke_corpus_bundle(SMOKE_ROOT).manifest).model_validate(
            payload
        )


def test_full_corpus_and_provenance_loaders_reject_smoke_artifacts() -> None:
    with pytest.raises(ValueError):
        load_model_benchmark_corpus(SMOKE_ROOT / "manifest.json")
    with pytest.raises(ValueError):
        load_frozen_ground_truth_provenance(SMOKE_ROOT / "provenance.json")


def test_smoke_bundle_has_a_strict_generated_non_authorizing_schema() -> None:
    filename = "authenticated_runner_smoke_corpus_bundle.schema.json"
    assert MODELS[filename] is AuthenticatedRunnerSmokeCorpusBundle
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    definitions = schema["$defs"]
    assert schema["additionalProperties"] is False
    assert schema["title"] == (
        "mmaudit exact noncrediting authenticated runner smoke corpus bundle"
    )
    for model_name in (
        "AuthenticatedRunnerSmokeCorpus",
        "AuthenticatedRunnerSmokeGroundTruth",
        "AuthenticatedRunnerSmokeProvenance",
        "AuthenticatedRunnerSmokeVerdictPolicy",
    ):
        definition = definitions[model_name]
        assert definition["additionalProperties"] is False
        assert set(definition["required"]) >= _FALSE_FLAGS
        for field_name in _FALSE_FLAGS:
            assert definition["properties"][field_name]["const"] is False
        assert definition["properties"]["purpose"]["const"] == "NONCREDITING_SMOKE"
    policy = definitions["AuthenticatedRunnerSmokeVerdictPolicy"]["properties"]
    assert policy["benchmark_case_count"]["const"] == 1
    assert policy["logical_request_count"]["const"] == 4
    assert policy["maximum_provider_attempts"]["const"] == 8
    assert policy["semantic_scores_creditable"]["const"] is False
    assert policy["representative_for_calibration"]["const"] is False
    assert policy["smoke_success_authorizes_full_launch"]["const"] is False
