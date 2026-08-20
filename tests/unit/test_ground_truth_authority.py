from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

import mmaudit.models.ground_truth_authority as ground_truth_authority_module
from mmaudit.benchmark.models import ModelBenchmarkSuite, load_model_benchmark_corpus
from mmaudit.models.ground_truth_authority import (
    FrozenGroundTruthProvenance,
    GroundTruthOriginKind,
    PublicEstablishedGroundTruthOrigin,
    SyntheticPlantedGroundTruthOrigin,
    VerifiedFrozenGroundTruth,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.orchestration.manifest import canonical_sha256

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
GROUND_TRUTH_PATH = ROOT / "benchmarks" / "model_corpus" / "ground_truth.json"
PROVENANCE_PATH = ROOT / "benchmarks" / "model_corpus" / "provenance.json"
REGRESSION_CONTRACT_PATH = ROOT / "tests" / "unit" / "test_model_benchmark_corpus_quality.py"

OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
PROVENANCE_SHA256 = "2a5aefecae5de53f2a390cefc1ee7bfe86922e41b51298e212c50f05d56e6ae9"
SOURCE_REVISION = "f794db0ba0e16e8cd1f028ac623b0486ce86c879"
CORPUS_SHA256 = "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
GROUND_TRUTH_SHA256 = "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
MANIFEST_FILE_SHA256 = "f0b4cee796501d2209048c65c3cf11926a1ed42bf1a9756d392505d12686cfb3"
GROUND_TRUTH_FILE_SHA256 = "bf007f7ee39d374b82e2c04d4af619a713e7bd6c319ce2a109141a2874ebec49"
REGRESSION_CONTRACT_FILE_SHA256 = "ae28d1c5773cd56d6e73cd96b6f62797aad09c38f2d6ec7380419fb85b961287"


def _suite() -> ModelBenchmarkSuite:
    return load_model_benchmark_corpus(MANIFEST_PATH)


def _payload() -> dict[str, Any]:
    value = json.loads(PROVENANCE_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _parse(payload: dict[str, Any]) -> FrozenGroundTruthProvenance:
    return FrozenGroundTruthProvenance.model_validate_json(
        json.dumps(payload, sort_keys=True),
        strict=True,
    )


def _reseal_binding(binding: dict[str, Any]) -> None:
    origin = binding["origin"]
    origin.pop("origin_sha256", None)
    origin["origin_sha256"] = canonical_sha256(origin)
    binding.pop("binding_sha256", None)
    binding["binding_sha256"] = canonical_sha256(binding)


def _reseal(payload: dict[str, Any]) -> FrozenGroundTruthProvenance:
    for binding in payload["case_bindings"]:
        _reseal_binding(binding)
    payload["case_binding_set_sha256"] = canonical_sha256(payload["case_bindings"])
    payload.pop("provenance_sha256", None)
    payload["provenance_sha256"] = canonical_sha256(payload)
    return _parse(payload)


def _resolve(
    provenance: FrozenGroundTruthProvenance,
    suite: ModelBenchmarkSuite,
) -> VerifiedFrozenGroundTruth:
    return resolve_verified_frozen_ground_truth(
        provenance=provenance,
        benchmark_suite=suite,
    )


def _required_pins() -> dict[str, str]:
    return {
        "objective_sha256": OBJECTIVE_SHA256,
        "provenance_sha256": PROVENANCE_SHA256,
        "source_revision": SOURCE_REVISION,
        "benchmark_corpus_sha256": CORPUS_SHA256,
        "benchmark_ground_truth_sha256": GROUND_TRUTH_SHA256,
    }


def _public_origin(case_id: str) -> dict[str, Any]:
    origin: dict[str, Any] = {
        "origin_kind": "PUBLIC_ESTABLISHED",
        "case_id": case_id,
        "authored_by_evaluated_process": False,
        "public_finding_id": "MMAUDIT-PUBLIC-0001",
        "publication_uri": "https://example.org/advisories/MMAUDIT-PUBLIC-0001",
        "published_at": "2025-01-01T00:00:00Z",
        "publication_artifact_sha256": "1" * 64,
        "publication_proof_kind": "EXTERNAL_TRANSPARENCY_INCLUSION",
        "publication_proof_sha256": "2" * 64,
        "upstream_source_revision": SOURCE_REVISION,
        "upstream_source_sha256": "3" * 64,
    }
    origin["origin_sha256"] = canonical_sha256(origin)
    return origin


def test_committed_provenance_resolves_exact_non_authorizing_projection() -> None:
    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    capability = _resolve(provenance, suite)
    projection = capability.require_for(**_required_pins())

    assert provenance.objective_sha256 == OBJECTIVE_SHA256
    assert provenance.provenance_sha256 == PROVENANCE_SHA256
    assert provenance.source_revision == SOURCE_REVISION
    assert projection.benchmark_corpus_sha256 == CORPUS_SHA256
    assert projection.benchmark_ground_truth_sha256 == GROUND_TRUTH_SHA256
    assert projection.case_count == 24
    assert projection.origin_kinds == (GroundTruthOriginKind.SYNTHETIC_PLANTED,)
    assert provenance.authored_by_evaluated_process is False
    assert provenance.source_egress_authorized is False
    assert provenance.benchmark_scoring_authorized is False
    assert provenance.model_qualification_authorized is False
    assert provenance.production_selection_authorized is False
    assert provenance.authority_issuance_authorized is False


def test_committed_synthetic_origins_match_independently_hashed_construction_files() -> None:
    """Guard the planted answer key with file bytes, not its durable self-hashes alone."""

    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    manifest_file_sha256 = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    ground_truth_file_sha256 = hashlib.sha256(GROUND_TRUTH_PATH.read_bytes()).hexdigest()
    regression_contract_file_sha256 = hashlib.sha256(
        REGRESSION_CONTRACT_PATH.read_bytes()
    ).hexdigest()

    assert manifest_file_sha256 == MANIFEST_FILE_SHA256
    assert ground_truth_file_sha256 == GROUND_TRUTH_FILE_SHA256
    assert regression_contract_file_sha256 == REGRESSION_CONTRACT_FILE_SHA256
    assert suite.corpus_sha256 == CORPUS_SHA256
    assert suite.ground_truth_sha256 == GROUND_TRUTH_SHA256

    cases = {case.case_id: case for case in suite.cases}
    truths = {case.case_id: case for case in suite.ground_truth.cases}
    assert tuple(binding.case_id for binding in provenance.case_bindings) == tuple(cases)
    for binding in provenance.case_bindings:
        assert isinstance(binding.origin, SyntheticPlantedGroundTruthOrigin)
        assert binding.origin.authored_by_evaluated_process is False
        assert binding.origin.construction_source_revision == SOURCE_REVISION
        assert binding.origin.construction_manifest_file_sha256 == manifest_file_sha256
        assert binding.origin.construction_ground_truth_file_sha256 == ground_truth_file_sha256
        assert binding.origin.regression_contract_file_sha256 == regression_contract_file_sha256
        assert binding.corpus_case_sha256 == canonical_sha256(
            cases[binding.case_id].model_dump(mode="json")
        )
        assert binding.ground_truth_case_sha256 == canonical_sha256(
            truths[binding.case_id].model_dump(mode="json")
        )
        assert (
            binding.source_excerpt_sha256
            == hashlib.sha256(cases[binding.case_id].source_excerpt.encode("utf-8")).hexdigest()
        )


def test_fixed_expected_pin_rejects_a_coherently_resealed_provenance() -> None:
    suite = _suite()
    payload = _payload()
    for binding in payload["case_bindings"]:
        binding["origin"]["regression_contract_file_sha256"] = "0" * 64
    provenance = _reseal(payload)

    with pytest.raises(ValueError, match="compiled frozen pins"):
        resolve_verified_frozen_ground_truth(
            provenance=provenance,
            benchmark_suite=suite,
        )


@pytest.mark.parametrize(
    "field",
    ["corpus_case_sha256", "ground_truth_case_sha256", "source_excerpt_sha256"],
)
def test_resolver_rebuilds_every_per_case_content_hash(field: str) -> None:
    suite = _suite()
    payload = _payload()
    payload["case_bindings"][0][field] = "0" * 64
    provenance = _reseal(payload)

    with pytest.raises(ValueError, match=r"compiled frozen pins|differs from benchmark truth"):
        _resolve(provenance, suite)


def test_resolver_rebuilds_case_disposition_and_exact_coverage() -> None:
    suite = _suite()
    payload = _payload()
    current = payload["case_bindings"][0]["disposition"]
    payload["case_bindings"][0]["disposition"] = "VULNERABILITY" if current == "SAFE" else "SAFE"
    disposition_tamper = _reseal(payload)
    with pytest.raises(ValueError, match=r"compiled frozen pins|disposition"):
        _resolve(disposition_tamper, suite)

    payload = _payload()
    payload["case_bindings"].pop()
    missing_case = _reseal(payload)
    with pytest.raises(ValueError, match=r"compiled frozen pins|exactly cover"):
        _resolve(missing_case, suite)

    payload = _payload()
    extra = copy.deepcopy(payload["case_bindings"][-1])
    extra["case_id"] = "case-ffffffffffffffff"
    extra["origin"]["case_id"] = extra["case_id"]
    payload["case_bindings"].append(extra)
    extra_case = _reseal(payload)
    with pytest.raises(ValueError, match=r"compiled frozen pins|absent"):
        _resolve(extra_case, suite)


@pytest.mark.parametrize("mutation", ["duplicate", "reordered"])
def test_provenance_rejects_noncanonical_case_binding_sets(mutation: str) -> None:
    payload = _payload()
    if mutation == "duplicate":
        payload["case_bindings"].insert(1, copy.deepcopy(payload["case_bindings"][0]))
    else:
        payload["case_bindings"][0], payload["case_bindings"][1] = (
            payload["case_bindings"][1],
            payload["case_bindings"][0],
        )
    payload["case_binding_set_sha256"] = canonical_sha256(payload["case_bindings"])
    payload.pop("provenance_sha256")
    payload["provenance_sha256"] = canonical_sha256(payload)

    with pytest.raises(ValidationError, match="unique and sorted"):
        _parse(payload)


def test_public_established_origin_cannot_issue_without_external_publication_capability() -> None:
    suite = _suite()
    payload = _payload()
    payload["case_bindings"][0]["origin"] = _public_origin(payload["case_bindings"][0]["case_id"])
    provenance = _reseal(payload)

    assert isinstance(provenance.case_bindings[0].origin, PublicEstablishedGroundTruthOrigin)
    with pytest.raises(ValueError, match=r"compiled frozen pins|publication capability"):
        _resolve(provenance, suite)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authored_by_evaluated_process", True),
        ("publication_uri", "http://example.org/advisories/MMAUDIT-PUBLIC-0001"),
        ("published_at", "2025-01-01T00:00:00.001Z"),
        ("publication_proof_kind", "MODEL_ASSERTION"),
    ],
)
def test_public_origin_rejects_nonexternal_or_noncanonical_evidence(
    field: str,
    value: object,
) -> None:
    payload = _payload()
    origin = _public_origin(payload["case_bindings"][0]["case_id"])
    origin[field] = value
    payload["case_bindings"][0]["origin"] = origin

    with pytest.raises(ValidationError):
        _reseal(payload)


@pytest.mark.parametrize(
    "field",
    [
        "authored_by_evaluated_process",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "authority_issuance_authorized",
    ],
)
def test_durable_provenance_can_never_carry_authority(field: str) -> None:
    payload = _payload()
    payload[field] = True

    with pytest.raises(ValidationError, match="literal false"):
        _reseal(payload)


def test_verified_capability_is_closure_issued_opaque_and_nonserializable() -> None:
    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    capability = _resolve(provenance, suite)

    with pytest.raises(TypeError, match="cannot be constructed"):
        VerifiedFrozenGroundTruth()
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(capability)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(capability)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(capability)
    assert not hasattr(
        ground_truth_authority_module,
        "_build_frozen_ground_truth_runtime_authority",
    )

    forged = object.__new__(VerifiedFrozenGroundTruth)
    with pytest.raises(ValueError, match="authority is absent"):
        forged.require_for(**_required_pins())


@pytest.mark.parametrize(
    "pin",
    [
        "objective_sha256",
        "provenance_sha256",
        "source_revision",
        "benchmark_corpus_sha256",
        "benchmark_ground_truth_sha256",
    ],
)
def test_capability_is_not_reusable_for_different_pins(pin: str) -> None:
    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    capability = _resolve(provenance, suite)
    pins = _required_pins()
    pins[pin] = "0" * (40 if pin == "source_revision" else 64)

    with pytest.raises(ValueError, match="mismatched"):
        capability.require_for(**pins)


def test_capability_copies_validated_state_and_rejects_string_subclass_pins() -> None:
    class StringSubclass(str):
        pass

    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    capability = _resolve(provenance, suite)
    object.__setattr__(provenance, "objective_sha256", "0" * 64)
    assert capability.require_for(**_required_pins()).case_count == 24

    pins = _required_pins()
    pins["objective_sha256"] = StringSubclass(OBJECTIVE_SHA256)
    with pytest.raises(ValueError, match="SHA-256 is invalid"):
        capability.require_for(**pins)


@pytest.mark.parametrize(
    ("field", "forged"),
    [
        ("objective_sha256", "0" * 64),
        ("provenance_sha256", "0" * 64),
        ("source_revision", "0" * 40),
        ("benchmark_corpus_sha256", "0" * 64),
        ("benchmark_ground_truth_sha256", "0" * 64),
        ("case_binding_set_sha256", "0" * 64),
        ("case_count", 1),
        ("origin_kinds", (GroundTruthOriginKind.PUBLIC_ESTABLISHED,)),
    ],
)
def test_returned_projection_mutation_cannot_retarget_the_opaque_capability(
    field: str,
    forged: object,
) -> None:
    suite = _suite()
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    capability = _resolve(provenance, suite)
    projection = capability.require_for(**_required_pins())
    original = getattr(projection, field)

    object.__setattr__(projection, field, forged)

    rebuilt = capability.require_for(**_required_pins())
    assert rebuilt is not projection
    assert getattr(rebuilt, field) == original


def test_loader_rejects_links_hardlinks_and_duplicate_json_keys(tmp_path: Path) -> None:
    original = tmp_path / "provenance.json"
    original.write_bytes(PROVENANCE_PATH.read_bytes())
    symlink = tmp_path / "provenance-symlink.json"
    symlink.symlink_to(original.name)
    with pytest.raises(ValueError):
        load_frozen_ground_truth_provenance(symlink)

    hardlink = tmp_path / "provenance-hardlink.json"
    try:
        os.link(original, hardlink)
    except OSError:
        pytest.skip("hardlinks are unavailable")
    with pytest.raises(ValueError):
        load_frozen_ground_truth_provenance(hardlink)

    duplicate = tmp_path / "provenance-duplicate.json"
    duplicate.write_text('{"schema_version":"1.0","schema_version":"1.0"}', encoding="utf-8")
    with pytest.raises(ValueError):
        load_frozen_ground_truth_provenance(duplicate)
