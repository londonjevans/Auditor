"""Exact selected source scope and non-qualifying response contracts, without external execution."""

from __future__ import annotations

import json
from decimal import Decimal

import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_corpus import (
    DevelopmentCorpusManifest,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusPlan,
    DevelopmentCorpusResponse,
    DevelopmentCorpusText,
    freeze_development_corpus,
    validate_development_corpus_response,
    validate_development_corpus_sources,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.development_review import DevelopmentScoredReviewResponse
from mmaudit.orchestration.manifest import canonical_sha256
from tests.development_corpus_support import corpus_case, corpus_payload, supplied_sources


def test_fourteen_file_plan_has_full_selected_context_and_exact_versioned_sources():
    prepared = corpus_case()
    plan = prepared.plan
    assert len(plan.shards) == len(plan.manifest.sources) == 14
    assert plan.manifest.total_source_bytes == 12213
    assert sum(s.line_count for s in plan.manifest.sources) == 424
    assert plan.manifest.dependency_closure == "NOT_ESTABLISHED"
    assert plan.manifest.provenance == "DECLARED_NOT_INDEPENDENTLY_AUTHENTICATED"
    for index, shard in enumerate(prepared.shards, 1):
        body = json.loads(shard.request_content)
        assert shard.shard_id == f"file-{index:04d}"
        assert all(
            "Source file: " + path in body["messages"][1]["content"]
            for path, _ in supplied_sources()
        )
        assert (
            body["response_format"]["json_schema"]["schema"]["properties"]["schema_version"][
                "const"
            ]
            == "3.0"
        )
        assert shard.estimate.within_estimated_budget
    assert DevelopmentCorpusPlan.model_validate_json(plan.model_dump_json(), strict=True) == plan
    assert (
        plan.findings_validated
        is plan.audit_complete
        is plan.qualification_eligible
        is plan.release_eligible
        is False
    )


@pytest.mark.parametrize("scope", ["OPERATOR_SUPPLIED_SYNTHETIC", "OPERATOR_SUPPLIED_PUBLIC"])
def test_declared_scope_never_authenticates_provenance_or_dependency_completeness(scope):
    manifest = freeze_development_corpus(
        corpus_id="local", source_scope=scope, source_files=supplied_sources()
    )
    assert manifest.inventory_scope == "EXPLICIT_MANIFEST_ONLY"
    assert manifest.dependency_closure == "NOT_ESTABLISHED"
    assert not manifest.audit_complete and not manifest.release_eligible


@pytest.mark.parametrize(
    "path",
    [
        "../Outside.sol",
        "/Outside.sol",
        "src/../Outside.sol",
        "src//File.sol",
        "src/./File.sol",
        "src\\File.sol",
        ".env",
        ".git/Hidden.sol",
        "src/File.txt",
        "src/\u202eFile.sol",
        "a" * 513 + ".sol",
        "src/.secret.sol",
    ],
)
def test_manifest_rejects_unselected_sensitive_ambiguous_or_non_source_paths(path):
    with pytest.raises(ValueError):
        freeze_development_corpus(
            corpus_id="local",
            source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
            source_files=((path, b"// Synthetic only.\n"),),
        )


@pytest.mark.parametrize(
    "kind",
    [
        "empty",
        "list",
        "pair_list",
        "reverse",
        "duplicate",
        "case_alias",
        "too_many",
        "empty_bytes",
        "bytearray",
        "too_large",
        "too_many_lines",
        "whole_bound",
        "invalid_utf8",
        "nul",
        "bom",
        "unicode_line_break",
        "secret",
    ],
)
def test_exact_source_manifest_rejects_invalid_or_ambiguous_bytes(kind):
    sources = supplied_sources()[:2]
    if kind == "empty":
        sources = ()
    elif kind == "list":
        sources = list(sources)
    elif kind == "pair_list":
        sources = (list(sources[0]),)
    elif kind == "reverse":
        sources = tuple(reversed(sources))
    elif kind == "duplicate":
        sources = (sources[0], sources[0])
    elif kind == "case_alias":
        sources = (("A.sol", b"x"), ("a.sol", b"x"))
    elif kind == "too_many":
        sources = tuple((f"src/F{i:03d}.sol", b"x") for i in range(65))
    elif kind == "whole_bound":
        sources = tuple((f"src/F{i:03d}.sol", b"x" * 65536) for i in range(9))
    else:
        content = {
            "empty_bytes": b"",
            "bytearray": bytearray(b"x"),
            "too_large": b"x" * 65537,
            "too_many_lines": b"x\n" * 10001,
            "invalid_utf8": b"\xff",
            "nul": b"x\x00",
            "bom": b"\xef\xbb\xbfpragma solidity ^0.8.20;",
            "unicode_line_break": "x\u2028y".encode(),
            "secret": b"// synthetic negative control: sk-or-v1-" + b"a" * 48,
        }[kind]
        sources = (("src/File.sol", content),)
    with pytest.raises(ValueError):
        freeze_development_corpus(
            corpus_id="local", source_scope="OPERATOR_SUPPLIED_SYNTHETIC", source_files=sources
        )


@pytest.mark.parametrize(
    "sources",
    [
        (("File.sol", b"x" * 65536),),
        (("File.sol", b"x\n" * 10000),),
        tuple((f"src/F{i:03d}.sol", b"// Synthetic boundary.\n") for i in range(64)),
        tuple((f"src/F{i:03d}.sol", b"x" * 65536) for i in range(8)),
    ],
)
def test_exact_file_line_count_and_whole_source_limits_are_inclusive(sources):
    manifest = freeze_development_corpus(
        corpus_id="boundary", source_scope="OPERATOR_SUPPLIED_SYNTHETIC", source_files=sources
    )
    validate_development_corpus_sources(manifest, sources)


@pytest.mark.parametrize(
    "field,value",
    [
        ("manifest_sha256", "0" * 64),
        ("total_source_bytes", 1),
        ("dependency_closure", "COMPLETE"),
        ("provenance", "VERIFIED"),
        ("source_scope", "PRIVATE"),
        ("audit_complete", True),
        ("findings_validated", True),
        ("qualification_eligible", True),
        ("release_eligible", True),
    ],
)
def test_manifest_cannot_reseal_wrong_totals_or_promote_declared_scope(field, value):
    data = corpus_case().plan.manifest.model_dump(mode="json")
    data[field] = value
    if field != "manifest_sha256":
        data["manifest_sha256"] = canonical_sha256(
            {k: v for k, v in data.items() if k != "manifest_sha256"}
        )
    with pytest.raises(ValueError):
        DevelopmentCorpusManifest.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize("deadline", [True, 0, -1, 1801, float("inf"), float("nan"), "60"])
def test_run_deadline_is_typed_finite_and_bounded(deadline):
    with pytest.raises(ValueError):
        corpus_case(maximum_run_seconds=deadline)


def test_source_material_preserves_every_original_byte_and_rejects_drift():
    prepared = corpus_case()
    sources = supplied_sources()
    material = DevelopmentCorpusMaterial(
        manifest=prepared.plan.manifest,
        sources=tuple(DevelopmentCorpusText(filename=p, content=b.decode()) for p, b in sources),
    )
    assert (
        DevelopmentCorpusMaterial.model_validate_json(material.model_dump_json()).source_files
        == sources
    )
    changed = (*sources[:-1], (sources[-1][0], sources[-1][1] + b"\n"))
    with pytest.raises(ValueError):
        validate_development_corpus_sources(material.manifest, changed)


def test_whole_estimate_is_checked_even_when_each_selected_shard_fits():
    with pytest.raises(ValueError, match="whole run"):
        corpus_case(
            policy=DevelopmentCostPolicy(
                overspend_risk_accepted=True,
                total_budget_usd=Decimal("5"),
                per_attempt_budget_usd=Decimal("5"),
            )
        )


@pytest.mark.parametrize("origin", ["src/AccessVault.sol", "src/SafeVariants.sol"])
def test_v3_nested_origin_is_validated_without_widening_the_old_v2_schema(origin):
    manifest = corpus_case().plan.manifest
    response = json.loads(corpus_payload(1, origin=origin)["choices"][0]["message"]["content"])
    parsed = DevelopmentCorpusResponse.model_validate_json(json.dumps(response), strict=True)
    validate_development_corpus_response(parsed, manifest, "src/AccessVault.sol")
    Draft202012Validator(DevelopmentCorpusResponse.model_json_schema()).validate(response)
    response["schema_version"] = "2.0"
    with pytest.raises(ValueError):
        DevelopmentScoredReviewResponse.model_validate_json(json.dumps(response), strict=True)


@pytest.mark.parametrize("kind", ["primary_path", "primary_line", "origin_path", "origin_line"])
def test_model_coordinates_must_exist_in_the_exact_manifest(kind):
    manifest = corpus_case().plan.manifest
    data = json.loads(
        corpus_payload(1, origin="src/AccessVault.sol")["choices"][0]["message"]["content"]
    )
    primary = "src/AccessVault.sol"
    if kind == "primary_path":
        primary = "src/Outside.sol"
    elif kind == "primary_line":
        data["findings"][0]["line_end"] = 10000
    elif kind == "origin_path":
        data["findings"][0]["root_cause_ref"]["filename"] = "src/Outside.sol"
    else:
        data["findings"][0]["root_cause_ref"]["line_end"] = 10000
    response = DevelopmentCorpusResponse.model_validate_json(json.dumps(data), strict=True)
    with pytest.raises(ValueError):
        validate_development_corpus_response(response, manifest, primary)
