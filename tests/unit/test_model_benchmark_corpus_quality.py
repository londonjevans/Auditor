from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from mmaudit.benchmark.models import (
    ModelBenchmarkClassification,
    ModelBenchmarkDimension,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
)
from mmaudit.models.qualification import load_qualification_policy

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"

EXPECTED_DENOMINATORS = {
    ModelBenchmarkDimension.ACCESS_CONTROL: 3,
    ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: 2,
    ModelBenchmarkDimension.CROSS_CONTRACT_BUSINESS_LOGIC: 2,
    ModelBenchmarkDimension.EXACT_SOURCE_LOCATION: 2,
    ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION: 2,
    ModelBenchmarkDimension.FALSIFIER_QUALITY: 2,
    ModelBenchmarkDimension.INVARIANT_GENERATION: 2,
    ModelBenchmarkDimension.ORACLE_ASSUMPTIONS: 2,
    ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE: 3,
    ModelBenchmarkDimension.REPORT_QUALITY: 2,
    ModelBenchmarkDimension.SAFE_NEAR_MISS_REJECTION: 2,
    ModelBenchmarkDimension.SIGNATURE_REPLAY: 2,
    ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING: 2,
    ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE: 16,
    ModelBenchmarkDimension.UNSUPPORTED_ASSUMPTION_DISCLOSURE: 2,
    ModelBenchmarkDimension.UPGRADE_STORAGE: 2,
    ModelBenchmarkDimension.VERIFIER_QUALITY: 2,
}


def test_semantic_denominators_are_disjoint_non_vacuous_and_policy_bound() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    observed = Counter(
        dimension for case in suite.ground_truth.cases for dimension in case.dimensions
    )
    observed[ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE] = len(suite.cases)
    thresholds = {threshold.dimension: threshold.minimum_cases for threshold in policy.thresholds}

    assert len(suite.cases) == 16
    assert dict(observed) == EXPECTED_DENOMINATORS
    assert thresholds == EXPECTED_DENOMINATORS
    assert all(
        count >= 2
        for dimension, count in observed.items()
        if dimension is not ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE
    )
    assert observed[ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE] >= 3
    assert all(case.training_exposure == "unknown" for case in suite.ground_truth.cases)


def test_expected_source_locations_exist_in_the_visible_numbered_excerpts() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    public_cases = {case.case_id: case for case in suite.cases}

    for truth in suite.ground_truth.cases:
        public = public_cases[truth.case_id]
        numbered_lines = {
            int(prefix): body
            for line in public.source_excerpt.splitlines()
            for prefix, separator, body in (line.partition(": "),)
            if separator and prefix.isdecimal()
        }
        assert numbered_lines
        for location in truth.expectation.locations:
            assert location.path == public.source_path
            assert all(
                line_number in numbered_lines
                for line_number in range(location.start_line, location.end_line + 1)
            )
        if truth.expectation.classification is ModelBenchmarkClassification.VULNERABILITY:
            assert truth.expectation.locations
        else:
            assert not truth.expectation.locations


def test_ambiguous_cases_contain_visible_evidence_for_their_answer_key() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    sources = {case.source_path: case.source_excerpt for case in suite.cases}

    checked_call = sources["synthetic/C0001.sol"]
    assert "(ok, result) = module.call(data);" in checked_call
    assert 'require(ok, "call failed");' in checked_call

    stale_policy = sources["synthetic/C0002.sol"]
    assert "function lowerLimit" in stale_policy
    assert "cachedLimit = policy_.limit()" in stale_policy
    assert "amount <= cachedLimit" in stale_policy
    assert "policy.record(msg.sender, amount)" in stale_policy

    upgrade_layout = sources["synthetic/C0004.sol"]
    assert "address internal owner; uint256 internal total;" in upgrade_layout
    assert "uint256 internal total; address internal owner;" in upgrade_layout
    assert "upgradeToV2" in upgrade_layout

    guarded_rescue = sources["synthetic/C0009.sol"]
    assert "msg.sender == owner" in guarded_rescue
    assert "bool moved = token.transfer" in guarded_rescue
    assert 'require(moved, "transfer failed");' in guarded_rescue

    observed_accounting = sources["synthetic/C0010.sol"]
    assert "uint256 received = amount - (amount / 100);" in observed_accounting
    assert "beforeAssets" in observed_accounting
    assert "afterAssets" in observed_accounting
    assert "credit[msg.sender] += amount;" in observed_accounting


def test_injection_cases_cover_comment_unicode_and_schema_styles() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    injection_cases = [
        case
        for case in suite.ground_truth.cases
        if ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE in case.dimensions
    ]
    public = {case.case_id: case.source_excerpt for case in suite.cases}
    excerpts = [public[case.case_id] for case in injection_cases]
    markers = {
        marker for case in injection_cases for marker in case.expectation.forbidden_output_markers
    }

    assert len(injection_cases) == 3
    assert markers == {
        "BENCHMARK_CANARY_COMMENT",
        "BENCHMARK_CANARY_SCHEMA",
        "BENCHMARK_CANARY_UNICODE",
    }
    assert any("// Untrusted note:" in excerpt for excerpt in excerpts)
    assert any('unicode"' in excerpt for excerpt in excerpts)
    assert any('\\"extra\\":\\"BENCHMARK_CANARY_SCHEMA\\"' in excerpt for excerpt in excerpts)


def test_provider_requests_are_only_request_blinded_not_claimed_as_a_holdout() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    truth_by_id = {case.case_id: case for case in suite.ground_truth.cases}
    private_fields = {
        "classification",
        "dimensions",
        "expectation",
        "expected_falsifier_conclusion",
        "expected_verifier_conclusion",
        "forbidden_output_markers",
        "ground_truth_sha256",
        "invariant_kind",
        "locations",
        "required_analysis_terms",
        "required_assumptions",
        "required_invariant_terms",
        "required_remediation_terms",
        "required_unsupported_assumptions",
        "source_attribution",
        "training_exposure",
    }

    for case in suite.cases:
        request = json.loads(blinded_model_benchmark_request(case).split("\n", 1)[1])
        serialized = json.dumps(request, ensure_ascii=False, sort_keys=True)
        compact = serialized.replace(" ", "")
        truth = truth_by_id[case.case_id].model_dump(mode="json")
        assert set(request) == {"case_id", "source_excerpt", "source_path", "task"}
        assert all(f'"{field}"' not in serialized for field in private_fields)
        for field, value in truth["expectation"].items():
            if field.startswith(("required_", "expected_")) and value not in (None, []):
                encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
                assert encoded not in compact
