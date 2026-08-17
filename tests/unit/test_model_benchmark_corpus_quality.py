from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.models import (
    DETERMINISTIC_MODEL_BENCHMARK_DIMENSIONS,
    MIN_BENCHMARK_JUDGMENT_CASES,
    ModelBenchmarkClassification,
    ModelBenchmarkCorpusPayload,
    ModelBenchmarkDimension,
    ModelBenchmarkGroundTruthPayload,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
)
from mmaudit.models.qualification import load_qualification_policy

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
POLICY_PATH = ROOT / "config" / "models.maximum-assurance.toml"

EXPECTED_DENOMINATORS = {
    ModelBenchmarkDimension.ACCESS_CONTROL: 4,
    ModelBenchmarkDimension.ACCOUNTING_CONSERVATION: 4,
    ModelBenchmarkDimension.CROSS_CONTRACT_BUSINESS_LOGIC: 4,
    ModelBenchmarkDimension.EXACT_SOURCE_LOCATION: 2,
    ModelBenchmarkDimension.FALSE_POSITIVE_REJECTION: 4,
    ModelBenchmarkDimension.FALSIFIER_QUALITY: 4,
    ModelBenchmarkDimension.INVARIANT_GENERATION: 4,
    ModelBenchmarkDimension.ORACLE_ASSUMPTIONS: 4,
    ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE: 3,
    ModelBenchmarkDimension.REPORT_QUALITY: 4,
    ModelBenchmarkDimension.SAFE_NEAR_MISS_REJECTION: 4,
    ModelBenchmarkDimension.SIGNATURE_REPLAY: 4,
    ModelBenchmarkDimension.SOLIDITY_SECURITY_REASONING: 4,
    ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE: 24,
    ModelBenchmarkDimension.UNSUPPORTED_ASSUMPTION_DISCLOSURE: 4,
    ModelBenchmarkDimension.UPGRADE_STORAGE: 4,
    ModelBenchmarkDimension.VERIFIER_QUALITY: 4,
}


def test_semantic_denominators_are_distinct_source_non_vacuous_and_policy_bound() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    policy = load_qualification_policy(POLICY_PATH)
    observed = Counter(
        dimension for case in suite.ground_truth.cases for dimension in case.dimensions
    )
    observed[ModelBenchmarkDimension.STRUCTURED_OUTPUT_COMPLIANCE] = len(suite.cases)
    thresholds = {threshold.dimension: threshold.minimum_cases for threshold in policy.thresholds}

    assert len(suite.cases) == 24
    assert suite.corpus_sha256 == (
        "f92ff08ffff2de6fc4b8a4be547d2a0aef45990f7090f734c551ec696ca33e38"
    )
    assert suite.ground_truth_sha256 == (
        "246f5f84aac6aaeecf20a017c9bd5a0f1897e56d54c82ce5ba75a02751d7118c"
    )
    assert dict(observed) == EXPECTED_DENOMINATORS
    assert thresholds == EXPECTED_DENOMINATORS
    judgment_dimensions = set(ModelBenchmarkDimension) - set(
        DETERMINISTIC_MODEL_BENCHMARK_DIMENSIONS
    )
    assert all(
        observed[dimension] >= MIN_BENCHMARK_JUDGMENT_CASES for dimension in judgment_dimensions
    )
    assert max(len(case.dimensions) for case in suite.ground_truth.cases) <= 5
    assert observed[ModelBenchmarkDimension.PROMPT_INJECTION_RESISTANCE] >= 3
    assert len({case.source_path for case in suite.cases}) == len(suite.cases)
    assert len({case.source_excerpt for case in suite.cases}) == len(suite.cases)
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

    expanded_accounting = sources["synthetic/C0017.sol"]
    assert "credit[msg.sender] -= amount;" in expanded_accounting
    assert "credit[to] += amount;" in expanded_accounting
    assert "totalCredit += amount;" in expanded_accounting

    remediated_accounting = sources["synthetic/C0018.sol"]
    assert "credit[msg.sender] -= amount;" in remediated_accounting
    assert "credit[to] += amount;" in remediated_accounting
    assert remediated_accounting.count("totalCredit +=") == 1
    assert "address(this).balance >= totalCredit" in remediated_accounting

    oracle_vulnerability = sources["synthetic/C0019.sol"]
    assert "cumulativePriceSeconds" in oracle_vulnerability
    assert "uint256 elapsed = block.timestamp - priorTimestamp;" in oracle_vulnerability
    assert "return delta / 1 hours;" in oracle_vulnerability

    oracle_boundary = sources["synthetic/C0020.sol"]
    assert "adapter.quote(asset)" in oracle_boundary
    assert "require(price > 0" in oracle_boundary
    assert "block.timestamp <= validUntil" in oracle_boundary

    upgrade_vulnerability = sources["synthetic/C0021.sol"]
    assert "function setImplementation(address next) external" in upgrade_vulnerability
    assert "beacon.implementation()" in upgrade_vulnerability
    assert "delegatecall(msg.data)" in upgrade_vulnerability

    upgrade_boundary = sources["synthetic/C0022.sol"]
    assert "_authorizeUpgrade(msg.sender, next)" in upgrade_boundary
    assert "_proxiableUUID(next) == SLOT" in upgrade_boundary
    assert "internal view virtual" in upgrade_boundary

    signature_vulnerability = sources["synthetic/C0023.sol"]
    assert "usedByRelayer[msg.sender][nonce]" in signature_vulnerability
    assert "block.chainid, address(this), recipient, amount, nonce" in signature_vulnerability
    assert "executedAmount[recipient] += amount;" in signature_vulnerability

    signature_boundary = sources["synthetic/C0024.sol"]
    assert "isValidSignature" in signature_boundary
    assert "mapping(bytes32 => bool) public consumed" in signature_boundary
    assert "block.chainid, address(this), recipient, amount, nonce" in signature_boundary


def test_corpus_rejects_duplicate_source_or_excerpt_and_underfilled_judgment() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    corpus = suite.corpus.model_dump(mode="json", exclude={"corpus_sha256"})

    duplicate_path = json.loads(json.dumps(corpus))
    duplicate_path["cases"][1]["source_path"] = duplicate_path["cases"][0]["source_path"]
    with pytest.raises(ValidationError, match="distinct source paths"):
        ModelBenchmarkCorpusPayload.model_validate(duplicate_path)

    duplicate_excerpt = json.loads(json.dumps(corpus))
    duplicate_excerpt["cases"][1]["source_excerpt"] = duplicate_excerpt["cases"][0][
        "source_excerpt"
    ]
    with pytest.raises(ValidationError, match="distinct source excerpts"):
        ModelBenchmarkCorpusPayload.model_validate(duplicate_excerpt)

    ground_truth = suite.ground_truth.model_dump(
        mode="json",
        exclude={"ground_truth_sha256"},
    )
    access_case = next(
        case for case in ground_truth["cases"] if case["case_id"] == "case-ecf501a2e15c8c5a"
    )
    access_case["dimensions"].remove(ModelBenchmarkDimension.ACCESS_CONTROL.value)
    with pytest.raises(ValidationError, match="at least four distinct cases"):
        ModelBenchmarkGroundTruthPayload.model_validate(ground_truth)


def test_ground_truth_rejects_more_than_five_dimensions_per_case() -> None:
    suite = load_model_benchmark_corpus(CORPUS_PATH)
    ground_truth = suite.ground_truth.model_dump(
        mode="json",
        exclude={"ground_truth_sha256"},
    )
    ground_truth["cases"][0]["dimensions"] = sorted(
        dimension.value for dimension in ModelBenchmarkDimension
    )[:6]
    with pytest.raises(ValidationError, match="at most 5 items"):
        ModelBenchmarkGroundTruthPayload.model_validate(ground_truth)


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
