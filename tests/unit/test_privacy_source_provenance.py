from __future__ import annotations

import copy
import hashlib
import json
import os
import pickle
import subprocess
from dataclasses import replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit
import mmaudit.config as config_module
import mmaudit.repository.privacy_provenance as provenance_module
from mmaudit.benchmark.models import (
    MODEL_BENCHMARK_SCHEMA_NAME,
    ModelBenchmarkCorpusPayload,
    ModelBenchmarkGroundTruthPayload,
    ModelBenchmarkReport,
    ModelBenchmarkResponse,
    ModelBenchmarkSuite,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
    model_benchmark_system_prompt,
    seal_model_benchmark_corpus,
    seal_model_benchmark_ground_truth,
)
from mmaudit.models.authenticated_runner_smoke_corpus import (
    load_authenticated_runner_smoke_corpus_bundle,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.privacy import (
    EffectivePrivacyPolicyEvidence,
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceEvidence,
    PrivacySourceProvenanceObservation,
    prove_pinned_noncrediting_smoke_model_benchmark_source,
    prove_privacy_source_classification,
    prove_release_pinned_model_benchmark_source,
    reobserve_retained_privacy_source_provenance,
    validate_privacy_source_provenance_observation,
    validate_release_pinned_model_benchmark_request,
)

_NOW = datetime(2026, 7, 29, 12, 0, tzinfo=UTC)
_DECLARATION_PATH = Path("src/mmaudit/resources/privacy-synthetic-sources.json")
_DEFAULT_SCOPE = "tests/fixtures/synthetic"
_MODEL_BENCHMARK_CORPUS = Path(__file__).parents[2] / "benchmarks/model_corpus/manifest.json"
_MODEL_BENCHMARK_SMOKE_CORPUS = Path(__file__).parents[2] / "benchmarks/model_corpus_smoke"


def _git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["/usr/bin/git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        input=input_bytes,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        },
    ).stdout


def _write_declaration(
    root: Path,
    *,
    scope: str,
    relative_path: str,
    data: bytes,
) -> Path:
    declaration_path = root / _DECLARATION_PATH
    declaration_path.parent.mkdir(parents=True, exist_ok=True)
    declaration_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "entries": [
                    {
                        "scope": scope,
                        "purpose": "Synthetic source reviewed solely for local privacy regression.",
                        "files": [
                            {
                                "path": relative_path,
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "size": len(data),
                            }
                        ],
                    }
                ],
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return declaration_path


def _distribution(
    tmp_path: Path,
    *,
    scope: str = _DEFAULT_SCOPE,
    relative_path: str = "src/SafeFixture.sol",
    declared_scope: str | None = None,
) -> tuple[Path, Path, Path]:
    root = tmp_path / "distribution"
    target = root / scope
    source = target / relative_path
    source.parent.mkdir(parents=True)
    source.write_text(
        "pragma solidity ^0.8.24; contract SafeFixture { function ok() external pure {} }\n",
        encoding="utf-8",
    )
    declaration = _write_declaration(
        root,
        scope=declared_scope or scope,
        relative_path=relative_path,
        data=source.read_bytes(),
    )
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "synthetic@example.test")
    _git(root, "config", "user.name", "Synthetic Test")
    _git(root, "add", "--", scope, str(_DECLARATION_PATH))
    _git(root, "commit", "-q", "-m", "Add reviewed synthetic fixture")
    return root, target, declaration


def _bind_distribution(
    monkeypatch: pytest.MonkeyPatch,
    *,
    root: Path,
    declaration: Path,
) -> None:
    monkeypatch.setattr(provenance_module, "_distribution_root", lambda: root.resolve())
    monkeypatch.setattr(
        provenance_module,
        "_TRUSTED_SYNTHETIC_DECLARATION_SHA256",
        hashlib.sha256(declaration.read_bytes()).hexdigest(),
    )


def _discovery(
    target: Path,
    *,
    relative_path: str = "src/SafeFixture.sol",
) -> DiscoveryResult:
    source = target / relative_path
    data = source.read_bytes()
    return DiscoveryResult(
        root=target.resolve(),
        files=(
            DiscoveredFile(
                absolute_path=source.resolve(),
                relative_path=relative_path,
                content=data.decode("utf-8", errors="replace"),
                size=len(data),
                lines=data.count(b"\n"),
                sha256=hashlib.sha256(data).hexdigest(),
                language="Solidity",
                categories=("smart_contract",),
            ),
        ),
        omitted=(),
        changed_paths=frozenset(),
        git_commit=None,
    )


def _source_sha256(discovery: DiscoveryResult) -> str:
    payload = [
        {"path": item.relative_path, "sha256": item.sha256, "size": item.size}
        for item in discovery.files
    ]
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
    ).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def _prove(discovery: DiscoveryResult) -> PrivacySourceProvenanceObservation:
    return prove_privacy_source_classification(
        discovery,
        requested_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_sha256=_source_sha256(discovery),
        now=_NOW,
    )


def _custom_model_benchmark_suite() -> ModelBenchmarkSuite:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    cases = list(suite.corpus.cases)
    cases[0] = cases[0].model_copy(
        update={"source_excerpt": cases[0].source_excerpt + "\n// custom corpus drift"}
    )
    corpus = seal_model_benchmark_corpus(
        ModelBenchmarkCorpusPayload(
            schema_version=suite.corpus.schema_version,
            name=suite.corpus.name,
            cases=cases,
        )
    )
    ground_truth = seal_model_benchmark_ground_truth(
        ModelBenchmarkGroundTruthPayload(
            schema_version=suite.ground_truth.schema_version,
            corpus_name=corpus.name,
            corpus_sha256=corpus.corpus_sha256,
            cases=suite.ground_truth.cases,
        )
    )
    return ModelBenchmarkSuite(corpus=corpus, ground_truth=ground_truth)


def test_release_pinned_model_benchmark_proves_exact_provider_visible_inventory() -> None:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)

    observation = prove_release_pinned_model_benchmark_source(suite, now=_NOW)
    evidence = validate_privacy_source_provenance_observation(
        observation,
        source_sha256=suite.corpus_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
    )

    assert evidence.proof_kind == "RELEASE_PINNED_MODEL_BENCHMARK"
    assert evidence.release_pin_set_sha256
    assert evidence.provider_visible_case_count == len(suite.cases)
    assert evidence.provider_visible_case_inventory_sha256
    assert evidence.committed_file_count == 0
    assert evidence.committed_file_inventory_sha256 is None
    assert evidence.synthetic_declaration_path is None
    assert evidence.synthetic_declaration_sha256 is None
    assert evidence.synthetic_declaration_entry_sha256 is None
    validated_request = validate_release_pinned_model_benchmark_request(
        observation,
        request_role="model_benchmark",
        system_prompt=model_benchmark_system_prompt(),
        user_prompt=blinded_model_benchmark_request(suite.cases[0]),
        response_model=ModelBenchmarkResponse,
        schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
        structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
        context_package=None,
    )
    assert validated_request.evidence_sha256 == evidence.evidence_sha256
    with pytest.raises(ValueError, match="absent from the live release-pinned"):
        validate_release_pinned_model_benchmark_request(
            observation,
            request_role="model_benchmark",
            system_prompt=model_benchmark_system_prompt(),
            user_prompt="arbitrary caller-controlled source",
            response_model=ModelBenchmarkResponse,
            schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
            structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
            context_package=None,
        )


def test_pinned_noncrediting_smoke_proves_only_the_exact_candidate_prompt() -> None:
    bundle = load_authenticated_runner_smoke_corpus_bundle(_MODEL_BENCHMARK_SMOKE_CORPUS)
    observation = prove_pinned_noncrediting_smoke_model_benchmark_source(bundle, now=_NOW)
    evidence = validate_privacy_source_provenance_observation(
        observation,
        source_sha256=bundle.source_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
    )

    assert evidence.proof_kind == "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"
    assert evidence.distribution_scope == "benchmarks/model_corpus_smoke"
    assert evidence.release_pin_set_sha256 == bundle.bundle_sha256
    assert evidence.provider_visible_case_count == 1
    assert evidence.adjudication_prepared_run_sha256 is None
    validated = validate_release_pinned_model_benchmark_request(
        observation,
        request_role="model_benchmark",
        system_prompt=model_benchmark_system_prompt(),
        user_prompt=blinded_model_benchmark_request(bundle.case),
        response_model=ModelBenchmarkResponse,
        schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
        structured_output_mode=StructuredOutputMode.JSON_OBJECT,
        context_package=None,
    )
    assert validated.evidence_sha256 == evidence.evidence_sha256

    policy = resolve_effective_privacy_policy(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        require_zdr=True,
        consent_observation=None,
        source_sha256=bundle.source_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=observation,
        configured_model_ids=("anthropic/claude-opus-4.1", "openai/gpt-5"),
        configured_provider_endpoints=("anthropic:claude", "openai:gpt"),
        requested_budget_usd=Decimal("1"),
        now=_NOW,
    )
    assert policy.source_proof_kind == "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK"
    assert policy.source_distribution_scope == "benchmarks/model_corpus_smoke"

    full_suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    assert full_suite.cases[0].case_id != bundle.case.case_id
    with pytest.raises(ValueError, match="pinned noncrediting smoke inventory"):
        validate_release_pinned_model_benchmark_request(
            observation,
            request_role="model_benchmark",
            system_prompt=model_benchmark_system_prompt(),
            user_prompt=blinded_model_benchmark_request(full_suite.cases[0]),
            response_model=ModelBenchmarkResponse,
            schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
            structured_output_mode=StructuredOutputMode.NATIVE_JSON_SCHEMA,
            context_package=None,
        )
    with pytest.raises(ValueError, match="exact pinned bundle type"):
        prove_pinned_noncrediting_smoke_model_benchmark_source(
            bundle.manifest,
            now=_NOW,
        )


def test_pinned_noncrediting_smoke_proves_only_the_exact_judge_prompt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tests.unit.test_authenticated_runner_smoke_benchmark as smoke_fixtures
    from mmaudit.benchmark.cross_lineage_adjudication import (
        CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        CrossLineageAdjudicationRunKind,
        CrossLineageAdjudicationWireResponse,
        cross_lineage_adjudication_source_sha256,
        cross_lineage_adjudication_system_prompt,
        prepare_noncrediting_cross_lineage_adjudication_smoke,
    )
    from mmaudit.models.public_lineage_authority import resolve_verified_public_model_lineage
    from mmaudit.repository.privacy_provenance import (
        prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source,
    )

    bundle = load_authenticated_runner_smoke_corpus_bundle(_MODEL_BENCHMARK_SMOKE_CORPUS)
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    original_structural_real = smoke_fixtures._as_structural_real

    def selected_structural_real(report: ModelBenchmarkReport) -> ModelBenchmarkReport:
        source = original_structural_real(report)
        model_result = source.results[0]
        selected = next(item for item in model_result.cases if item.case_id == bundle.case.case_id)
        reordered = [selected, *(item for item in model_result.cases if item is not selected)]
        return source.model_copy(
            update={"results": [model_result.model_copy(update={"cases": reordered})]}
        )

    monkeypatch.setattr(
        smoke_fixtures,
        "_selection",
        lambda _suite: (bundle.case, bundle.ground_truth_case),
    )
    monkeypatch.setattr(smoke_fixtures, "_as_structural_real", selected_structural_real)
    candidate_report = smoke_fixtures._smoke_report(suite)
    prepared = prepare_noncrediting_cross_lineage_adjudication_smoke(
        public_lineage_capability=resolve_verified_public_model_lineage(),
        suite=suite,
        selected_case=bundle.case,
        selected_ground_truth=bundle.ground_truth_case,
        selection_sha256=smoke_fixtures.SELECTION_SHA256,
        candidate_report=candidate_report,
        judge=smoke_fixtures._judge(smoke_fixtures.JUDGE_ID),
        run_kind=CrossLineageAdjudicationRunKind.PRIMARY,
    )

    observation = prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source(
        bundle,
        candidate_report.result,
        prepared,
        now=_NOW,
    )
    evidence = validate_privacy_source_provenance_observation(
        observation,
        source_sha256=cross_lineage_adjudication_source_sha256(prepared),
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
    )
    request = prepared.requests[0]

    assert evidence.proof_kind == ("PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION")
    assert evidence.distribution_scope == "benchmarks/model_corpus_smoke"
    assert evidence.release_pin_set_sha256 == bundle.bundle_sha256
    assert evidence.provider_visible_case_count == 1
    assert evidence.adjudication_prepared_run_sha256 == prepared.prepared_run_sha256
    assert evidence.adjudication_candidate_report_sha256 == candidate_report.report_sha256
    validated = validate_release_pinned_model_benchmark_request(
        observation,
        request_role="model_benchmark",
        system_prompt=cross_lineage_adjudication_system_prompt(),
        user_prompt=request.provider_visible_user_prompt,
        response_model=CrossLineageAdjudicationWireResponse,
        schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
        structured_output_mode=prepared.target.judge_structured_output_mode,
        context_package=None,
    )
    assert validated.evidence_sha256 == evidence.evidence_sha256
    with pytest.raises(ValueError, match="pinned noncrediting smoke inventory"):
        validate_release_pinned_model_benchmark_request(
            observation,
            request_role="model_benchmark",
            system_prompt=cross_lineage_adjudication_system_prompt(),
            user_prompt="arbitrary caller-controlled adjudication source",
            response_model=CrossLineageAdjudicationWireResponse,
            schema_name=CROSS_LINEAGE_ADJUDICATION_SCHEMA_NAME,
            structured_output_mode=prepared.target.judge_structured_output_mode,
            context_package=None,
        )
    forged_result = candidate_report.result.model_copy(update={"case_id": "case-0000000000000000"})
    with pytest.raises(ValueError, match="inputs failed detached validation"):
        prove_pinned_noncrediting_smoke_cross_lineage_adjudication_source(
            bundle,
            forged_result,
            prepared,
            now=_NOW,
        )


def test_retained_provenance_reobservation_requires_matching_current_live_authority() -> None:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    retained_observation = prove_release_pinned_model_benchmark_source(suite, now=_NOW)
    retained = retained_observation.evidence
    current_observation = prove_release_pinned_model_benchmark_source(
        suite,
        now=_NOW.replace(hour=_NOW.hour + 1),
    )

    reobserved = reobserve_retained_privacy_source_provenance(
        current_observation,
        retained,
    )

    assert reobserved.evidence == retained
    validated = validate_release_pinned_model_benchmark_request(
        reobserved,
        request_role="model_benchmark",
        system_prompt=model_benchmark_system_prompt(),
        user_prompt=blinded_model_benchmark_request(suite.cases[0]),
        response_model=ModelBenchmarkResponse,
        schema_name=MODEL_BENCHMARK_SCHEMA_NAME,
        structured_output_mode=StructuredOutputMode.JSON_OBJECT,
        context_package=None,
    )
    assert validated == retained


def test_retained_provenance_reobservation_rejects_forged_or_future_evidence() -> None:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    current = prove_release_pinned_model_benchmark_source(suite, now=_NOW)
    future = prove_release_pinned_model_benchmark_source(
        suite,
        now=_NOW.replace(hour=_NOW.hour + 1),
    ).evidence

    with pytest.raises(ValueError, match="differs from the current live observation"):
        reobserve_retained_privacy_source_provenance(current, future)
    forged = object.__new__(PrivacySourceProvenanceObservation)
    with pytest.raises(ValueError, match="not issued in this process"):
        reobserve_retained_privacy_source_provenance(forged, current.evidence)


def test_runtime_config_pin_monkeypatch_cannot_bless_custom_benchmark(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custom_suite = _custom_model_benchmark_suite()
    monkeypatch.setattr(
        config_module,
        "MAXIMUM_ASSURANCE_BENCHMARK_CORPUS_SHA256",
        custom_suite.corpus_sha256,
    )
    monkeypatch.setattr(
        config_module,
        "MAXIMUM_ASSURANCE_BENCHMARK_GROUND_TRUTH_SHA256",
        custom_suite.ground_truth_sha256,
    )

    with pytest.raises(ValueError, match="release-pinned synthetic prequalification"):
        prove_release_pinned_model_benchmark_source(custom_suite, now=_NOW)


@pytest.mark.parametrize(
    ("proof_kind", "scope", "case_count", "adjudication_values", "message"),
    [
        (
            "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
            "benchmarks/model_corpus",
            1,
            False,
            "pinned noncrediting smoke benchmark provenance",
        ),
        (
            "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
            "benchmarks/model_corpus_smoke",
            2,
            False,
            "pinned noncrediting smoke benchmark provenance",
        ),
        (
            "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
            "benchmarks/model_corpus_smoke",
            1,
            False,
            "pinned noncrediting smoke cross-lineage provenance",
        ),
        (
            "RELEASE_PINNED_MODEL_BENCHMARK",
            "benchmarks/model_corpus_smoke",
            1,
            False,
            "release-pinned model benchmark provenance",
        ),
    ],
)
def test_smoke_proof_kinds_reject_scope_count_and_adjudication_confusion(
    proof_kind: str,
    scope: str,
    case_count: int,
    adjudication_values: bool,
    message: str,
) -> None:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    payload = prove_release_pinned_model_benchmark_source(suite, now=_NOW).evidence.model_dump(
        mode="json",
        exclude={"evidence_sha256"},
    )
    payload.update(
        {
            "proof_kind": proof_kind,
            "distribution_scope": scope,
            "provider_visible_case_count": case_count,
            "adjudication_prepared_run_sha256": "a" * 64 if adjudication_values else None,
            "adjudication_candidate_report_sha256": "b" * 64 if adjudication_values else None,
            "adjudication_ground_truth_sha256": "c" * 64 if adjudication_values else None,
        }
    )

    with pytest.raises(ValidationError, match=message):
        PrivacySourceProvenanceEvidence.model_validate(
            {**payload, "evidence_sha256": _canonical_sha256(payload)}
        )


@pytest.mark.parametrize(
    "proof_kind",
    [
        "PINNED_NONCREDITING_SMOKE_MODEL_BENCHMARK",
        "PINNED_NONCREDITING_SMOKE_CROSS_LINEAGE_ADJUDICATION",
    ],
)
def test_effective_policy_accepts_smoke_proof_only_in_disjoint_scope(
    proof_kind: str,
) -> None:
    suite = load_model_benchmark_corpus(_MODEL_BENCHMARK_CORPUS)
    observation = prove_release_pinned_model_benchmark_source(suite, now=_NOW)
    release_policy = resolve_effective_privacy_policy(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        require_zdr=True,
        consent_observation=None,
        source_sha256=suite.corpus_sha256,
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=observation,
        configured_model_ids=("anthropic/claude-opus-4.1", "openai/gpt-5"),
        configured_provider_endpoints=("anthropic:claude", "openai:gpt"),
        requested_budget_usd=Decimal("1"),
        now=_NOW,
    )
    payload = release_policy.model_dump(mode="json", exclude={"evidence_sha256"})
    payload.update(
        {
            "source_proof_kind": proof_kind,
            "source_distribution_scope": "benchmarks/model_corpus_smoke",
        }
    )
    smoke_policy = EffectivePrivacyPolicyEvidence.model_validate(
        {**payload, "evidence_sha256": _canonical_sha256(payload)}
    )

    assert smoke_policy.source_distribution_scope == "benchmarks/model_corpus_smoke"
    wrong_scope = smoke_policy.model_dump(mode="json", exclude={"evidence_sha256"})
    wrong_scope["source_distribution_scope"] = "benchmarks/model_corpus"
    with pytest.raises(ValidationError, match="pinned noncrediting smoke privacy policy"):
        EffectivePrivacyPolicyEvidence.model_validate(
            {**wrong_scope, "evidence_sha256": _canonical_sha256(wrong_scope)}
        )


def test_clean_declared_distribution_fixture_proves_synthetic_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)

    observation = _prove(discovery)
    evidence = validate_privacy_source_provenance_observation(
        observation,
        source_sha256=_source_sha256(discovery),
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
    )

    assert evidence is not observation.evidence
    assert evidence.proof_kind == "DISTRIBUTION_COMMITTED_SYNTHETIC"
    assert evidence.distribution_scope == _DEFAULT_SCOPE
    assert evidence.committed_file_count == 1
    assert evidence.distribution_commit
    assert evidence.synthetic_declaration_path == _DECLARATION_PATH.as_posix()
    assert (
        evidence.synthetic_declaration_sha256
        == hashlib.sha256(declaration.read_bytes()).hexdigest()
    )
    assert evidence.synthetic_declaration_entry_sha256
    assert evidence.committed_file_inventory_sha256
    assert evidence.evidence_sha256

    policy = resolve_effective_privacy_policy(
        profile=PrivacyProfile.SYNTHETIC_BENCHMARK,
        require_zdr=True,
        consent_observation=None,
        source_sha256=_source_sha256(discovery),
        source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        source_provenance_observation=observation,
        configured_model_ids=("anthropic/claude-opus-4.1", "openai/gpt-5"),
        configured_provider_endpoints=("anthropic:claude", "openai:gpt"),
        requested_budget_usd=Decimal("20"),
        now=_NOW,
    )

    assert policy.source_provenance_sha256 == observation.evidence.evidence_sha256
    assert policy.source_synthetic_declaration_sha256 == evidence.synthetic_declaration_sha256
    assert (
        policy.source_synthetic_declaration_entry_sha256
        == evidence.synthetic_declaration_entry_sha256
    )


def test_packaged_trust_anchor_and_fixture_are_usable_without_checkout_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert mmaudit.__file__ is not None
    package_root = Path(mmaudit.__file__).resolve(strict=True).parent
    target = package_root / "resources" / "synthetic" / "provider_smoke"
    declaration = package_root / "resources" / "privacy-synthetic-sources.json"
    monkeypatch.setattr(provenance_module, "_distribution_root", lambda: package_root)
    discovery = _discovery(target, relative_path="src/ProviderSmoke.sol")

    evidence = _prove(discovery).evidence

    assert declaration.is_file()
    assert evidence.proof_kind == "PACKAGE_PINNED_SYNTHETIC"
    assert evidence.distribution_commit is None
    assert evidence.distribution_scope == "src/mmaudit/resources/synthetic/provider_smoke"
    assert (
        evidence.synthetic_declaration_sha256
        == hashlib.sha256(declaration.read_bytes()).hexdigest()
    )


@pytest.mark.parametrize("change", ["modified", "untracked", "declaration"])
def test_dirty_distribution_fixture_cannot_claim_synthetic_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    if change == "modified":
        (target / "src" / "SafeFixture.sol").write_text("changed\n", encoding="utf-8")
    elif change == "untracked":
        (target / "untracked.sol").write_text("untracked\n", encoding="utf-8")
    else:
        declaration.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"declaration|committed HEAD|code-pinned"):
        _prove(discovery)


def test_only_explicitly_declared_scope_can_claim_synthetic_committed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(
        tmp_path,
        declared_scope="tests/fixtures/different",
    )
    _bind_distribution(monkeypatch, root=root, declaration=declaration)

    with pytest.raises(ValueError, match="not explicitly approved"):
        _prove(_discovery(target))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("content", "forged provider-visible content"),
        ("size", 1),
        ("sha256", "0" * 64),
    ],
)
def test_forged_discovery_inventory_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    replacement: str | int,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    item = discovery.files[0]
    if field == "size":
        replacement = item.size + int(replacement)
    forged = replace(item, **{field: replacement})
    forged_discovery = replace(discovery, files=(forged,))

    with pytest.raises(ValueError, match=r"inventory|approved declaration"):
        _prove(forged_discovery)


def test_forged_discovery_absolute_path_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    alternate = root / "alternate.sol"
    alternate.write_bytes((target / "src" / "SafeFixture.sol").read_bytes())
    forged = replace(discovery.files[0], absolute_path=alternate)

    with pytest.raises(ValueError, match="path binding"):
        _prove(replace(discovery, files=(forged,)))


def test_hardlinked_current_source_is_rejected_even_when_bytes_match_head(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    source = target / "src" / "SafeFixture.sol"
    alternate = root / "same-bytes.sol"
    alternate.write_bytes(source.read_bytes())
    source.unlink()
    os.link(alternate, source)

    with pytest.raises(ValueError, match="metadata is unsafe"):
        _prove(discovery)


def test_symlinked_current_source_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    source = target / "src" / "SafeFixture.sol"
    alternate = root / "same-bytes.sol"
    alternate.write_bytes(source.read_bytes())
    source.unlink()
    source.symlink_to(alternate)

    with pytest.raises(ValueError, match=r"committed HEAD|opened safely"):
        _prove(discovery)


def test_source_change_during_descriptor_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    source = target / "src" / "SafeFixture.sol"
    source_inode = source.stat().st_ino
    original_read = os.read
    changed = False

    def mutating_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        content = original_read(descriptor, size)
        if not changed and os.fstat(descriptor).st_ino == source_inode:
            changed = True
            source.write_text("changed during read\n", encoding="utf-8")
        return content

    monkeypatch.setattr(provenance_module.os, "read", mutating_read)

    with pytest.raises(ValueError, match=r"changed while it was read|byte size"):
        _prove(discovery)


def test_active_git_replacement_refs_cannot_substitute_committed_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    original_blob = (
        _git(
            root,
            "rev-parse",
            f"HEAD:{_DEFAULT_SCOPE}/src/SafeFixture.sol",
        )
        .decode()
        .strip()
    )
    replacement_bytes = b"replacement-controlled bytes\n"
    replacement_blob = (
        _git(
            root,
            "hash-object",
            "-w",
            "--stdin",
            input_bytes=replacement_bytes,
        )
        .decode()
        .strip()
    )
    _git(root, "replace", original_blob, replacement_blob)
    assert _git(root, "cat-file", "blob", original_blob) == replacement_bytes

    evidence = _prove(discovery).evidence

    assert evidence.proof_kind == "DISTRIBUTION_COMMITTED_SYNTHETIC"


def test_unicode_inventory_uses_manifest_canonical_hash_algorithm(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    relative_path = "src/SaféFixture.sol"
    root, target, declaration = _distribution(tmp_path, relative_path=relative_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target, relative_path=relative_path)

    evidence = _prove(discovery).evidence

    assert evidence.source_sha256 == _source_sha256(discovery)
    assert "é" in discovery.files[0].relative_path


def test_provenance_observation_is_live_noncopyable_and_exactly_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, target, declaration = _distribution(tmp_path)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)
    discovery = _discovery(target)
    observation = _prove(discovery)

    with pytest.raises(TypeError, match="cannot be constructed directly"):
        PrivacySourceProvenanceObservation(evidence=observation.evidence)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(observation)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(observation)
    with pytest.raises(TypeError, match="cannot be serialized"):
        pickle.dumps(observation)
    with pytest.raises(ValueError, match="binding is inconsistent"):
        validate_privacy_source_provenance_observation(
            observation,
            source_sha256="0" * 64,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        )
    with pytest.raises(ValueError, match="binding is inconsistent"):
        validate_privacy_source_provenance_observation(
            observation,
            source_sha256=_source_sha256(discovery),
            source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        )


def test_provenance_authority_has_no_importable_issuer_or_registry_handles() -> None:
    forbidden_names = (
        "_TRUSTED_PROVENANCE_ISSUER",
        "_LIVE_PROVENANCE_OBSERVATIONS",
        "_ProvenanceBinding",
        "_issue_observation",
        "_build_privacy_source_provenance_authority",
        "_build_privacy_source_classification_evidence",
        "_build_release_pinned_model_benchmark_evidence",
        "_build_pinned_noncrediting_smoke_model_benchmark_evidence",
        "_build_pinned_noncrediting_smoke_cross_lineage_adjudication_evidence",
        "_validated_authenticated_runner_smoke_bundle",
        "_TRUSTED_REQUIRE_RELEASE_PINNED_MODEL_BENCHMARK",
    )
    assert all(not hasattr(provenance_module, name) for name in forbidden_names)

    forged = object.__new__(PrivacySourceProvenanceObservation)
    with pytest.raises(ValueError, match="not issued in this process"):
        validate_privacy_source_provenance_observation(
            forged,
            source_sha256="0" * 64,
            source_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
        )


def test_operator_enum_cannot_classify_arbitrary_or_public_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _target, declaration = _distribution(tmp_path)
    outside = root / "operator-project"
    (outside / "src").mkdir(parents=True)
    (outside / "src" / "SafeFixture.sol").write_text("contract SafeFixture {}\n")
    discovery = _discovery(outside)
    _bind_distribution(monkeypatch, root=root, declaration=declaration)

    with pytest.raises(ValueError, match="distribution-owned"):
        prove_privacy_source_classification(
            discovery,
            requested_classification=PrivacySourceClassification.SYNTHETIC_COMMITTED,
            source_sha256=_source_sha256(discovery),
            now=_NOW,
        )
    with pytest.raises(ValueError, match="independent publication provenance"):
        prove_privacy_source_classification(
            discovery,
            requested_classification=PrivacySourceClassification.PUBLIC_BENCHMARK,
            source_sha256=_source_sha256(discovery),
            now=_NOW,
        )
    with pytest.raises(ValueError, match="must be typed"):
        prove_privacy_source_classification(
            discovery,
            requested_classification="SYNTHETIC_COMMITTED",
            source_sha256=_source_sha256(discovery),
            now=_NOW,
        )


def test_private_default_does_not_claim_public_or_committed_proof(tmp_path: Path) -> None:
    target = tmp_path / "operator-project"
    (target / "src").mkdir(parents=True)
    (target / "src" / "SafeFixture.sol").write_text("contract SafeFixture {}\n")
    discovery = _discovery(target)

    observation = prove_privacy_source_classification(
        discovery,
        requested_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
        source_sha256=_source_sha256(discovery),
        now=_NOW,
    )
    evidence = observation.evidence

    assert evidence.proof_kind == "PRIVATE_DEFAULT"
    assert evidence.distribution_commit is None
    assert evidence.committed_file_count == 0
    assert evidence.synthetic_declaration_sha256 is None
