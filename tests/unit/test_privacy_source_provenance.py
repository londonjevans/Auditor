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

import mmaudit
import mmaudit.config as config_module
import mmaudit.repository.privacy_provenance as provenance_module
from mmaudit.benchmark.models import (
    MODEL_BENCHMARK_SCHEMA_NAME,
    ModelBenchmarkCorpusPayload,
    ModelBenchmarkGroundTruthPayload,
    ModelBenchmarkResponse,
    ModelBenchmarkSuite,
    blinded_model_benchmark_request,
    load_model_benchmark_corpus,
    model_benchmark_system_prompt,
    seal_model_benchmark_corpus,
    seal_model_benchmark_ground_truth,
)
from mmaudit.models.output_modes import StructuredOutputMode
from mmaudit.privacy import (
    PrivacyProfile,
    PrivacySourceClassification,
    resolve_effective_privacy_policy,
)
from mmaudit.repository.discovery import DiscoveredFile, DiscoveryResult
from mmaudit.repository.privacy_provenance import (
    PrivacySourceProvenanceObservation,
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
