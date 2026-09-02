from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from mmaudit.models.retrieval import SolidityRetrievalRolePolicy
from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityProvenance,
    SoliditySymbolIndex,
)
from mmaudit.orchestration.context import ContextBuilder, render_context
from mmaudit.repository.chunking import line_range_hash
from mmaudit.repository.discovery import discover_repository
from mmaudit.repository.ignore import IgnoreMatcher
from mmaudit.repository.mapping import build_repository_map
from mmaudit.solidity.retrieval import start_solidity_retrieval_transcript


def test_context_builder_retains_canonical_line_only_secret_taint(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "repository"
    source_path = repository / "src" / "Vault.sol"
    source_path.parent.mkdir(parents=True)
    first_key = "AKIA" + ("A" * 16)
    second_key = "AKIA" + ("B" * 16)
    third_key = "ASIA" + ("C" * 16)
    private_key_body = "c3ludGhldGljLW5vbi1vcGVyYXRpb25hbA=="
    source = "\n".join(
        (
            "safe = True",
            f"first = '{first_key}'; second = '{second_key}'",
            f"third = '{third_key}'",
            "gap = True",
            "-----BEGIN PRIVATE KEY-----",
            private_key_body,
            "-----END PRIVATE KEY-----",
        )
    )
    source_path.write_text(source, encoding="utf-8")
    config = config_factory(privacy={"redact_secrets": False, "fail_on_detected_secret": False})
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
    )

    taint = builder.retrieval_taint_line_intervals
    assert isinstance(taint, MappingProxyType)
    assert dict(taint) == {"src/Vault.sol": ((2, 3), (5, 7))}
    with pytest.raises(TypeError):
        taint["src/Other.sol"] = ((1, 1),)  # type: ignore[index]

    projection_json = json.dumps(dict(taint), sort_keys=True)
    for forbidden in (
        first_key,
        second_key,
        third_key,
        private_key_body,
        "private_key",
        "fingerprint",
        "offset",
    ):
        assert forbidden not in projection_json

    detached = dict(taint)
    detached["src/Other.sol"] = ((1, 1),)
    assert "src/Other.sol" not in builder.retrieval_taint_line_intervals


def test_context_builder_retains_only_reasons_for_whole_file_withholding(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "repository"
    nested = repository / "nested"
    nested.mkdir(parents=True)
    scanner_path = nested / "scanner.py"
    scanner_path.write_text("safe = True\n", encoding="utf-8")
    credential = "AKIA" + ("Q" * 16)
    credential_path = repository / f"{credential}.py"
    credential_path.write_text("safe = True\n", encoding="utf-8")
    config = config_factory(privacy={"redact_secrets": False, "fail_on_detected_secret": False})
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        scanner_secret_paths={"nested/scanner.py"},
    )

    withheld = builder.retrieval_withheld_path_reasons
    assert isinstance(withheld, MappingProxyType)
    assert dict(withheld) == {
        f"{credential}.py": frozenset({"path_secret_match"}),
        "nested/scanner.py": frozenset({"scanner_secret_path"}),
    }
    assert builder.retrieval_taint_line_intervals == {}
    assert builder.repository_map.files == []
    with pytest.raises(TypeError):
        withheld["other.py"] = frozenset({"scanner_secret_path"})  # type: ignore[index]

    retained_values = json.dumps(
        {path: sorted(reasons) for path, reasons in withheld.items()},
        sort_keys=True,
    )
    for forbidden in ("aws_access_key", "fingerprint", "offset", "start", "end"):
        assert forbidden not in retained_values


def test_retrieval_binding_replaces_unsafe_index_metadata_with_safe_subjects(
    tmp_path: Path,
    config_factory,
) -> None:
    repository = tmp_path / "repository"
    source_dir = repository / "src"
    source_dir.mkdir(parents=True)
    safe_source = "contract Vault { function audit() external {} }\n"
    secret_source = "contract Secret { function hidden() external {} }\n"
    secret_contract_name = "AKIA" + ("L" * 16)
    clean_child_source = (
        f"contract {secret_contract_name} {{\nfunction cleanChild() external {{}}\n}}\n"
    )
    (source_dir / "Vault.sol").write_text(safe_source, encoding="utf-8")
    (source_dir / "Secret.sol").write_text(secret_source, encoding="utf-8")
    (source_dir / "CleanChild.sol").write_text(clean_child_source, encoding="utf-8")

    def entity(
        *,
        subject_id: str,
        name: str,
        path: str,
        content: str,
        documentation: str,
    ) -> SolidityEntity:
        encoded = content.encode("utf-8")
        return SolidityEntity(
            id=subject_id,
            kind=SolidityEntityKind.FUNCTION,
            name=name,
            contract_name="Vault" if name == "audit" else "Secret",
            path=path,
            start_line=1,
            end_line=1,
            byte_start=0,
            byte_end=len(encoded),
            source_hash=hashlib.sha256(encoded).hexdigest(),
            provenance=SolidityProvenance.COMPILER,
            confidence=1.0,
            transformation="synthetic.compiler_ast",
            visibility="external",
            mutability="nonpayable",
            documentation=documentation,
        )

    index = SoliditySymbolIndex(
        projects=[],
        entities=[
            entity(
                subject_id="fn-safe",
                name="audit",
                path="src/Vault.sol",
                content=safe_source,
                documentation="SAFE_INDEX_DOCUMENTATION_MUST_BE_STRIPPED",
            ),
            entity(
                subject_id="fn-secret",
                name="hidden",
                path="src/Secret.sol",
                content=secret_source,
                documentation="SECRET_SENTINEL_DO_NOT_EGRESS",
            ),
            SolidityEntity(
                id="fn-clean-child",
                kind=SolidityEntityKind.FUNCTION,
                name="cleanChild",
                contract_name=secret_contract_name,
                path="src/CleanChild.sol",
                start_line=2,
                end_line=2,
                byte_start=len(f"contract {secret_contract_name} {{\n".encode()),
                byte_end=len(
                    (
                        f"contract {secret_contract_name} {{\nfunction cleanChild() external {{}}\n"
                    ).encode()
                ),
                source_hash=line_range_hash(clean_child_source, 2, 2),
                provenance=SolidityProvenance.COMPILER,
                confidence=1.0,
                transformation="synthetic.compiler_ast",
                visibility="external",
                mutability="nonpayable",
                documentation="CLEAN_CHILD_DOCUMENTATION_MUST_BE_STRIPPED",
            ),
        ],
        warnings=["SECRET_INDEX_WARNING_DO_NOT_EGRESS"],
    )
    config = config_factory(privacy={"redact_secrets": True, "fail_on_detected_secret": False})
    discovery = discover_repository(repository, config.repository, IgnoreMatcher())
    builder = ContextBuilder(
        discovery=discovery,
        repository_map=build_repository_map(discovery),
        repository_config=config.repository,
        privacy=config.privacy,
        scanner_findings=[],
        scanner_secret_paths={"src/Secret.sol"},
        solidity_index=index,
    )
    corpus = builder.build_retrieval_corpus()
    assert corpus is not None
    policy = SolidityRetrievalRolePolicy.build(role="source_audit")
    base = builder.build("source_audit")
    ordinary_render = render_context(base)
    assert base.solidity_retrieval_policy is None
    assert base.solidity_retrieval_transcript is None
    assert base.solidity_index is not None
    assert [item.id for item in base.solidity_index.entities] == [
        "fn-clean-child",
        "fn-safe",
    ]
    assert all(item.contract_name is None for item in base.solidity_index.entities)
    for forbidden in (
        "src/Secret.sol",
        "SECRET_SENTINEL_DO_NOT_EGRESS",
        "SECRET_INDEX_WARNING_DO_NOT_EGRESS",
        "SAFE_INDEX_DOCUMENTATION_MUST_BE_STRIPPED",
        "CLEAN_CHILD_DOCUMENTATION_MUST_BE_STRIPPED",
        secret_contract_name,
    ):
        assert forbidden not in ordinary_render

    planning = builder.bind_retrieval_context(
        base,
        policy=policy,
        corpus=corpus,
        byte_budget=config.repository.max_total_context_bytes,
    )
    planning_render = render_context(planning)
    assert '"phase": "planning"' in planning_render
    assert '"additional_requests_authorized": true' in planning_render
    assert tuple(item.subject_id for item in planning.solidity_retrieval_entities) == (
        "fn-clean-child",
        "fn-safe",
    )
    assert all(item.contract_name is None for item in planning.solidity_retrieval_entities)
    assert planning.solidity_index is not None
    assert [item.id for item in planning.solidity_index.entities] == [
        "fn-clean-child",
        "fn-safe",
    ]
    assert all(item.contract_name is None for item in planning.solidity_index.entities)
    for forbidden in (
        "src/Secret.sol",
        "SECRET_SENTINEL_DO_NOT_EGRESS",
        "SECRET_INDEX_WARNING_DO_NOT_EGRESS",
        "SAFE_INDEX_DOCUMENTATION_MUST_BE_STRIPPED",
        "synthetic.compiler_ast",
        "CLEAN_CHILD_DOCUMENTATION_MUST_BE_STRIPPED",
        secret_contract_name,
    ):
        assert forbidden not in planning_render

    final = builder.bind_retrieval_context(
        planning,
        policy=policy,
        corpus=corpus,
        transcript=start_solidity_retrieval_transcript(corpus=corpus, policy=policy),
        byte_budget=config.repository.max_total_context_bytes,
    )
    final_render = render_context(final)
    assert '"phase": "results_final"' in final_render
    assert '"additional_requests_authorized": false' in final_render
    assert secret_contract_name not in final_render
