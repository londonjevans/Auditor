from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from mmaudit.models.retrieval import (
    SolidityRetrievalEntity,
    SolidityRetrievalEntityKind,
    SolidityRetrievalExchange,
    SolidityRetrievalOmission,
    SolidityRetrievalOperation,
    SolidityRetrievalReason,
    SolidityRetrievalRecord,
    SolidityRetrievalRequest,
    SolidityRetrievalResult,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalStatus,
    SolidityRetrievalTranscript,
)
from mmaudit.models.schemas import ContextPackage, ContextRequestEvidence, RepositoryMap
from mmaudit.orchestration.context import (
    context_category_byte_counts,
    render_context,
    revalidate_context_package,
)


def _repository_map() -> RepositoryMap:
    return RepositoryMap(
        root_name="synthetic-retrieval-evidence",
        languages={"Solidity": 1},
        frameworks=[],
        manifests=[],
        entry_points=[],
        api_surfaces=[],
        auth_components=[],
        data_layers=[],
        network_clients=[],
        file_handlers=[],
        configuration_files=[],
        sensitive_processing=[],
        security_tests=[],
        files=[],
        omitted_files=[],
    )


def _ordinary_package() -> ContextPackage:
    package = ContextPackage(
        role="source_audit",
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=20_000,
        effective_source_byte_ceiling=0,
        repository_map=_repository_map(),
        scanner_findings=(),
        excerpts=(),
    )
    return package.model_copy(update={"bytes_used": len(render_context(package).encode("utf-8"))})


def _retrieval_exchange(
    *,
    sequence: int,
    previous_exchange_sha256: str | None,
    subject_id: str,
    content: str | None,
) -> SolidityRetrievalExchange:
    operation = (
        SolidityRetrievalOperation.FETCH_INDEXED_RANGE
        if content is not None
        else SolidityRetrievalOperation.RESOLVE_ENTITY
    )
    request = SolidityRetrievalRequest.build(operation=operation, subject_id=subject_id)
    if content is None:
        result = SolidityRetrievalResult.build(
            request=request,
            status=SolidityRetrievalStatus.UNAVAILABLE,
            omissions=(
                SolidityRetrievalOmission(
                    reason=SolidityRetrievalReason.UNINDEXED_SUBJECT,
                    count=1,
                ),
            ),
        )
    else:
        entity = SolidityRetrievalEntity(
            subject_id=subject_id,
            kind=SolidityRetrievalEntityKind.CONTRACT,
            name="Synthetic",
            path="src/Synthetic.sol",
            start_line=1,
            end_line=1,
            source_hash=hashlib.sha256(content.encode("utf-8")).hexdigest(),
            payable=False,
        )
        result = SolidityRetrievalResult.build(
            request=request,
            status=SolidityRetrievalStatus.COMPLETE,
            records=(SolidityRetrievalRecord(entity=entity, content=content),),
        )
    return SolidityRetrievalExchange.build(
        sequence=sequence,
        previous_exchange_sha256=previous_exchange_sha256,
        request=request,
        result=result,
    )


def _retrieval_package() -> tuple[
    ContextPackage,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalTranscript,
]:
    content = "contract Synthetic {}\n"
    policy = SolidityRetrievalRolePolicy.build(role="source_audit")
    exchange = _retrieval_exchange(
        sequence=1,
        previous_exchange_sha256=None,
        subject_id="sol-synthetic",
        content=content,
    )
    transcript = SolidityRetrievalTranscript.build(
        role="source_audit",
        policy_sha256=policy.policy_sha256,
        corpus_sha256="a" * 64,
        exchanges=(exchange,),
        accepted_request_count=1,
    )
    package = ContextPackage(
        role="source_audit",
        byte_budget=100_000,
        bytes_used=0,
        configured_maximum_source_tokens_per_request=20_000,
        effective_source_byte_ceiling=60_000,
        repository_map=_repository_map(),
        scanner_findings=(),
        excerpts=(),
        solidity_retrieval_policy=policy,
        solidity_retrieval_corpus_sha256=transcript.corpus_sha256,
        solidity_retrieval_transcript=transcript,
    )
    package = package.model_copy(
        update={"bytes_used": len(render_context(package).encode("utf-8"))}
    )
    return package, policy, transcript


def test_ordinary_v1_context_evidence_preserves_legacy_serialization() -> None:
    package = _ordinary_package()
    assert not any("retrieval" in key for key in package.model_dump(mode="json"))
    assert "<VALIDATED_SOLIDITY_RETRIEVAL_" not in render_context(package)

    legacy_payload = {
        "schema_version": "1.0",
        "request_id": "synthetic-request",
        "request_role": "source_audit",
        "context_role": "source_audit",
        "relationship": "exact",
        "byte_budget": package.byte_budget,
        "declared_bytes_used": package.bytes_used,
        "rendered_bytes": package.bytes_used,
        "source_bytes": 0,
        "configured_maximum_source_tokens_per_request": (
            package.configured_maximum_source_tokens_per_request
        ),
        "effective_source_byte_ceiling": package.effective_source_byte_ceiling,
        "rendered_sha256": hashlib.sha256(render_context(package).encode("utf-8")).hexdigest(),
    }
    expected_sha256 = hashlib.sha256(
        json.dumps(
            legacy_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    evidence = ContextRequestEvidence.build(
        request_id="synthetic-request",
        request_role="source_audit",
        context_role="source_audit",
        byte_budget=package.byte_budget,
        declared_bytes_used=package.bytes_used,
        rendered_bytes=package.bytes_used,
        source_bytes=0,
        configured_maximum_source_tokens_per_request=(
            package.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=package.effective_source_byte_ceiling,
        rendered_sha256=legacy_payload["rendered_sha256"],
    )

    assert evidence.model_dump(mode="json", exclude={"evidence_sha256"}) == legacy_payload
    assert evidence.evidence_sha256 == expected_sha256


def test_retrieved_source_counts_against_source_ceiling_and_exact_hash_custody() -> None:
    package, policy, transcript = _retrieval_package()
    content = transcript.exchanges[0].result.records[0].content
    assert content is not None
    assert package.delivered_source_bytes() == len(content.encode("utf-8"))
    assert revalidate_context_package(package) == package

    categories = context_category_byte_counts(package)
    assert categories["source"] == package.delivered_source_bytes()
    assert categories["workflow"] > 0
    assert sum(categories.values()) == package.bytes_used

    evidence = ContextRequestEvidence.build(
        request_id="synthetic-request",
        request_role="source_audit",
        context_role=package.role,
        byte_budget=package.byte_budget,
        declared_bytes_used=package.bytes_used,
        rendered_bytes=package.bytes_used,
        source_bytes=package.delivered_source_bytes(),
        configured_maximum_source_tokens_per_request=(
            package.configured_maximum_source_tokens_per_request
        ),
        effective_source_byte_ceiling=package.effective_source_byte_ceiling,
        rendered_sha256=hashlib.sha256(render_context(package).encode("utf-8")).hexdigest(),
        retrieval_policy=policy,
        retrieval_corpus_sha256=transcript.corpus_sha256,
        retrieval_transcript=transcript,
    )
    assert evidence.schema_version == "1.1"
    assert evidence.retrieval_transcript_sha256 == transcript.transcript_sha256
    assert evidence.retrieval_request_sha256s == (transcript.exchanges[0].request.request_sha256,)
    assert evidence.retrieval_result_sha256s == (transcript.exchanges[0].result.result_sha256,)
    assert evidence.retrieval_exchange_sha256s == (transcript.exchanges[0].exchange_sha256,)


def test_context_request_evidence_rejects_partial_transcript_coordinates() -> None:
    package = _ordinary_package()
    payload = {
        "schema_version": "1.0",
        "request_id": "synthetic-request",
        "request_role": "source_audit",
        "context_role": "source_audit",
        "relationship": "exact",
        "byte_budget": package.byte_budget,
        "declared_bytes_used": package.bytes_used,
        "rendered_bytes": package.bytes_used,
        "source_bytes": 0,
        "configured_maximum_source_tokens_per_request": (
            package.configured_maximum_source_tokens_per_request
        ),
        "effective_source_byte_ceiling": package.effective_source_byte_ceiling,
        "rendered_sha256": hashlib.sha256(render_context(package).encode("utf-8")).hexdigest(),
        "retrieval_exhausted": False,
    }
    evidence_sha256 = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    with pytest.raises(ValidationError, match="transcript coordinates are incomplete"):
        ContextRequestEvidence.model_validate({**payload, "evidence_sha256": evidence_sha256})


def test_context_rejects_transcript_exceeding_its_narrowed_policy() -> None:
    policy = SolidityRetrievalRolePolicy.build(role="source_audit", maximum_requests=1)
    first = _retrieval_exchange(
        sequence=1,
        previous_exchange_sha256=None,
        subject_id="missing-one",
        content=None,
    )
    second = _retrieval_exchange(
        sequence=2,
        previous_exchange_sha256=first.exchange_sha256,
        subject_id="missing-two",
        content=None,
    )
    transcript = SolidityRetrievalTranscript.build(
        role="source_audit",
        policy_sha256=policy.policy_sha256,
        corpus_sha256="a" * 64,
        exchanges=(first, second),
        accepted_request_count=2,
    )

    with pytest.raises(ValidationError, match="exceeds its exact role policy"):
        ContextPackage(
            role="source_audit",
            byte_budget=100_000,
            bytes_used=0,
            configured_maximum_source_tokens_per_request=20_000,
            effective_source_byte_ceiling=0,
            repository_map=_repository_map(),
            scanner_findings=(),
            excerpts=(),
            solidity_retrieval_policy=policy,
            solidity_retrieval_corpus_sha256=transcript.corpus_sha256,
            solidity_retrieval_transcript=transcript,
        )
