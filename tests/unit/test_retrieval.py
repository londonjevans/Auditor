from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

import pytest
from pydantic import ValidationError

from mmaudit.models.retrieval import (
    SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS,
    SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES,
    SolidityRetrievalEntityKind,
    SolidityRetrievalIntent,
    SolidityRetrievalOperation,
    SolidityRetrievalReason,
    SolidityRetrievalRequest,
    SolidityRetrievalRequestBatch,
    SolidityRetrievalRolePolicy,
    SolidityRetrievalStatus,
    SolidityRetrievalTranscript,
    solidity_retrieval_transcript_utf8_bytes,
)
from mmaudit.models.schemas import (
    SolidityEntity,
    SolidityEntityKind,
    SolidityGraphEdge,
    SolidityGraphKind,
    SolidityGraphOccurrenceKind,
    SolidityGraphOmission,
    SolidityGraphRetainedOccurrence,
    SolidityGraphSet,
    SolidityProvenance,
    SoliditySymbolIndex,
    solidity_graph_occurrence_sha256,
)
from mmaudit.solidity.retrieval import (
    SolidityRetrievalAccessStatus,
    SolidityRetrievalCorpus,
    SolidityRetrievalSecretInterval,
    build_solidity_retrieval_corpus,
    execute_solidity_retrieval,
    execute_solidity_retrieval_batch,
    start_solidity_retrieval_transcript,
    validate_solidity_retrieval_replay,
)

_MAIN_PATH = "src/Vault.sol"
_OUTSIDE_PATH = "lib/Outside.sol"
_WITHHELD_PATH = "private/Withheld.sol"
_MAIN_SOURCE = (
    "pragma solidity ^0.8.20;\n"
    "contract Vault {\n"
    "uint256 public balance;\n"
    "function target() internal {}\n"
    "function caller() internal { target(); }\n"
    "function writer() internal { balance = 1; target(); }\n"
    'string private credential = "secret-value";\n'
    "}\n"
)
_REDACTED_MAIN_SOURCE = _MAIN_SOURCE.replace("secret-value", "[REDACTED]")
_OUTSIDE_SOURCE = "contract Outside { function excluded() external {} }\n"
_WITHHELD_SOURCE = "contract Withheld { function hidden() external {} }\n"


def _line_range(content: str, line: int) -> str:
    return content.splitlines(keepends=True)[line - 1]


def _range_hash(content: str, line: int) -> str:
    return hashlib.sha256(_line_range(content, line).encode("utf-8")).hexdigest()


def _entity(
    *,
    subject_id: str,
    kind: SolidityEntityKind,
    name: str,
    path: str,
    line: int,
    content: str,
) -> SolidityEntity:
    return SolidityEntity(
        id=subject_id,
        kind=kind,
        name=name,
        contract_name="Vault" if path == _MAIN_PATH else "Outside",
        path=path,
        start_line=line,
        end_line=line,
        byte_start=0,
        byte_end=1,
        source_hash=_range_hash(content, line),
        provenance=SolidityProvenance.COMPILER,
        confidence=1.0,
        transformation="synthetic.compiler_ast",
        visibility="public" if kind is SolidityEntityKind.STATE_VARIABLE else "internal",
        mutability="nonpayable",
        documentation="DO_NOT_LEAK_ENTITY_DOCUMENTATION",
    )


def _edge(
    *,
    graph: SolidityGraphKind,
    source_id: str,
    target_id: str,
    line: int,
) -> SolidityGraphEdge:
    return SolidityGraphEdge(
        graph=graph,
        source_id=source_id,
        target_id=target_id,
        label="DO_NOT_LEAK_GRAPH_LABEL",
        provenance=SolidityProvenance.COMPILER,
        path=_MAIN_PATH,
        start_line=line,
        end_line=line,
        source_hash=_range_hash(_MAIN_SOURCE, line),
        confidence=1.0,
        transformation="synthetic.compiler_ast",
        metadata={"private_note": "DO_NOT_LEAK_GRAPH_METADATA"},
    )


def _retained_occurrences(
    edges: Sequence[SolidityGraphEdge],
    warnings: Sequence[str],
) -> tuple[SolidityGraphRetainedOccurrence, ...]:
    occurrences = [
        SolidityGraphRetainedOccurrence(
            subject_kind=SolidityGraphOccurrenceKind.EDGE,
            subject_sha256=solidity_graph_occurrence_sha256(
                SolidityGraphOccurrenceKind.EDGE,
                edge,
            ),
            occurrence_count=1,
        )
        for edge in edges
    ]
    occurrences.extend(
        SolidityGraphRetainedOccurrence(
            subject_kind=SolidityGraphOccurrenceKind.WARNING,
            subject_sha256=solidity_graph_occurrence_sha256(
                SolidityGraphOccurrenceKind.WARNING,
                warning,
            ),
            occurrence_count=1,
        )
        for warning in warnings
    )
    return tuple(
        sorted(
            occurrences,
            key=lambda item: (item.subject_kind.value, item.subject_sha256),
        )
    )


def _index() -> SoliditySymbolIndex:
    return SoliditySymbolIndex(
        projects=[],
        entities=[
            _entity(
                subject_id="fn-target",
                kind=SolidityEntityKind.FUNCTION,
                name="target",
                path=_MAIN_PATH,
                line=4,
                content=_MAIN_SOURCE,
            ),
            _entity(
                subject_id="fn-caller",
                kind=SolidityEntityKind.FUNCTION,
                name="caller",
                path=_MAIN_PATH,
                line=5,
                content=_MAIN_SOURCE,
            ),
            _entity(
                subject_id="state-balance",
                kind=SolidityEntityKind.STATE_VARIABLE,
                name="balance",
                path=_MAIN_PATH,
                line=3,
                content=_MAIN_SOURCE,
            ),
            _entity(
                subject_id="fn-writer",
                kind=SolidityEntityKind.FUNCTION,
                name="writer",
                path=_MAIN_PATH,
                line=6,
                content=_MAIN_SOURCE,
            ),
            _entity(
                subject_id="state-secret",
                kind=SolidityEntityKind.STATE_VARIABLE,
                name="credential",
                path=_MAIN_PATH,
                line=7,
                content=_MAIN_SOURCE,
            ),
            _entity(
                subject_id="fn-outside",
                kind=SolidityEntityKind.FUNCTION,
                name="excluded",
                path=_OUTSIDE_PATH,
                line=1,
                content=_OUTSIDE_SOURCE,
            ),
        ],
    )


def _graphs(*, partial_internal_calls: bool = False) -> SolidityGraphSet:
    edges = [
        _edge(
            graph=SolidityGraphKind.INTERNAL_CALL,
            source_id="fn-caller",
            target_id="fn-target",
            line=5,
        ),
        _edge(
            graph=SolidityGraphKind.INTERNAL_CALL,
            source_id="fn-writer",
            target_id="fn-target",
            line=6,
        ),
        _edge(
            graph=SolidityGraphKind.STATE_WRITE,
            source_id="fn-writer",
            target_id="state-balance",
            line=6,
        ),
    ]
    warnings = ["DO_NOT_LEAK_GRAPH_WARNING"]
    omissions: tuple[SolidityGraphOmission, ...] = ()
    analyzed_graphs = [SolidityGraphKind.INTERNAL_CALL, SolidityGraphKind.STATE_WRITE]
    if partial_internal_calls:
        omissions = (
            SolidityGraphOmission.build(
                graph=SolidityGraphKind.INTERNAL_CALL,
                candidate_count=3,
                retained_count=2,
                retained_occurrence_count=2,
                omitted_count=1,
                omitted_canonical_bytes=100,
                omitted_stream_sha256=hashlib.sha256(b"omitted-edge").hexdigest(),
                omitted_sample_sha256s=(hashlib.sha256(b"sample-edge").hexdigest(),),
            ),
        )
        analyzed_graphs = [SolidityGraphKind.STATE_WRITE]
    return SolidityGraphSet(
        edges=edges,
        retained_occurrences=_retained_occurrences(edges, warnings),
        analyzed_graphs=analyzed_graphs,
        coverage={
            SolidityGraphKind.INTERNAL_CALL.value: 2,
            SolidityGraphKind.STATE_WRITE.value: 1,
        },
        warnings=warnings,
        generation_complete=not partial_internal_calls,
        edge_omissions=omissions,
    )


def _sources() -> tuple[Mapping[str, str], Mapping[str, str]]:
    return (
        {_MAIN_PATH: _MAIN_SOURCE, _OUTSIDE_PATH: _OUTSIDE_SOURCE},
        {_MAIN_PATH: _REDACTED_MAIN_SOURCE, _OUTSIDE_PATH: _OUTSIDE_SOURCE},
    )


def _corpus(
    *,
    graphs: SolidityGraphSet | None = None,
    secret_intervals: Sequence[SolidityRetrievalSecretInterval] | None = None,
    redacted_sources: Mapping[str, str] | None = None,
) -> SolidityRetrievalCorpus:
    originals, default_redacted = _sources()
    return build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted_sources or default_redacted,
        secret_tainted_intervals=(
            [
                SolidityRetrievalSecretInterval(
                    path=_MAIN_PATH,
                    start_line=7,
                    end_line=7,
                )
            ]
            if secret_intervals is None
            else secret_intervals
        ),
        index=_index(),
        graphs=_graphs() if graphs is None else graphs,
        allowed_paths=[_MAIN_PATH],
    )


def _execute(
    corpus: SolidityRetrievalCorpus,
    transcript: SolidityRetrievalTranscript,
    policy: SolidityRetrievalRolePolicy,
    operation: SolidityRetrievalOperation,
    subject_id: str,
) -> SolidityRetrievalTranscript:
    return execute_solidity_retrieval(
        corpus=corpus,
        policy=policy,
        transcript=transcript,
        request=SolidityRetrievalRequest.build(operation=operation, subject_id=subject_id),
    )


def test_corpus_retains_only_hash_bound_redacted_safe_projections() -> None:
    corpus = _corpus()

    access = {item.subject_id: item.status for item in corpus.subject_access}
    assert access["state-secret"] is SolidityRetrievalAccessStatus.REDACTED_OR_SECRET
    assert access["fn-outside"] is SolidityRetrievalAccessStatus.OUT_OF_SCOPE
    assert {entity.subject_id for entity in corpus.entities} == {
        "fn-caller",
        "fn-target",
        "fn-writer",
        "state-balance",
    }
    assert all(record.content is not None for record in corpus.indexed_ranges)
    assert corpus.scope.scope_sha256
    assert corpus.corpus_sha256

    serialized = json.dumps(corpus.model_dump(mode="json"), sort_keys=True)
    assert "secret-value" not in serialized
    assert "[REDACTED]" not in serialized
    assert "DO_NOT_LEAK_ENTITY_DOCUMENTATION" not in serialized
    assert "DO_NOT_LEAK_GRAPH_LABEL" not in serialized
    assert "DO_NOT_LEAK_GRAPH_METADATA" not in serialized
    assert "DO_NOT_LEAK_GRAPH_WARNING" not in serialized
    assert "original_sources" not in serialized
    assert "redacted_sources" not in serialized

    with pytest.raises(ValidationError, match="frozen"):
        corpus.corpus_sha256 = "0" * 64  # type: ignore[misc]


def test_request_is_only_a_fixed_operation_and_opaque_subject_id() -> None:
    request = SolidityRetrievalRequest.build(
        operation=SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
        subject_id="fn-target",
    )

    assert set(request.model_dump()) == {
        "schema_version",
        "operation",
        "subject_id",
        "request_sha256",
    }
    with pytest.raises(ValidationError, match="Extra inputs"):
        SolidityRetrievalRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "path": _MAIN_PATH,
                "start_line": 1,
            }
        )


@pytest.mark.parametrize(
    "subject_id",
    [
        "src/Vault.sol",
        r"src\Vault.sol",
        "fn-*",
        "fn-?",
        "fn-[abc]",
        "fn target",
        "fn-target;rm",
        "$(command)",
        "fn-target|command",
        "../target",
        "-leading-dash",
    ],
)
def test_wire_intent_rejects_path_glob_shell_and_free_form_subjects(subject_id: str) -> None:
    with pytest.raises(ValidationError, match="opaque bounded ASCII identifier"):
        SolidityRetrievalIntent(
            operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
            subject_id=subject_id,
        )


def test_hash_free_wire_batch_is_ordered_unique_and_host_hashes_requests() -> None:
    first = SolidityRetrievalIntent(
        operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
        subject_id="fn-target",
    )
    second = SolidityRetrievalIntent(
        operation=SolidityRetrievalOperation.LIST_CALLERS,
        subject_id="fn-target",
    )
    empty = SolidityRetrievalRequestBatch(requests=())
    batch = SolidityRetrievalRequestBatch(requests=(first, second))

    assert empty.requests == ()
    assert set(batch.model_dump()) == {"schema_version", "requests"}
    assert "sha256" not in json.dumps(SolidityRetrievalRequestBatch.model_json_schema())
    assert [request.operation for request in batch.to_host_requests()] == [
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        SolidityRetrievalOperation.LIST_CALLERS,
    ]
    assert all(request.request_sha256 for request in batch.to_host_requests())
    with pytest.raises(ValidationError, match="identities must be unique"):
        SolidityRetrievalRequestBatch(requests=(first, first))
    with pytest.raises(ValidationError):
        SolidityRetrievalRequestBatch(requests=(first,) * 9)
    with pytest.raises(ValidationError, match="Extra inputs"):
        SolidityRetrievalRequestBatch.model_validate(
            {"schema_version": "1.0", "requests": (), "batch_sha256": "0" * 64}
        )


def test_role_policy_has_fixed_conservative_ceilings_and_review_roles_only() -> None:
    policy = SolidityRetrievalRolePolicy.build(role="source_audit")
    assert (
        policy.maximum_requests,
        policy.maximum_results_per_request,
        policy.maximum_result_utf8_bytes,
        policy.maximum_total_result_utf8_bytes,
        policy.maximum_total_result_tokens,
    ) == (4, 16, 8_192, 16_384, 5_462)
    assert SolidityRetrievalRolePolicy.build(role="threat_model").role == "threat_model"
    assert (
        SolidityRetrievalRolePolicy.build(
            role="whole_protocol_review:0",
            maximum_requests=1,
        ).maximum_requests
        == 1
    )
    with pytest.raises(ValidationError):
        SolidityRetrievalRolePolicy.build(role="source_audit", maximum_requests=5)
    with pytest.raises(ValidationError, match="supported review role"):
        SolidityRetrievalRolePolicy.build(role="judge")


def test_role_policy_allows_only_exact_zero_fallback_and_fixed_transcript_envelope() -> None:
    fallback = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=0,
        maximum_total_result_utf8_bytes=0,
        maximum_total_result_tokens=0,
    )
    assert (
        fallback.maximum_requests,
        fallback.maximum_total_result_utf8_bytes,
        fallback.maximum_total_result_tokens,
    ) == (0, 0, 0)
    assert fallback.maximum_transcript_utf8_bytes == SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES
    assert fallback.maximum_transcript_tokens == SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS

    for update in (
        {"maximum_requests": 0},
        {"maximum_total_result_utf8_bytes": 0},
        {"maximum_total_result_tokens": 0},
    ):
        with pytest.raises(ValidationError, match="must be allocated together"):
            SolidityRetrievalRolePolicy.build(role="source_audit", **update)
    with pytest.raises(ValidationError):
        SolidityRetrievalRolePolicy.build(
            role="source_audit",
            maximum_transcript_utf8_bytes=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_UTF8_BYTES - 1,
        )
    with pytest.raises(ValidationError):
        SolidityRetrievalRolePolicy.build(
            role="source_audit",
            maximum_transcript_tokens=SOLIDITY_RETRIEVAL_MAX_TRANSCRIPT_TOKENS - 1,
        )


def test_zero_role_allocation_records_every_intent_as_typed_exhaustion() -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_requests=0,
        maximum_total_result_utf8_bytes=0,
        maximum_total_result_tokens=0,
    )
    batch = SolidityRetrievalRequestBatch(
        requests=tuple(
            SolidityRetrievalIntent(
                operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
                subject_id=f"surplus-{index}",
            )
            for index in range(8)
        )
    )

    transcript = execute_solidity_retrieval_batch(
        corpus=corpus,
        policy=policy,
        transcript=start_solidity_retrieval_transcript(corpus=corpus, policy=policy),
        batch=batch,
    )

    assert len(transcript.exchanges) == 8
    assert transcript.accepted_request_count == 0
    assert transcript.retrieval_exhausted is True
    assert transcript.single_shot_fallback_required is True
    assert transcript.exchanges[0].result.omissions[0].reason is (
        SolidityRetrievalReason.REQUEST_COUNT_BUDGET
    )
    assert all(
        exchange.result.omissions[0].reason is SolidityRetrievalReason.RETRIEVAL_ALREADY_EXHAUSTED
        for exchange in transcript.exchanges[1:]
    )
    assert (
        solidity_retrieval_transcript_utf8_bytes(transcript) <= policy.maximum_transcript_utf8_bytes
    )
    assert (
        validate_solidity_retrieval_replay(
            corpus=corpus,
            policy=policy,
            transcript=transcript,
        )
        == transcript
    )


def test_all_fixed_operations_use_target_to_source_graph_semantics() -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(role="specialist:source_audit")
    transcript = start_solidity_retrieval_transcript(corpus=corpus, policy=policy)
    assert transcript.exchanges == ()
    assert transcript.retrieval_exhausted is False
    assert transcript.single_shot_fallback_required is True

    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-target",
    )
    resolved = transcript.exchanges[-1].result
    assert resolved.status is SolidityRetrievalStatus.COMPLETE
    assert resolved.records[0].entity.name == "target"
    assert resolved.records[0].entity.kind is SolidityRetrievalEntityKind.FUNCTION
    assert "documentation" not in resolved.records[0].entity.model_dump()

    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
        "fn-target",
    )
    fetched = transcript.exchanges[-1].result
    assert fetched.records[0].content == _line_range(_MAIN_SOURCE, 4)

    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.LIST_CALLERS,
        "fn-target",
    )
    callers = transcript.exchanges[-1].result
    assert [record.entity.subject_id for record in callers.records] == [
        "fn-caller",
        "fn-writer",
    ]

    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.LIST_CALLERS,
        "fn-caller",
    )
    assert transcript.exchanges[-1].result.records == ()

    transcript = start_solidity_retrieval_transcript(corpus=corpus, policy=policy)
    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.LIST_STATE_WRITERS,
        "state-balance",
    )
    writers = transcript.exchanges[-1].result
    assert [record.entity.subject_id for record in writers.records] == ["fn-writer"]


@pytest.mark.parametrize(
    ("subject_id", "reason"),
    [
        ("missing-subject", SolidityRetrievalReason.UNINDEXED_SUBJECT),
        ("state-secret", SolidityRetrievalReason.REDACTED_OR_SECRET_SUBJECT),
        ("fn-outside", SolidityRetrievalReason.OUT_OF_SCOPE_SUBJECT),
    ],
)
def test_refused_subjects_are_typed_and_recorded(
    subject_id: str,
    reason: SolidityRetrievalReason,
) -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(role="specialist:source_audit")
    transcript = start_solidity_retrieval_transcript(corpus=corpus, policy=policy)

    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        subject_id,
    )

    result = transcript.exchanges[-1].result
    assert result.status is SolidityRetrievalStatus.REFUSED
    assert result.records == ()
    assert [(item.reason, item.count) for item in result.omissions] == [(reason, 1)]
    assert transcript.accepted_request_count == 1


def test_redaction_mismatch_or_explicit_secret_taint_each_blocks_content() -> None:
    originals, redacted = _sources()
    mismatch_only = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted,
        secret_tainted_intervals=[],
        index=_index(),
        graphs=_graphs(),
        allowed_paths=[_MAIN_PATH],
    )
    explicit_taint_only = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=originals,
        secret_tainted_intervals=[
            SolidityRetrievalSecretInterval(path=_MAIN_PATH, start_line=7, end_line=7)
        ],
        index=_index(),
        graphs=_graphs(),
        allowed_paths=[_MAIN_PATH],
    )
    secret_and_out_of_scope = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted,
        secret_tainted_intervals=[
            SolidityRetrievalSecretInterval(path=_MAIN_PATH, start_line=7, end_line=7)
        ],
        index=_index(),
        graphs=_graphs(),
        allowed_paths=[_OUTSIDE_PATH],
    )

    for corpus in (mismatch_only, explicit_taint_only, secret_and_out_of_scope):
        access = {item.subject_id: item.status for item in corpus.subject_access}
        assert access["state-secret"] is SolidityRetrievalAccessStatus.REDACTED_OR_SECRET
        assert "state-secret" not in {item.entity.subject_id for item in corpus.indexed_ranges}


def test_invalid_original_entity_hash_fails_corpus_construction() -> None:
    originals, redacted = _sources()
    index = _index()
    bad_entity = index.entities[0].model_copy(update={"source_hash": "0" * 64})
    bad_index = index.model_copy(update={"entities": [bad_entity, *index.entities[1:]]})

    with pytest.raises(ValueError, match="range hash differs"):
        build_solidity_retrieval_corpus(
            original_sources=originals,
            redacted_sources=redacted,
            secret_tainted_intervals=[],
            index=bad_index,
            graphs=_graphs(),
        )


def test_wholly_withheld_indexed_path_is_secret_without_source_retention() -> None:
    originals, redacted = _sources()
    index = _index()
    withheld_entity = _entity(
        subject_id="fn-withheld",
        kind=SolidityEntityKind.FUNCTION,
        name="hidden",
        path=_WITHHELD_PATH,
        line=1,
        content=_WITHHELD_SOURCE,
    )
    withheld_index = index.model_copy(update={"entities": [*index.entities, withheld_entity]})
    corpus = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted,
        secret_tainted_intervals=[],
        index=withheld_index,
        graphs=_graphs(),
        withheld_paths=[_WITHHELD_PATH],
    )

    access = {item.subject_id: item.status for item in corpus.subject_access}
    assert access["fn-withheld"] is SolidityRetrievalAccessStatus.REDACTED_OR_SECRET
    assert corpus.withheld_path_count == 1
    assert _WITHHELD_PATH not in {binding.path for binding in corpus.source_bindings}
    assert _WITHHELD_PATH not in json.dumps(corpus.model_dump(mode="json"), sort_keys=True)

    policy = SolidityRetrievalRolePolicy.build(role="source_audit")
    transcript = _execute(
        corpus,
        start_solidity_retrieval_transcript(corpus=corpus, policy=policy),
        policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-withheld",
    )
    assert transcript.exchanges[-1].result.omissions[0].reason is (
        SolidityRetrievalReason.REDACTED_OR_SECRET_SUBJECT
    )

    with pytest.raises(ValueError, match="absent from exact source mappings"):
        build_solidity_retrieval_corpus(
            original_sources=originals,
            redacted_sources=redacted,
            secret_tainted_intervals=[],
            index=withheld_index,
            graphs=_graphs(),
        )


def test_graph_omission_is_partial_and_absent_graph_is_unavailable() -> None:
    originals, redacted = _sources()
    partial = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted,
        secret_tainted_intervals=[],
        index=_index(),
        graphs=_graphs(partial_internal_calls=True),
    )
    unavailable = build_solidity_retrieval_corpus(
        original_sources=originals,
        redacted_sources=redacted,
        secret_tainted_intervals=[],
        index=_index(),
        graphs=None,
    )
    policy = SolidityRetrievalRolePolicy.build(role="specialist:source_audit")

    partial_transcript = _execute(
        partial,
        start_solidity_retrieval_transcript(corpus=partial, policy=policy),
        policy,
        SolidityRetrievalOperation.LIST_CALLERS,
        "fn-target",
    )
    partial_result = partial_transcript.exchanges[-1].result
    assert partial_result.status is SolidityRetrievalStatus.PARTIAL
    assert SolidityRetrievalReason.UPSTREAM_GRAPH_OMISSION in {
        item.reason for item in partial_result.omissions
    }

    unavailable_transcript = _execute(
        unavailable,
        start_solidity_retrieval_transcript(corpus=unavailable, policy=policy),
        policy,
        SolidityRetrievalOperation.LIST_CALLERS,
        "fn-target",
    )
    unavailable_result = unavailable_transcript.exchanges[-1].result
    assert unavailable_result.status is SolidityRetrievalStatus.UNAVAILABLE
    assert unavailable_result.omissions[0].reason is SolidityRetrievalReason.GRAPH_UNAVAILABLE


def test_deterministic_item_cap_yields_partial_prefix() -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(
        role="specialist:source_audit",
        maximum_results_per_request=1,
    )
    transcript = _execute(
        corpus,
        start_solidity_retrieval_transcript(corpus=corpus, policy=policy),
        policy,
        SolidityRetrievalOperation.LIST_CALLERS,
        "fn-target",
    )

    result = transcript.exchanges[-1].result
    assert result.status is SolidityRetrievalStatus.PARTIAL
    assert [record.entity.subject_id for record in result.records] == ["fn-caller"]
    assert [(item.reason, item.count) for item in result.omissions] == [
        (SolidityRetrievalReason.RESULT_ITEM_LIMIT, 1)
    ]


def test_budget_exhaustion_is_a_terminal_recorded_event_without_an_exception() -> None:
    corpus = _corpus()
    tiny_result_policy = SolidityRetrievalRolePolicy.build(
        role="specialist:source_audit",
        maximum_result_utf8_bytes=1,
    )
    transcript = start_solidity_retrieval_transcript(
        corpus=corpus,
        policy=tiny_result_policy,
    )
    exhausted = _execute(
        corpus,
        transcript,
        tiny_result_policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-target",
    )
    result = exhausted.exchanges[-1].result
    assert result.status is SolidityRetrievalStatus.EXHAUSTED
    assert result.omissions[0].reason is SolidityRetrievalReason.RESULT_UTF8_LIMIT
    assert exhausted.retrieval_exhausted is True
    assert exhausted.single_shot_fallback_required is True

    ignored_after_terminal = _execute(
        corpus,
        exhausted,
        tiny_result_policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-caller",
    )
    assert len(ignored_after_terminal.exchanges) == 2
    assert ignored_after_terminal.accepted_request_count == 1
    assert ignored_after_terminal.exchanges[-1].result.omissions[0].reason is (
        SolidityRetrievalReason.RETRIEVAL_ALREADY_EXHAUSTED
    )

    one_request_policy = SolidityRetrievalRolePolicy.build(
        role="specialist:source_audit",
        maximum_requests=1,
    )
    one_request = start_solidity_retrieval_transcript(
        corpus=corpus,
        policy=one_request_policy,
    )
    one_request = _execute(
        corpus,
        one_request,
        one_request_policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-target",
    )
    one_request = _execute(
        corpus,
        one_request,
        one_request_policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-caller",
    )
    request_exhaustion = one_request.exchanges[-1].result
    assert request_exhaustion.status is SolidityRetrievalStatus.EXHAUSTED
    assert request_exhaustion.omissions[0].reason is SolidityRetrievalReason.REQUEST_COUNT_BUDGET
    assert one_request.accepted_request_count == 1

    one_token_policy = SolidityRetrievalRolePolicy.build(
        role="source_audit",
        maximum_total_result_tokens=1,
    )
    token_exhaustion = _execute(
        corpus,
        start_solidity_retrieval_transcript(corpus=corpus, policy=one_token_policy),
        one_token_policy,
        SolidityRetrievalOperation.RESOLVE_ENTITY,
        "fn-target",
    )
    assert token_exhaustion.exchanges[-1].result.omissions[0].reason is (
        SolidityRetrievalReason.TOTAL_RESULT_TOKEN_BUDGET
    )
    token_batch = SolidityRetrievalRequestBatch(
        requests=tuple(
            SolidityRetrievalIntent(
                operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
                subject_id=subject_id,
            )
            for subject_id in ("fn-target", "fn-caller", "fn-writer")
        )
    )
    token_batch_transcript = execute_solidity_retrieval_batch(
        corpus=corpus,
        policy=one_token_policy,
        transcript=start_solidity_retrieval_transcript(corpus=corpus, policy=one_token_policy),
        batch=token_batch,
    )
    assert len(token_batch_transcript.exchanges) == 3
    assert token_batch_transcript.accepted_request_count == 1
    assert all(
        exchange.result.status is SolidityRetrievalStatus.EXHAUSTED
        for exchange in token_batch_transcript.exchanges
    )


def test_eight_intent_batch_records_four_accepted_and_four_exhausted_exchanges() -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(role="source_audit")
    intents = tuple(
        SolidityRetrievalIntent(
            operation=SolidityRetrievalOperation.RESOLVE_ENTITY,
            subject_id=f"missing-{index}",
        )
        for index in range(8)
    )
    batch = SolidityRetrievalRequestBatch(requests=intents)

    transcript = execute_solidity_retrieval_batch(
        corpus=corpus,
        policy=policy,
        transcript=start_solidity_retrieval_transcript(corpus=corpus, policy=policy),
        batch=batch,
    )

    assert len(transcript.exchanges) == 8
    assert transcript.accepted_request_count == 4
    assert [exchange.request.subject_id for exchange in transcript.exchanges] == [
        intent.subject_id for intent in intents
    ]
    assert [exchange.result.status for exchange in transcript.exchanges] == [
        *([SolidityRetrievalStatus.REFUSED] * 4),
        *([SolidityRetrievalStatus.EXHAUSTED] * 4),
    ]
    assert transcript.exchanges[4].result.omissions[0].reason is (
        SolidityRetrievalReason.REQUEST_COUNT_BUDGET
    )
    assert all(
        exchange.result.omissions[0].reason is SolidityRetrievalReason.RETRIEVAL_ALREADY_EXHAUSTED
        for exchange in transcript.exchanges[5:]
    )
    assert (
        validate_solidity_retrieval_replay(
            corpus=corpus,
            policy=policy,
            transcript=transcript,
        )
        == transcript
    )


def test_every_exchange_is_self_hashed_and_replay_rejects_tampering() -> None:
    corpus = _corpus()
    policy = SolidityRetrievalRolePolicy.build(role="specialist:source_audit")
    transcript = start_solidity_retrieval_transcript(corpus=corpus, policy=policy)
    transcript = _execute(
        corpus,
        transcript,
        policy,
        SolidityRetrievalOperation.FETCH_INDEXED_RANGE,
        "fn-target",
    )

    exchange = transcript.exchanges[0]
    assert all(
        len(value) == 64
        for value in (
            corpus.scope.scope_sha256,
            corpus.corpus_sha256,
            policy.policy_sha256,
            exchange.request.request_sha256,
            exchange.result.result_sha256,
            exchange.exchange_sha256,
            transcript.transcript_sha256,
        )
    )
    assert (
        validate_solidity_retrieval_replay(
            corpus=corpus,
            policy=policy,
            transcript=transcript,
            expected_transcript_sha256=transcript.transcript_sha256,
        )
        == transcript
    )

    tampered = transcript.model_dump(mode="json")
    tampered["exchanges"][0]["result"]["records"][0]["content"] = "tampered\n"
    with pytest.raises(ValidationError):
        SolidityRetrievalTranscript.model_validate(tampered)
    with pytest.raises(ValueError, match="external replay commitment"):
        validate_solidity_retrieval_replay(
            corpus=corpus,
            policy=policy,
            transcript=transcript,
            expected_transcript_sha256="0" * 64,
        )
