from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

import mmaudit.models.truncation as truncation_module
from mmaudit.models.openrouter import strict_json_schema_sha256
from mmaudit.models.schemas import (
    CandidateFinding,
    CandidateReviewBatch,
    Evidence,
    Location,
    ModelSurfaceReviewCitation,
    ModelSurfaceReviewRecord,
    ModelSurfaceReviewStatus,
    Severity,
    VerificationTest,
)
from mmaudit.models.truncation import (
    MAX_CANDIDATE_REVIEW_JSON_DEPTH,
    MAX_CANDIDATE_REVIEW_RESPONSE_BYTES,
    CandidateReviewBeginFrame,
    CandidateReviewChannelState,
    CandidateReviewEndFrame,
    CandidateReviewFindingFrame,
    CandidateReviewFindingsEndFrame,
    CandidateReviewFramedDocument,
    CandidateReviewFramePhase,
    CandidateReviewSummaryFrame,
    CandidateReviewSurfaceReviewFrame,
    CandidateReviewSurfaceReviewsEndFrame,
    CandidateReviewTruncatedEnvelopeEvidence,
    CandidateReviewTruncationError,
    CandidateReviewTruncationFailureCode,
    CandidateReviewTruncationProjection,
    CandidateReviewTruncationTermination,
    candidate_review_batch_schema_sha256,
    candidate_review_frame_wire_schema_sha256,
    candidate_review_protocol_implementation_is_pristine,
    decode_complete_candidate_review_document,
    decode_complete_candidate_review_frames,
    frame_candidate_review_batch,
    normalize_candidate_review_document,
    project_truncated_candidate_review_prefix,
    seal_candidate_review_truncated_envelope_evidence,
)


def _candidate(candidate_id: str = "candidate-safe") -> CandidateFinding:
    return CandidateFinding(
        candidate_id=candidate_id,
        title="Synthetic bounded candidate",
        severity=Severity.HIGH,
        confidence=0.8,
        summary="A synthetic local transition may violate its declared invariant.",
        impact="Only the disposable synthetic fixture can enter the prohibited state.",
        preconditions=["The local synthetic transition is reachable."],
        locations=[
            Location(
                path="tests/fixtures/Synthetic.sol",
                start_line=7,
                end_line=9,
            )
        ],
        attack_path=["Exercise the bounded local transition."],
        evidence=[
            Evidence(
                type="model",
                source="source_audit",
                description="Synthetic model evidence for a defensive parser regression.",
            )
        ],
        false_positive_conditions=["A local guard preserves the invariant."],
        recommendation="Preserve the invariant and rerun the local negative regression.",
        verification_test=VerificationTest(
            description="Replay the disposable local negative-control fixture."
        ),
        role="source_audit",
        model_family="synthetic-lineage",
    )


def _surface(seed: str = "one") -> ModelSurfaceReviewRecord:
    surface_id = f"model-surface:{hashlib.sha256(seed.encode()).hexdigest()}"
    return ModelSurfaceReviewRecord(
        surface_id=surface_id,
        contract="SyntheticVault",
        function_or_state_surface=f"surface-{seed}",
        review_role="source_audit",
        status=ModelSurfaceReviewStatus.NOT_REVIEWED,
        rationale="The bounded synthetic surface was not completely reviewed.",
        citation=ModelSurfaceReviewCitation(symbol=f"surface-{seed}"),
        invariant_considered="Synthetic state remains within its declared local bound.",
        evidence_observations=(),
        reachability=None,
        assumptions=(),
        confidence=0.0,
    )


def _frames(
    findings: tuple[CandidateFinding, ...] = (),
    surface_reviews: tuple[ModelSurfaceReviewRecord, ...] = (),
) -> list[dict[str, object]]:
    frames: list[object] = [
        CandidateReviewBeginFrame(
            schema_version="1.0",
            sequence=0,
            phase=CandidateReviewFramePhase.BEGIN,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
            summary_count=1,
        )
    ]
    sequence = 1
    frames.extend(
        CandidateReviewFindingFrame(
            schema_version="1.0",
            sequence=sequence + index,
            phase=CandidateReviewFramePhase.FINDING,
            record=finding,
        )
        for index, finding in enumerate(findings)
    )
    sequence += len(findings)
    frames.append(
        CandidateReviewFindingsEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.FINDINGS_END,
            record_count=len(findings),
        )
    )
    sequence += 1
    frames.extend(
        CandidateReviewSurfaceReviewFrame(
            schema_version="1.0",
            sequence=sequence + index,
            phase=CandidateReviewFramePhase.SURFACE_REVIEW,
            record=review,
        )
        for index, review in enumerate(surface_reviews)
    )
    sequence += len(surface_reviews)
    frames.append(
        CandidateReviewSurfaceReviewsEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.SURFACE_REVIEWS_END,
            record_count=len(surface_reviews),
        )
    )
    sequence += 1
    frames.append(
        CandidateReviewSummaryFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.SUMMARY,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
        )
    )
    sequence += 1
    frames.append(
        CandidateReviewEndFrame(
            schema_version="1.0",
            sequence=sequence,
            phase=CandidateReviewFramePhase.END,
            frame_count=sequence + 1,
            finding_count=len(findings),
            surface_review_count=len(surface_reviews),
            summary_count=1,
        )
    )
    return [frame.model_dump(mode="json") for frame in frames]  # type: ignore[attr-defined]


def _frame_json(frame: dict[str, object]) -> str:
    return json.dumps(frame, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _document(frames: list[dict[str, object]]) -> str:
    return '{"frames":[' + ",".join(_frame_json(frame) for frame in frames) + "]}"


def _projection(content: str) -> CandidateReviewTruncationProjection:
    return project_truncated_candidate_review_prefix(
        content,
        finish_reason="stop",
        native_finish_reason="max_tokens",
    )


def _reseal(payload: dict[str, object]) -> None:
    canonical = {key: value for key, value in payload.items() if key != "evidence_sha256"}
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode()
    payload["evidence_sha256"] = hashlib.sha256(encoded).hexdigest()


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def test_complete_framed_document_decodes_to_normalized_candidate_review_batch() -> None:
    candidate = _candidate()
    surface = _surface()
    content = _document(_frames((candidate,), (surface,)))

    batch = decode_complete_candidate_review_frames(content)

    assert batch.findings == [candidate]
    assert batch.surface_reviews == (surface,)
    assert candidate_review_frame_wire_schema_sha256() != candidate_review_batch_schema_sha256()
    assert candidate_review_frame_wire_schema_sha256() == strict_json_schema_sha256(
        CandidateReviewFramedDocument
    )
    assert CandidateReviewFramedDocument.model_json_schema()["title"] == (
        "CandidateReviewFramedDocument"
    )


def test_complete_decode_preserves_ordinary_json_whitespace_compatibility() -> None:
    content = json.dumps(
        {"frames": _frames((_candidate(),), (_surface(),))},
        indent=2,
        ensure_ascii=True,
    )

    batch = decode_complete_candidate_review_frames(content)

    assert len(batch.findings) == 1
    assert len(batch.surface_reviews) == 1


def test_normalization_evidence_replays_wire_batch_and_inventory_joins() -> None:
    batch = CandidateReviewBatch(findings=[_candidate()], surface_reviews=(_surface(),))
    wire = frame_candidate_review_batch(batch)

    normalized, evidence = normalize_candidate_review_document(wire, request_id="request-1")

    assert normalized == batch
    assert evidence.require_exact_batch(normalized, request_id="request-1") is evidence
    assert evidence.wire_validated_response_sha256 == _canonical_sha256(
        wire.model_dump(mode="json")
    )
    assert evidence.normalized_batch_sha256 == _canonical_sha256(batch.model_dump(mode="json"))
    assert evidence.findings_sha256 == _canonical_sha256(
        [finding.model_dump(mode="json") for finding in batch.findings]
    )
    assert evidence.surface_reviews_sha256 == _canonical_sha256(
        [review.model_dump(mode="json") for review in batch.surface_reviews]
    )


def test_truncated_envelope_evidence_exactly_binds_validated_identity_scalars() -> None:
    evidence = seal_candidate_review_truncated_envelope_evidence(
        logical_request_id="candidate-review-request-1",
        generation_id="generation-1",
        generation_header_id="generation-1",
        requested_model="alpha/atlas-secure",
        returned_model="alpha/atlas-secure",
        selected_model="alpha/atlas-secure",
        response_provider_identity="provider-alias",
        selected_provider_endpoint="provider-endpoint",
        selected_provider_identity="provider-alias",
        selected_provider_name="Provider Name",
        router_metadata_sha256="1" * 64,
        finish_reason="length",
        native_finish_reason="max_tokens",
        wire_schema_sha256=candidate_review_frame_wire_schema_sha256(),
        response_sha256="2" * 64,
    )

    reparsed = CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(
        evidence.model_dump_json(),
        strict=True,
    )
    assert reparsed == evidence
    assert not reparsed.review_credit_eligible
    assert not reparsed.authority_eligible

    tampered = evidence.model_dump(mode="json")
    tampered["generation_header_id"] = "different-generation"
    _reseal(tampered)
    with pytest.raises(ValidationError, match="generation identities"):
        CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(json.dumps(tampered))

    omitted = evidence.model_dump(mode="json")
    del omitted["response_provider_identity"]
    with pytest.raises(ValidationError, match="every nested field"):
        CandidateReviewTruncatedEnvelopeEvidence.model_validate_json(json.dumps(omitted))


def test_protocol_guard_rejects_deceptively_equal_constant_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeceptiveWirePrefix(str):
        def __eq__(self, _other: object) -> bool:
            return True

    assert candidate_review_protocol_implementation_is_pristine()
    monkeypatch.setattr(
        truncation_module,
        "_WIRE_PREFIX",
        DeceptiveWirePrefix('{"frames":['),
    )

    assert not candidate_review_protocol_implementation_is_pristine()
    with pytest.raises(CandidateReviewTruncationError) as raised:
        frame_candidate_review_batch(CandidateReviewBatch(findings=[], surface_reviews=()))
    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_ARGUMENT


def test_protocol_guard_compares_model_descriptors_by_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeceptiveCallable:
        def __call__(self, *_args: object, **_kwargs: object) -> object:
            return self

        def __eq__(self, _other: object) -> bool:
            return True

    assert candidate_review_protocol_implementation_is_pristine()
    monkeypatch.setattr(
        CandidateReviewFramedDocument,
        "frame_sequence_is_semantically_complete",
        DeceptiveCallable(),
    )

    assert not candidate_review_protocol_implementation_is_pristine()


def test_protocol_guard_pins_transitive_json_decoder_callable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_loads = json.loads

    def duplicate_blind_loads(value: str, **_kwargs: object) -> object:
        return original_loads(value)

    assert candidate_review_protocol_implementation_is_pristine()
    monkeypatch.setattr(json, "loads", duplicate_blind_loads)

    assert not candidate_review_protocol_implementation_is_pristine()
    duplicate_begin = (
        '{"frames":[{"schema_version":"1.0","sequence":0,"sequence":0,'
        '"phase":"BEGIN","finding_count":0,"surface_review_count":0,'
        '"summary_count":1}'
    )
    with pytest.raises(CandidateReviewTruncationError) as raised:
        project_truncated_candidate_review_prefix(
            duplicate_begin,
            finish_reason="length",
            native_finish_reason=None,
        )
    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    ("owner", "attribute"),
    (
        (json, "JSONDecoder"),
        (json.JSONDecoder, "decode"),
        (json.JSONDecoder, "raw_decode"),
        (json, "JSONEncoder"),
        (json.JSONEncoder, "encode"),
        (json.JSONEncoder, "iterencode"),
    ),
)
def test_protocol_guard_pins_json_codec_classes_and_methods(
    monkeypatch: pytest.MonkeyPatch,
    owner: object,
    attribute: str,
) -> None:
    trusted = getattr(owner, attribute)
    expected_hash = truncation_module._canonical_sha256({"a": 1, "z": 0})

    def substituted(*args: object, **kwargs: object) -> object:
        return trusted(*args, **kwargs)

    assert candidate_review_protocol_implementation_is_pristine()
    monkeypatch.setattr(owner, attribute, substituted)

    assert not candidate_review_protocol_implementation_is_pristine()
    assert truncation_module._canonical_sha256({"a": 1, "z": 0}) == expected_hash
    with pytest.raises(CandidateReviewTruncationError) as raised:
        project_truncated_candidate_review_prefix(
            '{"frames":[{"schema_version":"1.0","sequence":0,"sequence":0, '
            '"phase":"BEGIN","finding_count":0,"surface_review_count":0,'
            '"summary_count":1}',
            finish_reason="length",
            native_finish_reason=None,
        )
    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_ARGUMENT


def test_complete_decode_enforces_the_same_frame_and_depth_resource_bounds() -> None:
    frames = _frames((_candidate(),), ())
    finding = frames[1]["record"]
    assert isinstance(finding, dict)
    finding["summary"] = "x" * 513_000
    content = _document(frames)
    assert len(_frame_json(frames[1]).encode()) > 512_000

    with pytest.raises(CandidateReviewTruncationError) as raised:
        decode_complete_candidate_review_document(content)

    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT


def test_truncated_prefix_retains_only_complete_schema_valid_records_and_no_raw_tail() -> None:
    candidate = _candidate()
    first_surface, second_surface = sorted(
        (_surface("one"), _surface("two")), key=lambda x: x.surface_id
    )
    frames = _frames((candidate,), (first_surface, second_surface))
    complete_prefix = '{"frames":[' + ",".join(_frame_json(frame) for frame in frames[:4]) + ","
    canary = "SYNTHETIC_INCOMPLETE_TAIL_CANARY_91f4"
    content = (
        complete_prefix
        + '{"schema_version":"1.0","sequence":4,"phase":"SURFACE_REVIEW","record":{"surface_id":"'
        + canary
    )

    projection = _projection(content)

    assert projection.findings == (candidate,)
    assert projection.surface_reviews == (first_surface,)
    assert projection.findings_state is CandidateReviewChannelState.COMPLETE
    assert projection.surface_reviews_state is CandidateReviewChannelState.OPEN
    assert projection.summary_state is CandidateReviewChannelState.NOT_STARTED
    assert projection.termination is CandidateReviewTruncationTermination.INCOMPLETE_TAIL
    assert projection.accepted_finding_count == 1
    assert projection.accepted_surface_review_count == 1
    assert projection.original_response_bytes == (
        projection.accepted_prefix_bytes + projection.discarded_suffix_bytes
    )
    assert canary not in projection.model_dump_json()
    assert canary not in repr(projection)
    assert projection.discarded_suffix_retained is False
    assert not projection.review_credit_eligible
    assert not projection.coverage_credit_eligible
    assert not projection.summary_credit_eligible
    assert not projection.authority_eligible


def test_accepted_frame_ranges_and_hashes_bind_exact_utf8_provider_bytes() -> None:
    candidate = _candidate("candidate-unicode-π")
    content = _document(_frames((candidate,), ()))
    projection = _projection(content[:-2])
    encoded = content.encode("utf-8")

    for frame in projection.accepted_frames:
        exact = encoded[frame.byte_start : frame.byte_end]
        assert len(exact) == frame.frame_bytes
        assert hashlib.sha256(exact).hexdigest() == frame.frame_sha256
    assert projection.original_response_sha256 == hashlib.sha256(encoded[:-2]).hexdigest()


def test_schema_invalid_finding_does_not_erase_independent_surface_or_summary_channel() -> None:
    surface = _surface()
    frames = _frames((_candidate(),), (surface,))
    finding_record = frames[1]["record"]
    assert isinstance(finding_record, dict)
    frames[1]["record"] = {**finding_record, "confidence": "0.8"}
    projection = _projection(_document(frames))

    assert projection.findings == ()
    assert projection.findings_state is CandidateReviewChannelState.INVALID
    assert projection.surface_reviews == (surface,)
    assert projection.surface_reviews_state is CandidateReviewChannelState.COMPLETE
    assert projection.summary_state is CandidateReviewChannelState.COMPLETE
    assert projection.document_complete
    assert not projection.stream_integrity_valid


def test_invalid_later_surface_does_not_erase_already_closed_findings_channel() -> None:
    candidate = _candidate()
    frames = _frames((candidate,), (_surface(),))
    surface_record = frames[3]["record"]
    assert isinstance(surface_record, dict)
    frames[3]["record"] = {**surface_record, "confidence": "0.0"}
    projection = _projection(_document(frames))

    assert projection.findings == (candidate,)
    assert projection.findings_state is CandidateReviewChannelState.COMPLETE
    assert projection.surface_reviews == ()
    assert projection.surface_reviews_state is CandidateReviewChannelState.INVALID
    assert projection.summary_state is CandidateReviewChannelState.COMPLETE


def test_duplicate_record_identities_are_removed_as_ambiguous() -> None:
    duplicate = _candidate("candidate-duplicate")
    surface = _surface()
    projection = _projection(_document(_frames((duplicate, duplicate), (surface,))))

    assert projection.findings == ()
    assert projection.accepted_finding_count == 0
    assert projection.findings_state is CandidateReviewChannelState.INVALID
    assert projection.surface_reviews == (surface,)
    assert all(frame.record_id != duplicate.candidate_id for frame in projection.accepted_frames)


def test_oversized_candidate_identity_fails_closed_without_raw_or_validation_leak() -> None:
    canary = "X" * 501
    frames = _frames((_candidate(),), ())
    finding_record = frames[1]["record"]
    assert isinstance(finding_record, dict)
    finding_record["candidate_id"] = canary

    projection = _projection(_document(frames))

    assert projection.findings == ()
    assert projection.findings_state is CandidateReviewChannelState.INVALID
    assert canary not in projection.model_dump_json()
    with pytest.raises(CandidateReviewTruncationError) as raised:
        decode_complete_candidate_review_frames(_document(frames))
    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
    assert canary not in str(raised.value)
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        ('"confidence":0.8', '"confidence":NaN'),
        ('"confidence":0.8', '"confidence":1e400'),
        ('"confidence":0.8', '"confidence":0.8,"confidence":0.7'),
    ],
)
def test_duplicate_and_nonfinite_json_stop_before_ambiguous_frame(
    needle: str,
    replacement: str,
) -> None:
    frames = _frames((_candidate(),), ())
    raw_begin = _frame_json(frames[0])
    raw_finding = _frame_json(frames[1]).replace(needle, replacement)
    content = '{"frames":[' + raw_begin + "," + raw_finding + "," + _frame_json(frames[2])

    projection = _projection(content)

    assert projection.findings == ()
    assert projection.observed_frame_count == 1
    assert projection.termination is CandidateReviewTruncationTermination.INVALID_FRAME
    assert not projection.stream_integrity_valid


def test_summary_count_mismatch_invalidates_only_summary_channel() -> None:
    candidate = _candidate()
    surface = _surface()
    frames = _frames((candidate,), (surface,))
    frames[-2]["finding_count"] = 0
    projection = _projection(_document(frames))

    assert projection.findings == (candidate,)
    assert projection.surface_reviews == (surface,)
    assert projection.findings_state is CandidateReviewChannelState.COMPLETE
    assert projection.surface_reviews_state is CandidateReviewChannelState.COMPLETE
    assert projection.summary_state is CandidateReviewChannelState.INVALID
    assert not projection.summary_credit_eligible


@pytest.mark.parametrize(
    "mutation",
    [
        lambda frames: frames.__setitem__(1, {**frames[1], "sequence": 7}),
        lambda frames: frames.__setitem__(1, {**frames[1], "phase": "SUMMARY"}),
        lambda frames: frames[-1].__setitem__("frame_count", 99),
    ],
)
def test_complete_decode_rejects_sequence_phase_and_end_count_drift(mutation: object) -> None:
    frames = _frames((_candidate(),), ())
    mutation(frames)  # type: ignore[operator]

    with pytest.raises(CandidateReviewTruncationError) as raised:
        decode_complete_candidate_review_frames(_document(frames))

    assert raised.value.code is CandidateReviewTruncationFailureCode.INVALID_COMPLETE_DOCUMENT
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_prefix_recovery_requires_exact_envelope_and_length_finish_reason() -> None:
    content = json.dumps({"frames": _frames()}, separators=(",", ": "))
    with pytest.raises(CandidateReviewTruncationError) as envelope_error:
        _projection(content)
    assert envelope_error.value.code is CandidateReviewTruncationFailureCode.INVALID_ENVELOPE

    with pytest.raises(CandidateReviewTruncationError) as reason_error:
        project_truncated_candidate_review_prefix(
            _document(_frames()),
            finish_reason="stop",
            native_finish_reason=None,
        )
    assert reason_error.value.code is CandidateReviewTruncationFailureCode.TRUNCATION_NOT_CONFIRMED


def test_response_size_is_fixed_and_bounded() -> None:
    oversized = _WIRE_PREFIX_FOR_TEST + "x" * MAX_CANDIDATE_REVIEW_RESPONSE_BYTES
    with pytest.raises(CandidateReviewTruncationError) as raised:
        _projection(oversized)
    assert raised.value.code is CandidateReviewTruncationFailureCode.RESPONSE_TOO_LARGE


def test_prefix_nesting_depth_is_fixed_and_fails_closed() -> None:
    begin = _frame_json(_frames()[0])
    nested = "{" * (MAX_CANDIDATE_REVIEW_JSON_DEPTH + 1)
    projection = _projection('{"frames":[' + begin + "," + nested)

    assert projection.termination is CandidateReviewTruncationTermination.INVALID_FRAME
    assert projection.invalid_frame_count == 1
    assert not projection.stream_integrity_valid
    assert projection.findings_state is CandidateReviewChannelState.INVALID


def test_projection_rejects_reseal_and_credit_tampering() -> None:
    projection = _projection(_document(_frames())[:-1])
    tampered = projection.model_dump(mode="json")
    tampered["review_credit_eligible"] = True

    with pytest.raises(ValidationError):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    tampered["accepted_prefix_bytes"] += 1
    tampered["evidence_sha256"] = projection.evidence_sha256
    with pytest.raises(ValidationError, match=r"byte partition|evidence hash"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_detached_record_swap_with_coherently_resealed_outer_hash() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    findings = tampered["findings"]
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    findings[0]["candidate_id"] = "candidate-swapped"
    _reseal(tampered)

    with pytest.raises(ValidationError, match=r"record/frame identities differ"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_overlapping_ranges_and_count_coercion() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    accepted = tampered["accepted_frames"]
    assert isinstance(accepted, list) and len(accepted) >= 2
    first, second = accepted[:2]
    assert isinstance(first, dict) and isinstance(second, dict)
    first_end = first["byte_end"]
    second_end = second["byte_end"]
    assert isinstance(first_end, int) and isinstance(second_end, int)
    second["byte_start"] = first_end - 1
    second["frame_bytes"] = second_end - (first_end - 1)
    _reseal(tampered)
    with pytest.raises(ValidationError, match="overlap"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    tampered["accepted_finding_count"] = "1"
    _reseal(tampered)
    with pytest.raises(ValidationError):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_coherently_resealed_count_and_channel_state_drift() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    tampered["declared_finding_count"] = 2
    _reseal(tampered)
    with pytest.raises(ValidationError, match=r"complete findings|observed record"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    tampered["findings_state"] = CandidateReviewChannelState.OPEN.value
    _reseal(tampered)
    with pytest.raises(ValidationError, match="channel state"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_coherent_outer_reseals_of_control_and_finish_evidence() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))

    tampered = projection.model_dump(mode="json")
    accepted = tampered["accepted_frames"]
    assert isinstance(accepted, list) and isinstance(accepted[0], dict)
    accepted[0]["normalized_value_sha256"] = "0" * 64
    _reseal(tampered)
    with pytest.raises(ValidationError, match="control-frame hash"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    tampered["end_declared_frame_count"] = 5
    _reseal(tampered)
    with pytest.raises(ValidationError, match=r"control-frame hash|END counts"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    tampered["finish_reason"] = "stop"
    tampered["native_finish_reason"] = "stop"
    _reseal(tampered)
    with pytest.raises(ValidationError, match="confirmed length"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_cannot_promote_end_without_closing_envelope() -> None:
    projection = _projection(_document(_frames())[:-2])
    assert projection.termination is CandidateReviewTruncationTermination.END_OF_INPUT_AFTER_FRAME
    tampered = projection.model_dump(mode="json")
    tampered["termination"] = CandidateReviewTruncationTermination.COMPLETE_DOCUMENT.value
    tampered["document_complete"] = True
    _reseal(tampered)

    with pytest.raises(ValidationError, match="closing envelope"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_open_begin_count_and_partial_end_reseals() -> None:
    frames = _frames((_candidate(),), ())
    content = '{"frames":[' + _frame_json(frames[0]) + ","
    projection = _projection(content)
    tampered = projection.model_dump(mode="json")
    tampered["declared_finding_count"] = 2
    _reseal(tampered)
    with pytest.raises(ValidationError, match="control-frame hash"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    complete = _projection(_document(frames))
    tampered = complete.model_dump(mode="json")
    tampered["end_declared_frame_count"] = None
    tampered["end_declared_finding_count"] = None
    _reseal(tampered)
    with pytest.raises(ValidationError, match="END count presence"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_invalid_separator_cannot_be_resealed_as_integrity_valid() -> None:
    frames = _frames()
    content = '{"frames":[' + _frame_json(frames[0]) + "!"
    projection = _projection(content)
    assert projection.termination is CandidateReviewTruncationTermination.INVALID_SEPARATOR
    tampered = projection.model_dump(mode="json")
    tampered["stream_integrity_valid"] = True
    _reseal(tampered)

    with pytest.raises(ValidationError, match="termination"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_omitted_nested_defaults_with_an_unchanged_seal() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    findings = tampered["findings"]
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    del findings[0]["origin_kind"]

    with pytest.raises(ValidationError, match="every nested field"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


@pytest.mark.parametrize("candidate_id", [" leading", "trailing ", "control\nline"])
def test_projection_rejects_coherently_resealed_unbounded_finding_identity(
    candidate_id: str,
) -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    findings = tampered["findings"]
    accepted = tampered["accepted_frames"]
    assert isinstance(findings, list) and isinstance(findings[0], dict)
    assert isinstance(accepted, list)
    finding_frame = next(
        frame
        for frame in accepted
        if isinstance(frame, dict) and frame["phase"] == CandidateReviewFramePhase.FINDING.value
    )
    findings[0]["candidate_id"] = candidate_id
    finding_frame["record_id"] = candidate_id
    finding_frame["normalized_value_sha256"] = _canonical_sha256(findings[0])
    _reseal(tampered)

    with pytest.raises(ValidationError, match="bounded"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_sequence_domain_and_begin_range_reseals() -> None:
    projection = _projection(_document(_frames((_candidate(),), ())))
    tampered = projection.model_dump(mode="json")
    accepted = tampered["accepted_frames"]
    assert isinstance(accepted, list)
    for sequence, frame in enumerate(accepted[1:], start=100):
        assert isinstance(frame, dict)
        frame["sequence"] = sequence
    _reseal(tampered)
    with pytest.raises(ValidationError, match="observed sequence domain"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))

    tampered = projection.model_dump(mode="json")
    accepted = tampered["accepted_frames"]
    assert isinstance(accepted, list) and isinstance(accepted[0], dict)
    accepted[0]["byte_start"] += 1
    accepted[0]["byte_end"] += 1
    _reseal(tampered)
    with pytest.raises(ValidationError, match="exact BEGIN"):
        CandidateReviewTruncationProjection.model_validate_json(json.dumps(tampered))


def test_projection_rejects_string_subclasses_and_surrogates_without_raw_context() -> None:
    class LyingText(str):
        def encode(self, *_args: object, **_kwargs: object) -> bytes:
            return b"x" * len(self)

    with pytest.raises(CandidateReviewTruncationError) as subclass_error:
        _projection(LyingText(_document(_frames())))
    assert subclass_error.value.code is CandidateReviewTruncationFailureCode.INVALID_ARGUMENT

    canary = "SYNTHETIC_RAW_CONTEXT_CANARY_8e91"
    with pytest.raises(CandidateReviewTruncationError) as surrogate_error:
        _projection('{"frames":[' + canary + "\ud800")
    assert surrogate_error.value.code is CandidateReviewTruncationFailureCode.INVALID_ARGUMENT
    assert surrogate_error.value.__cause__ is None
    assert surrogate_error.value.__context__ is None
    assert canary not in repr(surrogate_error.value)


_WIRE_PREFIX_FOR_TEST = '{"frames":['
