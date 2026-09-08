"""Bounded estimated-cost fixture transport, isolated from qualifying provider usage.

Only exact pinned fixture or explicit manifest-bound source requests can cross this boundary. HTTP observations
remain non-qualifying even when their JSON, routing, and reported cost validate.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from decimal import Decimal
from time import monotonic as _DEVELOPMENT_MONOTONIC
from typing import Any, NoReturn, cast

import httpx
from pydantic import BaseModel, ValidationError

from mmaudit.models.candidate_revocation import require_candidate_assignment_eligible
from mmaudit.models.development_audit import (
    DevelopmentAnyAuditShardObservation,
    DevelopmentAuditShardObservation,
    DevelopmentScoredAuditShardObservation,
    PreparedDevelopmentAuditShard,
    prepare_development_audit_shard,
)
from mmaudit.models.development_corpus import (
    DevelopmentCorpusResponse,
    DevelopmentCorpusShardObservation,
    PreparedDevelopmentCorpusShard,
    prepare_development_corpus_shard,
    validate_development_corpus_response,
)
from mmaudit.models.development_diagnostics import (
    DevelopmentCompletionTelemetry,
    DevelopmentResponseRejection,
    DevelopmentSchemaIssue,
    development_failure_stage,
    project_development_completion_telemetry,
    project_development_schema_failure,
)
from mmaudit.models.development_diagnostics import (
    DevelopmentResponseFailureReason as FailureReason,
)
from mmaudit.models.development_diagnostics import (
    DevelopmentResponseField as ResponseField,
)
from mmaudit.models.development_judgment import (
    DevelopmentJudgmentShardObservation,
    PreparedDevelopmentJudgmentShard,
    prepare_development_judgment_shard,
    validate_development_candidate_accounting,
    validate_development_judgment_response,
)
from mmaudit.models.development_review import (
    DevelopmentFinding,
    DevelopmentJudgmentResponse,
    DevelopmentReviewObservation,
    DevelopmentReviewResponse,
    DevelopmentScoredFinding,
    DevelopmentScoredReviewResponse,
    PreparedDevelopmentReview,
    prepare_development_review,
)
from mmaudit.models.development_review import (
    DevelopmentReviewDiagnostic as Diagnostic,
)
from mmaudit.models.development_routing import (
    DEVELOPMENT_GENERATION_ID,
    DevelopmentRoutingContext,
    DevelopmentRoutingEvidence,
    DevelopmentRoutingFailure,
    observe_development_routing,
)
from mmaudit.models.structured_output import (
    StructuredOutputDecodeError,
    StructuredOutputFailureCode,
    decode_structured_output,
)
from mmaudit.operator_secrets import MAX_OPERATOR_SECRET_VALUE_BYTES, OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostReservationOverrunError
from mmaudit.orchestration.development_budget import (
    DevelopmentBudgetSession,
    DevelopmentCostUncertainError,
)
from mmaudit.repository.redaction import detect_secrets

DEVELOPMENT_COMPLETION_URL = "https://openrouter.ai/api/v1/chat/completions"
MAX_DEVELOPMENT_RESPONSE_BYTES = 1_000_000
DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS = 180
_GENERATION_ID = DEVELOPMENT_GENERATION_ID
type _PreparedSource = (
    PreparedDevelopmentReview
    | PreparedDevelopmentAuditShard
    | PreparedDevelopmentJudgmentShard
    | PreparedDevelopmentCorpusShard
)


class DevelopmentTransportError(ValueError):
    """Controlled non-operational error; never embeds HTTP, source, or credential data."""


class _ResponseRejected(ValueError):
    def __init__(
        self, diagnostic: Diagnostic, *, rejection: DevelopmentResponseRejection | None = None
    ) -> None:
        self.diagnostic = diagnostic
        self.rejection = rejection
        super().__init__(diagnostic.value)


def _invalid_response(
    reason: FailureReason,
    *,
    finding_index: int | None = None,
    field: ResponseField | None = None,
) -> _ResponseRejected:
    return _ResponseRejected(
        Diagnostic.INVALID_RESPONSE,
        rejection=DevelopmentResponseRejection(
            stage=development_failure_stage(reason),
            reason=reason,
            finding_index=finding_index,
            field=field,
        ),
    )


def _decode_development_review[ResponseT: BaseModel](
    content: str, response_model: type[ResponseT]
) -> ResponseT:
    """Keep the strict decoder authoritative; revalidation can only describe its refusal.

    The optional diagnostic pass uses the same captured schema generation, with no
    coercion or repair. If it cannot explain the original refusal, detail stays absent.
    No diagnostic result is ever returned as a decoded response.
    """

    validator = response_model.__pydantic_validator__
    schema = response_model.__pydantic_core_schema__
    try:
        return decode_structured_output(content, response_model).value
    except StructuredOutputDecodeError as exc:
        issues: tuple[DevelopmentSchemaIssue, ...] = ()
        truncated = False
        if (
            exc.code is StructuredOutputFailureCode.SCHEMA_VALIDATION_FAILED
            and response_model.__pydantic_validator__ is validator
            and response_model.__pydantic_core_schema__ is schema
        ):
            try:
                validator.validate_json(content, strict=True, extra="forbid")
            except ValidationError as error:
                if (
                    response_model.__pydantic_validator__ is validator
                    and response_model.__pydantic_core_schema__ is schema
                ):
                    issues, truncated = project_development_schema_failure(error)
            except (ValueError, TypeError, AssertionError, RecursionError):
                pass
        raise _ResponseRejected(
            Diagnostic.INVALID_RESPONSE,
            rejection=DevelopmentResponseRejection(
                stage="STRUCTURED_OUTPUT",
                reason=FailureReason.STRUCTURED_OUTPUT,
                structured_failure=exc.code,
                schema_issues=issues,
                schema_issues_truncated=truncated,
            ),
        ) from None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate response JSON field")
        result[key] = value
    return result


def _reject_constant(_value: str) -> NoReturn:
    raise ValueError("nonfinite response JSON value")


def _decode_response(content: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            content.decode("utf-8"),
            parse_float=Decimal,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except (ValueError, UnicodeError, RecursionError, ArithmeticError):
        raise _invalid_response(FailureReason.RESPONSE_JSON) from None
    if type(value) is not dict:
        raise _invalid_response(FailureReason.RESPONSE_JSON)
    return value


def _reported_cost(payload: dict[str, Any]) -> Decimal | None:
    """Preserve exact reported spend even if the response later fails validation."""

    usage = payload.get("usage")
    value = usage.get("cost") if type(usage) is dict else None
    if type(value) not in {int, Decimal}:
        return None
    amount = Decimal(cast(Decimal | int, value))
    if not amount.is_finite() or not 0 <= amount < Decimal("1000000000000"):
        return None
    exponent = amount.as_tuple().exponent
    if type(exponent) is not int or exponent < -18:
        return None
    return amount


def _validate_routing(evidence: DevelopmentRoutingEvidence) -> None:
    """Require direct singleton routing with positively observed non-BYOK accounting."""

    if evidence.failure_codes:
        raise _ResponseRejected(Diagnostic.IDENTITY_MISMATCH)


def _token_count(usage: dict[str, Any], name: str) -> int:
    value = usage.get(name)
    if type(value) is not int or not 0 <= value <= 4_000_000:
        raise _invalid_response(FailureReason.TOKEN_COUNTS)
    return value


def _validated_review(
    payload: dict[str, Any],
    *,
    headers: httpx.Headers,
    prepared: _PreparedSource,
    api_key: str,
    routing_evidence: DevelopmentRoutingEvidence,
) -> tuple[
    str,
    DevelopmentReviewResponse
    | DevelopmentScoredReviewResponse
    | DevelopmentJudgmentResponse
    | DevelopmentCorpusResponse,
]:
    _validate_routing(routing_evidence)
    generation_id = payload.get("id")
    if type(generation_id) is not str or _GENERATION_ID.fullmatch(generation_id) is None:
        raise _invalid_response(FailureReason.GENERATION_ID)
    header_ids = headers.get_list("x-generation-id")
    if header_ids and header_ids != [generation_id]:
        raise _ResponseRejected(Diagnostic.IDENTITY_MISMATCH)
    if "error" in payload or payload.get("object") != "chat.completion":
        raise _invalid_response(FailureReason.COMPLETION_OBJECT)
    usage = payload.get("usage")
    if type(usage) is not dict or usage.get("is_byok", False) is not False:
        raise _invalid_response(FailureReason.USAGE)
    counts = [
        _token_count(usage, name) for name in ("prompt_tokens", "completion_tokens", "total_tokens")
    ]
    if (
        counts[0] + counts[1] != counts[2]
        or counts[0] > prepared.estimate.request_bytes
        or counts[1] > prepared.estimate.maximum_completion_tokens
    ):
        raise _invalid_response(FailureReason.TOKEN_COUNTS)
    if usage.get("server_tool_use_details") not in (None, {}):
        raise _invalid_response(FailureReason.SERVER_TOOLS)
    choices = payload.get("choices")
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise _invalid_response(FailureReason.CHOICES)
    choice = choices[0]
    if type(choice.get("index")) is not int or choice["index"] != 0:
        raise _invalid_response(FailureReason.CHOICE_INDEX)
    native_finish = choice.get("native_finish_reason")
    if choice.get("finish_reason") != "stop" or (
        native_finish is not None
        and (
            type(native_finish) is not str
            or native_finish.casefold()
            not in {"stop", "stop_sequence", "end_turn", "eos_token", "completed"}
        )
    ):
        raise _ResponseRejected(Diagnostic.INCOMPLETE_OUTPUT)
    message = choice.get("message")
    if (
        type(message) is not dict
        or message.get("role") != "assistant"
        or message.get("tool_calls")
        or message.get("function_call")
        or message.get("refusal") not in (None, "")
        or type(message.get("content")) is not str
    ):
        raise _invalid_response(FailureReason.MESSAGE)
    content = message["content"]
    if (
        api_key in content
        or api_key in generation_id
        or detect_secrets(content)
        or detect_secrets(generation_id)
    ):
        raise _ResponseRejected(Diagnostic.SECRET_OUTPUT)
    if type(prepared) is PreparedDevelopmentCorpusShard:
        corpus_response = _decode_development_review(content, DevelopmentCorpusResponse)
        try:
            validate_development_corpus_response(
                corpus_response, prepared.manifest, prepared.source_filename
            )
        except ValueError:
            raise _ResponseRejected(Diagnostic.INVALID_RESPONSE) from None
        return generation_id, corpus_response
    if type(prepared) is PreparedDevelopmentJudgmentShard:
        judgment = _decode_development_review(content, DevelopmentJudgmentResponse)
        try:
            validate_development_judgment_response(
                judgment, corpus_id=prepared.corpus_id, claims=prepared.claims
            )
        except ValueError:
            raise _ResponseRejected(Diagnostic.INVALID_RESPONSE) from None
        return generation_id, judgment
    response: DevelopmentReviewResponse | DevelopmentScoredReviewResponse
    if type(prepared) is PreparedDevelopmentAuditShard and prepared.schema_version == "2.0":
        response = _decode_development_review(content, DevelopmentScoredReviewResponse)
        source_lines = {
            name: len(material.splitlines()) for name, material in prepared.source_files
        }
        for index, finding in enumerate(response.findings):
            origin = finding.root_cause_ref
            if origin is not None and origin.filename not in source_lines:
                raise _invalid_response(
                    FailureReason.ORIGIN_FILE_SCOPE,
                    finding_index=index,
                    field=ResponseField.ORIGIN_FILENAME,
                )
            if origin is not None and origin.line_end > source_lines[origin.filename]:
                raise _invalid_response(
                    FailureReason.ORIGIN_LINE_BOUNDS,
                    finding_index=index,
                    field=ResponseField.ORIGIN_LINE_END,
                )
    else:
        response = _decode_development_review(content, DevelopmentReviewResponse)
    findings: tuple[DevelopmentFinding | DevelopmentScoredFinding, ...] = response.findings
    for index, item in enumerate(findings):
        if item.line_end > len(prepared.source_content.splitlines()):
            raise _invalid_response(
                FailureReason.FINDING_LINE_BOUNDS,
                finding_index=index,
                field=ResponseField.LINE_END,
            )
    return generation_id, response


async def _read_response(response: httpx.Response) -> bytes:
    if response.headers.get("content-encoding", "identity").lower() != "identity":
        raise _invalid_response(FailureReason.CONTENT_ENCODING)
    content_length = response.headers.get("content-length")
    if content_length is not None and (
        not content_length.isdecimal()
        or len(content_length) > 10
        or int(content_length) > MAX_DEVELOPMENT_RESPONSE_BYTES
    ):
        raise _invalid_response(FailureReason.CONTENT_LENGTH)
    material = bytearray()
    if response.is_stream_consumed:
        # MockTransport may return an already-buffered response. Owned network responses
        # use stream=True above; enforce the same size limit on either representation.
        if len(response.content) > MAX_DEVELOPMENT_RESPONSE_BYTES:
            raise _invalid_response(FailureReason.RESPONSE_SIZE)
        return response.content
    # A raw iterator avoids decompressing an unbounded response before enforcing the limit.
    async for chunk in response.aiter_raw():
        if len(material) + len(chunk) > MAX_DEVELOPMENT_RESPONSE_BYTES:
            raise _invalid_response(FailureReason.RESPONSE_SIZE)
        material.extend(chunk)
    return bytes(material)


async def review_development_fixture(
    *,
    prepared: PreparedDevelopmentReview,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    allow_code_egress: bool = False,
    attempt: int = 1,
    mock_transport: httpx.MockTransport | None = None,
) -> DevelopmentReviewObservation:
    """Retain the original two-fixture transport scope; do not admit audit shards here."""

    if type(prepared) is not PreparedDevelopmentReview:
        raise DevelopmentTransportError("fixture transport requires its exact prepared type")
    result = await _review_development_source(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=operator_secrets,
        allow_code_egress=allow_code_egress,
        attempt=attempt,
        mock_transport=mock_transport,
    )
    assert type(result) is DevelopmentReviewObservation
    return result


async def review_development_audit_shard(
    *,
    prepared: PreparedDevelopmentAuditShard,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
) -> DevelopmentAnyAuditShardObservation:
    """One rebuilt frozen-corpus shard, through the same accounting and HTTP protections."""

    if type(prepared) is not PreparedDevelopmentAuditShard:
        raise DevelopmentTransportError("audit shard transport requires its exact prepared type")
    result = await _review_development_source(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=operator_secrets,
        allow_code_egress=allow_code_egress,
        attempt=1,
        mock_transport=mock_transport,
    )
    if prepared.schema_version == "2.0":
        assert type(result) is DevelopmentScoredAuditShardObservation
    else:
        assert type(result) is DevelopmentAuditShardObservation
    return result


async def review_development_judgment_shard(
    *,
    prepared: PreparedDevelopmentJudgmentShard,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
) -> DevelopmentJudgmentShardObservation:
    """Review one exact candidate shard once through the shared accounted transport."""

    if type(prepared) is not PreparedDevelopmentJudgmentShard:
        raise DevelopmentTransportError("judgment transport requires its exact prepared type")
    result = await _review_development_source(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=operator_secrets,
        allow_code_egress=allow_code_egress,
        attempt=1,
        mock_transport=mock_transport,
    )
    assert type(result) is DevelopmentJudgmentShardObservation
    return result


async def review_development_corpus_shard(
    *,
    prepared: PreparedDevelopmentCorpusShard,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    allow_code_egress: bool = False,
    mock_transport: httpx.MockTransport | None = None,
) -> DevelopmentCorpusShardObservation:
    """Use the same exact request, cumulative accounting and routing boundary for a selected source."""

    if type(prepared) is not PreparedDevelopmentCorpusShard:
        raise DevelopmentTransportError("development corpus requires an exact prepared shard")
    result = await _review_development_source(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=operator_secrets,
        allow_code_egress=allow_code_egress,
        attempt=1,
        mock_transport=mock_transport,
    )
    assert type(result) is DevelopmentCorpusShardObservation
    return result


async def _review_development_source(
    *,
    prepared: _PreparedSource,
    ledger: AtomicCostLedger,
    operator_secrets: OperatorSecrets,
    allow_code_egress: bool,
    attempt: int,
    mock_transport: httpx.MockTransport | None,
) -> (
    DevelopmentReviewObservation
    | DevelopmentAnyAuditShardObservation
    | DevelopmentJudgmentShardObservation
    | DevelopmentCorpusShardObservation
):
    """Execute one explicit attempt; never automatically retry an ambiguous paid call.

    Normal callers use an owned TLS transport with no redirects, proxies, ambient
    credentials, HTTP retries, or arbitrary URLs. Injected transport is test-only,
    exact MockTransport, and permanently labelled MOCK_HTTP. No exception path
    after attempted dispatch may silently release its reservation.
    """

    if allow_code_egress is not True:
        raise DevelopmentTransportError("development fixture egress requires explicit consent")
    if (
        type(prepared)
        not in {
            PreparedDevelopmentReview,
            PreparedDevelopmentAuditShard,
            PreparedDevelopmentJudgmentShard,
            PreparedDevelopmentCorpusShard,
        }
        or type(ledger) is not AtomicCostLedger
    ):
        raise DevelopmentTransportError(
            "development transport requires exact prepared request and ledger types"
        )
    if mock_transport is not None and type(mock_transport) is not httpx.MockTransport:
        raise DevelopmentTransportError("development test transport must be an exact MockTransport")
    rebuilt: _PreparedSource
    if type(prepared) is PreparedDevelopmentReview:
        rebuilt = prepare_development_review(
            policy=prepared.estimate.policy,
            endpoint_snapshot=prepared.discovery
            if prepared.discovery is not None
            else prepared.endpoint_snapshot,
            source_filename=prepared.source_filename,
            source_content=prepared.source_content,
            request_id=prepared.estimate.request_id,
            maximum_completion_tokens=prepared.estimate.maximum_completion_tokens,
        )
    elif type(prepared) is PreparedDevelopmentAuditShard:
        if attempt != 1:
            raise DevelopmentTransportError("audit shards do not automatically retry")
        rebuilt = prepare_development_audit_shard(
            policy=prepared.estimate.policy,
            endpoint_snapshot=prepared.discovery
            if prepared.discovery is not None
            else prepared.endpoint_snapshot,
            corpus_id=prepared.corpus_id,
            source_files=prepared.source_files,
            primary_filename=prepared.source_filename,
            run_id=prepared.run_id,
            maximum_completion_tokens=prepared.estimate.maximum_completion_tokens,
            schema_version=prepared.schema_version,
        )
    elif type(prepared) is PreparedDevelopmentCorpusShard:
        if attempt != 1:
            raise DevelopmentTransportError("development corpus shards do not automatically retry")
        rebuilt = prepare_development_corpus_shard(
            policy=prepared.estimate.policy,
            endpoint_snapshot=prepared.discovery or prepared.endpoint_snapshot,
            manifest=prepared.manifest,
            source_files=prepared.source_files,
            primary_filename=prepared.source_filename,
            run_id=prepared.run_id,
            maximum_completion_tokens=prepared.estimate.maximum_completion_tokens,
        )
    else:
        assert type(prepared) is PreparedDevelopmentJudgmentShard
        if attempt != 1:
            raise DevelopmentTransportError("development judgments do not automatically retry")
        rebuilt = prepare_development_judgment_shard(
            candidate=prepared.candidate,
            policy=prepared.estimate.policy,
            endpoint_snapshot=prepared.discovery
            if prepared.discovery is not None
            else prepared.endpoint_snapshot,
            source_files=prepared.source_files,
            shard_id=prepared.shard_id,
            run_id=prepared.run_id,
            maximum_completion_tokens=prepared.estimate.maximum_completion_tokens,
        )
        validate_development_candidate_accounting(rebuilt.candidate, ledger.snapshot())
        if rebuilt.candidate.transport != (
            "MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION"
        ):
            raise DevelopmentTransportError("candidate and judgment transport observations differ")
    if rebuilt != prepared or not rebuilt.estimate.within_estimated_budget:
        raise DevelopmentTransportError(
            "development request or estimate changed or exceeds its targets"
        )
    prepared = rebuilt
    routing_context = DevelopmentRoutingContext.from_metadata(
        prepared.endpoint_snapshot, prepared.discovery
    )
    require_candidate_assignment_eligible(
        exact_model_id=prepared.estimate.exact_model_id,
        provider_endpoint=prepared.estimate.provider_endpoint,
    )
    if (
        routing_context.canonical_model_id is not None
        and routing_context.canonical_model_id != prepared.estimate.exact_model_id
    ):
        require_candidate_assignment_eligible(
            exact_model_id=routing_context.canonical_model_id,
            provider_endpoint=prepared.estimate.provider_endpoint,
        )
    if (
        type(operator_secrets) is not OperatorSecrets
        or not operator_secrets.openrouter_api_key_present
    ):
        raise DevelopmentTransportError(
            "development transport requires explicitly supplied operator credentials"
        )
    api_key = operator_secrets.openrouter_api_key
    if not 1 <= len(api_key) <= MAX_OPERATOR_SECRET_VALUE_BYTES or any(
        not 33 <= ord(c) <= 126 for c in api_key
    ):
        raise DevelopmentTransportError("development credential value is invalid")
    if api_key in prepared.request_content.decode() or api_key in routing_context.model_dump_json():
        raise DevelopmentTransportError("development credential overlaps provider-visible source")
    budget = DevelopmentBudgetSession(policy=prepared.estimate.policy, ledger=ledger)
    diagnostics: list[Diagnostic] = []
    actual: Decimal | None = None
    response_hash: str | None = None
    generation_id: str | None = None
    review: (
        DevelopmentReviewResponse
        | DevelopmentScoredReviewResponse
        | DevelopmentJudgmentResponse
        | DevelopmentCorpusResponse
        | None
    ) = None
    routing_evidence: DevelopmentRoutingEvidence | None = None
    rejection_evidence: DevelopmentResponseRejection | None = None
    completion_telemetry: DevelopmentCompletionTelemetry | None = None
    status_code: int | None = None
    started = _DEVELOPMENT_MONOTONIC()
    transport = (
        mock_transport
        if mock_transport is not None
        else httpx.AsyncHTTPTransport(
            retries=0,
            verify=True,
            trust_env=False,
        )
    )
    async with httpx.AsyncClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        timeout=httpx.Timeout(DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS, connect=10, pool=10),
    ) as client:
        reservation = budget.reserve(
            endpoint_snapshot=prepared.endpoint_snapshot,
            request_id=prepared.estimate.request_id,
            request_body=json.loads(prepared.request_content),
            attempt=attempt,
        )
        dispatched = False
        response: httpx.Response | None = None
        try:
            require_candidate_assignment_eligible(
                exact_model_id=prepared.estimate.exact_model_id,
                provider_endpoint=prepared.estimate.provider_endpoint,
            )
            if (
                routing_context.canonical_model_id is not None
                and routing_context.canonical_model_id != prepared.estimate.exact_model_id
            ):
                require_candidate_assignment_eligible(
                    exact_model_id=routing_context.canonical_model_id,
                    provider_endpoint=prepared.estimate.provider_endpoint,
                )
            request = client.build_request(
                "POST",
                DEVELOPMENT_COMPLETION_URL,
                content=prepared.request_content,
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "X-OpenRouter-Metadata": "enabled",
                },
            )
            if (
                request.content != prepared.request_content
                or hashlib.sha256(request.content).hexdigest()
                != reservation.estimate.request_sha256
            ):
                raise DevelopmentTransportError(
                    "development dispatch bytes differ from their reservation"
                )
            async with asyncio.timeout(DEVELOPMENT_ATTEMPT_TIMEOUT_SECONDS):
                # Set before the first transport await: errors/cancellation can mean paid usage.
                dispatched = True
                response = await client.send(request, stream=True)
                status_code = response.status_code
                material = await _read_response(response)
                response_hash = hashlib.sha256(material).hexdigest()
                payload = _decode_response(material)
                actual = _reported_cost(payload)
                try:
                    completion_telemetry = project_development_completion_telemetry(
                        payload, response_sha256=response_hash
                    )
                except Exception:
                    # Metadata must not repair a refusal or change admission/accounting.
                    # A broken diagnostic projection is absent, never invented usage.
                    completion_telemetry = None
                if status_code != 200:
                    raise _ResponseRejected(Diagnostic.HTTP_ERROR)
                routing_evidence = observe_development_routing(
                    payload,
                    context=routing_context,
                    api_key=api_key,
                    generation_header_ids=tuple(response.headers.get_list("x-generation-id")),
                )
                if type(prepared) is PreparedDevelopmentJudgmentShard and any(
                    item.generation_id == payload.get("id")
                    for item in prepared.candidate.observations
                ):
                    routing_evidence = DevelopmentRoutingEvidence.model_validate(
                        {
                            **routing_evidence.model_dump(),
                            "failure_codes": tuple(
                                dict.fromkeys(
                                    (
                                        *routing_evidence.failure_codes,
                                        DevelopmentRoutingFailure.GENERATION_REUSE,
                                    )
                                )
                            ),
                        }
                    )
                generation_id, review = _validated_review(
                    payload,
                    headers=response.headers,
                    prepared=prepared,
                    api_key=api_key,
                    routing_evidence=routing_evidence,
                )
        except _ResponseRejected as exc:
            diagnostics.append(exc.diagnostic)
            if exc.rejection is not None:
                rejection_evidence = DevelopmentResponseRejection.model_validate(
                    {**exc.rejection.model_dump(), "response_sha256": response_hash}
                )
        except (httpx.TimeoutException, TimeoutError):
            diagnostics.append(Diagnostic.TIMEOUT)
        except httpx.HTTPError:
            diagnostics.append(Diagnostic.TRANSPORT_ERROR)
        except (ValueError, TypeError, UnicodeError, RecursionError, ArithmeticError):
            if not dispatched:
                raise DevelopmentTransportError(
                    "development pre-dispatch validation failed"
                ) from None
            diagnostics.append(Diagnostic.INVALID_RESPONSE)
        except Exception:
            # Unanticipated adapter errors must not leak request headers or become successes.
            if not dispatched:
                raise DevelopmentTransportError(
                    "development pre-dispatch transport failed"
                ) from None
            diagnostics.append(Diagnostic.TRANSPORT_ERROR)
        finally:
            # Synchronous durable accounting must happen even during cancellation or stream failure.
            # If persistence fails, the existing hold remains blocking; no reset is attempted.
            try:
                if not dispatched:
                    budget.release_before_dispatch(reservation)
                else:
                    try:
                        budget.reconcile(reservation, actual_cost_usd=actual)
                    except DevelopmentCostUncertainError:
                        diagnostics.append(Diagnostic.UNKNOWN_COST)
                    except CostReservationOverrunError:
                        diagnostics.append(Diagnostic.COST_OVERRUN)
            finally:
                if response is not None:
                    try:
                        async with asyncio.timeout(5):
                            await response.aclose()
                    except Exception:
                        if Diagnostic.TRANSPORT_ERROR not in diagnostics:
                            diagnostics.append(Diagnostic.TRANSPORT_ERROR)
                api_key = ""
    entry = next(
        item
        for item in ledger.snapshot().entries
        if item.reservation_id == reservation.ledger_reservation.reservation_id
    )
    values: dict[str, Any] = dict(
        source_filename=prepared.source_filename,
        source_sha256=hashlib.sha256(prepared.source_content).hexdigest(),
        estimate=prepared.estimate,
        attempt=attempt,
        transport="MOCK_HTTP" if mock_transport is not None else "HTTP_OBSERVATION",
        status="INCOMPLETE" if diagnostics else "OBSERVED",
        diagnostics=tuple(diagnostics),
        http_status=status_code,
        response_sha256=response_hash,
        generation_id=generation_id,
        accounting_status=entry.status,
        reported_cost_usd=actual,
        accounted_cost_usd=entry.accounted_cost_usd,
        response=None if diagnostics else review,
        routing_evidence=routing_evidence,
        rejection_evidence=rejection_evidence,
        completion_telemetry=completion_telemetry,
    )
    if type(prepared) is PreparedDevelopmentReview:
        return DevelopmentReviewObservation.model_validate(values)
    if type(prepared) is PreparedDevelopmentCorpusShard:
        values.update(
            manifest=prepared.manifest,
            run_id=prepared.run_id,
            shard_id=prepared.shard_id,
            elapsed_seconds=_DEVELOPMENT_MONOTONIC() - started,
        )
        return DevelopmentCorpusShardObservation.model_validate(values)
    if type(prepared) is PreparedDevelopmentJudgmentShard:
        values.update(
            candidate_sha256=prepared.candidate_sha256,
            corpus_id=prepared.corpus_id,
            run_id=prepared.run_id,
            shard_id=prepared.shard_id,
            claims=prepared.claims,
            elapsed_seconds=_DEVELOPMENT_MONOTONIC() - started,
        )
        return DevelopmentJudgmentShardObservation.model_validate(values)
    assert type(prepared) is PreparedDevelopmentAuditShard
    values.update(
        corpus_id=prepared.corpus_id,
        corpus_sha256=prepared.corpus_sha256,
        run_id=prepared.run_id,
        shard_id=prepared.shard_id,
    )
    if prepared.schema_version == "2.0":
        values.update(schema_version="2.0", elapsed_seconds=_DEVELOPMENT_MONOTONIC() - started)
        return DevelopmentScoredAuditShardObservation.model_validate(values)
    return DevelopmentAuditShardObservation.model_validate(values)
