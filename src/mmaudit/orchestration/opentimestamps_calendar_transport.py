"""Owned calendar HTTP exchanges; observations are not chain or publication authority.

No default origin, credential, retry, pending-URI discovery or release issuer is
provided. Callers must select and authorize contact before an eventual live run.
Synthetic transports can exercise this code but cannot create authenticated seals.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import secrets
from dataclasses import dataclass

import httpx

from mmaudit.models.opentimestamps_calendar import (
    CalendarCommitmentUnavailable,
    OpenTimestampsCalendarRequest,
    _require_request,
    assemble_opentimestamps_submission_proof,
    prepare_opentimestamps_calendar_request,
    prepare_opentimestamps_submission,
    replay_opentimestamps_calendar_response,
)
from mmaudit.models.opentimestamps_replay import (
    MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES,
    OpenTimestampsCalendarReplay,
)
from mmaudit.orchestration.calibration_publication import (
    CalibrationPublicationSubject,
    calibration_publication_request,
)

_CLEANUP_SECONDS = 1.0
_MAX_HEADER_BYTES = 16_384
_MAX_HEADERS = 128


@dataclass(frozen=True, slots=True)
class CalendarSubmissionContext:
    """Original recovery data; the separate durable journal retains it before dispatch."""

    file_sha256: str
    nonce: bytes
    request: OpenTimestampsCalendarRequest
    calendar_origin: str


class CalendarTransportError(ValueError):
    """A refused exchange. A dispatched POST may already have published its digest."""

    def __init__(
        self,
        message: str,
        *,
        publication_may_have_occurred: bool,
        submission_context: CalendarSubmissionContext | None = None,
    ) -> None:
        super().__init__(message)
        self.publication_may_have_occurred = publication_may_have_occurred
        self.submission_context = submission_context


class CalendarSubmissionCancelled(asyncio.CancelledError):
    """Cancellation with original recovery data; cancellation is never a receipt."""

    def __init__(self, context: CalendarSubmissionContext) -> None:
        super().__init__("calendar submission cancelled; publication may have occurred")
        self.submission_context = context
        self.publication_may_have_occurred = True


@dataclass(frozen=True, slots=True)
class CalendarExchangeObservation:
    """Constructible unverified data from a completed, closed HTTP exchange."""

    calendar_origin: str
    request: OpenTimestampsCalendarRequest
    status_code: int
    response_body: bytes
    replay: OpenTimestampsCalendarReplay


@dataclass(frozen=True, slots=True)
class CalendarSubmissionObservation:
    """Original file/nonce/request/reply binding, not an authenticated publication."""

    file_sha256: str
    nonce: bytes
    exchange: CalendarExchangeObservation
    detached_proof: bytes


@dataclass(frozen=True, slots=True)
class CalibrationCalendarSubmissionObservation:
    """SHA256(binary subject digest) file convention; no population or policy authority."""

    subject_sha256: str
    submission: CalendarSubmissionObservation


def _require_contact(origin: str, allowed: bool, timeout_seconds: float) -> None:
    if allowed is not True:
        raise ValueError("calendar contact requires explicit up-front authorization")
    _require_origin(origin)
    if (
        type(timeout_seconds) is not float
        or not math.isfinite(timeout_seconds)
        or not 0.05 <= timeout_seconds <= 60.0
    ):
        raise ValueError("calendar aggregate timeout must be an exact bounded float")


def _require_origin(origin: str) -> None:
    """Validate offline origin data without implying permission to contact it."""

    if (
        type(origin) is not str
        or not 0 < len(origin) <= 512
        or not origin.isascii()
        or any(ord(character) <= 32 or ord(character) == 127 for character in origin)
        or any(character in origin for character in "?#@%\\")
    ):
        raise ValueError("calendar requires an exact canonical HTTPS origin")
    try:
        parsed = httpx.URL(origin)
    except (httpx.InvalidURL, ValueError):
        raise ValueError("calendar requires an exact canonical HTTPS origin") from None
    if (
        parsed.scheme != "https"
        or not parsed.host
        or parsed.raw_path != b"/"
        or origin.endswith("/")
        or str(parsed) != origin
        or (parsed.port is not None and not 1 <= parsed.port <= 65535)
    ):
        raise ValueError("calendar requires an exact canonical HTTPS origin")


def _new_client(timeout_seconds: float) -> httpx.AsyncClient:
    # Owned default TLS verification; no ambient proxy, certificate override,
    # netrc/auth hook, shared cookie jar or caller-supplied transport is admitted here.
    return httpx.AsyncClient(
        verify=True,
        trust_env=False,
        follow_redirects=False,
        max_redirects=0,
        http1=True,
        http2=False,
        timeout=httpx.Timeout(timeout_seconds),
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
        headers={"Accept-Encoding": "identity", "Connection": "close"},
    )


def _request_binding(request: httpx.Request) -> tuple[object, ...]:
    if type(request) is not httpx.Request:
        raise ValueError("calendar HTTP request type differs")
    return request.method, request.url, tuple(request.headers.raw), request.content


def _response_length(response: httpx.Response) -> int | None:
    headers = response.headers.raw
    if len(headers) > _MAX_HEADERS or sum(len(k) + len(v) for k, v in headers) > _MAX_HEADER_BYTES:
        raise ValueError("calendar response headers exceed their bound")
    encoding = [value.strip().lower() for value in response.headers.get_list("content-encoding")]
    if encoding and encoding != ["identity"]:
        raise ValueError("calendar response must not use content compression")
    length = response.headers.get_list("content-length")
    transfer = [value.strip().lower() for value in response.headers.get_list("transfer-encoding")]
    if transfer and (transfer != ["chunked"] or length):
        raise ValueError("calendar response framing is ambiguous or unsupported")
    if not length:
        return None
    if len(length) != 1 or not length[0].isascii() or not length[0].isdigit() or len(length[0]) > 5:
        raise ValueError("calendar response content length is invalid")
    value = int(length[0])
    if value > MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES:
        raise ValueError("calendar response content length exceeds its bound")
    return value


async def _close_owned(response: httpx.Response | None, client: httpx.AsyncClient | None) -> None:
    # Each resource gets its own bound; one failure must not skip the other close.
    failed = False
    try:
        if response is not None:
            try:
                async with asyncio.timeout(_CLEANUP_SECONDS):
                    await response.aclose()
                failed = not response.is_closed
            except Exception:
                failed = True
    finally:
        if client is not None:
            try:
                async with asyncio.timeout(_CLEANUP_SECONDS):
                    await client.aclose()
                failed = failed or not client.is_closed
            except Exception:
                failed = True
    if failed:
        raise ValueError("calendar owned transport cleanup failed")


async def _exchange(
    *, origin: str, request: OpenTimestampsCalendarRequest, timeout_seconds: float
) -> CalendarExchangeObservation:
    client = None
    response = None
    attempted = False
    try:
        try:
            async with asyncio.timeout(timeout_seconds):
                client = _new_client(timeout_seconds)
                outgoing = client.build_request(
                    request.method,
                    origin + "/" + request.relative_path,
                    headers=dict(request.headers),
                    content=request.body,
                )
                binding = _request_binding(outgoing)
                attempted = True
                response = await client.send(outgoing, stream=True, follow_redirects=False)
                if type(response) is not httpx.Response or response.request is not outgoing:
                    raise ValueError("calendar response differs from the original request")
                if response.history or _request_binding(outgoing) != binding:
                    raise ValueError("calendar HTTP request changed during dispatch")
                response_headers = tuple(response.headers.raw)
                length = _response_length(response)
                if response.status_code != 200:
                    # Existing wire rules distinguish lookup404, without reading
                    # or reflecting an untrusted HTTP error body.
                    replay_opentimestamps_calendar_response(
                        request, status_code=response.status_code, body=b""
                    )
                body = bytearray()
                # Raw iteration never decompresses. HTTPCore may buffer64KiB;
                # enforce the retained proof bound before copying each chunk.
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES:
                        raise ValueError("calendar response body exceeds its bound")
                    body.extend(chunk)
                if not response.is_stream_consumed or (length is not None and length != len(body)):
                    raise ValueError("calendar response body is incomplete")
                if _request_binding(outgoing) != binding:
                    raise ValueError("calendar HTTP request changed during response consumption")
                raw = bytes(body)
                replay = replay_opentimestamps_calendar_response(
                    request, status_code=response.status_code, body=raw
                )
                observation = CalendarExchangeObservation(origin, request, 200, raw, replay)
        finally:
            await _close_owned(response, client)
        if (
            response is None
            or response.request is not outgoing
            or response.history
            or response.status_code != 200
            or tuple(response.headers.raw) != response_headers
            or _request_binding(outgoing) != binding
        ):
            raise ValueError("calendar request/response binding changed during cleanup")
    except CalendarCommitmentUnavailable:
        raise
    except Exception:
        raise CalendarTransportError(
            "calendar exchange refused; do not infer publication success or automatically retry",
            publication_may_have_occurred=attempted and request.operation == "SUBMIT",
        ) from None
    return observation


async def submit_opentimestamps_calendar(
    *,
    file_sha256: str,
    calendar_origin: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalendarSubmissionObservation:
    """Submit once with an owned nonce; return only after complete replay and cleanup."""

    _require_contact(calendar_origin, allow_calendar_contact, timeout_seconds)
    context = _prepare_submission_context(file_sha256=file_sha256, calendar_origin=calendar_origin)
    return await _submit_prepared_context(
        context=context,
        allow_calendar_contact=allow_calendar_contact,
        timeout_seconds=timeout_seconds,
    )


def _prepare_submission_context(
    *, file_sha256: str, calendar_origin: str
) -> CalendarSubmissionContext:
    """Generate fresh offline request data that a durable owner can retain before dispatch."""

    _require_origin(calendar_origin)
    # Validate caller digest before generating entropy or opening a client.
    prepare_opentimestamps_submission(file_sha256=file_sha256, nonce=b"\x00" * 16)
    nonce = secrets.token_bytes(16)
    request = prepare_opentimestamps_submission(file_sha256=file_sha256, nonce=nonce)
    return CalendarSubmissionContext(file_sha256, nonce, request, calendar_origin)


def _require_submission_context(context: CalendarSubmissionContext) -> None:
    if type(context) is not CalendarSubmissionContext:
        raise ValueError("calendar submission requires exact context data")
    _require_origin(context.calendar_origin)
    _require_request(context.request)
    if context.request != prepare_opentimestamps_submission(
        file_sha256=context.file_sha256, nonce=context.nonce
    ):
        raise ValueError("calendar submission context differs from its original request")


async def _submit_prepared_context(
    *,
    context: CalendarSubmissionContext,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalendarSubmissionObservation:
    """Dispatch already-prepared data once; data alone supplies no contact authorization."""

    _require_submission_context(context)
    _require_contact(context.calendar_origin, allow_calendar_contact, timeout_seconds)
    file_sha256, nonce, request = context.file_sha256, context.nonce, context.request
    try:
        exchange = await _exchange(
            origin=context.calendar_origin, request=request, timeout_seconds=timeout_seconds
        )
    except asyncio.CancelledError:
        raise CalendarSubmissionCancelled(context) from None
    except CalendarTransportError as failure:
        raise CalendarTransportError(
            str(failure),
            publication_may_have_occurred=failure.publication_may_have_occurred,
            submission_context=context,
        ) from None
    try:
        detached = assemble_opentimestamps_submission_proof(
            request,
            file_sha256=file_sha256,
            nonce=nonce,
            status_code=exchange.status_code,
            body=exchange.response_body,
        )
    except Exception:
        raise CalendarTransportError(
            "calendar submission assembly refused after dispatch",
            publication_may_have_occurred=True,
            submission_context=context,
        ) from None
    return CalendarSubmissionObservation(file_sha256, nonce, exchange, detached)


async def lookup_opentimestamps_calendar(
    *,
    commitment: bytes,
    calendar_origin: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalendarExchangeObservation:
    """Look up only the supplied origin/commitment; never follow a pending URI or retry."""

    _require_contact(calendar_origin, allow_calendar_contact, timeout_seconds)
    request = prepare_opentimestamps_calendar_request(operation="LOOKUP", commitment=commitment)
    return await _exchange(origin=calendar_origin, request=request, timeout_seconds=timeout_seconds)


async def submit_calibration_publication_calendar(
    *,
    subject: CalibrationPublicationSubject,
    calendar_origin: str,
    allow_calendar_contact: bool = False,
    timeout_seconds: float = 10.0,
) -> CalibrationCalendarSubmissionObservation:
    """Timestamp the binary32-byte subject digest file, never full private source material."""

    _require_contact(calendar_origin, allow_calendar_contact, timeout_seconds)
    digest_file = calibration_publication_request(subject)
    result = await submit_opentimestamps_calendar(
        file_sha256=hashlib.sha256(digest_file).hexdigest(),
        calendar_origin=calendar_origin,
        allow_calendar_contact=allow_calendar_contact,
        timeout_seconds=timeout_seconds,
    )
    try:
        if calibration_publication_request(subject) != digest_file:
            raise ValueError("calendar publication subject changed during transport")
    except Exception:
        raise CalendarTransportError(
            "calendar publication subject binding refused after dispatch",
            publication_may_have_occurred=True,
            submission_context=CalendarSubmissionContext(
                result.file_sha256, result.nonce, result.exchange.request, calendar_origin
            ),
        ) from None
    return CalibrationCalendarSubmissionObservation(digest_file.hex(), result)
