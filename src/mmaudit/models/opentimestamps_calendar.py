"""Calendar wire data and detached-proof assembly, without transport or authority.

No origin is chosen, URI followed, randomness generated, service contacted or
publication/chain claim issued. An eventual owner must bind actual transport,
fresh nonce generation, source scope and independently authenticated block roots.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

from mmaudit.models.opentimestamps_replay import (
    _MAGIC,
    MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES,
    OpenTimestampsCalendarReplay,
    replay_detached_opentimestamps_proof,
    replay_opentimestamps_calendar_proof,
)

_HEADERS = (
    ("Accept", "application/vnd.opentimestamps.v1"),
    ("User-Agent", "mmaudit-opentimestamps"),
)


@dataclass(frozen=True, slots=True)
class OpenTimestampsCalendarRequest:
    """Constructible wire data. A relative path does not select or authorize an origin."""

    operation: Literal["SUBMIT", "LOOKUP"]
    method: Literal["POST", "GET"]
    relative_path: str
    headers: tuple[tuple[str, str], ...]
    commitment: bytes
    body: bytes


class CalendarCommitmentUnavailable(ValueError):
    """A lookup returned HTTP 404; neither success nor permanent irrecoverability."""


def prepare_opentimestamps_calendar_request(
    *, operation: Literal["SUBMIT", "LOOKUP"], commitment: bytes
) -> OpenTimestampsCalendarRequest:
    """Prepare only the protocol-relative path, fixed public headers and digest body."""

    if type(operation) is not str or operation not in {"SUBMIT", "LOOKUP"}:
        raise ValueError("OpenTimestamps calendar operation is unsupported")
    if type(commitment) is not bytes or not 0 < len(commitment) <= 4096:
        raise ValueError("OpenTimestamps calendar commitment must be bounded immutable bytes")
    if operation == "SUBMIT" and len(commitment) != 32:
        raise ValueError("OpenTimestamps submission profile requires a SHA-256 commitment")
    return OpenTimestampsCalendarRequest(
        operation=operation,
        method="POST" if operation == "SUBMIT" else "GET",
        relative_path="digest" if operation == "SUBMIT" else "timestamp/" + commitment.hex(),
        headers=_HEADERS,
        commitment=commitment,
        body=commitment if operation == "SUBMIT" else b"",
    )


def _require_request(request: OpenTimestampsCalendarRequest) -> None:
    if type(request) is not OpenTimestampsCalendarRequest:
        raise ValueError("OpenTimestamps calendar request requires its exact data type")
    if (
        type(request.method) is not str
        or type(request.relative_path) is not str
        or type(request.body) is not bytes
        or type(request.headers) is not tuple
        or len(request.headers) != 2
        or any(
            type(pair) is not tuple
            or len(pair) != 2
            or any(type(value) is not str for value in pair)
            for pair in request.headers
        )
        or request
        != prepare_opentimestamps_calendar_request(
            operation=request.operation, commitment=request.commitment
        )
    ):
        raise ValueError("OpenTimestamps calendar request fields differ from the wire contract")


def replay_opentimestamps_calendar_response(
    request: OpenTimestampsCalendarRequest, *, status_code: int, body: bytes
) -> OpenTimestampsCalendarReplay:
    """Check complete response bytes, never a caller-truncated prefix of a live stream.

    A future transport must detect overflow while reading at most limit+1 bytes,
    reject redirects and retain original request/response custody. This function
    can verify only the complete bytes it receives, not transport completeness.
    """

    _require_request(request)
    if type(body) is not bytes or len(body) > MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES:
        raise ValueError("OpenTimestamps calendar response exceeds its immutable byte bound")
    if type(status_code) is not int:
        raise ValueError("OpenTimestamps calendar HTTP status must be an exact integer")
    if status_code == 404 and request.operation == "LOOKUP":
        raise CalendarCommitmentUnavailable("OpenTimestamps calendar commitment is unavailable")
    if status_code != 200:
        raise ValueError("OpenTimestamps calendar HTTP response is not successful")
    return replay_opentimestamps_calendar_proof(body, expected_commitment=request.commitment)


def _submission_context(file_sha256: str, nonce: bytes) -> tuple[bytes, bytes]:
    if (
        type(file_sha256) is not str
        or len(file_sha256) != 64
        or any(character not in "0123456789abcdef" for character in file_sha256)
    ):
        raise ValueError("OpenTimestamps file SHA-256 must be exact lowercase hex")
    if type(nonce) is not bytes or len(nonce) != 16:
        raise ValueError("OpenTimestamps submission nonce must contain exactly 16 immutable bytes")
    digest = bytes.fromhex(file_sha256)
    return digest, hashlib.sha256(digest + nonce).digest()


def prepare_opentimestamps_submission(
    *, file_sha256: str, nonce: bytes
) -> OpenTimestampsCalendarRequest:
    """Prepare the nonce-protected commitment; caller nonce freshness is not proven."""

    _, commitment = _submission_context(file_sha256, nonce)
    return prepare_opentimestamps_calendar_request(operation="SUBMIT", commitment=commitment)


def assemble_opentimestamps_submission_proof(
    request: OpenTimestampsCalendarRequest,
    *,
    file_sha256: str,
    nonce: bytes,
    status_code: int,
    body: bytes,
) -> bytes:
    """Join the exact original submission context to a fully rechecked detached proof.

    The resulting bytes may still be pending or reference a false chain anchor.
    They do not establish that any request was sent, accepted, or published.
    """

    _require_request(request)
    digest, _ = _submission_context(file_sha256, nonce)
    if request != prepare_opentimestamps_submission(file_sha256=file_sha256, nonce=nonce):
        raise ValueError("OpenTimestamps submission context differs from the original request")
    replay_opentimestamps_calendar_response(request, status_code=status_code, body=body)
    raw = _MAGIC + b"\x01\x08" + digest + b"\xf0\x10" + nonce + b"\x08" + body
    # Recheck total depth/entry bounds, including the two added commitment operations.
    replay_detached_opentimestamps_proof(raw, expected_file_sha256=file_sha256)
    return raw
