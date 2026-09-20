"""Bounded offline OpenTimestamps replay; computed commitments are not chain authority.

This independent SHA-256-only reader uses the wire-format facts recorded in
docs/opentimestamps_replay.md. It neither imports the reference implementation nor
looks up a calendar, block header, clock, network, file or credential. A claimed
Bitcoin height is untrusted input, not evidence of publication or chronology.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal

MAX_OPENTIMESTAMPS_PROOF_BYTES = 1_048_576
MAX_OPENTIMESTAMPS_ENTRIES = 4096
MAX_OPENTIMESTAMPS_DEPTH = 256
MAX_OPENTIMESTAMPS_ATTESTATIONS = 1024
MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES = 10_000
_MESSAGE_BYTES = 4096
_PAYLOAD_BYTES = 8192
_HEIGHT_MAX = 2**32 - 1
_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
_BITCOIN = bytes.fromhex("0588960d73d71901")
_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
_URI_CHARACTERS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._/:")


@dataclass(frozen=True, slots=True)
class ReplayedTimestampAttestation:
    """An untrusted attestation and its calculated commitment, not a verified block."""

    kind: Literal["BITCOIN_HEIGHT", "PENDING", "OPAQUE"]
    tag_hex: str
    payload_sha256: str
    commitment_hex: str
    claimed_bitcoin_height: int | None


@dataclass(frozen=True, slots=True)
class OpenTimestampsReplay:
    """Data-only inspection. No consumer may treat this constructible value as a seal."""

    proof_sha256: str
    file_sha256: str
    entry_count: int
    maximum_depth: int
    attestations: tuple[ReplayedTimestampAttestation, ...]


@dataclass(frozen=True, slots=True)
class OpenTimestampsCalendarReplay:
    """Raw calendar-tree calculations, not an authenticated reply or publication."""

    response_sha256: str
    initial_commitment_hex: str
    entry_count: int
    maximum_depth: int
    attestations: tuple[ReplayedTimestampAttestation, ...]


@dataclass(slots=True)
class _Cursor:
    data: bytes
    offset: int = 0

    def take(self, count: int) -> bytes:
        end = self.offset + count
        if end > len(self.data):
            raise ValueError("OpenTimestamps proof is truncated")
        result = self.data[self.offset : end]
        self.offset = end
        return result

    def byte(self) -> int:
        return self.take(1)[0]

    def number(self, maximum: int) -> int:
        # Local admission profile: minimal unsigned LEB128, at most five bytes.
        value = 0
        for index in range(5):
            part = self.byte()
            value += (part & 127) << (7 * index)
            if value > maximum:
                raise ValueError("OpenTimestamps integer exceeds its bound")
            if part < 128:
                if index and part == 0:
                    raise ValueError("OpenTimestamps integer is not minimally encoded")
                return value
        raise ValueError("OpenTimestamps integer encoding exceeds its byte bound")

    def blob(self, maximum: int) -> bytes:
        return self.take(self.number(maximum))

    def finish(self) -> None:
        if self.offset != len(self.data):
            raise ValueError("OpenTimestamps proof or attestation has trailing bytes")


@dataclass(slots=True)
class _Branch:
    message: bytes
    depth: int
    entries: set[tuple[int, bytes]] = field(default_factory=set)


def _operation(tag: int, cursor: _Cursor, message: bytes) -> tuple[bytes, bytes]:
    argument = b""
    if tag in (0xF0, 0xF1):
        argument = cursor.blob(_MESSAGE_BYTES)
        if not argument:
            raise ValueError("OpenTimestamps append/prepend argument is empty")
        if len(message) + len(argument) > _MESSAGE_BYTES:
            raise ValueError("OpenTimestamps operation result exceeds its byte bound")
        result = message + argument if tag == 0xF0 else argument + message
    elif tag == 0x08:
        result = hashlib.sha256(message).digest()
    elif tag == 0xF2:
        result = message[::-1]
    elif tag == 0xF3:
        if len(message) > _MESSAGE_BYTES // 2:
            raise ValueError("OpenTimestamps hexlify result exceeds its byte bound")
        result = message.hex().encode("ascii")
    else:
        # Unsupported branches must not disappear behind a supported attestation.
        raise ValueError("OpenTimestamps operation is outside the supported SHA-256 profile")
    return argument, result


def _attestation(tag: bytes, payload: bytes, message: bytes) -> ReplayedTimestampAttestation:
    kind: Literal["BITCOIN_HEIGHT", "PENDING", "OPAQUE"] = "OPAQUE"
    height = None
    content = _Cursor(payload)
    if tag == _BITCOIN:
        kind = "BITCOIN_HEIGHT"
        height = content.number(_HEIGHT_MAX)
        content.finish()
        if len(message) != 32:
            raise ValueError("OpenTimestamps Bitcoin commitment must contain 32 bytes")
    elif tag == _PENDING:
        kind = "PENDING"
        uri = content.blob(1000)
        content.finish()
        if any(character not in _URI_CHARACTERS for character in uri):
            raise ValueError("OpenTimestamps pending URI contains unsupported characters")
        # Never expose a callable URI or attempt to fetch it, including loopback URIs.
    return ReplayedTimestampAttestation(
        kind=kind,
        tag_hex=tag.hex(),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        commitment_hex=message.hex(),
        claimed_bitcoin_height=height,
    )


def replay_detached_opentimestamps_proof(
    raw: bytes, *, expected_file_sha256: str
) -> OpenTimestampsReplay:
    """Replay every admitted branch from an exact caller-pinned SHA-256 file digest.

    The expected value is the detached file hash, not automatically the digest of
    a binary digest file or of a textual hex string. This function does no hashing
    convention conversion and issues no publication, time or release authority.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OPENTIMESTAMPS_PROOF_BYTES:
        raise ValueError("OpenTimestamps proof must be bounded nonempty immutable bytes")
    if (
        type(expected_file_sha256) is not str
        or len(expected_file_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_file_sha256)
    ):
        raise ValueError("OpenTimestamps expected file SHA-256 must be lowercase hex")
    cursor = _Cursor(raw)
    if cursor.take(len(_MAGIC)) != _MAGIC:
        raise ValueError("OpenTimestamps detached proof magic differs")
    if cursor.byte() != 1:
        raise ValueError("OpenTimestamps detached proof version is unsupported")
    if cursor.byte() != 0x08:
        raise ValueError("OpenTimestamps detached file hash must use SHA-256")
    digest = cursor.take(32)
    if digest.hex() != expected_file_sha256:
        raise ValueError("OpenTimestamps detached file digest differs from the expected digest")

    count, maximum_depth, attestations = _replay_tree(cursor, digest)
    return OpenTimestampsReplay(
        proof_sha256=hashlib.sha256(raw).hexdigest(),
        file_sha256=expected_file_sha256,
        entry_count=count,
        maximum_depth=maximum_depth,
        attestations=attestations,
    )


def replay_opentimestamps_calendar_proof(
    raw: bytes, *, expected_commitment: bytes
) -> OpenTimestampsCalendarReplay:
    """Replay a complete raw calendar tree at the caller's exact commitment.

    Pending commitments can exceed 32 bytes. No embedded file hash, network origin
    or header is available here; choosing a different initial commitment changes
    the calculation and cannot authenticate a different request or anchor.
    """

    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES:
        raise ValueError("OpenTimestamps calendar proof must be bounded immutable bytes")
    if type(expected_commitment) is not bytes or not 0 < len(expected_commitment) <= _MESSAGE_BYTES:
        raise ValueError("OpenTimestamps calendar commitment must be bounded immutable bytes")
    if raw.startswith(_MAGIC):
        raise ValueError("OpenTimestamps calendar reply must not be a detached file")
    count, maximum_depth, attestations = _replay_tree(_Cursor(raw), expected_commitment)
    return OpenTimestampsCalendarReplay(
        response_sha256=hashlib.sha256(raw).hexdigest(),
        initial_commitment_hex=expected_commitment.hex(),
        entry_count=count,
        maximum_depth=maximum_depth,
        attestations=attestations,
    )


def _replay_tree(
    cursor: _Cursor, initial_message: bytes
) -> tuple[int, int, tuple[ReplayedTimestampAttestation, ...]]:
    # Explicit depth-first stack avoids interpreter recursion and accounts for all
    # siblings, including those following an otherwise acceptable Bitcoin branch.
    stack = [_Branch(initial_message, 1)]
    attestations: list[ReplayedTimestampAttestation] = []
    count = 0
    maximum_depth = 1
    while stack:
        branch = stack[-1]
        count += 1
        if count > MAX_OPENTIMESTAMPS_ENTRIES:
            raise ValueError("OpenTimestamps proof exceeds its entry bound")
        marker = cursor.byte()
        more = marker == 0xFF
        tag = cursor.byte() if more else marker
        if not more:
            stack.pop()
        if tag == 0:
            if len(attestations) >= MAX_OPENTIMESTAMPS_ATTESTATIONS:
                raise ValueError("OpenTimestamps proof exceeds its attestation bound")
            attestation_tag = cursor.take(8)
            payload = cursor.blob(_PAYLOAD_BYTES)
            key = (tag, attestation_tag + payload)
            attestations.append(_attestation(attestation_tag, payload, branch.message))
        else:
            if branch.depth >= MAX_OPENTIMESTAMPS_DEPTH:
                raise ValueError("OpenTimestamps proof exceeds its depth bound")
            argument, result = _operation(tag, cursor, branch.message)
            key = (tag, argument)
            maximum_depth = max(maximum_depth, branch.depth + 1)
            stack.append(_Branch(result, branch.depth + 1))
        if key in branch.entries:
            raise ValueError("OpenTimestamps proof contains a duplicate node entry")
        branch.entries.add(key)
    cursor.finish()
    return count, maximum_depth, tuple(attestations)
