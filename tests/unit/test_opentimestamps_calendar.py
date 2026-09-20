"""Independently assembled calendar wire cases; no transport or chain authority."""

from __future__ import annotations

import hashlib
import socket
import subprocess
from dataclasses import FrozenInstanceError, replace

import pytest

from mmaudit.models.opentimestamps_calendar import (
    CalendarCommitmentUnavailable,
    assemble_opentimestamps_submission_proof,
    prepare_opentimestamps_calendar_request,
    prepare_opentimestamps_submission,
    replay_opentimestamps_calendar_response,
)
from mmaudit.models.opentimestamps_replay import (
    MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES,
    replay_detached_opentimestamps_proof,
    replay_opentimestamps_calendar_proof,
)

DIGEST = bytes(range(32))
NONCE = b"synthetic-nonce!"
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")


def number(value: int) -> bytes:
    pieces = [value % 128]
    value //= 128
    while value:
        pieces[-1] |= 128
        pieces.append(value % 128)
        value //= 128
    return bytes(pieces)


def blob(value: bytes) -> bytes:
    return number(len(value)) + value


def attestation(tag: bytes = BITCOIN, payload: bytes = b"\x01") -> bytes:
    return b"\x00" + tag + blob(payload)


def siblings(entries: list[bytes]) -> bytes:
    return b"".join(b"\xff" + entry for entry in entries[:-1]) + entries[-1]


def submission():
    return prepare_opentimestamps_submission(file_sha256=DIGEST.hex(), nonce=NONCE)


def assemble(body: bytes, **changes):
    arguments = {"file_sha256": DIGEST.hex(), "nonce": NONCE, "status_code": 200, "body": body}
    arguments.update(changes)
    return assemble_opentimestamps_submission_proof(submission(), **arguments)


@pytest.mark.parametrize("length", [1, 32, 44, 4096])
def test_lookup_uses_exact_bounded_commitment_and_only_a_relative_path(length):
    commitment = b"x" * length
    request = prepare_opentimestamps_calendar_request(operation="LOOKUP", commitment=commitment)
    assert request.method == "GET"
    assert request.relative_path == "timestamp/" + commitment.hex()
    assert request.commitment == commitment and request.body == b""
    assert request.headers == (
        ("Accept", "application/vnd.opentimestamps.v1"),
        ("User-Agent", "mmaudit-opentimestamps"),
    )
    assert not hasattr(request, "origin") and not hasattr(request, "url")
    result = replay_opentimestamps_calendar_response(
        request, status_code=200, body=attestation(PENDING, blob(b"https://calendar.invalid"))
    )
    assert result.initial_commitment_hex == commitment.hex()
    assert result.attestations[0].commitment_hex == commitment.hex()
    assert result.attestations[0].kind == "PENDING"
    assert "calendar.invalid" not in repr(result)


def test_submission_sends_only_the_nonce_protected_binary_commitment():
    request = submission()
    expected = hashlib.sha256(DIGEST + NONCE).digest()
    assert len(NONCE) == 16
    assert request.operation == "SUBMIT" and request.method == "POST"
    assert request.relative_path == "digest"
    assert request.body == request.commitment == expected
    assert request.body != DIGEST and request.body != expected.hex().encode()
    with pytest.raises(FrozenInstanceError):
        request.body = DIGEST


@pytest.mark.parametrize("operation", [None, 1, True, "", "POST", "GET", "submit", "LOOKUP "])
def test_unknown_operation_is_not_a_request(operation):
    with pytest.raises(ValueError, match="operation"):
        prepare_opentimestamps_calendar_request(operation=operation, commitment=DIGEST)


@pytest.mark.parametrize("operation", ["SUBMIT", "LOOKUP"])
@pytest.mark.parametrize(
    "commitment", [None, b"", "ff", bytearray(DIGEST), memoryview(DIGEST), b"x" * 4097]
)
def test_commitment_must_be_bounded_exact_immutable_bytes(operation, commitment):
    with pytest.raises(ValueError, match="commitment"):
        prepare_opentimestamps_calendar_request(operation=operation, commitment=commitment)


@pytest.mark.parametrize("length", [1, 16, 31, 33, 44, 4096])
def test_submission_profile_is_sha256_even_though_lookup_allows_other_lengths(length):
    with pytest.raises(ValueError, match="SHA-256"):
        prepare_opentimestamps_calendar_request(operation="SUBMIT", commitment=b"x" * length)


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"method": None},
        {"relative_path": "/digest"},
        {"relative_path": "https://calendar.invalid/digest"},
        {"relative_path": "digest?token=synthetic"},
        {"relative_path": None},
        {"body": b"changed"},
        {"body": bytearray(DIGEST)},
        {"headers": ()},
        {"headers": [("Accept", "application/vnd.opentimestamps.v1")]},
        {"headers": (("Accept", "application/vnd.opentimestamps.v1"), ("User-Agent",))},
        {"headers": (("Accept", "application/vnd.opentimestamps.v1"), ("User-Agent", 1))},
        {"headers": (("Accept", "application/json"), ("User-Agent", "mmaudit-opentimestamps"))},
        {"headers": (("Authorization", "synthetic"), ("User-Agent", "mmaudit-opentimestamps"))},
        {"operation": "LOOKUP"},
        {"operation": []},
        {"commitment": b"different"},
    ],
)
def test_forged_request_fields_are_refused_before_response_admission(changes):
    request = replace(submission(), **changes)
    with pytest.raises(ValueError):
        replay_opentimestamps_calendar_response(request, status_code=200, body=attestation())
    with pytest.raises(ValueError):
        assemble_opentimestamps_submission_proof(
            request, file_sha256=DIGEST.hex(), nonce=NONCE, status_code=200, body=attestation()
        )


@pytest.mark.parametrize("supplied_request", [None, {}, object()])
def test_arbitrary_objects_are_not_wire_requests(supplied_request):
    with pytest.raises(ValueError, match="exact data type"):
        replay_opentimestamps_calendar_response(
            supplied_request, status_code=200, body=attestation()
        )


@pytest.mark.parametrize("operation", ["SUBMIT", "LOOKUP"])
@pytest.mark.parametrize(
    "status", [201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 413, 429, 500, 503]
)
def test_non_200_status_and_redirects_cannot_be_replayed(operation, status):
    request = prepare_opentimestamps_calendar_request(operation=operation, commitment=DIGEST)
    with pytest.raises(ValueError, match="not successful") as failure:
        replay_opentimestamps_calendar_response(request, status_code=status, body=b"private body")
    assert type(failure.value) is ValueError and "private body" not in str(failure.value)


def test_404_is_unavailable_only_for_lookup_and_does_not_make_success_permanent():
    request = prepare_opentimestamps_calendar_request(operation="LOOKUP", commitment=DIGEST)
    with pytest.raises(CalendarCommitmentUnavailable):
        replay_opentimestamps_calendar_response(request, status_code=404, body=b"untrusted error")
    with pytest.raises(ValueError, match="not successful") as failure:
        replay_opentimestamps_calendar_response(submission(), status_code=404, body=b"error")
    assert type(failure.value) is ValueError
    # A subsequent caller-supplied response is still independently validated.
    result = replay_opentimestamps_calendar_response(request, status_code=200, body=attestation())
    assert result.attestations[0].claimed_bitcoin_height == 1
    assert not hasattr(result, "verified") and not hasattr(result, "release_authorized")


@pytest.mark.parametrize("status", [None, True, "200", 200.0])
def test_status_is_an_exact_integer(status):
    with pytest.raises(ValueError, match="exact integer"):
        replay_opentimestamps_calendar_response(
            submission(), status_code=status, body=attestation()
        )


@pytest.mark.parametrize("status", [200, 404, 500])
@pytest.mark.parametrize(
    "body", [None, "proof", bytearray(b"proof"), memoryview(b"proof"), b"x" * 10001]
)
def test_body_type_and_size_are_checked_even_for_error_statuses(status, body):
    request = prepare_opentimestamps_calendar_request(operation="LOOKUP", commitment=DIGEST)
    with pytest.raises(ValueError, match="immutable byte bound"):
        replay_opentimestamps_calendar_response(request, status_code=status, body=body)


def test_complete_calendar_body_byte_boundary_and_no_prefix_acceptance():
    body = siblings([attestation(b"opaque-a", b"a" * 8192), attestation(b"opaque-b", b"b" * 1785)])
    assert len(body) == MAX_OPENTIMESTAMPS_CALENDAR_PROOF_BYTES == 10000
    result = replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
    assert result.entry_count == 2 and len(result.attestations) == 2
    assert result.response_sha256 == hashlib.sha256(body).hexdigest()
    for extra in (b"\x00", b"ignored trailing data"):
        with pytest.raises(ValueError, match="byte bound"):
            replay_opentimestamps_calendar_response(
                submission(), status_code=200, body=body + extra
            )
    with pytest.raises(ValueError, match="trailing"):
        replay_opentimestamps_calendar_response(
            submission(), status_code=200, body=attestation() + b"x"
        )


@pytest.mark.parametrize(
    "commitment", [None, b"", bytearray(DIGEST), memoryview(DIGEST), b"x" * 4097]
)
def test_direct_raw_reader_enforces_its_own_commitment_boundary(commitment):
    with pytest.raises(ValueError, match="commitment"):
        replay_opentimestamps_calendar_proof(attestation(), expected_commitment=commitment)


@pytest.mark.parametrize(
    "body", [None, b"", bytearray(b"proof"), memoryview(b"proof"), b"x" * 10001]
)
def test_direct_raw_reader_enforces_its_own_proof_boundary(body):
    with pytest.raises(ValueError, match="immutable bytes"):
        replay_opentimestamps_calendar_proof(body, expected_commitment=DIGEST)


def test_raw_tree_and_detached_file_are_not_interchangeable():
    detached = MAGIC + b"\x01\x08" + DIGEST + attestation()
    with pytest.raises(ValueError, match="not be a detached file"):
        replay_opentimestamps_calendar_proof(detached, expected_commitment=DIGEST)
    with pytest.raises(ValueError):
        replay_detached_opentimestamps_proof(attestation(), expected_file_sha256=DIGEST.hex())


@pytest.mark.parametrize("tag", [2, 3, 0x67, 9, 0xFF])
@pytest.mark.parametrize("after_good_branch", [False, True])
def test_unsupported_raw_branch_refuses_the_entire_response(tag, after_good_branch):
    prefix = b"\xff" + attestation() if after_good_branch else b""
    with pytest.raises(ValueError):
        replay_opentimestamps_calendar_response(
            submission(), status_code=200, body=prefix + bytes([tag]) + attestation()
        )


@pytest.mark.parametrize(
    "body",
    [
        b"",
        attestation()[:-1],
        b"\xff" + attestation(),
        attestation() + b"\x00",
        siblings([attestation(), attestation()]),
        b"\x00" + BITCOIN + b"\x81\x00\x01",
        attestation(payload=b"\x01\x00"),
        b"\xf0\x00\x08" + attestation(),
        b"\xf0" + blob(b"x" * 4096) + attestation(),
        attestation(PENDING, blob(b"https://calendar.invalid?query")),
    ],
)
def test_raw_tree_keeps_existing_eof_duplicate_and_operation_restrictions(body):
    with pytest.raises(ValueError):
        replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)


def test_long_pending_commitment_can_hash_but_cannot_exceed_intermediate_limit():
    commitment = b"x" * 4096
    result = replay_opentimestamps_calendar_proof(
        b"\x08" + attestation(), expected_commitment=commitment
    )
    assert result.attestations[0].commitment_hex == hashlib.sha256(commitment).hexdigest()
    for prefix in (b"\xf0" + blob(b"x"), b"\xf1" + blob(b"x"), b"\xf3"):
        with pytest.raises(ValueError, match="bound"):
            replay_opentimestamps_calendar_proof(
                prefix + attestation(), expected_commitment=commitment
            )


@pytest.mark.parametrize(
    "field", ["body", "commitment", "operation", "path", "status", "digest", "nonce"]
)
def test_scalar_subclasses_cannot_override_wire_access(field):
    class SuppliedBytes(bytes):
        pass

    class SuppliedText(str):
        pass

    class SuppliedInt(int):
        pass

    with pytest.raises(ValueError):
        if field == "digest":
            prepare_opentimestamps_submission(file_sha256=SuppliedText(DIGEST.hex()), nonce=NONCE)
        elif field == "nonce":
            prepare_opentimestamps_submission(file_sha256=DIGEST.hex(), nonce=SuppliedBytes(NONCE))
        else:
            request = submission()
            if field == "commitment":
                request = replace(request, commitment=SuppliedBytes(request.commitment))
            elif field == "operation":
                request = replace(request, operation=SuppliedText("SUBMIT"))
            elif field == "path":
                request = replace(request, relative_path=SuppliedText("digest"))
            replay_opentimestamps_calendar_response(
                request,
                status_code=SuppliedInt(200) if field == "status" else 200,
                body=SuppliedBytes(attestation()) if field == "body" else attestation(),
            )


@pytest.mark.parametrize("nonce", [None, b"", b"x" * 15, b"x" * 17, "x" * 16, bytearray(b"x" * 16)])
def test_nonce_requires_exact_16_immutable_bytes_without_claiming_entropy(nonce):
    with pytest.raises(ValueError, match="nonce"):
        prepare_opentimestamps_submission(file_sha256=DIGEST.hex(), nonce=nonce)


@pytest.mark.parametrize("digest", [None, b"a" * 64, "", "ab" * 31, "AB" * 32, "g" * 64, "ab" * 33])
def test_submission_file_digest_requires_exact_lowercase_sha256(digest):
    with pytest.raises(ValueError, match="lowercase hex"):
        prepare_opentimestamps_submission(file_sha256=digest, nonce=NONCE)


@pytest.mark.parametrize(
    "changes",
    [
        {"nonce": b"x" * 16},
        {"file_sha256": "ff" * 32},
        {"file_sha256": hashlib.sha256(DIGEST).hexdigest()},
        {"file_sha256": hashlib.sha256(DIGEST.hex().encode()).hexdigest()},
    ],
)
def test_assembly_refuses_rebinding_the_original_request_to_another_context(changes):
    with pytest.raises(ValueError, match="original request"):
        assemble(attestation(), **changes)


def test_lookup_cannot_be_assembled_as_an_original_submission():
    request = prepare_opentimestamps_calendar_request(
        operation="LOOKUP", commitment=submission().commitment
    )
    with pytest.raises(ValueError, match="original request"):
        assemble_opentimestamps_submission_proof(
            request, file_sha256=DIGEST.hex(), nonce=NONCE, status_code=200, body=attestation()
        )


def test_assembled_detached_proof_replays_exact_nonce_and_all_reply_branches():
    body = siblings(
        [
            attestation(PENDING, blob(b"https://calendar.invalid")),
            b"\xf1" + blob(b"sibling") + b"\x08" + attestation(payload=number(321)),
        ]
    )
    detached = assemble(body)
    assert detached == MAGIC + b"\x01\x08" + DIGEST + b"\xf0\x10" + NONCE + b"\x08" + body
    raw = replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
    result = replay_detached_opentimestamps_proof(detached, expected_file_sha256=DIGEST.hex())
    assert result.attestations == raw.attestations
    assert result.entry_count == raw.entry_count + 2 == 6
    assert result.maximum_depth == raw.maximum_depth + 2 == 5
    assert (
        result.attestations[1].commitment_hex
        == hashlib.sha256(b"sibling" + submission().commitment).hexdigest()
    )
    assert not hasattr(result, "require") and not hasattr(raw, "require")
    with pytest.raises(FrozenInstanceError):
        raw.entry_count = 0


def test_pending_only_assembly_has_no_verified_publication_or_automatic_lookup():
    detached = assemble(attestation(PENDING, blob(b"http://127.0.0.1/private")))
    result = replay_detached_opentimestamps_proof(detached, expected_file_sha256=DIGEST.hex())
    assert result.attestations[0].kind == "PENDING"
    assert result.attestations[0].claimed_bitcoin_height is None
    assert "127.0.0.1" not in repr(result)


def test_coherently_changed_context_calculates_another_root_without_authenticating_it():
    roots = []
    for nonce in (NONCE, b"x" * 16):
        request = prepare_opentimestamps_submission(file_sha256=DIGEST.hex(), nonce=nonce)
        detached = assemble_opentimestamps_submission_proof(
            request, file_sha256=DIGEST.hex(), nonce=nonce, status_code=200, body=attestation()
        )
        result = replay_detached_opentimestamps_proof(detached, expected_file_sha256=DIGEST.hex())
        roots.append(result.attestations[0].commitment_hex)
    assert roots[0] != roots[1]
    # Raw proof bytes do not carry a request binding or a trusted root. Custody
    # and independent anchoring are required in a future external owner.


@pytest.mark.parametrize("hashes", [253, 254, 255, 256])
def test_assembly_rechecks_depth_including_its_two_added_operations(hashes):
    body = b"\x08" * hashes + attestation()
    if hashes >= 256:
        with pytest.raises(ValueError, match="depth bound"):
            replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
    else:
        raw = replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
        assert raw.maximum_depth == hashes + 1
    if hashes >= 254:
        with pytest.raises(ValueError, match="depth bound"):
            assemble(body)
    else:
        result = replay_detached_opentimestamps_proof(
            assemble(body), expected_file_sha256=DIGEST.hex()
        )
        assert result.maximum_depth == 256


@pytest.mark.parametrize("entries", [4094, 4095, 4096, 4097])
def test_assembly_rechecks_entry_count_including_its_two_added_operations(entries):
    counts = [240 + entries - 4094] + [240] * 15 + [254]
    body = siblings(
        [
            b"\xf0" + blob(bytes([index])) + b"\x08" * (count - 2) + attestation()
            for index, count in enumerate(counts)
        ]
    )
    assert sum(counts) == entries and len(body) < 10000
    if entries == 4097:
        with pytest.raises(ValueError, match="entry bound"):
            replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
    else:
        raw = replay_opentimestamps_calendar_response(submission(), status_code=200, body=body)
        assert raw.entry_count == entries and raw.maximum_depth == 254
    if entries > 4094:
        with pytest.raises(ValueError, match="entry bound"):
            assemble(body)
    else:
        result = replay_detached_opentimestamps_proof(
            assemble(body), expected_file_sha256=DIGEST.hex()
        )
        assert result.entry_count == 4096 and result.maximum_depth == 256


@pytest.mark.parametrize(
    "status, body", [(404, b"missing"), (302, b"redirect"), (200, b""), (200, b"\xff")]
)
def test_assembly_never_emits_a_proof_for_a_failed_or_malformed_reply(status, body):
    with pytest.raises(ValueError):
        assemble(body, status_code=status)


def test_calendar_wire_operations_do_not_open_network_or_launch_reference_tools(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("wire-only calendar handling attempted external execution")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    body = siblings([attestation(PENDING, blob(b"http://127.0.0.1/private")), attestation()])
    detached = assemble(body)
    result = replay_detached_opentimestamps_proof(detached, expected_file_sha256=DIGEST.hex())
    lookup = prepare_opentimestamps_calendar_request(
        operation="LOOKUP", commitment=submission().commitment
    )
    replay = replay_opentimestamps_calendar_response(lookup, status_code=200, body=body)
    assert replay.attestations == result.attestations
