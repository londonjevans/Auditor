"""Synthetic wire cases, never externally anchored timestamp or release evidence."""

from __future__ import annotations

import hashlib
import socket
import subprocess
from dataclasses import FrozenInstanceError

import pytest

from mmaudit.models.opentimestamps_replay import (
    MAX_OPENTIMESTAMPS_ATTESTATIONS,
    MAX_OPENTIMESTAMPS_DEPTH,
    MAX_OPENTIMESTAMPS_ENTRIES,
    MAX_OPENTIMESTAMPS_PROOF_BYTES,
    replay_detached_opentimestamps_proof,
)

MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
DIGEST = bytes(range(32))
BITCOIN = bytes.fromhex("0588960d73d71901")
PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OPAQUE = b"test-tag"


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


def envelope(tree: bytes) -> bytes:
    return MAGIC + b"\x01\x08" + DIGEST + tree


def replay(tree: bytes):
    return replay_detached_opentimestamps_proof(envelope(tree), expected_file_sha256=DIGEST.hex())


def siblings(entries: list[bytes]) -> bytes:
    return b"".join(b"\xff" + entry for entry in entries[:-1]) + entries[-1]


def test_all_siblings_and_descendants_use_their_own_parent_message():
    pending = attestation(PENDING, blob(b"http://127.0.0.1/private"))
    unknown = attestation(OPAQUE, b"synthetic opaque payload")
    tree = (
        b"\xff"
        + pending
        + b"\xff"
        + unknown
        + b"\xff\xf0"
        + blob(b"suffix")
        + b"\x08"
        + attestation(payload=number(321))
        + b"\xf1"
        + blob(b"prefix")
        + b"\x08"
        + attestation(payload=number(654))
    )
    observed = replay(tree)
    assert observed.entry_count == 8
    assert observed.maximum_depth == 3
    assert [item.kind for item in observed.attestations] == [
        "PENDING",
        "OPAQUE",
        "BITCOIN_HEIGHT",
        "BITCOIN_HEIGHT",
    ]
    assert [item.commitment_hex for item in observed.attestations] == [
        DIGEST.hex(),
        DIGEST.hex(),
        hashlib.sha256(DIGEST + b"suffix").hexdigest(),
        hashlib.sha256(b"prefix" + DIGEST).hexdigest(),
    ]
    assert [item.claimed_bitcoin_height for item in observed.attestations] == [None, None, 321, 654]
    assert observed.proof_sha256 == hashlib.sha256(envelope(tree)).hexdigest()
    assert "127.0.0.1" not in repr(observed)


@pytest.mark.parametrize(
    "operation, expected",
    [
        (b"\x08", hashlib.sha256(DIGEST).digest()),
        (b"\xf2", DIGEST[::-1]),
        (b"\xf3\x08", hashlib.sha256(DIGEST.hex().encode()).digest()),
        (b"\x08\x08", hashlib.sha256(hashlib.sha256(DIGEST).digest()).digest()),
    ],
)
def test_supported_unary_operations_are_replayed(operation, expected):
    assert replay(operation + attestation()).attestations[0].commitment_hex == expected.hex()


@pytest.mark.parametrize("height", [0, 127, 128, 16383, 16384, 2**32 - 1])
def test_minimal_leb128_height_boundaries(height):
    assert (
        replay(attestation(payload=number(height))).attestations[0].claimed_bitcoin_height == height
    )


@pytest.mark.parametrize(
    "payload", [b"", b"\x80", b"\x80\x00", b"\x81\x00", b"\x80" * 6, number(2**32)]
)
def test_bad_height_payload_is_not_attestation_evidence(payload):
    with pytest.raises(ValueError):
        replay(attestation(payload=payload))


@pytest.mark.parametrize("tree", [attestation(PENDING, blob(b"")), attestation(OPAQUE, b"")])
def test_pending_and_opaque_only_proofs_are_data_not_bitcoin_evidence(tree):
    observed = replay(tree)
    assert len(observed.attestations) == 1
    assert observed.attestations[0].claimed_bitcoin_height is None
    assert observed.attestations[0].kind != "BITCOIN_HEIGHT"
    with pytest.raises(FrozenInstanceError):
        observed.entry_count = 999
    with pytest.raises(FrozenInstanceError):
        observed.attestations[0].claimed_bitcoin_height = 1


@pytest.mark.parametrize(
    "tree",
    [
        attestation(PENDING, blob(b"https://calendar.invalid") + b"\x00"),
        attestation(PENDING, blob(b"https://calendar.invalid?query")),
        attestation(PENDING, blob(b"https://name@calendar.invalid")),
        attestation(PENDING, blob(b"https://calendar.invalid/%20")),
        attestation(PENDING, blob(b"\xff")),
        attestation(PENDING, blob(b"a" * 1001)),
        attestation(payload=b"\x01\x00"),
        b"\xf0" + blob(b"x") + attestation(),
    ],
)
def test_recognized_attestation_payloads_and_bitcoin_digest_length_are_strict(tree):
    with pytest.raises(ValueError):
        replay(tree)


def test_pending_uri_and_opaque_payload_upper_bounds():
    assert replay(attestation(PENDING, blob(b"a" * 1000))).attestations[0].kind == "PENDING"
    assert replay(attestation(OPAQUE, b"a" * 8192)).attestations[0].kind == "OPAQUE"
    with pytest.raises(ValueError, match="bound"):
        replay(attestation(OPAQUE, b"a" * 8193))


@pytest.mark.parametrize("tag", [2, 3, 0x67, 0x09, 0xFF])
@pytest.mark.parametrize("after_good_branch", [False, True])
def test_unsupported_operation_never_disappears_behind_a_good_branch(tag, after_good_branch):
    prefix = b"\xff" + attestation() if after_good_branch else b""
    with pytest.raises(ValueError):
        replay(prefix + bytes([tag]) + attestation())


@pytest.mark.parametrize(
    "entry",
    [attestation(), b"\x08" + attestation(), b"\xf0" + blob(b"x") + b"\x08" + attestation()],
)
def test_duplicate_entries_are_rejected_instead_of_overwritten_or_deduplicated(entry):
    with pytest.raises(ValueError, match="duplicate"):
        replay(b"\xff" + entry + entry)


@pytest.mark.parametrize("tag", [0xF0, 0xF1])
def test_binary_argument_and_message_boundaries(tag):
    assert replay(bytes([tag]) + blob(b"x" * 4064) + b"\x08" + attestation()).entry_count == 3
    for size in (0, 4065, 4096, 4097):
        with pytest.raises(ValueError):
            replay(bytes([tag]) + blob(b"x" * size) + b"\x08" + attestation())


def test_hexlify_bound_is_checked_before_expansion():
    good = b"\xf0" + blob(b"x" * 2016) + b"\xf3\x08" + attestation()
    assert replay(good).entry_count == 4
    with pytest.raises(ValueError, match="hexlify"):
        replay(b"\xf0" + blob(b"x" * 2017) + b"\xf3\x08" + attestation())


def test_depth_limit_uses_no_interpreter_recursion():
    assert (
        replay(b"\x08" * (MAX_OPENTIMESTAMPS_DEPTH - 1) + attestation()).maximum_depth
        == MAX_OPENTIMESTAMPS_DEPTH
    )
    with pytest.raises(ValueError, match="depth"):
        replay(b"\x08" * MAX_OPENTIMESTAMPS_DEPTH + attestation())


def test_attestation_limit_applies_across_siblings():
    entries = [
        attestation(payload=number(index)) for index in range(MAX_OPENTIMESTAMPS_ATTESTATIONS + 1)
    ]
    assert len(replay(siblings(entries[:-1])).attestations) == MAX_OPENTIMESTAMPS_ATTESTATIONS
    with pytest.raises(ValueError, match="attestation bound"):
        replay(siblings(entries))


def test_total_entry_limit_applies_across_many_shallow_branches():
    # 1024 distinct paths, each with append, two hashes and an attestation.
    paths = [
        b"\xf0" + blob(index.to_bytes(2)) + b"\x08\x08" + attestation() for index in range(1024)
    ]
    assert replay(siblings(paths)).entry_count == MAX_OPENTIMESTAMPS_ENTRIES
    paths[-1] = b"\x08" + paths[-1]
    with pytest.raises(ValueError, match="entry bound"):
        replay(siblings(paths))


def test_exact_proof_byte_bound_is_accepted_without_raising_attestation_credit():
    payload_bytes = MAX_OPENTIMESTAMPS_PROOF_BYTES - len(envelope(b"")) - 128 * 12 + 1
    size, remainder = divmod(payload_bytes, 128)
    entries = [
        attestation(index.to_bytes(8), b"x" * (size + (index < remainder))) for index in range(128)
    ]
    raw = envelope(siblings(entries))
    assert len(raw) == MAX_OPENTIMESTAMPS_PROOF_BYTES
    observed = replay_detached_opentimestamps_proof(raw, expected_file_sha256=DIGEST.hex())
    assert len(observed.attestations) == 128
    assert all(item.kind == "OPAQUE" for item in observed.attestations)
    with pytest.raises(ValueError, match="immutable bytes"):
        replay_detached_opentimestamps_proof(raw + b"\x00", expected_file_sha256=DIGEST.hex())


@pytest.mark.parametrize(
    "raw",
    [
        None,
        b"",
        bytearray(b"proof"),
        memoryview(b"proof"),
        b"x" * (MAX_OPENTIMESTAMPS_PROOF_BYTES + 1),
    ],
)
def test_only_bounded_immutable_bytes_are_accepted(raw):
    with pytest.raises(ValueError, match="immutable bytes"):
        replay_detached_opentimestamps_proof(raw, expected_file_sha256=DIGEST.hex())


@pytest.mark.parametrize(
    "expected", [None, 1, "", "ab" * 31, "ab" * 33, "AB" * 32, "g" * 64, " " + "1" * 63]
)
def test_expected_digest_is_exact_lowercase_sha256(expected):
    with pytest.raises(ValueError, match="lowercase hex"):
        replay_detached_opentimestamps_proof(envelope(attestation()), expected_file_sha256=expected)


def test_double_version_byte_and_wrong_file_hash_are_not_accepted():
    for raw in (
        MAGIC + b"\x01\x01\x08" + DIGEST + attestation(),
        MAGIC + b"\x02\x08" + DIGEST + attestation(),
        MAGIC + b"\x01\x02" + DIGEST + attestation(),
        b"x" + envelope(attestation())[1:],
        envelope(attestation()) + b"\x00",
    ):
        with pytest.raises(ValueError):
            replay_detached_opentimestamps_proof(raw, expected_file_sha256=DIGEST.hex())
    with pytest.raises(ValueError, match="differs from the expected digest"):
        replay_detached_opentimestamps_proof(
            envelope(attestation()), expected_file_sha256="ff" * 32
        )


@pytest.mark.parametrize(
    "prefix", range(len(envelope(b"\xf0" + blob(b"nonce") + b"\x08" + attestation())))
)
def test_every_truncated_prefix_is_rejected(prefix):
    raw = envelope(b"\xf0" + blob(b"nonce") + b"\x08" + attestation())
    with pytest.raises(ValueError):
        replay_detached_opentimestamps_proof(raw[:prefix], expected_file_sha256=DIGEST.hex())


def test_missing_continuation_and_nonminimal_payload_length_are_rejected():
    with pytest.raises(ValueError, match="truncated"):
        replay(b"\xff" + attestation())
    with pytest.raises(ValueError, match="minimally"):
        replay(b"\x00" + BITCOIN + b"\x81\x00\x01")


def test_different_digest_file_hashing_conventions_are_not_silently_interchanged():
    raw = envelope(attestation())
    for other in (
        hashlib.sha256(DIGEST).hexdigest(),
        hashlib.sha256(DIGEST.hex().encode()).hexdigest(),
    ):
        with pytest.raises(ValueError, match="differs from the expected digest"):
            replay_detached_opentimestamps_proof(raw, expected_file_sha256=other)


@pytest.mark.parametrize("which", ["bytes", "digest"])
def test_input_subclasses_cannot_override_digest_or_byte_access(which):
    class SuppliedBytes(bytes):
        pass

    class SuppliedText(str):
        pass

    raw = envelope(attestation())
    expected = DIGEST.hex()
    with pytest.raises(ValueError):
        replay_detached_opentimestamps_proof(
            SuppliedBytes(raw) if which == "bytes" else raw,
            expected_file_sha256=SuppliedText(expected) if which == "digest" else expected,
        )


def test_pending_and_bitcoin_replay_cannot_open_network_or_launch_tools(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("offline replay attempted external execution")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    observed = replay(
        siblings([attestation(PENDING, blob(b"http://127.0.0.1/private")), attestation()])
    )
    assert len(observed.attestations) == 2
    assert observed.attestations[0].kind == "PENDING"
    assert observed.attestations[1].kind == "BITCOIN_HEIGHT"
