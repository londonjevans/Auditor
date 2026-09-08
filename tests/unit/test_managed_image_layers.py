from __future__ import annotations

import gzip
import time
import zlib
from dataclasses import FrozenInstanceError

import pytest
from pydantic import ValidationError

import mmaudit.orchestration.managed_image_layers as layers
from tests.oci_image_layer_support import inert_tar, layer_case
from tests.oci_image_metadata_support import metadata_case, sha256


def verify(case, **kwargs):
    return layers.verify_managed_image_layers(case.bundle, blob_root=case.root, **kwargs)


@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("codecs", [("tar",), ("gzip",), ("tar", "gzip"), ("gzip", "gzip")])
def test_stored_and_expanded_identities_are_observed_in_exact_order(tmp_path, indexed, codecs):
    case = layer_case(tmp_path / "blobs", codecs=codecs, indexed=indexed)
    observation = verify(case)
    assert observation.metadata.source_bundle_sha256 == case.bundle.bundle_sha256
    assert observation.total_stored_bytes == sum(map(len, case.stored))
    assert observation.total_expanded_bytes == sum(map(len, case.expanded))
    assert [item.stored_binding.sha256 for item in observation.layers] == list(case.layer_digests)
    assert [item.expanded_sha256 for item in observation.layers] == [
        sha256(raw) for raw in case.expanded
    ]
    assert [item.expanded_bytes for item in observation.layers] == list(map(len, case.expanded))
    assert [item.gzip_members for item in observation.layers] == [
        int(codec == "gzip") for codec in codecs
    ]
    for key in (
        "independently_trusted",
        "filesystem_verified",
        "image_side_attestation_verified",
        "execution_evidence_verified",
        "runtime_authority",
        "managed_run_ready",
    ):
        assert getattr(observation, key) is False
    with pytest.raises(FrozenInstanceError):
        observation.runtime_authority = True


@pytest.mark.parametrize("which", [0, 1])
def test_changed_raw_bytes_refuse_before_decoder_access(tmp_path, monkeypatch, which):
    case = layer_case(tmp_path / "blobs", codecs=("gzip", "gzip"))
    leaf = case.root / case.layer_digests[which]
    leaf.write_bytes(b"x" * len(case.stored[which]))
    actual, calls = layers.zlib.decompressobj, []

    def counted(*args, **kwargs):
        calls.append(True)
        return actual(*args, **kwargs)

    monkeypatch.setattr(layers.zlib, "decompressobj", counted)
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)
    assert len(calls) == which


def test_fresh_metadata_cannot_stand_in_for_missing_layer_material(tmp_path):
    case = metadata_case(tmp_path / "blobs")
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)


@pytest.mark.parametrize(
    "mode",
    [
        "truncated-header",
        "truncated-footer",
        "crc",
        "length",
        "trailing",
        "padding",
        "zlib",
        "plain",
    ],
)
def test_malformed_gzip_refuses_even_with_matching_stored_digest(tmp_path, mode):
    raw = inert_tar()
    content = gzip.compress(raw, mtime=0)
    if mode == "truncated-header":
        content = content[:5]
    elif mode == "truncated-footer":
        content = content[:-1]
    elif mode in {"crc", "length"}:
        offset = -8 if mode == "crc" else -4
        value = bytearray(content)
        value[offset] ^= 1
        content = bytes(value)
    elif mode == "trailing":
        content += b"unaccounted"
    elif mode == "padding":
        content += b"\x00" * 4
    elif mode == "zlib":
        content = zlib.compress(raw)
    else:
        content = raw
    case = layer_case(tmp_path / "blobs", codecs=("gzip",), expanded=(raw,), stored=(content,))
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case)


def test_gzip_output_must_match_the_config_diff_id(tmp_path):
    case = layer_case(
        tmp_path / "blobs",
        codecs=("gzip",),
        expanded=(inert_tar(b"expected"),),
        stored=(gzip.compress(inert_tar(b"changed"), mtime=0),),
    )
    with pytest.raises(layers.ManagedImageLayerError, match="diff ID"):
        verify(case)


@pytest.mark.parametrize("pieces", [2, 3, 9])
@pytest.mark.parametrize("chunk_bytes", [1, 7, 65536])
def test_concatenated_gzip_members_and_split_headers_hash_the_entire_expansion(
    tmp_path, monkeypatch, pieces, chunk_bytes
):
    from mmaudit import release_io

    raw = inert_tar()
    step = len(raw) // pieces
    segments = [raw[i * step : (i + 1) * step] for i in range(pieces - 1)] + [
        raw[(pieces - 1) * step :]
    ]
    content = b"".join(gzip.compress(part, mtime=0) for part in segments)
    case = layer_case(tmp_path / "blobs", codecs=("gzip",), expanded=(raw,), stored=(content,))
    monkeypatch.setattr(release_io, "_READ_CHUNK_BYTES", chunk_bytes)
    observation = verify(case)
    assert observation.layers[0].gzip_members == pieces
    assert observation.layers[0].expanded_sha256 == sha256(raw)


def test_gzip_member_count_is_independently_bounded(tmp_path):
    raw = inert_tar()
    content = gzip.compress(b"", mtime=0) * 3 + gzip.compress(raw, mtime=0)
    case = layer_case(tmp_path / "blobs", codecs=("gzip",), expanded=(raw,), stored=(content,))
    assert verify(case).layers[0].gzip_members == 4
    with pytest.raises(layers.ManagedImageLayerError, match="member allowance"):
        verify(case, limits=layers.ManagedImageLayerLimits(max_gzip_members=3))


def test_zero_expansion_member_does_not_require_extra_total_byte_allowance(tmp_path):
    raw = inert_tar()
    case = layer_case(tmp_path / "blobs", codecs=("tar", "gzip"), expanded=(raw, b""))
    observation = verify(
        case, limits=layers.ManagedImageLayerLimits(max_total_expanded_bytes=len(raw))
    )
    assert observation.total_expanded_bytes == len(raw)
    assert observation.layers[1].expanded_bytes == 0


def test_repeated_layer_references_preserve_order_and_charge_each_occurrence(tmp_path):
    raw = inert_tar()
    case = layer_case(tmp_path / "blobs", codecs=("gzip", "gzip"), expanded=(raw, raw))
    result = verify(case)
    assert len(set(case.layer_digests)) == 1 and len(result.layers) == 2
    assert result.total_expanded_bytes == 2 * len(raw)
    assert result.total_stored_bytes == 2 * len(case.stored[0])
    with pytest.raises(layers.ManagedImageLayerError, match="stored layer"):
        verify(case, limits=layers.ManagedImageLayerLimits(max_total_bytes=len(case.stored[0])))


@pytest.mark.parametrize(
    "field",
    ["max_layer_bytes", "max_total_bytes", "max_expanded_layer_bytes", "max_total_expanded_bytes"],
)
@pytest.mark.parametrize("codecs", [("tar", "tar"), ("gzip", "gzip")])
def test_exact_and_one_byte_short_limits_narrow_each_layer_and_total(tmp_path, field, codecs):
    case = layer_case(tmp_path / "blobs", codecs=codecs)
    values = case.expanded if "expanded" in field else case.stored
    bound = sum(map(len, values)) if "total" in field else max(map(len, values))
    assert (
        verify(case, limits=layers.ManagedImageLayerLimits(**{field: bound})).total_expanded_bytes
        > 0
    )
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case, limits=layers.ManagedImageLayerLimits(**{field: bound - 1}))


def test_high_ratio_expansion_uses_bounded_decoder_calls(tmp_path, monkeypatch):
    raw = b"\x00" * (3 * 1024**2)
    case = layer_case(tmp_path / "blobs", codecs=("gzip",), expanded=(raw,))
    actual, calls = zlib.decompressobj, []

    class Observed:
        def __init__(self, *args, **kwargs):
            self.decoder = actual(*args, **kwargs)

        def decompress(self, data, max_length):
            calls.append(max_length)
            assert 0 < max_length <= layers._DECOMPRESS_CHUNK_BYTES
            return self.decoder.decompress(data, max_length)

        def __getattr__(self, name):
            assert name != "flush", "inflate flush is not an output bound"
            return getattr(self.decoder, name)

    monkeypatch.setattr(layers.zlib, "decompressobj", Observed)
    with pytest.raises(layers.ManagedImageLayerError, match="expanded byte"):
        verify(case, limits=layers.ManagedImageLayerLimits(max_expanded_layer_bytes=100000))
    assert len(calls) < 5


def test_unsupported_zstd_material_is_refused_before_any_layer_stream(tmp_path, monkeypatch):
    case = layer_case(tmp_path / "blobs", codecs=("zstd",))
    monkeypatch.setattr(
        layers, "stream_file_evidence", lambda **_: pytest.fail("unsupported codec read layer")
    )
    with pytest.raises(layers.ManagedImageLayerError, match="no supported local decoder"):
        verify(case)


@pytest.mark.parametrize(
    "field,value",
    [
        ("max_layer_bytes", True),
        ("max_layer_bytes", 0),
        ("max_total_bytes", "10"),
        ("max_expanded_layer_bytes", -1),
        ("max_gzip_members", 1025),
        ("timeout_seconds", float("inf")),
        ("timeout_seconds", float("nan")),
        ("timeout_seconds", 601),
    ],
)
def test_limits_refuse_invalid_values(field, value):
    with pytest.raises(ValidationError):
        layers.ManagedImageLayerLimits(**{field: value})


def test_mutated_limits_are_revalidated_before_metadata_reads(tmp_path, monkeypatch):
    case = layer_case(tmp_path / "blobs")
    limits = layers.ManagedImageLayerLimits()
    object.__setattr__(limits, "timeout_seconds", float("inf"))
    monkeypatch.setattr(
        layers,
        "read_managed_image_metadata",
        lambda *_, **__: pytest.fail("invalid limits read metadata"),
    )
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case, limits=limits)


def test_declared_limit_failure_precedes_layer_io(tmp_path, monkeypatch):
    case = layer_case(tmp_path / "blobs")
    monkeypatch.setattr(
        layers, "stream_file_evidence", lambda **_: pytest.fail("oversized selection read layers")
    )
    with pytest.raises(layers.ManagedImageLayerError, match="stored layer"):
        verify(case, limits=layers.ManagedImageLayerLimits(max_total_bytes=1))


@pytest.mark.parametrize("phase", ["metadata", "inflate", "between-layers", "final-metadata"])
def test_shared_deadline_cannot_restart_per_layer_or_per_phase(tmp_path, monkeypatch, phase):
    case = layer_case(tmp_path / "blobs", codecs=("gzip", "gzip"))
    now = [100.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    if phase in {"metadata", "final-metadata"}:
        actual, calls = layers.read_managed_image_metadata, []

        def expired(*args, **kwargs):
            result = actual(*args, **kwargs)
            calls.append(True)
            if len(calls) == (1 if phase == "metadata" else 2):
                now[0] = 102.0
            return result

        monkeypatch.setattr(layers, "read_managed_image_metadata", expired)
    elif phase == "between-layers":
        actual = layers._verify_layer

        def expired(*args, **kwargs):
            result = actual(*args, **kwargs)
            now[0] = 102.0
            return result

        monkeypatch.setattr(layers, "_verify_layer", expired)
    else:
        actual = layers.zlib.decompressobj

        def expired(*args, **kwargs):
            result = actual(*args, **kwargs)
            now[0] = 102.0
            return result

        monkeypatch.setattr(layers.zlib, "decompressobj", expired)
    with pytest.raises(layers.ManagedImageLayerError):
        verify(case, limits=layers.ManagedImageLayerLimits(timeout_seconds=1.0))
