from __future__ import annotations

import hashlib
import tarfile
import time

import pytest

import mmaudit.isolation.oci_layer as parser
from tests.oci_image_file_support import Entry, archive


def parse(raw, *, chunk_size=4096, limits=None):
    return parser.read_oci_layer(
        iter(raw[offset : offset + chunk_size] for offset in range(0, len(raw), chunk_size)),
        limits=limits or parser.OciLayerLimits(),
        absolute_deadline=time.monotonic() + 30,
    )


def record(key, value):
    payload = key + b"=" + value + b"\n"
    length = len(payload) + 2
    while len(str(length)) + 1 + len(payload) != length:
        length = len(str(length)) + 1 + len(payload)
    return str(length).encode() + b" " + payload


def pax_archive(payload, *, following=None, kind=tarfile.XHDTYPE, declared_size=None):
    info = tarfile.TarInfo("PaxHeader/synthetic")
    info.type = kind
    info.size = len(payload) if declared_size is None else declared_size
    return (
        info.tobuf(format=tarfile.USTAR_FORMAT)
        + payload
        + bytes((-len(payload)) % 512)
        + (archive([Entry("selected", b"inert")]) if following is None else following)
    )


@pytest.mark.parametrize("chunk_size", [1, 7, 511, 512, 513, 65536])
def test_exact_streamed_hashes_and_supported_entry_metadata(chunk_size):
    raw = archive(
        [
            Entry("./", kind=tarfile.DIRTYPE),
            Entry("./dir/", kind=tarfile.DIRTYPE),
            Entry("dir/value", b"synthetic", mode=0o444, uid=12, gid=34),
            Entry("dir/alias", kind=tarfile.LNKTYPE, target="dir/value"),
            Entry("link", kind=tarfile.SYMTYPE, target="/dir/value"),
            Entry("dir/.wh.old"),
            Entry("dir/.wh..wh..opq"),
        ]
    )
    result = parse(raw, chunk_size=chunk_size)
    assert [entry.kind for entry in result.entries] == [
        "directory",
        "directory",
        "file",
        "hardlink",
        "symlink",
        "whiteout",
        "opaque",
    ]
    assert [entry.path for entry in result.entries][:3] == ["", "dir", "dir/value"]
    file = result.entries[2]
    assert (file.sha256, file.size) == (hashlib.sha256(b"synthetic").hexdigest(), 9)
    assert (file.mode, file.uid, file.gid) == (0o444, 12, 34)
    assert result.headers == 7
    assert not any(hasattr(entry, "content") for entry in result.entries)


def test_local_pax_unicode_paths_and_numeric_overrides_are_bounded_byte_records():
    raw = archive(
        [
            Entry(
                "ignored",
                b"inert",
                pax={
                    "path": "nested/" + "é" * 70,
                    "size": "5",
                    "uid": "123",
                    "gid": "456",
                    "uname": "synthetic",
                    "gname": "synthetic",
                    "mtime": "-1.25",
                    "atime": "0",
                    "ctime": "1.0",
                },
            )
        ],
        format=tarfile.PAX_FORMAT,
    )
    result = parse(raw, chunk_size=7)
    assert result.entries[0].path == "nested/" + "é" * 70
    assert (result.entries[0].uid, result.entries[0].gid) == (123, 456)
    assert result.headers == 2
    assert result.metadata_bytes > len(result.entries[0].path.encode())


def test_pax_link_override_is_not_the_truncated_header_target():
    target = "/" + "nested/" * 20 + "value"
    result = parse(
        archive([Entry("link", kind=tarfile.SYMTYPE, target=target)], format=tarfile.PAX_FORMAT)
    )
    assert result.entries[0].link_target == target


def test_ustar_prefix_and_null_regular_type_are_supported():
    name = "parent/" * 15 + "value"
    result = parse(archive([Entry(name, b"inert", kind=tarfile.AREGTYPE)]))
    assert result.entries[0].path == name
    assert result.entries[0].kind == "file"


def test_empty_layer_still_consumes_all_end_padding():
    assert parse(archive([])).entries == ()
    with pytest.raises(ValueError):
        parse(archive([]) + b"extra")


@pytest.mark.parametrize(
    "path",
    [
        "/absolute",
        "../outside",
        "nested/../outside",
        "nested/./value",
        "nested//value",
        "value/",
        "././value",
        "",
        ".",
        "back\\slash",
        "control\x01",
        "control\x7f",
        ".wh.parent/child",
        "nested/.wh.parent/child",
    ],
)
def test_ambiguous_or_reserved_paths_refuse(path):
    with pytest.raises(ValueError):
        parse(archive([Entry(path, b"inert")]))


@pytest.mark.parametrize("paths", [("a", "a"), ("a", "./a"), ("dir/", "dir")])
def test_duplicate_canonical_names_refuse(paths):
    with pytest.raises(ValueError, match="duplicate"):
        parse(archive([Entry(path, kind=tarfile.DIRTYPE) for path in paths]))


@pytest.mark.parametrize(
    "entry",
    [
        Entry(".wh.old", b"not empty"),
        Entry(".wh.old", kind=tarfile.DIRTYPE),
        Entry(".wh.old", kind=tarfile.SYMTYPE, target="value"),
        Entry(".wh."),
        Entry(".wh.."),
        Entry(".wh..."),
        Entry(".wh..wh.unsupported"),
        Entry(".wh..wh..opq", b"not empty"),
    ],
)
def test_invalid_whiteouts_refuse(entry):
    with pytest.raises(ValueError):
        parse(archive([entry]))


@pytest.mark.parametrize(
    "kind",
    [
        tarfile.CHRTYPE,
        tarfile.BLKTYPE,
        tarfile.FIFOTYPE,
        tarfile.CONTTYPE,
        tarfile.GNUTYPE_LONGNAME,
        tarfile.GNUTYPE_LONGLINK,
        tarfile.GNUTYPE_SPARSE,
        tarfile.XGLTYPE,
        b"Z",
    ],
)
def test_unsupported_entries_and_global_extensions_refuse(kind):
    with pytest.raises(ValueError, match="unsupported"):
        parse(archive([Entry("synthetic", kind=kind)]))


def test_gnu_magic_refuses_even_for_a_regular_file():
    with pytest.raises(ValueError, match="ustar"):
        parse(archive([Entry("value", b"inert")], format=tarfile.GNU_FORMAT))


@pytest.mark.parametrize(
    "payload",
    [
        b"0 path=value\n",
        b"99 path=value\n",
        b"2 x",
        b"01 path=x\n",
        b"9 path=x!",
        record(b"path", b""),
        record(b"path", b"value\0"),
        record(b"path", b"value") * 2,
        record(b"unknown", b"value"),
        record(b"GNU.sparse.map", b"0,1"),
        record(b"SCHILY.xattr.security.capability", b"inert"),
        record(b"hdrcharset", b"BINARY"),
        record(b"size", b"-1"),
        record(b"uid", b"1.0"),
        record(b"gid", b"x"),
        record(b"mtime", b"nan"),
        record(b"path", b"\xff"),
        record(b"\xff", b"value"),
        b"1000000000000 path=x\n",
    ],
)
def test_malformed_duplicate_or_unmodeled_pax_records_refuse(payload):
    with pytest.raises(ValueError):
        parse(pax_archive(payload))


@pytest.mark.parametrize("mode", ["stacked", "orphan", "empty", "oversized"])
def test_pax_allocation_and_following_header_boundaries_refuse(mode):
    payload = record(b"path", b"value")
    raw = pax_archive(payload)
    if mode == "stacked":
        raw = pax_archive(payload, following=raw)
    elif mode == "orphan":
        raw = pax_archive(payload, following=archive([]))
    elif mode == "empty":
        raw = pax_archive(b"")
    else:
        raw = pax_archive(b"", declared_size=10**9)
    with pytest.raises(ValueError):
        parse(raw)


@pytest.mark.parametrize(
    "mode",
    [
        "short-header",
        "short-payload",
        "one-end",
        "short-padding",
        "checksum",
        "payload-padding",
        "second-end",
        "trailing-data",
    ],
)
def test_bad_headers_payload_padding_and_complete_eof_refuse(mode):
    raw = archive([Entry("value", b"inert")])
    if mode == "short-header":
        raw = raw[:511]
    elif mode == "short-payload":
        raw = raw[:514]
    elif mode == "one-end":
        raw = raw[:1536]
    elif mode == "short-padding":
        raw = raw[:-1]
    elif mode == "trailing-data":
        raw += b"x" * 512
    else:
        value = bytearray(raw)
        value[{"checksum": 0, "payload-padding": 517, "second-end": 1536}[mode]] ^= 1
        raw = bytes(value)
    with pytest.raises(ValueError):
        parse(raw)


@pytest.mark.parametrize(
    "entry",
    [
        Entry("link", kind=tarfile.SYMTYPE),
        Entry("link", kind=tarfile.LNKTYPE, target="../out"),
        Entry("link", kind=tarfile.LNKTYPE, target="/absolute"),
        Entry("link", kind=tarfile.SYMTYPE, target="bad\x01"),
        Entry("link", b"payload", kind=tarfile.SYMTYPE, target="value"),
        Entry("directory", b"payload", kind=tarfile.DIRTYPE),
        Entry("file", b"inert", target="unmodeled"),
        Entry("directory/", kind=tarfile.AREGTYPE),
        Entry("/", kind=tarfile.DIRTYPE),
    ],
)
def test_incompatible_type_size_and_link_metadata_refuse(entry):
    with pytest.raises(ValueError):
        parse(archive([entry]))


@pytest.mark.parametrize(
    "override",
    [
        {"max_headers": 1},
        {"max_metadata_bytes": 3},
        {"max_path_bytes": 3},
        {"max_path_depth": 1},
        {"max_pax_bytes": 1},
    ],
)
def test_independent_parser_allowances_refuse(override):
    raw = archive([Entry("a/value", b"inert", pax={"mtime": "1.0"})], format=tarfile.PAX_FORMAT)
    with pytest.raises(ValueError):
        parse(raw, limits=parser.OciLayerLimits(**override))


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), -1.0])
def test_invalid_absolute_deadlines_refuse(deadline):
    with pytest.raises(ValueError):
        parser.read_oci_layer(iter(()), limits=parser.OciLayerLimits(), absolute_deadline=deadline)


def test_deadline_exhaustion_during_streaming_refuses(monkeypatch):
    now = [1.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    raw = archive([Entry("value", b"inert")])

    def chunks():
        yield raw[:512]
        now[0] = 31.0
        yield raw[512:]

    with pytest.raises(ValueError, match="deadline"):
        parser.read_oci_layer(chunks(), limits=parser.OciLayerLimits(), absolute_deadline=31.0)


def test_parser_uses_no_tarfile_reader_or_extraction(monkeypatch):
    raw = archive([Entry("value", b"inert")])

    def refused(*args, **kwargs):
        pytest.fail("invariant: parser must not open a TarFile or extract")

    monkeypatch.setattr(tarfile, "open", refused)
    monkeypatch.setattr(tarfile.TarFile, "__init__", refused)
    assert parse(raw).entries[0].size == 5


def test_file_body_chunks_have_a_fixed_memory_bound():
    reader = parser._ChunkReader(iter([b"x" * (3 * 65536 + 17)]), time.monotonic() + 10)
    sizes = [len(piece) for piece in reader.pieces(3 * 65536 + 17)]
    assert sizes == [65536, 65536, 65536, 17]


@pytest.mark.parametrize(
    "offset, replacement",
    [(100, b"\x80"), (108, b"-"), (124, b"+"), (329, b"9"), (10, b"x"), (500, b"x")],
)
def test_non_ustar_numeric_or_hidden_header_text_refuses(offset, replacement):
    raw = bytearray(archive([Entry("value", b"inert")]))
    raw[offset : offset + 1] = replacement
    raw[148:156] = b" " * 8
    checksum = sum(raw[:512])
    raw[148:156] = f"{checksum:06o}\0 ".encode()
    with pytest.raises(ValueError):
        parse(bytes(raw))


def test_oversized_pax_is_refused_before_extension_payload_access():
    raw = pax_archive(b"", declared_size=10**9)

    def chunks():
        yield raw[:512]
        pytest.fail("invariant: oversized PAX must refuse before requesting its body")

    with pytest.raises(ValueError, match="oversized"):
        parser.read_oci_layer(
            chunks(), limits=parser.OciLayerLimits(), absolute_deadline=time.monotonic() + 10
        )


def test_mutated_limits_and_limits_subclasses_are_not_accepted():
    class Derived(parser.OciLayerLimits):
        pass

    for limits in (Derived(), parser.OciLayerLimits().model_copy(update={"max_headers": -1})):
        with pytest.raises(ValueError):
            parse(archive([]), limits=limits)
