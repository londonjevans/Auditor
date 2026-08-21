from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from scripts.capture_public_model_lineage import (
    MAX_PUBLIC_LINEAGE_SOURCE_BYTES,
    PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
    PUBLIC_LINEAGE_MANIFEST_FILENAME,
    PUBLIC_LINEAGE_SOURCE_SPECS,
    CapturedPublicLineageSource,
    PublicLineageCaptureError,
    PublicLineageCaptureObservations,
    PublicLineageSourceSpec,
    capture_public_lineage_source,
    capture_public_lineage_sources,
    write_captured_source_files,
)

RETRIEVED_AT = datetime(2026, 8, 18, 8, 30, tzinfo=UTC)
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def _spec() -> PublicLineageSourceSpec:
    return PUBLIC_LINEAGE_SOURCE_SPECS[0]


def _source_content(spec: PublicLineageSourceSpec) -> bytes:
    return ("\n".join(spec.required_markers) + "\n").encode()


DEFAULT_SOURCE_CONTENT = _source_content(_spec())


def _captures() -> tuple[CapturedPublicLineageSource, ...]:
    return tuple(
        CapturedPublicLineageSource(
            spec=spec,
            retrieved_at=RETRIEVED_AT,
            final_url=spec.requested_url,
            redirect_chain=(spec.requested_url,),
            media_type="text/plain",
            content=_source_content(spec),
        )
        for spec in PUBLIC_LINEAGE_SOURCE_SPECS
    )


def _client(handler: httpx.MockTransport) -> httpx.Client:
    return httpx.Client(transport=handler, follow_redirects=False, trust_env=False)


def _response(
    status_code: int = 200,
    *,
    content: bytes = DEFAULT_SOURCE_CONTENT,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    response_headers = {"Content-Type": "text/plain"}
    if headers is not None:
        response_headers.update(headers)
    response_headers.setdefault("Content-Length", str(len(content)))
    return httpx.Response(
        status_code,
        stream=httpx.ByteStream(content),
        headers=response_headers,
    )


def _redirect_url(spec: PublicLineageSourceSpec) -> str:
    return (
        f"https://huggingface.co/api/resolve-cache/models/{spec.repository_path}/"
        f"{spec.immutable_revision}/README.md?etag=%22fixture%22"
    )


def test_fixed_source_inventory_is_exact_unique_and_immutable() -> None:
    assert len(PUBLIC_LINEAGE_SOURCE_SPECS) == 16
    assert tuple(spec.source_id for spec in PUBLIC_LINEAGE_SOURCE_SPECS) == tuple(
        sorted(spec.source_id for spec in PUBLIC_LINEAGE_SOURCE_SPECS)
    )
    assert len({spec.requested_url for spec in PUBLIC_LINEAGE_SOURCE_SPECS}) == 16
    assert len({spec.relative_path for spec in PUBLIC_LINEAGE_SOURCE_SPECS}) == 16
    assert all(len(spec.immutable_revision) == 40 for spec in PUBLIC_LINEAGE_SOURCE_SPECS)
    assert all(spec.required_markers for spec in PUBLIC_LINEAGE_SOURCE_SPECS)
    assert all(
        "/resolve/" in spec.requested_url
        for spec in PUBLIC_LINEAGE_SOURCE_SPECS
        if spec.source_id != "openai-gpt-oss-120b-readme"
    )
    openai_spec = next(
        spec
        for spec in PUBLIC_LINEAGE_SOURCE_SPECS
        if spec.source_id == "openai-gpt-oss-120b-readme"
    )
    assert "/599476783c6f88508dab8577808b5ead5cbee8d2/" in openai_spec.requested_url
    tencent_spec = next(
        spec for spec in PUBLIC_LINEAGE_SOURCE_SPECS if spec.source_id == "tencent-hy3-card"
    )
    assert tencent_spec == PublicLineageSourceSpec(
        source_id="tencent-hy3-card",
        requested_url=(
            "https://huggingface.co/tencent/Hy3/resolve/"
            "a960ebc3da325ba167f069f76c41eb62c9280d22/README.md"
        ),
        publisher_id="tencent",
        independence_key="tencent",
        immutable_revision="a960ebc3da325ba167f069f76c41eb62c9280d22",
        repository_path="tencent/Hy3",
        relative_path="sources/tencent-hy3-card.md",
        required_markers=(
            "**Hy3** is a 295B-parameter Mixture-of-Experts (MoE) model",
            "developed by the Tencent Hy Team",
        ),
    )


@pytest.mark.parametrize(
    (
        "source_id",
        "staged_relative_path",
        "expected_size",
        "expected_sha256",
        "byte_start",
        "byte_end",
        "marker_sha256",
    ),
    (
        (
            "deepseek-deepseek-v4-pro-0813-card",
            "docs/remediation/v3/operator_captures/deepseek-v4-pro-0813-card.md",
            7_522,
            "61755d88e95789fcd7a36f50892f97bba977a30fc99d0f2907ab787ed10b0e66",
            1_896,
            2_246,
            "3c3b6f124f6fd16710f60e936aa019ba585f4cbb380b8789e1611aeab8aa6f70",
        ),
        (
            "moonshot-kimi-k3-card",
            "docs/remediation/v3/operator_captures/moonshot-kimi-k3-card.md",
            45_261,
            "57de265b5842dfa465c6e73b368b0e15a89b8793b5450528dad577da202cc6fe",
            42_081,
            42_228,
            "bc4d7b66366b975cfd5782bca59158f36b6c09ea61791aa85581d8853f70233d",
        ),
    ),
)
def test_operator_staged_sources_bind_exact_compiled_claim_marker(
    source_id: str,
    staged_relative_path: str,
    expected_size: int,
    expected_sha256: str,
    byte_start: int,
    byte_end: int,
    marker_sha256: str,
) -> None:
    spec = next(spec for spec in PUBLIC_LINEAGE_SOURCE_SPECS if spec.source_id == source_id)
    assert len(spec.required_markers) == 1
    marker = spec.required_markers[0].encode("utf-8")
    staged_path = REPOSITORY_ROOT / staged_relative_path
    content = staged_path.read_bytes()

    assert not staged_path.is_symlink()
    assert len(content) == expected_size
    assert hashlib.sha256(content).hexdigest() == expected_sha256
    assert content.count(marker) == 1
    assert content[byte_start:byte_end] == marker
    assert byte_end - byte_start == len(marker)
    assert hashlib.sha256(marker).hexdigest() == marker_sha256


def test_committed_capture_journal_replays_exact_source_bytes() -> None:
    corpus_root = REPOSITORY_ROOT / "config" / "public_model_lineage"
    attributes = (REPOSITORY_ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "config/public_model_lineage/sources/*.md -text whitespace=-trailing-space" in attributes
    journal = PublicLineageCaptureObservations.model_validate_json(
        (corpus_root / PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME).read_bytes()
    )

    specs_by_id = {spec.source_id: spec for spec in PUBLIC_LINEAGE_SOURCE_SPECS}
    assert tuple(source.source_id for source in journal.sources) == tuple(
        spec.source_id for spec in PUBLIC_LINEAGE_SOURCE_SPECS
    )
    assert (
        journal.observation_set_sha256
        == "6ae6e75a1732c05b85ffe189febbc3ecfa8ae2eeeb83000a8a24d30035b966eb"
    )
    assert journal.bundle_sha256 == (
        "7b6ff67506bceaaf05c944edb2c28bf6d8386df3690444b827035ed5c83bc134"
    )
    assert sum(source.file_binding.size for source in journal.sources) == 421_754
    assert journal.sources[-1].retrieved_at - journal.sources[0].retrieved_at == timedelta(
        seconds=3
    )
    for source in journal.sources:
        spec = specs_by_id[source.source_id]
        path = corpus_root / source.file_binding.path
        content = path.read_bytes()
        assert not path.is_symlink()
        assert source.requested_url == spec.requested_url
        assert source.publisher_id == spec.publisher_id
        assert source.independence_key == spec.independence_key
        assert source.immutable_revision == spec.immutable_revision
        assert source.file_binding.size == len(content)
        assert (
            source.file_binding.sha256
            == CapturedPublicLineageSource(
                spec=spec,
                retrieved_at=source.retrieved_at,
                final_url=source.final_url,
                redirect_chain=source.redirect_chain,
                media_type=source.media_type,
                content=content,
            ).sha256
        )
        decoded = content.decode("utf-8", errors="strict")
        assert all(marker in decoded for marker in spec.required_markers)

    tencent = next(source for source in journal.sources if source.source_id == "tencent-hy3-card")
    assert tencent.retrieved_at == datetime(2026, 8, 21, 11, 42, 34, tzinfo=UTC)
    assert tencent.file_binding.size == 10_325
    assert (
        tencent.file_binding.sha256
        == "dbdfc5920bf548fb484b5ec1837032f6c85e1886f2930aa5bee629c1f9620e8b"
    )


def test_capture_retains_exact_bytes_metadata_and_identity_request_headers() -> None:
    observed: list[httpx.Request] = []
    content = DEFAULT_SOURCE_CONTENT + b"exact\x00bytes\n"

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return _response(content=content)

    with _client(httpx.MockTransport(handler)) as client:
        capture = capture_public_lineage_source(_spec(), client=client, retrieved_at=RETRIEVED_AT)

    assert capture.content == content
    assert capture.retrieved_at == RETRIEVED_AT
    assert capture.final_url == _spec().requested_url
    assert capture.redirect_chain == (_spec().requested_url,)
    assert capture.media_type == "text/plain"
    assert capture.sha256 == hashlib.sha256(content).hexdigest()
    assert len(observed) == 1
    assert observed[0].headers["accept-encoding"] == "identity"
    assert "authorization" not in observed[0].headers
    assert "cookie" not in observed[0].headers


def test_capture_records_only_reviewed_same_origin_redirect() -> None:
    spec = _spec()
    final_url = _redirect_url(spec)
    observed: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        observed.append(str(request.url))
        if len(observed) == 1:
            return _response(307, headers={"Location": final_url})
        return _response(content=DEFAULT_SOURCE_CONTENT + b"redirected exact bytes\n")

    with _client(httpx.MockTransport(handler)) as client:
        capture = capture_public_lineage_source(spec, client=client, retrieved_at=RETRIEVED_AT)

    assert observed == [spec.requested_url, final_url]
    assert capture.final_url == final_url
    assert capture.redirect_chain == (spec.requested_url, final_url)


@pytest.mark.parametrize(
    "location",
    (
        "http://huggingface.co/unsafe",
        "https://example.invalid/unsafe",
        "https://huggingface.co/api/resolve-cache/models/other/repository/deadbeef/README.md",
        "https://user@huggingface.co/unsafe",
    ),
)
def test_capture_rejects_redirects_outside_exact_source(location: str) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _response(307, headers={"Location": location})

    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="redirect"),
    ):
        capture_public_lineage_source(_spec(), client=client, retrieved_at=RETRIEVED_AT)
    assert calls == 1


def test_capture_rejects_redirect_cycle() -> None:
    spec = _spec()

    def handler(_request: httpx.Request) -> httpx.Response:
        return _response(307, headers={"Location": spec.requested_url})

    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="redirect cycle"),
    ):
        capture_public_lineage_source(spec, client=client, retrieved_at=RETRIEVED_AT)


def test_capture_rejects_nonempty_card_without_compiled_identity_marker() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _response(content=b"---\nlicense: other\n---\n")

    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="compiled identity marker"),
    ):
        capture_public_lineage_source(_spec(), client=client, retrieved_at=RETRIEVED_AT)


@pytest.mark.parametrize(
    ("content", "headers", "match"),
    (
        (
            b"x",
            {"Content-Length": str(MAX_PUBLIC_LINEAGE_SOURCE_BYTES + 1)},
            "byte bound",
        ),
        (b"x", {"Content-Type": "text/html"}, "media type"),
        (b"x", {"Content-Encoding": "gzip"}, "identity encoding"),
        (b"", {}, "empty"),
    ),
)
def test_capture_rejects_unsafe_or_non_documentary_response(
    content: bytes, headers: dict[str, str], match: str
) -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return _response(content=content, headers=headers)

    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match=match),
    ):
        capture_public_lineage_source(_spec(), client=client, retrieved_at=RETRIEVED_AT)


def test_capture_inventory_rejects_duplicates_before_network() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _response()

    duplicate = (_spec(), replace(_spec()))
    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="exact and compiled"),
    ):
        capture_public_lineage_sources(client=client, specs=duplicate)
    assert calls == 0


def test_capture_inventory_bounds_an_infinite_iterable_before_network() -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _response()

    class InfiniteSpecs:
        def __init__(self) -> None:
            self.next_calls = 0

        def __iter__(self) -> InfiniteSpecs:
            return self

        def __next__(self) -> PublicLineageSourceSpec:
            self.next_calls += 1
            return PUBLIC_LINEAGE_SOURCE_SPECS[0]

    specs = InfiniteSpecs()
    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="exact and compiled"),
    ):
        capture_public_lineage_sources(client=client, specs=specs)

    assert specs.next_calls == len(PUBLIC_LINEAGE_SOURCE_SPECS) + 1
    assert calls == 0


@pytest.mark.parametrize(
    ("field", "value"),
    (
        (
            "requested_url",
            "https://huggingface.co/unreviewed/model/resolve/" + "a" * 40 + "/README.md",
        ),
        ("publisher_id", "caller-authored-publisher"),
    ),
)
def test_capture_inventory_rejects_same_id_metadata_override_before_network(
    field: str,
    value: str,
) -> None:
    calls = 0

    def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _response()

    specs = list(PUBLIC_LINEAGE_SOURCE_SPECS)
    if field == "requested_url":
        specs[0] = replace(specs[0], requested_url=value)
    else:
        specs[0] = replace(specs[0], publisher_id=value)
    with (
        _client(httpx.MockTransport(handler)) as client,
        pytest.raises(PublicLineageCaptureError, match="exact and compiled"),
    ):
        capture_public_lineage_sources(client=client, specs=specs)
    assert calls == 0


def test_source_writer_rejects_same_id_traversal_before_any_write(tmp_path: Path) -> None:
    captures = list(_captures())
    forged_spec = replace(captures[0].spec, relative_path="sources/../../escaped.md")
    captures[0] = replace(captures[0], spec=forged_spec)

    with pytest.raises(PublicLineageCaptureError, match="exact compiled spec"):
        write_captured_source_files(output_dir=tmp_path / "public-lineage", captures=captures)

    assert tuple(tmp_path.iterdir()) == ()


def test_source_writer_publishes_exact_inventory_and_non_authorizing_journal(
    tmp_path: Path,
) -> None:
    captures = _captures()
    output = tmp_path / "public-lineage"

    observations = write_captured_source_files(output_dir=output, captures=captures)

    assert not (output / PUBLIC_LINEAGE_MANIFEST_FILENAME).exists()
    assert {
        path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()
    } == {
        *(spec.relative_path for spec in PUBLIC_LINEAGE_SOURCE_SPECS),
        PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
    }
    replayed = PublicLineageCaptureObservations.model_validate_json(
        (output / PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME).read_bytes()
    )
    assert replayed == observations
    assert replayed.lineage_identity_authorized is False
    assert replayed.source_egress_authorized is False
    assert replayed.provider_call_authorized is False
    for capture in captures:
        assert (output / capture.spec.relative_path).read_bytes() == capture.content
    assert tuple(source.file_binding.sha256 for source in replayed.sources) == tuple(
        capture.sha256 for capture in captures
    )
    with pytest.raises(PublicLineageCaptureError, match="must be absent"):
        write_captured_source_files(output_dir=output, captures=captures)


def test_capture_journal_rejects_metadata_reseal(tmp_path: Path) -> None:
    captures = _captures()
    output = tmp_path / "public-lineage"
    observations = write_captured_source_files(output_dir=output, captures=captures)
    payload = observations.model_dump(mode="python")
    payload["sources"][0]["publisher_id"] = "untrusted-publisher"

    with pytest.raises(ValidationError, match="observation hash is inconsistent"):
        PublicLineageCaptureObservations.model_validate(payload)


def test_source_writer_rejects_partial_inventory(tmp_path: Path) -> None:
    capture = CapturedPublicLineageSource(
        spec=_spec(),
        retrieved_at=RETRIEVED_AT,
        final_url=_spec().requested_url,
        redirect_chain=(_spec().requested_url,),
        media_type="text/plain",
        content=b"partial\n",
    )
    with pytest.raises(PublicLineageCaptureError, match="not exact"):
        write_captured_source_files(output_dir=tmp_path / "partial", captures=(capture,))


def test_source_writer_rejects_complete_inventory_with_semantically_empty_card(
    tmp_path: Path,
) -> None:
    captures = tuple(
        CapturedPublicLineageSource(
            spec=spec,
            retrieved_at=RETRIEVED_AT,
            final_url=spec.requested_url,
            redirect_chain=(spec.requested_url,),
            media_type="text/plain",
            content=(
                b"---\nlicense: other\n---\n"
                if index == 0
                else ("\n".join(spec.required_markers) + "\n").encode()
            ),
        )
        for index, spec in enumerate(PUBLIC_LINEAGE_SOURCE_SPECS)
    )

    with pytest.raises(PublicLineageCaptureError, match="compiled identity marker"):
        write_captured_source_files(output_dir=tmp_path / "semantic-gap", captures=captures)
    assert not (tmp_path / "semantic-gap").exists()
