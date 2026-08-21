"""Capture the fixed public model-lineage documentary corpus.

This is a maintenance tool for the repository-owned, provider-free lineage bundle.
It fetches only the verifier-reviewed first-party source inventory below.  It does
not contact a model provider API, read credentials, or grant runtime authority.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Literal, Self
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.reporting.json_report import stable_json_bytes

MAX_PUBLIC_LINEAGE_SOURCE_BYTES = 100_000
MAX_PUBLIC_LINEAGE_REDIRECTS = 3
PUBLIC_LINEAGE_MANIFEST_FILENAME = "manifest.json"
PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME = "capture-observations.json"
_ALLOWED_MEDIA_TYPES = frozenset({"text/markdown", "text/plain"})
_CAPTURE_HEADERS = {
    "Accept": "text/markdown, text/plain;q=0.9",
    "Accept-Encoding": "identity",
    "User-Agent": "mmaudit-public-lineage-capture/1",
}
_TIMEOUT = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)


class PublicLineageCaptureError(ValueError):
    """Raised when a public documentary source cannot be captured exactly."""


class _StrictCaptureModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class PublicLineageCaptureObservation(_StrictCaptureModel):
    """Non-authorizing exact response observation for one captured source."""

    source_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,99}$")
    requested_url: str = Field(min_length=9, max_length=8_192)
    final_url: str = Field(min_length=9, max_length=8_192)
    redirect_chain: tuple[str, ...] = Field(min_length=1, max_length=5)
    publisher_id: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    independence_key: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    source_kind: Literal["PRIMARY_PUBLISHER_MODEL_CARD"]
    immutable_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    retrieved_at: datetime
    media_type: Literal["text/markdown", "text/plain"]
    file_binding: ManifestFileBinding
    observation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("retrieved_at")
    @classmethod
    def retrieval_is_whole_second_utc(cls, value: datetime) -> datetime:
        _validate_retrieved_at(value)
        return value

    @model_validator(mode="after")
    def redirect_and_hash_are_consistent(self) -> Self:
        if (
            self.redirect_chain[0] != self.requested_url
            or self.redirect_chain[-1] != self.final_url
            or len(self.redirect_chain) != len(set(self.redirect_chain))
        ):
            raise ValueError("public lineage redirect chain is inconsistent")
        expected = canonical_sha256(self.model_dump(mode="json", exclude={"observation_sha256"}))
        if self.observation_sha256 != expected:
            raise ValueError("public lineage capture observation hash is inconsistent")
        return self


class PublicLineageCaptureObservations(_StrictCaptureModel):
    """Canonical non-authorizing journal for one complete source capture."""

    schema_version: Literal["1.0"] = "1.0"
    sources: tuple[PublicLineageCaptureObservation, ...] = Field(min_length=1, max_length=32)
    lineage_identity_authorized: Literal[False] = False
    source_egress_authorized: Literal[False] = False
    provider_call_authorized: Literal[False] = False
    observation_set_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def inventory_and_hashes_are_consistent(self) -> Self:
        source_ids = tuple(source.source_id for source in self.sources)
        if source_ids != tuple(sorted(set(source_ids))):
            raise ValueError("public lineage capture observations must be unique and sorted")
        expected_set = canonical_sha256([source.observation_sha256 for source in self.sources])
        if self.observation_set_sha256 != expected_set:
            raise ValueError("public lineage capture observation set hash is inconsistent")
        expected_bundle = canonical_sha256(self.model_dump(mode="json", exclude={"bundle_sha256"}))
        if self.bundle_sha256 != expected_bundle:
            raise ValueError("public lineage capture bundle hash is inconsistent")
        return self


@dataclass(frozen=True, slots=True)
class PublicLineageSourceSpec:
    """One compiled first-party source that the capture tool may contact."""

    source_id: str
    requested_url: str
    publisher_id: str
    independence_key: str
    immutable_revision: str
    repository_path: str
    relative_path: str
    required_markers: tuple[str, ...]
    source_kind: str = "PRIMARY_PUBLISHER_MODEL_CARD"


@dataclass(frozen=True, slots=True)
class CapturedPublicLineageSource:
    """Exact bytes and response metadata observed for one source."""

    spec: PublicLineageSourceSpec
    retrieved_at: datetime
    final_url: str
    redirect_chain: tuple[str, ...]
    media_type: str
    content: bytes

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


PUBLIC_LINEAGE_SOURCE_SPECS = (
    PublicLineageSourceSpec(
        source_id="deepcogito-cogito-v2-1-671b-card",
        requested_url=(
            "https://huggingface.co/deepcogito/cogito-671b-v2.1/resolve/"
            "f5b0199c2c54a284b00f1a2db3942299d4198484/README.md"
        ),
        publisher_id="deepcogito",
        independence_key="deepcogito",
        immutable_revision="f5b0199c2c54a284b00f1a2db3942299d4198484",
        repository_path="deepcogito/cogito-671b-v2.1",
        relative_path="sources/deepcogito-cogito-v2-1-671b-card.md",
        required_markers=(
            "# Cogito v2.1 - 671B MoE",
            "- deepseek-ai/DeepSeek-V3-Base",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="deepseek-deepseek-v3-2-exp-card",
        requested_url=(
            "https://huggingface.co/deepseek-ai/DeepSeek-V3.2-Exp/resolve/"
            "a678d82902a8da587f29fd3f3ad22dd35b522ed5/README.md"
        ),
        publisher_id="deepseek-ai",
        independence_key="deepseek-ai",
        immutable_revision="a678d82902a8da587f29fd3f3ad22dd35b522ed5",
        repository_path="deepseek-ai/DeepSeek-V3.2-Exp",
        relative_path="sources/deepseek-deepseek-v3-2-exp-card.md",
        required_markers=(
            "# DeepSeek-V3.2-Exp",
            "official release of DeepSeek-V3.2-Exp",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="deepseek-deepseek-v4-pro-0813-card",
        requested_url=(
            "https://huggingface.co/deepseek-ai/DeepSeek-V4-Pro-0813/resolve/"
            "72e1d3230f6c080a530b0a1d46f8eb4602340597/README.md"
        ),
        publisher_id="deepseek-ai",
        independence_key="deepseek-ai",
        immutable_revision="72e1d3230f6c080a530b0a1d46f8eb4602340597",
        repository_path="deepseek-ai/DeepSeek-V4-Pro-0813",
        relative_path="sources/deepseek-deepseek-v4-pro-0813-card.md",
        required_markers=(
            "**DeepSeek-V4-Pro-0813** is the official release of **DeepSeek-V4-Pro**, "
            "superseding the preview version, with greatly enhanced agentic capabilities and "
            "performance improvements that are especially pronounced in production environments. "
            "It is built on the DeepSeek-V4-Pro (Preview) model structure, with a DSpark "
            "speculative decoding module attached.",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="google-gemma-4-26b-a4b-it-card",
        requested_url=(
            "https://huggingface.co/google/gemma-4-26B-A4B-it/resolve/"
            "b2a81a03d25f927590a91d84ba43f96e8ef7349f/README.md"
        ),
        publisher_id="google-deepmind",
        independence_key="google-deepmind",
        immutable_revision="b2a81a03d25f927590a91d84ba43f96e8ef7349f",
        repository_path="google/gemma-4-26B-A4B-it",
        relative_path="sources/google-gemma-4-26b-a4b-it-card.md",
        required_markers=(
            "- google/gemma-4-26B-A4B",
            "Gemma is a family of open models built by Google DeepMind.",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="meta-llama-4-maverick-card",
        requested_url=(
            "https://huggingface.co/meta-llama/Llama-4-Maverick-17B-128E-Instruct/resolve/"
            "73d14711bcc77c16df3470856949c3764056b617/README.md"
        ),
        publisher_id="meta",
        independence_key="meta",
        immutable_revision="73d14711bcc77c16df3470856949c3764056b617",
        repository_path="meta-llama/Llama-4-Maverick-17B-128E-Instruct",
        relative_path="sources/meta-llama-4-maverick-card.md",
        required_markers=(
            "- meta-llama/Llama-4-Maverick-17B-128E",
            '"**Meta**" or "**we**" means Meta Platforms',
        ),
    ),
    PublicLineageSourceSpec(
        source_id="minimax-m3-card",
        requested_url=(
            "https://huggingface.co/MiniMaxAI/MiniMax-M3/resolve/"
            "f0e1c1e04d40177e4673a22097036854f536e9c0/README.md"
        ),
        publisher_id="minimax",
        independence_key="minimax",
        immutable_revision="f0e1c1e04d40177e4673a22097036854f536e9c0",
        repository_path="MiniMaxAI/MiniMax-M3",
        relative_path="sources/minimax-m3-card.md",
        required_markers=("MiniMax-M3 is a native multimodal model",),
    ),
    PublicLineageSourceSpec(
        source_id="mistral-small-4-119b-2603-card",
        requested_url=(
            "https://huggingface.co/mistralai/Mistral-Small-4-119B-2603/resolve/"
            "97ee14542b6c053394af45dd2ff89aadecf457a0/README.md"
        ),
        publisher_id="mistral-ai",
        independence_key="mistral-ai",
        immutable_revision="97ee14542b6c053394af45dd2ff89aadecf457a0",
        repository_path="mistralai/Mistral-Small-4-119B-2603",
        relative_path="sources/mistral-small-4-119b-2603-card.md",
        required_markers=(
            "# Mistral Small 4 119B A6B",
            "mistralai/Mistral-Small-4-119B-2603",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="moonshot-kimi-k2-thinking-card",
        requested_url=(
            "https://huggingface.co/moonshotai/Kimi-K2-Thinking/resolve/"
            "1b9dbb7b20fe8e92047f956b75f3bc49d69f8f73/README.md"
        ),
        publisher_id="moonshot-ai",
        independence_key="moonshot-ai",
        immutable_revision="1b9dbb7b20fe8e92047f956b75f3bc49d69f8f73",
        repository_path="moonshotai/Kimi-K2-Thinking",
        relative_path="sources/moonshot-kimi-k2-thinking-card.md",
        required_markers=(
            "Kimi K2 Thinking is the latest",
            "Homepage-Moonshot%20AI",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="moonshot-kimi-k3-card",
        requested_url=(
            "https://huggingface.co/moonshotai/Kimi-K3/resolve/"
            "a590ce090cb049c93a33dfe8c208ec652aa20503/README.md"
        ),
        publisher_id="moonshot-ai",
        independence_key="moonshot-ai",
        immutable_revision="a590ce090cb049c93a33dfe8c208ec652aa20503",
        repository_path="moonshotai/Kimi-K3",
        relative_path="sources/moonshot-kimi-k3-card.md",
        required_markers=(
            "Kimi K3 applies quantization-aware training from the SFT stage onward, using MXFP4 "
            "weights with MXFP8 activations for broad hardware compatibility.",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="nvidia-nemotron-3-super-120b-a12b-base-card",
        requested_url=(
            "https://huggingface.co/nvidia/"
            "NVIDIA-Nemotron-3-Super-120B-A12B-Base-BF16/resolve/"
            "46cc6113d364942e7742b0b2afd35b5db5058b29/README.md"
        ),
        publisher_id="nvidia",
        independence_key="nvidia",
        immutable_revision="46cc6113d364942e7742b0b2afd35b5db5058b29",
        repository_path="nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-Base-BF16",
        relative_path="sources/nvidia-nemotron-3-super-120b-a12b-base-card.md",
        required_markers=(
            "# NVIDIA-Nemotron-3-Super-120B-A12B-Base",
            "trained from scratch by NVIDIA",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="nvidia-nemotron-3-super-120b-a12b-posttrain-card",
        requested_url=(
            "https://huggingface.co/nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16/resolve/"
            "d51eab0d1f979ebc26b546e634a04f450d99158e/README.md"
        ),
        publisher_id="nvidia",
        independence_key="nvidia",
        immutable_revision="d51eab0d1f979ebc26b546e634a04f450d99158e",
        repository_path="nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16",
        relative_path="sources/nvidia-nemotron-3-super-120b-a12b-posttrain-card.md",
        required_markers=(
            "# NVIDIA-Nemotron-3-Super-120B-A12B-BF16",
            "NVIDIA-Nemotron-3-Super-120B-A12B-Base-BF16",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="openai-gpt-oss-120b-readme",
        requested_url=(
            "https://raw.githubusercontent.com/openai/gpt-oss/"
            "599476783c6f88508dab8577808b5ead5cbee8d2/README.md"
        ),
        publisher_id="openai",
        independence_key="openai",
        immutable_revision="599476783c6f88508dab8577808b5ead5cbee8d2",
        repository_path="openai/gpt-oss",
        relative_path="sources/openai-gpt-oss-120b-readme.md",
        required_markers=(
            "https://huggingface.co/openai/gpt-oss-120b",
            "OpenAI's open-weight models",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="qwen-qwen3-6-35b-a3b-card",
        requested_url=(
            "https://huggingface.co/Qwen/Qwen3.6-35B-A3B/resolve/"
            "995ad96eacd98c81ed38be0c5b274b04031597b0/README.md"
        ),
        publisher_id="alibaba-qwen",
        independence_key="alibaba-qwen",
        immutable_revision="995ad96eacd98c81ed38be0c5b274b04031597b0",
        repository_path="Qwen/Qwen3.6-35B-A3B",
        relative_path="sources/qwen-qwen3-6-35b-a3b-card.md",
        required_markers=(
            "# Qwen3.6-35B-A3B",
            "Training Stage: Pre-training & Post-training",
        ),
    ),
    PublicLineageSourceSpec(
        source_id="tencent-hunyuan-a13b-instruct-card",
        requested_url=(
            "https://huggingface.co/tencent/Hunyuan-A13B-Instruct/resolve/"
            "290ddb9a56ed23c2c83a1c8081533e58925df952/README.md"
        ),
        publisher_id="tencent-hunyuan",
        independence_key="tencent-hunyuan",
        immutable_revision="290ddb9a56ed23c2c83a1c8081533e58925df952",
        repository_path="tencent/Hunyuan-A13B-Instruct",
        relative_path="sources/tencent-hunyuan-a13b-instruct-card.md",
        required_markers=("Hunyuan-A13B-Instruct",),
    ),
    PublicLineageSourceSpec(
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
    ),
    PublicLineageSourceSpec(
        source_id="z-ai-glm-4-7-card",
        requested_url=(
            "https://huggingface.co/zai-org/GLM-4.7/resolve/"
            "2765a661c9061116a4bef693c61f5de3f0687f2c/README.md"
        ),
        publisher_id="z-ai",
        independence_key="z-ai",
        immutable_revision="2765a661c9061116a4bef693c61f5de3f0687f2c",
        repository_path="zai-org/GLM-4.7",
        relative_path="sources/z-ai-glm-4-7-card.md",
        required_markers=("# GLM-4.7",),
    ),
)
_PUBLIC_LINEAGE_SOURCE_SPECS_BY_ID = {spec.source_id: spec for spec in PUBLIC_LINEAGE_SOURCE_SPECS}


def capture_public_lineage_source(
    spec: PublicLineageSourceSpec,
    *,
    client: httpx.Client,
    retrieved_at: datetime,
) -> CapturedPublicLineageSource:
    """Fetch one compiled source with bounded, recorded redirects and exact bytes."""

    _validate_retrieved_at(retrieved_at)
    _require_compiled_source_spec(spec)
    current_url = spec.requested_url
    redirect_chain = [current_url]

    for redirect_count in range(MAX_PUBLIC_LINEAGE_REDIRECTS + 1):
        try:
            with client.stream("GET", current_url, headers=_CAPTURE_HEADERS) as response:
                if response.is_redirect:
                    if redirect_count == MAX_PUBLIC_LINEAGE_REDIRECTS:
                        raise PublicLineageCaptureError("public lineage redirect bound exceeded")
                    locations = response.headers.get_list("location")
                    if len(locations) != 1:
                        raise PublicLineageCaptureError(
                            "public lineage redirect must have one Location"
                        )
                    next_url = urljoin(current_url, locations[0])
                    if next_url in redirect_chain:
                        raise PublicLineageCaptureError("public lineage redirect cycle detected")
                    _validate_redirect_target(spec, next_url)
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue
                if response.status_code != 200:
                    raise PublicLineageCaptureError(
                        f"public lineage source returned HTTP {response.status_code}"
                    )
                media_type = _validated_media_type(response)
                content = _read_bounded_response(response)
                _validate_semantic_minimum(spec, content)
        except httpx.HTTPError as exc:
            raise PublicLineageCaptureError("public lineage source request failed") from exc
        return CapturedPublicLineageSource(
            spec=spec,
            retrieved_at=retrieved_at,
            final_url=current_url,
            redirect_chain=tuple(redirect_chain),
            media_type=media_type,
            content=content,
        )
    raise AssertionError("unreachable public lineage redirect loop")


def capture_public_lineage_sources(
    *,
    client: httpx.Client,
    now: Callable[[], datetime] | None = None,
    specs: Iterable[PublicLineageSourceSpec] = PUBLIC_LINEAGE_SOURCE_SPECS,
) -> tuple[CapturedPublicLineageSource, ...]:
    """Capture an exact, unique, sorted source inventory."""

    clock = now or (lambda: datetime.now(UTC).replace(microsecond=0))
    requested = _bounded_exact_source_specs(specs)
    captures: list[CapturedPublicLineageSource] = []
    for spec in requested:
        try:
            capture = capture_public_lineage_source(spec, client=client, retrieved_at=clock())
        except PublicLineageCaptureError as exc:
            raise PublicLineageCaptureError(f"{spec.source_id}: {exc}") from exc
        captures.append(capture)
    return tuple(captures)


def write_captured_source_files(
    *, output_dir: Path, captures: Iterable[CapturedPublicLineageSource]
) -> PublicLineageCaptureObservations:
    """Publish exact sources and their non-authorizing journal to a fresh directory.

    The final authority manifest is deliberately not produced here.  It must be
    built through the strict public-lineage bundle model after exact claim spans
    have been selected and replayed.  ``output_dir`` may therefore be an arbitrary
    staging path; neither its location nor this journal confers authority.
    """

    validated_captures = _bounded_exact_captures(captures)
    if output_dir.exists() or output_dir.is_symlink():
        raise PublicLineageCaptureError("public lineage output directory must be absent")

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".public-lineage-", dir=output_dir.parent))
    published = False
    try:
        for capture in validated_captures:
            destination = _destination_under_staging(staging, capture.spec)
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with destination.open("xb") as handle:
                handle.write(capture.content)
                handle.flush()
                os.fsync(handle.fileno())
            destination.chmod(0o644)
        observations = build_capture_observations(validated_captures)
        observation_path = staging / PUBLIC_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME
        with observation_path.open("xb") as handle:
            handle.write(stable_json_bytes(observations))
            handle.flush()
            os.fsync(handle.fileno())
        observation_path.chmod(0o644)
        os.replace(staging, output_dir)
        published = True
    finally:
        if not published:
            shutil.rmtree(staging, ignore_errors=True)
    return observations


def build_capture_observations(
    captures: Iterable[CapturedPublicLineageSource],
) -> PublicLineageCaptureObservations:
    """Bind exact capture metadata and files without issuing lineage authority."""

    validated_captures = _bounded_exact_captures(captures)
    observations: list[PublicLineageCaptureObservation] = []
    for capture in validated_captures:
        file_binding = ManifestFileBinding(
            path=capture.spec.relative_path,
            sha256=capture.sha256,
            size=len(capture.content),
        )
        source_kind: Literal["PRIMARY_PUBLISHER_MODEL_CARD"] = "PRIMARY_PUBLISHER_MODEL_CARD"
        if capture.spec.source_kind != source_kind:
            raise PublicLineageCaptureError("public lineage source kind is not compiled")
        if capture.media_type not in _ALLOWED_MEDIA_TYPES:
            raise PublicLineageCaptureError("public lineage source media type is not allowed")
        media_type: Literal["text/markdown", "text/plain"] = (
            "text/markdown" if capture.media_type == "text/markdown" else "text/plain"
        )
        provisional = PublicLineageCaptureObservation.model_construct(
            source_id=capture.spec.source_id,
            requested_url=capture.spec.requested_url,
            final_url=capture.final_url,
            redirect_chain=capture.redirect_chain,
            publisher_id=capture.spec.publisher_id,
            independence_key=capture.spec.independence_key,
            source_kind=source_kind,
            immutable_revision=capture.spec.immutable_revision,
            retrieved_at=capture.retrieved_at,
            media_type=media_type,
            file_binding=file_binding,
            observation_sha256="0" * 64,
        )
        observations.append(
            PublicLineageCaptureObservation(
                source_id=capture.spec.source_id,
                requested_url=capture.spec.requested_url,
                final_url=capture.final_url,
                redirect_chain=capture.redirect_chain,
                publisher_id=capture.spec.publisher_id,
                independence_key=capture.spec.independence_key,
                source_kind=source_kind,
                immutable_revision=capture.spec.immutable_revision,
                retrieved_at=capture.retrieved_at,
                media_type=media_type,
                file_binding=file_binding,
                observation_sha256=canonical_sha256(
                    provisional.model_dump(mode="json", exclude={"observation_sha256"})
                ),
            )
        )
    observation_set_sha256 = canonical_sha256(
        [observation.observation_sha256 for observation in observations]
    )
    provisional_bundle = PublicLineageCaptureObservations.model_construct(
        schema_version="1.0",
        sources=tuple(observations),
        lineage_identity_authorized=False,
        source_egress_authorized=False,
        provider_call_authorized=False,
        observation_set_sha256=observation_set_sha256,
        bundle_sha256="0" * 64,
    )
    return PublicLineageCaptureObservations(
        schema_version="1.0",
        sources=tuple(observations),
        lineage_identity_authorized=False,
        source_egress_authorized=False,
        provider_call_authorized=False,
        observation_set_sha256=observation_set_sha256,
        bundle_sha256=canonical_sha256(
            provisional_bundle.model_dump(mode="json", exclude={"bundle_sha256"})
        ),
    )


def _read_bounded_response(response: httpx.Response) -> bytes:
    content_encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if content_encoding != "identity":
        raise PublicLineageCaptureError("public lineage source must use identity encoding")
    declared_length = response.headers.get("content-length")
    expected_size: int | None = None
    if declared_length is not None:
        try:
            expected_size = int(declared_length)
        except ValueError as exc:
            raise PublicLineageCaptureError("public lineage Content-Length is malformed") from exc
        if expected_size < 0 or expected_size > MAX_PUBLIC_LINEAGE_SOURCE_BYTES:
            raise PublicLineageCaptureError("public lineage source exceeds its byte bound")

    chunks: list[bytes] = []
    observed_size = 0
    for chunk in response.iter_raw():
        observed_size += len(chunk)
        if observed_size > MAX_PUBLIC_LINEAGE_SOURCE_BYTES:
            raise PublicLineageCaptureError("public lineage source exceeds its byte bound")
        chunks.append(chunk)
    if expected_size is not None and observed_size != expected_size:
        raise PublicLineageCaptureError("public lineage Content-Length does not match exact bytes")
    if observed_size == 0:
        raise PublicLineageCaptureError("public lineage source is empty")
    return b"".join(chunks)


def _validated_media_type(response: httpx.Response) -> str:
    content_types = response.headers.get_list("content-type")
    if len(content_types) != 1:
        raise PublicLineageCaptureError("public lineage source must have one Content-Type")
    media_type = content_types[0].partition(";")[0].strip().lower()
    if media_type not in _ALLOWED_MEDIA_TYPES:
        raise PublicLineageCaptureError("public lineage source media type is not allowed")
    return media_type


def _validate_semantic_minimum(spec: PublicLineageSourceSpec, content: bytes) -> None:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise PublicLineageCaptureError("public lineage source is not exact UTF-8 text") from exc
    missing = tuple(marker for marker in spec.required_markers if marker not in text)
    if missing:
        raise PublicLineageCaptureError(
            f"public lineage source lacks {len(missing)} compiled identity marker(s)"
        )


def _validate_retrieved_at(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value) or value.microsecond:
        raise PublicLineageCaptureError("public lineage retrieval time must be whole-second UTC")


def _validate_source_spec(spec: PublicLineageSourceSpec) -> None:
    parsed = urlsplit(spec.requested_url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.hostname not in {"huggingface.co", "raw.githubusercontent.com"}
    ):
        raise PublicLineageCaptureError("public lineage source URL is outside the fixed allowlist")
    if len(spec.immutable_revision) != 40 or any(
        character not in "0123456789abcdef" for character in spec.immutable_revision
    ):
        raise PublicLineageCaptureError("public lineage source revision is not an immutable SHA")
    _validated_relative_source_path(spec.relative_path)
    if not spec.relative_path.endswith(".md"):
        raise PublicLineageCaptureError("public lineage source path is not normalized")
    if (
        not spec.required_markers
        or len(spec.required_markers) > 8
        or any(
            not marker
            or len(marker.encode("utf-8")) > 500
            or any(ord(character) < 32 and character not in "\t" for character in marker)
            for marker in spec.required_markers
        )
    ):
        raise PublicLineageCaptureError("public lineage semantic marker inventory is not bounded")


def _require_compiled_source_spec(spec: PublicLineageSourceSpec) -> None:
    """Reject every caller-authored source or metadata override before egress."""

    if type(spec) is not PublicLineageSourceSpec:
        raise PublicLineageCaptureError("public lineage source is not the exact compiled spec")
    _validate_source_spec(spec)
    compiled = _PUBLIC_LINEAGE_SOURCE_SPECS_BY_ID.get(spec.source_id)
    if compiled is None or spec != compiled:
        raise PublicLineageCaptureError("public lineage source is not the exact compiled spec")


def _bounded_exact_source_specs(
    specs: Iterable[PublicLineageSourceSpec],
) -> tuple[PublicLineageSourceSpec, ...]:
    """Drain at most one item beyond the fixed inventory and require exact equality."""

    expected_count = len(PUBLIC_LINEAGE_SOURCE_SPECS)
    requested = tuple(islice(iter(specs), expected_count + 1))
    if requested != PUBLIC_LINEAGE_SOURCE_SPECS:
        raise PublicLineageCaptureError("public lineage source inventory is not exact and compiled")
    for spec in requested:
        _require_compiled_source_spec(spec)
    return requested


def _bounded_exact_captures(
    captures: Iterable[CapturedPublicLineageSource],
) -> tuple[CapturedPublicLineageSource, ...]:
    """Bound and fully validate a complete capture inventory before filesystem writes."""

    expected_count = len(PUBLIC_LINEAGE_SOURCE_SPECS)
    requested = tuple(islice(iter(captures), expected_count + 1))
    if len(requested) != expected_count:
        raise PublicLineageCaptureError("public lineage capture inventory is not exact")
    for capture, expected_spec in zip(requested, PUBLIC_LINEAGE_SOURCE_SPECS, strict=True):
        if type(capture) is not CapturedPublicLineageSource or capture.spec != expected_spec:
            raise PublicLineageCaptureError(
                "public lineage capture does not bind the exact compiled spec"
            )
        _validate_captured_source(capture)
    return requested


def _validate_captured_source(capture: CapturedPublicLineageSource) -> None:
    _require_compiled_source_spec(capture.spec)
    _validate_retrieved_at(capture.retrieved_at)
    if type(capture.content) is not bytes:
        raise PublicLineageCaptureError("public lineage captured content must be exact bytes")
    if not capture.content or len(capture.content) > MAX_PUBLIC_LINEAGE_SOURCE_BYTES:
        raise PublicLineageCaptureError("public lineage captured content exceeds its byte bound")
    if capture.media_type not in _ALLOWED_MEDIA_TYPES:
        raise PublicLineageCaptureError("public lineage source media type is not allowed")
    if (
        type(capture.redirect_chain) is not tuple
        or not capture.redirect_chain
        or len(capture.redirect_chain) > MAX_PUBLIC_LINEAGE_REDIRECTS + 1
        or len(capture.redirect_chain) != len(set(capture.redirect_chain))
        or capture.redirect_chain[0] != capture.spec.requested_url
        or capture.redirect_chain[-1] != capture.final_url
    ):
        raise PublicLineageCaptureError("public lineage captured redirect chain is inconsistent")
    for target in capture.redirect_chain[1:]:
        _validate_redirect_target(capture.spec, target)
    _validate_semantic_minimum(capture.spec, capture.content)


def _validated_relative_source_path(value: str) -> PurePosixPath:
    if type(value) is not str or len(value.encode("utf-8")) > 4_096:
        raise PublicLineageCaptureError("public lineage source path is not normalized")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or len(relative.parts) != 2
        or relative.parts[0] != "sources"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise PublicLineageCaptureError("public lineage source path is not normalized")
    return relative


def _destination_under_staging(staging: Path, spec: PublicLineageSourceSpec) -> Path:
    relative = _validated_relative_source_path(spec.relative_path)
    staging_root = staging.resolve(strict=True)
    destination = (staging_root / Path(*relative.parts)).resolve(strict=False)
    if not destination.is_relative_to(staging_root):
        raise PublicLineageCaptureError("public lineage source path leaves its staging directory")
    return destination


def _validate_redirect_target(spec: PublicLineageSourceSpec, target: str) -> None:
    parsed = urlsplit(target)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.fragment
        or parsed.hostname != "huggingface.co"
        or len(target.encode("utf-8")) > 8_192
    ):
        raise PublicLineageCaptureError("public lineage redirect leaves its constrained origin")
    expected_path = (
        f"/api/resolve-cache/models/{spec.repository_path}/{spec.immutable_revision}/README.md"
    )
    if parsed.path != expected_path:
        raise PublicLineageCaptureError("public lineage redirect changes the reviewed source")


def _bounded_output_path(value: str) -> Path:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("output path must be bounded single-line text")
    return Path(value)


def main(argv: list[str] | None = None) -> int:
    """Capture all compiled sources to a fresh directory."""

    parser = argparse.ArgumentParser(
        description=(
            "Capture fixed first-party public model-lineage source bytes and a non-authorizing "
            "observation journal to a fresh staging directory."
        )
    )
    parser.add_argument(
        "--output-dir",
        type=_bounded_output_path,
        required=True,
        help=(
            "fresh staging directory; arbitrary paths are allowed because capture observations "
            "do not grant lineage, egress, provider-call, or runtime authority"
        ),
    )
    arguments = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        with httpx.Client(
            timeout=_TIMEOUT,
            follow_redirects=False,
            trust_env=False,
        ) as client:
            captures = capture_public_lineage_sources(client=client)
        write_captured_source_files(output_dir=arguments.output_dir, captures=captures)
    except PublicLineageCaptureError as exc:
        parser.exit(1, f"public lineage capture failed: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
