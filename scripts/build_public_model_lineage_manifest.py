"""Build the frozen public documentary model-lineage manifest offline.

The builder consumes only the committed, non-authorizing capture journal and its
exact local source bytes.  It performs no network access and issues no runtime
authority.  The runtime verifier must still compile the emitted manifest digest.
"""

from __future__ import annotations

import argparse
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from mmaudit.models.public_lineage_authority import (
    PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
    PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT,
    PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME,
    PublicModelLineageAliasBinding,
    PublicModelLineageCaptureJournal,
    PublicModelLineageClaim,
    PublicModelLineageClaimKind,
    PublicModelLineageConstraintKind,
    PublicModelLineageEvidenceBundle,
    PublicModelLineageNonIndependenceConstraint,
    PublicModelLineageSourceEvidence,
    build_public_model_lineage_evidence_bundle,
)
from mmaudit.orchestration.manifest import ManifestFileBinding, canonical_sha256
from mmaudit.release_io import read_file_evidence, read_json_evidence, write_json_evidence

VERIFIED_AT = datetime(2026, 8, 18, 9, 0, tzinfo=UTC)
VALID_UNTIL = VERIFIED_AT + timedelta(days=180)


@dataclass(frozen=True, slots=True)
class _AliasSpec:
    exact_model_id: str
    documentary_model_id: str
    publisher_id: str
    source_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _ClaimSpec:
    claim_id: str
    subject_exact_model_id: str
    claim_kind: PublicModelLineageClaimKind
    target_exact_model_id: str | None
    source_id: str
    exact_marker: str
    documentary_basis: Literal[
        "BASE_DECLARATION",
        "PRETRAINING",
        "BUILD_ANCESTRY",
        "TRAINING_PROVENANCE",
        "UNRESOLVED_EXTERNAL_BASE",
        "TITLE_OR_IDENTITY_ONLY",
    ]
    decisive_primary_publisher: bool
    exact_marker_end: str | None = None


_ALIASES = (
    _AliasSpec(
        "deepcogito/cogito-v2.1-671b",
        "deepcogito/cogito-671b-v2.1",
        "deepcogito",
        ("deepcogito-cogito-v2-1-671b-card",),
    ),
    _AliasSpec(
        "deepseek/deepseek-v3.2-exp",
        "deepseek-ai/DeepSeek-V3.2-Exp",
        "deepseek-ai",
        ("deepseek-deepseek-v3-2-exp-card",),
    ),
    _AliasSpec(
        "google/gemma-4-26b-a4b-it",
        "google/gemma-4-26B-A4B-it",
        "google-deepmind",
        ("google-gemma-4-26b-a4b-it-card",),
    ),
    _AliasSpec(
        "meta-llama/llama-4-maverick",
        "meta-llama/Llama-4-Maverick-17B-128E-Instruct",
        "meta",
        ("meta-llama-4-maverick-card",),
    ),
    _AliasSpec(
        "minimax/minimax-m3",
        "MiniMaxAI/MiniMax-M3",
        "minimax",
        ("minimax-m3-card",),
    ),
    _AliasSpec(
        "mistralai/mistral-small-2603",
        "mistralai/Mistral-Small-4-119B-2603",
        "mistral-ai",
        ("mistral-small-4-119b-2603-card",),
    ),
    _AliasSpec(
        "moonshotai/kimi-k2-thinking",
        "moonshotai/Kimi-K2-Thinking",
        "moonshot-ai",
        ("moonshot-kimi-k2-thinking-card",),
    ),
    _AliasSpec(
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16",
        "nvidia",
        (
            "nvidia-nemotron-3-super-120b-a12b-base-card",
            "nvidia-nemotron-3-super-120b-a12b-posttrain-card",
        ),
    ),
    _AliasSpec(
        "openai/gpt-oss-120b",
        "openai/gpt-oss-120b",
        "openai",
        ("openai-gpt-oss-120b-readme",),
    ),
    _AliasSpec(
        "qwen/qwen3.6-35b-a3b",
        "Qwen/Qwen3.6-35B-A3B",
        "alibaba-qwen",
        ("qwen-qwen3-6-35b-a3b-card",),
    ),
    _AliasSpec(
        "tencent/hunyuan-a13b-instruct",
        "tencent/Hunyuan-A13B-Instruct",
        "tencent-hunyuan",
        ("tencent-hunyuan-a13b-instruct-card",),
    ),
    _AliasSpec(
        "z-ai/glm-4.7",
        "zai-org/GLM-4.7",
        "z-ai",
        ("z-ai-glm-4-7-card",),
    ),
)

_CLAIMS = (
    _ClaimSpec(
        "claim-cogito-deepseek",
        "deepcogito/cogito-v2.1-671b",
        PublicModelLineageClaimKind.ROOTS_WITH,
        "deepseek/deepseek-v3.2-exp",
        "deepcogito-cogito-v2-1-671b-card",
        "base_model:\n- deepseek-ai/DeepSeek-V3-Base",
        "BASE_DECLARATION",
        True,
    ),
    _ClaimSpec(
        "claim-deepseek-anchor",
        "deepseek/deepseek-v3.2-exp",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "deepseek-deepseek-v3-2-exp-card",
        "V3.2-Exp builds upon V3.1-Terminus by introducing DeepSeek Sparse Attention",
        "BUILD_ANCESTRY",
        True,
    ),
    _ClaimSpec(
        "claim-gemma-anchor",
        "google/gemma-4-26b-a4b-it",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "google-gemma-4-26b-a4b-it-card",
        "base_model:\n- google/gemma-4-26B-A4B",
        "BASE_DECLARATION",
        True,
    ),
    _ClaimSpec(
        "claim-gpt-oss-publisher-identity",
        "openai/gpt-oss-120b",
        PublicModelLineageClaimKind.VAGUE,
        None,
        "openai-gpt-oss-120b-readme",
        "Welcome to the gpt-oss series, [OpenAI's open-weight models](https://openai.com/open-models/) designed for powerful reasoning, agentic tasks, and versatile developer use cases.",
        "TITLE_OR_IDENTITY_ONLY",
        False,
    ),
    _ClaimSpec(
        "claim-hunyuan-anchor",
        "tencent/hunyuan-a13b-instruct",
        PublicModelLineageClaimKind.VAGUE,
        None,
        "tencent-hunyuan-a13b-instruct-card",
        "Welcome to the official repository of **Hunyuan-A13B**, an innovative and open-source large language model (LLM) built on a fine-grained Mixture-of-Experts (MoE) architecture.",
        "TITLE_OR_IDENTITY_ONLY",
        False,
    ),
    _ClaimSpec(
        "claim-hunyuan-pretrain-instruct",
        "tencent/hunyuan-a13b-instruct",
        PublicModelLineageClaimKind.VAGUE,
        None,
        "tencent-hunyuan-a13b-instruct-card",
        "We have open-sourced  **Hunyuan-A13B-Pretrain** , **Hunyuan-A13B-Instruct** , **Hunyuan-A13B-Instruct-FP8** , **Hunyuan-A13B-Instruct-GPTQ-Int4** on Hugging Face.",
        "UNRESOLVED_EXTERNAL_BASE",
        False,
    ),
    _ClaimSpec(
        "claim-kimi-anchor",
        "moonshotai/kimi-k2-thinking",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "moonshot-kimi-k2-thinking-card",
        "Kimi K2 Thinking is the latest, most capable version of open-source thinking model. Starting with Kimi K2, we built it as a thinking agent that reasons step-by-step while dynamically invoking tools. It sets a new state-of-the-art on Humanity's Last Exam (HLE), BrowseComp, and other benchmarks by dramatically scaling multi-step reasoning depth and maintaining stable tool-use across 200\u2013300 sequential calls. At the same time, K2 Thinking is a native INT4 quantization model with 256k context window, achieving lossless reductions in inference latency and GPU memory usage.",
        "BUILD_ANCESTRY",
        True,
    ),
    _ClaimSpec(
        "claim-llama-anchor",
        "meta-llama/llama-4-maverick",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "meta-llama-4-maverick-card",
        "Llama 4 Maverick was pretrained on \\~22 trillion tokens of multimodal data from a mix of publicly available, licensed data and information from Meta\u2019s products and services.",
        "PRETRAINING",
        True,
    ),
    _ClaimSpec(
        "claim-minimax-anchor",
        "minimax/minimax-m3",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "minimax-m3-card",
        "M3 undergoes mixed-modality training from the very first step, enabling deeper semantic fusion across text, image, and video.",
        "TRAINING_PROVENANCE",
        True,
    ),
    _ClaimSpec(
        "claim-mistral-anchor",
        "mistralai/mistral-small-2603",
        PublicModelLineageClaimKind.VAGUE,
        None,
        "mistral-small-4-119b-2603-card",
        "Mistral Small 4 is a powerful hybrid model capable of acting as both a general instruction model and a reasoning model. It unifies the capabilities of three different model families—**Instruct**, **Reasoning** (previously called Magistral), and **Devstral**—into a single, unified model.",
        "UNRESOLVED_EXTERNAL_BASE",
        False,
    ),
    _ClaimSpec(
        "claim-nemotron-base-anchor",
        "nvidia/nemotron-3-super-120b-a12b",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "nvidia-nemotron-3-super-120b-a12b-base-card",
        "**Nemotron-3-Super-120B-A12B-Base** is a base large language model (LLM) trained from scratch by NVIDIA",
        "PRETRAINING",
        True,
    ),
    _ClaimSpec(
        "claim-nemotron-posttrain-anchor",
        "nvidia/nemotron-3-super-120b-a12b",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "nvidia-nemotron-3-super-120b-a12b-posttrain-card",
        "**Nemotron-3-Super-120B-A12B-BF16** is a large language model (LLM) trained by NVIDIA, designed to deliver strong agentic, reasoning, and conversational capabilities.",
        "TRAINING_PROVENANCE",
        True,
    ),
    _ClaimSpec(
        "claim-qwen-anchor",
        "qwen/qwen3.6-35b-a3b",
        PublicModelLineageClaimKind.ROOT_ANCHOR,
        None,
        "qwen-qwen3-6-35b-a3b-card",
        "# Qwen3.6-35B-A3B",
        "TRAINING_PROVENANCE",
        True,
        exact_marker_end="- Training Stage: Pre-training & Post-training",
    ),
    _ClaimSpec(
        "claim-z-ai-anchor",
        "z-ai/glm-4.7",
        PublicModelLineageClaimKind.VAGUE,
        None,
        "z-ai-glm-4-7-card",
        "GLM-4.7 brings clear gains, compared to its predecessor GLM-4.6",
        "UNRESOLVED_EXTERNAL_BASE",
        False,
    ),
)

_DECISIVE_DOCUMENTARY_BASES = frozenset(
    {"BASE_DECLARATION", "PRETRAINING", "BUILD_ANCESTRY", "TRAINING_PROVENANCE"}
)
_NON_DECISIVE_DOCUMENTARY_BASES = frozenset({"UNRESOLVED_EXTERNAL_BASE", "TITLE_OR_IDENTITY_ONLY"})


def _hashed_alias(spec: _AliasSpec) -> PublicModelLineageAliasBinding:
    payload = {
        "alias_id": "alias-" + spec.exact_model_id.replace("/", "-").replace(".", "-"),
        "exact_model_id": spec.exact_model_id,
        "documentary_model_id": spec.documentary_model_id,
        "publisher_id": spec.publisher_id,
        "source_ids": spec.source_ids,
    }
    return PublicModelLineageAliasBinding(
        alias_id="alias-" + spec.exact_model_id.replace("/", "-").replace(".", "-"),
        exact_model_id=spec.exact_model_id,
        documentary_model_id=spec.documentary_model_id,
        publisher_id=spec.publisher_id,
        source_ids=spec.source_ids,
        alias_sha256=canonical_sha256(payload),
    )


def _hashed_claim(spec: _ClaimSpec, content: bytes) -> PublicModelLineageClaim:
    if spec.decisive_primary_publisher:
        if (
            spec.claim_kind is PublicModelLineageClaimKind.VAGUE
            or spec.documentary_basis not in _DECISIVE_DOCUMENTARY_BASES
        ):
            raise ValueError(
                f"{spec.claim_id}: title, identity, or unresolved-base evidence is not decisive"
            )
    elif (
        spec.claim_kind is not PublicModelLineageClaimKind.VAGUE
        or spec.target_exact_model_id is not None
        or spec.documentary_basis not in _NON_DECISIVE_DOCUMENTARY_BASES
    ):
        raise ValueError(f"{spec.claim_id}: non-decisive evidence must remain vague")
    marker_start = spec.exact_marker.encode("utf-8")
    if content.count(marker_start) != 1:
        raise ValueError(f"{spec.claim_id}: exact marker must occur exactly once")
    byte_start = content.index(marker_start)
    if spec.exact_marker_end is None:
        marker = marker_start
    else:
        marker_end = spec.exact_marker_end.encode("utf-8")
        if content.count(marker_end) != 1:
            raise ValueError(f"{spec.claim_id}: exact end marker must occur exactly once")
        byte_end = content.index(marker_end) + len(marker_end)
        if byte_end <= byte_start:
            raise ValueError(f"{spec.claim_id}: exact marker endpoints are reversed")
        marker = content[byte_start:byte_end]
    exact_marker = marker.decode("utf-8", errors="strict")
    payload = {
        "claim_id": spec.claim_id,
        "subject_exact_model_id": spec.subject_exact_model_id,
        "claim_kind": spec.claim_kind,
        "target_exact_model_id": spec.target_exact_model_id,
        "source_id": spec.source_id,
        "decisive_primary_publisher": spec.decisive_primary_publisher,
        "byte_start": byte_start,
        "byte_end": byte_start + len(marker),
        "exact_marker": exact_marker,
        "marker_sha256": hashlib.sha256(marker).hexdigest(),
    }
    return PublicModelLineageClaim(
        claim_id=spec.claim_id,
        subject_exact_model_id=spec.subject_exact_model_id,
        claim_kind=spec.claim_kind,
        target_exact_model_id=spec.target_exact_model_id,
        source_id=spec.source_id,
        decisive_primary_publisher=spec.decisive_primary_publisher,
        byte_start=byte_start,
        byte_end=byte_start + len(marker),
        exact_marker=exact_marker,
        marker_sha256=hashlib.sha256(marker).hexdigest(),
        claim_sha256=canonical_sha256(payload),
    )


def _hashed_constraint(
    *,
    constraint_id: str,
    constraint_kind: PublicModelLineageConstraintKind,
    member_exact_model_ids: tuple[str, ...],
    supporting_claim_ids: tuple[str, ...],
) -> PublicModelLineageNonIndependenceConstraint:
    payload = {
        "constraint_id": constraint_id,
        "constraint_kind": constraint_kind,
        "member_exact_model_ids": member_exact_model_ids,
        "supporting_claim_ids": supporting_claim_ids,
        "negative_only": True,
        "positive_root_assignment_authorized": False,
    }
    return PublicModelLineageNonIndependenceConstraint(
        constraint_id=constraint_id,
        constraint_kind=constraint_kind,
        member_exact_model_ids=member_exact_model_ids,
        supporting_claim_ids=supporting_claim_ids,
        negative_only=True,
        positive_root_assignment_authorized=False,
        constraint_sha256=canonical_sha256(payload),
    )


def build_manifest(
    evidence_root: Path = PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT,
) -> PublicModelLineageEvidenceBundle:
    """Build the deterministic bundle from exact local capture bytes."""

    journal_observation = read_json_evidence(
        evidence_root=evidence_root,
        relative_path=PUBLIC_MODEL_LINEAGE_CAPTURE_OBSERVATIONS_FILENAME,
        max_bytes=500_000,
    )
    journal = PublicModelLineageCaptureJournal.model_validate_json(journal_observation.content)
    sources = tuple(
        PublicModelLineageSourceEvidence.from_capture(source) for source in journal.sources
    )
    source_bytes = {
        source.source_id: read_file_evidence(
            evidence_root=evidence_root,
            relative_path=source.file_binding.path,
            max_bytes=100_000,
        ).content
        for source in sources
    }
    aliases = tuple(_hashed_alias(spec) for spec in _ALIASES)
    claims = tuple(_hashed_claim(spec, source_bytes[spec.source_id]) for spec in _CLAIMS)
    constraints = (
        _hashed_constraint(
            constraint_id="constraint-cogito-deepseek",
            constraint_kind=PublicModelLineageConstraintKind.DOCUMENTED_DIRECT_ANCESTRY,
            member_exact_model_ids=(
                "deepcogito/cogito-v2.1-671b",
                "deepseek/deepseek-v3.2-exp",
            ),
            supporting_claim_ids=("claim-cogito-deepseek", "claim-deepseek-anchor"),
        ),
        _hashed_constraint(
            constraint_id="constraint-gemma-gemini",
            constraint_kind=PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL,
            member_exact_model_ids=(
                "google/gemini-3.7-flash",
                "google/gemma-4-26b-a4b-it",
            ),
            supporting_claim_ids=("claim-gemma-anchor",),
        ),
        _hashed_constraint(
            constraint_id="constraint-gpt-oss-gpt-5-6",
            constraint_kind=PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL,
            member_exact_model_ids=("openai/gpt-5.6-sol", "openai/gpt-oss-120b"),
            supporting_claim_ids=("claim-gpt-oss-publisher-identity",),
        ),
        _hashed_constraint(
            constraint_id="constraint-nemotron-meta",
            constraint_kind=PublicModelLineageConstraintKind.SOURCE_CONFLICT_CORRECTION,
            member_exact_model_ids=(
                "meta-llama/llama-4-maverick",
                "nvidia/nemotron-3-super-120b-a12b",
            ),
            supporting_claim_ids=(
                "claim-llama-anchor",
                "claim-nemotron-base-anchor",
                "claim-nemotron-posttrain-anchor",
            ),
        ),
    )
    return build_public_model_lineage_evidence_bundle(
        capture_observations_file_binding=journal_observation.binding,
        verified_at=VERIFIED_AT,
        valid_until=VALID_UNTIL,
        sources=sources,
        aliases=aliases,
        claims=claims,
        conservative_non_independence_constraints=constraints,
    )


def write_manifest(
    evidence_root: Path = PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT,
) -> ManifestFileBinding:
    """Write the manifest once and return its exact raw file binding."""

    return write_json_evidence(
        evidence_root=evidence_root,
        relative_path=PUBLIC_MODEL_LINEAGE_MANIFEST_FILENAME,
        value=build_manifest(evidence_root),
        max_bytes=1_000_000,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-root",
        type=Path,
        default=PUBLIC_MODEL_LINEAGE_EVIDENCE_ROOT,
    )
    args = parser.parse_args()
    binding = write_manifest(args.evidence_root.resolve())
    print(binding.sha256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
