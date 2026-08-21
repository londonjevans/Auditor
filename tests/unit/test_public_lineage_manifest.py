from __future__ import annotations

import hashlib
from itertools import permutations
from pathlib import Path

import pytest

from mmaudit.models.public_lineage_authority import (
    PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS,
    PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256,
    PublicModelLineageAuthorityError,
    PublicModelLineageClaimKind,
    PublicModelLineageConstraintKind,
    PublicModelLineageDecisionStatus,
    PublicModelLineageEvidenceBundle,
    PublicModelLineageUnconfirmedReason,
    approved_public_model_lineages,
    public_model_lineage_inventory,
    require_independent_public_model_lineage,
    require_verified_public_model_lineage,
    resolve_verified_public_model_lineage,
)
from mmaudit.reporting.json_report import stable_json
from scripts.build_public_model_lineage_manifest import (
    _CLAIMS,
    _ClaimSpec,
    _hashed_claim,
    build_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = ROOT / "config" / "public_model_lineage"
MANIFEST_PATH = EVIDENCE_ROOT / "manifest.json"
CONFIRMED_EXACT_MODEL_IDS = (
    "deepcogito/cogito-v2.1-671b",
    "deepseek/deepseek-v3.2-exp",
    "deepseek/deepseek-v4-pro-0813",
    "google/gemma-4-26b-a4b-it",
    "meta-llama/llama-4-maverick",
    "minimax/minimax-m3",
    "moonshotai/kimi-k2-thinking",
    "moonshotai/kimi-k3",
    "nvidia/nemotron-3-super-120b-a12b",
    "qwen/qwen3.6-35b-a3b",
)
UNCONFIRMED_EXACT_MODEL_IDS = (
    "mistralai/mistral-small-2603",
    "openai/gpt-oss-120b",
    "tencent/hunyuan-a13b-instruct",
    "z-ai/glm-4.7",
)
HISTORICAL_DECISION_ROOTS = {
    "deepcogito/cogito-v2.1-671b": (
        "sha256:acc057978b0d0f05378221091c495a48344b8b2d8a3d8c9b2d96cd6913f2b0f5"
    ),
    "deepseek/deepseek-v3.2-exp": (
        "sha256:acc057978b0d0f05378221091c495a48344b8b2d8a3d8c9b2d96cd6913f2b0f5"
    ),
    "google/gemma-4-26b-a4b-it": (
        "sha256:af392aecac8fb109f7c577928242bc27edf0ad8a24142bc8e9c5151445b12b04"
    ),
    "meta-llama/llama-4-maverick": (
        "sha256:1067e91bf658c7080368ef49bd81134e7a10dc0e42108561a5efdeef0a5643e0"
    ),
    "minimax/minimax-m3": (
        "sha256:e251821340d79fe40fba647e729f9dd8feea7b988efad1a61936bf62b3b38161"
    ),
    "mistralai/mistral-small-2603": None,
    "moonshotai/kimi-k2-thinking": (
        "sha256:366bc38f2866df7d09e60b3fe8c32bc0ba88cf504ce17fd65045374da8b6d65c"
    ),
    "nvidia/nemotron-3-super-120b-a12b": (
        "sha256:a39b66884a35570fd22375af90fb732222aaab823ab14123c0061f7b3c6d0687"
    ),
    "openai/gpt-oss-120b": None,
    "qwen/qwen3.6-35b-a3b": (
        "sha256:434c90ff511c645580fa8063e912f163daf9285c0553a110b2d815c98eb2e46f"
    ),
    "tencent/hunyuan-a13b-instruct": None,
    "z-ai/glm-4.7": None,
}
EXPECTED_CLAIM_IDS = (
    "claim-cogito-deepseek",
    "claim-deepseek-anchor",
    "claim-deepseek-v4-anchor",
    "claim-gemma-anchor",
    "claim-gpt-oss-publisher-identity",
    "claim-hunyuan-anchor",
    "claim-hunyuan-pretrain-instruct",
    "claim-kimi-anchor",
    "claim-kimi-k3-anchor",
    "claim-llama-anchor",
    "claim-minimax-anchor",
    "claim-mistral-anchor",
    "claim-nemotron-base-anchor",
    "claim-nemotron-posttrain-anchor",
    "claim-qwen-anchor",
    "claim-z-ai-anchor",
)
EXPECTED_ALIASES = (
    (
        "deepcogito/cogito-v2.1-671b",
        "deepcogito/cogito-671b-v2.1",
        "deepcogito",
        ("deepcogito-cogito-v2-1-671b-card",),
    ),
    (
        "deepseek/deepseek-v3.2-exp",
        "deepseek-ai/DeepSeek-V3.2-Exp",
        "deepseek-ai",
        ("deepseek-deepseek-v3-2-exp-card",),
    ),
    (
        "deepseek/deepseek-v4-pro-0813",
        "deepseek-ai/DeepSeek-V4-Pro-0813",
        "deepseek-ai",
        ("deepseek-deepseek-v4-pro-0813-card",),
    ),
    (
        "google/gemma-4-26b-a4b-it",
        "google/gemma-4-26B-A4B-it",
        "google-deepmind",
        ("google-gemma-4-26b-a4b-it-card",),
    ),
    (
        "meta-llama/llama-4-maverick",
        "meta-llama/Llama-4-Maverick-17B-128E-Instruct",
        "meta",
        ("meta-llama-4-maverick-card",),
    ),
    (
        "minimax/minimax-m3",
        "MiniMaxAI/MiniMax-M3",
        "minimax",
        ("minimax-m3-card",),
    ),
    (
        "mistralai/mistral-small-2603",
        "mistralai/Mistral-Small-4-119B-2603",
        "mistral-ai",
        ("mistral-small-4-119b-2603-card",),
    ),
    (
        "moonshotai/kimi-k2-thinking",
        "moonshotai/Kimi-K2-Thinking",
        "moonshot-ai",
        ("moonshot-kimi-k2-thinking-card",),
    ),
    (
        "moonshotai/kimi-k3",
        "moonshotai/Kimi-K3",
        "moonshot-ai",
        ("moonshot-kimi-k3-card",),
    ),
    (
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-BF16",
        "nvidia",
        (
            "nvidia-nemotron-3-super-120b-a12b-base-card",
            "nvidia-nemotron-3-super-120b-a12b-posttrain-card",
        ),
    ),
    (
        "openai/gpt-oss-120b",
        "openai/gpt-oss-120b",
        "openai",
        ("openai-gpt-oss-120b-readme",),
    ),
    (
        "qwen/qwen3.6-35b-a3b",
        "Qwen/Qwen3.6-35B-A3B",
        "alibaba-qwen",
        ("qwen-qwen3-6-35b-a3b-card",),
    ),
    (
        "tencent/hunyuan-a13b-instruct",
        "tencent/Hunyuan-A13B-Instruct",
        "tencent-hunyuan",
        ("tencent-hunyuan-a13b-instruct-card",),
    ),
    (
        "z-ai/glm-4.7",
        "zai-org/GLM-4.7",
        "z-ai",
        ("z-ai-glm-4-7-card",),
    ),
)


def test_committed_public_lineage_manifest_rebuilds_and_resolves_exactly() -> None:
    raw_manifest = MANIFEST_PATH.read_bytes()
    assert hashlib.sha256(raw_manifest).hexdigest() == PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256

    bundle = PublicModelLineageEvidenceBundle.model_validate_json(raw_manifest)
    assert stable_json(bundle).encode("utf-8") == raw_manifest
    assert build_manifest(EVIDENCE_ROOT) == bundle
    assert (
        tuple(
            (
                item.exact_model_id,
                item.documentary_model_id,
                item.publisher_id,
                item.source_ids,
            )
            for item in bundle.aliases
        )
        == EXPECTED_ALIASES
    )
    assert tuple(item.exact_model_id for item in bundle.aliases) == (
        PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS
    )
    assert tuple(item.claim_id for item in bundle.claims) == EXPECTED_CLAIM_IDS
    assert {source_id for item in bundle.aliases for source_id in item.source_ids} == {
        item.source_id for item in bundle.sources
    }
    assert {
        item.exact_model_id: item.root_lineage
        for item in bundle.decisions
        if item.exact_model_id in HISTORICAL_DECISION_ROOTS
    } == HISTORICAL_DECISION_ROOTS

    capability = resolve_verified_public_model_lineage()
    inventory = public_model_lineage_inventory(capability)
    assert (
        tuple(
            sorted((*inventory.confirmed_exact_model_ids, *inventory.unconfirmed_exact_model_ids))
        )
        == PUBLIC_MODEL_LINEAGE_EXACT_CANDIDATE_IDS
    )
    assert inventory.confirmed_exact_model_ids == CONFIRMED_EXACT_MODEL_IDS
    assert inventory.unconfirmed_exact_model_ids == UNCONFIRMED_EXACT_MODEL_IDS
    assert inventory.excluded_exact_model_ids == UNCONFIRMED_EXACT_MODEL_IDS
    assert len(approved_public_model_lineages(capability)) == 9
    assert len(inventory.conservative_non_independence_constraints) == 6
    assert all(
        constraint.negative_only and not constraint.positive_root_assignment_authorized
        for constraint in inventory.conservative_non_independence_constraints
    )

    cogito = require_verified_public_model_lineage(capability, "deepcogito/cogito-v2.1-671b")
    deepseek = require_verified_public_model_lineage(capability, "deepseek/deepseek-v3.2-exp")
    assert cogito.root_lineage == deepseek.root_lineage
    with pytest.raises(PublicModelLineageAuthorityError, match="not independent"):
        require_independent_public_model_lineage(
            capability,
            "deepcogito/cogito-v2.1-671b",
            "deepseek/deepseek-v3.2-exp",
        )

    deepseek_v4 = require_verified_public_model_lineage(capability, "deepseek/deepseek-v4-pro-0813")
    assert deepseek_v4.root_lineage != deepseek.root_lineage
    for related_id in (
        "deepcogito/cogito-v2.1-671b",
        "deepseek/deepseek-v3.2-exp",
    ):
        with pytest.raises(
            PublicModelLineageAuthorityError, match="conservatively non-independent"
        ):
            require_independent_public_model_lineage(
                capability,
                related_id,
                "deepseek/deepseek-v4-pro-0813",
            )

    kimi_k2 = require_verified_public_model_lineage(capability, "moonshotai/kimi-k2-thinking")
    kimi_k3 = require_verified_public_model_lineage(capability, "moonshotai/kimi-k3")
    assert kimi_k2.root_lineage != kimi_k3.root_lineage
    with pytest.raises(PublicModelLineageAuthorityError, match="conservatively non-independent"):
        require_independent_public_model_lineage(
            capability,
            "moonshotai/kimi-k2-thinking",
            "moonshotai/kimi-k3",
        )

    active_triple = (
        "deepseek/deepseek-v4-pro-0813",
        "minimax/minimax-m3",
        "moonshotai/kimi-k3",
    )
    for left, right in permutations(active_triple, 2):
        independent = require_independent_public_model_lineage(capability, left, right)
        assert independent.independent is True
        assert independent.left_exact_model_id == left
        assert independent.right_exact_model_id == right
        assert independent.left_root_lineage != independent.right_root_lineage

    for exact_model_id in UNCONFIRMED_EXACT_MODEL_IDS:
        with pytest.raises(PublicModelLineageAuthorityError, match="lacks confirmed"):
            require_verified_public_model_lineage(capability, exact_model_id)
        decision = next(item for item in bundle.decisions if item.exact_model_id == exact_model_id)
        assert decision.status is PublicModelLineageDecisionStatus.UNCONFIRMED
        assert decision.root_lineage is None
        assert decision.supporting_claim_ids == ()
        assert decision.unconfirmed_reasons == (PublicModelLineageUnconfirmedReason.VAGUE_ONLY,)
        claims = tuple(
            item for item in bundle.claims if item.subject_exact_model_id == exact_model_id
        )
        assert claims
        assert all(
            item.claim_kind is PublicModelLineageClaimKind.VAGUE
            and item.decisive_primary_publisher is False
            for item in claims
        )
    gpt_oss_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-gpt-oss-gpt-5-6"
    )
    assert gpt_oss_constraint.supporting_claim_ids == ("claim-gpt-oss-publisher-identity",)

    direct_deepseek_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-cogito-deepseek"
    )
    assert (
        direct_deepseek_constraint.constraint_kind
        is PublicModelLineageConstraintKind.DOCUMENTED_DIRECT_ANCESTRY
    )
    assert direct_deepseek_constraint.member_exact_model_ids == (
        "deepcogito/cogito-v2.1-671b",
        "deepseek/deepseek-v3.2-exp",
    )
    assert direct_deepseek_constraint.supporting_claim_ids == (
        "claim-cogito-deepseek",
        "claim-deepseek-anchor",
    )
    deepseek_family_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-deepseek-family"
    )
    assert (
        deepseek_family_constraint.constraint_kind
        is PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL
    )
    assert deepseek_family_constraint.member_exact_model_ids == (
        "deepcogito/cogito-v2.1-671b",
        "deepseek/deepseek-v3.2-exp",
        "deepseek/deepseek-v4-pro-0813",
    )
    assert deepseek_family_constraint.supporting_claim_ids == (
        "claim-cogito-deepseek",
        "claim-deepseek-anchor",
        "claim-deepseek-v4-anchor",
    )
    kimi_family_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-kimi-k2-k3"
    )
    assert (
        kimi_family_constraint.constraint_kind
        is PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL
    )
    assert kimi_family_constraint.member_exact_model_ids == (
        "moonshotai/kimi-k2-thinking",
        "moonshotai/kimi-k3",
    )
    assert kimi_family_constraint.supporting_claim_ids == (
        "claim-kimi-anchor",
        "claim-kimi-k3-anchor",
    )

    meta = require_verified_public_model_lineage(capability, "meta-llama/llama-4-maverick")
    nvidia = require_verified_public_model_lineage(capability, "nvidia/nemotron-3-super-120b-a12b")
    assert meta.root_lineage != nvidia.root_lineage
    nemotron_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-nemotron-meta"
    )
    assert (
        nemotron_constraint.constraint_kind
        is PublicModelLineageConstraintKind.SOURCE_CONFLICT_CORRECTION
    )
    with pytest.raises(PublicModelLineageAuthorityError, match="conservatively non-independent"):
        require_independent_public_model_lineage(
            capability,
            "meta-llama/llama-4-maverick",
            "nvidia/nemotron-3-super-120b-a12b",
        )

    for field in (
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_authority_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "benchmark_authorized",
    ):
        assert getattr(inventory, field) is False


@pytest.mark.parametrize(
    (
        "claim_id",
        "documentary_basis",
        "source_id",
        "byte_start",
        "byte_end",
        "marker_sha256",
    ),
    (
        (
            "claim-deepseek-v4-anchor",
            "BUILD_ANCESTRY",
            "deepseek-deepseek-v4-pro-0813-card",
            1_896,
            2_246,
            "3c3b6f124f6fd16710f60e936aa019ba585f4cbb380b8789e1611aeab8aa6f70",
        ),
        (
            "claim-kimi-k3-anchor",
            "TRAINING_PROVENANCE",
            "moonshot-kimi-k3-card",
            42_081,
            42_228,
            "bc4d7b66366b975cfd5782bca59158f36b6c09ea61791aa85581d8853f70233d",
        ),
    ),
)
def test_new_exact_id_anchors_bind_the_prepared_decisive_spans(
    claim_id: str,
    documentary_basis: str,
    source_id: str,
    byte_start: int,
    byte_end: int,
    marker_sha256: str,
) -> None:
    spec = next(item for item in _CLAIMS if item.claim_id == claim_id)
    claim = next(item for item in build_manifest(EVIDENCE_ROOT).claims if item.claim_id == claim_id)
    source_bytes = (EVIDENCE_ROOT / "sources" / f"{source_id}.md").read_bytes()

    assert spec.documentary_basis == documentary_basis
    assert claim.claim_kind is PublicModelLineageClaimKind.ROOT_ANCHOR
    assert claim.decisive_primary_publisher is True
    assert claim.source_id == source_id
    assert (claim.byte_start, claim.byte_end) == (byte_start, byte_end)
    assert claim.marker_sha256 == marker_sha256
    assert source_bytes[byte_start:byte_end] == claim.exact_marker.encode("utf-8")


@pytest.mark.parametrize(
    ("exact_model_id", "source_id", "marker"),
    (
        (
            "mistralai/mistral-small-2603",
            "mistral-small-4-119b-2603-card",
            "# Mistral Small 4 119B A6B",
        ),
        (
            "qwen/qwen3.6-35b-a3b",
            "qwen-qwen3-6-35b-a3b-card",
            "# Qwen3.6-35B-A3B",
        ),
        ("z-ai/glm-4.7", "z-ai-glm-4-7-card", "# GLM-4.7"),
    ),
)
def test_title_or_identity_only_marker_cannot_be_declared_decisive(
    exact_model_id: str,
    source_id: str,
    marker: str,
) -> None:
    invalid = _ClaimSpec(
        claim_id="claim-title-only-negative",
        subject_exact_model_id=exact_model_id,
        claim_kind=PublicModelLineageClaimKind.ROOT_ANCHOR,
        target_exact_model_id=None,
        source_id=source_id,
        exact_marker=marker,
        documentary_basis="TITLE_OR_IDENTITY_ONLY",
        decisive_primary_publisher=True,
    )

    with pytest.raises(ValueError, match="title, identity, or unresolved-base evidence"):
        _hashed_claim(invalid, marker.encode("utf-8"))
