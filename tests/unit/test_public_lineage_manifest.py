from __future__ import annotations

import hashlib
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
    "google/gemma-4-26b-a4b-it",
    "meta-llama/llama-4-maverick",
    "minimax/minimax-m3",
    "moonshotai/kimi-k2-thinking",
    "nvidia/nemotron-3-super-120b-a12b",
    "qwen/qwen3.6-35b-a3b",
)
UNCONFIRMED_EXACT_MODEL_IDS = (
    "mistralai/mistral-small-2603",
    "openai/gpt-oss-120b",
    "tencent/hunyuan-a13b-instruct",
    "z-ai/glm-4.7",
)


def test_committed_public_lineage_manifest_rebuilds_and_resolves_exactly() -> None:
    raw_manifest = MANIFEST_PATH.read_bytes()
    assert hashlib.sha256(raw_manifest).hexdigest() == PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256

    bundle = PublicModelLineageEvidenceBundle.model_validate_json(raw_manifest)
    assert stable_json(bundle).encode("utf-8") == raw_manifest
    assert build_manifest(EVIDENCE_ROOT) == bundle

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
    assert len(approved_public_model_lineages(capability)) == 7
    assert len(inventory.conservative_non_independence_constraints) == 4
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
