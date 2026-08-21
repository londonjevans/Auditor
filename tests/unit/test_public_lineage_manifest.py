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
    "tencent/hy3",
    "z-ai/glm-5.2",
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
    "deepseek/deepseek-v4-pro-0813": (
        "sha256:8b67690ad7aa11f712b1edad5004d687c54382662fe8fb4d6960039409d94cd9"
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
    "moonshotai/kimi-k3": (
        "sha256:023696003e7f763ba904178265b60cdb11e4ed3deb362a768a0a87e8d6275363"
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
    "claim-tencent-hy3-anchor",
    "claim-z-ai-anchor",
    "claim-z-ai-glm-5-2-anchor",
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
        "tencent/hy3",
        "tencent/Hy3",
        "tencent",
        ("tencent-hy3-card",),
    ),
    (
        "z-ai/glm-4.7",
        "zai-org/GLM-4.7",
        "z-ai",
        ("z-ai-glm-4-7-card",),
    ),
    (
        "z-ai/glm-5.2",
        "zai-org/GLM-5.2",
        "z-ai",
        ("z-ai-glm-5-2-card",),
    ),
)
HISTORICAL_SOURCE_FILE_SHA256S = {
    "deepcogito-cogito-v2-1-671b-card": (
        "a3dff9d9f7763a830bae89d7d83b0eb0463afc7247a5e9bf646a344cc8a82037"
    ),
    "deepseek-deepseek-v3-2-exp-card": (
        "389d4fbe4d7fc75ecf0130f56a0123256b9100940116769eb01049119523b8ee"
    ),
    "deepseek-deepseek-v4-pro-0813-card": (
        "61755d88e95789fcd7a36f50892f97bba977a30fc99d0f2907ab787ed10b0e66"
    ),
    "google-gemma-4-26b-a4b-it-card": (
        "e4c134b9dd81fc5d0e3782bb04fbc7034d27c6b6a2437f9c940a0b64b0a8ab6a"
    ),
    "meta-llama-4-maverick-card": (
        "cae8c581b1787780d095f0f827cee3469014f642cb7d054c0cc7aed5d156d5e3"
    ),
    "minimax-m3-card": "6148856dbf8be26dcf3f9b913be0252c38454e852108fdab01212fe965f3e327",
    "mistral-small-4-119b-2603-card": (
        "7f5ef56105580603ecbcf224c28bb0b147fc0f5ec564bb2e76fdf7abadb342c9"
    ),
    "moonshot-kimi-k2-thinking-card": (
        "8343341da86d2a74ee576768ea2f8c0be2d3e9cf1cb51838a794581e7a1466cd"
    ),
    "moonshot-kimi-k3-card": ("57de265b5842dfa465c6e73b368b0e15a89b8793b5450528dad577da202cc6fe"),
    "nvidia-nemotron-3-super-120b-a12b-base-card": (
        "233bde2906a5aa7dab280e60137c365ad88bc7c507c884fb6b78978c4fb83dff"
    ),
    "nvidia-nemotron-3-super-120b-a12b-posttrain-card": (
        "258058128b7d82c16f53112d9cbee6cb85679465016df84a179d312de6c5d881"
    ),
    "openai-gpt-oss-120b-readme": (
        "d4ba8a9cfda709b49e794911278c5a663b8fec1e2bbd86d8f9dc99d8371293e4"
    ),
    "qwen-qwen3-6-35b-a3b-card": (
        "c4ddaa065649ff6352648f64747a16eda31726f3e34add94ce04abb461c77b75"
    ),
    "tencent-hunyuan-a13b-instruct-card": (
        "f7df4703f678f1baa19e4786be5fd8d55559bb3dc83c84cb6e015fb1aa08a969"
    ),
    "z-ai-glm-4-7-card": ("ad072cbe81374f18149a107f2e1cbed93f27a6b220409a6bb34ba97a4d36757e"),
}
HISTORICAL_ALIAS_SHA256S = {
    "deepcogito/cogito-v2.1-671b": (
        "2519ace3cd3faae48ff775ab0cbdc764fbc876e291eaa1ad1585610114d87e7d"
    ),
    "deepseek/deepseek-v3.2-exp": (
        "7d801a7f967fa9375d7f16b5e615a4e6086078a1771f6001e664ad965eb7a324"
    ),
    "deepseek/deepseek-v4-pro-0813": (
        "007fb8b58e8df2eb541c4f87955eba4c814a86ecfda9318f0921afcee13f7dda"
    ),
    "google/gemma-4-26b-a4b-it": (
        "31e9a536ec1bde330097fb0086ce638b84df3bbad902e44433302cfcac5fe95c"
    ),
    "meta-llama/llama-4-maverick": (
        "6f63b021e5e40019958f6771d6345847b324ceb9f4d6c3de3d47783545580306"
    ),
    "minimax/minimax-m3": "2ef09041514eafd591beba190109df45485281c3145eda2fda4f414df0562f3d",
    "mistralai/mistral-small-2603": (
        "6fdd04c88309f38db7458145388282c2339702d379d594df7663ad93dd5efed2"
    ),
    "moonshotai/kimi-k2-thinking": (
        "a6d9f05ff80b6891df1096b463f22ed8ac3baa2bbc6878563a7abb0bf6ebaadb"
    ),
    "moonshotai/kimi-k3": ("d021893d36b3f97cc32b0cde64d3692d2bd979b69197812e017ea5bb32656f82"),
    "nvidia/nemotron-3-super-120b-a12b": (
        "147733332aa42b5d70a1208412a2c65bdaeafeed2d014ebb34b8e10e0cdd3656"
    ),
    "openai/gpt-oss-120b": ("1ae940000d4f520c9655f92745b38f8a25b67db7f3b66ab4cb987110ca94863a"),
    "qwen/qwen3.6-35b-a3b": ("8c4b0cc344285ce321abb6a1387b7a7515d7bf50071824d65b34863e6162409d"),
    "tencent/hunyuan-a13b-instruct": (
        "374f4e8443ce01c1626ac5a661ac426b54a949a25fa1f9400b8c09ab51d24565"
    ),
    "z-ai/glm-4.7": "7e14303ba09761f15f69fc7222dced9e7b59d0312e18cc9923493ffc6144446d",
}
HISTORICAL_CLAIM_SHA256S = {
    "claim-cogito-deepseek": ("ab0609f42064ec07d8890529f8ea64af8dad8d233d8d5aaff8ff6cca21a68893"),
    "claim-deepseek-anchor": ("57cd0807b3d8162cfed00016b18dfe8e59343c359ee3f7e51feb5cd007f2559c"),
    "claim-deepseek-v4-anchor": (
        "757d0afd3689ce7a37778f77a70571038675731a98a90f2705d4f6f8a52a3fb2"
    ),
    "claim-gemma-anchor": ("a0d4a14f40030f4d23f19112bb4d22903a03aec2258daa1b027f701d9aa570a6"),
    "claim-gpt-oss-publisher-identity": (
        "3a88bd4122edeb3204191a73b748d0fc7494ad08296dec9fc066ff7ba2318105"
    ),
    "claim-hunyuan-anchor": ("12b3bebd757fae1ee852b0ce203f78714871ba0c71da026848d0ef159d9a190b"),
    "claim-hunyuan-pretrain-instruct": (
        "b585b54c4aee30509cf8d91f8498e48b0aff596060b185e6bf349b3c901a0daa"
    ),
    "claim-kimi-anchor": ("446a5f433fbd9ae05376c99b74b54e77d480b6224c2a72db281d2ff8a80507dd"),
    "claim-kimi-k3-anchor": ("92998874acc7664846fa8b05266a97765e02e308cdfb9fa5461f4ed862dfc29f"),
    "claim-llama-anchor": ("5f0a9fd419e94ee8defb6618ddc2c9edea7d727dfe729e5499f363070f994918"),
    "claim-minimax-anchor": ("bb4303323856bc24b9912a32ad793ab1b8349124f668aba52b20ae473860a539"),
    "claim-mistral-anchor": ("a2b6d9dcaf7726d97b9c75c0eac2bb0d33c826ac8d6469f4a2a31236e2095247"),
    "claim-nemotron-base-anchor": (
        "f439feee3ac17ceeae701cb3dc0af9bcb2b5d9dd2e3776a9d1692bce3103df7b"
    ),
    "claim-nemotron-posttrain-anchor": (
        "33714d70ab18fdf2a9180f66ca24419d377b22e95d7fb3ad28a8df3e70cf5c06"
    ),
    "claim-qwen-anchor": ("22b8d9e30db8cdef5e6e60870696402b13fb3d5b8a40650bd7bfce513883337a"),
    "claim-z-ai-anchor": ("18c8b275ad60b4279ab4fa464115350e26634d35b931cb379c59ad814c1645dc"),
}
HISTORICAL_CONSTRAINT_SHA256S = {
    "constraint-cogito-deepseek": (
        "7dfc4ea9597b0389307b87aaf912e3d2dad69bb315916707f17849dcffa6819c"
    ),
    "constraint-deepseek-family": (
        "c9092c3899dbff3bef7493a734ee489e71c4b9f99ce1a9f52cdad7c2997e9edb"
    ),
    "constraint-gemma-gemini": ("32b26951e4e867adf0bd42ae11a277c99210d8fe98ac7909dd8abf65e385fc3e"),
    "constraint-gpt-oss-gpt-5-6": (
        "3a5ac5ecb782e6ab985fea4f073402bef26ddc10e8112deb76c7d8727008703b"
    ),
    "constraint-kimi-k2-k3": ("0dd13e7eb259b838458380a69618734157de2b86a332f9bf8405784a76604c8a"),
    "constraint-nemotron-meta": (
        "5e2e16e7f2ad5270ed8419179a60d66cb8af86fed1ed67827f313238c167b4c0"
    ),
}


def test_committed_public_lineage_manifest_rebuilds_and_resolves_exactly() -> None:
    raw_manifest = MANIFEST_PATH.read_bytes()
    assert hashlib.sha256(raw_manifest).hexdigest() == PUBLIC_MODEL_LINEAGE_MANIFEST_FILE_SHA256

    bundle = PublicModelLineageEvidenceBundle.model_validate_json(raw_manifest)
    assert stable_json(bundle).encode("utf-8") == raw_manifest
    assert build_manifest(EVIDENCE_ROOT) == bundle
    assert bundle.bundle_sha256 == (
        "815fc0e376682f83f994ac5c21962c5f43556a78f5e736045f93a6ee81e5de0d"
    )
    assert bundle.verified_at.isoformat() == "2026-08-21T22:19:00+00:00"
    assert bundle.valid_until.isoformat() == "2027-02-17T22:19:00+00:00"
    assert max(item.retrieved_at for item in bundle.sources) < bundle.verified_at
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
    assert {
        item.source_id: item.file_binding.sha256
        for item in bundle.sources
        if item.source_id in HISTORICAL_SOURCE_FILE_SHA256S
    } == HISTORICAL_SOURCE_FILE_SHA256S
    assert {
        item.exact_model_id: item.alias_sha256
        for item in bundle.aliases
        if item.exact_model_id in HISTORICAL_ALIAS_SHA256S
    } == HISTORICAL_ALIAS_SHA256S
    assert {
        item.claim_id: item.claim_sha256
        for item in bundle.claims
        if item.claim_id in HISTORICAL_CLAIM_SHA256S
    } == HISTORICAL_CLAIM_SHA256S
    assert {
        item.constraint_id: item.constraint_sha256
        for item in bundle.conservative_non_independence_constraints
        if item.constraint_id in HISTORICAL_CONSTRAINT_SHA256S
    } == HISTORICAL_CONSTRAINT_SHA256S

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
    assert len(approved_public_model_lineages(capability)) == 11
    assert len(inventory.conservative_non_independence_constraints) == 8
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
        "z-ai/glm-5.2",
        "moonshotai/kimi-k3",
    )
    for left, right in permutations(active_triple, 2):
        independent = require_independent_public_model_lineage(capability, left, right)
        assert independent.independent is True
        assert independent.left_exact_model_id == left
        assert independent.right_exact_model_id == right
        assert independent.left_root_lineage != independent.right_root_lineage

    tencent = require_verified_public_model_lineage(capability, "tencent/hy3")
    assert tencent.root_lineage == (
        "sha256:932e8cdba524bbf5280d368b0cb711bf0bf36b6fb57ea744bda2a86caea534fb"
    )
    tencent_decision = next(
        item for item in bundle.decisions if item.exact_model_id == "tencent/hy3"
    )
    assert tencent_decision.decision_sha256 == (
        "c9bf714c289ca3ab66cc06062145ff4dd12770f9c9f035c1c23732f338395673"
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
    tencent_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-tencent-hy3-hunyuan"
    )
    assert (
        tencent_constraint.constraint_kind
        is PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL
    )
    assert tencent_constraint.member_exact_model_ids == (
        "tencent/hunyuan-a13b-instruct",
        "tencent/hy3",
    )
    assert tencent_constraint.supporting_claim_ids == (
        "claim-hunyuan-anchor",
        "claim-tencent-hy3-anchor",
    )
    with pytest.raises(PublicModelLineageAuthorityError, match="lacks confirmed"):
        require_independent_public_model_lineage(
            capability,
            "tencent/hy3",
            "tencent/hunyuan-a13b-instruct",
        )

    glm_5_2 = require_verified_public_model_lineage(capability, "z-ai/glm-5.2")
    assert glm_5_2.root_lineage == (
        "sha256:c75238db92f2deb5938759be4c163b22a95f1297a2eb560ab5d90ba69d0764e7"
    )
    glm_constraint = next(
        item
        for item in inventory.conservative_non_independence_constraints
        if item.constraint_id == "constraint-z-ai-glm-family"
    )
    assert (
        glm_constraint.constraint_kind
        is PublicModelLineageConstraintKind.CONSERVATIVE_ORGANIZATIONAL
    )
    assert glm_constraint.member_exact_model_ids == (
        "z-ai/glm-4.7",
        "z-ai/glm-5.2",
    )
    assert glm_constraint.supporting_claim_ids == (
        "claim-z-ai-anchor",
        "claim-z-ai-glm-5-2-anchor",
    )
    assert glm_constraint.negative_only is True
    assert glm_constraint.positive_root_assignment_authorized is False
    with pytest.raises(PublicModelLineageAuthorityError, match="lacks confirmed"):
        require_independent_public_model_lineage(
            capability,
            "z-ai/glm-4.7",
            "z-ai/glm-5.2",
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
        (
            "claim-tencent-hy3-anchor",
            "BUILD_ANCESTRY",
            "tencent-hy3-card",
            1_857,
            2_148,
            "b9e3eda30b51b800f26955d3f39299389dea8466df5292dd3504557a88b4ab9a",
        ),
        (
            "claim-z-ai-glm-5-2-anchor",
            "BUILD_ANCESTRY",
            "z-ai-glm-5-2-card",
            1_072,
            1_918,
            "93d6576eca27ee90d8b712a4594af35e6e3fc56d45ba537c378288ea5b749cb1",
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
