from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import dataclass
from decimal import ROUND_UP, DefaultContext, Rounded, localcontext
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.models.evidence_seal_authority as evidence_seal_module
from mmaudit.benchmark.model_portfolio import ModelBenchmarkPortfolio
from mmaudit.benchmark.models import (
    ModelBenchmarkProviderResult,
    ModelBenchmarkReport,
    ModelBenchmarkSuite,
    ModelBenchmarkTarget,
    load_model_benchmark_corpus,
    run_model_benchmark,
)
from mmaudit.models.autonomous_benchmark_verdict import (
    EvidenceSealPolicyDisposition,
    EvidenceSealVerdictPolicy,
    EvidenceSealVerdictProjection,
    load_evidence_seal_verdict_policy,
)
from mmaudit.models.candidate_benchmark import CandidateCostLedgerSnapshot
from mmaudit.models.evidence_seal_authority import (
    EvidenceAuthoritySubject,
    EvidenceSealCollisionMap,
    EvidenceSealDecisionProjection,
    EvidenceSealedAuthorityEvidence,
    EvidenceSealLineageBinding,
    EvidenceSealLineageRole,
    EvidenceSealRunKind,
    EvidenceTransparencyPrefixProof,
    build_evidence_authority_subject,
    build_evidence_seal_collision_map,
    build_evidence_seal_decision_projection,
    build_evidence_seal_lineage_binding,
    build_evidence_seal_verdict_projection,
    build_evidence_sealed_authority_evidence,
    build_transparency_prefix_proof,
)
from mmaudit.models.ground_truth_authority import (
    FrozenGroundTruthProvenance,
    VerifiedFrozenGroundTruth,
    VerifiedFrozenGroundTruthProjection,
    load_frozen_ground_truth_provenance,
    resolve_verified_frozen_ground_truth,
)
from mmaudit.models.lineage_authority import TrustedModelLineageReviewVerification
from mmaudit.models.schemas import ExecutionEvidenceKind
from mmaudit.orchestration.manifest import canonical_sha256
from tests.identity_fixtures import rebind_synthetic_token_plan
from tests.unit.test_model_benchmark_portfolio import (
    _DeterministicProvider,
    _UnavailableProvider,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "benchmarks" / "model_corpus" / "manifest.json"
PROVENANCE_PATH = ROOT / "benchmarks" / "model_corpus" / "provenance.json"
VERDICT_POLICY_PATH = ROOT / "benchmarks" / "model_corpus" / "verdict_policy.json"
CANDIDATE_ROOT = "sha256:" + ("a" * 64)
JUDGE_A_ROOT = "sha256:" + ("b" * 64)
JUDGE_B_ROOT = "sha256:" + ("c" * 64)
LOG_ID_SHA256 = "4e2ac450e7bc19e4e7b7bd3d0cf4a66f83968770fbbb05d2f8730322e6abf351"
PRIMARY_REPORT_SHA256 = "036bb233995faf9e5a0421e34035c2d2fb4d54a21752ee447f0a116c2ce2d908"
REPLAY_REPORT_SHA256 = "b3be16aba98e2c3a20ececdb59fd549da694b6657a55248149e16bea0f3d288e"
DECISION_OUTPUT_SHA256 = "2cf08db7380059b629ecc231a4e5f51c0ae558de3747c7f99c95896cdd2c96bd"
SUBJECT_SHA256 = "31884aee8d8ee4b68e72bb053b07f6fae048bd9f198f0d1e401530463f245c1c"
CHECKPOINT_SHA256 = "bd5b5ee2e4b3819c240d09824b01d47d06046b1d9c638da4e313198afc2dd0ca"
TREE_ROOT_SHA256 = "08c279fcf1bdfc975f4090810125568eaa7b8fc1d9d9de6191fc7f87d356e567"


class _ReplayProvider(_DeterministicProvider):
    async def evaluate(
        self,
        *,
        target: ModelBenchmarkTarget,
        system_prompt: str,
        user_prompt: str,
    ) -> ModelBenchmarkProviderResult:
        result = await super().evaluate(
            target=target,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
        )
        record = rebind_synthetic_token_plan(
            result.usage_record.model_copy(update={"role": target.request_role})
        )
        return ModelBenchmarkProviderResult(response=result.response, usage_record=record)


@dataclass(frozen=True, slots=True)
class _Fixture:
    suite: ModelBenchmarkSuite
    provenance: FrozenGroundTruthProvenance
    frozen_ground_truth: VerifiedFrozenGroundTruth
    ground_projection: VerifiedFrozenGroundTruthProjection
    primary_report: ModelBenchmarkReport
    replay_report: ModelBenchmarkReport
    candidate: EvidenceSealLineageBinding
    judges: tuple[EvidenceSealLineageBinding, EvidenceSealLineageBinding]
    collision_map: EvidenceSealCollisionMap
    projections: tuple[EvidenceSealDecisionProjection, EvidenceSealDecisionProjection]
    verdict_policy: EvidenceSealVerdictPolicy
    verdict: EvidenceSealVerdictProjection
    subject: EvidenceAuthoritySubject
    proof: EvidenceTransparencyPrefixProof


@pytest.fixture(scope="module")
def authority_fixture() -> _Fixture:
    suite = load_model_benchmark_corpus(MANIFEST_PATH)
    provenance = load_frozen_ground_truth_provenance(PROVENANCE_PATH)
    frozen_ground_truth = resolve_verified_frozen_ground_truth(
        provenance=provenance,
        benchmark_suite=suite,
    )
    ground_projection = frozen_ground_truth.require_for(
        objective_sha256=provenance.objective_sha256,
        provenance_sha256=provenance.provenance_sha256,
        source_revision=provenance.source_revision,
        benchmark_corpus_sha256=suite.corpus_sha256,
        benchmark_ground_truth_sha256=suite.ground_truth_sha256,
    )
    primary_target = ModelBenchmarkTarget(
        model_id="author-a/model-a",
        root_lineage=CANDIDATE_ROOT,
    )
    replay_target = ModelBenchmarkTarget(
        model_id="author-a/model-a",
        root_lineage=CANDIDATE_ROOT,
        request_role="model_benchmark:falsifier:verifier",
    )
    primary_report = asyncio.run(
        run_model_benchmark(
            corpus=suite,
            targets=[primary_target],
            provider=_DeterministicProvider(
                suite=suite,
                execution_evidence=ExecutionEvidenceKind.MOCK,
            ),
        )
    )
    replay_report = asyncio.run(
        run_model_benchmark(
            corpus=suite,
            targets=[replay_target],
            provider=_ReplayProvider(
                suite=suite,
                execution_evidence=ExecutionEvidenceKind.MOCK,
            ),
        )
    )
    candidate = build_evidence_seal_lineage_binding(
        exact_model_id=primary_target.model_id,
        root_lineage=CANDIDATE_ROOT,
        role=EvidenceSealLineageRole.CANDIDATE,
    )
    judges = (
        build_evidence_seal_lineage_binding(
            exact_model_id="judge-a/model",
            root_lineage=JUDGE_A_ROOT,
            role=EvidenceSealLineageRole.JUDGE,
        ),
        build_evidence_seal_lineage_binding(
            exact_model_id="judge-b/model",
            root_lineage=JUDGE_B_ROOT,
            role=EvidenceSealLineageRole.JUDGE,
        ),
    )
    collision_map = build_evidence_seal_collision_map(candidate=candidate, judges=judges)
    projections = (
        build_evidence_seal_decision_projection(
            suite=suite,
            report=primary_report,
            candidate=candidate,
            runner=judges[0],
            run_kind=EvidenceSealRunKind.PRIMARY,
            ground_truth_projection=ground_projection,
        ),
        build_evidence_seal_decision_projection(
            suite=suite,
            report=replay_report,
            candidate=candidate,
            runner=judges[1],
            run_kind=EvidenceSealRunKind.REPLAY,
            ground_truth_projection=ground_projection,
        ),
    )
    verdict_policy = load_evidence_seal_verdict_policy(VERDICT_POLICY_PATH)
    verdict = build_evidence_seal_verdict_projection(
        benchmark_suite=suite,
        ground_truth_projection=ground_projection,
        policy=verdict_policy,
        collision_map=collision_map,
        decision_projections=projections,
        benchmark_reports=(primary_report, replay_report),
    )
    subject = build_evidence_authority_subject(
        benchmark_suite=suite,
        ground_truth_projection=ground_projection,
        collision_map=collision_map,
        decision_projections=projections,
        benchmark_reports=(primary_report, replay_report),
        verdict_projection=verdict,
    )
    previous = build_transparency_prefix_proof(
        log_id_sha256=LOG_ID_SHA256,
        authority_subject_sha256s=("1" * 64,),
    )
    proof = build_transparency_prefix_proof(
        log_id_sha256=LOG_ID_SHA256,
        authority_subject_sha256s=("1" * 64, subject.authority_subject_sha256),
        previous_checkpoint=previous.checkpoint,
    )
    return _Fixture(
        suite=suite,
        provenance=provenance,
        frozen_ground_truth=frozen_ground_truth,
        ground_projection=ground_projection,
        primary_report=primary_report,
        replay_report=replay_report,
        candidate=candidate,
        judges=judges,
        collision_map=collision_map,
        projections=projections,
        verdict_policy=verdict_policy,
        verdict=verdict,
        subject=subject,
        proof=proof,
    )


def test_deterministic_comparison_fixture_is_exactly_pinned(
    authority_fixture: _Fixture,
) -> None:
    fixture = authority_fixture

    assert fixture.primary_report.report_sha256 == PRIMARY_REPORT_SHA256
    assert fixture.replay_report.report_sha256 == REPLAY_REPORT_SHA256
    assert fixture.subject.deterministic_decision_output_sha256 == DECISION_OUTPUT_SHA256
    assert fixture.subject.authority_subject_sha256 == SUBJECT_SHA256
    assert fixture.proof.checkpoint.checkpoint_sha256 == CHECKPOINT_SHA256
    assert fixture.proof.checkpoint.tree_root_sha256 == TREE_ROOT_SHA256
    assert fixture.proof.checkpoint.tree_size == 2


def test_decision_projection_is_independent_of_ambient_decimal_context(
    authority_fixture: _Fixture,
) -> None:
    original_rounded_flag = DefaultContext.flags[Rounded]
    original_rounded_trap = DefaultContext.traps[Rounded]
    try:
        DefaultContext.flags[Rounded] = True
        DefaultContext.traps[Rounded] = True
        with localcontext() as context:
            context.prec = 3
            context.Emin = -3
            context.Emax = 3
            context.rounding = ROUND_UP
            rebuilt = build_evidence_seal_decision_projection(
                suite=authority_fixture.suite,
                report=authority_fixture.primary_report,
                candidate=authority_fixture.candidate,
                runner=authority_fixture.judges[0],
                run_kind=EvidenceSealRunKind.PRIMARY,
                ground_truth_projection=authority_fixture.ground_projection,
            )
            rebuilt_verdict = build_evidence_seal_verdict_projection(
                benchmark_suite=authority_fixture.suite,
                ground_truth_projection=authority_fixture.ground_projection,
                policy=authority_fixture.verdict_policy,
                collision_map=authority_fixture.collision_map,
                decision_projections=authority_fixture.projections,
                benchmark_reports=(
                    authority_fixture.primary_report,
                    authority_fixture.replay_report,
                ),
            )
    finally:
        DefaultContext.flags[Rounded] = original_rounded_flag
        DefaultContext.traps[Rounded] = original_rounded_trap

    assert rebuilt == authority_fixture.projections[0]
    assert rebuilt.projection_sha256 == authority_fixture.projections[0].projection_sha256
    assert rebuilt_verdict == authority_fixture.verdict


def test_verdict_rejects_overbound_ledger_text_before_portfolio_revalidation(
    authority_fixture: _Fixture,
) -> None:
    overbound = CandidateCostLedgerSnapshot.model_construct(
        cap_usd="250",
        spent_usd="0." + ("1" * 37),
        active_reserved_usd="0",
        remaining_usd="250",
    )
    portfolio = ModelBenchmarkPortfolio.model_construct(
        initial_cost_ledger_snapshot=overbound,
        cost_ledger_snapshot=overbound,
    )

    with pytest.raises(ValueError, match="exceeds the autonomous verdict USD bound"):
        build_evidence_seal_verdict_projection(
            benchmark_suite=authority_fixture.suite,
            ground_truth_projection=authority_fixture.ground_projection,
            policy=authority_fixture.verdict_policy,
            collision_map=authority_fixture.collision_map,
            decision_projections=authority_fixture.projections,
            benchmark_reports=(
                authority_fixture.primary_report,
                authority_fixture.replay_report,
            ),
            campaign_portfolios=(portfolio, portfolio),
        )


def test_structural_seal_is_explicitly_non_authorizing(
    authority_fixture: _Fixture,
) -> None:
    evidence = build_evidence_sealed_authority_evidence(
        subject=authority_fixture.subject,
        transparency_proof=authority_fixture.proof,
    )

    assert isinstance(evidence, EvidenceSealedAuthorityEvidence)
    assert evidence.authority_basis == "EVIDENCE_SEALED_REPRODUCIBLE"
    assert evidence.external_comparison_required is True
    assert evidence.durable_authority is False
    assert evidence.source_egress_authorized is False
    assert evidence.benchmark_scoring_authorized is False
    assert evidence.authority_issuance_authorized is False
    assert evidence.model_qualification_authorized is False
    assert evidence.production_selection_authorized is False
    assert evidence.provider_access_authorized is False
    assert (
        authority_fixture.verdict.policy_disposition is EvidenceSealPolicyDisposition.NOT_SATISFIED
    )
    assert authority_fixture.verdict.baseline_disposition == "UNEVALUABLE"
    assert authority_fixture.verdict.comparison_only is True
    assert not hasattr(evidence_seal_module, "resolve_evidence_sealed_authority")
    assert not hasattr(evidence_seal_module, "VerifiedEvidenceSealedAuthority")


def test_mock_reports_and_caller_labeled_judges_cannot_mint_runtime_authority(
    authority_fixture: _Fixture,
) -> None:
    assert all(
        projection.execution_evidence == ExecutionEvidenceKind.MOCK.value
        for projection in authority_fixture.projections
    )
    evidence = build_evidence_sealed_authority_evidence(
        subject=authority_fixture.subject,
        transparency_proof=authority_fixture.proof,
    )
    assert evidence.authority_issuance_authorized is False
    assert type(evidence) is not TrustedModelLineageReviewVerification


def test_same_root_judgment_voids_the_subject(authority_fixture: _Fixture) -> None:
    same_root_judge = build_evidence_seal_lineage_binding(
        exact_model_id="judge-a/model",
        root_lineage=CANDIDATE_ROOT,
        role=EvidenceSealLineageRole.JUDGE,
    )
    collision_map = build_evidence_seal_collision_map(
        candidate=authority_fixture.candidate,
        judges=(same_root_judge, authority_fixture.judges[1]),
    )
    projections = (
        build_evidence_seal_decision_projection(
            suite=authority_fixture.suite,
            report=authority_fixture.primary_report,
            candidate=authority_fixture.candidate,
            runner=same_root_judge,
            run_kind=EvidenceSealRunKind.PRIMARY,
            ground_truth_projection=authority_fixture.ground_projection,
        ),
        authority_fixture.projections[1],
    )

    with pytest.raises(ValidationError, match="same-root judgment voids"):
        build_evidence_authority_subject(
            benchmark_suite=authority_fixture.suite,
            ground_truth_projection=authority_fixture.ground_projection,
            collision_map=collision_map,
            decision_projections=projections,
            benchmark_reports=(
                authority_fixture.primary_report,
                authority_fixture.replay_report,
            ),
            verdict_projection=authority_fixture.verdict,
        )


def test_runners_require_distinct_root_lineages(authority_fixture: _Fixture) -> None:
    duplicate_root_judge = build_evidence_seal_lineage_binding(
        exact_model_id="judge-b/model",
        root_lineage=JUDGE_A_ROOT,
        role=EvidenceSealLineageRole.JUDGE,
    )
    collision_map = build_evidence_seal_collision_map(
        candidate=authority_fixture.candidate,
        judges=(authority_fixture.judges[0], duplicate_root_judge),
    )
    replay = build_evidence_seal_decision_projection(
        suite=authority_fixture.suite,
        report=authority_fixture.replay_report,
        candidate=authority_fixture.candidate,
        runner=duplicate_root_judge,
        run_kind=EvidenceSealRunKind.REPLAY,
        ground_truth_projection=authority_fixture.ground_projection,
    )

    with pytest.raises(ValidationError, match="distinct root lineages"):
        build_evidence_authority_subject(
            benchmark_suite=authority_fixture.suite,
            ground_truth_projection=authority_fixture.ground_projection,
            collision_map=collision_map,
            decision_projections=(authority_fixture.projections[0], replay),
            benchmark_reports=(
                authority_fixture.primary_report,
                authority_fixture.replay_report,
            ),
            verdict_projection=authority_fixture.verdict,
        )


def test_replay_cannot_reuse_the_primary_report(authority_fixture: _Fixture) -> None:
    replay = build_evidence_seal_decision_projection(
        suite=authority_fixture.suite,
        report=authority_fixture.primary_report,
        candidate=authority_fixture.candidate,
        runner=authority_fixture.judges[1],
        run_kind=EvidenceSealRunKind.REPLAY,
        ground_truth_projection=authority_fixture.ground_projection,
    )

    with pytest.raises(ValidationError, match="cannot reuse benchmark report"):
        build_evidence_authority_subject(
            benchmark_suite=authority_fixture.suite,
            ground_truth_projection=authority_fixture.ground_projection,
            collision_map=authority_fixture.collision_map,
            decision_projections=(authority_fixture.projections[0], replay),
            benchmark_reports=(
                authority_fixture.primary_report,
                authority_fixture.primary_report,
            ),
            verdict_projection=authority_fixture.verdict,
        )


def test_replay_output_must_be_byte_identical(authority_fixture: _Fixture) -> None:
    unavailable_report = asyncio.run(
        run_model_benchmark(
            corpus=authority_fixture.suite,
            targets=[
                ModelBenchmarkTarget(
                    model_id=authority_fixture.candidate.exact_model_id,
                    root_lineage=authority_fixture.candidate.root_lineage,
                    request_role="model_benchmark:falsifier:verifier",
                )
            ],
            provider=_UnavailableProvider(),
        )
    )
    replay = build_evidence_seal_decision_projection(
        suite=authority_fixture.suite,
        report=unavailable_report,
        candidate=authority_fixture.candidate,
        runner=authority_fixture.judges[1],
        run_kind=EvidenceSealRunKind.REPLAY,
        ground_truth_projection=authority_fixture.ground_projection,
    )

    with pytest.raises(ValueError, match="not byte-identical"):
        build_evidence_authority_subject(
            benchmark_suite=authority_fixture.suite,
            ground_truth_projection=authority_fixture.ground_projection,
            collision_map=authority_fixture.collision_map,
            decision_projections=(authority_fixture.projections[0], replay),
            benchmark_reports=(authority_fixture.primary_report, unavailable_report),
            verdict_projection=authority_fixture.verdict,
        )


def test_transparency_prefix_is_exact_and_append_only(authority_fixture: _Fixture) -> None:
    with pytest.raises(ValueError, match="do not extend"):
        build_transparency_prefix_proof(
            log_id_sha256=LOG_ID_SHA256,
            authority_subject_sha256s=(
                "2" * 64,
                authority_fixture.subject.authority_subject_sha256,
            ),
            previous_checkpoint=authority_fixture.proof.previous_checkpoint,
        )

    raw = authority_fixture.proof.model_dump(mode="json")
    raw["leaf_sha256s"][0] = "f" * 64
    with pytest.raises(ValidationError, match="tree root is inconsistent"):
        EvidenceTransparencyPrefixProof.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


@pytest.mark.parametrize(
    "field",
    [
        "durable_authority",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
    ],
)
def test_durable_seal_cannot_carry_authority(
    authority_fixture: _Fixture,
    field: str,
) -> None:
    evidence = build_evidence_sealed_authority_evidence(
        subject=authority_fixture.subject,
        transparency_proof=authority_fixture.proof,
    )
    raw = evidence.model_dump(mode="json")
    raw[field] = True
    raw.pop("authority_sha256")
    raw["authority_sha256"] = canonical_sha256(raw)

    with pytest.raises(ValidationError, match="literal false"):
        EvidenceSealedAuthorityEvidence.model_validate_json(
            json.dumps(raw, sort_keys=True),
            strict=True,
        )


def test_subject_and_proof_must_match(authority_fixture: _Fixture) -> None:
    other = build_transparency_prefix_proof(
        log_id_sha256=LOG_ID_SHA256,
        authority_subject_sha256s=("2" * 64,),
    )
    with pytest.raises(ValueError, match="belongs to another"):
        build_evidence_sealed_authority_evidence(
            subject=authority_fixture.subject,
            transparency_proof=other,
        )


def test_structural_evidence_does_not_bridge_existing_lineage_authority(
    authority_fixture: _Fixture,
) -> None:
    evidence = build_evidence_sealed_authority_evidence(
        subject=authority_fixture.subject,
        transparency_proof=authority_fixture.proof,
    )

    assert not isinstance(evidence, TrustedModelLineageReviewVerification)
    with pytest.raises(TypeError, match="cannot be constructed"):
        TrustedModelLineageReviewVerification()


def test_mutated_models_are_revalidated_at_every_builder_boundary(
    authority_fixture: _Fixture,
) -> None:
    mutated_subject = copy.deepcopy(authority_fixture.subject)
    object.__setattr__(mutated_subject, "objective_sha256", "0" * 64)

    with pytest.raises(ValueError, match="structurally invalid"):
        build_evidence_sealed_authority_evidence(
            subject=mutated_subject,
            transparency_proof=authority_fixture.proof,
        )


def test_raw_self_hashes_do_not_create_an_issuer_api() -> None:
    exported_names = set(vars(evidence_seal_module))
    assert "resolve_evidence_sealed_authority" not in exported_names
    assert "VerifiedEvidenceSealedAuthority" not in exported_names
    assert "verify_operator_model_lineage_authority" not in exported_names
