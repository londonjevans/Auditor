"""Synthetic structural calibration data; never authenticated runtime authority."""

from functools import cache

from mmaudit.models import evidence_seal_authority as seals
from mmaudit.models.authenticated_calibration import (
    AuthenticatedCalibrationCandidateSource,
    AuthenticatedCalibrationRun,
)
from mmaudit.models.candidate_benchmark import CandidateBenchmarkDiagnostic
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.unit import test_authenticated_runner_durable_bundle as fixtures


@cache
def structural_source() -> AuthenticatedCalibrationCandidateSource:
    """Reuse the local non-crediting runner fixture without minting a live capability."""

    inputs = fixtures._v11_inputs()
    collision, decisions = fixtures._complete_authseal_inputs(inputs.live, inputs.evidence)
    runs = []
    for custody, decision in zip(inputs.live.runs, decisions, strict=True):
        portfolio = custody.candidate_portfolio
        diagnostic = portfolio.diagnostics[0].model_dump(mode="json")
        diagnostic["report_sha256"] = decision.benchmark_report_sha256
        runs.append(
            AuthenticatedCalibrationRun(
                decision=decision,
                diagnostic=CandidateBenchmarkDiagnostic.model_validate(diagnostic),
                dimensions=tuple(custody.candidate_report.results[0].dimensions),
                candidate_registry_sha256=portfolio.candidate_registry_sha256,
                discovery_manifest_sha256=portfolio.discovery_run_manifest_sha256,
                campaign_journal_sha256=portfolio.campaign_journal_sha256,
                portfolio_sha256=portfolio.portfolio_sha256,
                policy_sha256=custody.candidate_campaign_policy_sha256,
                effective_config_sha256=inputs.evidence.effective_config_sha256,
                ended_at=portfolio.ended_at,
            )
        )
    return AuthenticatedCalibrationCandidateSource(
        runner_evidence=inputs.evidence, collision_map=collision, runs=tuple(runs)
    )


def reseal_source(payload):
    """Rehash structural data only; no source or capability verification is performed."""

    evidence = payload["runner_evidence"]
    evidence["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in evidence.items() if key != "evidence_sha256"}
    )
    return AuthenticatedCalibrationCandidateSource.model_validate_json(stable_json(payload))


def reseal_decision(payload):
    """Create an internally consistent declaration, never an authenticated decision."""

    payload["deterministic_output_sha256"] = seals._decision_output_sha256(
        candidate=seals.EvidenceSealLineageBinding.model_validate_json(
            stable_json(payload["candidate"])
        ),
        corpus_sha256=payload["benchmark_corpus_sha256"],
        ground_truth_sha256=payload["benchmark_ground_truth_sha256"],
        case_outcome_sha256s=tuple(payload["case_outcome_sha256s"]),
        case_dimension_outcome_set_sha256=payload["case_dimension_outcome_set_sha256"],
        dimension_score_sha256s=tuple(payload["dimension_score_sha256s"]),
        overall_score_micros=payload["overall_score_micros"],
        execution_evidence=payload["execution_evidence"],
    )
    payload["projection_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "projection_sha256"}
    )


def population_source(index: int, *, root_index: int | None = None):
    """Namespace synthetic observations without claiming genuine models or REAL origins."""

    template = structural_source()
    payload = template.model_dump(mode="json")
    exact_id = f"calibration/model-{index:03}"
    root = "sha256:" + canonical_sha256(
        ["synthetic-root", index % 6 if root_index is None else root_index]
    )
    candidate = seals.build_evidence_seal_lineage_binding(
        exact_model_id=exact_id, root_lineage=root, role=seals.EvidenceSealLineageRole.CANDIDATE
    )
    payload["collision_map"] = seals.build_evidence_seal_collision_map(
        candidate=candidate, judges=template.collision_map.judges
    ).model_dump(mode="json")

    def bound(value: str) -> str:
        return canonical_sha256(["synthetic-calibration", index, value])

    def request(value: str) -> str:
        return f"cal{index:03}-{value}"

    for retained, run in zip(payload["runner_evidence"]["runs"], payload["runs"], strict=True):
        retained["candidate_model_id"] = exact_id
        retained["candidate_root_lineage"] = root
        for field in (
            "candidate_report_sha256",
            "candidate_portfolio_sha256",
            "prepared_run_sha256",
            "adjudication_report_sha256",
        ):
            retained[field] = bound(retained[field])
        retained["candidate_campaign_report_sha256s"] = sorted(
            bound(value) for value in retained["candidate_campaign_report_sha256s"]
        )
        for case in (*retained["candidate_cases"], *retained["judge_cases"]):
            case["request_id"] = request(case["request_id"])
            case["attempt_request_ids"] = [request(value) for value in case["attempt_request_ids"]]
            case["generation_id"] = request(case["generation_id"])
            for field in (
                "request_body_sha256",
                "validated_response_sha256",
                "generation_attestation_sha256",
            ):
                case[field] = bound(case[field])
        run["decision"]["candidate"] = candidate.model_dump(mode="json")
        run["decision"]["benchmark_report_sha256"] = retained["candidate_report_sha256"]
        run["diagnostic"]["exact_model_id"] = exact_id
        run["diagnostic"]["report_sha256"] = retained["candidate_report_sha256"]
        run["portfolio_sha256"] = retained["candidate_portfolio_sha256"]
        reseal_decision(run["decision"])
    ledger = payload["runner_evidence"]["ledger_interval"]
    for field in ("ledger_identity_sha256", "initial_snapshot_sha256", "final_snapshot_sha256"):
        ledger[field] = bound(ledger[field])
    for entry in ledger["entries"]:
        entry["request_id"] = request(entry["request_id"])
        entry["entry_sha256"] = bound(entry["entry_sha256"])
    return reseal_source(payload)


def population(count: int = 8, *, root_count: int = 6):
    return tuple(population_source(index, root_index=index % root_count) for index in range(count))
