from __future__ import annotations

import json
from collections.abc import Callable
from decimal import Decimal
from functools import cache
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import mmaudit.models.authenticated_runner_durable_bundle as durable_bundle_module
import mmaudit.models.evidence_seal_authority as evidence_seal_module
from mmaudit.benchmark.cross_lineage_adjudication import (
    CrossLineageAdjudicationCaseResult,
    CrossLineageAdjudicationReport,
    CrossLineageAdjudicationRunKind,
    build_cross_lineage_adjudication_case_result,
    build_cross_lineage_adjudication_report,
)
from mmaudit.benchmark.models import ModelBenchmarkReport
from mmaudit.models.authenticated_runner import (
    AuthenticatedCrossLineageCaseExecutionEvidence,
    AuthenticatedCrossLineageLedgerEntryEvidence,
    AuthenticatedCrossLineageLedgerIntervalEvidence,
    AuthenticatedCrossLineageRunnerEvidence,
    AuthenticatedCrossLineageRunnerRunEvidence,
)
from mmaudit.models.authenticated_runner_durable_bundle import (
    AuthenticatedRunnerAuthsealComplete,
    AuthenticatedRunnerAuthsealRejected,
    AuthenticatedRunnerDurableBundleError,
    AuthenticatedRunnerDurableEvidenceBundle,
    authenticated_runner_durable_bundle_bytes,
    build_authenticated_runner_durable_bundle,
    load_authenticated_runner_durable_bundle,
    revalidate_authenticated_runner_durable_bundle,
)
from mmaudit.models.evidence_seal_authority import (
    EvidenceSealDecisionProjection,
    EvidenceSealLineageRole,
    EvidenceSealRunKind,
    build_evidence_seal_collision_map,
    build_evidence_seal_lineage_binding,
)
from mmaudit.models.ground_truth_authority import (
    FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
    FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
    FROZEN_GROUND_TRUTH_SOURCE_REVISION,
    VerifiedFrozenGroundTruthProjection,
)
from mmaudit.models.schemas import UsageRecord
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_io import JsonEvidenceObservation
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.unit import test_authenticated_runner as runner_fixtures
from tests.unit.test_authenticated_runner import _LiveInputs

_LIVE_INPUTS_FACTORY = cast(Callable[[], _LiveInputs], runner_fixtures.live_inputs.__wrapped__)


@cache
def _live_inputs() -> _LiveInputs:
    return _LIVE_INPUTS_FACTORY()


def _case_evidence(
    *,
    case_id: str,
    usage: UsageRecord,
    generation_id: str,
    generation_sha256: str,
    validated_response_sha256: str,
) -> AuthenticatedCrossLineageCaseExecutionEvidence:
    assert usage.request_body_sha256 is not None
    assert usage.accounted_cost_usd_exact is not None
    attempt_ids = tuple(
        usage.request_id if index == 1 else f"{usage.request_id}:attempt:{index}"
        for index in range(1, usage.attempts + 1)
    )
    return AuthenticatedCrossLineageCaseExecutionEvidence(
        case_id=case_id,
        request_id=usage.request_id,
        attempt_count=usage.attempts,
        attempt_request_ids=attempt_ids,
        generation_id=generation_id,
        request_body_sha256=usage.request_body_sha256,
        validated_response_sha256=validated_response_sha256,
        generation_attestation_sha256=generation_sha256,
        accounted_cost_usd=usage.accounted_cost_usd_exact,
    )


def _ground_truth_projection(live: _LiveInputs) -> VerifiedFrozenGroundTruthProjection:
    return live.ground_truth.require_for(
        objective_sha256=FROZEN_GROUND_TRUTH_OBJECTIVE_SHA256,
        provenance_sha256=FROZEN_GROUND_TRUTH_PROVENANCE_SHA256,
        source_revision=FROZEN_GROUND_TRUTH_SOURCE_REVISION,
        benchmark_corpus_sha256=live.suite.corpus_sha256,
        benchmark_ground_truth_sha256=live.suite.ground_truth_sha256,
    )


def _runner_evidence(
    live: _LiveInputs,
    *,
    reports: tuple[CrossLineageAdjudicationReport, ...] | None = None,
) -> AuthenticatedCrossLineageRunnerEvidence:
    adjudications = (
        tuple(run.adjudication_report for run in live.runs) if reports is None else reports
    )
    run_evidence: list[AuthenticatedCrossLineageRunnerRunEvidence] = []
    ledger_costs: dict[str, str] = {}
    for custody, adjudication in zip(live.runs, adjudications, strict=True):
        candidate_cases = []
        for case in custody.candidate_report.results[0].cases:
            assert case.usage_record is not None
            assert case.generation_evidence is not None
            assert case.validated_response_sha256 is not None
            candidate = _case_evidence(
                case_id=case.case_id,
                usage=case.usage_record,
                generation_id=case.generation_evidence.generation_id,
                generation_sha256=case.generation_evidence.evidence_sha256,
                validated_response_sha256=case.validated_response_sha256,
            )
            candidate_cases.append(candidate)
            assert case.usage_record.accounted_cost_usd_exact is not None
            for request_id in candidate.attempt_request_ids:
                ledger_costs[request_id] = case.usage_record.accounted_cost_usd_exact
        judge_cases = []
        for case in adjudication.cases:
            judge = _case_evidence(
                case_id=case.case_id,
                usage=case.usage_record,
                generation_id=case.generation_evidence.generation_id,
                generation_sha256=case.generation_evidence.evidence_sha256,
                validated_response_sha256=case.judge_validated_response_sha256,
            )
            judge_cases.append(judge)
            assert case.usage_record.accounted_cost_usd_exact is not None
            for request_id in judge.attempt_request_ids:
                ledger_costs[request_id] = case.usage_record.accounted_cost_usd_exact
        target = adjudication.target
        run_evidence.append(
            AuthenticatedCrossLineageRunnerRunEvidence(
                run_kind=custody.run_kind,
                candidate_model_id=target.candidate_model_id,
                candidate_root_lineage=target.candidate_root_lineage,
                judge_model_id=target.judge_model_id,
                judge_root_lineage=target.judge_root_lineage,
                candidate_report_sha256=custody.candidate_report.report_sha256,
                candidate_portfolio_sha256=custody.candidate_portfolio.portfolio_sha256,
                candidate_campaign_report_sha256s=(custody.candidate_report.report_sha256,),
                prepared_run_sha256=adjudication.prepared_run_sha256,
                adjudication_report_sha256=adjudication.report_sha256,
                candidate_cases=tuple(candidate_cases),
                judge_cases=tuple(judge_cases),
            )
        )
    ledger_entries = tuple(
        AuthenticatedCrossLineageLedgerEntryEvidence(
            request_id=request_id,
            entry_sha256=canonical_sha256(
                {"request_id": request_id, "actual_cost_usd": actual_cost}
            ),
            actual_cost_usd=actual_cost,
        )
        for request_id, actual_cost in sorted(ledger_costs.items())
    )
    interval_cost = sum((float(item.actual_cost_usd) for item in ledger_entries), start=0.0)
    interval_cost_text = format(interval_cost, ".12f").rstrip("0").rstrip(".")
    ledger = AuthenticatedCrossLineageLedgerIntervalEvidence(
        ledger_identity_sha256="1" * 64,
        initial_snapshot_sha256="2" * 64,
        final_snapshot_sha256="3" * 64,
        cap_usd="250",
        initial_spent_usd="0",
        interval_spent_usd=interval_cost_text,
        final_spent_usd=interval_cost_text,
        entries=ledger_entries,
    )
    ground = _ground_truth_projection(live)
    first_target = adjudications[0].target
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "objective_sha256": ground.objective_sha256,
        "frozen_ground_truth_provenance_sha256": ground.provenance_sha256,
        "frozen_source_revision": ground.source_revision,
        "benchmark_corpus_sha256": ground.benchmark_corpus_sha256,
        "benchmark_ground_truth_sha256": ground.benchmark_ground_truth_sha256,
        "ground_truth_case_binding_set_sha256": ground.case_binding_set_sha256,
        "public_lineage_bundle_sha256": first_target.public_lineage_bundle_sha256,
        "public_lineage_manifest_file_sha256": (first_target.public_lineage_manifest_file_sha256),
        "case_ids": tuple(item.case_id for item in live.suite.cases),
        "runs": tuple(run_evidence),
        "ledger_interval": ledger,
        "serialized_authority": False,
        "lineage_identity_authorized": False,
        "provider_call_authorized": False,
        "source_egress_authorized": False,
        "runner_custody_authorized": False,
        "generation_verification_authorized": False,
        "adjudication_credit_authorized": False,
        "model_qualification_authorized": False,
        "production_selection_authorized": False,
        "seal_publication_authorized": False,
        "release_authorized": False,
        "benchmark_authorized": False,
    }
    json_payload = {
        key: value.model_dump(mode="json") if hasattr(value, "model_dump") else value
        for key, value in payload.items()
    }
    json_payload["runs"] = [item.model_dump(mode="json") for item in run_evidence]
    return AuthenticatedCrossLineageRunnerEvidence(
        **payload,
        evidence_sha256=canonical_sha256(json_payload),
    )


def _complete_authseal_inputs(
    live: _LiveInputs,
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> tuple[object, tuple[EvidenceSealDecisionProjection, ...]]:
    candidate_run = evidence.runs[0]
    candidate = build_evidence_seal_lineage_binding(
        exact_model_id=candidate_run.candidate_model_id,
        root_lineage=candidate_run.candidate_root_lineage,
        role=EvidenceSealLineageRole.CANDIDATE,
    )
    judges = tuple(
        build_evidence_seal_lineage_binding(
            exact_model_id=item.judge_model_id,
            root_lineage=item.judge_root_lineage,
            role=EvidenceSealLineageRole.JUDGE,
        )
        for item in sorted(
            evidence.runs,
            key=lambda item: (item.judge_model_id, item.judge_root_lineage),
        )
    )
    collision = build_evidence_seal_collision_map(candidate=candidate, judges=judges)
    judge_by_identity = {
        (item.exact_model_id, item.root_lineage): item for item in collision.judges
    }
    ground = _ground_truth_projection(live)
    decisions = tuple(
        evidence_seal_module._build_evidence_seal_decision_projection(
            suite=live.suite,
            report=custody.candidate_report,
            candidate=candidate,
            runner=judge_by_identity[(run.judge_model_id, run.judge_root_lineage)],
            run_kind=EvidenceSealRunKind(run.run_kind.value),
            ground_truth_projection=ground,
            authenticated_rootless_candidate=True,
        )
        for custody, run in zip(live.runs, evidence.runs, strict=True)
    )
    return collision, decisions


def _rejected_bundle() -> AuthenticatedRunnerDurableEvidenceBundle:
    live = _live_inputs()
    evidence = _runner_evidence(live)
    return build_authenticated_runner_durable_bundle(
        runner_evidence=evidence,
        candidate_reports=tuple(item.candidate_report for item in live.runs),
        prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
        adjudication_reports=tuple(item.adjudication_report for item in live.runs),
        authseal_collision_map=None,
        authseal_decision_projections=(),
        authseal_rejection_kind="EvidenceSealAuthorityError",
    )


def _candidate_report_with_sensitive_routing(
    report: ModelBenchmarkReport,
) -> ModelBenchmarkReport:
    result = report.results[0]
    case = result.cases[0]
    assert case.usage_record is not None
    usage_payload = case.usage_record.model_dump(mode="python")
    routing = dict(usage_payload["routing"])
    routing["access_token"] = "synthetic-redteam-marker"
    usage_payload["routing"] = routing
    usage = UsageRecord.model_validate(usage_payload)
    replacement_case = case.model_copy(update={"usage_record": usage})
    replacement_result = result.model_copy(update={"cases": [replacement_case, *result.cases[1:]]})
    provisional = report.model_copy(
        update={"results": [replacement_result], "report_sha256": "0" * 64}
    )
    payload = provisional.model_dump(mode="json", exclude={"report_sha256"})
    return ModelBenchmarkReport.model_validate_json(
        json.dumps(
            {**payload, "report_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def _single_case_runner_evidence(
    evidence: AuthenticatedCrossLineageRunnerEvidence,
) -> AuthenticatedCrossLineageRunnerEvidence:
    case_id = evidence.case_ids[0]
    runs = tuple(
        run.model_copy(
            update={
                "candidate_cases": run.candidate_cases[:1],
                "judge_cases": run.judge_cases[:1],
            }
        )
        for run in evidence.runs
    )
    retained_request_ids = {
        request_id
        for run in runs
        for cases in (run.candidate_cases, run.judge_cases)
        for case in cases
        for request_id in case.attempt_request_ids
    }
    entries = tuple(
        item for item in evidence.ledger_interval.entries if item.request_id in retained_request_ids
    )
    interval_cost = sum((Decimal(item.actual_cost_usd) for item in entries), start=Decimal(0))
    interval_cost_text = format(interval_cost, "f").rstrip("0").rstrip(".") or "0"
    ledger = evidence.ledger_interval.model_copy(
        update={
            "interval_spent_usd": interval_cost_text,
            "final_spent_usd": interval_cost_text,
            "entries": entries,
        }
    )
    payload = evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    payload.update(
        {
            "case_ids": [case_id],
            "runs": [item.model_dump(mode="json") for item in runs],
            "ledger_interval": ledger.model_dump(mode="json"),
        }
    )
    return AuthenticatedCrossLineageRunnerEvidence.model_validate_json(
        json.dumps(
            {**payload, "evidence_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def test_rejected_bundle_round_trips_canonically_without_authority() -> None:
    bundle = _rejected_bundle()
    raw = authenticated_runner_durable_bundle_bytes(bundle)
    replay = revalidate_authenticated_runner_durable_bundle(raw)

    assert replay == bundle
    assert isinstance(replay.authseal_comparison, AuthenticatedRunnerAuthsealRejected)
    assert tuple(item.run_kind for item in replay.runs) == (
        CrossLineageAdjudicationRunKind.PRIMARY,
        CrossLineageAdjudicationRunKind.REPLAY,
    )
    assert tuple(item.prepared_run for item in replay.runs) == tuple(
        item.prepared_adjudication for item in _live_inputs().runs
    )
    assert tuple(item.adjudication_report for item in replay.runs) == tuple(
        item.adjudication_report for item in _live_inputs().runs
    )
    assert replay.runner_evidence.ledger_interval == replay.closed_ledger_evidence
    assert replay.serialized_authority is False
    assert replay.runner_custody_authorized is False
    assert replay.authority_issuance_authorized is False
    assert replay.release_authorized is False


def test_complete_bundle_exactly_joins_authseal_inputs() -> None:
    live = _live_inputs()
    evidence = _runner_evidence(live)
    collision, decisions = _complete_authseal_inputs(live, evidence)
    bundle = build_authenticated_runner_durable_bundle(
        runner_evidence=evidence,
        candidate_reports=tuple(item.candidate_report for item in live.runs),
        prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
        adjudication_reports=tuple(item.adjudication_report for item in live.runs),
        authseal_collision_map=collision,
        authseal_decision_projections=decisions,
        authseal_rejection_kind=None,
    )

    comparison = bundle.authseal_comparison
    assert isinstance(comparison, AuthenticatedRunnerAuthsealComplete)
    assert tuple(item.run_kind for item in comparison.decision_projections) == (
        EvidenceSealRunKind.PRIMARY,
        EvidenceSealRunKind.REPLAY,
    )
    assert tuple(item.benchmark_report_sha256 for item in comparison.decision_projections) == (
        tuple(item.candidate_report_sha256 for item in evidence.runs)
    )
    assert (
        revalidate_authenticated_runner_durable_bundle(
            authenticated_runner_durable_bundle_bytes(bundle)
        )
        == bundle
    )


def test_bundle_rejects_order_hash_ledger_and_noncanonical_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = _rejected_bundle()
    payload = bundle.model_dump(mode="json")

    reversed_runs = dict(payload)
    reversed_runs["runs"] = list(reversed(payload["runs"]))
    reversed_runs["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in reversed_runs.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="PRIMARY then REPLAY"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(reversed_runs, sort_keys=True, separators=(",", ":"))
        )

    wrong_report = json.loads(json.dumps(payload))
    wrong_report["runs"][0]["runner_run_evidence_sha256"] = "f" * 64
    wrong_report["runs"][0]["run_bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_report["runs"][0].items() if key != "run_bundle_sha256"}
    )
    wrong_report["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_report.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="runner run hashes"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(wrong_report, sort_keys=True, separators=(",", ":"))
        )

    wrong_ledger = json.loads(json.dumps(payload))
    wrong_ledger["closed_ledger_evidence"]["entries"][0]["request_id"] = "unused-request"
    wrong_ledger["closed_ledger_evidence"]["entries"] = sorted(
        wrong_ledger["closed_ledger_evidence"]["entries"],
        key=lambda item: item["request_id"],
    )
    wrong_ledger["closed_ledger_evidence_sha256"] = canonical_sha256(
        wrong_ledger["closed_ledger_evidence"]
    )
    wrong_ledger["runner_evidence"]["ledger_interval"] = wrong_ledger["closed_ledger_evidence"]
    wrong_ledger["runner_evidence"]["evidence_sha256"] = canonical_sha256(
        {
            key: value
            for key, value in wrong_ledger["runner_evidence"].items()
            if key != "evidence_sha256"
        }
    )
    wrong_ledger["runner_evidence_sha256"] = wrong_ledger["runner_evidence"]["evidence_sha256"]
    wrong_ledger["bundle_sha256"] = canonical_sha256(
        {key: value for key, value in wrong_ledger.items() if key != "bundle_sha256"}
    )
    with pytest.raises(ValidationError, match="closed ledger differs"):
        AuthenticatedRunnerDurableEvidenceBundle.model_validate_json(
            json.dumps(wrong_ledger, sort_keys=True, separators=(",", ":"))
        )

    raw = authenticated_runner_durable_bundle_bytes(bundle)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="canonically serialized"):
        revalidate_authenticated_runner_durable_bundle(b" \n" + raw)
    with monkeypatch.context() as context:
        context.setattr(durable_bundle_module, "MAX_JSON_ARTIFACT_BYTES", 100)
        with pytest.raises(AuthenticatedRunnerDurableBundleError, match="over the byte ceiling"):
            revalidate_authenticated_runner_durable_bundle(b"x" * 101)


def test_bundle_rejects_sensitive_routing_even_when_report_is_resealed() -> None:
    live = _live_inputs()
    original = live.runs[0].adjudication_report
    first = original.cases[0]
    usage_payload = first.usage_record.model_dump(mode="python")
    usage_payload["routing"] = {**usage_payload["routing"], "private_source": "forbidden"}
    usage = UsageRecord.model_validate(usage_payload)
    replacement = build_cross_lineage_adjudication_case_result(
        request=first.request,
        response=first.response,
        usage_record=usage,
        generation_evidence=first.generation_evidence,
    )
    cases: tuple[CrossLineageAdjudicationCaseResult, ...] = (
        replacement,
        *original.cases[1:],
    )
    resealed = build_cross_lineage_adjudication_report(
        prepared=live.runs[0].prepared_adjudication,
        results=cases,
    )
    reports = (resealed, live.runs[1].adjudication_report)
    evidence = _runner_evidence(live, reports=reports)

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            runner_evidence=evidence,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=reports,
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_access_token_in_candidate_routing() -> None:
    live = _live_inputs()
    evidence = _runner_evidence(live)
    candidate_reports = (
        _candidate_report_with_sensitive_routing(live.runs[0].candidate_report),
        live.runs[1].candidate_report,
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            runner_evidence=evidence,
            candidate_reports=candidate_reports,
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_nested_access_token_in_judge_routing() -> None:
    live = _live_inputs()
    original = live.runs[0].adjudication_report
    first = original.cases[0]
    usage_payload = first.usage_record.model_dump(mode="python")
    routing = dict(usage_payload["routing"])
    identity_binding = dict(routing["identity_binding"])
    identity_binding["access_token"] = "synthetic-redteam-marker"
    routing["identity_binding"] = identity_binding
    usage_payload["routing"] = routing
    usage = UsageRecord.model_validate(usage_payload)
    replacement = build_cross_lineage_adjudication_case_result(
        request=first.request,
        response=first.response,
        usage_record=usage,
        generation_evidence=first.generation_evidence,
    )
    resealed = build_cross_lineage_adjudication_report(
        prepared=live.runs[0].prepared_adjudication,
        results=(replacement, *original.cases[1:]),
    )
    reports = (resealed, live.runs[1].adjudication_report)
    evidence = _runner_evidence(live, reports=reports)

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="sensitive field name"):
        build_authenticated_runner_durable_bundle(
            runner_evidence=evidence,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=reports,
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_bundle_rejects_runtime_shape_below_frozen_release_protocol() -> None:
    live = _live_inputs()
    evidence = _single_case_runner_evidence(_runner_evidence(live))
    assert len(evidence.case_ids) == 1
    assert len(evidence.ledger_interval.entries) == 4

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="two-run 24-case protocol"):
        build_authenticated_runner_durable_bundle(
            runner_evidence=evidence,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=None,
            authseal_decision_projections=(),
            authseal_rejection_kind="EvidenceSealAuthorityError",
        )


def test_complete_bundle_rejects_resealed_authseal_scoring_tamper() -> None:
    live = _live_inputs()
    evidence = _runner_evidence(live)
    collision, decisions = _complete_authseal_inputs(live, evidence)
    original = decisions[0]
    payload = original.model_dump(mode="json", exclude={"projection_sha256"})
    payload["overall_score_micros"] = 0
    payload["deterministic_output_sha256"] = evidence_seal_module._decision_output_sha256(
        candidate=original.candidate,
        corpus_sha256=original.benchmark_corpus_sha256,
        ground_truth_sha256=original.benchmark_ground_truth_sha256,
        case_outcome_sha256s=original.case_outcome_sha256s,
        case_dimension_outcome_set_sha256=original.case_dimension_outcome_set_sha256,
        dimension_score_sha256s=original.dimension_score_sha256s,
        overall_score_micros=0,
        execution_evidence=original.execution_evidence,
    )
    tampered = EvidenceSealDecisionProjection.model_validate_json(
        json.dumps(
            {**payload, "projection_sha256": canonical_sha256(payload)},
            sort_keys=True,
            separators=(",", ":"),
        )
    )

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="bundle is invalid"):
        build_authenticated_runner_durable_bundle(
            runner_evidence=evidence,
            candidate_reports=tuple(item.candidate_report for item in live.runs),
            prepared_runs=tuple(item.prepared_adjudication for item in live.runs),
            adjudication_reports=tuple(item.adjudication_report for item in live.runs),
            authseal_collision_map=collision,
            authseal_decision_projections=(tampered, decisions[1]),
            authseal_rejection_kind=None,
        )


def test_authseal_rejection_is_bounded_type_only() -> None:
    live = _live_inputs()
    evidence = _runner_evidence(live)
    common = {
        "runner_evidence": evidence,
        "candidate_reports": tuple(item.candidate_report for item in live.runs),
        "prepared_runs": tuple(item.prepared_adjudication for item in live.runs),
        "adjudication_reports": tuple(item.adjudication_report for item in live.runs),
        "authseal_collision_map": None,
        "authseal_decision_projections": (),
    }
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="exception type"):
        build_authenticated_runner_durable_bundle(
            **common,
            authseal_rejection_kind="ValueError: provider said secret text",
        )
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="collision map"):
        build_authenticated_runner_durable_bundle(
            **common,
            authseal_rejection_kind=None,
        )


def test_durable_bundle_release_schema_is_closed_bounded_and_non_authorizing() -> None:
    filename = "authenticated_runner_durable_evidence_bundle.schema.json"
    assert MODELS[filename] is AuthenticatedRunnerDurableEvidenceBundle
    schema = json.loads(rendered_schema(filename, MODELS[filename]))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["runs"]["minItems"] == 2
    assert schema["properties"]["runs"]["maxItems"] == 2
    assert (
        schema["properties"]["runs"]["prefixItems"][0]["allOf"][1]["properties"]["run_kind"][
            "const"
        ]
        == "PRIMARY"
    )
    assert (
        schema["properties"]["runs"]["prefixItems"][1]["allOf"][1]["properties"]["run_kind"][
            "const"
        ]
        == "REPLAY"
    )
    definitions = schema["$defs"]
    prepared = definitions["CrossLineageAdjudicationPreparedRun"]["properties"]
    report = definitions["CrossLineageAdjudicationReport"]["properties"]
    candidate_report = definitions["ModelBenchmarkReport"]["properties"]
    candidate_result = definitions["ModelBenchmarkModelResult"]["properties"]
    for inventory in (
        prepared["case_ids"],
        prepared["requests"],
        report["case_ids"],
        report["cases"],
        candidate_report["case_ids"],
        candidate_result["cases"],
    ):
        assert inventory["minItems"] == inventory["maxItems"] == 24
        assert inventory["uniqueItems"] is True
    assert candidate_report["results"]["minItems"] == 1
    assert candidate_report["results"]["maxItems"] == 1
    assert candidate_report["results"]["uniqueItems"] is True
    runner_run = definitions["AuthenticatedCrossLineageRunnerRunEvidence"]["properties"]
    for field_name in ("candidate_cases", "judge_cases"):
        assert runner_run[field_name]["minItems"] == 24
        assert runner_run[field_name]["maxItems"] == 24
        assert runner_run[field_name]["uniqueItems"] is True
    ledger_entries = definitions["AuthenticatedCrossLineageLedgerIntervalEvidence"]["properties"][
        "entries"
    ]
    assert ledger_entries["minItems"] == 96
    assert ledger_entries["maxItems"] == 3_072
    assert ledger_entries["uniqueItems"] is True
    decisions = definitions["AuthenticatedRunnerAuthsealComplete"]["properties"][
        "decision_projections"
    ]
    assert decisions["minItems"] == decisions["maxItems"] == 2
    assert decisions["uniqueItems"] is True
    assert [
        item["allOf"][1]["properties"]["run_kind"]["const"] for item in decisions["prefixItems"]
    ] == ["PRIMARY", "REPLAY"]
    routing = definitions["UsageRecord"]["properties"]["routing"]
    assert routing["maxProperties"] == 256
    assert routing["additionalProperties"] == {
        "$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"
    }
    allowed_routing_keys = set(routing["propertyNames"]["allOf"][-1]["enum"])
    assert "access_token" not in allowed_routing_keys
    bundle_payload = json.loads(authenticated_runner_durable_bundle_bytes(_rejected_bundle()))
    assert len(bundle_payload["runs"]) == schema["properties"]["runs"]["minItems"]
    assert len(bundle_payload["runner_evidence"]["case_ids"]) == 24
    assert len(bundle_payload["closed_ledger_evidence"]["entries"]) >= ledger_entries["minItems"]
    for retained_run in bundle_payload["runs"]:
        assert len(retained_run["candidate_report"]["case_ids"]) == 24
        assert len(retained_run["candidate_report"]["results"]) == 1
        assert len(retained_run["candidate_report"]["results"][0]["cases"]) == 24
        assert len(retained_run["prepared_run"]["case_ids"]) == 24
        assert len(retained_run["prepared_run"]["requests"]) == 24
        assert len(retained_run["adjudication_report"]["case_ids"]) == 24
        assert len(retained_run["adjudication_report"]["cases"]) == 24
        routing_values = (
            case["usage_record"]["routing"]
            for case in retained_run["candidate_report"]["results"][0]["cases"]
        )
        assert all(set(value) <= allowed_routing_keys for value in routing_values)
    assert (
        schema["$defs"]["AuthenticatedRunnerAuthsealRejected"]["properties"]["rejection_kind"][
            "pattern"
        ]
        == r"^[A-Za-z][A-Za-z0-9_]{0,99}$"
    )
    names = set()

    def collect(value: object) -> None:
        if isinstance(value, dict):
            properties = value.get("properties")
            if isinstance(properties, dict):
                names.update(properties)
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    collect(schema)
    assert {
        "api_key",
        "credential",
        "execution",
        "operator_secrets",
        "private_source",
        "runner_capability",
        "runner_custody",
        "secret",
    }.isdisjoint(names)
    assert {
        name for name, field in schema["properties"].items() if field.get("const") is False
    } == {
        "serialized_authority",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_custody_authorized",
        "authority_issuance_authorized",
        "benchmark_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
    }


def _write_private_bundle(path: Path, raw: bytes) -> None:
    path.parent.mkdir(mode=0o700)
    path.parent.chmod(0o700)
    path.write_bytes(raw)
    path.chmod(0o600)


def test_private_file_loader_replays_canonical_bundle(tmp_path: Path) -> None:
    bundle = _rejected_bundle()
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, authenticated_runner_durable_bundle_bytes(bundle))

    loaded = load_authenticated_runner_durable_bundle(path)

    assert loaded == bundle
    assert loaded.serialized_authority is False
    assert loaded.runner_custody_authorized is False


@pytest.mark.parametrize(
    "raw",
    (
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b'{"nonfinite":NaN}',
        b" {}",
    ),
)
def test_private_file_loader_rejects_duplicate_nonfinite_and_noncanonical_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, raw)

    with pytest.raises(AuthenticatedRunnerDurableBundleError):
        load_authenticated_runner_durable_bundle(path)


def test_private_file_loader_rejects_unsafe_mode_links_and_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = authenticated_runner_durable_bundle_bytes(_rejected_bundle())

    public_path = tmp_path / "public" / "runner-evidence.json"
    _write_private_bundle(public_path, raw)
    public_path.chmod(0o644)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(public_path)

    shared_path = tmp_path / "shared" / "runner-evidence.json"
    _write_private_bundle(shared_path, raw)
    shared_link = shared_path.parent / "second-name.json"
    shared_link.hardlink_to(shared_path)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(shared_path)

    source_path = tmp_path / "source" / "runner-evidence.json"
    _write_private_bundle(source_path, raw)
    linked_parent = tmp_path / "linked"
    linked_parent.mkdir(mode=0o700)
    linked_parent.chmod(0o700)
    symlink_path = linked_parent / "runner-evidence.json"
    symlink_path.symlink_to(source_path)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(symlink_path)

    bounded_path = tmp_path / "bounded" / "runner-evidence.json"
    _write_private_bundle(bounded_path, raw)
    monkeypatch.setattr(durable_bundle_module, "MAX_JSON_ARTIFACT_BYTES", 64)
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="owned, private"):
        load_authenticated_runner_durable_bundle(bounded_path)


def test_private_file_loader_rejects_path_replacement_during_observation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = authenticated_runner_durable_bundle_bytes(_rejected_bundle())
    path = tmp_path / "private" / "runner-evidence.json"
    _write_private_bundle(path, raw)
    real_read = durable_bundle_module.read_json_evidence

    def replace_after_read(
        *,
        evidence_root: Path,
        relative_path: str | Path,
        max_bytes: int,
    ) -> JsonEvidenceObservation:
        observed = real_read(
            evidence_root=evidence_root,
            relative_path=relative_path,
            max_bytes=max_bytes,
        )
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)
        return observed

    monkeypatch.setattr(durable_bundle_module, "read_json_evidence", replace_after_read)

    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="changed during observation"):
        load_authenticated_runner_durable_bundle(path)


def test_private_file_loader_requires_absolute_path(tmp_path: Path) -> None:
    del tmp_path
    with pytest.raises(AuthenticatedRunnerDurableBundleError, match="absolute private file"):
        load_authenticated_runner_durable_bundle(Path("runner-evidence.json"))
