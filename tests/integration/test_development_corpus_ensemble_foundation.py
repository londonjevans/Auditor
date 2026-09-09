"""Synthetic child execution and custody checks; no production parent runner or live requests."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from jsonschema import Draft202012Validator

from mmaudit.models.development_corpus_ensemble import (
    DevelopmentCorpusEnsembleObservation,
    manifest_review_has_all_available_opinions,
)
from mmaudit.models.development_corpus_judgment import (
    DevelopmentCorpusJudgmentObservation,
    prepare_development_corpus_judgment,
)
from mmaudit.models.development_judgment import validate_development_accounting_entries
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_judgment import (
    DevelopmentCorpusJudgmentUpstream,
    require_development_corpus_upstream,
    run_development_corpus_judgment,
)
from mmaudit.release_io import create_evidence_file_binding, write_json_evidence
from mmaudit.repository.directory_custody import observe_unlinked_directory
from tests.development_corpus_ensemble_support import (
    composed_observation,
    manifest_ensemble_case,
    manifest_ensemble_payload,
)
from tests.development_corpus_judgment_support import selected_policy
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("manifest ensemble foundation attempted real network or process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def retain(root, name, value):
    return write_json_evidence(
        evidence_root=root,
        relative_path=name,
        value=value,
        require_private_parent=True,
    )


async def candidate_case(tmp_path, *, fail_at=None, known=False, carry=False, claims=1):
    prepared = manifest_ensemble_case(policy=selected_policy(carry=carry))
    root = tmp_path / "synthetic-ensemble"
    root.mkdir(mode=0o700)
    retain(root, "plan.json", prepared.plan.model_dump(mode="json"))
    ledger = AtomicCostLedger.initialize(
        tmp_path / "synthetic-ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []

    def handler(request):
        calls.append(request)
        assert request.content == prepared.candidate.shards[len(calls) - 1].request_content
        if len(calls) == fail_at:
            return httpx.Response(429, json={"usage": {"cost": 0.01}} if known else {"error": {}})
        return httpx.Response(200, json=manifest_ensemble_payload(0, len(calls), count=claims))

    candidate = await run_development_corpus(
        prepared=prepared.candidate,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=root / "candidate",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    retain(root, "sources.json", json.loads((root / "candidate/sources.json").read_bytes()))
    return SimpleNamespace(
        prepared=prepared,
        candidate=candidate,
        root=root,
        ledger=ledger,
        secrets=secrets,
        reviews=[],
        plans=[],
    )


def review_inputs(case, role):
    selected = case.prepared.plan.reviewers[role - 1]
    prepared = prepare_development_corpus_judgment(
        candidate=case.candidate,
        policy=case.prepared.plan.policy,
        endpoint_snapshot=case.prepared.reviewer_metadata[role - 1],
        source_files=case.prepared.candidate.shards[0].source_files,
        run_id=selected.run_id,
        maximum_completion_tokens=selected.maximum_completion_tokens,
    )
    retain(case.root, selected.stage_id + "-plan.json", prepared.plan.model_dump(mode="json"))
    directories = (case.root, case.root / "candidate") + (
        (case.root / "review-01",) if role == 2 else ()
    )
    upstream = DevelopmentCorpusJudgmentUpstream(
        evidence_root=case.root,
        directories=tuple(
            observe_unlinked_directory(p, label="synthetic stage") for p in directories
        ),
        files=tuple(
            create_evidence_file_binding(
                evidence_root=case.root, relative_path=p.relative_to(case.root)
            )
            for p in sorted(case.root.rglob("*.json"))
        ),
        prior_review=case.reviews[0] if role == 2 else None,
    )
    return prepared, upstream


async def execute_review(case, role, *, inputs=None, handler=None, verdict="SUPPORTED"):
    prepared, upstream = review_inputs(case, role) if inputs is None else inputs
    calls = []

    def default_handler(request):
        index = len(calls)
        calls.append(request)
        shard = prepared.shards[index]
        assert request.content == shard.request_content
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        return httpx.Response(
            200,
            json=manifest_ensemble_payload(
                role, int(shard.shard_id.split("-")[1]), count=len(shard.claims), verdict=verdict
            ),
        )

    result = await run_development_corpus_judgment(
        prepared=prepared,
        ledger=case.ledger,
        operator_secrets=case.secrets,
        output_dir=case.root / f"review-{role:02d}",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(default_handler if handler is None else handler),
        upstream=upstream,
    )
    case.plans.append(prepared.plan)
    case.reviews.append(result)
    return result


@pytest.mark.asyncio
async def test_exact_child_stages_preserve_all_claims_two_refutations_and_unique_costs(tmp_path):
    case = await candidate_case(tmp_path)
    original = {p.name: p.read_bytes() for p in (case.root / "candidate").iterdir()}
    first = await execute_review(case, 1, verdict="REFUTED")
    second = await execute_review(case, 2, verdict="REFUTED")
    result = composed_observation(case.prepared.plan, case.candidate, case.reviews)
    assert result.status == "OBSERVED_ALL_STAGES" and result.completed_stage_count == 3
    assert len(result.claims) == 3 and result.completed_judgment_count == 6
    assert result.available_claim_reviews_complete
    assert all(r.refutation_scope == "REFUTED_BY_BOTH" for r in result.claims)
    assert all(r.consensus == "REFUTED" for r in result.claims)
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd == Decimal("0.12")
    assert result.reported_actual_cost_usd == result.total_accounted_cost_usd
    assert len(result.accounting) == 12 and len(case.ledger.snapshot().entries) == 12
    assert first.plan.candidate == second.plan.candidate == result.candidate == case.candidate
    assert original == {p.name: p.read_bytes() for p in (case.root / "candidate").iterdir()}
    assert not result.audit_complete and not result.findings_validated
    assert not result.release_eligible and result.lineage_independence == "NOT_ESTABLISHED"
    assert (
        DevelopmentCorpusEnsembleObservation.model_validate_json(result.model_dump_json()) == result
    )
    schema = json.loads(
        (
            Path(__file__).parents[2]
            / "schemas/development_corpus_ensemble_observation.schema.json"
        ).read_text()
    )
    Draft202012Validator(schema).validate(result.model_dump(mode="json"))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "known,carry", [(True, False), (True, True), (False, False), (False, True)]
)
async def test_available_reviews_never_complete_partial_candidate_or_clear_unknown_costs(
    tmp_path, known, carry
):
    case = await candidate_case(tmp_path, fail_at=3, known=known, carry=carry)
    old_entries = case.ledger.snapshot().entries
    if not known and not carry:
        with pytest.raises(ValueError):
            await execute_review(case, 1)
        assert case.ledger.snapshot().entries == old_entries
        assert not (case.root / "review-01").exists()
        return
    for role in (1, 2):
        review = await execute_review(case, role, verdict="REFUTED" if role == 1 else "SUPPORTED")
        assert manifest_review_has_all_available_opinions(review)
        assert review.stop_reason == "CANDIDATE_INCOMPLETE"
    result = composed_observation(case.prepared.plan, case.candidate, case.reviews)
    assert result.status == "INCOMPLETE" and result.stop_reason == "CANDIDATE_INCOMPLETE"
    assert result.completed_stage_count == 0 and result.available_claim_reviews_complete
    assert result.completed_judgment_count == 4 and len(result.unobserved_candidate_shard_ids) == 4
    assert all(r.refutation_scope == "REFUTED_BY_ONE" for r in result.claims)
    assert all(r.consensus == "INCONCLUSIVE" for r in result.claims)
    assert all(e in case.ledger.snapshot().entries for e in old_entries)
    assert result.total_accounted_cost_usd == case.ledger.snapshot().spent_usd
    assert bool(result.uncertain_accounted_cost_usd) is (not known)


@pytest.mark.asyncio
async def test_empty_candidate_has_no_manufactured_review_completion(tmp_path):
    case = await candidate_case(tmp_path, claims=0)
    result = composed_observation(case.prepared.plan, case.candidate)
    assert result.status == "NO_CANDIDATES" and result.completed_stage_count == 1
    assert result.unobserved_stage_ids == ("review-01", "review-02")
    assert not result.claims and not result.available_claim_reviews_complete
    assert result.completed_judgment_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "claims",
        "opinions",
        "refutations",
        "status",
        "stop_reason",
        "completed",
        "judgments",
        "source_gaps",
        "stage_gaps",
        "available",
        "total_cost",
        "actual_cost",
        "uncertain",
        "active",
        "elapsed",
        "stage_elapsed",
        "accounting_order",
        "duplicate_reservation",
        "omitted_accounting",
        "unplanned_stage",
        "review_order",
        "review_plan",
        "candidate",
        "transport",
        "authority",
        "generation",
    ],
)
async def test_aggregate_rejects_forged_original_scope_opinions_and_accounting(tmp_path, field):
    case = await candidate_case(tmp_path)
    await execute_review(case, 1)
    await execute_review(case, 2)
    result = composed_observation(case.prepared.plan, case.candidate, case.reviews)
    data = result.model_dump(mode="json")
    simple = {
        "claims": ("claims", []),
        "status": ("status", "NO_CANDIDATES"),
        "stop_reason": ("stop_reason", "INTERRUPTED"),
        "completed": ("completed_stage_count", 2),
        "judgments": ("completed_judgment_count", 5),
        "source_gaps": ("unobserved_candidate_shard_ids", ["file-0006"]),
        "stage_gaps": ("unobserved_stage_ids", ["review-02"]),
        "available": ("available_claim_reviews_complete", False),
        "total_cost": ("total_accounted_cost_usd", "0.11"),
        "actual_cost": ("reported_actual_cost_usd", "0.11"),
        "uncertain": ("uncertain_accounted_cost_usd", "1"),
        "active": ("active_reserved_usd", "1"),
        "elapsed": ("elapsed_seconds", 0.0),
        "stage_elapsed": ("observed_stage_elapsed_seconds", 0.0),
        "candidate": ("candidate", None),
        "transport": ("transport", "HTTP_OBSERVATION"),
        "authority": ("findings_validated", True),
    }
    if field in simple:
        key, value = simple[field]
        data[key] = value
    elif field == "opinions":
        data["claims"][0]["opinions"][0] = "REFUTED"
    elif field == "refutations":
        data["claims"][0]["refutation_scope"] = "REFUTED_BY_ONE"
    elif field == "accounting_order":
        data["accounting"].reverse()
    elif field == "duplicate_reservation":
        data["accounting"][1]["entry"]["reservation_id"] = data["accounting"][0]["entry"][
            "reservation_id"
        ]
    elif field == "omitted_accounting":
        data["accounting"].pop()
    elif field == "unplanned_stage":
        data["judgments"].pop()
        data["judgment_plans"].pop()
    elif field == "review_order":
        data["judgments"].reverse()
    elif field == "review_plan":
        data["judgment_plans"].reverse()
    else:
        data["judgments"][1]["observations"][0]["generation_id"] = data["candidate"][
            "observations"
        ][0]["generation_id"]
    with pytest.raises(ValueError):
        DevelopmentCorpusEnsembleObservation.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "plan.json",
        "sources.json",
        "candidate/plan.json",
        "candidate/result.json",
        "candidate/sources.json",
        "candidate/file-0001.json",
        "review-01-plan.json",
        "review-01/plan.json",
        "review-01/result.json",
        "review-01/file-0001.json",
    ],
)
@pytest.mark.parametrize("during", [False, True])
async def test_upstream_file_drift_refuses_before_any_further_request(tmp_path, target, during):
    case = await candidate_case(tmp_path)
    await execute_review(case, 1)
    inputs = review_inputs(case, 2)
    original = (case.root / target).read_bytes()
    calls = []

    def mutate():
        (case.root / target).write_bytes(original + b" ")

    def handler(request):
        calls.append(request)
        mutate()
        return httpx.Response(200, json=manifest_ensemble_payload(2, 1))

    if not during:
        mutate()
    with pytest.raises(ValueError):
        await execute_review(case, 2, inputs=inputs, handler=handler)
    assert len(calls) == int(during)
    assert len(case.ledger.snapshot().entries) == 9 + int(during)
    assert not (case.root / "review-02/result.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("directory", ["candidate", "review-01"])
@pytest.mark.parametrize("link", [False, True])
async def test_upstream_directory_replacement_or_link_refuses_before_dispatch(
    tmp_path, directory, link
):
    case = await candidate_case(tmp_path)
    await execute_review(case, 1)
    prepared, upstream = review_inputs(case, 2)
    original = case.root / directory
    moved = case.root / (directory + "-preserved")
    original.rename(moved)
    if link:
        original.symlink_to(moved, target_is_directory=True)
    else:
        original.mkdir(mode=0o700)
    with pytest.raises(ValueError):
        require_development_corpus_upstream(upstream, prepared=prepared, ledger=case.ledger)
    assert len(case.ledger.snapshot().entries) == 9


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field", ["type", "root", "directories", "files", "duplicate", "missing", "prior", "prior_type"]
)
async def test_upstream_shape_cannot_omit_required_prior_evidence(tmp_path, field):
    case = await candidate_case(tmp_path)
    await execute_review(case, 1)
    prepared, upstream = review_inputs(case, 2)
    if field == "type":
        upstream = {}
    elif field == "root":
        upstream = replace(upstream, evidence_root=Path("relative"))
    elif field == "directories":
        upstream = replace(upstream, directories=upstream.directories[::-1])
    elif field == "files":
        upstream = replace(upstream, files=list(upstream.files))
    elif field == "duplicate":
        upstream = replace(upstream, files=(*upstream.files, upstream.files[0]))
    elif field == "missing":
        upstream = replace(
            upstream, files=tuple(f for f in upstream.files if f.path != "candidate/result.json")
        )
    elif field == "prior":
        upstream = replace(upstream, prior_review=None)
    else:
        upstream = replace(upstream, prior_review={})
    with pytest.raises(ValueError):
        require_development_corpus_upstream(upstream, prepared=prepared, ledger=case.ledger)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["candidate", "review-01"])
async def test_prior_accounting_cannot_be_replaced_with_another_empty_ledger(tmp_path, stage):
    case = await candidate_case(tmp_path)
    role = 1
    if stage == "review-01":
        await execute_review(case, 1)
        role = 2
    prepared, upstream = review_inputs(case, role)
    replacement = AtomicCostLedger.initialize(
        tmp_path / "different-synthetic-ledger.json", cap_usd=Decimal("20")
    )
    with pytest.raises(ValueError):
        require_development_corpus_upstream(upstream, prepared=prepared, ledger=replacement)


@pytest.mark.asyncio
@pytest.mark.parametrize("stage", ["candidate", "review-01"])
@pytest.mark.parametrize(
    "field",
    [
        "cap",
        "request_id",
        "reservation_id",
        "status",
        "reserved_usd",
        "actual_cost_usd",
        "accounted_cost_usd",
    ],
)
async def test_each_retained_stage_accounting_field_must_match_its_ledger(tmp_path, stage, field):
    case = await candidate_case(tmp_path)
    child = case.candidate if stage == "candidate" else await execute_review(case, 1)
    original = case.ledger.snapshot()
    request_id = child.accounting[0].ledger_request_id
    if field == "cap":
        changed = replace(original, cap_usd=Decimal("21"))
    else:
        value = (
            "synthetic-different-request"
            if field == "request_id"
            else "a" * 32
            if field == "reservation_id"
            else CostEntryStatus.UNCERTAIN_ACCOUNTED
            if field == "status"
            else Decimal("0.02")
        )
        changed = replace(
            original,
            entries=tuple(
                replace(e, **{field: value}) if e.request_id == request_id else e
                for e in original.entries
            ),
        )
    with pytest.raises(ValueError):
        validate_development_accounting_entries(child.accounting, changed, budget_usd=Decimal("20"))
    validate_development_accounting_entries(child.accounting, original, budget_usd=Decimal("20"))
    assert case.ledger.snapshot() == original


@pytest.mark.asyncio
@pytest.mark.parametrize("known", [False, True])
async def test_incomplete_first_review_cannot_supply_second_review_custody(tmp_path, known):
    case = await candidate_case(tmp_path)

    def handler(_request):
        return httpx.Response(500, json={"usage": {"cost": 0.01}} if known else {"error": {}})

    first = await execute_review(case, 1, handler=handler)
    assert not manifest_review_has_all_available_opinions(first)
    old_entries = case.ledger.snapshot().entries
    with pytest.raises(ValueError):
        await execute_review(case, 2)
    assert case.ledger.snapshot().entries == old_entries
    assert not (case.root / "review-02").exists()
    result = composed_observation(case.prepared.plan, case.candidate, case.reviews)
    assert result.status == "INCOMPLETE" and result.completed_stage_count == 1
    assert result.completed_judgment_count == 0 and len(result.claims) == 3


@pytest.mark.asyncio
async def test_prior_review_generation_is_automatically_excluded_without_caller_list(tmp_path):
    case = await candidate_case(tmp_path)
    first = await execute_review(case, 1)
    calls = []

    def handler(request):
        calls.append(request)
        payload = manifest_ensemble_payload(2, 1)
        payload["id"] = first.observations[0].generation_id
        return httpx.Response(200, json=payload)

    result = await execute_review(case, 2, handler=handler)
    assert len(calls) == 1 and result.completed_judgment_count == 0
    assert result.status == "INCOMPLETE" and len(result.unreviewed_claim_ids) == 3
    assert result.accounting[0].status is CostEntryStatus.RECONCILED
    aggregate = composed_observation(case.prepared.plan, case.candidate, case.reviews)
    assert aggregate.status == "INCOMPLETE" and not aggregate.available_claim_reviews_complete
    assert len(aggregate.claims) == 3 and all(r.opinions[1] is None for r in aggregate.claims)


@pytest.mark.asyncio
async def test_cancelled_review_retains_upstream_and_durable_unknown_liability(tmp_path):
    case = await candidate_case(tmp_path)
    inputs = review_inputs(case, 1)
    entered = asyncio.Event()

    async def handler(_request):
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(execute_review(case, 1, inputs=inputs, handler=handler))
    await asyncio.wait_for(entered.wait(), timeout=3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    result = DevelopmentCorpusJudgmentObservation.model_validate_json(
        (case.root / "review-01/result.json").read_bytes(), strict=True
    )
    assert result.stop_reason == "INTERRUPTED" and result.completed_judgment_count == 0
    assert result.accounting[0].status is CostEntryStatus.UNCERTAIN_ACCOUNTED
    require_development_corpus_upstream(inputs[1], prepared=inputs[0], ledger=case.ledger)
    assert len(case.ledger.snapshot().entries) == 7
