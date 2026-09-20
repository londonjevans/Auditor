"""Actual local custody/accounting handoffs; every request is synthetic and mock-only."""

import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from types import SimpleNamespace

import httpx
import pytest

from mmaudit import development_cli
from mmaudit.models import development_transport as transport
from mmaudit.models.development_audit import development_ledger_request_id
from mmaudit.models.development_corpus_judgment import prepare_development_corpus_judgment
from mmaudit.models.development_corpus_resume import prepare_development_corpus_resume
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_budget import DevelopmentBudgetSession
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from mmaudit.orchestration.development_corpus_repeats import run_development_corpus_repeats
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import manifest_judgment_payload
from tests.development_corpus_repeats_support import repeat_payload
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.development_source_custody_support import candidate_case, custody_metadata, loaded_case
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    retained,
)
from tests.unit.test_development_source_custody import preparations


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("source custody attempted real network, subprocess or secret loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


async def candidate_run(tmp_path, *, partial=False, claims=1):
    loaded = loaded_case(tmp_path)
    prepared = candidate_case(loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []

    def handler(request):
        calls.append(request)
        assert request.content == prepared.shards[len(calls) - 1].request_content
        payload = corpus_payload(len(calls), count=claims)
        if partial and len(calls) == 2:
            payload["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=payload)

    observation = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "original",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert len(calls) == (2 if partial else 6)
    assert observation.status == ("INCOMPLETE" if partial else "OBSERVED_ALL_SHARDS")
    return SimpleNamespace(
        loaded=loaded, prepared=prepared, ledger=ledger, secrets=secrets, original=observation
    )


async def direct_case(tmp_path, kind):
    if kind == "judgment":
        case = await candidate_run(tmp_path)
        prepared = prepare_development_corpus_judgment(
            candidate=case.original,
            policy=case.prepared.plan.policy,
            endpoint_snapshot=custody_metadata(model_id="synthetic/development-reviewer"),
            source_files=case.loaded.material.source_files,
            run_id="synthetic-direct-review",
            source_custody=case.loaded,
        ).shards[0]
        call = transport.review_development_corpus_judgment_shard
        payload = manifest_judgment_payload(1, filename=prepared.source_filename)
    else:
        loaded = loaded_case(tmp_path)
        candidate = candidate_case(loaded)
        case = SimpleNamespace(
            loaded=loaded,
            ledger=AtomicCostLedger.initialize(
                tmp_path / "ledger.json", cap_usd=candidate.plan.policy.total_budget_usd
            ),
            secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
        )
        prepared, call, payload = (
            candidate.shards[0],
            transport.review_development_corpus_shard,
            corpus_payload(1),
        )
    return case, prepared, call, payload


def additional_entry(before, after, prepared):
    """Ledger rows are canonically request-id sorted, not insertion ordered."""

    old = {entry.request_id: entry for entry in before.entries}
    current = {entry.request_id: entry for entry in after.entries}
    selected = development_ledger_request_id(prepared.estimate.request_id)
    assert selected not in old and current.keys() == old.keys() | {selected}
    assert {key: value for key, value in current.items() if key != selected} == old
    return current[selected]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["candidate", "judgment"])
@pytest.mark.parametrize("change", ["strip", "add-source", "replace-source"])
async def test_direct_shard_api_cannot_bypass_actual_root_before_any_new_reservation(
    tmp_path, kind, change
):
    case, prepared, call, payload = await direct_case(tmp_path, kind)
    before = case.ledger.path.read_bytes()
    if change == "strip":
        prepared = replace(prepared, source_custody=None)
    elif change == "add-source":
        (case.loaded.corpus_root / "Added.sol").write_bytes(prepared.source_content)
    else:
        source = case.loaded.corpus_root / prepared.source_filename
        clone = source.with_suffix(".replacement")
        clone.write_bytes(source.read_bytes())
        clone.replace(source)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=payload)

    with pytest.raises(ValueError):
        await call(
            prepared=prepared,
            ledger=case.ledger,
            operator_secrets=case.secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert calls == [] and case.ledger.path.read_bytes() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["candidate", "judgment"])
async def test_drift_after_reservation_releases_only_the_undispatched_hold(
    tmp_path, monkeypatch, kind
):
    case, prepared, call, payload = await direct_case(tmp_path, kind)
    before = case.ledger.snapshot()
    reserve = DevelopmentBudgetSession.reserve

    def changed_after_reserve(self, **kwargs):
        reserved = reserve(self, **kwargs)
        (case.loaded.corpus_root / "Added.sol").write_bytes(prepared.source_content)
        return reserved

    monkeypatch.setattr(DevelopmentBudgetSession, "reserve", changed_after_reserve)
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json=payload)

    with pytest.raises(transport.DevelopmentTransportError, match="pre-dispatch"):
        await call(
            prepared=prepared,
            ledger=case.ledger,
            operator_secrets=case.secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    after = case.ledger.snapshot()
    assert not calls and after.spent_usd == before.spent_usd
    assert additional_entry(before, after, prepared).status is CostEntryStatus.RELEASED


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["candidate", "judgment"])
@pytest.mark.parametrize("known_cost", [True, False])
async def test_drift_during_dispatched_request_retains_every_known_or_unknown_charge(
    tmp_path, kind, known_cost
):
    case, prepared, call, payload = await direct_case(tmp_path, kind)
    before = case.ledger.snapshot()
    calls = []

    def handler(request):
        calls.append(request)
        (case.loaded.corpus_root / "Added.sol").write_bytes(prepared.source_content)
        return (
            httpx.Response(200, json=payload)
            if known_cost
            else httpx.Response(429, json={"error": "synthetic refusal"})
        )

    with pytest.raises(transport.DevelopmentTransportError, match="custody"):
        await call(
            prepared=prepared,
            ledger=case.ledger,
            operator_secrets=case.secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    after = case.ledger.snapshot()
    entry = additional_entry(before, after, prepared)
    assert len(calls) == 1
    assert entry.status is (
        CostEntryStatus.RECONCILED if known_cost else CostEntryStatus.UNCERTAIN_ACCOUNTED
    )
    assert entry.actual_cost_usd == (Decimal("0.01") if known_cost else None)
    assert after.spent_usd == before.spent_usd + (
        Decimal("0.01") if known_cost else entry.reserved_usd
    )
    # A later call on the same stale handle cannot hide the charge or dispatch again.
    with pytest.raises(ValueError):
        await call(
            prepared=prepared,
            ledger=case.ledger,
            operator_secrets=case.secrets,
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )
    assert len(calls) == 1 and case.ledger.snapshot() == after


@pytest.mark.asyncio
@pytest.mark.parametrize("role", [0, 2])
async def test_last_shard_drift_cannot_become_complete_candidate_or_ensemble(tmp_path, role):
    loaded = loaded_case(tmp_path)
    original = candidate_case(loaded)
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=original.plan.policy,
        source_custody=loaded,
        candidate_metadata=custody_metadata(model_id=ENSEMBLE_MODELS[0]),
        reviewer_metadata=tuple(custody_metadata(model_id=m) for m in ENSEMBLE_MODELS[1:]),
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False)

    def changed_last(selected_role, ordinal, _request):
        # Paired controls have three non-empty candidate claims for each reviewer.
        last = 6 if role == 0 else 3
        if selected_role == role and ordinal == last:
            (loaded.corpus_root / "Added.sol").write_bytes(loaded.material.source_files[0][1])

    result = await execute(case, custom=changed_last)
    assert result == retained(case) and result.status == "INCOMPLETE"
    assert case.counts == ([6, 0, 0] if role == 0 else [6, 3, 3])
    assert result.total_accounted_cost_usd == Decimal("0.01") * sum(case.counts)
    assert not result.audit_complete and not result.qualification_eligible
    if role == 0:
        assert result.candidate.status == "INCOMPLETE"
    else:
        assert result.judgments[-1].status == "INCOMPLETE"


@pytest.mark.asyncio
async def test_tree_backed_repeats_execute_every_predeclared_trial_with_custody(tmp_path):
    loaded = loaded_case(tmp_path)
    prepared = preparations(loaded)["repeats"](loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.trials[0].policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = []

    def handler(request):
        calls.append(request)
        trial, shard = divmod(len(calls) - 1, 6)
        assert request.content == prepared.trials[trial].shards[shard].request_content
        assert prepared.trials[trial].shards[shard].source_custody == loaded
        return httpx.Response(200, json=repeat_payload(len(calls)))

    result = await run_development_corpus_repeats(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "repeats",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "COMPLETE" and len(calls) == 12
    assert result.reported_actual_cost_usd == Decimal("0.12")
    assert str(tmp_path) not in result.model_dump_json()


@pytest.mark.asyncio
async def test_actual_tree_candidate_can_resume_without_replacing_original_history(tmp_path):
    case = await candidate_run(tmp_path, partial=True)
    prior = (tmp_path / "original/result.json").read_bytes()
    inputs = read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "original/result.json",
        material_file=tmp_path / "original/sources.json",
    )
    prepared = prepare_development_corpus_resume(
        history=inputs.history,
        endpoint_snapshot=case.prepared.shards[0].endpoint_snapshot,
        run_id="synthetic-root-resume",
        source_custody=case.loaded,
    )
    calls = []

    def handler(request):
        shard = next(s for s in prepared.candidate.shards if s.request_content == request.content)
        assert shard.shard_id in prepared.plan.selected_shard_ids and shard.shard_id != "file-0001"
        calls.append(shard.shard_id)
        payload = corpus_payload(int(shard.shard_id[-4:]))
        payload["id"] = "gen-synthetic-root-resume-" + shard.shard_id
        return httpx.Response(200, json=payload)

    result = await run_development_corpus_resume(
        prepared=prepared,
        ledger=case.ledger,
        operator_secrets=case.secrets,
        inputs=inputs,
        output_dir=tmp_path / "resume",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.summary.status == "OBSERVED_ALL_SOURCES_ACROSS_RECORDED_ATTEMPTS"
    assert calls == list(prepared.plan.selected_shard_ids)
    assert (tmp_path / "original/result.json").read_bytes() == prior
    assert case.ledger.snapshot().spent_usd == Decimal("0.07")
    assert str(tmp_path) not in result.model_dump_json()


@pytest.mark.asyncio
async def test_tree_backed_zero_claim_review_still_requires_its_original_root(tmp_path):
    case = await candidate_run(tmp_path, claims=0)
    prepared = prepare_development_corpus_judgment(
        candidate=case.original,
        policy=case.prepared.plan.policy,
        endpoint_snapshot=custody_metadata(model_id="synthetic/development-reviewer"),
        source_files=case.loaded.material.source_files,
        run_id="synthetic-empty-review",
        source_custody=case.loaded,
    )
    before = case.ledger.path.read_bytes()
    (case.loaded.corpus_root / "Added.sol").write_bytes(case.loaded.material.source_files[0][1])
    with pytest.raises(ValueError):
        await run_development_corpus_judgment(
            prepared=prepared,
            ledger=case.ledger,
            operator_secrets=case.secrets,
            output_dir=tmp_path / "empty-review",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _r: pytest.fail("no claims")),
        )
    assert case.ledger.path.read_bytes() == before and not (tmp_path / "empty-review").exists()
