"""Actual automatic source-to-plan-to-mock-run and reopened stage execution, never paid tests."""

from __future__ import annotations

import json
from decimal import Decimal

import httpx
import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.models.development_corpus_coverage import read_development_corpus_coverage
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_tree import run_development_tree_plan
from mmaudit.repository.development_tree_plan import write_development_tree_plan
from tests.development_corpus_judgment_support import manifest_judgment_payload
from tests.development_corpus_support import corpus_payload
from tests.development_ensemble_support import ENSEMBLE_MODELS
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.development_tree_support import tree_policy
from tests.integration.test_development_tree_plan_custody import (
    no_external_execution as no_external_execution,
)
from tests.integration.test_development_tree_plan_custody import (
    reopen,
    tree_plan_case,
)

pytestmark = pytest.mark.usefixtures("no_external_execution")


def execution(tmp_path, *, claims=1, policy=None):
    inputs = tree_plan_case(tmp_path, policy=policy)
    loaded = write_development_tree_plan(**inputs)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    calls = []

    def handler(request):
        assert request.method == "POST"
        body = json.loads(request.content)
        role = ENSEMBLE_MODELS.index(body["model"])
        prompt = body["messages"][1]["content"]
        path = next(
            line.removeprefix("Primary file: ")
            for line in prompt.splitlines()
            if line.startswith("Primary file: ")
        )
        primary = next(p for p in loaded.plan.primaries if p.primary_filename == path)
        assert len(request.content) <= primary.role_envelopes[role].serialized_request_bytes
        assert SYNTHETIC_CREDENTIAL.encode() not in request.content
        if role == 0:
            assert "Untrusted candidate hypotheses" not in prompt
            payload = corpus_payload(len(calls) + 1, count=claims, origin=path)
        else:
            payload = manifest_judgment_payload(
                len(calls) + 1,
                shard_id=primary.candidate.shards[0].shard_id,
                count=claims,
                filename=path,
            )
        model = ENSEMBLE_MODELS[role]
        payload["model"] = model
        payload["id"] = f"gen-synthetic-automatic-{len(calls) + 1}"
        routing = payload["openrouter_metadata"]
        routing["requested"] = model
        routing["endpoints"]["available"][0]["model"] = model
        routing["attempts"][0]["model"] = model
        calls.append((path, role, bytes(request.content)))
        return httpx.Response(200, json=payload)

    arguments = dict(
        loaded=loaded,
        ledger=ledger,
        operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    return inputs, arguments, calls


@pytest.mark.asyncio
async def test_every_primary_and_both_reviewers_run_automatically_with_whole_tree_coverage(
    tmp_path,
):
    _, arguments, calls = execution(tmp_path)
    progress = await run_development_tree_plan(**arguments)
    assert progress.status == "OBSERVED_ALL_AVAILABLE_STAGES"
    expected = [
        (p.primary_filename, r) for p in arguments["loaded"].plan.primaries for r in range(3)
    ]
    assert [(p, r) for p, r, _ in calls] == expected
    assert progress.completed_attempt_count == 15
    assert (
        progress.total_accounted_cost_usd
        == arguments["ledger"].snapshot().spent_usd
        == Decimal("0.15")
    )
    assert progress.coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert not progress.coverage.not_successfully_observed_paths
    assert (
        not progress.audit_complete
        and not progress.qualification_eligible
        and not progress.release_eligible
    )
    coverage = read_development_corpus_coverage(
        (arguments["output_dir"] / "coverage-0015.json").read_bytes()
    )
    assert coverage.summary == progress.coverage
    assert len(coverage.records) == len(coverage.partitions) == 5


@pytest.mark.asyncio
async def test_reopen_after_candidate_and_first_reviewer_never_repeats_a_paid_attempt(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    first = await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    assert first.status == "INCOMPLETE" and first.completed_attempt_count == 1
    assert len(calls) == 1 and calls[0][1] == 0
    retained = arguments["ledger"].snapshot().entries
    candidate_path = arguments["output_dir"] / "cases/case-0001/run/candidate/result.json"
    original_candidate = candidate_path.read_bytes()
    arguments["loaded"] = reopen(inputs)
    second = await run_development_tree_plan(
        **arguments, resume=True, maximum_stages_per_invocation=1
    )
    assert len(calls) == 2 and calls[1][1] == 1
    assert second.elapsed_active_seconds > first.elapsed_active_seconds
    arguments["loaded"] = reopen(inputs)
    final = await run_development_tree_plan(**arguments, resume=True)
    assert len(calls) == 15 and final.completed_attempt_count == 15
    assert final.status == "OBSERVED_ALL_AVAILABLE_STAGES"
    assert candidate_path.read_bytes() == original_candidate
    by_id = {e.request_id: e for e in arguments["ledger"].snapshot().entries}
    assert all(by_id[e.request_id] == e for e in retained)
    assert len(by_id) == 15
    again = await run_development_tree_plan(**arguments, resume=True)
    assert again == final and len(calls) == 15


@pytest.mark.asyncio
async def test_empty_candidates_skip_paid_reviews_but_never_claim_a_clean_audit(tmp_path):
    _, arguments, calls = execution(tmp_path, claims=0)
    progress = await run_development_tree_plan(**arguments)
    assert len(calls) == 5 and all(role == 0 for _, role, _ in calls)
    assert all(p.status == "NO_CANDIDATES" for p in progress.primary_statuses)
    assert progress.coverage.status == "ALL_PRIMARY_RESPONSES_OBSERVED"
    assert progress.total_accounted_cost_usd == Decimal("0.05")
    assert not progress.audit_complete


@pytest.mark.asyncio
async def test_impossible_plan_refuses_before_ledger_access_or_first_request(tmp_path, monkeypatch):
    _, arguments, calls = execution(tmp_path, policy=tree_policy(maximum_requests=1))
    monkeypatch.setattr(
        AtomicCostLedger, "snapshot", lambda *_: pytest.fail("refused plan accessed ledger")
    )
    with pytest.raises(ValueError, match="READY"):
        await run_development_tree_plan(**arguments)
    assert calls == [] and not arguments["output_dir"].exists()


@pytest.mark.asyncio
async def test_unclosed_stage_with_durable_result_cannot_be_redispatched(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    end = arguments["output_dir"] / "cases/case-0001/run/candidate-end.json"
    end.rename(tmp_path / "retained-end-receipt.json")
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="unclosed stage"):
        await run_development_tree_plan(**arguments, resume=True)
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
async def test_changed_completed_child_refuses_resume_without_a_new_charge(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    child = arguments["output_dir"] / "cases/case-0001/run/candidate/result.json"
    child.write_bytes(child.read_bytes() + b"\n")
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="child output"):
        await run_development_tree_plan(**arguments, resume=True)
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.asyncio
@pytest.mark.parametrize("liability", ["active", "uncertain", "headroom"])
async def test_existing_ledger_liabilities_refuse_before_output_or_calls(tmp_path, liability):
    _, arguments, calls = execution(tmp_path)
    ledger = arguments["ledger"]
    reservation = ledger.reserve(
        "synthetic-preexisting", Decimal("200") if liability == "headroom" else Decimal("1")
    )
    if liability != "active":
        ledger.reconcile(reservation, None if liability == "uncertain" else Decimal("200"))
    before = ledger.snapshot()
    with pytest.raises(ValueError, match=r"accounting|headroom"):
        await run_development_tree_plan(**arguments)
    assert calls == [] and ledger.snapshot() == before
    assert not arguments["output_dir"].exists()


@pytest.mark.asyncio
async def test_elapsed_stage_budget_is_not_reset_on_resume(tmp_path):
    inputs, arguments, calls = execution(tmp_path)
    await run_development_tree_plan(**arguments, maximum_stages_per_invocation=1)
    end = arguments["output_dir"] / "cases/case-0001/run/candidate-end.json"
    value = json.loads(end.read_bytes())
    value["elapsed_seconds"] = value["start"]["allotted_seconds"] + 1
    end.write_text(json.dumps(value))
    # Keep the synthetic checkpoint consistent so this still exercises the time-limit guard.
    checkpoint = arguments["output_dir"] / "progress-0001.json"
    retained = json.loads(checkpoint.read_bytes())
    retained["elapsed_active_seconds"] = value["elapsed_seconds"]
    retained["primary_statuses"][0]["elapsed_seconds"] = value["elapsed_seconds"]
    checkpoint.write_text(json.dumps(retained))
    before = arguments["ledger"].snapshot()
    arguments["loaded"] = reopen(inputs)
    with pytest.raises(ValueError, match="active-time"):
        await run_development_tree_plan(**arguments, resume=True)
    assert len(calls) == 1 and arguments["ledger"].snapshot() == before


@pytest.mark.parametrize("refused", [False, True])
def test_plan_tree_cli_retains_ready_or_explicit_refused_plan_offline(tmp_path, refused):
    inputs = tree_plan_case(tmp_path, policy=tree_policy(maximum_requests=1) if refused else None)
    args = ["development", "plan-tree"]
    for key, value in inputs.items():
        args.extend(["--" + key.replace("_", "-"), str(value)])
    result = CliRunner().invoke(app, args)
    assert result.exit_code == (ExitCode.INCOMPLETE if refused else ExitCode.SUCCESS), result.output
    assert ("REFUSED" if refused else "READY") in result.output
    assert (inputs["output_dir"] / "plan.json").is_file()


def test_run_tree_cli_requires_consent_and_reopens_real_controller_with_mock_only(
    tmp_path, monkeypatch
):
    inputs, arguments, calls = execution(tmp_path)
    command = ["development", "run-tree-plan"]
    selected = dict(
        plan_file=inputs["output_dir"] / "plan.json",
        corpus_root=inputs["corpus_root"],
        remappings_file=inputs["remappings_file"],
        policy_file=inputs["policy_file"],
        cost_ledger=tmp_path / "synthetic-ledger.json",
        secrets_env_file=tmp_path / "synthetic-no-file.env",
        output_dir=arguments["output_dir"],
    )
    for key, value in selected.items():
        command.extend(["--" + key.replace("_", "-"), str(value)])
    runner = CliRunner()
    refusal = runner.invoke(app, command)
    assert refusal.exit_code == ExitCode.CONFIGURATION and not calls

    def synthetic_secrets(*_args, **kwargs):
        assert kwargs == {"environ": {}, "required": True}
        return OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})

    async def local_controller(**kwargs):
        return await run_development_tree_plan(**kwargs, mock_transport=arguments["mock_transport"])

    monkeypatch.setattr(development_cli, "load_operator_secrets", synthetic_secrets)
    monkeypatch.setattr(development_cli, "run_development_tree_plan", local_controller)
    command += ["--accept-estimate-risk", "--allow-code-egress"]
    first = runner.invoke(app, [*command, "--maximum-stages-per-invocation", "1"])
    assert first.exit_code == ExitCode.INCOMPLETE, first.output
    assert len(calls) == 1
    second = runner.invoke(app, [*command, "--resume", "--maximum-stages-per-invocation", "2"])
    assert second.exit_code == ExitCode.INCOMPLETE, second.output
    assert [r for _, r, _ in calls] == [0, 1, 2]
    assert not selected["secrets_env_file"].exists()
