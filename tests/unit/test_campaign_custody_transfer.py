"""Move-only campaign custody using original synthetic local issuers and verifiers."""

import copy
import os
import pickle
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

import mmaudit.benchmark.model_portfolio as campaign
from tests.integration.test_campaign_transfer_custody import CampaignInputs, campaign_inputs


@pytest.fixture
def inputs(tmp_path: Path) -> Iterator[CampaignInputs]:
    value = campaign_inputs(tmp_path)
    try:
        yield value
    finally:
        try:
            campaign.revoke_trusted_candidate_benchmark_campaign_verification(value.original)
        except ValueError as error:
            assert str(error) == "trusted campaign verification is absent, mismatched, or revoked"


def test_move_invalidates_all_original_aliases_and_retains_original_verifier(
    inputs: CampaignInputs,
) -> None:
    retained = inputs.original
    successor = campaign.transfer_trusted_candidate_benchmark_campaign_verification(
        inputs.original, **inputs.arguments()
    )
    try:
        assert successor is not retained and type(successor) is type(retained)
        inputs.require(successor)
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            inputs.require(retained)
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                retained, **inputs.arguments()
            )
    finally:
        campaign.revoke_trusted_candidate_benchmark_campaign_verification(successor)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        inputs.require(successor)


@pytest.mark.parametrize("field", ("portfolio_sha256", "policy_sha256", "effective_config_sha256"))
@pytest.mark.parametrize("value", ("9" * 64, "invalid", None))
def test_changed_binding_never_consumes_original(
    inputs: CampaignInputs, field: str, value: object
) -> None:
    arguments = inputs.arguments()
    arguments[field] = value
    with pytest.raises(ValueError):
        campaign.transfer_trusted_candidate_benchmark_campaign_verification(
            inputs.original, **arguments
        )
    inputs.require(inputs.original)


@pytest.mark.parametrize(
    "kind", ("empty", "list", "duplicate", "oversize", "wrong-type", "content")
)
def test_invalid_report_set_preserves_original(inputs: CampaignInputs, kind: str) -> None:
    arguments = inputs.arguments()
    arguments["reports"] = {
        "empty": (),
        "list": list(inputs.reports),
        "duplicate": inputs.reports * 2,
        "oversize": inputs.reports * 129,
        "wrong-type": (object(),),
        "content": (inputs.reports[0].model_copy(update={"corpus_name": "altered"}),),
    }[kind]
    with pytest.raises(ValueError):
        campaign.transfer_trusted_candidate_benchmark_campaign_verification(
            inputs.original, **arguments
        )
    inputs.require(inputs.original)


@pytest.mark.parametrize("operation", (copy.copy, copy.deepcopy, pickle.dumps))
def test_successor_cannot_be_copied_or_serialized(inputs: CampaignInputs, operation: Any) -> None:
    successor = campaign.transfer_trusted_candidate_benchmark_campaign_verification(
        inputs.original, **inputs.arguments()
    )
    try:
        with pytest.raises(TypeError):
            operation(successor)
    finally:
        campaign.revoke_trusted_candidate_benchmark_campaign_verification(successor)


def test_forged_and_wrong_type_proofs_cannot_move(inputs: CampaignInputs) -> None:
    for forged in (
        object(),
        object.__new__(campaign.TrustedCandidateBenchmarkCampaignVerification),
    ):
        with pytest.raises(ValueError):
            campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                forged, **inputs.arguments()
            )
    inputs.require(inputs.original)


@pytest.mark.parametrize(
    "name",
    (
        "_move_trusted_campaign_capability",
        "_require_trusted_campaign_capability_positional",
        "_report_content_bindings",
        "canonical_sha256",
        "issue_trusted_candidate_benchmark_campaign_verification",
        "transfer_trusted_candidate_benchmark_campaign_verification",
    ),
)
def test_binding_retargeting_refuses_without_consuming_source(
    inputs: CampaignInputs, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    transfer = campaign.transfer_trusted_candidate_benchmark_campaign_verification
    with monkeypatch.context() as patch:
        patch.setattr(campaign, name, object())
        with pytest.raises(ValueError, match="not pristine"):
            transfer(inputs.original, **inputs.arguments())
    inputs.require(inputs.original)


def test_competing_moves_publish_exactly_one_successor(inputs: CampaignInputs) -> None:
    start = threading.Barrier(2)

    def move() -> object:
        start.wait(timeout=5)
        try:
            return campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                inputs.original, **inputs.arguments()
            )
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(move) for _ in range(2)]
        outcomes = [future.result(timeout=10) for future in futures]
    successors = [
        item
        for item in outcomes
        if type(item) is campaign.TrustedCandidateBenchmarkCampaignVerification
    ]
    assert len(successors) == 1 and sum(isinstance(item, ValueError) for item in outcomes) == 1
    inputs.require(successors[0])
    campaign.revoke_trusted_candidate_benchmark_campaign_verification(successors[0])


@pytest.mark.parametrize("kind", ("code", "defaults", "kwdefaults", "method"))
def test_callable_state_changes_cannot_consume_source(
    inputs: CampaignInputs, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    with monkeypatch.context() as patch:
        if kind == "code":

            def altered(_reports: object) -> tuple[()]:
                return ()

            patch.setattr(campaign._report_content_bindings, "__code__", altered.__code__)
        elif kind == "defaults":
            patch.setattr(
                campaign._require_trusted_campaign_capability_positional, "__defaults__", ()
            )
        elif kind == "kwdefaults":
            patch.setattr(campaign._require_trusted_campaign_capability, "__kwdefaults__", {})
        else:
            patch.setattr(
                campaign.TrustedCandidateBenchmarkCampaignVerification, "require_for", object()
            )
        with pytest.raises(ValueError, match="not pristine"):
            campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                inputs.original, **inputs.arguments()
            )
    inputs.require(inputs.original)


def test_string_subclass_cannot_spoof_exact_binding(inputs: CampaignInputs) -> None:
    class EqualDigest(str):
        def __eq__(self, _other: object) -> bool:
            return True

    arguments = inputs.arguments()
    arguments["policy_sha256"] = EqualDigest("9" * 64)
    with pytest.raises(ValueError, match="exact bounded"):
        campaign.transfer_trusted_candidate_benchmark_campaign_verification(
            inputs.original, **arguments
        )
    inputs.require(inputs.original)


def test_existing_separate_issuance_is_not_revoked_by_another_handle_move(
    inputs: CampaignInputs,
) -> None:
    independent = campaign.issue_trusted_candidate_benchmark_campaign_verification(
        campaign=inputs.journal, portfolio=inputs.portfolio, reports=inputs.reports
    )
    successor = campaign.transfer_trusted_candidate_benchmark_campaign_verification(
        inputs.original, **inputs.arguments()
    )
    try:
        inputs.require(independent)
        inputs.require(successor)
    finally:
        campaign.revoke_trusted_candidate_benchmark_campaign_verification(independent)
        campaign.revoke_trusted_candidate_benchmark_campaign_verification(successor)


@pytest.mark.parametrize("failure", (ValueError, RuntimeError, KeyboardInterrupt))
def test_successor_replay_failure_disposes_both_handles(
    inputs: CampaignInputs, failure: type[BaseException]
) -> None:
    code = campaign._require_trusted_campaign_capability_positional.__code__
    calls = 0
    retained: list[Any] = []

    def reject_successor(frame: Any, event: str, _argument: Any) -> Any:
        nonlocal calls
        if event == "call" and frame.f_code is code:
            calls += 1
            if calls == 2:
                retained.append(frame.f_locals["capability"])
                raise failure("synthetic successor replay failure")
        return reject_successor

    previous = sys.gettrace()
    sys.settrace(reject_successor)
    try:
        with pytest.raises(failure, match="synthetic successor replay failure"):
            campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                inputs.original, **inputs.arguments()
            )
    finally:
        sys.settrace(previous)
    assert len(retained) == 1
    for capability in (inputs.original, retained[0]):
        with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
            inputs.require(capability)


def test_revocation_during_pristine_replay_prevents_move(inputs: CampaignInputs) -> None:
    started = threading.Event()
    resume = threading.Event()
    code = campaign._report_content_bindings.__code__

    def pause(frame: Any, event: str, _argument: Any) -> Any:
        if event == "call" and frame.f_code is code:
            started.set()
            if not resume.wait(timeout=5):
                raise AssertionError("campaign move replay timed out")
        return pause

    def move() -> object:
        sys.settrace(pause)
        try:
            return campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                inputs.original, **inputs.arguments()
            )
        except ValueError as error:
            return error
        finally:
            sys.settrace(None)

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(move)
        try:
            assert started.wait(timeout=5)
            campaign.revoke_trusted_candidate_benchmark_campaign_verification(inputs.original)
        finally:
            resume.set()
        assert isinstance(future.result(timeout=10), ValueError)
    with pytest.raises(ValueError, match="absent, mismatched, or revoked"):
        inputs.require(inputs.original)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires a real POSIX child process")
def test_forked_child_cannot_move_parent_campaign_proof(inputs: CampaignInputs) -> None:
    child = os.fork()
    if child == 0:
        status = 1
        try:
            with pytest.raises(ValueError, match="not pristine"):
                campaign.transfer_trusted_candidate_benchmark_campaign_verification(
                    inputs.original, **inputs.arguments()
                )
            with pytest.raises(ValueError, match="another process"):
                campaign._move_trusted_campaign_capability(
                    inputs.original,
                    inputs.portfolio.portfolio_sha256,
                    inputs.reports,
                    inputs.journal.manifest.qualification_policy_sha256,
                    inputs.journal.manifest.effective_config_sha256,
                )
            status = 0
        finally:
            os._exit(status)
    waited, status = os.waitpid(child, 0)
    assert waited == child and os.waitstatus_to_exitcode(status) == 0
    inputs.require(inputs.original)
