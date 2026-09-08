from __future__ import annotations

import hashlib
import os
import shutil
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from inspect import signature
from pathlib import Path

import pytest
from pydantic import ValidationError

import mmaudit.benchmark.mutations as mutation_module
from mmaudit.benchmark.mutations import (
    REQUIRED_MUTATION_KINDS,
    MutationApplicabilityBinding,
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    MutationCampaignExecutor,
    MutationKind,
    MutationKindAccounting,
    MutationKindInventoryStatus,
    MutationNonApplicabilityReason,
    MutationNonApplicabilityRecord,
    MutationPropertyOutcome,
    MutationScorecard,
    MutationScorecardEvidenceOrigin,
    MutationSuiteObservation,
    MutationSuiteTestObservation,
    MutationSuiteTestStatus,
    MutationTestOutcome,
    SourceMutationSpec,
    apply_source_mutation,
    load_mutation_scorecard,
    mutation_repository_sha256,
    revert_source_mutation,
    run_owned_mutation_campaign,
    score_mutation_outcomes,
    score_planned_mutation_campaigns,
)
from mmaudit.models.schemas import ExecutionEvidenceKind
from tests.unit.test_foundry_mutation_executor import _executor as _shared_domain_executor
from tests.unit.test_foundry_mutation_executor import (
    _repository_suite_run as _shared_domain_repository_suite_run,
)
from tests.unit.test_foundry_mutation_executor import (
    _specification as _shared_domain_specification,
)
from tests.unit.test_foundry_mutation_executor import (
    _synthetic_execution_path as _shared_domain_execution_path,
)
from tests.unit.test_foundry_mutation_executor import (
    _SyntheticIsolation as _SharedDomainSyntheticIsolation,
)
from tests.unit.test_foundry_mutation_executor import (
    _workspace_pair as _shared_domain_workspace_pair,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mutations"
SOURCE_PATH = "solidity/SafeMutationTargets.sol"
PROPERTY_ACCESS = "prop-" + ("a" * 24)
PROPERTY_REPLAY = "prop-" + ("b" * 24)
APPROVED_EXECUTOR_SHA256 = "e" * 64
APPROVED_ISOLATION_POLICY_SHA256 = "9" * 64


def _source_sha256() -> str:
    return hashlib.sha256((FIXTURE / SOURCE_PATH).read_bytes()).hexdigest()


def _specification(
    *,
    identifier: str,
    kind: MutationKind,
    line: int,
    expected_line: str,
    original_operator: str | None = None,
    replacement_operator: str | None = None,
) -> SourceMutationSpec:
    return SourceMutationSpec(
        id=identifier,
        kind=kind,
        path=SOURCE_PATH,
        line=line,
        expected_file_sha256=_source_sha256(),
        expected_line=expected_line,
        original_operator=original_operator,
        replacement_operator=replacement_operator,
    )


def _assert_apply_revert_round_trip(
    tmp_path: Path,
    specification: SourceMutationSpec,
) -> None:
    original_source = (FIXTURE / SOURCE_PATH).read_bytes()
    original_tree_sha256 = mutation_repository_sha256(FIXTURE)
    first = apply_source_mutation(
        source_repository=FIXTURE,
        workspace=tmp_path / "first",
        specification=specification,
    )
    second = apply_source_mutation(
        source_repository=FIXTURE,
        workspace=tmp_path / "second",
        specification=specification,
    )

    assert first.source_repository_sha256 == original_tree_sha256
    assert first.pristine_workspace_sha256 == original_tree_sha256
    assert first.mutated_workspace_sha256 == second.mutated_workspace_sha256
    assert first.mutated_file_sha256 == second.mutated_file_sha256
    assert first.mutated_line_sha256 == second.mutated_line_sha256
    assert first.mutated_workspace_sha256 != original_tree_sha256
    assert (FIXTURE / SOURCE_PATH).read_bytes() == original_source

    first_restoration = revert_source_mutation(first)
    second_restoration = revert_source_mutation(second)
    assert first_restoration.exact_restoration
    assert second_restoration.exact_restoration
    assert (first.workspace / SOURCE_PATH).read_bytes() == original_source
    assert (second.workspace / SOURCE_PATH).read_bytes() == original_source
    assert (FIXTURE / SOURCE_PATH).read_bytes() == original_source


def test_access_control_guard_removal_applies_and_reverts(tmp_path: Path) -> None:
    _assert_apply_revert_round_trip(
        tmp_path,
        _specification(
            identifier="mut-access-control",
            kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
            line=16,
            expected_line='        require(msg.sender == owner, "not owner");',
        ),
    )


def test_replay_state_update_removal_applies_and_reverts(tmp_path: Path) -> None:
    _assert_apply_revert_round_trip(
        tmp_path,
        _specification(
            identifier="mut-replay-state",
            kind=MutationKind.REPLAY_STATE_UPDATE_REMOVAL,
            line=22,
            expected_line="        consumedIdentifiers[identifier] = true;",
        ),
    )


def test_boundary_check_weakening_applies_and_reverts(tmp_path: Path) -> None:
    _assert_apply_revert_round_trip(
        tmp_path,
        _specification(
            identifier="mut-boundary",
            kind=MutationKind.BOUNDARY_CHECK_WEAKENING,
            line=26,
            expected_line='        require(amount < limit, "limit reached");',
            original_operator="<",
            replacement_operator="<=",
        ),
    )


def test_accounting_operator_replacement_applies_and_reverts(tmp_path: Path) -> None:
    _assert_apply_revert_round_trip(
        tmp_path,
        _specification(
            identifier="mut-accounting",
            kind=MutationKind.ACCOUNTING_OPERATOR_REPLACEMENT,
            line=31,
            expected_line="        return assets - fee;",
            original_operator="-",
            replacement_operator="+",
        ),
    )


def test_external_call_result_check_removal_applies_and_reverts(tmp_path: Path) -> None:
    _assert_apply_revert_round_trip(
        tmp_path,
        _specification(
            identifier="mut-call-result",
            kind=MutationKind.EXTERNAL_CALL_RESULT_CHECK_REMOVAL,
            line=36,
            expected_line='        require(success, "delivery failed");',
        ),
    )


def test_required_mutation_portfolio_has_one_round_trip_case_per_kind() -> None:
    assert tuple(MutationKind) == REQUIRED_MUTATION_KINDS
    assert len(REQUIRED_MUTATION_KINDS) == 5


def test_mutation_rejects_stale_source_hash_before_copy(tmp_path: Path) -> None:
    specification = _specification(
        identifier="mut-stale",
        kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        line=16,
        expected_line='        require(msg.sender == owner, "not owner");',
    ).model_copy(update={"expected_file_sha256": "0" * 64})

    with pytest.raises(ValueError, match="source hash"):
        apply_source_mutation(
            source_repository=FIXTURE,
            workspace=tmp_path / "stale",
            specification=specification,
        )

    assert not (tmp_path / "stale").exists()


def test_mutation_rejects_workspace_inside_source_repository() -> None:
    specification = _specification(
        identifier="mut-contained",
        kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        line=16,
        expected_line='        require(msg.sender == owner, "not owner");',
    )

    with pytest.raises(ValueError, match="outside the source repository"):
        apply_source_mutation(
            source_repository=FIXTURE,
            workspace=FIXTURE / "disallowed-workspace",
            specification=specification,
        )


def test_mutation_rejects_broken_destination_symlink_without_escape(tmp_path: Path) -> None:
    parent = tmp_path / "owned"
    parent.mkdir()
    escaped = tmp_path / "escaped"
    workspace = parent / "mutant"
    try:
        workspace.symlink_to(escaped, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")

    with pytest.raises(ValueError, match="must not already exist"):
        apply_source_mutation(
            source_repository=FIXTURE,
            workspace=workspace,
            specification=_specification(
                identifier="mut-link",
                kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
                line=16,
                expected_line='        require(msg.sender == owner, "not owner");',
            ),
        )

    assert workspace.is_symlink()
    assert not escaped.exists()


def test_mutation_schema_rejects_untyped_or_unsafe_targets() -> None:
    payload = _specification(
        identifier="mut-schema",
        kind=MutationKind.BOUNDARY_CHECK_WEAKENING,
        line=26,
        expected_line='        require(amount < limit, "limit reached");',
        original_operator="<",
        replacement_operator="<=",
    ).model_dump(mode="json")

    with pytest.raises(ValidationError):
        SourceMutationSpec.model_validate({**payload, "path": "../outside.sol"})
    with pytest.raises(ValidationError):
        SourceMutationSpec.model_validate(
            {
                **payload,
                "replacement_operator": ">=",
            }
        )


def _applicability_plan() -> MutationApplicabilityPlan:
    access = _specification(
        identifier="mut-access-control",
        kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        line=16,
        expected_line='        require(msg.sender == owner, "not owner");',
    )
    replay = _specification(
        identifier="mut-replay-state",
        kind=MutationKind.REPLAY_STATE_UPDATE_REMOVAL,
        line=22,
        expected_line="        consumedIdentifiers[identifier] = true;",
    )
    specifications = [access, replay]
    kind_accounting = []
    for kind in sorted(REQUIRED_MUTATION_KINDS, key=lambda item: item.value):
        candidate_ids = sorted(item.id for item in specifications if item.kind is kind)
        kind_accounting.append(
            MutationKindAccounting(
                kind=kind,
                status=(
                    MutationKindInventoryStatus.CANDIDATES_DECLARED
                    if candidate_ids
                    else MutationKindInventoryStatus.NO_CANDIDATE_DECLARED
                ),
                candidate_count=len(candidate_ids),
                candidate_ids=candidate_ids,
                limitation=(
                    None
                    if candidate_ids
                    else "No source candidate is declared for this synthetic component plan."
                ),
            )
        )
    return MutationApplicabilityPlan.sealed(
        property_corpus_hash="c" * 64,
        source_repository_sha256=mutation_repository_sha256(FIXTURE),
        approved_executor_sha256=APPROVED_EXECUTOR_SHA256,
        approved_isolation_policy_sha256=APPROVED_ISOLATION_POLICY_SHA256,
        property_repositories={
            PROPERTY_ACCESS: "synthetic",
            PROPERTY_REPLAY: "synthetic",
        },
        specifications=specifications,
        bindings=[
            MutationApplicabilityBinding(
                property_id=PROPERTY_ACCESS,
                mutation_id=access.id,
                test_ids=["testAccess"],
            ),
            MutationApplicabilityBinding(
                property_id=PROPERTY_REPLAY,
                mutation_id=replay.id,
                test_ids=["testReplay"],
            ),
        ],
        non_applicability=[
            MutationNonApplicabilityRecord(
                property_id=PROPERTY_ACCESS,
                mutation_id=replay.id,
                reason=MutationNonApplicabilityReason.PROPERTY_SCOPE_MISMATCH,
                rationale="Replay-state mutation does not challenge the access-control property.",
            ),
            MutationNonApplicabilityRecord(
                property_id=PROPERTY_REPLAY,
                mutation_id=access.id,
                reason=MutationNonApplicabilityReason.PROPERTY_SCOPE_MISMATCH,
                rationale="Access-control mutation does not challenge the replay-state property.",
            ),
        ],
        kind_accounting=kind_accounting,
    )


class _ObservedExecutor(MutationCampaignExecutor):
    def __init__(
        self,
        *,
        baseline_status: MutationSuiteTestStatus = MutationSuiteTestStatus.PASSED,
        mutant_status: MutationSuiteTestStatus = MutationSuiteTestStatus.FAILED,
        compilation_succeeded: bool = True,
        mismatched_suite: bool = False,
        isolation_attested: bool = True,
        source_binding_valid: bool = True,
        executor_binding_valid: bool = True,
        isolation_policy_binding_valid: bool = True,
        selection_binding_valid: bool = True,
        execution_evidence: ExecutionEvidenceKind = ExecutionEvidenceKind.MOCK,
    ) -> None:
        self.baseline_status = baseline_status
        self.mutant_status = mutant_status
        self.compilation_succeeded = compilation_succeeded
        self.mismatched_suite = mismatched_suite
        self.isolation_attested = isolation_attested
        self.source_binding_valid = source_binding_valid
        self.executor_binding_valid = executor_binding_valid
        self.isolation_policy_binding_valid = isolation_policy_binding_valid
        self.selection_binding_valid = selection_binding_valid
        self.execution_evidence = execution_evidence
        self.last_observation: MutationSuiteObservation | None = None

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        test_id = "testAccess" if specification.id == "mut-access-control" else "testReplay"
        mutant_test_id = f"{test_id}Different" if self.mismatched_suite else test_id
        baseline_source_sha256 = mutation_repository_sha256(baseline_workspace)
        mutant_source_sha256 = mutation_repository_sha256(mutant_workspace)
        selection_sha256 = MutationSuiteObservation.calculate_selection_sha256([test_id])
        observation = MutationSuiteObservation.sealed(
            mutation_id=specification.id,
            baseline_source_sha256=(
                baseline_source_sha256 if self.source_binding_valid else "0" * 64
            ),
            mutant_source_sha256=mutant_source_sha256,
            suite_selection_sha256=selection_sha256 if self.selection_binding_valid else "d" * 64,
            executor_sha256=(APPROVED_EXECUTOR_SHA256 if self.executor_binding_valid else "2" * 64),
            isolation_policy_sha256=(
                APPROVED_ISOLATION_POLICY_SHA256
                if self.isolation_policy_binding_valid
                else "3" * 64
            ),
            baseline_execution_evidence=self.execution_evidence,
            mutant_execution_evidence=self.execution_evidence,
            baseline_isolation_attestation_sha256=("f" * 64 if self.isolation_attested else None),
            mutant_isolation_attestation_sha256=("1" * 64 if self.isolation_attested else None),
            baseline_compilation_succeeded=self.compilation_succeeded,
            mutant_compilation_succeeded=self.compilation_succeeded,
            baseline_tests=[
                MutationSuiteTestObservation(
                    test_id=test_id,
                    status=self.baseline_status,
                )
            ],
            mutant_tests=[
                MutationSuiteTestObservation(
                    test_id=mutant_test_id,
                    status=self.mutant_status,
                )
            ],
        )
        self.last_observation = observation
        return observation


def test_suite_observation_rejects_selection_hash_not_derived_from_test_inventory() -> None:
    test = MutationSuiteTestObservation(
        test_id="testAccess",
        status=MutationSuiteTestStatus.PASSED,
    )

    with pytest.raises(ValidationError, match="selection hash"):
        MutationSuiteObservation.sealed(
            mutation_id="mut-access-control",
            baseline_source_sha256="a" * 64,
            mutant_source_sha256="b" * 64,
            suite_selection_sha256="0" * 64,
            executor_sha256=APPROVED_EXECUTOR_SHA256,
            isolation_policy_sha256=APPROVED_ISOLATION_POLICY_SHA256,
            baseline_execution_evidence=ExecutionEvidenceKind.MOCK,
            mutant_execution_evidence=ExecutionEvidenceKind.MOCK,
            baseline_isolation_attestation_sha256="c" * 64,
            mutant_isolation_attestation_sha256="d" * 64,
            baseline_compilation_succeeded=True,
            mutant_compilation_succeeded=True,
            baseline_tests=[test],
            mutant_tests=[test.model_copy()],
        )


def test_planned_mutation_denominator_includes_missing_outcome(tmp_path: Path) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[evidence],
        minimum_property_kill_score=1,
    )

    assert scorecard.mutation_count == 2
    assert len(scorecard.outcomes) == 2
    outcomes = {(item.property_id, item.mutation_id): item.outcome for item in scorecard.outcomes}
    assert outcomes[(PROPERTY_ACCESS, "mut-access-control")] is MutationTestOutcome.INCONCLUSIVE
    assert outcomes[(PROPERTY_REPLAY, "mut-replay-state")] is MutationTestOutcome.INCONCLUSIVE
    scores = {item.property_id: item for item in scorecard.property_scores}
    assert scores[PROPERTY_ACCESS].applicable_mutations == 1
    assert scores[PROPERTY_REPLAY].applicable_mutations == 1
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert scorecard.applicability_plan_sha256 == plan.plan_sha256
    scorecard.require_planned_campaign_origin()
    assert not scorecard.gate_passed


def _declarative_killed_scorecard() -> MutationScorecard:
    return score_mutation_outcomes(
        property_corpus_hash="c" * 64,
        expected_property_ids=[PROPERTY_ACCESS],
        property_repositories={PROPERTY_ACCESS: "synthetic"},
        outcomes=[
            MutationPropertyOutcome(
                mutation_id="mut-access-control",
                mutation_kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
                property_id=PROPERTY_ACCESS,
                outcome=MutationTestOutcome.KILLED,
                evidence_sha256="d" * 64,
            )
        ],
        minimum_property_kill_score=1,
    )


def test_legacy_scorecard_is_typed_declarative_and_rejected_for_audited_suite() -> None:
    scorecard = _declarative_killed_scorecard()

    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.DECLARATIVE
    assert scorecard.applicability_plan_sha256 is None
    assert scorecard.gate_passed
    with pytest.raises(ValueError, match="planned campaign origin"):
        scorecard.require_planned_campaign_origin()


@pytest.mark.parametrize("bypass", ["model_copy", "model_construct"])
def test_origin_spoof_cannot_turn_declarative_kill_into_planned_evidence(
    bypass: str,
) -> None:
    scorecard = _declarative_killed_scorecard()
    if bypass == "model_copy":
        spoofed = scorecard.model_copy(
            update={
                "evidence_origin": MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED,
                "applicability_plan_sha256": "e" * 64,
            }
        )
    else:
        values = {name: getattr(scorecard, name) for name in type(scorecard).model_fields}
        values["evidence_origin"] = MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
        values["applicability_plan_sha256"] = "e" * 64
        spoofed = type(scorecard).model_construct(**values)

    with pytest.raises(ValidationError, match="cannot award decisive credit"):
        spoofed.require_planned_campaign_origin()


def test_loader_accepts_only_declarative_scorecards(tmp_path: Path) -> None:
    declarative = _declarative_killed_scorecard()
    declarative_path = tmp_path / "declarative.json"
    declarative_path.write_text(declarative.model_dump_json(), encoding="utf-8")
    assert (
        load_mutation_scorecard(declarative_path).evidence_origin
        is MutationScorecardEvidenceOrigin.DECLARATIVE
    )

    plan = _applicability_plan()
    planned = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[],
        minimum_property_kill_score=1,
    )
    planned_path = tmp_path / "planned.json"
    planned_path.write_text(planned.model_dump_json(), encoding="utf-8")
    with pytest.raises(ValueError, match="must have declarative evidence origin"):
        load_mutation_scorecard(planned_path)


def test_legacy_v1_scorecard_bytes_remain_exact_after_comparison_extension() -> None:
    scorecards = {
        "declarative": (
            _declarative_killed_scorecard(),
            844,
            "761ab8f419dfe8ffe306e66a5280d50d1604323819281a312500102d7c172abd",
        ),
        "planned": (
            score_planned_mutation_campaigns(
                plan=_applicability_plan(),
                campaigns=[],
                minimum_property_kill_score=1,
            ),
            1_408,
            "e191b548ac6c0e8aa381dde02cf39dae46fbbadc5527fc31bb1e57cb0ebaa492",
        ),
    }

    for scorecard, expected_bytes, expected_sha256 in scorecards.values():
        raw = scorecard.model_dump_json().encode("utf-8")
        assert scorecard.schema_version == "1.0"
        assert scorecard.projection_authority is None
        assert b"projection_authority" not in raw
        assert len(raw) == expected_bytes
        assert hashlib.sha256(raw).hexdigest() == expected_sha256


@pytest.mark.parametrize(
    ("executor", "expected"),
    [
        (_ObservedExecutor(), MutationTestOutcome.INCONCLUSIVE),
        (
            _ObservedExecutor(baseline_status=MutationSuiteTestStatus.FAILED),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(mutant_status=MutationSuiteTestStatus.UNAVAILABLE),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(mutant_status=MutationSuiteTestStatus.TIMED_OUT),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(mutant_status=MutationSuiteTestStatus.INVALID_OUTPUT),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(compilation_succeeded=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(isolation_attested=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(source_binding_valid=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(executor_binding_valid=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(isolation_policy_binding_valid=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(selection_binding_valid=False),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(mismatched_suite=True),
            MutationTestOutcome.INCONCLUSIVE,
        ),
        (
            _ObservedExecutor(mutant_status=MutationSuiteTestStatus.PASSED),
            MutationTestOutcome.INCONCLUSIVE,
        ),
    ],
)
def test_mock_or_incomplete_campaign_cannot_earn_production_kill_credit(
    tmp_path: Path,
    executor: MutationCampaignExecutor,
    expected: MutationTestOutcome,
) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=executor,
    )
    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[evidence],
        minimum_property_kill_score=1,
    )

    outcome = next(item for item in scorecard.outcomes if item.mutation_id == "mut-access-control")
    assert outcome.outcome is expected


def test_mock_campaign_exercises_only_pure_status_derivation(tmp_path: Path) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    observation = evidence.executor_observation
    assert observation is not None
    binding = next(item for item in plan.bindings if item.mutation_id == "mut-access-control")

    assert (
        mutation_module._derive_mutation_suite_outcome(binding, observation)
        is MutationTestOutcome.KILLED
    )
    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[evidence],
        minimum_property_kill_score=1,
    )
    production_outcome = next(
        item for item in scorecard.outcomes if item.mutation_id == "mut-access-control"
    )
    assert production_outcome.outcome is MutationTestOutcome.INCONCLUSIVE


def _synthetic_process_local_campaign(
    tmp_path: Path,
    *,
    compilation_succeeded: bool = True,
) -> tuple[
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    object,
    object,
    object,
    object,
    set[int],
]:
    """Exercise authority closures without pretending synthetic runs are production evidence."""

    plan, declared_real, _observation, live_observation_ids = _synthetic_declared_real_campaign(
        tmp_path,
        compilation_succeeded=compilation_succeeded,
    )

    def return_exact_campaign(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, preserving_copy, subscribe, _campaign_lease = (
        mutation_module._build_mutation_campaign_runtime_authority(
            campaign_body=return_exact_campaign,
            observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
            executor_authority_resolver=lambda candidate: candidate is not None,
            disposal_authority_resolver=lambda private_root, executor: bool(
                private_root is not None and executor is not None
            ),
        )
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    assert contains(campaign)
    return (
        plan,
        campaign,
        contains,
        preserving_copy,
        subscribe,
        _campaign_lease,
        live_observation_ids,
    )


def test_process_local_scorer_derives_kill_only_while_campaign_seal_is_live(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, live_observation_ids = (
        _synthetic_process_local_campaign(tmp_path)
    )
    score, has_score_authority, preserving_score_copy = (
        mutation_module._build_runtime_mutation_scorer(
            campaign_authority_resolver=contains,
            campaign_copy_preserver=preserving_copy,
            campaign_revocation_registrar=subscribe,
        )
    )

    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    outcome = next(item for item in scorecard.outcomes if item.mutation_id == "mut-access-control")
    assert scorecard.schema_version == "1.1"
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PROCESS_LOCAL_COMPARISON
    assert scorecard.projection_authority == "comparison_only"
    assert outcome.outcome is MutationTestOutcome.KILLED
    assert has_score_authority(scorecard)
    assert preserving_copy(campaign) is campaign
    preserved_scorecard = preserving_score_copy(scorecard)
    assert preserved_scorecard is scorecard
    assert has_score_authority(preserved_scorecard)

    serialized = MutationScorecard.model_validate_json(scorecard.model_dump_json())
    assert not has_score_authority(serialized)
    assert not has_score_authority(scorecard.model_copy())

    if hasattr(os, "fork"):
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the parent-side pipe
            os.close(read_fd)
            try:
                mutation_module.os.getpid = lambda: os.getppid()
                child_scorecard = score(
                    plan=plan,
                    campaigns=[campaign],
                    minimum_property_kill_score=1,
                )
                fork_result = b"".join(
                    (
                        b"1" if contains(campaign) else b"0",
                        b"1" if has_score_authority(scorecard) else b"0",
                        (
                            b"1"
                            if child_scorecard.evidence_origin
                            is MutationScorecardEvidenceOrigin.PROCESS_LOCAL_COMPARISON
                            else b"0"
                        ),
                    )
                )
                os.write(write_fd, fork_result)
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            fork_result = os.read(read_fd, 3)
        finally:
            os.close(read_fd)
        waited_pid, status = os.waitpid(child_pid, 0)
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(status) == 0
        assert fork_result == b"000"

    live_observation_ids.clear()
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_process_local_scorer_keeps_compilation_failure_inconclusive(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(
            tmp_path,
            compilation_succeeded=False,
        )
    )
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )

    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    outcome = next(item for item in scorecard.outcomes if item.mutation_id == "mut-access-control")
    assert outcome.outcome is MutationTestOutcome.INCONCLUSIVE
    assert has_score_authority(scorecard)
    assert not scorecard.gate_passed


def test_process_local_scorer_downgrades_when_campaign_authority_expires_before_seal(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    authority_checks = 0

    def expiring_authority(candidate: MutationCampaignEvidence) -> bool:
        nonlocal authority_checks
        authority_checks += 1
        return authority_checks == 1 and contains(candidate)

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=expiring_authority,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )

    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    assert authority_checks == 2
    assert scorecard.schema_version == "1.0"
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in scorecard.outcomes)
    assert not has_score_authority(scorecard)


def test_process_local_scorer_rejects_transient_self_hashed_campaign_snapshot(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    original_observation = campaign.executor_observation
    assert original_observation is not None
    transient_observation_values = original_observation.model_dump(
        mode="python",
        exclude={"observation_sha256"},
    )
    transient_observation_values["baseline_tests"] = list(original_observation.baseline_tests)
    transient_observation_values["mutant_tests"] = [
        item.model_copy(update={"status": MutationSuiteTestStatus.PASSED})
        for item in original_observation.mutant_tests
    ]
    transient_observation = MutationSuiteObservation.sealed(**transient_observation_values)
    transient_campaign_values = campaign.model_dump(
        mode="python",
        exclude={"evidence_sha256", "executor_observation"},
    )
    transient_campaign = MutationCampaignEvidence.sealed(
        **transient_campaign_values,
        executor_observation=transient_observation,
    )
    original_evidence_sha256 = campaign.evidence_sha256
    mutation_injected = False

    @contextmanager
    def transient_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        nonlocal mutation_injected
        with campaign_lease(candidate) as authority_sha256:
            if not mutation_injected:
                mutation_injected = True
                object.__setattr__(candidate, "executor_observation", transient_observation)
                object.__setattr__(candidate, "evidence_sha256", transient_campaign.evidence_sha256)
            try:
                yield authority_sha256
            finally:
                object.__setattr__(candidate, "executor_observation", original_observation)
                object.__setattr__(candidate, "evidence_sha256", original_evidence_sha256)

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=transient_campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    assert mutation_injected
    assert scorecard.schema_version == "1.0"
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in scorecard.outcomes)
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_process_local_scorer_never_rekeys_decisive_credit_from_mutable_projection(
    tmp_path: Path,
) -> None:
    plan, declared_campaign, original_observation, _ = _synthetic_declared_real_campaign(tmp_path)
    shared_test_ids = ["testAccess", "testReplay"]

    def observation_for(mutation_id: str) -> MutationSuiteObservation:
        values = original_observation.model_dump(
            mode="python",
            exclude={
                "baseline_tests",
                "mutant_tests",
                "observation_sha256",
                "suite_selection_sha256",
            },
        )
        values["mutation_id"] = mutation_id
        return MutationSuiteObservation.sealed(
            **values,
            suite_selection_sha256=MutationSuiteObservation.calculate_selection_sha256(
                shared_test_ids
            ),
            baseline_tests=[
                MutationSuiteTestObservation(
                    test_id=test_id,
                    status=MutationSuiteTestStatus.PASSED,
                )
                for test_id in shared_test_ids
            ],
            mutant_tests=[
                MutationSuiteTestObservation(
                    test_id=test_id,
                    status=MutationSuiteTestStatus.FAILED,
                )
                for test_id in shared_test_ids
            ],
        )

    access_observation = observation_for("mut-access-control")
    replay_observation = observation_for("mut-replay-state")
    access_values = declared_campaign.model_dump(
        mode="python",
        exclude={"evidence_sha256", "executor_observation"},
    )
    access_campaign = MutationCampaignEvidence.sealed(
        **access_values,
        executor_observation=access_observation,
    )
    replay_specification = next(
        item for item in plan.specifications if item.id == "mut-replay-state"
    )
    replay_values = {
        **access_values,
        "mutation_id": replay_specification.id,
        "mutation_specification_sha256": replay_specification.specification_sha256(),
    }
    replay_projection = MutationCampaignEvidence.sealed(
        **replay_values,
        executor_observation=replay_observation,
    )

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(
            values,
            campaign=access_campaign,
            observation=access_observation,
        )
        return access_campaign

    executor = _ObservedExecutor()
    invoke, contains, _, subscribe, campaign_lease = (
        mutation_module._build_mutation_campaign_runtime_authority(
            campaign_body=body,
            observation_authority_resolver=lambda candidate: candidate is access_observation,
            executor_authority_resolver=lambda candidate: candidate is executor,
            disposal_authority_resolver=lambda _root, _executor: True,
        )
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=executor,
    )
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=lambda _candidate: replay_projection,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    outcomes = {item.mutation_id: item.outcome for item in scorecard.outcomes}

    assert outcomes["mut-access-control"] is MutationTestOutcome.KILLED
    assert outcomes["mut-replay-state"] is MutationTestOutcome.INCONCLUSIVE
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PROCESS_LOCAL_COMPARISON
    assert has_score_authority(scorecard)


def test_process_local_scorer_never_rebinds_live_campaign_to_projected_plan(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, _preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    projected_plan_values = plan.model_dump(
        mode="python",
        exclude={
            "bindings",
            "kind_accounting",
            "non_applicability",
            "plan_sha256",
            "specifications",
        },
    )
    projected_plan_values["property_corpus_hash"] = "d" * 64
    projected_plan = MutationApplicabilityPlan.sealed(
        **projected_plan_values,
        specifications=list(plan.specifications),
        bindings=list(plan.bindings),
        non_applicability=list(plan.non_applicability),
        kind_accounting=list(plan.kind_accounting),
    )
    projected_campaign_values = campaign.model_dump(
        mode="python",
        exclude={"evidence_sha256", "executor_observation"},
    )
    projected_campaign_values["plan_sha256"] = projected_plan.plan_sha256
    projected_campaign = MutationCampaignEvidence.sealed(
        **projected_campaign_values,
        executor_observation=campaign.executor_observation,
    )
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=lambda _candidate: projected_campaign,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=campaign_lease,
    )

    scorecard = score(
        plan=projected_plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    assert scorecard.schema_version == "1.0"
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in scorecard.outcomes)
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_scorecard_registration_rolls_back_when_campaign_lease_expires(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    lease_entered = threading.Event()
    release_lease = threading.Event()

    @contextmanager
    def blocking_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        with campaign_lease(candidate) as authority_sha256:
            lease_entered.set()
            if not release_lease.wait(timeout=5):
                raise RuntimeError("score registration lease timed out")
            yield authority_sha256

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=blocking_campaign_lease,
    )
    scorecards: list[MutationScorecard] = []

    def score_campaign() -> None:
        scorecards.append(
            score(
                plan=plan,
                campaigns=[campaign],
                minimum_property_kill_score=1,
            )
        )

    scoring = threading.Thread(target=score_campaign, daemon=True)
    scoring.start()
    if not lease_entered.wait(timeout=5):
        release_lease.set()
        scoring.join(timeout=5)
        pytest.fail("score registration did not acquire the campaign lease")
    object.__setattr__(campaign, "failure_kind", "ExpiredDuringScoreRegistration")
    release_lease.set()
    scoring.join(timeout=5)
    object.__setattr__(campaign, "failure_kind", None)

    assert not scoring.is_alive()
    assert len(scorecards) == 1
    assert scorecards[0].schema_version == "1.0"
    assert scorecards[0].evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert all(
        outcome.outcome is MutationTestOutcome.INCONCLUSIVE for outcome in scorecards[0].outcomes
    )
    assert not contains(campaign)
    assert not has_score_authority(scorecards[0])


def test_scorecard_registration_rechecks_local_seal_after_campaign_lease_exit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    dependency_exit_entered = threading.Event()
    release_dependency_exit = threading.Event()
    lease_calls = 0
    created_scorecards: list[MutationScorecard] = []
    returned_scorecards: list[MutationScorecard] = []
    scoring_errors: list[type[BaseException]] = []
    original_score_outcomes = mutation_module._score_mutation_outcomes

    @contextmanager
    def blocking_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        nonlocal lease_calls
        lease_calls += 1
        current_call = lease_calls
        with campaign_lease(candidate) as authority_sha256:
            yield authority_sha256
            if current_call == 2:
                dependency_exit_entered.set()
                if not release_dependency_exit.wait(timeout=5):
                    raise RuntimeError("score registration dependency exit timed out")

    def capture_scorecard(**values: object) -> MutationScorecard:
        scorecard = original_score_outcomes(**values)
        created_scorecards.append(scorecard)
        return scorecard

    monkeypatch.setattr(mutation_module, "_score_mutation_outcomes", capture_scorecard)
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=blocking_campaign_lease,
    )

    def score_campaign() -> None:
        try:
            returned_scorecards.append(
                score(
                    plan=plan,
                    campaigns=[campaign],
                    minimum_property_kill_score=1,
                )
            )
        except BaseException as exc:
            scoring_errors.append(type(exc))

    scoring = threading.Thread(target=score_campaign, daemon=True)
    scoring.start()
    if not dependency_exit_entered.wait(timeout=5):
        release_dependency_exit.set()
        scoring.join(timeout=5)
        pytest.fail("score registration did not reach campaign-lease exit")
    assert len(created_scorecards) == 1
    object.__setattr__(created_scorecards[0], "projection_authority", None)
    release_dependency_exit.set()
    scoring.join(timeout=5)
    object.__setattr__(created_scorecards[0], "projection_authority", "comparison_only")

    assert not scoring.is_alive()
    assert scoring_errors == []
    assert len(returned_scorecards) == 1
    assert returned_scorecards[0].schema_version == "1.0"
    assert (
        returned_scorecards[0].evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    )
    assert not has_score_authority(created_scorecards[0])
    assert not has_score_authority(returned_scorecards[0])


def test_process_local_scorer_base_exception_after_registration_revokes_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    authority_checks = 0
    created_scorecards: list[MutationScorecard] = []
    original_score_outcomes = mutation_module._score_mutation_outcomes

    def interrupting_authority(candidate: MutationCampaignEvidence) -> bool:
        nonlocal authority_checks
        authority_checks += 1
        if authority_checks == 3:
            raise KeyboardInterrupt("synthetic interrupt after scorecard registration")
        return contains(candidate)

    def capture_scorecard(**values: object) -> MutationScorecard:
        scorecard = original_score_outcomes(**values)
        created_scorecards.append(scorecard)
        return scorecard

    monkeypatch.setattr(mutation_module, "_score_mutation_outcomes", capture_scorecard)
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=interrupting_authority,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )

    with pytest.raises(KeyboardInterrupt, match="after scorecard registration"):
        score(
            plan=plan,
            campaigns=[campaign],
            minimum_property_kill_score=1,
        )

    assert authority_checks == 3
    assert len(created_scorecards) == 1
    assert not has_score_authority(created_scorecards[0])


def test_process_local_scorer_revocation_registrar_interrupt_revokes_and_propagates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, campaign, contains, preserving_copy, _, _lease, _ = _synthetic_process_local_campaign(
        tmp_path
    )
    created_scorecards: list[MutationScorecard] = []
    original_score_outcomes = mutation_module._score_mutation_outcomes

    def interrupting_registrar(
        candidate: MutationCampaignEvidence,
        dependent_revoker: object,
    ) -> object:
        del candidate, dependent_revoker
        raise KeyboardInterrupt("synthetic scorecard revocation registrar interrupt")

    def capture_scorecard(**values: object) -> MutationScorecard:
        scorecard = original_score_outcomes(**values)
        created_scorecards.append(scorecard)
        return scorecard

    monkeypatch.setattr(mutation_module, "_score_mutation_outcomes", capture_scorecard)
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=interrupting_registrar,
    )

    with pytest.raises(KeyboardInterrupt, match="revocation registrar interrupt"):
        score(
            plan=plan,
            campaigns=[campaign],
            minimum_property_kill_score=1,
        )

    assert len(created_scorecards) == 1
    assert not has_score_authority(created_scorecards[0])


def test_process_local_scorer_lock_interrupt_after_final_dependency_check_revokes_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    created_scorecards: list[MutationScorecard] = []
    original_score_outcomes = mutation_module._score_mutation_outcomes
    original_rlock = threading.RLock

    class InterruptingRLock:
        def __init__(self) -> None:
            self._lock = original_rlock()
            self._acquisitions = 0

        def __enter__(self) -> InterruptingRLock:
            self._acquisitions += 1
            if self._acquisitions == 3:
                raise KeyboardInterrupt("synthetic interrupt after final score dependency check")
            self._lock.acquire()
            return self

        def __exit__(self, *exc: object) -> None:
            self._lock.release()

    def capture_scorecard(**values: object) -> MutationScorecard:
        scorecard = original_score_outcomes(**values)
        created_scorecards.append(scorecard)
        return scorecard

    monkeypatch.setattr(mutation_module, "_score_mutation_outcomes", capture_scorecard)
    monkeypatch.setattr(mutation_module.threading, "RLock", InterruptingRLock)
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )

    with pytest.raises(KeyboardInterrupt, match="after final score dependency check"):
        score(
            plan=plan,
            campaigns=[campaign],
            minimum_property_kill_score=1,
        )

    assert len(created_scorecards) == 1
    assert not has_score_authority(created_scorecards[0])


def test_public_process_local_scorer_cannot_credit_reconstructed_real_campaign(
    tmp_path: Path,
) -> None:
    plan = _applicability_plan()
    mock = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    declared_real = _self_hashed_declared_real_campaign(mock)

    scorecard = mutation_module.score_process_local_mutation_campaigns(
        plan=plan,
        campaigns=[declared_real],
        minimum_property_kill_score=1,
    )

    assert scorecard.schema_version == "1.0"
    assert scorecard.evidence_origin is MutationScorecardEvidenceOrigin.PLANNED_UNATTESTED
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in scorecard.outcomes)
    assert not mutation_module.has_host_mutation_scorecard_runtime_authority(scorecard)


def _self_hashed_declared_real_campaign(
    evidence: MutationCampaignEvidence,
) -> MutationCampaignEvidence:
    """Build persisted declarations only; this does not confer trusted runtime authority."""

    observation = evidence.executor_observation
    assert observation is not None
    observation_values = {
        name: getattr(observation, name)
        for name in MutationSuiteObservation.model_fields
        if name != "observation_sha256"
    }
    observation_values["baseline_execution_evidence"] = ExecutionEvidenceKind.REAL
    observation_values["mutant_execution_evidence"] = ExecutionEvidenceKind.REAL
    declared_observation = MutationSuiteObservation.sealed(**observation_values)
    campaign_values = evidence.model_dump(
        mode="python",
        exclude={"evidence_sha256", "executor_observation"},
    )
    campaign_values["executor_observation"] = declared_observation
    return MutationCampaignEvidence.sealed(**campaign_values)


def _synthetic_declared_real_campaign(
    tmp_path: Path,
    *,
    compilation_succeeded: bool = True,
) -> tuple[
    MutationApplicabilityPlan,
    MutationCampaignEvidence,
    MutationSuiteObservation,
    set[int],
]:
    plan = _applicability_plan()
    mock = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(compilation_succeeded=compilation_succeeded),
    )
    declared_real = _self_hashed_declared_real_campaign(mock)
    observation = declared_real.executor_observation
    assert observation is not None
    return plan, declared_real, observation, {id(observation)}


def _stage_synthetic_campaign_cleanup(
    values: dict[str, object],
    *,
    campaign: MutationCampaignEvidence,
    observation: MutationSuiteObservation | None = None,
) -> None:
    """Drive the private one-shot stage callback without granting production authority."""

    stage = values["_stage_cleanup_handoff"]
    plan = values["plan"]
    mutation_id = values["mutation_id"]
    source_repository = values["source_repository"]
    private_root = values["private_root"]
    executor = values["executor"]
    assert callable(stage)
    assert type(plan) is MutationApplicabilityPlan
    assert isinstance(mutation_id, str)
    assert isinstance(source_repository, Path)
    assert isinstance(private_root, Path)
    assert executor is not None
    specification = next(item for item in plan.specifications if item.id == mutation_id)
    root_stat = private_root.lstat()
    live_observation = observation or campaign.executor_observation
    stage(
        campaign=campaign,
        observation=live_observation,
        plan=plan,
        specification=specification,
        source_repository=source_repository,
        private_root=private_root,
        private_root_device=root_stat.st_dev,
        private_root_inode=root_stat.st_ino,
        executor=executor,
    )


def test_shared_revocation_domain_cascades_run_expiry_through_score(
    tmp_path: Path,
) -> None:
    baseline_workspace, mutant_workspace = _shared_domain_workspace_pair(tmp_path)
    baseline_run = _shared_domain_repository_suite_run(baseline_workspace)
    mutant_run = _shared_domain_repository_suite_run(mutant_workspace)
    block_reader = False
    reader_at_baseline_exit = threading.Event()
    release_reader = threading.Event()

    def run_lease_exit_hook(run: object) -> None:
        if block_reader and run is baseline_run:
            reader_at_baseline_exit.set()
            assert release_reader.wait(timeout=5)

    (
        execution_path,
        contains_observation,
        _preserve_observation,
        _calls,
        contains_run,
        _run_authority_lease,
        observation_authority_lease,
        revocation_lease,
    ) = _shared_domain_execution_path(
        [baseline_run, mutant_run],
        run_lease_exit_hook=run_lease_exit_hook,
    )
    specification = _shared_domain_specification()
    observation = _shared_domain_executor(
        execution_path,
        _SharedDomainSyntheticIsolation(),
    ).execute(
        baseline_workspace=baseline_workspace,
        mutant_workspace=mutant_workspace,
        specification=specification,
    )
    test_id = observation.baseline_tests[0].test_id
    kind_accounting = []
    for kind in sorted(REQUIRED_MUTATION_KINDS, key=lambda item: item.value):
        candidate_ids = [specification.id] if kind is specification.kind else []
        kind_accounting.append(
            MutationKindAccounting(
                kind=kind,
                status=(
                    MutationKindInventoryStatus.CANDIDATES_DECLARED
                    if candidate_ids
                    else MutationKindInventoryStatus.NO_CANDIDATE_DECLARED
                ),
                candidate_count=len(candidate_ids),
                candidate_ids=candidate_ids,
                limitation=(
                    None
                    if candidate_ids
                    else "No candidate is declared for this synthetic shared-domain plan."
                ),
            )
        )
    plan = MutationApplicabilityPlan.sealed(
        property_corpus_hash="c" * 64,
        source_repository_sha256=observation.baseline_source_sha256,
        approved_executor_sha256=observation.executor_sha256,
        approved_isolation_policy_sha256=observation.isolation_policy_sha256,
        property_repositories={PROPERTY_ACCESS: "synthetic-shared-domain"},
        specifications=[specification],
        bindings=[
            MutationApplicabilityBinding(
                property_id=PROPERTY_ACCESS,
                mutation_id=specification.id,
                test_ids=[test_id],
            )
        ],
        non_applicability=[],
        kind_accounting=kind_accounting,
    )
    declared_campaign = MutationCampaignEvidence.sealed(
        plan_sha256=plan.plan_sha256,
        mutation_id=specification.id,
        mutation_specification_sha256=specification.specification_sha256(),
        source_repository_sha256=plan.source_repository_sha256,
        pristine_workspace_sha256=observation.baseline_source_sha256,
        mutated_workspace_sha256=observation.mutant_source_sha256,
        restored_workspace_sha256=observation.baseline_source_sha256,
        executor_observation=observation,
        restoration_verified=True,
        workspace_disposed=True,
        source_preserved=True,
        disposal_entry_count=1,
        failure_kind=None,
    )

    def campaign_body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(
            values,
            campaign=declared_campaign,
            observation=observation,
        )
        return declared_campaign

    campaign_executor = _ObservedExecutor()
    (
        invoke_campaign,
        contains_campaign,
        preserve_campaign,
        subscribe_campaign_revocation,
        campaign_authority_lease,
    ) = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=campaign_body,
        observation_authority_lease=observation_authority_lease,
        observation_authority_resolver=contains_observation,
        executor_authority_resolver=lambda candidate: candidate is campaign_executor,
        disposal_authority_resolver=lambda _root, _executor: True,
        revocation_lease=revocation_lease,
    )
    private_root = tmp_path / "campaign-private"
    private_root.mkdir(mode=0o700)
    campaign = invoke_campaign(
        source_repository=baseline_workspace,
        private_root=private_root,
        plan=plan,
        mutation_id=specification.id,
        executor=campaign_executor,
    )
    score, contains_score, _preserve_score = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains_campaign,
        campaign_copy_preserver=preserve_campaign,
        campaign_revocation_registrar=subscribe_campaign_revocation,
        campaign_authority_lease=campaign_authority_lease,
        revocation_lease=revocation_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )

    assert contains_run(baseline_run)
    assert contains_observation(observation)
    assert contains_campaign(campaign)
    assert contains_score(scorecard)

    downstream_results: list[bool] = []
    original_duration_seconds = baseline_run.duration_seconds
    block_reader = True
    reader = threading.Thread(
        target=lambda: downstream_results.append(contains_score(scorecard)),
        daemon=True,
    )
    invalidator = threading.Thread(
        target=lambda: setattr(
            baseline_run,
            "duration_seconds",
            original_duration_seconds + 1,
        ),
        daemon=True,
    )
    try:
        reader.start()
        assert reader_at_baseline_exit.wait(timeout=5)
        invalidator.start()
        invalidator.join(timeout=5)
        assert not invalidator.is_alive()
        release_reader.set()
        reader.join(timeout=5)
        assert not reader.is_alive()
        assert downstream_results == [False]
        assert not contains_run(baseline_run)
        assert not contains_observation(observation)
        assert not contains_campaign(campaign)
        assert not contains_score(scorecard)

        baseline_run.duration_seconds = original_duration_seconds
        assert not contains_run(baseline_run)
        assert not contains_observation(observation)
        assert not contains_campaign(campaign)
        assert not contains_score(scorecard)
    finally:
        release_reader.set()
        reader.join(timeout=5)
        invalidator.join(timeout=5)
        baseline_run.duration_seconds = original_duration_seconds


def test_owned_body_handoff_retains_live_observation_across_nested_normalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import mmaudit.benchmark.foundry_mutation_executor as executor_module
    import mmaudit.scanners.base as scanner_base

    plan = _applicability_plan()
    executor = _ObservedExecutor(execution_evidence=ExecutionEvidenceKind.REAL)
    live_observation_ids: set[int] = set()
    source_custody_finalized = False
    cleanup_observed_at_stage = False

    original_finalize = scanner_base.ScannerWorkspaceSourceCustody.finalize

    def tracked_finalize(custody: scanner_base.ScannerWorkspaceSourceCustody) -> str:
        nonlocal source_custody_finalized
        result = original_finalize(custody)
        source_custody_finalized = True
        return result

    def tracked_body(**values: object) -> MutationCampaignEvidence:
        nonlocal cleanup_observed_at_stage
        original_stage = values["_stage_cleanup_handoff"]
        private_root = values["private_root"]
        mutation_id = values["mutation_id"]
        assert callable(original_stage)
        assert isinstance(private_root, Path)
        assert isinstance(mutation_id, str)

        def tracked_stage(**stage_values: object) -> None:
            nonlocal cleanup_observed_at_stage
            campaign = stage_values["campaign"]
            assert type(campaign) is MutationCampaignEvidence
            assert source_custody_finalized
            assert not (private_root / f"mmaudit-campaign-{mutation_id}").exists()
            assert campaign.workspace_disposed
            assert campaign.source_preserved
            cleanup_observed_at_stage = True
            original_stage(**stage_values)

        body_values = dict(values)
        body_values["_stage_cleanup_handoff"] = tracked_stage
        return mutation_module._run_owned_mutation_campaign_body(**body_values)

    def preserve(observation: MutationSuiteObservation) -> MutationSuiteObservation:
        live_observation_ids.add(id(observation))
        return observation

    monkeypatch.setattr(
        executor_module,
        "validated_mutation_suite_observation_copy_preserving_runtime_authority",
        preserve,
    )
    monkeypatch.setattr(
        scanner_base.ScannerWorkspaceSourceCustody,
        "finalize",
        tracked_finalize,
    )
    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=tracked_body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is executor,
        disposal_authority_resolver=lambda private_root, candidate: bool(
            private_root == tmp_path and candidate is executor
        ),
    )

    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=executor,
    )

    assert executor.last_observation is not None
    assert id(executor.last_observation) in live_observation_ids
    assert campaign.executor_observation is not executor.last_observation
    assert campaign.executor_observation is not None
    assert id(campaign.executor_observation) not in live_observation_ids
    assert campaign.executor_observation.model_dump(mode="json") == (
        executor.last_observation.model_dump(mode="json")
    )
    assert cleanup_observed_at_stage
    assert contains(campaign)
    assert not contains(campaign.model_copy())
    assert not contains(MutationCampaignEvidence.model_validate_json(campaign.model_dump_json()))


@pytest.mark.parametrize(
    "handoff_failure",
    ["missing", "duplicate", "returned_copy", "body_exception"],
)
def test_campaign_cleanup_handoff_failure_never_registers_authority(
    tmp_path: Path,
    handoff_failure: str,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)

    def invalid_body(**values: object) -> MutationCampaignEvidence:
        if handoff_failure != "missing":
            _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        if handoff_failure == "duplicate":
            _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        if handoff_failure == "returned_copy":
            return declared_real.model_copy()
        if handoff_failure == "body_exception":
            raise RuntimeError("synthetic post-stage failure")
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=invalid_body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: bool(
            private_root is not None and executor is not None
        ),
    )

    expected_error = RuntimeError if handoff_failure == "body_exception" else ValueError
    with pytest.raises(expected_error):
        invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )
    assert not contains(declared_real)


@pytest.mark.parametrize("substitution", ["plan", "mutation", "source", "root", "executor"])
def test_campaign_cleanup_handoff_binds_the_exact_invocation(
    tmp_path: Path,
    substitution: str,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    alternate_root = tmp_path / "alternate"
    alternate_root.mkdir(mode=0o700)

    def substituted_body(**values: object) -> MutationCampaignEvidence:
        staged_values = dict(values)
        if substitution == "plan":
            staged_values["plan"] = plan.model_copy(update={"approved_executor_sha256": "1" * 64})
        elif substitution == "mutation":
            staged_values["mutation_id"] = "mut-replay-state"
        elif substitution == "source":
            staged_values["source_repository"] = tmp_path / "different-source"
        elif substitution == "root":
            staged_values["private_root"] = alternate_root
        elif substitution == "executor":
            staged_values["executor"] = _ObservedExecutor()
        _stage_synthetic_campaign_cleanup(staged_values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=substituted_body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    with pytest.raises(ValueError, match="changed invocation identity"):
        invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )
    assert not contains(declared_real)


def test_campaign_cleanup_handoff_rechecks_observation_authority_before_registration(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    authority_checks = 0

    def expiring_authority(candidate: MutationSuiteObservation) -> bool:
        nonlocal authority_checks
        authority_checks += 1
        return authority_checks == 1 and id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=expiring_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert authority_checks == 2
    assert not contains(campaign)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("workspace_disposed", False),
        ("source_preserved", False),
        ("restoration_verified", False),
        ("failure_kind", "SyntheticCleanupFailure"),
    ],
)
def test_campaign_cleanup_handoff_cannot_seal_failed_cleanup_claims(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    plan, declared_real, live_observation, live_observation_ids = _synthetic_declared_real_campaign(
        tmp_path
    )
    campaign_values = {
        name: getattr(declared_real, name)
        for name in MutationCampaignEvidence.model_fields
        if name != "evidence_sha256"
    }
    campaign_values[field] = value
    failed_campaign = MutationCampaignEvidence.sealed(**campaign_values)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(
            values,
            campaign=failed_campaign,
            observation=live_observation,
        )
        return failed_campaign

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert campaign is failed_campaign
    assert not contains(campaign)


def test_campaign_cleanup_handoff_rechecks_private_root_after_staging(tmp_path: Path) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        private_root = values["private_root"]
        assert isinstance(private_root, Path)
        private_root.chmod(0o755)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    try:
        campaign = invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )
    finally:
        tmp_path.chmod(0o700)

    assert not contains(campaign)


def test_campaign_cleanup_handoff_rechecks_private_root_after_disposal_gate(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    private_root = tmp_path / "private-root"
    displaced_root = tmp_path / "displaced-root"
    private_root.mkdir(mode=0o700)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    def swapping_disposal(root: Path, executor: MutationCampaignExecutor) -> bool:
        del executor
        root.rename(displaced_root)
        root.mkdir(mode=0o700)
        return True

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=swapping_disposal,
    )

    campaign = invoke(
        source_repository=FIXTURE,
        private_root=private_root,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert not contains(campaign)


def test_campaign_registration_rechecks_local_seal_after_observation_lease_exit(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    exit_check_entered = threading.Event()
    release_exit_check = threading.Event()
    observation_checks = 0
    invocation_results: list[MutationCampaignEvidence] = []
    invocation_errors: list[type[BaseException]] = []

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        nonlocal observation_checks
        observation_checks += 1
        if observation_checks == 2:
            exit_check_entered.set()
            if not release_exit_check.wait(timeout=5):
                return False
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=observation_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    def invoke_campaign() -> None:
        try:
            invocation_results.append(
                invoke(
                    source_repository=FIXTURE,
                    private_root=tmp_path,
                    plan=plan,
                    mutation_id="mut-access-control",
                    executor=_ObservedExecutor(),
                )
            )
        except BaseException as exc:
            invocation_errors.append(type(exc))

    invocation = threading.Thread(target=invoke_campaign, daemon=True)
    invocation.start()
    if not exit_check_entered.wait(timeout=5):
        release_exit_check.set()
        invocation.join(timeout=5)
        pytest.fail("campaign registration did not reach observation-lease exit")
    object.__setattr__(declared_real, "failure_kind", "ChangedDuringRegistrationExit")
    release_exit_check.set()
    invocation.join(timeout=5)
    object.__setattr__(declared_real, "failure_kind", None)

    assert not invocation.is_alive()
    assert observation_checks == 2
    assert invocation_errors == []
    assert invocation_results == [declared_real]
    assert not contains(declared_real)


def test_campaign_cleanup_handoff_replay_during_finalization_poisoned_atomically(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    staged_values: dict[str, object] = {}
    replay_errors: list[type[BaseException]] = []

    def body(**values: object) -> MutationCampaignEvidence:
        staged_values.update(values)
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    def replay() -> None:
        try:
            _stage_synthetic_campaign_cleanup(staged_values, campaign=declared_real)
        except BaseException as exc:
            replay_errors.append(type(exc))

    def replaying_disposal(private_root: Path, executor: MutationCampaignExecutor) -> bool:
        del private_root, executor
        thread = threading.Thread(target=replay)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        return True

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=replaying_disposal,
    )

    with pytest.raises(ValueError, match="absent or invalid"):
        invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert replay_errors == [ValueError]
    assert not contains(declared_real)


def test_campaign_cleanup_handoff_base_exception_after_registration_revokes_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    original_event = threading.Event

    class InterruptingEvent:
        def __init__(self) -> None:
            self._event = original_event()
            self._checks = 0

        def is_set(self) -> bool:
            self._checks += 1
            if self._checks == 5:
                raise KeyboardInterrupt("synthetic interrupt after campaign registration")
            return self._event.is_set()

        def set(self) -> None:
            self._event.set()

    events: list[object] = [original_event(), InterruptingEvent()]

    def event_factory() -> object:
        return events.pop(0)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    monkeypatch.setattr(mutation_module.threading, "Event", event_factory)
    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    with pytest.raises(KeyboardInterrupt, match="after campaign registration"):
        invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert not contains(declared_real)


def test_campaign_cleanup_handoff_rejects_a_previously_issued_campaign_identity(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )
    invocation = {
        "source_repository": FIXTURE,
        "private_root": tmp_path,
        "plan": plan,
        "mutation_id": "mut-access-control",
        "executor": _ObservedExecutor(),
    }

    first = invoke(**invocation)
    assert contains(first)
    with pytest.raises(ValueError, match="replayed an issued campaign"):
        invoke(**invocation)

    assert contains(first)


def test_campaign_cleanup_handoff_child_process_cannot_stage_parent_authority(
    tmp_path: Path,
) -> None:
    if not hasattr(os, "fork"):
        pytest.skip("fork is unavailable")
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    child_result = b""

    def body(**values: object) -> MutationCampaignEvidence:
        nonlocal child_result
        read_fd, write_fd = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:  # pragma: no cover - asserted through the parent-side pipe
            os.close(read_fd)
            try:
                mutation_module.os.getpid = lambda: os.getppid()
                try:
                    _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
                except ValueError:
                    os.write(write_fd, b"0")
                else:
                    os.write(write_fd, b"1")
            finally:
                os.close(write_fd)
                os._exit(0)
        os.close(write_fd)
        try:
            child_result = os.read(read_fd, 1)
        finally:
            os.close(read_fd)
        waited_pid, status = os.waitpid(child_pid, 0)
        assert waited_pid == child_pid
        assert os.waitstatus_to_exitcode(status) == 0
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )

    with pytest.raises(ValueError, match="absent or invalid"):
        invoke(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert child_result == b"0"
    assert not contains(declared_real)


def test_captured_production_disposal_gate_stays_closed_after_module_alias_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    monkeypatch.setattr(
        mutation_module,
        "_has_portable_mutation_campaign_disposal_authority",
        lambda private_root, executor: True,
    )
    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
        executor_authority_resolver=lambda candidate: candidate is not None,
    )

    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert not contains(campaign)


def test_invalidated_campaign_seal_cannot_regain_authority_after_restoration(
    tmp_path: Path,
) -> None:
    _, campaign, contains, _, _, _lease, _ = _synthetic_process_local_campaign(tmp_path)

    object.__setattr__(campaign, "failure_kind", "ChangedAfterIssuance")
    assert not contains(campaign)
    object.__setattr__(campaign, "failure_kind", None)
    assert not contains(campaign)


def test_campaign_authority_read_cannot_outlive_concurrent_invalidation(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    reader_entered = threading.Event()
    release_reader = threading.Event()
    reader_identifier: int | None = None
    reader_results: list[bool] = []

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        if threading.get_ident() == reader_identifier:
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                return False
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=observation_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    assert contains(campaign)

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains(campaign))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("campaign authority reader did not reach its validation barrier")
    try:
        object.__setattr__(campaign, "failure_kind", "ChangedDuringAuthorityRead")
    finally:
        release_reader.set()
    reader.join(timeout=5)
    object.__setattr__(campaign, "failure_kind", None)

    assert not reader.is_alive()
    assert reader_results == [False]
    assert not contains(campaign)


def test_campaign_authority_rechecks_local_seal_after_observation_lease_exit(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    exit_check_entered = threading.Event()
    release_exit_check = threading.Event()
    reader_identifier: int | None = None
    reader_checks = 0
    reader_results: list[bool] = []

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        nonlocal reader_checks
        if threading.get_ident() == reader_identifier:
            reader_checks += 1
            if reader_checks == 2:
                exit_check_entered.set()
                if not release_exit_check.wait(timeout=5):
                    return False
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=observation_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains(campaign))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not exit_check_entered.wait(timeout=5):
        release_exit_check.set()
        reader.join(timeout=5)
        pytest.fail("campaign reader did not reach observation-lease exit")
    object.__setattr__(campaign, "failure_kind", "ChangedDuringObservationLeaseExit")
    release_exit_check.set()
    reader.join(timeout=5)
    object.__setattr__(campaign, "failure_kind", None)

    assert not reader.is_alive()
    assert reader_checks == 2
    assert reader_results == [False]
    assert not contains(campaign)


def test_campaign_dependency_exit_interrupt_revokes_without_becoming_restorable(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    interrupt_enabled = False
    authority_checks = 0

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        nonlocal authority_checks
        authority_checks += 1
        if interrupt_enabled and authority_checks == 2:
            raise KeyboardInterrupt("synthetic observation dependency exit interrupt")
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=observation_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    authority_checks = 0
    interrupt_enabled = True

    with pytest.raises(KeyboardInterrupt, match="dependency exit interrupt"):
        contains(campaign)

    interrupt_enabled = False
    assert not contains(campaign)


def test_campaign_lease_preserves_primary_interrupt_and_revokes_on_recheck_interrupt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, campaign, contains, _, _, campaign_lease, _ = _synthetic_process_local_campaign(tmp_path)
    original_model_dump = MutationCampaignEvidence.model_dump
    validation_interrupt_armed = False

    def interrupting_model_dump(
        candidate: MutationCampaignEvidence,
        *args: object,
        **kwargs: object,
    ) -> dict[str, object]:
        if validation_interrupt_armed and candidate is campaign:
            raise SystemExit("synthetic secondary campaign validation interrupt")
        return original_model_dump(candidate, *args, **kwargs)

    monkeypatch.setattr(MutationCampaignEvidence, "model_dump", interrupting_model_dump)

    with (
        pytest.raises(KeyboardInterrupt, match="synthetic primary campaign interrupt"),
        campaign_lease(campaign),
    ):
        validation_interrupt_armed = True
        raise KeyboardInterrupt("synthetic primary campaign interrupt")

    validation_interrupt_armed = False
    assert not contains(campaign)


def test_campaign_and_scorecard_read_cannot_outlive_observation_revocation(
    tmp_path: Path,
) -> None:
    plan, declared_real, live_observation, live_observation_ids = _synthetic_declared_real_campaign(
        tmp_path
    )
    reader_entered = threading.Event()
    release_reader = threading.Event()
    reader_identifier: int | None = None
    reader_observation_checks = 0
    reader_results: list[bool] = []

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        nonlocal reader_observation_checks
        if threading.get_ident() == reader_identifier:
            reader_observation_checks += 1
            if reader_observation_checks == 2:
                reader_entered.set()
                if not release_reader.wait(timeout=5):
                    return False
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, preserving_copy, subscribe, campaign_lease = (
        mutation_module._build_mutation_campaign_runtime_authority(
            campaign_body=body,
            observation_authority_resolver=observation_authority,
            executor_authority_resolver=lambda candidate: candidate is not None,
            disposal_authority_resolver=lambda private_root, executor: True,
        )
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert contains(campaign)
    assert has_score_authority(scorecard)

    def read_campaign_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains(campaign))

    reader = threading.Thread(target=read_campaign_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("campaign reader did not reach observation-lease exit")
    live_observation_ids.clear()
    release_reader.set()
    reader.join(timeout=5)
    live_observation_ids.add(id(live_observation))

    assert not reader.is_alive()
    assert reader_results == [False]
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_campaign_authority_read_cannot_outlive_completed_handoff_replay(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    staged_values: dict[str, object] = {}
    reader_entered = threading.Event()
    release_reader = threading.Event()
    replay_started = threading.Event()
    replay_finished = threading.Event()
    reader_identifier: int | None = None
    reader_results: list[bool] = []
    replay_errors: list[type[BaseException]] = []

    def observation_authority(candidate: MutationSuiteObservation) -> bool:
        if threading.get_ident() == reader_identifier:
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                return False
        return id(candidate) in live_observation_ids

    def body(**values: object) -> MutationCampaignEvidence:
        staged_values.update(values)
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, _, _, _lease = mutation_module._build_mutation_campaign_runtime_authority(
        campaign_body=body,
        observation_authority_resolver=observation_authority,
        executor_authority_resolver=lambda candidate: candidate is not None,
        disposal_authority_resolver=lambda private_root, executor: True,
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    assert contains(campaign)

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(contains(campaign))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("campaign authority reader did not reach its replay barrier")

    def replay_handoff() -> None:
        replay_started.set()
        try:
            _stage_synthetic_campaign_cleanup(staged_values, campaign=declared_real)
        except BaseException as exc:
            replay_errors.append(type(exc))
        finally:
            replay_finished.set()

    replayer = threading.Thread(target=replay_handoff, daemon=True)
    replayer.start()
    if not replay_started.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        replayer.join(timeout=5)
        pytest.fail("campaign replay thread did not start")
    try:
        assert not replay_finished.is_set()
    finally:
        release_reader.set()
    reader.join(timeout=5)
    replayer.join(timeout=5)

    assert not reader.is_alive()
    assert not replayer.is_alive()
    assert reader_results == [True]
    assert replay_errors == [ValueError]
    assert not contains(campaign)


def test_invalidated_scorecard_seal_cannot_regain_authority_after_restoration(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)

    object.__setattr__(scorecard, "projection_authority", None)
    assert not has_score_authority(scorecard)
    object.__setattr__(scorecard, "projection_authority", "comparison_only")
    assert not has_score_authority(scorecard)


def test_scorecard_authority_read_cannot_outlive_concurrent_invalidation(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, _lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    reader_entered = threading.Event()
    release_reader = threading.Event()
    reader_identifier: int | None = None
    reader_results: list[bool] = []

    def campaign_authority(candidate: MutationCampaignEvidence) -> bool:
        if threading.get_ident() == reader_identifier:
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                return False
        return contains(candidate)

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=campaign_authority,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(has_score_authority(scorecard))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("scorecard authority reader did not reach its validation barrier")
    try:
        object.__setattr__(scorecard, "projection_authority", None)
    finally:
        release_reader.set()
    reader.join(timeout=5)
    object.__setattr__(scorecard, "projection_authority", "comparison_only")

    assert not reader.is_alive()
    assert reader_results == [False]
    assert not has_score_authority(scorecard)


def test_scorecard_authority_rechecks_local_seal_after_campaign_lease_exit(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    exit_barrier_enabled = False
    exit_barrier_entered = threading.Event()
    release_exit_barrier = threading.Event()

    @contextmanager
    def blocking_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        with campaign_lease(candidate) as authority_sha256:
            yield authority_sha256
            if exit_barrier_enabled:
                exit_barrier_entered.set()
                if not release_exit_barrier.wait(timeout=5):
                    raise RuntimeError("campaign dependency exit timed out")

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=blocking_campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)
    exit_barrier_enabled = True
    reader_results: list[bool] = []
    reader = threading.Thread(
        target=lambda: reader_results.append(has_score_authority(scorecard)),
        daemon=True,
    )
    reader.start()
    if not exit_barrier_entered.wait(timeout=5):
        release_exit_barrier.set()
        reader.join(timeout=5)
        pytest.fail("score reader did not reach campaign-lease exit")
    object.__setattr__(scorecard, "projection_authority", None)
    release_exit_barrier.set()
    reader.join(timeout=5)
    object.__setattr__(scorecard, "projection_authority", "comparison_only")

    assert not reader.is_alive()
    assert reader_results == [False]
    assert not has_score_authority(scorecard)


def test_scorecard_dependency_exit_interrupt_revokes_without_becoming_restorable(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    interrupt_enabled = False

    @contextmanager
    def interrupting_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        with campaign_lease(candidate) as authority_sha256:
            yield authority_sha256
            if interrupt_enabled:
                raise KeyboardInterrupt("synthetic campaign dependency exit interrupt")

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=interrupting_campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)
    interrupt_enabled = True

    with pytest.raises(KeyboardInterrupt, match="dependency exit interrupt"):
        has_score_authority(scorecard)

    interrupt_enabled = False
    assert not has_score_authority(scorecard)


def test_scorecard_read_cannot_outlive_campaign_lease_revocation(
    tmp_path: Path,
) -> None:
    plan, campaign, contains, preserving_copy, subscribe, campaign_lease, _ = (
        _synthetic_process_local_campaign(tmp_path)
    )
    lease_entered = threading.Event()
    release_lease = threading.Event()
    blocking_enabled = False

    @contextmanager
    def blocking_campaign_lease(
        candidate: MutationCampaignEvidence,
    ) -> Iterator[str]:
        with campaign_lease(candidate) as authority_sha256:
            if blocking_enabled:
                lease_entered.set()
                if not release_lease.wait(timeout=5):
                    raise RuntimeError("score authority lease timed out")
            yield authority_sha256

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=contains,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
        campaign_authority_lease=blocking_campaign_lease,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)
    blocking_enabled = True
    reader_results: list[bool] = []
    reader = threading.Thread(
        target=lambda: reader_results.append(has_score_authority(scorecard)),
        daemon=True,
    )
    reader.start()
    if not lease_entered.wait(timeout=5):
        release_lease.set()
        reader.join(timeout=5)
        pytest.fail("score reader did not acquire the campaign lease")
    object.__setattr__(campaign, "failure_kind", "ExpiredDuringScoreRead")
    release_lease.set()
    reader.join(timeout=5)
    object.__setattr__(campaign, "failure_kind", None)

    assert not reader.is_alive()
    assert reader_results == [False]
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_scorecard_authority_read_cannot_outlive_completed_campaign_handoff_replay(
    tmp_path: Path,
) -> None:
    plan, declared_real, _, live_observation_ids = _synthetic_declared_real_campaign(tmp_path)
    staged_values: dict[str, object] = {}

    def body(**values: object) -> MutationCampaignEvidence:
        staged_values.update(values)
        _stage_synthetic_campaign_cleanup(values, campaign=declared_real)
        return declared_real

    invoke, contains, preserving_copy, subscribe, _campaign_lease = (
        mutation_module._build_mutation_campaign_runtime_authority(
            campaign_body=body,
            observation_authority_resolver=lambda candidate: id(candidate) in live_observation_ids,
            executor_authority_resolver=lambda candidate: candidate is not None,
            disposal_authority_resolver=lambda private_root, executor: True,
        )
    )
    campaign = invoke(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    reader_entered = threading.Event()
    release_reader = threading.Event()
    replay_started = threading.Event()
    replay_finished = threading.Event()
    reader_identifier: int | None = None
    reader_campaign_checks = 0
    reader_results: list[bool] = []
    replay_errors: list[type[BaseException]] = []

    def campaign_authority(candidate: MutationCampaignEvidence) -> bool:
        nonlocal reader_campaign_checks
        result = contains(candidate)
        if threading.get_ident() == reader_identifier:
            reader_campaign_checks += 1
        if threading.get_ident() == reader_identifier and reader_campaign_checks == 2:
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                return False
        return result

    score, has_score_authority, _ = mutation_module._build_runtime_mutation_scorer(
        campaign_authority_resolver=campaign_authority,
        campaign_copy_preserver=preserving_copy,
        campaign_revocation_registrar=subscribe,
    )
    scorecard = score(
        plan=plan,
        campaigns=[campaign],
        minimum_property_kill_score=1,
    )
    assert has_score_authority(scorecard)

    def read_authority() -> None:
        nonlocal reader_identifier
        reader_identifier = threading.get_ident()
        reader_results.append(has_score_authority(scorecard))

    reader = threading.Thread(target=read_authority, daemon=True)
    reader.start()
    if not reader_entered.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        pytest.fail("scorecard authority reader did not reach its replay barrier")

    def replay_handoff() -> None:
        replay_started.set()
        try:
            _stage_synthetic_campaign_cleanup(staged_values, campaign=declared_real)
        except BaseException as exc:
            replay_errors.append(type(exc))
        finally:
            replay_finished.set()

    replayer = threading.Thread(target=replay_handoff, daemon=True)
    replayer.start()
    if not replay_started.wait(timeout=5):
        release_reader.set()
        reader.join(timeout=5)
        replayer.join(timeout=5)
        pytest.fail("scorecard campaign replay thread did not start")
    try:
        assert not replay_finished.is_set()
    finally:
        release_reader.set()
    reader.join(timeout=5)
    replayer.join(timeout=5)

    assert not reader.is_alive()
    assert not replayer.is_alive()
    assert reader_results == [True]
    assert replay_errors == [ValueError]
    assert not contains(campaign)
    assert not has_score_authority(scorecard)


def test_self_hashed_declared_real_evidence_remains_inconclusive(
    tmp_path: Path,
) -> None:
    plan = _applicability_plan()
    mock_evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    declared_real = _self_hashed_declared_real_campaign(mock_evidence)

    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[declared_real],
        minimum_property_kill_score=1,
    )

    outcome = next(item for item in scorecard.outcomes if item.mutation_id == "mut-access-control")
    assert outcome.outcome is MutationTestOutcome.INCONCLUSIVE


def test_public_planned_scorer_exposes_no_runtime_credit_capability(
    tmp_path: Path,
) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert (
        "trusted_execution_receipts" not in signature(score_planned_mutation_campaigns).parameters
    )
    assert not hasattr(mutation_module, "TrustedMutationExecutionReceipt")
    assert not hasattr(mutation_module, "_TRUSTED_MUTATION_EXECUTION_RECEIPT_ISSUER")
    with pytest.raises(TypeError, match="unexpected keyword"):
        score_planned_mutation_campaigns(
            plan=plan,
            campaigns=[evidence],
            minimum_property_kill_score=1,
            trusted_execution_receipts=[],
        )


@pytest.mark.parametrize("bypass", ["model_copy", "model_construct"])
def test_stale_declared_real_observation_bypass_is_revalidated(
    tmp_path: Path,
    bypass: str,
) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    observation = evidence.executor_observation
    assert observation is not None
    if bypass == "model_copy":
        stale_observation = observation.model_copy(
            update={
                "baseline_execution_evidence": ExecutionEvidenceKind.REAL,
                "mutant_execution_evidence": ExecutionEvidenceKind.REAL,
            }
        )
    else:
        values = {
            name: getattr(observation, name) for name in MutationSuiteObservation.model_fields
        }
        values["baseline_execution_evidence"] = ExecutionEvidenceKind.REAL
        values["mutant_execution_evidence"] = ExecutionEvidenceKind.REAL
        stale_observation = MutationSuiteObservation.model_construct(**values)
    stale_campaign = evidence.model_copy(update={"executor_observation": stale_observation})

    with pytest.raises(ValidationError):
        score_planned_mutation_campaigns(
            plan=plan,
            campaigns=[stale_campaign],
            minimum_property_kill_score=1,
        )


class _FailingResidueExecutor(MutationCampaignExecutor):
    def __init__(self) -> None:
        self.workspaces: list[Path] = []

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        del specification
        self.workspaces = [baseline_workspace, mutant_workspace]
        for workspace in self.workspaces:
            residue = workspace / "out" / "generated.bin"
            residue.parent.mkdir(exist_ok=True)
            residue.write_bytes(b"synthetic generated output")
        raise RuntimeError("synthetic executor failure")


def test_owned_campaign_disposes_generated_residue_after_executor_failure(
    tmp_path: Path,
) -> None:
    plan = _applicability_plan()
    source_sha256 = mutation_repository_sha256(FIXTURE)
    executor = _FailingResidueExecutor()

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=executor,
    )

    assert mutation_repository_sha256(FIXTURE) == source_sha256
    assert executor.workspaces
    assert all(not workspace.exists() for workspace in executor.workspaces)
    assert evidence.restoration_verified
    assert evidence.workspace_disposed
    assert evidence.source_preserved
    assert evidence.executor_observation is None
    assert evidence.failure_kind == "RuntimeError"
    assert str(tmp_path) not in evidence.model_dump_json()
    assert {
        "workspace",
        "baseline_workspace",
        "mutant_workspace",
    }.isdisjoint(evidence.model_dump(mode="json"))


def test_owned_campaign_disposes_partial_setup_after_apply_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _applicability_plan()
    source_sha256 = mutation_repository_sha256(FIXTURE)

    def fail_after_partial_copy(
        *,
        source_repository: Path,
        workspace: Path,
        specification: SourceMutationSpec,
    ) -> object:
        del source_repository, specification
        residue = workspace / "out" / "partial.bin"
        residue.parent.mkdir(parents=True)
        residue.write_bytes(b"partial synthetic setup")
        raise RuntimeError("synthetic apply failure")

    monkeypatch.setattr(mutation_module, "apply_source_mutation", fail_after_partial_copy)

    with pytest.raises(RuntimeError, match="synthetic apply failure"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert mutation_repository_sha256(FIXTURE) == source_sha256
    assert not list(tmp_path.iterdir())


def test_owned_campaign_never_overwrites_preexisting_deterministic_name(
    tmp_path: Path,
) -> None:
    campaign = tmp_path / "mmaudit-campaign-mut-access-control"
    campaign.mkdir()
    marker = campaign / "operator-owned.txt"
    marker.write_text("preserve", encoding="utf-8")
    source_sha256 = mutation_repository_sha256(FIXTURE)

    with pytest.raises(ValueError, match="setup failed"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert mutation_repository_sha256(FIXTURE) == source_sha256


def test_owned_campaign_closes_and_removes_child_after_capture_stat_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_name = "mmaudit-campaign-mut-access-control"
    real_stat = mutation_module.os.stat
    real_create_child = mutation_module._OwnedMutationRoot.create_child
    real_workspace_close = mutation_module._OwnedMutationWorkspace.close
    closed_descriptors: list[int] = []
    stat_failures = 0

    def fail_child_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal stat_failures
        if path == campaign_name:
            stat_failures += 1
            raise OSError("synthetic post-mkdir stat failure")
        return real_stat(path, *args, **kwargs)

    def fail_during_create(
        root: object,
        name: str,
    ) -> object:
        with monkeypatch.context() as context:
            context.setattr(mutation_module.os, "stat", fail_child_stat)
            return real_create_child(root, name)

    def tracking_workspace_close(workspace: object) -> None:
        closed_descriptors.append(workspace.descriptor)
        real_workspace_close(workspace)

    monkeypatch.setattr(mutation_module._OwnedMutationRoot, "create_child", fail_during_create)
    monkeypatch.setattr(
        mutation_module._OwnedMutationWorkspace,
        "close",
        tracking_workspace_close,
    )

    with pytest.raises(ValueError, match="setup failed"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert stat_failures == 1
    assert closed_descriptors
    assert not list(tmp_path.iterdir())


def test_owned_campaign_fails_closed_with_residue_after_capture_open_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_name = "mmaudit-campaign-mut-access-control"
    real_open = mutation_module.os.open
    real_stat = mutation_module.os.stat
    real_create_child = mutation_module._OwnedMutationRoot.create_child
    open_failures = 0
    stat_failures = 0

    def fail_child_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        nonlocal open_failures
        if path == campaign_name:
            open_failures += 1
            raise OSError("synthetic post-mkdir open failure")
        return real_open(path, flags, *args, **kwargs)

    def fail_child_stat(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        nonlocal stat_failures
        if path == campaign_name:
            stat_failures += 1
            raise OSError("synthetic post-mkdir stat failure")
        return real_stat(path, *args, **kwargs)

    def fail_during_create(
        root: object,
        name: str,
    ) -> object:
        with monkeypatch.context() as context:
            context.setattr(mutation_module.os, "open", fail_child_open)
            context.setattr(mutation_module.os, "stat", fail_child_stat)
            return real_create_child(root, name)

    monkeypatch.setattr(mutation_module._OwnedMutationRoot, "create_child", fail_during_create)

    with pytest.raises(ValueError, match="setup failed"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert open_failures == 1
    assert stat_failures == 0
    residue = tmp_path / campaign_name
    assert residue.is_dir()
    assert not list(residue.iterdir())


def test_capture_open_failure_preserves_owned_residue_and_unbound_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_name = "mmaudit-campaign-mut-access-control"
    owned_residue = tmp_path / "renamed-owned-residue"
    replacement = tmp_path / campaign_name
    real_open = mutation_module.os.open
    real_create_child = mutation_module._OwnedMutationRoot.create_child
    replacement_marker = replacement / "unbound-marker"

    def replace_before_open(
        path: object,
        flags: int,
        *args: object,
        **kwargs: object,
    ) -> int:
        if path == campaign_name:
            (tmp_path / campaign_name).rename(owned_residue)
            replacement.mkdir(mode=0o700)
            replacement_marker.write_text("preserve", encoding="utf-8")
            raise OSError("synthetic child capture failure after replacement")
        return real_open(path, flags, *args, **kwargs)

    def replace_during_create(
        root: object,
        name: str,
    ) -> object:
        with monkeypatch.context() as context:
            context.setattr(mutation_module.os, "open", replace_before_open)
            return real_create_child(root, name)

    monkeypatch.setattr(
        mutation_module._OwnedMutationRoot,
        "create_child",
        replace_during_create,
    )

    with pytest.raises(ValueError, match="setup failed"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert owned_residue.is_dir()
    assert replacement_marker.read_text(encoding="utf-8") == "preserve"


class _InterruptingExecutor(MutationCampaignExecutor):
    def __init__(self) -> None:
        self.workspaces: list[Path] = []

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        del specification
        self.workspaces = [baseline_workspace, mutant_workspace]
        residue = mutant_workspace / "out" / "interrupt.bin"
        residue.parent.mkdir()
        residue.write_bytes(b"synthetic interrupt residue")
        raise KeyboardInterrupt


def test_owned_campaign_closes_and_disposes_after_executor_base_exception(
    tmp_path: Path,
) -> None:
    executor = _InterruptingExecutor()
    source_sha256 = mutation_repository_sha256(FIXTURE)

    with pytest.raises(KeyboardInterrupt):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=executor,
        )

    assert executor.workspaces
    assert all(not workspace.exists() for workspace in executor.workspaces)
    assert not list(tmp_path.iterdir())
    assert mutation_repository_sha256(FIXTURE) == source_sha256


class _BaselineMutatingExecutor(_ObservedExecutor):
    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        target = baseline_workspace / SOURCE_PATH
        target.write_bytes(target.read_bytes() + b"// synthetic integrity change\n")
        return super().execute(
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def test_owned_campaign_records_baseline_integrity_failure_as_inconclusive(
    tmp_path: Path,
) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_BaselineMutatingExecutor(),
    )
    scorecard = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[evidence],
        minimum_property_kill_score=1,
    )

    outcome = next(item for item in scorecard.outcomes if item.mutation_id == "mut-access-control")
    assert outcome.outcome is MutationTestOutcome.INCONCLUSIVE
    assert not evidence.restoration_verified
    assert evidence.restored_workspace_sha256 == evidence.source_repository_sha256
    assert evidence.workspace_disposed
    assert evidence.source_preserved


def test_applicability_plan_rejects_stale_hash_and_hidden_pair() -> None:
    plan = _applicability_plan()
    payload = plan.model_dump(mode="json")
    payload["bindings"] = payload["bindings"][:-1]

    with pytest.raises(ValidationError):
        MutationApplicabilityPlan.model_validate(payload)


def _unsealed_plan_values(plan: MutationApplicabilityPlan) -> dict[str, object]:
    return {
        name: getattr(plan, name)
        for name in MutationApplicabilityPlan.model_fields
        if name != "plan_sha256"
    }


def test_plan_requires_explicit_applicability_for_every_candidate_property_pair() -> None:
    plan = _applicability_plan()
    values = _unsealed_plan_values(plan)
    values["non_applicability"] = plan.non_applicability[:-1]

    with pytest.raises(ValidationError, match="requires explicit applicability"):
        MutationApplicabilityPlan.sealed(**values)


def test_plan_requires_exact_implemented_kind_accounting() -> None:
    plan = _applicability_plan()
    values = _unsealed_plan_values(plan)
    values["kind_accounting"] = plan.kind_accounting[:-1]

    with pytest.raises(ValidationError):
        MutationApplicabilityPlan.sealed(**values)


def test_plan_kind_accounting_must_match_declared_source_candidates() -> None:
    plan = _applicability_plan()
    values = _unsealed_plan_values(plan)
    accounting = list(plan.kind_accounting)
    access_index = next(
        index
        for index, item in enumerate(accounting)
        if item.kind is MutationKind.ACCESS_CONTROL_GUARD_REMOVAL
    )
    accounting[access_index] = MutationKindAccounting(
        kind=MutationKind.ACCESS_CONTROL_GUARD_REMOVAL,
        status=MutationKindInventoryStatus.CANDIDATES_DECLARED,
        candidate_count=1,
        candidate_ids=["mut-replay-state"],
    )
    values["kind_accounting"] = accounting

    with pytest.raises(ValidationError, match="differs from declared candidates"):
        MutationApplicabilityPlan.sealed(**values)


def test_plan_explicitly_limits_scope_to_implemented_five_class_subset() -> None:
    plan = _applicability_plan()

    assert plan.portfolio_scope == "implemented_five_class_subset"
    assert len(plan.kind_accounting) == 5
    payload = plan.model_dump(mode="json")
    payload["portfolio_scope"] = "full_eleven_class"
    with pytest.raises(ValidationError):
        MutationApplicabilityPlan.model_validate(payload)


def test_owned_campaign_revalidates_model_copy_plan_before_setup(tmp_path: Path) -> None:
    plan = _applicability_plan()
    stale_plan = plan.model_copy(update={"approved_executor_sha256": "4" * 64})

    with pytest.raises(ValidationError, match="plan hash"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=tmp_path,
            plan=stale_plan,
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert not list(tmp_path.iterdir())


def test_planned_scoring_revalidates_model_construct_plan() -> None:
    plan = _applicability_plan()
    values = {name: getattr(plan, name) for name in MutationApplicabilityPlan.model_fields}
    values["approved_isolation_policy_sha256"] = "5" * 64
    stale_plan = MutationApplicabilityPlan.model_construct(**values)

    with pytest.raises(ValidationError, match="plan hash"):
        score_planned_mutation_campaigns(
            plan=stale_plan,
            campaigns=[],
            minimum_property_kill_score=1,
        )


@pytest.mark.parametrize("bypass", ["model_copy", "model_construct"])
def test_planned_scoring_revalidates_stale_campaign_hash(
    tmp_path: Path,
    bypass: str,
) -> None:
    plan = _applicability_plan()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=plan,
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )
    if bypass == "model_copy":
        stale_evidence = evidence.model_copy(update={"failure_kind": "ForgedEvidence"})
    else:
        values = {name: getattr(evidence, name) for name in MutationCampaignEvidence.model_fields}
        values["failure_kind"] = "ForgedEvidence"
        stale_evidence = MutationCampaignEvidence.model_construct(**values)

    with pytest.raises(ValidationError, match="campaign evidence hash"):
        score_planned_mutation_campaigns(
            plan=plan,
            campaigns=[stale_evidence],
            minimum_property_kill_score=1,
        )


class _SymlinkResidueExecutor(_FailingResidueExecutor):
    def __init__(self, external: Path) -> None:
        super().__init__()
        self.external = external

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        link = mutant_workspace / "out" / "external-link"
        link.parent.mkdir()
        link.symlink_to(self.external)
        return super().execute(
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def test_owned_campaign_unlinks_residue_symlink_without_following_target(
    tmp_path: Path,
) -> None:
    external = tmp_path / "external.txt"
    external.write_text("preserve", encoding="utf-8")
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=private_root,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=_SymlinkResidueExecutor(external),
    )

    assert evidence.workspace_disposed
    assert external.read_text(encoding="utf-8") == "preserve"
    assert not list(private_root.iterdir())


class _ReplacingCampaignExecutor(MutationCampaignExecutor):
    def __init__(self) -> None:
        self.moved: Path | None = None

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        del specification
        campaign = baseline_workspace.parent
        moved = campaign.with_name(f"{campaign.name}-moved")
        residue = mutant_workspace / "out" / "renamed-residue.bin"
        residue.parent.mkdir()
        residue.write_bytes(b"synthetic renamed residue")
        campaign.rename(moved)
        self.moved = moved
        campaign.mkdir(mode=0o700)
        (campaign / "foreign-marker").write_text("preserve", encoding="utf-8")
        raise RuntimeError("synthetic campaign replacement")


def test_owned_campaign_erases_renamed_owned_tree_but_preserves_replacement(
    tmp_path: Path,
) -> None:
    executor = _ReplacingCampaignExecutor()
    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=executor,
    )

    replacement = tmp_path / "mmaudit-campaign-mut-access-control"
    assert evidence.workspace_disposed
    assert not evidence.restoration_verified
    assert evidence.source_preserved
    assert executor.moved is not None
    assert not executor.moved.exists()
    assert (replacement / "foreign-marker").read_text(encoding="utf-8") == "preserve"


def test_owned_campaign_fails_closed_when_identity_moves_during_final_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_name = "mmaudit-campaign-mut-access-control"
    campaign = tmp_path / campaign_name
    retained = tmp_path / f"{campaign_name}-retained"
    replacement_marker = campaign / "foreign-marker"
    real_rmdir = mutation_module.os.rmdir
    real_dispose = mutation_module._OwnedMutationWorkspace.dispose
    swapped = False

    def swap_during_final_removal(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal swapped
        if path == campaign_name and not swapped:
            swapped = True
            campaign.rename(retained)
            campaign.mkdir(mode=0o700)
            real_rmdir(path, *args, **kwargs)
            campaign.mkdir(mode=0o700)
            replacement_marker.write_text("preserve", encoding="utf-8")
            return
        real_rmdir(path, *args, **kwargs)

    def dispose_during_final_removal(
        workspace: mutation_module._OwnedMutationWorkspace,
        budget: mutation_module._MutationRemovalBudget,
    ) -> bool:
        with monkeypatch.context() as context:
            context.setattr(mutation_module.os, "rmdir", swap_during_final_removal)
            return real_dispose(workspace, budget)

    monkeypatch.setattr(
        mutation_module._OwnedMutationWorkspace,
        "dispose",
        dispose_during_final_removal,
    )

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert swapped
    assert not evidence.workspace_disposed
    assert evidence.failure_kind == "WorkspaceDisposalError"
    assert retained.is_dir()
    assert not list(retained.iterdir())
    assert replacement_marker.read_text(encoding="utf-8") == "preserve"


def test_owned_campaign_fails_closed_when_identity_moves_below_private_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_name = "mmaudit-campaign-mut-access-control"
    campaign = tmp_path / campaign_name
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir(mode=0o700)
    retained = quarantine / "retained"
    replacement_marker = campaign / "foreign-marker"
    real_rmdir = mutation_module.os.rmdir
    real_dispose = mutation_module._OwnedMutationWorkspace.dispose
    swapped = False

    def move_below_private_root(
        path: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        nonlocal swapped
        if path == campaign_name and not swapped:
            swapped = True
            campaign.rename(retained)
            campaign.mkdir(mode=0o700)
            real_rmdir(path, *args, **kwargs)
            campaign.mkdir(mode=0o700)
            replacement_marker.write_text("preserve", encoding="utf-8")
            return
        real_rmdir(path, *args, **kwargs)

    def dispose_during_final_removal(
        workspace: mutation_module._OwnedMutationWorkspace,
        budget: mutation_module._MutationRemovalBudget,
    ) -> bool:
        with monkeypatch.context() as context:
            context.setattr(mutation_module.os, "rmdir", move_below_private_root)
            return real_dispose(workspace, budget)

    monkeypatch.setattr(
        mutation_module._OwnedMutationWorkspace,
        "dispose",
        dispose_during_final_removal,
    )

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=tmp_path,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=_ObservedExecutor(),
    )

    assert swapped
    assert not evidence.workspace_disposed
    assert evidence.failure_kind == "WorkspaceDisposalError"
    assert retained.is_dir()
    assert not list(retained.iterdir())
    assert replacement_marker.read_text(encoding="utf-8") == "preserve"


class _ReplacingPrivateRootExecutor(MutationCampaignExecutor):
    def __init__(self) -> None:
        self.moved_root: Path | None = None

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        del specification
        residue = mutant_workspace / "out" / "parent-renamed-residue.bin"
        residue.parent.mkdir()
        residue.write_bytes(b"synthetic parent rename residue")
        private_root = baseline_workspace.parents[1]
        moved_root = private_root.with_name(f"{private_root.name}-moved")
        private_root.rename(moved_root)
        self.moved_root = moved_root
        private_root.mkdir(mode=0o700)
        (private_root / "replacement-marker").write_text("preserve", encoding="utf-8")
        raise RuntimeError("synthetic private-root replacement")


def test_owned_campaign_erases_child_after_private_root_rename_and_replacement(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    outside = tmp_path / "outside.txt"
    outside.write_text("preserve", encoding="utf-8")
    executor = _ReplacingPrivateRootExecutor()

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=private_root,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=executor,
    )

    assert evidence.workspace_disposed
    assert not evidence.restoration_verified
    assert evidence.source_preserved
    assert executor.moved_root is not None
    assert not (executor.moved_root / "mmaudit-campaign-mut-access-control").exists()
    assert not list(executor.moved_root.iterdir())
    assert (private_root / "replacement-marker").read_text(encoding="utf-8") == "preserve"
    assert outside.read_text(encoding="utf-8") == "preserve"


class _WideningPrivateRootExecutor(_ObservedExecutor):
    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        baseline_workspace.parents[1].chmod(0o755)
        return super().execute(
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def test_owned_campaign_requires_an_exact_owner_only_private_namespace(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    private_root.chmod(0o750)
    source_sha256 = mutation_repository_sha256(FIXTURE)

    with pytest.raises(ValueError, match="mode 0700"):
        run_owned_mutation_campaign(
            source_repository=FIXTURE,
            private_root=private_root,
            plan=_applicability_plan(),
            mutation_id="mut-access-control",
            executor=_ObservedExecutor(),
        )

    assert not list(private_root.iterdir())
    assert mutation_repository_sha256(FIXTURE) == source_sha256


def test_owned_campaign_fails_closed_if_private_namespace_loses_mode_0700(
    tmp_path: Path,
) -> None:
    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)

    evidence = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=private_root,
        plan=_applicability_plan(),
        mutation_id="mut-access-control",
        executor=_WideningPrivateRootExecutor(),
    )

    assert not evidence.workspace_disposed
    assert evidence.failure_kind == "WorkspaceDisposalError"
    assert evidence.source_preserved
    assert (private_root / "mmaudit-campaign-mut-access-control").is_dir()


class _ReplacingSourceIdentityExecutor(_ObservedExecutor):
    def __init__(self, source: Path) -> None:
        super().__init__()
        self.source = source

    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: SourceMutationSpec,
    ) -> MutationSuiteObservation:
        source_file = self.source / SOURCE_PATH
        replacement = source_file.with_name("replacement.sol")
        replacement.write_bytes(source_file.read_bytes())
        replacement.replace(source_file)
        return super().execute(
            baseline_workspace=baseline_workspace,
            mutant_workspace=mutant_workspace,
            specification=specification,
        )


def test_owned_campaign_detects_same_byte_source_identity_replacement(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source"
    shutil.copytree(FIXTURE, source)
    plan = _applicability_plan()
    values = _unsealed_plan_values(plan)
    values["source_repository_sha256"] = mutation_repository_sha256(source)
    source_plan = MutationApplicabilityPlan.sealed(**values)

    evidence = run_owned_mutation_campaign(
        source_repository=source,
        private_root=tmp_path,
        plan=source_plan,
        mutation_id="mut-access-control",
        executor=_ReplacingSourceIdentityExecutor(source),
    )

    assert not evidence.source_preserved
    assert evidence.failure_kind == "SourceIntegrityError"
    assert evidence.workspace_disposed


def test_cleanup_accepts_the_full_copyable_source_depth(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    current = source
    for _ in range(128):
        current /= "d"
        current.mkdir()
    (current / "Safe.sol").write_text("contract Safe {}\n", encoding="utf-8")
    mutation_repository_sha256(source)

    private_root = tmp_path / "private"
    private_root.mkdir(mode=0o700)
    root = mutation_module._open_owned_mutation_root(private_root)
    child = root.create_child("campaign")
    try:
        mutation_module._copy_pristine_mutation_workspace(
            source,
            private_root / "campaign" / "baseline",
        )
        assert child.dispose(mutation_module._MutationRemovalBudget())
    finally:
        child.close()
        root.close()

    assert not (private_root / "campaign").exists()


def test_owned_cleanup_bounds_enumeration_before_sorting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SyntheticEntry:
        def __init__(self, name: str) -> None:
            self.name = name

    class SyntheticScandir:
        def __enter__(self) -> object:
            return iter([SyntheticEntry("first"), SyntheticEntry("sentinel")])

        def __exit__(self, *args: object) -> None:
            del args

    monkeypatch.setattr(mutation_module.os, "scandir", lambda _: SyntheticScandir())
    budget = mutation_module._MutationRemovalBudget(
        removed_entries=mutation_module._MAX_MUTATION_REMOVAL_ENTRIES - 1
    )

    with pytest.raises(ValueError, match="entry limit"):
        mutation_module._remove_owned_mutation_contents(
            -1,
            root_device=1,
            depth=0,
            budget=budget,
        )
