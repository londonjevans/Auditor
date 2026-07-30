from __future__ import annotations

import hashlib
import shutil
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
        return MutationSuiteObservation.sealed(
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
            baseline_execution_evidence=ExecutionEvidenceKind.MOCK,
            mutant_execution_evidence=ExecutionEvidenceKind.MOCK,
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
