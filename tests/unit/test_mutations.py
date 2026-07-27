from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.benchmark.mutations import (
    REQUIRED_MUTATION_KINDS,
    MutationKind,
    SourceMutationSpec,
    apply_source_mutation,
    mutation_repository_sha256,
    revert_source_mutation,
)

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "mutations"
SOURCE_PATH = "solidity/SafeMutationTargets.sol"


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
