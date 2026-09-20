"""Eleven-class source transforms and denominator controls on synthetic local inputs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator  # type: ignore[import-untyped]

from mmaudit.benchmark.mutation_portfolio import (
    PortfolioSourceMutationSpec,
    SecurityMutationClass,
    mutate_portfolio_source,
    restore_portfolio_source,
    transform_portfolio_span,
)
from mmaudit.benchmark.mutations import (
    REQUIRED_MUTATION_KINDS,
    MutationApplicabilityPlan,
    MutationPropertyOutcome,
    MutationScorecard,
    MutationSpecification,
    MutationSuiteObservation,
    MutationTestOutcome,
    _class_mutation_scores,
    apply_source_mutation,
    mutation_repository_sha256,
    revert_source_mutation,
    run_owned_mutation_campaign,
    score_planned_mutation_campaigns,
)
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.mutation_portfolio_support import (
    CASES,
    FIXTURE,
    SOURCE_PATH,
    portfolio_plan,
    property_id,
    specification,
)


@pytest.mark.parametrize("kind", list(SecurityMutationClass))
def test_every_required_class_applies_in_disposable_copy_and_restores(
    tmp_path: Path,
    kind: SecurityMutationClass,
) -> None:
    spec = specification(kind)
    original = (FIXTURE / SOURCE_PATH).read_bytes()
    tree = mutation_repository_sha256(FIXTURE)
    applied = apply_source_mutation(
        source_repository=FIXTURE, workspace=tmp_path / "copy", specification=spec
    )
    assert applied.mutated_file_sha256 != applied.original_file_sha256
    assert applied.original_span_sha256 and applied.mutated_span_sha256
    assert mutation_repository_sha256(FIXTURE) == tree
    assert revert_source_mutation(applied).exact_restoration
    assert (applied.workspace / SOURCE_PATH).read_bytes() == original


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r", ""])
@pytest.mark.parametrize("kind", list(SecurityMutationClass))
def test_line_endings_and_final_newline_restore_byte_exactly(
    ending: str,
    kind: SecurityMutationClass,
) -> None:
    base = specification(kind)
    separator = ending or "\n"
    original = separator.join(base.expected_lines).encode() + ending.encode()
    spec = PortfolioSourceMutationSpec.model_validate(
        {
            **base.model_dump(),
            "line": 1,
            "expected_file_sha256": hashlib.sha256(original).hexdigest(),
        }
    )
    mutated, old_span, new_span, endings = mutate_portfolio_source(original, spec)
    assert old_span == original and mutated != original
    restored = restore_portfolio_source(
        mutated,
        spec,
        line_endings=endings,
        expected_mutated_span_sha256=hashlib.sha256(new_span).hexdigest(),
    )
    assert restored == original


@pytest.mark.parametrize("kind", list(SecurityMutationClass))
@pytest.mark.parametrize("mask", ["comment", "string"])
def test_comment_and_string_tokens_do_not_become_mutation_targets(
    kind: SecurityMutationClass,
    mask: str,
) -> None:
    base = specification(kind)
    source = "\n".join(base.expected_lines)
    masked = "/* " + source + " */" if mask == "comment" else repr(source)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate(
            {**base.model_dump(), "expected_lines": tuple(masked.splitlines())}
        )


def test_whole_file_comment_context_is_checked_not_just_selected_lines() -> None:
    base = specification(SecurityMutationClass.AUTHORIZATION_REMOVAL)
    content = ("/*\n" + "\n".join(base.expected_lines) + "\n*/\n").encode()
    spec = PortfolioSourceMutationSpec.model_validate(
        {
            **base.model_dump(),
            "line": 2,
            "expected_file_sha256": hashlib.sha256(content).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="comment or string"):
        mutate_portfolio_source(content, spec)


@pytest.mark.parametrize(
    "field,value",
    [
        ("replacement_token", "3 seconds"),
        ("replacement_token", "2 seconds"),
        ("replacement_token", "0; run()"),
        ("original_token", "two seconds"),
    ],
)
def test_timelock_must_weaken_a_numeric_duration_without_source_injection(
    field: str, value: str
) -> None:
    spec = specification(SecurityMutationClass.TIMELOCK_WEAKENING)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate({**spec.model_dump(), field: value})


@pytest.mark.parametrize(
    "original,replacement", [("1e18", "1000000000000000000"), ("1e18", "2e18"), ("1e18", "1e78")]
)
def test_decimal_scale_rejects_equivalence_nonpowers_and_overflow(
    original: str, replacement: str
) -> None:
    spec = specification(SecurityMutationClass.INCORRECT_DECIMAL_SCALE)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate(
            {**spec.model_dump(), "original_token": original, "replacement_token": replacement}
        )


@pytest.mark.parametrize(
    "lines",
    [
        ("uint256 state = 0;", "observer.observe(state);"),
        ("state = 0; observer.observe(1);",),
        ("state = 0;", "observer.observe(1);", "another = 0;"),
        ("state = calculate();", "observer.observe(1);"),
        ("state = 0;", "internalCall(1);"),
    ],
)
def test_reorder_refuses_ambiguous_scope_declarations_and_extra_statements(
    lines: tuple[str, ...],
) -> None:
    base = specification(SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate({**base.model_dump(), "expected_lines": lines})


def test_multiline_call_moves_before_state_without_losing_comments() -> None:
    base = specification(SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE)
    lines = (
        "  balances[user] = 0; // finalize",
        "  target.notify(",
        "    value",
        "  ); // observe",
    )
    spec = PortfolioSourceMutationSpec.model_validate(
        {**base.model_dump(), "expected_lines": lines}
    )
    assert transform_portfolio_span(spec) == (*lines[1:], lines[0])


@pytest.mark.parametrize(
    "kind,modifier",
    [
        (SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL, "initializer"),
        (SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL, "whenNotPaused"),
    ],
)
def test_standard_protection_modifier_can_be_removed_from_an_exact_header(
    kind: SecurityMutationClass, modifier: str
) -> None:
    base = specification(kind)
    line = "function guarded() external " + modifier + " {"
    spec = PortfolioSourceMutationSpec.model_validate(
        {**base.model_dump(), "expected_lines": (line,)}
    )
    assert transform_portfolio_span(spec) == (line.replace(modifier, ""),)


def test_span_hash_covers_every_line_and_restoration_rejects_changed_evidence(
    tmp_path: Path,
) -> None:
    base = specification(SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE)
    altered = PortfolioSourceMutationSpec.model_validate(
        {**base.model_dump(), "expected_lines": ("        balance = 0;", *base.expected_lines[1:])}
    )
    assert base.specification_sha256() != altered.specification_sha256()
    applied = apply_source_mutation(
        source_repository=FIXTURE, workspace=tmp_path / "copy", specification=base
    )
    with pytest.raises(ValueError, match="span"):
        revert_source_mutation(replace(applied, mutated_span_sha256="0" * 64))
    assert revert_source_mutation(applied).exact_restoration


def test_plan_is_versioned_and_keeps_all_eleven_classes_and_property_pairs() -> None:
    plan = portfolio_plan()
    assert len(REQUIRED_MUTATION_KINDS) == 5
    assert len(CASES) == len(plan.kind_accounting) == 11
    assert len(plan.bindings) == 11 and len(plan.non_applicability) == 110
    assert MutationApplicabilityPlan.model_validate_json(plan.model_dump_json()) == plan
    payload = {name: getattr(plan, name) for name in type(plan).model_fields}
    updates: tuple[dict[str, object], ...] = (
        {"schema_version": "1.1"},
        {"portfolio_scope": "implemented_five_class_subset"},
        {"kind_accounting": plan.kind_accounting[:-1]},
        {"non_applicability": []},
    )
    for update in updates:
        with pytest.raises(ValueError):
            MutationApplicabilityPlan.sealed(
                **{**{k: v for k, v in payload.items() if k != "plan_sha256"}, **update}
            )


def test_missing_runtime_retains_every_class_and_is_inconclusive() -> None:
    plan = portfolio_plan()
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    )
    assert score.schema_version == "2.0" and score.portfolio_scope == "required_eleven_class"
    assert score.class_scores is not None and len(score.class_scores) == 11
    assert len(score.outcomes) == 11 and not score.gate_passed
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in score.outcomes)
    assert MutationScorecard.model_validate_json(score.model_dump_json()) == score


def test_passing_observed_classes_cannot_hide_an_absent_required_class() -> None:
    # Pure arithmetic inputs are not executor evidence or a measured kill-rate claim.
    outcomes = [
        MutationPropertyOutcome(
            mutation_id=specification(kind).id,
            mutation_kind=kind,
            property_id=property_id(kind),
            outcome=MutationTestOutcome.KILLED,
            evidence_sha256="f" * 64,
        )
        for kind in list(SecurityMutationClass)[:-1]
    ]
    classes = _class_mutation_scores(outcomes, minimum_required=0.95)
    assert len(classes) == 11 and sum(item.gate_passed for item in classes) == 10
    assert (
        next(
            item
            for item in classes
            if item.mutation_class is SecurityMutationClass.INCORRECT_DECIMAL_SCALE
        ).property_scores
        == []
    )


def test_weak_property_cannot_hide_inside_a_passing_class_average() -> None:
    kind = SecurityMutationClass.AUTHORIZATION_REMOVAL
    outcomes = [
        MutationPropertyOutcome(
            mutation_id=f"mut-control-{index}",
            mutation_kind=kind,
            property_id="prop-" + ("a" if index else "b") * 24,
            outcome=MutationTestOutcome.KILLED if index else MutationTestOutcome.SURVIVED,
            evidence_sha256="f" * 64,
        )
        for index in range(100)
    ]
    selected = next(
        item
        for item in _class_mutation_scores(outcomes, minimum_required=0.95)
        if item.mutation_class is kind
    )
    assert not selected.gate_passed and len(selected.property_scores) == 2


@pytest.mark.parametrize(
    "line",
    [
        "require(block.timestamp >= scheduledAt - 2 seconds + 10 seconds);",
        "require(block.timestamp <= scheduledAt + 2 seconds);",
        "require(block.timestamp >= scheduledAt + 2 seconds || bypass);",
    ],
)
def test_timelock_does_not_mislabel_strengthening_or_an_alternative_condition(line: str) -> None:
    base = specification(SecurityMutationClass.TIMELOCK_WEAKENING)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate({**base.model_dump(), "expected_lines": (line,)})


@pytest.mark.parametrize(
    "line",
    [
        "function initializer() external {",
        "function named(uint256 initializer) external {",
        "function named() external returns(initializer) {",
    ],
)
def test_initializer_name_is_not_itself_a_protection_modifier(line: str) -> None:
    base = specification(SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate({**base.model_dump(), "expected_lines": (line,)})


@pytest.mark.parametrize("excess", [False, True])
def test_exact_span_line_and_total_character_bounds(excess: bool) -> None:
    base = specification(SecurityMutationClass.AUTHORIZATION_REMOVAL)
    line = base.expected_lines[0]
    for lines in (
        (line, *([""] * (32 if excess else 31))),
        (line, "//" + " " * 19998, "//" + " " * (40000 - 20000 - len(line) - 2 + excess)),
    ):
        values = {**base.model_dump(), "expected_lines": lines}
        if excess:
            with pytest.raises(ValueError):
                PortfolioSourceMutationSpec.model_validate(values)
        else:
            assert PortfolioSourceMutationSpec.model_validate(values).expected_lines == lines


def test_generic_accounting_is_not_explicit_rounding_direction() -> None:
    base = specification(SecurityMutationClass.ROUNDING_DIRECTION)
    with pytest.raises(ValueError):
        PortfolioSourceMutationSpec.model_validate(
            {
                **base.model_dump(),
                "expected_lines": ("return assets / shares;",),
                "original_token": "/",
                "replacement_token": "*",
            }
        )


def test_public_schemas_refuse_mixed_versions_and_missing_class_inventory() -> None:
    plan = portfolio_plan()
    name = "mutation_applicability_plan.schema.json"
    schema = json.loads(rendered_schema(name, MODELS[name]))
    validator = Draft202012Validator(schema)
    payload = plan.model_dump(mode="json")
    validator.validate(payload)
    assert not validator.is_valid({**payload, "schema_version": "1.1"})
    assert not validator.is_valid({**payload, "kind_accounting": payload["kind_accounting"][:-1]})
    assert not validator.is_valid({**payload, "portfolio_scope": "implemented_five_class_subset"})
    score = score_planned_mutation_campaigns(
        plan=plan, campaigns=[], minimum_property_kill_score=0.95
    )
    name = "mutation_scorecard.schema.json"
    validator = Draft202012Validator(json.loads(rendered_schema(name, MODELS[name])))
    payload = score.model_dump(mode="json")
    validator.validate(payload)
    assert not validator.is_valid({**payload, "class_scores": payload["class_scores"][:-1]})
    assert not validator.is_valid({**payload, "schema_version": "1.0"})
    assert not validator.is_valid({**payload, "evidence_origin": "declarative"})


class _UnavailableSyntheticExecutor:
    def execute(
        self,
        *,
        baseline_workspace: Path,
        mutant_workspace: Path,
        specification: MutationSpecification,
    ) -> MutationSuiteObservation:
        assert type(specification) is PortfolioSourceMutationSpec
        assert baseline_workspace.is_dir() and mutant_workspace.is_dir()
        raise RuntimeError("synthetic selected suite unavailable")


@pytest.mark.parametrize("kind", list(SecurityMutationClass))
def test_owned_campaign_restores_and_disposes_new_spans_after_executor_failure(
    tmp_path: Path,
    kind: SecurityMutationClass,
) -> None:
    root = tmp_path / "campaign"
    root.mkdir(mode=0o700)
    plan = portfolio_plan()
    result = run_owned_mutation_campaign(
        source_repository=FIXTURE,
        private_root=root,
        plan=plan,
        mutation_id=specification(kind).id,
        executor=_UnavailableSyntheticExecutor(),
    )
    assert result.failure_kind == "RuntimeError"
    assert result.source_preserved and result.restoration_verified and result.workspace_disposed
    assert not tuple(root.iterdir())
    score = score_planned_mutation_campaigns(
        plan=plan,
        campaigns=[result],
        minimum_property_kill_score=0.95,
    )
    assert not score.gate_passed
    assert all(item.outcome is MutationTestOutcome.INCONCLUSIVE for item in score.outcomes)


def test_portfolio_maps_the_exact_eleven_frozen_requirements() -> None:
    document = json.loads(
        (Path(__file__).resolve().parents[2] / "docs/evaluation/benchmark_results.json").read_text()
    )
    requested = document["benchmark_layers"]["B_security_mutation_testing"][
        "requested_mutation_classes"
    ]
    mapping = {
        "removed authorization": SecurityMutationClass.AUTHORIZATION_REMOVAL,
        "removed nonce update": SecurityMutationClass.NONCE_UPDATE_REMOVAL,
        "changed rounding direction": SecurityMutationClass.ROUNDING_DIRECTION,
        "removed stale-price validation": SecurityMutationClass.STALE_PRICE_VALIDATION_REMOVAL,
        "external call reordered before state update": SecurityMutationClass.EXTERNAL_CALL_BEFORE_STATE_UPDATE,
        "removed initializer protection": SecurityMutationClass.INITIALIZER_PROTECTION_REMOVAL,
        "weakened timelock": SecurityMutationClass.TIMELOCK_WEAKENING,
        "changed storage slot": SecurityMutationClass.STORAGE_SLOT_CHANGE,
        "removed pause enforcement": SecurityMutationClass.PAUSE_ENFORCEMENT_REMOVAL,
        "unchecked return handling": SecurityMutationClass.UNCHECKED_RETURN_HANDLING,
        "incorrect decimal scale": SecurityMutationClass.INCORRECT_DECIMAL_SCALE,
    }
    assert [item["class"] for item in requested] == list(mapping)
    assert set(mapping.values()) == set(SecurityMutationClass) == set(CASES)
