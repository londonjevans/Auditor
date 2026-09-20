"""Grammar regressions: implicit dependencies and malformed event/error statements cannot pass."""

from __future__ import annotations

import pytest

from tests.unit.test_development_dependency_syntax import body_sources, context_for


def test_implicit_modifier_invocation_cannot_be_a_successful_empty_call_census():
    path, raw = body_sources("return value;", extra="modifier guarded { _; }")[0]
    files = ((path, raw.replace(b"external returns", b"external guarded returns")),)
    context = context_for(files)
    assert context.sources[0].syntax_coverage == "NOT_ESTABLISHED"
    assert context.gaps
    assert not context.complete_static_resolution


@pytest.mark.parametrize(
    "body",
    [
        "emit value; return value;",
        "revert Missing;",
        "emit check(1) + check(2); return value;",
        "revert Missing + check(1);",
        "emit target.send{value: 1}(value); return value;",
    ],
)
def test_event_and_custom_error_statements_require_their_own_call_grammar(body):
    context = context_for(body_sources(body))
    assert context.sources[0].syntax_coverage == "NOT_ESTABLISHED"
    assert context.gaps


@pytest.mark.parametrize(
    "statement,kind",
    [
        ("emit Recorded(check(value)); return value;", "EVENT"),
        ("emit Events.Recorded(check(value)); return value;", "EVENT"),
        ("emit Recorded({amount: check(value)}); return value;", "EVENT"),
        ("revert Missing(check(value));", "ERROR"),
        ("revert Errors.Missing(check(value));", "ERROR"),
        ("revert Missing({amount: check(value)});", "ERROR"),
    ],
)
def test_event_and_custom_error_argument_calls_are_accounted(statement, kind):
    files = body_sources(
        statement, extra="event Recorded(uint256 amount); error Missing(uint256 amount);"
    )
    context = context_for(files)
    assert context.gaps == ()
    assert len(context.calls) == 3
    assert len([c for c in context.calls if c.kind == kind]) == 1
    assert not context.complete_static_resolution


@pytest.mark.parametrize("expression", ["+check(value)", "00", "01", "00.5"])
def test_unsupported_unary_or_numeric_forms_cannot_claim_accounted_grammar(expression):
    context = context_for(body_sources(f"return {expression};"))
    assert context.gaps and context.sources[0].syntax_coverage == "NOT_ESTABLISHED"
