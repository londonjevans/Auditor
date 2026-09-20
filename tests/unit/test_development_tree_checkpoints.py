"""Bounded closed-prefix projections and checkpoint namespace parsing, never paid execution."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mmaudit.orchestration import development_tree as module


def cases():
    """Only the private projection's record/list operations are exercised by these sentinels."""
    first = module._Case(1, None, None, None, [], records=[1, 2, 3], ends=[11, 12, 13])
    second = module._Case(2, None, None, None, [], records=[4, 5], ends=[14])
    return [first, second, module._UnstartedCase(3)]


@pytest.mark.parametrize("count", range(5))
def test_closed_prefix_preserves_every_original_slot_without_mutating_current_records(count):
    original = cases()
    projected = module._closed_prefix(original, count)
    assert [case.index for case in projected] == [1, 2, 3]
    assert [r for case in projected for r in case.records] == list(range(1, count + 1))
    assert [e for case in projected for e in case.ends] == list(range(11, 11 + count))
    assert original[0].records == [1, 2, 3] and original[0].ends == [11, 12, 13]
    assert original[1].records == [4, 5] and original[1].ends == [14]
    assert projected[-1].records == () and projected[-1].ends == ()
    for actual, previous in zip(projected, original, strict=True):
        if isinstance(actual, module._Case):
            assert actual.records is not previous.records
            assert actual.ends is not previous.ends


@pytest.mark.parametrize("count", [-1, 5, True, 1.0, "1", None])
def test_closed_prefix_rejects_invalid_or_unavailable_stage_counts(count):
    with pytest.raises(ValueError, match="prefix"):
        module._closed_prefix(cases(), count)


def test_closed_prefix_cannot_project_an_end_without_its_original_child():
    original = cases()
    original[0].records.clear()
    with pytest.raises(ValueError, match="prefix"):
        module._closed_prefix(original, 1)


def test_checkpoint_names_are_canonical_and_ordered(tmp_path):
    for name in ("plan.json", "cases", "progress-0768.json", "coverage-0000.json"):
        (tmp_path / name).touch()
    assert module._checkpoint_names(tmp_path) == (
        "coverage-0000.json",
        "progress-0768.json",
    )


@pytest.mark.parametrize(
    "name",
    [
        "progress-1.json",
        "progress--001.json",
        "progress-0769.json",
        "progress-0000.json.extra",
        "coverage-0000.txt",
        "coverage-9999.json",
        "unselected.json",
    ],
)
def test_checkpoint_names_refuse_foreign_or_unbounded_entries(tmp_path, name):
    (tmp_path / name).touch()
    with pytest.raises(ValueError, match="checkpoint"):
        module._checkpoint_names(tmp_path)


def test_checkpoint_enumeration_stops_and_closes_its_iterator_at_the_bound(tmp_path, monkeypatch):
    seen = []
    closed = []

    class Entries:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            closed.append(True)

        def __iter__(self):
            for index in range(100):
                seen.append(index)
                yield SimpleNamespace(name="plan.json")

    monkeypatch.setattr(module, "_MAX_CHECKPOINT_ROOT_ENTRIES", 2)
    monkeypatch.setattr(module, "os", SimpleNamespace(scandir=lambda _root: Entries()))
    with pytest.raises(ValueError, match="checkpoint"):
        module._checkpoint_names(tmp_path)
    assert seen == [0, 1, 2] and closed == [True]
