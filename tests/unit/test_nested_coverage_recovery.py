"""Versioned coverage-only data cannot erase findings liability or original ancestry."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Literal, cast

import pytest

import mmaudit.models.truncation_recovery_journal as protocol
from mmaudit.models.schemas import ContextPackage
from mmaudit.models.truncation import CandidateReviewChannelState
from mmaudit.models.truncation_recovery import TruncationRecoveryChannel
from mmaudit.models.truncation_recovery_journal import (
    SchedulerTruncationRecoveryChildActivation,
    SchedulerTruncationRecoveryChildResult,
    SchedulerTruncationRecoveryFamilyRoot,
    resolve_truncation_recovery_root_family,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.pipeline import _build_nested_truncation_recovery_plan
from mmaudit.reporting.json_report import stable_json_bytes
from tests.nested_coverage_support import NestedCoverageCase, nested_coverage_case

LEGACY_PATH = Path(__file__).parents[1] / "fixtures/nested_coverage/legacy_family_v1.json"


def _rebuild_family(
    family: SchedulerTruncationRecoveryFamilyRoot,
    version: Literal["1.0", "1.1"] | None = None,
) -> SchedulerTruncationRecoveryFamilyRoot:
    values: dict[str, Any] = {
        name: getattr(family, name)
        for name in (
            "request_limit_binding",
            "family_index",
            "parent_kind",
            "parent_family_id",
            "parent_terminal_result_sha256",
            "requested_surface_manifest",
            "truncation_projection",
            "recovery_plan",
            "request_count_before_family",
            "request_limit_count_before_family",
            "entry_index",
            "previous_entry_sha256",
        )
    }
    if version is not None:
        values["schema_version"] = version
    return SchedulerTruncationRecoveryFamilyRoot.build(**values)


def test_default_factory_preserves_exact_prechange_v1_fixture_bytes() -> None:
    raw = LEGACY_PATH.read_bytes()
    assert (
        hashlib.sha256(raw).hexdigest()
        == "0dc1427e670f10faa1b12649baca8e13b7dd0c169f2835204a4b8dbf5be022ba"
    )
    legacy = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(raw, strict=True)
    assert stable_json_bytes(_rebuild_family(legacy)) == raw
    assert stable_json_bytes(_rebuild_family(legacy, "1.0")) == raw


def test_family_schema_exposes_only_the_two_explicit_versions() -> None:
    field = SchedulerTruncationRecoveryFamilyRoot.model_json_schema()["properties"][
        "schema_version"
    ]
    assert field["enum"] == ["1.0", "1.1"]
    assert field["default"] == "1.0"


def test_coverage_only_version_cannot_reclassify_a_complete_root() -> None:
    legacy = SchedulerTruncationRecoveryFamilyRoot.model_validate_json(
        LEGACY_PATH.read_bytes(), strict=True
    )
    with pytest.raises(ValueError, match=r"v1\.1 nested coverage"):
        _rebuild_family(legacy, "1.1")


@pytest.fixture(
    scope="module", params=(CandidateReviewChannelState.OPEN, CandidateReviewChannelState.INVALID)
)
def coverage_case(
    request: pytest.FixtureRequest, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[NestedCoverageCase]:
    path = tmp_path_factory.mktemp("original-nested-coverage-unit") / "journal"
    with nested_coverage_case(path, request.param) as case:
        yield case


@pytest.fixture
def coverage_family(coverage_case: NestedCoverageCase) -> SchedulerTruncationRecoveryFamilyRoot:
    case = coverage_case
    entries = case.journal.truncation_recovery_entries
    return SchedulerTruncationRecoveryFamilyRoot.build(
        schema_version="1.1",
        request_limit_binding=case.root.request_limit_binding,
        family_index=1,
        parent_kind=protocol.SchedulerTruncationRecoveryParentKind.RECOVERY_CHILD,
        parent_family_id=case.root.family_id,
        parent_terminal_result_sha256=case.bridge_result.entry_sha256,
        requested_surface_manifest=case.manifest,
        truncation_projection=case.projection,
        recovery_plan=case.plan,
        request_count_before_family=case.root.request_count_after_family,
        request_limit_count_before_family=case.root.request_limit_count_after_family,
        entry_index=len(entries),
        previous_entry_sha256=entries[-1].entry_sha256,
    )


def _resolve(
    case: NestedCoverageCase,
    family: SchedulerTruncationRecoveryFamilyRoot,
    *,
    missing_sibling: bool = False,
) -> SchedulerTruncationRecoveryFamilyRoot:
    entries = case.journal.truncation_recovery_entries
    activations = {
        e.child_task_id: e
        for e in entries
        if isinstance(e, SchedulerTruncationRecoveryChildActivation)
    }
    results = {
        e.child_task_id: e for e in entries if isinstance(e, SchedulerTruncationRecoveryChildResult)
    }
    if missing_sibling:
        results.pop(case.leaf_result.child_task_id)
    return resolve_truncation_recovery_root_family(
        family=family,
        families={case.root.family_id: case.root},
        activations=activations,
        results=results,
        closures={},
    )


def test_new_family_identity_is_distinct_and_legacy_downgrade_still_refuses_ancestry(
    coverage_case: NestedCoverageCase, coverage_family: SchedulerTruncationRecoveryFamilyRoot
) -> None:
    legacy = _rebuild_family(coverage_family)
    assert legacy.schema_version == "1.0"
    assert legacy.family_id != coverage_family.family_id
    assert legacy.entry_sha256 != coverage_family.entry_sha256
    assert legacy.recovery_plan == coverage_family.recovery_plan
    assert _resolve(coverage_case, coverage_family) == coverage_case.root
    with pytest.raises(ValueError, match="ancestry differs"):
        _resolve(coverage_case, legacy)


@pytest.mark.parametrize(
    "mutation",
    (
        "unknown_version",
        "complete_findings",
        "not_started_findings",
        "missing_liability",
        "wrong_channel",
        "wrong_parent",
        "wrong_terminal",
        "wrong_activation",
        "missing_sibling",
    ),
)
def test_new_scope_cannot_bypass_original_ancestry(
    coverage_case: NestedCoverageCase,
    coverage_family: SchedulerTruncationRecoveryFamilyRoot,
    mutation: str,
) -> None:
    family = coverage_family
    if mutation == "unknown_version":
        family = family.model_copy(update={"schema_version": "2.0"})
    elif mutation in {"complete_findings", "not_started_findings"}:
        family = family.model_copy(
            update={
                "truncation_projection": family.truncation_projection.model_copy(
                    update={
                        "findings_state": CandidateReviewChannelState.COMPLETE
                        if mutation == "complete_findings"
                        else CandidateReviewChannelState.NOT_STARTED
                    }
                )
            }
        )
    elif mutation == "missing_liability":
        family = family.model_copy(
            update={
                "recovery_plan": family.recovery_plan.model_copy(
                    update={"irreducible_channels": ()}
                )
            }
        )
    elif mutation == "wrong_channel":
        children = family.recovery_plan.children
        first = children[0].model_copy(update={"channel": TruncationRecoveryChannel.FINDINGS})
        family = family.model_copy(
            update={
                "recovery_plan": family.recovery_plan.model_copy(
                    update={"children": (first, children[1])}
                )
            }
        )
    elif mutation == "wrong_parent":
        family = family.model_copy(
            update={"parent_family_id": "scheduler-recovery-family-" + "0" * 64}
        )
    elif mutation == "wrong_terminal":
        family = family.model_copy(update={"parent_terminal_result_sha256": "0" * 64})
    elif mutation == "wrong_activation":
        parent = family.recovery_plan.parent.model_copy(
            update={"parent_activation_sha256": "0" * 64}
        )
        family = family.model_copy(
            update={"recovery_plan": family.recovery_plan.model_copy(update={"parent": parent})}
        )
    with pytest.raises(ValueError):
        _resolve(coverage_case, family, missing_sibling=mutation == "missing_sibling")


@pytest.mark.parametrize("mode", (False, None, 0, 1, "true"))
def test_planner_refuses_incomplete_findings_without_an_exact_explicit_coverage_mode(
    coverage_case: NestedCoverageCase, mode: Any
) -> None:
    case = coverage_case
    with pytest.raises(ValueError, match="outside the bounded investigator slice"):
        _build_nested_truncation_recovery_plan(
            journal=case.journal,
            parent_family=case.root,
            parent_child=case.root.recovery_plan.children[0],
            parent_result=case.bridge_result,
            parent_context=cast(ContextPackage, None),
            atomic_ledger=cast(AtomicCostLedger, None),
            coverage_only=mode,
        )


@pytest.mark.parametrize("mode", (False, True))
def test_planner_never_admits_not_started_findings(
    coverage_case: NestedCoverageCase, mode: bool
) -> None:
    case = coverage_case
    projection = case.projection.model_copy(
        update={"findings_state": CandidateReviewChannelState.NOT_STARTED}
    )
    result = case.bridge_result.model_copy(update={"truncation_projection": projection})
    with pytest.raises(ValueError, match="outside the bounded investigator slice"):
        _build_nested_truncation_recovery_plan(
            journal=case.journal,
            parent_family=case.root,
            parent_child=case.root.recovery_plan.children[0],
            parent_result=result,
            parent_context=cast(ContextPackage, None),
            atomic_ledger=cast(AtomicCostLedger, None),
            coverage_only=mode,
        )


@pytest.mark.parametrize(
    "field",
    (
        "provider_dispatch_authorized",
        "review_credit_authorized",
        "coverage_credit_authorized",
        "completion_authorized",
        "release_authorized",
    ),
)
def test_rehashed_coverage_family_cannot_claim_authority(
    coverage_family: SchedulerTruncationRecoveryFamilyRoot, field: str
) -> None:
    payload = coverage_family.model_dump(mode="json")
    assert (
        protocol._entry_body_sha256({k: v for k, v in payload.items() if k != "entry_sha256"})
        == payload["entry_sha256"]
    )
    payload[field] = True
    payload["entry_sha256"] = protocol._entry_body_sha256(
        {k: v for k, v in payload.items() if k != "entry_sha256"}
    )
    with pytest.raises(ValueError):
        SchedulerTruncationRecoveryFamilyRoot.model_validate_json(json.dumps(payload), strict=True)
