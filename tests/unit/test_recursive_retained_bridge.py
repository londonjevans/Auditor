"""Retained bridge records require exact closed-tree custody, never a successful bridge."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from decimal import Decimal
from typing import Any

import pytest

from mmaudit.models.schemas import (
    ExecutionEvidenceKind,
    ModelRequestValidationStatus,
    ModelSurfaceReviewStatus,
    UsageRecord,
)
from mmaudit.models.truncation import candidate_review_schema_algorithm_version
from mmaudit.models.truncation_closure import (
    TruncationRecoveredRecursiveSurfaceReviewArtifact,
    TruncationRecoveryBridgeAttemptEvidence,
    TruncationSurfaceOriginKind,
    _scheduler_canonical_sha256,
)
from mmaudit.orchestration.truncation_recovery_evidence import TruncationRecoveryEvidenceError
from tests.unit.test_truncation_recovery_evidence import (
    _recursive_tree_fixture,
    _verify_recursive_fixture,
)


@pytest.mark.parametrize("retained_count", [1, 2])
def test_retained_bridge_closes_only_its_exact_unfinished_partition(retained_count: int) -> None:
    fixture = _recursive_tree_fixture(bridge_retained_count=retained_count)
    _, artifact = _verify_recursive_fixture(fixture)
    retained = artifact.bridge.retained_surface_ids
    assert len(retained) == retained_count
    assert artifact.schema_version == artifact.bridge.schema_version == "1.1"
    assert artifact.bridge.usage_record.validation_status is ModelRequestValidationStatus.TRUNCATED
    bridge_result = next(
        result
        for result in fixture.root_results
        if result.child_logical_request_id == fixture.bridge_usage.request_id
    )
    assert bridge_result.runtime_output_artifact is None
    assert bridge_result.runtime_normalized_batch is None
    assert bridge_result.completed_surface_ids == ()
    nested = artifact.nested_recovery_plan
    assert nested.parent.retained_surface_ids == retained
    children = tuple(surface for child in nested.children for surface in child.surface_ids)
    assert set(children).isdisjoint(retained)
    assert set(children) | set(retained) == set(nested.parent.requested_surface_ids)
    assert len(children) == len(set(children)) == 2
    origins = tuple(origin for origin in artifact.origins if origin.surface_id in retained)
    assert len(origins) == retained_count
    assert all(
        origin.origin_kind is TruncationSurfaceOriginKind.PARENT_PROVISIONAL
        and origin.provisional is True
        and origin.request_id == fixture.bridge_usage.request_id
        and origin.generation_id == fixture.bridge_usage.openrouter_generation_id
        and origin.usage_record_sha256 == artifact.bridge.usage_record_sha256
        for origin in origins
    )
    assert artifact.accounting.provider_request_count == 5
    assert artifact.accounting.parent_cost_refunded is False
    usages = (fixture.parent_usage, fixture.bridge_usage, *fixture.leaf_usages)
    assert Decimal(artifact.accounting.family_accounted_cost_usd_exact) == sum(
        (Decimal(usage.accounted_cost_usd_exact or "NaN") for usage in usages), Decimal("0")
    )
    assert artifact.accounting.provider_attempt_count == sum(usage.attempts for usage in usages)
    assert artifact.accounting.completion_tokens == sum(usage.completion_tokens for usage in usages)
    assert artifact.provider_dispatch_authorized is artifact.coverage_credit_authorized is False
    assert artifact.completion_authorized is artifact.release_authorized is False


def test_original_zero_retained_private_data_remains_byte_exact() -> None:
    fixture = _recursive_tree_fixture()
    _, artifact = _verify_recursive_fixture(fixture)
    values = {
        "artifact": artifact,
        "bridge": artifact.bridge,
        "root_plan": artifact.recovery_plan,
        "nested_plan": artifact.nested_recovery_plan,
        "root_closure": fixture.root_closure,
        "nested_closure": fixture.nested_closure,
        "root_family": fixture.root_family,
        "nested_family": fixture.nested_family,
    }
    expected = {
        "artifact": "9f65bb038b2f92c28b2466bc24df6726e225066ec678975fcdcacb3958862f03",
        "bridge": "d3404063214eb7f0abe9def642a682b1236b6d8dd2683bf3415ec94d994b3213",
        "root_plan": "0a97cde38051dcf6a42ef8abdc6735e61a0336034a7094d0da86c2028630c766",
        "nested_plan": "75cf57d9c9a205d56bf81c0cc2c9d29c158c1bc3172fe93f70bd806d7cebf318",
        "root_closure": "abba1e2fdb37fb321b3c0aa5f18a4f03f7fe15ee1cea412c12f336d3ba5c0840",
        "nested_closure": "2eacdfa9aefb4e7bb430d9d6d6d6bc22536dd2850392776f9b2de03ff8285476",
        "root_family": "a2e26bdd4aefb2a16aef9d2dfbb1221d06eb1a65c096e2ee7a579e27302eb0fd",
        "nested_family": "8f9af0d620f476a7600fb930ac72c79d65a7c05bdaa93731b154e1a9a74cfa15",
    }
    assert {
        key: hashlib.sha256(value.model_dump_json().encode()).hexdigest()
        for key, value in values.items()
    } == expected


def _rehash(payload: dict[str, Any], field: str, artifact: Any) -> dict[str, Any]:
    projection = artifact.bridge.projection
    payload[field] = _scheduler_canonical_sha256(
        {key: value for key, value in payload.items() if key != field},
        algorithm_version=candidate_review_schema_algorithm_version(
            wire_schema_sha256=projection.wire_schema_sha256,
            normalized_batch_schema_sha256=projection.normalized_batch_schema_sha256,
        ),
    )
    return payload


@pytest.mark.parametrize(
    "mutation", ["legacy_version", "missing_id", "foreign_id", "hash", "duplicate"]
)
def test_bridge_rejects_rehashed_retention_inventory_drift(mutation: str) -> None:
    _, artifact = _verify_recursive_fixture(_recursive_tree_fixture(bridge_retained_count=2))
    payload = artifact.bridge.model_dump(mode="json")
    if mutation == "legacy_version":
        payload["schema_version"] = "1.0"
    elif mutation == "missing_id":
        payload["retained_surface_ids"] = []
    elif mutation == "foreign_id":
        payload["retained_surface_ids"][0] = artifact.parent.retained_surface_ids[0]
    elif mutation == "hash":
        payload["retained_surface_record_sha256s"][0] = "f" * 64
    else:
        payload["retained_surface_ids"] = [payload["retained_surface_ids"][0]] * 2
    with pytest.raises(ValueError, match="retained partition"):
        TruncationRecoveryBridgeAttemptEvidence.model_validate_json(
            json.dumps(_rehash(payload, "bridge_attempt_evidence_sha256", artifact))
        )


@pytest.mark.parametrize(
    "mutation",
    ["legacy_version", "algorithm", "request", "frame", "generation", "record", "missing_record"],
)
def test_recursive_comparison_rejects_rehashed_retained_record_or_origin_drift(
    mutation: str,
) -> None:
    _, artifact = _verify_recursive_fixture(_recursive_tree_fixture(bridge_retained_count=1))
    payload = artifact.model_dump(mode="json")
    bridge_id = artifact.bridge.retained_surface_ids[0]
    origin = next(item for item in payload["origins"] if item["surface_id"] == bridge_id)
    if mutation == "legacy_version":
        payload["schema_version"] = "1.0"
    elif mutation == "algorithm":
        payload["algorithm_version"] = "mmaudit.truncation-recursive-closure.v1"
    elif mutation == "request":
        origin["request_id"] = artifact.parent.parent_logical_request_id
    elif mutation == "frame":
        origin["accepted_frame_sha256"] = "f" * 64
    elif mutation == "generation":
        origin["generation_id"] = artifact.parent.envelope.generation_id
    elif mutation == "record":
        origin["record_sha256"] = "f" * 64
    else:
        payload["records"] = [
            item for item in payload["records"] if item["surface_id"] != bridge_id
        ]
    with pytest.raises(
        ValueError, match=r"exact tree custody|origins are inconsistent|gap or mutation"
    ):
        TruncationRecoveredRecursiveSurfaceReviewArtifact.model_validate_json(
            json.dumps(_rehash(payload, "artifact_sha256", artifact))
        )


@pytest.mark.parametrize(
    "mutation",
    ["serialized_bridge", "mock_bridge", "wrong_context", "missing_leaf", "retention_claim"],
)
def test_retained_bridge_never_bypasses_live_tree_custody(mutation: str) -> None:
    fixture = _recursive_tree_fixture(bridge_retained_count=1)
    if mutation == "serialized_bridge":
        fixture = replace(
            fixture,
            bridge_usage=UsageRecord.model_validate_json(fixture.bridge_usage.model_dump_json()),
        )
    elif mutation == "mock_bridge":
        fixture = replace(
            fixture,
            bridge_usage=fixture.bridge_usage.model_copy(
                update={"execution_evidence": ExecutionEvidenceKind.MOCK}
            ),
        )
    elif mutation == "wrong_context":
        fixture = replace(fixture, bridge_context=fixture.parent_context)
    elif mutation == "missing_leaf":
        fixture = replace(fixture, leaf_usages=fixture.leaf_usages[:-1])
    else:
        fixture = replace(
            fixture,
            root_results=tuple(
                result.model_copy(update={"retained_surface_ids": ()})
                if result.child_logical_request_id == fixture.bridge_usage.request_id
                else result
                for result in fixture.root_results
            ),
        )
    with pytest.raises(TruncationRecoveryEvidenceError):
        _verify_recursive_fixture(fixture)


def test_empty_bridge_cannot_claim_the_retained_evidence_version() -> None:
    _, artifact = _verify_recursive_fixture(_recursive_tree_fixture())
    payload = artifact.bridge.model_dump(mode="json")
    payload["schema_version"] = "1.1"
    with pytest.raises(ValueError, match="retained partition"):
        TruncationRecoveryBridgeAttemptEvidence.model_validate_json(
            json.dumps(_rehash(payload, "bridge_attempt_evidence_sha256", artifact))
        )


@pytest.mark.parametrize(
    "status", [ModelSurfaceReviewStatus.INCONCLUSIVE, ModelSurfaceReviewStatus.NOT_REVIEWED]
)
def test_complete_but_noncreditable_bridge_frame_cannot_close_coverage(
    monkeypatch: pytest.MonkeyPatch, status: ModelSurfaceReviewStatus
) -> None:
    from tests.unit import test_truncation_recovery_evidence as support

    fixture = _recursive_tree_fixture(bridge_retained_count=1)
    bridge_id = fixture.nested_family.recovery_plan.parent.retained_surface_ids[0]
    original_record = support._record

    def noncreditable_record(request: Any, **kwargs: Any) -> Any:
        record = original_record(request, **kwargs)
        return (
            record.model_copy(update={"status": status})
            if request.surface_id == bridge_id
            else record
        )

    monkeypatch.setattr(support, "_record", noncreditable_record)
    rejected = _recursive_tree_fixture(bridge_retained_count=1)
    records = rejected.nested_family.truncation_projection.surface_reviews
    assert len(records) == 1
    assert records[0].status is status
    with pytest.raises(TruncationRecoveryEvidenceError):
        _verify_recursive_fixture(rejected)
