"""Original saved scheduler trees roundtrip as comparison data, never live authority."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from mmaudit.models.scheduler import SchedulerArtifact, SchedulerPassKind
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryFullTreeBinding
from mmaudit.orchestration import manifest
from mmaudit.orchestration.scheduler import (
    require_verified_promoted_recursive_truncation_recovery_surface_coverage,
)
from tests.integration.test_truncation_tree_manifest_files import _write_model
from tests.integration.test_truncation_tree_manifest_files import (
    no_provider_or_operator_secrets as no_provider_or_operator_secrets,
)
from tests.unit.test_truncation_tree_consumers import public_tree as public_tree
from tests.unit.test_truncation_tree_promotion import promoted_tree as promoted_tree


@pytest.fixture(scope="module")
def original_scheduler(public_tree: tuple[Any, Any]) -> SchedulerArtifact:
    fixture, _token = public_tree
    fixture.journal.seal_pass_result(SchedulerPassKind.BLIND_SHARD_REVIEW)
    artifact = fixture.journal.artifact()
    promotions = [
        promotion
        for result in artifact.summary.pass_results
        for promotion in result.recovery_promotion_bindings
    ]
    assert len(promotions) == 1 and promotions[0].schema_version == "1.2"
    assert promotions[0].full_tree_binding is not None
    assert len(promotions[0].full_tree_binding.child_result_sha256s) == 6
    return artifact


def test_original_saved_scheduler_tree_roundtrip_is_comparison_only(
    original_scheduler: SchedulerArtifact, tmp_path: Path
) -> None:
    path = tmp_path / "scheduler-state.json"
    _write_model(path, original_scheduler)
    original_bytes = path.read_bytes()
    decoded = manifest._load_scheduler_artifact(tmp_path)
    assert decoded == original_scheduler
    assert decoded.model_dump_json() == original_scheduler.model_dump_json()
    assert decoded.evidence_authority == "comparison_required"
    assert path.read_bytes() == original_bytes
    # Named invariant: saved evidence cannot become the original live recovery capability.
    with pytest.raises(ValueError):
        require_verified_promoted_recursive_truncation_recovery_surface_coverage(decoded)


def test_full_tree_python_validation_still_refuses_json_lists(
    original_scheduler: SchedulerArtifact,
) -> None:
    tree = next(
        promotion.full_tree_binding
        for result in original_scheduler.summary.pass_results
        for promotion in result.recovery_promotion_bindings
    )
    assert tree is not None
    with pytest.raises(ValidationError, match="valid tuple"):
        SchedulerTruncationRecoveryFullTreeBinding.model_validate(tree.model_dump(mode="json"))


def _tree_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return next(
        promotion["full_tree_binding"]
        for result in payload["summary"]["pass_results"]
        for promotion in result.get("recovery_promotion_bindings", [])
    )


@pytest.mark.parametrize(
    "field",
    (
        "family_root_sha256s",
        "family_closure_sha256s",
        "child_result_sha256s",
        "bridge_result_sha256s",
        "leaf_result_sha256s",
    ),
)
@pytest.mark.parametrize("mutation", ("duplicate", "empty", "string", "number", "missing"))
def test_saved_full_tree_inventories_remain_strict_and_complete(
    original_scheduler: SchedulerArtifact, tmp_path: Path, field: str, mutation: str
) -> None:
    payload = original_scheduler.model_dump(mode="json")
    tree = _tree_payload(payload)
    if mutation == "duplicate":
        tree[field].append(tree[field][0])
    elif mutation == "empty":
        tree[field] = []
    elif mutation == "string":
        tree[field] = tree[field][0]
    elif mutation == "number":
        tree[field][0] = 7
    else:
        del tree[field]
    path = tmp_path / "scheduler-state.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError) as refused:
        manifest._load_scheduler_artifact(tmp_path)
    assert any("full_tree_binding" in error["loc"] for error in refused.value.errors())


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
@pytest.mark.parametrize("value", (True, "false", None))
def test_saved_tree_cannot_change_or_coerce_false_authority(
    original_scheduler: SchedulerArtifact, tmp_path: Path, field: str, value: object
) -> None:
    payload = original_scheduler.model_dump(mode="json")
    _tree_payload(payload)[field] = value
    (tmp_path / "scheduler-state.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError) as refused:
        manifest._load_scheduler_artifact(tmp_path)
    assert any(error["loc"][-1] == field for error in refused.value.errors())


@pytest.mark.parametrize("mutation", ("hash", "extra_field"))
def test_saved_scheduler_hash_and_unknown_field_checks_remain_required(
    original_scheduler: SchedulerArtifact, tmp_path: Path, mutation: str
) -> None:
    payload = original_scheduler.model_dump(mode="json")
    if mutation == "hash":
        payload["artifact_sha256"] = "0" * 64
    else:
        payload["live_scheduler_authority"] = True
    (tmp_path / "scheduler-state.json").write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValidationError):
        manifest._load_scheduler_artifact(tmp_path)


@pytest.mark.parametrize(
    ("raw", "message"),
    (
        (b'{"schema_version":"1.0","schema_version":"1.0"}', "duplicate keys"),
        (b'{"value":NaN}', "non-finite"),
        (b'{"value":1e9999}', "out-of-range"),
        (b"[]", "must contain an object"),
        (b"\xff", "not valid UTF-8 JSON"),
    ),
)
def test_scheduler_loader_preserves_the_bounded_unique_json_reader(
    tmp_path: Path, raw: bytes, message: str
) -> None:
    (tmp_path / "scheduler-state.json").write_bytes(raw)
    with pytest.raises(ValueError, match=message):
        manifest._load_scheduler_artifact(tmp_path)


@pytest.mark.parametrize("link_kind", ("symlink", "hardlink"))
def test_scheduler_loader_refuses_linked_original_artifact(
    original_scheduler: SchedulerArtifact, tmp_path: Path, link_kind: str
) -> None:
    target = tmp_path / "original.json"
    _write_model(target, original_scheduler)
    linked = tmp_path / "scheduler-state.json"
    if link_kind == "symlink":
        linked.symlink_to(target)
    else:
        linked.hardlink_to(target)
    with pytest.raises(ValueError, match=r"link|bounded unique regular file"):
        manifest._load_scheduler_artifact(tmp_path)
