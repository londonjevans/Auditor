"""Synthetic live completion custody stays live only through the original journal path."""

from pathlib import Path

import pytest

from mmaudit.models.scheduler import SchedulerPassKind, SchedulerTaskOutput
from mmaudit.models.schemas import UsageRecord
from mmaudit.models.usage import is_creditable_usage_record
from mmaudit.reporting.json_report import stable_json
from tests.scheduler_support import (
    build_scheduler_test_model_payload,
    build_scheduler_test_real_usage,
)
from tests.unit import test_scheduler_journal as fixtures


@pytest.mark.parametrize("source", ("owned", "decoded", "copied"))
def test_live_output_preserves_only_an_original_usage_attestation(
    tmp_path: Path, source: str
) -> None:
    journal = fixtures.create_scheduler_journal(
        tmp_path / "original-owner",
        bindings=fixtures._bindings(with_audit_policy=True),
        shard_inventory=fixtures._inventory(),
    )
    try:
        plan = journal.seal_pass_plan(fixtures._plan(journal, SchedulerPassKind.ORIENTATION))
        task = plan.tasks[0]
        activation = journal.activate_task(
            task.task_id,
            actual_input_sha256=task.input_sha256,
            system_prompt_sha256=task.system_prompt_sha256,
            user_prompt_sha256="1" * 64,
            provider_prompt_sha256="2" * 64,
            response_schema_sha256=task.response_schema_sha256,
        )
        journal.mark_dispatched(task.task_id)
        payload = build_scheduler_test_model_payload(plan, task)
        original = build_scheduler_test_real_usage(
            task,
            activation,
            validated_output=payload,
            privacy_evidence_custody=journal.manifest.privacy_evidence_custody,
            audit_model_selection=journal.manifest.bindings.audit_model_selection,
            audit_model_refresh=journal.manifest.bindings.audit_model_refresh,
        )
        assert is_creditable_usage_record(original, require_real=True)
        supplied = (
            original
            if source == "owned"
            else (
                UsageRecord.model_validate_json(original.model_dump_json())
                if source == "decoded"
                else original.model_copy()
            )
        )
        assert is_creditable_usage_record(supplied, require_real=True) is (source == "owned")
        output = journal.persist_output(task.task_id, payload, usage_record=supplied)
        detached = SchedulerTaskOutput.model_validate_json(stable_json(output))
        assert detached.model_completion_evidence is not None
        assert not is_creditable_usage_record(
            detached.model_completion_evidence.usage_record, require_real=True
        )
        assert detached == output and stable_json(detached) == stable_json(output)
        for retained in (output, *journal.outputs):
            completion = retained.model_completion_evidence
            assert completion is not None and completion.usage_record == original
            # Named invariant: serialization never creates runtime execution authority.
            assert is_creditable_usage_record(completion.usage_record, require_real=True) is (
                source == "owned"
            )
    finally:
        journal.close()
