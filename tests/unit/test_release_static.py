from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from pydantic import ValidationError

import mmaudit.release_static as static_module
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_static import StaticReleaseEvidence, collect_static_release_evidence

ROOT = Path(__file__).resolve().parents[2]


def _candidate() -> ReleaseCandidateObservation:
    payload = {
        "schema_version": "1.0",
        "generated_by": "mmaudit",
        "candidate_commit": "1" * 40,
        "git_object_format": "sha1",
        "candidate_tree_object": "2" * 40,
        "tracked_source_inventory_sha256": "3" * 64,
        "tracked_file_count": 1,
        "tracked_file_bytes": 1,
        "worktree_clean": True,
        "worktree_status_sha256": canonical_sha256([]),
        "observed_at": datetime(2026, 7, 28, tzinfo=UTC).isoformat().replace("+00:00", "Z"),
    }
    return ReleaseCandidateObservation.model_validate(
        {
            **payload,
            "observation_sha256": canonical_sha256(payload),
        }
    )


def test_static_release_inputs_are_validated_and_hash_bound() -> None:
    candidate = _candidate()
    with patch.object(
        static_module,
        "observe_release_candidate",
        return_value=candidate,
    ):
        evidence = collect_static_release_evidence(ROOT, candidate=candidate)

    assert evidence.candidate_commit == candidate.candidate_commit
    assert evidence.candidate_observation_sha256 == candidate.observation_sha256
    assert len(evidence.schemas) >= 1
    assert evidence.benchmark_source_bindings == 15
    assert evidence.model_cases >= 1
    assert evidence.economic_cases == 18
    assert evidence.adversarial_cases == 10
    assert evidence.full_protocol_files == 9
    assert evidence.evidence_sha256 == canonical_sha256(
        evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    )


def test_static_release_evidence_rejects_resealed_inventory_tampering() -> None:
    candidate = _candidate()
    with patch.object(
        static_module,
        "observe_release_candidate",
        return_value=candidate,
    ):
        evidence = collect_static_release_evidence(ROOT, candidate=candidate)
    payload = evidence.model_dump(mode="json")
    payload["schema_inventory_sha256"] = "0" * 64
    payload["evidence_sha256"] = canonical_sha256(
        {key: value for key, value in payload.items() if key != "evidence_sha256"}
    )

    with pytest.raises(ValidationError, match="schema inventory hash"):
        StaticReleaseEvidence.model_validate(payload)


def test_static_release_validation_rejects_linked_schema(
    tmp_path: Path,
) -> None:
    schema_root = tmp_path / "schemas"
    schema_root.mkdir(parents=True)
    target = tmp_path / "outside.json"
    target.write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "additionalProperties": False,
            }
        ),
        encoding="utf-8",
    )
    (schema_root / "linked.json").symlink_to(target)

    candidate = _candidate()
    with (
        patch.object(
            static_module,
            "observe_release_candidate",
            return_value=candidate,
        ),
        pytest.raises(ValueError, match=r"unshared regular file|opened safely"),
    ):
        collect_static_release_evidence(tmp_path, candidate=candidate)
