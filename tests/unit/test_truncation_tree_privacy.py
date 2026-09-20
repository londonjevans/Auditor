"""Exact pre-campaign privacy bytes over comment-only local source; no provider execution."""

import hashlib
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from mmaudit.orchestration import manifest, pipeline
from mmaudit.orchestration.assurance import AssuranceRuntime
from mmaudit.privacy import PrivacyProfile, PrivacySourceClassification
from mmaudit.reporting.json_report import stable_json
from mmaudit.repository.privacy_provenance import validate_privacy_source_provenance_observation
from tests.truncation_tree_manifest_support import (
    build_review_manifest_report,
    build_review_privacy_fixture,
    build_review_source_fixture,
)
from tests.unit import test_assurance as assurance


@pytest.fixture
def privacy_inputs(config_factory: Any, tmp_path: Path) -> tuple[Any, ...]:
    config = assurance._maximum_config(
        lambda **sections: config_factory(**sections, execution={"budget_usd": 250})
    )
    source = build_review_source_fixture()
    now = datetime.now(UTC).replace(microsecond=0)
    privacy = build_review_privacy_fixture(config, source, tmp_path / "run", now=now)
    report = build_review_manifest_report(
        config,
        source,
        AssuranceRuntime(index=source.index, graphs=source.graphs, invariants=source.invariants),
        "250",
        privacy=privacy,
    )
    return config, source, privacy, report, now


def test_privacy_builder_binds_real_private_files_before_any_journal_exists(
    privacy_inputs: tuple[Any, ...],
) -> None:
    config, source, privacy, report, _ = privacy_inputs
    custody = privacy.custody
    assert privacy.provenance == validate_privacy_source_provenance_observation(
        privacy.observation,
        source_sha256=source.scheduler_shards.source_tree_sha256,
        source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
    )
    assert privacy.provenance.proof_kind == "PRIVATE_DEFAULT"
    assert privacy.provenance.committed_file_count == 0
    assert privacy.provenance.provider_visible_case_count == 0
    assert privacy.policy.privacy_profile is PrivacyProfile.STRICT_ZDR
    assert privacy.policy.require_zdr and privacy.policy.data_collection == "deny"
    assert privacy.policy.consent_sha256 is None
    assert float(privacy.policy.requested_budget_usd) == config.execution.budget_usd == 250
    assert not (privacy.run_directory / "private" / "scheduler-journal").exists()
    for name, evidence, size, sha in (
        (
            custody.source_provenance_path,
            privacy.provenance,
            custody.source_provenance_size,
            custody.source_provenance_artifact_sha256,
        ),
        (
            custody.effective_policy_path,
            privacy.policy,
            custody.effective_policy_size,
            custody.effective_policy_artifact_sha256,
        ),
    ):
        path = privacy.run_directory / name
        raw = path.read_bytes()
        assert raw == stable_json(evidence).encode("utf-8")
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == sha
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    manifest._validate_scheduler_privacy_artifacts(
        root=privacy.run_directory, report=report, custody=custody
    )
    manifest.validate_report_privacy_consistency(
        report,
        source_tree_sha256=source.scheduler_shards.source_tree_sha256,
        expected_source_classification=PrivacySourceClassification.PRIVATE_OPERATOR_SOURCE,
    )
    assert not report.completed and report.usage == []


@pytest.mark.parametrize("name", ("privacy-source-provenance.json", "privacy-policy.json"))
@pytest.mark.parametrize("alteration", ("missing", "whitespace", "same_size", "symlink"))
def test_exact_privacy_custody_refuses_missing_changed_or_replaced_files(
    privacy_inputs: tuple[Any, ...], name: str, alteration: str
) -> None:
    _, _, privacy, report, _ = privacy_inputs
    path = privacy.run_directory / name
    original = path.read_bytes()
    if alteration == "missing":
        path.unlink()
    elif alteration == "whitespace":
        path.write_bytes(original + b"\n")
    elif alteration == "same_size":
        changed = original.replace(b"PRIVATE_OPERATOR_SOURCE", b"PRIVATX_OPERATOR_SOURCE", 1)
        assert changed != original and len(changed) == len(original)
        path.write_bytes(changed)
    else:
        target = path.with_suffix(".retained-json")
        path.rename(target)
        path.symlink_to(target.name)
    # Named invariant: equal declarations or parseable JSON never replace original file custody.
    with pytest.raises(ValueError):
        pipeline._build_scheduler_privacy_evidence_custody(
            privacy.run_directory, provenance=privacy.provenance, policy=privacy.policy
        )
    with pytest.raises(ValueError):
        manifest._validate_scheduler_privacy_artifacts(
            root=privacy.run_directory, report=report, custody=privacy.custody
        )


@pytest.mark.parametrize("field", ("source_provenance", "effective_policy"))
def test_privacy_files_reject_other_valid_reported_evidence(
    privacy_inputs: tuple[Any, ...], field: str
) -> None:
    config, source, privacy, report, now = privacy_inputs
    other = build_review_privacy_fixture(
        config, source, privacy.run_directory.parent / "other-run", now=now + timedelta(seconds=1)
    )
    changed = report.model_copy(
        update={"privacy": report.privacy | {field: other.report_payload()[field]}}
    )
    with pytest.raises(ValueError, match="differs from the final report"):
        manifest._validate_scheduler_privacy_artifacts(
            root=privacy.run_directory, report=changed, custody=privacy.custody
        )


def test_present_invalid_final_manifest_cannot_fall_back_to_pre_manifest_privacy(
    privacy_inputs: tuple[Any, ...],
) -> None:
    _, _, privacy, report, _ = privacy_inputs
    (privacy.run_directory / "run-evidence-manifest.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        manifest._validate_scheduler_privacy_artifacts(
            root=privacy.run_directory, report=report, custody=privacy.custody
        )


def test_privacy_fixture_refuses_to_overwrite_an_existing_campaign_policy(
    privacy_inputs: tuple[Any, ...],
) -> None:
    config, source, privacy, _, now = privacy_inputs
    original = {
        path.name: path.read_bytes() for path in privacy.run_directory.iterdir() if path.is_file()
    }
    with pytest.raises(AssertionError, match="fresh original campaign"):
        build_review_privacy_fixture(config, source, privacy.run_directory, now=now)
    assert original == {
        path.name: path.read_bytes() for path in privacy.run_directory.iterdir() if path.is_file()
    }
