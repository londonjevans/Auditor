from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.economic_acceptance import (
    EconomicAcceptanceManifest,
    EconomicAcceptanceObservation,
    EconomicAcceptanceReport,
    EconomicAcceptanceStatus,
    build_economic_acceptance_report,
    load_economic_acceptance_manifest,
    write_economic_acceptance_report,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "tests" / "fixtures" / "solidity" / "maximum_assurance_economic" / "manifest.json"


def _manifest() -> EconomicAcceptanceManifest:
    return load_economic_acceptance_manifest(MANIFEST, repository_root=ROOT)


def _complete_observations(
    manifest: EconomicAcceptanceManifest,
) -> list[EconomicAcceptanceObservation]:
    return [
        EconomicAcceptanceObservation(
            ticket_id=case.ticket_id,
            first_unsafe_contracts_executed=case.unsafe_contracts,
            first_unsafe_counterexamples=case.unsafe_contracts,
            second_unsafe_contracts_executed=case.unsafe_contracts,
            second_unsafe_counterexamples=case.unsafe_contracts,
            safe_contracts_executed=case.safe_contracts,
            safe_contracts_passed=case.safe_contracts,
        )
        for case in manifest.cases
    ]


def _copy_manifest_fixtures(
    tmp_path: Path,
    manifest: EconomicAcceptanceManifest,
) -> Path:
    repository = tmp_path / "repository"
    for case in manifest.cases:
        source = ROOT / case.fixture_path
        destination = repository / case.fixture_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(source, destination)
    return repository


def test_manifest_is_source_bound_and_covers_the_economic_portfolio() -> None:
    manifest = _manifest()

    assert [case.ticket_id for case in manifest.cases] == [
        f"ECO-{index:03d}" for index in range(1, 19)
    ]
    assert len({case.fixture_path for case in manifest.cases}) == 18
    assert sum(len(case.unsafe_contracts) for case in manifest.cases) == 21
    assert sum(len(case.safe_contracts) for case in manifest.cases) == 22


def test_complete_observations_build_stable_passing_report(tmp_path: Path) -> None:
    manifest = _manifest()
    report = build_economic_acceptance_report(
        manifest,
        _complete_observations(manifest),
    )

    assert report.status is EconomicAcceptanceStatus.PASSED
    assert report.total_cases == 18
    assert report.applicable_harnesses == report.executed_harnesses == 43
    assert report.planted_issues == report.reproduced_issues == 21
    assert report.safe_near_misses == report.unconfirmed_safe_near_misses == 22
    assert all(item.all_applicable_harnesses_executed for item in report.outcomes)
    assert all(item.replay_confirmed for item in report.outcomes)
    assert all(item.safe_near_misses_remain_unconfirmed for item in report.outcomes)

    output = tmp_path / "economic-acceptance.json"
    write_economic_acceptance_report(output, report)
    reloaded = EconomicAcceptanceReport.model_validate_json(output.read_text(encoding="utf-8"))
    assert reloaded == report
    assert reloaded.report_sha256 == report.report_sha256


def test_missing_reproduction_fails_without_hiding_harness_execution() -> None:
    manifest = _manifest()
    observations = _complete_observations(manifest)
    first = observations[0]
    observations[0] = first.model_copy(
        update={"second_unsafe_counterexamples": first.second_unsafe_counterexamples[1:]}
    )

    report = build_economic_acceptance_report(manifest, observations)

    assert report.status is EconomicAcceptanceStatus.FAILED
    assert report.executed_harnesses == report.applicable_harnesses
    assert report.reproduced_issues == report.planted_issues - 1
    assert report.outcomes[0].all_applicable_harnesses_executed
    assert not report.outcomes[0].replay_confirmed
    assert not report.outcomes[0].passed


def test_unknown_or_unexecuted_observation_is_rejected() -> None:
    manifest = _manifest()
    observations = _complete_observations(manifest)
    observations[0] = observations[0].model_copy(
        update={"first_unsafe_counterexamples": ["UnknownInvariant"]}
    )
    with pytest.raises(ValueError, match="unknown contract"):
        build_economic_acceptance_report(manifest, observations)

    observations = _complete_observations(manifest)
    observations[0] = observations[0].model_copy(update={"first_unsafe_contracts_executed": []})
    with pytest.raises(ValueError, match="did not execute"):
        build_economic_acceptance_report(manifest, observations)


def test_manifest_and_report_tampering_are_rejected(tmp_path: Path) -> None:
    manifest_payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    manifest_payload["cases"][0]["template"] = "rounding_exploitation"
    tampered_manifest = tmp_path / "manifest.json"
    tampered_manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
    with pytest.raises(ValidationError, match="manifest hash"):
        load_economic_acceptance_manifest(tampered_manifest, repository_root=ROOT)

    manifest = _manifest()
    report = build_economic_acceptance_report(
        manifest,
        _complete_observations(manifest),
    )
    report_payload = report.model_dump(mode="json")
    report_payload["executed_harnesses"] = 0
    with pytest.raises(ValidationError, match="totals"):
        EconomicAcceptanceReport.model_validate(report_payload)


def test_fixture_hash_drift_and_links_are_rejected(tmp_path: Path) -> None:
    manifest = _manifest()
    repository = _copy_manifest_fixtures(tmp_path, manifest)
    first = manifest.cases[0]
    source = repository / first.fixture_path / first.source_path
    source.write_text(source.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="source hash mismatch"):
        load_economic_acceptance_manifest(MANIFEST, repository_root=repository)

    repository = _copy_manifest_fixtures(tmp_path / "linked", manifest)
    linked_source = repository / first.fixture_path / first.source_path
    link_target = tmp_path / "linked-source.sol"
    shutil.copy2(linked_source, link_target)
    linked_source.unlink()
    linked_source.symlink_to(link_target)
    with pytest.raises(ValueError, match="links"):
        load_economic_acceptance_manifest(MANIFEST, repository_root=repository)

    manifest_link = tmp_path / "manifest-link.json"
    manifest_link.symlink_to(MANIFEST)
    with pytest.raises(ValueError, match="regular non-link"):
        load_economic_acceptance_manifest(manifest_link, repository_root=ROOT)


def test_report_writer_rejects_link_destination(tmp_path: Path) -> None:
    manifest = _manifest()
    report = build_economic_acceptance_report(
        manifest,
        _complete_observations(manifest),
    )
    real_output = tmp_path / "real.json"
    real_output.write_text("{}\n", encoding="utf-8")
    linked_output = tmp_path / "linked.json"
    linked_output.symlink_to(real_output)

    with pytest.raises(ValueError, match="may not be a link"):
        write_economic_acceptance_report(linked_output, report)


def test_manifest_and_report_schemas_are_strict_and_complete() -> None:
    manifest_schema = json.loads(
        (ROOT / "schemas/economic_acceptance_manifest.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (ROOT / "schemas/economic_acceptance_report.schema.json").read_text(encoding="utf-8")
    )

    assert manifest_schema["additionalProperties"] is False
    assert manifest_schema["$defs"]["case"]["additionalProperties"] is False
    assert manifest_schema["properties"]["cases"]["minItems"] == 18
    assert report_schema["additionalProperties"] is False
    assert report_schema["$defs"]["outcome"]["additionalProperties"] is False
    assert report_schema["properties"]["outcomes"]["minItems"] == 18
    assert set(report_schema["required"]) == set(EconomicAcceptanceReport.model_fields)
