from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from mmaudit.config import AuditConfig, PriorAuditConfig
from mmaudit.models.schemas import (
    CandidateFinding,
    LocationValidation,
    PriorAuditComparison,
    PriorAuditDiscoveryStatus,
    PriorAuditRemediationStatus,
)
from mmaudit.orchestration.prior_audit import (
    build_prior_audit_comparison,
    prior_audit_quality_gate,
    withhold_prior_audit_from_discovery,
)
from mmaudit.repository.discovery import DiscoveryResult, discover_repository
from mmaudit.repository.ignore import IgnoreMatcher


def _range_hash(path: Path, start_line: int, end_line: int) -> str:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    selected = "".join(lines[start_line - 1 : end_line])
    return hashlib.sha256(selected.encode()).hexdigest()


def _write_corpus(path: Path, findings: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"schema_version": "1.0", "findings": findings}),
        encoding="utf-8",
    )


def _comparison(
    root: Path,
    config: PriorAuditConfig,
    discovery: DiscoveryResult,
    *,
    candidates: list[CandidateFinding] | None = None,
    validations: dict[str, LocationValidation] | None = None,
) -> PriorAuditComparison:
    return build_prior_audit_comparison(
        repository_root=root,
        config=config,
        discovery=discovery,
        candidates=candidates or [],
        candidate_validations=validations or {},
        findings=[],
        model_request_count_before_load=7,
        prior_material_withheld_from_discovery=True,
    )


def test_prior_findings_are_withheld_then_rediscovered_with_unresolved_state(
    config_factory: Callable[..., AuditConfig],
    candidate_factory: Callable[..., CandidateFinding],
    vulnerable_repo: Path,
) -> None:
    prior_path = vulnerable_repo / "audit" / "prior.json"
    canary = "BLIND-PRIOR-CANARY"
    _write_corpus(
        prior_path,
        [
            {
                "prior_id": "PRIOR-001",
                "title": canary,
                "severity": "high",
                "cwe": ["CWE-89"],
                "previous_state": "open",
                "locations": [
                    {
                        "path": "app.py",
                        "start_line": 11,
                        "end_line": 14,
                        "historical_content_sha256": _range_hash(
                            vulnerable_repo / "app.py", 11, 14
                        ),
                    }
                ],
            }
        ],
    )
    config = config_factory(prior_audit={"path": "audit/prior.json"})
    unfiltered = discover_repository(
        vulnerable_repo,
        config.repository,
        IgnoreMatcher(),
    )
    assert "audit/prior.json" in {item.relative_path for item in unfiltered.files}

    discovery, withheld = withhold_prior_audit_from_discovery(
        unfiltered,
        config.prior_audit.path,
    )
    candidate = candidate_factory()
    comparison = _comparison(
        vulnerable_repo,
        config.prior_audit,
        discovery,
        candidates=[candidate],
        validations={candidate.candidate_id: LocationValidation(valid=True)},
    )

    assert withheld
    assert "audit/prior.json" not in {item.relative_path for item in discovery.files}
    assert canary not in "\n".join(item.content for item in discovery.files)
    assert all("audit/prior.json" not in item for item in discovery.omitted)
    assert comparison.loaded
    assert comparison.prior_material_withheld_from_discovery
    assert comparison.blind_discovery_completed_before_load
    assert comparison.model_request_count_before_load == 7
    assert comparison.items[0].discovery_status is PriorAuditDiscoveryStatus.REDISCOVERED
    assert comparison.items[0].remediation_status is PriorAuditRemediationStatus.UNRESOLVED
    assert comparison.items[0].matched_candidate_ids == ["candidate-1"]
    assert PriorAuditComparison.model_validate_json(comparison.model_dump_json()) == comparison


def test_prior_audit_allows_auditable_generic_parent_directory(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    path = "credentials/prior.json"
    _write_corpus(tmp_path / path, [])
    config = config_factory(prior_audit={"path": path})
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    discovery, withheld = withhold_prior_audit_from_discovery(
        discovery,
        config.prior_audit.path,
    )

    comparison = _comparison(tmp_path, config.prior_audit, discovery)

    assert withheld
    assert comparison.loaded


def test_remediation_and_discovery_states_are_independent_and_source_validated(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    source_states = {
        "safe.py": "safe implementation\n",
        "regressed.py": "historical unsafe condition\n",
        "changed.py": "independently changed implementation\n",
    }
    for name, content in source_states.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    safe_hash = _range_hash(tmp_path / "safe.py", 1, 1)
    regressed_hash = _range_hash(tmp_path / "regressed.py", 1, 1)
    _write_corpus(
        tmp_path / "audit" / "prior.json",
        [
            {
                "prior_id": "CHANGED",
                "title": "Changed finding",
                "severity": "medium",
                "previous_state": "open",
                "locations": [
                    {
                        "path": "changed.py",
                        "start_line": 1,
                        "end_line": 1,
                        "historical_content_sha256": "3" * 64,
                    }
                ],
            },
            {
                "prior_id": "OUTSIDE",
                "title": "Out-of-scope finding",
                "severity": "low",
                "previous_state": "open",
                "locations": [
                    {
                        "path": "not-audited.py",
                        "start_line": 1,
                        "end_line": 1,
                        "historical_content_sha256": "4" * 64,
                    }
                ],
            },
            {
                "prior_id": "REGRESSED",
                "title": "Regressed finding",
                "severity": "high",
                "previous_state": "remediated",
                "locations": [
                    {
                        "path": "regressed.py",
                        "start_line": 1,
                        "end_line": 1,
                        "historical_content_sha256": regressed_hash,
                        "remediated_content_sha256": "2" * 64,
                    }
                ],
            },
            {
                "prior_id": "REMEDIATED",
                "title": "Remediated finding",
                "severity": "high",
                "previous_state": "remediated",
                "locations": [
                    {
                        "path": "safe.py",
                        "start_line": 1,
                        "end_line": 1,
                        "historical_content_sha256": "1" * 64,
                        "remediated_content_sha256": safe_hash,
                    }
                ],
            },
        ],
    )
    config = config_factory(prior_audit={"path": "audit/prior.json"})
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    discovery, _ = withhold_prior_audit_from_discovery(
        discovery,
        config.prior_audit.path,
    )

    comparison = _comparison(tmp_path, config.prior_audit, discovery)
    items = {item.prior_id: item for item in comparison.items}

    assert items["CHANGED"].discovery_status is PriorAuditDiscoveryStatus.MISSED
    assert items["CHANGED"].remediation_status is PriorAuditRemediationStatus.CHANGED_UNVERIFIED
    assert items["OUTSIDE"].discovery_status is PriorAuditDiscoveryStatus.INCONCLUSIVE
    assert items["OUTSIDE"].remediation_status is PriorAuditRemediationStatus.INCONCLUSIVE
    assert not items["OUTSIDE"].source_valid
    assert items["REGRESSED"].discovery_status is PriorAuditDiscoveryStatus.MISSED
    assert items["REGRESSED"].remediation_status is PriorAuditRemediationStatus.REGRESSED
    assert items["REMEDIATED"].discovery_status is PriorAuditDiscoveryStatus.MISSED
    assert items["REMEDIATED"].remediation_status is PriorAuditRemediationStatus.REMEDIATED


@pytest.mark.parametrize(
    ("path", "expected_error"),
    [
        ("audit/malformed.json", "not valid JSON"),
        ("audit/credentials.json", "credential-like filename"),
    ],
)
def test_prior_parser_fails_safely_for_invalid_local_input(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
    path: str,
    expected_error: str,
) -> None:
    target = tmp_path / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not-json", encoding="utf-8")
    config = config_factory(prior_audit={"path": path})
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    discovery, _ = withhold_prior_audit_from_discovery(
        discovery,
        config.prior_audit.path,
    )

    comparison = _comparison(tmp_path, config.prior_audit, discovery)

    assert not comparison.loaded
    assert comparison.errors
    assert expected_error in comparison.errors[0]


def test_prior_parser_rejects_links_and_enforces_missed_gate(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.json"
    _write_corpus(source, [])
    link = tmp_path / "audit" / "prior.json"
    link.parent.mkdir()
    link.symlink_to(source)
    config = config_factory(
        prior_audit={
            "path": "audit/prior.json",
            "required": True,
            "fail_on_missed": True,
        }
    )
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    comparison = _comparison(tmp_path, config.prior_audit, discovery)

    assert not comparison.loaded
    assert "symlink" in comparison.errors[0]
    gate = prior_audit_quality_gate(comparison, config.prior_audit)
    assert gate.required
    assert not gate.passed
    assert gate.artifacts == ["prior-audit-comparison.json"]


def test_prior_schema_error_does_not_echo_untrusted_finding_text(
    config_factory: Callable[..., AuditConfig],
    tmp_path: Path,
) -> None:
    canary = "UNTRUSTED-PRIOR-NARRATIVE-CANARY"
    _write_corpus(
        tmp_path / "audit" / "prior.json",
        [
            {
                "prior_id": "INVALID",
                "title": canary,
                "severity": "not-a-severity",
                "previous_state": "open",
                "locations": [],
            }
        ],
    )
    config = config_factory(prior_audit={"path": "audit/prior.json"})
    discovery = discover_repository(tmp_path, config.repository, IgnoreMatcher())
    discovery, _ = withhold_prior_audit_from_discovery(
        discovery,
        config.prior_audit.path,
    )

    comparison = _comparison(tmp_path, config.prior_audit, discovery)

    assert comparison.errors == ["prior-audit input failed schema validation"]
    assert canary not in comparison.model_dump_json()


def test_prior_configuration_rejects_unsafe_paths_and_missing_required_input() -> None:
    with pytest.raises(ValidationError, match="safe repository-relative"):
        PriorAuditConfig(path="../outside.json")
    with pytest.raises(ValidationError, match="requires a configured path"):
        PriorAuditConfig(required=True)


def test_published_prior_audit_schema_is_strict_and_bounded() -> None:
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "prior_audit.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    finding = schema["properties"]["findings"]["items"]
    location = finding["properties"]["locations"]["items"]

    assert schema["additionalProperties"] is False
    assert schema["properties"]["findings"]["maxItems"] == 2_000
    assert finding["additionalProperties"] is False
    assert finding["properties"]["locations"]["maxItems"] == 100
    assert location["additionalProperties"] is False
    assert location["properties"]["historical_content_sha256"]["pattern"] == "^[0-9a-f]{64}$"
