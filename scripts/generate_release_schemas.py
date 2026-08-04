"""Generate or verify the typed release-evidence JSON schemas."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from mmaudit.benchmark.engine import BenchmarkReport
from mmaudit.config import ModelsConfig
from mmaudit.forensic_export import ForensicDeliveryDescriptor
from mmaudit.models.calibration import ModelCalibrationArtifact
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.qualification import ModelQualificationArtifact
from mmaudit.models.refresh import (
    ModelRefreshAttempt,
    ModelRefreshDiff,
    ModelRefreshFreshness,
    ModelRefreshSnapshot,
    ModelRefreshSourceEvidence,
)
from mmaudit.models.refresh_staging import ModelRefreshWorkflowStatus
from mmaudit.models.scheduler import SchedulerArtifact, SchedulerRetainedJournalReference
from mmaudit.models.schemas import (
    HardhatInventoryPhaseRequest,
    HardhatReporterExecution,
    HardhatReporterInventory,
    HardhatTestPhaseRequest,
)
from mmaudit.models.sharding import SolidityShardsArtifact
from mmaudit.orchestration.context_manifest import ContextManifest
from mmaudit.privacy import PrivacyRetentionConsent
from mmaudit.release_candidate import ReleaseCandidateObservation
from mmaudit.release_gates import ReleaseGateEvidenceBundle
from mmaudit.release_observations import BoundReleaseGateResult
from mmaudit.release_report import ReleaseGateReport
from mmaudit.release_run import ReleaseRunBinding
from mmaudit.release_runtime import LocalReleaseGateResult
from mmaudit.release_static import StaticReleaseEvidence
from mmaudit.release_verification import ReleaseRunVerificationBinding
from mmaudit.reporting.bundle import (
    MANIFEST_BOUND_REPORT_DELIVERABLES,
    CoverageArtifact,
    FindingsArtifact,
    ModelExecutionArtifact,
)
from mmaudit.reporting.run_authority import (
    RUN_TERMINAL_REPORT_AUTHORITY_PATH,
    RunTerminalReportAuthority,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas"
SCHEMA_BASE = "https://mmaudit.local/schemas"
MODELS: dict[str, type[BaseModel]] = {
    "benchmark_report.schema.json": BenchmarkReport,
    "context_manifest.schema.json": ContextManifest,
    "coverage_artifact.schema.json": CoverageArtifact,
    "findings_artifact.schema.json": FindingsArtifact,
    "forensic_delivery_descriptor.schema.json": ForensicDeliveryDescriptor,
    "hardhat_reporter_inventory.schema.json": HardhatReporterInventory,
    "hardhat_reporter_test.schema.json": HardhatReporterExecution,
    "hardhat_request_inventory.schema.json": HardhatInventoryPhaseRequest,
    "hardhat_request_test.schema.json": HardhatTestPhaseRequest,
    "model_calibration.schema.json": ModelCalibrationArtifact,
    "model_execution_artifact.schema.json": ModelExecutionArtifact,
    "model_lineage_review.schema.json": ModelLineageReviewArtifact,
    "models_config.schema.json": ModelsConfig,
    "model_qualification.schema.json": ModelQualificationArtifact,
    "model_refresh_attempt.schema.json": ModelRefreshAttempt,
    "model_refresh_diff.schema.json": ModelRefreshDiff,
    "model_refresh_freshness.schema.json": ModelRefreshFreshness,
    "model_refresh_snapshot.schema.json": ModelRefreshSnapshot,
    "model_refresh_source_evidence.schema.json": ModelRefreshSourceEvidence,
    "model_refresh_workflow_status.schema.json": ModelRefreshWorkflowStatus,
    "privacy_retention_consent.schema.json": PrivacyRetentionConsent,
    "release_candidate_observation.schema.json": ReleaseCandidateObservation,
    "release_bound_gate_result.schema.json": BoundReleaseGateResult,
    "release_gate_evidence.schema.json": ReleaseGateEvidenceBundle,
    "release_gate_report.schema.json": ReleaseGateReport,
    "release_local_gate_result.schema.json": LocalReleaseGateResult,
    "release_run_binding.schema.json": ReleaseRunBinding,
    "release_run_verification_binding.schema.json": ReleaseRunVerificationBinding,
    "release_static_evidence.schema.json": StaticReleaseEvidence,
    "run_terminal_report_authority.schema.json": RunTerminalReportAuthority,
    "scheduler_state.schema.json": SchedulerArtifact,
    "scheduler_retained_journal_reference.schema.json": SchedulerRetainedJournalReference,
    "semantic_shard_inventory.schema.json": SolidityShardsArtifact,
}
TITLE_OVERRIDES = {
    "benchmark_report.schema.json": "mmaudit benchmark report",
    "coverage_artifact.schema.json": "mmaudit forensic coverage artifact",
    "findings_artifact.schema.json": "mmaudit forensic findings artifact",
    "forensic_delivery_descriptor.schema.json": "mmaudit complete forensic delivery descriptor",
    "hardhat_reporter_inventory.schema.json": "mmaudit Hardhat inventory observation",
    "hardhat_reporter_test.schema.json": "mmaudit Hardhat test observation",
    "hardhat_request_inventory.schema.json": "mmaudit Hardhat inventory phase request",
    "hardhat_request_test.schema.json": "mmaudit Hardhat test phase request",
    "model_calibration.schema.json": "mmaudit model calibration artifact",
    "model_execution_artifact.schema.json": "mmaudit model execution artifact",
    "model_lineage_review.schema.json": "mmaudit model lineage review artifact",
    "models_config.schema.json": "mmaudit models configuration",
    "model_qualification.schema.json": "mmaudit model qualification artifact",
    "model_refresh_attempt.schema.json": "mmaudit model refresh attempt",
    "model_refresh_diff.schema.json": "mmaudit model refresh diff",
    "model_refresh_freshness.schema.json": "mmaudit model refresh freshness",
    "model_refresh_snapshot.schema.json": "mmaudit model refresh snapshot",
    "model_refresh_source_evidence.schema.json": "mmaudit model refresh source evidence",
    "model_refresh_workflow_status.schema.json": "mmaudit model refresh workflow status",
    "run_terminal_report_authority.schema.json": "mmaudit private terminal report authority",
    "scheduler_state.schema.json": "mmaudit seven-pass scheduler state",
    "scheduler_retained_journal_reference.schema.json": (
        "mmaudit retained scheduler journal reference"
    ),
    "semantic_shard_inventory.schema.json": "mmaudit Solidity semantic shard inventory",
}


def run_evidence_manifest_report_bundle_rule() -> dict[str, Any]:
    """Return the published schema-1.2 contract for every manifest-bound report leaf."""

    return {
        "if": {
            "properties": {"schema_version": {"const": "1.2"}},
            "required": ["schema_version"],
        },
        "then": {
            "properties": {
                "artifacts": {
                    "allOf": [
                        {
                            "contains": {
                                "properties": {"path": {"const": name}},
                                "required": ["path"],
                            },
                            "maxContains": 1,
                            "minContains": 1,
                        }
                        for name in sorted(
                            MANIFEST_BOUND_REPORT_DELIVERABLES
                            | {RUN_TERMINAL_REPORT_AUTHORITY_PATH}
                        )
                    ]
                }
            }
        },
    }


def _run_evidence_manifest_contract_is_current() -> bool:
    """Verify the hand-authored manifest schema retains the generated 1.2 leaf contract."""

    path = SCHEMA_ROOT / "run_evidence_manifest.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    rules = [
        rule
        for rule in schema.get("allOf", [])
        if rule.get("if", {}).get("properties", {}).get("schema_version", {}).get("const") == "1.2"
    ]
    return rules == [run_evidence_manifest_report_bundle_rule()]


def rendered_schema(filename: str, model: type[BaseModel]) -> str:
    """Return one deterministic draft-2020-12 schema."""

    schema = model.model_json_schema()
    if filename == "models_config.schema.json":
        lineage = schema["$defs"]["ModelLineageConfig"]
        measured_quality = lineage["properties"]["measured_quality"]
        non_null_options = [
            option for option in measured_quality["anyOf"] if option.get("type") != "null"
        ]
        if len(non_null_options) != 1:
            raise ValueError("models configuration schema has an unexpected quality union")
        lineage["properties"]["measured_quality"] = non_null_options[0]
        lineage["properties"]["aliases"]["uniqueItems"] = True
        lineage["$comment"] = (
            "Canonical model ID and aliases are also required to be case-insensitively "
            "distinct by ModelsConfig runtime validation."
        )
        schema["properties"]["registry"]["$comment"] = (
            "Canonical IDs and aliases are required to be globally case-insensitively unique "
            "by ModelsConfig runtime validation; this cross-item relation is not expressible "
            "in JSON Schema draft 2020-12."
        )
        quality = schema["$defs"]["ModelQualityMeasurementConfig"]
        quality["allOf"] = [
            {
                "if": {
                    "properties": {"tier": {"const": tier}},
                    "required": ["tier"],
                },
                "then": {"properties": {"score": {"minimum": minimum, "type": "number"}}},
            }
            for tier, minimum in (("high", 0.75), ("highest", 0.9))
        ]
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = f"{SCHEMA_BASE}/{filename}"
    if filename in TITLE_OVERRIDES:
        schema["title"] = TITLE_OVERRIDES[filename]
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write generated schemas; without this option, verify committed bytes.",
    )
    arguments = parser.parse_args(argv)
    failures: list[str] = []
    for filename, model in sorted(MODELS.items()):
        expected = rendered_schema(filename, model)
        path = SCHEMA_ROOT / filename
        if arguments.write:
            path.write_text(expected, encoding="utf-8")
            continue
        try:
            observed = path.read_text(encoding="utf-8")
        except OSError:
            failures.append(f"{filename}: missing")
            continue
        if observed != expected:
            failures.append(f"{filename}: stale")
    if not _run_evidence_manifest_contract_is_current():
        failures.append("run_evidence_manifest.schema.json: stale report-bundle contract")
    if failures:
        raise SystemExit("release schema verification failed: " + ", ".join(failures))


if __name__ == "__main__":
    main()
