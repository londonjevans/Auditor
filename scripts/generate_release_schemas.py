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
from mmaudit.models.lineage_authority import (
    ModelLineageAuthorityEnvelope,
    ModelLineageTrustAnchor,
)
from mmaudit.models.lineage_review import ModelLineageReviewArtifact
from mmaudit.models.policy_eligibility import (
    ClientPolicyConstraints,
    ModelPolicyEligibilityArtifact,
    PolicyEligibilityEvaluation,
    PolicyReviewSignal,
)
from mmaudit.models.policy_eligibility_authority import (
    ModelPolicyEligibilityAuthorityEnvelope,
    ModelPolicyEligibilityAuthorityVerificationReceipt,
    ModelPolicyEligibilityTrustAnchor,
    PolicyEligibilitySourceObservation,
)
from mmaudit.models.policy_eligibility_refresh import ModelPolicyEligibilityRefreshArtifact
from mmaudit.models.policy_selection import (
    AuditModelSelection,
    AuditModelSelectionEvidenceBundle,
)
from mmaudit.models.qualification import ModelQualificationArtifact, QualificationPolicy
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
    LanguageCapabilityArtifact,
    SolidityGraphFactKind,
    SolidityGraphKind,
    SolidityGraphNodeKind,
)
from mmaudit.models.sharding import (
    SolidityCoverageArtifact,
    SolidityGraphsArtifact,
    SolidityShardsArtifact,
)
from mmaudit.orchestration.context_manifest import ContextManifest
from mmaudit.orchestration.manifest import (
    AUDIT_MODEL_SELECTION_BINDING_IDS,
    AUDIT_MODEL_SELECTION_EVIDENCE_PATH,
    LANGUAGE_CAPABILITY_ARTIFACT_PATH,
)
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
    ScannerSourceEvidenceArtifact,
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
    "audit_model_selection.schema.json": AuditModelSelection,
    "audit_model_selection_evidence.schema.json": AuditModelSelectionEvidenceBundle,
    "context_manifest.schema.json": ContextManifest,
    "coverage_artifact.schema.json": CoverageArtifact,
    "findings_artifact.schema.json": FindingsArtifact,
    "forensic_delivery_descriptor.schema.json": ForensicDeliveryDescriptor,
    "hardhat_reporter_inventory.schema.json": HardhatReporterInventory,
    "hardhat_reporter_test.schema.json": HardhatReporterExecution,
    "hardhat_request_inventory.schema.json": HardhatInventoryPhaseRequest,
    "hardhat_request_test.schema.json": HardhatTestPhaseRequest,
    "language_capability.schema.json": LanguageCapabilityArtifact,
    "model_calibration.schema.json": ModelCalibrationArtifact,
    "model_lineage_authority.schema.json": ModelLineageAuthorityEnvelope,
    "model_execution_artifact.schema.json": ModelExecutionArtifact,
    "model_lineage_review.schema.json": ModelLineageReviewArtifact,
    "model_lineage_trust_anchor.schema.json": ModelLineageTrustAnchor,
    "model_policy_eligibility.schema.json": ModelPolicyEligibilityArtifact,
    "model_policy_eligibility_authority.schema.json": ModelPolicyEligibilityAuthorityEnvelope,
    "model_policy_eligibility_authority_receipt.schema.json": (
        ModelPolicyEligibilityAuthorityVerificationReceipt
    ),
    "model_policy_eligibility_trust_anchor.schema.json": ModelPolicyEligibilityTrustAnchor,
    "model_policy_eligibility_refresh.schema.json": ModelPolicyEligibilityRefreshArtifact,
    "models_config.schema.json": ModelsConfig,
    "model_qualification.schema.json": ModelQualificationArtifact,
    "model_qualification_policy.schema.json": QualificationPolicy,
    "model_refresh_attempt.schema.json": ModelRefreshAttempt,
    "model_refresh_diff.schema.json": ModelRefreshDiff,
    "model_refresh_freshness.schema.json": ModelRefreshFreshness,
    "model_refresh_snapshot.schema.json": ModelRefreshSnapshot,
    "model_refresh_source_evidence.schema.json": ModelRefreshSourceEvidence,
    "model_refresh_workflow_status.schema.json": ModelRefreshWorkflowStatus,
    "privacy_retention_consent.schema.json": PrivacyRetentionConsent,
    "client_policy_constraints.schema.json": ClientPolicyConstraints,
    "policy_eligibility_evaluation.schema.json": PolicyEligibilityEvaluation,
    "policy_eligibility_source_observation.schema.json": PolicyEligibilitySourceObservation,
    "policy_review_signal.schema.json": PolicyReviewSignal,
    "release_candidate_observation.schema.json": ReleaseCandidateObservation,
    "release_bound_gate_result.schema.json": BoundReleaseGateResult,
    "release_gate_evidence.schema.json": ReleaseGateEvidenceBundle,
    "release_gate_report.schema.json": ReleaseGateReport,
    "release_local_gate_result.schema.json": LocalReleaseGateResult,
    "release_run_binding.schema.json": ReleaseRunBinding,
    "release_run_verification_binding.schema.json": ReleaseRunVerificationBinding,
    "release_static_evidence.schema.json": StaticReleaseEvidence,
    "run_terminal_report_authority.schema.json": RunTerminalReportAuthority,
    "scanner_source_evidence.schema.json": ScannerSourceEvidenceArtifact,
    "scheduler_state.schema.json": SchedulerArtifact,
    "scheduler_retained_journal_reference.schema.json": SchedulerRetainedJournalReference,
    "semantic_shard_inventory.schema.json": SolidityShardsArtifact,
    "solidity_graphs.schema.json": SolidityGraphsArtifact,
    "solidity_coverage.schema.json": SolidityCoverageArtifact,
}
TITLE_OVERRIDES = {
    "audit_model_selection.schema.json": "mmaudit audit-scoped model selection",
    "audit_model_selection_evidence.schema.json": ("mmaudit audit-scoped model selection evidence"),
    "benchmark_report.schema.json": "mmaudit benchmark report",
    "coverage_artifact.schema.json": "mmaudit forensic coverage artifact",
    "findings_artifact.schema.json": "mmaudit forensic findings artifact",
    "forensic_delivery_descriptor.schema.json": "mmaudit complete forensic delivery descriptor",
    "hardhat_reporter_inventory.schema.json": "mmaudit Hardhat inventory observation",
    "hardhat_reporter_test.schema.json": "mmaudit Hardhat test observation",
    "hardhat_request_inventory.schema.json": "mmaudit Hardhat inventory phase request",
    "hardhat_request_test.schema.json": "mmaudit Hardhat test phase request",
    "language_capability.schema.json": "mmaudit language capability artifact",
    "model_calibration.schema.json": "mmaudit model calibration artifact",
    "model_lineage_authority.schema.json": "mmaudit signed model lineage authority",
    "model_execution_artifact.schema.json": "mmaudit model execution artifact",
    "model_lineage_review.schema.json": "mmaudit model lineage review artifact",
    "model_lineage_trust_anchor.schema.json": "mmaudit model lineage trust anchor",
    "model_policy_eligibility.schema.json": "mmaudit model policy eligibility artifact",
    "model_policy_eligibility_authority.schema.json": (
        "mmaudit signed model policy eligibility authority"
    ),
    "model_policy_eligibility_authority_receipt.schema.json": (
        "mmaudit model policy eligibility authority verification receipt"
    ),
    "model_policy_eligibility_trust_anchor.schema.json": (
        "mmaudit model policy eligibility trust anchor"
    ),
    "model_policy_eligibility_refresh.schema.json": (
        "mmaudit model policy eligibility refresh artifact"
    ),
    "models_config.schema.json": "mmaudit models configuration",
    "model_qualification.schema.json": "mmaudit model qualification artifact",
    "model_qualification_policy.schema.json": "mmaudit model qualification policy",
    "model_refresh_attempt.schema.json": "mmaudit model refresh attempt",
    "model_refresh_diff.schema.json": "mmaudit model refresh diff",
    "model_refresh_freshness.schema.json": "mmaudit model refresh freshness",
    "model_refresh_snapshot.schema.json": "mmaudit model refresh snapshot",
    "model_refresh_source_evidence.schema.json": "mmaudit model refresh source evidence",
    "model_refresh_workflow_status.schema.json": "mmaudit model refresh workflow status",
    "client_policy_constraints.schema.json": "mmaudit per-audit client policy constraints",
    "policy_eligibility_evaluation.schema.json": ("mmaudit model policy eligibility evaluation"),
    "policy_eligibility_source_observation.schema.json": (
        "mmaudit current policy eligibility source observation"
    ),
    "policy_review_signal.schema.json": "mmaudit model policy review signal",
    "run_terminal_report_authority.schema.json": "mmaudit private terminal report authority",
    "scanner_source_evidence.schema.json": "mmaudit private scanner source evidence",
    "scheduler_state.schema.json": "mmaudit seven-pass scheduler state",
    "scheduler_retained_journal_reference.schema.json": (
        "mmaudit retained scheduler journal reference"
    ),
    "semantic_shard_inventory.schema.json": "mmaudit Solidity semantic shard inventory",
    "solidity_graphs.schema.json": "mmaudit bounded Solidity semantic graphs artifact",
    "solidity_coverage.schema.json": "mmaudit Solidity coverage artifact",
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
                            | {
                                LANGUAGE_CAPABILITY_ARTIFACT_PATH,
                                RUN_TERMINAL_REPORT_AUTHORITY_PATH,
                            }
                        )
                    ]
                }
            }
        },
    }


def run_evidence_manifest_audit_model_selection_rules() -> list[dict[str, Any]]:
    """Return the bidirectional artifact/binding custody contract."""

    artifact_match = {
        "properties": {"path": {"const": AUDIT_MODEL_SELECTION_EVIDENCE_PATH}},
        "required": ["path"],
    }
    binding_matches = [
        {
            "contains": {
                "properties": {"identifier": {"const": identifier}},
                "required": ["identifier"],
            },
            "maxContains": 1,
            "minContains": 1,
        }
        for identifier in sorted(AUDIT_MODEL_SELECTION_BINDING_IDS)
    ]
    any_binding_match = {
        "properties": {"identifier": {"enum": sorted(AUDIT_MODEL_SELECTION_BINDING_IDS)}},
        "required": ["identifier"],
    }
    return [
        {
            "if": {
                "properties": {"artifacts": {"contains": artifact_match}},
                "required": ["artifacts"],
            },
            "then": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"allOf": binding_matches},
                        },
                        "required": ["models"],
                    }
                }
            },
        },
        {
            "if": {
                "properties": {
                    "bindings": {
                        "properties": {
                            "models": {"contains": any_binding_match},
                        },
                        "required": ["models"],
                    }
                },
                "required": ["bindings"],
            },
            "then": {
                "properties": {
                    "artifacts": {
                        "contains": artifact_match,
                        "maxContains": 1,
                        "minContains": 1,
                    }
                }
            },
        },
    ]


def _run_evidence_manifest_contract_is_current() -> bool:
    """Verify the hand-authored manifest schema retains the generated 1.2 leaf contract."""

    path = SCHEMA_ROOT / "run_evidence_manifest.schema.json"
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    expected = [
        run_evidence_manifest_report_bundle_rule(),
        *run_evidence_manifest_audit_model_selection_rules(),
    ]
    return all(rule in schema.get("allOf", []) for rule in expected)


_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS = (
    "graph_edge_counts",
    "graph_retained_edge_occurrence_counts",
    "graph_candidate_edge_counts",
)
_SOLIDITY_COVERAGE_FACT_DENSE_MAPS = (
    "graph_fact_retained_counts",
    "graph_fact_retained_occurrence_counts",
    "graph_fact_candidate_counts",
)
_SOLIDITY_COVERAGE_GRAPH_MAPS = (
    *_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS,
    "graph_omitted_edge_counts",
    "graph_node_counts",
    *_SOLIDITY_COVERAGE_FACT_DENSE_MAPS,
    "graph_fact_omitted_counts",
    "asset_flow_operation_counts",
    "asset_flow_direction_counts",
    "control_resolution_counts",
    "governance_stage_counts",
    "dependency_resolution_counts",
    "oracle_freshness_counts",
)
_SOLIDITY_COVERAGE_GRAPH_LISTS = (
    "graph_omission_evidence_sha256s",
    "graph_fact_omission_evidence_sha256s",
    "graph_warnings",
)


def _strengthen_solidity_coverage_contract(schema: dict[str, Any]) -> None:
    """Expose runtime graph-accounting invariants at the standalone schema boundary."""

    coverage = schema["$defs"]["SolidityCoverage"]
    properties = coverage["properties"]
    edge_kinds = [kind.value for kind in SolidityGraphKind]
    fact_kinds = [kind.value for kind in SolidityGraphFactKind]
    node_kinds = [kind.value for kind in SolidityGraphNodeKind]

    coverage["required"] = sorted(
        {
            *coverage.get("required", []),
            "graph_analysis_state",
            *_SOLIDITY_COVERAGE_GRAPH_MAPS,
            *_SOLIDITY_COVERAGE_GRAPH_LISTS,
        }
    )
    properties["graph_analysis_state"] = {
        "default": "not_analyzed",
        "enum": [
            "not_analyzed",
            "attempted_but_failed",
            "analyzed_with_fallback_parser",
            "deterministic",
        ],
        "title": "Graph Analysis State",
        "type": "string",
    }
    for field_name in (*_SOLIDITY_COVERAGE_EDGE_DENSE_MAPS, "graph_omitted_edge_counts"):
        properties[field_name]["propertyNames"] = {"enum": edge_kinds}
    for field_name in (
        *_SOLIDITY_COVERAGE_FACT_DENSE_MAPS,
        "graph_fact_omitted_counts",
    ):
        properties[field_name]["propertyNames"] = {"enum": fact_kinds}
    properties["graph_node_counts"]["propertyNames"] = {"enum": node_kinds}
    properties["graph_omitted_edge_counts"]["additionalProperties"]["minimum"] = 1
    properties["graph_fact_omitted_counts"]["additionalProperties"]["minimum"] = 1

    empty_graph_evidence = {
        **{field_name: {"maxProperties": 0} for field_name in _SOLIDITY_COVERAGE_GRAPH_MAPS},
        **{field_name: {"maxItems": 0} for field_name in _SOLIDITY_COVERAGE_GRAPH_LISTS},
    }
    dense_analyzed_evidence = {
        **{
            field_name: {
                "maxProperties": len(edge_kinds),
                "minProperties": len(edge_kinds),
            }
            for field_name in _SOLIDITY_COVERAGE_EDGE_DENSE_MAPS
        },
        **{
            field_name: {
                "maxProperties": len(fact_kinds),
                "minProperties": len(fact_kinds),
            }
            for field_name in _SOLIDITY_COVERAGE_FACT_DENSE_MAPS
        },
    }
    coverage["allOf"] = [
        {
            "if": {
                "properties": {"graph_analysis_state": {"const": "not_analyzed"}},
                "required": ["graph_analysis_state"],
            },
            "then": {"properties": empty_graph_evidence},
            "else": {"properties": dense_analyzed_evidence},
        },
        {
            "if": {
                "properties": {"graph_analysis_state": {"const": "attempted_but_failed"}},
                "required": ["graph_analysis_state"],
            },
            "then": {
                "anyOf": [
                    {
                        "properties": {
                            "graph_omitted_edge_counts": {"minProperties": 1},
                            "graph_omission_evidence_sha256s": {"minItems": 1},
                        }
                    },
                    {
                        "properties": {
                            "graph_fact_omitted_counts": {"minProperties": 1},
                            "graph_fact_omission_evidence_sha256s": {"minItems": 1},
                        }
                    },
                ]
            },
        },
        {
            "if": {
                "properties": {
                    "graph_analysis_state": {
                        "enum": ["analyzed_with_fallback_parser", "deterministic"]
                    }
                },
                "required": ["graph_analysis_state"],
            },
            "then": {
                "properties": {
                    "graph_omitted_edge_counts": {"maxProperties": 0},
                    "graph_omission_evidence_sha256s": {"maxItems": 0},
                    "graph_fact_omitted_counts": {"maxProperties": 0},
                    "graph_fact_omission_evidence_sha256s": {"maxItems": 0},
                }
            },
        },
    ]
    coverage["$comment"] = (
        "Runtime validation additionally requires one canonical evidence hash per sparse "
        "omitted-kind entry and exact candidate = retained-occurrence + omitted arithmetic."
    )


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
    if filename in {"coverage_artifact.schema.json", "solidity_coverage.schema.json"}:
        _strengthen_solidity_coverage_contract(schema)
    if filename == "audit_model_selection_evidence.schema.json":
        schema["required"] = sorted({*schema.get("required", []), "technical_evidence_mode"})
    if filename == "model_execution_artifact.schema.json":
        schema.setdefault("allOf", []).append(
            {
                "if": {
                    "properties": {
                        "audit_model_selection": {"not": {"type": "null"}},
                    },
                    "required": ["audit_model_selection"],
                },
                "then": {
                    "properties": {"schema_version": {"const": "1.2"}},
                },
            }
        )
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
