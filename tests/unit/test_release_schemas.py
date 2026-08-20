from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mmaudit.benchmark.cross_lineage_adjudication import CrossLineageAdjudicationReport
from mmaudit.config import ModelLineageConfig
from mmaudit.models.authenticated_runner import AuthenticatedCrossLineageRunnerEvidence
from mmaudit.models.autonomous_benchmark_verdict import (
    EvidenceSealVerdictPolicy,
    EvidenceSealVerdictProjection,
)
from mmaudit.models.coverage_planning import (
    ModelSurfaceCoveragePlan,
    ModelSurfaceResourcePreflight,
)
from mmaudit.models.evidence_seal_authority import EvidenceSealedAuthorityEvidence
from mmaudit.models.frozen_lineage_authority import FrozenModelLineageProvenance
from mmaudit.models.ground_truth_authority import FrozenGroundTruthProvenance
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
from mmaudit.models.public_lineage_authority import PublicModelLineageEvidenceBundle
from mmaudit.models.qualification import QualificationPolicy
from scripts.generate_release_schemas import MODELS, rendered_schema

ROOT = Path(__file__).resolve().parents[2]


def test_release_schemas_are_exact_strict_generated_models() -> None:
    for filename, model in MODELS.items():
        path = ROOT / "schemas" / filename
        observed_text = path.read_text(encoding="utf-8")
        assert observed_text == rendered_schema(filename, model)
        schema = json.loads(observed_text)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["$id"] == f"https://mmaudit.local/schemas/{filename}"
        assert schema["additionalProperties"] is False


def _assert_non_authorizing_model_schema(definition: dict[str, object]) -> None:
    properties = definition["properties"]
    assert isinstance(properties, dict)
    for field_name in (
        "authorizes_dispatch",
        "grants_review_credit",
        "grants_completion_credit",
    ):
        assert properties[field_name] == {
            "const": False,
            "default": False,
            "title": properties[field_name]["title"],
            "type": "boolean",
        }


def test_model_surface_coverage_plan_schema_is_closed_bounded_and_non_authorizing() -> None:
    filename = "model_surface_coverage_plan.schema.json"
    assert MODELS[filename] is ModelSurfaceCoveragePlan
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    definitions = schema["$defs"]
    sha256_pattern = r"^[0-9a-f]{64}$"

    assert definitions["ModelSurfaceRiskTier"] == {
        "description": "Closed deterministic risk tiers for model-review surfaces.",
        "enum": ["T0", "T1", "T2", "T3"],
        "title": "ModelSurfaceRiskTier",
        "type": "string",
    }
    policy = definitions["ModelSurfaceCoveragePolicy"]
    requirements = policy["properties"]["requirements"]
    assert requirements["minItems"] == requirements["maxItems"] == 4
    assert requirements["items"] == {"$ref": "#/$defs/ModelSurfaceTierRequirement"}
    tier_requirement = definitions["ModelSurfaceTierRequirement"]
    assert tier_requirement["properties"]["tier"] == {"$ref": "#/$defs/ModelSurfaceRiskTier"}
    assert tier_requirement["properties"]["minimum_root_lineages"] == {
        "maximum": 16,
        "minimum": 1,
        "title": "Minimum Root Lineages",
        "type": "integer",
    }
    assert tier_requirement["properties"]["completion_blocking"]["const"] is True
    assert {
        "tier",
        "minimum_root_lineages",
        "requirement_sha256",
    }.issubset(tier_requirement["required"])

    task = definitions["ModelSurfaceGapTask"]
    for field_name in ("surface_ids", "assignment_sha256s"):
        assert task["properties"][field_name]["minItems"] == 1
        assert task["properties"][field_name]["maxItems"] == 32
    assert task["properties"]["lineage_gap_assignment_count"]["maximum"] == 32
    assert task["properties"]["responsibility_seed_assignment_count"]["maximum"] == 32

    model_definitions = (
        "ModelSurfaceCoverageDeficit",
        "ModelSurfaceCoveragePolicy",
        "ModelSurfaceCoverageRequirement",
        "ModelSurfaceGapAssignment",
        "ModelSurfaceGapTask",
        "ModelSurfaceReviewerBinding",
        "ModelSurfaceTierRequirement",
    )
    for definition_name in model_definitions:
        definition = definitions[definition_name]
        assert definition["additionalProperties"] is False
        _assert_non_authorizing_model_schema(definition)
    _assert_non_authorizing_model_schema(schema)

    self_hashes = {
        "ModelSurfaceCoverageDeficit": "deficit_sha256",
        "ModelSurfaceCoveragePolicy": "policy_sha256",
        "ModelSurfaceCoverageRequirement": "requirement_sha256",
        "ModelSurfaceGapAssignment": "assignment_sha256",
        "ModelSurfaceGapTask": "task_sha256",
        "ModelSurfaceReviewerBinding": "binding_sha256",
        "ModelSurfaceTierRequirement": "requirement_sha256",
    }
    for definition_name, field_name in self_hashes.items():
        definition = definitions[definition_name]
        assert definition["properties"][field_name]["pattern"] == sha256_pattern
        assert field_name in definition["required"]
    assert schema["properties"]["plan_sha256"]["pattern"] == sha256_pattern
    assert "plan_sha256" in schema["required"]


def test_model_surface_resource_preflight_schema_binds_tasks_caps_and_failures() -> None:
    filename = "model_surface_resource_preflight.schema.json"
    assert MODELS[filename] is ModelSurfaceResourcePreflight
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    definitions = schema["$defs"]
    sha256_pattern = r"^[0-9a-f]{64}$"

    preview = definitions["ModelSurfaceTaskResourcePreview"]
    identity_fields = {
        "coverage_task_id": r"^model-surface-gap-task-[0-9a-f]{64}$",
        "coverage_task_sha256": sha256_pattern,
        "scheduler_task_id": r"^scheduler-task-[0-9a-f]{64}$",
        "scheduler_task_plan_sha256": sha256_pattern,
    }
    for field_name, pattern in identity_fields.items():
        assert preview["properties"][field_name]["pattern"] == pattern
        assert field_name in preview["required"]

    projection_hash_fields = {
        "campaign_manifest_sha256",
        "rendered_context_sha256",
        "context_request_evidence_sha256",
        "request_token_plan_projection_sha256",
        "request_material_projection_sha256",
        "endpoint_policy_snapshot_sha256",
        "endpoint_policy_pricing_sha256",
        "endpoint_pricing_snapshot_sha256",
        "endpoint_cost_bound_projection_sha256",
    }
    for field_name in projection_hash_fields:
        assert preview["properties"][field_name] == {
            "pattern": sha256_pattern,
            "title": preview["properties"][field_name]["title"],
            "type": "string",
        }
        assert field_name in preview["required"]
    assert preview["properties"]["request_material_projection_utf8_bytes"] == {
        "exclusiveMinimum": 0,
        "maximum": 2**63 - 1,
        "title": "Request Material Projection Utf8 Bytes",
        "type": "integer",
    }
    assert preview["properties"]["provider_endpoint"] == {
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9 ._:/-]{0,255}$",
        "title": "Provider Endpoint",
        "type": "string",
    }
    assert {
        "request_material_projection_utf8_bytes",
        "provider_endpoint",
    } <= set(preview["required"])

    exact_preview_properties = {
        "artifact_kind",
        "schema_version",
        *identity_fields,
        *projection_hash_fields,
        "request_material_projection_utf8_bytes",
        "provider_endpoint",
        "maximum_attempts",
        "maximum_prompt_tokens_per_attempt",
        "maximum_completion_tokens_per_attempt",
        "maximum_cost_usd_per_attempt_exact",
        "maximum_request_count",
        "maximum_input_tokens",
        "maximum_output_tokens",
        "maximum_cost_usd_exact",
        "preview_sha256",
        "authorizes_dispatch",
        "grants_review_credit",
        "grants_completion_credit",
    }
    assert set(preview["properties"]) == exact_preview_properties
    assert set(preview["required"]) == exact_preview_properties - {
        "artifact_kind",
        "schema_version",
        "authorizes_dispatch",
        "grants_review_credit",
        "grants_completion_credit",
    }
    assert {
        "request_token_plan_sha256",
        "request_material_sha256",
        "request_material_utf8_bytes",
        "endpoint_cost_bound_sha256",
    }.isdisjoint(preview["properties"])
    assert preview["properties"]["preview_sha256"]["pattern"] == sha256_pattern
    assert "preview_sha256" in preview["required"]

    assert definitions["ModelSurfaceResourceScopeKind"]["enum"] == ["role", "model"]
    assert definitions["ModelSurfaceResourceFailureCode"]["enum"] == [
        "COVERAGE_PLAN_INFEASIBLE",
        "REQUEST_CAP_EXCEEDED",
        "INPUT_TOKEN_CAP_EXCEEDED",
        "OUTPUT_TOKEN_CAP_EXCEEDED",
        "USD_CAP_EXCEEDED",
        "ROLE_USD_CAP_MISSING",
        "ROLE_USD_CAP_EXCEEDED",
        "MODEL_USD_CAP_MISSING",
        "MODEL_USD_CAP_EXCEEDED",
    ]
    scoped_collections = {
        "planned_costs_by_role": "ModelSurfaceResourceScopeCost",
        "planned_costs_by_model": "ModelSurfaceResourceScopeCost",
        "remaining_cost_caps_by_role": "ModelSurfaceResourceScopeCap",
        "remaining_cost_caps_by_model": "ModelSurfaceResourceScopeCap",
        "scoped_failures": "ModelSurfaceResourceScopeFailure",
    }
    for field_name, definition_name in scoped_collections.items():
        collection = schema["properties"][field_name]
        assert collection["items"] == {"$ref": f"#/$defs/{definition_name}"}
        assert field_name in schema["required"]
    assert schema["properties"]["planned_costs_by_role"]["maxItems"] == 256
    assert schema["properties"]["planned_costs_by_model"]["maxItems"] == 256
    assert schema["properties"]["remaining_cost_caps_by_role"]["maxItems"] == 256
    assert schema["properties"]["remaining_cost_caps_by_model"]["maxItems"] == 256
    assert schema["properties"]["scoped_failures"]["maxItems"] == 512

    model_definitions = tuple(
        name for name, definition in definitions.items() if definition.get("type") == "object"
    )
    for definition_name in model_definitions:
        definition = definitions[definition_name]
        assert definition["additionalProperties"] is False
        _assert_non_authorizing_model_schema(definition)
    _assert_non_authorizing_model_schema(schema)

    self_hashes = {
        "ModelSurfaceCoverageDeficit": "deficit_sha256",
        "ModelSurfaceCoveragePlan": "plan_sha256",
        "ModelSurfaceCoveragePolicy": "policy_sha256",
        "ModelSurfaceCoverageRequirement": "requirement_sha256",
        "ModelSurfaceGapAssignment": "assignment_sha256",
        "ModelSurfaceGapTask": "task_sha256",
        "ModelSurfaceResourceScopeCap": "cap_sha256",
        "ModelSurfaceResourceScopeCost": "cost_sha256",
        "ModelSurfaceResourceScopeFailure": "failure_sha256",
        "ModelSurfaceReviewerBinding": "binding_sha256",
        "ModelSurfaceTaskResourcePreview": "preview_sha256",
        "ModelSurfaceTierRequirement": "requirement_sha256",
    }
    for definition_name, field_name in self_hashes.items():
        definition = definitions[definition_name]
        assert definition["properties"][field_name]["pattern"] == sha256_pattern
        assert field_name in definition["required"]
    assert schema["properties"]["preflight_sha256"]["pattern"] == sha256_pattern
    assert "preflight_sha256" in schema["required"]

    forbidden_private_fields = {
        "context_package",
        "context_units",
        "endpoint_cost_bound",
        "endpoint_policy_pricing",
        "endpoint_policy_snapshot",
        "endpoint_pricing_snapshot",
        "framed_schema_json",
        "prompt",
        "raw_prompt",
        "rendered_context",
        "request_body",
        "request_token_plan",
        "response",
        "raw_response",
        "scanner_findings",
        "source_content",
        "source_contents",
        "system_prompt",
        "usage",
        "usage_record",
        "user_prompt",
    }
    forbidden_private_definitions = {
        "CandidateReviewBatch",
        "CandidateReviewOutput",
        "ContextPackage",
        "ContextRequestEvidence",
        "EndpointPolicySnapshot",
        "EndpointPricingSnapshot",
        "EndpointRequestCostBound",
        "RequestTokenPlan",
        "ScannerFinding",
        "UsageRecord",
    }
    assert forbidden_private_definitions.isdisjoint(definitions)
    serialized_properties = [schema["properties"]]
    serialized_properties.extend(
        definition.get("properties", {}) for definition in definitions.values()
    )
    for properties in serialized_properties:
        assert forbidden_private_fields.isdisjoint(properties)


def test_scheduler_recovery_schema_is_hash_only_versioned_and_terminal_discriminated() -> None:
    schema = json.loads((ROOT / "schemas" / "scheduler_state.schema.json").read_text())
    definitions = schema["$defs"]
    sha256_pattern = r"^[0-9a-f]{64}$"

    recovery_inventory = schema["properties"]["recovery_model_requests"]
    assert recovery_inventory["default"] == []
    assert recovery_inventory["maxItems"] == 32
    assert recovery_inventory["items"] == {
        "$ref": "#/$defs/SchedulerTruncationRecoveryModelRequestEvidence"
    }

    pass_result = definitions["SchedulerPassResult"]
    assert pass_result["additionalProperties"] is False
    assert pass_result["properties"]["schema_version"]["enum"] == ["1.0", "1.1"]
    promotions = pass_result["properties"]["recovery_promotion_bindings"]
    assert promotions["default"] == []
    assert promotions["maxItems"] == 100_000
    assert promotions["items"] == {"$ref": "#/$defs/SchedulerTruncationRecoveryPromotionBinding"}
    assert "recovery_promotion_bindings" not in pass_result["required"]
    assert pass_result["allOf"] == [
        {
            "if": {
                "properties": {"schema_version": {"const": "1.1"}},
                "required": ["schema_version"],
            },
            "then": {
                "properties": {"recovery_promotion_bindings": {"minItems": 1}},
                "required": ["recovery_promotion_bindings"],
            },
            "else": {"not": {"required": ["recovery_promotion_bindings"]}},
        }
    ]

    promotion = definitions["SchedulerTruncationRecoveryPromotionBinding"]
    assert promotion["additionalProperties"] is False
    assert set(promotion["properties"]) == {
        "binding_sha256",
        "completion_authorized",
        "coverage_credit_authorized",
        "delivered_source_inventory_sha256",
        "direct_child_result_sha256s",
        "evidence_authority",
        "original_truncated_result_sha256",
        "parent_task_id",
        "promotion_entry_sha256",
        "provider_dispatch_authorized",
        "recovered_output_artifact_sha256",
        "release_authorized",
        "review_credit_authorized",
        "schema_version",
    }
    for field_name in (
        "original_truncated_result_sha256",
        "promotion_entry_sha256",
        "recovered_output_artifact_sha256",
        "delivered_source_inventory_sha256",
        "binding_sha256",
    ):
        assert promotion["properties"][field_name]["pattern"] == sha256_pattern
    direct_children = promotion["properties"]["direct_child_result_sha256s"]
    assert direct_children["minItems"] == 2
    assert direct_children["maxItems"] == 2
    assert direct_children["uniqueItems"] is True
    assert direct_children["prefixItems"] == [
        {"pattern": sha256_pattern, "type": "string"},
        {"pattern": sha256_pattern, "type": "string"},
    ]
    for field_name in (
        "provider_dispatch_authorized",
        "review_credit_authorized",
        "coverage_credit_authorized",
        "completion_authorized",
        "release_authorized",
    ):
        assert promotion["properties"][field_name]["const"] is False

    request = definitions["SchedulerTruncationRecoveryModelRequestEvidence"]
    assert request["additionalProperties"] is False
    assert request["properties"]["terminal_status"]["enum"] == ["SUCCEEDED", "TRUNCATED"]
    completion_fields = (
        "runtime_completion_evidence_sha256",
        "validated_response_sha256",
        "normalization_evidence_sha256",
        "output_artifact_sha256",
    )
    for field_name in completion_fields:
        assert request["properties"][field_name]["anyOf"] == [
            {"pattern": sha256_pattern, "type": "string"},
            {"type": "null"},
        ]
        assert field_name not in request["required"]
    assert request["allOf"] == [
        {
            "if": {
                "properties": {"terminal_status": {"const": "SUCCEEDED"}},
                "required": ["terminal_status"],
            },
            "then": {
                "properties": {
                    field_name: {"not": {"type": "null"}} for field_name in completion_fields
                },
                "required": list(completion_fields),
            },
            "else": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in (*completion_fields, "promotion_entry_sha256")
                    ]
                }
            },
        }
    ]
    for field_name in (
        "provider_dispatch_authorized",
        "review_credit_authorized",
        "coverage_credit_authorized",
        "completion_authorized",
        "release_authorized",
    ):
        assert request["properties"][field_name]["const"] is False

    private_definitions = {
        "CandidateReviewBatch",
        "ContextRequestEvidence",
        "SchedulerRecoveredCandidateOrigin",
        "SchedulerRecoveredCandidateReviewOutput",
        "SchedulerTruncationRecoveryFamilyPromotion",
        "UsageRecord",
    }
    assert private_definitions.isdisjoint(definitions)
    private_properties = {
        "candidate_origins",
        "context_request_evidence",
        "recovered_batch",
        "runtime_normalized_batch",
        "runtime_output_artifact",
        "runtime_requested_surface_requests",
        "runtime_usage_record",
        "scanner_fingerprints_by_request",
    }
    for definition in definitions.values():
        assert private_properties.isdisjoint(definition.get("properties", {}))


def test_recovery_usage_schema_preserves_cost_and_optional_minimum_floor_bindings() -> None:
    model_execution = json.loads(
        (ROOT / "schemas" / "model_execution_artifact.schema.json").read_text()
    )
    cost_attempt = model_execution["$defs"]["CostLedgerAttemptEvidence"]
    assert cost_attempt["properties"]["logical_request_id"]["pattern"] == (
        r"^(?:scheduler-request|scheduler-recovery-request)-[0-9a-f]{64}$"
    )
    assert cost_attempt["properties"]["usage_record_sha256"]["anyOf"] == [
        {"pattern": r"^[0-9a-f]{64}$", "type": "string"},
        {"type": "null"},
    ]

    for filename in MODELS:
        schema = json.loads((ROOT / "schemas" / filename).read_text())
        definitions = schema.get("$defs", {})
        floor = definitions.get("MinimumAnalysisFloor")
        if floor is None:
            continue
        assert floor["properties"]["schema_version"]["enum"] == ["1.0", "1.1"]
        bindings = floor["properties"]["recovery_model_usage_bindings"]
        assert bindings["default"] == []
        assert bindings["maxItems"] == 32
        assert bindings["items"] == {"$ref": "#/$defs/MinimumFloorRecoveryModelUsageBinding"}
        assert floor["allOf"] == [
            {
                "if": {
                    "properties": {"schema_version": {"const": "1.1"}},
                    "required": ["schema_version"],
                },
                "then": {
                    "properties": {"recovery_model_usage_bindings": {"minItems": 1}},
                    "required": ["recovery_model_usage_bindings"],
                },
                "else": {"not": {"required": ["recovery_model_usage_bindings"]}},
            }
        ]
        binding = definitions["MinimumFloorRecoveryModelUsageBinding"]
        assert binding["additionalProperties"] is False
        assert binding["properties"]["request_id"]["pattern"] == (
            r"^scheduler-recovery-request-[0-9a-f]{64}$"
        )
        for field_name in (
            "usage_record_sha256",
            "scheduler_request_evidence_sha256",
            "binding_sha256",
        ):
            assert binding["properties"][field_name]["pattern"] == r"^[0-9a-f]{64}$"
        for field_name in (
            "review_credit_authorized",
            "completion_authorized",
            "release_authorized",
        ):
            assert binding["properties"][field_name]["const"] is False


def test_ground_truth_and_evidence_seal_schemas_are_strictly_non_authorizing() -> None:
    filenames = {
        "frozen_ground_truth_provenance.schema.json": FrozenGroundTruthProvenance,
        "evidence_sealed_authority.schema.json": EvidenceSealedAuthorityEvidence,
    }
    schemas = {
        filename: json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        for filename in filenames
    }
    for filename, model in filenames.items():
        assert MODELS[filename] is model
        assert schemas[filename]["additionalProperties"] is False

    provenance = schemas["frozen_ground_truth_provenance.schema.json"]
    assert provenance["title"] == "mmaudit frozen ground-truth provenance"
    assert provenance["properties"]["case_bindings"]["minItems"] == 1
    assert provenance["properties"]["case_bindings"]["maxItems"] == 10_000
    assert provenance["$defs"]["FrozenGroundTruthCaseBinding"]["additionalProperties"] is False
    assert provenance["$defs"]["SyntheticPlantedGroundTruthOrigin"]["additionalProperties"] is False
    assert (
        provenance["$defs"]["PublicEstablishedGroundTruthOrigin"]["additionalProperties"] is False
    )
    for field in (
        "authored_by_evaluated_process",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "authority_issuance_authorized",
    ):
        assert provenance["properties"][field]["const"] is False

    seal = schemas["evidence_sealed_authority.schema.json"]
    assert seal["title"] == "mmaudit non-authorizing evidence-seal comparison artifact"
    assert seal["properties"]["external_comparison_required"]["const"] is True
    for field in (
        "durable_authority",
        "source_egress_authorized",
        "benchmark_scoring_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
    ):
        assert seal["properties"][field]["const"] is False
    collision = seal["$defs"]["EvidenceSealCollisionMap"]
    assert collision["additionalProperties"] is False
    assert collision["properties"]["judges"]["minItems"] == 2
    assert collision["properties"]["judges"]["maxItems"] == 64
    prefix = seal["$defs"]["EvidenceTransparencyPrefixProof"]
    assert prefix["additionalProperties"] is False
    assert prefix["properties"]["leaf_sha256s"]["minItems"] == 1
    assert prefix["properties"]["leaf_sha256s"]["maxItems"] == 10_000


def test_frozen_model_lineage_provenance_schema_is_strictly_non_authorizing() -> None:
    filename = "frozen_model_lineage_provenance.schema.json"
    assert MODELS[filename] is FrozenModelLineageProvenance
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    assert schema["$id"] == f"https://mmaudit.local/schemas/{filename}"
    assert schema["title"] == "mmaudit mechanism-only frozen model lineage provenance"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["authority_basis"]["const"] == "MECHANISM_ONLY"
    assert schema["properties"]["projection_scope"]["const"] == ("LOCAL_SYNTHETIC_MECHANISM_TEST")
    assert schema["properties"]["bindings"]["minItems"] == 1
    assert schema["properties"]["bindings"]["maxItems"] == 128
    for field in (
        "completion_eligible",
        "non_model_authorship_verified",
        "external_provenance_verified",
        "real_provider_model_applicable",
        "lineage_identity_authorized",
        "provider_lineage_authorized",
        "runner_authority_authorized",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "release_authorized",
        "source_egress_authorized",
        "provider_access_authorized",
    ):
        assert schema["properties"][field]["const"] is False

    binding = schema["$defs"]["FrozenModelLineageBinding"]
    assert binding["additionalProperties"] is False
    assert binding["properties"]["root_lineage"]["pattern"] == r"^sha256:[0-9a-f]{64}$"
    assert binding["properties"]["origin"]["discriminator"] == {
        "mapping": {
            "PUBLIC_ESTABLISHED": "#/$defs/PublicEstablishedModelLineageOrigin",
            "SYNTHETIC_CONSTRUCTED": "#/$defs/SyntheticConstructedModelLineageOrigin",
        },
        "propertyName": "origin_kind",
    }
    synthetic = schema["$defs"]["SyntheticConstructedModelLineageOrigin"]
    public = schema["$defs"]["PublicEstablishedModelLineageOrigin"]
    assert synthetic["additionalProperties"] is False
    assert public["additionalProperties"] is False
    assert synthetic["properties"]["origin_kind"]["const"] == "SYNTHETIC_CONSTRUCTED"
    assert public["properties"]["origin_kind"]["const"] == "PUBLIC_ESTABLISHED"
    assert synthetic["properties"]["exact_model_id"]["pattern"] == (
        r"^synthetic-lineage:[a-z][a-z0-9_-]{0,31}/[a-z][a-z0-9._-]{0,63}$"
    )
    assert synthetic["properties"]["model_identity_domain"]["const"] == (
        "MMAUDIT_NON_DEPLOYABLE_SYNTHETIC_MODEL_LINEAGE_V1"
    )
    assert synthetic["properties"]["provenance_class"]["const"] == (
        "SYNTHETIC_CONSTRUCTED_TEST_FIXTURE"
    )
    assert synthetic["properties"]["construction_group_id"]["pattern"] == (
        r"^constructed-root-[a-z][a-z0-9-]{0,47}$"
    )
    assert synthetic["properties"]["construction_group_model_ids"]["minItems"] == 1
    assert synthetic["properties"]["construction_group_model_ids"]["maxItems"] == 32
    for field in (
        "construction_group_sha256",
        "construction_manifest_file_sha256",
        "construction_source_file_sha256",
        "regression_contract_file_sha256",
        "origin_sha256",
    ):
        assert synthetic["properties"][field]["pattern"] == r"^[0-9a-f]{64}$"
    assert synthetic["properties"]["construction_source_revision"]["pattern"] == (
        r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$"
    )
    for field in (
        "non_model_authorship_verified",
        "external_provenance_verified",
        "real_provider_model_applicable",
    ):
        assert synthetic["properties"][field]["const"] is False
    for field in ("non_model_authorship_verified", "external_provenance_verified"):
        assert public["properties"][field]["const"] is False
    assert (
        not {
            "VerifiedFrozenModelLineage",
            "VerifiedFrozenModelLineageProjection",
            "VerifiedFrozenModelLineagePairProjection",
        }
        & schema["$defs"].keys()
    )
    assert (
        not {"capability", "verified_capability", "verified_projection"}
        & schema["properties"].keys()
    )


def test_public_model_lineage_provenance_schema_is_bounded_and_non_authorizing() -> None:
    filename = "public_model_lineage_provenance.schema.json"
    assert MODELS[filename] is PublicModelLineageEvidenceBundle
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    properties = schema["properties"]
    definitions = schema["$defs"]
    sha256_pattern = r"^[0-9a-f]{64}$"
    exact_model_id_pattern = r"^[a-z0-9][a-z0-9._-]{0,127}/[a-z0-9][a-z0-9._:-]{0,255}$"

    assert schema["title"] == "mmaudit documentary public model lineage provenance"
    assert schema["additionalProperties"] is False
    assert properties["schema_version"]["const"] == "1.0"
    assert properties["evidence_standard"]["const"] == "DOCUMENTARY_EXACT_BYTES_V1"
    assert properties["sources"]["minItems"] == 1
    assert properties["sources"]["maxItems"] == 32
    assert properties["aliases"]["minItems"] == 1
    assert properties["aliases"]["maxItems"] == 128
    assert properties["claims"]["minItems"] == 1
    assert properties["claims"]["maxItems"] == 256
    assert properties["decisions"]["minItems"] == 1
    assert properties["decisions"]["maxItems"] == 128
    assert properties["conservative_non_independence_constraints"]["maxItems"] == 32
    for field_name in (
        "sources",
        "aliases",
        "claims",
        "decisions",
        "conservative_non_independence_constraints",
        "confirmed_exact_model_ids",
        "unconfirmed_exact_model_ids",
        "excluded_exact_model_ids",
        "approved_root_lineages",
    ):
        assert properties[field_name]["uniqueItems"] is True
    for field_name in (
        "confirmed_exact_model_ids",
        "unconfirmed_exact_model_ids",
        "excluded_exact_model_ids",
    ):
        assert properties[field_name]["maxItems"] == 128
        assert properties[field_name]["items"]["pattern"] == exact_model_id_pattern
    assert properties["approved_root_lineages"]["items"]["pattern"] == (r"^sha256:[0-9a-f]{64}$")
    for field_name in (
        "source_set_sha256",
        "alias_set_sha256",
        "claim_set_sha256",
        "decision_set_sha256",
        "constraint_set_sha256",
        "bundle_sha256",
    ):
        assert field_name in schema["required"]
        assert properties[field_name]["pattern"] == sha256_pattern

    assert definitions["PublicModelLineageSourceKind"]["enum"] == [
        "PRIMARY_PUBLISHER_MODEL_CARD",
        "AUTHORITATIVE_SECONDARY",
    ]
    assert definitions["PublicModelLineageClaimKind"]["enum"] == [
        "ROOT_ANCHOR",
        "ROOTS_WITH",
        "VAGUE",
    ]
    assert definitions["PublicModelLineageDecisionStatus"]["enum"] == [
        "CONFIRMED",
        "UNCONFIRMED",
    ]
    assert definitions["PublicModelLineageUnconfirmedReason"]["enum"] == [
        "MISSING_CLAIM",
        "VAGUE_ONLY",
        "INSUFFICIENT_CORROBORATION",
        "CONFLICTING_CLAIMS",
        "CYCLE",
        "UPSTREAM_UNCONFIRMED",
        "ALIAS_SOURCE_MISMATCH",
    ]
    assert definitions["PublicModelLineageConstraintKind"]["enum"] == [
        "DOCUMENTED_DIRECT_ANCESTRY",
        "CONSERVATIVE_ORGANIZATIONAL",
        "SOURCE_CONFLICT_CORRECTION",
    ]

    for definition_name in (
        "ManifestFileBinding",
        "PublicModelLineageSourceEvidence",
        "PublicModelLineageAliasBinding",
        "PublicModelLineageClaim",
        "PublicModelLineageDecision",
        "PublicModelLineageNonIndependenceConstraint",
    ):
        assert definitions[definition_name]["additionalProperties"] is False

    capture_binding = properties["capture_observations_file_binding"]["allOf"]
    assert capture_binding[0] == {"$ref": "#/$defs/ManifestFileBinding"}
    assert capture_binding[1]["properties"] == {
        "path": {"const": "capture-observations.json"},
        "size": {"maximum": 500_000, "minimum": 1},
    }
    file_binding = definitions["ManifestFileBinding"]
    assert set(file_binding["required"]) == {"path", "sha256", "size"}
    assert file_binding["properties"]["sha256"]["pattern"] == sha256_pattern

    source = definitions["PublicModelLineageSourceEvidence"]
    source_properties = source["properties"]
    assert {
        "source_id",
        "requested_url",
        "final_url",
        "redirect_chain",
        "publisher_id",
        "independence_key",
        "immutable_revision",
        "retrieved_at",
        "file_binding",
        "capture_observation_sha256",
        "source_evidence_sha256",
    }.issubset(source["required"])
    assert source_properties["redirect_chain"]["minItems"] == 1
    assert source_properties["redirect_chain"]["maxItems"] == 5
    assert source_properties["redirect_chain"]["uniqueItems"] is True
    assert source_properties["requested_url"]["pattern"].startswith("^https://")
    assert source_properties["final_url"]["pattern"].startswith("^https://")
    assert "@" not in source_properties["requested_url"]["pattern"]
    assert source_properties["immutable_revision"]["pattern"] == r"^[0-9a-f]{40}$"
    source_binding = source_properties["file_binding"]["allOf"]
    assert source_binding[0] == {"$ref": "#/$defs/ManifestFileBinding"}
    assert source_binding[1]["properties"]["size"] == {
        "maximum": 100_000,
        "minimum": 1,
    }
    for field_name in ("capture_observation_sha256", "source_evidence_sha256"):
        assert source_properties[field_name]["pattern"] == sha256_pattern

    alias = definitions["PublicModelLineageAliasBinding"]
    assert alias["properties"]["exact_model_id"]["pattern"] == exact_model_id_pattern
    assert alias["properties"]["source_ids"]["minItems"] == 1
    assert alias["properties"]["source_ids"]["maxItems"] == 32
    assert alias["properties"]["source_ids"]["uniqueItems"] is True
    assert alias["properties"]["alias_sha256"]["pattern"] == sha256_pattern

    claim = definitions["PublicModelLineageClaim"]
    claim_properties = claim["properties"]
    assert {
        "claim_id",
        "subject_exact_model_id",
        "claim_kind",
        "source_id",
        "decisive_primary_publisher",
        "byte_start",
        "byte_end",
        "exact_marker",
        "marker_sha256",
        "claim_sha256",
    }.issubset(claim["required"])
    assert claim_properties["subject_exact_model_id"]["pattern"] == exact_model_id_pattern
    assert claim_properties["source_id"]["pattern"] == r"^[a-z][a-z0-9-]{0,99}$"
    assert claim_properties["byte_start"]["minimum"] == 0
    assert claim_properties["byte_start"]["maximum"] == 100_000
    assert claim_properties["byte_end"]["exclusiveMinimum"] == 0
    assert claim_properties["byte_end"]["maximum"] == 100_000
    assert claim_properties["exact_marker"]["minLength"] == 1
    assert claim_properties["exact_marker"]["maxLength"] == 2_000
    for field_name in ("marker_sha256", "claim_sha256"):
        assert claim_properties[field_name]["pattern"] == sha256_pattern
    assert "UTF-8 marker length and SHA-256" in claim["$comment"]
    assert claim["allOf"][0]["then"]["required"] == ["target_exact_model_id"]
    assert claim["allOf"][1]["then"]["properties"]["decisive_primary_publisher"] == {"const": False}

    decision = definitions["PublicModelLineageDecision"]["properties"]
    assert decision["exact_model_id"]["pattern"] == exact_model_id_pattern
    assert decision["supporting_claim_ids"]["maxItems"] == 256
    assert decision["supporting_claim_ids"]["uniqueItems"] is True
    assert decision["decision_sha256"]["pattern"] == sha256_pattern
    root_options = decision["root_lineage"]["anyOf"]
    assert {option.get("pattern") for option in root_options} == {
        None,
        r"^sha256:[0-9a-f]{64}$",
    }

    constraint = definitions["PublicModelLineageNonIndependenceConstraint"]["properties"]
    assert constraint["member_exact_model_ids"]["minItems"] == 2
    assert constraint["member_exact_model_ids"]["maxItems"] == 16
    assert constraint["member_exact_model_ids"]["items"]["pattern"] == exact_model_id_pattern
    assert constraint["member_exact_model_ids"]["uniqueItems"] is True
    assert constraint["negative_only"]["const"] is True
    assert constraint["positive_root_assignment_authorized"]["const"] is False
    assert constraint["constraint_sha256"]["pattern"] == sha256_pattern

    for field_name in (
        "operator_review_authoritative",
        "provider_route_identity_required",
        "sigstore_lineage_receipt_required",
        "serialized_authority",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_authority_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "benchmark_authorized",
    ):
        assert properties[field_name]["const"] is False

    def property_names(value: object) -> set[str]:
        if isinstance(value, dict):
            names = set(value.get("properties", {}))
            return names | set().union(*(property_names(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(property_names(item) for item in value))
        return set()

    names = property_names(schema)
    assert {name for name in names if "route" in name} == {"provider_route_identity_required"}
    assert {name for name in names if "sigstore" in name} == {"sigstore_lineage_receipt_required"}
    assert (
        not {
            "provider_endpoint",
            "provider_id",
            "provider_route_id",
            "credential",
            "api_key",
            "authorization_header",
            "secret",
            "token",
            "sigstore_bundle",
            "sigstore_receipt",
            "rekor_entry",
            "tuf_metadata",
            "capability",
            "verified_capability",
            "private_capability",
        }
        & names
    )
    assert (
        not {
            "VerifiedPublicModelLineage",
            "VerifiedPublicModelLineageBindingProjection",
            "VerifiedPublicModelLineageInventory",
            "PublicModelLineageConfigurationProjection",
        }
        & definitions.keys()
    )


def test_autonomous_evidence_seal_verdict_schemas_are_strictly_non_authorizing() -> None:
    filenames = {
        "evidence_seal_verdict_policy.schema.json": EvidenceSealVerdictPolicy,
        "evidence_seal_verdict.schema.json": EvidenceSealVerdictProjection,
    }
    schemas = {
        filename: json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        for filename in filenames
    }
    for filename, model in filenames.items():
        assert MODELS[filename] is model
        assert schemas[filename]["additionalProperties"] is False

    policy = schemas["evidence_seal_verdict_policy.schema.json"]
    assert policy["title"] == "mmaudit frozen autonomous evidence-seal verdict policy"
    assert policy["properties"]["authority_basis"]["const"] == ("EVIDENCE_SEALED_REPRODUCIBLE")
    assert policy["properties"]["benchmark_case_count"]["const"] == 24
    assert policy["properties"]["dimension_floors"]["minItems"] == 17
    assert policy["properties"]["dimension_floors"]["maxItems"] == 17
    assert policy["properties"]["minimum_overall_score_micros"]["const"] == 1_000_000
    assert policy["properties"]["safety_dimensions"]["minItems"] == 3
    assert policy["properties"]["safety_dimensions"]["maxItems"] == 3
    assert policy["properties"]["required_execution_evidence"]["const"] == "real"
    assert policy["properties"]["exact_primary_count"]["const"] == 1
    assert policy["properties"]["minimum_replay_count"]["const"] == 1
    assert policy["properties"]["minimum_distinct_judge_roots"]["const"] == 2
    assert policy["properties"]["maximum_evidence_age_days"]["const"] == 7
    assert policy["properties"]["maximum_campaign_cost_usd_exact"]["const"] == "250"
    assert policy["properties"]["budget_comparator"]["const"] == "LESS_THAN"
    assert policy["properties"]["budget_scope"]["const"] == ("CANDIDATE_PRIMARY_AND_REPLAY")
    for field in (
        "require_zero_case_errors",
        "require_distinct_report_request_and_generation_ids",
        "require_byte_identical_replay",
        "require_closed_ledger_reconciliation",
        "comparison_only",
    ):
        assert policy["properties"][field]["const"] is True
    for field in (
        "durable_authority",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        "source_egress_authorized",
    ):
        assert policy["properties"][field]["const"] is False
    floor = policy["$defs"]["EvidenceSealDimensionFloor"]
    assert floor["additionalProperties"] is False
    assert floor["properties"]["exact_evaluated"]["minimum"] == 1
    assert floor["properties"]["exact_evaluated"]["maximum"] == 10_000
    assert floor["properties"]["minimum_score_micros"]["minimum"] == 0
    assert floor["properties"]["minimum_score_micros"]["maximum"] == 1_000_000
    baseline = policy["$defs"]["EvidenceSealFrozenBaselinePolicy"]
    assert baseline["additionalProperties"] is False
    assert baseline["properties"]["status"]["const"] == "NOT_FROZEN"
    assert baseline["properties"]["comparison_rule"]["const"] == (
        "PAIRED_CASE_DIMENSION_NON_REGRESSION_ONE_STRICT"
    )
    assert baseline["properties"]["baseline_projection_sha256"]["type"] == "null"
    assert baseline["properties"]["baseline_authority_subject_sha256"]["type"] == "null"

    verdict = schemas["evidence_seal_verdict.schema.json"]
    assert verdict["title"] == "mmaudit non-authorizing evidence-seal verdict projection"
    assert verdict["properties"]["authority_basis"]["const"] == ("EVIDENCE_SEALED_REPRODUCIBLE")
    assert verdict["properties"]["baseline_disposition"]["const"] == "UNEVALUABLE"
    assert verdict["properties"]["report_bindings"]["minItems"] == 2
    assert verdict["properties"]["report_bindings"]["maxItems"] == 64
    assert verdict["properties"]["case_dimension_outcomes"]["minItems"] == 1
    assert verdict["properties"]["case_dimension_outcomes"]["maxItems"] == 10_000
    assert verdict["properties"]["case_dimension_outcome_set_sha256"]["pattern"] == (
        r"^[0-9a-f]{64}$"
    )
    assert verdict["properties"]["dimensions"]["minItems"] == 17
    assert verdict["properties"]["dimensions"]["maxItems"] == 17
    assert verdict["properties"]["overall_score_micros"]["minimum"] == 0
    assert verdict["properties"]["overall_score_micros"]["maximum"] == 1_000_000
    assert verdict["properties"]["reason_codes"]["maxItems"] == 32
    assert verdict["properties"]["comparison_only"]["const"] is True
    for field in (
        "durable_authority",
        "authority_issuance_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "provider_access_authorized",
        "source_egress_authorized",
    ):
        assert verdict["properties"][field]["const"] is False
    for model_name in (
        "EvidenceSealBudgetProjection",
        "EvidenceSealCaseDimensionOutcome",
        "EvidenceSealDimensionFloor",
        "EvidenceSealDimensionVerdict",
        "EvidenceSealFrozenBaselinePolicy",
        "EvidenceSealVerdictPolicy",
        "EvidenceSealVerdictReportBinding",
        "QualificationDimensionThreshold",
        "QualificationPolicy",
        "RoleQualificationPolicy",
    ):
        assert verdict["$defs"][model_name]["additionalProperties"] is False
    assert verdict["$defs"]["EvidenceSealRequirementState"]["enum"] == [
        "PASS",
        "FAIL",
        "UNEVALUABLE",
    ]
    assert verdict["$defs"]["EvidenceSealPolicyDisposition"]["enum"] == [
        "STRUCTURALLY_SATISFIED",
        "NOT_SATISFIED",
        "UNEVALUABLE",
    ]
    assert verdict["$defs"]["EvidenceSealBudgetScope"]["enum"] == [
        "REPORT_USAGE_LOWER_BOUND",
        "CLOSED_CANDIDATE_PRIMARY_AND_REPLAY_LEDGER_CHAIN",
    ]
    assert verdict["$defs"]["EvidenceSealVerdictReason"]["enum"] == [
        "BASELINE_NOT_FROZEN",
        "BUDGET_AT_OR_ABOVE_CEILING",
        "BUDGET_CLOSURE_MISSING",
        "BUDGET_CLOSURE_UNRESOLVED",
        "CASE_EXECUTION_FAILED",
        "DIMENSION_FLOOR_NOT_MET",
        "EVIDENCE_STALE",
        "EVIDENCE_TIME_UNBOUND",
        "EXECUTION_NOT_REAL",
        "LINEAGE_COLLISION",
        "OVERALL_FLOOR_NOT_MET",
        "REPLAY_DIVERGED",
        "REPLAY_IDENTITY_REUSED",
    ]


def test_qualification_policy_has_a_published_strict_release_schema() -> None:
    filename = "model_qualification_policy.schema.json"
    assert MODELS[filename] is QualificationPolicy
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    assert schema["$id"] == f"https://mmaudit.local/schemas/{filename}"
    assert schema["title"] == "mmaudit model qualification policy"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["schema_version"]["enum"] == ["1.0", "2.0"]
    assert schema["properties"]["policy_sha256"]["pattern"] == r"^[0-9a-f]{64}$"
    assert schema["$defs"]["QualificationDimensionThreshold"]["additionalProperties"] is False
    assert schema["$defs"]["RoleQualificationPolicy"]["additionalProperties"] is False


def test_policy_eligibility_has_strict_non_authorizing_release_schemas() -> None:
    filenames = {
        "client_policy_constraints.schema.json": ClientPolicyConstraints,
        "model_policy_eligibility.schema.json": ModelPolicyEligibilityArtifact,
        "policy_eligibility_evaluation.schema.json": PolicyEligibilityEvaluation,
        "policy_review_signal.schema.json": PolicyReviewSignal,
    }
    schemas = {
        filename: json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        for filename in filenames
    }
    for filename, model in filenames.items():
        assert MODELS[filename] is model
        assert schemas[filename]["additionalProperties"] is False

    artifact = schemas["model_policy_eligibility.schema.json"]
    assert artifact["title"] == "mmaudit model policy eligibility artifact"
    assert artifact["properties"]["operator_decision_authenticity"]["const"] == (
        "NOT_INDEPENDENTLY_PROVEN"
    )
    assert artifact["properties"]["automated_eligibility_inference"]["const"] is False
    assert artifact["properties"]["production_selection_authorized"]["const"] is False
    assert "no authority" in artifact["description"]
    assert set(artifact["required"]) == {
        "artifact_sha256",
        "created_at",
        "determinations",
        "official_evidence",
    }
    for model_name in (
        "ModelPolicyEligibilityDetermination",
        "OfficialPolicyEvidenceReference",
        "PolicyCriterionAssessment",
        "PolicyEligibilityRoute",
    ):
        assert artifact["$defs"][model_name]["additionalProperties"] is False
    determination = artifact["$defs"]["ModelPolicyEligibilityDetermination"]
    assert determination["properties"]["assessments"]["minItems"] == 8
    assert determination["properties"]["assessments"]["maxItems"] == 8
    assert set(determination["required"]) == {
        "applicable_client_entity_sha256s",
        "applicable_client_jurisdictions",
        "applicable_operator_entity_sha256s",
        "applicable_operator_jurisdictions",
        "assessments",
        "decision",
        "determination_sha256",
        "effective_at",
        "expires_at",
        "intended_use",
        "review_record_sha256",
        "reviewed_at",
        "reviewed_by",
        "route",
    }
    for field in (
        "applicable_client_entity_sha256s",
        "applicable_client_jurisdictions",
        "applicable_operator_entity_sha256s",
        "applicable_operator_jurisdictions",
    ):
        assert determination["properties"][field]["minItems"] == 1
        assert determination["properties"][field]["maxItems"] == 128
    assert artifact["$defs"]["PolicyUsePurpose"]["enum"] == [
        "PAID_CUSTOMER_FACING_DEFENSIVE_SOURCE_AUDIT",
        "PUBLIC_OR_SYNTHETIC_DEFENSIVE_EVALUATION",
    ]
    assert artifact["$defs"]["PolicyEligibilityDecision"]["enum"] == [
        "ELIGIBLE",
        "INELIGIBLE",
        "REVIEW_REQUIRED",
    ]
    assert artifact["$defs"]["PolicyCriterionDisposition"]["enum"] == [
        "AMBIGUOUS",
        "PERMITTED",
        "PROHIBITED",
    ]
    assert artifact["$defs"]["PolicyLegalCriterion"]["enum"] == [
        "CLIENT_ENTITY_AND_JURISDICTION",
        "COMMERCIAL_CUSTOMER_FACING_USE",
        "COMMERCIAL_REPORT_INCORPORATION",
        "DEFENSIVE_SECURITY_ANALYSIS",
        "DEFENSIVE_TASK_SCOPE",
        "NO_RELEVANT_PROVIDER_OR_MODEL_RESTRICTION",
        "OPERATOR_ENTITY_AND_JURISDICTION",
        "SOURCE_CODE_ANALYSIS",
    ]

    constraints = schemas["client_policy_constraints.schema.json"]
    assert constraints["title"] == "mmaudit per-audit client policy constraints"
    assert "Unauthenticated" in constraints["description"]
    assert set(constraints["required"]) == {
        "audit_context",
        "constraint_basis_sha256",
        "constraints_sha256",
        "effective_at",
        "exact_model_ids",
        "exact_routes",
        "expires_at",
        "mode",
        "provider_names",
        "reviewed_at",
        "reviewed_by",
    }
    assert constraints["$defs"]["ClientConstraintMode"]["enum"] == [
        "ALLOW_ONLY",
        "DENY_ONLY",
    ]
    context = constraints["$defs"]["PolicyAuditContext"]
    assert context["additionalProperties"] is False
    assert set(context["required"]) == {
        "audit_scope_sha256",
        "client_entity_sha256",
        "client_jurisdiction",
        "context_sha256",
        "intended_use",
        "operator_entity_sha256",
        "operator_jurisdiction",
        "source_classification",
        "source_sha256",
    }
    assert context["properties"]["client_jurisdiction"]["pattern"] == (
        r"^[A-Z]{2,3}(?:-[A-Z0-9]{1,8})?$"
    )
    assert context["properties"]["operator_jurisdiction"]["pattern"] == (
        r"^[A-Z]{2,3}(?:-[A-Z0-9]{1,8})?$"
    )
    assert constraints["$defs"]["PolicyEligibilityRoute"]["additionalProperties"] is False

    evaluation = schemas["policy_eligibility_evaluation.schema.json"]
    assert evaluation["title"] == "mmaudit model policy eligibility evaluation"
    assert "never a production capability" in evaluation["description"]
    assert evaluation["properties"]["operator_decision_authenticity"]["const"] == (
        "NOT_INDEPENDENTLY_PROVEN"
    )
    assert evaluation["properties"]["automated_eligibility_inference"]["const"] is False
    assert evaluation["properties"]["production_selection_authorized"]["const"] is False
    assert evaluation["$defs"]["PolicyEligibilityExclusion"]["additionalProperties"] is False
    assert evaluation["$defs"]["PolicyEligibilityRoute"]["additionalProperties"] is False
    assert evaluation["$defs"]["PolicyExclusionReason"]["enum"] == [
        "AUDIT_SCOPE_RESTRICTED",
        "CLIENT_CONSTRAINTS_EXPIRED",
        "CLIENT_CONSTRAINTS_FUTURE",
        "CLIENT_ENDPOINT_RESTRICTED",
        "CLIENT_ENTITY_RESTRICTED",
        "CLIENT_JURISDICTION_RESTRICTED",
        "CLIENT_MODEL_RESTRICTED",
        "CLIENT_PROVIDER_RESTRICTED",
        "DECISION_INELIGIBLE",
        "DECISION_REVIEW_REQUIRED",
        "DETERMINATION_EXPIRED",
        "DETERMINATION_FUTURE",
        "MISSING_DETERMINATION",
        "OPERATOR_ENTITY_RESTRICTED",
        "OPERATOR_JURISDICTION_RESTRICTED",
        "ROUTE_MISMATCH",
        "SOURCE_RESTRICTED",
        "USE_PURPOSE_RESTRICTED",
    ]

    signal = schemas["policy_review_signal.schema.json"]
    assert signal["title"] == "mmaudit model policy review signal"
    assert "Non-authorizing" in signal["description"]
    assert signal["properties"]["automated_eligibility_inference"]["const"] is False
    assert signal["properties"]["production_selection_authorized"]["const"] is False
    assert signal["properties"]["reasons"]["minItems"] == 1
    assert signal["properties"]["reasons"]["maxItems"] == 4
    assert signal["$defs"]["PolicyReviewReason"]["enum"] == [
        "EXPIRED",
        "MISSING",
        "REVIEW_REQUIRED",
        "SOURCE_CHANGED",
    ]
    assert not any("ELIGIBLE" in reason for reason in signal["$defs"]["PolicyReviewReason"]["enum"])
    signal_observations = next(
        item
        for item in signal["properties"]["source_reference_observations"]["anyOf"]
        if item.get("type") == "array"
    )
    assert signal_observations["minItems"] == 1
    assert signal_observations["maxItems"] == 32
    assert "expected_source_content_sha256s" not in signal["properties"]
    assert "current_source_content_sha256s" not in signal["properties"]


def test_policy_eligibility_authority_has_strict_freshness_bound_release_schemas() -> None:
    filenames = {
        "model_policy_eligibility_authority.schema.json": (ModelPolicyEligibilityAuthorityEnvelope),
        "model_policy_eligibility_authority_receipt.schema.json": (
            ModelPolicyEligibilityAuthorityVerificationReceipt
        ),
        "model_policy_eligibility_trust_anchor.schema.json": (ModelPolicyEligibilityTrustAnchor),
        "policy_eligibility_source_observation.schema.json": (PolicyEligibilitySourceObservation),
    }
    schemas = {
        filename: json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        for filename in filenames
    }
    for filename, model in filenames.items():
        assert MODELS[filename] is model
        assert schemas[filename]["additionalProperties"] is False

    authority = schemas["model_policy_eligibility_authority.schema.json"]
    assert authority["title"] == "mmaudit signed model policy eligibility authority"
    assert authority["properties"]["detached_signature"]["maxLength"] == 16_384
    statement = authority["$defs"]["ModelPolicyEligibilityAuthorityStatement"]
    assert statement["additionalProperties"] is False
    assert statement["properties"]["signature_namespace"]["const"] == (
        "mmaudit-model-policy-eligibility-v1"
    )
    assert statement["properties"]["purpose"]["const"] == "POLICY_SELECTION_ONLY"
    assert statement["properties"]["operator_decision_authenticity"]["const"] == (
        "SSHSIG_ED25519_VERIFIED"
    )
    assert statement["properties"]["policy_selection_authorized"]["const"] is True
    assert statement["properties"]["qualification_authorized"]["const"] is False
    assert statement["properties"]["source_egress_authorized"]["const"] is False
    assert statement["properties"]["general_production_authorized"]["const"] is False
    assert {
        "audit_context_sha256",
        "client_constraints_sha256",
        "eligible_route_set_sha256",
        "initial_source_observation_sha256",
        "source_commitment_set_sha256",
        "source_observation_expires_at",
        "technical_route_set_sha256",
        "trust_anchor_sha256",
    }.issubset(statement["required"])

    anchor = schemas["model_policy_eligibility_trust_anchor.schema.json"]
    assert anchor["title"] == "mmaudit model policy eligibility trust anchor"
    assert "Operator-pinned" in anchor["description"]
    assert set(anchor["required"]) == {
        "operator_principal",
        "public_key",
        "public_key_sha256",
        "trust_anchor_sha256",
        "verifier_executable_sha256",
    }

    observation = schemas["policy_eligibility_source_observation.schema.json"]
    assert observation["title"] == "mmaudit current policy eligibility source observation"
    assert "required at issue and every use" in observation["description"]
    # An empty observation can record an all-missing refresh set, but the live
    # authority verifier still requires exact commitments for every eligible route.
    assert observation["properties"]["source_commitments"]["minItems"] == 0
    assert observation["properties"]["source_commitments"]["maxItems"] == 128
    commitment = observation["$defs"]["PolicyEligibilitySourceCommitment"]
    assert commitment["additionalProperties"] is False
    reference_observations = commitment["properties"]["source_reference_observations"]
    assert reference_observations["minItems"] == 1
    assert reference_observations["maxItems"] == 32
    assert "expected_source_content_sha256s" not in commitment["properties"]
    assert "current_source_content_sha256s" not in commitment["properties"]
    reference_observation = observation["$defs"]["PolicyEligibilitySourceReferenceObservation"]
    assert reference_observation["additionalProperties"] is False
    assert set(reference_observation["required"]) == {
        "reference_sha256",
        "expected_content_sha256",
        "current_content_sha256",
        "observation_sha256",
    }
    assert observation["$defs"]["PolicyEligibilityRoute"]["additionalProperties"] is False

    receipt = schemas["model_policy_eligibility_authority_receipt.schema.json"]
    assert receipt["title"] == ("mmaudit model policy eligibility authority verification receipt")
    assert "deliberately not authority" in receipt["description"]
    assert receipt["properties"]["policy_selection_authorized"]["const"] is False
    assert receipt["properties"]["qualification_authorized"]["const"] is False
    assert receipt["properties"]["source_egress_authorized"]["const"] is False
    assert receipt["properties"]["general_production_authorized"]["const"] is False
    assert {
        "audit_context_sha256",
        "client_constraints_sha256",
        "eligible_route_set_sha256",
        "initial_source_observation_sha256",
        "source_commitment_set_sha256",
        "source_observation_expires_at",
        "technical_route_set_sha256",
        "trust_anchor_sha256",
    }.issubset(receipt["required"])


def test_policy_eligibility_refresh_has_a_strict_non_authorizing_release_schema() -> None:
    filename = "model_policy_eligibility_refresh.schema.json"
    assert MODELS[filename] is ModelPolicyEligibilityRefreshArtifact
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    assert schema["title"] == "mmaudit model policy eligibility refresh artifact"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["projection_kind"]["const"] == (
        "POLICY_REDETERMINATION_SIGNAL_ONLY"
    )
    assert schema["properties"]["daily_refresh_max_age_hours"]["const"] == 24
    for field in (
        "automated_eligibility_inference",
        "policy_selection_authorized",
        "qualification_authorized",
        "source_egress_authorized",
        "production_selection_authorized",
    ):
        assert schema["properties"][field]["const"] is False
    route_record = schema["$defs"]["PolicyEligibilityRefreshRouteRecord"]
    assert route_record["additionalProperties"] is False
    assert route_record["properties"]["disposition"]["$ref"] == (
        "#/$defs/PolicyEligibilityRefreshRouteDisposition"
    )
    assert schema["$defs"]["PolicyEligibilityRefreshRouteDisposition"]["enum"] == [
        "NO_REVIEW_SIGNAL",
        "REDETERMINATION_REQUIRED",
    ]
    assert not any(
        "ELIGIBLE" in value
        for value in schema["$defs"]["PolicyEligibilityRefreshRouteDisposition"]["enum"]
    )


def test_audit_model_selection_has_a_strict_non_authorizing_release_schema() -> None:
    filename = "audit_model_selection.schema.json"
    assert MODELS[filename] is AuditModelSelection
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    assert schema["title"] == "mmaudit audit-scoped model selection"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["selection_policy"]["const"] == (
        "verified_technical_and_policy_eligible"
    )
    for field in (
        "technical_qualification_authorized",
        "policy_selection_authorized",
        "source_egress_authorized",
        "general_production_authorized",
    ):
        assert schema["properties"][field]["const"] is False
    assert schema["properties"]["models"]["minItems"] == 8
    assert schema["properties"]["models"]["maxItems"] == 128
    assert schema["properties"]["policy_exclusions"]["maxItems"] == 128
    assert {
        "audit_context_sha256",
        "client_constraints_sha256",
        "eligible_route_set_sha256",
        "policy_artifact_sha256",
        "policy_authority_envelope_sha256",
        "policy_authority_receipt_sha256",
        "policy_authority_statement_sha256",
        "policy_authority_trust_anchor_sha256",
        "policy_evaluation_sha256",
        "policy_exclusion_set_sha256",
        "policy_source_commitment_set_sha256",
        "policy_source_observation_sha256",
        "selected_model_set_sha256",
        "technical_production_selection_sha256",
        "technical_route_set_sha256",
    }.issubset(schema["required"])
    selected = schema["$defs"]["AuditSelectedTechnicalModel"]
    assert selected["additionalProperties"] is False
    assert selected["properties"]["technical_qualification_status"]["const"] == ("VERIFIED_TIER_A")
    assert selected["properties"]["policy_eligibility_status"]["const"] == "ELIGIBLE"


def test_audit_model_selection_evidence_has_a_strict_external_authority_schema() -> None:
    filename = "audit_model_selection_evidence.schema.json"
    assert MODELS[filename] is AuditModelSelectionEvidenceBundle
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))

    assert schema["title"] == "mmaudit audit-scoped model selection evidence"
    assert schema["additionalProperties"] is False
    assert schema["properties"]["technical_evidence_mode"]["const"] == (
        "EXTERNAL_AUTHORITY_HASH_JOIN_REQUIRED"
    )
    assert "technical_evidence_mode" in schema["required"]
    assert {
        "selection",
        "policy_artifact",
        "policy_evaluation",
        "audit_context",
        "client_constraints",
        "current_source_observation",
        "policy_authority_evidence",
        "bundle_sha256",
    }.issubset(schema["required"])
    assert schema["properties"]["selection"]["$ref"] == "#/$defs/AuditModelSelection"
    assert schema["properties"]["policy_artifact"]["$ref"] == (
        "#/$defs/ModelPolicyEligibilityArtifact"
    )
    assert schema["properties"]["policy_evaluation"]["$ref"] == (
        "#/$defs/PolicyEligibilityEvaluation"
    )
    assert schema["properties"]["policy_authority_evidence"]["$ref"] == (
        "#/$defs/ModelPolicyEligibilityAuthorityEvidenceProjection"
    )
    for definition in (
        "AuditModelSelection",
        "ClientPolicyConstraints",
        "ModelPolicyEligibilityArtifact",
        "ModelPolicyEligibilityAuthorityEnvelope",
        "ModelPolicyEligibilityAuthorityEvidenceProjection",
        "ModelPolicyEligibilityAuthorityStatement",
        "ModelPolicyEligibilityAuthorityVerificationReceipt",
        "ModelPolicyEligibilityTrustAnchor",
        "PolicyAuditContext",
        "PolicyEligibilityEvaluation",
        "PolicyEligibilitySourceObservation",
    ):
        assert schema["$defs"][definition]["additionalProperties"] is False
    for field in (
        "technical_qualification_authorized",
        "policy_selection_authorized",
        "source_egress_authorized",
        "general_production_authorized",
    ):
        assert schema["properties"][field]["const"] is False
        assert schema["$defs"]["AuditModelSelection"]["properties"][field]["const"] is False
        assert (
            schema["$defs"]["ModelPolicyEligibilityAuthorityEvidenceProjection"]["properties"][
                field
                if field != "technical_qualification_authorized"
                else "qualification_authorized"
            ]["const"]
            is False
        )
    assert (
        schema["$defs"]["ModelPolicyEligibilityArtifact"]["properties"][
            "automated_eligibility_inference"
        ]["const"]
        is False
    )
    assert (
        schema["$defs"]["ModelPolicyEligibilityArtifact"]["properties"][
            "production_selection_authorized"
        ]["const"]
        is False
    )
    assert (
        schema["$defs"]["PolicyEligibilityEvaluation"]["properties"][
            "automated_eligibility_inference"
        ]["const"]
        is False
    )
    assert (
        schema["$defs"]["PolicyEligibilityEvaluation"]["properties"][
            "production_selection_authorized"
        ]["const"]
        is False
    )
    assert schema["$defs"]["PolicyEligibilityExclusion"]["additionalProperties"] is False


def test_versioned_report_artifacts_bind_language_capability_without_rewriting_legacy() -> None:
    contracts = {
        "findings_artifact.schema.json": (["1.1", "1.2"], ["1.1"]),
        "model_execution_artifact.schema.json": (["1.0", "1.1", "1.2"], ["1.0", "1.1"]),
    }
    for filename, (versions, legacy_versions) in contracts.items():
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert schema["properties"]["schema_version"]["enum"] == versions
        assert schema["properties"]["schema_version"]["default"] == "1.2"
        language_rules = [
            {
                "if": {"properties": {"schema_version": {"const": "1.2"}}},
                "then": {
                    "properties": {"language_capability": {"not": {"type": "null"}}},
                    "required": ["language_capability"],
                },
            },
            {
                "if": {
                    "properties": {"schema_version": {"enum": legacy_versions}},
                    "required": ["schema_version"],
                },
                "then": {"not": {"required": ["language_capability"]}},
            },
        ]
        assert schema["allOf"][:2] == language_rules
        if filename == "model_execution_artifact.schema.json":
            assert "audit_model_selection" in schema["properties"]
            assert schema["allOf"][2] == {
                "if": {
                    "properties": {"audit_model_selection": {"not": {"type": "null"}}},
                    "required": ["audit_model_selection"],
                },
                "then": {"properties": {"schema_version": {"const": "1.2"}}},
            }
        else:
            assert len(schema["allOf"]) == 2


def test_models_config_schema_separates_identity_from_optional_measured_quality() -> None:
    schema = json.loads((ROOT / "schemas" / "models_config.schema.json").read_text())
    lineage = schema["$defs"]["ModelLineageConfig"]
    quality = schema["$defs"]["ModelQualityMeasurementConfig"]

    assert "measured_quality" not in lineage["required"]
    assert lineage["properties"]["measured_quality"] == {
        "$ref": "#/$defs/ModelQualityMeasurementConfig"
    }
    assert set(quality["required"]) == {"measurement", "score", "tier"}
    assert quality["additionalProperties"] is False
    assert quality["properties"]["measurement"]["pattern"] == r"^sha256:[0-9a-f]{64}$"
    assert lineage["properties"]["root_lineage"]["pattern"] == r"^sha256:[0-9a-f]{64}$"
    assert lineage["properties"]["canonical_model_id"]["pattern"] == (r"^[^\s/]+/[^\s/]+$")
    assert lineage["properties"]["aliases"]["items"]["pattern"] == r"^[^\s/]+/[^\s/]+$"
    assert lineage["properties"]["aliases"]["uniqueItems"] is True
    assert quality["allOf"] == [
        {
            "if": {"properties": {"tier": {"const": "high"}}, "required": ["tier"]},
            "then": {"properties": {"score": {"minimum": 0.75, "type": "number"}}},
        },
        {
            "if": {"properties": {"tier": {"const": "highest"}}, "required": ["tier"]},
            "then": {"properties": {"score": {"minimum": 0.9, "type": "number"}}},
        },
    ]
    assert "case-insensitively distinct" in lineage["$comment"]
    assert "not expressible" in schema["properties"]["registry"]["$comment"]


def _commented_lineage_example(path: Path, *, measured: bool) -> ModelLineageConfig:
    selected: list[str] = []
    in_example = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line == "# [[models.registry]]":
            in_example = True
        if not in_example:
            continue
        if line == "# [models.registry.measured_quality]" and not measured:
            break
        if line.startswith(
            (
                "# [[models.registry]]",
                "# [models.registry.measured_quality]",
                "# root_lineage =",
                "# canonical_model_id =",
                "# aliases =",
                "# retention_policy =",
                "# score =",
                "# tier =",
                "# measurement =",
            )
        ):
            selected.append(line.removeprefix("# "))
        if line.startswith("# measurement ="):
            break
    payload = tomllib.loads("\n".join(selected))
    return ModelLineageConfig.model_validate(payload["models"]["registry"][0])


def test_both_templates_expose_valid_identity_only_and_measured_examples() -> None:
    paths = (
        ROOT / "mmaudit.example.toml",
        ROOT / "src" / "mmaudit" / "templates" / "mmaudit.example.toml",
    )
    for path in paths:
        identity = _commented_lineage_example(path, measured=False)
        measured = _commented_lineage_example(path, measured=True)

        assert identity.measured_quality is None
        assert "measured_quality" not in identity.model_dump(mode="json")
        assert measured.aliases == identity.aliases
        assert measured.measured_quality is not None
        assert measured.measured_quality.measurement == "sha256:" + ("0" * 64)


def test_operator_templates_select_the_solidity_evm_capability_explicitly() -> None:
    for path in (
        ROOT / "mmaudit.example.toml",
        ROOT / "src" / "mmaudit" / "templates" / "mmaudit.example.toml",
        ROOT / "config" / "openrouter-qualification.toml",
    ):
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
        assert payload["language_profile"] == "solidity-evm"


def _release_schema_nodes(value: object) -> list[dict[str, object]]:
    nodes: list[dict[str, object]] = []
    if isinstance(value, dict):
        nodes.append(value)
        for child in value.values():
            nodes.extend(_release_schema_nodes(child))
    elif isinstance(value, list):
        for child in value:
            nodes.extend(_release_schema_nodes(child))
    return nodes


def _release_schema_property_names(schema: dict[str, object]) -> set[str]:
    names: set[str] = set()
    for node in _release_schema_nodes(schema):
        properties = node.get("properties")
        if isinstance(properties, dict):
            names.update(str(name) for name in properties)
    return names


def _assert_sha256_property_schema(property_schema: object) -> None:
    assert any(
        node.get("pattern") == r"^[0-9a-f]{64}$" for node in _release_schema_nodes(property_schema)
    )


def _assert_bounded_closed_authrunner_schema(schema: dict[str, object]) -> None:
    safe_value_ref = {"$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"}
    for node in _release_schema_nodes(schema):
        if node.get("type") == "array":
            assert isinstance(node.get("maxItems"), int)
        if node.get("type") != "object":
            continue
        additional = node.get("additionalProperties")
        assert additional is False or additional == safe_value_ref
        if additional == safe_value_ref:
            assert node.get("maxProperties") == 256
            assert isinstance(node.get("propertyNames"), dict)


def test_authenticated_cross_lineage_runner_release_schema_is_exact_and_non_authorizing() -> None:
    filename = "authenticated_cross_lineage_runner_evidence.schema.json"
    assert MODELS[filename] is AuthenticatedCrossLineageRunnerEvidence
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    definitions = schema["$defs"]

    assert schema["title"] == (
        "mmaudit non-authorizing authenticated cross-lineage runner evidence"
    )
    assert "retained PID-local custody" in schema["$comment"]
    assert schema["properties"]["case_ids"] == {
        "items": {"pattern": r"^case-[0-9a-f]{16}$", "type": "string"},
        "maxItems": 24,
        "minItems": 24,
        "title": "Case Ids",
        "type": "array",
        "uniqueItems": True,
    }
    runs = schema["properties"]["runs"]
    assert runs["minItems"] == runs["maxItems"] == 2
    assert runs["uniqueItems"] is True
    assert [
        item["allOf"][1]["properties"]["run_kind"]["const"] for item in runs["prefixItems"]
    ] == [
        "PRIMARY",
        "REPLAY",
    ]
    assert runs["items"] is False
    assert [item["contains"]["properties"]["run_kind"]["const"] for item in runs["allOf"]] == [
        "PRIMARY",
        "REPLAY",
    ]

    run = definitions["AuthenticatedCrossLineageRunnerRunEvidence"]
    for field_name in ("candidate_cases", "judge_cases"):
        inventory = run["properties"][field_name]
        assert inventory["minItems"] == inventory["maxItems"] == 24
        assert inventory["uniqueItems"] is True
    assert run["properties"]["candidate_campaign_report_sha256s"]["maxItems"] == 128
    assert run["properties"]["candidate_campaign_report_sha256s"]["uniqueItems"] is True

    ledger = definitions["AuthenticatedCrossLineageLedgerIntervalEvidence"]
    assert ledger["properties"]["cap_usd"]["const"] == "250"
    assert ledger["properties"]["entries"]["minItems"] == 96
    assert ledger["properties"]["entries"]["maxItems"] == 96 * 32
    assert ledger["properties"]["entries"]["uniqueItems"] is True
    decimal_pattern = r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$"
    for field_name in ("initial_spent_usd", "interval_spent_usd", "final_spent_usd"):
        assert ledger["properties"][field_name]["pattern"] == decimal_pattern
    entry = definitions["AuthenticatedCrossLineageLedgerEntryEvidence"]
    assert entry["properties"]["actual_cost_usd"]["pattern"] == decimal_pattern

    durable_false_fields = {
        "serialized_authority",
        "lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_custody_authorized",
        "generation_verification_authorized",
        "adjudication_credit_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "benchmark_authorized",
    }
    assert {
        name
        for name, property_schema in schema["properties"].items()
        if property_schema.get("const") is False
    } == durable_false_fields
    for owner in (schema, *definitions.values()):
        for name, property_schema in owner.get("properties", {}).items():
            if name.endswith("_sha256"):
                _assert_sha256_property_schema(property_schema)

    names = _release_schema_property_names(schema)
    assert {
        "api_key",
        "authorization_header",
        "credential",
        "private_source",
        "raw_source",
        "runner_capability",
        "runner_custody",
        "secret",
        "source_code",
        "verified_capability",
    }.isdisjoint(names)
    assert not any(name.startswith(("Trusted", "Verified")) for name in definitions)
    _assert_bounded_closed_authrunner_schema(schema)


def test_cross_lineage_adjudication_release_schema_is_real_bounded_and_non_authorizing() -> None:
    filename = "cross_lineage_adjudication_report.schema.json"
    assert MODELS[filename] is CrossLineageAdjudicationReport
    schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
    definitions = schema["$defs"]

    assert schema["title"] == "mmaudit non-authorizing cross-lineage adjudication report"
    assert "derived only from the frozen synthetic/public case" in schema["$comment"]
    assert definitions["CrossLineageAdjudicationRunKind"]["enum"] == ["PRIMARY", "REPLAY"]
    assert schema["properties"]["execution_evidence"]["const"] == "real"
    for field_name in ("case_ids", "cases"):
        inventory = schema["properties"][field_name]
        assert inventory["minItems"] == inventory["maxItems"] == 24
        assert inventory["uniqueItems"] is True
    assert schema["properties"]["case_ids"]["items"]["pattern"] == (r"^case-[0-9a-f]{16}$")

    request = definitions["CrossLineageAdjudicationCaseRequest"]
    prompt = request["properties"]["provider_visible_user_prompt"]
    assert prompt == {
        "maxLength": 500_000,
        "minLength": 1,
        "title": "Provider Visible User Prompt",
        "type": "string",
    }
    assert {
        "target_sha256",
        "candidate_report_sha256",
        "provider_visible_payload_sha256",
        "system_prompt_sha256",
        "user_prompt_sha256",
        "response_schema_sha256",
        "request_sha256",
    } <= set(request["required"])
    assert request["properties"]["schema_name"]["const"] == ("mmaudit_cross_lineage_adjudication")
    target = definitions["CrossLineageAdjudicationTarget"]
    exact_model_fields = {
        "candidate_model_id",
        "judge_model_id",
        "judge_canonical_model_id",
    }
    assert exact_model_fields <= set(target["required"])
    for field_name in exact_model_fields:
        assert target["properties"][field_name]["pattern"] == (
            r"^[A-Za-z0-9._-]+/[A-Za-z0-9._:/-]+$"
        )
    for field_name in ("candidate_root_lineage", "judge_root_lineage"):
        assert target["properties"][field_name]["pattern"] == r"^sha256:[0-9a-f]{64}$"

    for definition_name in ("UsageRecord", "OpenRouterGenerationEvidence"):
        assert definitions[definition_name]["properties"]["execution_evidence"]["const"] == ("real")
    usage = definitions["UsageRecord"]
    endpoints = usage["properties"]["configured_provider_endpoints"]
    assert endpoints["minItems"] == endpoints["maxItems"] == 1
    assert endpoints["uniqueItems"] is True
    routing = usage["properties"]["routing"]
    assert routing["additionalProperties"] == {
        "$ref": "#/$defs/AuthenticatedRunnerSafeRoutingValue"
    }
    assert routing["maxProperties"] == 256
    property_name_rules = routing["propertyNames"]["allOf"]
    assert property_name_rules[0]["pattern"] == r"^[a-z][a-z0-9_]{0,127}$"
    assert {
        "api_key",
        "api_token",
        "authorization_header",
        "bearer_token",
        "context_package",
        "context_request_evidence",
        "credential",
        "private_source",
        "provider_visible_user_prompt",
        "raw_source",
        "registry_state",
        "runner_capability",
        "runner_custody",
        "secret",
        "source_code",
        "verified_capability",
    } <= set(property_name_rules[1]["not"]["enum"])
    assert "secret" in property_name_rules[2]["not"]["pattern"]
    assert property_name_rules[3]["anyOf"] == [
        {"not": {"pattern": "capability"}},
        {"pattern": r"_capability_sha256$"},
    ]
    assert set(routing["required"]) == {
        "canonical_model",
        "data_collection",
        "discovery_evidence_sha256",
        "effective_privacy_policy_sha256",
        "endpoint_pricing_sha256",
        "endpoint_snapshot_sha256",
        "model_metadata_snapshot_sha256",
        "output_capability_sha256",
        "privacy_authorization",
        "privacy_endpoint_policy_class",
        "privacy_profile",
        "privacy_source_classification",
        "privacy_source_proof_kind",
        "privacy_source_provenance_sha256",
        "privacy_source_sha256",
        "provider_fallbacks_allowed",
        "selected_provider_endpoint",
        "selected_provider_name",
        "structured_output_capability_sha256",
        "structured_output_mode",
        "zdr_requested",
    }
    assert routing["properties"]["privacy_profile"]["const"] == "SYNTHETIC_BENCHMARK"
    assert routing["properties"]["privacy_source_classification"]["enum"] == [
        "PUBLIC_BENCHMARK",
        "SYNTHETIC_COMMITTED",
    ]
    assert routing["properties"]["privacy_source_proof_kind"]["const"] == (
        "RELEASE_PINNED_CROSS_LINEAGE_ADJUDICATION"
    )
    assert routing["properties"]["provider_fallbacks_allowed"]["const"] is False
    assert routing["properties"]["data_collection"]["const"] == "deny"

    response = definitions["CrossLineageAdjudicationResponse"]
    for field_name in ("wire_response_sha256", "adjudication_sha256"):
        assert response["properties"][field_name]["pattern"] == r"^[0-9a-f]{64}$"
    case_result = definitions["CrossLineageAdjudicationCaseResult"]
    for field_name in (
        "judge_validated_response_sha256",
        "judge_request_body_sha256",
        "usage_record_sha256",
        "case_result_sha256",
    ):
        assert case_result["properties"][field_name]["pattern"] == r"^[0-9a-f]{64}$"

    durable_false_fields = {
        "serialized_authority",
        "lineage_identity_authorized",
        "provider_call_authorized",
        "source_egress_authorized",
        "runner_authority_authorized",
        "generation_verification_authorized",
        "adjudication_credit_authorized",
        "model_qualification_authorized",
        "production_selection_authorized",
        "seal_publication_authorized",
        "release_authorized",
        "benchmark_authorized",
    }
    for owner in (
        schema,
        definitions["CrossLineageAdjudicationTarget"],
        definitions["CrossLineageAdjudicationCaseRequest"],
        case_result,
    ):
        assert {
            name
            for name, property_schema in owner["properties"].items()
            if property_schema.get("const") is False
        } == durable_false_fields
    for owner in (schema, *definitions.values()):
        for name, property_schema in owner.get("properties", {}).items():
            if name.endswith("_sha256"):
                _assert_sha256_property_schema(property_schema)

    names = _release_schema_property_names(schema)
    assert {
        "api_key",
        "authorization_header",
        "credential",
        "private_source",
        "raw_source",
        "runner_capability",
        "runner_custody",
        "secret",
        "source_code",
        "verified_capability",
    }.isdisjoint(names)
    assert "context_package" not in names
    assert "context_request_evidence" not in names
    assert "registry_state" not in names
    assert "provider_visible_user_prompt" in names
    assert all(name.endswith("_sha256") for name in names if "capability" in name)
    assert not any(name.startswith(("Trusted", "Verified")) for name in definitions)
    _assert_bounded_closed_authrunner_schema(schema)
