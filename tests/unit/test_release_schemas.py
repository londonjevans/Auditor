from __future__ import annotations

import json
import tomllib
from pathlib import Path

from mmaudit.config import ModelLineageConfig
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
