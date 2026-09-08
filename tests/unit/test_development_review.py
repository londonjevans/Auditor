from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from mmaudit.models.candidate_revocation import CandidateSelectionRevocationError
from mmaudit.models.development_costs import DevelopmentCostError
from mmaudit.models.development_review import (
    DEVELOPMENT_FIXTURE_PINS,
    DevelopmentReviewObservation,
    DevelopmentReviewResponse,
    prepare_development_review,
)
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.models.reasoning import ReasoningEffort, resolve_effective_reasoning_effort_inventory
from mmaudit.models.structured_output import StructuredOutputDecodeError, decode_structured_output
from scripts.generate_release_schemas import MODELS, rendered_schema
from tests.development_cost_support import FIXTURE
from tests.development_review_support import (
    FIXTURE_ROOT,
    discovery_review_case,
    response_payload,
    review_case,
)


@pytest.mark.parametrize("filename", ("ControlA.sol", "ControlB.sol"))
def test_preparation_binds_pinned_nondeployable_source_and_the_exact_request(filename: str) -> None:
    prepared = review_case(filename=filename)
    assert (
        filename,
        hashlib.sha256(prepared.source_content).hexdigest(),
    ) in DEVELOPMENT_FIXTURE_PINS
    body = json.loads(prepared.request_content)
    assert "abstract contract" in prepared.source_content.decode()
    assert (
        "only the configured administrator may change the limit" in prepared.source_content.decode()
    )
    assert body["model"] == prepared.estimate.exact_model_id
    assert body["reasoning"] == {"effort": "high"}
    assert body["response_format"]["json_schema"]["strict"] is True
    assert body["provider"]["allow_fallbacks"] is False
    assert body["provider"]["zdr"] is True
    assert len(prepared.request_content) == prepared.estimate.request_bytes
    assert "source_content=" not in repr(prepared)
    assert "request_content=" not in repr(prepared)


@pytest.mark.parametrize("change", ("bytes", "name", "oversize", "mutable"))
def test_unpinned_source_never_becomes_egress_by_caller_labelling(change: str) -> None:
    prepared = review_case()
    name = prepared.source_filename
    content = prepared.source_content
    if change == "bytes":
        content += b"\n// source drift\n"
    elif change == "name":
        name = "Private.sol"
    elif change == "oversize":
        content = b"x" * 16_385
    else:
        content = bytearray(content)  # type: ignore[assignment]
    with pytest.raises(DevelopmentCostError):
        prepare_development_review(
            policy=prepared.estimate.policy,
            endpoint_snapshot=prepared.endpoint_snapshot,
            source_filename=name,
            source_content=content,
            request_id="reject",
        )


@pytest.mark.parametrize("change", ("reasoning", "schema", "revoked"))
def test_preparation_retains_capability_and_negative_revocation_requirements(change: str) -> None:
    data = json.loads(FIXTURE.read_text())
    endpoint = data["endpoint"]
    model = data["request"]["model"]
    if change == "reasoning":
        endpoint["reasoning"]["supported_efforts"] = ["low"]
    elif change == "schema":
        endpoint["supported_parameters"].remove("structured_outputs")
    else:
        model = "deepseek/deepseek-v4-pro-0813"
        endpoint["tag"] = "parasail/fp8"
    snapshot = validate_openrouter_endpoint_snapshot(
        exact_model_id=model,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": model, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": model}]},
    )
    prepared = review_case()
    with pytest.raises((DevelopmentCostError, CandidateSelectionRevocationError)):
        prepare_development_review(
            policy=prepared.estimate.policy,
            endpoint_snapshot=snapshot,
            source_filename=prepared.source_filename,
            source_content=prepared.source_content,
            request_id="reject",
        )


@pytest.mark.parametrize(
    "change", ("commands", "omission", "fence", "duplicate", "reversed", "too_many")
)
def test_review_response_reuses_strict_decoder_without_repair_or_executable_fields(
    change: str,
) -> None:
    content = response_payload()["choices"][0]["message"]["content"]
    response = json.loads(content)
    if change == "commands":
        response["commands"] = ["synthetic-disabled-command"]
    elif change == "omission":
        del response["findings"][0]["recommendation"]
    elif change == "reversed":
        response["findings"][0]["line_start"] = 16
    elif change == "too_many":
        response["findings"] *= 17
    if change == "fence":
        content = f"```json\n{content}\n```"
    elif change == "duplicate":
        content = '{"summary":"a","summary":"b","findings":[]}'
    else:
        content = json.dumps(response)
    with pytest.raises(StructuredOutputDecodeError):
        decode_structured_output(content, DevelopmentReviewResponse)


def test_development_observation_schema_cannot_claim_audit_or_validation_credit() -> None:
    schema = DevelopmentReviewObservation.model_json_schema()
    for marker in (
        "findings_validated",
        "audit_complete",
        "qualification_eligible",
        "release_eligible",
    ):
        assert schema["properties"][marker]["const"] is False


@pytest.mark.parametrize(
    "filename",
    (
        "development_fixture_review_response.schema.json",
        "development_fixture_review_observation.schema.json",
    ),
)
def test_development_review_schemas_are_canonical(filename: str) -> None:
    material = (Path(__file__).resolve().parents[2] / "schemas" / filename).read_text()
    assert material == rendered_schema(filename, MODELS[filename])


def test_fixture_files_are_exact_and_have_guarded_counterpart() -> None:
    assert {path.name for path in FIXTURE_ROOT.iterdir()} == {
        name for name, _ in DEVELOPMENT_FIXTURE_PINS
    } | {"PreparedFormalProperties.sol"}
    for name, digest in DEVELOPMENT_FIXTURE_PINS:
        assert hashlib.sha256((FIXTURE_ROOT / name).read_bytes()).hexdigest() == digest
    assert "require(msg.sender == administrator" not in (FIXTURE_ROOT / "ControlA.sol").read_text()
    assert "require(msg.sender == administrator" in (FIXTURE_ROOT / "ControlB.sol").read_text()
    # The existing formal plumbing fixture shares this directory, not the paid allowlist.
    assert "PreparedFormalProperties.sol" not in dict(DEVELOPMENT_FIXTURE_PINS)
    baseline = review_case()
    with pytest.raises(DevelopmentCostError):
        prepare_development_review(
            policy=baseline.estimate.policy,
            endpoint_snapshot=baseline.endpoint_snapshot,
            source_filename="PreparedFormalProperties.sol",
            source_content=(FIXTURE_ROOT / "PreparedFormalProperties.sol").read_bytes(),
            request_id="formal-is-not-a-review-fixture",
        )


@pytest.mark.parametrize("form", ("discovery", "constrained_snapshot"))
def test_model_only_reasoning_metadata_reaches_pinned_development_preparation(form: str) -> None:
    discovery = discovery_review_case(constrained=form == "constrained_snapshot")
    snapshot = discovery.endpoint_snapshot
    assert snapshot.endpoints[0].supported_reasoning_efforts is None
    assert discovery.model_supported_reasoning_efforts == ("low", "high", "max")
    metadata = snapshot if form == "constrained_snapshot" else discovery
    if form == "discovery":
        assert snapshot.normalized_route_facts is None
    original = metadata.model_dump_json()
    baseline = review_case()
    prepared = prepare_development_review(
        policy=baseline.estimate.policy,
        endpoint_snapshot=metadata,
        source_filename=baseline.source_filename,
        source_content=baseline.source_content,
        request_id=baseline.estimate.request_id,
    )
    body = json.loads(prepared.request_content)
    assert body["reasoning"] == {"effort": "high"}
    assert body["provider"] == json.loads(baseline.request_content)["provider"]
    assert prepared.endpoint_snapshot == snapshot
    assert prepared.estimate.endpoint_snapshot_sha256 == snapshot.snapshot_sha256
    assert original == metadata.model_dump_json()
    assert discovery.canonical_slug.encode() not in prepared.request_content
    assert "discovery=" not in repr(prepared)


@pytest.mark.parametrize(
    ("endpoint_efforts", "model_efforts", "accepted"),
    (
        (None, ("low", "high", "max"), True),
        (("high",), None, True),
        (("high",), ("low", "high", "max"), True),
        ((), ("low", "high", "max"), False),
        (("low",), ("low", "high", "max"), False),
        (("high",), ("low",), False),
        (("low", "high"), ("high",), False),
        (None, None, False),
        (None, (), False),
        (None, ("low",), False),
        ((), None, False),
    ),
)
def test_development_reasoning_matches_shared_absence_only_admission_rules(
    endpoint_efforts: tuple[ReasoningEffort, ...] | None,
    model_efforts: tuple[ReasoningEffort, ...] | None,
    accepted: bool,
) -> None:
    _, state, _, supports_high = resolve_effective_reasoning_effort_inventory(
        endpoint_efforts=endpoint_efforts, model_efforts=model_efforts
    )
    assert accepted is (state == "PUBLISHED" and supports_high is True)
    baseline = review_case()

    def prepare() -> None:
        metadata = discovery_review_case(
            endpoint_efforts=endpoint_efforts, model_efforts=model_efforts
        )
        result = prepare_development_review(
            policy=baseline.estimate.policy,
            endpoint_snapshot=metadata,
            source_filename=baseline.source_filename,
            source_content=baseline.source_content,
            request_id="metadata-matrix",
        )
        assert result.discovery == metadata
        assert result.discovery is not metadata

    if accepted:
        prepare()
    else:
        # Contradictions may fail earlier in the existing discovery validator, never be promoted.
        with pytest.raises(ValueError):
            prepare()


def test_extracting_an_unconstrained_snapshot_does_not_invent_the_discarded_model_inventory() -> (
    None
):
    discovery = discovery_review_case()
    assert discovery.endpoint_snapshot.normalized_route_facts is None
    baseline = review_case()
    with pytest.raises(DevelopmentCostError, match="high reasoning"):
        prepare_development_review(
            policy=baseline.estimate.policy,
            endpoint_snapshot=discovery.endpoint_snapshot,
            source_filename=baseline.source_filename,
            source_content=baseline.source_content,
            request_id="discarded-model-inventory",
        )


@pytest.mark.parametrize("missing", ("reasoning", "structured_outputs"))
def test_published_effort_does_not_override_negative_model_parameter_inventory(
    missing: str,
) -> None:
    parameters = ("max_tokens", "reasoning", "response_format", "structured_outputs", "temperature")
    baseline = review_case()
    with pytest.raises(ValueError):
        discovery = discovery_review_case(
            model_parameters=tuple(value for value in parameters if value != missing)
        )
        prepare_development_review(
            policy=baseline.estimate.policy,
            endpoint_snapshot=discovery,
            source_filename=baseline.source_filename,
            source_content=baseline.source_content,
            request_id="negative-model-capability",
        )
