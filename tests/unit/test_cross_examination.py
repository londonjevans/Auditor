from __future__ import annotations

import pytest

from mmaudit.agents.verifier import (
    anonymize_cross_examination_candidates,
    normalize_cross_examination_response,
    select_candidate_falsifier_models,
    select_validation_falsifier_models,
)
from mmaudit.models.openrouter import OpenRouterSchemaError
from mmaudit.models.schemas import (
    CandidateCrossExaminationResponse,
    CandidateCrossExaminationResponseDecision,
    CandidateCrossExaminationVerdict,
)
from tests.conftest import model_registry_entry


def test_cross_examination_payload_removes_origin_identity(candidate_factory) -> None:
    candidate = candidate_factory(
        candidate_id="internal-candidate-id",
        role="specialist:access_control",
        family="origin/root-family",
    )

    payload, candidate_ids = anonymize_cross_examination_candidates([candidate])

    assert candidate_ids == {"candidate-0001": "internal-candidate-id"}
    assert payload[0]["candidate_ref"] == "candidate-0001"
    assert {
        "candidate_id",
        "role",
        "model_family",
        "model_votes",
    }.isdisjoint(payload[0])
    assert all("source" not in evidence for evidence in payload[0]["evidence"])


def test_candidate_falsifier_rejects_unknown_intake_reference() -> None:
    response = CandidateCrossExaminationResponse(
        decisions=[
            CandidateCrossExaminationResponseDecision(
                candidate_ref="candidate-0001",
                verdict=CandidateCrossExaminationVerdict.SUPPORTED,
                rationale="The supplied evidence remains internally consistent.",
            ),
            CandidateCrossExaminationResponseDecision(
                candidate_ref="candidate-9999",
                verdict=CandidateCrossExaminationVerdict.DISPUTED,
                rationale="This reference was never submitted.",
            ),
        ]
    )

    with pytest.raises(OpenRouterSchemaError, match="unknown candidate"):
        normalize_cross_examination_response(
            response,
            candidate_ids={"candidate-0001": "candidate-real"},
            request_id="request-falsifier-1",
            reviewer_index=1,
            requested_model="reviewer/one",
            returned_model="reviewer/one",
            root_lineage="sha256:" + ("a" * 64),
        )


def test_candidate_falsifiers_use_two_distinct_registered_lineages(
    config_factory,
) -> None:
    base = config_factory()
    falsifier_entry = model_registry_entry("reviewer/falsifier")
    registry = [
        *(entry.model_dump(mode="json") for entry in base.models.registry),
        falsifier_entry,
    ]
    config = config_factory(
        privacy={"approved_model_lineages": [entry["root_lineage"] for entry in registry]},
        models={
            "specialists": {
                "falsifier": {
                    "primary": "reviewer/falsifier",
                    "fallbacks": [],
                }
            },
            "registry": registry,
        },
    )

    selected = select_candidate_falsifier_models(config)

    assert len(selected) == 2
    assert len({root_lineage for _model_id, root_lineage in selected}) == 2


def test_candidate_falsifier_portfolios_use_registered_roles_without_optional_specialist(
    config_factory,
) -> None:
    config = config_factory()

    cross_examiners = select_candidate_falsifier_models(config)
    validation_falsifiers = select_validation_falsifier_models(config)

    assert [model_id for model_id, _lineage in cross_examiners] == [
        config.models.verifier.primary,
        config.models.judge.primary,
    ]
    assert [model_id for model_id, _lineage in validation_falsifiers] == [
        config.models.judge.primary,
        config.models.business_logic.primary,
    ]
    verifier_lineage = next(
        entry.root_lineage
        for entry in config.models.registry
        if entry.canonical_model_id == config.models.verifier.primary
    )
    assert verifier_lineage not in {lineage for _model_id, lineage in validation_falsifiers}
    assert len({lineage for _model_id, lineage in validation_falsifiers}) == 2


def test_candidate_falsifiers_exclude_unapproved_lineages(
    config_factory,
) -> None:
    base = config_factory()
    falsifier_entry = model_registry_entry("reviewer/falsifier")
    registry = [
        *(entry.model_dump(mode="json") for entry in base.models.registry),
        falsifier_entry,
    ]
    config = config_factory(
        privacy={"approved_model_lineages": []},
        models={
            "specialists": {
                "falsifier": {
                    "primary": "reviewer/falsifier",
                    "fallbacks": [],
                }
            },
            "registry": registry,
        },
    )

    assert select_candidate_falsifier_models(config) == []
