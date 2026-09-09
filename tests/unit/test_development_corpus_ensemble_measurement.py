"""Original-score recomputation and descriptive opinions from synthetic retained observations."""

from __future__ import annotations

import asyncio
import json
import socket
import subprocess
from itertools import product
from pathlib import Path

import httpx
import pytest
from jsonschema import Draft202012Validator

from mmaudit.benchmark.development_corpus import score_development_corpus
from mmaudit.benchmark.development_corpus_ensemble import (
    DevelopmentCorpusEnsembleScore,
    score_development_corpus_ensemble,
)
from tests.development_corpus_benchmark_support import truth_binding
from tests.development_corpus_ensemble_support import composed_observation, manifest_ensemble_case
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    response_payload,
)


def forbid_external(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("ensemble measurement control attempted external execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture(scope="module")
def measured(tmp_path_factory):
    with pytest.MonkeyPatch.context() as monkeypatch:
        forbid_external(monkeypatch)
        case = execution_case(tmp_path_factory.mktemp("synthetic-ensemble-measurement"))
        observation = asyncio.run(execute(case))
        return score_development_corpus_ensemble(binding=case.binding, observation=observation)


def test_original_score_and_all_claims_survive_refutation(measured):
    assert measured.candidate_score == score_development_corpus(
        binding=measured.binding, observation=measured.observation.candidate
    )
    assert (
        tuple(row.candidate_measurement for row in measured.claims)
        == measured.candidate_score.claims
    )
    assert measured.summary.refuted_by_one_count == measured.summary.disagreement_count == 3
    assert measured.summary.matched_root_claims_refuted_by_one_count == 1
    assert measured.candidate_score.summary.unique_root_recall.value == 1
    assert not measured.audit_complete and not measured.findings_validated
    assert measured.lineage_independence == "NOT_ESTABLISHED"


def test_composed_score_conforms_to_its_canonical_schema(measured):
    path = (
        Path(__file__).resolve().parents[2]
        / "schemas/development_corpus_ensemble_score.schema.json"
    )
    validator = Draft202012Validator(json.loads(path.read_text()))
    validator.validate(measured.model_dump(mode="json"))
    data = measured.model_dump(mode="json")
    data["findings_validated"] = True
    assert not validator.is_valid(data)


@pytest.mark.parametrize(
    "field",
    [
        "digest",
        "original_score",
        "drop_claim",
        "opinion",
        "consensus",
        "refutation",
        "count",
        "fraction",
        "scope",
        "cost",
        "labels",
        "authority",
        "lineage",
    ],
)
def test_serialized_measurement_cannot_rewrite_originals_or_promote_opinions(measured, field):
    data = measured.model_dump(mode="json")
    if field == "digest":
        data["observation_sha256"] = "a" * 64
    elif field == "original_score":
        data["candidate_score"] = None
    elif field == "drop_claim":
        data["claims"].pop()
    elif field == "opinion":
        data["claims"][0]["opinions"][1] = "SUPPORTED"
    elif field == "consensus":
        data["claims"][0]["consensus"] = "SUPPORTED"
    elif field == "refutation":
        data["claims"][0]["refutation_scope"] = "REFUTED_BY_BOTH"
    elif field == "count":
        data["summary"]["matched_root_claims_refuted_by_one_count"] = 0
    elif field == "fraction":
        data["summary"]["available_claim_opinion_observation_fraction"]["value"] = 0
    elif field == "scope":
        data["summary"]["overall_observation_scope"] = "NO_CANDIDATES"
    elif field == "cost":
        data["observation"]["total_accounted_cost_usd"] = "0"
    elif field == "labels":
        data["binding"]["truth_file_sha256"] = "b" * 64
    elif field == "authority":
        data["qualification_eligible"] = True
    else:
        data["lineage_independence"] = "ESTABLISHED"
    with pytest.raises(ValueError):
        DevelopmentCorpusEnsembleScore.model_validate_json(json.dumps(data), strict=True)


@pytest.mark.parametrize(
    "opinions", list(product(("SUPPORTED", "REFUTED", "INCONCLUSIVE"), repeat=2))
)
def test_every_complete_opinion_pair_is_descriptive_not_filtered(tmp_path, monkeypatch, opinions):
    forbid_external(monkeypatch)
    case = execution_case(tmp_path)

    def response(role, ordinal, _request):
        if role:
            return httpx.Response(
                200, json=response_payload(case.prepared, role, ordinal, verdict=opinions[role - 1])
            )

    observation = asyncio.run(execute(case, custom=response))
    score = score_development_corpus_ensemble(binding=case.binding, observation=observation)
    assert len(score.claims) == len(score.candidate_score.claims) == 3
    assert all(row.opinions == opinions for row in score.claims)
    assert score.summary.refuted_by_one_count == (3 if opinions.count("REFUTED") == 1 else 0)
    assert score.summary.refuted_by_both_count == (3 if opinions.count("REFUTED") == 2 else 0)
    assert score.summary.disagreement_count == (3 if opinions[0] != opinions[1] else 0)
    assert score.summary.inconclusive_opinion_count == 3 * opinions.count("INCONCLUSIVE")
    assert score.candidate_score.summary.unique_root_recall.value == 1


def test_missing_original_candidate_has_no_fabricated_baseline_or_quality():
    prepared = manifest_ensemble_case()
    observation = composed_observation(prepared.plan)
    result = score_development_corpus_ensemble(
        binding=truth_binding(prepared.candidate), observation=observation
    )
    assert result.candidate_score is None and result.claims == ()
    assert result.summary.overall_observation_scope == "INCOMPLETE_OBSERVATIONS"
    assert result.summary.unobserved_candidate_shard_count == 6
    assert result.summary.available_claim_opinion_observation_fraction.value is None


@pytest.mark.parametrize("kind", ["binding", "observation"])
def test_untyped_measurement_input_refuses(measured, kind):
    values = dict(binding=measured.binding, observation=measured.observation)
    values[kind] = values[kind].model_dump()
    with pytest.raises(ValueError, match="exact original input types"):
        score_development_corpus_ensemble(**values)
