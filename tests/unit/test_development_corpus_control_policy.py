"""Published v1 bytes stay exact while every documented claim-weight branch is exercised."""

from __future__ import annotations

import hashlib
import socket
import subprocess

import pytest

from mmaudit.benchmark.development_corpus_control_measurement import (
    DevelopmentCorpusControlMeasurement,
    measure_development_corpus_controls,
)
from tests.development_corpus_control_measurement_support import direct_responses, retained_score

# Captured from the published 4d85e7f implementation before its schema-only wording change.
EXPECTED_JSON_SHA256 = {
    "0-0-advisory": "f2d7528eb743428c84530edb2b4a47b8448aad03dfa1f9d85b640cf4eaa6bbdc",
    "0-0-invariant": "a5d8394f2e301f3a65d9ef95e1ab939ebb353af5e638fc2f387ccf1bd6eaf38f",
    "0-0-unmatched_advisory": "6932542b504b55c9aaadd9aa50afb0310520bfe21e6e615cd06068e3c9936766",
    "0-0-unmatched_invariant": "193cc2b743657e31aeff5d38a88dc81432227a7c3c557d26235b4ece53369671",
    "0-1-advisory": "0b6c9681e99beba2091e7dd7c85bd68bec57676421b705b91345399e8511c2d3",
    "0-1-invariant": "1eef4943165d7593ec7b7d2ee9f8544eb1121f7a89a49c727a2814261f4099d4",
    "0-1-unmatched_advisory": "a7f6b086de95fcd76f6af9bfc460e7cc7137f35f748b05eba9ce29aa031f100a",
    "0-1-unmatched_invariant": "cf8107dc0113ce7e0282a43a6310381f9c99ba43795890c2cab6bdff3ac0a074",
    "1-0-advisory": "f869d3a6667bfd2096a14d39f2530d0d161a0536f8e7f7b0a479cb7f0571a519",
    "1-0-invariant": "a7ffc3d9dcdf9608e2e63bbaee3ddf6250723b2723a3f94c53014ca1f22da578",
    "1-0-unmatched_advisory": "af0bfc0800cadf024721ebde777f01a3523e8be1738ef3e887236ba6bbe0858b",
    "1-0-unmatched_invariant": "c82cbbd0e70556d66787fba74e0c57ddfcb628a558b3e59996b8cd5376d210f1",
    "1-1-advisory": "e4031e81f58e3827ccc2b122e095c433ee2b321bef549a440aae357723b7bd79",
    "1-1-invariant": "f8bd48264bc8538de438be4797280b5c652755b00d86defed2ce5b3626c5fe89",
    "1-1-unmatched_advisory": "2b03a45e77340dac69b7bb812ca9b46929460c36ca0ccd5bda90db1ea4348bd6",
    "1-1-unmatched_invariant": "f650e5826ec2e10ab94bf20e182942efb20f75cad25ef21f169681b5d2690224",
}


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("control policy evidence attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def measured(*, cumulative=False, complete=True, kind="invariant", severity="critical"):
    responses = direct_responses(advisory=kind.endswith("advisory"), severity=severity)
    if kind.startswith("unmatched_"):
        for response in responses:
            for finding in response["findings"]:
                finding.update(line_start=1, line_end=1)
    return measure_development_corpus_controls(
        score=retained_score(cumulative=cumulative, complete=complete, responses=responses)
    )


@pytest.mark.parametrize("cumulative", [False, True])
@pytest.mark.parametrize("complete", [False, True])
@pytest.mark.parametrize(
    "kind", ["invariant", "advisory", "unmatched_invariant", "unmatched_advisory"]
)
def test_policy_description_preserves_published_original_and_cumulative_measurement_bytes(
    cumulative, complete, kind
):
    value = measured(cumulative=cumulative, complete=complete, kind=kind)
    key = f"{int(cumulative)}-{int(complete)}-{kind}"
    assert hashlib.sha256(value.model_dump_json().encode()).hexdigest() == EXPECTED_JSON_SHA256[key]
    assert value.schema_version == "1.0"
    assert value.scorer_version == "manifest-annotation-independent-controls-v1"
    assert value.precision_denominator == "ALL_CLAIMS_WITH_FROZEN_MATCH_OR_MAX_AMBIGUOUS_WEIGHTS"


@pytest.mark.parametrize("kind", ["unmatched_invariant", "unmatched_advisory"])
@pytest.mark.parametrize(
    "severity,weight",
    [("critical", 10), ("high", 5), ("medium", 3), ("low", 1), ("informational", 1)],
)
def test_every_unmatched_claim_keeps_its_reported_severity_in_both_denominators(
    kind, severity, weight
):
    value = measured(kind=kind, severity=severity)
    assert len(value.claims) == value.summary.unmatched_claim_count == 2
    assert all(
        claim.disposition == "UNMATCHED" and claim.weight == weight for claim in value.claims
    )
    assert value.summary.severity_weighted_structural_precision.denominator == 2 * weight
    assert value.summary.severity_weighted_asserted_structural_precision.denominator == 2 * weight
    assert not value.summary.located_root_ids and not value.summary.invariant_asserted_root_ids
    assert value.summary.severity_weighted_structural_precision.numerator == 0
    assert value.summary.severity_weighted_asserted_structural_precision.numerator == 0


def test_schema_explains_frozen_ambiguous_and_unmatched_weights_without_replacing_v1_identifier():
    field = DevelopmentCorpusControlMeasurement.model_json_schema()["properties"][
        "precision_denominator"
    ]
    assert field["const"] == "ALL_CLAIMS_WITH_FROZEN_MATCH_OR_MAX_AMBIGUOUS_WEIGHTS"
    assert field["default"] == field["const"]
    description = field["description"]
    assert "every claim contributes to both precision denominators" in description
    assert "frozen control severity" in description
    assert "maximum candidate control weight" in description
    assert "unmatched claim uses reported severity" in description
