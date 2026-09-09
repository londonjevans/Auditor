"""Signer-free calibration observations preserve evidence and never self-authorize."""

import copy
import json
import pickle
import socket
import subprocess

import pytest

import mmaudit.models.authenticated_calibration as calibration
import mmaudit.models.calibration as legacy
from mmaudit.models.autonomous_benchmark_verdict import canonical_usd_sum
from mmaudit.models.qualification import (
    DETERMINISTIC_QUALIFICATION_DIMENSIONS,
    QualificationRoleClass,
)
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.authenticated_calibration_support import (
    population,
    reseal_decision,
    reseal_source,
    structural_source,
)


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("calibration validation attempted network or subprocess execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


def artifact():
    source = structural_source()
    return calibration._assemble_artifact(
        (source.collision_map.candidate.exact_model_id,), (source,)
    )


def test_exact_structural_observations_retain_primary_replay_and_costs_without_authority():
    source = structural_source()
    measured = artifact()
    assert measured.sources == (source,)
    assert measured.candidates[0].dimensions == source.runs[0].dimensions
    assert len(measured.sources[0].runs) == 2
    assert measured.included_root_lineage_count == 1
    assert measured.retained_cost_usd == source.runner_evidence.ledger_interval.final_spent_usd
    assert all(d.candidate_count == d.included_candidate_count == 1 for d in measured.distributions)
    assert measured.external_seal_required and not measured.serialized_authority
    assert not measured.model_qualification_authorized and not measured.policy_adoption_authorized
    raw = calibration.authenticated_model_calibration_bytes(measured)
    assert calibration.read_authenticated_model_calibration(raw) == measured
    with pytest.raises(ValueError, match="candidate/root support"):
        calibration._policy_proposal(measured)


@pytest.mark.parametrize("capability", [None, {}, object()])
def test_structural_calibration_never_creates_live_policy_authority(capability):
    with pytest.raises(ValueError, match="absent or revoked"):
        calibration.derive_authenticated_calibration_policy(
            calibration=artifact(), verification=capability
        )


def test_forged_opaque_object_cannot_derive_or_revoke():
    with pytest.raises(TypeError):
        calibration.VerifiedAuthenticatedModelCalibration()
    forged = object.__new__(calibration.VerifiedAuthenticatedModelCalibration)
    with pytest.raises(ValueError, match="absent or revoked"):
        forged.require_for(artifact())
    with pytest.raises(ValueError, match="absent or revoked"):
        calibration.revoke_verified_authenticated_model_calibration(forged)
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError):
            operation(forged)


def measure(sources):
    return calibration._assemble_artifact(
        tuple(source.collision_map.candidate.exact_model_id for source in sources), sources
    )


def test_eight_candidates_six_roots_use_fixed_policy_and_exact_primary_denominators():
    measured = measure(population())
    assert len(measured.candidates) == 8 and measured.included_root_lineage_count == 6
    assert measured.retained_cost_usd == "7.68"
    proposal = calibration._policy_proposal(measured)
    assert proposal.calibration_artifact_sha256 == measured.artifact_sha256
    assert proposal.maximum_validity_days == 30
    assert proposal.maximum_benchmark_evidence_age_days == 7
    assert len(proposal.role_policies) == 4
    assert {r.role_class for r in proposal.role_policies} == set(QualificationRoleClass)
    for threshold, distribution in zip(proposal.thresholds, measured.distributions, strict=True):
        assert distribution.candidate_count == distribution.included_candidate_count == 8
        assert distribution.excluded_candidate_count == 0
        assert threshold.minimum_cases == distribution.observations[0].evaluated
        assert threshold.minimum_score == (
            1.0 if threshold.dimension in DETERMINISTIC_QUALIFICATION_DIMENSIONS else 0.75
        )


@pytest.mark.parametrize("count,roots", [(7, 6), (8, 5), (16, 2)])
def test_aliases_or_missing_candidates_cannot_supply_required_policy_support(count, roots):
    measured = measure(population(count, root_count=roots))
    with pytest.raises(ValueError, match="candidate/root support"):
        calibration._policy_proposal(measured)


def test_replays_are_retained_without_becoming_extra_primary_observations():
    source = population(1)[0].model_dump(mode="json")
    replay = source["runs"][1]
    for dimension in replay["dimensions"]:
        dimension.update(passed=0, score=0.0)
    replay["decision"]["dimension_score_sha256s"] = [
        canonical_sha256(item) for item in replay["dimensions"]
    ]
    replay["decision"]["overall_score_micros"] = 0
    reseal_decision(replay["decision"])
    measured = measure((reseal_source(source),))
    assert len(measured.candidates) == 1
    assert all(d.score == 1.0 for d in measured.candidates[0].dimensions)
    assert all(d.score == 0.0 for d in measured.sources[0].runs[1].dimensions)
    assert measured.retained_cost_usd == "0.96"


def test_poor_but_complete_candidate_remains_in_every_distribution_and_all_costs():
    sources = list(population(9))
    poor = sources[-1].model_dump(mode="json")
    for run in poor["runs"]:
        for dimension in run["dimensions"]:
            dimension.update(passed=0, score=0.0)
        run["decision"]["dimension_score_sha256s"] = [
            canonical_sha256(d) for d in run["dimensions"]
        ]
        run["decision"]["overall_score_micros"] = 0
        reseal_decision(run["decision"])
    sources[-1] = reseal_source(poor)
    measured = measure(tuple(sources))
    assert measured.retained_cost_usd == "8.64"
    assert measured.candidates[-1].included_in_distribution
    assert measured.candidates[-1].overall_score == 0
    assert all(
        d.included_candidate_count == 9 and d.observations[-1].score == 0
        for d in measured.distributions
    )
    assert calibration._policy_proposal(measured).calibration_included_candidate_count == 9


def test_actual_maximum_selected_population_is_retained_and_next_count_rejected():
    sources = population(128)
    measured = measure(sources)
    assert len(measured.sources) == len(measured.candidates) == 128
    assert measured.retained_cost_usd == "122.88"
    assert all(len(d.observations) == 128 for d in measured.distributions)
    assert (
        calibration.read_authenticated_model_calibration(
            calibration.authenticated_model_calibration_bytes(measured)
        )
        == measured
    )
    with pytest.raises(ValueError, match="loses a selected candidate"):
        measure((*sources, sources[-1]))


@pytest.mark.parametrize(
    "selection", [(), ("calibration/model-001",), ("calibration/model-000",) * 2]
)
def test_missing_substituted_or_duplicate_selection_is_rejected(selection):
    with pytest.raises(ValueError, match=r"selected|selection"):
        calibration._assemble_artifact(selection, population(1))


@pytest.mark.parametrize("field", ["generation_id", "request_body_sha256"])
def test_cross_candidate_execution_reuse_is_rejected(field):
    first, second = population(2)
    payload = second.model_dump(mode="json")
    payload["runner_evidence"]["runs"][0]["candidate_cases"][0][field] = getattr(
        first.runner_evidence.runs[0].candidate_cases[0], field
    )
    with pytest.raises(ValueError, match="reuses execution identities"):
        measure((first, reseal_source(payload)))


def test_cross_candidate_billed_request_reuse_is_rejected():
    first, second = population(2)
    payload = second.model_dump(mode="json")
    case = payload["runner_evidence"]["runs"][0]["candidate_cases"][0]
    old = case["request_id"]
    reused = first.runner_evidence.runs[0].candidate_cases[0].request_id
    case["request_id"] = reused
    case["attempt_request_ids"] = [reused]
    entries = payload["runner_evidence"]["ledger_interval"]["entries"]
    for entry in entries:
        if entry["request_id"] == old:
            entry["request_id"] = reused
    entries.sort(key=lambda entry: entry["request_id"])
    with pytest.raises(ValueError, match="billed attempt"):
        measure((first, reseal_source(payload)))


@pytest.mark.parametrize("field", ["public_lineage_bundle_sha256", "effective_config_sha256"])
def test_individually_valid_sources_cannot_mix_lineage_or_config(field):
    first, second = population(2)
    payload = second.model_dump(mode="json")
    payload["runner_evidence"][field] = "a" * 64
    if field == "effective_config_sha256":
        for run in payload["runs"]:
            run[field] = "a" * 64
    with pytest.raises(ValueError, match="mixes truth, lineage or configuration"):
        measure((first, reseal_source(payload)))


def test_individually_valid_sources_cannot_mix_policies():
    first, second = population(2)
    payload = second.model_dump(mode="json")
    for run in payload["runs"]:
        run["policy_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="mixes benchmark policies"):
        measure((first, reseal_source(payload)))


def ledger_source(source, *, ledger_id="d" * 64, start="e" * 64, end="f" * 64, initial="7"):
    payload = source.model_dump(mode="json")
    ledger = payload["runner_evidence"]["ledger_interval"]
    ledger.update(
        ledger_identity_sha256=ledger_id,
        initial_snapshot_sha256=start,
        final_snapshot_sha256=end,
        initial_spent_usd=initial,
        final_spent_usd=canonical_usd_sum((initial, ledger["interval_spent_usd"])),
    )
    return reseal_source(payload)


def test_contiguous_ledger_chain_counts_prior_spend_once_in_any_source_order():
    a, b = population(2)
    first = ledger_source(a)
    second = ledger_source(b, start="f" * 64, end="a" * 64, initial="7.96")
    assert measure((first, second)).retained_cost_usd == "8.92"
    assert calibration._retained_cost((second, first)) == "8.92"


@pytest.mark.parametrize("fault", ["overlap", "gap", "cycle", "prior_spend"])
def test_inconsistent_ledger_chains_are_rejected(fault):
    a, b = population(2)
    first = ledger_source(a)
    if fault == "overlap":
        second = ledger_source(b, end="a" * 64)
    elif fault == "gap":
        second = ledger_source(b, start="b" * 64, end="a" * 64, initial="7.96")
    elif fault == "cycle":
        second = ledger_source(b, start="f" * 64, end="e" * 64, initial="7.96")
    else:
        second = ledger_source(b, start="f" * 64, end="a" * 64, initial="8")
    with pytest.raises(ValueError, match="ledger chain"):
        measure((first, second))


@pytest.mark.parametrize("initial,allowed", [("124", True), ("124.04", False), ("125", False)])
def test_all_distinct_ledger_prior_costs_count_toward_hard_ceiling(initial, allowed):
    a, b = population(2)
    sources = (
        ledger_source(a, initial=initial),
        ledger_source(b, ledger_id="b" * 64, initial=initial),
    )
    if allowed:
        assert measure(sources).retained_cost_usd == "249.92"
    else:
        with pytest.raises(ValueError, match="250 USD ceiling"):
            measure(sources)


@pytest.mark.parametrize(
    "field,value",
    [
        ("included_root_lineage_count", 2),
        ("retained_cost_usd", "0"),
        ("serialized_authority", True),
        ("policy_adoption_authorized", 0),
        ("external_seal_required", 1),
        ("release_authorized", "false"),
    ],
)
def test_rehashing_false_metrics_or_authority_flags_does_not_accept_them(field, value):
    payload = artifact().model_dump(mode="json")
    payload[field] = value
    payload["artifact_sha256"] = canonical_sha256(
        {k: v for k, v in payload.items() if k != "artifact_sha256"}
    )
    with pytest.raises(ValueError):
        calibration.read_authenticated_model_calibration(stable_json(payload).encode())


@pytest.mark.parametrize("kind", ["whitespace", "duplicate_key", "compact", "extra_field"])
def test_noncanonical_or_ambiguous_encoding_is_rejected(kind):
    measured = artifact()
    raw = calibration.authenticated_model_calibration_bytes(measured)
    if kind == "whitespace":
        raw += b" "
    elif kind == "duplicate_key":
        raw = raw.replace(b"{", b'{"schema_version":"1.0",', 1)
    elif kind == "compact":
        raw = json.dumps(measured.model_dump(mode="json"), separators=(",", ":")).encode()
    else:
        raw = raw.replace(b"{", b'{"unrecognized":null,', 1)
    with pytest.raises(ValueError):
        calibration.read_authenticated_model_calibration(raw)


@pytest.mark.parametrize("raw", [b"", None, "{}", bytearray(b"{}")])
def test_reader_requires_nonempty_exact_bytes(raw):
    with pytest.raises(ValueError, match="bytes are absent"):
        calibration.read_authenticated_model_calibration(raw)


@pytest.mark.parametrize(
    "kind", ["native_limit", "native_floor", "shared_floor", "shared_role", "shared_helper"]
)
def test_live_entry_rejects_changed_frozen_rules_before_observing_any_inputs(monkeypatch, kind):
    if kind == "native_limit":
        monkeypatch.setattr(calibration, "MAX_AUTHENTICATED_CALIBRATION_BYTES", 64_000_000)
    elif kind == "native_floor":
        monkeypatch.setattr(calibration, "_CALIBRATION_GLOBAL_ROOT_SUPPORT", 1)
    elif kind == "shared_floor":
        monkeypatch.setattr(legacy, "_CALIBRATION_GLOBAL_ROOT_SUPPORT", 1)
    elif kind == "shared_role":
        monkeypatch.setitem(legacy._CALIBRATION_ROLE_ROOT_SUPPORT, QualificationRoleClass.JUDGE, 1)
    else:
        monkeypatch.setattr(legacy, "_has_required_empirical_support", lambda **_kwargs: True)
    with pytest.raises(ValueError, match="not pristine"):
        calibration.observe_authenticated_model_calibration(
            selected_model_ids=(), benchmark_suite=None, ground_truth=None, inputs=()
        )


def test_case_accounting_must_match_all_original_ledger_attempts():
    payload = population(1)[0].model_dump(mode="json")
    payload["runner_evidence"]["runs"][0]["candidate_cases"][0]["accounted_cost_usd"] = "0"
    with pytest.raises(ValueError, match="case costs differ"):
        measure((reseal_source(payload),))


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_actual_reader_byte_limit_does_not_accept_padding_or_raise_the_bound(delta):
    raw = calibration.authenticated_model_calibration_bytes(artifact())
    limit = calibration.MAX_AUTHENTICATED_CALIBRATION_BYTES
    bounded = raw + b" " * (limit + delta - len(raw))
    assert len(bounded) == limit + delta
    with pytest.raises(ValueError, match="exceed the bound" if delta > 0 else "not canonical"):
        calibration.read_authenticated_model_calibration(bounded)


@pytest.mark.parametrize(
    "kind", ["pid", "class_validator", "model_reader", "compiled_validator", "helper_code"]
)
def test_live_entry_rejects_process_class_or_code_replacement(monkeypatch, kind):
    if kind == "pid":
        original = calibration.os.getpid()
        monkeypatch.setattr(calibration.os, "getpid", lambda: original + 1)
    elif kind == "class_validator":
        monkeypatch.setattr(
            calibration.AuthenticatedModelCalibrationArtifact,
            "observations_and_self_hash_are_exact",
            lambda self: self,
        )
    elif kind == "model_reader":
        monkeypatch.setattr(
            calibration.AuthenticatedModelCalibrationArtifact,
            "model_validate_json",
            lambda *_args, **_kwargs: None,
        )
    elif kind == "compiled_validator":
        monkeypatch.setattr(
            calibration.AuthenticatedModelCalibrationArtifact, "__pydantic_validator__", object()
        )
    else:

        def replacement(**_kwargs):
            return True

        monkeypatch.setattr(
            legacy._has_required_empirical_support, "__code__", replacement.__code__
        )
    with pytest.raises(ValueError, match="not pristine"):
        calibration.observe_authenticated_model_calibration(
            selected_model_ids=(), benchmark_suite=None, ground_truth=None, inputs=()
        )
