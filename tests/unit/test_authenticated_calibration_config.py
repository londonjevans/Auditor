"""Native C1/C2 data handoff tests with explicitly isolated, non-REAL source custody."""

from __future__ import annotations

import asyncio
import hashlib
import json
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

import pytest

import mmaudit.config as config_module
import mmaudit.orchestration.authenticated_calibration_config as transition
from mmaudit.config import AuditConfig, canonical_audit_config_json, parse_canonical_audit_config
from mmaudit.models.calibration_transition import qualification_policy_independent_config_sha256
from mmaudit.models.qualification import load_qualification_policy
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.conftest import base_config_data
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_publication import prepare_publication
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)

ROOT = Path(__file__).parents[2]
REQUIRED = (
    "external_population_seal_required",
    "successor_release_binding_required",
    "independent_qualification_required",
)
FALSE_FLAGS = (
    "serialized_authority",
    "policy_adoption_authorized",
    "model_qualification_authorized",
    "production_selection_authorized",
    "provider_call_authorized",
    "release_authorized",
)


def prepare_config(factory, *, count=8, bind=True, profile="SYNTHETIC_BENCHMARK"):
    data = base_config_data()
    data["profile"] = AuditProfile.MAXIMUM_ASSURANCE
    data["privacy"]["profile"] = profile
    config = AuditConfig.model_validate(data).effective()
    predecessor = load_qualification_policy(ROOT / "config/models.maximum-assurance.toml")
    state = prepare_publication(
        factory(
            count,
            source_config_bindings=(config.stable_hash(), predecessor.policy_sha256)
            if bind
            else None,
        )
    )
    state.predecessor = predecessor
    state.config = config
    state.publication_module = SimpleNamespace(
        build_calibration_measurement_publication=state.build_publication
    )
    namespace, builder = isolated_factory(
        transition, "_build_native_config_proposal", {"_publication": state.publication_module}
    )
    state.config_namespace = namespace
    state.build_config = builder
    return state


def build_config(state, live, **changes):
    args = dict(
        live=live,
        evidence_root=state.root,
        ledger=state.ledger,
        predecessor_policy=state.predecessor,
        predecessor_config=state.config,
    )
    return state.build_config(**{**args, **changes})


def reseal(payload):
    payload = dict(payload)
    payload.pop("proposal_sha256", None)
    payload["proposal_sha256"] = canonical_sha256(payload)
    return stable_json(payload).encode()


@pytest.fixture(scope="module")
def proposal_data(tmp_path_factory):
    factory = measurement_protocol.__wrapped__(tmp_path_factory.mktemp("config-proposal"))
    state = prepare_config(factory)

    async def collect():
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            result = build_config(state, live)
            state.require(live.verification, live.calibration)
            return result

    result = asyncio.run(collect())
    assert state.closed and state.secret.cleared
    return result


def test_native_configuration_proposal_changes_exactly_one_field(proposal_data):
    proposal = proposal_data
    first = json.loads(proposal.predecessor_effective_config_json)
    last = json.loads(proposal.successor_effective_config_json)
    assert first != last
    policy = proposal.measurement_subject.policy
    assert policy is not None
    assert last["maximum_assurance"]["qualification"]["policy_sha256"] == policy.policy_sha256
    last["maximum_assurance"]["qualification"]["policy_sha256"] = (
        proposal.predecessor_policy.policy_sha256
    )
    assert first == last
    assert proposal.measurement_subject.calibration.included_root_lineage_count == 6
    assert len(proposal.measurement_subject.calibration.sources) == 8
    assert proposal.measurement_subject.population_events[-1].ledger_snapshot.spent_usd == Decimal(
        "7.93"
    )
    assert proposal.measurement_subject.calibration.retained_cost_usd == "7.93"
    assert all(getattr(proposal, field) is False for field in FALSE_FLAGS)
    assert all(getattr(proposal, field) is True for field in REQUIRED)
    assert not hasattr(proposal, "successor_release_bindings")
    assert not hasattr(proposal, "verification")


def test_readback_and_export_do_not_activate_p2_in_current_p1_release(proposal_data):
    raw = transition.authenticated_calibration_config_proposal_bytes(proposal_data)
    assert transition.read_authenticated_calibration_config_proposal(raw) == proposal_data
    proposed = transition.proposed_successor_config_bytes(proposal_data)
    assert proposed == proposal_data.successor_effective_config_json.encode()
    assert hashlib.sha256(proposed).hexdigest() == proposal_data.successor_effective_config_sha256
    assert parse_canonical_audit_config(proposal_data.predecessor_effective_config_json)
    with pytest.raises(ValueError, match="invalid"):
        parse_canonical_audit_config(proposed.decode())
    assert (
        proposal_data.predecessor_policy.policy_sha256
    ) == config_module.MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256


def test_data_readback_under_simulated_successor_pin_does_not_grant_release(
    proposal_data, monkeypatch
):
    # Simulate only structural source-P2 config parsing, not an original native issuer or adoption.
    raw = transition.authenticated_calibration_config_proposal_bytes(proposal_data)
    monkeypatch.setattr(
        config_module,
        "MAXIMUM_ASSURANCE_QUALIFICATION_POLICY_SHA256",
        proposal_data.measurement_subject.policy.policy_sha256,
    )
    with pytest.raises(ValueError, match="invalid"):
        parse_canonical_audit_config(proposal_data.predecessor_effective_config_json)
    assert parse_canonical_audit_config(proposal_data.successor_effective_config_json)
    result = transition.read_authenticated_calibration_config_proposal(raw)
    assert result == proposal_data and not result.release_authorized


@pytest.mark.asyncio
async def test_current_production_builder_rejects_isolated_proof(measurement_protocol):
    state = prepare_config(measurement_protocol, count=1)
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="absent or revoked"):
            transition.build_authenticated_calibration_config_proposal(
                live=live,
                evidence_root=state.root,
                ledger=state.ledger,
                predecessor_policy=state.predecessor,
                predecessor_config=state.config,
            )


@pytest.mark.asyncio
async def test_policy_refusal_preserves_measurement_without_fabricating_successor(
    measurement_protocol,
):
    state = prepare_config(measurement_protocol, count=1)
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="refusal cannot produce"):
            build_config(state, live)
        assert (state.output / "calibration.json").is_file()
        state.require(live.verification, live.calibration)
    assert (state.output / "measurement.json").is_file()
    assert not (state.output / "policy.json").exists()


@pytest.mark.asyncio
async def test_unbound_native_configuration_is_not_accepted_by_relabelling(measurement_protocol):
    state = prepare_config(measurement_protocol, bind=False)
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="measured P1/C1"):
            build_config(state, live)


@pytest.mark.asyncio
async def test_native_config_handoff_requires_synthetic_benchmark_scope(measurement_protocol):
    state = prepare_config(measurement_protocol, profile="STRICT_ZDR")
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="effective maximum profile"):
            build_config(state, live)


@pytest.mark.asyncio
async def test_native_config_handoff_cannot_outlive_original_measurement(measurement_protocol):
    state = prepare_config(measurement_protocol)
    async with state.scope(**state.args) as live:
        state.proof = live.verification
        build_config(state, live)
        state.require(live.verification, live.calibration)
    with pytest.raises(ValueError, match="absent or revoked"):
        build_config(state, live)


@pytest.mark.asyncio
async def test_publication_export_drift_is_refused_before_filesystem_use(measurement_protocol):
    state = prepare_config(measurement_protocol, count=1)
    state.publication_module.build_calibration_measurement_publication = lambda **_: None
    with pytest.raises(ValueError, match="publication binding changed"):
        build_config(state, None)
    assert not state.entered and not list(state.root.iterdir())


@pytest.mark.parametrize("field", (*REQUIRED, *FALSE_FLAGS))
@pytest.mark.parametrize("bad", ["opposite", 0, "false"])
def test_proposal_flags_cannot_authorize_or_drop_required_gates(proposal_data, field, bad):
    payload = proposal_data.model_dump(mode="json")
    payload[field] = field not in REQUIRED if bad == "opposite" else bad
    with pytest.raises(ValueError):
        transition.read_authenticated_calibration_config_proposal(reseal(payload))


@pytest.mark.parametrize(
    "field", ["execution", "privacy", "models", "repository", "reporting", "profile"]
)
def test_other_configuration_changes_are_refused_after_coherent_outer_reseal(proposal_data, field):
    payload = proposal_data.model_dump(mode="json")
    successor = json.loads(payload["successor_effective_config_json"])
    if field == "profile":
        successor[field] = "standard"
    elif field == "execution":
        successor[field]["budget_usd"] = 249
    elif field == "privacy":
        successor[field]["store_raw_prompts"] = True
    elif field == "models":
        successor[field]["allow_non_independent_models"] = True
    elif field == "repository":
        successor[field]["include_docs"] = not successor[field]["include_docs"]
    else:
        successor[field]["markdown"] = not successor[field]["markdown"]
    payload["successor_effective_config_json"] = json.dumps(
        successor, sort_keys=True, separators=(",", ":")
    )
    payload["successor_effective_config_sha256"] = hashlib.sha256(
        payload["successor_effective_config_json"].encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="more than the allowed policy pin"):
        transition.read_authenticated_calibration_config_proposal(reseal(payload))


@pytest.mark.parametrize(
    "change",
    [
        "hash",
        "projection",
        "registration",
        "predecessor",
        "extra",
        "padding",
        "duplicate",
        "empty",
        "bytearray",
    ],
)
def test_proposal_reader_rejects_wrong_or_noncanonical_material(proposal_data, change):
    payload = proposal_data.model_dump(mode="json")
    if change == "hash":
        payload["successor_effective_config_sha256"] = "f" * 64
    elif change == "projection":
        payload["policy_independent_config_sha256"] = "f" * 64
    elif change == "registration":
        payload["measurement_subject"]["phase"] = "POPULATION_REGISTRATION"
    elif change == "predecessor":
        payload["predecessor_policy"] = payload["measurement_subject"]["policy"]
    elif change == "extra":
        payload["successor_release_bindings"] = {"source_commit": "a" * 40}
    raw = reseal(payload)
    if change == "padding":
        raw += b"\n"
    elif change == "duplicate":
        raw = b'{"schema_version":"1.0",' + raw[1:]
    elif change == "empty":
        raw = b""
    elif change == "bytearray":
        raw = bytearray(raw)
    with pytest.raises(ValueError):
        transition.read_authenticated_calibration_config_proposal(raw)


@pytest.mark.parametrize(
    "bound",
    ["MAX_AUTHENTICATED_CALIBRATION_CONFIG_PROPOSAL_BYTES", "_CONFIG_BYTES", "_POLICY_BYTES"],
)
def test_proposal_preserves_original_and_outer_byte_bounds(proposal_data, monkeypatch, bound):
    raw = transition.authenticated_calibration_config_proposal_bytes(proposal_data)
    monkeypatch.setattr(transition, bound, 1)
    with pytest.raises(ValueError, match="bound"):
        transition.read_authenticated_calibration_config_proposal(raw)


def test_configuration_proposal_has_no_executable_config_or_write_api(proposal_data):
    assert not isinstance(proposal_data, AuditConfig)
    assert not hasattr(proposal_data, "write")
    predecessor = parse_canonical_audit_config(proposal_data.predecessor_effective_config_json)
    assert (
        canonical_audit_config_json(predecessor) == proposal_data.predecessor_effective_config_json
    )


def test_coherent_full_config_rewrite_does_not_relabel_native_measurement(proposal_data):
    payload = proposal_data.model_dump(mode="json")
    for prefix in ("predecessor", "successor"):
        field = f"{prefix}_effective_config_json"
        config = json.loads(payload[field])
        config["execution"]["budget_usd"] += 1
        payload[field] = json.dumps(config, sort_keys=True, separators=(",", ":"))
        payload[f"{prefix}_effective_config_sha256"] = hashlib.sha256(
            payload[field].encode()
        ).hexdigest()
    active = parse_canonical_audit_config(payload["predecessor_effective_config_json"])
    payload["policy_independent_config_sha256"] = qualification_policy_independent_config_sha256(
        active
    )
    with pytest.raises(ValueError, match="measured P1/C1"):
        transition.read_authenticated_calibration_config_proposal(reseal(payload))
