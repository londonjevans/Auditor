"""Publication data and isolated native protocol tests, never REAL campaign evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import fields, replace
from decimal import Decimal
from types import SimpleNamespace

import pytest

import mmaudit.models.authenticated_calibration as native
import mmaudit.orchestration.calibration_publication as publication
from mmaudit.models.evidence_seal_authority import build_transparency_prefix_proof
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostReservationOverrunError
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_population_journal import journal_inputs, registrations
from tests.unit.test_registered_calibration_measurement import isolated_factory
from tests.unit.test_registered_calibration_measurement import (
    measurement_protocol as measurement_protocol,
)

FLAGS = (
    "serialized_authority",
    "external_publication_verified",
    "pre_dispatch_anchoring_verified",
    "policy_adoption_authorized",
    "model_qualification_authorized",
    "provider_call_authorized",
    "release_authorized",
    "external_comparison_required",
)


def prepare_publication(state):
    """Clone only the selected factory; original exported native verifiers stay untouched."""

    def registered():
        state.registration = publication.build_calibration_registration_publication(
            evidence_root=state.root,
            expected_registration_sha256=state.journal.registration.event_sha256,
        )

    state.on_registered = registered
    namespace, builder = isolated_factory(
        publication, "_build_native_measurement_publication", {"_native": state.native_module}
    )
    state.publication_namespace = namespace
    state.build_publication = builder
    return state


def measured(state, live):
    return state.build_publication(live=live, evidence_root=state.root, ledger=state.ledger)


def compare(registration, measurement, *, log_id="a" * 64, preceding=()):
    first = build_transparency_prefix_proof(
        log_id_sha256=log_id,
        authority_subject_sha256s=(*preceding, registration.subject_sha256),
    )
    last = build_transparency_prefix_proof(
        log_id_sha256=log_id,
        authority_subject_sha256s=(
            *preceding,
            registration.subject_sha256,
            "b" * 64,
            measurement.subject_sha256,
        ),
        previous_checkpoint=first.checkpoint,
    )
    return publication.build_calibration_publication_comparison(
        registration=registration,
        measurement=measurement,
        registration_proof=first,
        measurement_proof=last,
    )


def reseal(payload, field="subject_sha256"):
    payload = dict(payload)
    payload.pop(field, None)
    payload[field] = canonical_sha256(payload)
    return stable_json(payload).encode()


@pytest.fixture(scope="module")
def publication_data(tmp_path_factory):
    # Synchronous fixture creates the existing asyncio.run-based structural source first.
    factory = measurement_protocol.__wrapped__(tmp_path_factory.mktemp("publication-data"))
    state = prepare_publication(factory())

    async def collect():
        async with state.scope(**state.args) as live:
            return state.registration, measured(state, live)

    registration, measurement = asyncio.run(collect())
    return compare(registration, measurement)


@pytest.mark.parametrize("liability", ["settled", "pending", "unknown", "overrun"])
def test_registration_retains_missing_population_and_every_prior_liability(tmp_path, liability):
    root, plan, ledger = journal_inputs(tmp_path)
    charge = ledger.reserve("synthetic-prior", Decimal("1"))
    if liability == "settled":
        ledger.reconcile(charge, Decimal("0.25"))
    elif liability == "unknown":
        ledger.reconcile(charge, None)
    elif liability == "overrun":
        with pytest.raises(CostReservationOverrunError):
            ledger.reconcile(charge, Decimal("251"))
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan)[:1],
    )
    subject = publication.build_calibration_registration_publication(
        evidence_root=root, expected_registration_sha256=journal.registration.event_sha256
    )
    assert subject.population_events == (journal.registration,)
    assert subject.population_events[0].ledger_snapshot == ledger.snapshot()
    assert tuple(slot.state for slot in subject.population_events[0].slots) == (
        "PENDING",
        "MISSING",
        "MISSING",
    )
    assert subject.policy is subject.calibration is None
    assert not subject.provider_call_authorized and not subject.pre_dispatch_anchoring_verified
    assert subject.proposal_status == "NOT_MEASURED"


def test_registration_rejects_wrong_pin_and_post_preflight_prefix(tmp_path):
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    with pytest.raises(ValueError):
        publication.build_calibration_registration_publication(
            evidence_root=root, expected_registration_sha256="f" * 64
        )
    journal.append("PREFLIGHT_PASSED", exact_model_id=plan.entries[0].exact_model_id)
    with pytest.raises(ValueError, match="later work"):
        publication.build_calibration_registration_publication(
            evidence_root=root, expected_registration_sha256=journal.registration.event_sha256
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_live_native_population_and_policy_refusal_are_bound_without_capability_transfer(
    measurement_protocol, count
):
    state = prepare_publication(measurement_protocol(count))
    async with state.scope(**state.args) as live:
        state.proof = live.verification
        subject = measured(state, live)
        assert subject.calibration == live.calibration
        assert subject.policy == live.policy
        assert len(subject.population_events) == 3 * count + 1
        assert subject.population_events[-1].ledger_snapshot == state.ledger.snapshot()
        assert subject.population_events[0] == state.registration.population_events[0]
        assert subject.proposal_status == (
            "PROPOSED_NOT_ADOPTED" if count == 8 else "NATIVE_POLICY_DERIVATION_REFUSED"
        )
        state.require(live.verification, live.calibration)  # Borrowing never disposes its owner.
        result = compare(state.registration, subject, preceding=("d" * 64,))
        assert not result.external_publication_verified and not result.release_authorized
        assert result.external_comparison_required
    with pytest.raises(ValueError, match="absent or revoked"):
        measured(state, live)
    assert state.closed and state.secret.cleared


@pytest.mark.asyncio
async def test_original_production_builder_rejects_isolated_native_proof(measurement_protocol):
    state = prepare_publication(measurement_protocol())
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="absent or revoked"):
            publication.build_calibration_measurement_publication(
                live=live, evidence_root=state.root, ledger=state.ledger
            )
        with pytest.raises(ValueError, match="absent or revoked"):
            native._require_verified_authenticated_model_calibration(
                live.verification, live.calibration
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["fake_live", "missing_proof", "wrong_registration", "ledger"])
async def test_native_builder_rejects_reconstructed_or_mismatched_inputs(
    measurement_protocol, tmp_path, change
):
    state = prepare_publication(measurement_protocol())
    async with state.scope(**state.args) as live:
        candidate, ledger = live, state.ledger
        if change == "fake_live":
            candidate = SimpleNamespace(
                **{field.name: getattr(live, field.name) for field in fields(live)}
            )
        elif change == "missing_proof":
            candidate = replace(live, verification=None)
        elif change == "wrong_registration":
            candidate = replace(live, registration_sha256="f" * 64)
        else:
            ledger = AtomicCostLedger.initialize(tmp_path / "other.json", cap_usd=Decimal("250"))
        with pytest.raises(ValueError):
            state.build_publication(live=candidate, evidence_root=state.root, ledger=ledger)


@pytest.mark.asyncio
async def test_policy_proposal_cannot_be_omitted_from_supported_population(measurement_protocol):
    state = prepare_publication(measurement_protocol(8))
    async with state.scope(**state.args) as live:
        with pytest.raises(ValueError, match="original policy/refusal"):
            measured(state, replace(live, policy=None))


@pytest.mark.asyncio
async def test_native_export_drift_is_refused_before_journal_read(measurement_protocol):
    state = prepare_publication(measurement_protocol())
    async with state.scope(**state.args) as live:
        original = state.native_module.derive_authenticated_calibration_policy
        state.native_module.derive_authenticated_calibration_policy = lambda **_: None
        try:
            with pytest.raises(ValueError, match="bindings changed"):
                state.build_publication(
                    live=live, evidence_root=state.root / "absent", ledger=state.ledger
                )
        finally:
            state.native_module.derive_authenticated_calibration_policy = original


def test_canonical_roundtrip_exposes_only_digest_not_private_population(publication_data):
    result = publication_data
    raw = publication.calibration_publication_comparison_bytes(result)
    assert publication.read_calibration_publication_comparison(raw) == result
    for subject in (result.registration, result.measurement):
        request = publication.calibration_publication_request(subject)
        assert request == bytes.fromhex(subject.subject_sha256) and len(request) == 32
        proof = (
            result.registration_proof
            if subject is result.registration
            else result.measurement_proof
        )
        assert (
            hashlib.sha256(b"\x00" + request).hexdigest()
            == proof.leaf_sha256s[proof.subject_leaf_index]
        )
        assert not hasattr(subject, "verification")


@pytest.mark.parametrize("field", FLAGS)
@pytest.mark.parametrize("bad", [True, 0, "false"])
def test_serialized_flags_cannot_acquire_authority_or_coerce_types(publication_data, field, bad):
    if field == "external_comparison_required" and bad is True:
        bad = False
    for obj, reader, hash_field in (
        (
            publication_data.registration,
            publication.read_calibration_publication_subject,
            "subject_sha256",
        ),
        (
            publication_data,
            publication.read_calibration_publication_comparison,
            "comparison_sha256",
        ),
    ):
        payload = obj.model_dump(mode="json")
        payload[field] = bad
        with pytest.raises(ValueError):
            reader(reseal(payload, hash_field))


@pytest.mark.parametrize("kind", ["subject", "comparison"])
@pytest.mark.parametrize("change", ["empty", "padding", "bytearray", "duplicate", "hash", "extra"])
def test_readers_reject_noncanonical_or_changed_data(publication_data, kind, change):
    subject = kind == "subject"
    obj = publication_data.registration if subject else publication_data
    reader = (
        publication.read_calibration_publication_subject
        if subject
        else publication.read_calibration_publication_comparison
    )
    hash_field = "subject_sha256" if subject else "comparison_sha256"
    raw = stable_json(obj.model_dump(mode="json")).encode()
    if change == "empty":
        raw = b""
    elif change == "padding":
        raw += b"\n"
    elif change == "bytearray":
        raw = bytearray(raw)
    elif change == "duplicate":
        raw = b'{"schema_version":"1.0",' + raw[1:]
    else:
        payload = json.loads(raw)
        payload[hash_field if change == "hash" else "unexpected"] = "f" * 64
        raw = stable_json(payload).encode()
    with pytest.raises(ValueError):
        reader(raw)


@pytest.mark.parametrize(
    "bound,kind",
    [
        ("MAX_CALIBRATION_PUBLICATION_SUBJECT_BYTES", "subject"),
        ("MAX_CALIBRATION_PUBLICATION_COMPARISON_BYTES", "comparison"),
        ("_MAX_EVENT_BYTES", "event"),
        ("_MAX_JOURNAL_BYTES", "journal"),
    ],
)
def test_original_and_outer_byte_bounds_are_enforced(publication_data, monkeypatch, bound, kind):
    # Lower only the data reader's limit; never alter native production issuer bindings.
    monkeypatch.setattr(publication, bound, 1)
    reader = (
        publication.read_calibration_publication_comparison
        if kind == "comparison"
        else publication.read_calibration_publication_subject
    )
    obj = publication_data if kind == "comparison" else publication_data.registration
    with pytest.raises(ValueError, match="bound"):
        reader(stable_json(obj.model_dump(mode="json")).encode())


@pytest.mark.parametrize(
    "change",
    ["missing_event", "reordered", "finished", "registration_has_work", "cost", "policy_status"],
)
def test_population_projection_cannot_drop_or_rewrite_measured_work(publication_data, change):
    payload = publication_data.measurement.model_dump(mode="json")
    events = payload["population_events"]
    if change == "missing_event":
        events.pop(1)
    elif change == "reordered":
        events[1], events[2] = events[2], events[1]
    elif change == "finished":
        events[-1]["disposition"] = "CONSUMED"
    elif change == "registration_has_work":
        payload["phase"] = "POPULATION_REGISTRATION"
    elif change == "cost":
        payload["calibration"]["retained_cost_usd"] = "0"
    else:
        payload["proposal_status"] = "PROPOSED_NOT_ADOPTED"
    with pytest.raises(ValueError):
        publication.read_calibration_publication_subject(reseal(payload))


@pytest.mark.parametrize(
    "change", ["wrong_phase", "wrong_subject", "wrong_log", "no_predecessor", "fork", "reversed"]
)
def test_comparison_rejects_unjoined_or_forked_log_proofs(publication_data, change):
    data = publication_data
    registration, measurement = data.registration, data.measurement
    first, last = data.registration_proof, data.measurement_proof
    if change == "wrong_phase":
        registration = measurement
    elif change == "wrong_subject":
        first = build_transparency_prefix_proof(
            log_id_sha256="a" * 64, authority_subject_sha256s=("e" * 64,)
        )
    elif change == "wrong_log":
        last = build_transparency_prefix_proof(
            log_id_sha256="f" * 64,
            authority_subject_sha256s=(registration.subject_sha256, measurement.subject_sha256),
        )
    elif change == "no_predecessor":
        last = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=(registration.subject_sha256, measurement.subject_sha256),
        )
    elif change == "fork":
        fork = build_transparency_prefix_proof(
            log_id_sha256="a" * 64, authority_subject_sha256s=("e" * 64,)
        )
        last = build_transparency_prefix_proof(
            log_id_sha256="a" * 64,
            authority_subject_sha256s=("e" * 64, measurement.subject_sha256),
            previous_checkpoint=fork.checkpoint,
        )
    else:
        first, last = last, first
    with pytest.raises(ValueError, match="exact population/log"):
        publication.build_calibration_publication_comparison(
            registration=registration,
            measurement=measurement,
            registration_proof=first,
            measurement_proof=last,
        )


def test_comparison_cannot_accept_a_second_locally_consistent_registration(
    publication_data, tmp_path
):
    root, plan, ledger = journal_inputs(tmp_path)
    journal = CalibrationPopulationJournal(
        evidence_root=root,
        selection_plan=plan,
        ledger=ledger,
        present_registries=registrations(plan),
    )
    other = publication.build_calibration_registration_publication(
        evidence_root=root, expected_registration_sha256=journal.registration.event_sha256
    )
    with pytest.raises(ValueError, match="exact population/log"):
        compare(other, publication_data.measurement)
