"""Isolated native lease protocol with genuine local journal/ledger/file operations.

Structural synthetic observations are explicitly rebased onto a disposable ledger
before isolated issuance. They are NOT original runner custody or REAL evidence.
The production observer and every original exported verifier remain untouched.
"""

from __future__ import annotations

import ast
import asyncio
import pickle
from contextlib import asynccontextmanager
from dataclasses import fields
from decimal import Decimal
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest

import mmaudit.models.authenticated_calibration as native
import mmaudit.orchestration.authenticated_calibration_measurement as measurement
from mmaudit.models.authenticated_runner_ledger import (
    _decimal_text,
    _entry_sha256,
    _snapshot_sha256,
)
from mmaudit.models.candidate_selection import (
    seal_candidate_selection_entry,
    seal_candidate_selection_plan,
)
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.authenticated_calibration_openrouter import (
    AuthenticatedOpenRouterCalibrationInputs,
)
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256
from mmaudit.reporting.json_report import stable_json
from tests.authenticated_calibration_support import population, reseal_source, structural_source
from tests.unit.test_authenticated_calibration import measure
from tests.unit.test_authenticated_calibration import no_external_execution as no_external_execution
from tests.unit.test_calibration_population_journal import population_plan, read_journal


def isolated_factory(module, name, replacements):
    namespace = {**vars(module), **replacements}
    path = Path(module.__file__)
    nodes = [
        node
        for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(nodes) == 1 and not hasattr(module, name)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), namespace)
    return namespace, namespace[name]()


@pytest.fixture
def measurement_protocol(tmp_path):
    # This existing synchronous fixture uses asyncio.run; construct it before a test loop exists.
    structural_source()

    def make(count=1, *, original_native=False, source_config_bindings=None):
        root = tmp_path / "events"
        output = tmp_path / "outputs"
        root.mkdir(mode=0o700)
        output.mkdir(mode=0o700)
        ledger = AtomicCostLedger.initialize(tmp_path / "cost.json", cap_usd=Decimal("250"))
        prior = ledger.reserve("known-prior", Decimal("1"))
        ledger.reconcile(prior, Decimal("0.25"))
        sources = population(count)
        if source_config_bindings is not None:
            # Explicit structural-fixture rebinding only; production observers reject these data.
            config_sha, policy_sha = source_config_bindings
            rebound_sources = []
            for source in sources:
                payload = source.model_dump(mode="json")
                payload["runner_evidence"]["effective_config_sha256"] = config_sha
                for run in payload["runs"]:
                    run["effective_config_sha256"] = config_sha
                    run["policy_sha256"] = policy_sha
                rebound_sources.append(reseal_source(payload))
            sources = tuple(rebound_sources)
        plan = seal_candidate_selection_plan(
            source_bindings=population_plan().source_bindings,
            entries=tuple(
                seal_candidate_selection_entry(
                    exact_model_id=source.collision_map.candidate.exact_model_id,
                    priority_rank=index + 1,
                    advisory_lineage_group=f"Synthetic {index}",
                    allowed_provider_endpoints=("synthetic-provider",),
                )
                for index, source in enumerate(sources)
            ),
            authenticated_runner_selection=None,
            unresolved_requirements=("Synthetic protocol data has no runtime authority.",),
        )
        state = SimpleNamespace(
            root=root,
            output=output,
            ledger=ledger,
            plan=plan,
            entered=False,
            closed=False,
            on_observe=None,
            on_cleanup=None,
            before_measure=None,
            on_registered=None,
            observations=0,
            proof=None,
            sources=sources,
            native_module=native,
            original_native=original_native,
        )

        def observe_values(**_kwargs):
            state.observations += 1
            if state.on_observe is not None:
                state.on_observe()
            return state.measured

        if not original_native:
            namespace, exports = isolated_factory(
                native,
                "_build_calibration_authority",
                {
                    "_observe_inputs": observe_values,
                },
            )
            names = (
                "observe_authenticated_model_calibration",
                "derive_authenticated_calibration_policy",
                "_require_verified_authenticated_model_calibration",
                "revoke_verified_authenticated_model_calibration",
            )
            namespace.update(zip(names, exports, strict=True))
            state.native_module = SimpleNamespace(**{name: namespace[name] for name in names})
            state.native_namespace = namespace
            state.require = exports[2]
            state.revoke = exports[3]

        @asynccontextmanager
        async def batch_scope(**_kwargs):
            state.entered = True
            journal = CalibrationPopulationJournal(
                evidence_root=root,
                selection_plan=plan,
                ledger=ledger,
                present_registries=tuple(
                    (
                        source.collision_map.candidate.exact_model_id,
                        source.runs[0].candidate_registry_sha256,
                        "b" * 64,
                    )
                    for source in sources
                ),
            )
            state.journal = journal
            rebound = []
            try:
                if state.on_registered is not None:
                    state.on_registered()
                for entry in plan.entries:
                    journal.append("PREFLIGHT_PASSED", exact_model_id=entry.exact_model_id)
                for source in sources:
                    exact_id = source.collision_map.candidate.exact_model_id
                    journal.append("RUNNER_STARTED", exact_model_id=exact_id)
                    initial = ledger.snapshot()
                    payload = source.model_dump(mode="json")
                    interval = payload["runner_evidence"]["ledger_interval"]
                    for entry in interval["entries"]:
                        reserved = ledger.reserve(
                            entry["request_id"], Decimal(entry["reserved_usd"] or "1")
                        )
                        ledger.reconcile(reserved, Decimal(entry["actual_cost_usd"]))
                    final = ledger.snapshot()
                    actual_entries = {entry.request_id: entry for entry in final.entries}
                    for entry in interval["entries"]:
                        actual = actual_entries[entry["request_id"]]
                        entry["entry_sha256"] = _entry_sha256(actual)
                        entry["reserved_usd"] = _decimal_text(actual.reserved_usd)
                    interval.update(
                        ledger_identity_sha256=ledger.identity_sha256,
                        initial_snapshot_sha256=_snapshot_sha256(initial),
                        final_snapshot_sha256=_snapshot_sha256(final),
                        initial_spent_usd=_decimal_text(initial.spent_usd),
                        final_spent_usd=_decimal_text(final.spent_usd),
                    )
                    bound = reseal_source(payload)
                    rebound.append(bound)
                    journal.append(
                        "RUNNER_RETAINED",
                        exact_model_id=exact_id,
                        runner_evidence_sha256=bound.runner_evidence.evidence_sha256,
                    )
                state.measured = measure(tuple(rebound))
                if state.before_measure is not None:
                    state.before_measure()
                yield (
                    AuthenticatedOpenRouterCalibrationInputs(
                        state.measured.selected_model_ids,
                        None,
                        None,
                        (),
                    ),
                    journal,
                )
                if state.proof is not None:
                    with pytest.raises(ValueError, match="absent or revoked"):
                        state.require(state.proof, state.measured)
                if state.on_cleanup is not None:
                    state.on_cleanup()
                journal.append("FINISHED", disposition="CONSUMED")
            except BaseException as exc:
                if journal.current.disposition == "OPEN":
                    journal.append(
                        "FINISHED",
                        disposition=(
                            "CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED"
                        ),
                    )
                raise
            finally:
                state.closed = True

        namespace, scope = isolated_factory(
            measurement,
            "_build_registered_measurement_scope",
            {
                "_native": state.native_module,
                "_owned_registered_calibration_scope": batch_scope,
            },
        )
        state.namespace = namespace
        state.scope = scope
        state.secret = OperatorSecrets({"OPENROUTER_API_KEY": "synthetic-not-a-real-credential"})
        state.args = dict(
            selection_plan=plan,
            ledger=ledger,
            evidence_root=root,
            output_root=output,
            launches=(),
            operator_secrets=(state.secret,),
        )
        return state

    return make


def read_result(state):
    return measurement.load_registered_calibration_measurement(
        evidence_root=state.root,
        output_root=state.output,
        expected_registration_sha256=state.journal.registration.event_sha256,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_original_numeric_rules_preserve_measurement_and_dispose_before_receipt(
    measurement_protocol,
    count,
):
    state = measurement_protocol(count)
    async with state.scope(**state.args) as live:
        state.proof = live.verification
        state.require(live.verification, live.calibration)
        assert (live.policy is not None) == (count == 8)
        assert (state.output / "calibration.json").is_file()
        assert not (state.output / "measurement.json").exists()
        with pytest.raises(ValueError, match="absent or revoked"):
            live.verification.require_for(live.calibration)
        with pytest.raises(TypeError, match="cannot be serialized"):
            pickle.dumps(live)
    assert state.closed
    assert state.secret.cleared
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(live.verification, live.calibration)
    result = read_result(state)
    assert result.calibration == state.measured
    assert result.calibration.retained_cost_usd == _decimal_text(state.ledger.snapshot().spent_usd)
    assert result.calibration.retained_cost_usd == str(Decimal("0.25") + Decimal("0.96") * count)
    assert result.receipt.serialized_authority is result.receipt.release_authorized is False
    assert result.receipt.policy_adoption_authorized is False
    assert result.receipt.external_population_seal_required is True
    assert not any(field.name == "verification" for field in fields(result))
    assert result.receipt.proposal_status == (
        "PROPOSED_NOT_ADOPTED" if count == 8 else "NATIVE_POLICY_DERIVATION_REFUSED"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("error", [RuntimeError, asyncio.CancelledError, TimeoutError])
async def test_consumer_failure_disposes_proof_and_cannot_publish_completion(
    measurement_protocol, error
):
    state = measurement_protocol()
    with pytest.raises(error):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            raise error("synthetic consumer termination")
    assert state.closed and not (state.output / "measurement.json").exists()
    assert state.secret.cleared
    assert (state.output / "calibration.json").exists()
    assert read_journal(state.root)[-1].disposition == (
        "CANCELLED" if error is asyncio.CancelledError else "FAILED"
    )
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(live.verification, live.calibration)


@pytest.mark.asyncio
async def test_invalid_native_proof_is_not_downgraded_to_policy_refusal(measurement_protocol):
    state = measurement_protocol()

    def invalidate():
        if state.observations >= 3:
            raise ValueError("synthetic upstream proof lost")

    state.on_observe = invalidate
    with pytest.raises(ValueError, match="upstream proof lost"):
        async with state.scope(**state.args):
            pytest.fail("invalid custody yielded a measurement")
    assert state.closed and not (state.output / "measurement.json").exists()
    assert (state.output / "calibration.json").exists()
    assert read_journal(state.root)[-1].disposition == "FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change", ["ledger", "handle", "artifact", "early_revoke", "native_export"]
)
async def test_source_or_owned_custody_change_cannot_complete(measurement_protocol, change):
    state = measurement_protocol()
    original = state.native_module.derive_authenticated_calibration_policy
    with pytest.raises(ValueError):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            if change == "ledger":
                reserved = state.ledger.reserve("unexpected", Decimal("1"))
                state.ledger.reconcile(reserved, Decimal("0.01"))
            elif change == "handle":
                object.__setattr__(live, "verification", object())
            elif change == "artifact":
                object.__setattr__(live.calibration, "retained_cost_usd", "0")
            elif change == "early_revoke":
                state.revoke(live.verification)
            else:
                state.native_module.derive_authenticated_calibration_policy = None
    state.native_module.derive_authenticated_calibration_policy = original
    assert state.closed and not (state.output / "measurement.json").exists()
    with pytest.raises(ValueError, match="absent or revoked"):
        state.require(state.proof, state.measured)


@pytest.mark.asyncio
async def test_original_native_observer_rejects_isolated_batch_without_minting_evidence(
    measurement_protocol,
):
    state = measurement_protocol(original_native=True)
    with pytest.raises(ValueError):
        async with state.scope(**state.args):
            pytest.fail("the real observer accepted isolated protocol inputs")
    assert state.closed and not tuple(state.output.iterdir())
    assert read_journal(state.root)[-1].disposition == "FAILED"


@pytest.mark.asyncio
async def test_cleanup_failure_has_no_completion_receipt_even_after_valid_measurement(
    measurement_protocol,
):
    state = measurement_protocol()

    def fail_cleanup():
        raise RuntimeError("synthetic batch cleanup failed")

    state.on_cleanup = fail_cleanup
    with pytest.raises(RuntimeError, match="batch cleanup failed"):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
    assert state.closed and not (state.output / "measurement.json").exists()
    assert read_journal(state.root)[-1].disposition == "FAILED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "registration_sha256",
        "retained_event_sha256",
        "completed_event_sha256",
        "selection_plan_sha256",
        "ledger_identity_sha256",
        "final_ledger_snapshot_sha256",
        "measurement_sha256",
    ],
)
async def test_rehashed_receipt_cannot_change_any_population_cost_or_measurement_join(
    measurement_protocol, field
):
    state = measurement_protocol()
    async with state.scope(**state.args):
        pass
    receipt = read_result(state).receipt.model_dump(mode="json")
    receipt[field] = "0" * 64
    receipt["receipt_sha256"] = canonical_sha256(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    (state.output / "measurement.json").write_text(stable_json(receipt))
    with pytest.raises(ValueError, match=r"differs|differ"):
        read_result(state)


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 8])
async def test_unattended_wrapper_returns_detached_data_after_cleanup(measurement_protocol, count):
    state = measurement_protocol(count)
    # Execute the original wrapper bytecode in an isolated namespace; no product export changes.
    original = measurement.execute_registered_calibration_measurement
    wrapper = FunctionType(
        original.__code__,
        {
            **vars(measurement),
            "registered_calibration_measurement_scope": state.scope,
        },
    )
    wrapper.__kwdefaults__ = original.__kwdefaults__
    result = await wrapper(**state.args)
    assert state.closed and state.secret.cleared
    assert result == read_result(state)
    assert not hasattr(result, "verification")


@pytest.mark.asyncio
async def test_native_export_drift_refuses_before_entry_and_clears_secrets(measurement_protocol):
    state = measurement_protocol()
    state.native_module.observe_authenticated_model_calibration = None
    with pytest.raises(ValueError, match="native exports changed"):
        async with state.scope(**state.args):
            pytest.fail("changed observer was admitted")
    assert not state.entered and state.secret.cleared
    assert not tuple(state.root.iterdir()) and not tuple(state.output.iterdir())


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing_candidate", "registry", "ledger_identity", "interval"])
async def test_native_structural_measurement_must_join_registered_population(
    measurement_protocol, change
):
    state = measurement_protocol(2)

    def change_measurement():
        sources = state.measured.sources
        if change == "missing_candidate":
            state.measured = measure(sources[:1])
            return
        payload = sources[0].model_dump(mode="json")
        if change == "registry":
            for run in payload["runs"]:
                run["candidate_registry_sha256"] = "0" * 64
        else:
            field = (
                "ledger_identity_sha256"
                if change == "ledger_identity"
                else "initial_snapshot_sha256"
            )
            payload["runner_evidence"]["ledger_interval"][field] = "0" * 64
        state.measured = measure((reseal_source(payload), *sources[1:]))

    state.before_measure = change_measurement
    with pytest.raises(ValueError):
        async with state.scope(**state.args):
            pytest.fail("unjoined measurement reached consumption")
    assert state.closed and state.secret.cleared
    assert not tuple(state.output.iterdir())


@pytest.mark.asyncio
async def test_policy_object_mutation_during_consumption_prevents_completion(measurement_protocol):
    state = measurement_protocol(8)
    with pytest.raises(ValueError, match="qualification policy self-hash is inconsistent"):
        async with state.scope(**state.args) as live:
            state.proof = live.verification
            assert live.policy is not None
            object.__setattr__(live.policy, "policy_sha256", "0" * 64)
    assert state.closed and not (state.output / "measurement.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "field",
    [
        "serialized_authority",
        "policy_adoption_authorized",
        "model_qualification_authorized",
        "provider_call_authorized",
        "release_authorized",
        "external_population_seal_required",
    ],
)
async def test_rehashing_cannot_promote_a_receipt_or_remove_external_sealing(
    measurement_protocol, field
):
    state = measurement_protocol()
    async with state.scope(**state.args):
        pass
    payload = read_result(state).receipt.model_dump(mode="json")
    for invalid in (not payload[field], int(payload[field])):
        payload[field] = invalid
        payload["receipt_sha256"] = canonical_sha256(
            {key: value for key, value in payload.items() if key != "receipt_sha256"}
        )
        with pytest.raises(ValueError):
            measurement.RegisteredCalibrationMeasurementReceipt.model_validate_json(
                stable_json(payload)
            )
