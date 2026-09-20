"""Bounded ownership of live calibration inputs, not a qualified campaign or paid permission.

All launches are supplied before execution. This scope retains their original native
runner proofs on one ledger until consumption finishes, then revokes every runner
before closing accounting. Full frozen-population registration and release remain
separate requirements; an incomplete batch never yields a successful input set.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import TYPE_CHECKING, Never, SupportsIndex

from mmaudit.benchmark.models import ModelBenchmarkSuite
from mmaudit.models.authenticated_calibration import AuthenticatedCalibrationCandidateInputs
from mmaudit.models.authenticated_runner_execution import AuthenticatedRunnerExecutionResult
from mmaudit.models.candidate_selection import CandidateSelectionPlan
from mmaudit.models.ground_truth_authority import VerifiedFrozenGroundTruth
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.authenticated_calibration_accounting import (
    calibration_ledger_accounting_scope,
    require_calibration_accounting_ready,
)
from mmaudit.orchestration.authenticated_runner_openrouter import (
    AuthenticatedRunnerOpenRouterError,
    AuthenticatedRunnerOpenRouterLaunch,
    _owned_authenticated_openrouter_runner_scope,
    _require_live_runner_consumption,
    preflight_authenticated_openrouter_launch,
)
from mmaudit.orchestration.calibration_population import CalibrationPopulationJournal
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.manifest import canonical_sha256

if TYPE_CHECKING:
    from mmaudit.orchestration.calibration_calendar_controller import _CalendarRecording


@dataclass(frozen=True, slots=True)
class AuthenticatedOpenRouterCalibrationInputs:
    """Exact native-consumer inputs valid only while the surrounding scope is live."""

    selected_model_ids: tuple[str, ...]
    benchmark_suite: ModelBenchmarkSuite
    ground_truth: VerifiedFrozenGroundTruth
    inputs: tuple[AuthenticatedCalibrationCandidateInputs, ...]

    def __reduce__(self) -> Never:
        raise TypeError("live calibration batch inputs cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("live calibration batch inputs cannot be serialized")


def _candidate_ids(launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...]) -> tuple[str, ...]:
    return tuple(launch.candidate_registry.candidates[0].exact_model_id for launch in launches)


def _population_launch_binding(launch: AuthenticatedRunnerOpenRouterLaunch) -> tuple[str, str, str]:
    """Freeze declared data, not secrets, paths or a serialization of opaque capabilities."""

    return (
        launch.candidate_registry.candidates[0].exact_model_id,
        launch.candidate_registry.registry_sha256,
        canonical_sha256(
            {
                "config": launch.config.model_dump(mode="json"),
                "explicitly_allow_synthetic_egress": launch.explicitly_allow_synthetic_egress,
                "corpus": launch.benchmark_suite.model_dump(mode="json"),
                "policy": launch.qualification_policy.model_dump(mode="json"),
                "registry": launch.candidate_registry.model_dump(mode="json"),
                "discovery": launch.candidate_discovery_manifest.model_dump(mode="json"),
                "evidence": [
                    item.model_dump(mode="json") for item in launch.candidate_discovery_evidence
                ],
                "runs": [
                    {
                        "kind": run.run_kind.value,
                        "registry": run.judge_registry.model_dump(mode="json"),
                        "discovery": run.judge_discovery_manifest.model_dump(mode="json"),
                        "evidence": [
                            item.model_dump(mode="json") for item in run.judge_discovery_evidence
                        ],
                        "candidate_cap_usd": str(run.candidate_declared_cost_cap_usd_per_attempt),
                        "judge_cap_usd": str(run.judge_declared_cost_cap_usd_per_attempt),
                    }
                    for run in launch.run_plans
                ],
            }
        ),
    )


def _require_native_batch(
    batch: AuthenticatedOpenRouterCalibrationInputs,
    executions: tuple[AuthenticatedRunnerExecutionResult, ...],
) -> None:
    """Data, replaced handles and child substitutions cannot stand in for native custody."""

    if len(batch.inputs) != len(executions):
        raise AuthenticatedRunnerOpenRouterError("calibration batch lost retained inputs")
    for item, execution in zip(batch.inputs, executions, strict=True):
        if (
            type(item) is not AuthenticatedCalibrationCandidateInputs
            or item.runner_custody is not execution.runner_capability
            or item.runner_evidence is not execution.runner_evidence
            or type(item.runs) is not tuple
            or len(item.runs) != len(execution.runs)
            or any(
                run is not retained.custody
                for run, retained in zip(item.runs, execution.runs, strict=True)
            )
        ):
            raise AuthenticatedRunnerOpenRouterError("calibration batch replaced native inputs")
        _require_live_runner_consumption(execution)


def _require_registered_launches(
    journal: CalibrationPopulationJournal,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
) -> None:
    journal.require_unchanged()
    if tuple(_population_launch_binding(item) for item in launches) != tuple(
        (slot.exact_model_id, slot.registry_sha256, slot.launch_binding_sha256)
        for slot in journal.current.slots
    ):
        raise AuthenticatedRunnerOpenRouterError("registered population registry bindings changed")


@asynccontextmanager
async def authenticated_openrouter_calibration_scope(
    *,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
    operator_secrets: tuple[OperatorSecrets, ...],
    timeout_seconds: float = 3600.0,
) -> AsyncIterator[AuthenticatedOpenRouterCalibrationInputs]:
    """Own an exact sequential batch and native consumption under one cooperative deadline.

    Each launch retains its ordinary budget, route, lineage and source preflight.
    A failure aborts without a retry or a shortened successful population. The
    timeout also rejects synchronous late returns; it is not a Python sandbox.
    Secret ownership is accepted only for an exact tuple of at most 128 holders.
    """

    async with _owned_calibration_batch(
        launches=launches, operator_secrets=operator_secrets, timeout_seconds=timeout_seconds
    ) as batch:
        yield batch


@asynccontextmanager
async def registered_openrouter_calibration_scope(
    *,
    selection_plan: CandidateSelectionPlan,
    ledger: AtomicCostLedger,
    evidence_root: Path,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
    operator_secrets: tuple[OperatorSecrets, ...],
    timeout_seconds: float = 3600.0,
) -> AsyncIterator[AuthenticatedOpenRouterCalibrationInputs]:
    """Precommit every reference-plan slot before preflight, then own the exact native batch.

    Use an existing empty private evidence directory. Missing launches remain visible
    and prevent execution. Each launch retains its own authenticated route ancestry;
    this reference plan is a population declaration, not an ancestry/root authority.
    Files record runner entry, not an assertion that transport was dispatched. There
    is no resume/retry API. Journal failure refuses further work; a retained OPEN
    prefix after process or storage failure must never be treated as completion.
    """

    async with _owned_registered_calibration_scope(
        selection_plan=selection_plan,
        ledger=ledger,
        evidence_root=evidence_root,
        launches=launches,
        operator_secrets=operator_secrets,
        timeout_seconds=timeout_seconds,
    ) as (batch, _journal):
        yield batch


@asynccontextmanager
async def _owned_registered_calibration_scope(
    *,
    selection_plan: CandidateSelectionPlan,
    ledger: AtomicCostLedger,
    evidence_root: Path,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
    operator_secrets: tuple[OperatorSecrets, ...],
    timeout_seconds: float,
    _calendar_recording: _CalendarRecording | None = None,
) -> AsyncIterator[tuple[AuthenticatedOpenRouterCalibrationInputs, CalibrationPopulationJournal]]:
    """Keep the original journal inside trusted orchestration, not caller-authored data."""

    if type(operator_secrets) is not tuple or not 0 <= len(operator_secrets) <= 64:
        raise AuthenticatedRunnerOpenRouterError(
            "registered population requires 0..64 secret holders"
        )
    journal: CalibrationPopulationJournal | None = None
    try:
        if (
            type(launches) is not tuple
            or len(launches) > 64
            or len(launches) != len(operator_secrets)
            or any(type(launch) is not AuthenticatedRunnerOpenRouterLaunch for launch in launches)
            or any(type(secret) is not OperatorSecrets for secret in operator_secrets)
            or len({id(secret) for secret in operator_secrets}) != len(operator_secrets)
            or any(
                launch.budget.atomic_ledger is not ledger
                or len(launch.candidate_registry.candidates) != 1
                or not 2 <= len(launch.run_plans) <= 32
                for launch in launches
            )
        ):
            raise AuthenticatedRunnerOpenRouterError(
                "registered population launch shape is invalid"
            )
        present_bindings = tuple(_population_launch_binding(launch) for launch in launches)
        journal = CalibrationPopulationJournal(
            evidence_root=evidence_root,
            selection_plan=selection_plan,
            ledger=ledger,
            present_registries=present_bindings,
        )
        if not launches:
            raise AuthenticatedRunnerOpenRouterError(
                "registered population has no available launches"
            )
        if _calendar_recording is not None:
            from mmaudit.orchestration.calibration_calendar_controller import (
                _record_calendar_registration,
            )

            await _record_calendar_registration(_calendar_recording, journal)
            journal.require_unchanged()
            if tuple(_population_launch_binding(launch) for launch in launches) != present_bindings:
                raise AuthenticatedRunnerOpenRouterError(
                    "registered population launch bindings changed during publication"
                )
        async with _owned_calibration_batch(
            launches=launches,
            operator_secrets=operator_secrets,
            timeout_seconds=timeout_seconds,
            _journal=journal,
            _calendar_recording=_calendar_recording,
        ) as batch:
            yield batch, journal
        _require_registered_launches(journal, launches)
        journal.append("FINISHED", disposition="CONSUMED")
    except BaseException as exc:
        if journal is not None and journal.current.disposition == "OPEN":
            journal.append(
                "FINISHED",
                disposition="CANCELLED" if isinstance(exc, asyncio.CancelledError) else "FAILED",
            )
        raise
    finally:
        for secret in operator_secrets:
            if type(secret) is OperatorSecrets:
                secret.clear()


@asynccontextmanager
async def _owned_calibration_batch(
    *,
    launches: tuple[AuthenticatedRunnerOpenRouterLaunch, ...],
    operator_secrets: tuple[OperatorSecrets, ...],
    timeout_seconds: float,
    _journal: CalibrationPopulationJournal | None = None,
    _calendar_recording: _CalendarRecording | None = None,
) -> AsyncIterator[AuthenticatedOpenRouterCalibrationInputs]:
    """Shared native lifecycle; an optional internal journal cannot grant runner authority."""

    if type(operator_secrets) is not tuple or not 1 <= len(operator_secrets) <= 128:
        raise AuthenticatedRunnerOpenRouterError("calibration requires 1..128 secret holders")
    try:
        if (
            type(launches) is not tuple
            or not 1 <= len(launches) <= 128
            or len(launches) != len(operator_secrets)
            or any(type(launch) is not AuthenticatedRunnerOpenRouterLaunch for launch in launches)
            or any(type(secret) is not OperatorSecrets for secret in operator_secrets)
            or len({id(secret) for secret in operator_secrets}) != len(operator_secrets)
        ):
            raise AuthenticatedRunnerOpenRouterError("calibration requires exact bounded launches")
        if type(timeout_seconds) not in {int, float} or not 0 < timeout_seconds <= 86400:
            raise AuthenticatedRunnerOpenRouterError("calibration deadline must be within 86400s")
        task = asyncio.current_task()
        if task is None or task.cancelling():
            raise asyncio.CancelledError
        deadline = monotonic() + timeout_seconds
        timer = asyncio.timeout(timeout_seconds)

        def require_time() -> None:
            if task.cancelling():
                raise asyncio.CancelledError
            if timer.expired() or monotonic() >= deadline:
                raise AuthenticatedRunnerOpenRouterError("calibration batch deadline expired")
            if _calendar_recording is not None:
                from mmaudit.orchestration.calibration_calendar_controller import (
                    _require_calendar_recording,
                )

                _require_calendar_recording(_calendar_recording)

        try:
            async with timer:
                # No dispatch until every selected launch passes its real local preflight.
                if _journal is None:
                    inventories = tuple(
                        preflight_authenticated_openrouter_launch(x) for x in launches
                    )
                else:
                    admitted = []
                    for launch in launches:
                        require_time()
                        _journal.require_unchanged()
                        model_id = launch.candidate_registry.candidates[0].exact_model_id
                        try:
                            inventory = preflight_authenticated_openrouter_launch(launch)
                        except Exception:
                            # Retain only constant failure state, never exception text/secrets.
                            _journal.append("PREFLIGHT_REFUSED", exact_model_id=model_id)
                        else:
                            _journal.append("PREFLIGHT_PASSED", exact_model_id=model_id)
                            admitted.append(inventory)
                    if any(slot.state != "READY" for slot in _journal.current.slots):
                        raise AuthenticatedRunnerOpenRouterError(
                            "registered population contains missing or refused launches"
                        )
                    inventories = tuple(admitted)
                selected = _candidate_ids(launches)
                if selected != tuple(sorted(set(selected))):
                    raise AuthenticatedRunnerOpenRouterError(
                        "calibration candidates must be unique and sorted"
                    )
                first = launches[0]
                ledger = first.budget.atomic_ledger
                if type(ledger) is not AtomicCostLedger or any(
                    launch.budget.atomic_ledger is not ledger
                    or launch.benchmark_suite is not first.benchmark_suite
                    or launch.ground_truth_capability is not first.ground_truth_capability
                    or launch.public_lineage_capability is not first.public_lineage_capability
                    or launch.qualification_policy != first.qualification_policy
                    or inventory.effective_config_sha256 != inventories[0].effective_config_sha256
                    for launch, inventory in zip(launches, inventories, strict=True)
                ):
                    raise AuthenticatedRunnerOpenRouterError(
                        "calibration launches must share original ledger, truth, lineage and policy"
                    )
                require_time()
                with calibration_ledger_accounting_scope(ledger) as accounting:
                    async with AsyncExitStack() as owned:
                        executions: list[AuthenticatedRunnerExecutionResult] = []
                        for index, (launch, secret) in enumerate(
                            zip(launches, operator_secrets, strict=True)
                        ):
                            require_time()
                            require_calibration_accounting_ready(accounting)
                            if _candidate_ids(launches) != selected:
                                raise AuthenticatedRunnerOpenRouterError(
                                    "calibration launch population changed"
                                )
                            if _journal is not None:
                                _require_registered_launches(_journal, launches)
                                _journal.append("RUNNER_STARTED", exact_model_id=selected[index])
                            execution = await owned.enter_async_context(
                                _owned_authenticated_openrouter_runner_scope(
                                    launch=launch, operator_secrets=secret, _accounting=accounting
                                )
                            )
                            executions.append(execution)
                            if not execution.runner_evidence.runs or any(
                                run.candidate_model_id != selected[index]
                                for run in execution.runner_evidence.runs
                            ):
                                raise AuthenticatedRunnerOpenRouterError(
                                    "calibration execution differs from selected candidate"
                                )
                            if _journal is not None:
                                _require_live_runner_consumption(execution)
                                _journal.append(
                                    "RUNNER_RETAINED",
                                    exact_model_id=selected[index],
                                    runner_evidence_sha256=execution.runner_evidence.evidence_sha256,
                                )
                            require_time()
                        retained = tuple(executions)
                        inputs = tuple(
                            AuthenticatedCalibrationCandidateInputs(
                                runner_custody=execution.runner_capability,
                                runner_evidence=execution.runner_evidence,
                                runs=tuple(item.custody for item in execution.runs),
                            )
                            for execution in retained
                        )
                        batch = AuthenticatedOpenRouterCalibrationInputs(
                            selected, first.benchmark_suite, first.ground_truth_capability, inputs
                        )
                        bindings = (
                            selected,
                            first.benchmark_suite,
                            first.ground_truth_capability,
                            inputs,
                        )
                        _require_native_batch(batch, retained)
                        require_time()
                        yield batch
                        require_time()
                        if any(
                            getattr(batch, name) is not original
                            for name, original in zip(
                                ("selected_model_ids", "benchmark_suite", "ground_truth", "inputs"),
                                bindings,
                                strict=True,
                            )
                        ):
                            raise AuthenticatedRunnerOpenRouterError(
                                "calibration consumer replaced original batch inputs"
                            )
                        require_calibration_accounting_ready(accounting)
                        _require_native_batch(batch, retained)
                        require_time()
                require_time()
        except TimeoutError:
            if timer.expired():
                raise AuthenticatedRunnerOpenRouterError(
                    "calibration batch deadline expired"
                ) from None
            raise
    finally:
        for secret in operator_secrets:
            if type(secret) is OperatorSecrets:
                secret.clear()
