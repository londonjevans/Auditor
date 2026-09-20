"""Original disposable accounting for full-tree integration; never operator billing."""

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.models.schemas import (
    AuditModelRefreshPricingAttemptEvidence,
    ContextPackage,
    UsageRecord,
)
from mmaudit.models.truncation_recovery_journal import SchedulerTruncationRecoveryChildActivation
from mmaudit.models.usage import (
    recovery_request_token_plan_from_usage,
    request_token_plan_from_usage,
)
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus, CostReservation
from mmaudit.orchestration.scheduler_runtime import build_scheduler_cost_ledger_baseline
from tests.identity_fixtures import reattest_synthetic_real_usage
from tests.refresh_runtime_support import (
    SyntheticRefreshRuntime,
    bind_usage_to_refresh_pricing_runtime,
)
from tests.truncation_tree_request_support import bind_configured_original_request


class OriginalRunAccounting:
    """Reserve before simulated dispatch and reconcile only this fixture's scripted cost."""

    def __init__(self, directory: Path, *, configured_requests: bool = False) -> None:
        directory.mkdir(mode=0o700)
        self.ledger = AtomicCostLedger.initialize(directory / "ledger.json", cap_usd=Decimal("250"))
        self.baseline = build_scheduler_cost_ledger_baseline(self.ledger)
        self.pending: dict[str, CostReservation] = {}
        self.dispatched_requests: list[str] = []
        self.configured_requests = configured_requests
        self.spent_input_tokens = 0
        self.spent_output_tokens = 0

    def prepare(
        self,
        record: UsageRecord,
        runtime: SyntheticRefreshRuntime,
        *,
        recovery_activation: SchedulerTruncationRecoveryChildActivation | None = None,
        context: ContextPackage | None = None,
    ) -> UsageRecord:
        """Build coherent synthetic prices before retaining any output or dispatch marker."""

        if record.request_id in self.pending or record.request_id in self.dispatched_requests:
            raise ValueError("synthetic accounting request was already reserved")
        if recovery_activation is not None:
            if recovery_activation.child_logical_request_id != record.request_id:
                raise ValueError("synthetic cost plan differs from original recovery activation")
            plan = recovery_request_token_plan_from_usage(
                record,
                request_limit_scope=recovery_activation.request_limit_id,
                request_limit_count_before=recovery_activation.request_limit_count_before_child,
            )
        else:
            plan = request_token_plan_from_usage(record)
        if plan is None or record.attempts != 1:
            raise ValueError("synthetic accounting requires one original planned attempt")
        if self.configured_requests:
            if context is None or self.pending:
                raise ValueError(
                    "configured synthetic dispatch requires original context and serial cost"
                )
            record = bind_configured_original_request(
                record,
                runtime,
                plan,
                context,
                spent_input_tokens=self.spent_input_tokens,
                spent_output_tokens=self.spent_output_tokens,
            )
            if recovery_activation is None:
                plan = request_token_plan_from_usage(record)
            else:
                plan = recovery_request_token_plan_from_usage(
                    record,
                    request_limit_scope=recovery_activation.request_limit_id,
                    request_limit_count_before=recovery_activation.request_limit_count_before_child,
                )
            assert plan is not None
        routes = tuple(
            route
            for route in runtime.pricing_evidence.routes
            if route.exact_model_id == record.requested_model and route.audit_selected
        )
        if len(routes) != 1:
            raise ValueError("synthetic accounting lacks one original pricing route")
        pricing = routes[0].current_pricing
        limits = {
            "prompt": plan.hard_prompt_tokens,
            "completion": plan.requested_completion_tokens,
            "request": 1,
        }
        observed = {
            "prompt": record.prompt_tokens,
            "completion": record.completion_tokens,
            "request": 1,
        }
        if not set(pricing) <= set(limits):
            raise ValueError("synthetic accounting does not support that priced component")
        if any(observed[field] > limits[field] for field in pricing):
            raise ValueError("scripted usage exceeds its original request plan")
        cost = sum(
            (Decimal(price) * observed[field] for field, price in pricing.items()), Decimal(0)
        )
        exact = format(cost.normalize(), "f")
        scripted = record.model_copy(
            update={
                "reported_cost_usd": float(cost),
                "reported_cost_usd_exact": exact,
                "accounted_cost_usd": float(cost),
                "accounted_cost_usd_exact": exact,
            }
        )
        priced = bind_usage_to_refresh_pricing_runtime(
            scripted, runtime, planned_maximum_units={field: limits[field] for field in pricing}
        )
        priced = reattest_synthetic_real_usage(priced)
        attempt = AuditModelRefreshPricingAttemptEvidence.model_validate_json(
            json.dumps(priced.routing["audit_model_refresh_pricing_attempt"])
        )
        self.pending[record.request_id] = self.ledger.reserve(
            record.request_id,
            Decimal(attempt.maximum_cost_usd_exact),
            require_known_prior_costs=True,
        )
        return priced

    def dispatch(
        self, journal: Any, task_id: str, record: UsageRecord, *, recovery: bool = False
    ) -> None:
        """Observe an actual RESERVED row before the original journal's dispatch transition."""

        reservation = self.pending[record.request_id]
        entry = next(
            item for item in self.ledger.snapshot().entries if item.request_id == record.request_id
        )
        assert entry.status is CostEntryStatus.RESERVED
        assert entry.reservation_id == reservation.reservation_id
        assert record.request_id not in self.dispatched_requests
        if recovery:
            journal.mark_truncation_recovery_child_dispatched(task_id)
        else:
            journal.mark_dispatched(task_id)
        self.dispatched_requests.append(record.request_id)

    def finish(self, record: UsageRecord) -> None:
        """Keep original synthetic usage and the terminal ledger charge exactly joined."""

        if record.request_id not in self.dispatched_requests:
            raise ValueError("synthetic cost cannot finish before original dispatch")
        reservation = self.pending.pop(record.request_id)
        assert record.reported_cost_usd_exact is not None
        entry = self.ledger.reconcile(reservation, Decimal(record.reported_cost_usd_exact))
        assert entry.accounted_cost_usd == Decimal(record.accounted_cost_usd_exact)
        self.spent_input_tokens += record.prompt_tokens
        self.spent_output_tokens += record.completion_tokens
