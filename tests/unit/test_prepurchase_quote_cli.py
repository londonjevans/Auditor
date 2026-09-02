from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import mmaudit.cli as cli_module
from mmaudit.cli import app
from mmaudit.models.prepurchase_quote import (
    AcceptedPrepurchaseQuote,
    PrepurchaseQuote,
    PrepurchaseQuoteReconciliation,
    PrepurchaseQuoteReconciliationStatus,
)
from mmaudit.models.sharding import SolidityShardsArtifact
from mmaudit.reporting.bundle import build_model_execution_artifact, build_run_cost_ledger_evidence
from mmaudit.reporting.json_report import stable_json
from tests.unit.test_forensic_cost_ledger import _report, _usage  # type: ignore[attr-defined]
from tests.unit.test_prepurchase_quote import _quote_fixture

runner = CliRunner()
_CLI_TIME = datetime(2026, 8, 28, 2, 0, tzinfo=UTC)


class _FixedDatetime:
    @staticmethod
    def now(timezone: object) -> datetime:
        assert timezone is UTC
        return _CLI_TIME


def _write_model(path: Path, value: Any) -> None:
    path.write_text(stable_json(value), encoding="utf-8")


def test_quote_create_uses_only_exact_frozen_local_inputs(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="quote-cli-create")
    config = config_factory()
    manifest_path = tmp_path / "campaign-manifest.json"
    shards_path = tmp_path / "solidity-shards.json"
    preflight_path = tmp_path / "portfolio-preflight.json"
    discovery_run = tmp_path / "frozen-discovery"
    output = tmp_path / "quote.json"
    discovery_manifest = object()
    discovery_evidence = (object(),)
    _write_model(manifest_path, fixture.manifest)
    _write_model(
        shards_path,
        SolidityShardsArtifact(schema_version="1.0", inventory=fixture.inventory),
    )
    _write_model(preflight_path, fixture.preflight)
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda path: (
            (
                discovery_manifest,
                discovery_evidence,
            )
            if path == discovery_run
            else pytest.fail("unexpected discovery path")
        ),
    )

    def build_quote(
        observed_config: Any,
        **kwargs: Any,
    ) -> PrepurchaseQuote:
        assert observed_config is config
        assert kwargs == {
            "campaign_manifest": fixture.manifest,
            "solidity_shard_inventory": fixture.inventory,
            "portfolio_preflight": fixture.preflight,
            "discovery_manifest": discovery_manifest,
            "discovery_evidence": discovery_evidence,
        }
        return fixture.quote

    monkeypatch.setattr(cli_module, "build_prepurchase_quote_from_frozen_inputs", build_quote)

    result = runner.invoke(
        app,
        [
            "quote",
            "create",
            "--config",
            str(tmp_path / "config.toml"),
            "--campaign-manifest",
            str(manifest_path),
            "--solidity-shards",
            str(shards_path),
            "--portfolio-preflight",
            str(preflight_path),
            "--discovery-run",
            str(discovery_run),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert PrepurchaseQuote.model_validate_json(output.read_bytes(), strict=True) == fixture.quote
    assert output.stat().st_mode & 0o777 == 0o600


def test_quote_create_applies_explicit_schema_retry_selection_exactly(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _quote_fixture(
        tmp_path,
        config_factory,
        seed="quote-cli-schema-retry",
        transient_retry_limit=1,
        schema_validation_retry_limit=2,
    )
    config = config_factory(execution={"max_model_retries": 1})
    manifest_path = tmp_path / "campaign-manifest.json"
    shards_path = tmp_path / "solidity-shards.json"
    preflight_path = tmp_path / "portfolio-preflight.json"
    discovery_run = tmp_path / "frozen-discovery"
    output = tmp_path / "quote.json"
    _write_model(manifest_path, fixture.manifest)
    _write_model(
        shards_path,
        SolidityShardsArtifact(schema_version="1.0", inventory=fixture.inventory),
    )
    _write_model(preflight_path, fixture.preflight)
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        cli_module,
        "load_model_discovery_run",
        lambda path: (object(), (object(),)) if path == discovery_run else pytest.fail(path),
    )

    def build_quote(observed_config: Any, **_kwargs: Any) -> PrepurchaseQuote:
        assert observed_config.execution.max_model_retries == 1
        assert observed_config.execution.max_schema_validation_retries == 2
        assert observed_config.execution.model_retry_policy.maximum_attempts == 4
        return fixture.quote

    monkeypatch.setattr(cli_module, "build_prepurchase_quote_from_frozen_inputs", build_quote)

    result = runner.invoke(
        app,
        [
            "quote",
            "create",
            "--config",
            str(tmp_path / "config.toml"),
            "--campaign-manifest",
            str(manifest_path),
            "--solidity-shards",
            str(shards_path),
            "--portfolio-preflight",
            str(preflight_path),
            "--discovery-run",
            str(discovery_run),
            "--schema-validation-retries",
            "2",
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    emitted = PrepurchaseQuote.model_validate_json(output.read_bytes(), strict=True)
    assert emitted.retry_policy == fixture.quote.retry_policy
    assert emitted.retry_policy.transient_retry_limit == 1
    assert emitted.retry_policy.schema_validation_retry_limit == 2
    assert emitted.retry_policy.maximum_attempts == 4
    assert emitted.maximum_request_count == fixture.quote.maximum_request_count
    assert emitted.cost_range == fixture.quote.cost_range
    assert emitted.wall_clock_range == fixture.quote.wall_clock_range


@pytest.mark.parametrize(
    ("configured_retries", "selection", "message"),
    [
        (1, None, "require explicit --schema-validation-retries selection"),
        (2, 1, "selection conflicts with the configured schema-retry quota"),
    ],
)
def test_quote_create_rejects_implicit_or_conflicting_schema_retry_before_input_reads(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
    configured_retries: int,
    selection: int | None,
    message: str,
) -> None:
    config = config_factory(execution={"max_schema_validation_retries": configured_retries})
    monkeypatch.setattr(cli_module, "load_config", lambda _path: config)
    monkeypatch.setattr(
        cli_module,
        "_read_quote_json",
        lambda _path: pytest.fail("quote input read before retry-policy rejection"),
    )
    arguments = [
        "quote",
        "create",
        "--campaign-manifest",
        str(tmp_path / "missing-manifest.json"),
        "--solidity-shards",
        str(tmp_path / "missing-shards.json"),
        "--portfolio-preflight",
        str(tmp_path / "missing-preflight.json"),
        "--discovery-run",
        str(tmp_path / "missing-discovery"),
        "--output",
        str(tmp_path / "quote.json"),
        "--no-color",
    ]
    if selection is not None:
        arguments.extend(["--schema-validation-retries", str(selection)])

    result = runner.invoke(app, arguments)

    assert result.exit_code != 0
    assert message in " ".join(result.stdout.split())
    assert not (tmp_path / "quote.json").exists()


def test_quote_accept_records_explicit_utc_nonauthorizing_acceptance(
    tmp_path: Path,
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed="quote-cli-accept")
    quote_path = tmp_path / "quote.json"
    output = tmp_path / "accepted-quote.json"
    _write_model(quote_path, fixture.quote)
    monkeypatch.setattr(cli_module, "datetime", _FixedDatetime)

    result = runner.invoke(
        app,
        [
            "quote",
            "accept",
            "--quote",
            str(quote_path),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    acceptance = AcceptedPrepurchaseQuote.model_validate_json(output.read_bytes(), strict=True)
    assert acceptance.quote == fixture.quote
    offset = acceptance.accepted_at.utcoffset()
    assert offset is not None
    assert offset.total_seconds() == 0
    assert not acceptance.authorizes_dispatch


@pytest.mark.parametrize("source_kind", ["ledger", "model-execution"])
def test_quote_reconcile_accepts_exact_terminal_evidence_sources(
    source_kind: str,
    tmp_path: Path,
    config_factory: Callable[..., Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _quote_fixture(tmp_path, config_factory, seed=f"quote-cli-{source_kind}")
    baseline = fixture.manifest.cost_ledger_baseline
    assert baseline is not None
    request_id = fixture.preflight.task_envelopes[0].scheduler_logical_request_id
    reservation = fixture.ledger.reserve(request_id, Decimal("0.2"))
    fixture.ledger.reconcile(reservation, Decimal("0.1"))
    usage = _usage(cost="0.1", request_id=request_id)
    evidence = build_run_cost_ledger_evidence(
        baseline=baseline,
        final_snapshot=fixture.ledger.snapshot(),
        campaign_logical_request_ids=(request_id,),
        usage_records=(usage,),
        campaign_id=fixture.manifest.campaign_id,
        campaign_manifest_sha256=fixture.manifest.manifest_sha256,
    )
    acceptance_path = tmp_path / "accepted-quote.json"
    source_path = tmp_path / f"{source_kind}.json"
    output = tmp_path / "reconciliation.json"
    _write_model(acceptance_path, fixture.acceptance)
    monkeypatch.setattr(cli_module, "datetime", _FixedDatetime)
    if source_kind == "ledger":
        source_option = "--cost-ledger-evidence"
        _write_model(source_path, evidence)
    else:
        source_option = "--model-execution"
        report = _report().model_copy(
            update={
                "usage": [usage],
                "accounted_cost_usd": usage.accounted_cost_usd,
                "accounted_cost_usd_exact": usage.accounted_cost_usd_exact,
                "budget_usd": float(Decimal(baseline.cap_usd_exact)),
            }
        )
        _write_model(
            source_path,
            build_model_execution_artifact(report, cost_ledger_evidence=evidence),
        )

    result = runner.invoke(
        app,
        [
            "quote",
            "reconcile",
            "--acceptance",
            str(acceptance_path),
            source_option,
            str(source_path),
            "--output",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == 0, result.stdout
    reconciliation = PrepurchaseQuoteReconciliation.model_validate_json(
        output.read_bytes(),
        strict=True,
    )
    assert reconciliation.status is PrepurchaseQuoteReconciliationStatus.CONCLUSIVE
    assert reconciliation.actual_cost_usd_exact == "0.1"
    assert reconciliation.within_worst_case


def test_quote_reconcile_requires_exactly_one_terminal_evidence_source(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "quote",
            "reconcile",
            "--acceptance",
            str(tmp_path / "missing-acceptance.json"),
            "--model-execution",
            str(tmp_path / "missing-model-execution.json"),
            "--cost-ledger-evidence",
            str(tmp_path / "missing-ledger.json"),
            "--output",
            str(tmp_path / "reconciliation.json"),
            "--no-color",
        ],
    )

    assert result.exit_code != 0
    assert "requires exactly one" in result.stdout


def test_run_forwards_accepted_quote_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_execute_audit", lambda **kwargs: captured.update(kwargs))
    accepted_quote = tmp_path / "accepted-quote.json"

    result = runner.invoke(
        app,
        ["run", "--accepted-quote", str(accepted_quote), "--no-color"],
    )

    assert result.exit_code == 0, result.stdout
    assert captured["accepted_quote"] == accepted_quote
    assert captured["schema_validation_retries"] is None


def test_run_forwards_explicit_schema_retry_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}
    monkeypatch.setattr(cli_module, "_execute_audit", lambda **kwargs: captured.update(kwargs))

    result = runner.invoke(
        app,
        ["run", "--schema-validation-retries", "3", "--no-color"],
    )

    assert result.exit_code == 0, result.stdout
    assert captured["schema_validation_retries"] == 3


def test_scanner_only_run_rejects_accepted_quote_before_read(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "run",
            "--scanner-only",
            "--accepted-quote",
            str(tmp_path / "missing-accepted-quote.json"),
            "--no-color",
        ],
    )

    assert result.exit_code != 0
    assert "rejected by scanner-only and CI" in result.stdout


def test_scanner_only_run_rejects_schema_retry_selection_before_config_read() -> None:
    result = runner.invoke(
        app,
        ["run", "--scanner-only", "--schema-validation-retries", "1", "--no-color"],
    )

    assert result.exit_code != 0
    assert "accepted only by paid provider audits" in " ".join(result.stdout.split())


@pytest.mark.parametrize("command", ["scan", "ci"])
def test_provider_free_commands_reject_accepted_quote_option(
    command: str,
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [command, "--accepted-quote", str(tmp_path / "accepted-quote.json")],
    )

    assert result.exit_code != 0
    assert "No such option" in result.stderr
