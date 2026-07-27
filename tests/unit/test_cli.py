from __future__ import annotations

import json
import shutil
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from mmaudit.benchmark.certificate import (
    BenchmarkCertificatePayload,
    CertificateVerificationStatus,
    load_benchmark_certificate,
    observe_file_backed_certificate,
    seal_benchmark_certificate,
    write_benchmark_certificate,
)
from mmaudit.benchmark.claims import (
    ComparativeMetricEvidence,
    HumanComparisonEvidencePayload,
    ProportionSample,
    SuperiorityClaimStatus,
    seal_human_comparison_evidence,
)
from mmaudit.benchmark.engine import (
    BenchmarkBlindingProtocol,
    BenchmarkGate,
    BenchmarkReport,
    BenchmarkRepositoryMetrics,
    BenchmarkStatus,
)
from mmaudit.benchmark.mutations import (
    MutationKind,
    MutationPropertyOutcome,
    MutationTestOutcome,
    score_mutation_outcomes,
)
from mmaudit.cli import app
from mmaudit.config import ConfigError, configured_model_ids
from mmaudit.constants import ExitCode
from mmaudit.models.schemas import AuditProfile
from mmaudit.orchestration.cost_ledger import AtomicCostLedger

ROOT = Path(__file__).parents[2]
runner = CliRunner()
CERTIFICATE_COMMIT = "a" * 40


def test_help_lists_required_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "init",
        "doctor",
        "models",
        "snapshot",
        "scan",
        "run",
        "explain",
        "benchmark",
        "verify-certificate",
        "verify-run",
        "replay",
    ):
        assert command in result.stdout


def test_run_help_lists_fork_aliases() -> None:
    result = runner.invoke(app, ["run", "--help"])
    assert result.exit_code == 0
    assert "--allow-fork" in result.stdout
    assert "--scope" in result.stdout
    assert "--cost-ledger" in result.stdout


def test_models_benchmark_help_lists_blinded_corpus_and_egress_controls() -> None:
    result = runner.invoke(app, ["models", "benchmark", "--help"])
    assert result.exit_code == 0
    assert "--corpus" in result.stdout
    assert "--model" in result.stdout
    assert "--allow-code-egress" in result.stdout
    assert "--cost-ledger" in result.stdout


@pytest.mark.parametrize(
    "arguments",
    [
        ["doctor", "--help"],
        ["models", "list", "--help"],
        ["models", "check", "--help"],
        ["models", "benchmark", "--help"],
        ["scan", "--help"],
        ["run", "--help"],
    ],
)
def test_provider_commands_expose_explicit_secret_file_option(arguments: list[str]) -> None:
    result = runner.invoke(app, arguments, env={"COLUMNS": "240"})
    assert result.exit_code == 0
    assert "--secrets-env-file" in result.stdout


def test_models_benchmark_requires_explicit_egress_before_provider_access(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    config = config_factory(privacy={"allow_code_egress": False})
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    model_id = config.models.threat_model.primary
    arguments = [
        "models",
        "benchmark",
        "--config",
        str(tmp_path / "synthetic.toml"),
        "--corpus",
        str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
        "--model",
        model_id,
        "--output",
        str(tmp_path / "model-benchmark.json"),
        "--no-color",
    ]

    without_approval = runner.invoke(app, arguments)
    with_approval = runner.invoke(app, [*arguments, "--allow-code-egress"])

    assert without_approval.exit_code == ExitCode.CONFIGURATION
    assert "explicit synthetic-source egress" in without_approval.stdout
    assert "approval" in without_approval.stdout
    assert with_approval.exit_code == ExitCode.CONFIGURATION
    assert "--cost-ledger" in with_approval.stdout
    assert not (tmp_path / "model-benchmark.json").exists()


def test_models_cost_ledger_initialization_is_explicit_and_one_time(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory(execution={"budget_usd": 250.0})
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger = tmp_path / "provider-cost-ledger.json"
    arguments = [
        "models",
        "init-cost-ledger",
        "--config",
        str(tmp_path / "synthetic.toml"),
        "--cost-ledger",
        str(ledger),
        "--no-color",
    ]

    first = runner.invoke(app, arguments)
    second = runner.invoke(app, arguments)

    assert first.exit_code == 0, first.stdout
    assert ledger.is_file()
    assert second.exit_code == ExitCode.CONFIGURATION
    assert "one-time" in second.stdout


def test_provider_run_missing_ledger_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires an existing --cost-ledger" in result.stdout
    assert not secret_accessed


def test_provider_run_deleted_ledger_fails_without_recreating_budget_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    ledger_path = tmp_path / "deleted-campaign-ledger.json"
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--cost-ledger",
            str(ledger_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "existing cost ledger lock" in result.stdout
    assert not secret_accessed
    assert not ledger_path.exists()
    assert not ledger_path.with_name(f".{ledger_path.name}.lock").exists()


def test_provider_run_cap_mismatch_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory(execution={"budget_usd": 20.0})
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger_path = tmp_path / "different-cap-ledger.json"
    AtomicCostLedger.initialize(ledger_path, cap_usd=Decimal("19.0"))
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--repo",
            str(tmp_path),
            "--cost-ledger",
            str(ledger_path),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "cost cap does not match" in result.stdout
    assert not secret_accessed


def test_provider_run_uses_existing_configured_campaign_ledger(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    config = config_factory(
        execution={"cost_ledger_path": str(ledger_path)},
    )
    AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    secret_file = tmp_path / "operator-secrets.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-provider-canary\n", encoding="utf-8")
    secret_file.chmod(0o600)
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    observed_ledgers: list[AtomicCostLedger] = []

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, _fail_on: object) -> ExitCode:
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, _config: object, **kwargs: object) -> None:
            ledger = kwargs["cost_ledger"]
            assert isinstance(ledger, AtomicCostLedger)
            self.ledger = ledger
            observed_ledgers.append(ledger)

        async def run(self, **_kwargs: object) -> SyntheticPipelineResult:
            index = len(observed_ledgers)
            reservation = self.ledger.reserve(
                f"synthetic-provider-run-{index}",
                Decimal("1.0"),
            )
            self.ledger.reconcile(reservation, Decimal("0.25"))
            return SyntheticPipelineResult()

        def clear_credentials(self) -> None:
            return None

    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    for index in range(2):
        output = tmp_path / f"output-{index}"
        result = runner.invoke(
            app,
            [
                "run",
                "--config",
                str(tmp_path / "synthetic.toml"),
                "--secrets-env-file",
                str(secret_file),
                "--repo",
                str(repository),
                "--output",
                str(output),
                "--no-color",
            ],
        )
        assert result.exit_code == ExitCode.SUCCESS, result.stdout
        assert not list(output.rglob("model-cost-ledger.json"))

    assert [ledger.path for ledger in observed_ledgers] == [ledger_path, ledger_path]
    snapshot = observed_ledgers[-1].snapshot()
    assert snapshot.spent_usd == Decimal("0.5")
    assert len(snapshot.entries) == 2


def test_models_benchmark_missing_ledger_fails_before_secret_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    secret_accessed = False

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_accessed
        secret_accessed = True
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "models",
            "benchmark",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--corpus",
            str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
            "--model",
            config.models.threat_model.primary,
            "--output",
            str(output),
            "--cost-ledger",
            str(tmp_path / "missing-cost-ledger.json"),
            "--allow-code-egress",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "existing cost ledger lock" in result.stdout
    assert not secret_accessed
    assert not output.exists()
    assert not (tmp_path / "missing-cost-ledger.json").exists()
    assert not (tmp_path / ".missing-cost-ledger.json.lock").exists()


def test_models_benchmark_output_path_does_not_select_or_create_budget_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )
    secret_calls = 0

    def stop_at_secret_boundary(*_args: object, **_kwargs: object) -> None:
        nonlocal secret_calls
        secret_calls += 1
        raise ConfigError("synthetic secret boundary reached")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", stop_at_secret_boundary)
    outputs = (tmp_path / "first-report.json", tmp_path / "second-report.json")
    for output in outputs:
        result = runner.invoke(
            app,
            [
                "models",
                "benchmark",
                "--config",
                str(tmp_path / "synthetic.toml"),
                "--corpus",
                str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
                "--model",
                config.models.threat_model.primary,
                "--output",
                str(output),
                "--cost-ledger",
                str(ledger_path),
                "--allow-code-egress",
                "--no-color",
            ],
        )
        assert result.exit_code == ExitCode.CONFIGURATION
        assert "synthetic secret boundary reached" in result.stdout
        assert not output.exists()

    assert secret_calls == 2
    snapshot = AtomicCostLedger.open_existing(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    ).snapshot()
    assert snapshot.entries == ()
    for output in outputs:
        derived = output.with_name(f"{output.stem}-cost-ledger.json")
        assert not derived.exists()
        assert not derived.with_name(f".{derived.name}.lock").exists()


@pytest.mark.parametrize("protected_name", ["ledger", "lock"])
def test_models_benchmark_rejects_output_that_aliases_cost_state_before_secret_access(
    protected_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    config_factory: Any,
) -> None:
    tmp_path.chmod(0o700)
    config = config_factory()
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    ledger_path = tmp_path / "campaign-cost-ledger.json"
    ledger = AtomicCostLedger.initialize(
        ledger_path,
        cap_usd=Decimal(str(config.execution.budget_usd)),
    )

    def forbidden_secret_access(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("operator secrets must not be accessed")

    monkeypatch.setattr("mmaudit.cli.load_operator_secrets", forbidden_secret_access)
    output = ledger.path if protected_name == "ledger" else ledger.lock_path
    result = runner.invoke(
        app,
        [
            "models",
            "benchmark",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--corpus",
            str(ROOT / "benchmarks" / "model_corpus" / "manifest.json"),
            "--model",
            config.models.threat_model.primary,
            "--output",
            str(output),
            "--cost-ledger",
            str(ledger_path),
            "--allow-code-egress",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "distinct from cost-ledger" in result.stdout
    assert "state" in result.stdout
    assert (
        AtomicCostLedger.open_existing(
            ledger_path,
            cap_usd=Decimal(str(config.execution.budget_usd)),
        )
        .snapshot()
        .entries
        == ()
    )


def test_benchmark_without_reports_is_explicitly_incomplete(tmp_path: Path) -> None:
    output = tmp_path / "benchmark.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.INCOMPLETE
    assert "incomplete" in result.stdout
    assert output.is_file()


def test_benchmark_loads_typed_mutation_scorecard(tmp_path: Path) -> None:
    scorecard = score_mutation_outcomes(
        property_corpus_hash="a" * 64,
        expected_property_ids=["prop-" + ("b" * 24)],
        property_repositories={
            "prop-" + ("b" * 24): "maximum_assurance_protocol",
        },
        outcomes=[
            MutationPropertyOutcome(
                mutation_id="mut-cli-fixture",
                mutation_kind=MutationKind.BOUNDARY_CHECK_WEAKENING,
                property_id="prop-" + ("b" * 24),
                outcome=MutationTestOutcome.KILLED,
                evidence_sha256="c" * 64,
            )
        ],
        minimum_property_kill_score=1,
    )
    scorecard_path = tmp_path / "mutation-scorecard.json"
    scorecard_path.write_text(scorecard.model_dump_json(), encoding="utf-8")
    output = tmp_path / "benchmark.json"

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--mutation-scorecard",
            str(scorecard_path),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["mutation_scorecard"]["gate_passed"] is True


def test_benchmark_refuses_symlinked_mutation_scorecard(tmp_path: Path) -> None:
    target = tmp_path / "scorecard.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "linked-scorecard.json"
    try:
        link.symlink_to(target)
    except OSError:
        return

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--mutation-scorecard",
            str(link),
            "--output-json",
            str(tmp_path / "benchmark.json"),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "regular non-symlink" in result.stdout


def test_benchmark_serializes_demonstrated_human_comparison_claim(
    tmp_path: Path,
) -> None:
    corpus_sha256 = "186534e1d0d263920d42041e39b05fd6fb4acc57f5e7e4c9c1321a403756845b"
    metric = ComparativeMetricEvidence(
        mmaudit=ProportionSample(successes=95, trials=100),
        human=ProportionSample(successes=70, trials=100),
    )
    evidence = seal_human_comparison_evidence(
        HumanComparisonEvidencePayload(
            comparison_id="cli-synthetic-comparison",
            corpus_sha256=corpus_sha256,
            benchmark_report_sha256="b" * 64,
            reports_generated_blind=True,
            ground_truth_withheld_from_humans=True,
            ground_truth_withheld_from_mmaudit=True,
            blinding_protocol_sha256="c" * 64,
            same_corpus=True,
            same_scope=True,
            same_time_budget=True,
            same_evidence_access=True,
            review_protocol_sha256="d" * 64,
            human_reviewer_count=3,
            adjudicators_independent=True,
            adjudicator_count=2,
            adjudication_sha256="e" * 64,
            precision=metric,
            recall=metric,
        )
    )
    evidence_path = tmp_path / "human-comparison.json"
    evidence_path.write_text(evidence.model_dump_json(), encoding="utf-8")
    output = tmp_path / "benchmark.json"

    result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--human-comparison",
            str(evidence_path),
            "--output-json",
            str(output),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.INCOMPLETE
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["superiority_claim"]["status"] == SuperiorityClaimStatus.DEMONSTRATED
    assert all(item["passed"] for item in payload["superiority_claim"]["preconditions"])
    assert payload["superiority_claim"]["benchmark_report_sha256"] == "b" * 64

    wrong_payload = evidence.model_dump(mode="json", exclude={"evidence_sha256"})
    wrong_payload["corpus_sha256"] = "f" * 64
    wrong_evidence = seal_human_comparison_evidence(
        HumanComparisonEvidencePayload.model_validate(wrong_payload)
    )
    wrong_path = tmp_path / "wrong-corpus-comparison.json"
    wrong_path.write_text(wrong_evidence.model_dump_json(), encoding="utf-8")
    wrong_output = tmp_path / "wrong-benchmark.json"
    wrong_result = runner.invoke(
        app,
        [
            "benchmark",
            "--corpus",
            str(ROOT / "benchmarks" / "corpus" / "manifest.json"),
            "--ground-truth-root",
            str(ROOT),
            "--human-comparison",
            str(wrong_path),
            "--output-json",
            str(wrong_output),
            "--no-color",
        ],
    )
    assert wrong_result.exit_code == ExitCode.CONFIGURATION
    assert "evaluated benchmark corpus" in wrong_result.stdout
    assert not wrong_output.exists()


def _write_certificate_components(
    tmp_path: Path,
    *,
    status: BenchmarkStatus = BenchmarkStatus.PASSED,
) -> tuple[Path, Path]:
    component_root = tmp_path / "components"
    (component_root / "prompts").mkdir(parents=True)
    component_contents = {
        "mmaudit.toml": 'profile = "standard"\n',
        "prompts/discovery.md": "Synthetic defensive prompt.\n",
        "models.json": '{"lineage":"synthetic-a"}\n',
        "tools.json": '{"scanner":"synthetic","version":"1"}\n',
        "compilers.json": '{"compiler":"solc","version":"0.8.30"}\n',
        "corpus.json": '{"cases":["unsafe","safe"]}\n',
        "ground-truth.json": '{"case_hashes":["aaaaaaaa"]}\n',
    }
    for relative_path, contents in component_contents.items():
        (component_root / relative_path).write_text(contents, encoding="utf-8")
    passed = status is BenchmarkStatus.PASSED
    repository_metrics = BenchmarkRepositoryMetrics(
        repository_id="synthetic_repository",
        report_loaded=True,
        vulnerable_cases=1,
        vulnerable_cases_detected=int(passed),
        recall=float(passed),
        critical_cases=1,
        critical_cases_detected=int(passed),
        critical_recall=float(passed),
        safe_cases=1,
        safe_false_confirmations=0,
        safe_false_confirmation_rate=0,
        location_cases=1,
        exact_locations=int(passed),
        location_accuracy=float(passed),
        vulnerable_cases_reproduced=int(passed),
        reproduction_success_rate=float(passed),
        cost_usd=0,
        total_tokens=0,
    )
    report = BenchmarkReport(
        corpus_name="Synthetic CLI benchmark",
        corpus_sha256="a" * 64,
        blinding=BenchmarkBlindingProtocol(),
        profile=AuditProfile.STANDARD,
        status=status,
        reports_expected=1,
        reports_loaded=1,
        vulnerable_cases=1,
        vulnerable_cases_detected=int(passed),
        vulnerable_cases_reproduced=int(passed),
        critical_cases=1,
        critical_cases_detected=int(passed),
        safe_cases=1,
        safe_high_critical_confirmations=0,
        evidence_cap_bypasses=0,
        reports_missing_coverage=0,
        model_only_findings_kept_below_confirmed=0,
        recall=float(passed),
        recall_by_severity={"critical": float(passed)},
        critical_recall=float(passed),
        precision=float(passed),
        false_positive_rate=0,
        safe_false_confirmation_rate=0,
        reproduction_success_rate=float(passed),
        location_cases=1,
        exact_locations=int(passed),
        location_accuracy=float(passed),
        total_cost_usd=0,
        total_tokens=0,
        repository_metrics=[repository_metrics],
        case_results=[],
        gates=[
            BenchmarkGate(
                name="synthetic_gate",
                passed=passed,
                detail="synthetic passed gate" if passed else "synthetic failed gate",
            )
        ],
        limitations=[],
    )
    (component_root / "benchmark-results.json").write_text(
        report.model_dump_json(),
        encoding="utf-8",
    )
    inputs = {
        "configuration": ["mmaudit.toml"],
        "prompts": ["prompts/discovery.md"],
        "models": ["models.json"],
        "tools": ["tools.json"],
        "compilers": ["compilers.json"],
        "corpus": ["corpus.json"],
        "ground_truth": ["ground-truth.json"],
        "benchmark_report": "benchmark-results.json",
    }
    inputs_path = tmp_path / "certificate-inputs.json"
    inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
    return component_root, inputs_path


def _certify(
    tmp_path: Path,
    component_root: Path,
    inputs_path: Path,
) -> tuple[Path, object]:
    certificate_path = tmp_path / "benchmark-certificate.json"
    result = runner.invoke(
        app,
        [
            "benchmark",
            "certify",
            "--component-root",
            str(component_root),
            "--inputs",
            str(inputs_path),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(certificate_path),
            "--no-color",
        ],
    )
    return certificate_path, result


def test_benchmark_certificate_cli_success_and_current_verification(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    verification_path = tmp_path / "verification.json"

    verify_result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(verification_path),
            "--no-color",
        ],
    )

    assert certify_result.exit_code == ExitCode.SUCCESS
    assert load_benchmark_certificate(certificate_path).benchmark_name == (
        "Synthetic CLI benchmark"
    )
    assert verify_result.exit_code == ExitCode.SUCCESS
    assert json.loads(verification_path.read_text(encoding="utf-8"))["status"] == ("current")


def test_verify_certificate_cli_rejects_stale_component_binding(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "mmaudit.toml").write_text(
        'profile = "changed"\n',
        encoding="utf-8",
    )
    verification_path = tmp_path / "stale-verification.json"

    result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--output",
            str(verification_path),
            "--no-color",
        ],
    )

    payload = json.loads(verification_path.read_text(encoding="utf-8"))
    assert result.exit_code == ExitCode.INCOMPLETE
    assert payload["status"] == "stale"
    assert payload["mismatches"][0]["identifier"] == "configuration/00000"


def test_verify_certificate_cli_rejects_tampered_certificate(
    tmp_path: Path,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    tampered = json.loads(certificate_path.read_text(encoding="utf-8"))
    tampered["benchmark_name"] = "Tampered"
    certificate_path.write_text(json.dumps(tampered), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(certificate_path),
            "--component-root",
            str(component_root),
            "--repository-commit",
            CERTIFICATE_COMMIT,
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "self-hash" in result.stdout


def test_benchmark_certify_cli_requires_passed_gates(tmp_path: Path) -> None:
    component_root, inputs_path = _write_certificate_components(
        tmp_path,
        status=BenchmarkStatus.FAILED,
    )
    certificate_path, result = _certify(tmp_path, component_root, inputs_path)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires a passed" in result.stdout
    assert "report and passed gates" in result.stdout
    assert not certificate_path.exists()


def _run_gate_arguments(
    *,
    tmp_path: Path,
    repository: Path,
    certificate_path: Path | None = None,
    component_root: Path | None = None,
) -> list[str]:
    arguments = [
        "run",
        "--config",
        str(ROOT / "mmaudit.example.toml"),
        "--repo",
        str(repository),
        "--output",
        str(tmp_path / "audit-output"),
        "--scanner-only",
        "--skip-codeql",
        "--benchmark-gate",
        "--no-color",
    ]
    if certificate_path is not None:
        arguments.extend(["--benchmark-certificate", str(certificate_path)])
    if component_root is not None:
        arguments.extend(["--benchmark-component-root", str(component_root)])
    if certificate_path is not None and component_root is not None:
        arguments.extend(["--benchmark-repository-commit", CERTIFICATE_COMMIT])
    return arguments


def _synthetic_run_repository(tmp_path: Path) -> Path:
    repository = tmp_path / "audit-repository"
    repository.mkdir()
    (repository / "app.py").write_text("value = 1\n", encoding="utf-8")
    return repository


def test_run_benchmark_gate_passes_typed_verification_to_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            captured["constructed"] = True

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.SUCCESS
    verification = captured["benchmark_verification"]
    assert verification.status is CertificateVerificationStatus.CURRENT


def test_run_benchmark_gate_rejects_absent_certificate_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(tmp_path=tmp_path, repository=repository),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark gate requires" in result.stdout
    assert not constructed


def test_run_benchmark_gate_allows_wholly_missing_inputs_with_explicit_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = [
        *_run_gate_arguments(tmp_path=tmp_path, repository=repository),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    assert captured["benchmark_verification"] is None
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_preserves_configured_downgrade_when_flag_is_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    config_path = tmp_path / "maximum-downgrade.toml"
    config_contents = (ROOT / "mmaudit.example.toml").read_text(encoding="utf-8")
    config_contents = config_contents.replace(
        'profile = "standard"',
        'profile = "maximum-assurance"',
        1,
    ).replace(
        "allow_downgrade = false",
        "allow_downgrade = true",
        1,
    )
    config_path.write_text(config_contents, encoding="utf-8")
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, config, *args, **kwargs) -> None:
            del args, kwargs
            captured["config"] = config

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = _run_gate_arguments(tmp_path=tmp_path, repository=repository)
    arguments[arguments.index("--config") + 1] = str(config_path)

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    config = captured["config"]
    assert config.maximum_assurance.allow_downgrade is True
    assert captured["benchmark_verification"] is None
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_preserves_configured_maximum_requirement_when_flag_is_absent(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    config_path = tmp_path / "required-maximum.toml"
    config_contents = (ROOT / "mmaudit.example.toml").read_text(encoding="utf-8")
    config_path.write_text(
        config_contents.replace("require = false", "require = true", 1),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, config, *args, **kwargs) -> None:
            del args, kwargs
            captured["config"] = config

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)

    result = runner.invoke(
        app,
        [
            "run",
            "--config",
            str(config_path),
            "--repo",
            str(repository),
            "--output",
            str(tmp_path / "audit-output"),
            "--scanner-only",
            "--skip-codeql",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.SUCCESS
    config = captured["config"]
    assert config.maximum_assurance.require is True
    assert captured["require_maximum_assurance"] is None
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_rejects_partial_inputs_even_with_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)
    arguments = [
        *_run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=tmp_path / "partial-certificate.json",
        ),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "benchmark gate requires" in result.stdout
    assert not constructed


def test_run_benchmark_gate_rejects_stale_binding_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "tools.json").write_text(
        '{"scanner":"changed"}\n',
        encoding="utf-8",
    )
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "certificate is stale" in result.stdout
    assert not constructed


def test_run_benchmark_gate_allows_stale_binding_with_explicit_downgrade(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    (component_root / "tools.json").write_text(
        '{"scanner":"changed"}\n',
        encoding="utf-8",
    )
    repository = _synthetic_run_repository(tmp_path)
    captured: dict[str, object] = {}

    class SyntheticPipelineResult:
        run_dir = tmp_path / "synthetic-run"

        def exit_for_findings(self, fail_on) -> ExitCode:
            del fail_on
            return ExitCode.SUCCESS

    class SyntheticPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs

        async def run(self, **kwargs):
            captured.update(kwargs)
            return SyntheticPipelineResult()

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", SyntheticPipeline)
    arguments = [
        *_run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
        "--profile",
        "maximum-assurance",
        "--allow-maximum-assurance-downgrade",
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == ExitCode.SUCCESS
    verification = captured["benchmark_verification"]
    assert verification.status is CertificateVerificationStatus.STALE
    assert captured["allow_maximum_assurance_downgrade"] is None


def test_run_benchmark_gate_rejects_current_failed_corpus_before_pipeline(
    tmp_path: Path,
    monkeypatch,
) -> None:
    component_root, inputs_path = _write_certificate_components(tmp_path)
    certificate_path, certify_result = _certify(
        tmp_path,
        component_root,
        inputs_path,
    )
    assert certify_result.exit_code == ExitCode.SUCCESS
    report_path = component_root / "benchmark-results.json"
    failed_report = json.loads(report_path.read_text(encoding="utf-8"))
    failed_report["status"] = "failed"
    failed_report["gates"][0]["passed"] = False
    report_path.write_text(json.dumps(failed_report), encoding="utf-8")
    original = load_benchmark_certificate(certificate_path)
    observed_bindings, observed_report = observe_file_backed_certificate(
        original,
        component_root=component_root,
    )
    manually_resealed = seal_benchmark_certificate(
        BenchmarkCertificatePayload(
            certificate_id=original.certificate_id,
            benchmark_name=original.benchmark_name,
            profile=original.profile,
            repository_git_commit=original.repository_git_commit,
            bindings=observed_bindings,
            benchmark_report=observed_report,
        )
    )
    write_benchmark_certificate(certificate_path, manually_resealed)
    repository = _synthetic_run_repository(tmp_path)
    constructed = False

    class ForbiddenPipeline:
        def __init__(self, *args, **kwargs) -> None:
            del args, kwargs
            nonlocal constructed
            constructed = True

    monkeypatch.setattr("mmaudit.cli.AuditPipeline", ForbiddenPipeline)

    result = runner.invoke(
        app,
        _run_gate_arguments(
            tmp_path=tmp_path,
            repository=repository,
            certificate_path=certificate_path,
            component_root=component_root,
        ),
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "requires a passed report" in result.stdout
    assert "passed gates" in result.stdout
    assert not constructed


def test_snapshot_import_requires_explicit_opt_in_before_plan_or_network_access(
    tmp_path: Path,
) -> None:
    result = runner.invoke(
        app,
        [
            "snapshot",
            "import",
            "--plan",
            str(tmp_path / "missing.json"),
            "--rpc-url",
            "http://127.0.0.1:8545",
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "--allow-read-only-import" in result.stdout


def test_init_does_not_overwrite_without_force(tmp_path: Path) -> None:
    first = runner.invoke(app, ["init", "--directory", str(tmp_path)])
    assert first.exit_code == 0
    config = tmp_path / "mmaudit.toml"
    config.write_text("sentinel", encoding="utf-8")
    second = runner.invoke(app, ["init", "--directory", str(tmp_path)])
    assert second.exit_code == ExitCode.CONFIGURATION
    assert config.read_text(encoding="utf-8") == "sentinel"
    forced = runner.invoke(app, ["init", "--directory", str(tmp_path), "--force"])
    assert forced.exit_code == 0
    assert "version = 1" in config.read_text(encoding="utf-8")


def test_init_refuses_symlink_even_with_force(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    try:
        (target / "mmaudit.toml").symlink_to(outside)
    except OSError:
        return
    result = runner.invoke(
        app,
        ["init", "--directory", str(target), "--force"],
    )
    assert result.exit_code == ExitCode.CONFIGURATION
    assert outside.read_text(encoding="utf-8") == "sentinel"


def test_init_force_does_not_write_through_hardlink(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_text("sentinel", encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    try:
        (target / "mmaudit.toml").hardlink_to(outside)
    except OSError:
        return
    result = runner.invoke(
        app,
        ["init", "--directory", str(target), "--force"],
    )
    assert result.exit_code == 0
    assert outside.read_text(encoding="utf-8") == "sentinel"
    assert "version = 1" in (target / "mmaudit.toml").read_text(encoding="utf-8")


def test_doctor_without_credentials_fails_safely(tmp_path: Path, monkeypatch) -> None:
    canary = "sk-or-v1-ambient-value-must-be-ignored"
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--repo",
            str(tmp_path),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "Operator secret file" in result.stdout
    assert "rejected" in result.stdout
    assert "missing" in result.stdout
    assert "invalid" in result.stdout
    assert canary not in result.stdout
    assert "replace-with-an-openrouter-key" not in result.stdout


@pytest.mark.parametrize(("authenticated", "status"), [(True, "valid"), (False, "invalid")])
def test_doctor_reports_only_secret_and_authentication_state(
    tmp_path: Path,
    monkeypatch,
    authenticated: bool,
    status: str,
) -> None:
    canary = "sk-or-v1-synthetic-doctor-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    observed: list[str] = []

    def validate(_config, api_key: str) -> bool:
        observed.append(api_key)
        return authenticated

    monkeypatch.setattr("mmaudit.cli._openrouter_authentication_valid", validate)
    result = runner.invoke(
        app,
        [
            "doctor",
            "--config",
            str(config),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(tmp_path),
            "--output",
            str(tmp_path / "output"),
            "--no-color",
        ],
    )

    assert observed == [canary]
    assert "Operator secret file" in result.stdout
    assert "accepted" in result.stdout
    assert "present" in result.stdout
    assert status in result.stdout
    assert canary not in result.stdout
    assert str(secret_file) not in result.stdout


def test_scanner_only_cli_never_requires_api_key(
    tmp_path: Path, vulnerable_repo: Path, monkeypatch
) -> None:
    canary = "sk-or-v1-scanner-only-artifact-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    monkeypatch.setenv("OPENROUTER_API_KEY", canary)
    monkeypatch.setenv("MMAUDIT_SECRETS_ENV_FILE", str(secret_file))
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    output = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            "--config",
            str(config),
            "--secrets-env-file",
            str(secret_file),
            "--repo",
            str(vulnerable_repo),
            "--output",
            str(output),
            "--skip-codeql",
            "--allow-fork",
            "--no-color",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert (output / "latest" / "scanner-results.json").is_file()
    assert (output / "latest" / "audit-results.sarif").is_file()
    serialized = result.stdout + result.stderr
    serialized += "".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in output.rglob("*")
        if path.is_file()
    )
    assert canary not in serialized


def test_models_check_requires_operator_secret_file(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OPENROUTER_API_KEY", "ambient-value-must-be-ignored")
    monkeypatch.delenv("MMAUDIT_SECRETS_ENV_FILE", raising=False)
    config = tmp_path / "mmaudit.toml"
    shutil.copy2(ROOT / "mmaudit.example.toml", config)
    result = runner.invoke(app, ["models", "check", "--config", str(config)])
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "operator secret file is not selected" in result.stdout


def test_models_check_rejects_empty_provider_endpoint_policy_before_network(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    secret_file = tmp_path / "operator.env"
    secret_file.write_text("OPENROUTER_API_KEY=synthetic-check-key\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory(
        models={
            "provider_policy": {
                "only": [],
                "order": [],
                "allow_fallbacks": False,
            }
        }
    )
    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)

    class UnexpectedClient:
        def __init__(self, **_kwargs: object) -> None:
            raise AssertionError("models check reached the network client")

    monkeypatch.setattr("mmaudit.cli.OpenRouterClient", UnexpectedClient)
    result = runner.invoke(
        app,
        [
            "models",
            "check",
            "--config",
            str(tmp_path / "mmaudit.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--no-color",
        ],
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert "explicit provider endpoint" in result.stdout
    assert "allowlist" in result.stdout


def test_models_check_rejects_unavailable_exact_provider_endpoint(
    tmp_path: Path,
    monkeypatch,
    config_factory,
) -> None:
    canary = "sk-or-v1-synthetic-model-check-canary"
    secret_file = tmp_path / "operator.env"
    secret_file.write_text(f"OPENROUTER_API_KEY={canary}\n", encoding="utf-8")
    secret_file.chmod(0o600)
    config = config_factory()
    model_ids = tuple(sorted(set(configured_model_ids(config, include_fallbacks=True))))
    observed_models: list[str] = []
    observed_keys: list[str] = []
    closed = False

    def endpoint_record(model_id: str, endpoint: str) -> dict[str, object]:
        return {
            "model_id": model_id,
            "tag": endpoint,
            "provider_name": "Synthetic Provider",
            "status": 0,
            "context_length": 200_000,
            "max_prompt_tokens": 180_000,
            "max_completion_tokens": 20_000,
            "supported_parameters": ["max_tokens", "response_format", "temperature"],
            "pricing": {
                "prompt": "0.000001",
                "completion": "0.00001",
                "request": "0",
            },
        }

    class EndpointMismatchClient:
        def __init__(self, *, api_key: str, **_kwargs: object) -> None:
            observed_keys.append(api_key)

        async def list_models(self) -> list[dict[str, object]]:
            return [
                {
                    "id": model_id,
                    "supported_parameters": ["response_format"],
                }
                for model_id in model_ids
            ]

        async def list_zdr_endpoints(self) -> dict[str, object]:
            return {
                "data": [endpoint_record(model_id, "synthetic-provider") for model_id in model_ids]
            }

        async def get_model_endpoint_metadata(self, model_id: str) -> dict[str, object]:
            observed_models.append(model_id)
            return {
                "data": {
                    "id": model_id,
                    "endpoints": [endpoint_record(model_id, "unapproved-provider")],
                }
            }

        async def close(self) -> None:
            nonlocal closed
            closed = True

    monkeypatch.setattr("mmaudit.cli.load_config", lambda _path: config)
    monkeypatch.setattr("mmaudit.cli.OpenRouterClient", EndpointMismatchClient)

    result = runner.invoke(
        app,
        [
            "models",
            "check",
            "--config",
            str(tmp_path / "synthetic.toml"),
            "--secrets-env-file",
            str(secret_file),
            "--refresh",
            "--no-color",
        ],
        env={"COLUMNS": "500"},
    )

    assert result.exit_code == ExitCode.CONFIGURATION
    assert observed_keys == [canary]
    assert observed_models == list(model_ids)
    assert closed is True
    assert "exact provider endpoint validation failed" in result.stdout
    assert "configured endpoint tag or slug is unavailable: synthetic-provider" in result.stdout
    assert "Validated" not in result.stdout
    assert canary not in result.stdout
    assert str(secret_file) not in result.stdout
