"""Explicitly non-qualifying previews and opt-in pinned synthetic fixture reviews."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Any, cast

import typer
from pydantic import TypeAdapter

from mmaudit.benchmark.development import (
    MAX_DEVELOPMENT_TRUTH_BYTES,
    bind_development_benchmark,
    read_development_benchmark_truth,
)
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import (
    DEVELOPMENT_AUDIT_SOURCE_PINS,
    MAX_DEVELOPMENT_AUDIT_SOURCE_BYTES,
    DevelopmentCorpusId,
    prepare_development_audit,
)
from mmaudit.models.development_costs import (
    MAX_DEVELOPMENT_REQUEST_BYTES,
    DevelopmentCostError,
    DevelopmentCostPolicy,
    estimate_development_request,
)
from mmaudit.models.development_review import (
    DEVELOPMENT_FIXTURE_PINS,
    MAX_DEVELOPMENT_FIXTURE_BYTES,
    DevelopmentReviewMetadata,
    prepare_development_review,
)
from mmaudit.models.development_transport import review_development_fixture
from mmaudit.models.endpoint_snapshots import OpenRouterEndpointSnapshotEvidence
from mmaudit.operator_secrets import load_operator_secrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_audit import run_development_audit
from mmaudit.orchestration.development_comparison import compare_development_score_files
from mmaudit.release_io import read_file_evidence, read_json_evidence

development_app = typer.Typer(help="Explicitly non-qualifying development utilities.")


@development_app.command("compare-scores")
def compare_development_scores_command(
    score_files: Annotated[list[Path], typer.Option("--score-file")],
    output_file: Annotated[Path, typer.Option("--output-file")],
) -> None:
    """Compare two through eight same-corpus scores locally, without provider or ledger access."""

    try:
        result = compare_development_score_files(
            score_files=tuple(score_files), output_file=output_file
        )
    except Exception:
        typer.echo(
            "Development comparison refused: invalid, repeated or incompatible scores, "
            "unsafe input/output paths or changed file custody. No provider call was selected.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(
        "Development comparison written: "
        + result.comparison_sha256
        + "; "
        + result.union.quality_scope
        + ". No ensemble execution or qualification is implied."
    )
    if result.union.quality_scope != "COMPLETE_OBSERVATIONS":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("preview-cost")
def preview_development_cost(
    endpoint_snapshot: Annotated[Path, typer.Option("--endpoint-snapshot")],
    request_file: Annotated[Path, typer.Option("--request-file")],
    budget_usd: Annotated[str, typer.Option("--budget-usd")],
    per_attempt_usd: Annotated[str, typer.Option("--per-attempt-usd")],
    request_id: Annotated[str, typer.Option("--request-id")] = "development-preview",
    maximum_attempts: Annotated[int, typer.Option("--maximum-attempts", min=1, max=32)] = 1,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
) -> None:
    """Estimate supplied local JSON only; never select a model or send a request."""

    if not accept_estimate_risk:
        typer.echo(
            "Development estimates require --accept-estimate-risk; overspend is possible.", err=True
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "maximum_attempts": maximum_attempts,
            }
        )
        if not endpoint_snapshot.is_absolute() or not request_file.is_absolute():
            raise DevelopmentCostError("development input paths must be absolute")
        snapshot_observation = read_json_evidence(
            evidence_root=endpoint_snapshot.parent,
            relative_path=endpoint_snapshot.name,
            max_bytes=2_000_000,
        )
        request_observation = read_json_evidence(
            evidence_root=request_file.parent,
            relative_path=request_file.name,
            max_bytes=MAX_DEVELOPMENT_REQUEST_BYTES,
        )
        if type(request_observation.value) is not dict:
            raise DevelopmentCostError("development request file must contain one JSON object")
        snapshot = OpenRouterEndpointSnapshotEvidence.model_validate_json(
            snapshot_observation.content
        )
        estimate = estimate_development_request(
            policy=policy,
            endpoint_snapshot=snapshot,
            request_id=request_id,
            request_body=cast(dict[str, Any], request_observation.value),
        )
    except DevelopmentCostError as exc:
        typer.echo(f"Development cost preview rejected: {exc}", err=True)
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    except (OSError, ValueError) as exc:
        typer.echo(
            "Development cost preview rejected: invalid policy or local JSON evidence.", err=True
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from exc
    typer.echo(estimate.model_dump_json(indent=2))
    if not estimate.within_estimated_budget:
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("review-fixture")
def review_development_fixture_command(
    endpoint_snapshot: Annotated[
        Path,
        typer.Option(
            "--endpoint-snapshot",
            help="Validated endpoint snapshot or complete discovery candidate JSON; local input only.",
        ),
    ],
    fixture_file: Annotated[Path, typer.Option("--fixture-file")],
    cost_ledger: Annotated[Path, typer.Option("--cost-ledger")],
    secrets_env_file: Annotated[Path, typer.Option("--secrets-env-file")],
    request_id: Annotated[str, typer.Option("--request-id")],
    budget_usd: Annotated[str, typer.Option("--budget-usd")],
    per_attempt_usd: Annotated[str, typer.Option("--per-attempt-usd")],
    maximum_attempts: Annotated[int, typer.Option("--maximum-attempts", min=1, max=32)] = 1,
    attempt: Annotated[int, typer.Option("--attempt", min=1, max=32)] = 1,
    maximum_completion_tokens: Annotated[
        int, typer.Option("--maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
) -> None:
    """Paid-capable, explicit one-attempt review of a pinned non-deployable fixture.

    No arbitrary source, automatic retry, candidate adoption, ledger initialization,
    execution of model output, or qualifying evidence. The supplied ledger is the
    cumulative account, not a newly reset per-command budget.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development fixture review requires --accept-estimate-risk and --allow-code-egress; "
            "a provider request may spend more than the estimate.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "maximum_attempts": maximum_attempts,
            }
        )
        if attempt > maximum_attempts:
            raise DevelopmentCostError("development attempt exceeds its policy")
        if any(
            not path.is_absolute()
            for path in (endpoint_snapshot, fixture_file, cost_ledger, secrets_env_file)
        ):
            raise DevelopmentCostError("development input and control paths must be absolute")
        if len({endpoint_snapshot, fixture_file, cost_ledger, secrets_env_file}) != 4:
            raise DevelopmentCostError("development input and control paths must be distinct")
        if fixture_file.name not in {name for name, _digest in DEVELOPMENT_FIXTURE_PINS}:
            raise DevelopmentCostError("development fixture filename is not allowlisted")
        snapshot: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
            read_json_evidence(
                evidence_root=endpoint_snapshot.parent,
                relative_path=endpoint_snapshot.name,
                max_bytes=2_000_000,
            ).content,
            strict=True,
        )
        source = read_file_evidence(
            evidence_root=fixture_file.parent,
            relative_path=fixture_file.name,
            max_bytes=MAX_DEVELOPMENT_FIXTURE_BYTES,
        ).content
        prepared = prepare_development_review(
            policy=policy,
            endpoint_snapshot=snapshot,
            source_filename=fixture_file.name,
            source_content=source,
            request_id=request_id,
            maximum_completion_tokens=maximum_completion_tokens,
        )
        if not prepared.estimate.within_estimated_budget:
            raise DevelopmentCostError("development estimate exceeds its targets")
        # Never initialize, reset, repair, or choose a ledger from ambient configuration.
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                review_development_fixture(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    allow_code_egress=allow_code_egress,
                    attempt=attempt,
                )
            )
    except Exception:
        # The CLI is a redaction boundary, including unexpected HTTP cleanup errors.
        typer.echo(
            "Development fixture review refused: invalid input, consent, route, credentials, "
            "or cumulative accounting. No qualification or audit completion is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status != "OBSERVED":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("audit-corpus")
def audit_development_corpus_command(
    endpoint_snapshot: Annotated[Path, typer.Option("--endpoint-snapshot")],
    corpus_root: Annotated[Path, typer.Option("--corpus-root")],
    corpus_id: Annotated[str, typer.Option("--corpus-id")],
    cost_ledger: Annotated[Path, typer.Option("--cost-ledger")],
    secrets_env_file: Annotated[Path, typer.Option("--secrets-env-file")],
    output_dir: Annotated[Path, typer.Option("--output-dir")],
    run_id: Annotated[str, typer.Option("--run-id")],
    budget_usd: Annotated[str, typer.Option("--budget-usd")],
    per_attempt_usd: Annotated[str, typer.Option("--per-attempt-usd")],
    maximum_completion_tokens: Annotated[
        int, typer.Option("--maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    maximum_run_seconds: Annotated[
        int, typer.Option("--maximum-run-seconds", min=1, max=1800)
    ] = 600,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    truth_manifest: Annotated[
        Path | None,
        typer.Option(
            "--truth-manifest",
            help="Exact frozen development-control JSON; selects v2 and writes a non-qualifying score.",
        ),
    ] = None,
) -> None:
    """Opt-in, non-qualifying three-file audit of one frozen synthetic corpus.

    Sends three sequential single-attempt requests with exact shared context. Output
    must be a new directory. No arbitrary sources, automatic retries/resume, ledger
    creation/reset, model-output execution, qualification or audit-completion credit.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development corpus audit requires --accept-estimate-risk and --allow-code-egress; "
            "estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        inputs: tuple[Path, ...] = (endpoint_snapshot, corpus_root, cost_ledger, secrets_env_file)
        if truth_manifest is not None:
            inputs += (truth_manifest,)
        paths = (*inputs, output_dir)
        if any(not path.is_absolute() or ".." in path.parts for path in paths) or len(
            set(paths)
        ) != len(paths):
            raise DevelopmentCostError(
                "development audit paths must be absolute, distinct and normalized"
            )
        if output_dir.is_relative_to(corpus_root) or any(
            path.is_relative_to(output_dir) for path in paths[:-1]
        ):
            raise DevelopmentCostError("development audit output overlaps its input/control scope")
        if corpus_id not in DEVELOPMENT_AUDIT_SOURCE_PINS:
            raise DevelopmentCostError("development audit corpus ID is not allowlisted")
        truth = (
            read_development_benchmark_truth(
                read_file_evidence(
                    evidence_root=truth_manifest.parent,
                    relative_path=truth_manifest.name,
                    max_bytes=MAX_DEVELOPMENT_TRUTH_BYTES,
                ).content
            )
            if truth_manifest is not None
            else None
        )
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "maximum_attempts": 1,
            }
        )
        metadata: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
            read_json_evidence(
                evidence_root=endpoint_snapshot.parent,
                relative_path=endpoint_snapshot.name,
                max_bytes=2_000_000,
            ).content,
            strict=True,
        )
        sources = tuple(
            (
                name,
                read_file_evidence(
                    evidence_root=corpus_root,
                    relative_path=name,
                    max_bytes=MAX_DEVELOPMENT_AUDIT_SOURCE_BYTES,
                ).content,
            )
            for name, _digest, _size, _lines in DEVELOPMENT_AUDIT_SOURCE_PINS[corpus_id]
        )
        prepared = prepare_development_audit(
            policy=policy,
            endpoint_snapshot=metadata,
            corpus_id=cast(DevelopmentCorpusId, corpus_id),
            source_files=sources,
            run_id=run_id,
            maximum_completion_tokens=maximum_completion_tokens,
            schema_version="2.0" if truth is not None else "1.0",
        )
        if truth is not None:
            bind_development_benchmark(plan=prepared.plan, truth=truth)
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_audit(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    output_dir=output_dir,
                    allow_code_egress=allow_code_egress,
                    maximum_run_seconds=float(maximum_run_seconds),
                    benchmark_truth=truth,
                )
            )
    except Exception:
        typer.echo(
            "Development corpus audit refused: invalid scope, consent, route, controls, "
            "cumulative accounting or output custody. Inspect retained local plan/shard "
            "records and ledger before any further attempt; no audit completion is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status != "OBSERVED_ALL_SHARDS":
        raise typer.Exit(ExitCode.INCOMPLETE)
