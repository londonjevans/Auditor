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
from mmaudit.benchmark.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
    bind_development_corpus_benchmark,
)
from mmaudit.constants import ExitCode
from mmaudit.models.development_audit import (
    DEVELOPMENT_AUDIT_SOURCE_PINS,
    MAX_DEVELOPMENT_AUDIT_SOURCE_BYTES,
    DevelopmentAuditObservation,
    DevelopmentCorpusId,
    prepare_development_audit,
)
from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    prepare_development_corpus,
)
from mmaudit.models.development_corpus_ensemble import prepare_development_corpus_ensemble
from mmaudit.models.development_corpus_judgment import prepare_development_corpus_judgment
from mmaudit.models.development_costs import (
    MAX_DEVELOPMENT_REQUEST_BYTES,
    DevelopmentCostError,
    DevelopmentCostPolicy,
    estimate_development_request,
)
from mmaudit.models.development_ensemble import prepare_development_ensemble
from mmaudit.models.development_judgment import (
    MAX_DEVELOPMENT_JUDGMENT_INPUT_BYTES,
    prepare_development_judgment,
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
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_ensemble import run_development_corpus_ensemble
from mmaudit.orchestration.development_corpus_judgment import run_development_corpus_judgment
from mmaudit.orchestration.development_ensemble import run_development_ensemble
from mmaudit.orchestration.development_judgment import run_development_judgment
from mmaudit.release_io import (
    read_file_evidence,
    read_json_evidence,
    revalidate_evidence_file_binding,
)
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)

development_app = typer.Typer(help="Explicitly non-qualifying development utilities.")


@development_app.command("judge-manifest")
def judge_development_manifest_command(
    candidate_audit_file: Annotated[Path, typer.Option("--candidate-audit-file")],
    source_material_file: Annotated[Path, typer.Option("--source-material-file")],
    endpoint_snapshot: Annotated[Path, typer.Option("--endpoint-snapshot")],
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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends the run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[bool, typer.Option("--carry-uncertain-estimates")] = False,
) -> None:
    """Review observed manifest claims against the retained sources.json snapshot.

    Incomplete candidates stay incomplete even when every available claim receives an opinion.
    No source discovery, truth scoring, automatic retry or lineage qualification is performed.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Manifest judgment requires --accept-estimate-risk and --allow-code-egress; "
            "estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        inputs = (
            candidate_audit_file,
            source_material_file,
            endpoint_snapshot,
            cost_ledger,
            secrets_env_file,
        )
        paths = (*inputs, output_dir)
        if any(not p.is_absolute() or ".." in p.parts for p in paths) or len(set(paths)) != len(
            paths
        ):
            raise DevelopmentCostError(
                "manifest judgment paths must be absolute, distinct and normalized"
            )
        if any(p.is_relative_to(output_dir) for p in inputs):
            raise DevelopmentCostError("manifest judgment output overlaps an input or control")
        candidate_input = read_json_evidence(
            evidence_root=candidate_audit_file.parent,
            relative_path=candidate_audit_file.name,
            max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
        )
        candidate = DevelopmentCorpusObservation.model_validate_json(
            candidate_input.content, strict=True
        )
        material_input = read_json_evidence(
            evidence_root=source_material_file.parent,
            relative_path=source_material_file.name,
            max_bytes=2_000_000,
        )
        material = DevelopmentCorpusMaterial.model_validate_json(
            material_input.content, strict=True
        )
        if material.manifest != candidate.plan.manifest:
            raise DevelopmentCostError(
                "manifest judgment source snapshot differs from its candidate"
            )
        metadata_input = read_json_evidence(
            evidence_root=endpoint_snapshot.parent,
            relative_path=endpoint_snapshot.name,
            max_bytes=2_000_000,
        )
        metadata: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
            metadata_input.content, strict=True
        )
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"
                if carry_uncertain_estimates
                else "STOP",
            }
        )
        prepared = prepare_development_corpus_judgment(
            candidate=candidate,
            policy=policy,
            endpoint_snapshot=metadata,
            source_files=material.source_files,
            run_id=run_id,
            maximum_completion_tokens=maximum_completion_tokens,
            maximum_run_seconds=float(maximum_run_seconds),
        )
        for path, evidence, bound in (
            (candidate_audit_file, candidate_input, MAX_DEVELOPMENT_CORPUS_RESULT_BYTES),
            (source_material_file, material_input, 2_000_000),
            (endpoint_snapshot, metadata_input, 2_000_000),
        ):
            revalidate_evidence_file_binding(
                evidence_root=path.parent, binding=evidence.binding, max_bytes=bound
            )
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_corpus_judgment(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    output_dir=output_dir,
                    allow_code_egress=allow_code_egress,
                )
            )
    except Exception:
        typer.echo(
            "Manifest judgment refused: invalid candidate, retained source, identity, consent, "
            "cumulative accounting or output custody. No validated finding or independent-lineage "
            "authority is implied; preserve existing costs and incomplete source scope.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status == "INCOMPLETE":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("audit-manifest")
def audit_development_manifest_command(
    source_manifest: Annotated[Path, typer.Option("--source-manifest")],
    corpus_root: Annotated[Path, typer.Option("--corpus-root")],
    endpoint_snapshot: Annotated[Path, typer.Option("--endpoint-snapshot")],
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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[bool, typer.Option("--carry-uncertain-estimates")] = False,
    truth_manifest: Annotated[Path | None, typer.Option("--truth-manifest")] = None,
    truth_sha256: Annotated[str | None, typer.Option("--truth-sha256")] = None,
) -> None:
    """Review only a frozen local source manifest; no discovery or qualified audit completion.

    The supplied synthetic/public declaration does not authenticate provenance or complete
    dependency scope. This paid-capable command requires separate explicit source/cost consent.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development manifest audit requires --accept-estimate-risk and --allow-code-egress; estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        if (truth_manifest is None) != (truth_sha256 is None):
            raise DevelopmentCostError("manifest scoring requires both truth file and SHA-256")
        inputs: tuple[Path, ...] = (
            source_manifest,
            corpus_root,
            endpoint_snapshot,
            cost_ledger,
            secrets_env_file,
        )
        if truth_manifest is not None:
            inputs += (truth_manifest,)
        paths = (*inputs, output_dir)
        if any(not p.is_absolute() or ".." in p.parts for p in paths) or len(set(paths)) != len(
            paths
        ):
            raise DevelopmentCostError(
                "development manifest paths must be absolute, distinct and normalized"
            )
        if output_dir.is_relative_to(corpus_root) or any(
            p.is_relative_to(output_dir) for p in inputs
        ):
            raise DevelopmentCostError(
                "development corpus output overlaps selected inputs or controls"
            )
        loaded = load_development_corpus(manifest_file=source_manifest, corpus_root=corpus_root)
        truth_input = (
            read_json_evidence(
                evidence_root=truth_manifest.parent,
                relative_path=truth_manifest.name,
                max_bytes=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
            )
            if truth_manifest is not None
            else None
        )
        metadata_input = read_json_evidence(
            evidence_root=endpoint_snapshot.parent,
            relative_path=endpoint_snapshot.name,
            max_bytes=2_000_000,
        )
        metadata: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
            metadata_input.content, strict=True
        )
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"
                if carry_uncertain_estimates
                else "STOP",
            }
        )
        prepared = prepare_development_corpus(
            policy=policy,
            endpoint_snapshot=metadata,
            manifest=loaded.material.manifest,
            source_files=loaded.material.source_files,
            run_id=run_id,
            maximum_completion_tokens=maximum_completion_tokens,
            maximum_run_seconds=float(maximum_run_seconds),
        )
        benchmark_binding = None
        if truth_input is not None:
            assert truth_sha256 is not None
            benchmark_binding = bind_development_corpus_benchmark(
                plan=prepared.plan,
                truth_content=truth_input.content,
                expected_truth_sha256=truth_sha256,
            )
        revalidate_loaded_development_corpus(loaded)
        revalidate_evidence_file_binding(
            evidence_root=endpoint_snapshot.parent,
            binding=metadata_input.binding,
            max_bytes=2_000_000,
        )
        if truth_manifest is not None and truth_input is not None:
            revalidate_evidence_file_binding(
                evidence_root=truth_manifest.parent,
                binding=truth_input.binding,
                max_bytes=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
            )
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_corpus(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    output_dir=output_dir,
                    allow_code_egress=allow_code_egress,
                    benchmark_binding=benchmark_binding,
                )
            )
    except Exception:
        typer.echo(
            "Development manifest audit refused: invalid selected source, metadata/allowance, consent, cumulative accounting or output custody. No complete dependency scope or validated audit is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status == "INCOMPLETE":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("ensemble-manifest")
def ensemble_development_manifest_command(
    source_manifest: Annotated[Path, typer.Option("--source-manifest")],
    corpus_root: Annotated[Path, typer.Option("--corpus-root")],
    candidate_endpoint_snapshot: Annotated[Path, typer.Option("--candidate-endpoint-snapshot")],
    first_reviewer_endpoint_snapshot: Annotated[
        Path, typer.Option("--first-reviewer-endpoint-snapshot")
    ],
    second_reviewer_endpoint_snapshot: Annotated[
        Path, typer.Option("--second-reviewer-endpoint-snapshot")
    ],
    cost_ledger: Annotated[Path, typer.Option("--cost-ledger")],
    secrets_env_file: Annotated[Path, typer.Option("--secrets-env-file")],
    output_dir: Annotated[Path, typer.Option("--output-dir")],
    run_id: Annotated[str, typer.Option("--run-id")],
    budget_usd: Annotated[str, typer.Option("--budget-usd")],
    per_attempt_usd: Annotated[str, typer.Option("--per-attempt-usd")],
    candidate_maximum_completion_tokens: Annotated[
        int, typer.Option("--candidate-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    first_reviewer_maximum_completion_tokens: Annotated[
        int, typer.Option("--first-reviewer-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    second_reviewer_maximum_completion_tokens: Annotated[
        int, typer.Option("--second-reviewer-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    maximum_run_seconds: Annotated[
        int, typer.Option("--maximum-run-seconds", min=1, max=1800)
    ] = 600,
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; never extends the shared whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[bool, typer.Option("--carry-uncertain-estimates")] = False,
    truth_manifest: Annotated[Path | None, typer.Option("--truth-manifest")] = None,
    truth_sha256: Annotated[str | None, typer.Option("--truth-sha256")] = None,
) -> None:
    """Run a frozen source-manifest candidate and two reviews under one ledger and deadline.

    Optional SHA-pinned labels never enter prompts; original scope, claims, costs and opinions
    remain unvalidated development evidence, including incomplete or cancelled stages.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development manifest ensemble requires --accept-estimate-risk and --allow-code-egress; "
            "estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        if (truth_manifest is None) != (truth_sha256 is None):
            raise DevelopmentCostError(
                "manifest ensemble scoring requires both truth file and SHA-256"
            )
        metadata_paths = (
            candidate_endpoint_snapshot,
            first_reviewer_endpoint_snapshot,
            second_reviewer_endpoint_snapshot,
        )
        inputs: tuple[Path, ...] = (
            source_manifest,
            corpus_root,
            *metadata_paths,
            cost_ledger,
            secrets_env_file,
        )
        if truth_manifest is not None:
            inputs += (truth_manifest,)
        paths = (*inputs, output_dir)
        if any(not p.is_absolute() or ".." in p.parts for p in paths) or len(set(paths)) != len(
            paths
        ):
            raise DevelopmentCostError(
                "manifest ensemble paths must be absolute, distinct and normalized"
            )
        if output_dir.is_relative_to(corpus_root) or any(
            p.is_relative_to(output_dir) for p in inputs
        ):
            raise DevelopmentCostError(
                "manifest ensemble output overlaps selected inputs or controls"
            )
        loaded = load_development_corpus(manifest_file=source_manifest, corpus_root=corpus_root)
        metadata_inputs = tuple(
            read_json_evidence(evidence_root=p.parent, relative_path=p.name, max_bytes=2_000_000)
            for p in metadata_paths
        )
        metadata: tuple[DevelopmentReviewMetadata, ...] = tuple(
            TypeAdapter(DevelopmentReviewMetadata).validate_json(item.content, strict=True)
            for item in metadata_inputs
        )
        truth_input = (
            read_json_evidence(
                evidence_root=truth_manifest.parent,
                relative_path=truth_manifest.name,
                max_bytes=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
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
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"
                if carry_uncertain_estimates
                else "STOP",
            }
        )
        prepared = prepare_development_corpus_ensemble(
            policy=policy,
            candidate_metadata=metadata[0],
            reviewer_metadata=metadata[1:],
            manifest=loaded.material.manifest,
            source_files=loaded.material.source_files,
            run_id=run_id,
            candidate_maximum_completion_tokens=candidate_maximum_completion_tokens,
            reviewer_maximum_completion_tokens=(
                first_reviewer_maximum_completion_tokens,
                second_reviewer_maximum_completion_tokens,
            ),
            maximum_run_seconds=float(maximum_run_seconds),
        )
        benchmark_binding = None
        if truth_input is not None:
            assert truth_sha256 is not None
            benchmark_binding = bind_development_corpus_benchmark(
                plan=prepared.plan.candidate,
                truth_content=truth_input.content,
                expected_truth_sha256=truth_sha256,
            )
        revalidate_loaded_development_corpus(loaded)
        for path, evidence in zip(metadata_paths, metadata_inputs, strict=True):
            revalidate_evidence_file_binding(
                evidence_root=path.parent, binding=evidence.binding, max_bytes=2_000_000
            )
        if truth_manifest is not None and truth_input is not None:
            revalidate_evidence_file_binding(
                evidence_root=truth_manifest.parent,
                binding=truth_input.binding,
                max_bytes=MAX_DEVELOPMENT_CORPUS_TRUTH_BYTES,
            )
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_corpus_ensemble(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    output_dir=output_dir,
                    allow_code_egress=allow_code_egress,
                    benchmark_binding=benchmark_binding,
                )
            )
    except Exception:
        typer.echo(
            "Development manifest ensemble refused: invalid source, role metadata/allowance, "
            "pinned labels, consent, cumulative accounting/headroom or output custody. "
            "Inspect retained stage records; no validated audit or independent-lineage authority is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status == "INCOMPLETE":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("ensemble-corpus")
def ensemble_development_corpus_command(
    candidate_endpoint_snapshot: Annotated[Path, typer.Option("--candidate-endpoint-snapshot")],
    first_reviewer_endpoint_snapshot: Annotated[
        Path, typer.Option("--first-reviewer-endpoint-snapshot")
    ],
    second_reviewer_endpoint_snapshot: Annotated[
        Path, typer.Option("--second-reviewer-endpoint-snapshot")
    ],
    corpus_root: Annotated[Path, typer.Option("--corpus-root")],
    corpus_id: Annotated[str, typer.Option("--corpus-id")],
    cost_ledger: Annotated[Path, typer.Option("--cost-ledger")],
    secrets_env_file: Annotated[Path, typer.Option("--secrets-env-file")],
    output_dir: Annotated[Path, typer.Option("--output-dir")],
    run_id: Annotated[str, typer.Option("--run-id")],
    budget_usd: Annotated[str, typer.Option("--budget-usd")],
    per_attempt_usd: Annotated[str, typer.Option("--per-attempt-usd")],
    candidate_maximum_completion_tokens: Annotated[
        int, typer.Option("--candidate-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    first_reviewer_maximum_completion_tokens: Annotated[
        int, typer.Option("--first-reviewer-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    second_reviewer_maximum_completion_tokens: Annotated[
        int, typer.Option("--second-reviewer-maximum-completion-tokens", min=1, max=65536)
    ] = 4096,
    maximum_run_seconds: Annotated[
        int, typer.Option("--maximum-run-seconds", min=1, max=1800)
    ] = 600,
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[bool, typer.Option("--carry-uncertain-estimates")] = False,
    truth_manifest: Annotated[Path | None, typer.Option("--truth-manifest")] = None,
) -> None:
    """Execute source candidates and two reviews with one ledger and bounded whole-run scope.

    Role-specific allowances are independent. Unknown costs stay accounted, failed stages
    stop, and distinct model names or agreement never establish qualified root independence.
    Optional truth is consumed only by local scoring, never included in model prompts.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development ensemble requires --accept-estimate-risk and --allow-code-egress; "
            "estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        metadata_paths = (
            candidate_endpoint_snapshot,
            first_reviewer_endpoint_snapshot,
            second_reviewer_endpoint_snapshot,
        )
        inputs: tuple[Path, ...] = (*metadata_paths, corpus_root, cost_ledger, secrets_env_file)
        if truth_manifest is not None:
            inputs += (truth_manifest,)
        paths = (*inputs, output_dir)
        if any(not path.is_absolute() or ".." in path.parts for path in paths) or len(
            set(paths)
        ) != len(paths):
            raise DevelopmentCostError(
                "development ensemble paths must be absolute, distinct and normalized"
            )
        if output_dir.is_relative_to(corpus_root) or any(
            path.is_relative_to(output_dir) for path in inputs
        ):
            raise DevelopmentCostError("development ensemble output overlaps input/control scope")
        if corpus_id not in DEVELOPMENT_AUDIT_SOURCE_PINS:
            raise DevelopmentCostError("development ensemble corpus is not allowlisted")
        metadata_inputs = tuple(
            read_json_evidence(
                evidence_root=path.parent, relative_path=path.name, max_bytes=2_000_000
            )
            for path in metadata_paths
        )
        metadata: tuple[DevelopmentReviewMetadata, ...] = tuple(
            TypeAdapter(DevelopmentReviewMetadata).validate_json(item.content, strict=True)
            for item in metadata_inputs
        )
        truth_input = (
            read_file_evidence(
                evidence_root=truth_manifest.parent,
                relative_path=truth_manifest.name,
                max_bytes=MAX_DEVELOPMENT_TRUTH_BYTES,
            )
            if truth_manifest is not None
            else None
        )
        truth = (
            read_development_benchmark_truth(truth_input.content)
            if truth_input is not None
            else None
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
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"
                if carry_uncertain_estimates
                else "STOP",
            }
        )
        prepared = prepare_development_ensemble(
            policy=policy,
            candidate_metadata=metadata[0],
            reviewer_metadata=metadata[1:],
            corpus_id=cast(DevelopmentCorpusId, corpus_id),
            source_files=sources,
            run_id=run_id,
            candidate_maximum_completion_tokens=candidate_maximum_completion_tokens,
            reviewer_maximum_completion_tokens=(
                first_reviewer_maximum_completion_tokens,
                second_reviewer_maximum_completion_tokens,
            ),
            maximum_run_seconds=float(maximum_run_seconds),
        )
        if truth is not None:
            bind_development_benchmark(plan=prepared.plan.candidate, truth=truth)
        for path, evidence in zip(metadata_paths, metadata_inputs, strict=True):
            revalidate_evidence_file_binding(
                evidence_root=path.parent, binding=evidence.binding, max_bytes=2_000_000
            )
        if truth_manifest is not None and truth_input is not None:
            revalidate_evidence_file_binding(
                evidence_root=truth_manifest.parent,
                binding=truth_input.binding,
                max_bytes=MAX_DEVELOPMENT_TRUTH_BYTES,
            )
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_ensemble(
                    prepared=prepared,
                    ledger=ledger,
                    operator_secrets=secrets,
                    output_dir=output_dir,
                    allow_code_egress=allow_code_egress,
                    benchmark_truth=truth,
                )
            )
    except Exception:
        typer.echo(
            "Development ensemble refused: invalid source, role metadata/allowance, consent, "
            "cumulative accounting/headroom or output custody. Inspect retained stage records; "
            "no independent-lineage authority or validated audit is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status == "INCOMPLETE":
        raise typer.Exit(ExitCode.INCOMPLETE)


@development_app.command("judge-audit")
def judge_development_audit_command(
    candidate_audit_file: Annotated[Path, typer.Option("--candidate-audit-file")],
    endpoint_snapshot: Annotated[Path, typer.Option("--endpoint-snapshot")],
    corpus_root: Annotated[Path, typer.Option("--corpus-root")],
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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[bool, typer.Option("--carry-uncertain-estimates")] = False,
    truth_manifest: Annotated[Path | None, typer.Option("--truth-manifest")] = None,
) -> None:
    """Review every retained v2 candidate once with another explicitly selected model.

    Requires the original cumulative ledger and frozen corpus. Review opinions and
    distinct model names never establish root-lineage independence or validated findings.
    Optional truth is used locally for impact scoring, never sent to the reviewing model.
    """

    if not accept_estimate_risk or not allow_code_egress:
        typer.echo(
            "Development judgment requires --accept-estimate-risk and --allow-code-egress; "
            "estimated budgets can be exceeded.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION)
    try:
        inputs: tuple[Path, ...] = (
            candidate_audit_file,
            endpoint_snapshot,
            corpus_root,
            cost_ledger,
            secrets_env_file,
        )
        if truth_manifest is not None:
            inputs += (truth_manifest,)
        paths = (*inputs, output_dir)
        if any(not path.is_absolute() or ".." in path.parts for path in paths) or len(
            set(paths)
        ) != len(paths):
            raise DevelopmentCostError(
                "development judgment paths must be absolute, distinct and normalized"
            )
        if output_dir.is_relative_to(corpus_root) or any(
            path.is_relative_to(output_dir) for path in inputs
        ):
            raise DevelopmentCostError(
                "development judgment output overlaps its input/control scope"
            )
        candidate_input = read_json_evidence(
            evidence_root=candidate_audit_file.parent,
            relative_path=candidate_audit_file.name,
            max_bytes=MAX_DEVELOPMENT_JUDGMENT_INPUT_BYTES,
        )
        candidate = DevelopmentAuditObservation.model_validate_json(
            candidate_input.content, strict=True
        )
        metadata_input = read_json_evidence(
            evidence_root=endpoint_snapshot.parent,
            relative_path=endpoint_snapshot.name,
            max_bytes=2_000_000,
        )
        metadata: DevelopmentReviewMetadata = TypeAdapter(DevelopmentReviewMetadata).validate_json(
            metadata_input.content, strict=True
        )
        truth_input = (
            read_file_evidence(
                evidence_root=truth_manifest.parent,
                relative_path=truth_manifest.name,
                max_bytes=MAX_DEVELOPMENT_TRUTH_BYTES,
            )
            if truth_manifest is not None
            else None
        )
        truth = (
            read_development_benchmark_truth(truth_input.content)
            if truth_input is not None
            else None
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
            for name, _digest, _size, _lines in DEVELOPMENT_AUDIT_SOURCE_PINS[
                candidate.plan.corpus_id
            ]
        )
        policy = DevelopmentCostPolicy.model_validate(
            {
                "overspend_risk_accepted": accept_estimate_risk,
                "total_budget_usd": budget_usd,
                "per_attempt_budget_usd": per_attempt_usd,
                "safety_multiplier": safety_multiplier,
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": "CARRY_RESERVED_ESTIMATE"
                if carry_uncertain_estimates
                else "STOP",
            }
        )
        prepared = prepare_development_judgment(
            candidate=candidate,
            policy=policy,
            endpoint_snapshot=metadata,
            source_files=sources,
            run_id=run_id,
            maximum_completion_tokens=maximum_completion_tokens,
        )
        if truth is not None:
            bind_development_benchmark(plan=prepared.plan.candidate.plan, truth=truth)
        revalidate_evidence_file_binding(
            evidence_root=candidate_audit_file.parent,
            binding=candidate_input.binding,
            max_bytes=MAX_DEVELOPMENT_JUDGMENT_INPUT_BYTES,
        )
        revalidate_evidence_file_binding(
            evidence_root=endpoint_snapshot.parent,
            binding=metadata_input.binding,
            max_bytes=2_000_000,
        )
        if truth_manifest is not None and truth_input is not None:
            revalidate_evidence_file_binding(
                evidence_root=truth_manifest.parent,
                binding=truth_input.binding,
                max_bytes=MAX_DEVELOPMENT_TRUTH_BYTES,
            )
        ledger = AtomicCostLedger.open_existing(cost_ledger, cap_usd=policy.total_budget_usd)
        with load_operator_secrets(secrets_env_file, environ={}, required=True) as secrets:
            observation = asyncio.run(
                run_development_judgment(
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
            "Development judgment refused: invalid candidate, source, identity, consent, "
            "cumulative accounting or output custody. Inspect retained local records before "
            "another attempt; no validated finding or independent-lineage authority is implied.",
            err=True,
        )
        raise typer.Exit(ExitCode.CONFIGURATION) from None
    typer.echo(observation.model_dump_json(indent=2))
    if observation.status == "INCOMPLETE":
        raise typer.Exit(ExitCode.INCOMPLETE)


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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    carry_uncertain_estimates: Annotated[
        bool,
        typer.Option(
            "--carry-uncertain-estimates",
            help="Carry unknown development costs at their estimates; never settle or retry them.",
        ),
    ] = False,
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
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": maximum_attempts,
                "uncertain_cost_policy": (
                    "CARRY_RESERVED_ESTIMATE" if carry_uncertain_estimates else "STOP"
                ),
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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
    safety_multiplier: Annotated[str, typer.Option("--safety-multiplier")] = "2",
    accept_estimate_risk: Annotated[bool, typer.Option("--accept-estimate-risk")] = False,
    allow_code_egress: Annotated[bool, typer.Option("--allow-code-egress")] = False,
    carry_uncertain_estimates: Annotated[
        bool,
        typer.Option(
            "--carry-uncertain-estimates",
            help="Carry unknown development costs at their estimates; never settle or retry them.",
        ),
    ] = False,
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
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": maximum_attempts,
                "uncertain_cost_policy": (
                    "CARRY_RESERVED_ESTIMATE" if carry_uncertain_estimates else "STOP"
                ),
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
    request_timeout_seconds: Annotated[
        int | None,
        typer.Option(
            "--request-timeout-seconds",
            min=1,
            max=1800,
            help="Per-request wait limit; defaults to 180s and never extends a whole-run deadline.",
        ),
    ] = None,
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
    carry_uncertain_estimates: Annotated[
        bool,
        typer.Option(
            "--carry-uncertain-estimates",
            help="Carry unknown development costs at their estimates; never settle or retry them.",
        ),
    ] = False,
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
                "request_timeout_seconds": request_timeout_seconds,
                "maximum_attempts": 1,
                "uncertain_cost_policy": (
                    "CARRY_RESERVED_ESTIMATE" if carry_uncertain_estimates else "STOP"
                ),
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
