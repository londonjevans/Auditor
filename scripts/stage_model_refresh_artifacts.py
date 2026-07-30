"""Validate and stage exact model-refresh workflow evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

from mmaudit.models.qualification import load_candidate_registry
from mmaudit.models.refresh import load_model_refresh_snapshot
from mmaudit.models.refresh_staging import (
    ModelRefreshStagingError,
    stage_model_refresh_evidence,
)


def _bounded_path(value: str) -> Path:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 16_384
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("path must be bounded single-line text")
    return Path(value)


def _bounded_identity(value: str) -> str:
    if (
        not value.strip()
        or len(value.encode("utf-8")) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise argparse.ArgumentTypeError("identity must be bounded single-line text")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Strictly validate and stage one model-refresh workflow bundle."
    )
    parser.add_argument("--output-dir", type=_bounded_path, required=True)
    parser.add_argument("--staging-dir", type=_bounded_path, required=True)
    parser.add_argument("--candidate-registry", type=_bounded_path, required=True)
    parser.add_argument("--previous-snapshot", type=_bounded_path)
    parser.add_argument("--refresh-exit-status", type=int, required=True)
    parser.add_argument("--source-commit", type=_bounded_identity, required=True)
    parser.add_argument("--workflow-run-id", type=_bounded_identity, required=True)
    parser.add_argument("--workflow-run-attempt", type=_bounded_identity, required=True)
    parser.add_argument("--pricing-tolerance-fraction", type=_bounded_identity, required=True)
    parser.add_argument("--soft-max-age-hours", type=int, required=True)
    parser.add_argument("--hard-max-age-hours", type=int, required=True)
    arguments = parser.parse_args(argv)
    try:
        registry = load_candidate_registry(arguments.candidate_registry)
        previous_snapshot = (
            load_model_refresh_snapshot(arguments.previous_snapshot)
            if arguments.previous_snapshot is not None
            else None
        )
        status = stage_model_refresh_evidence(
            output_dir=arguments.output_dir,
            staging_dir=arguments.staging_dir,
            candidate_registry=registry,
            refresh_exit_status=arguments.refresh_exit_status,
            source_commit=arguments.source_commit,
            workflow_run_id=arguments.workflow_run_id,
            workflow_run_attempt=arguments.workflow_run_attempt,
            pricing_tolerance_fraction=arguments.pricing_tolerance_fraction,
            soft_max_age_hours=arguments.soft_max_age_hours,
            hard_max_age_hours=arguments.hard_max_age_hours,
            previous_snapshot=previous_snapshot,
        )
    except (ModelRefreshStagingError, ValueError):
        print("model-refresh artifact staging failed")
        return 74
    print(
        "model-refresh artifacts staged: "
        f"disposition={status.disposition.value} artifacts={len(status.artifacts)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
