"""Run fixed full-pipeline/replay observations serially, with no real transport or CI dispatch."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import platform
from pathlib import Path
from typing import Any

from tests.pipeline_replay_capture import snapshot_replay_evidence
from tests.pipeline_replay_scaling_support import (
    CASE_PATH,
    load_pipeline_replay_cases,
    measure_original_pipeline_replay,
)
from tests.pipeline_replay_workload import (
    ReplayDeclaration,
    build_replay_declaration,
    load_replay_declaration,
    require_current_replay_inputs,
    write_replay_declaration,
)


async def _main(
    workspace: Path, selected: str | None, declaration: ReplayDeclaration | None = None
) -> None:
    if declaration is not None:
        if selected is not None:
            raise ValueError("declared comparisons require both original cases")
        require_current_replay_inputs(declaration)
    cases = load_pipeline_replay_cases()
    if selected is not None:
        cases = tuple(case for case in cases if case.name == selected)

    def emit(value: Any) -> None:
        print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)

    identity = (
        {
            "declaration_sha256": declaration.sha256,
            "workload_sha256": declaration.workload_sha256,
            "implementation_sha256": declaration.implementation_sha256,
            "declaration_is_execution_or_qualification_evidence": False,
        }
        if declaration is not None
        else {}
    )
    emit(
        {
            "experiment": (
                "pipeline-replay-scaling-v2"
                if declaration is not None
                else "pipeline-replay-scaling-v1"
            ),
            **identity,
            "cases_sha256": hashlib.sha256(CASE_PATH.read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "platform": platform.system(),
            "cases": [case.name for case in cases],
            "fresh_pipeline_samples": 1,
            "unprofiled_resume_samples": 3,
            "additional_profiled_resume_samples": 1,
            "serial_execution": True,
            "test_only_model_plan_override": True,
        }
    )
    for case in cases:

        def progress(phase: str, *, name: str = case.name) -> None:
            if declaration is not None:
                require_current_replay_inputs(declaration)
            emit({"case": name, "phase_started": phase})

        result = await measure_original_pipeline_replay(case, workspace, progress=progress)
        if declaration is not None:
            require_current_replay_inputs(declaration)
            result["original_evidence"] = snapshot_replay_evidence(
                workspace, case.name, result
            ).model_dump(mode="json")
        emit({"completed_case": {**result, **identity}})
    emit(
        {
            "experiment_complete": True,
            "real_provider_calls": 0,
            # Legacy constant, not revision evidence: v2 pins actual implementation inputs.
            "optimization_applied": False,
            **identity,
        }
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path)
    parser.add_argument("--case", choices=["generic-open", "mixed-specialist"])
    parser.add_argument(
        "--predeclare", type=Path, help="Create a new v2 input declaration; run nothing"
    )
    parser.add_argument(
        "--declaration", type=Path, help="Use an existing v2 declaration for both cases"
    )
    parser.add_argument("--declaration-sha256", help="Exact canonical declaration hash")
    args = parser.parse_args()
    if args.predeclare is not None:
        if any(
            value is not None
            for value in (args.workspace, args.case, args.declaration, args.declaration_sha256)
        ):
            parser.error("--predeclare cannot be combined with execution arguments")
        prepared = build_replay_declaration()
        sha256 = write_replay_declaration(args.predeclare, prepared)
        print(
            json.dumps(
                {
                    "declaration_sha256": sha256,
                    "workload_sha256": prepared.workload_sha256,
                    "workloads_executed": 0,
                    "real_provider_calls": 0,
                }
            )
        )
        return
    if args.workspace is None:
        parser.error("--workspace is required for measurement")
    if (args.declaration is None) != (args.declaration_sha256 is None):
        parser.error("--declaration and --declaration-sha256 must be supplied together")
    if args.declaration is not None and args.case is not None:
        parser.error("declared comparisons require both original cases")
    declaration = (
        load_replay_declaration(args.declaration, args.declaration_sha256)
        if args.declaration is not None
        else None
    )
    asyncio.run(_main(args.workspace, args.case, declaration))


if __name__ == "__main__":
    main()
