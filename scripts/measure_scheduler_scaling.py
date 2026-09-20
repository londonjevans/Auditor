"""Run the predeclared provider-free journal experiment, serially and without CI dispatch."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import socket
from pathlib import Path
from typing import Any

import httpx
import pytest

import mmaudit.operator_secrets as secrets_module
from tests.scheduler_scaling_support import CASE_PATH, load_scaling_cases, measure_original_tree


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--case", choices=["depth-1", "depth-2", "depth-3", "depth-4"])
    args = parser.parse_args()
    cases = load_scaling_cases()
    if args.case:
        cases = tuple(case for case in cases if case.case_id == args.case)

    def forbidden(*_args: Any, **_kwargs: Any) -> None:
        raise AssertionError("scaling measurements must not access networks or operator secrets")

    def emit(value: Any) -> None:
        print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False), flush=True)

    emit(
        {
            "experiment": "scheduler-scaling-v1",
            "cases_sha256": hashlib.sha256(CASE_PATH.read_bytes()).hexdigest(),
            "python": platform.python_version(),
            "platform": platform.system(),
            "cases": [case.case_id for case in cases],
            "unprofiled_samples": 3,
            "serial_execution": True,
        }
    )
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(socket.socket, "connect", forbidden)
        patch.setattr(socket, "create_connection", forbidden)
        patch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
        patch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
        patch.setattr(secrets_module, "load_operator_secrets", forbidden)
        for case in cases:

            def progress(phase: str, *, selected_case_id: str = case.case_id) -> None:
                emit({"case": selected_case_id, "phase_started": phase})

            result = measure_original_tree(
                case,
                args.workspace,
                progress=progress,
            )
            emit({"completed_case": result})
    emit({"experiment_complete": True, "provider_calls": 0, "optimization_applied": False})


if __name__ == "__main__":
    main()
