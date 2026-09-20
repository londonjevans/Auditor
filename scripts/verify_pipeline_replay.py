"""Verify two complete caller-pinned local replay captures; never launch or retry a workload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from tests.pipeline_replay_capture import verify_replay_pair


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    for side in ("before", "after"):
        for artifact in ("capture", "declaration"):
            parser.add_argument(f"--{side}-{artifact}", type=Path, required=True)
            parser.add_argument(f"--{side}-{artifact}-sha256", required=True)
        parser.add_argument(f"--{side}-workspace", type=Path, required=True)
        parser.add_argument(f"--{side}-session", type=int, required=True)
    args = vars(parser.parse_args())
    selections = [
        {
            key.removeprefix(side + "_"): value
            for key, value in args.items()
            if key.startswith(side + "_")
        }
        for side in ("before", "after")
    ]
    report: dict[str, Any]
    try:
        if not __debug__ or sys.flags.optimize:
            raise ValueError("original assertions must be enabled")
        report = verify_replay_pair(*selections)
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        # Do not echo untrusted diagnostics, file content, host paths or exception values.
        report = {
            "schema_version": "2.0",
            "accepted": False,
            "reason": "INCOMPLETE_INVALID_OR_MISMATCHED_REPLAY_EVIDENCE",
            "input_artifacts_retained_unchanged": True,
            "new_workloads_executed": 0,
            "real_provider_calls": 0,
            "execution_attested": False,
            "qualification_or_release_authority": False,
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False))
    if not report["accepted"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
