from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43"
OBJECTIVE_BYTES = 40_779
OBJECTIVE_LOGICAL_LINES = 1_418
OBJECTIVE_GIT_ATTRIBUTES = f"{OBJECTIVE_RELATIVE_PATH} -text"


def test_product_objective_is_exact_regular_repository_file() -> None:
    objective = ROOT / OBJECTIVE_RELATIVE_PATH
    metadata = objective.lstat()

    assert not stat.S_ISLNK(metadata.st_mode)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_nlink == 1

    content = objective.read_bytes()
    assert len(content) == OBJECTIVE_BYTES
    assert len(content.splitlines()) == OBJECTIVE_LOGICAL_LINES
    assert hashlib.sha256(content).hexdigest() == OBJECTIVE_SHA256

    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert OBJECTIVE_GIT_ATTRIBUTES in attributes


def test_product_objective_authorities_bind_exact_path_and_digest() -> None:
    traceability = json.loads(
        (ROOT / "docs/remediation/v3/review_traceability.json").read_text(encoding="utf-8")
    )
    queue_header = (
        (ROOT / "docs/remediation/v3/work_queue.md")
        .read_text(encoding="utf-8")
        .split("Statuses:", maxsplit=1)[0]
    )
    worklog_header = (
        (ROOT / "docs/remediation/v3/worklog.md")
        .read_text(encoding="utf-8")
        .split("AUTORUN_STATUS:", maxsplit=1)[0]
    )

    assert traceability["objective_path"] == OBJECTIVE_RELATIVE_PATH
    assert traceability["objective_sha256"] == OBJECTIVE_SHA256
    for header in (queue_header, worklog_header):
        assert f"`{OBJECTIVE_RELATIVE_PATH}`" in header
        assert f"`{OBJECTIVE_SHA256}`" in header
