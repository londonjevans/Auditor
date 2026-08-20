from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OBJECTIVE_RELATIVE_PATH = "docs/remediation/v3/product_completion_goal.txt"
OBJECTIVE_SHA256 = "e3b895de9c7f5c7836dd7b77c09ae2a31adefa9469d46588ee6f52b78caa0d15"
OBJECTIVE_BYTES = 2_892
OBJECTIVE_LOGICAL_LINES = 24
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


def test_product_objective_records_explicit_supersession_and_integrity_backstops() -> None:
    objective = (ROOT / OBJECTIVE_RELATIVE_PATH).read_text(encoding="utf-8")
    traceability = json.loads(
        (ROOT / "docs/remediation/v3/review_traceability.json").read_text(encoding="utf-8")
    )
    runtime_status = json.loads(
        (ROOT / "docs/remediation/v3/runtime_status.json").read_text(encoding="utf-8")
    )
    supersession = traceability["objective_supersession"]

    assert supersession == {
        "prior_path": OBJECTIVE_RELATIVE_PATH,
        "prior_sha256": "f77db665fe3092e6b809402dcac7e370bc9c3c507542fd40ef7c6f5eaad32e43",
        "prior_git_blob": "360944d9a44cadfbb7134b23175aa04749994be6",
        "prior_introduced_commit": "517559e5c9526f78e516374ebc194933d01eac7f",
        "successor_path": OBJECTIVE_RELATIVE_PATH,
        "successor_sha256": OBJECTIVE_SHA256,
        "authorized_at": "2026-08-17T20:06:41Z",
        "decision": "EXPLICIT_OPERATOR_TARGET_CHANGE",
    }
    assert runtime_status["objective_path"] == OBJECTIVE_RELATIVE_PATH
    assert runtime_status["objective_sha256"] == OBJECTIVE_SHA256
    assert runtime_status["objective_supersession"] == supersession
    for required_text in (
        "hash alone is never enough",
        "External frozen ground-truth",
        "Cross-lineage independence",
        "append-only transparency log",
        "same-root judgement voids it",
        "real, non-model-generated corpus ground-truth",
    ):
        assert required_text in objective
