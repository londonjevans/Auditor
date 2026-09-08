"""Real local files only: comparison cannot call providers, read credentials or mutate a ledger."""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

import mmaudit.development_cli as development_cli
import mmaudit.orchestration.development_comparison as comparison_io
from mmaudit.benchmark.development_comparison import DevelopmentBenchmarkComparison
from mmaudit.cli import app
from mmaudit.constants import ExitCode
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_comparison_support import comparison_score

RUNNER = CliRunner()


@pytest.fixture(autouse=True)
def prohibit_external_actions(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("comparison attempted credential, ledger, network or subprocess access")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "open_existing", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "reserve", forbidden)
    monkeypatch.setattr(AtomicCostLedger, "reconcile", forbidden)


def inputs(tmp_path, *, variant="a", mode="matched", failure=None):
    paths = tuple(tmp_path / f"score-{n}.json" for n in range(2))
    for index, path in enumerate(paths):
        score = comparison_score(
            f"run-{index}", variant=variant, mode=mode, failure=failure if index else None
        )
        path.write_text(score.model_dump_json(indent=2))
    parent = tmp_path / "private-output"
    parent.mkdir(mode=0o700)
    return paths, parent / "comparison.json"


def invoke(paths, output):
    args = ["development", "compare-scores"]
    for path in paths:
        args.extend(("--score-file", str(path)))
    return RUNNER.invoke(app, [*args, "--output-file", str(output)])


@pytest.mark.parametrize("variant", ["a", "b"])
@pytest.mark.parametrize("mode", ["matched", "advisory", "empty"])
def test_cli_writes_one_private_recomputable_comparison_without_external_actions(
    tmp_path, variant, mode
):
    paths, output = inputs(tmp_path, variant=variant, mode=mode)
    before = tuple(path.read_bytes() for path in paths)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.SUCCESS, result.output
    comparison = DevelopmentBenchmarkComparison.model_validate_json(
        output.read_bytes(), strict=True
    )
    assert comparison.comparison_sha256 in result.output
    assert comparison.union.quality_scope == "COMPLETE_OBSERVATIONS"
    assert comparison.lineage_independence == "NOT_ESTABLISHED"
    assert comparison.qualification_eligible is comparison.audit_complete is False
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert tuple(path.read_bytes() for path in paths) == before
    assert set(output.parent.iterdir()) == {output}
    other = output.with_name("reordered.json")
    assert invoke(tuple(reversed(paths)), other).exit_code == ExitCode.SUCCESS
    assert output.read_bytes() == other.read_bytes()


@pytest.mark.parametrize("failure", ["known", "unknown", "overrun", "reserved"])
def test_partial_cli_output_is_retained_but_cannot_report_complete_quality(tmp_path, failure):
    paths, output = inputs(tmp_path, failure=failure)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.INCOMPLETE, result.output
    comparison = DevelopmentBenchmarkComparison.model_validate_json(output.read_bytes())
    assert comparison.union.unique_root_recall.value is None
    assert comparison.union.first_attempt_shard_completion.numerator == 4
    assert comparison.union.first_attempt_shard_completion.denominator == 6
    assert comparison.union.incomplete_run_ids == ("run-1",)
    assert "INCOMPLETE_OBSERVATIONS" in result.output


@pytest.mark.parametrize(
    "kind",
    [
        "relative_input",
        "relative_output",
        "repeated",
        "overlap",
        "missing",
        "input_link",
        "parent_link",
        "input_hardlink",
        "output_link",
        "existing_output",
        "missing_parent",
        "writable_parent",
        "input_directory",
        "fifo",
        "output_below_input",
    ],
)
def test_unsafe_or_overlapping_files_refuse_without_overwrite(tmp_path, kind):
    paths, output = inputs(tmp_path)
    sentinel = b"synthetic-existing-output-must-not-be-overwritten"
    preserved = None
    if kind == "relative_input":
        paths = (Path("score-0.json"), paths[1])
    elif kind == "relative_output":
        output = Path("comparison.json")
    elif kind == "repeated":
        paths = (paths[0], paths[0])
    elif kind == "overlap":
        output = paths[0]
        preserved = output.read_bytes()
    elif kind == "missing":
        paths = (tmp_path / "absent.json", paths[1])
    elif kind in {"input_link", "input_hardlink"}:
        alias = tmp_path / "alias.json"
        if kind == "input_link":
            alias.symlink_to(paths[0])
        else:
            os.link(paths[0], alias)
        paths = (alias, paths[1])
    elif kind == "parent_link":
        alias = tmp_path / "linked-parent"
        alias.symlink_to(output.parent, target_is_directory=True)
        output = alias / output.name
    elif kind == "output_link":
        target = tmp_path / "preserved.json"
        target.write_bytes(sentinel)
        output.symlink_to(target)
        preserved = sentinel
    elif kind == "existing_output":
        output.write_bytes(sentinel)
        preserved = sentinel
    elif kind == "missing_parent":
        output = output.parent / "missing" / output.name
    elif kind == "writable_parent":
        output.parent.chmod(0o777)
    elif kind == "input_directory":
        paths = (output.parent, paths[1])
    elif kind == "fifo":
        fifo = tmp_path / "not-a-score"
        os.mkfifo(fifo)
        paths = (fifo, paths[1])
    else:
        output = paths[0] / "inside.json"
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert "refused" in result.output and sentinel.decode() not in result.output
    if preserved is not None:
        assert output.read_bytes() == preserved
    else:
        assert not output.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "duplicate_key",
        "nonfinite",
        "syntax",
        "invalid_utf8",
        "wrong_score",
        "forged_score",
        "mixed_corpus",
        "too_large",
    ],
)
def test_untrusted_json_is_bounded_and_redacted_before_output(tmp_path, monkeypatch, kind):
    paths, output = inputs(tmp_path)
    if kind == "duplicate_key":
        paths[1].write_bytes(b'{"private-canary":1,"private-canary":2}')
    elif kind == "nonfinite":
        paths[1].write_bytes(b'{"private-canary":NaN}')
    elif kind == "syntax":
        paths[1].write_bytes(b"private-canary{")
    elif kind == "invalid_utf8":
        paths[1].write_bytes(b"\xffprivate-canary")
    elif kind == "wrong_score":
        paths[1].write_text('{"private-canary":true}')
    elif kind == "forged_score":
        data = json.loads(paths[1].read_bytes())
        data["summary"]["total_claim_count"] = 0
        paths[1].write_text(json.dumps(data))
    elif kind == "mixed_corpus":
        paths[1].write_text(comparison_score("run-1", variant="b").model_dump_json())
    else:
        monkeypatch.setattr(comparison_io, "MAX_DEVELOPMENT_COMPARISON_SCORE_BYTES", 64)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.CONFIGURATION, result.output
    assert not output.exists() and "private-canary" not in result.output


@pytest.mark.parametrize("count", [1, 9])
def test_invalid_input_count_refuses_before_reading_any_file(tmp_path, monkeypatch, count):
    def unexpected_read(**_kwargs):
        pytest.fail("out-of-bound input list must refuse before file access")

    monkeypatch.setattr(comparison_io, "read_json_evidence", unexpected_read)
    result = invoke(
        tuple(tmp_path / f"unused-{n}.json" for n in range(count)), tmp_path / "output.json"
    )
    assert result.exit_code == ExitCode.CONFIGURATION


@pytest.mark.parametrize("phase", ["before_write", "during_validation"])
def test_changed_input_cannot_publish_a_comparison_and_only_owned_output_is_cleaned(
    tmp_path, monkeypatch, phase
):
    paths, output = inputs(tmp_path)
    before = paths[0].read_bytes()
    if phase == "before_write":
        compare = comparison_io.compare_development_scores

        def changed(scores):
            result = compare(scores)
            paths[0].write_bytes(before + b"\n")
            return result

        monkeypatch.setattr(comparison_io, "compare_development_scores", changed)
    else:
        write = comparison_io.write_json_evidence

        def changed(**kwargs):
            validate = kwargs["validate_content"]

            def check(content):
                paths[0].write_bytes(before + b"\n")
                validate(content)

            return write(**{**kwargs, "validate_content": check})

        monkeypatch.setattr(comparison_io, "write_json_evidence", changed)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert not output.exists()
    assert paths[0].read_bytes() == before + b"\n"


def test_output_tamper_during_validation_cannot_report_success(tmp_path, monkeypatch):
    paths, output = inputs(tmp_path)
    write = comparison_io.write_json_evidence

    def tampered(**kwargs):
        validate = kwargs["validate_content"]

        def check(content):
            validate(content)
            output.write_text("synthetic-corrupt-output")

        return write(**{**kwargs, "validate_content": check})

    monkeypatch.setattr(comparison_io, "write_json_evidence", tampered)
    assert invoke(paths, output).exit_code == ExitCode.CONFIGURATION
    assert not output.exists()


def test_output_replacement_is_preserved_when_owned_cleanup_refuses(tmp_path, monkeypatch):
    paths, output = inputs(tmp_path)
    write = comparison_io.write_json_evidence
    moved = output.with_name("moved-owned-output.json")

    def replaced(**kwargs):
        validate = kwargs["validate_content"]

        def check(content):
            validate(content)
            output.rename(moved)
            output.write_text("synthetic-replacement-belongs-to-someone-else")

        return write(**{**kwargs, "validate_content": check})

    monkeypatch.setattr(comparison_io, "write_json_evidence", replaced)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert output.read_text() == "synthetic-replacement-belongs-to-someone-else"
    assert moved.is_file()
    assert "someone-else" not in result.output


def test_unexpected_failure_is_redacted_and_cannot_be_reported_as_success(tmp_path, monkeypatch):
    paths, output = inputs(tmp_path)

    def unavailable(**_kwargs):
        raise RuntimeError("private-canary")

    monkeypatch.setattr(development_cli, "compare_development_score_files", unavailable)
    result = invoke(paths, output)
    assert result.exit_code == ExitCode.CONFIGURATION
    assert "private-canary" not in result.output and not output.exists()
