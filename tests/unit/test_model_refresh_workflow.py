"""Static regressions for the protected model-metadata refresh workflow."""

import os
import re
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "mmaudit-model.yml"


def _read() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job_block(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    _, separator, remainder = workflow.partition(marker)
    assert separator, f"missing workflow job {name!r}"
    next_job = re.search(r"(?m)^  [a-z0-9][a-z0-9-]*:\n", remainder)
    return remainder if next_job is None else remainder[: next_job.start()]


def _step_block(job: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    _, separator, remainder = job.partition(marker)
    assert separator, f"missing workflow step {name!r}"
    next_step = re.search(r"(?m)^      - (?:name|uses):", remainder)
    return remainder if next_step is None else remainder[: next_step.start()]


def _run_script(step: str) -> str:
    marker = "        run: |\n"
    _, separator, script = step.partition(marker)
    assert separator, "workflow step lacks a literal run script"
    return textwrap.dedent(script)


def test_refresh_runs_manually_only_on_the_default_branch_and_protected_environment() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")

    triggers = workflow.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
    assert re.findall(r"(?m)^  ([a-z_]+):", triggers) == ["workflow_dispatch"]
    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "environment: mmaudit-provider" in provider_job
    assert (
        "if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        in provider_job
    )
    assert "permissions:\n  actions: read\n  contents: read" in workflow
    assert "needs: [refresh-artifact-validation]" in provider_job


def test_refresh_uses_explicit_secret_file_and_fresh_runner_temporary_roots() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    roots = _step_block(provider_job, "Create fresh runner-temporary refresh roots")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")
    secret = _step_block(provider_job, "Prepare explicit operator secret file")
    cleanup = _step_block(provider_job, "Remove operator secret file")

    assert 'mktemp -d "$RUNNER_TEMP/mmaudit-model-refresh-root.XXXXXX"' in roots
    assert 'output_dir="$refresh_root/output"' in roots
    assert 'test ! -e "$output_dir"' in roots
    assert 'mktemp -d "$RUNNER_TEMP/mmaudit-model-refresh-history.XXXXXX"' in roots
    assert 'history_dir="$history_root/evidence"' in roots
    assert 'history_archive="$history_root/history.zip"' in roots
    assert 'test ! -e "$history_dir"' in roots
    assert 'test ! -e "$history_archive"' in roots
    assert "REFRESH_HISTORY_ARCHIVE" in roots
    assert (
        'staging_root="$(mktemp -d "$RUNNER_TEMP/mmaudit-model-refresh-staging.XXXXXX")"' in roots
    )
    assert 'staging_dir="$staging_root/evidence"' in roots
    assert 'test ! -e "$staging_dir"' in roots
    assert 'mktemp "$RUNNER_TEMP/mmaudit-operator-secrets.XXXXXX.env"' in secret
    assert "umask 077" in secret
    assert 'chmod 600 "$secret_file"' in secret
    assert "MMAUDIT_SECRETS_ENV_FILE" in secret
    assert "if: always()" in cleanup
    assert 'rm -f -- "$secret_file"' in cleanup
    assert workflow.index("Remove operator secret file") < workflow.index(
        "Stage exact non-secret refresh artifacts"
    )
    assert workflow.index("Resolve and validate prior durable refresh history") < workflow.index(
        "Prepare explicit operator secret file"
    )
    assert "github.token" in history


def test_provider_job_calls_only_the_metadata_refresh_model_command() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    refresh = _step_block(provider_job, "Refresh exact provider metadata and capture its gate")

    assert provider_job.count("mmaudit models refresh") == 1
    assert "--candidate-registry config/models.candidates.toml" in refresh
    assert "--previous-candidate-registry" in refresh
    assert "--previous-snapshot" in refresh
    assert "--previous-source-evidence" in refresh
    assert 'if [[ "$MMAUDIT_REFRESH_HISTORY_MODE" == "prior" ]]' in refresh
    assert '--secrets-env-file "$MMAUDIT_SECRETS_ENV_FILE"' in refresh
    assert '--output-dir "$REFRESH_OUTPUT_DIR"' in refresh
    assert "--soft-max-age-hours 30" in refresh
    assert "--hard-max-age-hours 72" in refresh
    assert "--pricing-tolerance-fraction 0.05" in refresh
    for prohibited in (
        "mmaudit doctor",
        "mmaudit models check",
        "mmaudit models benchmark",
        "mmaudit models qualify",
        "mmaudit run",
        "mmaudit audit",
    ):
        assert prohibited not in provider_job
    assert "MMAUDIT_RUN_REAL_PROVIDER_TESTS" not in provider_job


def test_refresh_stages_an_exact_status_dependent_non_secret_inventory() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    stage = _step_block(provider_job, "Stage exact non-secret refresh artifacts")
    upload = _step_block(provider_job, "Upload exact non-secret refresh evidence")

    assert "if: always()" in stage
    assert "python scripts/stage_model_refresh_artifacts.py" in stage
    assert '--output-dir "$REFRESH_OUTPUT_DIR"' in stage
    assert '--staging-dir "$REFRESH_STAGING_DIR"' in stage
    assert "--candidate-registry config/models.candidates.toml" in stage
    assert '--previous-history-dir "$REFRESH_HISTORY_DIR"' in stage
    assert '--expected-previous-workflow-run-id "$PREVIOUS_WORKFLOW_RUN_ID"' in stage
    assert '--expected-previous-workflow-run-attempt "$PREVIOUS_WORKFLOW_RUN_ATTEMPT"' in stage
    assert '--refresh-exit-status "$refresh_exit"' in stage
    assert '--source-commit "$WORKFLOW_SOURCE_COMMIT"' in stage
    assert '--workflow-run-id "$WORKFLOW_RUN_ID"' in stage
    assert '--workflow-run-attempt "$WORKFLOW_RUN_ATTEMPT"' in stage
    assert "--pricing-tolerance-fraction 0.05" in stage
    assert "--soft-max-age-hours 30" in stage
    assert "--hard-max-age-hours 72" in stage
    assert "stage_required" not in stage
    assert "install -m" not in stage
    assert "OPENROUTER_API_KEY" not in stage
    assert "MMAUDIT_SECRETS_ENV_FILE" not in stage
    assert "cp -a" not in stage
    assert '"$REFRESH_OUTPUT_DIR/."' not in stage
    assert "*" not in upload
    assert "mmaudit-model-refresh-${{ env.MMAUDIT_REFRESH_ARTIFACT_CLASS }}" in upload
    assert "path: ${{ env.REFRESH_STAGING_DIR }}" in upload
    assert "if-no-files-found: error" in upload
    assert "include-hidden-files: false" in upload


def test_refresh_failure_is_propagated_only_after_cleanup_staging_and_upload() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    refresh_index = provider_job.index("Refresh exact provider metadata and capture its gate")
    cleanup_index = provider_job.index("Remove operator secret file")
    stage_index = provider_job.index("Stage exact non-secret refresh artifacts")
    declaration_index = provider_job.index(
        "      - name: Declare durable refresh history publication requirement"
    )
    upload_index = provider_job.index("Upload exact non-secret refresh evidence")
    gate_index = provider_job.index("Propagate refresh and artifact gates")
    gate = _step_block(provider_job, "Propagate refresh and artifact gates")

    assert (
        refresh_index < cleanup_index < stage_index < declaration_index < upload_index < gate_index
    )
    assert 'refresh_exit="${MMAUDIT_REFRESH_EXIT:-70}"' in gate
    assert 'stage_exit="${MMAUDIT_REFRESH_STAGE_EXIT:-70}"' in gate
    assert 'exit "$refresh_exit"' in gate
    assert 'exit "$stage_exit"' in gate
    assert gate.index('exit "$stage_exit"') < gate.index('exit "$refresh_exit"')
    assert "if: always()" in gate


def test_history_lookup_is_default_branch_exact_and_accepts_blocked_success_bundles() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")
    stage = _step_block(provider_job, "Stage exact non-secret refresh artifacts")

    assert "/actions/workflows/mmaudit-model.yml/runs" in history
    assert '-f branch="$WORKFLOW_DEFAULT_BRANCH"' in history
    assert "-f status=completed" in history
    assert "-f status=success" not in history
    assert "--paginate" not in history
    assert "--slurp" not in history
    assert "max_history_runs=100" in history
    assert "max_attempts_per_run=10" in history
    assert "max_total_history_attempts=100" in history
    assert "max_repository_artifacts=1000" in history
    assert "max_history_archive_bytes=32000000" in history
    assert "ulimit -f 31250" in history
    assert "ulimit -f 62500" not in history
    assert "/actions/artifacts" in history
    assert 'eligible_run_ids=("$GITHUB_RUN_ID")' in history
    assert "lookup_eligible_run" in history
    assert '[[ "$run_id" -lt "$GITHUB_RUN_ID" ]]' in history
    assert "A newer successful refresh workflow attempt is missing its history artifact" in history
    assert "Declare durable refresh history publication requirement" in history
    assert "^mmaudit-model-refresh-history-([1-9][0-9]*)-([1-9][0-9]*)$" in history
    assert 'named_run_attempt="${BASH_REMATCH[2]}"' in history
    assert 'history_precedes_current "$named_run_id" "$named_run_attempt"' in history
    assert '"$named_run_id" -gt "$selected_run_id"' in history
    assert '"$named_run_attempt" -gt "$selected_run_attempt"' in history
    assert '"$artifact_expired" != "false"' in history
    assert "gh run download" not in history
    assert "/actions/artifacts/$selected_artifact_id/zip" in history
    assert "timeout --signal=KILL 120s gh api" in history
    assert "extract-history" in history
    assert '--archive "$REFRESH_HISTORY_ARCHIVE"' in history
    assert '--expected-archive-bytes "$observed_size"' in history
    assert "validate-history" in history
    assert '--expected-workflow-run-id "$selected_run_id"' in history
    assert '--expected-workflow-run-attempt "$selected_run_attempt"' in history
    assert '--expected-source-commit "$selected_source_commit"' in history
    assert "/actions/runs/$selected_run_id/attempts/$selected_run_attempt" in history
    assert "[.id, .run_attempt, .head_sha, .head_branch]" in history
    assert '"$attempt_branch" != "$WORKFLOW_DEFAULT_BRANCH"' in history
    assert "/actions/artifacts/$selected_artifact_id" in history
    assert ".size_in_bytes" in history
    assert '"$observed_source_commit" != "$selected_source_commit"' in history
    assert "sort_by(.id) | reverse[]" in history
    assert "/compare/$selected_source_commit...$GITHUB_SHA" in history
    assert '"$comparison_merge_base" != "$selected_source_commit"' in history
    assert "PREVIOUS_WORKFLOW_SOURCE_COMMIT=%s" in history
    assert '--expected-previous-source-commit "$PREVIOUS_WORKFLOW_SOURCE_COMMIT"' in stage
    assert 'chmod 600 "$REFRESH_HISTORY_ARCHIVE"' in history
    assert '"$refresh_exit" -eq 0 || "$refresh_exit" -eq 6' in stage
    assert "artifact_class=history" in stage


def test_history_lookup_captures_api_failures_before_bootstrap_decision() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")

    assert 'if ! eligible_runs_tsv="$(' in history
    assert 'if ! artifact_page_tsv="$(' in history
    assert 'if ! guarded_attempt_tsv="$(' in history
    assert "Prior refresh workflow history lookup failed" in history
    assert "Prior refresh artifact history lookup failed" in history
    assert "done < <(" not in history
    bootstrap_index = history.index('if [[ -z "$selected_run_id" ]]')
    assert history.index("Prior refresh workflow history lookup failed") < bootstrap_index
    assert history.index("Prior refresh artifact history lookup failed") < bootstrap_index


def test_history_lookup_selects_newest_artifact_attempt_and_uses_run_metadata_only_as_guard() -> (
    None
):
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")

    run_query = history[history.index("eligible_runs_tsv") : history.index("selected_run_id")]
    artifact_query = history[
        history.index("artifact_page_tsv") : history.index('if [[ "$selected_matches"')
    ]
    selection = history[history.index("artifact_records") :]
    assert '["RUN", (.id | tostring), (.run_attempt | tostring)]' in run_query
    assert ".workflow_runs" in run_query
    assert '["ARTIFACT", (.id | tostring)' in artifact_query
    assert ".artifacts[]" in artifact_query
    assert ".workflow_run.id" in artifact_query
    assert 'named_run_attempt="${BASH_REMATCH[2]}"' in selection
    assert 'selected_run_attempt="$named_run_attempt"' in selection
    assert "selected_matches=$((selected_matches + 1))" in selection
    assert "ambiguous history artifact" in selection


def _run_history_selector(
    tmp_path: Path,
    *,
    scenario: str,
    current_attempt: int = 1,
    event_name: str = "schedule",
    bootstrap: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")
    script = _run_script(history)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True)
    gh_stub = bin_dir / "gh"
    gh_stub.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            set -euo pipefail
            printf '%s\\n' "$*" >> "$GH_STUB_LOG"
            endpoint=""
            for argument in "$@"; do
              if [[ "$argument" == /repos/* ]]; then
                endpoint="$argument"
                break
              fi
            done
            case "$endpoint" in
              */actions/workflows/mmaudit-model.yml/runs)
                case "$GH_STUB_MODE" in
                  masked-success|masked-blocked|failed-fallback)
                    printf 'META\\t2\\t2\\nRUN\\t101\\t2\\nRUN\\t100\\t1\\n'
                    ;;
                  current-success|same-run-present)
                    printf 'META\\t1\\t1\\nRUN\\t100\\t1\\n'
                    ;;
                  *)
                    printf 'META\\t2\\t2\\nRUN\\t101\\t1\\nRUN\\t100\\t1\\n'
                    ;;
                esac
                ;;
              */actions/artifacts/*/zip)
                printf 'PK'
                ;;
              */actions/artifacts/1000)
                printf '1000\\t100\\t%s\\tmmaudit-model-refresh-history-100-1\\tfalse\\t1024\\n' \
                  "$GH_STUB_SOURCE_COMMIT"
                ;;
              */actions/artifacts/1001)
                printf '1001\\t101\\t%s\\tmmaudit-model-refresh-history-101-1\\tfalse\\t1024\\n' \
                  "$GH_STUB_SOURCE_COMMIT"
                ;;
              */actions/artifacts/2001)
                printf '2001\\t200\\t%s\\tmmaudit-model-refresh-history-200-1\\tfalse\\t1024\\n' \
                  "$GH_STUB_SOURCE_COMMIT"
                ;;
              */actions/artifacts)
                case "$GH_STUB_MODE" in
                  legacy-none|current-success)
                    printf 'META\\t0\\t0\\n'
                    ;;
                  latest-present)
                    printf 'META\\t2\\t2\\n'
                    printf 'ARTIFACT\\t1001\\t101\\tmmaudit-model-refresh-history-101-1\\tfalse\\t1024\\n'
                    printf 'ARTIFACT\\t1000\\t100\\tmmaudit-model-refresh-history-100-1\\tfalse\\t1024\\n'
                    ;;
                  same-run-present)
                    printf 'META\\t2\\t2\\n'
                    printf 'ARTIFACT\\t2001\\t200\\tmmaudit-model-refresh-history-200-1\\tfalse\\t1024\\n'
                    printf 'ARTIFACT\\t1000\\t100\\tmmaudit-model-refresh-history-100-1\\tfalse\\t1024\\n'
                    ;;
                  *)
                    printf 'META\\t1\\t1\\n'
                    printf 'ARTIFACT\\t1000\\t100\\tmmaudit-model-refresh-history-100-1\\tfalse\\t1024\\n'
                    ;;
                esac
                ;;
              */actions/runs/*/attempts/*/jobs)
                if [[ "$GH_STUB_MODE" == "masked-blocked" ]]; then
                  printf 'META\\t2\\t2\\nPROVIDER\\tcompleted\\tfailure\\t1\\tcompleted\\tsuccess\\n'
                elif [[ "$GH_STUB_MODE" == "no-provider-job" ]]; then
                  printf 'META\\t1\\t1\\n'
                else
                  printf 'META\\t2\\t2\\nPROVIDER\\tcompleted\\tfailure\\t0\\t\\t\\n'
                fi
                ;;
              */actions/runs/*/attempts/*)
                if [[ "$GH_STUB_MODE" == "api-failure" ]]; then
                  exit 93
                fi
                run_id="${endpoint%/attempts/*}"
                run_id="${run_id##*/runs/}"
                attempt_number="${endpoint##*/attempts/}"
                if [[ "$*" == *'.status'* ]]; then
                  conclusion=failure
                  case "$GH_STUB_MODE:$run_id:$attempt_number" in
                    masked-success:101:1|missing-newer:101:1|current-success:200:1)
                      conclusion=success
                      ;;
                  esac
                  printf '%s\\t%s\\t%s\\tmain\\tcompleted\\t%s\\n' \
                    "$run_id" "$attempt_number" "$GH_STUB_SOURCE_COMMIT" "$conclusion"
                else
                  printf '%s\\t%s\\t%s\\tmain\\n' \
                    "$run_id" "$attempt_number" "$GH_STUB_SOURCE_COMMIT"
                fi
                ;;
              *)
                exit 91
                ;;
            esac
            """
        ),
        encoding="utf-8",
    )
    gh_stub.chmod(0o755)
    python_stub = bin_dir / "python"
    python_stub.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    python_stub.chmod(0o755)
    timeout_stub = bin_dir / "timeout"
    timeout_stub.write_text(
        '#!/usr/bin/env bash\nset -euo pipefail\nshift 2\nexec "$@"\n',
        encoding="utf-8",
    )
    timeout_stub.chmod(0o755)
    source_commit = "a" * 40
    history_root = tmp_path / "history-root"
    history_root.mkdir(mode=0o700)
    github_env = tmp_path / "github-env"
    log_path = tmp_path / "gh.log"
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
        "GITHUB_ENV": str(github_env),
        "GITHUB_REPOSITORY": "synthetic/repository",
        "GITHUB_RUN_ATTEMPT": str(current_attempt),
        "GITHUB_RUN_ID": "200",
        "GITHUB_SHA": source_commit,
        "GH_STUB_LOG": str(log_path),
        "GH_STUB_MODE": scenario,
        "GH_STUB_SOURCE_COMMIT": source_commit,
        "REFRESH_HISTORY_ARCHIVE": str(history_root / "history.zip"),
        "REFRESH_HISTORY_DIR": str(history_root / "evidence"),
        "WORKFLOW_BOOTSTRAP_REQUESTED": str(bootstrap).lower(),
        "WORKFLOW_DEFAULT_BRANCH": "main",
        "WORKFLOW_EVENT_NAME": event_name,
    }
    completed = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", script],
        check=False,
        capture_output=True,
        env=environment,
        text=True,
    )
    return completed, github_env, log_path


def test_history_lookup_never_falls_back_past_a_newer_successful_run(tmp_path: Path) -> None:
    completed, github_env, _log = _run_history_selector(
        tmp_path,
        scenario="missing-newer",
        event_name="workflow_dispatch",
        bootstrap=True,
    )

    assert completed.returncode == 74
    assert "newer successful refresh workflow attempt" in completed.stdout
    assert not github_env.exists()


def test_history_lookup_detects_success_masked_by_a_later_failed_rerun(tmp_path: Path) -> None:
    completed, _github_env, log = _run_history_selector(tmp_path, scenario="masked-success")

    assert completed.returncode == 74
    assert "newer successful refresh workflow attempt" in completed.stdout
    assert "/runs/101/attempts/1" in log.read_text(encoding="utf-8")


def test_history_lookup_detects_deleted_production_blocked_history_marker(
    tmp_path: Path,
) -> None:
    completed, _github_env, log = _run_history_selector(tmp_path, scenario="masked-blocked")

    assert completed.returncode == 74
    assert "history-publishing refresh attempt" in completed.stdout
    assert "/runs/101/attempts/1/jobs" in log.read_text(encoding="utf-8")


def test_history_lookup_detects_missing_success_from_current_run_attempt(tmp_path: Path) -> None:
    completed, _github_env, log = _run_history_selector(
        tmp_path,
        scenario="current-success",
        current_attempt=2,
        event_name="workflow_dispatch",
        bootstrap=True,
    )

    assert completed.returncode == 74
    assert "newer successful refresh workflow attempt" in completed.stdout
    assert "/runs/200/attempts/1" in log.read_text(encoding="utf-8")


def test_history_lookup_propagates_attempt_api_failure(tmp_path: Path) -> None:
    completed, _github_env, _log = _run_history_selector(tmp_path, scenario="api-failure")

    assert completed.returncode == 74
    assert "attempt guard lookup failed" in completed.stdout


def test_history_lookup_preserves_failed_attempt_fallback(tmp_path: Path) -> None:
    completed, github_env, _log = _run_history_selector(tmp_path, scenario="failed-fallback")

    assert completed.returncode == 0, completed.stderr
    environment = github_env.read_text(encoding="utf-8")
    assert "PREVIOUS_WORKFLOW_RUN_ID=100\n" in environment
    assert "MMAUDIT_REFRESH_HISTORY_MODE=prior\n" in environment


def test_history_lookup_preserves_fallback_when_failed_attempt_has_no_provider_job(
    tmp_path: Path,
) -> None:
    completed, github_env, log = _run_history_selector(tmp_path, scenario="no-provider-job")

    assert completed.returncode == 0, completed.stderr
    environment = github_env.read_text(encoding="utf-8")
    assert "PREVIOUS_WORKFLOW_RUN_ID=100\n" in environment
    assert "/runs/101/attempts/1/jobs" in log.read_text(encoding="utf-8")


def test_history_lookup_accepts_latest_and_same_run_history_artifacts(tmp_path: Path) -> None:
    latest, latest_env, _latest_log = _run_history_selector(
        tmp_path / "latest",
        scenario="latest-present",
    )
    same_run, same_run_env, _same_run_log = _run_history_selector(
        tmp_path / "same-run",
        scenario="same-run-present",
        current_attempt=2,
    )

    assert latest.returncode == 0, latest.stderr
    assert "PREVIOUS_WORKFLOW_RUN_ID=101\n" in latest_env.read_text(encoding="utf-8")
    assert same_run.returncode == 0, same_run.stderr
    same_run_environment = same_run_env.read_text(encoding="utf-8")
    assert "PREVIOUS_WORKFLOW_RUN_ID=200\n" in same_run_environment
    assert "PREVIOUS_WORKFLOW_RUN_ATTEMPT=1\n" in same_run_environment


def test_legacy_success_without_history_preserves_only_explicit_manual_bootstrap(
    tmp_path: Path,
) -> None:
    manual, manual_env, _manual_log = _run_history_selector(
        tmp_path / "manual",
        scenario="legacy-none",
        event_name="workflow_dispatch",
        bootstrap=True,
    )
    scheduled, scheduled_env, _scheduled_log = _run_history_selector(
        tmp_path / "scheduled",
        scenario="legacy-none",
    )

    assert manual.returncode == 0, manual.stderr
    assert "MMAUDIT_REFRESH_HISTORY_MODE=bootstrap\n" in manual_env.read_text(encoding="utf-8")
    assert scheduled.returncode == 0, scheduled.stderr
    scheduled_environment = scheduled_env.read_text(encoding="utf-8")
    assert "MMAUDIT_REFRESH_HISTORY_MODE=missing\n" in scheduled_environment
    assert "MMAUDIT_REFRESH_EXIT=78\n" in scheduled_environment


def test_same_run_attempt_one_strictly_precedes_attempt_two() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")
    predicate = re.search(
        r"(?ms)^          history_precedes_current\(\) \{\n.*?^          \}\n",
        history,
    )
    assert predicate is not None
    probe = (
        textwrap.dedent(predicate.group(0))
        + """
GITHUB_RUN_ID=200
GITHUB_RUN_ATTEMPT=2
history_precedes_current 199 99 || exit 10
history_precedes_current 200 1 || exit 11
if history_precedes_current 200 2; then exit 12; fi
if history_precedes_current 200 3; then exit 13; fi
if history_precedes_current 201 1; then exit 14; fi
"""
    )

    completed = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", probe],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_missing_history_bootstrap_is_manual_explicit_and_non_overriding() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    history = _step_block(provider_job, "Resolve and validate prior durable refresh history")
    refresh = _step_block(provider_job, "Refresh exact provider metadata and capture its gate")
    secret = _step_block(provider_job, "Prepare explicit operator secret file")

    assert "bootstrap_without_history:" in workflow
    assert "required: true" in workflow
    assert "default: false" in workflow
    assert "type: boolean" in workflow
    assert '"$WORKFLOW_EVENT_NAME" == "workflow_dispatch"' in history
    assert '"$bootstrap_requested" == "true"' in history
    assert "explicit manual bootstrap accepted" in history
    assert "Durable refresh history exists; the bootstrap permission is ignored" in history
    assert "invalid-bootstrap" not in history
    assert "MMAUDIT_REFRESH_HISTORY_MODE=missing" in history
    assert "MMAUDIT_REFRESH_EXIT=78" in history
    assert "MMAUDIT_REFRESH_HISTORY_READY=true" in history
    assert "env.MMAUDIT_REFRESH_HISTORY_READY == 'true'" in secret
    assert "env.MMAUDIT_REFRESH_HISTORY_READY == 'true'" in refresh


def test_provider_free_job_exercises_local_artifact_and_diff_regressions() -> None:
    workflow = _read()
    local_job = _job_block(workflow, "refresh-artifact-validation")

    assert "environment:" not in local_job
    assert "secrets." not in local_job
    assert 'OPENROUTER_API_KEY: ""' in local_job
    assert 'MMAUDIT_RUN_REAL_PROVIDER_TESTS: "0"' in local_job
    assert "tests/unit/test_model_refresh.py" in local_job
    assert "tests/unit/test_model_refresh_cli.py" in local_job
    assert "tests/unit/test_model_refresh_schemas.py" in local_job
    assert "tests/unit/test_model_refresh_staging.py" in local_job
    assert "tests/unit/test_model_refresh_workflow.py" in local_job
    assert "python scripts/generate_release_schemas.py" in local_job
    assert "mmaudit models refresh" not in local_job
    assert "--secrets-env-file" not in local_job
