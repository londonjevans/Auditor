"""Static regressions for the protected model-metadata refresh workflow."""

import re
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


def test_refresh_runs_daily_only_on_the_default_branch_and_protected_environment() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")

    assert 'cron: "17 3 * * *"' in workflow
    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "environment: mmaudit-provider" in provider_job
    assert (
        "if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
        in provider_job
    )
    assert "permissions:\n  contents: read" in workflow
    assert "needs: [refresh-artifact-validation]" in provider_job


def test_refresh_uses_explicit_secret_file_and_fresh_runner_temporary_roots() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    roots = _step_block(provider_job, "Create fresh runner-temporary refresh roots")
    secret = _step_block(provider_job, "Prepare explicit operator secret file")
    cleanup = _step_block(provider_job, "Remove operator secret file")

    assert 'mktemp -d "$RUNNER_TEMP/mmaudit-model-refresh-root.XXXXXX"' in roots
    assert 'output_dir="$refresh_root/output"' in roots
    assert 'test ! -e "$output_dir"' in roots
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


def test_provider_job_calls_only_the_metadata_refresh_model_command() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    refresh = _step_block(provider_job, "Refresh exact provider metadata and capture its gate")

    assert provider_job.count("mmaudit models refresh") == 1
    assert "--candidate-registry config/models.candidates.toml" in refresh
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
    assert "path: ${{ env.REFRESH_STAGING_DIR }}" in upload
    assert "if-no-files-found: error" in upload
    assert "include-hidden-files: false" in upload


def test_refresh_failure_is_propagated_only_after_cleanup_staging_and_upload() -> None:
    workflow = _read()
    provider_job = _job_block(workflow, "provider-check")
    refresh_index = provider_job.index("Refresh exact provider metadata and capture its gate")
    cleanup_index = provider_job.index("Remove operator secret file")
    stage_index = provider_job.index("Stage exact non-secret refresh artifacts")
    upload_index = provider_job.index("Upload exact non-secret refresh evidence")
    gate_index = provider_job.index("Propagate refresh and artifact gates")
    gate = _step_block(provider_job, "Propagate refresh and artifact gates")

    assert refresh_index < cleanup_index < stage_index < upload_index < gate_index
    assert 'refresh_exit="${MMAUDIT_REFRESH_EXIT:-70}"' in gate
    assert 'stage_exit="${MMAUDIT_REFRESH_STAGE_EXIT:-70}"' in gate
    assert 'exit "$refresh_exit"' in gate
    assert 'exit "$stage_exit"' in gate
    assert gate.index('exit "$stage_exit"') < gate.index('exit "$refresh_exit"')
    assert "if: always()" in gate


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
