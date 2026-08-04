"""Static regressions for provider-free CI and fail-closed baseline admission."""

import hashlib
import json
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "mmaudit.yml"
PROVIDER_WORKFLOW = ROOT / ".github" / "workflows" / "mmaudit-model.yml"
README = ROOT / "README.md"
PUBLIC_REQUIRED_NAMES = frozenset(
    {
        "audit-results.sarif",
        "client-report.md",
        "coverage.json",
        "ci-state.json",
        "final-findings.json",
        "findings.json",
        "forensic-report.md",
        "maximum_assurance_traceability.json",
        "model-execution.json",
        "scanner-results.json",
    }
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


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


def _public_staging_python() -> str:
    workflow = _read(CI_WORKFLOW)
    scanner_job = _job_block(workflow, "scanner-only")
    step = _step_block(scanner_job, "Stage exact manifest-bound public evidence")
    marker = 'python - "$MMAUDIT_RUN_DIR" "$public_root" <<\'PY\'\n'
    _, separator, remainder = step.partition(marker)
    assert separator
    script, terminator, _ = remainder.partition("\n          PY")
    assert terminator
    return textwrap.dedent(script)


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _run_public_staging(
    tmp_path: Path,
    *,
    omitted: frozenset[str] = frozenset(),
    extra_public: frozenset[str] = frozenset(),
    prohibited: frozenset[str] = frozenset(),
) -> tuple[subprocess.CompletedProcess[str], Path]:
    source = tmp_path / "source"
    source.mkdir()
    names = sorted((PUBLIC_REQUIRED_NAMES - omitted) | extra_public | prohibited)
    bindings: list[dict[str, object]] = []
    for name in names:
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        data = (
            b'{"runs":[],"version":"2.1.0"}\n'
            if name == "audit-results.sarif"
            else f"artifact:{name}\n".encode()
        )
        path.write_bytes(data)
        bindings.append(
            {
                "path": name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    source_manifest = {
        "run_id": "synthetic-ci-run",
        "manifest_sha256": "a" * 64,
        "artifacts": bindings,
    }
    (source / "run-evidence-manifest.json").write_text(
        json.dumps(source_manifest, sort_keys=True),
        encoding="utf-8",
    )

    stub_root = tmp_path / "stub"
    package = stub_root / "mmaudit" / "orchestration"
    package.mkdir(parents=True)
    (stub_root / "mmaudit" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "manifest.py").write_text(
        """
import json
from types import SimpleNamespace

def load_run_evidence_manifest(path):
    payload = json.loads(path.read_text(encoding="utf-8"))
    return SimpleNamespace(
        run_id=payload["run_id"],
        manifest_sha256=payload["manifest_sha256"],
        artifacts=[SimpleNamespace(**item) for item in payload["artifacts"]],
    )
""".lstrip(),
        encoding="utf-8",
    )
    destination = tmp_path / "public"
    environment = {
        "PYTHONPATH": str(stub_root),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-c", _public_staging_python(), str(source), str(destination)],
        cwd=tmp_path,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )
    return completed, destination


def test_pull_request_workflow_is_provider_and_model_free() -> None:
    workflow = _read(CI_WORKFLOW)

    assert "pull_request:" in workflow
    assert "pull_request_target" not in workflow
    assert "OPENROUTER" not in workflow
    assert "secrets." not in workflow
    assert "mmaudit run" not in workflow
    assert "mmaudit models" not in workflow
    assert workflow.count("mmaudit ci") == 1
    assert "--secrets-env-file" not in workflow
    assert "MMAUDIT_RUN_REAL_PROVIDER_TESTS" not in workflow
    assert workflow.count("fetch-depth: 0") >= 2


def test_ci_workflow_binds_changed_since_and_optional_baseline() -> None:
    workflow = _read(CI_WORKFLOW)
    scanner_job = _job_block(workflow, "scanner-only")
    baseline_step = _step_block(scanner_job, "Validate and admit a successful baseline run")
    save_step = _step_block(scanner_job, "Save validated default-branch run candidate")

    assert '--changed-since "$BASE_SHA"' in workflow
    assert '--baseline-run "$BASELINE_RUN"' in workflow
    assert "run-evidence-manifest.json" in baseline_step
    assert "final-findings.json" in baseline_step
    assert "ci-state.json" in baseline_step
    assert '[[ ! -f "$path" || -L "$path" ]]' in baseline_step
    assert "admitted-success-commit" in baseline_step
    assert 'cmp --silent -- "$admission_marker"' in baseline_step
    assert "load_ci_baseline_bundle" in baseline_step
    assert "expected_repository_git_commit=sys.argv[2]" in baseline_step
    assert workflow.index("Install mmaudit") < workflow.index(
        "Validate and admit a successful baseline run"
    )
    assert "actions/cache/restore@" in workflow
    assert "actions/cache/save@" in workflow
    assert "needs: [quality]" in scanner_job
    assert re.search(r"(?m)^    if: always\(\)$", scanner_job)
    assert "success()" in save_step
    assert "needs.quality.result == 'success'" in save_step
    assert "github.event_name == 'push'" in save_step
    assert "github.event.repository.default_branch" in save_step
    assert "env.MMAUDIT_AUDIT_EXIT == '0'" in save_step
    assert "env.MMAUDIT_INTEGRITY_EXIT == '0'" in save_step
    assert "env.MMAUDIT_CACHE_ADMISSION_EXIT == '0'" in save_step
    assert "env.MMAUDIT_CACHE_READY == 'true'" in save_step


def test_failed_or_unusable_run_cannot_poison_the_baseline_cache() -> None:
    workflow = _read(CI_WORKFLOW)
    readme = _read(README)
    scanner_job = _job_block(workflow, "scanner-only")
    stage_step = _step_block(
        scanner_job,
        "Stage admissible public baseline bundle",
    )
    save_step = _step_block(scanner_job, "Save validated default-branch run candidate")
    gate_step = _step_block(scanner_job, "Propagate deterministic audit and evidence gates")

    assert 'audit_exit="${MMAUDIT_AUDIT_EXIT:-70}"' in stage_step
    assert 'discovery_exit="${MMAUDIT_RUN_DISCOVERY_EXIT:-70}"' in stage_step
    assert 'artifact_exit="${MMAUDIT_ARTIFACT_EXIT:-70}"' in stage_step
    assert 'integrity_exit="${MMAUDIT_INTEGRITY_EXIT:-70}"' in stage_step
    assert 'public_stage_exit="${MMAUDIT_PUBLIC_STAGE_EXIT:-70}"' in stage_step
    assert (
        '[[ "$audit_exit" -eq 0 && "$discovery_exit" -eq 0 &&\n'
        '                "$artifact_exit" -eq 0 && "$integrity_exit" -eq 0 &&\n'
        '                "$public_stage_exit" -eq 0 ]]'
    ) in stage_step
    assert "load_ci_baseline" in stage_step
    assert "load_ci_baseline_bundle" in stage_step
    assert "expected_repository_git_commit=sys.argv[2]" in stage_step
    assert '"$MMAUDIT_RUN_DIR" "$GITHUB_SHA"' in stage_step
    assert '"$staged_cache/run" "$GITHUB_SHA"' in stage_step
    assert "run-evidence-manifest.json" in stage_step
    assert "final-findings.json" in stage_step
    assert "ci-state.json" in stage_step
    assert "cp -a" not in stage_step
    assert '"$MMAUDIT_RUN_DIR/."' not in stage_step
    assert "private" not in stage_step
    assert "admitted-success-commit" in stage_step
    assert stage_step.index("load_ci_baseline") < stage_step.index("admitted-success-commit")
    assert stage_step.index("load_ci_baseline_bundle") < stage_step.index("admitted-success-commit")
    assert stage_step.index("admitted-success-commit") < stage_step.index(
        "MMAUDIT_CACHE_READY=true"
    )
    assert "env.MMAUDIT_AUDIT_EXIT == '0'" in save_step
    assert "env.MMAUDIT_RUN_DISCOVERY_EXIT == '0'" in save_step
    assert "env.MMAUDIT_ARTIFACT_EXIT == '0'" in save_step
    assert "env.MMAUDIT_INTEGRITY_EXIT == '0'" in save_step
    assert "env.MMAUDIT_PUBLIC_STAGE_EXIT == '0'" in save_step
    assert "env.MMAUDIT_CACHE_ADMISSION_EXIT == '0'" in save_step
    assert 'cache_admission_exit="${MMAUDIT_CACHE_ADMISSION_EXIT:-70}"' in gate_step
    assert 'public_stage_exit="${MMAUDIT_PUBLIC_STAGE_EXIT:-70}"' in gate_step
    assert '"$public_stage_exit" -ne 0' in gate_step
    assert '"$cache_admission_exit" -ne 0' in gate_step
    assert "never saved as an admissible cache" in readme
    assert "comparison-only optimization candidate" in readme


def test_ci_workflow_retains_evidence_before_propagating_failure() -> None:
    workflow = _read(CI_WORKFLOW)
    scanner_job = _job_block(workflow, "scanner-only")
    run_index = workflow.index("Run scanner-only CI audit and capture its gate")
    observe_index = workflow.index("Observe emitted public artifacts")
    verify_index = workflow.index("Verify emitted deterministic evidence")
    public_stage_index = workflow.index("Stage exact manifest-bound public evidence")
    baseline_stage_index = workflow.index("Stage admissible public baseline bundle")
    upload_index = workflow.index("Upload public scanner evidence")
    gate_index = workflow.index("Propagate deterministic audit and evidence gates")
    save_index = workflow.index("Save validated default-branch run candidate")

    assert (
        run_index
        < observe_index
        < verify_index
        < public_stage_index
        < baseline_stage_index
        < upload_index
        < gate_index
        < save_index
    )
    assert "MMAUDIT_AUDIT_EXIT" in workflow
    for name in (
        "Locate emitted run without accepting ambiguity",
        "Observe emitted public artifacts",
        "Verify emitted deterministic evidence",
        "Stage exact manifest-bound public evidence",
        "Stage admissible public baseline bundle",
        "Upload public scanner evidence",
        "Propagate deterministic audit and evidence gates",
    ):
        assert "if: always()" in _step_block(scanner_job, name)
    assert "if-no-files-found: warn" in workflow
    upload_step = _step_block(scanner_job, "Upload public scanner evidence")
    assert "${{ runner.temp }}/mmaudit-public-evidence" in upload_step
    assert ".mmaudit" not in upload_step
    assert "*" not in upload_step
    public_stage = _step_block(scanner_job, "Stage exact manifest-bound public evidence")
    assert "MMAUDIT_AUDIT_EXIT" not in public_stage
    gate_step = _step_block(scanner_job, "Propagate deterministic audit and evidence gates")
    assert 'exit "$audit_exit"' in gate_step
    assert "exit 70" in gate_step


def test_sarif_job_is_isolated_and_has_fork_artifact_fallback() -> None:
    workflow = _read(CI_WORKFLOW)
    sarif_job = _job_block(workflow, "upload-sarif")
    readme = _read(README)

    assert "actions/checkout@" not in sarif_job
    assert re.search(r"(?m)^\s+run:", sarif_job) is None
    assert "actions/download-artifact@" in sarif_job
    assert "github/codeql-action/upload-sarif@" in sarif_job
    assert "security-events: write" in sarif_job
    assert "github.event.pull_request.head.repo.full_name == github.repository" in sarif_job
    assert "continue-on-error: true" in sarif_job
    assert "needs.scanner-only.result == 'success'" not in sarif_job
    assert "needs.scanner-only.outputs.sarif_ready == 'true'" in sarif_job
    assert "sarif_file: reports/run/audit-results.sarif" in sarif_job
    assert "sarif_file: reports/runs" not in sarif_job
    assert "*" not in sarif_job
    scanner_job = _job_block(workflow, "scanner-only")
    public_stage = _step_block(scanner_job, "Stage exact manifest-bound public evidence")
    assert "id: public_stage" in public_stage
    assert "sarif_ready=false" in public_stage
    assert "sarif_ready=true" in public_stage
    assert "outputs:" in scanner_job
    assert "steps.public_stage.outputs.sarif_ready" in scanner_job
    assert '"audit-results.sarif"' in public_stage
    for artifact_name in (
        "client-report.md",
        "forensic-report.md",
        "findings.json",
        "coverage.json",
        "model-execution.json",
    ):
        assert f'"{artifact_name}"' in public_stage
    assert '"validated-sarif.json"' in public_stage
    assert "manifest-bound SARIF failed structural validation" in public_stage
    assert '"sarif_sha256": copied["audit-results.sarif"]' in public_stage
    assert "Fork pull requests" in readme
    assert "`mmaudit-scanner-reports` artifact is the explicit fallback" in readme


def test_repository_suite_policy_remains_hardened_and_fail_closed() -> None:
    workflow = _read(CI_WORKFLOW)
    readme = _read(README)

    assert "Install hardened local isolation" in workflow
    assert "bubblewrap" in workflow
    assert "forge test" not in workflow
    assert "npx hardhat" not in workflow
    assert "does not fall back to executing those suites directly on the host" in readme
    assert "unavailable/incomplete" in readme


def test_ci_output_and_public_artifacts_never_use_checkout_wildcards() -> None:
    workflow = _read(CI_WORKFLOW)
    scanner_job = _job_block(workflow, "scanner-only")
    output_step = _step_block(scanner_job, "Create fresh runner-temporary output root")
    run_step = _step_block(scanner_job, "Run scanner-only CI audit and capture its gate")
    locate_step = _step_block(scanner_job, "Locate emitted run without accepting ambiguity")
    public_stage = _step_block(scanner_job, "Stage exact manifest-bound public evidence")

    assert 'mktemp -d "$RUNNER_TEMP/mmaudit-output.XXXXXX"' in output_step
    assert 'case "$canonical_root" in' in output_step
    assert '"$RUNNER_TEMP"/*)' in output_step
    assert '--output "$MMAUDIT_OUTPUT_ROOT"' in run_step
    assert "--output .mmaudit" not in run_step
    assert '"$MMAUDIT_OUTPUT_ROOT/runs"' in locate_step
    assert "find .mmaudit" not in locate_step
    assert 'public_root="$RUNNER_TEMP/mmaudit-public-evidence"' in public_stage
    assert "required_public_names = frozenset({" in public_stage
    assert "public_artifact_allowlist = frozenset({" in public_stage
    assert "bindings.get(name)" in public_stage
    assert "hashlib.sha256(data).hexdigest() != binding.sha256" in public_stage
    assert 'prohibited_artifact_prefixes = ("logs/", "private/")' in public_stage
    assert 'bundle_kind": "NON_FORENSIC_PUBLIC_SUBSET"' in public_stage
    assert '"forensic_bundle_complete": False' in public_stage
    assert ".mmaudit/runs/*" not in workflow


def test_public_staging_requires_canonical_bundle_and_copies_all_allowlisted_leaves() -> None:
    workflow = _read(CI_WORKFLOW)
    scanner_job = _job_block(workflow, "scanner-only")
    public_stage = _step_block(scanner_job, "Stage exact manifest-bound public evidence")

    required_block, separator, allowlist_block = public_stage.partition(
        "public_artifact_allowlist = frozenset({"
    )
    assert separator
    for artifact_name in PUBLIC_REQUIRED_NAMES:
        assert f'"{artifact_name}"' in required_block
    for artifact_name in (
        "audit-report.md",
        "solidity-coverage.json",
        "solidity-graphs.json",
        "model-review-coverage.json",
        "reproduction-results.json",
    ):
        assert f'"{artifact_name}"' in allowlist_block
    assert "public_names = set(bindings) & public_artifact_allowlist" in public_stage
    assert "missing_required = sorted(required_public_names - public_names)" in public_stage
    assert "for name in sorted(public_names):" in public_stage


def test_public_staging_emits_a_self_contained_non_forensic_subset(tmp_path: Path) -> None:
    completed, destination = _run_public_staging(
        tmp_path,
        extra_public=frozenset({"solidity-graphs.json", "reproduction-results.json"}),
    )

    assert completed.returncode == 0, completed.stderr
    run = destination / "run"
    subset_path = run / "public-evidence-subset-manifest.json"
    subset = json.loads(subset_path.read_text(encoding="utf-8"))
    subset_hash = subset.pop("subset_manifest_sha256")
    assert subset_hash == _canonical_sha256(subset)
    assert subset["bundle_kind"] == "NON_FORENSIC_PUBLIC_SUBSET"
    assert subset["forensic_bundle_complete"] is False
    assert subset["omitted_artifact_classes"] == ["logs/**", "private/**"]
    inventory = subset["artifacts"]
    assert subset["artifact_inventory_sha256"] == _canonical_sha256(inventory)
    expected = {
        *PUBLIC_REQUIRED_NAMES,
        "reproduction-results.json",
        "run-evidence-manifest.json",
        "solidity-graphs.json",
    }
    assert {entry["path"] for entry in inventory} == expected
    assert {path.name for path in run.iterdir()} == {
        *expected,
        "public-evidence-subset-manifest.json",
    }
    for entry in inventory:
        data = (run / entry["path"]).read_bytes()
        assert len(data) == entry["size"]
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]


def test_public_staging_fails_when_a_required_manifest_leaf_is_omitted(tmp_path: Path) -> None:
    completed, destination = _run_public_staging(
        tmp_path,
        omitted=frozenset({"coverage.json"}),
    )

    assert completed.returncode != 0
    assert "manifest omits required public artifacts: coverage.json" in completed.stderr
    assert not (destination / "run" / "public-evidence-subset-manifest.json").exists()


@pytest.mark.parametrize("prefix", ["private", "logs"])
def test_public_staging_excludes_prohibited_manifest_artifacts(
    tmp_path: Path,
    prefix: str,
) -> None:
    prohibited_name = f"{prefix}/synthetic-custody.json"
    completed, destination = _run_public_staging(
        tmp_path,
        prohibited=frozenset({prohibited_name}),
    )

    assert completed.returncode == 0, completed.stderr
    run = destination / "run"
    assert not (run / prefix).exists()
    subset = json.loads((run / "public-evidence-subset-manifest.json").read_text(encoding="utf-8"))
    assert prohibited_name not in {entry["path"] for entry in subset["artifacts"]}
    assert subset["omitted_prohibited_artifact_count"] == 1


def test_provider_workflow_is_separate_and_never_runs_on_pull_requests() -> None:
    ci_workflow = _read(CI_WORKFLOW)
    provider_workflow = _read(PROVIDER_WORKFLOW)
    provider_job = _job_block(provider_workflow, "provider-check")

    assert "OPENROUTER_API_KEY" not in ci_workflow
    assert "OPENROUTER_API_KEY" in provider_workflow
    assert "pull_request" not in provider_workflow
    assert "pull_request_target" not in provider_workflow
    assert "workflow_dispatch:" in provider_workflow
    assert "schedule:" in provider_workflow
    assert "environment: mmaudit-provider" in provider_job
    assert (
        "if: github.ref == format('refs/heads/{0}', github.event.repository.default_branch)"
    ) in provider_job
    assert "--secrets-env-file" in provider_workflow
    assert 'mktemp "$RUNNER_TEMP/mmaudit-operator-secrets.' in provider_workflow
    assert "always()" in provider_workflow
    readme = _read(README)
    assert "required\nreviewers and a default-branch deployment rule" in readme


def test_all_third_party_actions_are_commit_pinned() -> None:
    for path in (CI_WORKFLOW, PROVIDER_WORKFLOW):
        workflow = _read(path)
        action_refs = re.findall(r"(?m)^\s*(?:-\s*)?uses:\s+([^#\s]+)", workflow)
        assert action_refs
        for action_ref in action_refs:
            assert re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_./-]+@[0-9a-f]{40}", action_ref), (
                f"{path.name} has a mutable or malformed action reference: {action_ref}"
            )
