"""Actual maximum-width repeats over existing synthetic source and constructed line labels."""

import json
from decimal import Decimal
from pathlib import Path

from mmaudit.models.development_corpus_repeats import prepare_development_corpus_repeats
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.models.endpoint_snapshots import validate_openrouter_endpoint_snapshot
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_corpus_resume_score_support import maximum_scoring_case
from tests.development_corpus_support import CORPUS_MODEL
from tests.development_review_support import SYNTHETIC_CREDENTIAL


def maximum_repeat_case(*, capacity_quote):
    """Freeze eight real candidate plans; construct responses, never passing final observations."""

    candidate, labels, responses = maximum_scoring_case()
    first = candidate.shards[0]
    metadata = first.discovery or first.endpoint_snapshot
    if capacity_quote:
        path = (
            Path(__file__).parent
            / "fixtures/model_responses/development_repeat_capacity_quote.json"
        )
        endpoint = json.loads(path.read_bytes())["endpoint"]
        metadata = validate_openrouter_endpoint_snapshot(
            exact_model_id=CORPUS_MODEL,
            configured_provider_endpoints=(endpoint["tag"],),
            provider_policy_mode="only",
            endpoint_payload={"data": {"id": CORPUS_MODEL, "endpoints": [endpoint]}},
            require_zdr=True,
            zdr_payload={"data": [{**endpoint, "model_id": CORPUS_MODEL}]},
        )
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("250"),
        per_attempt_budget_usd=Decimal("5"),
    )
    prepared = prepare_development_corpus_repeats(
        policy=policy,
        endpoint_snapshot=metadata,
        manifest=candidate.plan.manifest,
        source_files=first.source_files,
        run_id="synthetic-maximum-repeat-series",
        trial_count=8,
        truth_content=labels.truth_file_content.encode(),
        expected_truth_sha256=labels.truth_file_sha256,
        maximum_completion_tokens=4096,
        maximum_trial_seconds=1800.0,
        maximum_run_seconds=1800.0,
    )
    return prepared, responses


def maximum_repeat_cli_inputs(tmp_path):
    prepared, responses = maximum_repeat_case(capacity_quote=True)
    first = prepared.trials[0].shards[0]
    root = tmp_path / "synthetic-corpus"
    root.mkdir(mode=0o700)
    for name, raw in first.source_files:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    manifest = tmp_path / "synthetic-source-manifest.json"
    manifest.write_text(prepared.plan.trials[0].manifest.model_dump_json())
    metadata = tmp_path / "synthetic-metadata.json"
    metadata.write_text((first.discovery or first.endpoint_snapshot).model_dump_json())
    labels = tmp_path / "synthetic-labels.json"
    labels.write_bytes(prepared.plan.benchmark.truth_file_content.encode())
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    secret = tmp_path / "synthetic-secrets.txt"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    output = tmp_path / "run"
    fields = dict(
        source_manifest=manifest,
        corpus_root=root,
        endpoint_snapshot=metadata,
        truth_manifest=labels,
        truth_sha256=prepared.plan.benchmark.truth_file_sha256,
        cost_ledger=ledger.path,
        secrets_env_file=secret,
        output_dir=output,
        run_id=prepared.plan.run_id,
        trial_count=8,
        budget_usd="250",
        per_attempt_usd="5",
        maximum_completion_tokens=4096,
        maximum_trial_seconds=1800,
        maximum_run_seconds=1800,
    )
    args = ["development", "repeat-manifest"]
    for name, value in fields.items():
        args += ["--" + name.replace("_", "-"), str(value)]
    args += ["--accept-estimate-risk", "--allow-code-egress"]
    return args, prepared, responses, ledger, output
