"""Repeat only existing paired synthetic source/labels; no external truth or provider execution."""

from decimal import Decimal

from mmaudit.models.development_corpus_repeats import prepare_development_corpus_repeats
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from tests.development_corpus_benchmark_support import paired_case, paired_payload, truth_binding
from tests.development_review_support import SYNTHETIC_CREDENTIAL


def repeat_case(**changes):
    candidate = paired_case()
    binding = truth_binding(candidate)
    first = candidate.shards[0]
    values = dict(
        policy=candidate.plan.policy,
        endpoint_snapshot=first.discovery or first.endpoint_snapshot,
        manifest=candidate.plan.manifest,
        source_files=first.source_files,
        run_id="synthetic-repeat-series",
        trial_count=2,
        truth_content=binding.truth_file_content.encode(),
        expected_truth_sha256=binding.truth_file_sha256,
    )
    values.update(changes)
    return prepare_development_corpus_repeats(**values)


def repeat_payload(ordinal, primary_index=None):
    payload = paired_payload(primary_index or (ordinal - 1) % 6 + 1)
    payload["id"] = f"gen-synthetic-repeat-{ordinal}"
    return payload


def repeat_input_files(tmp_path, *, count=2, budget="20", metadata=None):
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal(budget),
        per_attempt_budget_usd=Decimal("5"),
    )
    changes = {} if metadata is None else {"endpoint_snapshot": metadata}
    prepared = repeat_case(trial_count=count, policy=policy, **changes)
    first = prepared.trials[0].shards[0]
    root = tmp_path / "corpus"
    root.mkdir(mode=0o700)
    for name, raw in first.source_files:
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    manifest = tmp_path / "source-manifest.json"
    manifest.write_text(prepared.plan.trials[0].manifest.model_dump_json())
    endpoint = tmp_path / "metadata.json"
    endpoint.write_text((first.discovery or first.endpoint_snapshot).model_dump_json())
    truth = tmp_path / "truth.json"
    truth.write_bytes(prepared.plan.benchmark.truth_file_content.encode())
    ledger = AtomicCostLedger.initialize(tmp_path / "repeat-ledger.json", cap_usd=Decimal(budget))
    secret = tmp_path / "synthetic-secrets.txt"
    secret.write_text("OPENROUTER_API_KEY=" + SYNTHETIC_CREDENTIAL + "\n")
    secret.chmod(0o600)
    arguments = dict(
        source_manifest=manifest,
        corpus_root=root,
        endpoint_snapshot=endpoint,
        truth_manifest=truth,
        truth_sha256=prepared.plan.benchmark.truth_file_sha256,
        policy=policy,
        run_id=prepared.plan.run_id,
        trial_count=count,
    )
    return arguments, ledger, secret, tmp_path / "run"
