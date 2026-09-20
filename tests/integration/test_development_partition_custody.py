"""Original and derived synthetic trees remain inseparable through ordinary source consumers."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace

import httpx
import pytest
from typer.testing import CliRunner

from mmaudit import development_cli
from mmaudit.cli import app
from mmaudit.models.development_corpus_coverage import (
    compute_development_corpus_coverage,
    read_development_corpus_coverage,
)
from mmaudit.models.development_corpus_partition import derive_development_corpus_partition
from mmaudit.models.development_corpus_resume import prepare_development_corpus_resume
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger, CostEntryStatus
from mmaudit.orchestration.development_corpus import run_development_corpus
from mmaudit.orchestration.development_corpus_coverage import (
    measure_development_corpus_coverage_files,
)
from mmaudit.orchestration.development_corpus_resume import (
    read_development_corpus_resume_inputs,
    run_development_corpus_resume,
)
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from mmaudit.repository.development_corpus_partition import (
    load_development_corpus_partition,
    materialize_development_corpus_partition,
)
from tests.development_corpus_ensemble_support import manifest_ensemble_case
from tests.development_corpus_judgment_support import selected_policy
from tests.development_corpus_support import corpus_payload
from tests.development_review_support import SYNTHETIC_CREDENTIAL
from tests.integration.test_development_corpus_ensemble_execution import (
    execute,
    execution_case,
    response_payload,
    retained,
)
from tests.unit.test_development_context_sources import partitioned_tree, prepared_partition
from tests.unit.test_development_corpus_coverage import candidate


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("partition work attempted network, subprocess or secret loading")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(development_cli, "load_operator_secrets", forbidden)


def bundle(tmp_path, primaries=("src/IReserve.sol",)):
    tmp_path.mkdir(parents=True, exist_ok=True)
    reference = partitioned_tree(tmp_path / "original")
    partition = derive_development_corpus_partition(
        reference=reference.material, primary_filenames=primaries
    )
    loaded = materialize_development_corpus_partition(
        reference=reference, partition=partition, output_dir=tmp_path / "bundle"
    )
    return reference, partition, loaded


def test_materialization_retains_exact_private_minimal_sources(tmp_path):
    reference, partition, loaded = bundle(tmp_path)
    assert loaded.material.manifest == partition.manifest
    assert loaded.material.source_files == (
        ("src/IReserve.sol", dict(reference.material.source_files)["src/IReserve.sol"]),
    )
    assert loaded.partition_custody.reference is reference
    assert loaded.corpus_root.stat().st_mode & 0o777 == 0o700
    assert (loaded.corpus_root / "src/IReserve.sol").stat().st_mode & 0o777 == 0o600
    revalidate_loaded_development_corpus(loaded)


def test_origin_custody_cannot_be_stripped_from_a_derived_bundle(tmp_path):
    _, _, loaded = bundle(tmp_path)
    with pytest.raises(ValueError, match="origin"):
        revalidate_loaded_development_corpus(replace(loaded, partition_custody=None))


def test_plain_loader_cannot_detach_a_derived_origin(tmp_path):
    _, _, loaded = bundle(tmp_path)
    with pytest.raises(ValueError, match="origin"):
        load_development_corpus(manifest_file=loaded.manifest_file, corpus_root=loaded.corpus_root)


def test_bound_loader_restores_the_same_reference_for_later_invocations(tmp_path):
    reference, recipe, loaded = bundle(tmp_path)
    restored = load_development_corpus_partition(
        reference=reference,
        partition_file=tmp_path / "bundle/partition.json",
        manifest_file=loaded.manifest_file,
        corpus_root=loaded.corpus_root,
    )
    assert restored.material == loaded.material
    assert restored.partition_custody.partition == recipe
    assert prepared_partition(restored).plan == prepared_partition(loaded).plan


@pytest.mark.parametrize(
    "mutation",
    [
        "original_bytes",
        "original_inode",
        "added_original_source",
        "bundle_bytes",
        "recipe_bytes",
        "recipe_inode",
    ],
)
def test_origin_or_bundle_drift_refuses_preparation(tmp_path, mutation):
    reference, _, loaded = bundle(tmp_path)
    if mutation.startswith("original"):
        path = reference.corpus_root / "src/Controller.sol"
    elif mutation.startswith("recipe"):
        path = tmp_path / "bundle/partition.json"
    else:
        path = loaded.corpus_root / "src/IReserve.sol"
    if mutation == "added_original_source":
        (reference.corpus_root / "Added.sol").write_bytes(
            b"// Synthetic namespace control.\ncontract Added {}\n"
        )
    elif mutation.endswith("inode"):
        content = path.read_bytes()
        path.rename(tmp_path / "retained-previous-file")
        path.write_bytes(content)
        assert path.read_bytes() == content
    else:
        path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        prepared_partition(loaded)


@pytest.mark.parametrize("mutation", ["missing", "nested", "wrong_type"])
def test_original_custody_cannot_be_replaced_or_nested(tmp_path, mutation):
    _, _, loaded = bundle(tmp_path)
    custody = loaded.partition_custody
    selected = (
        None
        if mutation == "missing"
        else replace(custody, reference=loaded)
        if mutation == "nested"
        else object()
    )
    with pytest.raises(ValueError):
        prepared_partition(replace(loaded, partition_custody=selected))


@pytest.mark.parametrize(
    "failure", ["existing", "inside_origin", "origin_inside_output", "relative", "symlink"]
)
def test_materializer_refuses_unsafe_output_before_copying_sources(tmp_path, failure):
    reference = partitioned_tree(tmp_path / "original")
    recipe = derive_development_corpus_partition(
        reference=reference.material, primary_filenames=("src/IReserve.sol",)
    )
    output = tmp_path / "output"
    if failure == "existing":
        output.mkdir()
        (output / "keep").write_bytes(b"preserve synthetic marker")
    elif failure == "inside_origin":
        output = reference.corpus_root / "output"
    elif failure == "origin_inside_output":
        output = tmp_path
    elif failure == "relative":
        output = output.relative_to(tmp_path)
    else:
        parent = tmp_path / "alias"
        parent.symlink_to(tmp_path / "original", target_is_directory=True)
        output = parent / "output"
    with pytest.raises((ValueError, FileExistsError)):
        materialize_development_corpus_partition(
            reference=reference, partition=recipe, output_dir=output
        )
    revalidate_loaded_development_corpus(reference)
    if failure == "existing":
        assert (output / "keep").read_bytes() == b"preserve synthetic marker"


@pytest.mark.asyncio
@pytest.mark.parametrize("claims", [0, 1])
async def test_minimal_bundle_reaches_candidate_and_both_reviewers(tmp_path, claims):
    reference, recipe, loaded = bundle(tmp_path, ("src/Reserve.sol",))
    prepared = manifest_ensemble_case(
        source_files=loaded.material.source_files,
        manifest=loaded.material.manifest,
        policy=selected_policy(total="60", per_attempt="3"),
        source_custody=loaded,
    )
    case = execution_case(tmp_path, prepared=prepared, scored=False, claims=claims)
    primary = prepared.candidate.shards[0]

    def inspect(role, ordinal, request):
        prompt = json.loads(request.content)["messages"][1]["content"]
        assert "Both original and bundle roots require replay" in prompt
        assert recipe.reference_manifest_sha256 in prompt
        assert "Source file: src/Controller.sol" not in prompt
        for path, _ in loaded.material.source_files:
            assert "Source file: " + path in prompt
        value = response_payload(prepared, role, ordinal, claims=claims)
        value["choices"][0]["message"]["content"] = value["choices"][0]["message"][
            "content"
        ].replace("file-0001", primary.shard_id)
        return httpx.Response(200, json=value)

    result = await execute(case, custom=inspect)
    assert result == retained(case)
    assert case.counts == ([1, 1, 1] if claims else [1, 0, 0])
    assert len(case.ledger.snapshot().entries) == (3 if claims else 1)
    assert not result.audit_complete
    revalidate_loaded_development_corpus(reference)


@pytest.mark.asyncio
async def test_original_drift_after_preparation_refuses_before_any_reservation(tmp_path):
    reference, _, loaded = bundle(tmp_path)
    prepared = prepared_partition(loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    path = reference.corpus_root / "src/Controller.sol"
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(ValueError):
        await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(lambda _: pytest.fail("source drift dispatched")),
        )
    assert not ledger.snapshot().entries and not (tmp_path / "run").exists()


@pytest.mark.asyncio
async def test_mid_request_original_drift_preserves_cost_but_cannot_credit_response(tmp_path):
    reference, _, loaded = bundle(tmp_path)
    prepared = prepared_partition(loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )

    def reply(_request):
        path = reference.corpus_root / "src/Controller.sol"
        path.write_bytes(path.read_bytes() + b"\n")
        return httpx.Response(200, json=corpus_payload(1, count=0))

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(reply),
    )
    assert result.status == "INCOMPLETE" and result.completed_shard_count == 0
    assert len(ledger.snapshot().entries) == 1
    assert ledger.snapshot().entries[0].status is CostEntryStatus.RECONCILED
    assert result.total_accounted_cost_usd > 0


@pytest.mark.asyncio
@pytest.mark.parametrize("unknown", [False, True])
async def test_origin_bound_continuation_preserves_original_evidence_and_billing_stop(
    tmp_path, unknown
):
    reference, recipe, loaded = bundle(tmp_path)
    prepared = prepared_partition(loaded)
    ledger = AtomicCostLedger.initialize(
        tmp_path / "ledger.json", cap_usd=prepared.plan.policy.total_budget_usd
    )
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})

    def failure(_request):
        if unknown:
            return httpx.Response(429, json={"error": {"message": "Synthetic missing usage."}})
        value = corpus_payload(1, count=0)
        value["choices"][0]["message"]["content"] = "{}"
        return httpx.Response(200, json=value)

    original = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(failure),
    )
    original_bytes = (tmp_path / "run/result.json").read_bytes()
    original_rows = ledger.snapshot().entries
    inputs = read_development_corpus_resume_inputs(
        candidate_file=tmp_path / "run/result.json", material_file=tmp_path / "run/sources.json"
    )
    restored = load_development_corpus_partition(
        reference=reference,
        partition_file=tmp_path / "bundle/partition.json",
        manifest_file=loaded.manifest_file,
        corpus_root=loaded.corpus_root,
    )
    continuation = prepare_development_corpus_resume(
        history=inputs.history,
        endpoint_snapshot=prepared.shards[0].endpoint_snapshot,
        run_id="synthetic-derived-continuation",
        source_custody=restored,
    )

    def success(_request):
        if unknown:
            pytest.fail("unknown billing stop was bypassed")
        value = corpus_payload(1, count=0)
        value["id"] = "gen-synthetic-derived-continuation"
        return httpx.Response(200, json=value)

    if unknown:
        with pytest.raises(ValueError):
            await run_development_corpus_resume(
                prepared=continuation,
                ledger=ledger,
                operator_secrets=secrets,
                output_dir=tmp_path / "continued",
                allow_code_egress=True,
                mock_transport=httpx.MockTransport(success),
                inputs=inputs,
            )
        record = original
        assert ledger.snapshot().entries == original_rows
    else:
        record = await run_development_corpus_resume(
            prepared=continuation,
            ledger=ledger,
            operator_secrets=secrets,
            output_dir=tmp_path / "continued",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(success),
            inputs=inputs,
        )
        assert record.original == original and record.summary.cumulative_completed_shard_count == 1
    assert (tmp_path / "run/result.json").read_bytes() == original_bytes
    rows = {e.request_id: e for e in ledger.snapshot().entries}
    assert all(rows[e.request_id] == e for e in original_rows)
    covered = compute_development_corpus_coverage(
        reference=reference.material, records=(record,), partitions=(recipe,)
    )
    assert covered.summary.successful_primary_paths == (() if unknown else ("src/IReserve.sol",))
    assert not covered.summary.original_first_attempt_complete
    assert covered.summary.status == "INCOMPLETE"


def test_offline_coverage_cli_replays_explicit_partition_and_preserves_original_files(tmp_path):
    reference, recipe, loaded = bundle(tmp_path)
    _, observed = candidate(loaded)
    record = tmp_path / "observed.json"
    record.write_text(observed.model_dump_json())
    original_bytes = record.read_bytes()
    output = tmp_path / "coverage"
    result = CliRunner().invoke(
        app,
        [
            "development",
            "corpus-coverage",
            "--manifest-file",
            str(reference.manifest_file),
            "--corpus-root",
            str(reference.corpus_root),
            "--record-file",
            str(record),
            "--partition-file",
            str(tmp_path / "bundle/partition.json"),
            "--output-dir",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    covered = read_development_corpus_coverage((output / "coverage.json").read_bytes())
    assert covered.schema_version == "1.1" and covered.partitions == (recipe,)
    assert covered.summary.successful_primary_paths == ("src/IReserve.sol",)
    assert len(covered.summary.unselected_paths) == 4
    assert record.read_bytes() == original_bytes
    assert output.stat().st_mode & 0o777 == 0o700
    assert (output / "coverage.json").stat().st_mode & 0o777 == 0o600


def test_missing_partition_keeps_derived_primary_uncredited(tmp_path):
    reference, _, loaded = bundle(tmp_path)
    _, observed = candidate(loaded)
    covered = compute_development_corpus_coverage(reference=reference.material, records=(observed,))
    assert covered.summary.successful_primary_paths == ()
    assert "SOURCE_ORIGIN_NOT_REPLAYED" in covered.run_coverage[0].identity_shortfalls
    assert covered.summary.invalidated_primary_paths == ("src/IReserve.sol",)


def test_coverage_refuses_changed_partition_file_before_output(tmp_path):
    reference, recipe, loaded = bundle(tmp_path)
    _, observed = candidate(loaded)
    record = tmp_path / "observed.json"
    record.write_text(observed.model_dump_json())
    data = recipe.model_dump(mode="json")
    data["reference_tree_sha256"] = "0" * 64
    (tmp_path / "bundle/partition.json").write_text(json.dumps(data))
    with pytest.raises(ValueError):
        measure_development_corpus_coverage_files(
            manifest_file=reference.manifest_file,
            corpus_root=reference.corpus_root,
            record_files=(record,),
            partition_files=(tmp_path / "bundle/partition.json",),
            output_dir=tmp_path / "coverage",
        )
    assert not (tmp_path / "coverage").exists()
