"""Real local custody and runtime handoffs for synthetic protocol-labelled capacity fixtures."""

from __future__ import annotations

import json
import socket
import subprocess
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import NoReturn

import httpx
import pytest

from mmaudit.models.development_corpus import (
    MAX_DEVELOPMENT_CORPUS_BYTES,
    MAX_DEVELOPMENT_CORPUS_FILE_BYTES,
    MAX_DEVELOPMENT_CORPUS_RESULT_BYTES,
    DevelopmentCorpusMaterial,
    DevelopmentCorpusObservation,
    DevelopmentCorpusText,
    freeze_development_corpus,
)
from mmaudit.models.development_corpus_judgment import prepare_development_corpus_judgment
from mmaudit.models.development_corpus_resume import (
    freeze_development_corpus_resume_history,
    prepare_development_corpus_resume,
)
from mmaudit.models.development_costs import DevelopmentCostPolicy
from mmaudit.operator_secrets import OperatorSecrets
from mmaudit.orchestration.cost_ledger import AtomicCostLedger
from mmaudit.orchestration.development_audit import _write as write_fixed_fixture
from mmaudit.orchestration.development_corpus import _write, run_development_corpus
from mmaudit.repository.development_corpus import (
    load_development_corpus,
    revalidate_loaded_development_corpus,
)
from tests.development_corpus_protocol_support import capacity_metadata, protocol_sources
from tests.development_corpus_support import corpus_case, corpus_payload
from tests.development_judgment_support import judgment_metadata
from tests.development_review_support import SYNTHETIC_CREDENTIAL


@pytest.fixture(autouse=True)
def no_external_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("protocol-labelled synthetic control attempted real network/process execution")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.mark.parametrize("size,count", [(189_779, 11), (262_144, 1), (None, 256)])
def test_loader_retains_every_larger_source_and_refuses_later_drift(
    tmp_path: Path, size: int | None, count: int
) -> None:
    sources = protocol_sources(count, size=size)
    root = tmp_path / "corpus"
    root.mkdir(mode=0o700)
    for name, raw in sources:
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(raw)
    manifest = freeze_development_corpus(
        corpus_id="synthetic-local", source_scope="OPERATOR_SUPPLIED_PROTOCOL", source_files=sources
    )
    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())
    loaded = load_development_corpus(manifest_file=path, corpus_root=root)
    assert loaded.material.source_files == sources
    assert loaded.material.manifest.source_scope == "OPERATOR_SUPPLIED_PROTOCOL"
    assert len(loaded.source_bindings) == count
    (root / sources[-1][0]).write_bytes(sources[-1][1] + b"\n")
    with pytest.raises(ValueError):
        revalidate_loaded_development_corpus(loaded)
    assert loaded.material.source_files == sources


@pytest.mark.asyncio
@pytest.mark.parametrize("count,claims,size", [(1, 1, 189_779), (65, 16, None), (256, 0, None)])
async def test_protocol_prompt_larger_scope_and_results_survive_exact_mock_runtime(
    tmp_path: Path, count: int, claims: int, size: int | None
) -> None:
    sources = protocol_sources(count, size=size)
    manifest = freeze_development_corpus(
        corpus_id="synthetic-runtime",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=sources,
    )
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("250"),
        per_attempt_budget_usd=Decimal("5"),
    )
    # The256-file case isolates source capacity with separately labelled fake prices;
    # the ordinary synthetic prices exceed250 and are tested as a refusal separately.
    prepared = corpus_case(
        source_files=sources,
        manifest=manifest,
        policy=policy,
        **({"endpoint_snapshot": capacity_metadata()} if count == 256 else {}),
    )
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    secrets = OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL})
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        assert request.content == prepared.shards[calls].request_content
        body = json.loads(request.content)
        system = body["messages"][0]["content"]
        assert "deployed or undeployed" in system and "declared" not in system
        assert "synthetic" not in system and "non-deployable" not in system
        calls += 1
        return httpx.Response(200, json=corpus_payload(calls, count=claims))

    result = await run_development_corpus(
        prepared=prepared,
        ledger=ledger,
        operator_secrets=secrets,
        output_dir=tmp_path / "run",
        allow_code_egress=True,
        mock_transport=httpx.MockTransport(handler),
    )
    assert result.status == "OBSERVED_ALL_SHARDS"
    assert calls == result.completed_shard_count == len(result.accounting) == count
    assert result.candidate_claim_count == count * claims
    assert result.reported_actual_cost_usd == Decimal("0.01") * count
    assert result.uncertain_accounted_cost_usd == 0
    assert not result.findings_validated and not result.audit_complete
    assert not result.qualification_eligible and not result.release_eligible
    assert result == DevelopmentCorpusObservation.model_validate_json(
        (tmp_path / "run/result.json").read_bytes()
    )
    assert (
        DevelopmentCorpusMaterial.model_validate_json(
            (tmp_path / "run/sources.json").read_bytes()
        ).source_files
        == sources
    )
    if count == 65:
        judgment = prepare_development_corpus_judgment(
            candidate=result,
            policy=policy,
            endpoint_snapshot=judgment_metadata(),
            source_files=sources,
            run_id="synthetic-protocol-review",
        )
        assert len(judgment.shards) == 65
        assert judgment.shards[-1].claims[-1].claim_id == "file-0065:16"


@pytest.mark.asyncio
@pytest.mark.parametrize("blocker", ["uncertain", "prompt-drift", "incomplete"])
async def test_real_scope_preserves_stop_and_resume_boundaries(
    tmp_path: Path, blocker: str
) -> None:
    sources = protocol_sources(65)
    manifest = freeze_development_corpus(
        corpus_id="synthetic-stop", source_scope="OPERATOR_SUPPLIED_PROTOCOL", source_files=sources
    )
    policy = DevelopmentCostPolicy(
        overspend_risk_accepted=True,
        total_budget_usd=Decimal("250"),
        per_attempt_budget_usd=Decimal("5"),
    )
    prepared = corpus_case(source_files=sources, manifest=manifest, policy=policy)
    ledger = AtomicCostLedger.initialize(tmp_path / "synthetic-ledger.json", cap_usd=Decimal("250"))
    if blocker == "uncertain":
        ledger.reconcile(ledger.reserve("synthetic-prior", Decimal("1")), None)
    elif blocker == "prompt-drift":
        body = json.loads(prepared.shards[0].request_content)
        body["messages"][0]["content"] = "Synthetic fixture with a declared invariant."
        prepared = replace(
            prepared,
            shards=(
                replace(prepared.shards[0], request_content=json.dumps(body).encode()),
                *prepared.shards[1:],
            ),
        )
    before = ledger.path.read_bytes()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        assert blocker == "incomplete"
        calls += 1
        return httpx.Response(429, json={"error": "synthetic refusal", "usage": {"cost": 0.01}})

    async def execute() -> DevelopmentCorpusObservation:
        return await run_development_corpus(
            prepared=prepared,
            ledger=ledger,
            operator_secrets=OperatorSecrets({"OPENROUTER_API_KEY": SYNTHETIC_CREDENTIAL}),
            output_dir=tmp_path / "run",
            allow_code_egress=True,
            mock_transport=httpx.MockTransport(handler),
        )

    if blocker != "incomplete":
        with pytest.raises(ValueError):
            await execute()
        assert calls == 0 and ledger.path.read_bytes() == before
        assert not (tmp_path / "run").exists()
    else:
        result = await execute()
        assert calls == 1 and result.status == "INCOMPLETE"
        assert len(
            result.unobserved_shard_ids
        ) == 65 and result.reported_actual_cost_usd == Decimal("0.01")
        material = DevelopmentCorpusMaterial(
            manifest=manifest,
            sources=tuple(
                DevelopmentCorpusText(filename=p, content=b.decode()) for p, b in sources
            ),
        )
        history = freeze_development_corpus_resume_history(original=result, material=material)
        continuation = prepare_development_corpus_resume(
            history=history,
            endpoint_snapshot=prepared.shards[0].endpoint_snapshot,
            run_id="synthetic-protocol-resume",
        )
        assert len(continuation.plan.selected_shard_ids) == 65
        assert (
            "deployed or undeployed"
            in json.loads(continuation.candidate.shards[-1].request_content)["messages"][0][
                "content"
            ]
        )
        assert history.original == result and history.summary.reported_actual_cost_usd == Decimal(
            "0.01"
        )


def test_corpus_writer_retains_large_escaped_source_without_widening_fixed_fixture_writer(
    tmp_path: Path,
) -> None:
    raw = b"//" + b"\t" * (MAX_DEVELOPMENT_CORPUS_FILE_BYTES - 3) + b"\n"
    sources = tuple(
        (f"Source{i:04d}.sol", raw) for i in range(MAX_DEVELOPMENT_CORPUS_BYTES // len(raw))
    )
    manifest = freeze_development_corpus(
        corpus_id="synthetic-serialization",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=sources,
    )
    material = DevelopmentCorpusMaterial(
        manifest=manifest,
        sources=tuple(DevelopmentCorpusText(filename=p, content=b.decode()) for p, b in sources),
    )
    output = tmp_path / "run"
    output.mkdir(mode=0o700)
    with pytest.raises(ValueError, match="output byte bound"):
        write_fixed_fixture(
            output, "fixed.json", material, max_bytes=MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
        )
    assert not (output / "fixed.json").exists()
    binding = _write(output, "sources.json", material)
    assert 16_000_000 < binding.size <= MAX_DEVELOPMENT_CORPUS_RESULT_BYTES
    retained = output / binding.path
    assert retained.stat().st_mode & 0o777 == 0o600
    assert (
        DevelopmentCorpusMaterial.model_validate_json(retained.read_bytes()).source_files == sources
    )


@pytest.mark.parametrize("bound", [True, 0, -1, 64_000_001])
def test_corpus_writer_refuses_invalid_byte_limits_before_writing(
    tmp_path: Path, bound: int
) -> None:
    manifest = freeze_development_corpus(
        corpus_id="synthetic-writer-bound",
        source_scope="OPERATOR_SUPPLIED_PROTOCOL",
        source_files=protocol_sources(),
    )
    with pytest.raises(ValueError, match="output byte bound"):
        _write(tmp_path, "refused.json", manifest, max_bytes=bound)
    assert not (tmp_path / "refused.json").exists()
