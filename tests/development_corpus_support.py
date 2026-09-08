"""Source-only use of existing synthetic paired fixtures; no compilation, deployment or network."""

from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path
from typing import Any

from mmaudit.models.development_corpus import freeze_development_corpus, prepare_development_corpus
from mmaudit.models.development_costs import DevelopmentCostPolicy
from tests.development_benchmark_support import scored_file_response, scored_payload
from tests.development_judgment_support import judgment_metadata

CORPUS_ROOT = Path(__file__).parent / "fixtures/solidity/maximum_assurance_protocol"
SOURCE_NAMES = (
    "AccessVault.sol",
    "BadLiquidation.sol",
    "FeeTokenVault.sol",
    "InflationVault.sol",
    "ReentrantBank.sol",
    "ReplayClaim.sol",
    "ReplayInitializer.sol",
    "RewardReplay.sol",
    "RoundingPool.sol",
    "SafeControls.sol",
    "SafeVariants.sol",
    "SpotOracleLender.sol",
    "UnsafeDelegate.sol",
    "UnsafeUUPS.sol",
)
CORPUS_MODEL = "synthetic/corpus-review"


def supplied_sources():
    return tuple(
        ("src/" + name, (CORPUS_ROOT / "src" / name).read_bytes()) for name in SOURCE_NAMES
    )


def corpus_case(*, source_files=None, **changes: Any):
    sources = supplied_sources() if source_files is None else source_files
    values = dict(
        policy=DevelopmentCostPolicy(
            overspend_risk_accepted=True,
            total_budget_usd=Decimal("20"),
            per_attempt_budget_usd=Decimal("5"),
        ),
        endpoint_snapshot=judgment_metadata(model_id=CORPUS_MODEL),
        manifest=freeze_development_corpus(
            corpus_id="synthetic-medium",
            source_scope="OPERATOR_SUPPLIED_SYNTHETIC",
            source_files=sources,
        ),
        source_files=sources,
        run_id="synthetic-corpus",
    )
    values.update(changes)
    return prepare_development_corpus(**values)


def corpus_payload(ordinal: int, *, count: int = 1, origin: str | None = None):
    response = scored_file_response(1, advisory=origin is None)
    response["schema_version"] = "3.0"
    finding = response["findings"][0]
    finding.update(line_start=1, line_end=1)
    if origin is not None:
        finding["root_cause_ref"] = {"filename": origin, "line_start": 1, "line_end": 1}
    response["findings"] = [dict(finding) for _ in range(count)]
    payload = scored_payload(1, response=response)
    payload["id"] = f"gen-synthetic-corpus-{ordinal}"
    payload["model"] = CORPUS_MODEL
    routing = payload["openrouter_metadata"]
    routing["requested"] = CORPUS_MODEL
    routing["endpoints"]["available"][0]["model"] = CORPUS_MODEL
    routing["attempts"][0]["model"] = CORPUS_MODEL
    assert json.loads(payload["choices"][0]["message"]["content"])["schema_version"] == "3.0"
    return payload
