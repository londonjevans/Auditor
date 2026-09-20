"""Synthetic capacity controls for protocol-labelled source; never actual deployed source."""

import json
from pathlib import Path

from mmaudit.models.development_audit import DevelopmentSourceBytes
from mmaudit.models.endpoint_snapshots import (
    OpenRouterEndpointSnapshotEvidence,
    validate_openrouter_endpoint_snapshot,
)
from tests.development_corpus_support import CORPUS_MODEL
from tests.development_cost_support import FIXTURE

REFERENCE = Path(__file__).parent / "fixtures/development_corpus_protocol/Reference.sol"


def protocol_sources(count: int = 1, *, size: int | None = None) -> DevelopmentSourceBytes:
    """Pad a non-deployable source control with inert comments, preserving exact byte sizes."""

    raw = REFERENCE.read_bytes()
    if size is not None:
        assert size >= len(raw) + 3
        raw += b"//" + b" " * (size - len(raw) - 3) + b"\n"
        assert len(raw) == size
    return tuple((f"src/Control{index:04d}.sol", raw) for index in range(count))


def capacity_metadata() -> OpenRouterEndpointSnapshotEvidence:
    """Use separately labelled synthetic prices to test capacity under unchanged USD250 caps."""

    endpoint = json.loads(FIXTURE.read_bytes())["endpoint"]
    pricing = json.loads((REFERENCE.parent / "capacity_pricing.json").read_bytes())
    assert (
        pricing["fixture_scope"]
        == "SYNTHETIC_CAPACITY_ONLY_NOT_PROVIDER_PRICES_OR_EXECUTION_AUTHORITY"
    )
    endpoint["pricing"] = pricing["pricing"]
    return validate_openrouter_endpoint_snapshot(
        exact_model_id=CORPUS_MODEL,
        configured_provider_endpoints=(endpoint["tag"],),
        provider_policy_mode="only",
        endpoint_payload={"data": {"id": CORPUS_MODEL, "endpoints": [endpoint]}},
        require_zdr=True,
        zdr_payload={"data": [{**endpoint, "model_id": CORPUS_MODEL}]},
    )
