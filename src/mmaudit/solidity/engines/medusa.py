"""Deterministic Medusa configuration over the shared Solidity property harness."""

from __future__ import annotations

import json
from dataclasses import replace

from mmaudit.models.schemas import PropertyCorpus, SoliditySymbolIndex
from mmaudit.solidity.engines.echidna import (
    PropertyEngineTranslation,
    translate_property_corpus,
)


def translate_medusa_corpus(
    corpus: PropertyCorpus,
    index: SoliditySymbolIndex,
    *,
    timeout_seconds: float,
) -> PropertyEngineTranslation:
    """Translate the same safe property subset with Medusa-specific bounds."""

    translation = translate_property_corpus(
        corpus,
        index,
        harness_contract_name="MMAuditMedusaProperties",
        property_prefix="echidna",
        engine_name="Medusa",
        generated_source_path="mmaudit-medusa/MMAuditMedusa.sol",
    )
    if not translation.property_map or translation.seed is None:
        return translation
    configuration = {
        "compilation": {
            "platform": "crytic-compile",
            "platformConfig": {
                "target": "mmaudit-medusa/MMAuditMedusa.sol",
            },
        },
        "fuzzing": {
            "callSequenceLength": translation.depth,
            "corpusDirectory": "mmaudit-medusa/corpus",
            "coverageEnabled": True,
            "seed": translation.seed,
            "targetContracts": ["MMAuditMedusaProperties"],
            "testLimit": translation.runs,
            "testing": {
                "stopOnFailedTest": False,
                "stopOnNoTests": True,
                "testAllContracts": False,
                "traceAll": False,
            },
            "timeout": max(1, int(timeout_seconds)),
            "workerResetLimit": 50,
            "workers": 1,
        },
        "logging": {
            "level": "info",
            "noColor": True,
        },
    }
    return replace(
        translation,
        configuration=json.dumps(configuration, sort_keys=True, indent=2) + "\n",
        configuration_path="mmaudit-medusa/medusa.json",
        property_map_path="mmaudit-medusa/property-map.json",
    )
