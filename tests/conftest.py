from __future__ import annotations

import hashlib
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from mmaudit.config import AuditConfig
from mmaudit.models.schemas import (
    CandidateFinding,
    Evidence,
    Location,
    SourceSink,
    VerificationTest,
)

FIXTURES = Path(__file__).parent / "fixtures"
MODEL_IDS = {
    "threat_model": "alpha/atlas-secure",
    "source_audit": "bravo/borealis-secure",
    "business_logic": "charlie/cirrus-secure",
    "configuration": "delta/denali-secure",
    "verifier": "echo/equinox-secure",
    "judge": "foxtrot/fjord-secure",
}


def model_registry_entry(
    model_id: str,
    *,
    root_lineage: str | None = None,
    aliases: list[str] | None = None,
    measured_quality_score: float = 0.95,
    measured_quality_tier: str = "highest",
    retention_policy: str = "zero",
) -> dict[str, Any]:
    """Build deterministic synthetic registry metadata for local tests."""

    return {
        "root_lineage": root_lineage or _sha256_identifier(f"lineage:{model_id}"),
        "canonical_model_id": model_id,
        "aliases": aliases or [],
        "measured_quality_score": measured_quality_score,
        "measured_quality_tier": measured_quality_tier,
        "quality_measurement": _sha256_identifier(f"quality:{model_id}"),
        "retention_policy": retention_policy,
    }


def _sha256_identifier(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode()).hexdigest()}"


def base_config_data() -> dict[str, Any]:
    registry = [model_registry_entry(model_id) for model_id in MODEL_IDS.values()]
    return {
        "version": 1,
        "repository": {
            "root": ".",
            "ignore_file": ".mmauditignore",
            "include_tests": True,
            "include_docs": False,
            "max_files": 200,
            "max_file_bytes": 250_000,
            "max_total_context_bytes": 600_000,
            "follow_symlinks": False,
        },
        "privacy": {
            "allow_code_egress": True,
            "require_zdr": True,
            "redact_secrets": True,
            "fail_on_detected_secret": True,
            "store_raw_prompts": False,
            "store_raw_responses": False,
            "maximum_model_retention": "zero",
            "approved_model_lineages": [entry["root_lineage"] for entry in registry],
        },
        "execution": {
            "concurrency": 3,
            "request_timeout_seconds": 1,
            "scanner_timeout_seconds": 2,
            "max_model_retries": 0,
            "max_json_repair_attempts": 0,
            "budget_usd": 20,
            "max_output_tokens_per_request": 2_048,
            "max_requests_per_agent": 2,
            "conservative_usd_per_million_tokens": 10,
        },
        "models": {
            "minimum_distinct_families": 3,
            "allow_non_independent_models": False,
            "provider_policy": {
                "only": ["synthetic-provider"],
                "allow_fallbacks": False,
            },
            "registry": registry,
            **{
                role: {"primary": model_id, "fallbacks": []} for role, model_id in MODEL_IDS.items()
            },
        },
        "scanners": {
            "semgrep": {"enabled": False, "required": False},
            "gitleaks": {"enabled": False, "required": False},
            "trivy": {"enabled": False, "required": False},
            "osv": {"enabled": False, "required": False},
            "codeql": {"enabled": False, "required": False},
        },
        "reporting": {"markdown": True, "json": True, "sarif": True},
    }


@pytest.fixture
def config_factory() -> Callable[..., AuditConfig]:
    def factory(**sections: dict[str, Any]) -> AuditConfig:
        data = base_config_data()
        for section, updates in sections.items():
            if isinstance(data.get(section), dict):
                data[section].update(updates)
            else:
                data[section] = updates
        return AuditConfig.model_validate(data)

    return factory


@pytest.fixture
def vulnerable_repo(tmp_path: Path) -> Path:
    target = tmp_path / "vulnerable_app"
    shutil.copytree(FIXTURES / "vulnerable_app", target)
    return target


@pytest.fixture
def candidate_factory() -> Callable[..., CandidateFinding]:
    def factory(
        *,
        candidate_id: str = "candidate-1",
        role: str = "source_audit",
        family: str = "bravo/borealis-secure",
        path: str = "app.py",
        start_line: int = 11,
        end_line: int = 14,
        title: str = "SQL injection in user search",
        cwe: list[str] | None = None,
    ) -> CandidateFinding:
        return CandidateFinding(
            candidate_id=candidate_id,
            title=title,
            severity="high",
            confidence=0.9,
            cwe=cwe or ["CWE-89"],
            owasp=["A03:2021"],
            summary="Attacker input is interpolated into a SQL statement.",
            impact="An authenticated attacker can alter the synthetic query.",
            preconditions=["Attacker can call the search function"],
            locations=[
                Location(
                    path=path,
                    start_line=start_line,
                    end_line=end_line,
                    symbol="search_users" if path == "app.py" else None,
                )
            ],
            source=SourceSink(
                description="Attacker-controlled search text",
                path=path,
                line=start_line + 1,
            ),
            sink=SourceSink(
                description="SQL execution",
                path=path,
                line=end_line,
            ),
            attack_path=["Supply SQL metacharacters", "Reach query execution"],
            evidence=[
                Evidence(
                    type="model",
                    source=role,
                    description="Direct source-to-sink trace",
                )
            ],
            compensating_controls=[],
            false_positive_conditions=["The database driver rejects all interpolated syntax"],
            recommendation="Use a parameterized query.",
            verification_test=VerificationTest(
                description="Use an in-memory fake database and a synthetic input"
            ),
            role=role,
            model_family=family,
            model_votes=[],
        )

    return factory
