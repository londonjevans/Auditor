"""Shared constants used throughout mmaudit."""

from __future__ import annotations

from enum import IntEnum
from typing import Final

VERSION = "0.1.0"
REPORT_SCHEMA_VERSION: Final = "1.0"
SARIF_VERSION = "2.1.0"
OPENROUTER_DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_CONFIG_NAME = "mmaudit.toml"
DEFAULT_IGNORE_NAME = ".mmauditignore"


class ExitCode(IntEnum):
    """Stable process exit codes."""

    SUCCESS = 0
    FINDINGS = 1
    CONFIGURATION = 2
    SCANNER_FAILURE = 3
    MODEL_FAILURE = 4
    PRIVACY_REFUSAL = 5
    INCOMPLETE = 6


SEVERITY_ORDER = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

ANALYSIS_ROLES = (
    "threat_model",
    "source_audit",
    "business_logic",
    "configuration",
)
ALL_MODEL_ROLES = (*ANALYSIS_ROLES, "verifier", "judge")

# These are distinct analytical responsibilities, not repeated generic prompts.
# Verifier and judge remain first-class base roles; falsifier and generation roles
# use the specialist routing table.
SPECIALIST_INVESTIGATOR_ROLES = (
    "access_control",
    "reentrancy_control_flow",
    "economic_game_theory",
    "oracle_price_manipulation",
    "accounting_invariant",
    "token_standard",
    "erc4626_vault",
    "amm_dex_liquidity",
    "lending_liquidation",
    "governance_timelock",
    "upgradeability_storage",
    "initialization_deployment",
    "signature_permit_replay",
    "mev_ordering",
    "denial_of_service_griefing",
    "precision_rounding",
    "cross_chain_bridge",
    "dependency_supply_chain",
    "formal_methods_property",
    "false_negative_hunter",
)

SPECIALIST_AUXILIARY_ROLES = (
    "invariant_review",
    "test_generation",
    "exploit_reproduction_planner",
    "falsifier",
    "report_quality",
)

ALL_SPECIALIST_ROLES = (*SPECIALIST_INVESTIGATOR_ROLES, *SPECIALIST_AUXILIARY_ROLES)

PERMANENT_EXCLUSIONS = (
    ".git",
    ".git/**",
    ".env",
    ".env.*",
    "**/.env",
    "**/.env.*",
    "*.keystore",
    "**/*.keystore",
    "*.pem",
    "*.key",
    "**/*.pem",
    "**/*.key",
    ".ssh",
    ".ssh/**",
    "**/.ssh",
    "**/.ssh/**",
    ".aws",
    ".aws/**",
    "**/.aws",
    "**/.aws/**",
    ".azure",
    ".azure/**",
    "**/.azure",
    "**/.azure/**",
    ".config/gcloud",
    ".config/gcloud/**",
    "**/.config/gcloud",
    "**/.config/gcloud/**",
    ".kube/config",
    "**/.kube/config",
    ".docker/config.json",
    "**/.docker/config.json",
    ".netrc",
    "**/.netrc",
    ".npmrc",
    "**/.npmrc",
    ".pypirc",
    "**/.pypirc",
    "id_rsa",
    "**/id_rsa",
    "id_ed25519",
    "**/id_ed25519",
)

DEFAULT_EXCLUSIONS = (
    ".git/",
    "node_modules/",
    "vendor/",
    "dist/",
    "build/",
    "coverage/",
    ".next/",
    "target/",
    "out/",
    "artifacts/",
    "cache/",
    "broadcast/",
    ".venv/",
    "venv/",
    "__pycache__/",
    "*.min.js",
    "*.map",
    "*.lock",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.pdf",
    "*.zip",
    "*.tar",
    "*.gz",
    "*.pem",
    "*.key",
    ".env",
    ".env.*",
    ".mmaudit/",
    ".mmaudit/runs/",
    ".mmaudit/latest/",
)
