"""Filename-level secret withholding for copied audit workspaces.

These checks deliberately use names only. They are a last-resort guard for
dynamic execution workspaces, not a substitute for content redaction or secret
scanning.
"""

from __future__ import annotations

_SENSITIVE_FILE_NAMES = frozenset(
    {
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "keystore.json",
        "mnemonic",
        "mnemonic.txt",
        "seed",
        "seed.txt",
        "secrets.json",
        "wallet.json",
    }
)
_SENSITIVE_SUFFIXES = (".key", ".pem")


def is_sensitive_workspace_name(name: str) -> bool:
    """Return true for filenames that must not enter dynamic workspaces."""

    normalized = name.lower()
    return (
        normalized == ".env"
        or normalized.startswith(".env.")
        or normalized.endswith(_SENSITIVE_SUFFIXES)
        or normalized in _SENSITIVE_FILE_NAMES
    )
