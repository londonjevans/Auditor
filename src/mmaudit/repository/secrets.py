"""Filename-level secret withholding for copied audit workspaces.

These checks deliberately use names only. They are a last-resort guard for
dynamic execution workspaces, not a substitute for content redaction or secret
scanning.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

_SENSITIVE_FILE_NAMES = frozenset(
    {
        "credential",
        "credentials",
        "credentials.json",
        "id_ed25519",
        "id_rsa",
        "key",
        "key.json",
        "keys",
        "keystore",
        "keystore.json",
        "mnemonic",
        "mnemonic.txt",
        "mnemonics",
        "seed",
        "seed.txt",
        "seeds",
        "secrets.json",
        "wallet",
        "wallet.json",
        "wallets",
    }
)
_SENSITIVE_PREFIXES = (
    "credential.",
    "credentials.",
    "key.",
    "keys.",
    "keystore.",
    "mnemonic.",
    "mnemonics.",
    "seed.",
    "seeds.",
    "wallet.",
    "wallets.",
)
_SENSITIVE_SUFFIXES = (".key", ".keystore", ".pem", ".wallet")
_AUDITABLE_SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".sol",
        ".ts",
        ".tsx",
        ".vy",
        ".yul",
    }
)
_CONTROL_PLANE_DIRECTORY_NAMES = frozenset(
    {
        ".aws",
        ".azure",
        ".docker",
        ".git",
        ".gnupg",
        ".kube",
        ".ssh",
    }
)
_CONTROL_PLANE_FILE_NAMES = frozenset({".netrc", ".npmrc", ".pypirc"})
_CONTROL_PLANE_PATH_SEQUENCES = ((".config", "gcloud"),)


def is_sensitive_workspace_name(name: str) -> bool:
    """Return true for sensitive leaf filenames that must not enter workspaces."""

    normalized = name.lower()
    if normalized == ".env" or normalized.startswith(".env."):
        return True
    suffix = PurePosixPath(normalized).suffix
    if suffix in _AUDITABLE_SOURCE_SUFFIXES:
        return False
    return (
        normalized.startswith(_SENSITIVE_PREFIXES)
        or normalized.endswith(_SENSITIVE_SUFFIXES)
        or normalized in _SENSITIVE_FILE_NAMES
    )


def is_sensitive_workspace_path(
    path: str | Path | PurePosixPath,
    *,
    is_dir: bool = False,
) -> bool:
    """Reject control-plane paths and sensitive leaf artifacts.

    Generic directory names such as ``wallet``, ``keys``, and ``credentials`` are
    valid source-code namespaces. Only a leaf file with a credential-like name is
    withheld; known control-plane directories remain forbidden at every depth.
    """

    parts = tuple(
        part.lower()
        for part in PurePosixPath(str(path).replace("\\", "/")).parts
        if part not in {"", "/"}
    )
    if not parts:
        return False
    if any(
        part in _CONTROL_PLANE_DIRECTORY_NAMES or part == ".env" or part.startswith(".env.")
        for part in parts
    ):
        return True
    if any(
        parts[index : index + len(sequence)] == sequence
        for sequence in _CONTROL_PLANE_PATH_SEQUENCES
        for index in range(len(parts) - len(sequence) + 1)
    ):
        return True
    if is_dir:
        return False
    return parts[-1] in _CONTROL_PLANE_FILE_NAMES or is_sensitive_workspace_name(parts[-1])
