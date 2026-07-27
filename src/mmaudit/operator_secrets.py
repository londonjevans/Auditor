"""Explicit in-memory loading for operator control-plane credentials."""

from __future__ import annotations

import io
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Never, SupportsIndex

from dotenv import dotenv_values

SECRETS_ENV_FILE_VARIABLE = "MMAUDIT_SECRETS_ENV_FILE"
OPENROUTER_API_KEY_NAME = "OPENROUTER_API_KEY"
APPROVED_OPERATOR_SECRET_NAMES = frozenset({OPENROUTER_API_KEY_NAME})
RESERVED_OPERATOR_CONTROL_PLANE_NAMES = frozenset(
    {
        OPENROUTER_API_KEY_NAME,
        SECRETS_ENV_FILE_VARIABLE,
    }
)
MAX_OPERATOR_SECRET_FILE_BYTES = 64 * 1024
MAX_OPERATOR_SECRET_VALUE_BYTES = 4_096


class OperatorSecretError(ValueError):
    """A non-operational secret-file validation failure."""


class OperatorSecrets:
    """Small non-serializable credential holder with best-effort memory clearing."""

    __slots__ = ("_cleared", "_values")

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values = {
            name: bytearray(value.encode("utf-8"))
            for name, value in (values or {}).items()
            if name in APPROVED_OPERATOR_SECRET_NAMES and value
        }
        self._cleared = False

    def __enter__(self) -> OperatorSecrets:
        return self

    def __exit__(self, *_args: object) -> None:
        self.clear()

    def __repr__(self) -> str:
        return "OperatorSecrets([REDACTED])"

    def __str__(self) -> str:
        return "[REDACTED OPERATOR SECRETS]"

    def __reduce__(self) -> Never:
        raise TypeError("operator secrets cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("operator secrets cannot be serialized")

    @property
    def openrouter_api_key(self) -> str:
        return self.get(OPENROUTER_API_KEY_NAME)

    @property
    def openrouter_api_key_present(self) -> bool:
        return bool(self._values.get(OPENROUTER_API_KEY_NAME)) and not self._cleared

    @property
    def cleared(self) -> bool:
        return self._cleared

    def get(self, name: str) -> str:
        if name not in APPROVED_OPERATOR_SECRET_NAMES or self._cleared:
            return ""
        value = self._values.get(name)
        return bytes(value).decode("utf-8") if value else ""

    def clear(self) -> None:
        for value in self._values.values():
            value[:] = b"\x00" * len(value)
        self._values.clear()
        self._cleared = True


def select_operator_secret_file(
    explicit_path: Path | None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path | None:
    """Select one explicit control-plane file without consulting target paths."""

    environment = os.environ if environ is None else environ
    configured = environment.get(SECRETS_ENV_FILE_VARIABLE, "").strip()
    configured_path = Path(configured).expanduser() if configured else None
    if explicit_path is not None and configured_path is not None:
        try:
            explicit_identity = explicit_path.expanduser().absolute()
            configured_identity = configured_path.absolute()
        except (OSError, RuntimeError, ValueError) as exc:
            raise OperatorSecretError("operator secret file selection is invalid") from exc
        if explicit_identity != configured_identity:
            raise OperatorSecretError("operator secret file selection is ambiguous")
    return explicit_path.expanduser() if explicit_path is not None else configured_path


def load_operator_secrets(
    explicit_path: Path | None,
    *,
    environ: Mapping[str, str] | None = None,
    required: bool = False,
) -> OperatorSecrets:
    """Validate and parse the selected dotenv file without shell evaluation."""

    selected = select_operator_secret_file(explicit_path, environ=environ)
    if selected is None:
        if required:
            raise OperatorSecretError("operator secret file is not selected")
        return OperatorSecrets()
    raw = _read_validated_secret_file(selected)
    try:
        parsed = dotenv_values(stream=io.StringIO(raw), interpolate=False, verbose=False)
    except (OSError, UnicodeError, ValueError):
        parsed = None
    if parsed is None:
        raise OperatorSecretError("operator secret file could not be parsed")
    approved: dict[str, str] = {}
    for name in APPROVED_OPERATOR_SECRET_NAMES:
        value = parsed.get(name)
        if value is None:
            continue
        if not isinstance(value, str) or not _valid_operator_secret_value(value):
            raise OperatorSecretError("operator secret file contains an invalid approved value")
        approved[name] = value
    return OperatorSecrets(approved)


def _read_validated_secret_file(path: Path) -> str:
    try:
        absolute = path.expanduser().absolute()
        cursor = Path(absolute.anchor)
        for part in absolute.parts[1:]:
            cursor /= part
            if cursor.is_symlink() or cursor.is_junction():
                raise OperatorSecretError("operator secret file is rejected")
        resolved = absolute.resolve(strict=True)
        metadata = resolved.stat()
    except OperatorSecretError:
        raise
    except (OSError, RuntimeError, ValueError):
        raise OperatorSecretError("operator secret file is rejected") from None
    if not stat.S_ISREG(metadata.st_mode):
        raise OperatorSecretError("operator secret file is rejected")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise OperatorSecretError("operator secret file is rejected")
    if metadata.st_size > MAX_OPERATOR_SECRET_FILE_BYTES:
        raise OperatorSecretError("operator secret file is rejected")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(resolved, flags)
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise OperatorSecretError("operator secret file is rejected")
            if opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise OperatorSecretError("operator secret file is rejected")
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise OperatorSecretError("operator secret file changed during validation")
            if opened.st_size > MAX_OPERATOR_SECRET_FILE_BYTES:
                raise OperatorSecretError("operator secret file is rejected")
            content = stream.read(MAX_OPERATOR_SECRET_FILE_BYTES + 1)
    except OperatorSecretError:
        raise
    except OSError:
        raise OperatorSecretError("operator secret file is rejected") from None
    if len(content) > MAX_OPERATOR_SECRET_FILE_BYTES or b"\x00" in content:
        raise OperatorSecretError("operator secret file is rejected")
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError:
        decoded = None
    if decoded is None:
        raise OperatorSecretError("operator secret file must be UTF-8")
    return decoded


def _valid_operator_secret_value(value: str) -> bool:
    encoded = value.encode("utf-8")
    return (
        0 < len(encoded) <= MAX_OPERATOR_SECRET_VALUE_BYTES
        and value.isascii()
        and all(33 <= ord(character) <= 126 for character in value)
    )
