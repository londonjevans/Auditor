"""Privacy-conscious console and JSONL logging."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

_SECRET_PATTERNS = (
    re.compile(r"(?i)(authorization['\"\s:=]+(?:bearer\s+)?)[^\s,'\"}]+"),
    re.compile(r"(?i)(api[_-]?key['\"\s:=]+)[^\s,'\"}]+"),
    re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]+\b"),
)


def redact_log_text(value: str) -> str:
    """Remove credential-shaped text from a log message."""

    redacted = value
    for pattern in _SECRET_PATTERNS:
        if pattern.groups:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        else:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_log_text(str(record.msg))
        if record.args:
            record.args = tuple(redact_log_text(str(value)) for value in record.args)
        return True


class JsonLineHandler(logging.Handler):
    """Write structured metadata without source content."""

    def __init__(self, path: Path) -> None:
        super().__init__()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = path.open("a", encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": redact_log_text(record.getMessage()),
        }
        for name in ("run_id", "request_id", "role", "status"):
            value = getattr(record, name, None)
            if value is not None:
                payload[name] = value
        self._stream.write(json.dumps(payload, sort_keys=True) + "\n")
        self._stream.flush()

    def close(self) -> None:
        self._stream.close()
        super().close()


def configure_logging(
    *,
    verbose: bool,
    no_color: bool,
    log_path: Path | None = None,
) -> logging.Logger:
    """Configure the package logger and return it."""

    logger = logging.getLogger("mmaudit")
    logger.handlers.clear()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.propagate = False

    console = RichHandler(
        console=Console(no_color=no_color),
        rich_tracebacks=verbose,
        markup=False,
        show_path=verbose,
        show_time=verbose,
        omit_repeated_times=False,
    )
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    console.addFilter(RedactingFilter())
    logger.addHandler(console)
    if log_path is not None:
        file_handler = JsonLineHandler(log_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(RedactingFilter())
        logger.addHandler(file_handler)
    return logger
