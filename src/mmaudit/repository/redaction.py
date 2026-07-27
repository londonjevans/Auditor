"""Local secret detection and deterministic redaction before code egress."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass


class SecretSafetyError(RuntimeError):
    """Raised when source egress is blocked by a high-confidence secret."""


@dataclass(frozen=True)
class SecretMatch:
    kind: str
    start: int
    end: int
    confidence: str
    fingerprint: str


_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "high",
    ),
    ("openrouter_key", re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("github_token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,}\b"), "high"),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("slack_token", re.compile(r"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,}\b"), "high"),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"), "high"),
    ("stripe_live_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "high"),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high"),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
        "high",
    ),
    (
        "credential_assignment",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|access[_-]?token|secret|password|passwd)\b
            \s*[:=]\s*
            (?P<quote>["'])(?P<value>[^"'\r\n]{16,})(?P=quote)
            """
        ),
        "conditional",
    ),
    (
        "credential_assignment_unquoted",
        re.compile(
            r"""(?ix)
            \b(?:api[_-]?key|access[_-]?token|secret|password|passwd)\b
            \s*[:=]\s*
            (?P<value>[A-Za-z0-9_./+=-]{20,})
            """
        ),
        "conditional",
    ),
    (
        "credentialed_service_url",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:\s/@]+:[^@\s/]+@[^\s]+",
            re.IGNORECASE,
        ),
        "high",
    ),
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def detect_secrets(text: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    occupied: list[tuple[int, int]] = []
    for kind, pattern, confidence in _PATTERNS:
        for found in pattern.finditer(text):
            start, end = found.span()
            if any(start < other_end and end > other_start for other_start, other_end in occupied):
                continue
            actual_confidence = confidence
            if confidence == "conditional":
                value = found.groupdict().get("value", "")
                if _entropy(value) < 3.5 or value.lower().startswith(
                    ("example", "placeholder", "not-a-", "test-only")
                ):
                    actual_confidence = "low"
                else:
                    actual_confidence = "high"
            secret = found.group(0)
            fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:12]
            matches.append(
                SecretMatch(
                    kind=kind,
                    start=start,
                    end=end,
                    confidence=actual_confidence,
                    fingerprint=fingerprint,
                )
            )
            occupied.append((start, end))
    return sorted(matches, key=lambda item: item.start)


def redact_text(
    text: str,
    *,
    fail_on_detected_secret: bool,
    redact: bool = True,
) -> tuple[str, list[SecretMatch]]:
    """Detect secrets, optionally block, then redact without retaining values."""

    matches = detect_secrets(text)
    high_confidence = [match for match in matches if match.confidence == "high"]
    if high_confidence and fail_on_detected_secret:
        kinds = ", ".join(sorted({match.kind for match in high_confidence}))
        raise SecretSafetyError(f"high-confidence secret detected ({kinds}); model egress blocked")
    if not redact or not matches:
        return text, matches
    pieces: list[str] = []
    cursor = 0
    for match in matches:
        pieces.append(text[cursor : match.start])
        secret_text = text[match.start : match.end]
        replacement = f"[REDACTED:{match.kind}]"
        for line_ending in re.findall(r"\r\n|\r|\n", secret_text):
            replacement += f"{line_ending}[REDACTED:continuation]"
        pieces.append(replacement)
        cursor = match.end
    pieces.append(text[cursor:])
    return "".join(pieces), matches
