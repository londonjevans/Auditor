"""Local secret detection and deterministic redaction before code egress."""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from collections.abc import Iterator
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


_ASSIGNMENT_NAMES = (
    "apikey",
    "api_key",
    "api-key",
    "accesstoken",
    "access_token",
    "access-token",
    "secret",
    "password",
    "passwd",
)

# Each marker is necessary, never sufficient, for its unchanged regex to match.
# Keep the marker beside its rule; the lookup below is keyed by the exact regex,
# not the display kind, so an unknown/replaced pattern always gets a full scan.
_RULES: tuple[tuple[str, re.Pattern[str], str, tuple[str, ...]], ...] = (
    (
        "private_key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?"
            r"-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
            re.DOTALL,
        ),
        "high",
        ("-----BEGIN ",),
    ),
    (
        "openrouter_key",
        re.compile(r"\bsk-or-v1-[A-Za-z0-9_-]{20,}\b"),
        "high",
        ("sk-or-v1-",),
    ),
    ("github_token", re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,}\b"), "high", ("gh",)),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"), "high", ("glpat-",)),
    ("slack_token", re.compile(r"\bxox(?:b|p|a|r|s)-[A-Za-z0-9-]{20,}\b"), "high", ("xox",)),
    ("google_api_key", re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"), "high", ("AIza",)),
    ("stripe_live_key", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "high", ("sk_live_",)),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high", ("AKIA", "ASIA")),
    (
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"),
        "high",
        ("eyJ",),
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
        _ASSIGNMENT_NAMES,
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
        _ASSIGNMENT_NAMES,
    ),
    (
        "credentialed_service_url",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://"
            r"[^:\s/@]+:[^@\s/]+@[^\s]+",
            re.IGNORECASE,
        ),
        "high",
        ("postgres", "mysql", "mongodb", "redis"),
    ),
)
_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (kind, pattern, confidence) for kind, pattern, confidence, _ in _RULES
)
_LITERAL_HINTS = {pattern: literals for _, pattern, _, literals in _RULES}
_ASSIGNMENT_PATTERNS = frozenset(
    pattern
    for kind, pattern, _, _ in _RULES
    if kind in {"credential_assignment", "credential_assignment_unquoted"}
)


def _has_assignment_delimiter(ascii_lowered: str) -> bool:
    """Check only a necessary ASCII name/whitespace/delimiter prefix, not a value."""

    for name in _ASSIGNMENT_NAMES:
        start = ascii_lowered.find(name)
        while start >= 0:
            end = start + len(name)
            while end < len(ascii_lowered) and ascii_lowered[end].isspace():
                end += 1
            if end < len(ascii_lowered) and ascii_lowered[end] in ":=":
                return True
            start = ascii_lowered.find(name, start + 1)
    return False


def _candidate_patterns(text: str) -> Iterator[tuple[str, re.Pattern[str], str]]:
    """Skip only proven-impossible rules; preserve Unicode and unknown-rule scans."""

    if type(text) is not str:
        # A str subclass can override containment/lower/isascii, but not the
        # regex engine's native string observation. Do not trust its shortcuts.
        yield from _PATTERNS
        return
    # Unicode IGNORECASE accepts more than lower(): e.g. dotted/dotless I,
    # long S and Kelvin sign. Preserve the original regex scan for that input.
    lowered = text.lower() if text.isascii() else None
    assignment_possible: bool | None = None
    for kind, pattern, confidence in _PATTERNS:
        literals = _LITERAL_HINTS.get(pattern)
        material = lowered if pattern.flags & re.IGNORECASE else text
        if literals is not None and material is not None:
            if pattern in _ASSIGNMENT_PATTERNS:
                if assignment_possible is None:
                    assignment_possible = _has_assignment_delimiter(material)
                if not assignment_possible:
                    continue
            elif not any(literal in material for literal in literals):
                continue
        yield kind, pattern, confidence


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    return -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())


def detect_secrets(text: str) -> list[SecretMatch]:
    matches: list[SecretMatch] = []
    occupied: list[tuple[int, int]] = []
    for kind, pattern, confidence in _candidate_patterns(text):
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
