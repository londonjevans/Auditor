"""Synthetic detector-equivalence controls; no credentials or network operations."""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import random
import re
from collections import Counter

import pytest

from mmaudit.models.development_tree_request_bounds import development_tree_review_claims_bound
from mmaudit.repository import redaction

_VALUE = "Ab9_Xy7-Qp2/Zm8+Vk4.Nr6=Ts1"
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


def _reference_matches(text: str) -> list[redaction.SecretMatch]:
    """Original full-scan behavior, deliberately independent of any prefilter."""

    result = []
    occupied = []
    for kind, pattern, confidence in redaction._PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if any(start < right and end > left for left, right in occupied):
                continue
            effective = confidence
            if confidence == "conditional":
                value = match.groupdict().get("value", "")
                counts = Counter(value)
                entropy = -sum(
                    (count / len(value)) * math.log2(count / len(value))
                    for count in counts.values()
                )
                effective = (
                    "low"
                    if entropy < 3.5
                    or value.lower().startswith(("example", "placeholder", "not-a-", "test-only"))
                    else "high"
                )
            result.append(
                redaction.SecretMatch(
                    kind=kind,
                    start=start,
                    end=end,
                    confidence=effective,
                    fingerprint=hashlib.sha256(match.group(0).encode()).hexdigest()[:12],
                )
            )
            occupied.append((start, end))
    return sorted(result, key=lambda item: item.start)


def _samples() -> tuple[str, ...]:
    tokens = (
        "sk-or-v1-" + "A" * 20,
        *("gh" + variant + "_" + "A" * 30 for variant in "pousr"),
        "glpat-" + "A" * 20,
        *("xox" + variant + "-" + "A" * 20 for variant in "bpars"),
        "AIza" + "A" * 30,
        "sk_live_" + "A" * 20,
        "AKIA" + "A" * 16,
        "ASIA" + "A" * 16,
        "eyJ" + "A" * 10 + "." + "B" * 10 + "." + "C" * 8,
    )
    assignments = tuple(
        f"{name.upper()} \t:{quote}{_VALUE}{quote}"
        for name in _ASSIGNMENT_NAMES
        for quote in ('"', "'", "")
    )
    blocks = tuple(
        "-----BEGIN "
        + kind
        + "PRIVATE KEY-----\r\nsynthetic non-key material\n-----END "
        + kind
        + "PRIVATE KEY-----"
        for kind in ("", "RSA ", "EC ", "OPENSSH ", "DSA ")
    )
    urls = tuple(
        scheme + "://synthetic:fixture-only@fixture.invalid/db"
        for scheme in ("postgres", "postgresql", "mysql", "mongodb", "mongodb+srv", "redis")
    )
    placeholders = tuple(
        f'password="{value}"'
        for value in (
            "A" * 30,
            "example" + _VALUE,
            "placeholder" + _VALUE,
            "not-a-" + _VALUE,
            "test-only" + _VALUE,
        )
    )
    return (*tokens, *assignments, *blocks, *urls, *placeholders)


_SAMPLES = _samples()


def test_prefilter_does_not_change_the_original_ordered_rules() -> None:
    rules = [(kind, p.pattern, p.flags, confidence) for kind, p, confidence in redaction._PATTERNS]
    digest = hashlib.sha256(json.dumps(rules, separators=(",", ":")).encode()).hexdigest()
    assert digest == "4c54b9d105d62bcffd016e67612310854cceaae57f7e1737efdfa6f1ea2bfdbe"


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda value: f"synthetic-{_SAMPLES.index(value)}")
@pytest.mark.parametrize(
    "prefix,suffix", [("", ""), ("before\n", "\nafter"), ("_", "_"), ("λ🧪 ", " é")]
)
def test_detection_matches_original_spans_confidence_and_fingerprints(
    sample: str, prefix: str, suffix: str
) -> None:
    text = prefix + sample + suffix
    assert redaction.detect_secrets(text) == _reference_matches(text)


@pytest.mark.parametrize("name", _ASSIGNMENT_NAMES)
def test_all_ascii_keyword_case_combinations_keep_original_matching(name: str) -> None:
    choices = [(char.lower(), char.upper()) if char.isalpha() else (char,) for char in name]
    for variant in itertools.product(*choices):
        text = "".join(variant) + ' = "' + _VALUE + '"'
        expected = _reference_matches(text)
        assert expected and expected[0].confidence == "high"
        assert redaction.detect_secrets(text) == expected


@pytest.mark.parametrize(
    "name",
    (
        "ap\u0131_key",
        "AP\u0130_KEY",
        "api_\u212aey",
        "\u017fecret",
        "acce\u017fs_token",
        "pa\u017f\u017fword",
        "passwD",
    ),
)
@pytest.mark.parametrize("whitespace", (" ", "\t\r\n", "\x1c", "\u00a0", "\u2028"))
def test_unicode_case_and_whitespace_do_not_narrow_assignment_matching(
    name: str, whitespace: str
) -> None:
    text = name + whitespace + ":" + whitespace + '"' + _VALUE + '"'
    expected = _reference_matches(text)
    assert expected and expected[0].kind == "credential_assignment"
    assert redaction.detect_secrets(text) == expected


@pytest.mark.parametrize(
    "scheme", ("PoStGrEs", "po\u017ftgres", "my\u017fql", "RED\u0130S", "red\u0131s")
)
def test_unicode_service_schemes_keep_original_matching(scheme: str) -> None:
    text = scheme + "://synthetic:fixture-only@fixture.invalid/db"
    expected = _reference_matches(text)
    assert expected and expected[0].kind == "credentialed_service_url"
    assert redaction.detect_secrets(text) == expected


@pytest.mark.parametrize("sample", _SAMPLES, ids=lambda value: f"synthetic-{_SAMPLES.index(value)}")
def test_redaction_and_blocking_keep_original_behavior(sample: str) -> None:
    text = "before\n" + sample + "\nafter"
    expected = _reference_matches(text)
    pieces = []
    cursor = 0
    for match in expected:
        pieces.append(text[cursor : match.start])
        replacement = f"[REDACTED:{match.kind}]"
        for ending in re.findall(r"\r\n|\r|\n", text[match.start : match.end]):
            replacement += ending + "[REDACTED:continuation]"
        pieces.append(replacement)
        cursor = match.end
    pieces.append(text[cursor:])
    assert redaction.redact_text(text, fail_on_detected_secret=False) == ("".join(pieces), expected)
    assert redaction.redact_text(text, fail_on_detected_secret=False, redact=False) == (
        text,
        expected,
    )
    if any(match.confidence == "high" for match in expected):
        for redact in (False, True):
            with pytest.raises(redaction.SecretSafetyError, match="model egress blocked"):
                redaction.redact_text(text, fail_on_detected_secret=True, redact=redact)
    else:
        assert redaction.redact_text(text, fail_on_detected_secret=True)[1] == expected


def test_overlapping_and_adjacent_tokens_keep_original_priority() -> None:
    token = "ghp_" + "A" * 30
    block = "-----BEGIN PRIVATE KEY-----\n" + token + "\n-----END PRIVATE KEY-----"
    text = 'password="' + token + '"\n' + block + "\n" + " ".join(_SAMPLES)
    expected = _reference_matches(text)
    assert {match.kind for match in expected} == {kind for kind, _, _ in redaction._PATTERNS}
    assert redaction.detect_secrets(text) == expected


def test_seeded_mixed_ascii_and_unicode_texts_keep_original_results() -> None:
    rng = random.Random(20260919)
    alphabet = "abcdeABCDEFGHIJKLMNOP_-=:./\"' \t\r\n0123\u0130\u0131\u017f\u212aλ🧪"
    for _ in range(256):
        parts = ["".join(rng.choices(alphabet, k=rng.randrange(96))) for _ in range(4)]
        parts.insert(rng.randrange(5), rng.choice(_SAMPLES))
        text = "".join(parts)
        assert redaction.detect_secrets(text) == _reference_matches(text)


def test_every_ascii_separator_retains_the_original_assignment_decision() -> None:
    for codepoint in range(128):
        separator = chr(codepoint)
        for name in _ASSIGNMENT_NAMES:
            text = name + separator + ":" + separator + '"' + _VALUE + '"'
            assert redaction.detect_secrets(text) == _reference_matches(text)


def test_prefilter_avoids_all_regex_scans_for_the_original_claims_envelope() -> None:
    claims, _ = development_tree_review_claims_bound()
    text = json.dumps(
        {"messages": [{"content": claims}]}, separators=(",", ":"), ensure_ascii=False
    )
    assert len(text.encode()) == 533534
    assert hashlib.sha256(text.encode()).hexdigest() == (
        "1e444e505122b45a0408df53760b493eb37f183db7b9c0bb87be1156bba131fd"
    )
    assert _reference_matches(text) == []
    assert list(redaction._candidate_patterns(text)) == []
    assert redaction.detect_secrets(text) == []


def test_unknown_pattern_is_scanned_without_assuming_its_kind_is_a_guard(monkeypatch) -> None:
    pattern = re.compile("synthetic-custom-marker")
    monkeypatch.setattr(redaction, "_PATTERNS", (("credential_assignment", pattern, "high"),))
    text = "synthetic-custom-marker"
    assert list(redaction._candidate_patterns(text)) == list(redaction._PATTERNS)
    assert redaction.detect_secrets(text) == _reference_matches(text)


def test_non_ascii_text_keeps_every_case_insensitive_rule() -> None:
    actual = {pattern for _, pattern, _ in redaction._candidate_patterns("🧪")}
    expected = {pattern for _, pattern, _ in redaction._PATTERNS if pattern.flags & re.IGNORECASE}
    assert actual == expected


def test_string_subclasses_use_the_original_scans_without_overridden_methods() -> None:
    class UntrustedText(str):
        def __contains__(self, _value):
            raise AssertionError("subclass containment must not decide detector omissions")

        def isascii(self):
            raise AssertionError("subclass ASCII claim must not decide detector omissions")

        def lower(self):
            raise AssertionError("subclass lower must not decide detector omissions")

    text = UntrustedText(_SAMPLES[0])
    assert list(redaction._candidate_patterns(text)) == list(redaction._PATTERNS)
    assert redaction.detect_secrets(text) == _reference_matches(text)


def test_no_filter_result_is_reused_for_later_source_text() -> None:
    for text in ("synthetic source without markers", *_SAMPLES, "synthetic source without markers"):
        assert redaction.detect_secrets(text) == _reference_matches(text)
