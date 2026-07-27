from __future__ import annotations

import pytest

from mmaudit.models.identifiers import is_exact_openrouter_model_id


@pytest.mark.parametrize(
    "model_id",
    [
        "openrouter/auto",
        "openrouter/random",
        "author/model:auto",
        "author/model-free",
        "author/model_latest",
        "author/model.online",
        "author/model-router",
        "author/model:online",
    ],
)
def test_mutable_or_routed_model_variants_are_not_exact(model_id: str) -> None:
    assert is_exact_openrouter_model_id(model_id) is False


@pytest.mark.parametrize(
    "model_id",
    [
        "anthropic/claude-sonnet-4.5",
        "deepseek/deepseek-v3.2",
        "openai/gpt-5.2-pro",
    ],
)
def test_versioned_lowercase_author_model_slugs_are_exact(model_id: str) -> None:
    assert is_exact_openrouter_model_id(model_id) is True
