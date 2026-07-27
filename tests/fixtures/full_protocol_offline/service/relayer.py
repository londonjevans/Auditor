"""Synthetic offline relayer assumption used only for scope evidence."""

from __future__ import annotations


def accepts_message(*, configured_relayer: str, caller: str, consumed: bool) -> bool:
    """Mirror the declared authorization and duplicate-consumption assumptions."""

    return caller == configured_relayer and not consumed
