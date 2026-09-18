"""Helpers for producing safe Python names in generated tests."""

from __future__ import annotations

import re

_INVALID_IDENTIFIER_CHARS = re.compile(r"[^0-9A-Za-z_]+")
_REPEATED_UNDERSCORES = re.compile(r"_+")


def identifier(value: str, *, fallback: str = "case") -> str:
    """Convert arbitrary text to a stable lowercase Python-style identifier."""
    value = _INVALID_IDENTIFIER_CHARS.sub("_", value)
    value = _REPEATED_UNDERSCORES.sub("_", value).strip("_").lower()

    if not value:
        return fallback

    if value[0].isdigit():
        return f"{fallback}_{value}"

    return value
