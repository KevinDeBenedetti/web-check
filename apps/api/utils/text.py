"""Sanitisation of text produced by scanners before it is stored, streamed or printed."""

import re
from urllib.parse import urlsplit

# C0/C1 control characters except tab and newline. Scanner output goes to the SSE
# stream, the database, the CLI's terminal and exported reports: an escape sequence
# must never reach any of them.
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

ELLIPSIS = "…"


def clean_text(value: str, max_length: int) -> str:
    """Normalise line endings, drop control characters and cap the length."""
    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = _CONTROL_CHARS.sub("", text).strip()
    if len(text) > max_length:
        text = text[: max_length - 1].rstrip() + ELLIPSIS
    return text


def safe_reference(value: str | None, max_length: int) -> str | None:
    """Keep a reference only when it is an absolute http(s) URL: clients render it as a link."""
    if value is None:
        return None
    text = clean_text(value, max_length + 1)
    if len(text) > max_length:
        return None
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    return text
