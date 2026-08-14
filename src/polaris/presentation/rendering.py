from __future__ import annotations

import html
import re

from polaris.security.text import normalize_untrusted_text

# Escape sequences and control characters can rewrite a terminal, hide text in a log, or reorder
# what a reviewer reads. None of them belong in text drawn from a policy source or a model.
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Bidirectional overrides can visually reverse a rendered string without changing its bytes, which
# is exactly how an approver is shown one action and shown another.
_BIDI = re.compile("[‪-‮⁦-⁩]")
# Schemes that execute or embed rather than reference. An approved policy excerpt has no use for
# them, and a UI that linkifies text would otherwise turn retrieved content into a live payload.
_EXECUTABLE_SCHEME = re.compile(r"\b(?:javascript|vbscript|data|file|blob)\s*:", re.IGNORECASE)

DEFAULT_LIMIT = 2_000
TRUNCATION_MARK = "…"


def render_inert(value: str, *, limit: int = DEFAULT_LIMIT) -> str:
    """Return untrusted text as inert, escaped, single-line-safe display text.

    The contract for every consumer is: this string is plain text. Render it as text, never as HTML,
    markdown, or a terminal sequence. The escaping here is defense in depth for a consumer that
    ignores that contract — it is not permission to interpret the result.
    """

    if limit < 1:
        raise ValueError("Inert rendering limit must be at least one character")
    normalized, _ = normalize_untrusted_text(value)
    stripped = _BIDI.sub("", _CONTROL.sub("", _ANSI.sub("", normalized)))
    defanged = _EXECUTABLE_SCHEME.sub(_defang, stripped)
    escaped = html.escape(defanged, quote=True)
    if len(escaped) <= limit:
        return escaped
    return f"{escaped[: limit - 1].rstrip()}{TRUNCATION_MARK}"


def contains_active_content(value: str) -> bool:
    """Report whether the source text carried anything a renderer must not execute.

    This is a display warning, not a filter. The text is rendered inert either way; the flag lets a
    trusted surface tell a reviewer that the source contained something unusual.
    """

    normalized, _ = normalize_untrusted_text(value)
    return bool(
        _ANSI.search(normalized)
        or _CONTROL.search(value)
        or _BIDI.search(normalized)
        or _EXECUTABLE_SCHEME.search(normalized)
        or "<" in normalized
        or ">" in normalized
    )


def _defang(match: re.Match[str]) -> str:
    return match.group(0).replace(":", "[:]")
