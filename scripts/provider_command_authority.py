"""One canonical, secret-free authority digest for provider argv.

WorkerTransaction, provider-runtime materialization, and WER must compare the
same command bytes.  General JSON artifact digests are intentionally not reused:
some include a trailing newline or ASCII-escape Unicode, which can make the
three lifecycle layers disagree only on non-ASCII hosts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Sequence


class ProviderCommandAuthorityError(ValueError):
    """A provider command cannot be represented as one exact argv."""


def argv_authority_sha256(argv: Sequence[str]) -> str:
    """Return the canonical UTF-8 digest for one non-empty exact argv."""

    if isinstance(argv, (str, bytes)) or not argv:
        raise ProviderCommandAuthorityError(
            "provider argv must be a non-empty sequence"
        )
    values = list(argv)
    if any(
        not isinstance(value, str) or "\x00" in value
        for value in values
    ):
        raise ProviderCommandAuthorityError(
            "provider argv contains a non-string or NUL"
        )
    raw = json.dumps(
        values,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


__all__ = [
    "ProviderCommandAuthorityError",
    "argv_authority_sha256",
]
