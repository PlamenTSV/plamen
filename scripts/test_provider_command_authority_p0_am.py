from __future__ import annotations

import hashlib
import json

import pytest

from provider_command_authority import (
    ProviderCommandAuthorityError,
    argv_authority_sha256,
)


def _expected(argv: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(
            argv,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


@pytest.mark.parametrize(
    "argv",
    (
        [r"C:\Program Files\Claude\claude.exe", "-p", "audit"],
        ["/opt/Claude Tools/claude", "--model", "opus"],
        ["/tmp/κώδικας/claude", "-p", "审计"],
    ),
)
def test_argv_authority_has_one_unicode_and_space_safe_encoding(
    argv: list[str],
) -> None:
    assert argv_authority_sha256(argv) == _expected(argv)
    assert argv_authority_sha256(tuple(argv)) == _expected(argv)


@pytest.mark.parametrize(
    "argv",
    (
        "claude -p",
        b"claude",
        (),
        ("claude", 7),
        ("claude", "bad\x00value"),
    ),
)
def test_argv_authority_rejects_non_exact_commands(argv: object) -> None:
    with pytest.raises(ProviderCommandAuthorityError):
        argv_authority_sha256(argv)  # type: ignore[arg-type]
