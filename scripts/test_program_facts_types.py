from __future__ import annotations

import hashlib
import json

import pytest

from program_facts_types import (
    ProgramFactsTypeError,
    canonical_file_bytes,
    canonical_json_bytes,
    derive_stable_id,
    signed_payload,
    strict_json_loads,
    validate_portable_path,
    validate_signed_payload,
    validate_stable_id,
)


def test_canonical_json_is_compact_unicode_codepoint_sorted_and_has_no_newline() -> None:
    value = {"z": [3, True, None], "ä": "value", "a": {"β": 2, "A": 1}}
    raw = canonical_json_bytes(value)
    assert raw == (
        '{"a":{"A":1,"β":2},"z":[3,true,null],"ä":"value"}'.encode("utf-8")
    )
    assert not raw.endswith(b"\n")
    assert b"\xef\xbb\xbf" not in raw


def test_canonical_file_bytes_adds_exactly_one_lf() -> None:
    assert canonical_file_bytes({"b": 2, "a": 1}) == b'{"a":1,"b":2}\n'


@pytest.mark.parametrize(
    "value",
    [
        {"bad": 1.0},
        {"bad": float("nan")},
        {"bad": float("inf")},
        {1: "non-string-key"},
        {"bad": b"bytes"},
        {"bad": object()},
        {"bad": "e\u0301"},
        {"bad": "\ud800"},
    ],
)
def test_canonical_json_rejects_non_json_and_noncanonical_unicode(value: object) -> None:
    with pytest.raises(ProgramFactsTypeError):
        canonical_json_bytes(value)


def test_signed_payload_omits_only_its_own_digest_field() -> None:
    unsigned = {"schema_version": "fixture.v1", "rows": [{"id": "a"}]}
    signed = signed_payload(unsigned, "payload_sha256")
    expected = hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()
    assert signed == {**unsigned, "payload_sha256": expected}
    validate_signed_payload(signed, "payload_sha256")

    signed["rows"] = [{"id": "b"}]
    with pytest.raises(ProgramFactsTypeError, match="digest"):
        validate_signed_payload(signed, "payload_sha256")


@pytest.mark.parametrize(
    "raw, message",
    [
        (b'{"a":1,"a":2}\n', "duplicate"),
        (b"\xef\xbb\xbf{}\n", "BOM"),
        (b'{"a":1.0}\n', "float"),
        (b'{"a":NaN}\n', "non-finite"),
        (b"\xff\n", "UTF-8"),
    ],
)
def test_strict_json_loads_rejects_ambiguous_encodings(
    raw: bytes, message: str
) -> None:
    with pytest.raises(ProgramFactsTypeError, match=message):
        strict_json_loads(raw, require_final_lf=True)


def test_strict_json_loads_enforces_file_newline_and_canonical_bytes() -> None:
    with pytest.raises(ProgramFactsTypeError, match="final LF"):
        strict_json_loads(b'{"a":1}', require_final_lf=True)
    with pytest.raises(ProgramFactsTypeError, match="canonical"):
        strict_json_loads(b'{ "a": 1 }\n', require_final_lf=True)
    assert strict_json_loads(b'{"a":1}\n', require_final_lf=True) == {"a": 1}


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute",
        "C:/drive",
        "../escape",
        "a/../escape",
        "a\\windows",
        "a//double",
        "a/./dot",
        "a/file.sol:stream",
        "a/\x00/file",
        "a/line\nbreak.sol",
        "a/tab\tname.sol",
        "e\u0301/file.sol",
    ],
)
def test_portable_path_rejects_nonportable_or_ambiguous_forms(path: str) -> None:
    with pytest.raises(ProgramFactsTypeError):
        validate_portable_path(path)


def test_portable_path_preserves_valid_project_relative_posix_form() -> None:
    assert validate_portable_path("src/Vault.sol") == "src/Vault.sol"
    assert validate_portable_path("packages/core/lib.move") == "packages/core/lib.move"


def test_stable_id_is_content_addressed_and_prefix_checked() -> None:
    binding = {
        "source_scope_digest": "1" * 64,
        "path": "src/Vault.sol",
        "source_sha256": "2" * 64,
        "scope_class": "PRODUCTION",
    }
    expected = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()[:24]
    stable_id = derive_stable_id("PFS", binding)
    assert stable_id == f"PFS-{expected}"
    assert validate_stable_id(stable_id, "PFS") == stable_id

    with pytest.raises(ProgramFactsTypeError):
        validate_stable_id(stable_id.upper(), "PFS")
    with pytest.raises(ProgramFactsTypeError):
        validate_stable_id(stable_id, "PFN")


def test_python_json_round_trip_does_not_weaken_duplicate_key_check() -> None:
    raw = canonical_file_bytes({"schema_version": "fixture.v1", "rows": []})
    decoded = strict_json_loads(raw, require_final_lf=True)
    assert json.loads(raw) == decoded
