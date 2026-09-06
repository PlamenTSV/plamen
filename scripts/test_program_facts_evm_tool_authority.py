from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from program_facts_evm_helper import (
    ANALYSIS_RELEASE_STATE,
    HELPER_NAME,
    HELPER_VERSION,
    SLITHER_VERSION,
    main as helper_main,
    version_line,
)
from program_facts_evm_tool_authority import (
    EVM_TOOL_MANIFEST_PATH,
    ProgramFactsEvmToolAuthorityError,
    load_installed_evm_tool_authority,
    validate_evm_tool_manifest_bytes_structural_test_only,
)
from program_facts_types import canonical_file_bytes, canonical_json_bytes


def _resign(value: dict[str, object]) -> bytes:
    unsigned = deepcopy(value)
    unsigned.pop("manifest_sha256", None)
    value["manifest_sha256"] = hashlib.sha256(
        canonical_json_bytes(unsigned)
    ).hexdigest()
    return canonical_file_bytes(value)


def test_installed_manifest_is_exact_and_truthfully_disabled() -> None:
    authority = load_installed_evm_tool_authority()

    assert authority.production_ready is False
    assert authority.analysis_release_state == ANALYSIS_RELEASE_STATE
    assert authority.unavailable_reason == "PROVIDER_UNAVAILABLE"
    assert authority.helper_name == HELPER_NAME
    assert authority.helper_version == HELPER_VERSION
    assert authority.slither_version == SLITHER_VERSION
    assert authority.manifest_file_sha256 == hashlib.sha256(
        EVM_TOOL_MANIFEST_PATH.read_bytes()
    ).hexdigest()
    assert authority.replay().manifest_file_sha256 == (
        authority.manifest_file_sha256
    )


def test_manifest_replays_helper_parser_schema_and_distribution_pins() -> None:
    authority = load_installed_evm_tool_authority()
    root = Path(__file__).resolve().parents[1]
    record = authority.to_dict()

    for field, identity in (
        ("helper", record["helper"]["source_identity"]),
        ("parser", record["parser"]["source_identity"]),
        ("raw_schema", record["raw_schema"]["source_identity"]),
    ):
        raw = (root / identity).read_bytes()
        assert record[field]["sha256"] == hashlib.sha256(raw).hexdigest()
        assert record[field]["size_bytes"] == len(raw)
    assert record["slither_distribution"] == {
        "name": "slither-analyzer",
        "version": "0.11.5",
        "wheel_filename": "slither_analyzer-0.11.5-py3-none-any.whl",
        "wheel_sha256": (
            "3c7cb43651464543ed9152ed2f383dad4e15220b173754878ba6b291698be977"
        ),
        "sdist_filename": "slither_analyzer-0.11.5.tar.gz",
        "sdist_sha256": (
            "d90af76b86bdf7ced56fc4c8eea8792cde1ec2c375372d5e70298c2ff998d5e1"
        ),
    }


def test_structural_manifest_cannot_mint_production_and_rejects_drift() -> None:
    raw = EVM_TOOL_MANIFEST_PATH.read_bytes()
    structural = validate_evm_tool_manifest_bytes_structural_test_only(raw)
    assert structural.production_ready is False
    assert structural.authority_state == "STRUCTURAL_TEST_ONLY"

    value = json.loads(raw)
    value["helper"]["sha256"] = "0" * 64
    tampered = _resign(value)
    with pytest.raises(
        ProgramFactsEvmToolAuthorityError,
        match="helper source digest differs",
    ):
        validate_evm_tool_manifest_bytes_structural_test_only(tampered)


def test_helper_has_stable_version_and_no_semantic_success(capsys, monkeypatch) -> None:
    assert version_line() == (
        "plamen-evm-slither-helper 1.0.0 "
        "(slither-analyzer 0.11.5; "
        "disabled_pending_semantic_review)"
    )
    assert helper_main(("--version",)) == 0
    assert capsys.readouterr().out == version_line() + "\n"

    monkeypatch.setattr(
        "sys.stdin",
        type("_Input", (), {"read": lambda self: '{"schema_version":"x"}'})(),
    )
    # json.load needs an iterable file object; a StringIO is deliberately used
    # only in this unit fixture, never by production authority.
    import io

    monkeypatch.setattr("sys.stdin", io.StringIO('{"schema_version":"x"}'))
    assert helper_main(("--stdin-json",)) == 78
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "disabled pending independent review" in captured.err
