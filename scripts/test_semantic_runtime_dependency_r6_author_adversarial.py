"""Author reds for canonical RECORD replay and immutable dependency import.

R6 is deliberately narrower than a generic package installer.  It proves that
the exact dependency bytes admitted by the semantic executor cannot change
between validation and import.  Windows is the only native executor currently
supported, so the positive sealing fixture is Windows-only; every other host
must report typed capability debt before provider launch.
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import sys

import pytest


SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import isolated_execution_host as H  # noqa: E402
import worker_execution_receipts as W  # noqa: E402


def _digest(raw: bytes) -> str:
    return base64.urlsafe_b64encode(
        hashlib.sha256(raw).digest()
    ).decode("ascii").rstrip("=")


@pytest.mark.parametrize(
    "record_path",
    (
        ".",
        "./module.py",
        "package/.",
        "package/../module.py",
        "../module.py",
        "package//module.py",
        r"package\module.py",
        "/module.py",
        "C:/module.py",
        "C:module.py",
        "package/C:/module.py",
        "package/:/module.py",
        "package/name:stream.py",
    ),
)
def test_record_path_is_canonical_posix_wheel_member(
    tmp_path: Path,
    record_path: str,
) -> None:
    raw = b"x"
    record = (
        f"{record_path},sha256={_digest(raw)},{len(raw)}\n"
    ).encode("utf-8")
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="RECORD path|canonical|alias",
    ):
        H._distribution_record_entries(record, root=tmp_path.resolve())


@pytest.mark.parametrize(
    "encoded",
    (
        lambda value: value + "=",
        lambda value: value + "===",
        lambda value: value.replace("-", "+"),
        lambda value: value.replace("_", "/"),
    ),
)
def test_record_digest_requires_exact_unpadded_urlsafe_roundtrip(
    encoded: object,
) -> None:
    # A digest with both URL-safe alphabet characters makes the alphabet
    # substitutions observable.
    canonical = base64.urlsafe_b64encode(
        bytes([251, 255]) * 16
    ).decode("ascii").rstrip("=")
    candidate = encoded(canonical)  # type: ignore[operator]
    assert candidate != canonical
    assert H._record_sha256(f"sha256={candidate}") is None


def test_runtime_file_hardlink_is_not_an_import_authority(
    tmp_path: Path,
) -> None:
    original = tmp_path / "origin.py"
    alias = tmp_path / "alias.py"
    original.write_bytes(b"x = 1\n")
    os.link(original, alias)
    assert alias.stat().st_nlink > 1
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="hardlink|link count|alias|race",
    ):
        H._assert_runtime_path_chain(
            alias.resolve(strict=True),
            label="R6 hardlinked runtime file",
        )


def test_runtime_file_reparse_origin_is_not_an_import_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    origin = (tmp_path / "origin.py").resolve()
    origin.write_bytes(b"x = 1\n")
    origin_key = os.path.normcase(str(origin))
    monkeypatch.setattr(
        H,
        "_runtime_path_is_alias",
        lambda candidate: (
            os.path.normcase(str(Path(candidate))) == origin_key
        ),
    )
    with pytest.raises(
        H.IsolatedExecutionProtocolError,
        match="reparse|alias|race",
    ):
        H._assert_runtime_path_chain(
            origin,
            label="R6 reparse runtime file",
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows sealed-stage primitive")
def test_sealed_stage_blocks_source_and_stage_mutation_until_import_finishes(
    tmp_path: Path,
) -> None:
    source = tmp_path / "dependency.py"
    source.write_bytes(b"VALUE = 1\n")
    raw = source.read_bytes()
    record = {
        "path": str(source.resolve(strict=True)),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
    }
    stage_root = tmp_path / "stage"
    stage_root.mkdir()
    stage = H._WindowsImmutableDependencyStage(stage_root.resolve())
    try:
        staged = stage.copy_verified(
            record,
            relative=Path("dependency.py"),
        )
        assert staged.read_bytes() == raw
        with pytest.raises(OSError):
            source.write_bytes(b"VALUE = 2\n")
        with pytest.raises(OSError):
            staged.write_bytes(b"VALUE = 3\n")
        assert staged.read_bytes() == raw
        stage.verify_all()
    finally:
        stage.close()


def test_unavailable_immutable_stage_is_typed_capability_debt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(H.os, "name", "unsupported-r6")
    with pytest.raises(
        H.SemanticDependencyIsolationUnavailable,
        match="immutable|unsupported|capability",
    ) as caught:
        H._create_immutable_dependency_stage(tmp_path)
    assert caught.value.reason_code == (
        "RUNTIME_DEPENDENCY_IMMUTABILITY_UNAVAILABLE"
    )


def test_pep660_editable_authority_is_typed_fail_closed(
    tmp_path: Path,
) -> None:
    direct_url = tmp_path / "direct_url.json"
    direct_url.write_text(
        '{"dir_info":{"editable":true},"url":"file:///mutable-source"}',
        encoding="utf-8",
    )
    with pytest.raises(
        W.SemanticRuntimeDependencyUnsupported,
        match="PEP-660|editable",
    ) as caught:
        W._reject_pep660_editable_authority(
            direct_url,
            distribution_name="fixture-distribution",
        )
    assert caught.value.reason_code == (
        "RUNTIME_DEPENDENCY_EDITABLE_UNSUPPORTED"
    )
