"""Privacy, path, deterministic snapshot, index, and seal fixtures for RB-1."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

import runbundle_privacy as P


PAYLOADS = {
    "run_manifest.json": b'{"fixture":"manifest"}\n',
    "phase_events.jsonl": b'{"fixture":"event"}\n',
    "candidate_findings.json": b'{"fixture":"candidates"}\n',
    "candidate_lineage.json": b'{"fixture":"lineage"}\n',
    "raw_outputs.json": b'{"fixture":"raw"}\n',
    "report_projection.json": b'{"fixture":"report"}\n',
    "harvest_receipt.json": b'{"fixture":"receipt"}\n',
}


def _staging_tree(root: Path) -> None:
    root.mkdir()
    for relative, raw in PAYLOADS.items():
        (root / relative).write_bytes(raw)
    (root / "objects" / "sha256").mkdir(parents=True)
    blob = b"binary object fixture\x00"
    (root / "objects" / "sha256" / hashlib.sha256(blob).hexdigest()).write_bytes(blob)


def _seal_tree(root: Path) -> dict[str, object]:
    index = P.build_bundle_index(root)
    (root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    (root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    return index


@pytest.mark.parametrize(
    "value",
    [
        "../answer.json",
        "scratch/../../answer.json",
        "/etc/passwd",
        r"C:\Users\name\answer.json",
        "C:/Users/name/answer.json",
        r"\\server\share\answer.json",
        "//server/share/answer.json",
        r"safe\wrong-separator.json",
        "safe/file.txt:secret",
        "safe/./file.json",
        "safe//file.json",
        "safe/NUL.txt",
        "safe/trailing. ",
        "\x00bad",
    ],
)
def test_unsafe_relative_paths_are_rejected(value: str):
    with pytest.raises(P.RunBundlePrivacyError, match="relative path"):
        P.assert_safe_relative_path(value)


@pytest.mark.parametrize(
    "value",
    [
        "src/Vault.sol",
        ".scratchpad/recon/findings.md",
        "objects/sha256/" + ("a" * 64),
    ],
)
def test_safe_relative_paths_are_preserved_exactly(value: str):
    assert P.assert_safe_relative_path(value) == value


def test_casefold_and_unicode_normalization_collisions_are_rejected():
    with pytest.raises(P.RunBundlePrivacyError, match="casefold collision"):
        P.assert_no_casefold_collisions(["src/Vault.sol", "SRC/vault.sol"])
    with pytest.raises(P.RunBundlePrivacyError, match="normalized"):
        P.assert_safe_relative_path("docs/e\u0301.md")


@pytest.mark.parametrize(
    "payload",
    [
        {"innocent": r"C:\Users\alice\Downloads\gt.json"},
        {"innocent": "/home/alice/private/answer.json"},
        {"innocent": "-----BEGIN PRIVATE KEY-----\nnot-public"},
        {"innocent": "Authorization: Bearer secret-token-value"},
        {"innocent": "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"},
        {"innocent": "plamen.private-case-lock.v2"},
        {"candidateMatch": "issue-1"},
        {"root_cause": "root-1"},
        {"expectedCount": 7},
    ],
)
def test_public_payload_privacy_scan_blocks_paths_secrets_and_private_semantics(
    payload,
):
    with pytest.raises(P.RunBundlePrivacyError):
        P.validate_public_payload(payload)


@pytest.mark.parametrize(
    "schema_marker",
    [
        "plamen.hidden-private-roster.v9",
        "plamen.score.v2",
        "plamen.reference-answer.v1",
        "plamen.gt-lock.v2",
        "plamen.ground_truth-annotation.v2",
    ],
)
def test_all_private_gt_reference_and_score_schema_variants_are_rejected(
    schema_marker: str,
):
    with pytest.raises(P.RunBundlePrivacyError, match="private contract|schema"):
        P.validate_public_payload({"schema_version": schema_marker})


@pytest.mark.parametrize(
    "physical_path",
    [
        "leaked from /root/private/gt.json",
        "leaked from /opt/corpus/answer.json",
        "leaked from /workspace/evaluator/answer.json",
        "leaked from /data/private/reference.json",
        "leaked from /app/private/audit.md",
        "leaked from /build/worker/secrets.env",
        "leaked from /foo/bar/baz",
        "leaked from /customroot",
        "leaked from /srv/evaluator/private.json",
        "leaked from /mnt/control/gt.json",
        "leaked from /media/disk/reference.json",
        "leaked from /home/alice/gt.json",
        "leaked from /Users/alice/gt.json",
        "leaked from /private/var/answer.json",
        "leaked from /var/tmp/answer.json",
        "leaked from /tmp/answer.json",
        r"leaked from C:\Users\alice\answer.json",
        r"leaked from \\server\share\answer.json",
        "leaked from ~/private/answer.json",
        "leaked from $HOME/private/answer.json",
        "leaked from ${HOME}/private/answer.json",
        "leaked from %USERPROFILE%/private/answer.json",
    ],
)
def test_embedded_physical_paths_are_rejected(physical_path: str):
    with pytest.raises(P.RunBundlePrivacyError, match="path"):
        P.validate_public_payload({"description": physical_path})


def test_benign_private_score_reference_prose_and_source_comments_are_allowed():
    payload = {
        "description": (
            "A private helper receives a score parameter and reference value."
        ),
        "content": "// SPDX-License-Identifier: MIT\ncontract Fixture {}\n",
        "documentation_url": "https://example.invalid/reference/score",
    }
    assert P.validate_public_payload(payload) is payload


@pytest.mark.parametrize(
    "payload",
    [
        {"api_k-e-y": "public-looking-but-secret-value"},
        {"PASSWORD": "correct horse battery staple"},
        {"credentials": {"part_a": "sk-proj-", "part_b": "A" * 30}},
        {"outer": [{"authorization": {"scheme": "Bearer", "value": "A" * 24}}]},
        {"parts": ["sk-proj-", "B" * 30]},
    ],
)
def test_field_aware_recursive_privacy_rejects_nested_and_split_credentials(
    payload,
):
    with pytest.raises(P.RunBundlePrivacyError, match="credential"):
        P.validate_public_payload(payload)


@pytest.mark.parametrize(
    "token",
    [
        "xox" + "b-123456789012-abcdefghijklmnopqrst",
        "AK" + "IA1234567890ABCDEF",
        "gh" + "p_abcdefghijklmnopqrstuvwxyz123456",
    ],
    ids=["slack", "aws-access-key-id", "github"],
)
def test_json_and_binary_use_one_canonical_secret_signature_policy(
    token: str,
):
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_payload({"description": token})
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_object_bytes(
            token.encode("ascii"),
            media_type="application/octet-stream",
        )


def test_field_aware_privacy_does_not_overreach_on_benign_key_and_secret_prose():
    payload = {
        "key_count": 2,
        "key_rotation_enabled": True,
        "description": (
            "The function accepts a password label, a private key type, "
            "and a credential count but contains no credential value."
        ),
        "source_contract_ref": "typed-reference-contract.v1",
        "documentation_url": "https://example.invalid/data/reference",
    }
    assert P.validate_public_payload(payload) is payload


def test_textual_and_binary_object_privacy_scans_fail_closed():
    with pytest.raises(P.RunBundlePrivacyError, match="path"):
        P.validate_public_object_bytes(
            b"worker copied /arbitrary/private/output.json",
            media_type="text/plain",
        )
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_object_bytes(
            b"\x00\xffBEGIN\x00-----BEGIN PRIVATE KEY-----\x00binary",
            media_type="application/octet-stream",
        )
    assert (
        P.validate_public_object_bytes(
            b"see https://example.invalid/foo/bar",
            media_type="text/plain",
        )
        is None
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"binary-labeled UTF-8 leaked from /app/private/audit.md",
        b"sk-proj-ABCDEFGHIJ\x00KLMNOPQRSTUVWXYZ",
        b"Authorization:\x00Bearer\x00abcdefghijklmnopqrstuvwx",
    ],
)
def test_binary_mime_scans_utf8_text_and_bounded_split_secret_signatures(raw):
    with pytest.raises(P.RunBundlePrivacyError, match="path|credential|secret"):
        P.validate_public_object_bytes(
            raw,
            media_type="application/octet-stream",
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"\xffapi_\x00key=\x00abcdefghijk",
        b"\xffaccess_\x00token=\x00abcdefghijklmnopqrst",
        b"\xffclient_\x00secret=\x00abcdefghijkl",
        b"\xffpass\x00word=\x00abcdefghijk",
        b"\xffxox" + b"b-123456789012-abcdefghijklmnopqrst",
        (b"A" * ((1 << 20) - 6))
        + b":api_\x00key=\x00abcdefghijk"
        + b"\xff",
    ],
    ids=[
        "invalid-utf8-api-key",
        "invalid-utf8-access-token",
        "invalid-utf8-client-secret",
        "invalid-utf8-password",
        "invalid-utf8-xox-token",
        "compact-chunk-boundary-api-key",
    ],
)
def test_invalid_utf8_binary_generic_and_chunk_boundary_secrets_are_rejected(raw):
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_object_bytes(
            raw,
            media_type="application/octet-stream",
        )


@pytest.mark.parametrize(
    "raw",
    [
        b"xoxb-123456\xff789012-abcdefghijklmnopqrst",
        b"AKIA12345678\xff90ABCDEF",
        b"ghp_abcdefghij\xffklmnopqrstuvwxyz123456",
    ],
    ids=[
        "slack-invalid-byte-obfuscation",
        "aws-invalid-byte-obfuscation",
        "github-invalid-byte-obfuscation",
    ],
)
def test_invalid_bytes_cannot_obfuscate_canonical_secret_signatures(raw: bytes):
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_object_bytes(
            raw,
            media_type="application/octet-stream",
        )


@pytest.mark.parametrize(
    "raw, expected",
    [
        (
            b"prefix C:\xff\\Users\\alice\\private\\audit.md suffix",
            "absolute",
        ),
        (
            b"prefix /home/\xffalice/private/audit.md suffix",
            "absolute",
        ),
        (
            b"plamen.private-\xffcase-lock.v1",
            "private|reference|score",
        ),
        (
            b"plamen.reference-\xfffinding.v1",
            "private|reference|score",
        ),
    ],
    ids=[
        "windows-path-compact-projection",
        "posix-path-compact-projection",
        "private-schema-compact-projection",
        "reference-schema-compact-projection",
    ],
)
def test_invalid_utf8_binary_projections_scan_paths_and_private_schema_markers(
    raw: bytes,
    expected: str,
):
    with pytest.raises(P.RunBundlePrivacyError, match=expected):
        P.validate_public_object_bytes(
            raw,
            media_type="application/octet-stream",
        )


_NEW_CREDENTIAL_SIGNATURES = {
    "npm": "npm_" + ("A" * 36),
    "google-api": "AIza" + ("A" * 35),
    "stripe-live-secret": "sk_live_" + ("A" * 24),
}


@pytest.mark.parametrize(
    "token",
    list(_NEW_CREDENTIAL_SIGNATURES.values()),
    ids=list(_NEW_CREDENTIAL_SIGNATURES),
)
@pytest.mark.parametrize(
    "carrier",
    ["json", "text", "binary", "invalid-byte-projection"],
)
def test_versioned_credential_registry_is_shared_across_all_public_carriers(
    token: str,
    carrier: str,
):
    if carrier == "json":
        with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
            P.validate_public_payload({"public_value": token})
        return
    raw = token.encode("ascii")
    media_type = (
        "text/plain" if carrier == "text" else "application/octet-stream"
    )
    if carrier == "invalid-byte-projection":
        midpoint = len(raw) // 2
        raw = raw[:midpoint] + b"\xff" + raw[midpoint:]
    with pytest.raises(P.RunBundlePrivacyError, match="credential|secret"):
        P.validate_public_object_bytes(raw, media_type=media_type)


@pytest.mark.parametrize(
    "value",
    [
        "npm_package_name",
        "npm_" + ("A" * 35),
        "npm_" + ("A" * 37),
        "AIza" + ("A" * 34),
        "AIza" + ("A" * 36),
        "pk_live_" + ("A" * 24),
        "sk_test_" + ("A" * 24),
        "sk_live_example_documentation_token",
    ],
)
def test_narrow_new_credential_signatures_preserve_documentation_false_positives(
    value: str,
):
    payload = {"public_value": value}
    assert P.validate_public_payload(payload) == payload
    P.validate_public_object_bytes(
        value.encode("ascii"),
        media_type="text/plain",
    )
    P.validate_public_object_bytes(
        b"\xff" + value.encode("ascii") + b"\xff",
        media_type="application/octet-stream",
    )


def test_compact_projection_property_rejects_every_new_signature_split():
    for token in _NEW_CREDENTIAL_SIGNATURES.values():
        raw = token.encode("ascii")
        for split in range(1, len(raw)):
            obfuscated = raw[:split] + b"\xff" + raw[split:]
            with pytest.raises(
                P.RunBundlePrivacyError,
                match="credential|secret",
            ):
                P.validate_public_object_bytes(
                    obfuscated,
                    media_type="application/octet-stream",
                )


def test_public_structural_scan_policy_is_versioned_evaluator_owned_and_narrow():
    preimage = P.public_structural_scan_policy_preimage()
    assert preimage["policy_id"] == (
        "plamen.runbundle-public-structural-exclusion-policy"
    )
    assert preimage["policy_version"] == "1"
    assert preimage["claim_scope"] == "PUBLIC_STRUCTURAL_EXCLUSION_ONLY"
    serialized = repr(preimage).casefold()
    assert "ground_truth_isolation" not in serialized
    assert "private_corpus_isolation" not in serialized
    assert P.public_structural_scan_policy_sha256() == P.sha256_bytes(
        P._canonical_json_bytes(preimage)
    )
    registry = preimage["credential_signature_registry"]
    assert registry["registry_version"] == P.CREDENTIAL_SIGNATURE_REGISTRY_VERSION
    assert {
        row["signature_id"] for row in registry["signatures"]
    }.issuperset({"npm-access-token", "google-api-key", "stripe-live-secret"})


def test_private_token_scan_rejects_innocent_key_without_echo_or_hash():
    token = "corpus-private-canary-91a72"
    with pytest.raises(P.RunBundlePrivacyError) as raised:
        P.validate_public_payload(
            {"description": f"ordinary prose {token} ordinary prose"},
            forbidden_tokens=[token],
        )
    message = str(raised.value)
    assert token not in message
    assert hashlib.sha256(token.encode()).hexdigest() not in message


def test_configured_forbidden_field_alias_is_normalized_and_rejected():
    with pytest.raises(P.RunBundlePrivacyError, match="configured"):
        P.validate_public_payload(
            {"benchmarkReference": "opaque"},
            forbidden_field_aliases=["benchmark-reference"],
        )


def test_fixed_blinding_field_names_are_allowed_only_when_false():
    payload = {
        "ground_truth_available_to_runner": False,
        "private_case_lock_available_to_runner": False,
        "grader_labels_available_to_runner": False,
    }
    assert P.validate_public_payload(payload) is payload
    payload["ground_truth_available_to_runner"] = True
    with pytest.raises(P.RunBundlePrivacyError, match="must be false"):
        P.validate_public_payload(payload)


def test_tree_inventory_is_sorted_stable_and_casefold_safe(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "tree"
    (root / "z").mkdir(parents=True)
    (root / "a").mkdir()
    (root / "z" / "two.txt").write_bytes(b"two")
    (root / "a" / "one.txt").write_bytes(b"one")
    first = P.inspect_regular_tree(root)
    second = P.inspect_regular_tree(root)
    assert first == second
    assert P.inspect_exact_tree(root)["directories"] == ["a", "z"]
    assert [row["relative_path"] for row in first] == [
        "a/one.txt",
        "z/two.txt",
    ]

    # A case-insensitive filesystem cannot physically create both spellings.
    # Inject the ambiguous directory roster at the enumeration boundary so the
    # same fail-closed behavior is exercised on Windows and POSIX.
    original = P._sorted_entry_names
    monkeypatch.setattr(
        P,
        "_sorted_entry_names",
        lambda path: ["A", "a", "z"] if path == root else original(path),
    )
    with pytest.raises(P.RunBundlePrivacyError, match="casefold collision"):
        P.inspect_regular_tree(root)


def test_tree_inventory_rejects_symlinks_reparse_and_hardlinks(
    tmp_path: Path, monkeypatch
):
    target = tmp_path / "target.txt"
    target.write_bytes(b"target")
    symlink_root = tmp_path / "symlink-tree"
    symlink_root.mkdir()
    link = symlink_root / "link.txt"
    try:
        os.symlink(target, link)
    except OSError as exc:
        pytest.skip(f"fixture filesystem cannot create a symlink: {exc}")
    with pytest.raises(P.RunBundlePrivacyError, match="link|reparse"):
        P.inspect_regular_tree(symlink_root)

    reparse_root = tmp_path / "reparse-tree"
    reparse_root.mkdir()
    marker = reparse_root / "marker.txt"
    marker.write_bytes(b"marker")
    original = P._is_reparse_point
    monkeypatch.setattr(
        P,
        "_is_reparse_point",
        lambda path, row=None: path == marker or original(path, row),
    )
    with pytest.raises(P.RunBundlePrivacyError, match="reparse"):
        P.inspect_regular_tree(reparse_root)
    monkeypatch.setattr(P, "_is_reparse_point", original)

    hardlink_root = tmp_path / "hardlink-tree"
    hardlink_root.mkdir()
    first = hardlink_root / "first.txt"
    second = hardlink_root / "second.txt"
    first.write_bytes(b"same inode")
    try:
        os.link(first, second)
    except OSError as exc:
        pytest.skip(f"fixture filesystem cannot create a hardlink: {exc}")
    with pytest.raises(P.RunBundlePrivacyError, match="hardlink"):
        P.inspect_regular_tree(hardlink_root)


@pytest.mark.skipif(os.name != "nt", reason="NTFS ADS is Windows-specific")
def test_physical_ntfs_alternate_data_stream_is_rejected(tmp_path: Path):
    root = tmp_path / "ads-tree"
    root.mkdir()
    ordinary = root / "ordinary.txt"
    ordinary.write_bytes(b"public")
    stream = Path(str(ordinary) + ":private-stream")
    try:
        stream.write_bytes(b"private")
    except OSError as exc:
        pytest.skip(f"fixture volume does not support named streams: {exc}")
    with pytest.raises(P.RunBundlePrivacyError, match="alternate data stream"):
        P.inspect_exact_tree(root)


@pytest.mark.skipif(os.name != "nt", reason="Windows ctypes ABI is Windows-specific")
def test_windows_stream_abi_is_process_stable_across_repeated_enumeration(
    tmp_path: Path,
):
    ordinary = tmp_path / "ordinary.txt"
    ordinary.write_bytes(b"public")
    stream_type = P._WINDOWS_FIND_STREAM_DATA
    first_argtypes = tuple(P._WINDOWS_FIND_FIRST_STREAM.argtypes)
    next_argtypes = tuple(P._WINDOWS_FIND_NEXT_STREAM.argtypes)

    for _ in range(256):
        assert P._enumerate_windows_streams(ordinary) == ("::$DATA",)
        assert P._WINDOWS_FIND_STREAM_DATA is stream_type
        assert tuple(P._WINDOWS_FIND_FIRST_STREAM.argtypes) == first_argtypes
        assert tuple(P._WINDOWS_FIND_NEXT_STREAM.argtypes) == next_argtypes


@pytest.mark.skipif(os.name != "nt", reason="NTFS directory ADS is Windows-specific")
def test_physical_ntfs_directory_alternate_data_stream_is_rejected(
    tmp_path: Path,
):
    root = tmp_path / "directory-ads-tree"
    child = root / "ordinary-directory"
    child.mkdir(parents=True)
    stream = Path(str(child) + ":private-stream")
    try:
        stream.write_bytes(b"private")
    except OSError as exc:
        pytest.skip(f"directory named-stream primitive unavailable: {exc}")
    with pytest.raises(P.RunBundlePrivacyError, match="alternate data stream"):
        P.inspect_exact_tree(root)


@pytest.mark.skipif(os.name != "nt", reason="junctions are Windows-specific")
def test_physical_windows_junction_is_rejected(tmp_path: Path):
    target = tmp_path / "junction-target"
    target.mkdir()
    root = tmp_path / "junction-tree"
    root.mkdir()
    junction = root / "junction"
    completed = subprocess.run(
        ["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode:
        pytest.skip("fixture environment cannot create a directory junction")
    with pytest.raises(P.RunBundlePrivacyError, match="link|reparse"):
        P.inspect_exact_tree(root)


def test_physical_sparse_file_is_rejected_when_supported(tmp_path: Path):
    root = tmp_path / "sparse-tree"
    root.mkdir()
    sparse = root / "sparse.bin"
    sparse.write_bytes(b"physical sparse fixture")
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            create_file = kernel32.CreateFileW
            create_file.argtypes = [
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ]
            create_file.restype = wintypes.HANDLE
            device_io = kernel32.DeviceIoControl
            device_io.argtypes = [
                wintypes.HANDLE,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ]
            device_io.restype = wintypes.BOOL
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = [wintypes.HANDLE]
            close_handle.restype = wintypes.BOOL
            handle = create_file(
                str(sparse),
                0xC0000000,
                0x00000007,
                None,
                3,
                0x80,
                None,
            )
            if handle == ctypes.c_void_p(-1).value:
                raise OSError(ctypes.get_last_error(), "CreateFileW failed")
            try:
                returned = wintypes.DWORD()
                if not device_io(
                    handle,
                    0x000900C4,  # FSCTL_SET_SPARSE
                    None,
                    0,
                    None,
                    0,
                    ctypes.byref(returned),
                    None,
                ):
                    raise OSError(
                        ctypes.get_last_error(), "FSCTL_SET_SPARSE failed"
                    )
            finally:
                close_handle(handle)
        except (AttributeError, OSError) as exc:
            pytest.skip(f"FSCTL_SET_SPARSE primitive unavailable: {exc}")
    else:
        with sparse.open("wb") as handle:
            handle.seek(8 * 1024 * 1024)
            handle.write(b"\0")
    row = sparse.stat()
    attributes = int(getattr(row, "st_file_attributes", 0) or 0)
    blocks = getattr(row, "st_blocks", None)
    physically_sparse = bool(
        attributes & 0x200
        or (
            isinstance(blocks, int)
            and row.st_size > 4096
            and blocks * 512 < row.st_size
        )
    )
    if not physically_sparse:
        pytest.skip("sparse-file primitive unavailable on fixture filesystem")
    with pytest.raises(P.RunBundlePrivacyError, match="sparse"):
        P.inspect_exact_tree(root)


def test_ads_is_checked_on_root_and_every_directory_before_and_after_enumeration(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "ads-directory-coverage"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "file.txt").write_bytes(b"fixture")
    calls: list[Path] = []
    monkeypatch.setattr(
        P,
        "_assert_no_alternate_data_streams",
        lambda path: calls.append(Path(path)),
    )
    P.inspect_exact_tree(root)
    for directory in (root, root / "a", root / "a" / "b"):
        assert calls.count(directory) >= 2


@pytest.mark.skipif(os.name != "nt", reason="ADS inspection applies on Windows")
def test_unavailable_ads_inspection_refuses_a_false_clean_result(
    tmp_path: Path, monkeypatch
):
    root = tmp_path / "ads-inspection-debt"
    root.mkdir()
    (root / "ordinary.txt").write_bytes(b"public")
    monkeypatch.setattr(
        P,
        "_enumerate_windows_streams",
        lambda path: (_ for _ in ()).throw(NotImplementedError()),
    )
    with pytest.raises(P.RunBundlePrivacyError, match="ADS_INSPECTION_UNAVAILABLE"):
        P.inspect_exact_tree(root)


def test_snapshot_and_double_read_detect_input_mutation(tmp_path: Path):
    root = tmp_path / "inputs"
    root.mkdir()
    (root / "a.json").write_bytes(b'{"a":1}\n')
    before = P.snapshot_export_inputs(root)
    assert P.verify_export_inputs_unchanged(root, before) == before
    (root / "a.json").write_bytes(b'{"a":2}\n')
    with pytest.raises(P.RunBundlePrivacyError, match="changed"):
        P.verify_export_inputs_unchanged(root, before)


def test_snapshot_detects_added_or_removed_empty_directories(tmp_path: Path):
    root = tmp_path / "directory-inputs"
    root.mkdir()
    (root / "artifact.json").write_bytes(b"{}\n")
    before = P.snapshot_export_inputs(root)
    (root / "unexpected-empty").mkdir()
    with pytest.raises(P.RunBundlePrivacyError, match="changed"):
        P.verify_export_inputs_unchanged(root, before)


def test_double_export_requires_two_complete_sealed_trees(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    _staging_tree(first)
    _staging_tree(second)
    _seal_tree(first)
    _seal_tree(second)
    seal = P.assert_deterministic_exports(first, second)
    assert seal == P.bundle_seal_sha256(P.verify_bundle_index(first))


def test_double_export_materializer_is_invoked_twice_into_fresh_trees(
    tmp_path: Path, monkeypatch,
):
    import runbundle_contracts as C

    calls: list[Path] = []
    verified: list[Path] = []

    def materialize(root: Path) -> None:
        assert not root.exists()
        calls.append(root)
        _staging_tree(root)
        _seal_tree(root)

    first = tmp_path / "independent-first"
    second = tmp_path / "independent-second"
    def fake_verify(root, exact_public_lock_bytes):
        del exact_public_lock_bytes
        bundle = Path(root)
        verified.append(bundle)
        index = P.verify_bundle_index(bundle)
        files = tuple(
            (
                row["relative_path"],
                P.read_stable_regular_bytes(bundle / row["relative_path"]),
            )
            for row in P.inspect_exact_tree(bundle)["files"]
        )
        return SimpleNamespace(
            verified_files=files,
            bundle_seal_sha256=P.bundle_seal_sha256(index),
            verification_sha256="fixture-verification",
        )

    monkeypatch.setattr(C, "verify_runbundle_v2", fake_verify)
    seal = P.prove_deterministic_double_export(
        materialize,
        first,
        second,
        exact_public_lock_bytes=b"canonical-lock-fixture\n",
    )
    assert calls == [first, second]
    assert verified == [first, second]
    assert seal == P.bundle_seal_sha256(P.verify_bundle_index(first))


def test_double_export_compares_exact_object_index_and_seal_bytes(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    _staging_tree(first)
    _staging_tree(second)
    _seal_tree(first)
    object_file = next((second / "objects" / "sha256").iterdir())
    object_file.write_bytes(b"different object bytes")
    object_file.rename(
        object_file.with_name(hashlib.sha256(b"different object bytes").hexdigest())
    )
    _seal_tree(second)
    with pytest.raises(P.RunBundlePrivacyError, match="nondeterministic"):
        P.assert_deterministic_exports(first, second)

    with pytest.raises(P.RunBundlePrivacyError, match="complete sealed"):
        P.assert_deterministic_exports({}, {})


def test_bundle_index_and_seal_are_canonical_and_verify_exact_tree(tmp_path: Path):
    root = tmp_path / "bundle"
    _staging_tree(root)
    index_one = P.build_bundle_index(root)
    index_two = P.build_bundle_index(root)
    assert index_one == index_two
    assert P.bundle_index_bytes(index_one).endswith(b"\n")
    assert P.bundle_seal_sha256(index_one) == hashlib.sha256(
        P.bundle_index_bytes(index_one)
    ).hexdigest()

    (root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index_one))
    (root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index_one).encode("ascii") + b"\n"
    )
    assert P.verify_bundle_index(root) == index_one

    (root / "candidate_findings.json").write_bytes(b"tampered\n")
    with pytest.raises(P.RunBundlePrivacyError, match="index|digest|length"):
        P.verify_bundle_index(root)


def test_index_only_interrupted_staging_can_rebuild_but_cannot_verify(tmp_path: Path):
    root = tmp_path / "interrupted-bundle"
    _staging_tree(root)
    index = P.build_bundle_index(root)
    (root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    assert P.build_bundle_index(root) == index
    with pytest.raises(P.RunBundlePrivacyError, match="incomplete"):
        P.verify_bundle_index(root)


def test_unindexed_file_and_bad_object_name_fail_closed(tmp_path: Path):
    root = tmp_path / "bundle"
    _staging_tree(root)
    index = P.build_bundle_index(root)
    (root / "bundle_index.json").write_bytes(P.bundle_index_bytes(index))
    (root / "SEALED.sha256").write_bytes(
        P.bundle_seal_sha256(index).encode("ascii") + b"\n"
    )
    (root / "unexpected.txt").write_text("not indexed", encoding="utf-8")
    with pytest.raises(P.RunBundlePrivacyError, match="root entry|index"):
        P.verify_bundle_index(root)

    other = tmp_path / "bad-object"
    _staging_tree(other)
    blob = next((other / "objects" / "sha256").iterdir())
    blob.rename(blob.with_name("0" * 64))
    with pytest.raises(P.RunBundlePrivacyError, match="object"):
        P.build_bundle_index(other)


def test_unexpected_empty_or_nested_object_directories_fail_closed(tmp_path: Path):
    root = tmp_path / "unexpected-directory"
    _staging_tree(root)
    (root / "objects" / "sha256" / "empty").mkdir()
    with pytest.raises(P.RunBundlePrivacyError, match="directory"):
        P.build_bundle_index(root)
