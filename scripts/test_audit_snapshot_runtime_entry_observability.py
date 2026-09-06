from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

import pytest

import audit_snapshot as snapshot


def _toolchain(
    runtime_entries: list[tuple[str, bytes]],
    *,
    persistent: bytes = b"persistent-toolchain",
) -> dict[str, Any]:
    entries: list[tuple[str, snapshot.EntryPayload]] = [
        ("scripts/static.py", persistent),
        *runtime_entries,
    ]
    component = snapshot._digest_entries(entries)
    component["runtime_entries"] = snapshot._runtime_entry_manifest(entries)
    return component


def _sealed_snapshot(toolchain: dict[str, Any]) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": snapshot.SNAPSHOT_SCHEMA,
        "components": {
            "source_scope": {
                "digest": "1" * 64,
                "path_set_digest": "2" * 64,
                "file_count": 1,
                "byte_count": 1,
                "language": "evm",
                "pipeline": "sc",
                "git_head": "UNAVAILABLE",
                "coverage_limitations": [],
            },
            "audit_config": {"digest": "3" * 64, "field_count": 1},
            "methodology": {
                "digest": "4" * 64,
                "path_set_digest": "5" * 64,
                "file_count": 1,
                "byte_count": 1,
            },
            "toolchain": toolchain,
        },
    }
    value["snapshot_digest"] = snapshot._sha256(snapshot._canonical_json(value))
    assert snapshot._valid_snapshot(value)
    return value


def _reseal(value: dict[str, Any]) -> None:
    value.pop("snapshot_digest", None)
    value["snapshot_digest"] = snapshot._sha256(snapshot._canonical_json(value))


def test_toolchain_component_persists_only_runtime_digest_and_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = b"PLAMEN_PRIVATE_VALUE=do-not-persist"
    runtime = [
        ("@runtime/tool/claude", b"claude-2.1.252"),
        ("@runtime/semantic_env", secret),
        ("@runtime/python", b"python-3.12"),
    ]
    monkeypatch.setattr(
        snapshot,
        "_tree_entries",
        lambda *_args, **_kwargs: [("scripts/static.py", b"static")],
    )
    monkeypatch.setattr(
        snapshot,
        "_runtime_tool_entries",
        lambda **_kwargs: list(reversed(runtime)),
    )

    component = snapshot._toolchain_component(tmp_path, project_root=tmp_path)

    manifest = component["runtime_entries"]
    assert list(manifest) == sorted(identity for identity, _payload in runtime)
    assert manifest["@runtime/semantic_env"] == {
        "sha256": hashlib.sha256(secret).hexdigest(),
        "byte_count": len(secret),
    }
    encoded = json.dumps(manifest, sort_keys=True)
    assert "do-not-persist" not in encoded
    assert "claude-2.1.252" not in encoded
    assert str(tmp_path) not in encoded


def test_toolchain_tree_binds_npm_sources_but_not_generated_payload(
    tmp_path: Path,
) -> None:
    package_root = tmp_path / "mcp-packages"
    generated = package_root / "node_modules" / "fixture"
    generated.mkdir(parents=True)
    (package_root / "package.json").write_text(
        '{"dependencies":{"fixture":"1.0.0"}}\n', encoding="utf-8"
    )
    (package_root / "package-lock.json").write_text(
        '{"lockfileVersion":3}\n', encoding="utf-8"
    )
    (generated / "index.js").write_text(
        "module.exports = 'generated';\n", encoding="utf-8"
    )

    entries = snapshot._tree_entries(tmp_path, ("mcp-packages",))

    assert [identity for identity, _payload in entries] == [
        "mcp-packages/package-lock.json",
        "mcp-packages/package.json",
    ]


def test_windows_codex_ca_bundle_is_external_and_content_bound(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    bundle = tmp_path / "trusted-ca.pem"
    bundle.write_bytes(b"TEST-CA-BYTES")

    selected = snapshot.resolve_windows_codex_ca_bundle(
        {"CODEX_CA_CERTIFICATE": str(bundle)},
        project_root=target,
        platform_name="win32",
    )

    assert selected == bundle.resolve()
    payload = snapshot._canonical_json({
        "path": str(selected),
        "sha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
        "size": bundle.stat().st_size,
    })
    assert hashlib.sha256(payload).hexdigest() != hashlib.sha256(
        snapshot._canonical_json({
            "path": str(selected),
            "sha256": "0" * 64,
            "size": bundle.stat().st_size,
        })
    ).hexdigest()


def test_windows_codex_ca_bundle_rejects_target_controlled_trust_root(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "malicious-ca.pem"
    bundle.write_bytes(b"TARGET-CONTROLLED")

    with pytest.raises(
        snapshot.SnapshotInputError,
        match="cannot be controlled by the audit target",
    ):
        snapshot.resolve_windows_codex_ca_bundle(
            {"SSL_CERT_FILE": str(bundle)},
            project_root=tmp_path,
            platform_name="win32",
        )


def test_windows_codex_runtime_snapshot_binds_selected_ca_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = tmp_path / "trusted-ca.pem"
    bundle.write_bytes(b"CA-V1")
    monkeypatch.setattr(snapshot.sys, "platform", "win32")
    monkeypatch.setattr(snapshot, "_fixed_runtime_tool_entries", lambda **_: ())
    monkeypatch.setattr(
        snapshot,
        "resolve_windows_codex_ca_bundle",
        lambda *_args, **_kwargs: bundle,
    )

    first = dict(snapshot._runtime_tool_entries(
        project_root=tmp_path / "target",
        config={"cli_backend": "codex"},
    ))["@runtime/codex_ca_certificate"]
    bundle.write_bytes(b"CA-V2")
    second = dict(snapshot._runtime_tool_entries(
        project_root=tmp_path / "target",
        config={"cli_backend": "codex"},
    ))["@runtime/codex_ca_certificate"]

    assert first != second
    assert hashlib.sha256(b"CA-V1").hexdigest().encode() in first
    assert hashlib.sha256(b"CA-V2").hexdigest().encode() in second


def test_non_windows_codex_ca_bundle_uses_native_store() -> None:
    assert snapshot.resolve_windows_codex_ca_bundle(
        {"CODEX_CA_CERTIFICATE": "missing"},
        platform_name="linux",
    ) is None


def test_runtime_drift_names_exact_changed_logical_entry() -> None:
    old_payload = b"TIMEOUT"
    new_payload = b"rc=0\nscip-go version 0.4.0"
    unchanged = ("@runtime/tool/claude", b"claude-stable")
    stored = _sealed_snapshot(
        _toolchain([unchanged, ("@runtime/tool/scip-go", old_payload)])
    )
    current = _sealed_snapshot(
        _toolchain([unchanged, ("@runtime/tool/scip-go", new_payload)])
    )

    verdict = snapshot.classify_snapshot(
        stored, current, has_prior_progress=True
    )

    assert verdict.state == snapshot.MISMATCH
    assert verdict.changed_components == ("toolchain",)
    assert verdict.runtime_entry_changes == (
        {
            "component": "toolchain",
            "identity": "@runtime/tool/scip-go",
            "stored": {
                "sha256": hashlib.sha256(old_payload).hexdigest(),
                "byte_count": len(old_payload),
            },
            "current": {
                "sha256": hashlib.sha256(new_payload).hexdigest(),
                "byte_count": len(new_payload),
            },
        },
    )


def test_runtime_drift_reports_added_and_removed_entries_deterministically() -> None:
    stored = _sealed_snapshot(
        _toolchain(
            [
                ("@runtime/tool/unchanged", b"same"),
                ("@runtime/tool/removed", b"old"),
            ]
        )
    )
    current = _sealed_snapshot(
        _toolchain(
            [
                ("@runtime/tool/added", b"new"),
                ("@runtime/tool/unchanged", b"same"),
            ]
        )
    )

    changes = snapshot.classify_snapshot(
        stored, current, has_prior_progress=True
    ).runtime_entry_changes

    assert [row["identity"] for row in changes] == [
        "@runtime/tool/added",
        "@runtime/tool/removed",
    ]
    assert changes[0]["stored"] is None
    assert changes[0]["current"] is not None
    assert changes[1]["stored"] is not None
    assert changes[1]["current"] is None


def test_legacy_v1_toolchain_without_manifest_remains_compatible() -> None:
    current = _sealed_snapshot(
        _toolchain([("@runtime/tool/claude", b"stable")])
    )
    stored = json.loads(json.dumps(current))
    stored["components"]["toolchain"].pop("runtime_entries")
    _reseal(stored)

    assert snapshot._valid_snapshot(stored)
    verdict = snapshot.classify_snapshot(
        stored, current, has_prior_progress=True
    )
    assert verdict.state == snapshot.MATCH
    assert verdict.runtime_entry_changes == ()


def test_persistent_toolchain_drift_does_not_invent_runtime_cause() -> None:
    runtime = [("@runtime/tool/claude", b"stable")]
    stored = _sealed_snapshot(_toolchain(runtime, persistent=b"old"))
    current = _sealed_snapshot(_toolchain(runtime, persistent=b"new"))

    verdict = snapshot.classify_snapshot(
        stored, current, has_prior_progress=True
    )

    assert verdict.state == snapshot.MISMATCH
    assert verdict.changed_components == ("toolchain",)
    assert verdict.runtime_entry_changes == ()


def test_python_package_inventory_ignores_temporary_sys_path_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    baseline = snapshot._installed_python_packages()
    injected_name = "plamen-snapshot-path-injection"
    dist_info = tmp_path / f"{injected_name}-999.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\n"
        f"Name: {injected_name}\n"
        "Version: 999.0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "path", [str(tmp_path), *sys.path])

    observed = snapshot._installed_python_packages()

    assert observed == baseline
    assert injected_name not in observed.decode("utf-8")


@pytest.mark.parametrize(
    "manifest",
    [
        {"@runtime/tool/x": {"sha256": "0" * 64, "byte_count": True}},
        {
            "@runtime/tool/x": {
                "sha256": "0" * 64,
                "byte_count": 1,
                "raw": "secret",
            }
        },
        {"not-runtime": {"sha256": "0" * 64, "byte_count": 1}},
        {"@runtime/tool/x": {"sha256": "not-a-digest", "byte_count": 1}},
    ],
)
def test_runtime_manifest_validation_rejects_ambiguous_or_raw_evidence(
    manifest: dict[str, Any],
) -> None:
    value = _sealed_snapshot(
        _toolchain([("@runtime/tool/claude", b"stable")])
    )
    value["components"]["toolchain"]["runtime_entries"] = manifest
    _reseal(value)
    assert not snapshot._valid_snapshot(value)
