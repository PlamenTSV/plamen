from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import audit_snapshot as snapshot


class _Headers(dict):
    def get(self, key: str, default: str = "") -> str:
        return str(super().get(key, default))


class _Response:
    def __init__(self, payload: bytes, url: str) -> None:
        self._payload = payload
        self._url = url
        self.headers = _Headers({"Content-Type": "text/markdown"})

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self._payload[:limit]

    def geturl(self) -> str:
        return self._url


def _config(root: Path, inputs: list[str]) -> dict:
    return {
        "project_root": str(root),
        "pipeline": "sc",
        "language": "evm",
        "docs_inputs": inputs,
        "docs_path": "",
    }


def test_typed_docs_materializes_two_local_files_with_spaces(
    tmp_path: Path,
) -> None:
    first = tmp_path / "authority docs" / "impact map.md"
    second = tmp_path / "authority docs" / "REPO MANIFEST.md"
    first.parent.mkdir()
    first.write_text("impact\n", encoding="utf-8")
    second.write_text("repos\n", encoding="utf-8")
    receipt = tmp_path / ".scratchpad" / "docs_input_bundle_receipt.json"

    config = _config(tmp_path, [str(first), str(second)])
    bundle = snapshot.materialize_document_inputs(
        config,
        receipt_path=receipt,
    )

    assert bundle is not None and bundle.is_dir()
    assert config["docs_path"] == str(bundle)
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "plamen.document-input-bundle.v1"
    assert [row["source_kind"] for row in manifest["documents"]] == [
        "local",
        "local",
    ]
    assert len(list(bundle.glob("*.md"))) == 2
    assert receipt.is_file()


def test_typed_docs_supports_mixed_url_and_local_with_stub_fetch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = tmp_path / "local authority.md"
    local.write_text("local\n", encoding="utf-8")
    url = "https://example.invalid/program/scope.md"
    monkeypatch.setattr(
        snapshot,
        "_fetch_remote_document",
        lambda source, **_kwargs: (
            b"remote\n",
            source,
            _Headers({"Content-Type": "text/markdown"}),
        ),
    )

    config = _config(tmp_path, [url, str(local)])
    bundle = snapshot.materialize_document_inputs(
        config,
        receipt_path=tmp_path / "receipt.json",
    )
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert {row["source_kind"] for row in manifest["documents"]} == {
        "remote",
        "local",
    }
    assert {row["content_sha256"] for row in manifest["documents"]} == {
        hashlib.sha256(b"remote\n").hexdigest(),
        hashlib.sha256(local.read_bytes()).hexdigest(),
    }


def test_typed_docs_partial_fetch_failure_leaves_no_receipt_or_effective_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fetch(source, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("offline")
        return (
            b"first\n",
            source,
            _Headers({"Content-Type": "text/markdown"}),
        )

    monkeypatch.setattr(snapshot, "_fetch_remote_document", fetch)
    receipt = tmp_path / "receipt.json"
    config = _config(
        tmp_path,
        [
            "https://example.invalid/one.md",
            "https://example.invalid/two.md",
        ],
    )
    with pytest.raises(snapshot.SnapshotInputError, match="fetch failed"):
        snapshot.materialize_document_inputs(config, receipt_path=receipt)
    assert not receipt.exists()
    assert config["docs_path"] == ""
    bundle_root = tmp_path / ".plamen-audit-inputs"
    if bundle_root.exists():
        assert not [
            path for path in bundle_root.iterdir()
            if path.is_dir() and not path.name.startswith(".tmp-")
        ]


def test_typed_docs_resume_reuses_bound_remote_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = "https://example.invalid/scope.md"
    receipt = tmp_path / "receipt.json"
    monkeypatch.setattr(
        snapshot,
        "_fetch_remote_document",
        lambda source, **_kwargs: (
            b"frozen\n",
            source,
            _Headers({"Content-Type": "text/markdown"}),
        ),
    )
    first = _config(tmp_path, [url])
    expected = snapshot.materialize_document_inputs(
        first,
        receipt_path=receipt,
    )

    def no_network(*_args, **_kwargs):
        raise AssertionError("resume attempted network")

    monkeypatch.setattr(snapshot, "_fetch_remote_document", no_network)
    resumed = _config(tmp_path, [url])
    actual = snapshot.materialize_document_inputs(
        resumed,
        receipt_path=receipt,
        allow_remote_fetch=False,
    )
    assert actual == expected
    assert resumed["docs_path"] == str(expected)


def test_typed_docs_resume_detects_local_mutation(
    tmp_path: Path,
) -> None:
    local = tmp_path / "scope.md"
    local.write_text("v1\n", encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    first = _config(tmp_path, [str(local)])
    snapshot.materialize_document_inputs(first, receipt_path=receipt)
    local.write_text("v2\n", encoding="utf-8")

    resumed = _config(tmp_path, [str(local)])
    with pytest.raises(snapshot.SnapshotInputError, match="local documentation changed"):
        snapshot.materialize_document_inputs(
            resumed,
            receipt_path=receipt,
            allow_remote_fetch=False,
        )


def test_typed_docs_rejects_legacy_path_ambiguity(tmp_path: Path) -> None:
    local = tmp_path / "scope.md"
    local.write_text("scope\n", encoding="utf-8")
    config = _config(tmp_path, [str(local)])
    config["docs_path"] = str(local)
    with pytest.raises(snapshot.SnapshotInputError, match="docs_path"):
        snapshot.materialize_document_inputs(config)


def test_typed_docs_rejects_root_symlink_or_reparse_input(tmp_path: Path) -> None:
    source = tmp_path / "real.md"
    source.write_text("real\n", encoding="utf-8")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(source)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")
    with pytest.raises(
        snapshot.SnapshotInputError,
        match="link|reparse",
    ):
        snapshot.materialize_document_inputs(
            _config(tmp_path, [str(link)]),
            receipt_path=tmp_path / "receipt.json",
        )


def test_typed_docs_resume_rejects_unmanifested_bundle_member(
    tmp_path: Path,
) -> None:
    source = tmp_path / "scope.md"
    source.write_text("scope\n", encoding="utf-8")
    receipt = tmp_path / "receipt.json"
    first = _config(tmp_path, [str(source)])
    bundle = snapshot.materialize_document_inputs(first, receipt_path=receipt)
    (bundle / "unmanifested.md").write_text("extra\n", encoding="utf-8")

    with pytest.raises(snapshot.SnapshotInputError, match="roster"):
        snapshot.materialize_document_inputs(
            _config(tmp_path, [str(source)]),
            receipt_path=receipt,
            allow_remote_fetch=False,
        )


def test_typed_docs_caps_remote_inputs_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        snapshot,
        "_fetch_remote_document",
        lambda *_args, **_kwargs: pytest.fail("network should not be reached"),
    )
    config = _config(
        tmp_path,
        [
            f"https://example.invalid/{index}.md"
            for index in range(snapshot._MAX_REMOTE_DOCUMENTS + 1)
        ],
    )
    with pytest.raises(snapshot.SnapshotInputError, match="too many remote"):
        snapshot.materialize_document_inputs(config)


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1/scope.md",
        "https://[::1]/scope.md",
        "https://[64:ff9b::7f00:1]/scope.md",
        "https://[64:ff9b:1::7f00:1]/scope.md",
        "https://[::ffff:127.0.0.1]/scope.md",
        "https://[2002:7f00:1::]/scope.md",
        "http://example.com/scope.md",
    ],
)
def test_typed_docs_rejects_private_or_insecure_remote_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    url: str,
) -> None:
    monkeypatch.setattr(
        snapshot,
        "_request_remote_document_once",
        lambda *_args, **_kwargs: pytest.fail("transport must not run"),
    )
    with pytest.raises(
        snapshot.SnapshotInputError,
        match="private|non-global|HTTPS",
    ):
        snapshot.materialize_document_inputs(
            _config(tmp_path, [url]),
            receipt_path=tmp_path / "receipt.json",
        )


def test_typed_docs_rejects_dns_name_resolving_to_private_address(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        snapshot.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                snapshot.socket.AF_INET,
                snapshot.socket.SOCK_STREAM,
                6,
                "",
                ("10.0.0.7", 443),
            )
        ],
    )
    monkeypatch.setattr(
        snapshot,
        "_request_remote_document_once",
        lambda *_args, **_kwargs: pytest.fail("transport must not run"),
    )
    with pytest.raises(snapshot.SnapshotInputError, match="non-global"):
        snapshot.materialize_document_inputs(
            _config(tmp_path, ["https://docs.example/scope.md"]),
            receipt_path=tmp_path / "receipt.json",
        )


def test_typed_docs_revalidates_redirect_before_following_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        snapshot.socket,
        "getaddrinfo",
        lambda *_args, **_kwargs: [
            (
                snapshot.socket.AF_INET,
                snapshot.socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ],
    )
    calls: list[str] = []

    def request_once(url, *_args, **_kwargs):
        calls.append(url)
        return 302, {"Location": "https://127.0.0.1/internal"}, b""

    monkeypatch.setattr(snapshot, "_request_remote_document_once", request_once)
    with pytest.raises(snapshot.SnapshotInputError, match="private|non-global"):
        snapshot.materialize_document_inputs(
            _config(tmp_path, ["https://docs.example/scope.md"]),
            receipt_path=tmp_path / "receipt.json",
        )
    assert calls == ["https://docs.example/scope.md"]


def test_typed_docs_private_http_requires_both_explicit_opt_ins(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        snapshot,
        "_request_remote_document_once",
        lambda url, *_args, **_kwargs: (
            200,
            {"Content-Type": "text/markdown"},
            b"authorized local docs\n",
        ),
    )
    config = _config(tmp_path, ["http://127.0.0.1/scope.md"])
    config["allow_private_document_urls"] = True
    config["allow_insecure_document_http"] = True
    bundle = snapshot.materialize_document_inputs(
        config,
        receipt_path=tmp_path / "receipt.json",
    )
    assert bundle is not None
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["documents"][0]["effective_source"] == (
        "http://127.0.0.1/scope.md"
    )


def test_orphan_typed_docs_receipt_is_not_prior_audit_evidence(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    (scratchpad / "docs_input_bundle_receipt.json").write_text(
        '{"schema":"plamen.document-input-receipt.v1"}\n',
        encoding="utf-8",
    )
    import plamen_driver as driver

    assert not driver._scratchpad_has_prior_evidence(
        scratchpad,
        checkpoint_existed=False,
        config_path=None,
    )


def test_precreated_driver_redirect_logs_are_not_prior_audit_evidence(
    tmp_path: Path,
) -> None:
    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    config_path = scratchpad / "config.json"
    config_path.write_text("{}\n", encoding="utf-8")
    (scratchpad / "_driver.stdout.log").write_bytes(b"")
    (scratchpad / "_driver.stderr.log").write_bytes(b"")
    import plamen_driver as driver

    assert not driver._scratchpad_has_prior_evidence(
        scratchpad,
        checkpoint_existed=False,
        config_path=config_path,
    )
    (scratchpad / "findings_inventory.md").write_text(
        "real prior evidence\n", encoding="utf-8"
    )
    assert driver._scratchpad_has_prior_evidence(
        scratchpad,
        checkpoint_existed=False,
        config_path=config_path,
    )


def test_precheckpoint_orphan_receipt_resumes_offline_and_binds_new_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import plamen_driver as driver

    scratchpad = tmp_path / ".scratchpad"
    scratchpad.mkdir()
    url = "https://example.invalid/frozen.md"
    receipt = scratchpad / "docs_input_bundle_receipt.json"
    monkeypatch.setattr(
        snapshot,
        "_fetch_remote_document",
        lambda source, **_kwargs: (
            b"frozen\n",
            source,
            _Headers({"Content-Type": "text/markdown"}),
        ),
    )
    staged = _config(tmp_path, [url])
    expected_bundle = snapshot.materialize_document_inputs(
        staged,
        receipt_path=receipt,
    )

    def no_network(*_args, **_kwargs):
        raise AssertionError("orphan receipt restart attempted network")

    monkeypatch.setattr(snapshot, "_fetch_remote_document", no_network)
    real_materialize = snapshot.materialize_document_inputs
    calls: list[bool] = []

    def materialize(config, **kwargs):
        calls.append(bool(kwargs.get("allow_remote_fetch")))
        return real_materialize(config, **kwargs)

    monkeypatch.setattr(driver, "materialize_document_inputs", materialize)
    monkeypatch.setattr(driver, "_resolve_snapshot_build_root", lambda config: tmp_path)
    monkeypatch.setattr(
        driver,
        "prepare_backend_runtime_contract",
        lambda config, scratchpad: None,
    )
    monkeypatch.setattr(
        driver,
        "_prepare_snapshot_bound_inputs",
        lambda config: {"status": "SKIPPED", "reason": "fixture"},
    )
    current = {
        "schema": snapshot.SNAPSHOT_SCHEMA,
        "components": {
            "source_scope": {"coverage_limitations": []},
            "audit_config": {},
            "methodology": {},
            "toolchain": {},
        },
        "snapshot_digest": "d" * 64,
    }
    monkeypatch.setattr(driver, "build_audit_snapshot", lambda *_args: current)
    monkeypatch.setattr(
        driver,
        "classify_snapshot",
        lambda *_args, **_kwargs: driver.SnapshotVerdict(
            driver.SNAPSHOT_NEW,
            (),
        ),
    )
    config = _config(tmp_path, [url])
    checkpoint, verdict, archive = driver._bind_checkpoint_audit_snapshot(
        driver.Checkpoint(),
        scratchpad,
        config,
        config_path=None,
        checkpoint_existed=False,
    )
    assert calls == [False]
    assert Path(config["docs_path"]) == expected_bundle
    assert checkpoint.run_id
    assert config["_run_id"] == checkpoint.run_id
    assert verdict.state == driver.SNAPSHOT_NEW
    assert archive is None


def test_typed_docs_are_snapshot_config_bound(tmp_path: Path) -> None:
    first = snapshot._config_component(
        _config(tmp_path, ["https://example.invalid/one.md"])
    )
    second = snapshot._config_component(
        _config(tmp_path, ["https://example.invalid/two.md"])
    )
    assert first["digest"] != second["digest"]
