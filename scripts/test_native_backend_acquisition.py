from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from scripts import backend_acquisition
from scripts import native_backend_acquisition as producer
from scripts import runtime_image_materializer
from scripts.native_fixed_role_acquisition import RetainedPrivateStoreFactory


ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "verification_policy/native_backend_acquisition.v2.json"


def _elf(tag: bytes = b"") -> bytes:
    head = bytearray(64)
    head[:4] = b"\x7fELF"
    head[4] = 2
    head[5] = 1
    head[6] = 1
    head[16:18] = (3).to_bytes(2, "little")
    head[18:20] = (183).to_bytes(2, "little")
    return bytes(head) + tag


def _archive(selector: str, *, body: bytes | None = None, path: str | None = None) -> bytes:
    executable = body or _elf(selector.encode())
    member_path = path or (
        "package/claude" if selector == "claude" else
        "package/vendor/aarch64-unknown-linux-musl/bin/codex"
    )
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo(member_path)
        info.mode = 0o755
        info.size = len(executable)
        archive.addfile(info, io.BytesIO(executable))
    return stream.getvalue()


def _platform_row(selector: str, version: str, payload: bytes) -> dict:
    package = (
        "@anthropic-ai/claude-code-linux-arm64"
        if selector == "claude" else "@openai/codex"
    )
    release = version if selector == "claude" else version + "-linux-arm64"
    leaf = package.rsplit("/", 1)[-1]
    url = f"https://registry.npmjs.org/{package}/-/{leaf}-{release}.tgz"
    return {
        "install_name": (
            "@anthropic-ai/claude-code-linux-arm64"
            if selector == "claude" else "@openai/codex-linux-arm64"
        ),
        "package": package,
        "version": release,
        "metadata_url": "https://registry.npmjs.org/metadata/" + selector,
        "metadata_sha256": "11" * 32,
        "tarball_url": url,
        "integrity": "sha512-" + base64.b64encode(
            hashlib.sha512(payload).digest()
        ).decode(),
        "shasum": hashlib.sha1(payload, usedforsecurity=False).hexdigest(),
        "registry_signature": {"keyid": "test", "signature": "test"},
        "provenance": (
            {"predicate_type": "https://slsa.dev/provenance/v1", "url": "test"}
            if selector == "codex" else None
        ),
    }


def _resolutions(payloads: dict[str, bytes], version: str = "9.8.7") -> dict:
    result = {}
    for selector in ("claude", "codex"):
        platform = _platform_row(selector, version, payloads[selector])
        row = {
            "selector": selector,
            "package": (
                "@anthropic-ai/claude-code" if selector == "claude"
                else "@openai/codex"
            ),
            "version": version,
            "metadata_sha256": "22" * 32,
            "metadata_url": "https://registry.npmjs.org/latest/" + selector,
            "tarball_url": "https://registry.npmjs.org/root/" + selector + ".tgz",
            "integrity": "sha512-" + base64.b64encode(b"r" * 64).decode(),
            "shasum": "33" * 20,
            "registry_signature": {"keyid": "root", "signature": "root"},
            "trusted_publisher": (
                {"id": "github", "oidc_config_id": "oidc:test"}
                if selector == "codex" else None
            ),
            "provenance": (
                {"predicate_type": "https://slsa.dev/provenance/v1", "url": "root"}
                if selector == "codex" else None
            ),
            "platform_package": platform,
        }
        if selector == "claude":
            executable = _elf(b"claude")
            row["upstream_release"] = {
                "latest_url": "https://downloads.claude.ai/claude-code-releases/latest",
                "latest_sha256": "44" * 32,
                "manifest_url": (
                    "https://downloads.claude.ai/claude-code-releases/"
                    + version + "/manifest.json"
                ),
                "manifest_sha256": "55" * 32,
                "manifest_size": 100,
                "commit": "66" * 20,
                "platform": "linux-arm64",
                "executable_sha256": hashlib.sha256(executable).hexdigest(),
                "executable_size": len(executable),
            }
        result[selector] = row
    return result


class Source:
    _PLAMEN_RETAINED_FROZEN_SOURCE_ROSTER_V1 = True

    def __init__(self, fd: int) -> None:
        self.fd = fd

    def duplicate_member(self, role: str) -> int:
        assert role == "native_backend_latest_acquisition_policy"
        return os.dup(self.fd)


class Transport:
    _PLAMEN_BACKEND_SETUP_TRANSPORT_V1 = True

    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.payloads = payloads
        self._endpoints = [f"https://registry.npmjs.org/input/{i}" for i in range(6)]

    def fetch_json(self, url: str):
        raise AssertionError("resolver is independently tested")

    def fetch_bytes(self, url: str):
        raise AssertionError("resolver is independently tested")

    def download(self, url: str, *, writer_fd: int) -> None:
        selector = "claude" if "claude-code" in url else "codex"
        os.write(writer_fd, self.payloads[selector])
        self._endpoints.append(url)

    def endpoints(self) -> tuple[str, ...]:
        return tuple(self._endpoints)


class Probe:
    _PLAMEN_LINUX_ARM64_BACKEND_PROBE_AUTHORITY_V1 = True

    def __init__(self, policy: dict) -> None:
        self.policy = policy
        self.calls = []

    def run(
        self, *, selector, executable_fd, executable_sha256,
        executable_size, resolved_version, argv,
    ):
        assert os.pread(executable_fd, 4, 0) == b"\x7fELF"
        assert hashlib.sha256(
            os.pread(executable_fd, executable_size, 0)
        ).hexdigest() == executable_sha256
        self.calls.append((selector, argv))
        if argv == ("--version",):
            text = (
                f"{resolved_version} (Claude Code)" if selector == "claude"
                else f"codex-cli {resolved_version}"
            )
        else:
            key = (
                "help_required_flags" if selector == "claude"
                else "exec_help_required_flags"
            )
            text = "usage\n" + "\n".join(
                self.policy["backends"][selector]["cli_contract"][key]
            )
        return {"returncode": 0, "stdout": (text + "\n").encode(), "stderr": b""}


@pytest.fixture
def setup(tmp_path: Path):
    policy, policy_sha = backend_acquisition.load_policy(POLICY)
    policy_path = tmp_path / "policy.json"
    policy_path.write_bytes(POLICY.read_bytes()); policy_path.chmod(0o400)
    policy_fd = os.open(policy_path, os.O_RDONLY | os.O_CLOEXEC)
    store_path = tmp_path / "store"
    store_path.mkdir(mode=0o700)
    store_fd = os.open(store_path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        yield (
            policy, policy_sha, Source(policy_fd),
            RetainedPrivateStoreFactory(store_fd), store_path,
        )
    finally:
        os.close(store_fd); os.close(policy_fd)


def test_policy_digest_binds_exact_retained_newline(setup):
    _policy, digest, source, _store, _store_path = setup
    assert digest == hashlib.sha256(POLICY.read_bytes()).hexdigest()
    assert digest != hashlib.sha256(POLICY.read_bytes().rstrip(b"\n")).hexdigest()
    assert backend_acquisition.load_policy_bytes(POLICY.read_bytes())[1] == digest
    forged = POLICY.read_bytes().rstrip(b"\n")
    with pytest.raises(backend_acquisition.BackendAcquisitionError, match="canonical"):
        backend_acquisition.load_policy_bytes(forged)
    assert source.duplicate_member


def test_default_transport_rejects_aliases_ports_and_duplicate_json_keys(
    monkeypatch,
):
    for url in (
        "http://registry.npmjs.org/x",
        "https://user@registry.npmjs.org/x",
        "https://registry.npmjs.org:443/x",
        "https://downloads.claude.ai/foreign/x",
    ):
        with pytest.raises(producer.NativeBackendAcquisitionError):
            producer.DefaultBackendSetupTransport._admit_url(url)
    transport = producer.DefaultBackendSetupTransport()
    monkeypatch.setattr(
        producer.DefaultBackendSetupTransport, "_fetch",
        lambda self, url, maximum: b'{"name":"one","name":"two"}',
    )
    with pytest.raises(producer.NativeBackendAcquisitionError, match="duplicate"):
        transport.fetch_json("https://registry.npmjs.org/x")


def test_producer_resolves_materializes_probes_and_retains_exact_fds(
    setup, monkeypatch,
):
    policy, policy_sha, source, store, store_path = setup
    payloads = {"codex": _archive("codex"), "claude": _archive("claude")}
    resolutions = _resolutions(payloads)
    monkeypatch.setattr(
        producer.receipt_authority, "resolve_latest_backends",
        lambda policy, **kwargs: copy.deepcopy(resolutions),
    )
    probe = Probe(policy)
    authority = producer.acquire_production_linux_arm64_backend_inputs(
        source_authority=source, private_store=store,
        transaction_id="install-test", probe_authority=probe,
        transport=Transport(payloads),
    )
    records = authority.records()
    assert [(row["selector"], row["role"]) for row in records] == [
        ("codex", 5), ("claude", 6),
    ]
    assert len({fd for row in records for fd in (
        row["unsigned_receipt_fd"], row["payload_fd"],
        row["source_manifest_fd"],
    )}) == 6
    for row in records:
        unsigned_raw = os.pread(
            row["unsigned_receipt_fd"],
            os.fstat(row["unsigned_receipt_fd"]).st_size, 0,
        )
        unsigned = json.loads(unsigned_raw)
        assert unsigned_raw == backend_acquisition.canonical_json(unsigned)
        assert unsigned["policy_sha256"] == policy_sha
        assert unsigned["resolved_version"] == "9.8.7"
        assert "authentication" not in unsigned and "receipt_sha256" not in unsigned
        assert "upstream_release" not in unsigned["registry"]
        assert unsigned["install"]["generation_id"].startswith("npm-")
        assert unsigned["payload"]["sha256"] == hashlib.sha256(
            payloads[row["selector"]]
        ).hexdigest()
        manifest_raw = os.pread(
            row["source_manifest_fd"],
            os.fstat(row["source_manifest_fd"]).st_size, 0,
        )
        manifest = json.loads(manifest_raw)
        assert manifest["platform"] == "linux/arm64"
        assert manifest["archive_member_count"] == 1
        assert manifest["installed_sha256"] == unsigned["installed"]["executable_sha256"]
        assert manifest_raw == runtime_image_materializer.render_backend_archive_source_manifest(
            selector=row["selector"], resolved_version="9.8.7",
            payload=unsigned["payload"], installed=unsigned["installed"],
        )
    assert len(probe.calls) == 4

    first = records[0]["payload_fd"]
    os.close(first)
    with pytest.raises(producer.NativeBackendAcquisitionError, match="unavailable"):
        authority.records()
    assert authority.close() is True
    assert authority.close() is True
    assert list(store_path.iterdir()) == []


@pytest.mark.parametrize(
    ("selector", "payload", "match"),
    [
        ("codex", _archive("codex", body=b"not-an-elf" * 10), "AArch64"),
        (
            "codex",
            _archive("codex", path="package/vendor/x86_64-unknown-linux-musl/bin/codex"),
            "absent",
        ),
        ("claude", _archive("claude", path="../package/claude"), "unsafe"),
    ],
    ids=("codex-bad-elf", "codex-wrong-arch", "claude-unsafe-path"),
)
def test_archive_identity_substitution_fails_and_cleans(
    setup, monkeypatch, selector, payload, match,
):
    policy, _digest, source, store, store_path = setup
    payloads = {
        "codex": payload if selector == "codex" else _archive("codex"),
        "claude": payload if selector == "claude" else _archive("claude"),
    }
    resolutions = _resolutions(payloads)
    if selector == "claude":
        # Reach archive safety before the official-manifest equality check.
        resolutions["claude"]["upstream_release"]["executable_sha256"] = "00" * 32
        resolutions["claude"]["upstream_release"]["executable_size"] = 1
    monkeypatch.setattr(
        producer.receipt_authority, "resolve_latest_backends",
        lambda policy, **kwargs: copy.deepcopy(resolutions),
    )
    with pytest.raises(producer.NativeBackendAcquisitionError, match=match):
        producer.acquire_production_linux_arm64_backend_inputs(
            source_authority=source, private_store=store,
            transaction_id="install-negative", probe_authority=Probe(policy),
            transport=Transport(payloads),
        )
    assert list(store_path.iterdir()) == []


def test_probe_degradation_is_not_accepted(setup, monkeypatch):
    policy, _digest, source, store, store_path = setup
    payloads = {"codex": _archive("codex"), "claude": _archive("claude")}
    monkeypatch.setattr(
        producer.receipt_authority, "resolve_latest_backends",
        lambda policy, **kwargs: copy.deepcopy(_resolutions(payloads)),
    )

    class BrokenProbe(Probe):
        def run(self, **kwargs):
            return {"returncode": 127, "stdout": b"", "stderr": b"unavailable"}

    with pytest.raises(producer.NativeBackendAcquisitionError, match="conformance"):
        producer.acquire_production_linux_arm64_backend_inputs(
            source_authority=source, private_store=store,
            transaction_id="install-no-degrade", probe_authority=BrokenProbe(policy),
            transport=Transport(payloads),
        )
    assert list(store_path.iterdir()) == []


def test_help_flag_prefix_is_not_cli_conformance(setup, monkeypatch):
    policy, _digest, source, store, store_path = setup
    payloads = {"codex": _archive("codex"), "claude": _archive("claude")}
    monkeypatch.setattr(
        producer.receipt_authority, "resolve_latest_backends",
        lambda policy, **kwargs: copy.deepcopy(_resolutions(payloads)),
    )

    class PrefixProbe(Probe):
        def run(self, **kwargs):
            result = super().run(**kwargs)
            if kwargs["selector"] == "codex" and kwargs["argv"] == ("exec", "--help"):
                result["stdout"] = result["stdout"].replace(b"--model\n", b"--model-evil\n")
            return result

    with pytest.raises(producer.NativeBackendAcquisitionError, match="conformance"):
        producer.acquire_production_linux_arm64_backend_inputs(
            source_authority=source, private_store=store,
            transaction_id="install-prefix", probe_authority=PrefixProbe(policy),
            transport=Transport(payloads),
        )
    assert list(store_path.iterdir()) == []
