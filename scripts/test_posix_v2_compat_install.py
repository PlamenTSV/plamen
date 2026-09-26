"""Focused integrity tests for the explicit POSIX V2 compatibility install."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import types

import pytest

import posix_v2_compat_install as I


ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX-only installer")
_REAL_SOURCE_JS_GATE = I._validate_source_js_package
_REAL_STAGED_JS_GATE = I._validate_staged_js_package
_REAL_RUNTIME_CLOSURE_GATE = I._validate_complete_runtime_closure
_REAL_ARCHIVE_MATERIALIZER = I._materialize_absent_js_distributable
_REAL_DEPENDENCY_REPAIR = I._repair_python_dependencies
_MOCK_JS_RECEIPT = {
    "artifacts": [],
    "manifest_content_sha256": "0" * 64,
    "runtime_closure_sha256": "1" * 64,
    "schema": "plamen.posix_compat_v2.js_package.test-only.v1",
}


def _uninitialized_control_authority():
    """Load the exact shared loader without consuming the stale live manifest.

    Root regenerates that derived manifest only after all concurrent production
    sources freeze.  This test seam removes only the module's import-time live
    root initialization; the derivation and loader implementation are exact.
    """

    path = ROOT / "scripts/toolchain_control_authority.py"
    source = path.read_text(encoding="utf-8")
    source = source.split(
        "\nif (_MODULE_ROOT / _RUNTIME_CLOSURE_PATH).is_file():", 1
    )[0]
    name = "_plamen_test_uninitialized_toolchain_control_authority"
    module = types.ModuleType(name)
    module.__file__ = str(path)
    prior = sys.modules.get(name)
    sys.modules[name] = module
    try:
        exec(compile(source, str(path), "exec"), module.__dict__)
    finally:
        if prior is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = prior
    return module


_TEST_CONTROL_AUTHORITY = _uninitialized_control_authority()


def _use_real_complete_closure_gate(monkeypatch):
    monkeypatch.setattr(
        I, "_validate_complete_runtime_closure", _REAL_RUNTIME_CLOSURE_GATE,
    )
    monkeypatch.setattr(
        I, "_toolchain_control_authority_module",
        lambda: _TEST_CONTROL_AUTHORITY,
    )


def _mock_complete_runtime_closure(root, _label, *, captured_rows):
    raw = (Path(root) / I.JS_RUNTIME_CLOSURE_FILE).read_bytes()
    return I._runtime_closure_binding(
        captured_rows, json.loads(raw.decode("ascii")), raw
    )


@pytest.fixture(autouse=True)
def _portable_rule_authority_fixture(monkeypatch):
    """Generic installer fixtures do not reproduce three upstream Git repos.

    Exact source/runtime rule replay is covered by
    ``test_opengrep_rule_authority.py``; these tests retain ownership of the
    surrounding descriptor-copy/publication transaction.
    """
    monkeypatch.setattr(I, "_validate_source_rule_package", lambda _root: None)
    monkeypatch.setattr(I, "_validate_staged_rule_package", lambda _root: None)
    # The JS authority is under concurrent source freeze.  Bind fixtures to
    # the anchor bytes they actually copied without weakening the production
    # installer's compiled trust pin.
    monkeypatch.setattr(
        I,
        "EXPECTED_JS_BOOTSTRAP_ANCHOR_SHA256",
        hashlib.sha256((ROOT / I.JS_BOOTSTRAP_ANCHOR_FILE).read_bytes()).hexdigest(),
    )
    # Tiny transaction fixtures deliberately do not reproduce the reviewed
    # ~250 MiB seven-platform JS distributable.  Full-package admission and a
    # complete source census are exercised with the real gates below.
    monkeypatch.setattr(
        I,
        "_validate_source_js_package",
        lambda _root, **_kwargs: _MOCK_JS_RECEIPT,
    )
    monkeypatch.setattr(
        I,
        "_validate_staged_js_package",
        lambda _root, **_kwargs: _MOCK_JS_RECEIPT,
    )
    monkeypatch.setattr(
        I, "_validate_complete_runtime_closure",
        _mock_complete_runtime_closure,
    )
    monkeypatch.setattr(
        I, "_materialize_absent_js_distributable",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        I,
        "_repair_python_dependencies",
        lambda *, home, python_path, provenance: {
            "schema": "plamen.posix_v2_compat_python_dependencies.v1",
            "status": "VALID",
            "reduced_isolation": True,
            "generation_sha256": provenance["generation_sha256"],
            "dependency_authority_sha256": "a" * 64,
            "trust_boundary": "USER_WRITABLE_DRIFT_DETECTION_ONLY",
            "native_install_authority": False,
        },
    )


def _runtime_python() -> Path:
    candidates = [
        Path.home() / ".local/share/plamen/runtime/py312/bin/python",
        Path(sys.executable),
    ]
    for candidate in candidates:
        try:
            completed = subprocess.run(
                [str(candidate), "-I", "-c", "import sys;print(sys.implementation.name,sys.version_info.major,sys.version_info.minor)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={},
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if completed.returncode == 0 and completed.stdout.strip() == b"cpython 3 12":
            return candidate.absolute()
    pytest.skip("focused compatibility install tests require CPython 3.12")


def _source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    scripts = source / "scripts"
    scripts.mkdir(parents=True)
    (source / "plamen.py").write_text(
        "import json,sys\nprint(json.dumps(sys.argv[1:],separators=(',',':')))\n",
        encoding="utf-8",
    )
    (scripts / "plamen_driver.py").write_text("COMPAT_TEST = True\n", encoding="utf-8")
    (scripts / "posix_v2_compat_runtime.py").write_text(
        "COMPAT_RUNTIME_TEST = True\n", encoding="utf-8"
    )
    (scripts / "posix_v2_compat_exec_helper.py").write_text(
        "COMPAT_EXEC_HELPER_TEST = True\n", encoding="utf-8"
    )
    (scripts / "toolchain_control_authority.py").write_text(
        "COMPAT_RUNTIME_CLOSURE_AUTHORITY_TEST = True\n", encoding="utf-8"
    )
    for leaf in (
        "js_dependency_materializer_authority.py",
        "js_dependency_materializer_runtime.py",
        "js_lock_authority.py",
        "js_toolchain_authority.py",
    ):
        (scripts / leaf).write_text("COMPAT_JS_AUTHORITY_TEST = True\n", encoding="utf-8")
    shutil.copyfile(
        ROOT / "requirements-runtime-core.lock",
        source / "requirements-runtime-core.lock",
    )
    shutil.copyfile(
        ROOT / "requirements-runtime-full.lock",
        source / "requirements-runtime-full.lock",
    )
    rule_authority = source / "opengrep-rules/rule-tree-authority.v1.json"
    rule_authority.parent.mkdir(parents=True)
    rule_authority.write_text("{}\n", encoding="utf-8")
    policy_root = source / "verification_policy"
    policy_root.mkdir()
    (policy_root / "js_toolchain_authority.v1.json").write_text(
        "{}\n", encoding="utf-8"
    )
    shutil.copyfile(
        ROOT / I.JS_ACQUISITION_POLICY_FILE,
        policy_root / "js_toolchain_acquisition.v1.json",
    )
    shutil.copyfile(
        ROOT / I.JS_BOOTSTRAP_ANCHOR_FILE,
        policy_root / "js_toolchain_bootstrap.v1.json",
    )
    (policy_root / "toolchain_runtime_closure.v1.json").write_text(
        json.dumps({
            "assets": [],
            "derivation": "test-only-structural-seam",
            "entrypoints": [],
            "files": [I.JS_RUNTIME_CLOSURE_FILE],
            "manifest_control": {
                "kind": "control", "path": I.JS_RUNTIME_CLOSURE_FILE,
            },
            "schema": "test-only-structural-seam",
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    (source / "assets").mkdir()
    (source / "assets" / "policy.txt").write_bytes(b"exact-policy\n")
    skill_payloads = {
        "plamen/SKILL.md": b"---\nname: plamen\n---\nsee plamen-wizard.md and plamen-l1-wizard.md\n",
        "plamen/plamen-wizard.md": b"smart-contract wizard\n",
        "plamen/plamen-l1-wizard.md": b"l1 wizard\n",
        "plamen-l1/SKILL.md": b"---\nname: plamen-l1\n---\n",
        "plamen-l1-wizard/SKILL.md": b"---\nname: plamen-l1-wizard\n---\n",
        "plamen-wizard/SKILL.md": b"---\nname: plamen-wizard\n---\n",
    }
    skills = source / "codex-adapter" / "skills"
    for relative, raw in skill_payloads.items():
        destination = skills / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
    return source.resolve()


def _materialize_explicit_mock_js_package(source: Path) -> None:
    """Create a tiny, internally hash-bound package for the subprocess seam."""

    specifications = (
        ("node-windows-x86_64", "zip", "node/node-v24.20.0-win-x64.zip"),
        ("node-windows-arm64", "zip", "node/node-v24.20.0-win-arm64.zip"),
        ("node-linux-x86_64", "tar.xz", "node/node-v24.20.0-linux-x64.tar.xz"),
        ("node-linux-arm64", "tar.xz", "node/node-v24.20.0-linux-arm64.tar.xz"),
        ("node-darwin-x86_64", "tar.gz", "node/node-v24.20.0-darwin-x64.tar.gz"),
        ("node-darwin-arm64", "tar.gz", "node/node-v24.20.0-darwin-arm64.tar.gz"),
        ("yarn-classic-noarch", "tar.gz", "yarn/yarn-v1.22.22.tar.gz"),
    )
    artifacts = []
    for artifact_id, archive_format, suffix in specifications:
        relative = f"runtime/toolchains/js/{suffix}"
        raw = I.JS_ARCHIVE_MAGIC[archive_format] + artifact_id.encode("ascii")
        destination = source / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(raw)
        artifacts.append(
            {
                "archive_format": archive_format,
                "artifact_id": artifact_id,
                "packaged_path": relative,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw),
            }
        )
    policy = source / I.JS_AUTHORITY_POLICY_FILE
    policy.write_text(
        json.dumps({"artifacts": artifacts}, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    required = set(I.JS_AUTHORITY_MODULE_FILES) | {
        I.JS_AUTHORITY_POLICY_FILE,
        *(row["packaged_path"] for row in artifacts),
    }
    rows = []
    for relative in sorted(required):
        rows.append(
            {
                "digest_mode": "raw-v1",
                "kind": (
                    "control"
                    if relative.startswith("verification_policy/")
                    else "python-source"
                    if relative.endswith(".py")
                    else "runtime-data"
                ),
                "path": relative,
                "sha256": hashlib.sha256((source / relative).read_bytes()).hexdigest(),
            }
        )
    (source / I.JS_RUNTIME_CLOSURE_FILE).write_text(
        json.dumps({
            "assets": rows,
            "derivation": "test-only-structural-seam",
            "entrypoints": [],
            "files": sorted(
                [I.JS_RUNTIME_CLOSURE_FILE, *(row["path"] for row in rows)]
            ),
            "manifest_control": {
                "kind": "control", "path": I.JS_RUNTIME_CLOSURE_FILE,
            },
            "schema": "test-only-structural-seam",
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def _acquisition_policy_stage(tmp_path: Path) -> tuple[Path, int]:
    stage = tmp_path / "archive-free-stage"
    policy = stage / I.JS_ACQUISITION_POLICY_FILE
    policy.parent.mkdir(parents=True)
    shutil.copyfile(ROOT / I.JS_ACQUISITION_POLICY_FILE, policy)
    return stage, os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )


def test_clean_clone_acquisition_policy_needs_no_local_archives(tmp_path):
    stage, stage_fd = _acquisition_policy_stage(tmp_path)
    try:
        artifacts, policy_sha256 = (
            I._authenticated_archive_acquisition_policy(stage_fd)
        )
    finally:
        os.close(stage_fd)

    assert not (stage / "runtime/toolchains/js").exists()
    assert len(artifacts) == 7
    assert {artifact.packaged_path for artifact in artifacts} == set(
        I.JS_DISTRIBUTABLE_PATHS
    )
    assert all(artifact.source_url.startswith("https://") for artifact in artifacts)
    assert policy_sha256 == hashlib.sha256(
        (ROOT / I.JS_ACQUISITION_POLICY_FILE).read_bytes()
    ).hexdigest()
    assert policy_sha256 == I.EXPECTED_JS_ACQUISITION_POLICY_SHA256


def test_archive_free_clone_routes_all_pinned_artifacts_to_atomic_acquirer(
    tmp_path, monkeypatch,
):
    _stage, stage_fd = _acquisition_policy_stage(tmp_path)
    observed = []

    def acquire(_stage_fd, artifact, _uid, *, fetcher=None):
        assert _stage_fd == stage_fd
        assert fetcher is None
        observed.append(
            (artifact.artifact_id, artifact.packaged_path, artifact.source_url)
        )

    monkeypatch.setattr(I, "_acquire_archive", acquire)
    try:
        receipt = _REAL_ARCHIVE_MATERIALIZER(stage_fd, [], os.getuid())
    finally:
        os.close(stage_fd)

    assert receipt["artifact_count"] == 7
    assert receipt["mode"] == "VERIFIED_HTTPS_MATERIALIZATION_V1"
    assert {row[1] for row in observed} == set(I.JS_DISTRIBUTABLE_PATHS)
    assert len({row[0] for row in observed}) == 7
    assert all(row[2].startswith("https://") for row in observed)


def test_clean_clone_offline_install_fails_before_publication(tmp_path, monkeypatch):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    monkeypatch.setattr(
        I, "_materialize_absent_js_distributable", _REAL_ARCHIVE_MATERIALIZER,
    )

    def offline(_url):
        raise OSError("ambient network error must not affect the result")

    with pytest.raises(I.CompatInstallError, match="acquisition unavailable"):
        I.install_compat_v2(
            source, home, python, archive_fetcher=offline,
        )

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_dependency_repair_leaf_is_exact_and_validated(tmp_path, monkeypatch):
    home = _home(tmp_path)
    python = str(tmp_path / "managed-python")
    generation = "b" * 64
    calls = []

    class Process:
        pid = 919191

        def __init__(self, argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            result = {
                "schema": "plamen.posix_v2_compat_python_dependencies.v1",
                "status": "VALID", "reduced_isolation": True,
                "generation_sha256": generation,
                "dependency_authority_sha256": "a" * 64,
                "trust_boundary": "USER_WRITABLE_DRIFT_DETECTION_ONLY",
                "native_install_authority": False,
            }
            kwargs["stdout"].write(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
                + b"\n"
            )

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(I.subprocess, "Popen", Process)
    monkeypatch.setattr(
        I.os, "killpg",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    result = _REAL_DEPENDENCY_REPAIR(
        home=str(home), python_path=python,
        provenance={"generation_sha256": generation},
    )
    assert result["status"] == "VALID"
    assert calls[0][0] == [
        python, "-B", str(home / ".plamen/plamen.py"), "install",
        "--posix-compat-v2-dependencies",
    ]
    assert calls[0][1]["start_new_session"] is True
    assert calls[0][1]["shell"] is False


def test_full_lock_repair_command_is_forced_isolated_and_hash_locked():
    source = (ROOT / "plamen.py").read_text(encoding="utf-8")
    repair = source[source.index("Repairing exact hash-locked Python dependency runtime") :]
    repair = repair[: repair.index("candidate = _write_python_dependency_stamp")]
    for option in (
        '"--isolated"', '"--no-input"', '"--require-hashes"',
        '"--only-binary=:all:"', '"--force-reinstall"',
    ):
        assert option in repair
    assert '"--no-deps"' not in repair


def test_malformed_dependency_digest_is_controlled_fail_closed(
    tmp_path, monkeypatch,
):
    home = _home(tmp_path)

    class Process:
        pid = 939393

        def __init__(self, _argv, **kwargs):
            result = {
                "schema": "plamen.posix_v2_compat_python_dependencies.v1",
                "status": "VALID", "reduced_isolation": True,
                "generation_sha256": "b" * 64,
                "dependency_authority_sha256": 7,
                "trust_boundary": "USER_WRITABLE_DRIFT_DETECTION_ONLY",
                "native_install_authority": False,
            }
            kwargs["stdout"].write(json.dumps(result).encode() + b"\n")

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    monkeypatch.setattr(I.subprocess, "Popen", Process)
    monkeypatch.setattr(
        I.os, "killpg",
        lambda *_args: (_ for _ in ()).throw(ProcessLookupError()),
    )
    with pytest.raises(I.CompatInstallError, match="differs from admission"):
        _REAL_DEPENDENCY_REPAIR(
            home=str(home), python_path=str(tmp_path / "python"),
            provenance={"generation_sha256": "b" * 64},
        )


def test_dependency_repair_failure_prevents_compatibility_commit(
    tmp_path, monkeypatch,
):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)

    def fail(**_kwargs):
        I._fail(
            "dependency repair failed; Python package changes were not rolled back"
        )

    monkeypatch.setattr(I, "_repair_python_dependencies", fail)
    with pytest.raises(I.CompatInstallError, match="not rolled back"):
        I.install_compat_v2(source, home, python)
    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()


def test_dependency_repair_kills_group_when_leader_exits_with_descendant(
    tmp_path, monkeypatch,
):
    home = _home(tmp_path)
    killed = []
    group_alive = True

    class Process:
        pid = 929292

        def __init__(self, _argv, **kwargs):
            kwargs["stdout"].write(b"{}\n")

        def poll(self):
            return 0

        def wait(self, timeout):
            return 0

    def killpg(_pid, sent):
        nonlocal group_alive
        if sent == 0:
            if group_alive:
                return None
            raise ProcessLookupError()
        killed.append(sent)
        if sent == signal.SIGKILL:
            group_alive = False

    clock = iter(index * 0.25 for index in range(100))
    monkeypatch.setattr(I.subprocess, "Popen", Process)
    monkeypatch.setattr(I.os, "killpg", killpg)
    monkeypatch.setattr(I.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(I.time, "sleep", lambda _seconds: None)
    with pytest.raises(I.CompatInstallError, match="rc=127"):
        _REAL_DEPENDENCY_REPAIR(
            home=str(home), python_path=str(tmp_path / "python"),
            provenance={"generation_sha256": "b" * 64},
        )
    assert signal.SIGTERM in killed
    assert signal.SIGKILL in killed


def test_acquisition_manifest_tamper_fails_before_fetch(tmp_path, monkeypatch):
    stage, stage_fd = _acquisition_policy_stage(tmp_path)
    policy = stage / I.JS_ACQUISITION_POLICY_FILE
    raw = policy.read_bytes()
    policy.write_bytes(raw[:-2] + b" \n")
    monkeypatch.setattr(
        I, "_open_https_artifact",
        lambda _url: pytest.fail("tampered policy reached the network"),
    )
    try:
        with pytest.raises(I.CompatInstallError, match="installer authority"):
            I._authenticated_archive_acquisition_policy(stage_fd)
    finally:
        os.close(stage_fd)


class _ArchiveResponse(io.BytesIO):
    def __init__(self, raw: bytes, *, url: str, headers=None, status=200):
        super().__init__(raw)
        self._url = url
        self.headers = headers or {}
        self.status = status

    def geturl(self):
        return self._url


def test_https_fetch_ignores_proxy_environment_and_requires_tls12(monkeypatch):
    observed = {}
    response = _ArchiveResponse(b"", url="https://nodejs.org/dist/test")

    class Opener:
        def open(self, request, *, timeout):
            observed["request"] = request
            observed["timeout"] = timeout
            return response

    def build_opener(*handlers):
        observed["handlers"] = handlers
        return Opener()

    monkeypatch.setattr(I.urllib.request, "build_opener", build_opener)
    monkeypatch.setenv("HTTPS_PROXY", "http://ambient-proxy.invalid:8080")

    assert I._open_https_artifact("https://nodejs.org/dist/test") is response
    proxy, redirect, https = observed["handlers"]
    assert isinstance(proxy, I.urllib.request.ProxyHandler)
    assert proxy.proxies == {}
    assert isinstance(redirect, I._HTTPSOnlyRedirectHandler)
    assert isinstance(https, I.urllib.request.HTTPSHandler)
    assert https._context.minimum_version == I.ssl.TLSVersion.TLSv1_2
    assert observed["timeout"] == I.JS_ACQUISITION_TIMEOUT_SECONDS
    assert observed["request"].get_header("Accept-encoding") == "identity"


def _synthetic_artifact(raw: bytes, relative: str = "runtime/toolchains/js/test/test.tar.gz"):
    return types.SimpleNamespace(
        archive_format="tar.gz",
        artifact_id="synthetic-test-artifact",
        packaged_path=relative,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        source_url="https://nodejs.org/dist/v1.0.0/test.tar.gz",
    )


def test_atomic_acquisition_verifies_stream_without_ambient_local_archive(tmp_path):
    stage = tmp_path / "stage"
    stage.mkdir(mode=0o700)
    stage_fd = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    raw = I.JS_ARCHIVE_MAGIC["tar.gz"] + b"independent-clean-clone-fixture"
    artifact = _synthetic_artifact(raw)
    calls = []

    def fetch(url):
        calls.append(url)
        return _ArchiveResponse(
            raw,
            url=url,
            headers={"Content-Length": str(len(raw)), "Content-Encoding": "identity"},
        )

    try:
        I._acquire_archive(stage_fd, artifact, os.getuid(), fetcher=fetch)
    finally:
        os.close(stage_fd)

    installed = stage / artifact.packaged_path
    assert calls == [artifact.source_url]
    assert installed.read_bytes() == raw
    assert stat.S_IMODE(installed.stat().st_mode) == 0o600
    assert not list(installed.parent.glob(".*.acquire-*"))


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ("offline", "acquisition unavailable"),
        ("digest", "acquisition identity differs"),
        ("oversize", "acquisition exceeds size"),
        ("encoding", "acquisition response differs"),
        ("redirect-downgrade", "acquisition URL is not admitted"),
    ],
)
def test_acquisition_failures_are_deterministic_and_leave_no_partial_file(
    tmp_path, mutation, expected,
):
    stage = tmp_path / mutation
    stage.mkdir(mode=0o700)
    stage_fd = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    raw = I.JS_ARCHIVE_MAGIC["tar.gz"] + b"authenticated"
    artifact = _synthetic_artifact(raw)

    def fetch(url):
        if mutation == "offline":
            raise OSError("network-specific detail must not escape")
        payload = raw
        headers = {"Content-Length": str(len(raw))}
        final_url = url
        if mutation == "digest":
            payload = raw[:-1] + bytes([raw[-1] ^ 1])
        elif mutation == "oversize":
            payload = raw + b"x"
            headers = {}
        elif mutation == "encoding":
            headers["Content-Encoding"] = "gzip"
        elif mutation == "redirect-downgrade":
            final_url = "http://nodejs.org/dist/v1.0.0/test.tar.gz"
        return _ArchiveResponse(payload, url=final_url, headers=headers)

    try:
        with pytest.raises(I.CompatInstallError, match=expected):
            I._acquire_archive(stage_fd, artifact, os.getuid(), fetcher=fetch)
    finally:
        os.close(stage_fd)
    assert not (stage / artifact.packaged_path).exists()
    assert not list(stage.rglob("*.acquire-*"))


def test_midstream_transport_failure_is_deterministic_and_leaves_no_partial(
    tmp_path,
):
    stage = tmp_path / "midstream"
    stage.mkdir(mode=0o700)
    stage_fd = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    raw = I.JS_ARCHIVE_MAGIC["tar.gz"] + b"authenticated"
    artifact = _synthetic_artifact(raw)

    class BrokenResponse(_ArchiveResponse):
        def __init__(self):
            super().__init__(raw, url=artifact.source_url)
            self._reads = 0

        def read(self, size=-1):
            self._reads += 1
            if self._reads == 1:
                return super().read(5)
            raise RuntimeError("transport-specific detail must not escape")

    try:
        with pytest.raises(I.CompatInstallError, match="acquisition failed"):
            I._acquire_archive(
                stage_fd, artifact, os.getuid(), fetcher=lambda _url: BrokenResponse()
            )
    finally:
        os.close(stage_fd)
    assert not (stage / artifact.packaged_path).exists()
    assert not list(stage.rglob("*.acquire-*"))


def test_acquisition_rejects_partial_foreign_and_symlinked_sources(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(
        I, "_authenticated_archive_acquisition_policy",
        lambda _fd: pytest.fail("partial package reached network policy"),
    )
    partial = [{"kind": "file", "path": next(iter(I.JS_DISTRIBUTABLE_PATHS))}]
    stage = tmp_path / "partial"
    stage.mkdir(mode=0o700)
    stage_fd = os.open(
        stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        with pytest.raises(I.CompatInstallError, match="partial or foreign"):
            _REAL_ARCHIVE_MATERIALIZER(stage_fd, partial, os.getuid())
    finally:
        os.close(stage_fd)

    linked_stage = tmp_path / "linked"
    linked_stage.mkdir(mode=0o700)
    (linked_stage / "runtime").symlink_to(tmp_path)
    linked_fd = os.open(
        linked_stage,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    raw = I.JS_ARCHIVE_MAGIC["tar.gz"] + b"link-rejection"
    artifact = _synthetic_artifact(raw)
    try:
        with pytest.raises(I.CompatInstallError):
            I._acquire_archive(
                linked_fd,
                artifact,
                os.getuid(),
                fetcher=lambda url: _ArchiveResponse(raw, url=url),
            )
    finally:
        os.close(linked_fd)
    assert (linked_stage / "runtime").is_symlink()


@pytest.mark.parametrize(
    "url",
    [
        "http://nodejs.org/dist/v1.0.0/test.tar.gz",
        "https://attacker.invalid/test.tar.gz",
        "https://user@nodejs.org/dist/v1.0.0/test.tar.gz",
        "https://nodejs.org/dist/v1.0.0/test.tar.gz?mutable=1",
        "https://nodejs.org:444/dist/v1.0.0/test.tar.gz",
    ],
)
def test_acquisition_initial_url_policy_is_exact(url):
    with pytest.raises(I.CompatInstallError, match="URL is not admitted"):
        I._validated_acquisition_url(url, redirected=False)


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/nodejs/node/releases/download/v1/test.tar.gz",
        "https://nodejs.org/dist/v1/test.tar.gz",
        "https://attacker.invalid/test.tar.gz",
        "http://release-assets.githubusercontent.com/test.tar.gz",
        "https://user@release-assets.githubusercontent.com/test.tar.gz",
    ],
)
def test_acquisition_redirect_url_policy_is_exact(url):
    with pytest.raises(I.CompatInstallError, match="URL is not admitted"):
        I._validated_acquisition_url(url, redirected=True)


def _copy_current_runtime_closure(destination: Path) -> Path:
    """Copy and render a self-consistent closure for destructive tests."""

    rendered = None
    for _attempt in range(8):
        try:
            rendered = _TEST_CONTROL_AUTHORITY.render_runtime_closure_manifest(
                ROOT
            )
            break
        except _TEST_CONTROL_AUTHORITY.ToolchainControlError as exc:
            if "runtime path index changed during derivation" not in str(exc):
                raise
    if rendered is None:
        raise RuntimeError(
            "live source did not quiesce for the test-only closure rendering"
        )
    value = json.loads(rendered)
    destination.mkdir()
    for relative in value["files"]:
        if relative == I.JS_RUNTIME_CLOSURE_FILE:
            continue
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for row in value["assets"]:
        raw = (destination / row["path"]).read_bytes()
        if row["digest_mode"] == "utf8-lf-v1":
            raw = raw.decode("utf-8", "strict").replace("\r\n", "\n").encode(
                "utf-8"
            )
        row["sha256"] = hashlib.sha256(raw).hexdigest()
    target_closure = destination / I.JS_RUNTIME_CLOSURE_FILE
    target_closure.parent.mkdir(parents=True, exist_ok=True)
    target_closure.write_text(
        json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    anchor = ROOT / I.JS_BOOTSTRAP_ANCHOR_FILE
    target_anchor = destination / I.JS_BOOTSTRAP_ANCHOR_FILE
    target_anchor.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(anchor, target_anchor)
    return destination.resolve()


def _captured_installed_rows(source: Path) -> list[dict[str, object]]:
    descriptor = os.open(
        source,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        rows, _total = I._census_tree(descriptor)
    finally:
        os.close(descriptor)
    return I._source_rows_as_installed(rows)


def _load_real_js_authority(
    source: Path, captured_rows: list[dict[str, object]]
):
    binding = I._js_install_binding(captured_rows)
    module = I._js_authority_module()
    trusted = module.TrustedJSBootstrapAuthority(
        anchor_relative_path=binding["anchor_path"],
        anchor_sha256=binding["anchor_sha256"],
        source_census_sha256=binding["source_census_sha256"],
        install_provenance_sha256=binding["js_package_binding_sha256"],
        trust_boundary=binding["trust_boundary"],
    )
    return module.load_authority_manifest(source, bootstrap_authority=trusted)


def _installable_rendered_source(tmp_path: Path) -> Path:
    source = _copy_current_runtime_closure(tmp_path / "closure-source")
    # The small acquisition authority is a new source-freeze input and may
    # not yet appear in the concurrently regenerated runtime closure.
    acquisition = source / I.JS_ACQUISITION_POLICY_FILE
    if not acquisition.exists():
        acquisition.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / I.JS_ACQUISITION_POLICY_FILE, acquisition)
    shutil.copytree(
        ROOT / "codex-adapter/skills",
        source / "codex-adapter/skills",
    )
    rule_manifest = source / "opengrep-rules/rule-tree-authority.v1.json"
    rule_manifest.parent.mkdir(parents=True)
    shutil.copy2(
        ROOT / "opengrep-rules/rule-tree-authority.v1.json", rule_manifest
    )
    return source


def _python_with_matching_stamp(tmp_path: Path, source: Path) -> Path:
    actual = _runtime_python()
    runtime = tmp_path / "managed" / "py312"
    binary = runtime / "bin" / "python"
    binary.parent.mkdir(parents=True)
    binary.symlink_to(actual)
    digest = hashlib.sha256((source / "requirements-runtime-core.lock").read_bytes()).hexdigest()
    (runtime / ".plamen-runtime.json").write_text(
        json.dumps(
            {
                "lock_sha256": digest,
                "python_abi": "cp312",
                "schema": "plamen.python_runtime.v1",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return binary.absolute()


def _installed_python_with_matching_stamp(home: Path, source: Path) -> Path:
    actual = _runtime_python()
    actual_runtime = actual.parent.parent
    runtime = home / ".local/share/plamen/runtime/py312"
    binary = runtime / "bin/python"
    binary.parent.mkdir(parents=True)
    binary.symlink_to(actual.resolve(strict=True))
    shutil.copyfile(actual_runtime / "pyvenv.cfg", runtime / "pyvenv.cfg")
    site_packages = runtime / "lib/python3.12/site-packages"
    site_packages.parent.mkdir(parents=True)
    site_packages.symlink_to(
        actual_runtime / "lib/python3.12/site-packages",
        target_is_directory=True,
    )
    digest = hashlib.sha256(
        (source / "requirements-runtime-core.lock").read_bytes()
    ).hexdigest()
    (runtime / ".plamen-runtime.json").write_text(
        json.dumps({
            "lock_sha256": digest,
            "python_abi": "cp312",
            "schema": "plamen.python_runtime.v1",
        }, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return binary.absolute()


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    return home.resolve()


def _install(tmp_path: Path, *, hook=None):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    result = I.install_compat_v2(source, home, python, fault_hook=hook)
    return source, home, python, result


def test_success_exact_census_and_launcher(tmp_path):
    source, home, python, provenance = _install(tmp_path)

    installed = home / ".plamen"
    launcher = home / ".local/bin/plamen"
    assert installed.is_dir() and not installed.is_symlink()
    assert launcher.is_file() and not launcher.is_symlink()
    assert stat.S_IMODE(launcher.stat().st_mode) == 0o700
    assert provenance == I.verify_install(home)
    assert provenance["source_entry_count"] == len(provenance["source_census"])
    assert provenance["js_package_binding"] == I._js_install_binding(
        provenance["source_census"]
    )
    assert provenance["runtime_closure_binding"]["schema"] == (
        I.RUNTIME_CLOSURE_BINDING_SCHEMA
    )
    assert provenance["runtime_closure_binding"]["source_census_sha256"] == (
        provenance["generation_sha256"]
    )
    assert provenance["python"]["path"] == str(python)
    census_paths = {
        row["path"] for row in provenance["source_census"] if row["kind"] == "file"
    }
    assert "scripts/posix_v2_compat_runtime.py" in census_paths
    assert (installed / "scripts/posix_v2_compat_runtime.py").read_text(
        encoding="utf-8"
    ) == "COMPAT_RUNTIME_TEST = True\n"
    assert (installed / "assets/policy.txt").read_bytes() == b"exact-policy\n"
    skill_paths = {
        row["path"]: row
        for row in provenance["source_census"]
        if row["kind"] == "file"
        and row["path"].startswith(I.CODEX_SKILL_SOURCE_PREFIX)
    }
    for relative in I.REQUIRED_CODEX_SKILL_FILES:
        source_relative = I.CODEX_SKILL_SOURCE_PREFIX + relative
        installed_skill = home / ".codex" / "skills" / relative
        assert installed_skill.is_file() and not installed_skill.is_symlink()
        raw = installed_skill.read_bytes()
        assert raw == (source / source_relative).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == skill_paths[source_relative]["sha256"]
    assert not list((home / ".codex/skills").glob(".plamen-compat-v2-skills-*"))
    completed = subprocess.run(
        [str(launcher), "probe", "--posix-compat-v2"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        timeout=10,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    assert json.loads(completed.stdout) == ["probe", "--posix-compat-v2"]
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_current_source_clean_temporary_install_includes_all_skill_companions(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr(I, "_validate_source_js_package", _REAL_SOURCE_JS_GATE)
    monkeypatch.setattr(I, "_validate_staged_js_package", _REAL_STAGED_JS_GATE)
    _use_real_complete_closure_gate(monkeypatch)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, ROOT)

    provenance = I.install_compat_v2(ROOT, home, python)

    census = {
        row["path"]: row
        for row in provenance["source_census"]
        if row["kind"] == "file"
    }
    authority = _load_real_js_authority(ROOT, provenance["source_census"])
    assert len(authority.artifacts) == 7
    for artifact in authority.artifacts:
        row = census[artifact.packaged_path]
        assert row["size"] == artifact.size
        assert row["sha256"] == artifact.sha256
    assert I.REQUIRED_SOURCE_FILES.issubset(census)
    for relative in I.REQUIRED_CODEX_SKILL_FILES:
        source_relative = I.CODEX_SKILL_SOURCE_PREFIX + relative
        expected = (ROOT / source_relative).read_bytes()
        installed = (home / ".codex/skills" / relative).read_bytes()
        assert installed == expected
        assert census[source_relative]["sha256"] == hashlib.sha256(expected).hexdigest()
    assert I.verify_install(home) == provenance


def test_real_js_package_defects_fail_before_any_publication(
    tmp_path, monkeypatch
):
    source = _copy_current_runtime_closure(tmp_path / "closure-source")
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    monkeypatch.setattr(I, "_validate_source_js_package", _REAL_SOURCE_JS_GATE)
    monkeypatch.setattr(I, "_validate_staged_js_package", _REAL_STAGED_JS_GATE)
    _use_real_complete_closure_gate(monkeypatch)

    # Establish that the destructive fixture starts from the complete,
    # all-platform package admitted by the production validator.
    captured_rows = _captured_installed_rows(source)
    binding = I._js_install_binding(captured_rows)
    _REAL_SOURCE_JS_GATE(
        str(source),
        bootstrap_binding=binding,
        captured_rows=captured_rows,
    )
    authority = _load_real_js_authority(source, captured_rows)
    yarn = next(
        row for row in authority.artifacts if row.artifact_id == "yarn-classic-noarch"
    )
    cases = (
        ("payload", source / yarn.packaged_path),
        ("module", source / "scripts/js_toolchain_authority.py"),
        ("policy", source / I.JS_AUTHORITY_POLICY_FILE),
    )

    for label, target in cases:
        saved = target.read_bytes()
        backup = tmp_path / f"{label}.saved"
        target.replace(backup)
        with pytest.raises(I.CompatInstallError):
            I.install_compat_v2(source, home, python)
        backup.replace(target)
        assert not (home / ".plamen").exists()
        assert not (home / ".local/bin/plamen").exists()
        assert not (home / ".codex/skills/plamen").exists()
        assert not list(home.glob(".plamen-compat-v2-*"))

        tampered = bytes([saved[0] ^ 1]) + saved[1:]
        target.chmod(0o600)
        target.write_bytes(tampered)
        with pytest.raises(I.CompatInstallError):
            I.install_compat_v2(source, home, python)
        target.write_bytes(saved)
        assert not (home / ".plamen").exists()
        assert not (home / ".local/bin/plamen").exists()
        assert not (home / ".codex/skills/plamen").exists()
        assert not list(home.glob(".plamen-compat-v2-*"))


def test_rendered_runtime_closure_installs_real_js_package_transactionally(
    tmp_path, monkeypatch
):
    source = _installable_rendered_source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    monkeypatch.setattr(I, "_validate_source_js_package", _REAL_SOURCE_JS_GATE)
    monkeypatch.setattr(I, "_validate_staged_js_package", _REAL_STAGED_JS_GATE)
    _use_real_complete_closure_gate(monkeypatch)

    provenance = I.install_compat_v2(source, home, python)

    authority = _load_real_js_authority(source, provenance["source_census"])
    census = {
        row["path"]: row
        for row in provenance["source_census"]
        if row["kind"] == "file"
    }
    assert len(authority.artifacts) == 7
    for artifact in authority.artifacts:
        assert census[artifact.packaged_path]["size"] == artifact.size
        assert census[artifact.packaged_path]["sha256"] == artifact.sha256
        assert (home / ".plamen" / artifact.packaged_path).is_file()
    assert I.verify_install(home) == provenance


def test_complete_closure_shrink_retaining_all_js_members_fails_prepublication(
    tmp_path, monkeypatch,
):
    source = _installable_rendered_source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    closure_path = source / I.JS_RUNTIME_CLOSURE_FILE
    payload = json.loads(closure_path.read_text(encoding="ascii"))
    anchor = json.loads(
        (source / I.JS_BOOTSTRAP_ANCHOR_FILE).read_text(encoding="ascii")
    )
    js_members = {row["path"] for row in anchor["signed_set"]}
    assert js_members.issubset(payload["files"])
    omitted = next(
        row["path"]
        for row in payload["assets"]
        if row["path"] not in js_members
        and row["path"] not in payload["entrypoints"]
        and row["path"] != "scripts/toolchain_control_authority.py"
    )
    payload["files"].remove(omitted)
    payload["assets"] = [
        row for row in payload["assets"] if row["path"] != omitted
    ]
    assert js_members.issubset(payload["files"])
    closure_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
    )

    _use_real_complete_closure_gate(monkeypatch)
    with pytest.raises(
        I.CompatInstallError,
        match="complete runtime closure rejected",
    ):
        I.install_compat_v2(source, home, python)

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_source_semantic_swap_cannot_bless_different_captured_bytes(
    tmp_path, monkeypatch
):
    source = _installable_rendered_source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    module_path = source / "scripts/js_toolchain_authority.py"
    admitted = module_path.read_bytes()
    tampered = admitted[:-1] + bytes([admitted[-1] ^ 1])
    module_path.chmod(0o600)
    module_path.write_bytes(tampered)

    def ephemeral_valid_source(root, **kwargs):
        target = Path(root) / "scripts/js_toolchain_authority.py"
        target.write_bytes(admitted)
        try:
            return _REAL_SOURCE_JS_GATE(root, **kwargs)
        finally:
            target.write_bytes(tampered)

    monkeypatch.setattr(
        I, "_validate_source_js_package", ephemeral_valid_source
    )
    monkeypatch.setattr(I, "_validate_staged_js_package", _REAL_STAGED_JS_GATE)

    with pytest.raises(
        I.CompatInstallError, match="(?:member|asset) differs from census"
    ):
        I.install_compat_v2(source, home, python)
    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_coherent_module_anchor_and_closure_replacement_cannot_self_authorize(
    tmp_path, monkeypatch,
):
    source = _installable_rendered_source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    target_relative = "scripts/js_toolchain_authority.py"
    target = source / target_relative
    original = target.read_bytes()
    assert original.endswith(b"\n")
    mutated = original[:-1] + b" "
    assert len(mutated) == len(original)
    target.chmod(0o600)
    target.write_bytes(mutated)
    old_digest = hashlib.sha256(original).hexdigest()
    new_digest = hashlib.sha256(mutated).hexdigest()

    anchor_path = source / I.JS_BOOTSTRAP_ANCHOR_FILE
    anchor_raw = anchor_path.read_bytes()
    anchor = json.loads(anchor_raw)
    member = next(
        row for row in anchor["signed_set"] if row["path"] == target_relative
    )
    assert member["sha256"] == old_digest
    prior_signed_set = anchor["signed_set_sha256"]
    member["sha256"] = new_digest
    next_signed_set = hashlib.sha256(
        I._canonical_json(anchor["signed_set"])
    ).hexdigest()
    forged_anchor_raw = anchor_raw.replace(
        old_digest.encode("ascii"), new_digest.encode("ascii"), 1
    ).replace(
        prior_signed_set.encode("ascii"), next_signed_set.encode("ascii"), 1
    )
    assert len(forged_anchor_raw) == len(anchor_raw)
    anchor_path.write_bytes(forged_anchor_raw)

    closure_path = source / I.JS_RUNTIME_CLOSURE_FILE
    closure_raw = closure_path.read_bytes()
    forged_closure_raw = closure_raw.replace(
        old_digest.encode("ascii"), new_digest.encode("ascii"), 1
    )
    assert forged_closure_raw != closure_raw
    assert len(forged_closure_raw) == len(closure_raw)
    closure_path.write_bytes(forged_closure_raw)

    monkeypatch.setattr(I, "_validate_source_js_package", _REAL_SOURCE_JS_GATE)
    monkeypatch.setattr(I, "_validate_staged_js_package", _REAL_STAGED_JS_GATE)
    with pytest.raises(
        I.CompatInstallError,
        match="bootstrap anchor differs from trusted installer",
    ):
        I.install_compat_v2(source, home, python)

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_stage_mutation_after_semantic_validation_fails_recensus(
    tmp_path, monkeypatch
):
    source = _installable_rendered_source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)

    def mutate_after_staged_validation(root, **kwargs):
        receipt = _REAL_STAGED_JS_GATE(root, **kwargs)
        target = Path(root) / "scripts/js_toolchain_authority.py"
        admitted = target.read_bytes()
        target.chmod(0o600)
        target.write_bytes(admitted[:-1] + bytes([admitted[-1] ^ 1]))
        return receipt

    monkeypatch.setattr(I, "_validate_source_js_package", _REAL_SOURCE_JS_GATE)
    monkeypatch.setattr(
        I, "_validate_staged_js_package", mutate_after_staged_validation
    )

    with pytest.raises(I.CompatInstallError, match="changed after semantic"):
        I.install_compat_v2(source, home, python)
    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_staged_js_rejection_removes_private_capture_without_publication(
    tmp_path, monkeypatch
):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    observed = []

    def source_gate(root, **_kwargs):
        observed.append(("source", Path(root)))

    def staged_gate(root, **_kwargs):
        observed.append(("stage", Path(root)))
        raise I.CompatInstallError("injected staged JavaScript rejection")

    monkeypatch.setattr(I, "_validate_source_js_package", source_gate)
    monkeypatch.setattr(I, "_validate_staged_js_package", staged_gate)
    with pytest.raises(I.CompatInstallError, match="staged JavaScript"):
        I.install_compat_v2(source, home, python)

    assert [kind for kind, _root in observed] == ["source", "stage"]
    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_staged_js_receipt_drift_blocks_publication(tmp_path, monkeypatch):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    source_receipt = dict(_MOCK_JS_RECEIPT)
    staged_receipt = dict(_MOCK_JS_RECEIPT)
    staged_receipt["runtime_closure_sha256"] = "2" * 64
    monkeypatch.setattr(
        I,
        "_validate_source_js_package",
        lambda _root, **_kwargs: source_receipt,
    )
    monkeypatch.setattr(
        I,
        "_validate_staged_js_package",
        lambda _root, **_kwargs: staged_receipt,
    )

    with pytest.raises(I.CompatInstallError, match="provenance differs from source"):
        I.install_compat_v2(source, home, python)

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_js_authority_runtime_inputs_are_mandatory() -> None:
    assert I.JS_AUTHORITY_MODULE_FILES | {
        I.JS_AUTHORITY_POLICY_FILE,
        I.JS_RUNTIME_CLOSURE_FILE,
    } <= I.REQUIRED_SOURCE_FILES


def test_rule_authority_replays_on_source_and_git_free_stage_before_publication(
    tmp_path, monkeypatch
):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    (source / "opengrep-rules/example/.git").mkdir(parents=True)
    (source / "opengrep-rules/example/rule.yaml").write_text(
        "rules: []\n", encoding="utf-8"
    )
    calls = []

    def source_gate(root):
        calls.append(("source", Path(root)))
        assert Path(root) == source
        assert (Path(root) / "opengrep-rules/example/.git").is_dir()

    def staged_gate(root):
        calls.append(("stage", Path(root)))
        assert not (home / ".plamen").exists()
        assert not list(Path(root).rglob(".git"))
        assert (Path(root) / "opengrep-rules/example/rule.yaml").is_file()

    monkeypatch.setattr(I, "_validate_source_rule_package", source_gate)
    monkeypatch.setattr(I, "_validate_staged_rule_package", staged_gate)
    I.install_compat_v2(source, home, python)
    assert [kind for kind, _root in calls] == ["source", "stage"]


def test_missing_declared_skill_companion_fails_before_publication(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    (source / "codex-adapter/skills/plamen/plamen-wizard.md").unlink()

    with pytest.raises(I.CompatInstallError, match="required Codex skill companion"):
        I.install_compat_v2(source, home, python)

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()
    assert not (home / ".codex/skills/plamen").exists()


def test_codex_skill_projection_preserves_unmanaged_skill_tree(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    foreign = home / ".codex/skills/user-owned/reference.md"
    foreign.parent.mkdir(parents=True)
    foreign.write_bytes(b"user-owned\n")

    I.install_compat_v2(source, home, python)

    assert foreign.read_bytes() == b"user-owned\n"
    assert (home / ".codex/skills/plamen/plamen-wizard.md").is_file()


def test_unowned_path_inside_managed_skill_is_never_deleted(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    foreign = home / ".codex/skills/plamen/user-notes.md"
    foreign.parent.mkdir(parents=True)
    foreign.write_bytes(b"do not delete\n")

    with pytest.raises(I.CompatInstallError, match="unowned stale path"):
        I.install_compat_v2(source, home, python)

    assert foreign.read_bytes() == b"do not delete\n"
    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()


def test_reinstall_retires_only_authenticated_stale_skill_file(tmp_path):
    source = _source(tmp_path)
    stale_source = source / "codex-adapter/skills/plamen/retired.md"
    stale_source.write_bytes(b"retired companion\n")
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)

    I.install_compat_v2(source, home, python)
    stale_installed = home / ".codex/skills/plamen/retired.md"
    assert stale_installed.read_bytes() == b"retired companion\n"

    stale_source.unlink()
    I.install_compat_v2(source, home, python)

    assert not stale_installed.exists()
    assert (home / ".codex/skills/plamen/plamen-wizard.md").is_file()
    assert I.verify_install(home)["schema"] == I.SCHEMA


def _rewrite_installed_as_pre_js_v1(home: Path) -> None:
    runtime = home / ".plamen"
    provenance_path = runtime / I.PROVENANCE_LEAF
    predecessor = json.loads(provenance_path.read_text(encoding="utf-8"))
    exact_js = set(I.JS_AUTHORITY_MODULE_FILES) | {
        I.JS_AUTHORITY_POLICY_FILE,
        I.JS_BOOTSTRAP_ANCHOR_FILE,
        I.JS_RUNTIME_CLOSURE_FILE,
    }
    retained = []
    for row in predecessor["source_census"]:
        relative = row["path"]
        is_js = (
            relative in exact_js
            or relative == "runtime/toolchains/js"
            or relative.startswith("runtime/toolchains/js/")
        )
        if not is_js:
            retained.append(row)
        elif row["kind"] == "file":
            (runtime / relative).unlink()
    js_root = runtime / "runtime/toolchains/js"
    if js_root.exists():
        shutil.rmtree(js_root)
    predecessor["schema"] = I.LEGACY_SCHEMA
    predecessor.pop("js_package_binding")
    predecessor.pop("runtime_closure_binding")
    predecessor["source_census"] = retained
    predecessor["source_entry_count"] = len(retained)
    predecessor["source_total_bytes"] = sum(
        row["size"] for row in retained if row["kind"] == "file"
    )
    predecessor["generation_sha256"] = I._tree_digest(retained)
    provenance_path.write_text(
        json.dumps(predecessor, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_reinstall_supersedes_only_explicitly_authenticated_pre_js_v1(
    tmp_path, monkeypatch,
):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    I.install_compat_v2(source, home, python)
    _rewrite_installed_as_pre_js_v1(home)
    predecessor = json.loads(
        (home / ".plamen" / I.PROVENANCE_LEAF).read_text(encoding="utf-8")
    )
    monkeypatch.setattr(
        I,
        "AUTHENTIC_PRE_JS_V1_GENERATIONS",
        frozenset({predecessor["generation_sha256"]}),
    )

    successor = I.install_compat_v2(source, home, python)

    assert successor["schema"] == I.SCHEMA
    assert successor["js_package_binding"] == I._js_install_binding(
        successor["source_census"]
    )
    assert I.verify_install(home) == successor


def test_reinstall_rejects_delete_all_js_and_recomputed_v1_downgrade(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    I.install_compat_v2(source, home, python)
    _rewrite_installed_as_pre_js_v1(home)

    with pytest.raises(
        I.CompatInstallError,
        match="legacy compatibility generation is not authenticated",
    ):
        I.install_compat_v2(source, home, python)


def test_reinstall_rejects_v1_downgrade_of_js_package(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    I.install_compat_v2(source, home, python)
    provenance_path = home / ".plamen" / I.PROVENANCE_LEAF
    predecessor = json.loads(provenance_path.read_text(encoding="utf-8"))
    predecessor["schema"] = I.LEGACY_SCHEMA
    predecessor.pop("js_package_binding")
    predecessor.pop("runtime_closure_binding")
    provenance_path.write_text(
        json.dumps(predecessor, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(
        I.CompatInstallError,
        match="legacy JavaScript compatibility generation is not authenticated for retirement",
    ):
        I.install_compat_v2(source, home, python)


def test_exact_js_v1_is_retirement_only_and_cannot_authorize_successor(
    tmp_path, monkeypatch,
):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    predecessor = I.install_compat_v2(source, home, python)
    provenance_path = home / ".plamen" / I.PROVENANCE_LEAF
    legacy = dict(predecessor)
    legacy["schema"] = I.LEGACY_SCHEMA
    legacy.pop("js_package_binding")
    legacy.pop("runtime_closure_binding")
    provenance_path.write_text(
        json.dumps(legacy, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        I,
        "AUTHENTIC_JS_V1_RETIREMENT_GENERATIONS",
        frozenset({legacy["generation_sha256"]}),
    )

    # Retirement admission cannot be confused with current runtime authority.
    with pytest.raises(
        I.CompatInstallError,
        match="compatibility provenance schema differs",
    ):
        I.verify_install(home)

    successor = I.install_compat_v2(source, home, python)

    assert successor["schema"] == I.SCHEMA
    assert successor["generation_sha256"] == predecessor["generation_sha256"]
    assert successor["js_package_binding"] == I._js_install_binding(
        successor["source_census"]
    )
    assert successor["runtime_closure_binding"] == (
        _mock_complete_runtime_closure(
            source, "source package", captured_rows=successor["source_census"]
        )
    )
    assert I.verify_install(home) == successor


def test_modified_authenticated_stale_skill_file_blocks_reinstall(tmp_path):
    source = _source(tmp_path)
    stale_source = source / "codex-adapter/skills/plamen/retired.md"
    stale_source.write_bytes(b"owned predecessor\n")
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)

    I.install_compat_v2(source, home, python)
    stale_installed = home / ".codex/skills/plamen/retired.md"
    stale_installed.write_bytes(b"user modified\n")
    stale_source.unlink()

    with pytest.raises(I.CompatInstallError, match="differs from prior authority"):
        I.install_compat_v2(source, home, python)

    assert stale_installed.read_bytes() == b"user modified\n"
    assert (home / ".plamen/codex-adapter/skills/plamen/retired.md").read_bytes() == b"owned predecessor\n"


def test_plain_installed_real_front_reaches_non_tty_wizard_guard(tmp_path):
    source = _source(tmp_path)
    shutil.copyfile(ROOT / "plamen.py", source / "plamen.py")
    for leaf in (
        "plamen_driver.py",
        "opengrep_rule_authority.py",
        "posix_v2_compat_install.py",
        "posix_v2_compat_runtime.py",
    ):
        shutil.copyfile(ROOT / "scripts" / leaf, source / "scripts" / leaf)
    shutil.copyfile(ROOT / "VERSION", source / "VERSION")
    home = _home(tmp_path)
    python = _installed_python_with_matching_stamp(home, source)
    I.install_compat_v2(source, home, python)

    completed = subprocess.run(
        [str(home / ".local/bin/plamen")],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"HOME": str(home)},
        timeout=20,
        check=False,
    )

    error = completed.stderr.decode("utf-8", "replace")
    assert completed.returncode == 2, error
    assert "interactive wizard needs a real terminal" in error
    assert "maintenance admission denied" not in error.lower()
    assert ".plamen-install.admission.lock" not in error


def test_plain_installed_real_front_rejects_provenance_drift(tmp_path):
    source = _source(tmp_path)
    shutil.copyfile(ROOT / "plamen.py", source / "plamen.py")
    for leaf in (
        "plamen_driver.py",
        "posix_v2_compat_install.py",
        "posix_v2_compat_runtime.py",
    ):
        shutil.copyfile(ROOT / "scripts" / leaf, source / "scripts" / leaf)
    shutil.copyfile(ROOT / "VERSION", source / "VERSION")
    home = _home(tmp_path)
    python = _installed_python_with_matching_stamp(home, source)
    I.install_compat_v2(source, home, python)
    (home / ".plamen/assets/policy.txt").write_bytes(b"drifted\n")

    completed = subprocess.run(
        [str(home / ".local/bin/plamen")],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"HOME": str(home)},
        timeout=20,
        check=False,
    )

    error = completed.stderr.decode("utf-8", "replace")
    assert completed.returncode == 75
    assert "POSIX compatibility admission denied" in error


@pytest.mark.parametrize(
    "mutation", [
        "binding-digest", "closure-binding-digest", "legacy-downgrade",
        "legacy-delete-js",
    ],
)
def test_plain_front_rejects_js_binding_tamper_or_v1_downgrade(
    tmp_path, mutation
):
    source = _source(tmp_path)
    shutil.copyfile(ROOT / "plamen.py", source / "plamen.py")
    for leaf in (
        "plamen_driver.py",
        "posix_v2_compat_install.py",
        "posix_v2_compat_runtime.py",
    ):
        shutil.copyfile(ROOT / "scripts" / leaf, source / "scripts" / leaf)
    shutil.copyfile(ROOT / "VERSION", source / "VERSION")
    home = _home(tmp_path)
    python = _installed_python_with_matching_stamp(home, source)
    I.install_compat_v2(source, home, python)
    provenance_path = home / ".plamen" / I.PROVENANCE_LEAF
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if mutation == "binding-digest":
        provenance["js_package_binding"]["js_package_binding_sha256"] = "f" * 64
    elif mutation == "closure-binding-digest":
        provenance["runtime_closure_binding"][
            "runtime_closure_binding_sha256"
        ] = "f" * 64
    elif mutation == "legacy-downgrade":
        provenance["schema"] = I.LEGACY_SCHEMA
        provenance.pop("js_package_binding")
        provenance.pop("runtime_closure_binding")
    if mutation == "legacy-delete-js":
        _rewrite_installed_as_pre_js_v1(home)
    else:
        provenance_path.write_text(
            json.dumps(provenance, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )

    completed = subprocess.run(
        [str(home / ".local/bin/plamen")],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"HOME": str(home)},
        timeout=20,
        check=False,
    )

    assert completed.returncode == 75
    assert b"POSIX compatibility admission denied" in completed.stderr


def test_source_link_is_rejected_before_publication(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    (source / "scripts" / "indirect.py").symlink_to(source / "plamen.py")

    with pytest.raises(I.CompatInstallError, match="link or special"):
        I.install_compat_v2(source, home, python)

    assert not (home / ".plamen").exists()
    assert not (home / ".local/bin/plamen").exists()


def test_source_drift_is_rejected_and_staging_removed(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)

    def mutate(stage):
        if stage == "after_source_capture":
            (source / "assets/policy.txt").write_bytes(b"changed\n")

    with pytest.raises(I.CompatInstallError, match="source snapshot changed"):
        I.install_compat_v2(source, home, python, fault_hook=mutate)

    assert not (home / ".plamen").exists()
    assert not list(home.glob(".plamen-compat-v2-*"))


def test_published_tamper_fails_exact_verification(tmp_path):
    _source_path, home, _python, _provenance = _install(tmp_path)
    (home / ".plamen/assets/policy.txt").write_bytes(b"tampered\n")

    with pytest.raises(I.CompatInstallError, match="differs from provenance"):
        I.verify_install(home)


def test_codex_skill_companion_tamper_fails_exact_verification(tmp_path):
    _source_path, home, _python, _provenance = _install(tmp_path)
    (home / ".codex/skills/plamen/plamen-wizard.md").write_bytes(b"tampered\n")

    with pytest.raises(I.CompatInstallError, match="skill projection differs"):
        I.verify_install(home)


def test_success_retires_old_v2_instead_of_preserving_it(tmp_path):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    prior = home / ".plamen"
    prior.mkdir()
    (prior / "plamen.py").write_bytes(b"OLD-RUNTIME\n")
    (prior / "old-v2-only.txt").write_bytes(b"must not survive\n")

    I.install_compat_v2(source, home, python)

    assert not (home / ".plamen/old-v2-only.txt").exists()
    assert (home / ".plamen/plamen.py").read_bytes() == (source / "plamen.py").read_bytes()
    assert not list(home.glob(".plamen-compat-v2-rollback-*"))


@pytest.mark.parametrize(
    "failure_stage",
    [
        "after_prior_retired", "after_runtime_published",
        "after_skills_published", "after_python_dependencies_validated",
    ],
)
def test_failure_rolls_back_prior_runtime_and_launcher(tmp_path, failure_stage):
    source = _source(tmp_path)
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    prior = home / ".plamen"
    prior.mkdir()
    (prior / "plamen.py").write_bytes(b"OLD-RUNTIME\n")
    command = home / ".local/bin/plamen"
    command.parent.mkdir(parents=True)
    old_launcher = b"#!/bin/sh\n# Plamen old .plamen launcher\nexit 9\n"
    command.write_bytes(old_launcher)
    command.chmod(0o700)

    def fail(stage):
        if stage == failure_stage:
            raise RuntimeError("injected failure")

    with pytest.raises(RuntimeError, match="injected failure"):
        I.install_compat_v2(source, home, python, fault_hook=fail)

    assert (home / ".plamen/plamen.py").read_bytes() == b"OLD-RUNTIME\n"
    assert command.read_bytes() == old_launcher
    assert not any(
        (home / ".codex/skills" / name).exists()
        for name in I.MANAGED_CODEX_SKILL_NAMES
    )
    assert not list((home / ".codex/skills").glob(".plamen-compat-v2-skills-*"))
    assert not list(home.glob(".plamen-compat-v2-*"))
    assert not (home / ".local/share/plamen/compat-v2/compat-install-transaction.json").exists()


def test_provenance_distinguishes_snapshot_from_conditional_dependency_repair(tmp_path):
    _source_path, home, _python, provenance = _install(tmp_path)
    security = provenance["security_properties"]
    assert security == {
        "descriptor_admitted_source": True,
        "native_broker": False,
        "native_guest_isolation": False,
        "native_install_receipt": False,
        "reduced_isolation": True,
        "site_packages_modified_by_snapshot_publisher": False,
        "managed_site_packages_repair": (
            "CONDITIONAL_ISOLATED_HASH_LOCKED_BINARY_ONLY_BEFORE_COMMIT"
        ),
        "managed_site_packages_transactional_rollback": False,
    }
    raw = (home / ".plamen" / I.PROVENANCE_LEAF).read_bytes()
    assert b'"native_broker":true' not in raw
    assert b'"native_guest_isolation":true' not in raw
    assert b'"native_install_receipt":true' not in raw
    assert not list(home.rglob("native-install-receipt-v2.bin"))


def test_exact_executable_cli_requires_both_explicit_tokens(tmp_path):
    source = _source(tmp_path)
    # This isolated child cannot inherit pytest's in-process repair double.
    # Keep the fixture inert: exercise CLI dispatch/publication with an explicit
    # protocol double, never pip or the operator's managed dependency runtime.
    (source / "plamen.py").write_text(
        "import json,sys\n"
        "from pathlib import Path\n"
        "assert sys.argv[1:]==['install','--posix-compat-v2-dependencies']\n"
        "root=Path(__file__).parent\n"
        "provenance=json.loads((root/'.plamen-posix-compat-v2-provenance.json').read_text())\n"
        "result={'schema':'plamen.posix_v2_compat_python_dependencies.v1',"
        "'status':'VALID','reduced_isolation':True,"
        "'generation_sha256':provenance['generation_sha256'],"
        "'dependency_authority_sha256':'a'*64,"
        "'trust_boundary':'USER_WRITABLE_DRIFT_DETECTION_ONLY',"
        "'native_install_authority':False}\n"
        "print(json.dumps(result,sort_keys=True,separators=(',',':')))\n",
        encoding="utf-8",
    )
    _materialize_explicit_mock_js_package(source)
    # Exercise the isolated executable route with a sibling authority double.
    # The rule-package authority's real multi-repository Git replay belongs to
    # its dedicated tests; this fixture isolates CLI token parsing and install
    # dispatch without adding a production bypass.
    cli_tool = tmp_path / "cli-tool"
    cli_tool.mkdir()
    script = cli_tool / "posix_v2_compat_install.py"
    shutil.copyfile(ROOT / "scripts/posix_v2_compat_install.py", script)
    (cli_tool / "opengrep_rule_authority.py").write_text(
        "def validate_source_rule_authority(_root):\n"
        "    return None\n"
        "def validate_installed_rule_authority(_root):\n"
        "    return None\n",
        encoding="utf-8",
    )
    (cli_tool / "js_toolchain_authority.py").write_text(
        "import hashlib,json\n"
        "from pathlib import Path\n"
        "from types import SimpleNamespace\n"
        "class TrustedJSBootstrapAuthority:\n"
        "    def __init__(self,**values): self.__dict__.update(values)\n"
        "def load_authority_manifest(root,*,bootstrap_authority):\n"
        "    root=Path(root)\n"
        "    value=json.loads((Path(root)/'verification_policy/js_toolchain_authority.v1.json').read_text())\n"
        "    closure=json.loads((root/'verification_policy/toolchain_runtime_closure.v1.json').read_text())\n"
        "    members=tuple(SimpleNamespace(path=row['path'],kind='test',digest_mode='raw-v1',sha256=row['sha256'],size=(root/row['path']).stat().st_size) for row in closure['assets'])\n"
        "    return SimpleNamespace(artifacts=tuple(SimpleNamespace(**row) for row in value['artifacts']),bootstrap_anchor_sha256=bootstrap_authority.anchor_sha256,bootstrap_signed_set_sha256='2'*64,bootstrap_members=members,content_sha256='0'*64,runtime_closure_sha256='1'*64)\n",
        encoding="utf-8",
    )
    (cli_tool / "toolchain_control_authority.py").write_text(
        "import json\n"
        "from pathlib import Path\n"
        "def load_runtime_closure_manifest(root):\n"
        "    return json.loads((Path(root)/'verification_policy/toolchain_runtime_closure.v1.json').read_text())\n",
        encoding="utf-8",
    )
    home = _home(tmp_path)
    python = _python_with_matching_stamp(tmp_path, source)
    command = [
        str(_runtime_python()),
        "-I",
        "-B",
        str(script),
        "--posix-compat-v2",
        "--source",
        str(source),
        "--install",
        "--home",
        str(home),
        "--python",
        str(python),
    ]

    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={},
        timeout=30,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    summary = json.loads(completed.stdout)
    assert summary["schema"] == I.SCHEMA
    assert summary["reduced_isolation"] is True
    with pytest.raises(I.CompatInstallError, match="explicit --install"):
        I.main(
            [
                "--posix-compat-v2",
                "--source",
                str(source),
                "--home",
                str(home),
                "--python",
                str(python),
            ]
        )
