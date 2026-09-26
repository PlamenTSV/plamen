#!/usr/bin/env python3
"""Deterministic POSIX V2 compatibility installer for Plamen V3.

This is deliberately a compatibility transaction, not a native installer.  It
copies one descriptor-admitted source snapshot into ``~/.plamen``, reuses an
already materialized and hash-stamped CPython 3.12 runtime, and publishes the
public launcher only after the exact full Python dependency repair validates.
It remains reduced-isolation and never emits a native-install receipt.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.machinery
import importlib.util
import json
import os
if os.name == "posix":
    import fcntl
    import pwd
else:
    fcntl = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]
from pathlib import Path
import re
import signal
import shlex
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import types
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, NoReturn


SCHEMA = "plamen.posix_compat_v2.install.v2"
LEGACY_SCHEMA = "plamen.posix_compat_v2.install.v1"
LEGACY_JOURNAL_SCHEMA = "plamen.posix_compat_v2.transaction.v1"
JOURNAL_SCHEMA = "plamen.posix_compat_v2.transaction.v2"
PROVENANCE_LEAF = ".plamen-posix-compat-v2-provenance.json"
JOURNAL_LEAF = "compat-install-transaction.json"
RUNTIME_LEAF = ".plamen"
LAUNCHER_LEAF = "plamen"
MAX_PATH_BYTES = 4096
MAX_FILES = 50_000
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_INTERPRETER_OUTPUT = 16 * 1024
JS_ACQUISITION_TIMEOUT_SECONDS = 60
JS_ACQUISITION_MAX_REDIRECTS = 5
REQUIRED_SOURCE_FILES = frozenset(
    {
        "plamen.py",
        "opengrep-rules/rule-tree-authority.v1.json",
        "requirements-runtime-core.lock",
        "requirements-runtime-full.lock",
        "scripts/js_dependency_materializer_authority.py",
        "scripts/js_dependency_materializer_runtime.py",
        "scripts/js_lock_authority.py",
        "scripts/js_toolchain_authority.py",
        "scripts/plamen_driver.py",
        "scripts/posix_v2_compat_runtime.py",
        "scripts/posix_v2_compat_exec_helper.py",
        "scripts/toolchain_control_authority.py",
        "verification_policy/js_toolchain_authority.v1.json",
        "verification_policy/js_toolchain_acquisition.v1.json",
        "verification_policy/js_toolchain_bootstrap.v1.json",
        "verification_policy/toolchain_runtime_closure.v1.json",
    }
)
EXCLUDED_NAMES = frozenset(
    {
        ".git",
        ".pytest_cache",
        ".scratchpad",
        ".venv",
        ".venv-dev",
        "__pycache__",
        ".DS_Store",
    }
)
EXCLUDED_SUFFIXES = (".pyc", ".pyo")
_TXN_LEAF = re.compile(r"\A\.plamen-compat-v2-(?:stage|rollback)-[0-9a-f]{32}\Z")
_SKILL_TXN_LEAF = re.compile(
    r"\A\.plamen-compat-v2-skills-(?:stage|rollback)-[0-9a-f]{32}\Z"
)
CODEX_SKILL_SOURCE_PREFIX = "codex-adapter/skills/"
MANAGED_CODEX_SKILL_NAMES = (
    "plamen",
    "plamen-l1",
    "plamen-l1-wizard",
    "plamen-wizard",
)
REQUIRED_CODEX_SKILL_FILES = frozenset(
    {
        "plamen/SKILL.md",
        "plamen/plamen-l1-wizard.md",
        "plamen/plamen-wizard.md",
        "plamen-l1/SKILL.md",
        "plamen-l1-wizard/SKILL.md",
        "plamen-wizard/SKILL.md",
    }
)
JS_AUTHORITY_MODULE_FILES = frozenset(
    {
        "scripts/js_dependency_materializer_authority.py",
        "scripts/js_dependency_materializer_runtime.py",
        "scripts/js_lock_authority.py",
        "scripts/js_toolchain_authority.py",
    }
)
JS_AUTHORITY_POLICY_FILE = "verification_policy/js_toolchain_authority.v1.json"
JS_ACQUISITION_POLICY_FILE = (
    "verification_policy/js_toolchain_acquisition.v1.json"
)
EXPECTED_JS_ACQUISITION_POLICY_SHA256 = (
    "1415be669b64a60c82bdd18b9b0d15364ebc5c3696d687f0a722bdef85c0681f"
)
JS_BOOTSTRAP_ANCHOR_FILE = "verification_policy/js_toolchain_bootstrap.v1.json"
JS_RUNTIME_CLOSURE_FILE = "verification_policy/toolchain_runtime_closure.v1.json"
JS_INSTALL_BINDING_SCHEMA = "plamen.js-bootstrap-install-provenance.v1"
JS_INSTALL_TRUST_BOUNDARY = "AUTHENTICATED_INSTALLER_LAUNCHER_BOUNDARY_V1"
EXPECTED_JS_BOOTSTRAP_ANCHOR_SHA256 = (
    "20dcb25530d73e14ad8e1a8bb9d827b8395b5fa17c29d2b5513582d63f11ec97"
)
RUNTIME_CLOSURE_BINDING_SCHEMA = (
    "plamen.toolchain-runtime-closure-install-provenance.v1"
)
RUNTIME_CLOSURE_BINDING_FIELDS = frozenset({
    "assets_sha256", "file_count", "files_sha256", "manifest_path",
    "manifest_sha256", "runtime_closure_binding_sha256", "schema",
    "source_census_sha256",
})
# A legacy generation is migration authority only after its exact descriptor
# census has been independently reviewed and frozen here.  Structural absence
# of JS rows is necessary but never authenticates a predecessor by itself.
AUTHENTIC_PRE_JS_V1_GENERATIONS = frozenset()
# JS-bearing v1 generations in this set are authority only for retiring the
# exact prior runtime and its byte-identical Codex skill projection during a
# transactional v2 replacement.  They are never accepted by verify_install(),
# never supply JavaScript bootstrap authority, and never authorize the staged
# successor.  The successor independently validates its v2 JS/bootstrap and
# complete-runtime-closure bindings before this predecessor is inspected.
AUTHENTIC_JS_V1_RETIREMENT_GENERATIONS = frozenset({
    "885e353e15e1c05c265f4662688870042f30291fba57aeaa2d725e474ceb462e",
})
# A current-schema predecessor carries its own bootstrap anchor. Once that
# anchor changes, it cannot be revalidated as the successor's package. Admit
# only exact reviewed census identities here, and only for transactional
# retirement; verify_install() never consults this migration allowlist.
AUTHENTIC_V2_RETIREMENT_GENERATIONS = frozenset({
    "824826532d6f950b4bc32c930c0a57cd40ff3b07af6bb2c255650547070e7686",
})
JS_ARCHIVE_MAGIC = {
    "tar.gz": b"\x1f\x8b\x08",
    "tar.xz": b"\xfd7zXZ\x00",
    "zip": b"PK\x03\x04",
}
JS_DISTRIBUTABLE_PATHS = frozenset(
    {
        "runtime/toolchains/js/node/node-v24.20.0-win-x64.zip",
        "runtime/toolchains/js/node/node-v24.20.0-win-arm64.zip",
        "runtime/toolchains/js/node/node-v24.20.0-linux-x64.tar.xz",
        "runtime/toolchains/js/node/node-v24.20.0-linux-arm64.tar.xz",
        "runtime/toolchains/js/node/node-v24.20.0-darwin-x64.tar.gz",
        "runtime/toolchains/js/node/node-v24.20.0-darwin-arm64.tar.gz",
        "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz",
    }
)
JS_ACQUISITION_INITIAL_HOSTS = frozenset({"github.com", "nodejs.org"})
JS_ACQUISITION_REDIRECT_HOSTS = frozenset(
    {"objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)
LEGACY_PROVENANCE_FIELDS = frozenset(
    {
        "claim",
        "generation_sha256",
        "python",
        "schema",
        "security_properties",
        "source_census",
        "source_entry_count",
        "source_exclusions",
        "source_total_bytes",
    }
)
PROVENANCE_FIELDS = LEGACY_PROVENANCE_FIELDS | {
    "js_package_binding", "runtime_closure_binding",
}


class CompatInstallError(RuntimeError):
    """A bounded compatibility-install failure."""


def _fail(message: str) -> NoReturn:
    raise CompatInstallError(message) from None


def _rule_authority_module():
    module_path = Path(__file__).with_name("opengrep_rule_authority.py")
    spec = importlib.util.spec_from_file_location(
        "_plamen_posix_rule_authority", module_path
    )
    if (
        spec is None
        or type(spec.loader) is not importlib.machinery.SourceFileLoader
    ):
        _fail("OpenGrep rule authority module is unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except (OSError, RuntimeError, ValueError) as exc:
        _fail(f"OpenGrep rule authority module rejected: {exc}")
    return module


def _validate_source_rule_package(source_root: str) -> None:
    try:
        module = _rule_authority_module()
        module.validate_source_rule_authority(Path(source_root) / "opengrep-rules")
    except CompatInstallError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        _fail(f"OpenGrep source rule authority rejected: {exc}")


def _validate_staged_rule_package(staged_root: Path) -> None:
    try:
        module = _rule_authority_module()
        module.validate_installed_rule_authority(staged_root / "opengrep-rules")
    except CompatInstallError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        _fail(f"OpenGrep staged rule authority rejected: {exc}")


def _js_authority_module():
    """Load the installer-reviewed JS authority implementation.

    The running installer, rather than executable bytes from the candidate
    tree, supplies validation code.  The candidate module is nevertheless a
    required, closure-bound runtime input and is copied byte-for-byte into the
    admitted generation.
    """

    module_path = Path(__file__).with_name("js_toolchain_authority.py")
    spec = importlib.util.spec_from_file_location(
        "_plamen_posix_js_toolchain_authority", module_path
    )
    if (
        spec is None
        or type(spec.loader) is not importlib.machinery.SourceFileLoader
    ):
        _fail("JavaScript toolchain authority module is unavailable")
    module = importlib.util.module_from_spec(spec)
    module_name = spec.name
    prior = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        _fail(f"JavaScript toolchain authority module rejected: {exc}")
    finally:
        if prior is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior
    return module


def _toolchain_control_authority_module():
    """Load the running installer's complete-closure derivation authority."""

    module_path = Path(__file__).with_name("toolchain_control_authority.py")
    spec = importlib.util.spec_from_file_location(
        "_plamen_posix_toolchain_control_authority", module_path
    )
    if (
        spec is None
        or type(spec.loader) is not importlib.machinery.SourceFileLoader
    ):
        _fail("toolchain runtime closure authority module is unavailable")
    module = importlib.util.module_from_spec(spec)
    module_name = spec.name
    prior = sys.modules.get(module_name)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        _fail(f"toolchain runtime closure authority module rejected: {exc}")
    finally:
        if prior is None:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = prior
    return module


def _read_js_archive(path: Path, expected_size: int, expected_sha256: str) -> bytes:
    """Hash one bounded, no-follow archive and return its format prefix."""

    flags = os.O_RDONLY | os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("JavaScript archive no-follow support is unavailable")
    flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size != expected_size
            or before.st_size <= 0
            or before.st_size > MAX_FILE_BYTES
        ):
            _fail("JavaScript toolchain archive size or file authority differs")
        digest = hashlib.sha256()
        prefix = b""
        total = 0
        while True:
            chunk = os.read(
                descriptor, min(1024 * 1024, MAX_FILE_BYTES + 1 - total)
            )
            if not chunk:
                break
            if len(prefix) < 6:
                prefix += chunk[: 6 - len(prefix)]
            total += len(chunk)
            if total > MAX_FILE_BYTES:
                _fail("JavaScript toolchain archive exceeds its byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if _identity(before) != _identity(after) or total != expected_size:
            _fail("JavaScript toolchain archive identity drifted during admission")
        if digest.hexdigest() != expected_sha256:
            _fail("JavaScript toolchain archive digest differs")
        return prefix
    except CompatInstallError:
        raise
    except OSError:
        _fail("JavaScript toolchain archive admission failed")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _strict_manifest_bytes(raw: bytes, label: str) -> dict[str, object]:
    """Parse bounded installer policy without duplicate or non-integer values."""

    def pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                _fail(f"{label} contains duplicate keys")
            value[key] = item
        return value

    def reject_number(_value: str) -> None:
        _fail(f"{label} contains a non-integer number")

    try:
        value = json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=pairs_hook,
            parse_float=reject_number,
            parse_constant=reject_number,
        )
    except CompatInstallError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError):
        _fail(f"{label} is malformed")
    if type(value) is not dict:
        _fail(f"{label} is malformed")
    return value


def _authenticated_archive_acquisition_policy(
    staged_fd: int,
) -> tuple[tuple[object, ...], str]:
    """Load the exact external distribution roster from a compiled hash pin.

    The small policy is committed while the 231 MiB payload is not.  It is a
    separate installer trust root, so ongoing runtime-source edits cannot make
    clean-clone acquisition depend on a freshly generated closure or on files
    that do not exist yet.  Full JS bootstrap and closure replay still occurs
    after materialization and before publication.
    """

    raw = _read_relative_bounded(
        staged_fd, JS_ACQUISITION_POLICY_FILE, MAX_MANIFEST_BYTES, _current_uid()
    )
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_JS_ACQUISITION_POLICY_SHA256:
        _fail("JavaScript acquisition policy differs from installer authority")
    policy = _strict_manifest_bytes(raw, "JavaScript acquisition policy")
    if set(policy) != {"artifacts", "schema", "transport"} or policy.get(
        "schema"
    ) != "plamen.js-toolchain-acquisition.v1":
        _fail("JavaScript acquisition policy is malformed")
    expected_transport = {
        "allowed_redirect_hosts": [
            "objects.githubusercontent.com", "release-assets.githubusercontent.com"
        ],
        "credentials": "FORBIDDEN",
        "initial_hosts": ["github.com", "nodejs.org"],
        "maximum_redirects": JS_ACQUISITION_MAX_REDIRECTS,
        "minimum_tls": "1.2",
        "proxy_environment": "IGNORED",
        "scheme": "https",
    }
    if policy.get("transport") != expected_transport:
        _fail("JavaScript acquisition transport policy differs")
    rows = policy.get("artifacts")
    if type(rows) is not list or len(rows) != 7:
        _fail("JavaScript acquisition artifact roster differs")
    artifacts: list[object] = []
    paths: list[str] = []
    ids: set[str] = set()
    for row in rows:
        if type(row) is not dict or set(row) != {
            "archive_format", "artifact_id", "path", "sha256", "size", "url"
        }:
            _fail("JavaScript acquisition artifact row is malformed")
        artifact_id = row.get("artifact_id")
        relative = row.get("path")
        archive_format = row.get("archive_format")
        size = row.get("size")
        sha256 = row.get("sha256")
        url = row.get("url")
        if (
            type(artifact_id) is not str
            or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", artifact_id) is None
            or artifact_id in ids
            or type(relative) is not str
            or relative not in JS_DISTRIBUTABLE_PATHS
            or archive_format not in JS_ARCHIVE_MAGIC
            or type(size) is not int
            or isinstance(size, bool)
            or size <= 0
            or size > MAX_FILE_BYTES
            or type(sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", sha256) is None
            or type(url) is not str
        ):
            _fail("JavaScript acquisition artifact row is malformed")
        _validated_acquisition_url(url, redirected=False)
        suffix = {"zip": ".zip", "tar.gz": ".tar.gz", "tar.xz": ".tar.xz"}[
            archive_format
        ]
        if not relative.endswith(suffix) or not url.endswith("/" + relative.rsplit("/", 1)[1]):
            _fail("JavaScript acquisition artifact URL identity differs")
        ids.add(artifact_id)
        paths.append(relative)
        artifacts.append(
            types.SimpleNamespace(
                archive_format=archive_format,
                artifact_id=artifact_id,
                packaged_path=relative,
                sha256=sha256,
                size=size,
                source_url=url,
            )
        )
    if paths != sorted(paths) or set(paths) != set(JS_DISTRIBUTABLE_PATHS):
        _fail("JavaScript acquisition artifact roster differs")
    return tuple(artifacts), digest


def _validated_acquisition_url(value: str, *, redirected: bool) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        _fail("JavaScript archive acquisition URL is malformed")
    if (
        type(value) is not str
        or not value
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
        or parsed.scheme != "https"
        or parsed.hostname not in (
            JS_ACQUISITION_REDIRECT_HOSTS
            if redirected
            else JS_ACQUISITION_INITIAL_HOSTS
        )
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
        or not parsed.path.startswith("/")
        or (not redirected and (parsed.query or parsed.netloc != parsed.hostname))
    ):
        _fail("JavaScript archive acquisition URL is not admitted")
    return value


class _HTTPSOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    max_redirections = JS_ACQUISITION_MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        _validated_acquisition_url(resolved, redirected=True)
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _open_https_artifact(url: str):
    """Open one verified-target request without PATH, proxies, or TLS fallback."""

    _validated_acquisition_url(url, redirected=False)
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _HTTPSOnlyRedirectHandler(),
        urllib.request.HTTPSHandler(context=context),
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/octet-stream",
            "Accept-Encoding": "identity",
            "User-Agent": "Plamen-V3-compat-installer/1",
        },
        method="GET",
    )
    return opener.open(request, timeout=JS_ACQUISITION_TIMEOUT_SECONDS)


def _open_or_create_relative_parent(
    root_fd: int, relative: str, uid: int
) -> tuple[int, str]:
    parts = relative.split("/")
    if len(parts) < 2 or any(not part or part in {".", ".."} for part in parts):
        _fail("JavaScript archive acquisition path is malformed")
    current = os.dup(root_fd)
    os.set_inheritable(current, False)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
                os.fsync(current)
            except FileExistsError:
                pass
            child = _open_child_directory(
                current, part, "JavaScript archive acquisition directory", uid
            )
            info = os.fstat(child)
            if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
                os.close(child)
                _fail("JavaScript archive acquisition directory authority differs")
            os.close(current)
            current = child
        return current, parts[-1]
    except BaseException:
        os.close(current)
        raise


def _acquire_archive(
    staged_fd: int,
    artifact: object,
    uid: int,
    *,
    fetcher: Callable[[str], object] | None = None,
) -> None:
    """Stream one exact archive into an unpublished no-follow stage."""

    relative = str(getattr(artifact, "packaged_path"))
    artifact_id = str(getattr(artifact, "artifact_id"))
    expected_size = int(getattr(artifact, "size"))
    expected_sha256 = str(getattr(artifact, "sha256"))
    archive_format = str(getattr(artifact, "archive_format"))
    url = _validated_acquisition_url(
        str(getattr(artifact, "source_url")), redirected=False
    )
    parent_fd, leaf = _open_or_create_relative_parent(staged_fd, relative, uid)
    temporary = f".{leaf}.acquire-{os.urandom(16).hex()}"
    target_fd = -1
    response = None
    try:
        try:
            os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _fail("JavaScript archive acquisition target already exists")
        target_fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_fd,
        )
        try:
            response = (fetcher or _open_https_artifact)(url)
        except Exception:
            _fail(f"JavaScript archive acquisition unavailable: {artifact_id}")
        final_url = getattr(response, "geturl", lambda: url)()
        _validated_acquisition_url(final_url, redirected=(final_url != url))
        status = getattr(response, "status", 200)
        headers = getattr(response, "headers", {})
        content_encoding = headers.get("Content-Encoding") if headers else None
        content_length = headers.get("Content-Length") if headers else None
        if (
            status != 200
            or content_encoding not in {None, "", "identity"}
            or (
                content_length is not None
                and (not str(content_length).isdigit()
                     or int(content_length) != expected_size)
            )
        ):
            _fail(f"JavaScript archive acquisition response differs: {artifact_id}")
        digest = hashlib.sha256()
        prefix = b""
        total = 0
        while True:
            remaining = expected_size - total
            chunk = response.read(min(1024 * 1024, remaining) if remaining else 1)
            if not chunk:
                break
            if type(chunk) is not bytes:
                _fail(f"JavaScript archive acquisition stream differs: {artifact_id}")
            if len(prefix) < 6:
                prefix += chunk[: 6 - len(prefix)]
            total += len(chunk)
            if total > expected_size:
                _fail(f"JavaScript archive acquisition exceeds size: {artifact_id}")
            _write_all(target_fd, chunk)
            digest.update(chunk)
        if (
            total != expected_size
            or digest.hexdigest() != expected_sha256
            or not prefix.startswith(JS_ARCHIVE_MAGIC[archive_format])
        ):
            _fail(f"JavaScript archive acquisition identity differs: {artifact_id}")
        os.fchmod(target_fd, 0o600)
        os.fsync(target_fd)
        os.close(target_fd)
        target_fd = -1
        # link/unlink is the portable POSIX no-replace publication primitive.
        os.link(
            temporary, leaf,
            src_dir_fd=parent_fd, dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except CompatInstallError:
        raise
    except Exception:
        _fail(f"JavaScript archive acquisition failed: {artifact_id}")
    finally:
        if response is not None:
            try:
                response.close()
            except Exception:
                pass
        if target_fd >= 0:
            os.close(target_fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass
        os.close(parent_fd)


def _materialize_absent_js_distributable(
    staged_fd: int,
    source_rows: list[dict[str, object]],
    uid: int,
    *,
    fetcher: Callable[[str], object] | None = None,
) -> dict[str, object] | None:
    """Acquire all seven archives only for an archive-free clean checkout."""

    file_paths = {
        str(row.get("path"))
        for row in source_rows
        if row.get("kind") == "file"
    }
    present = file_paths & JS_DISTRIBUTABLE_PATHS
    archive_like = {
        path for path in file_paths
        if path.startswith("runtime/toolchains/js/")
        and path.endswith((".zip", ".tar.gz", ".tar.xz"))
    }
    if present == JS_DISTRIBUTABLE_PATHS:
        return None
    # Never assemble a release from a mixture of local and downloaded bytes,
    # nor let alternate archive names masquerade as a clean checkout.
    if present or archive_like:
        _fail("JavaScript distributable source package is partial or foreign")
    artifacts, policy_sha256 = _authenticated_archive_acquisition_policy(staged_fd)
    for artifact in artifacts:
        _acquire_archive(staged_fd, artifact, uid, fetcher=fetcher)
    return {
        "artifact_count": len(artifacts),
        "manifest_path": JS_ACQUISITION_POLICY_FILE,
        "manifest_sha256": policy_sha256,
        "mode": "VERIFIED_HTTPS_MATERIALIZATION_V1",
    }


def _validate_js_closure_membership(
    root: Path,
    required_paths: frozenset[str],
) -> None:
    """Require every bootstrap member in the observed closure evidence."""

    closure_path = root / JS_RUNTIME_CLOSURE_FILE
    try:
        raw = closure_path.read_bytes()
        if not raw or len(raw) > MAX_MANIFEST_BYTES:
            _fail("JavaScript runtime closure authority differs")
        value = json.loads(raw.decode("utf-8", "strict"))
    except CompatInstallError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError):
        _fail("JavaScript runtime closure authority differs")
    assets = value.get("assets") if type(value) is dict else None
    if type(assets) is not list:
        _fail("JavaScript runtime closure asset roster is unavailable")
    closure_rows: dict[str, dict[str, object]] = {}
    for row in assets:
        if type(row) is not dict:
            _fail("JavaScript runtime closure asset roster is malformed")
        relative = row.get("path")
        digest = row.get("sha256")
        if (
            type(relative) is not str
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or relative in closure_rows
        ):
            _fail("JavaScript runtime closure asset roster is malformed")
        closure_rows[relative] = row
    missing = sorted(required_paths - closure_rows.keys())
    if missing:
        _fail("JavaScript runtime closure is missing required input: " + missing[0])
    # ``load_authority_manifest`` already validates every closure member using
    # its declared raw-v1/utf8-lf-v1 digest mode.  This is supplementary
    # reachability evidence only: authority comes from the externally bound
    # bootstrap member set checked against the descriptor census below.


def _validate_js_package(
    root: Path,
    label: str,
    *,
    bootstrap_binding: dict[str, str],
    captured_rows: list[dict[str, object]],
) -> dict[str, object]:
    """Admit the exact all-platform Node/Yarn distributable package."""

    if bootstrap_binding != _js_install_binding(captured_rows):
        _fail(f"JavaScript {label} bootstrap binding differs from census")
    try:
        module = _js_authority_module()
        trusted = module.TrustedJSBootstrapAuthority(
            anchor_relative_path=bootstrap_binding["anchor_path"],
            anchor_sha256=bootstrap_binding["anchor_sha256"],
            source_census_sha256=bootstrap_binding["source_census_sha256"],
            install_provenance_sha256=bootstrap_binding[
                "js_package_binding_sha256"
            ],
            trust_boundary=bootstrap_binding["trust_boundary"],
        )
        authority = module.load_authority_manifest(
            root, bootstrap_authority=trusted
        )
    except CompatInstallError:
        raise
    except Exception as exc:
        _fail(f"JavaScript {label} authority rejected: {exc}")
    artifacts = getattr(authority, "artifacts", None)
    if type(artifacts) is not tuple or len(artifacts) != 7:
        _fail(f"JavaScript {label} artifact roster differs")
    artifact_paths: set[str] = set()
    artifact_ids: set[str] = set()
    for artifact in artifacts:
        artifact_id = getattr(artifact, "artifact_id", None)
        relative = getattr(artifact, "packaged_path", None)
        expected_size = getattr(artifact, "size", None)
        expected_sha256 = getattr(artifact, "sha256", None)
        archive_format = getattr(artifact, "archive_format", None)
        if (
            type(artifact_id) is not str
            or not artifact_id
            or artifact_id in artifact_ids
            or type(relative) is not str
            or not relative
            or relative in artifact_paths
            or type(expected_size) is not int
            or isinstance(expected_size, bool)
            or expected_size <= 0
            or expected_size > MAX_FILE_BYTES
            or type(expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
            or archive_format not in JS_ARCHIVE_MAGIC
        ):
            _fail(f"JavaScript {label} artifact identity differs")
        suffix = {"zip": ".zip", "tar.gz": ".tar.gz", "tar.xz": ".tar.xz"}[
            archive_format
        ]
        if not relative.endswith(suffix):
            _fail(f"JavaScript {label} archive type differs")
        artifact_ids.add(artifact_id)
        artifact_paths.add(relative)
        prefix = _read_js_archive(
            root.joinpath(*relative.split("/")), expected_size, expected_sha256
        )
        if not prefix.startswith(JS_ARCHIVE_MAGIC[archive_format]):
            _fail(f"JavaScript {label} archive type differs")
    required_paths = frozenset(
        set(JS_AUTHORITY_MODULE_FILES)
        | {JS_AUTHORITY_POLICY_FILE}
        | artifact_paths
    )
    members = getattr(authority, "bootstrap_members", None)
    if type(members) is not tuple or len(members) != len(required_paths):
        _fail(f"JavaScript {label} bootstrap member roster differs")
    captured_files = _captured_file_rows(captured_rows)
    member_paths: set[str] = set()
    member_receipt: list[dict[str, object]] = []
    for member in members:
        relative = getattr(member, "path", None)
        digest_mode = getattr(member, "digest_mode", None)
        member_sha256 = getattr(member, "sha256", None)
        member_size = getattr(member, "size", None)
        kind = getattr(member, "kind", None)
        captured = captured_files.get(relative) if type(relative) is str else None
        if (
            type(relative) is not str
            or relative in member_paths
            or relative not in required_paths
            or digest_mode not in {"raw-v1", "utf8-lf-v1"}
            or type(kind) is not str
            or not kind
            or type(member_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", member_sha256) is None
            or type(member_size) is not int
            or isinstance(member_size, bool)
            or member_size <= 0
            or captured is None
            or captured.get("size") != member_size
            # Canonical release text is LF-normalized, making its semantic
            # bootstrap digest equal to the raw descriptor-census digest.
            # Reject CRLF/alternate raw encodings instead of weakening this
            # exact-byte binding.
            or captured.get("sha256") != member_sha256
        ):
            _fail(f"JavaScript {label} bootstrap member differs from census")
        member_paths.add(relative)
        member_receipt.append(
            {
                "digest_mode": digest_mode,
                "kind": kind,
                "path": relative,
                "sha256": member_sha256,
                "size": member_size,
            }
        )
    if member_paths != set(required_paths):
        _fail(f"JavaScript {label} bootstrap member roster differs")
    _validate_js_closure_membership(root, required_paths)
    content_sha256 = getattr(authority, "content_sha256", None)
    closure_sha256 = getattr(authority, "runtime_closure_sha256", None)
    anchor_sha256 = getattr(authority, "bootstrap_anchor_sha256", None)
    signed_set_sha256 = getattr(authority, "bootstrap_signed_set_sha256", None)
    if (
        type(content_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", content_sha256) is None
        or type(closure_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", closure_sha256) is None
        or anchor_sha256 != bootstrap_binding["anchor_sha256"]
        or type(signed_set_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", signed_set_sha256) is None
    ):
        _fail(f"JavaScript {label} provenance differs")
    return {
        "schema": "plamen.posix_compat_v2.js_package.v2",
        "bootstrap_binding": bootstrap_binding,
        "bootstrap_signed_set_sha256": signed_set_sha256,
        "manifest_content_sha256": content_sha256,
        "runtime_closure_sha256": closure_sha256,
        "bootstrap_members": member_receipt,
        "artifacts": [
            {
                "archive_format": artifact.archive_format,
                "artifact_id": artifact.artifact_id,
                "packaged_path": artifact.packaged_path,
                "sha256": artifact.sha256,
                "size": artifact.size,
            }
            for artifact in artifacts
        ],
    }


def _validate_source_js_package(
    source_root: str,
    *,
    bootstrap_binding: dict[str, str],
    captured_rows: list[dict[str, object]],
) -> dict[str, object]:
    return _validate_js_package(
        Path(source_root),
        "source package",
        bootstrap_binding=bootstrap_binding,
        captured_rows=captured_rows,
    )


def _validate_staged_js_package(
    staged_root: Path,
    *,
    bootstrap_binding: dict[str, str],
    captured_rows: list[dict[str, object]],
) -> dict[str, object]:
    return _validate_js_package(
        staged_root,
        "staged package",
        bootstrap_binding=bootstrap_binding,
        captured_rows=captured_rows,
    )


def _canonical_absolute(value: os.PathLike[str] | str, label: str) -> str:
    try:
        path = os.fspath(value)
    except TypeError:
        _fail(f"{label} is malformed")
    if type(path) is not str or not path or "\x00" in path:
        _fail(f"{label} is malformed")
    try:
        raw = path.encode("utf-8", "strict")
    except UnicodeError:
        _fail(f"{label} is malformed")
    if (
        len(raw) > MAX_PATH_BYTES
        or path != unicodedata.normalize("NFC", path)
        or any(ord(character) < 32 for character in path)
        or not path.startswith("/")
        or path.startswith("//")
        or os.path.normpath(path) != path
    ):
        _fail(f"{label} must be canonical absolute")
    components = path.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        _fail(f"{label} must be canonical absolute")
    return path


def _current_uid() -> int:
    if os.name != "posix" or sys.platform not in {"darwin", "linux"}:
        _fail("POSIX V2 compatibility install requires macOS or Linux")
    uid = os.getuid()
    if type(uid) is not int or isinstance(uid, bool) or uid < 0:
        _fail("account identity is malformed")
    return uid


def _directory_safe(info: os.stat_result, uid: int) -> bool:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}:
        return False
    others_write = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    root_sticky = info.st_uid == 0 and bool(info.st_mode & stat.S_ISVTX)
    return not others_write or root_sticky


def _open_absolute_directory(path: str, label: str, uid: int) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if not hasattr(os, "O_NOFOLLOW"):
        _fail("no-follow descriptor support is unavailable")
    flags |= os.O_NOFOLLOW
    current = -1
    try:
        current = os.open("/", flags)
        if not _directory_safe(os.fstat(current), uid):
            _fail(f"{label} traversal root is unsafe")
        for component in path.split("/")[1:]:
            opened = os.open(component, flags, dir_fd=current)
            info = os.fstat(opened)
            if not _directory_safe(info, uid):
                os.close(opened)
                _fail(f"{label} traversal is unsafe")
            os.close(current)
            current = opened
        os.set_inheritable(current, False)
        return current
    except CompatInstallError:
        if current >= 0:
            os.close(current)
        raise
    except (OSError, OverflowError, ValueError):
        if current >= 0:
            os.close(current)
        _fail(f"{label} descriptor admission failed")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_uid),
        int(info.st_gid),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
        int(info.st_ctime_ns),
    )


def _valid_component(name: object) -> str:
    if type(name) is not str or name in {"", ".", ".."} or "/" in name or "\x00" in name:
        _fail("source contains a malformed path component")
    try:
        raw = name.encode("utf-8", "strict")
    except UnicodeError:
        _fail("source contains a malformed path component")
    if (
        len(raw) > 255
        or name != unicodedata.normalize("NFC", name)
        or any(ord(character) < 32 for character in name)
    ):
        _fail("source contains a malformed path component")
    return name


def _excluded(name: str) -> bool:
    return name in EXCLUDED_NAMES or name.endswith(EXCLUDED_SUFFIXES)


def _ensure_directory(parent_fd: int, name: str, uid: int) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileExistsError:
        pass
    except OSError:
        _fail("compatibility install directory creation failed")
    try:
        opened = os.open(name, flags, dir_fd=parent_fd)
        info = os.fstat(opened)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid:
            os.close(opened)
            _fail("compatibility install directory authority differs")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            os.close(opened)
            _fail("compatibility install directory is broadly writable")
        os.set_inheritable(opened, False)
        return opened
    except CompatInstallError:
        raise
    except OSError:
        _fail("compatibility install directory admission failed")


def _write_all(fd: int, raw: bytes) -> None:
    view = memoryview(raw)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            _fail("compatibility install write made no progress")
        view = view[count:]


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _atomic_write(parent_fd: int, leaf: str, raw: bytes, mode: int = 0o600) -> None:
    if len(raw) > MAX_MANIFEST_BYTES:
        _fail("compatibility metadata exceeds its bound")
    temporary = f".{leaf}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    fd = -1
    try:
        fd = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
            dir_fd=parent_fd,
        )
        _write_all(fd, raw)
        os.fchmod(fd, mode)
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    except CompatInstallError:
        raise
    except OSError:
        _fail("atomic compatibility metadata publication failed")
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except OSError:
            pass


def _read_bounded(parent_fd: int, leaf: str, maximum: int) -> bytes:
    fd = -1
    try:
        fd = os.open(leaf, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 0 or info.st_size > maximum:
            _fail("compatibility metadata authority differs")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            _fail("compatibility metadata exceeds its bound")
        return raw
    except CompatInstallError:
        raise
    except OSError:
        _fail("compatibility metadata read failed")
    finally:
        if fd >= 0:
            os.close(fd)


def _read_relative_bounded(
    root_fd: int, relative: str, maximum: int, uid: int
) -> bytes:
    parts = relative.split("/")
    if (
        not parts
        or any(not part or part in {".", ".."} for part in parts)
        or "\\" in relative
    ):
        _fail("compatibility metadata path is malformed")
    opened: list[int] = []
    parent_fd = root_fd
    try:
        for part in parts[:-1]:
            child = _open_child_directory(
                parent_fd, part, "compatibility metadata directory", uid
            )
            opened.append(child)
            parent_fd = child
        return _read_bounded(parent_fd, parts[-1], maximum)
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def _hash_fd(fd: int, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            _fail("source file exceeds its bound")
        digest.update(chunk)
    return digest.hexdigest(), total


def _tree_digest(rows: list[dict[str, object]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: str(item["path"])):
        digest.update(
            (
                f"{row['kind']}\0{row['path']}\0{row['mode']}\0"
                f"{row['size']}\0{row['sha256']}\n"
            ).encode("utf-8")
        )
    return digest.hexdigest()


def _js_install_binding(
    captured_rows: list[dict[str, object]],
) -> dict[str, str]:
    """Bind the external JS bootstrap root to one descriptor census."""

    generation_sha256 = _tree_digest(captured_rows)
    anchors = [
        row
        for row in captured_rows
        if row.get("kind") == "file"
        and row.get("path") == JS_BOOTSTRAP_ANCHOR_FILE
    ]
    if len(anchors) != 1:
        _fail("JavaScript bootstrap anchor is missing from the captured census")
    anchor = anchors[0]
    anchor_sha256 = anchor.get("sha256")
    if (
        type(anchor_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", anchor_sha256) is None
        or type(anchor.get("size")) is not int
        or int(anchor["size"]) <= 0
        or int(anchor["size"]) > MAX_MANIFEST_BYTES
    ):
        _fail("JavaScript bootstrap anchor census identity differs")
    if anchor_sha256 != EXPECTED_JS_BOOTSTRAP_ANCHOR_SHA256:
        _fail("JavaScript bootstrap anchor differs from trusted installer")
    signed = {
        "anchor_path": JS_BOOTSTRAP_ANCHOR_FILE,
        # This is the installer-embedded trust root.  The captured row above
        # proves the candidate supplied exactly these bytes; it cannot choose
        # a replacement anchor and then use that replacement to authorize its
        # own signed member set.
        "anchor_sha256": EXPECTED_JS_BOOTSTRAP_ANCHOR_SHA256,
        "schema": JS_INSTALL_BINDING_SCHEMA,
        "source_census_sha256": generation_sha256,
        "trust_boundary": JS_INSTALL_TRUST_BOUNDARY,
    }
    return {
        **signed,
        "js_package_binding_sha256": hashlib.sha256(
            _canonical_json(signed)
        ).hexdigest(),
    }


def _captured_file_rows(
    captured_rows: list[dict[str, object]],
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for row in captured_rows:
        if row.get("kind") != "file":
            continue
        relative = row.get("path")
        if type(relative) is not str or relative in result:
            _fail("captured JavaScript census is malformed")
        result[relative] = row
    return result


def _legacy_census_has_js(captured_rows: list[dict[str, object]]) -> bool:
    """Identify every census shape that requires successor JS provenance."""

    exact = set(JS_AUTHORITY_MODULE_FILES) | {
        JS_AUTHORITY_POLICY_FILE,
        JS_BOOTSTRAP_ANCHOR_FILE,
        JS_RUNTIME_CLOSURE_FILE,
    }
    for row in captured_rows:
        relative = row.get("path") if type(row) is dict else None
        if type(relative) is not str:
            _fail("legacy compatibility census is malformed")
        if relative in exact or relative.startswith("runtime/toolchains/js/"):
            return True
    return False


def _read_runtime_closure_manifest(root: Path) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            root / JS_RUNTIME_CLOSURE_FILE,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > MAX_MANIFEST_BYTES
        ):
            _fail("toolchain runtime closure manifest authority differs")
        chunks: list[bytes] = []
        remaining = MAX_MANIFEST_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(descriptor)
        if (
            len(raw) > MAX_MANIFEST_BYTES
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or len(raw) != before.st_size
        ):
            _fail("toolchain runtime closure manifest changed during admission")
        return raw
    except CompatInstallError:
        raise
    except OSError:
        _fail("toolchain runtime closure manifest is unreadable")
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _runtime_closure_binding(
    captured_rows: list[dict[str, object]],
    payload: dict[str, object],
    manifest_raw: bytes,
) -> dict[str, object]:
    """Bind the independently derived complete closure to one census."""

    if type(payload) is not dict or set(payload) != {
        "assets", "derivation", "entrypoints", "files", "manifest_control",
        "schema",
    }:
        _fail("toolchain runtime closure receipt is malformed")
    try:
        observed_payload = json.loads(manifest_raw.decode("ascii", "strict"))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _fail("toolchain runtime closure manifest is malformed")
    if observed_payload != payload:
        _fail("toolchain runtime closure changed during semantic admission")
    files = payload.get("files")
    assets = payload.get("assets")
    if (
        type(files) is not list
        or not files
        or files != sorted(set(files))
        or type(assets) is not list
        or len(assets) != len(files) - 1
    ):
        _fail("toolchain runtime closure receipt is malformed")
    captured = _captured_file_rows(captured_rows)
    manifest_row = captured.get(JS_RUNTIME_CLOSURE_FILE)
    manifest_sha256 = hashlib.sha256(manifest_raw).hexdigest()
    if (
        manifest_row is None
        or manifest_row.get("sha256") != manifest_sha256
        or manifest_row.get("size") != len(manifest_raw)
    ):
        _fail("toolchain runtime closure manifest differs from census")
    asset_paths: set[str] = set()
    for asset in assets:
        if type(asset) is not dict or set(asset) != {
            "digest_mode", "kind", "path", "sha256",
        }:
            _fail("toolchain runtime closure asset receipt is malformed")
        relative = asset.get("path")
        digest = asset.get("sha256")
        row = captured.get(relative) if type(relative) is str else None
        if (
            type(relative) is not str
            or relative in asset_paths
            or asset.get("digest_mode") not in {"raw-v1", "utf8-lf-v1"}
            or asset.get("kind")
            not in {"python-source", "runtime-data", "control"}
            or type(digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or row is None
            # Release text is canonical LF.  Requiring equality to the raw
            # descriptor digest prevents a semantically normalized payload
            # from blessing different captured bytes.
            or row.get("sha256") != digest
        ):
            _fail("toolchain runtime closure asset differs from census")
        asset_paths.add(relative)
    if set(files) != asset_paths | {JS_RUNTIME_CLOSURE_FILE}:
        _fail("toolchain runtime closure member roster differs")
    signed: dict[str, object] = {
        "assets_sha256": hashlib.sha256(_canonical_json(assets)).hexdigest(),
        "file_count": len(files),
        "files_sha256": hashlib.sha256(_canonical_json(files)).hexdigest(),
        "manifest_path": JS_RUNTIME_CLOSURE_FILE,
        "manifest_sha256": manifest_sha256,
        "schema": RUNTIME_CLOSURE_BINDING_SCHEMA,
        "source_census_sha256": _tree_digest(captured_rows),
    }
    return {
        **signed,
        "runtime_closure_binding_sha256": hashlib.sha256(
            _canonical_json(signed)
        ).hexdigest(),
    }


def _validate_complete_runtime_closure(
    root: Path,
    label: str,
    *,
    captured_rows: list[dict[str, object]],
) -> dict[str, object]:
    try:
        authority = _toolchain_control_authority_module()
        payload = authority.load_runtime_closure_manifest(root)
        raw = _read_runtime_closure_manifest(root)
        return _runtime_closure_binding(captured_rows, payload, raw)
    except CompatInstallError:
        raise
    except Exception as exc:
        _fail(f"toolchain {label} complete runtime closure rejected: {exc}")


def _copy_snapshot(
    source_fd: int,
    target_fd: int,
    *,
    uid: int,
    prefix: str = "",
    rows: list[dict[str, object]] | None = None,
    budget: list[int] | None = None,
) -> tuple[list[dict[str, object]], int]:
    if rows is None:
        rows = []
    if budget is None:
        budget = [0]
    before = _identity(os.fstat(source_fd))
    try:
        names = sorted(_valid_component(name) for name in os.listdir(source_fd))
    except OSError:
        _fail("source directory census failed")
    casefolded: set[str] = set()
    for name in names:
        if _excluded(name):
            continue
        folded = name.casefold()
        if folded in casefolded:
            _fail("source contains a case-colliding path")
        casefolded.add(folded)
        relative = f"{prefix}/{name}" if prefix else name
        if len(relative.encode("utf-8")) > MAX_PATH_BYTES:
            _fail("source relative path exceeds its bound")
        if relative == PROVENANCE_LEAF:
            _fail("source contains the reserved compatibility provenance path")
        try:
            initial = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError:
            _fail("source entry census failed")
        mode = stat.S_IMODE(initial.st_mode)
        if stat.S_ISDIR(initial.st_mode):
            try:
                child_source = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=source_fd,
                )
                os.mkdir(name, 0o700, dir_fd=target_fd)
                child_target = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=target_fd,
                )
            except OSError:
                _fail("source directory materialization failed")
            try:
                if os.fstat(child_source).st_dev != os.fstat(source_fd).st_dev:
                    _fail("source census crossed a filesystem boundary")
                rows.append(
                    {"kind": "directory", "path": relative, "mode": mode, "size": 0, "sha256": ""}
                )
                if len(rows) > MAX_FILES:
                    _fail("source census exceeds its entry bound")
                _copy_snapshot(
                    child_source,
                    child_target,
                    uid=uid,
                    prefix=relative,
                    rows=rows,
                    budget=budget,
                )
                os.fsync(child_target)
            finally:
                os.close(child_target)
                os.close(child_source)
        elif stat.S_ISREG(initial.st_mode):
            if initial.st_nlink != 1 or initial.st_size < 0 or initial.st_size > MAX_FILE_BYTES:
                _fail("source file authority differs")
            source_file = -1
            target_file = -1
            try:
                source_file = os.open(
                    name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=source_fd
                )
                if _identity(os.fstat(source_file)) != _identity(initial):
                    _fail("source file identity drifted before capture")
                installed_mode = 0o700 if mode & 0o111 else 0o600
                target_file = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                    installed_mode,
                    dir_fd=target_fd,
                )
                digest = hashlib.sha256()
                size = 0
                while True:
                    chunk = os.read(source_file, 1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > MAX_FILE_BYTES:
                        _fail("source file exceeds its bound")
                    _write_all(target_file, chunk)
                    digest.update(chunk)
                if size != initial.st_size or _identity(os.fstat(source_file)) != _identity(initial):
                    _fail("source file identity drifted during capture")
                os.fchmod(target_file, installed_mode)
                os.fsync(target_file)
            finally:
                if target_file >= 0:
                    os.close(target_file)
                if source_file >= 0:
                    os.close(source_file)
            budget[0] += size
            if budget[0] > MAX_TOTAL_BYTES:
                _fail("source snapshot exceeds its byte bound")
            rows.append(
                {
                    "kind": "file",
                    "path": relative,
                    "mode": mode,
                    "size": size,
                    "sha256": digest.hexdigest(),
                }
            )
            if len(rows) > MAX_FILES:
                _fail("source census exceeds its entry bound")
        else:
            _fail("source contains a link or special entry")
    if _identity(os.fstat(source_fd)) != before:
        _fail("source directory identity drifted during capture")
    return rows, budget[0]


def _census_tree(
    directory_fd: int, *, prefix: str = "", include_provenance: bool = False
) -> tuple[list[dict[str, object]], int]:
    rows: list[dict[str, object]] = []
    total = 0

    def walk(parent_fd: int, current_prefix: str) -> None:
        nonlocal total
        before = _identity(os.fstat(parent_fd))
        try:
            names = sorted(_valid_component(name) for name in os.listdir(parent_fd))
        except OSError:
            _fail("installed runtime census failed")
        folded: set[str] = set()
        for name in names:
            if not include_provenance and name == PROVENANCE_LEAF:
                continue
            if _excluded(name):
                continue
            key = name.casefold()
            if key in folded:
                _fail("installed runtime contains a case collision")
            folded.add(key)
            relative = f"{current_prefix}/{name}" if current_prefix else name
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=parent_fd,
                )
                try:
                    rows.append(
                        {"kind": "directory", "path": relative, "mode": mode, "size": 0, "sha256": ""}
                    )
                    walk(child, relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent_fd)
                try:
                    digest, size = _hash_fd(fd, MAX_FILE_BYTES)
                    if _identity(os.fstat(fd)) != _identity(info):
                        _fail("installed runtime file drifted during census")
                finally:
                    os.close(fd)
                total += size
                if total > MAX_TOTAL_BYTES:
                    _fail("installed runtime exceeds its byte bound")
                rows.append(
                    {"kind": "file", "path": relative, "mode": mode, "size": size, "sha256": digest}
                )
            else:
                _fail("installed runtime contains a link or special entry")
            if len(rows) > MAX_FILES:
                _fail("installed runtime census exceeds its entry bound")
        if _identity(os.fstat(parent_fd)) != before:
            _fail("installed runtime directory drifted during census")

    walk(directory_fd, prefix)
    return rows, total


def _source_rows_as_installed(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    projected = []
    for row in rows:
        item = dict(row)
        item["mode"] = 0o700 if row["kind"] == "directory" or int(row["mode"]) & 0o111 else 0o600
        projected.append(item)
    return projected


def _codex_skill_rows(
    source_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Project the exact source skill subtree into Codex-relative rows."""
    projected: list[dict[str, object]] = []
    for row in source_rows:
        path = row.get("path")
        if type(path) is not str or not path.startswith(CODEX_SKILL_SOURCE_PREFIX):
            continue
        relative = path[len(CODEX_SKILL_SOURCE_PREFIX) :]
        if not relative:
            continue
        parts = relative.split("/")
        if (
            any(_valid_component(part) != part for part in parts)
            or parts[0] not in MANAGED_CODEX_SKILL_NAMES
        ):
            _fail("Codex skill source path is outside the declared bundles")
        item = dict(row)
        item["path"] = relative
        projected.append(item)
    projected.sort(key=lambda item: str(item["path"]))
    paths = {str(row["path"]) for row in projected}
    roots = {
        str(row["path"])
        for row in projected
        if row.get("kind") == "directory" and "/" not in str(row["path"])
    }
    files = {
        str(row["path"])
        for row in projected
        if row.get("kind") == "file"
    }
    if roots != set(MANAGED_CODEX_SKILL_NAMES):
        _fail("Codex skill source bundle roster differs")
    if not REQUIRED_CODEX_SKILL_FILES.issubset(files):
        missing = sorted(REQUIRED_CODEX_SKILL_FILES - files)
        _fail("required Codex skill companion is missing: " + missing[0])
    if len(paths) != len(projected):
        _fail("Codex skill source contains a duplicate path")
    return projected


def _open_child_directory(parent_fd: int, name: str, label: str, uid: int) -> int:
    try:
        opened = os.open(
            name,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        info = os.fstat(opened)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            os.close(opened)
            _fail(f"{label} authority differs")
        os.set_inheritable(opened, False)
        return opened
    except CompatInstallError:
        raise
    except OSError:
        _fail(f"{label} descriptor admission failed")


def _census_managed_codex_skills(
    skills_fd: int, uid: int, *, require_all: bool
) -> tuple[list[dict[str, object]], int]:
    rows: list[dict[str, object]] = []
    total = 0
    for name in MANAGED_CODEX_SKILL_NAMES:
        if not _exists(skills_fd, name):
            if require_all:
                _fail("installed Codex skill bundle is missing: " + name)
            continue
        child = _open_child_directory(skills_fd, name, "Codex skill bundle", uid)
        try:
            info = os.fstat(child)
            rows.append(
                {
                    "kind": "directory",
                    "path": name,
                    "mode": stat.S_IMODE(info.st_mode),
                    "size": 0,
                    "sha256": "",
                }
            )
            child_rows, child_total = _census_tree(child, prefix=name)
            rows.extend(child_rows)
            total += child_total
        finally:
            os.close(child)
    rows.sort(key=lambda item: str(item["path"]))
    return rows, total


def _verify_codex_skill_projection(
    home_fd: int, source_rows: list[dict[str, object]], uid: int
) -> None:
    expected = _codex_skill_rows(source_rows)
    codex_fd = skills_fd = -1
    try:
        codex_fd = _open_child_directory(home_fd, ".codex", "Codex home", uid)
        skills_fd = _open_child_directory(codex_fd, "skills", "Codex skills", uid)
        observed, total = _census_managed_codex_skills(
            skills_fd, uid, require_all=True
        )
    finally:
        if skills_fd >= 0:
            os.close(skills_fd)
        if codex_fd >= 0:
            os.close(codex_fd)
    expected_total = sum(
        int(row["size"]) for row in expected if row["kind"] == "file"
    )
    if observed != expected or total != expected_total:
        _fail("installed Codex skill projection differs from source authority")


def _lookup_file(rows: list[dict[str, object]], path: str) -> dict[str, object]:
    for row in rows:
        if row["kind"] == "file" and row["path"] == path:
            return row
    _fail(f"required source input is missing: {path}")


def _validate_python(
    python_path: str, source_rows: list[dict[str, object]], uid: int
) -> dict[str, object]:
    presented = _canonical_absolute(python_path, "managed CPython path")
    try:
        resolved = _canonical_absolute(os.path.realpath(presented), "resolved CPython path")
        fd = os.open(resolved, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except CompatInstallError:
        raise
    except OSError:
        _fail("managed CPython descriptor admission failed")
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid not in {0, uid}
            or not info.st_mode & stat.S_IXUSR
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            _fail("managed CPython executable authority differs")
        digest, size = _hash_fd(fd, MAX_FILE_BYTES)
        expected_identity = _identity(info)
    finally:
        os.close(fd)
    runtime_root = os.path.dirname(os.path.dirname(presented))
    runtime_fd = _open_absolute_directory(
        _canonical_absolute(runtime_root, "managed CPython runtime root"),
        "managed CPython runtime",
        uid,
    )
    try:
        raw_stamp = _read_bounded(runtime_fd, ".plamen-runtime.json", 4096)
    finally:
        os.close(runtime_fd)
    try:
        stamp = json.loads(raw_stamp.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        _fail("managed CPython runtime stamp is malformed")
    lock_row = _lookup_file(source_rows, "requirements-runtime-core.lock")
    expected_stamp = {
        "lock_sha256": lock_row["sha256"],
        "python_abi": "cp312",
        "schema": "plamen.python_runtime.v1",
    }
    if stamp != expected_stamp:
        _fail("managed CPython runtime stamp differs from the source lock")
    probe = (
        "import json,sys;"
        "print(json.dumps({'implementation':sys.implementation.name,"
        "'version':list(sys.version_info[:3]),'executable':sys.executable},"
        "sort_keys=True,separators=(',',':')))"
    )
    try:
        completed = subprocess.run(
            [presented, "-I", "-c", probe],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("managed CPython validation could not execute")
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_INTERPRETER_OUTPUT
        or len(completed.stderr) > MAX_INTERPRETER_OUTPUT
    ):
        _fail("managed CPython validation failed")
    try:
        observed = json.loads(completed.stdout.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        _fail("managed CPython validation output is malformed")
    version = observed.get("version")
    if (
        observed.get("implementation") != "cpython"
        or not isinstance(version, list)
        or len(version) != 3
        or version[:2] != [3, 12]
        or any(type(value) is not int for value in version)
    ):
        _fail("managed interpreter is not CPython 3.12")
    try:
        after = os.stat(presented)
    except OSError:
        _fail("managed CPython identity revalidation failed")
    if _identity(after) != expected_identity:
        _fail("managed CPython identity drifted")
    return {
        "implementation": "cpython",
        "version": ".".join(str(value) for value in version),
        "python_abi": "cp312",
        "path": presented,
        "resolved_path": resolved,
        "sha256": digest,
        "size": size,
        "lock_sha256": lock_row["sha256"],
    }


def _exists(parent_fd: int, leaf: str) -> bool:
    try:
        os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        _fail("compatibility transaction state could not be inspected")


def _delete_tree(parent_fd: int, leaf: str, expected_device: int | None = None) -> None:
    try:
        info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        _fail("compatibility transaction cleanup could not inspect an entry")
    if stat.S_ISDIR(info.st_mode):
        if expected_device is not None and info.st_dev != expected_device:
            _fail("compatibility transaction cleanup crossed a filesystem boundary")
        fd = os.open(
            leaf,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        try:
            for name in os.listdir(fd):
                _delete_tree(fd, _valid_component(name), info.st_dev)
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            os.rmdir(leaf, dir_fd=parent_fd)
        except OSError:
            _fail("compatibility transaction directory cleanup failed")
    else:
        try:
            os.unlink(leaf, dir_fd=parent_fd)
        except OSError:
            _fail("compatibility transaction entry cleanup failed")


def _prepare_codex_skill_projection(
    home_fd: int,
    runtime_stage: str,
    skills_fd: int,
    token: str,
    expected_rows: list[dict[str, object]],
    prior_rows: list[dict[str, object]],
    uid: int,
) -> tuple[str, str, list[dict[str, object]]]:
    """Stage declared skill bundles and reject unowned stale live content."""
    current = {str(row["path"]): row for row in expected_rows}
    prior = {str(row["path"]): row for row in prior_rows}
    observed, _observed_total = _census_managed_codex_skills(
        skills_fd, uid, require_all=False
    )
    for row in observed:
        path = str(row["path"])
        if path in current:
            continue
        predecessor = prior.get(path)
        if predecessor is None:
            _fail("managed Codex skill bundle contains an unowned stale path: " + path)
        if any(
            row.get(field) != predecessor.get(field)
            for field in ("kind", "size", "sha256")
        ):
            _fail("managed Codex skill stale path differs from prior authority: " + path)

    skill_stage = f".plamen-compat-v2-skills-stage-{token}"
    skill_rollback = f".plamen-compat-v2-skills-rollback-{token}"
    runtime_fd = adapter_fd = source_skills_fd = staged_fd = -1
    try:
        os.mkdir(skill_stage, 0o700, dir_fd=skills_fd)
        os.mkdir(skill_rollback, 0o700, dir_fd=skills_fd)
        staged_fd = _open_child_directory(
            skills_fd, skill_stage, "Codex skill staging root", uid
        )
        runtime_fd = _open_child_directory(
            home_fd, runtime_stage, "compatibility runtime staging root", uid
        )
        adapter_fd = _open_child_directory(
            runtime_fd, "codex-adapter", "Codex adapter source", uid
        )
        source_skills_fd = _open_child_directory(
            adapter_fd, "skills", "Codex skill source", uid
        )
        staged_rows, staged_total = _copy_snapshot(
            source_skills_fd, staged_fd, uid=uid
        )
        staged_rows.sort(key=lambda item: str(item["path"]))
        expected_total = sum(
            int(row["size"]) for row in expected_rows if row["kind"] == "file"
        )
        if staged_rows != expected_rows or staged_total != expected_total:
            _fail("staged Codex skill projection differs from source authority")
        os.fsync(staged_fd)
        os.fsync(skills_fd)
        return skill_stage, skill_rollback, observed
    except BaseException:
        for leaf in (skill_rollback, skill_stage):
            try:
                _delete_tree(skills_fd, leaf)
            except BaseException:
                pass
        raise
    finally:
        for fd in (source_skills_fd, adapter_fd, runtime_fd, staged_fd):
            if fd >= 0:
                os.close(fd)


def _publish_codex_skill_projection(
    skills_fd: int,
    skill_stage: str,
    skill_rollback: str,
    expected_live_rows: list[dict[str, object]],
    uid: int,
) -> None:
    rollback_fd = stage_fd = -1
    try:
        rollback_fd = _open_child_directory(
            skills_fd, skill_rollback, "Codex skill rollback root", uid
        )
        stage_fd = _open_child_directory(
            skills_fd, skill_stage, "Codex skill staging root", uid
        )
        observed_live_rows, _observed_live_total = _census_managed_codex_skills(
            skills_fd, uid, require_all=False
        )
        if observed_live_rows != expected_live_rows:
            _fail("Codex skill projection changed after preflight")
        for name in MANAGED_CODEX_SKILL_NAMES:
            if _exists(skills_fd, name):
                os.rename(
                    name, name, src_dir_fd=skills_fd, dst_dir_fd=rollback_fd
                )
        os.fsync(rollback_fd)
        os.fsync(skills_fd)
        for name in MANAGED_CODEX_SKILL_NAMES:
            if _exists(skills_fd, name) or not _exists(stage_fd, name):
                _fail("Codex skill projection staging authority differs")
            os.rename(
                name, name, src_dir_fd=stage_fd, dst_dir_fd=skills_fd
            )
        os.fsync(stage_fd)
        os.fsync(rollback_fd)
        os.fsync(skills_fd)
    except OSError:
        _fail("Codex skill projection publication failed")
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if rollback_fd >= 0:
            os.close(rollback_fd)


def _recover_codex_skill_projection(
    skills_fd: int,
    skill_stage: str,
    skill_rollback: str,
    *,
    committed: bool,
    publication_started: bool = True,
    uid: int,
) -> None:
    if not _SKILL_TXN_LEAF.fullmatch(skill_stage) or not _SKILL_TXN_LEAF.fullmatch(
        skill_rollback
    ):
        _fail("Codex skill transaction paths are malformed")
    if committed or not publication_started:
        _delete_tree(skills_fd, skill_rollback)
        _delete_tree(skills_fd, skill_stage)
        return
    stage_fd = rollback_fd = -1
    try:
        stage_fd = _open_child_directory(
            skills_fd, skill_stage, "Codex skill staging root", uid
        )
        rollback_fd = _open_child_directory(
            skills_fd, skill_rollback, "Codex skill rollback root", uid
        )
        for name in MANAGED_CODEX_SKILL_NAMES:
            live = _exists(skills_fd, name)
            staged = _exists(stage_fd, name)
            prior = _exists(rollback_fd, name)
            if prior:
                if live:
                    if staged:
                        _fail("Codex skill recovery found two staged successors")
                    os.rename(
                        name, name, src_dir_fd=skills_fd, dst_dir_fd=stage_fd
                    )
                os.rename(
                    name, name, src_dir_fd=rollback_fd, dst_dir_fd=skills_fd
                )
            elif live and not staged:
                os.rename(name, name, src_dir_fd=skills_fd, dst_dir_fd=stage_fd)
            elif live and staged:
                _fail("Codex skill recovery found an unauthenticated live bundle")
        os.fsync(skills_fd)
    except CompatInstallError:
        raise
    except OSError:
        _fail("Codex skill projection recovery failed")
    finally:
        if rollback_fd >= 0:
            os.close(rollback_fd)
        if stage_fd >= 0:
            os.close(stage_fd)
    _delete_tree(skills_fd, skill_rollback)
    _delete_tree(skills_fd, skill_stage)


def _journal(compat_fd: int, value: dict[str, object] | None) -> None:
    if value is None:
        try:
            os.unlink(JOURNAL_LEAF, dir_fd=compat_fd)
            os.fsync(compat_fd)
        except FileNotFoundError:
            pass
        except OSError:
            _fail("compatibility transaction journal retirement failed")
    else:
        _atomic_write(compat_fd, JOURNAL_LEAF, _canonical_json(value))


def _recover(home_fd: int, compat_fd: int, skills_fd: int | None = None) -> None:
    if not _exists(compat_fd, JOURNAL_LEAF):
        return
    raw = _read_bounded(compat_fd, JOURNAL_LEAF, 16 * 1024)
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        _fail("compatibility transaction journal is malformed")
    legacy_required = {"schema", "state", "stage", "rollback", "had_prior"}
    current_required = legacy_required | {"skill_stage", "skill_rollback"}
    if not isinstance(value, dict):
        _fail("compatibility transaction journal authority differs")
    if value.get("schema") == LEGACY_JOURNAL_SCHEMA and set(value) == legacy_required:
        skill_stage = skill_rollback = None
    elif value.get("schema") == JOURNAL_SCHEMA and set(value) == current_required:
        skill_stage = value["skill_stage"]
        skill_rollback = value["skill_rollback"]
        if (
            type(skill_stage) is not str
            or not _SKILL_TXN_LEAF.fullmatch(skill_stage)
            or type(skill_rollback) is not str
            or not _SKILL_TXN_LEAF.fullmatch(skill_rollback)
            or skills_fd is None
        ):
            _fail("compatibility Codex skill journal authority differs")
    else:
        _fail("compatibility transaction journal authority differs")
    stage = value["stage"]
    rollback = value["rollback"]
    had_prior = value["had_prior"]
    state = value["state"]
    if (
        type(stage) is not str
        or not _TXN_LEAF.fullmatch(stage)
        or type(rollback) is not str
        or not _TXN_LEAF.fullmatch(rollback)
        or type(had_prior) is not bool
        or state not in {
            "PREPARED",
            "RETIRED",
            "PUBLISHED",
            "SKILLS_PUBLISHED",
            "COMMITTED",
        }
    ):
        _fail("compatibility transaction journal values are malformed")
    if state == "COMMITTED":
        _delete_tree(home_fd, rollback)
        _delete_tree(home_fd, stage)
        if skill_stage is not None and skill_rollback is not None:
            _recover_codex_skill_projection(
                skills_fd,
                skill_stage,
                skill_rollback,
                committed=True,
                publication_started=True,
                uid=_current_uid(),
            )
        _journal(compat_fd, None)
        return
    if skill_stage is not None and skill_rollback is not None:
        _recover_codex_skill_projection(
            skills_fd,
            skill_stage,
            skill_rollback,
            committed=False,
            publication_started=state != "PREPARED",
            uid=_current_uid(),
        )
    rollback_exists = _exists(home_fd, rollback)
    live_exists = _exists(home_fd, RUNTIME_LEAF)
    stage_exists = _exists(home_fd, stage)
    if rollback_exists:
        if live_exists:
            if stage_exists:
                _delete_tree(home_fd, stage)
            os.rename(RUNTIME_LEAF, stage, src_dir_fd=home_fd, dst_dir_fd=home_fd)
        os.rename(rollback, RUNTIME_LEAF, src_dir_fd=home_fd, dst_dir_fd=home_fd)
        os.fsync(home_fd)
        _delete_tree(home_fd, stage)
    elif state == "PREPARED" and had_prior and live_exists and stage_exists:
        _delete_tree(home_fd, stage)
    elif not had_prior:
        if live_exists and not stage_exists:
            _delete_tree(home_fd, RUNTIME_LEAF)
        _delete_tree(home_fd, stage)
    else:
        _fail("compatibility transaction rollback authority is missing")
    _journal(compat_fd, None)


def _admit_prior_runtime(home_fd: int, uid: int) -> bool:
    if not _exists(home_fd, RUNTIME_LEAF):
        return False
    info = os.stat(RUNTIME_LEAF, dir_fd=home_fd, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        _fail("existing installed runtime authority differs")
    fd = os.open(
        RUNTIME_LEAF,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=home_fd,
    )
    try:
        entry = os.stat("plamen.py", dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(entry.st_mode) or entry.st_uid != uid:
            _fail("existing installed runtime is not an admitted Plamen tree")
    except FileNotFoundError:
        _fail("existing installed runtime is not an admitted Plamen tree")
    finally:
        os.close(fd)
    return True


def _validate_codex_projection(home: str) -> None:
    projection = os.path.join(home, ".codex", "plamen")
    try:
        info = os.lstat(projection)
    except FileNotFoundError:
        return
    except OSError:
        _fail("existing Codex Plamen projection could not be inspected")
    if not stat.S_ISLNK(info.st_mode):
        _fail("existing Codex Plamen projection is not the admitted link")
    try:
        target = os.readlink(projection)
    except OSError:
        _fail("existing Codex Plamen projection could not be read")
    expected = os.path.join(home, RUNTIME_LEAF)
    resolved = os.path.normpath(
        target if os.path.isabs(target) else os.path.join(os.path.dirname(projection), target)
    )
    if resolved != expected:
        _fail("existing Codex Plamen projection names a different runtime")


def _admit_launcher(bin_fd: int, home: str, uid: int) -> None:
    if not _exists(bin_fd, LAUNCHER_LEAF):
        return
    info = os.stat(LAUNCHER_LEAF, dir_fd=bin_fd, follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(LAUNCHER_LEAF, dir_fd=bin_fd)
        absolute = target if os.path.isabs(target) else os.path.join(home, ".local", "bin", target)
        admitted = {
            os.path.join(home, RUNTIME_LEAF, "plamen"),
            os.path.join(home, RUNTIME_LEAF, "plamen.sh"),
            os.path.join(home, RUNTIME_LEAF, "plamen.py"),
        }
        if os.path.normpath(absolute) not in admitted:
            _fail("existing public launcher is not Plamen-owned")
        return
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > 8192:
        _fail("existing public launcher is not Plamen-owned")
    raw = _read_bounded(bin_fd, LAUNCHER_LEAF, 8192)
    if b"Plamen" not in raw or b".plamen" not in raw:
        _fail("existing public launcher is not Plamen-owned")


def _launcher_bytes(python_path: str, home: str) -> bytes:
    target = os.path.join(home, RUNTIME_LEAF, "plamen.py")
    return (
        "#!/bin/sh\n"
        "# Plamen POSIX compatibility launcher v2; reduced isolation, not native.\n"
        f"exec {shlex.quote(python_path)} -I -B {shlex.quote(target)} \"$@\"\n"
    ).encode("utf-8")


def _verified_runtime_provenance(
    runtime_fd: int, *, allow_legacy_for_retirement: bool = False
) -> dict[str, object]:
    raw = _read_bounded(runtime_fd, PROVENANCE_LEAF, MAX_MANIFEST_BYTES)
    try:
        provenance = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeError, ValueError):
        _fail("compatibility provenance is malformed")
    schema = provenance.get("schema") if isinstance(provenance, dict) else None
    if schema not in (
        {SCHEMA, LEGACY_SCHEMA}
        if allow_legacy_for_retirement
        else {SCHEMA}
    ):
        _fail("compatibility provenance schema differs")
    expected_fields = (
        PROVENANCE_FIELDS if schema == SCHEMA else LEGACY_PROVENANCE_FIELDS
    )
    if set(provenance) != expected_fields:
        _fail("compatibility provenance fields differ")
    rows, total = _census_tree(runtime_fd)
    if (
        rows != provenance.get("source_census")
        or total != provenance.get("source_total_bytes")
        or _tree_digest(rows) != provenance.get("generation_sha256")
    ):
        _fail("installed compatibility runtime differs from provenance")
    if (
        schema == SCHEMA
        and allow_legacy_for_retirement
        and provenance.get("generation_sha256")
        in AUTHENTIC_V2_RETIREMENT_GENERATIONS
    ):
        # The exact byte census above is the reviewed predecessor authority.
        # It can be moved into rollback custody, but cannot authorize or be
        # mistaken for the independently validated successor below.
        return provenance
    if schema == SCHEMA:
        binding = provenance.get("js_package_binding")
        if type(binding) is not dict or binding != _js_install_binding(rows):
            _fail("installed JavaScript package binding differs from provenance")
        closure_binding = provenance.get("runtime_closure_binding")
        raw = _read_relative_bounded(
            runtime_fd, JS_RUNTIME_CLOSURE_FILE, MAX_MANIFEST_BYTES,
            _current_uid(),
        )
        try:
            payload = json.loads(raw.decode("ascii", "strict"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            _fail("installed toolchain runtime closure is malformed")
        expected_closure = _runtime_closure_binding(rows, payload, raw)
        if (
            type(closure_binding) is not dict
            or set(closure_binding) != RUNTIME_CLOSURE_BINDING_FIELDS
            or closure_binding != expected_closure
        ):
            _fail("installed runtime closure binding differs from provenance")
    else:
        if "js_package_binding" in provenance:
            _fail(
                "legacy compatibility provenance cannot contain a JavaScript binding"
            )
        generation = provenance.get("generation_sha256")
        if _legacy_census_has_js(rows):
            if not allow_legacy_for_retirement:
                _fail(
                    "legacy compatibility provenance cannot admit a JavaScript package"
                )
            if generation not in AUTHENTIC_JS_V1_RETIREMENT_GENERATIONS:
                _fail(
                    "legacy JavaScript compatibility generation is not "
                    "authenticated for retirement"
                )
        elif generation not in AUTHENTIC_PRE_JS_V1_GENERATIONS:
            _fail("legacy compatibility generation is not authenticated")
    return provenance


def _prior_codex_skill_rows(home_fd: int, uid: int) -> list[dict[str, object]]:
    """Return prior skill ownership only from a verified compat generation."""
    if not _exists(home_fd, RUNTIME_LEAF):
        return []
    runtime_fd = os.open(
        RUNTIME_LEAF,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=home_fd,
    )
    try:
        if not _exists(runtime_fd, PROVENANCE_LEAF):
            return []
        if os.fstat(runtime_fd).st_uid != uid:
            _fail("existing compatibility runtime authority differs")
        provenance = _verified_runtime_provenance(
            runtime_fd, allow_legacy_for_retirement=True
        )
    finally:
        os.close(runtime_fd)
    source_rows = provenance.get("source_census")
    if not isinstance(source_rows, list):
        _fail("existing compatibility source census is malformed")
    return _codex_skill_rows(source_rows)


def verify_install(home_path: os.PathLike[str] | str) -> dict[str, object]:
    """Verify an installed compatibility closure without mutating it."""
    uid = _current_uid()
    home = _canonical_absolute(home_path, "account home")
    home_fd = _open_absolute_directory(home, "account home", uid)
    runtime_fd = -1
    try:
        runtime_fd = os.open(
            RUNTIME_LEAF,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=home_fd,
        )
        provenance = _verified_runtime_provenance(runtime_fd)
        source_rows = provenance.get("source_census")
        if not isinstance(source_rows, list):
            _fail("compatibility source census is malformed")
        _verify_codex_skill_projection(home_fd, source_rows, uid)
        return provenance
    except (UnicodeError, ValueError, OSError, AttributeError):
        _fail("installed compatibility runtime verification failed")
    finally:
        if runtime_fd >= 0:
            os.close(runtime_fd)
        os.close(home_fd)


def _repair_python_dependencies(
    *, home: str, python_path: str, provenance: dict[str, object],
) -> dict[str, object]:
    """Run the exact admitted compatibility-only full-lock repair leaf."""

    script = os.path.join(home, RUNTIME_LEAF, "plamen.py")
    environment = dict(os.environ)
    environment["HOME"] = home
    for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT"):
        environment.pop(name, None)
    argv = [
        python_path, "-B", script, "install",
        "--posix-compat-v2-dependencies",
    ]
    returncode = 125
    termination_debt = ""
    process = None
    def group_exists(process_group: int) -> bool:
        try:
            os.killpg(process_group, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError:
            return True

    def terminate_group(process_group: int) -> str:
        try:
            os.killpg(process_group, signal.SIGTERM)
        except ProcessLookupError:
            return ""
        except OSError:
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and group_exists(process_group):
            time.sleep(0.05)
        # Always issue the final group-wide SIGKILL if anything remains. A
        # leader exit after SIGTERM is not evidence that pip descendants exited.
        if group_exists(process_group):
            try:
                os.killpg(process_group, signal.SIGKILL)
            except OSError:
                pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and group_exists(process_group):
            time.sleep(0.05)
        return (
            " process-group termination could not prove all dependency mutation stopped;"
            if group_exists(process_group) else ""
        )

    try:
        with tempfile.TemporaryFile(mode="w+b") as stdout_file, \
                tempfile.TemporaryFile(mode="w+b") as stderr_file:
            process = subprocess.Popen(
                argv, stdin=subprocess.DEVNULL, stdout=stdout_file,
                stderr=stderr_file, env=environment, shell=False,
                start_new_session=True, close_fds=True,
            )
            deadline = time.monotonic() + 3600.0
            while True:
                observed = process.poll()
                stdout_size = os.fstat(stdout_file.fileno()).st_size
                stderr_size = os.fstat(stderr_file.fileno()).st_size
                if stdout_size > 2 * 1024 * 1024 or stderr_size > 2 * 1024 * 1024:
                    termination_debt = terminate_group(process.pid)
                    returncode = 126
                    break
                if observed is not None:
                    returncode = int(observed)
                    if group_exists(process.pid):
                        termination_debt = terminate_group(process.pid)
                        returncode = 127
                    break
                if time.monotonic() >= deadline:
                    termination_debt = terminate_group(process.pid)
                    returncode = 124
                    break
                time.sleep(0.1)
            stdout_size = os.fstat(stdout_file.fileno()).st_size
            stderr_size = os.fstat(stderr_file.fileno()).st_size
            stderr_file.seek(max(0, stderr_size - 2048))
            stderr_tail = stderr_file.read(2048).decode("utf-8", "replace")
            if stdout_size > 2 * 1024 * 1024 or stderr_size > 2 * 1024 * 1024:
                _fail(
                    "locked Python dependency repair output exceeded its bound;"
                    + termination_debt
                    + " Python package changes, if any, were not transactionally rolled back; "
                    + stderr_tail[-1000:]
                )
            stdout_file.seek(0)
            stdout_raw = stdout_file.read()
    except CompatInstallError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        _fail(
            "locked Python dependency repair could not execute "
            f"({type(exc).__name__}); Python package changes, if any, were not "
            "transactionally rolled back"
        )
    finally:
        if process is not None:
            try:
                leader_running = process.poll() is None
            except BaseException:
                leader_running = True
            if leader_running or group_exists(process.pid):
                residual = terminate_group(process.pid)
                if residual:
                    termination_debt = residual
            try:
                process.wait(timeout=2)
            except (AttributeError, OSError, subprocess.TimeoutExpired):
                if not termination_debt:
                    termination_debt = (
                        " process leader could not be reaped after dependency repair;"
                    )
    if termination_debt and returncode == 0:
        returncode = 127
    if returncode != 0:
        _fail(
            f"locked Python dependency repair failed rc={returncode};"
            + termination_debt
            + " Python package changes, if any, were not transactionally rolled back; "
            + stderr_tail[-1000:]
        )
    try:
        lines = stdout_raw.decode("utf-8", "strict").splitlines()
        result = json.loads(next(line for line in reversed(lines) if line.strip()))
    except (UnicodeError, ValueError, StopIteration):
        _fail(
            "locked Python dependency repair result is malformed; Python "
            "package changes, if any, were not transactionally rolled back"
        )
    expected_keys = {
        "schema", "status", "reduced_isolation", "generation_sha256",
        "dependency_authority_sha256", "trust_boundary",
        "native_install_authority",
    }
    if (
        not isinstance(result, dict)
        or set(result) != expected_keys
        or result.get("schema")
        != "plamen.posix_v2_compat_python_dependencies.v1"
        or result.get("status") != "VALID"
        or result.get("reduced_isolation") is not True
        or result.get("native_install_authority") is not False
        or result.get("generation_sha256") != provenance.get("generation_sha256")
        or result.get("trust_boundary")
        != "USER_WRITABLE_DRIFT_DETECTION_ONLY"
        or not isinstance(result.get("dependency_authority_sha256"), str)
        or re.fullmatch(
            r"[0-9a-f]{64}", result["dependency_authority_sha256"]
        ) is None
    ):
        _fail(
            "locked Python dependency repair result differs from admission; "
            "Python package changes, if any, were not transactionally rolled back"
        )
    return result


def install_compat_v2(
    source_path: os.PathLike[str] | str,
    home_path: os.PathLike[str] | str,
    python_executable: os.PathLike[str] | str,
    *,
    fault_hook: Callable[[str], None] | None = None,
    archive_fetcher: Callable[[str], object] | None = None,
) -> dict[str, object]:
    """Install one exact V3 snapshot and return its reduced-isolation provenance.

    All descriptors are borrowed only within this call and closed before return.
    ``fault_hook`` and ``archive_fetcher`` are deterministic transaction and
    transport seams for tests; neither is exposed by the command-line
    interface.
    """
    if fcntl is None or pwd is None:
        raise CompatInstallError(
            "the POSIX V2 compatibility installer requires POSIX descriptor APIs"
        )
    uid = _current_uid()
    source = _canonical_absolute(source_path, "source root")
    home = _canonical_absolute(home_path, "account home")
    python_path = _canonical_absolute(python_executable, "managed CPython path")
    if source == home or source.startswith(home + "/.plamen/") or source == os.path.join(home, RUNTIME_LEAF):
        _fail("install source overlaps the published runtime")
    source_fd = _open_absolute_directory(source, "source root", uid)
    home_fd = _open_absolute_directory(home, "account home", uid)
    local_fd = share_fd = plamen_share_fd = compat_fd = bin_fd = lock_fd = -1
    codex_fd = skills_fd = -1
    stage_fd = -1
    stage = rollback = ""
    skill_stage = skill_rollback = ""
    journal: dict[str, object] | None = None
    launcher_temp = ""
    try:
        _validate_codex_projection(home)
        # Validate source identity enough to reject self-publication before any mutation.
        if os.fstat(source_fd).st_dev == os.fstat(home_fd).st_dev and os.fstat(source_fd).st_ino == os.fstat(home_fd).st_ino:
            _fail("install source and account home are identical")
        # Git is source/build-time authority only.  The copied stage excludes
        # every `.git` entry and must independently replay from its portable
        # release-pinned manifest before it can become canonical.
        _validate_source_rule_package(source)

        # Capture first into a private sibling.  Its random name is transaction
        # identity only; generation identity is the deterministic census digest.
        token = os.urandom(16).hex()
        stage = f".plamen-compat-v2-stage-{token}"
        rollback = f".plamen-compat-v2-rollback-{token}"
        try:
            os.mkdir(stage, 0o700, dir_fd=home_fd)
            stage_fd = os.open(
                stage,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=home_fd,
            )
        except OSError:
            _fail("compatibility staging generation could not be created")
        source_rows, source_total = _copy_snapshot(source_fd, stage_fd, uid=uid)
        missing = sorted(REQUIRED_SOURCE_FILES - {str(row["path"]) for row in source_rows if row["kind"] == "file"})
        if missing:
            _fail("required compatibility runtime input is missing: " + missing[0])
        acquisition = _materialize_absent_js_distributable(
            stage_fd, source_rows, uid, fetcher=archive_fetcher
        )
        installed_rows, installed_total = _census_tree(stage_fd)
        js_package_binding = _js_install_binding(installed_rows)
        source_runtime_closure = source_js_authority = None
        if acquisition is None:
            expected_installed_rows = _source_rows_as_installed(source_rows)
            if installed_rows != expected_installed_rows or installed_total != source_total:
                _fail("staged source snapshot differs before semantic admission")
            source_runtime_closure = _validate_complete_runtime_closure(
                Path(source), "source package", captured_rows=installed_rows
            )
            source_js_authority = _validate_source_js_package(
                source,
                bootstrap_binding=js_package_binding,
                captured_rows=installed_rows,
            )
        _validate_staged_rule_package(Path(home) / stage)
        staged_runtime_closure = _validate_complete_runtime_closure(
            Path(home) / stage, "staged package", captured_rows=installed_rows
        )
        staged_js_authority = _validate_staged_js_package(
            Path(home) / stage,
            bootstrap_binding=js_package_binding,
            captured_rows=installed_rows,
        )
        if source_js_authority is not None and staged_js_authority != source_js_authority:
            _fail("JavaScript staged package provenance differs from source")
        if source_runtime_closure is not None and staged_runtime_closure != source_runtime_closure:
            _fail("staged complete runtime closure differs from source")
        staged_rows, staged_total = _census_tree(stage_fd)
        if staged_rows != installed_rows or staged_total != installed_total:
            _fail("JavaScript staged package changed after semantic admission")
        if fault_hook is not None:
            fault_hook("after_source_capture")
        observed_rows, observed_total = _census_tree(source_fd)
        if source_rows != observed_rows or source_total != observed_total:
            _fail("source snapshot changed before compatibility admission completed")
        codex_skill_rows = _codex_skill_rows(installed_rows)
        generation_sha256 = _tree_digest(installed_rows)
        if generation_sha256 != js_package_binding["source_census_sha256"]:
            _fail("JavaScript package binding differs from generation identity")
        python = _validate_python(python_path, source_rows, uid)
        provenance: dict[str, object] = {
            "schema": SCHEMA,
            "claim": "reduced-isolation POSIX V2 compatibility runtime",
            "generation_sha256": generation_sha256,
            "js_package_binding": js_package_binding,
            "runtime_closure_binding": source_runtime_closure,
            "source_census": installed_rows,
            "source_entry_count": len(installed_rows),
            "source_total_bytes": installed_total,
            "source_exclusions": sorted(EXCLUDED_NAMES) + list(EXCLUDED_SUFFIXES),
            "python": python,
            "security_properties": {
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
            },
        }
        _atomic_write(stage_fd, PROVENANCE_LEAF, _canonical_json(provenance))
        os.fsync(stage_fd)
        os.close(stage_fd)
        stage_fd = -1

        # Only after every immutable input validates do we create transaction
        # control directories or inspect replaceable authorities.
        local_fd = _ensure_directory(home_fd, ".local", uid)
        share_fd = _ensure_directory(local_fd, "share", uid)
        plamen_share_fd = _ensure_directory(share_fd, "plamen", uid)
        compat_fd = _ensure_directory(plamen_share_fd, "compat-v2", uid)
        bin_fd = _ensure_directory(local_fd, "bin", uid)
        codex_fd = _ensure_directory(home_fd, ".codex", uid)
        skills_fd = _ensure_directory(codex_fd, "skills", uid)
        try:
            lock_fd = os.open(
                "install.lock",
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=compat_fd,
            )
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except OSError:
            _fail("compatibility install writer lock failed")
        _recover(home_fd, compat_fd, skills_fd)
        had_prior = _admit_prior_runtime(home_fd, uid)
        prior_skill_rows = _prior_codex_skill_rows(home_fd, uid) if had_prior else []
        _admit_launcher(bin_fd, home, uid)

        launcher_raw = _launcher_bytes(python_path, home)
        launcher_temp = f".plamen.compat-v2.{token}.tmp"
        launcher_fd = -1
        try:
            launcher_fd = os.open(
                launcher_temp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o700,
                dir_fd=bin_fd,
            )
            _write_all(launcher_fd, launcher_raw)
            os.fchmod(launcher_fd, 0o700)
            os.fsync(launcher_fd)
        finally:
            if launcher_fd >= 0:
                os.close(launcher_fd)

        skill_stage, skill_rollback, prior_live_skill_rows = (
            _prepare_codex_skill_projection(
                home_fd,
                stage,
                skills_fd,
                token,
                codex_skill_rows,
                prior_skill_rows,
                uid,
            )
        )

        journal = {
            "schema": JOURNAL_SCHEMA,
            "state": "PREPARED",
            "stage": stage,
            "rollback": rollback,
            "had_prior": had_prior,
            "skill_stage": skill_stage,
            "skill_rollback": skill_rollback,
        }
        _journal(compat_fd, journal)
        if fault_hook is not None:
            fault_hook("prepared")
        if had_prior:
            os.rename(RUNTIME_LEAF, rollback, src_dir_fd=home_fd, dst_dir_fd=home_fd)
            os.fsync(home_fd)
        journal["state"] = "RETIRED"
        _journal(compat_fd, journal)
        if fault_hook is not None:
            fault_hook("after_prior_retired")
        os.rename(stage, RUNTIME_LEAF, src_dir_fd=home_fd, dst_dir_fd=home_fd)
        os.fsync(home_fd)
        journal["state"] = "PUBLISHED"
        _journal(compat_fd, journal)
        if fault_hook is not None:
            fault_hook("after_runtime_published")
        _publish_codex_skill_projection(
            skills_fd,
            skill_stage,
            skill_rollback,
            prior_live_skill_rows,
            uid,
        )
        journal["state"] = "SKILLS_PUBLISHED"
        _journal(compat_fd, journal)
        if fault_hook is not None:
            fault_hook("after_skills_published")
        verified = verify_install(home)
        if verified != provenance:
            _fail("published compatibility provenance differs")
        _repair_python_dependencies(
            home=home, python_path=python_path, provenance=provenance,
        )
        if fault_hook is not None:
            fault_hook("after_python_dependencies_validated")
        # The public launcher is the final externally usable publication.
        os.replace(launcher_temp, LAUNCHER_LEAF, src_dir_fd=bin_fd, dst_dir_fd=bin_fd)
        launcher_temp = ""
        os.fsync(bin_fd)
        journal["state"] = "COMMITTED"
        _journal(compat_fd, journal)
        _delete_tree(home_fd, rollback)
        _recover_codex_skill_projection(
            skills_fd,
            skill_stage,
            skill_rollback,
            committed=True,
            publication_started=True,
            uid=uid,
        )
        _journal(compat_fd, None)
        return provenance
    except BaseException:
        if journal is not None and compat_fd >= 0:
            try:
                _recover(home_fd, compat_fd, skills_fd)
            except BaseException:
                pass
        elif stage:
            try:
                _delete_tree(home_fd, stage)
            except BaseException:
                pass
            if skills_fd >= 0:
                for leaf in (skill_rollback, skill_stage):
                    if not leaf:
                        continue
                    try:
                        _delete_tree(skills_fd, leaf)
                    except BaseException:
                        pass
        raise
    finally:
        if launcher_temp and bin_fd >= 0:
            try:
                os.unlink(launcher_temp, dir_fd=bin_fd)
            except OSError:
                pass
        if stage_fd >= 0:
            os.close(stage_fd)
        for fd in (
            lock_fd,
            skills_fd,
            codex_fd,
            bin_fd,
            compat_fd,
            plamen_share_fd,
            share_fd,
            local_fd,
            home_fd,
            source_fd,
        ):
            if fd >= 0:
                os.close(fd)


def _account_home() -> str:
    uid = _current_uid()
    try:
        record = pwd.getpwuid(uid)
    except (KeyError, OSError):
        _fail("account home is unavailable")
    if record.pw_uid != uid:
        _fail("account home identity differs")
    return _canonical_absolute(record.pw_dir, "account home")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install the explicit reduced-isolation POSIX V2 compatibility runtime."
    )
    parser.add_argument("--posix-compat-v2", action="store_true")
    parser.add_argument("--install", action="store_true")
    parser.add_argument("--source", required=True)
    parser.add_argument("--python", dest="python_executable")
    parser.add_argument("--home", help="explicit account home (primarily for controlled tests)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if not args.posix_compat_v2:
        _fail("the compatibility installer requires explicit --posix-compat-v2")
    if not args.install:
        _fail("the compatibility installer requires explicit --install")
    home = _canonical_absolute(args.home, "account home") if args.home else _account_home()
    python_path = args.python_executable or os.path.join(
        home, ".local", "share", "plamen", "runtime", "py312", "bin", "python"
    )
    provenance = install_compat_v2(args.source, home, python_path)
    summary = {
        "generation_sha256": provenance["generation_sha256"],
        "installed_root": os.path.join(home, RUNTIME_LEAF),
        "launcher": os.path.join(home, ".local", "bin", LAUNCHER_LEAF),
        "reduced_isolation": True,
        "schema": SCHEMA,
        "source_entry_count": provenance["source_entry_count"],
    }
    sys.stdout.write(_canonical_json(summary).decode("utf-8"))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CompatInstallError as exc:
        sys.stderr.write(f"Plamen compatibility install failed: {exc}\n")
        raise SystemExit(2) from None
