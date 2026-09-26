from __future__ import annotations

import base64
import copy
import hashlib
import ctypes
import os
import pathlib
import subprocess

import pytest

import native_operation4_acquisition_validation as validation


ROOT = pathlib.Path(__file__).resolve().parents[1]


PAYLOAD = b"retained-platform-npm-tarball" * 4


def _signature(message: bytes, encoded: str = "AA==") -> dict[str, str]:
    return {
        "keyid": validation._NPM_KEY_ID,
        "message_sha256": hashlib.sha256(message).hexdigest(),
        "signature": encoded,
    }


def _registry(*, selector: str, sri: str) -> dict:
    version = "0.154.0" if selector == "codex" else "2.1.270"
    package = "@openai/codex" if selector == "codex" else "@anthropic-ai/claude-code"
    platform_install_name = (
        "@openai/codex-linux-arm64" if selector == "codex"
        else "@anthropic-ai/claude-code-linux-arm64"
    )
    platform_package = (
        "@openai/codex" if selector == "codex"
        else platform_install_name
    )
    platform_version = version + "-linux-arm64" if selector == "codex" else version
    provenance = (
        {"predicate_type": "https://slsa.dev/provenance/v1", "url": "https://registry.npmjs.org/-/npm/v1/attestations/vector"}
        if selector == "codex" else None
    )
    root_message = f"{package}@{version}:{sri}".encode("ascii")
    platform_message = f"{platform_package}@{platform_version}:{sri}".encode("ascii")
    return {
        "selector": selector,
        "package": package,
        "version": version,
        "metadata_sha256": "10" * 32,
        "metadata_url": "https://registry.npmjs.org/" + package.replace("/", "%2f") + "/latest",
        "tarball_url": "https://registry.npmjs.org/root.tgz",
        "integrity": sri,
        "shasum": "11" * 20,
        "registry_signature": _signature(root_message),
        "trusted_publisher": {"id": "github", "oidc_config_id": "oidc"} if selector == "codex" else None,
        "provenance": provenance,
        "platform_package": {
            "install_name": platform_install_name,
            "package": platform_package,
            "version": platform_version,
            "metadata_url": "https://registry.npmjs.org/platform/exact",
            "metadata_sha256": "12" * 32,
            "tarball_url": "https://registry.npmjs.org/platform.tgz",
            "integrity": sri,
            "shasum": "13" * 20,
            "registry_signature": _signature(platform_message),
            "provenance": provenance,
        },
    }


def _resign(value: dict, private) -> None:
    value.pop("authentication", None)
    value.pop("receipt_sha256", None)
    public = private.public_key().public_bytes_raw()
    value["authentication"] = {
        "scheme": "ed25519",
        "key_id": hashlib.sha256(public).hexdigest(),
        "signature": private.sign(validation._canonical(value)).hex(),
    }
    value["receipt_sha256"] = hashlib.sha256(validation._canonical(value)).hexdigest()


def _receipt(selector: str, private, footer: dict) -> dict:
    version = "0.154.0" if selector == "codex" else "2.1.270"
    sri = "sha512-" + base64.b64encode(hashlib.sha512(PAYLOAD).digest()).decode("ascii")
    registry = _registry(selector=selector, sri=sri)
    observed = (
        ["--allowedTools", "--disallowedTools", "--json-schema", "--mcp-config", "--model", "--output-format", "--permission-mode", "--strict-mcp-config"]
        if selector == "claude" else
        ["--ephemeral", "--json", "--model", "--output-last-message", "--sandbox", "--skip-git-repo-check"]
    )
    executable_sha = "21" * 32
    value = {
        "schema": "plamen.native-backend-latest-acquisition-receipt.v1",
        "selector": selector,
        "policy_schema": "plamen.native-backend-acquisition.v2",
        "policy_sha256": footer["policy_sha256"],
        "resolved_version": version,
        "resolved_release": registry["platform_package"]["version"],
        "registry": registry,
        "upstream": None,
        "transport": {
            "tls_minimum": "1.2", "redirect_count": 0,
            "credentials": "FORBIDDEN", "proxy_environment": "IGNORED",
            "endpoints_sha256": "22" * 32,
        },
        "payload": {
            "source_url": registry["platform_package"]["tarball_url"],
            "size": len(PAYLOAD), "sha256": hashlib.sha256(PAYLOAD).hexdigest(),
            "sha512_sri": sri, "archive_format": "tar.gz", "member_count": 2,
            "member_roster_sha256": "23" * 32, "selected_member": (
                "package/vendor/aarch64-unknown-linux-gnu/bin/codex"
                if selector == "codex" else "package/claude"
            ),
            "path_traversal_rejected": True,
        },
        "installed": {
            "platform": "linux-arm64", "relative_path": (
                "node_modules/@openai/codex-linux-arm64/vendor/"
                "aarch64-unknown-linux-gnu/bin/codex"
                if selector == "codex" else
                "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
            ),
            "executable_sha256": executable_sha, "executable_size": 456,
            "closure_sha256": "24" * 32, "closure_count": 3, "closure_bytes": 789,
            "code_signature": {
                "mode": "REGISTRY_SIGNATURE_ONLY", "identifier": None,
                "team_identifier": None, "cdhash_sha256": None,
            },
        },
        "probes": {
            "version": {
                "argv": ["--version"], "returncode": 0,
                "stdout_sha256": "26" * 32, "stderr_sha256": "27" * 32,
                "normalized_output": f"{version} (Claude Code)" if selector == "claude" else f"codex-cli {version}",
                "observed_contract": [],
            },
            "help": {
                "argv": ["--help"] if selector == "claude" else ["exec", "--help"],
                "returncode": 0, "stdout_sha256": "28" * 32,
                "stderr_sha256": "29" * 32, "normalized_output": "help",
                "observed_contract": observed,
            },
        },
        "install": {
            "transaction_id": "install-1", "generation_id": "npm-" + "30" * 32,
            "install_receipt_sha256": "31" * 32,
            "source_manifest_sha256": footer["manifest_sha256"],
            "source_manifest_size": footer["manifest_size"],
        },
    }
    if selector == "claude":
        value["upstream"] = {
            "latest_url": "https://downloads.claude.ai/claude-code-releases/latest",
            "latest_sha256": "32" * 32,
            "manifest_url": f"https://downloads.claude.ai/claude-code-releases/{version}/manifest.json",
            "manifest_sha256": "33" * 32, "manifest_size": 1234,
            "platform": "linux-arm64", "commit": "34" * 20,
            "executable_sha256": executable_sha, "executable_size": 456,
        }
    _resign(value, private)
    return value


@pytest.fixture
def signed_backend():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    footer = {
        "policy_sha256": "aa" * 32,
        "payload_sha256": hashlib.sha256(PAYLOAD).hexdigest(),
        "payload_size": len(PAYLOAD),
        "manifest_sha256": "cc" * 32,
        "manifest_size": 222,
    }
    return private, footer


@pytest.mark.parametrize("selector,role", [("codex", 5), ("claude", 6)])
def test_backend_latest_receipt_authenticates_without_version_pin(monkeypatch, signed_backend, selector, role):
    private, footer = signed_backend
    footer = {**footer, "version": "0.154.0" if selector == "codex" else "2.1.270"}
    monkeypatch.setattr(validation, "_verify_registry_signature", lambda *_args: None)
    validation._validate_backend(
        _receipt(selector, private, footer), footer, role,
        private.public_key().public_bytes_raw(), PAYLOAD,
    )


def test_backend_non_darwin_windows_uses_registry_authority_not_fabricated_authenticode(monkeypatch, signed_backend):
    private, footer = signed_backend
    footer = {**footer, "version": "2.1.270"}
    value = _receipt("claude", private, footer)
    value["installed"]["platform"] = "win32-x64"
    value["upstream"]["platform"] = "win32-x64"
    value["registry"]["platform_package"]["install_name"] = (
        "@anthropic-ai/claude-code-win32-x64"
    )
    value["registry"]["platform_package"]["package"] = (
        "@anthropic-ai/claude-code-win32-x64"
    )
    _resign(value, private)
    monkeypatch.setattr(validation, "_verify_registry_signature", lambda *_args: None)
    validation._validate_backend(value, footer, 6, private.public_key().public_bytes_raw(), PAYLOAD)
    value["installed"]["code_signature"]["mode"] = "WINDOWS_AUTHENTICODE"
    _resign(value, private)
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._validate_backend(value, footer, 6, private.public_key().public_bytes_raw(), PAYLOAD)


@pytest.mark.parametrize(
    "selector,mutation",
    [
        ("codex", "registry_package"),
        ("claude", "registry_version"),
        ("codex", "install_name"),
        ("codex", "platform_package"),
        ("codex", "platform_version"),
        ("claude", "platform_arch"),
        ("codex", "selected_member_traversal"),
        ("codex", "installed_package_arch"),
        ("codex", "installed_relative_traversal"),
    ],
)
def test_backend_release_and_executable_joins_reject_resigned_cross_binding(
    monkeypatch, signed_backend, selector, mutation,
):
    private, footer = signed_backend
    footer = {
        **footer,
        "version": "0.154.0" if selector == "codex" else "2.1.270",
    }
    value = _receipt(selector, private, footer)
    monkeypatch.setattr(validation, "_verify_registry_signature", lambda *_args: None)
    if mutation == "registry_package":
        value["registry"]["package"] = "@attacker/backend"
    elif mutation == "registry_version":
        value["registry"]["version"] = "9.9.9"
    elif mutation == "install_name":
        value["registry"]["platform_package"]["install_name"] = "@attacker/backend-linux-arm64"
    elif mutation == "platform_package":
        value["registry"]["platform_package"]["package"] = "@attacker/backend"
    elif mutation == "platform_version":
        value["registry"]["platform_package"]["version"] = "0.154.0-linux-x64"
        value["resolved_release"] = "0.154.0-linux-x64"
    elif mutation == "platform_arch":
        value["installed"]["platform"] = "linux-x64"
        value["upstream"]["platform"] = "linux-x64"
    elif mutation == "selected_member_traversal":
        value["payload"]["selected_member"] = "package/vendor/../bin/codex"
    elif mutation == "installed_package_arch":
        value["installed"]["relative_path"] = (
            "node_modules/@openai/codex-linux-x64/vendor/"
            "aarch64-unknown-linux-gnu/bin/codex"
        )
    else:
        value["installed"]["relative_path"] = (
            "node_modules/@openai/codex-linux-arm64/vendor/../bin/codex"
        )
    _resign(value, private)
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._validate_backend(
            value, footer, 5 if selector == "codex" else 6,
            private.public_key().public_bytes_raw(), PAYLOAD,
        )


@pytest.mark.parametrize("mutation", ["signature", "selector", "projection", "publisher", "nested_extra", "payload"])
def test_backend_latest_receipt_rejects_forgery_and_cross_binding(monkeypatch, signed_backend, mutation):
    private, footer = signed_backend
    footer = {**footer, "version": "0.154.0"}
    value = _receipt("codex", private, footer)
    monkeypatch.setattr(validation, "_verify_registry_signature", lambda *_args: None)
    if mutation == "signature":
        value["authentication"]["signature"] = "00" * 64
    elif mutation == "selector":
        value["selector"] = "claude"
        _resign(value, private)
    elif mutation == "projection":
        value["install"]["source_manifest_sha256"] = "00" * 32
        _resign(value, private)
    elif mutation == "publisher":
        value["installed"]["code_signature"]["mode"] = "APPLE_DEVELOPER_ID"
        _resign(value, private)
    elif mutation == "nested_extra":
        value["registry"]["platform_package"]["ambient"] = True
        _resign(value, private)
    else:
        value["payload"]["sha256"] = "00" * 32
        _resign(value, private)
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._validate_backend(
            value, footer, 5, private.public_key().public_bytes_raw(), PAYLOAD,
        )


def test_real_npm_p256_registry_signatures_and_mutation():
    rows = [
        ("@openai/codex", "0.154.0", "sha512-FV/x1OHXYv/ifjf3mXj9ThTTAWcUZN6cGIRQRhRxkKNOPuImu1WW0c8ev1vUkE9XGH90dEnYG1tBjIkxRikg0w==", "MEYCIQDRpG84Ly0XYkYhUObqKlYOHq13TScD5/uSwD+lhrcBawIhAIxoYbuh5tcA9p/ftyjuXzmIsiaYeIpAkQZK7b1TUvtm"),
        ("@anthropic-ai/claude-code", "2.1.270", "sha512-0zMkfIWQu7/SG56VP8r780HZWvrNShzK28AbAnhKRK0ns+ToGXPT0W8UqyZmZCUKAkJDd5//TrwSOhk1+hysiw==", "MEUCICswNn0ZCH6n8b+WSQFDOEk3QcOvuTFLZwQA0RkGt7r8AiEA514qgU8Z5E/KTJIyHGcXZv2L4B/pTejvTh1xjp/qnzI="),
    ]
    for package, version, integrity, signature in rows:
        message = f"{package}@{version}:{integrity}".encode("ascii")
        row = {"package": package, "version": version, "integrity": integrity, "registry_signature": _signature(message, signature)}
        validation._verify_registry_signature(row, package, version)
        mutated = copy.deepcopy(row)
        mutated["registry_signature"]["signature"] = base64.b64encode(b"not a signature").decode()
        with pytest.raises(validation.NativeOperation4ValidationError):
            validation._verify_registry_signature(mutated, package, version)
    redundant_zero = base64.b64decode(
        "MEcCIgAA0aRvOC8tF2JGIVDm6ipWDh6td00nA+f7ksA/pYa3AWsCIQCMaGG7oebXAPaf37co7l85iLImmHiKQJEGSu29U1L7Zg=="
    )
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_p256(
            b"@openai/codex@0.154.0:sha512-FV/x1OHXYv/ifjf3mXj9ThTTAWcUZN6cGIRQRhRxkKNOPuImu1WW0c8ev1vUkE9XGH90dEnYG1tBjIkxRikg0w==",
            redundant_zero,
        )


def test_ed25519_rfc8032_vector_noncanonical_and_small_order_rejected():
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    validation._verify_ed25519(public, b"", signature)
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_ed25519(b"\x01" + b"\0" * 31, b"", signature)
    noncanonical = signature[:32] + validation._ED_L.to_bytes(32, "little")
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_ed25519(public, b"", noncanonical)
    mixed_public = bytes.fromhex("003789297ce02defa2f4bc7635d1d7ce99b96d76eb91d31f905101674ddab720")
    mixed_signature = bytes.fromhex("58666666666666666666666666666666666666666666666666666666666666669b6eab6a8b6012162473230a43304a832f5deff5d6eef30cafe3cbfefb427603")
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_ed25519(mixed_public, b"plamen-op4-mixed-order-test", mixed_signature)


def test_ed25519_cryptography_differential_and_mutation():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes_raw()
    message = b"retained operation-4 semantic receipt"
    signature = private.sign(message)
    validation._verify_ed25519(public, message, signature)
    mutated = bytearray(signature)
    mutated[17] ^= 1
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_ed25519(public, message, bytes(mutated))


def test_p256_cryptography_differential_and_mutation():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    private = ec.generate_private_key(ec.SECP256R1())
    public_numbers = private.public_key().public_numbers()
    message = b"operation-4 P-256 differential"
    signature = private.sign(message, ec.ECDSA(hashes.SHA256()))
    validation._verify_p256_public((public_numbers.x, public_numbers.y), message, signature)
    mutated = bytearray(signature)
    mutated[-1] ^= 1
    with pytest.raises(validation.NativeOperation4ValidationError):
        validation._verify_p256_public((public_numbers.x, public_numbers.y), message, bytes(mutated))


@pytest.mark.skipif(os.uname().sysname != "Darwin", reason="Darwin mapped-vnode attestation")
def test_sandboxed_suspended_python_attests_actual_mapped_vnode(tmp_path):
    library_path = tmp_path / "liboperation4-helper.dylib"
    compiled = subprocess.run([
        "/usr/bin/clang", "-std=c11", "-Wall", "-Wextra", "-Werror",
        "-DPLAMEN_NATIVE_OPERATION4_TESTING",
        "-I", str(ROOT / "native" / "darwin"), "-dynamiclib",
        str(ROOT / "native" / "darwin" / "plamen_native_operation4_helper_v1.c"),
        "-lproc", "-o", str(library_path),
    ], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert compiled.returncode == 0, compiled.stderr.decode("utf-8", "replace")
    library = ctypes.CDLL(str(library_path))
    attest = library.plamen_native_operation4_attest_python_for_testing_v1
    attest.argtypes = [ctypes.c_int, ctypes.c_int]
    attest.restype = ctypes.c_int
    python_fd = os.open(pathlib.Path(os.sys.executable).resolve(), os.O_RDONLY | os.O_CLOEXEC)
    wrong_fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
    try:
        assert attest(python_fd, python_fd) == 0
        assert attest(python_fd, wrong_fd) != 0
    finally:
        os.close(wrong_fd)
        os.close(python_fd)
