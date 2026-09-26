import base64
import copy
import hashlib
import io
import json
import tarfile
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from scripts import backend_acquisition as authority
from scripts import plamen_mcp_runtime as mcp_runtime


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "verification_policy" / "native_backend_acquisition.v2.json"


def _policy_with_test_registry_key():
    policy, _digest = authority.load_policy(POLICY_PATH)
    policy = copy.deepcopy(policy)
    private = ec.generate_private_key(ec.SECP256R1())
    der = private.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    keyid = "SHA256:" + base64.b64encode(hashlib.sha256(der).digest()).decode()
    policy["npm_registry"]["signature_keys"] = [{
        "expires": None,
        "key": base64.b64encode(der).decode(),
        "keyid": keyid,
        "keytype": "ecdsa-sha2-nistp256",
        "scheme": "ecdsa-sha2-nistp256",
    }]
    return policy, private, keyid


def _signed_metadata(
    selector, version, policy, private, keyid, *, platform=False,
    platform_name="darwin-arm64",
):
    package = policy["backends"][selector]["npm_package"]
    if platform:
        suffix = platform_name
        if selector == "claude":
            package += "-" + suffix
            actual_version = version
        else:
            actual_version = version + "-" + suffix
    else:
        actual_version = version
    leaf = package.rsplit("/", 1)[-1]
    integrity = "sha512-" + base64.b64encode(b"x" * 64).decode()
    message = f"{package}@{actual_version}:{integrity}".encode()
    signature = base64.b64encode(
        private.sign(message, ec.ECDSA(hashes.SHA256()))
    ).decode()
    dist = {
        "integrity": integrity,
        "shasum": "1" * 40,
        "tarball": f"https://registry.npmjs.org/{package}/-/{leaf}-{actual_version}.tgz",
        "signatures": [{"keyid": keyid, "sig": signature}],
    }
    if selector == "codex":
        dist["attestations"] = {
            "url": (
                "https://registry.npmjs.org/-/npm/v1/attestations/"
                f"@openai%2fcodex@{actual_version}"
            ),
            "provenance": {"predicateType": "https://slsa.dev/provenance/v1"},
        }
    metadata = {
        "name": package,
        "version": actual_version,
        "dist": dist,
        "maintainers": [{
            "email": "release" + policy["backends"][selector]["publisher"][
                "npm_maintainer_email_suffix"
            ],
        }],
    }
    if not platform:
        prefix = "claude-code" if selector == "claude" else "codex"
        install_name = (
            "@anthropic-ai/" if selector == "claude" else "@openai/"
        ) + prefix + "-" + platform_name
        metadata["optionalDependencies"] = {
            install_name: (
                version if selector == "claude"
                else f"npm:@openai/codex@{version}-{platform_name}"
            )
        }
    if selector == "codex":
        metadata["_npmUser"] = {
            "trustedPublisher": {"id": "github", "oidcConfigId": "oidc:test"},
        }
    return metadata


def _resolution(selector="claude", platform_name="darwin-arm64"):
    policy, private, keyid = _policy_with_test_registry_key()
    version = "9.8.7"
    package_platform = (
        platform_name[:-5]
        if selector == "codex" and platform_name.endswith("-musl")
        else platform_name
    )
    main = _signed_metadata(
        selector, version, policy, private, keyid,
        platform_name=(platform_name if selector == "claude" else package_platform),
    )
    result = authority.validate_npm_release_metadata(selector, main, policy)
    platform = _signed_metadata(
        selector, version, policy, private, keyid, platform=True,
        platform_name=(platform_name if selector == "claude" else package_platform),
    )
    pdist = platform["dist"]
    result["platform_package"] = {
        "install_name": (
            "@anthropic-ai/claude-code-" + platform_name
            if selector == "claude" else "@openai/codex-" + package_platform
        ),
        "package": platform["name"],
        "version": platform["version"],
        "metadata_url": authority.exact_metadata_url(
            policy, platform["name"], platform["version"],
        ),
        "metadata_sha256": authority.sha256_bytes(authority.canonical_json(platform)),
        "tarball_url": pdist["tarball"],
        "integrity": pdist["integrity"],
        "shasum": pdist["shasum"],
        "registry_signature": pdist["signatures"][0],
        "provenance": (
            {"predicate_type": "https://slsa.dev/provenance/v1",
             "url": pdist["attestations"]["url"]}
            if selector == "codex" else None
        ),
    }
    return policy, result


def test_checked_policy_is_canonical_and_never_pins_release():
    policy, digest = authority.load_policy(POLICY_PATH)
    assert len(digest) == 64
    raw = POLICY_PATH.read_bytes()
    assert raw == authority.canonical_json(policy) + b"\n"
    assert b"2.1.270" not in raw and b"0.154.0" not in raw
    assert policy["materialization"]["audit_time_resolution"] == "FORBIDDEN"


def test_policy_semantic_mutations_fail_closed(tmp_path):
    policy, _digest = authority.load_policy(POLICY_PATH)
    mutations = (
        lambda value: value["materialization"].update(tls_minimum="1.0"),
        lambda value: value["materialization"].update(lifecycle_scripts="ALLOWED"),
        lambda value: value["npm_registry"]["signature_keys"][0].update(
            keyid="SHA256:" + "A" * 43,
        ),
        lambda value: value["backends"]["claude"]["cli_contract"].update(
            help_required_flags=["--model"],
        ),
    )
    for index, mutation in enumerate(mutations):
        forged = copy.deepcopy(policy)
        mutation(forged)
        path = tmp_path / f"policy-{index}.json"
        path.write_bytes(authority.canonical_json(forged) + b"\n")
        with pytest.raises(authority.BackendAcquisitionError):
            authority.load_policy(path)


def test_safety_lock_excludes_dynamic_backends():
    package = json.loads((ROOT / "mcp-packages/package.json").read_text())
    lock = json.loads((ROOT / "mcp-packages/package-lock.json").read_text())
    forbidden = {"@anthropic-ai/claude-code", "@openai/codex"}
    assert forbidden.isdisjoint(package["dependencies"])
    assert forbidden.isdisjoint(lock["packages"][""]["dependencies"])
    assert not any(
        path.startswith("node_modules/@anthropic-ai/claude-code")
        or path.startswith("node_modules/@openai/codex")
        for path in lock["packages"]
    )


def test_resolver_calls_each_latest_once_and_joins_claude_manifest():
    policy, private, keyid = _policy_with_test_registry_key()
    version = "9.8.7"
    calls = []
    fixtures = {}
    for selector in ("claude", "codex"):
        main = _signed_metadata(selector, version, policy, private, keyid)
        fixtures[authority.latest_metadata_url(policy, selector)] = main
        platform = _signed_metadata(
            selector, version, policy, private, keyid, platform=True,
        )
        fixtures[authority.exact_metadata_url(
            policy, platform["name"], platform["version"],
        )] = platform
    latest_url = policy["backends"]["claude"]["release"]["latest_url"]
    manifest_url = policy["backends"]["claude"]["release"][
        "manifest_url_template"
    ].format(version=version)
    fixtures[manifest_url] = {
        "version": version, "commit": "a" * 40,
        "platforms": {"darwin-arm64": {
            "binary": "claude", "checksum": "b" * 64, "size": 123,
        }},
    }

    def fetch_json(url):
        calls.append(url)
        return fixtures[url]

    def fetch_bytes(url):
        calls.append(url)
        assert url == latest_url
        return (version + "\n").encode()

    resolved = authority.resolve_latest_backends(
        policy, fetch_json=fetch_json, fetch_bytes=fetch_bytes,
        platform="darwin-arm64",
    )
    assert {name: row["version"] for name, row in resolved.items()} == {
        "claude": version, "codex": version,
    }
    assert calls.count(authority.latest_metadata_url(policy, "claude")) == 1
    assert calls.count(authority.latest_metadata_url(policy, "codex")) == 1
    assert resolved["claude"]["upstream_release"]["commit"] == "a" * 40


def test_linux_musl_uses_claude_musl_and_codex_gnu_package():
    policy, private, keyid = _policy_with_test_registry_key()
    version = "9.8.7"
    fixtures = {}
    for selector in ("claude", "codex"):
        main_platform = (
            "linux-x64-musl" if selector == "claude" else "linux-x64"
        )
        main = _signed_metadata(
            selector, version, policy, private, keyid,
            platform_name=main_platform,
        )
        fixtures[authority.latest_metadata_url(policy, selector)] = main
        native = _signed_metadata(
            selector, version, policy, private, keyid, platform=True,
            platform_name=main_platform,
        )
        fixtures[authority.exact_metadata_url(
            policy, native["name"], native["version"],
        )] = native
    latest_url = policy["backends"]["claude"]["release"]["latest_url"]
    manifest_url = policy["backends"]["claude"]["release"][
        "manifest_url_template"
    ].format(version=version)
    fixtures[manifest_url] = {
        "version": version, "commit": "a" * 40,
        "platforms": {"linux-x64-musl": {
            "binary": "claude", "checksum": "b" * 64, "size": 123,
        }},
    }

    resolved = authority.resolve_latest_backends(
        policy, fetch_json=lambda url: fixtures[url],
        fetch_bytes=lambda url: (version + "\n").encode()
        if url == latest_url else b"", platform="linux-x64-musl",
    )
    assert resolved["claude"]["platform_package"]["install_name"] == (
        "@anthropic-ai/claude-code-linux-x64-musl"
    )
    assert resolved["codex"]["platform_package"]["install_name"] == (
        "@openai/codex-linux-x64"
    )


def test_registry_signature_publisher_and_provenance_fail_closed():
    policy, private, keyid = _policy_with_test_registry_key()
    metadata = _signed_metadata("codex", "9.8.7", policy, private, keyid)
    for mutation, match in (
        (lambda value: value["dist"]["signatures"][0].update(sig="AAAA"), "signature"),
        (lambda value: value.update(maintainers=[]), "publisher"),
        (lambda value: value["dist"].pop("attestations"), "provenance"),
        (lambda value: value["dist"].update(tarball="https://evil.test/x.tgz"), "tarball"),
    ):
        forged = copy.deepcopy(metadata)
        mutation(forged)
        with pytest.raises(authority.BackendAcquisitionError, match=match):
            authority.validate_npm_release_metadata("codex", forged, policy)


def test_archive_integrity_and_safe_member_census():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("package/bin/codex")
        body = b"binary"
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    payload = stream.getvalue()
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    row = authority.authenticate_archive_payload(
        payload, source_url="https://registry.npmjs.org/x.tgz",
        expected_integrity=integrity,
        selected_member_pattern=r"package/bin/codex",
    )
    assert row["selected_member"] == "package/bin/codex"
    with pytest.raises(authority.BackendAcquisitionError, match="sha512"):
        authority.authenticate_archive_payload(
            payload + b"x", source_url=row["source_url"],
            expected_integrity=integrity,
            selected_member_pattern=r"package/bin/codex",
        )


def _receipt(selector="claude", platform_name="darwin-arm64"):
    policy, resolution = _resolution(selector, platform_name)
    policy_digest = authority.sha256_bytes(
        authority.canonical_json(policy) + b"\n"
    )
    signing = ed25519.Ed25519PrivateKey.generate()
    public_raw = signing.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    signing_key_id = hashlib.sha256(public_raw).hexdigest()

    def signer(raw):
        return {"scheme": "ed25519", "key_id": signing_key_id, "signature": signing.sign(raw).hex()}

    version = resolution["version"]
    executable_sha = "b" * 64
    executable_size = 123
    upstream = None
    if selector == "claude":
        upstream = {
            "latest_url": policy["backends"]["claude"]["release"]["latest_url"],
            "latest_sha256": "1" * 64,
            "manifest_url": policy["backends"]["claude"]["release"][
                "manifest_url_template"
            ].format(version=version),
            "manifest_sha256": "2" * 64, "manifest_size": 100,
            "commit": "3" * 40, "platform": platform_name,
            "executable_sha256": executable_sha,
            "executable_size": executable_size,
        }
    required = policy["backends"][selector]["cli_contract"][
        "help_required_flags" if selector == "claude" else "exec_help_required_flags"
    ]
    common = {
        "returncode": 0, "stdout_sha256": "4" * 64,
        "stderr_sha256": "5" * 64,
    }
    receipt = authority.build_generation_receipt(
        selector=selector, policy_sha256=policy_digest, resolution=resolution,
        resolved_release=resolution["platform_package"]["version"],
        upstream=upstream,
        transport={"tls_minimum": "1.2", "redirect_count": 0,
                   "credentials": "FORBIDDEN", "proxy_environment": "IGNORED",
                   "endpoints_sha256": "6" * 64},
        payload={"source_url": resolution["platform_package"]["tarball_url"],
                 "size": 321, "sha256": "7" * 64,
                 "sha512_sri": resolution["platform_package"]["integrity"],
                 "archive_format": "tar.gz", "member_count": 3,
                 "member_roster_sha256": "8" * 64,
                 "selected_member": (
                     "package/claude" if selector == "claude"
                     else "package/vendor/test/bin/codex"
                 ),
                 "path_traversal_rejected": True},
        installed={"platform": platform_name, "relative_path": (
                       "node_modules/@anthropic-ai/claude-code/bin/claude.exe"
                       if selector == "claude" else
                       "node_modules/@openai/codex-test/vendor/test/bin/codex"
                   ), "executable_size": executable_size,
                   "executable_sha256": executable_sha, "closure_count": 3,
                   "closure_bytes": 456, "closure_sha256": "9" * 64,
                   "code_signature": (
                       {"mode": "APPLE_DEVELOPER_ID",
                        "identifier": policy["backends"][selector]["publisher"]["apple_identifier"],
                        "team_identifier": policy["backends"][selector]["publisher"]["apple_team_identifier"],
                        "cdhash_sha256": "a" * 64}
                       if platform_name.startswith("darwin") else
                       {"mode": "REGISTRY_SIGNATURE_ONLY", "identifier": None,
                        "team_identifier": None, "cdhash_sha256": None}
                   )},
        probes={
            "version": {**common, "argv": ["--version"],
                        "normalized_output": (f"{version} (Claude Code)" if selector == "claude" else f"codex-cli {version}"),
                        "observed_contract": []},
            "help": {**common, "argv": (["--help"] if selector == "claude" else ["exec", "--help"]),
                     "normalized_output": "", "observed_contract": required},
        },
        install={"transaction_id": "txn-test", "generation_id": "npm-" + "c" * 64,
                 "install_receipt_sha256": "d" * 64,
                 "source_manifest_sha256": "e" * 64,
                 "source_manifest_size": 111},
        signer=signer,
    )

    def verifier(raw, authentication):
        try:
            signing.public_key().verify(bytes.fromhex(authentication["signature"]), raw)
            return True
        except Exception:
            return False

    return policy, policy_digest, receipt, verifier


def test_generation_receipt_replays_and_adversarial_mutations_fail():
    policy, digest, receipt, verifier = _receipt("claude")
    assert authority.validate_generation_receipt(
        receipt, policy=policy, policy_sha256=digest, verifier=verifier,
    ).resolved_version == "9.8.7"
    mutations = (
        lambda value: value.update(extra=True),
        lambda value: value.update(resolved_version="9.8.8"),
        lambda value: value["payload"].update(source_url="https://evil.test/x"),
        lambda value: value["installed"].update(executable_sha256="e" * 64),
        lambda value: value["probes"]["version"].update(normalized_output="forged"),
        lambda value: value.update(selector="codex"),
    )
    for mutation in mutations:
        forged = copy.deepcopy(receipt)
        mutation(forged)
        with pytest.raises(authority.BackendAcquisitionError):
            authority.validate_generation_receipt(
                forged, policy=policy, policy_sha256=digest, verifier=verifier,
            )


@pytest.mark.parametrize("platform_name", ["linux-x64", "win32-x64"])
def test_non_darwin_receipt_uses_registry_signature_mode(platform_name):
    policy, digest, receipt, verifier = _receipt("claude", platform_name)
    replayed = authority.validate_generation_receipt(
        receipt, policy=policy, policy_sha256=digest, verifier=verifier,
    )
    assert replayed.resolved_version == "9.8.7"
    forged = copy.deepcopy(receipt)
    forged["installed"]["code_signature"] = {
        "mode": "WINDOWS_AUTHENTICODE", "identifier": "publisher",
        "team_identifier": None, "cdhash_sha256": "a" * 64,
    }
    candidate = dict(forged)
    candidate.pop("receipt_sha256")
    forged["receipt_sha256"] = authority.sha256_bytes(
        authority.canonical_json(candidate)
    )
    with pytest.raises(authority.BackendAcquisitionError, match="publisher mode"):
        authority.validate_generation_receipt(
            forged, policy=policy, policy_sha256=digest,
            verifier=lambda *_args: True,
        )


def _dynamic_finalizer_policy(version="9.8.7"):
    return {
        "schema": "plamen.mcp_finalizer_policy.v1",
        "output_entrypoint": "schema-sanitizer.js",
        "require_ordinary_file": True,
        "require_single_link": True,
        "post_npm_actions": [{
            "schema": "plamen.claude_native_finalizer.v2",
            "package": "@anthropic-ai/claude-code", "version": version,
            "script": "node_modules/@anthropic-ai/claude-code/install.cjs",
            "output": "node_modules/@anthropic-ai/claude-code/bin/claude.exe",
            "probe_args": ["--version"],
            "acquisition_policy_sha256": "1" * 64,
            "registry_metadata_sha256": "2" * 64,
            "upstream_manifest_sha256": "3" * 64,
            "expected_executable_sha256": "4" * 64,
            "expected_executable_size": 123,
        }],
    }


def test_runtime_finalizer_policy_accepts_receipt_bound_dynamic_version_only():
    policy = _dynamic_finalizer_policy()
    assert mcp_runtime._validate_finalizer_policy(policy) == policy
    for mutation in (
        lambda row: row.update(version="latest"),
        lambda row: row.update(acquisition_policy_sha256="x" * 64),
        lambda row: row.pop("upstream_manifest_sha256"),
    ):
        forged = copy.deepcopy(policy)
        mutation(forged["post_npm_actions"][0])
        with pytest.raises(mcp_runtime.MCPRuntimeSecurityError, match="finalizer"):
            mcp_runtime._validate_finalizer_policy(forged)


def test_claude_finalizer_checks_manifest_bytes_before_version_success(tmp_path):
    package = tmp_path / "node_modules/@anthropic-ai/claude-code"
    (package / "bin").mkdir(parents=True)
    (package / "install.cjs").write_text("// reviewed", encoding="ascii")
    executable = package / "bin/claude.exe"
    executable.write_bytes(b"exact-native")
    executable.chmod(0o700)
    digest = hashlib.sha256(b"exact-native").hexdigest()
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        output = "9.8.7 (Claude Code)\n" if argv[-1:] == ["--version"] else ""
        return subprocess.CompletedProcess(argv, 0, output, "")

    result = mcp_runtime.finalize_claude_native(
        tmp_path, version="9.8.7",
        acquisition_policy_sha256="1" * 64,
        registry_metadata_sha256="2" * 64,
        upstream_manifest_sha256="3" * 64,
        expected_executable_sha256=digest,
        expected_executable_size=len(b"exact-native"),
        node_executable=sys.executable, environment={}, runner=runner,
    )
    assert result["sha256"] == digest and len(calls) == 2
    with pytest.raises(
        mcp_runtime.MCPRuntimeSecurityError, match="acquisition manifest",
    ):
        mcp_runtime.finalize_claude_native(
            tmp_path, version="9.8.7",
            acquisition_policy_sha256="1" * 64,
            registry_metadata_sha256="2" * 64,
            upstream_manifest_sha256="3" * 64,
            expected_executable_sha256="f" * 64,
            expected_executable_size=len(b"exact-native"),
            node_executable=sys.executable, environment={}, runner=runner,
        )


def test_native_retained_binder_wire_has_no_lf_before_fixed_footer(monkeypatch):
    public = b"p" * 32
    source = b"source-manifest"
    receipt = {
        "authentication": {"key_id": hashlib.sha256(public).hexdigest()},
        "schema": authority.RECEIPT_SCHEMA,
    }
    projection = authority.ValidatedBackendGeneration(
        selector="claude", resolved_version="9.8.7", resolved_release="9.8.7",
        executable_sha256="1" * 64, executable_size=1,
        closure_sha256="2" * 64, closure_count=1, closure_bytes=1,
        receipt_sha256="3" * 64,
        signer_key_id=hashlib.sha256(public).hexdigest(),
        generation_id="npm-" + "4" * 64, relative_path="backend/claude",
        transaction_id="txn", install_receipt_sha256="5" * 64,
        source_manifest_sha256=hashlib.sha256(source).hexdigest(),
        source_manifest_size=len(source),
    )
    semantic = authority.canonical_json(receipt) + b"f" * 512
    rows = {1: b"payload", 2: semantic, 3: source, 4: public}
    monkeypatch.setattr(
        authority, "_read_retained_regular_fd",
        lambda fd, _label, _maximum: rows[fd],
    )
    monkeypatch.setattr(
        authority, "validate_generation_receipt",
        lambda *_args, **_kwargs: projection,
    )
    bound = authority.bind_retained_generation_authority(
        receipt=receipt, policy={}, policy_sha256="0" * 64,
        verifier=lambda *_args: True, payload_fd=1, semantic_receipt_fd=2,
        source_manifest_fd=3, verifier_public_key_fd=4,
    )
    assert bound.generation is projection
    rows[2] = authority.canonical_json(receipt) + b"\n" + b"f" * 512
    with pytest.raises(authority.BackendAcquisitionError, match="semantic receipt"):
        authority.bind_retained_generation_authority(
            receipt=receipt, policy={}, policy_sha256="0" * 64,
            verifier=lambda *_args: True, payload_fd=1, semantic_receipt_fd=2,
            source_manifest_fd=3, verifier_public_key_fd=4,
        )
