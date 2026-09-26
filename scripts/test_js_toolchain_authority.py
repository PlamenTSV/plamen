"""Focused tests for the pinned Node/Yarn Classic authority."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil

import pytest

import js_toolchain_authority as JS
import render_js_toolchain_bootstrap as BOOTSTRAP_RENDERER
import toolchain_control_authority as CONTROL


ROOT = Path(__file__).resolve().parents[1]
ANCHOR = ROOT / JS.BOOTSTRAP_RELATIVE_PATH


@pytest.fixture(scope="session")
def trusted_bootstrap() -> JS.TrustedJSBootstrapAuthority:
    anchor_sha256 = hashlib.sha256(ANCHOR.read_bytes()).hexdigest()
    source_census_sha256 = hashlib.sha256(
        b"authenticated-test-source-census"
    ).hexdigest()
    provenance_sha256 = JS.bootstrap_install_provenance_sha256(
        anchor_relative_path=JS.BOOTSTRAP_RELATIVE_PATH.as_posix(),
        anchor_sha256=anchor_sha256,
        source_census_sha256=source_census_sha256,
        trust_boundary=JS.BOOTSTRAP_TRUST_BOUNDARY,
    )
    return JS.TrustedJSBootstrapAuthority(
        anchor_relative_path=JS.BOOTSTRAP_RELATIVE_PATH.as_posix(),
        anchor_sha256=anchor_sha256,
        source_census_sha256=source_census_sha256,
        install_provenance_sha256=provenance_sha256,
        trust_boundary=JS.BOOTSTRAP_TRUST_BOUNDARY,
    )
MANIFEST = ROOT / JS.MANIFEST_RELATIVE_PATH


def test_reviewed_bootstrap_anchor_matches_deterministic_release_render():
    rendered = BOOTSTRAP_RENDERER.render_anchor(ROOT)
    observed = ANCHOR.read_bytes()
    assert rendered == observed
    assert hashlib.sha256(observed).hexdigest() == (
        "c9609f874818af35c8ea4fbab93ce37fe348be58b61a710b0ecb2833905fcbfc"
    )
    payload = json.loads(observed.decode("ascii"))
    archive_rows = {
        row["path"]: (row["sha256"], row["size"])
        for row in payload["signed_set"]
        if row["kind"] == "runtime-data"
    }
    assert archive_rows == BOOTSTRAP_RENDERER.ARCHIVE_IDENTITIES


@pytest.fixture(scope="session")
def current_runtime_closure(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("js-runtime-closure") / "closure.json"
    member_paths = {
        "scripts/js_dependency_materializer_authority.py",
        "scripts/js_dependency_materializer_runtime.py",
        "scripts/js_lock_authority.py",
        "scripts/js_toolchain_authority.py",
        JS.BOOTSTRAP_RELATIVE_PATH.as_posix(),
        JS.MANIFEST_RELATIVE_PATH.as_posix(),
    }
    policy = json.loads(MANIFEST.read_text(encoding="utf-8"))
    member_paths.update(row["packaged_path"] for row in policy["artifacts"])
    assets = []
    for relative in sorted(member_paths):
        raw = (ROOT / relative).read_bytes()
        if relative.endswith(".py"):
            kind = "python-source"
            digest_mode = "utf8-lf-v1"
            canonical = raw.decode("utf-8").replace("\r\n", "\n").encode()
        elif relative.startswith("verification_policy/"):
            kind = "control"
            digest_mode = "utf8-lf-v1"
            canonical = raw.decode("utf-8").replace("\r\n", "\n").encode()
        else:
            kind = "runtime-data"
            digest_mode = "raw-v1"
            canonical = raw
        assets.append(
            {
                "digest_mode": digest_mode,
                "kind": kind,
                "path": relative,
                "sha256": hashlib.sha256(canonical).hexdigest(),
            }
        )
    closure_relative = JS.RUNTIME_CLOSURE_RELATIVE_PATH.as_posix()
    payload = {
        "assets": assets,
        "derivation": "python-ast-typed-runtime-closure-v2",
        "entrypoints": ["scripts/js_toolchain_authority.py"],
        "files": sorted({*member_paths, closure_relative}),
        "manifest_control": {
            "kind": "control",
            "path": closure_relative,
        },
        "schema": JS.RUNTIME_CLOSURE_SCHEMA,
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="ascii",
        newline="\n",
    )
    return path


def _load(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> JS.AuthorityManifest:
    return JS.load_authority_manifest(
        ROOT,
        bootstrap_authority=trusted_bootstrap,
        runtime_closure_path=current_runtime_closure,
    )


def _receipt_bytes(
    authority: JS.AuthorityManifest,
    artifact: JS.ArtifactIdentity,
    *,
    destination_root: str = "/private/toolchain/extracted",
) -> bytes:
    policy = artifact.extraction_policy
    value = {
        "archive": {
            "archive_format": artifact.archive_format,
            "archive_root": artifact.archive_root,
            "artifact_id": artifact.artifact_id,
            "path": artifact.packaged_path,
            "sha256": artifact.sha256,
            "size": artifact.size,
        },
        "bootstrap": {
            "anchor_sha256": authority.bootstrap_anchor_sha256,
            "signed_set_sha256": authority.bootstrap_signed_set_sha256,
        },
        "census": {
            "directory_count": policy.directory_count,
            "expanded_regular_file_bytes": (
                policy.max_expanded_regular_file_bytes
            ),
            "max_path_utf8_bytes": policy.max_path_utf8_bytes,
            "max_single_regular_file_bytes": (
                policy.max_single_regular_file_bytes
            ),
            "member_count": policy.max_members,
            "regular_file_count": policy.regular_file_count,
            "rejected_member_count": 0,
            "reviewed_skipped_symlinks_sha256": (
                policy.reviewed_skipped_symlinks_sha256
            ),
            "skipped_symlink_count": policy.skipped_symlink_count,
        },
        "destination": {
            "identity_sha256": hashlib.sha256(b"destination").hexdigest(),
            "root": destination_root,
            "sealed_state": "IMMUTABLE_READ_ONLY_VERIFIED",
        },
        "parser": {
            "id": policy.parser_id,
            "path": policy.parser_path,
            "sha256": policy.parser_sha256,
        },
        "policy_sha256": policy.policy_sha256,
        "schema": JS.EXTRACTION_RECEIPT_SCHEMA,
        "terminal": {
            "destination_alias_free": True,
            "exit_code": 0,
            "network_mode": "NO_NETWORK",
            "source_archive_unchanged": True,
        },
        "tree": {
            "algorithm": "PLAMEN_CANONICAL_TREE_SHA256_V1",
            "executable_relative_path": (
                f"{artifact.archive_root}/{artifact.executable}"
            ),
            "file_count": policy.regular_file_count,
            "logical_bytes": policy.max_expanded_regular_file_bytes,
            "sha256": hashlib.sha256(b"extracted-tree").hexdigest(),
        },
    }
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def test_external_bootstrap_anchor_is_acyclic_and_exact(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    paths = {row.path for row in authority.bootstrap_members}
    assert JS.BOOTSTRAP_RELATIVE_PATH.as_posix() not in paths
    assert paths == {
        "scripts/js_dependency_materializer_authority.py",
        "scripts/js_dependency_materializer_runtime.py",
        "scripts/js_lock_authority.py",
        "scripts/js_toolchain_authority.py",
        "verification_policy/js_toolchain_authority.v1.json",
        *(row.packaged_path for row in authority.artifacts),
    }
    assert authority.bootstrap_anchor_sha256 == trusted_bootstrap.anchor_sha256
    assert "runtime_closure_sha256" not in ANCHOR.read_text(encoding="utf-8")


def test_ambient_or_mismatched_bootstrap_values_never_authorize(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="BOOTSTRAP_INSTALL_PROVENANCE_BINDING_INVALID",
    ):
        JS.load_authority_manifest(
            ROOT,
            bootstrap_authority=replace(
                trusted_bootstrap,
                install_provenance_sha256="0" * 64,
            ),
            runtime_closure_path=current_runtime_closure,
        )
    forged_anchor_sha256 = hashlib.sha256(
        ANCHOR.read_bytes() + b"\n"
    ).hexdigest()
    forged = replace(
        trusted_bootstrap,
        anchor_sha256=forged_anchor_sha256,
        install_provenance_sha256=JS.bootstrap_install_provenance_sha256(
            anchor_relative_path=JS.BOOTSTRAP_RELATIVE_PATH.as_posix(),
            anchor_sha256=forged_anchor_sha256,
            source_census_sha256=trusted_bootstrap.source_census_sha256,
            trust_boundary=JS.BOOTSTRAP_TRUST_BOUNDARY,
        ),
    )
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="BOOTSTRAP_ANCHOR_DIGEST_MISMATCH",
    ):
        JS.load_authority_manifest(
            ROOT,
            bootstrap_authority=forged,
            runtime_closure_path=current_runtime_closure,
        )


def test_module_and_updated_observed_closure_cannot_bypass_anchor(
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The observed closure cannot authorize a same-size module mutation."""

    anchor = json.loads(ANCHOR.read_text(encoding="utf-8"))
    identities = {row["path"]: row["sha256"] for row in anchor["signed_set"]}
    target = "scripts/js_toolchain_authority.py"

    def observed_digest(
        path: Path,
        *,
        digest_mode: str,
        maximum_bytes: int,
    ) -> str:
        del digest_mode, maximum_bytes
        relative = path.relative_to(ROOT).as_posix()
        if relative == target:
            return "0" * 64
        return identities[relative]

    monkeypatch.setattr(JS, "_closure_file_digest", observed_digest)
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="BOOTSTRAP_MEMBER_DIGEST_MISMATCH",
    ):
        JS._load_bootstrap_anchor(ROOT, trusted_bootstrap)


def test_current_manifest_and_observed_runtime_closure_are_exact(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    assert authority.content_sha256 == JS.EXPECTED_MANIFEST_CONTENT_SHA256
    assert authority.runtime_closure_sha256 == hashlib.sha256(
        current_runtime_closure.read_bytes()
    ).hexdigest()
    assert tuple(row.artifact_id for row in authority.artifacts) == (
        "node-windows-x86_64",
        "node-windows-arm64",
        "node-linux-x86_64",
        "node-linux-arm64",
        "node-darwin-x86_64",
        "node-darwin-arm64",
        "yarn-classic-noarch",
    )
    assert {row.version for row in authority.artifacts[:-1]} == {"24.20.0"}
    assert authority.artifacts[-1].version == "1.22.22"
    assert authority.artifacts[-1].sha256 == JS.YARN_ARCHIVE_SHA256
    assert authority.artifacts[-1].size == JS.YARN_ARCHIVE_SIZE
    assert authority.artifacts[-1].identity_state == (
        "CONTENT_DIGEST_AND_SIGNATURE_PINNED"
    )
    assert tuple(row.size for row in authority.artifacts) == (
        37_539_751,
        33_621_271,
        31_838_904,
        30_778_928,
        54_021_618,
        52_813_331,
        1_247_457,
    )
    policy = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert policy["declared_packaging_debt"] == []
    assert "runtime_closure_sha256" not in policy["manifest_authentication"]
    assert "EXPECTED_RUNTIME_CLOSURE_SHA256" not in (
        ROOT / "scripts/js_toolchain_authority.py"
    ).read_text(encoding="utf-8")


def test_manifest_or_runtime_closure_drift_fails_authentication(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    manifest = tmp_path / "manifest.json"
    closure = tmp_path / "closure.json"
    manifest.write_bytes(MANIFEST.read_bytes())
    closure.write_bytes(current_runtime_closure.read_bytes())

    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["toolchain"]["yarn_version"] = "1.22.21"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="MANIFEST_AUTHENTICATION_FAILED",
    ):
        JS.load_authority_manifest(
            ROOT,
            bootstrap_authority=trusted_bootstrap,
            manifest_path=manifest,
            runtime_closure_path=closure,
        )

    manifest.write_bytes(MANIFEST.read_bytes())
    original_digest = hashlib.sha256(closure.read_bytes()).hexdigest()
    closure.write_bytes(closure.read_bytes() + b"\n")
    admitted = JS.load_authority_manifest(
        ROOT,
        bootstrap_authority=trusted_bootstrap,
        manifest_path=manifest,
        runtime_closure_path=closure,
    )
    assert admitted.runtime_closure_sha256 != original_digest
    assert admitted.runtime_closure_sha256 == hashlib.sha256(
        closure.read_bytes()
    ).hexdigest()


def test_runtime_closure_missing_required_member_fails_closed(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    payload = json.loads(current_runtime_closure.read_text(encoding="utf-8"))
    missing = "runtime/toolchains/js/yarn/yarn-v1.22.22.tar.gz"
    payload["files"].remove(missing)
    payload["assets"] = [
        row for row in payload["assets"] if row["path"] != missing
    ]
    closure = tmp_path / "closure.json"
    closure.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="RUNTIME_CLOSURE_REQUIRED_MEMBERS_MISSING",
    ):
        JS.load_authority_manifest(
            ROOT,
            bootstrap_authority=trusted_bootstrap,
            runtime_closure_path=closure,
        )


def test_runtime_closure_same_size_archive_digest_tamper_fails_closed(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    payload = json.loads(current_runtime_closure.read_text(encoding="utf-8"))
    target = "runtime/toolchains/js/node/node-v24.20.0-linux-x64.tar.xz"
    row = next(row for row in payload["assets"] if row["path"] == target)
    row["sha256"] = ("0" if row["sha256"][0] != "0" else "1") + row[
        "sha256"
    ][1:]
    closure = tmp_path / "closure.json"
    closure.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="RUNTIME_CLOSURE_ARCHIVE_AUTHORITY_MISMATCH",
    ):
        JS.load_authority_manifest(
            ROOT,
            bootstrap_authority=trusted_bootstrap,
            runtime_closure_path=closure,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "self-shrink",
        "dependency-shrink-with-entrypoint",
        "duplicate-row",
        "missing-row",
    ],
)
def test_shared_runtime_closure_loader_rejects_incomplete_denominators(
    tmp_path: Path,
    mutation: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    entrypoint = "scripts/runtime_entry.py"
    dependency = "scripts/runtime_dependency.py"
    (tmp_path / entrypoint).write_text(
        "import runtime_dependency\n",
        encoding="utf-8",
        newline="\n",
    )
    (tmp_path / dependency).write_text(
        "VALUE = 1\n",
        encoding="utf-8",
        newline="\n",
    )
    (scripts / "toolchain_control_authority.py").write_text(
        "# independently included closure authority\n",
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(
        CONTROL,
        "_RUNTIME_ENTRYPOINTS",
        (entrypoint,),
    )
    closure_relative = JS.RUNTIME_CLOSURE_RELATIVE_PATH.as_posix()
    valid = tmp_path / closure_relative
    valid.parent.mkdir(parents=True)
    valid.write_bytes(CONTROL.render_runtime_closure_manifest(tmp_path))
    payload = json.loads(valid.read_text(encoding="utf-8"))
    assert CONTROL.load_runtime_closure_manifest(tmp_path)["files"] == payload[
        "files"
    ]
    if mutation == "self-shrink":
        payload["files"] = [closure_relative]
        payload["assets"] = []
    elif mutation == "dependency-shrink-with-entrypoint":
        payload["files"].remove(dependency)
        payload["assets"] = [
            row for row in payload["assets"] if row["path"] != dependency
        ]
    elif mutation == "duplicate-row":
        payload["files"].append("scripts/zz_duplicate_denominator.py")
        payload["files"].sort()
        payload["assets"].append(dict(payload["assets"][0]))
        payload["assets"].sort(key=lambda row: row["path"])
    else:
        payload["assets"].pop()
    destination = tmp_path / closure_relative
    destination.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(
        CONTROL.ToolchainControlError,
        match="toolchain runtime closure manifest",
    ):
        CONTROL.load_runtime_closure_manifest(tmp_path)


def test_shared_loader_rejects_shrink_retaining_all_public_entrypoints(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.loads(
        CONTROL.render_runtime_closure_manifest(ROOT).decode("ascii")
    )
    assert payload["entrypoints"] == list(CONTROL._RUNTIME_ENTRYPOINTS)
    assert len(payload["entrypoints"]) == 19
    assert set(payload["entrypoints"]).issubset(payload["files"])
    omitted_dependency = "scripts/js_dependency_materializer_authority.py"
    assert omitted_dependency not in payload["entrypoints"]
    payload["files"].remove(omitted_dependency)
    payload["assets"] = [
        row
        for row in payload["assets"]
        if row["path"] != omitted_dependency
    ]
    forged = (
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    ).encode("ascii")
    original_read = CONTROL._read_control

    def read_control(path: Path, label: str) -> bytes:
        if Path(path) == ROOT / CONTROL._RUNTIME_CLOSURE_PATH:
            return forged
        return original_read(path, label)

    monkeypatch.setattr(CONTROL, "_read_control", read_control)
    with pytest.raises(
        CONTROL.ToolchainControlError,
        match="independently derived runtime closure",
    ):
        CONTROL.load_runtime_closure_manifest(ROOT)


@pytest.mark.parametrize(
    ("os_name", "arch", "artifact_id"),
    [
        ("windows", "amd64", "node-windows-x86_64"),
        ("win32", "aarch64", "node-windows-arm64"),
        ("linux", "x64", "node-linux-x86_64"),
        ("linux", "arm64", "node-linux-arm64"),
        ("macos", "x86_64", "node-darwin-x86_64"),
        ("darwin", "aarch64", "node-darwin-arm64"),
    ],
)
def test_platform_selection_never_uses_path_or_corepack(
    os_name: str,
    arch: str,
    artifact_id: str,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    node, yarn = JS.select_artifacts(
        authority, os_name=os_name, arch=arch
    )
    assert node.artifact_id == artifact_id
    assert yarn.artifact_id == "yarn-classic-noarch"


def test_repository_packaged_artifacts_verify_for_every_platform(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    assert JS.classify_packaging_debt(authority, ROOT) == ()

    for os_name, arch in (
        ("windows", "x86_64"),
        ("windows", "arm64"),
        ("linux", "x86_64"),
        ("linux", "arm64"),
        ("darwin", "x86_64"),
        ("darwin", "arm64"),
    ):
        node, yarn = JS.select_artifacts(
            authority, os_name=os_name, arch=arch
        )
        packaged = JS.require_packaged_artifacts(
            authority, ROOT, os_name=os_name, arch=arch
        )
        assert dict(packaged) == {
            node.artifact_id: ROOT / node.packaged_path,
            yarn.artifact_id: ROOT / yarn.packaged_path,
        }


def test_real_archive_census_drives_tight_extraction_bounds(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    policies = {row.artifact_id: row.extraction_policy for row in authority.artifacts}
    assert policies["node-linux-x86_64"].max_members == 5_888
    assert (
        policies["node-linux-x86_64"].max_single_regular_file_bytes
        == 126_458_664
    )
    assert policies["node-linux-x86_64"].skipped_symlink_count == 3
    assert policies["node-windows-x86_64"].skipped_symlink_count == 0
    assert policies["yarn-classic-noarch"].max_members == 13
    for policy in policies.values():
        assert policy.type_policy.startswith("REJECT_HARDLINK")
        assert policy.symlink_policy == (
            "SKIP_EXACT_DIGEST_BOUND_ROSTER_NEVER_CREATE_LINKS_V1"
        )
        assert policy.parser_sha256 == next(
            row.sha256
            for row in authority.bootstrap_members
            if row.path == "scripts/js_toolchain_authority.py"
        )


def test_typed_extraction_receipt_is_parser_and_policy_bound(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    artifact, _ = JS.select_artifacts(
        authority,
        os_name="linux",
        arch="x86_64",
    )
    raw = _receipt_bytes(authority, artifact)
    receipt = JS.parse_toolchain_extraction_receipt(
        authority,
        artifact,
        raw,
        expected_destination_root="/private/toolchain/extracted",
        target_os="linux",
    )
    assert receipt.member_count == 5_888
    assert receipt.max_single_regular_file_bytes == 126_458_664
    assert receipt.skipped_symlink_count == 3
    assert receipt.receipt_sha256 == hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize(
    ("section", "field", "replacement", "code"),
    [
        ("parser", "sha256", "0" * 64, "EXTRACTION_RECEIPT_PARSER_IDENTITY_INVALID"),
        ("census", "member_count", 5_887, "EXTRACTION_RECEIPT_CENSUS_MISMATCH"),
        ("census", "rejected_member_count", 1, "EXTRACTION_RECEIPT_CENSUS_MISMATCH"),
        ("terminal", "destination_alias_free", False, "EXTRACTION_RECEIPT_TERMINAL_INVALID"),
    ],
)
def test_extraction_receipt_tamper_fails_closed(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
    section: str,
    field: str,
    replacement: object,
    code: str,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    artifact, _ = JS.select_artifacts(
        authority,
        os_name="linux",
        arch="x86_64",
    )
    payload = json.loads(_receipt_bytes(authority, artifact))
    payload[section][field] = replacement
    raw = (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("ascii")
    with pytest.raises(JS.JSToolchainAuthorityError, match=code):
        JS.parse_toolchain_extraction_receipt(
            authority,
            artifact,
            raw,
            expected_destination_root="/private/toolchain/extracted",
            target_os="linux",
        )


def test_missing_temp_copy_fails_closed(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    node, yarn = JS.select_artifacts(
        authority, os_name="linux", arch="arm64"
    )
    for artifact in (node, yarn):
        destination = tmp_path / artifact.packaged_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / artifact.packaged_path, destination)
    (tmp_path / yarn.packaged_path).unlink()

    with pytest.raises(JS.JSToolchainPackagingError) as raised:
        JS.require_packaged_artifacts(
            authority, tmp_path, os_name="linux", arch="arm64"
        )
    assert {(row.artifact_id, row.code) for row in raised.value.debt} == {
        ("yarn-classic-noarch", "PACKAGED_ARTIFACT_MISSING"),
    }


def test_same_size_digest_tamper_fails_closed(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    node, _yarn = JS.select_artifacts(
        authority, os_name="linux", arch="x86_64"
    )
    archive = tmp_path / node.packaged_path
    archive.parent.mkdir(parents=True)
    shutil.copy2(ROOT / node.packaged_path, archive)
    archive.chmod(0o600)
    with archive.open("r+b") as stream:
        first_byte = stream.read(1)
        assert first_byte
        stream.seek(0)
        stream.write(bytes([first_byte[0] ^ 0x01]))
    debt = JS.classify_packaging_debt(
        authority, tmp_path, artifacts=(node,)
    )
    assert debt == (
        JS.PackagingDebt(
            artifact_id=node.artifact_id,
            code="PACKAGED_ARTIFACT_DIGEST_MISMATCH",
            packaged_path=node.packaged_path,
        ),
    )


def test_yarn_size_tamper_fails_closed(
    tmp_path: Path,
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    yarn = authority.artifacts[-1]
    archive = tmp_path / yarn.packaged_path
    archive.parent.mkdir(parents=True)
    shutil.copy2(ROOT / yarn.packaged_path, archive)
    archive.chmod(0o600)
    archive.write_bytes(archive.read_bytes()[:-1])
    debt = JS.classify_packaging_debt(
        authority, tmp_path, artifacts=(yarn,)
    )
    assert debt == (
        JS.PackagingDebt(
            artifact_id="yarn-classic-noarch",
            code="PACKAGED_ARTIFACT_SIZE_MISMATCH",
            packaged_path=yarn.packaged_path,
        ),
    )


def test_signed_upstream_provenance_is_exact_and_mechanically_bound(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    assert {
        row.upstream_authentication for row in authority.artifacts[:-1]
    } == {"VERIFIED_NODEJS_CLEARSIGNED_SHA256_MANIFEST"}
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    provenance = payload["upstream_verification"]
    assert authority.upstream_verification_sha256 == hashlib.sha256(
        (
            json.dumps(
                provenance,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            )
            + "\n"
        ).encode("ascii")
    ).hexdigest()
    assert provenance["yarn"] == {
        "archive": {
            "sha256": JS.YARN_ARCHIVE_SHA256,
            "size": JS.YARN_ARCHIVE_SIZE,
            "source_url": (
                "https://github.com/yarnpkg/yarn/releases/download/"
                "v1.22.22/yarn-v1.22.22.tar.gz"
            ),
        },
        "detached_signature": {
            "sha256": "ce5a2cc19283cee2a4f931cc50769dcf695afb0dd40657d374f50f573bcb6cac",
            "size": 847,
            "source_url": (
                "https://github.com/yarnpkg/yarn/releases/download/"
                "v1.22.22/yarn-v1.22.22.tar.gz.asc"
            ),
        },
        "public_key": {
            "sha256": "63edc60568db873b70db03a3c4dd062a16c6b3d6e3015eb748edc234e6a4facd",
            "size": 23138,
            "source_commit": "8e1ecd1ab460f82245316a4cdd888aaad6e041a5",
            "source_url": (
                "https://raw.githubusercontent.com/yarnpkg/releases/"
                "8e1ecd1ab460f82245316a4cdd888aaad6e041a5/"
                "debian/pubkey.gpg"
            ),
        },
        "signer_fingerprint": "72ECF46A56B4AD39C907BBB71646B01B86E50310",
        "verification_kind": "OPENPGP_DETACHED_SIGNATURE",
        "verification_result": "SIGNATURE_VALID_AND_ARCHIVE_DIGEST_MATCHES",
    }
    assert provenance["node"]["signer_fingerprint"] == (
        "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"
    )
    assert provenance["node"]["signed_manifest"] == {
        "sha256": "8cc4c2dc94d07c7bfd4898ff1ca641d09e65e465becb50baecb4578ed93d95dc",
        "size": 3449,
        "source_url": "https://nodejs.org/dist/v24.20.0/SHASUMS256.txt.asc",
    }
    assert provenance["node"]["plaintext_manifest"]["sha256"] == (
        "ccf01a92bf3036a46551f02037b1d2347c5c52435642a951a3c9bec4f93c8272"
    )
    assert provenance["node"]["public_key"]["sha256"] == (
        "5115095e2f8010c75da052ecb1cfb3af630e084f0f8daa93a863557b01b0f90a"
    )


def test_closed_environments_are_ambient_free_and_phase_exact(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    roots = JS.writable_roots("/private/js-install", target_os="linux")
    offline = dict(
        JS.closed_environment(
            authority,
            node_binary="/runtime/node/bin/node",
            roots=roots,
            phase="offline",
            target_os="linux",
        )
    )
    online = dict(
        JS.closed_environment(
            authority,
            node_binary="/runtime/node/bin/node",
            roots=roots,
            phase="online",
            target_os="linux",
        )
    )
    assert offline["PATH"] == "/runtime/node/bin"
    assert offline["PLAMEN_JS_NETWORK_MODE"] == "NO_NETWORK"
    assert "PLAMEN_JS_EGRESS_TARGET_ID" not in offline
    assert online["PLAMEN_JS_NETWORK_MODE"] == (
        "VERIFIED_EXACT_LOCK_ORIGIN_ALLOWLIST"
    )
    assert online["PLAMEN_JS_EGRESS_TARGET_ID"] == "yarn-classic-registry"
    assert online["PLAMEN_JS_EGRESS_TARGET_AUTHORITY_SHA256"] == (
        authority.online_target.authority_sha256
    )
    forbidden = {
        "NODE_OPTIONS",
        "NODE_PATH",
        "COREPACK_HOME",
        "NPM_CONFIG_USERCONFIG",
        "YARN_RC_FILENAME",
        "HTTPS_PROXY",
        "HTTP_PROXY",
    }
    assert forbidden.isdisjoint(offline)
    assert forbidden.isdisjoint(online)
    assert offline["HOME"] == "/private/js-install/home"
    assert offline["YARN_CACHE_FOLDER"] == "/private/js-install/cache"
    assert offline["TMPDIR"] == "/private/js-install/temp"


def test_yarn_argv_is_absolute_fixed_and_network_phase_bound(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    roots = JS.writable_roots("/private/js-install", target_os="linux")
    shared = (
        "/runtime/node/bin/node",
        "/runtime/yarn/bin/yarn.js",
        "install",
        "--no-default-rc",
        "--ignore-path",
        "--frozen-lockfile",
        "--ignore-scripts",
        "--production=false",
        "--no-bin-links",
        "--non-interactive",
        "--modules-folder",
        "/private/js-install/modules",
        "--cache-folder",
        "/private/js-install/cache",
        "--mutex",
        "file:/private/js-install/temp/yarn-install.mutex",
    )
    offline = JS.yarn_install_argv(
        authority,
        node_binary=shared[0],
        yarn_cli=shared[1],
        roots=roots,
        phase="offline",
        target_os="linux",
    )
    online = JS.yarn_install_argv(
        authority,
        node_binary=shared[0],
        yarn_cli=shared[1],
        roots=roots,
        phase="online",
        target_os="linux",
    )
    assert offline == (*shared, "--offline")
    assert online == (*shared, "--registry", "https://registry.yarnpkg.com")
    assert not any("corepack" in item.lower() for item in offline)


def test_windows_environment_requires_an_explicit_system_root(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    roots = JS.writable_roots(r"C:\private\js", target_os="windows")
    with pytest.raises(
        JS.JSToolchainAuthorityError,
        match="WINDOWS_SYSTEM_ROOT_REQUIRED",
    ):
        JS.closed_environment(
            authority,
            node_binary=r"C:\runtime\node.exe",
            roots=roots,
            phase="offline",
            target_os="windows",
        )
    environment = JS.closed_environment(
        authority,
        node_binary=r"C:\runtime\node.exe",
        roots=roots,
        phase="offline",
        target_os="windows",
        windows_system_root=r"C:\Windows",
    )
    assert environment["PATH"] == r"C:\runtime"
    assert environment["SYSTEMROOT"] == r"C:\Windows"


def test_authority_values_are_immutable(
    current_runtime_closure: Path,
    trusted_bootstrap: JS.TrustedJSBootstrapAuthority,
) -> None:
    authority = _load(current_runtime_closure, trusted_bootstrap)
    with pytest.raises(Exception):
        authority.artifacts[0].sha256 = "0" * 64  # type: ignore[misc]
    assert replace(authority.artifacts[0]).sha256 == authority.artifacts[0].sha256
