from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import threading

import pytest

import oci_release_authority as R
import runtime_image_materializer as runtime_materializer


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def build_oci_fixture() -> tuple[dict[str, object], dict[str, bytes]]:
    bodies = {
        "attestations/census.json": b'{"census":1}\n',
        "attestations/provenance.json": b'{"provenance":1}\n',
        "attestations/sbom.json": b'{"sbom":1}\n',
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
            b'{"derivation":1}\n'
        ),
    }
    roles = {
        "attestations/census.json": ("runtime-census", "runtime-census"),
        "attestations/provenance.json": ("provenance", "provenance"),
        "attestations/sbom.json": ("sbom", "sbom"),
        "usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json": (
            "cache-free-rootfs-derivation",
            "generated-attestation",
        ),
    }
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for path in (
            "attestations",
            "usr",
            "usr/local",
            "usr/local/lib",
            "usr/local/lib/plamen",
            "usr/local/lib/plamen/attestations",
        ):
            directory = tarfile.TarInfo(path + "/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.mtime = 0
            archive.addfile(directory)
        for path, body in sorted(bodies.items()):
            item = tarfile.TarInfo(path)
            item.size = len(body)
            item.mode = 0o444
            item.mtime = 0
            archive.addfile(item, io.BytesIO(body))
    raw_tar = tar_buffer.getvalue()
    compressed = gzip.compress(raw_tar, mtime=0)
    diff_id = "sha256:" + hashlib.sha256(raw_tar).hexdigest()
    layer_digest = "sha256:" + hashlib.sha256(compressed).hexdigest()
    directories = [
        {"kind": "directory", "linkname": "", "mode": "0755", "path": path,
         "sha256": None, "size": 0}
        for path in (
            "attestations",
            "usr",
            "usr/local",
            "usr/local/lib",
            "usr/local/lib/plamen",
            "usr/local/lib/plamen/attestations",
        )
    ]
    rootfs_entries = directories + [
        {"kind": "file", "linkname": "", "mode": "0444", "path": path,
         "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}
        for path, body in bodies.items()
    ]
    rootfs_entries.sort(key=lambda item: item["path"].encode("utf-8"))
    census_raw = _canonical({
        "schema_version": R.INSTALLED_RUNTIME_CENSUS_SCHEMA,
        "entries": rootfs_entries,
    })
    materialization_payloads = {
        "composition_manifest": _canonical({"schema_version": "plamen.runtime_composition_manifest.test.v1", "sources": []}),
        "receipt": _canonical({"schema_version": "plamen.runtime_materialization_receipt.test.v1", "status": "TEST_ONLY"}),
        "census": census_raw,
        "sbom": _canonical({"spdxVersion": "SPDX-2.3", "files": []}),
        "provenance": _canonical({"schema_version": "plamen.source_output_provenance.v1", "outputs": []}),
    }
    def retained(name: str, **extra: object) -> dict[str, object]:
        raw = materialization_payloads[name]
        return {"path": f"materialization/{name.replace('_', '-')}.json", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), **extra}
    runtime_materialization = {
        "schema_version": R.RUNTIME_MATERIALIZATION_SCHEMA,
        "required_roles": list(R.RUNTIME_MATERIALIZATION_REQUIRED_ROLES),
        "source_roster_sha256": "a" * 64,
        "composition_manifest": retained("composition_manifest", schema_version="plamen.runtime_composition_manifest.test.v1"),
        "archive": {"path": "materialization/runtime.tar", "sha256": hashlib.sha256(raw_tar).hexdigest(), "size": len(raw_tar), "diff_id": diff_id, "media_type": "application/vnd.oci.image.layer.v1.tar"},
        "receipt": retained("receipt"),
        "census": retained("census", schema_version=R.INSTALLED_RUNTIME_CENSUS_SCHEMA, entry_count=len(rootfs_entries), expanded_bytes=sum(row["size"] for row in rootfs_entries)),
        "sbom": retained("sbom", format="spdx-json-2.3"),
        "provenance": retained("provenance", schema_version="plamen.source_output_provenance.v1"),
    }
    config = {
        "architecture": "arm64", "os": "linux",
        "rootfs": {"diff_ids": [diff_id], "type": "layers"},
    }
    config_raw = _canonical(config)
    config_digest = "sha256:" + hashlib.sha256(config_raw).hexdigest()
    manifest_raw = _canonical({
        "config": {"digest": config_digest, "mediaType": R.CONFIG_MEDIA_TYPE, "size": len(config_raw)},
        "layers": [{"digest": layer_digest, "mediaType": R.LAYER_MEDIA_TYPE, "size": len(compressed)}],
        "mediaType": R.MANIFEST_MEDIA_TYPE, "schemaVersion": 2,
    })
    manifest_digest = "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    index_raw = _canonical({
        "manifests": [{
            "digest": manifest_digest, "mediaType": R.MANIFEST_MEDIA_TYPE,
            "platform": {"architecture": "arm64", "os": "linux"},
            "size": len(manifest_raw),
        }],
        "mediaType": R.INDEX_MEDIA_TYPE, "schemaVersion": 2,
    })
    index_digest = "sha256:" + hashlib.sha256(index_raw).hexdigest()
    artifacts = [
        {
            "artifact_id": roles[path][0], "role": roles[path][1], "path": path,
            "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "mode": "0444",
        }
        for path, body in sorted(bodies.items())
    ]
    by_id = {item["artifact_id"]: item for item in artifacts}
    attestations = {
        "provenance": {key: by_id["provenance"][key] for key in ("artifact_id", "path", "sha256", "size")},
        "runtime_census": {key: by_id["runtime-census"][key] for key in ("artifact_id", "path", "sha256", "size")},
        "sbom": {key: by_id["sbom"][key] for key in ("artifact_id", "path", "sha256", "size")},
    }
    layout = b'{"imageLayoutVersion":"1.0.0"}\n'
    files = {
        "oci-layout": layout,
        "index.json": index_raw,
        f"blobs/sha256/{manifest_digest[7:]}": manifest_raw,
        f"blobs/sha256/{config_digest[7:]}": config_raw,
        f"blobs/sha256/{layer_digest[7:]}": compressed,
    }
    role_for = {
        "oci-layout": "oci-layout", "index.json": "index",
        f"blobs/sha256/{manifest_digest[7:]}": "manifest",
        f"blobs/sha256/{config_digest[7:]}": "config",
        f"blobs/sha256/{layer_digest[7:]}": "layer-0",
    }
    commitments: dict[str, object] = {
        "schema_version": R.COMMITMENTS_SCHEMA,
        "image_reference": "registry.invalid/plamen@" + index_digest,
        "apple_container_configuration_sha256": hashlib.sha256(
            json.dumps(
                config,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest(),
        "platform": {"architecture": "arm64", "os": "linux"},
        "index": {"media_type": R.INDEX_MEDIA_TYPE, "digest": index_digest, "size": len(index_raw)},
        "manifest": {"media_type": R.MANIFEST_MEDIA_TYPE, "digest": manifest_digest, "size": len(manifest_raw)},
        "config": {"media_type": R.CONFIG_MEDIA_TYPE, "digest": config_digest, "size": len(config_raw)},
        "layers": [{
            "media_type": R.LAYER_MEDIA_TYPE, "digest": layer_digest,
            "size": len(compressed), "diff_id": diff_id, "uncompressed_size": len(raw_tar),
        }],
        "attestations": attestations, "artifacts": artifacts,
        "rootfs_entries": rootfs_entries,
        "runtime_materialization": runtime_materialization,
        "directories": [
            {"path": path, "mode": "0755"}
            for path in (
                "attestations",
                "usr",
                "usr/local",
                "usr/local/lib",
                "usr/local/lib/plamen",
                "usr/local/lib/plamen/attestations",
            )
        ],
        "rootfs_derivation": {
            "schema_version": R.ROOTFS_DERIVATION_BINDING_SCHEMA,
            "derivation_schema_version": "plamen.cache_free_rootfs_derivation.test.v1",
            "recipe_version": "TEST_ONLY_PRE_DERIVED_CACHE_FREE_V1",
            "authentication_scope": "TEST_ONLY_NO_RELEASE_AUTHORITY",
            "production_authority": False,
            "source_asset_id": "complete-rootfs",
            "source_reference": "TEST_ONLY_SYNTHETIC_CACHE_FREE_ROOT",
            "source_sha256": "d" * 64,
            "source_size": 123,
            "source_diff_id": "sha256:" + "e" * 64,
            "derived_sha256": "d" * 64,
            "derived_size": 123,
            "derived_diff_id": "sha256:" + "e" * 64,
            "derived_tar_size": 123,
            "derived_census_sha256": "f" * 64,
            "derived_entry_count": 1,
            "manifest_sha256": hashlib.sha256(
                bodies["usr/local/lib/plamen/attestations/cache-free-rootfs-derivation.json"]
            ).hexdigest(),
            "removed_cache_path": "/etc/ld.so.cache",
            "removed_cache_sha256": "0" * 64,
            "removed_cache_size": 0,
            "forbidden_environment": {
                "exact_names": ["GLIBC_TUNABLES"],
                "prefixes": ["LD_"],
            },
        },
        "layout_files": [
            {"role": role_for[path], "path": path, "sha256": hashlib.sha256(body).hexdigest(), "size": len(body), "mode": "0444"}
            for path, body in sorted(files.items())
        ],
    }
    return commitments, files


def _refresh_installed_census(commitments: dict[str, object]) -> None:
    materialization = commitments["runtime_materialization"]
    entries = commitments["rootfs_entries"]
    raw = _canonical({
        "schema_version": R.INSTALLED_RUNTIME_CENSUS_SCHEMA,
        "entries": entries,
    })
    materialization["census"].update(
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        entry_count=len(entries),
        expanded_bytes=sum(row["size"] for row in entries if row["kind"] == "file"),
    )


def _helper_source(*, fail: bool = False, consume: bool = True, counter: str = "", extra: bool = False) -> str:
    return f'''import argparse,hashlib,json,os
p=argparse.ArgumentParser();p.add_argument("--plamen-oci-protocol");p.add_argument("--role");p.add_argument("--request-fd",type=int);p.add_argument("--response-fd",type=int);p.add_argument("--descriptor",action="append",default=[]);a=p.parse_args()
if {fail!r}: raise SystemExit(23)
def read(fd):
 b=b""
 while True:
  c=os.read(fd,1048576)
  if not c:return b
  b+=c
raw=read(a.request_fd);q=json.loads(raw);ds={{k:int(v) for k,v in (x.split("=",1) for x in a.descriptor)}}
if {consume!r}: read(ds["release-document"]);read(ds["release-signature"])
if {counter!r}:
 with open({counter!r},"ab") as f:f.write(b"1\\n")
canon=lambda v:(json.dumps(v,sort_keys=True,separators=(",",":"))+"\\n").encode()
r={{"schema_version":"plamen.oci_release_authority_receipt.v6","status":"TEST_ONLY_AUTHENTICATED","protocol":q["protocol"],"request_sha256":hashlib.sha256(canon(q)).hexdigest(),"attempt_id":q["attempt_id"],"release_nonce":q["release_nonce"],"release_generation":q["release_generation"],"lock_sha256":q["lock_sha256"],"commitments":q["commitments"],"commitments_sha256":q["commitments_sha256"],"authenticated_signer":q["expected_signer"],"release_document_sha256":q["release_document"]["sha256"],"signature_sha256":q["signature"]["sha256"],"test_executable_provenance":q["test_executable_provenance"]}}
if {extra!r}:r["forged"]="field"
os.write(a.response_fd,canon(r))
'''


def _helper(tmp_path: Path, **options: object):
    path = tmp_path / (hashlib.sha256(repr(options).encode()).hexdigest()[:8] + ".py")
    path.write_text(_helper_source(**options))
    return R.TEST_ONLY_open_executable((sys.executable, str(path)))


def _documents(tmp_path: Path):
    first = tmp_path / "release.json"; second = tmp_path / "release.sig"
    first.write_bytes(b"release\n"); second.write_bytes(b"signature\n")
    return first.open("rb"), second.open("rb")


def _kwargs(first, second, timeout: object = 10):
    return {
        "attempt_id": "a" * 32, "release_nonce": "b" * 32,
        "release_generation": 7, "lock_sha256": "c" * 64,
        "expected_signer": "test-signer", "commitments": build_oci_fixture()[0],
        "release_document_fd": first.fileno(), "signature_fd": second.fileno(),
        "timeout_seconds": timeout,
    }


def test_production_has_no_python_mint_and_hard_stops() -> None:
    for forbidden in ("_EXECUTABLE_ISSUER", "_RECEIPT_ISSUER", "_ExecutableRecord", "PinnedNativeExecutable", "VerifiedReleaseReceipt", "ReleaseAuthority"):
        assert not hasattr(R, forbidden)
    with pytest.raises(R.OCIReleaseAuthorityError, match="INTEGRATION_REQUIRED"):
        R.open_pinned_native_executable("/bin/echo", expected_sha256="0" * 64, expected_size=1)
    with pytest.raises(R.OCIReleaseAuthorityError, match="INTEGRATION_REQUIRED"):
        R.authenticate_release(native_authority_capability=object())


def test_commitments_bind_exact_graph_artifacts_and_attestations() -> None:
    commitments, _ = build_oci_fixture()
    assert R.validate_output_commitments(commitments) == commitments
    assert len(R.commitments_sha256(commitments)) == 64
    assert commitments["index"]["digest"] != commitments["manifest"]["digest"]
    assert commitments["image_reference"].endswith(
        "@" + commitments["index"]["digest"]
    )
    assert len(commitments["apple_container_configuration_sha256"]) == 64
    bad = json.loads(json.dumps(commitments))
    bad["image_reference"] = (
        "registry.invalid/plamen@" + bad["manifest"]["digest"]
    )
    with pytest.raises(R.OCIReleaseAuthorityError, match="bind the index"):
        R.validate_output_commitments(bad)
    bad = json.loads(json.dumps(commitments))
    bad["manifest"]["digest"] = bad["index"]["digest"]
    with pytest.raises(R.OCIReleaseAuthorityError, match="must be distinct"):
        R.validate_output_commitments(bad)
    bad = json.loads(json.dumps(commitments))
    bad["apple_container_configuration_sha256"] = "sha256:" + "f" * 64
    with pytest.raises(
        R.OCIReleaseAuthorityError,
        match="Apple Container configuration",
    ):
        R.validate_output_commitments(bad)
    bad = json.loads(json.dumps(commitments)); bad["attestations"]["sbom"]["path"] = "attestations/census.json"
    with pytest.raises(R.OCIReleaseAuthorityError, match="exact committed artifact"):
        R.validate_output_commitments(bad)
    bad = json.loads(json.dumps(commitments)); bad["layout_files"].append(dict(bad["layout_files"][0]))
    with pytest.raises(R.OCIReleaseAuthorityError, match="exact OCI closure"):
        R.validate_output_commitments(bad)


def test_installed_runtime_census_binds_symlink_and_hardlink_rows() -> None:
    commitments, _ = build_oci_fixture()
    links = [
        ("hardlink", "attestations/hard-copy", "attestations/census.json"),
        ("symlink", "attestations/census-link", "census.json"),
    ]
    for kind, path, target in links:
        commitments["rootfs_entries"].append({
            "kind": kind, "linkname": target, "mode": "0777", "path": path,
            "sha256": hashlib.sha256((kind + "\0" + target).encode()).hexdigest(),
            "size": 0,
        })
    commitments["rootfs_entries"].sort(key=lambda row: row["path"].encode())
    _refresh_installed_census(commitments)
    assert R.validate_output_commitments(commitments)["rootfs_entries"] == commitments["rootfs_entries"]

    bad = json.loads(json.dumps(commitments))
    next(row for row in bad["rootfs_entries"] if row["kind"] == "symlink")["linkname"] = "/proc/keys"
    row = next(row for row in bad["rootfs_entries"] if row["kind"] == "symlink")
    row["sha256"] = hashlib.sha256(("symlink\0" + row["linkname"]).encode()).hexdigest()
    _refresh_installed_census(bad)
    with pytest.raises(R.OCIReleaseAuthorityError, match="provider-owned"):
        R.validate_output_commitments(bad)


def test_derivation_schema_environment_and_nonempty_census_are_fail_closed() -> None:
    commitments, _ = build_oci_fixture()
    mutations = (
        ("schema_version", "plamen.oci_rootfs_derivation_binding.v0"),
        ("derived_entry_count", 0),
        ("source_size", 0),
    )
    for key, value in mutations:
        bad = json.loads(json.dumps(commitments))
        bad["rootfs_derivation"][key] = value
        if key == "source_size":
            bad["rootfs_derivation"]["derived_size"] = value
            bad["rootfs_derivation"]["derived_tar_size"] = value
        with pytest.raises(R.OCIReleaseAuthorityError, match="rootfs derivation"):
            R.validate_output_commitments(bad)

    bad = json.loads(json.dumps(commitments))
    bad["rootfs_derivation"]["forbidden_environment"] = {
        "exact_names": [],
        "prefixes": ["LD_"],
    }
    with pytest.raises(R.OCIReleaseAuthorityError, match="environment denial"):
        R.validate_output_commitments(bad)

    old = json.loads(json.dumps(commitments))
    old["schema_version"] = "plamen.oci_output_commitments.v4"
    with pytest.raises(R.OCIReleaseAuthorityError, match="schema is unsupported"):
        R.validate_output_commitments(old)


def test_exact_pinned_derivation_is_bound_into_release_commitments() -> None:
    commitments, _ = build_oci_fixture()
    derivation = commitments["rootfs_derivation"]
    derivation.update(
        {
            "derivation_schema_version": R.elf_closure.SCHEMA_VERSION,
            "recipe_version": R.elf_closure.RECIPE_VERSION,
            "authentication_scope": R.elf_closure.AUTHENTICATION_SCOPE,
            "source_reference": R.elf_closure.SOURCE_REFERENCE,
            "source_sha256": R.elf_closure.SOURCE_LAYER_SHA256,
            "source_size": R.elf_closure.SOURCE_LAYER_SIZE,
            "source_diff_id": "sha256:" + R.elf_closure.SOURCE_DIFF_ID,
            "derived_sha256": R.elf_closure.DERIVED_LAYER_SHA256,
            "derived_size": R.elf_closure.DERIVED_LAYER_SIZE,
            "derived_diff_id": "sha256:" + R.elf_closure.DERIVED_DIFF_ID,
            "derived_tar_size": R.elf_closure.SOURCE_TAR_SIZE,
            "derived_census_sha256": (
                "3d90ba706639fde6be674a520875aff6bcbc8f3a82dca8e35bf47bb090242112"
            ),
            "derived_entry_count": 4_218,
            "manifest_sha256": R.elf_closure.DERIVATION_MANIFEST_SHA256,
            "removed_cache_sha256": (
                "4f3163cd39f4dfd4669e9c79e71bc6f04a4c8275658211671ed2b740c0ec434f"
            ),
            "removed_cache_size": 4_587,
        }
    )
    artifact = next(
        row
        for row in commitments["artifacts"]
        if row["artifact_id"] == "cache-free-rootfs-derivation"
    )
    artifact["sha256"] = R.elf_closure.DERIVATION_MANIFEST_SHA256
    next(
        row for row in commitments["rootfs_entries"]
        if row["path"] == artifact["path"]
    )["sha256"] = artifact["sha256"]
    _refresh_installed_census(commitments)
    normalized = R.validate_output_commitments(commitments)
    assert normalized["rootfs_derivation"] == derivation
    assert R.commitments_sha256(commitments) == R.commitments_sha256(normalized)


@pytest.mark.parametrize("timeout", [True, False, 1.0, float("nan"), float("inf"), 0, 301])
def test_timeout_requires_exact_bounded_integer(tmp_path: Path, timeout: object) -> None:
    ledger = tmp_path / "ledger"; ledger.mkdir(mode=0o700)
    helper = _helper(tmp_path); first, second = _documents(tmp_path)
    try:
        with pytest.raises(R.OCIReleaseAuthorityError, match="exact whole second"):
            R.TEST_ONLY_create_release_authority(helper, ledger).authenticate_for_testing(**_kwargs(first, second, timeout))
    finally:
        helper.close(); first.close(); second.close()


def test_test_only_full_receipt_exact_schema_and_recovery(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger"; ledger.mkdir(mode=0o700)
    helper = _helper(tmp_path); first, second = _documents(tmp_path)
    try:
        initial = R.TEST_ONLY_create_release_authority(helper, ledger).authenticate_for_testing(**_kwargs(first, second))
        assert initial.value["status"] == "TEST_ONLY_AUTHENTICATED"
        os.lseek(first.fileno(), 0, os.SEEK_SET); os.lseek(second.fileno(), 0, os.SEEK_SET)
        recovered = R.TEST_ONLY_create_release_authority(helper, ledger).authenticate_for_testing(**_kwargs(first, second))
        assert recovered.recovered and recovered.canonical_bytes == initial.canonical_bytes
    finally:
        helper.close(); first.close(); second.close()


def test_extra_receipt_field_and_incomplete_consumption_fail(tmp_path: Path) -> None:
    for number, options in enumerate(({"extra": True}, {"consume": False})):
        case = tmp_path / str(number); case.mkdir(); ledger = case / "ledger"; ledger.mkdir(mode=0o700)
        helper = _helper(case, **options); first, second = _documents(case)
        try:
            with pytest.raises(R.OCIReleaseAuthorityError):
                R.TEST_ONLY_create_release_authority(helper, ledger).authenticate_for_testing(**_kwargs(first, second))
        finally:
            helper.close(); first.close(); second.close()


def test_failed_attempt_is_ambiguous(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger"; ledger.mkdir(mode=0o700)
    bad = _helper(tmp_path, fail=True); good = _helper(tmp_path); first, second = _documents(tmp_path)
    try:
        with pytest.raises(R.OCIReleaseAuthorityError, match="failed closed"):
            R.TEST_ONLY_create_release_authority(bad, ledger).authenticate_for_testing(**_kwargs(first, second))
        os.lseek(first.fileno(), 0, os.SEEK_SET); os.lseek(second.fileno(), 0, os.SEEK_SET)
        with pytest.raises(R.AmbiguousReleaseAttemptError):
            R.TEST_ONLY_create_release_authority(good, ledger).authenticate_for_testing(**_kwargs(first, second))
    finally:
        bad.close(); good.close(); first.close(); second.close()


def test_concurrent_replay_executes_once(tmp_path: Path) -> None:
    ledger = tmp_path / "ledger"; ledger.mkdir(mode=0o700); counter = tmp_path / "counter"
    helper = _helper(tmp_path, counter=str(counter)); first, second = _documents(tmp_path)
    first2 = (tmp_path / "release.json").open("rb"); second2 = (tmp_path / "release.sig").open("rb")
    receipts: list[object] = []; failures: list[BaseException] = []; barrier = threading.Barrier(2)
    def run(a, b):
        try:
            barrier.wait(); receipts.append(R.TEST_ONLY_create_release_authority(helper, ledger).authenticate_for_testing(**_kwargs(a, b)))
        except BaseException as exc: failures.append(exc)
    threads = [threading.Thread(target=run, args=pair) for pair in ((first, second), (first2, second2))]
    try:
        for thread in threads: thread.start()
        for thread in threads: thread.join(15)
        assert not failures and not any(thread.is_alive() for thread in threads)
        assert sorted(item.recovered for item in receipts) == [False, True]
        assert counter.read_bytes() == b"1\n"
    finally:
        helper.close(); first.close(); second.close(); first2.close(); second2.close()


def test_locked_runtime_census_budgets_exceed_old_cap_but_remain_finite() -> None:
    assert R._MAX_ARTIFACTS == 131_072
    assert R._MAX_DIRECTORIES == 131_072
    assert R._MAX_ARTIFACTS == runtime_materializer.MAX_ENTRIES
    assert R._MAX_DIRECTORIES == runtime_materializer.MAX_ENTRIES
    assert R._MAX_ARTIFACTS > 56_637 > 32_768
    assert R._MAX_TOTAL_EXPANDED == 12 * 1024 * 1024 * 1024
    assert R._MAX_TOTAL_EXPANDED == runtime_materializer.MAX_EXPANDED_BYTES
    assert R._MAX_JSON_BYTES == 64 * 1024 * 1024
    assert R._MAX_JSON_NODES == 4_194_304
