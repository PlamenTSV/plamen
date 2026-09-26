from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

import oci_context_consumer as C
import oci_release_authority as R
from test_oci_release_authority_protocol import build_oci_fixture


def _helper_source(files: dict[str, bytes], *, fail: bool = False, consume: bool = True, extra: bool = False, unexpected: bool = False) -> str:
    encoded = {path: base64.b64encode(body).decode() for path, body in files.items()}
    return f'''import argparse,base64,hashlib,json,os,stat
p=argparse.ArgumentParser();p.add_argument("--plamen-oci-protocol");p.add_argument("--role");p.add_argument("--request-fd",type=int);p.add_argument("--response-fd",type=int);p.add_argument("--descriptor",action="append",default=[]);a=p.parse_args()
if {fail!r}:raise SystemExit(29)
def read(fd):
 b=b""
 while True:
  c=os.read(fd,1048576)
  if not c:return b
  b+=c
canon=lambda v:(json.dumps(v,sort_keys=True,separators=(",",":"))+"\\n").encode()
raw=read(a.request_fd);q=json.loads(raw);ds={{k:int(v) for k,v in (x.split("=",1) for x in a.descriptor)}}
if {consume!r}:
 for n in range(len(q["inputs"])):read(ds[f"input-{{n}}"])
parent=ds["output-parent"];root=q["output_basename"];os.mkdir(root,0o700,dir_fd=parent);rootfd=os.open(root,os.O_RDONLY|os.O_DIRECTORY,dir_fd=parent)
try:
 os.mkdir("blobs",0o755,dir_fd=rootfd);blobs=os.open("blobs",os.O_RDONLY|os.O_DIRECTORY,dir_fd=rootfd)
 try:
  os.mkdir("sha256",0o755,dir_fd=blobs)
 finally:os.close(blobs)
 content={encoded!r}
 for path,b64 in content.items():
  bits=path.split("/");fd=rootfd
  opened=[]
  try:
   for bit in bits[:-1]:
    child=os.open(bit,os.O_RDONLY|os.O_DIRECTORY,dir_fd=fd);opened.append(child);fd=child
   out=os.open(bits[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444,dir_fd=fd)
   try:
    body=base64.b64decode(b64);off=0
    while off<len(body):off+=os.write(out,body[off:])
   finally:os.close(out)
  finally:
   for item in reversed(opened):os.close(item)
 if {unexpected!r}:
  out=os.open("unexpected",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o444,dir_fd=rootfd);os.write(out,b"x");os.close(out)
finally:os.close(rootfd)
info=os.stat(root,dir_fd=parent,follow_symlinks=False);identity={{"device":int(info.st_dev),"inode":int(info.st_ino),"mode":int(stat.S_IFMT(info.st_mode)|stat.S_IMODE(info.st_mode)),"uid":int(info.st_uid),"gid":int(info.st_gid),"nlink":int(info.st_nlink)}}
arts=[{{k:item[k] for k in ("path","sha256","size","mode")}} for item in q["commitments"]["artifacts"]];arts.sort(key=lambda x:x["path"])
layout=[{{"path":path,"sha256":hashlib.sha256(base64.b64decode(body)).hexdigest(),"size":len(base64.b64decode(body))}} for path,body in sorted({encoded!r}.items())]
census={{"schema_version":"plamen.oci_output_census.v3","commitments_sha256":q["commitments_sha256"],"layout_files":layout,"rootfs_entries":q["commitments"]["rootfs_entries"]}}
r={{"schema_version":"plamen.oci_context_consumer_receipt.v3","status":"TEST_ONLY_CONSUMED","protocol":q["protocol"],"request_sha256":hashlib.sha256(canon(q)).hexdigest(),"attempt_id":q["attempt_id"],"context_nonce":q["context_nonce"],"release_receipt_sha256":q["release_receipt_sha256"],"release_nonce":q["release_nonce"],"lock_sha256":q["lock_sha256"],"commitments_sha256":q["commitments_sha256"],"input_closure_sha256":q["input_closure_sha256"],"output_parent_identity":q["output_parent_identity"],"output_basename":q["output_basename"],"output_identity":identity,"output_census_sha256":hashlib.sha256(canon(census)).hexdigest()}}
if {extra!r}:r["forged"]="field"
os.write(a.response_fd,canon(r))
'''


def _helper(tmp_path: Path, **options: bool):
    _, files = build_oci_fixture()
    path = tmp_path / (hashlib.sha256(repr(options).encode()).hexdigest()[:8] + "-context.py")
    path.write_text(_helper_source(files, **options))
    return R.TEST_ONLY_open_executable((sys.executable, str(path)))


class _Handles:
    def __init__(self, values): self.values = values
    def fileno(self):
        for value in self.values: os.lseek(value.fileno(), 0, os.SEEK_SET)
        return self.values[0].fileno()
    def close(self):
        for value in self.values: value.close()


def _input(tmp_path: Path, *, writable: bool = False):
    commitments, files = build_oci_fixture()
    materialization = commitments["runtime_materialization"]
    layer = commitments["layers"][0]
    compressed = files[f"blobs/sha256/{layer['digest'][7:]}"]
    bodies = {
        materialization["composition_manifest"]["path"]: R._canonical_bytes({"schema_version": "plamen.runtime_composition_manifest.test.v1", "sources": []}),
        materialization["archive"]["path"]: __import__("gzip").decompress(compressed),
        materialization["receipt"]["path"]: R._canonical_bytes({"schema_version": "plamen.runtime_materialization_receipt.test.v1", "status": "TEST_ONLY"}),
        materialization["census"]["path"]: R._canonical_bytes({"schema_version": R.INSTALLED_RUNTIME_CENSUS_SCHEMA, "entries": commitments["rootfs_entries"]}),
        materialization["sbom"]["path"]: R._canonical_bytes({"spdxVersion": "SPDX-2.3", "files": []}),
        materialization["provenance"]["path"]: R._canonical_bytes({"schema_version": "plamen.source_output_provenance.v1", "outputs": []}),
    }
    handles = []
    items = []
    for number, (path, body) in enumerate(sorted(bodies.items())):
        disk = tmp_path / f"input-{number}"
        disk.write_bytes(body); disk.chmod(0o600)
        handle = disk.open("r+b" if writable and number == 0 else "rb")
        handles.append(handle)
        items.append(C.TEST_ONLY_ContextInput(path=path, sha256=hashlib.sha256(body).hexdigest(), size=len(body), mode="0600", descriptor=handle.fileno()))
    return _Handles(handles), tuple(items)


def _kwargs(parent: int, item, *, timeout: object = 10):
    commitments, _ = build_oci_fixture()
    receipt = R.TEST_ONLY_issue_release_binding(
        attempt_id="f" * 32, release_nonce="b" * 32, release_generation=7,
        lock_sha256="c" * 64, commitments=commitments,
    )
    return {
        "attempt_id": "a" * 32, "context_nonce": "d" * 32,
        "release_receipt": receipt, "inputs": item,
        "output_parent_fd": parent, "output_basename": "plamen-layout",
        "timeout_seconds": timeout,
    }


def _case(tmp_path: Path, **helper_options: bool):
    ledger = tmp_path / "ledger"; output = tmp_path / "output"
    ledger.mkdir(mode=0o700); output.mkdir(mode=0o700)
    helper = _helper(tmp_path, **helper_options); handle, item = _input(tmp_path)
    parent = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    return ledger, output, helper, handle, item, parent


def test_production_has_no_python_receipt_or_consumer_and_hard_stops() -> None:
    for forbidden in ("_RECEIPT_ISSUER", "VerifiedContextReceipt", "ContextConsumer", "ContextInput"):
        assert not hasattr(C, forbidden)
    with pytest.raises(C.OCIContextConsumerError, match="INTEGRATION_REQUIRED"):
        C.consume_context(native_context_capability=object(), authenticated_release_receipt=object())


def test_context_publishes_and_validates_exact_oci_closure(tmp_path: Path) -> None:
    ledger, output, helper, handle, item, parent = _case(tmp_path)
    try:
        receipt = C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**_kwargs(parent, item))
        assert receipt.value["status"] == "TEST_ONLY_CONSUMED"
        assert len(receipt.value["output_census_sha256"]) == 64
        assert (output / "plamen-layout" / "index.json").is_file()
    finally:
        os.close(parent); handle.close(); helper.close()


def test_context_requires_all_separate_materialization_descriptors_before_publish(tmp_path: Path) -> None:
    ledger, output, helper, handle, items, parent = _case(tmp_path)
    try:
        with pytest.raises(C.OCIContextConsumerError, match="materialization evidence is incomplete"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(
                **_kwargs(parent, items[:-1])
            )
        assert not (output / "plamen-layout").exists()
    finally:
        os.close(parent); handle.close(); helper.close()


def test_context_recomputes_apple_configuration_from_exact_config_bytes(tmp_path: Path) -> None:
    ledger, _output, helper, handle, items, parent = _case(tmp_path)
    kwargs = _kwargs(parent, items)
    commitments, _ = build_oci_fixture()
    commitments["apple_container_configuration_sha256"] = "f" * 64
    kwargs["release_receipt"] = R.TEST_ONLY_issue_release_binding(
        attempt_id="f" * 32, release_nonce="b" * 32,
        release_generation=7, lock_sha256="c" * 64,
        commitments=commitments,
    )
    try:
        with pytest.raises(C.OCIContextConsumerError, match="Apple Container configuration"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
    finally:
        os.close(parent); handle.close(); helper.close()


def test_committed_recovery_recensuses_and_rejects_equal_size_mutation(tmp_path: Path) -> None:
    ledger, output, helper, handle, item, parent = _case(tmp_path)
    kwargs = _kwargs(parent, item)
    try:
        initial = C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
        os.lseek(handle.fileno(), 0, os.SEEK_SET)
        recovered = C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
        assert recovered.recovered and recovered.canonical_bytes == initial.canonical_bytes
        index = output / "plamen-layout" / "index.json"
        body = bytearray(index.read_bytes()); body[0] ^= 1; index.chmod(0o644); index.write_bytes(body); index.chmod(0o444)
        os.lseek(handle.fileno(), 0, os.SEEK_SET)
        with pytest.raises(C.OCIContextConsumerError, match="digest"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
    finally:
        os.close(parent); handle.close(); helper.close()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_committed_recovery_rejects_links_and_aliases(tmp_path: Path, kind: str) -> None:
    ledger, output, helper, handle, item, parent = _case(tmp_path)
    kwargs = _kwargs(parent, item)
    try:
        C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
        root = output / "plamen-layout"
        if kind == "symlink":
            (root / "alias").symlink_to("index.json")
        elif kind == "hardlink":
            os.link(root / "index.json", root / "alias")
        else:
            os.mkfifo(root / "alias")
        os.lseek(handle.fileno(), 0, os.SEEK_SET)
        with pytest.raises(C.OCIContextConsumerError, match="link|alias|unexpected"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
    finally:
        os.close(parent); handle.close(); helper.close()


@pytest.mark.parametrize("options", [{"unexpected": True}, {"extra": True}, {"consume": False}])
def test_unexpected_output_extra_receipt_and_unconsumed_input_fail(tmp_path: Path, options: dict[str, bool]) -> None:
    ledger, _output, helper, handle, item, parent = _case(tmp_path, **options)
    try:
        with pytest.raises(C.OCIContextConsumerError):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**_kwargs(parent, item))
    finally:
        os.close(parent); handle.close(); helper.close()


def test_release_receipt_requires_exact_full_canonical_schema(tmp_path: Path) -> None:
    ledger, _output, helper, handle, item, parent = _case(tmp_path)
    kwargs = _kwargs(parent, item)
    legitimate = kwargs["release_receipt"]
    value = legitimate.value
    del value["signature_sha256"]
    forged = R._TestOnlyVerifiedReleaseReceipt(R._canonical_bytes(value))
    kwargs["release_receipt"] = forged
    try:
        with pytest.raises(C.OCIContextConsumerError, match="exact schema"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**kwargs)
    finally:
        os.close(parent); handle.close(); helper.close()


@pytest.mark.parametrize("timeout", [True, 1.0, float("nan"), float("inf"), 0, 301])
def test_context_timeout_rejects_bool_float_nonfinite_and_bounds(tmp_path: Path, timeout: object) -> None:
    ledger, _output, helper, handle, item, parent = _case(tmp_path)
    try:
        with pytest.raises(C.OCIContextConsumerError, match="exact whole second"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**_kwargs(parent, item, timeout=timeout))
    finally:
        os.close(parent); handle.close(); helper.close()


def test_writable_input_preexisting_output_symlink_and_hardlink_rejected(tmp_path: Path) -> None:
    # Writable admission.
    case = tmp_path / "writable"; case.mkdir(); ledger = case / "ledger"; output = case / "out"; ledger.mkdir(mode=0o700); output.mkdir()
    helper = _helper(case); handle, item = _input(case, writable=True); parent = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(C.OCIContextConsumerError, match="read-only"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**_kwargs(parent, item))
    finally:
        os.close(parent); handle.close(); helper.close()

    # A pre-existing destination is rejected before mutation.
    case = tmp_path / "existing"; case.mkdir(); ledger = case / "ledger"; output = case / "out"; ledger.mkdir(mode=0o700); output.mkdir(); (output / "plamen-layout").mkdir()
    helper = _helper(case); handle, item = _input(case); parent = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(C.OCIContextConsumerError, match="already exists"):
            C.TEST_ONLY_create_context_consumer(helper, ledger).consume_for_testing(**_kwargs(parent, item))
    finally:
        os.close(parent); handle.close(); helper.close()


def test_failed_attempt_is_ambiguous(tmp_path: Path) -> None:
    ledger, _output, failing, handle, item, parent = _case(tmp_path, fail=True)
    good = _helper(tmp_path)
    kwargs = _kwargs(parent, item)
    try:
        with pytest.raises(C.OCIContextConsumerError, match="failed closed"):
            C.TEST_ONLY_create_context_consumer(failing, ledger).consume_for_testing(**kwargs)
        os.lseek(handle.fileno(), 0, os.SEEK_SET)
        with pytest.raises(C.AmbiguousContextAttemptError):
            C.TEST_ONLY_create_context_consumer(good, ledger).consume_for_testing(**kwargs)
    finally:
        os.close(parent); handle.close(); failing.close(); good.close()
