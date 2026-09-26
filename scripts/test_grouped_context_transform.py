"""Pure OCI context transforms: synthetic content is never release authority."""

import copy
import gzip
import hashlib
import io
import json
import os
import tarfile

import pytest

import oci_context_consumer as C
import oci_release_authority as R
import plamen_oci_context_transform as V
import plamen_transform_bundle as T
from test_grouped_transform import encode, fixture
from test_oci_release_authority_protocol import build_oci_fixture


def context_payloads():
    commitments, files = build_oci_fixture()
    layer = commitments["layers"][0]
    facts = {
        "schema_version": "plamen.oci_build_transform_facts.v1",
        "request_sha256": "1" * 64,
        "layer_sha256": layer["digest"], "layer_size": layer["size"],
        "layer_diff_id": layer["diff_id"],
        "apple_container_configuration_sha256": commitments["apple_container_configuration_sha256"],
        "runtime_files_sha256": "2" * 64,
        "runtime_dependency_census_sha256": "3" * 64,
        **{key + "_digest": commitments[key]["digest"] for key in ("config", "manifest", "index")},
    }
    facts_raw = R._canonical_bytes(facts)
    request = {
        "schema_version": V.REQUEST_SCHEMA, "commitments": commitments,
        "build_plan_sha256": facts["request_sha256"],
        "build_facts_sha256": hashlib.sha256(facts_raw).hexdigest(),
    }
    names = ["blobs/sha256/" + layer["digest"][7:]]
    names += ["blobs/sha256/" + commitments[key]["digest"][7:] for key in ("config", "manifest")]
    names += ["index.json", "oci-layout"]
    return {
        "control/oci-context-request.json": R._canonical_bytes(request),
        **{name: files[name] for name in names}, "build-facts.json": facts_raw,
    }, request


def encoded(payloads):
    raw = encode(payloads, operation=1)
    raw[40:72] = hashlib.sha256(next(iter(payloads.values()))).digest()
    return raw


def test_retained_context_verifies_graph_and_full_census_without_authority(fixture):
    _, group, output, path = fixture
    payloads, request = context_payloads()
    fd = group(encoded(payloads))
    os.lseek(fd, 23, os.SEEK_SET)
    T.run(1, fd, (output,), ())
    observed = json.loads(path.read_bytes())
    assert observed["schema_version"] == V.OBSERVATION_SCHEMA
    assert observed["production_authority"] is False
    assert observed["rootfs_entries"] == request["commitments"]["rootfs_entries"]
    assert observed["commitments_sha256"] == R.commitments_sha256(request["commitments"])
    assert observed["build_facts_sha256"] == request["build_facts_sha256"]
    assert observed["layout_files"] == [
        {key: row[key] for key in ("path", "sha256", "size")}
        for row in request["commitments"]["layout_files"]
    ]
    assert os.lseek(fd, 0, os.SEEK_CUR) == 23
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("case", [
    "request_binding", "facts_binding", "plan_binding", "facts_layer", "member_order",
    "layout_commitment", "damaged_layer", "extra_row", "extra_request_key", "scratch", "output_count",
])
def test_context_rejects_mismatch_before_any_output(fixture, case):
    _, group, output, path = fixture
    payloads, request = context_payloads()
    if case == "facts_binding": request["build_facts_sha256"] = "4" * 64
    elif case == "plan_binding": request["build_plan_sha256"] = "4" * 64
    elif case == "facts_layer":
        facts = json.loads(payloads["build-facts.json"])
        facts["layer_diff_id"] = "sha256:" + "4" * 64
        payloads["build-facts.json"] = R._canonical_bytes(facts)
        request["build_facts_sha256"] = hashlib.sha256(payloads["build-facts.json"]).hexdigest()
    elif case == "layout_commitment":
        payloads["oci-layout"] = b"bad marker"
    elif case == "extra_request_key": request["receipt"] = "not authority"
    payloads["control/oci-context-request.json"] = R._canonical_bytes(request)
    if case == "member_order":
        rows = list(payloads.items())
        rows[1], rows[2] = rows[2], rows[1]
        payloads = dict(rows)
    elif case == "extra_row": payloads["extra.json"] = b"{}\n"
    raw = encoded(payloads)
    if case == "request_binding": raw[40] ^= 1
    elif case == "damaged_layer":
        layer_offset = 256 + 256 * len(payloads) + len(next(iter(payloads.values())))
        raw[layer_offset + 12] ^= 1
    with pytest.raises((T.TransformError, C.OCIContextConsumerError, R.OCIReleaseAuthorityError)):
        T.run(1, group(raw), () if case == "output_count" else (output,),
              (output,) if case == "scratch" else ())
    assert path.read_bytes() == b""


def layer_fixture():
    body = b"bounded-stream-content" * 200000
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo("large-file")
        entry.mode, entry.size = 0o444, len(body)
        archive.addfile(entry, io.BytesIO(body))
    raw = target.getvalue()
    return gzip.compress(raw, mtime=0), {
        "uncompressed_size": len(raw), "diff_id": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }, body


def test_layer_census_stream_reads_are_bounded(monkeypatch):
    compressed, layer, body = layer_fixture()
    read_sizes = []
    original = C._BoundedLayerReader.read

    def bounded(self, size):
        read_sizes.append(size)
        assert 0 <= size <= 1024 * 1024
        return original(self, size)

    monkeypatch.setattr(C._BoundedLayerReader, "read", bounded)
    entries = C._tar_census_stream(io.BytesIO(compressed), layer)
    assert entries == [{"kind": "file", "linkname": "", "mode": "0444", "path": "large-file",
                        "sha256": hashlib.sha256(body).hexdigest(), "size": len(body)}]
    assert len(read_sizes) > 2


@pytest.mark.parametrize("case", ["crc", "truncated", "smaller", "larger", "diffid"])
def test_stream_census_rejects_bad_compression_or_expanded_commitment(case):
    compressed, layer, _ = layer_fixture()
    layer = copy.deepcopy(layer)
    if case == "crc": compressed = compressed[:-8] + bytes([compressed[-8] ^ 1]) + compressed[-7:]
    elif case == "truncated": compressed = compressed[:-8]
    elif case == "smaller": layer["uncompressed_size"] -= 1
    elif case == "larger": layer["uncompressed_size"] += 1
    elif case == "diffid": layer["diff_id"] = "sha256:" + "0" * 64
    with pytest.raises(C.OCIContextConsumerError):
        C._tar_census_stream(io.BytesIO(compressed), layer)
