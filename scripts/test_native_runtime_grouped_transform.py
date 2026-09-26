from __future__ import annotations

import builtins
import hashlib
import json
import os
import struct
import tempfile

import pytest

import native_runtime_grouped_transform as G
import plamen_transform_bundle as T
import test_runtime_image_materializer as F
import runtime_image_materializer as R


pytestmark = pytest.mark.skipif(os.name != "posix", reason="retained POSIX FDs required")


def _linked_output(tmp_path, label: str):
    path = tmp_path / label
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.fchmod(descriptor, 0o600)
    path.unlink()
    return descriptor, path


def _anonymous_read_only(tmp_path, raw: bytes, label: str) -> int:
    path = tmp_path / label
    writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.write(writer, raw)
        os.fsync(writer)
        reader = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        path.unlink()
        return reader
    finally:
        os.close(writer)


def _golden(tmp_path, manifest, payloads, source_manifests, raw_manifest):
    retained = []
    for index, source in enumerate(manifest["sources"]):
        artifact = source["artifact_id"]
        retained.append(
            R.RetainedRuntimeInput(
                artifact,
                _anonymous_read_only(tmp_path, payloads[artifact], f"golden-payload-{index}"),
                _anonymous_read_only(tmp_path, source_manifests[artifact], f"golden-manifest-{index}"),
            )
        )
    output_path = tmp_path / "golden-output"
    writer = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    reader = os.open(output_path, os.O_RDONLY | os.O_NOFOLLOW)
    output_path.unlink()
    return R._TEST_ONLY_materialize_runtime_image(
        raw_manifest,
        expected_manifest_sha256=hashlib.sha256(raw_manifest).hexdigest(),
        retained_inputs=tuple(retained),
        output_writer_descriptor=writer,
        output_reader_descriptor=reader,
    )


def _group_bytes(rows: list[tuple[str, bytes]]) -> bytes:
    roster = bytearray()
    data = bytearray()
    data_start = 256 + 256 * len(rows)
    for name, payload in rows:
        row = bytearray(256)
        raw_name = name.encode("ascii")
        struct.pack_into(">H", row, 0, len(raw_name))
        struct.pack_into(">QQ", row, 8, len(payload), data_start + len(data))
        row[24:56] = hashlib.sha256(payload).digest()
        row[56:56 + len(raw_name)] = raw_name
        roster.extend(row)
        data.extend(payload)
    header = bytearray(256)
    header[:8] = b"PLMRHG1\0"
    struct.pack_into(
        ">HHIIIQQ", header, 8, 1, 256, 4, len(rows), 256, data_start, len(data)
    )
    header[40:72] = hashlib.sha256(rows[0][1]).digest()
    header[72:104] = hashlib.sha256(roster).digest()
    return bytes(header + roster + data)


def _group_fixture(tmp_path, *, production: bool = True):
    manifest, payloads, source_manifests = F._fixture_values()
    if production:
        manifest["schema_version"] = R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
        manifest["authentication_scope"] = R.NATIVE_RETAINED_AUTHENTICATION_SCOPE
        for source in manifest["sources"]:
            artifact = source["artifact_id"]
            value = json.loads(source_manifests[artifact])
            value["schema_version"] = R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION
            value["authentication_scope"] = R.NATIVE_RETAINED_AUTHENTICATION_SCOPE
            raw_source = F._canonical(value)
            source_manifests[artifact] = raw_source
            source["source_manifest_sha256"] = hashlib.sha256(raw_source).hexdigest()
            source["source_manifest_size"] = len(raw_source)
    raw_manifest = F._canonical(manifest)
    rows = [(G.ROW_PATHS[0], raw_manifest)]
    for index, source in enumerate(manifest["sources"]):
        artifact = source["artifact_id"]
        rows.extend(
            (
                (G.ROW_PATHS[1 + index * 2], payloads[artifact]),
                (G.ROW_PATHS[2 + index * 2], source_manifests[artifact]),
            )
        )
    group_path = tmp_path / "group"
    raw_group = _group_bytes(rows)
    writer = os.open(group_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    os.write(writer, raw_group)
    os.fsync(writer)
    os.fchmod(writer, 0o400)
    group_fd = os.open(group_path, os.O_RDONLY | os.O_NOFOLLOW)
    os.close(writer)
    group_path.unlink()
    return manifest, payloads, source_manifests, raw_manifest, group_fd, rows


def _scratch() -> tuple[tuple[int, ...], tuple[object, ...]]:
    files = tuple(
        tempfile.TemporaryFile(mode="w+b") for _ in range(len(G.ROLES) * 2 + 2)
    )
    for stream in files:
        os.fchmod(stream.fileno(), 0o600)
    return tuple(stream.fileno() for stream in files), files


def _read(descriptor: int) -> bytes:
    size = os.fstat(descriptor).st_size
    return os.pread(descriptor, size, 0)


def test_actual_op4_matches_existing_canonical_compositor_without_path_opens(monkeypatch, tmp_path):
    test_manifest, payloads, test_source_manifests = F._fixture_values()
    test_raw = F._canonical(test_manifest)
    golden = _golden(
        tmp_path, test_manifest, payloads, test_source_manifests, test_raw
    )
    manifest, _, _, raw_manifest, group_fd, rows = _group_fixture(tmp_path)
    outputs_and_paths = tuple(_linked_output(tmp_path, role) for role in G.OUTPUT_ROLES)
    outputs = tuple(row[0] for row in outputs_and_paths)
    scratch, scratch_files = _scratch()
    try:
        def forbidden(*unused, **ignored):
            raise AssertionError("pathname/tempfile operation reached admitted transform")

        monkeypatch.setattr(builtins, "open", forbidden)
        monkeypatch.setattr(R.tempfile, "TemporaryFile", forbidden)
        os.lseek(group_fd, 17, os.SEEK_SET)
        assert T.run(4, group_fd, outputs, scratch) is None
        assert os.lseek(group_fd, 0, os.SEEK_CUR) == 17
        assert _read(outputs[0]) == _read(golden.archive_descriptor)
        expected_sbom = json.loads(golden.sbom_bytes)
        manifest_sha256 = hashlib.sha256(raw_manifest).hexdigest()
        expected_sbom["documentNamespace"] = (
            "https://plamen.invalid/runtime/" + manifest_sha256
        )
        expected_sbom_raw = F._canonical(expected_sbom)
        expected_provenance = json.loads(golden.provenance_bytes)
        expected_provenance["composition_manifest_sha256"] = manifest_sha256
        expected_provenance_raw = F._canonical(expected_provenance)
        golden_receipt = json.loads(golden.receipt_bytes)
        expected_observation = {
            "archive": golden_receipt["archive"],
            "authority_boundary": "PLAMEN_NATIVE_RETAINED_HELPER_RECEIPT_V1_REQUIRED",
            "composition_manifest_sha256": manifest_sha256,
            "environment_denials": golden_receipt["environment_denials"],
            "installed": {
                **golden_receipt["installed"],
                "sbom_sha256": hashlib.sha256(expected_sbom_raw).hexdigest(),
                "provenance_sha256": hashlib.sha256(expected_provenance_raw).hexdigest(),
            },
            "network": "DENY",
            "package_execution": golden_receipt["package_execution"],
            "production_authority": False,
            "schema_version": G.OBSERVATION_SCHEMA_VERSION,
            "solc_execution_policy": golden_receipt["solc_execution_policy"],
            "source_roster_sha256": R._source_roster_sha256(manifest["sources"]),
            "status": "CONTENT_COMPOSED_PENDING_NATIVE_RUNNER_RECEIPT",
            "target": "linux/arm64",
        }
        assert _read(outputs[1]) == F._canonical(expected_observation)
        assert _read(outputs[2]) == golden.census_bytes
        assert _read(outputs[3]) == expected_sbom_raw
        assert _read(outputs[4]) == expected_provenance_raw
        assert json.loads(_read(outputs[2]))["schema_version"] == "plamen.installed_runtime_census.v1"
        assert all(os.fstat(fd).st_mode & 0o777 == 0o600 for fd in outputs)
        source_row_count = len(G.ROLES) * 2
        assert [os.fstat(fd).st_size for fd in scratch[:source_row_count]] == [
            len(raw) for _, raw in rows[1:]
        ]
        assert os.fstat(scratch[source_row_count]).st_size > 0
        assert os.fstat(scratch[source_row_count + 1]).st_size > 0
    finally:
        os.close(group_fd)
        os.close(golden.archive_descriptor)
        for descriptor in outputs:
            os.close(descriptor)
        for stream in scratch_files:
            stream.close()


def test_failure_preserves_exact_partial_native_residue(monkeypatch, tmp_path):
    _, _, _, _, group_fd, _ = _group_fixture(tmp_path)
    outputs_and_paths = tuple(_linked_output(tmp_path, "residue-" + role) for role in G.OUTPUT_ROLES)
    outputs = tuple(row[0] for row in outputs_and_paths)
    scratch, scratch_files = _scratch()
    original = G._write_document
    calls = 0

    def partial(descriptor, raw, label):
        nonlocal calls
        calls += 1
        if calls == 1:
            os.write(descriptor, b"invalid-residue")
            raise G.NativeRuntimeTransformError("injected document failure")
        original(descriptor, raw, label)

    monkeypatch.setattr(G, "_write_document", partial)
    try:
        with pytest.raises(G.NativeRuntimeTransformError, match="injected"):
            T.run(4, group_fd, outputs, scratch)
        assert os.fstat(outputs[0]).st_size > 0
        assert _read(outputs[1]) == b"invalid-residue"
        assert all(os.fstat(fd).st_size == 0 for fd in outputs[2:])
    finally:
        os.close(group_fd)
        for descriptor in outputs:
            os.close(descriptor)
        for stream in scratch_files:
            stream.close()


def test_operation4_rejects_legacy_test_only_input_schema(tmp_path):
    _, _, _, _, group_fd, _ = _group_fixture(tmp_path, production=False)
    outputs_and_paths = tuple(
        _linked_output(tmp_path, "legacy-" + role) for role in G.OUTPUT_ROLES
    )
    outputs = tuple(row[0] for row in outputs_and_paths)
    scratch, scratch_files = _scratch()
    try:
        with pytest.raises(R.RuntimeMaterializationError, match="composition policy"):
            T.run(4, group_fd, outputs, scratch)
        assert all(os.fstat(fd).st_size == 0 for fd in outputs)
    finally:
        os.close(group_fd)
        for descriptor in outputs:
            os.close(descriptor)
        for stream in scratch_files:
            stream.close()


def test_production_validators_reject_cross_schema_scope_pairs():
    manifest, _, source_manifests = F._fixture_values()
    manifest["schema_version"] = R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
    raw_manifest = F._canonical(manifest)
    with pytest.raises(R.RuntimeMaterializationError, match="composition policy"):
        R._validate_composition_manifest(
            raw_manifest,
            hashlib.sha256(raw_manifest).hexdigest(),
            expected_schema_version=R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )

    source = manifest["sources"][0]
    raw_source = source_manifests[source["artifact_id"]]
    with pytest.raises(R.RuntimeMaterializationError, match="does not bind"):
        R._validate_source_manifest(
            raw_source,
            source,
            expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )

    with pytest.raises(R.RuntimeMaterializationError, match="policy is unsupported"):
        R._validate_composition_manifest(
            F._canonical(F._fixture_values()[0]),
            hashlib.sha256(F._canonical(F._fixture_values()[0])).hexdigest(),
            expected_schema_version=R.SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )


@pytest.mark.parametrize("case", ["operation", "roster", "outputs", "scratch", "alias"])
def test_transport_denominator_fails_before_effects(case, tmp_path):
    _, _, _, _, group_fd, _ = _group_fixture(tmp_path)
    outputs_and_paths = tuple(_linked_output(tmp_path, "negative-" + role) for role in G.OUTPUT_ROLES)
    outputs = tuple(row[0] for row in outputs_and_paths)
    scratch, scratch_files = _scratch()
    try:
        operation = 3 if case == "operation" else 4
        selected_outputs = outputs[:-1] if case == "outputs" else outputs
        selected_scratch = scratch[:-1] if case == "scratch" else scratch
        if case == "alias":
            selected_scratch = (outputs[0], *scratch[1:])
        if case == "roster":
            raw = bytearray(os.pread(group_fd, os.fstat(group_fd).st_size, 0))
            raw[256 + 56] ^= 1
            raw[72:104] = hashlib.sha256(raw[256:256 + 21 * 256]).digest()
            os.close(group_fd)
            path = tmp_path / "bad-roster"
            writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.write(writer, raw)
            os.fchmod(writer, 0o400)
            group_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            os.close(writer)
            path.unlink()
        with pytest.raises((G.NativeRuntimeTransformError, T.TransformError)):
            T.run(operation, group_fd, selected_outputs, selected_scratch)
        assert all(os.fstat(fd).st_size == 0 for fd in outputs)
    finally:
        os.close(group_fd)
        for descriptor in outputs:
            os.close(descriptor)
        for stream in scratch_files:
            stream.close()
