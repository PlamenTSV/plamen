from __future__ import annotations

from dataclasses import replace
import builtins
import hashlib
import json
import os
import struct
import tempfile

import pytest

import native_runtime_grouped_transform as G
import plamen_transform_bundle as T
import runtime_image_materializer as R
import runtime_source_manifest_renderer as S
import test_runtime_image_materializer as F


pytestmark = pytest.mark.skipif(os.name != "posix", reason="retained POSIX FDs required")


def _retained(tmp_path, name: str, raw: bytes) -> tuple[int, S.RetainedFileIdentity]:
    path = tmp_path / name
    writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.write(writer, raw)
        os.fsync(writer)
    finally:
        os.close(writer)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    return descriptor, S.retained_file_identity(descriptor)


def _sources(tmp_path):
    manifest, payloads, source_manifests = F._fixture_values()
    retained = []
    descriptors = []
    for ordinal, row in enumerate(manifest["sources"]):
        artifact = row["artifact_id"]
        semantic = json.loads(source_manifests[artifact])
        payload_fd, payload_identity = _retained(
            tmp_path, f"payload-{ordinal}", payloads[artifact]
        )
        receipt_raw = (
            b"producer-receipt-v1\0"
            + row["role"].encode("ascii")
            + hashlib.sha256(payloads[artifact]).digest()
        )
        receipt_fd, receipt_identity = _retained(
            tmp_path, f"producer-receipt-{ordinal}", receipt_raw
        )
        descriptors.extend((payload_fd, receipt_fd))
        retained.append(
            S.RetainedRuntimeSource(
                role=row["role"],
                artifact_id=artifact,
                version=semantic["version"],
                source_reference="retained:" + artifact,
                payload_descriptor=payload_fd,
                payload_identity=payload_identity,
                producer_receipt_descriptor=receipt_fd,
                producer_receipt_identity=receipt_identity,
                policy_sha256=hashlib.sha256(
                    ("policy:" + row["role"]).encode("ascii")
                ).hexdigest(),
                archive_member=semantic.get("archive_member"),
                archive_member_count=semantic.get("archive_member_count"),
                archive_member_roster_sha256=semantic.get(
                    "archive_member_roster_sha256"
                ),
                installed_sha256=semantic.get("installed_sha256"),
                installed_size=semantic.get("installed_size"),
            )
        )
    return tuple(retained), tuple(descriptors), payloads


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
    struct.pack_into(">HHIIIQQ", header, 8, 1, 256, 4, len(rows), 256, data_start, len(data))
    header[40:72] = hashlib.sha256(rows[0][1]).digest()
    header[72:104] = hashlib.sha256(roster).digest()
    return bytes(header + roster + data)


def _unlinked_output(tmp_path, name: str) -> int:
    path = tmp_path / name
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    path.unlink()
    return descriptor


def _anonymous_group(tmp_path, raw: bytes) -> int:
    path = tmp_path / "group"
    writer = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
    try:
        os.write(writer, raw)
        os.fsync(writer)
        os.fchmod(writer, 0o400)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        path.unlink()
        return descriptor
    finally:
        os.close(writer)


def _read(descriptor: int) -> bytes:
    return os.pread(descriptor, os.fstat(descriptor).st_size, 0)


def test_renderer_emits_exact_native_op4_inputs_and_real_transform_consumes_them(
    monkeypatch, tmp_path
):
    sources, descriptors, payloads = _sources(tmp_path)
    for descriptor in descriptors:
        os.lseek(descriptor, 1, os.SEEK_SET)
    try:
        def forbidden(*unused, **ignored):
            raise AssertionError("renderer attempted a pathname open")

        monkeypatch.setattr(builtins, "open", forbidden)
        rendered = S.render_native_retained_runtime_inputs(sources)
        assert rendered.production_authority is False
        assert rendered.next_required_authority == S.NEXT_REQUIRED_AUTHORITY
        assert rendered.op4_row_paths == G.ROW_PATHS
        assert rendered.composition_manifest.endswith(b"\n")
        assert not rendered.composition_manifest.endswith(b"\n\n")
        assert all(manifest.raw.endswith(b"\n") for manifest in rendered.source_manifests)
        assert all(os.lseek(descriptor, 0, os.SEEK_CUR) == 1 for descriptor in descriptors)
        assert tuple(row.role for row in rendered.acquisition_roster) == S.ROLES
        assert len(
            {row.producer_receipt_descriptor for row in rendered.acquisition_roster}
        ) == len(S.ROLES)

        composition, rows = R._validate_composition_manifest(
            rendered.composition_manifest,
            rendered.composition_manifest_sha256,
            expected_schema_version=R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION,
            expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
        )
        assert composition["schema_version"] == R.NATIVE_RETAINED_COMPOSITION_SCHEMA_VERSION
        for row, source_manifest in zip(rows, rendered.source_manifests, strict=True):
            R._validate_source_manifest(
                source_manifest.raw,
                row,
                expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
                expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
            )

        grouped_rows = [(G.ROW_PATHS[0], rendered.composition_manifest)]
        for ordinal, source_manifest in enumerate(rendered.source_manifests):
            grouped_rows.extend(
                (
                    (G.ROW_PATHS[1 + ordinal * 2], payloads[source_manifest.artifact_id]),
                    (G.ROW_PATHS[2 + ordinal * 2], source_manifest.raw),
                )
            )
        group_fd = _anonymous_group(tmp_path, _group_bytes(grouped_rows))
        outputs = tuple(
            _unlinked_output(tmp_path, "output-" + role)
            for role in G.OUTPUT_ROLES
        )
        scratch_files = tuple(
            tempfile.TemporaryFile(mode="w+b")
            for _ in range(len(G.ROLES) * 2 + 2)
        )
        scratch = tuple(stream.fileno() for stream in scratch_files)
        try:
            assert T.run(4, group_fd, outputs, scratch) is None
            assert _read(outputs[0])
            assert json.loads(_read(outputs[1]))["production_authority"] is False
            assert json.loads(_read(outputs[2]))["schema_version"] == R.CENSUS_SCHEMA_VERSION
        finally:
            os.close(group_fd)
            for descriptor in outputs:
                os.close(descriptor)
            for stream in scratch_files:
                stream.close()
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@pytest.mark.parametrize(
    "mutation,error",
    [
        ("missing", "roster"),
        ("order", "role order"),
        ("payload_alias", "descriptors alias"),
        ("receipt_alias", "descriptors alias"),
        ("inode_alias", "objects alias"),
        ("identity", "retained identity"),
        ("digest", "digest differs"),
        ("policy", "exact sha256"),
        ("fixture", "non-production fixture"),
        ("unicode", "canonical printable ASCII"),
    ],
)
def test_renderer_rejects_incomplete_aliased_or_descriptive_authority(
    mutation, error, tmp_path
):
    sources, descriptors, _ = _sources(tmp_path)
    extra = []
    try:
        candidate = list(sources)
        if mutation == "missing":
            candidate.pop()
        elif mutation == "order":
            candidate[0], candidate[1] = candidate[1], candidate[0]
        elif mutation == "payload_alias":
            candidate[1] = replace(candidate[1], payload_descriptor=candidate[0].payload_descriptor)
        elif mutation == "receipt_alias":
            candidate[1] = replace(
                candidate[1],
                producer_receipt_descriptor=candidate[0].producer_receipt_descriptor,
            )
        elif mutation == "inode_alias":
            duplicate = os.dup(candidate[0].payload_descriptor)
            extra.append(duplicate)
            candidate[1] = replace(
                candidate[1],
                payload_descriptor=duplicate,
                payload_identity=candidate[0].payload_identity,
            )
        elif mutation == "identity":
            candidate[0] = replace(
                candidate[0],
                payload_identity=replace(candidate[0].payload_identity, inode=0),
            )
        elif mutation == "digest":
            candidate[0] = replace(
                candidate[0],
                payload_identity=replace(candidate[0].payload_identity, sha256="0" * 64),
            )
        elif mutation == "policy":
            candidate[0] = replace(candidate[0], policy_sha256="A" * 64)
        elif mutation == "fixture":
            candidate[0] = replace(candidate[0], source_reference="fixture://base")
        elif mutation == "unicode":
            candidate[0] = replace(candidate[0], version="vérsion")
        with pytest.raises(S.RuntimeSourceRenderError, match=error):
            S.render_native_retained_runtime_inputs(tuple(candidate))
    finally:
        for descriptor in descriptors + tuple(extra):
            os.close(descriptor)


def test_renderer_rejects_writable_inheritable_and_empty_receipt_descriptors(tmp_path):
    sources, descriptors, _ = _sources(tmp_path)
    extra = []
    try:
        writable_path = tmp_path / "writable"
        writable = os.open(writable_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        extra.append(writable)
        with pytest.raises(S.RuntimeSourceRenderError, match="custody"):
            S.render_native_retained_runtime_inputs(
                (replace(sources[0], payload_descriptor=writable), *sources[1:])
            )

        os.set_inheritable(sources[0].payload_descriptor, True)
        with pytest.raises(S.RuntimeSourceRenderError, match="custody"):
            S.render_native_retained_runtime_inputs(sources)
        os.set_inheritable(sources[0].payload_descriptor, False)

        empty_fd, empty_identity = _retained(tmp_path, "empty-receipt", b"")
        extra.append(empty_fd)
        with pytest.raises(S.RuntimeSourceRenderError, match="producer receipt is empty"):
            S.render_native_retained_runtime_inputs(
                (
                    replace(
                        sources[0],
                        producer_receipt_descriptor=empty_fd,
                        producer_receipt_identity=empty_identity,
                    ),
                    *sources[1:],
                )
            )
    finally:
        for descriptor in descriptors + tuple(extra):
            os.close(descriptor)


def test_renderer_never_accepts_legacy_test_schema_as_an_input(tmp_path):
    sources, descriptors, _ = _sources(tmp_path)
    try:
        rendered = S.render_native_retained_runtime_inputs(sources)
        legacy = json.loads(rendered.source_manifests[0].raw)
        legacy["schema_version"] = R.SOURCE_MANIFEST_SCHEMA_VERSION
        legacy["authentication_scope"] = "TEST_ONLY_EXACT_CONTENT"
        raw = R._canonical_json(legacy)
        source = json.loads(rendered.composition_manifest)["sources"][0]
        with pytest.raises(R.RuntimeMaterializationError, match="does not bind"):
            R._validate_source_manifest(
                raw,
                source,
                expected_schema_version=R.NATIVE_RETAINED_SOURCE_MANIFEST_SCHEMA_VERSION,
                expected_authentication_scope=R.NATIVE_RETAINED_AUTHENTICATION_SCOPE,
            )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
