"""Retained-input OCI graph/census transformation, never a receipt issuer.

The native parent must authenticate the release and prior build receipt before
admitting these bytes. Neither the input JSON nor this observation grants that
authority, publishes a layout, or authorizes an image import.
"""

import os

import oci_context_consumer as context
import oci_release_authority as release
from plamen_oci_build_transform import _private_fd, _write
from plamen_transform_bundle import GroupedInputs, TransformError, _SliceReader


REQUEST_SCHEMA = "plamen.oci_context_transform_request.v1"
OBSERVATION_SCHEMA = "plamen.oci_context_observation.v1"
_FACT_KEYS = {
    "schema_version", "request_sha256", "layer_sha256", "layer_size",
    "layer_diff_id", "config_digest", "manifest_digest", "index_digest",
    "apple_container_configuration_sha256", "runtime_files_sha256",
    "runtime_dependency_census_sha256",
}


def _read_document(group, row, maximum):
    if row.size > maximum:
        raise TransformError("context document exceeds its bound")
    reader = _SliceReader(group, row)
    raw = reader.read(row.size)
    reader.finish()
    return raw


def verify(group_fd, output_fds, scratch_fds):
    if type(output_fds) is not tuple or len(output_fds) != 1:
        raise TransformError("context requires exactly one output")
    if type(scratch_fds) is not tuple or scratch_fds:
        raise TransformError("context has no scratch descriptors")
    with GroupedInputs(group_fd, 1) as group:
        identity = _private_fd(output_fds[0], scratch=False)
        if identity == group.identity[:2]:
            raise TransformError("context input and output alias")
        if len(group.rows) != 7 or group.rows[0].path != "control/oci-context-request.json":
            raise TransformError("context input roster differs")
        if group.rows[0].sha256 != group.request_sha256:
            raise TransformError("context request is not bound to row zero")
        request = release._parse_canonical_json(
            _read_document(group, group.rows[0], release._MAX_JSON_BYTES), "context request",
        )
        release._exact(request, {"schema_version", "commitments", "build_plan_sha256", "build_facts_sha256"}, "context request")
        if request["schema_version"] != REQUEST_SCHEMA:
            raise TransformError("context request schema differs")
        for key in ("build_plan_sha256", "build_facts_sha256"):
            release._sha256(request[key], key)
        commitments = release.validate_output_commitments(request["commitments"])
        if len(commitments["layers"]) != 1 or commitments["platform"] != {"architecture": "arm64", "os": "linux"}:
            raise TransformError("context requires the exact single-layer arm64 image")
        layer = commitments["layers"][0]
        expected_names = (
            "blobs/sha256/" + layer["digest"][7:],
            "blobs/sha256/" + commitments["config"]["digest"][7:],
            "blobs/sha256/" + commitments["manifest"]["digest"][7:],
            "index.json", "oci-layout", "build-facts.json",
        )
        if tuple(row.path for row in group.rows[1:]) != expected_names:
            raise TransformError("context member order differs")
        expected_files = {row["path"]: row for row in commitments["layout_files"]}
        for row in group.rows[1:6]:
            expected = expected_files[row.path]
            if row.size != expected["size"] or row.sha256.hex() != expected["sha256"]:
                raise TransformError("context layout member commitment differs")
        facts_row = group.rows[6]
        if facts_row.sha256.hex() != request["build_facts_sha256"]:
            raise TransformError("context build facts commitment differs")
        facts = release._parse_canonical_json(
            _read_document(group, facts_row, release._MAX_DOCUMENT_BYTES), "build facts",
        )
        release._exact(facts, _FACT_KEYS, "build facts")
        if (facts["schema_version"] != "plamen.oci_build_transform_facts.v1"
                or facts["request_sha256"] != request["build_plan_sha256"]
                or facts["layer_sha256"] != layer["digest"]
                or type(facts["layer_size"]) is not int or facts["layer_size"] != layer["size"]
                or facts["layer_diff_id"] != layer["diff_id"]
                or any(facts[key + "_digest"] != commitments[key]["digest"] for key in ("config", "manifest", "index"))
                or facts["apple_container_configuration_sha256"] != commitments["apple_container_configuration_sha256"]):
            raise TransformError("context build facts differ from image commitments")
        for key in ("runtime_files_sha256", "runtime_dependency_census_sha256"):
            release._sha256(facts[key], key)
        documents = {row.path: _read_document(group, row, release._MAX_DOCUMENT_BYTES)
                     for row in group.rows[2:6]}
        layer_reader = _SliceReader(group, group.rows[1])
        entries = context._verify_oci_graph(
            documents, commitments, layer_streams={group.rows[1].path: layer_reader},
        )
        layer_reader.finish()
        if entries != commitments["rootfs_entries"]:
            raise TransformError("context layer census differs from release commitments")
        group.rejoin()
        observation = {
            "schema_version": OBSERVATION_SCHEMA,
            "production_authority": False,
            "request_sha256": group.request_sha256.hex(),
            "build_plan_sha256": request["build_plan_sha256"],
            "build_facts_sha256": request["build_facts_sha256"],
            "commitments_sha256": release.commitments_sha256(commitments),
            "layout_files": [{"path": row.path, "sha256": row.sha256.hex(), "size": row.size}
                             for row in sorted(group.rows[1:6], key=lambda row: row.path)],
            "rootfs_entries": entries,
        }
        raw = release._canonical_bytes(observation)
        _write(output_fds[0], raw)
        group.rejoin()
        if os.fstat(output_fds[0]).st_size != len(raw):
            raise TransformError("context output size differs")
