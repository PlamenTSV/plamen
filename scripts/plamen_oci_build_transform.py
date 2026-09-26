"""Pure deterministic OCI build over native-retained inputs and scratch FDs.

No release receipt, context capability, layout publication or authority is
created by this module. The supervising native operation owns those effects.
"""

import json
import os
import stat

import deterministic_oci_layout as layout
import oci_retained_archive_transform as archive_transform
from plamen_transform_bundle import GroupedInputs, TransformError, _SliceReader


OUTPUT_ROLES = ("layer.tar.gz", "config.json", "manifest.json", "index.json", "oci-layout", "build-facts.json")


def _private_fd(fd, *, scratch):
    if archive_transform._access(fd) != os.O_RDWR:
        raise TransformError("build descriptor is not read-write")
    if archive_transform.fcntl.fcntl(fd, archive_transform.fcntl.F_GETFL) & os.O_APPEND:
        raise TransformError("append build descriptor is forbidden")
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size != 0
            or info.st_nlink != (0 if scratch else 1)):
        raise TransformError("build descriptor is not empty private retained storage")
    return info.st_dev, info.st_ino


class _Scratch:
    def __init__(self, descriptors):
        self.descriptors, self.used = descriptors, 0

    def __call__(self):
        if self.used == len(self.descriptors):
            raise TransformError("build scratch roster exhausted")
        descriptor = self.descriptors[self.used]
        _private_fd(descriptor, scratch=True)
        self.used += 1
        stream = os.fdopen(os.dup(descriptor), "w+b", buffering=0)
        stream.seek(0)
        return stream


def _write(fd, raw):
    position = 0
    while position < len(raw):
        count = os.pwrite(fd, raw[position:], position)
        if count <= 0:
            raise TransformError("build output write failed")
        position += count
    os.fsync(fd)


def build(group_fd, output_fds, scratch_fds):
    if type(output_fds) is not tuple or len(output_fds) != 6:
        raise TransformError("build requires its exact six outputs")
    if type(scratch_fds) is not tuple or len(scratch_fds) != 3:
        raise TransformError("build requires its exact three scratch files")
    with GroupedInputs(group_fd, 2) as group:
        seen = {group.identity[:2]}
        for fd, scratch in [(fd, False) for fd in output_fds] + [(fd, True) for fd in scratch_fds]:
            identity = _private_fd(fd, scratch=scratch)
            if identity in seen:
                raise TransformError("build descriptor roles alias")
            seen.add(identity)
        first = group.rows[0]
        if first.size > layout._MAX_JSON_BYTES or first.sha256 != group.request_sha256:
            raise TransformError("build request is not bound to row zero")
        plan_reader = _SliceReader(group, first)
        plan_raw = plan_reader.read(first.size)
        plan_reader.finish()
        try:
            plan = json.loads(plan_raw)
        except (ValueError, UnicodeError) as exc:
            raise TransformError("build plan is malformed") from exc
        if type(plan) is not dict or layout._canonical_bytes(plan) != plan_raw:
            raise TransformError("build plan is not canonical")
        metadata = layout._validate_plan_shape(plan)
        if [(row.path, row.size, row.sha256.hex()) for row in group.rows[1:]] != [
            (row.path, row.size, row.sha256) for row in metadata
        ]:
            raise TransformError("build inputs differ from plan")
        readers = [layout._RetainedTransformReader(group.fd, row.offset, expected)
                   for row, expected in zip(group.rows[1:], metadata, strict=True)]
        scratch = _Scratch(scratch_fds)
        entries, spool = [], None
        try:
            entries, runtime_sha, dependency_sha, derivation, spool = layout._expand_runtime_closure(
                plan, metadata, readers, spool_factory=scratch,
            )
            if derivation != {key: plan["rootfs_derivation"][key] for key in (
                "manifest_sha256", "derived_sha256", "derived_diff_id", "derived_census_sha256",
            )}:
                raise TransformError("rootfs derivation differs before build")
            if scratch.used != 3 or any(reader.offset != reader.metadata.size for reader in readers):
                raise TransformError("build did not consume its exact input/scratch roster")
            group.rejoin()
            with os.fdopen(os.dup(output_fds[0]), "wb", buffering=0) as destination:
                destination.seek(0)
                layer = layout._write_layer(destination, entries)
                os.fsync(destination.fileno())
            config, manifest, index, config_sha, manifest_sha, index_sha, apple_sha = layout._image_documents(
                layer, plan, runtime_sha, dependency_sha,
            )
            if (manifest_sha != layout._expected_manifest_digest(plan)
                    or index_sha != layout._expected_index_digest(plan)
                    or config_sha != plan["expected_config_digest"]
                    or apple_sha != plan["expected_apple_container_configuration_sha256"]):
                raise TransformError("built image differs from locked commitments")
            facts = {
                "schema_version": "plamen.oci_build_transform_facts.v1",
                "request_sha256": group.request_sha256.hex(),
                "layer_sha256": layer.blob_digest,
                "layer_size": layer.blob_size,
                "layer_diff_id": layer.diff_id,
                "config_digest": config_sha,
                "manifest_digest": manifest_sha,
                "index_digest": index_sha,
                "apple_container_configuration_sha256": apple_sha,
                "runtime_files_sha256": runtime_sha,
                "runtime_dependency_census_sha256": dependency_sha,
            }
            documents = (config, manifest, index, layout._canonical_bytes({"imageLayoutVersion": layout.OCI_LAYOUT_VERSION}), layout._canonical_bytes(facts))
            for fd, document in zip(output_fds[1:], documents, strict=True):
                _write(fd, document)
            group.rejoin()
        finally:
            for entry in entries:
                if entry.source is not None:
                    entry.source.close()
            if spool is not None:
                spool.close()
