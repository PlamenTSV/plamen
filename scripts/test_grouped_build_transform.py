"""Pure transform tests using explicit test-only OCI plan fixtures, not authority."""

import hashlib
import json
import os

import pytest

import deterministic_oci_layout as L
import plamen_transform_bundle as T
import plamen_oci_build_transform as B
import test_deterministic_oci_layout as vectors
from test_grouped_transform import encode, fixture


@pytest.fixture
def build_case(tmp_path, fixture):
    _, group, _, _ = fixture
    root, lock, installed = vectors._fixture(tmp_path / "inputs")
    plan = vectors._plan(root, lock)
    descriptors = []
    try:
        plan_raw = L._canonical_bytes(dict(plan))
        payloads = {"build-plan.json": plan_raw}
        payloads.update({row.path: (root / row.path).read_bytes() for row in L._validate_plan_shape(plan)})
        encoded = encode(payloads, operation=2)
        encoded[40:72] = hashlib.sha256(plan_raw).digest()
        group_fd = group(encoded)
        outputs, scratch, paths = [], [], []
        for name in B.OUTPUT_ROLES:
            path = tmp_path / name
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            outputs.append(fd)
            descriptors.append(fd)
            paths.append(path)
        for index in range(3):
            path = tmp_path / f"scratch-{index}"
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            path.unlink()
            scratch.append(fd)
            descriptors.append(fd)
        yield group_fd, tuple(outputs), tuple(scratch), paths, lock, installed
    finally:
        plan._authority.close()
        for fd in descriptors:
            os.close(fd)


def test_real_grouped_build_matches_independent_golden_without_ambient_scratch(build_case, monkeypatch):
    group, outputs, scratch, paths, lock, installed = build_case

    def forbidden(*args, **kwargs):
        raise AssertionError("transform tried to create ambient temporary storage")

    monkeypatch.setattr(L.tempfile, "TemporaryFile", forbidden)
    assert T.run(2, group, outputs, scratch) is None
    facts = json.loads(paths[-1].read_bytes())
    assert facts["manifest_digest"] == vectors._GOLDEN_MANIFEST
    assert facts["manifest_digest"] == lock["image"]["manifest_digest"]
    assert facts["index_digest"] == lock["image"]["index_digest"]
    assert facts["config_digest"] == lock["image"]["config_digest"]
    expected_layer, _, _ = vectors._oracle_layer(installed)
    assert paths[0].read_bytes() == expected_layer
    for path, key in zip(paths[1:4], ("config_digest", "manifest_digest", "index_digest")):
        assert "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == facts[key]
    assert paths[4].read_bytes() == b'{"imageLayoutVersion":"1.0.0"}\n'
    assert all(os.fstat(fd).st_size > 0 for fd in scratch)


@pytest.mark.parametrize("case", ["missing_scratch", "aliased_scratch", "output_scratch_alias", "nonempty_output", "nonempty_scratch"])
def test_invalid_build_storage_preserves_outputs(build_case, case):
    group, outputs, scratch, paths, _, _ = build_case
    if case == "missing_scratch": scratch = scratch[:-1]
    elif case == "aliased_scratch": scratch = (scratch[0], scratch[0], scratch[2])
    elif case == "output_scratch_alias": outputs = (scratch[0], *outputs[1:])
    elif case == "nonempty_output": os.write(outputs[0], b"preserved")
    elif case == "nonempty_scratch": os.write(scratch[0], b"preserved")
    before = [path.read_bytes() for path in paths]
    with pytest.raises(T.TransformError):
        T.run(2, group, outputs, scratch)
    assert [path.read_bytes() for path in paths] == before
