from __future__ import annotations

from copy import deepcopy
import hashlib
from typing import Any, Callable, Mapping

from review_fixtures.program_facts_r2_1_b0_red_support import (
    body_digest,
    require_accepts,
    require_callable,
)


SNAPSHOT_MODULE = "program_facts_evm_build_input_snapshot"


def _leaf(
    root_id: str,
    portable_path: str,
    input_class: str,
    payload: bytes,
    identity: str,
) -> tuple[dict[str, Any], bytes]:
    return (
        {
            "root_id": root_id,
            "portable_path": portable_path,
            "casefold_key": f"{root_id}:{portable_path}".casefold(),
            "input_class": input_class,
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "physical_capture_identity_digest": hashlib.sha256(
                identity.encode("ascii")
            ).hexdigest(),
            "link_state": "REGULAR_SINGLE_LINK",
        },
        payload,
    )


def _positive_capture() -> tuple[dict[str, Any], dict[str, bytes]]:
    raw = (
        _leaf("project", "src/Main.sol", "SOURCE", b"contract Main {}\n", "source"),
        _leaf(
            "project",
            "foundry.toml",
            "CONFIG",
            b"[profile.default]\nlibs=['lib']\n",
            "config",
        ),
        _leaf(
            "project",
            "foundry.lock",
            "LOCK",
            b'{"version":1,"packages":[]}\n',
            "lock",
        ),
        _leaf(
            "deps",
            "vendor/nested/Lib.sol",
            "DEPENDENCY",
            b"library Lib {}\n",
            "dependency",
        ),
        _leaf(
            "generated",
            "bindings/Generated.sol",
            "GENERATED_INPUT",
            b"library Generated {}\n",
            "generated",
        ),
        _leaf(
            "tools",
            "solc/include/std.json",
            "TOOL_SUPPORT",
            b'{"language":"Solidity"}\n',
            "tool-support",
        ),
    )
    files = sorted(
        (row for row, _payload in raw),
        key=lambda row: (row["root_id"], row["portable_path"]),
    )
    leaves = {
        f"{row['root_id']}:{row['portable_path']}": payload
        for row, payload in raw
    }
    total_bytes = sum(row["size"] for row in files)
    document: dict[str, Any] = {
        "schema": "plamen.program_facts_evm_build_input_snapshot.v1",
        "status": "CAPTURED",
        "capture_policy": {
            "max_file_count": len(files) + 2,
            "max_total_bytes": total_bytes + 64,
            "max_file_bytes": max(row["size"] for row in files) + 16,
            "max_path_bytes": 256,
            "max_depth": 16,
            "allowed_input_classes": [
                "SOURCE",
                "CONFIG",
                "LOCK",
                "DEPENDENCY",
                "GENERATED_INPUT",
                "TOOL_SUPPORT",
            ],
        },
        "roots": [
            {"root_id": "deps", "root_class": "EXTERNAL_DEPENDENCY"},
            {"root_id": "generated", "root_class": "GENERATED_INPUT"},
            {"root_id": "project", "root_class": "AUDIT_SOURCE"},
            {"root_id": "tools", "root_class": "TOOL_SUPPORT"},
        ],
        "files": files,
        "capture_observations": [
            {
                "root_id": row["root_id"],
                "portable_path": row["portable_path"],
                "before_identity_digest": row[
                    "physical_capture_identity_digest"
                ],
                "after_identity_digest": row[
                    "physical_capture_identity_digest"
                ],
                "before_sha256": row["sha256"],
                "after_sha256": row["sha256"],
                "link_state": row["link_state"],
            }
            for row in files
        ],
        "pack_manifest": {
            "format": "PFCAS1",
            "file_count": len(files),
            "total_leaf_bytes": total_bytes,
            "leaf_identities": sorted(leaves),
        },
        "materialization": {
            "source": "SEALED_PFCAS_ONLY",
            "live_project_fallback": False,
        },
    }
    document["snapshot_body_sha256"] = body_digest(
        document, "snapshot_body_sha256"
    )
    _assert_local_positive(document, leaves)
    return document, leaves


def _assert_local_positive(
    document: Mapping[str, Any],
    leaves: Mapping[str, bytes],
) -> None:
    files = document["files"]
    identities = [
        f"{row['root_id']}:{row['portable_path']}" for row in files
    ]
    assert identities == sorted(identities)
    assert len(identities) == len(set(identities))
    assert len({identity.casefold() for identity in identities}) == len(
        identities
    )
    assert set(identities) == set(leaves)
    for row in files:
        identity = f"{row['root_id']}:{row['portable_path']}"
        payload = leaves[identity]
        assert len(payload) == row["size"]
        assert hashlib.sha256(payload).hexdigest() == row["sha256"]
    assert document["pack_manifest"]["file_count"] == len(files)
    assert document["pack_manifest"]["total_leaf_bytes"] == sum(
        row["size"] for row in files
    )
    assert any(row["input_class"] == "TOOL_SUPPORT" for row in files)
    assert document["materialization"] == {
        "source": "SEALED_PFCAS_ONLY",
        "live_project_fallback": False,
    }
    assert document["snapshot_body_sha256"] == body_digest(
        document, "snapshot_body_sha256"
    )


def _resign(document: dict[str, Any]) -> None:
    document["snapshot_body_sha256"] = body_digest(
        document, "snapshot_body_sha256"
    )


def _validator(law: str) -> Callable[..., Any]:
    return require_callable(
        SNAPSHOT_MODULE,
        "validate_build_input_snapshot_v1",
        law,
    )


def _require_targeted_rejection(
    validator: Callable[..., Any],
    law: str,
    reason_code: str,
    document: Mapping[str, Any],
    leaves: Mapping[str, bytes],
) -> None:
    try:
        result = validator(document, pack_leaves=leaves)
    except Exception as exc:
        assert reason_code in str(exc), (
            f"R21_B0_RED[{law}]: wrong rejection cause: "
            f"{exc.__class__.__name__}: {exc}; expected {reason_code}"
        )
        return
    assert isinstance(result, Mapping), (
        f"R21_B0_RED[{law}]: rejection must carry {reason_code}"
    )
    assert result.get("accepted") is False
    assert result.get("reason_code") == reason_code


def _accept_positive(
    validator: Callable[..., Any],
    law: str,
    document: Mapping[str, Any],
    leaves: Mapping[str, bytes],
) -> None:
    _assert_local_positive(document, leaves)
    require_accepts(validator, law, document, pack_leaves=leaves)


def test_a3_config_lock_dependency_and_generated_mutation_after_capture_rejected() -> None:
    law = "A3/capture-before-after-stability"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation = deepcopy(document)
    observation = next(
        row
        for row in mutation["capture_observations"]
        if row["portable_path"] == "foundry.toml"
    )
    observation["after_sha256"] = "f" * 64
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_CAPTURE_DRIFT",
        mutation,
        leaves,
    )


def test_a3_same_path_size_different_dependency_content_rejected() -> None:
    law = "A3/content-digest-not-path-size"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation_leaves = dict(leaves)
    identity = "deps:vendor/nested/Lib.sol"
    original = mutation_leaves[identity]
    mutation_leaves[identity] = b"X" * len(original)
    assert len(mutation_leaves[identity]) == len(original)
    assert mutation_leaves[identity] != original
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_PACK_LEAF_DIGEST_MISMATCH",
        document,
        mutation_leaves,
    )


def test_a3_nested_dependency_and_casefold_collisions_rejected() -> None:
    law = "A3/nested-dependency-casefold-uniqueness"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation = deepcopy(document)
    duplicate = deepcopy(
        next(
            row
            for row in mutation["files"]
            if row["portable_path"] == "vendor/nested/Lib.sol"
        )
    )
    duplicate["portable_path"] = "vendor/NESTED/lib.sol"
    duplicate["casefold_key"] = "deps:vendor/nested/lib.sol"
    duplicate["physical_capture_identity_digest"] = hashlib.sha256(
        b"case-alias"
    ).hexdigest()
    mutation["files"].append(duplicate)
    mutation["files"].sort(
        key=lambda row: (row["root_id"], row["portable_path"])
    )
    duplicate_observation = {
        "root_id": duplicate["root_id"],
        "portable_path": duplicate["portable_path"],
        "before_identity_digest": duplicate[
            "physical_capture_identity_digest"
        ],
        "after_identity_digest": duplicate[
            "physical_capture_identity_digest"
        ],
        "before_sha256": duplicate["sha256"],
        "after_sha256": duplicate["sha256"],
        "link_state": duplicate["link_state"],
    }
    mutation["capture_observations"].append(duplicate_observation)
    mutation["pack_manifest"]["file_count"] += 1
    mutation["pack_manifest"]["total_leaf_bytes"] += duplicate["size"]
    duplicate_identity = "deps:vendor/NESTED/lib.sol"
    mutation["pack_manifest"]["leaf_identities"].append(duplicate_identity)
    mutation["pack_manifest"]["leaf_identities"].sort()
    mutation_leaves = dict(leaves)
    mutation_leaves[duplicate_identity] = leaves[
        "deps:vendor/nested/Lib.sol"
    ]
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_CASEFOLD_PATH_COLLISION",
        mutation,
        mutation_leaves,
    )


def test_a3_hardlink_reparse_substitution_before_materialization_rejected() -> None:
    law = "A3/no-link-substitution-before-materialization"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation = deepcopy(document)
    observation = next(
        row
        for row in mutation["capture_observations"]
        if row["portable_path"] == "src/Main.sol"
    )
    observation["link_state"] = "HARDLINK_OR_REPARSE_SUBSTITUTED"
    observation["after_identity_digest"] = hashlib.sha256(
        b"substituted-identity"
    ).hexdigest()
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_LINK_OR_IDENTITY_SUBSTITUTION",
        mutation,
        leaves,
    )


def test_a3_missing_content_pack_leaf_rejected() -> None:
    law = "A3/complete-content-pack-leaf-denominator"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation_leaves = dict(leaves)
    mutation_leaves.pop("generated:bindings/Generated.sol")
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_MISSING_PACK_LEAF",
        document,
        mutation_leaves,
    )


def test_a3_live_project_fallback_after_seal_is_impossible() -> None:
    law = "A3/no-live-project-fallback-after-seal"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation = deepcopy(document)
    mutation["materialization"] = {
        "source": "LIVE_PROJECT_FALLBACK",
        "live_project_fallback": True,
    }
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_LIVE_PROJECT_FALLBACK_FORBIDDEN",
        mutation,
        leaves,
    )


def test_a3_tool_support_file_and_total_capture_ceiling_are_authoritative() -> None:
    law = "A3/tool-support-enters-total-capture-ceiling"
    document, leaves = _positive_capture()
    validator = _validator(law)
    _accept_positive(validator, law, document, leaves)

    mutation = deepcopy(document)
    total = mutation["pack_manifest"]["total_leaf_bytes"]
    tool_support_size = next(
        row["size"]
        for row in mutation["files"]
        if row["input_class"] == "TOOL_SUPPORT"
    )
    assert tool_support_size > 0
    mutation["capture_policy"]["max_total_bytes"] = total - 1
    _resign(mutation)
    _require_targeted_rejection(
        validator,
        law,
        "PF_A3_TOTAL_CAPTURE_CEILING_EXCEEDED",
        mutation,
        leaves,
    )
