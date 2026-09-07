#!/usr/bin/env python3
"""Replay the public-safe portion of the archived model-routing evidence.

The archived validators are immutable historical artifacts.  This tool does not
rewrite them, inject sanitized bytes under raw names, or inspect ignored/private
locations.  It runs a validator only when its complete exact prerequisite
closure is public and reports every other validator as explicitly blocked.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
from typing import Any


REPLAY_MANIFEST = Path("docs/continuation/MODEL_ROUTING_PORTABLE_REPLAY.json")
VALIDATOR_GLOB = "validate_plamen_model_routing*.py"
CORPUS_SOURCE_COUNT = 131
CORPUS_SOURCE_BYTES = 5_372_712
CORPUS_INVENTORY_SHA256 = (
    "babc11675df83454556a5ccee534db3a0f0fa63f9e79a32b37d9b2586c878ded"
)
VALID_REQUIREMENT_KINDS = {
    "raw_source_with_sanitized_port",
    "omitted_private_review_witness",
    "frozen_environment",
}
PUBLICATION_MODES = {
    "EXACT",
    "SANITIZED",
    "SANITIZED_WITH_PRIVATE_RAW_GAP",
}


class ReplayIntegrityError(RuntimeError):
    """The public replay projection is incomplete, malformed, or changed."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ReplayIntegrityError(f"JSON_OBJECT_REQUIRED:{path.name}")
    return value


def _safe_path(root: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts:
        raise ReplayIntegrityError(f"UNSAFE_REPOSITORY_PATH:{relative}")
    resolved_root = root.resolve()
    resolved = (resolved_root / Path(*candidate.parts)).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError as exc:
        raise ReplayIntegrityError(f"REPOSITORY_PATH_ESCAPE:{relative}") from exc
    return resolved


def _corpus_index(corpus: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if corpus.get("schema") != "plamen.continuation.corpus-manifest.v2":
        raise ReplayIntegrityError("CORPUS_MANIFEST_SCHEMA_MISMATCH")
    by_path: dict[str, Any] = {}
    by_identity: dict[str, Any] = {}
    inventory = corpus.get("source_inventory", [])
    if not isinstance(inventory, list) or len(inventory) != CORPUS_SOURCE_COUNT:
        raise ReplayIntegrityError("CORPUS_SOURCE_DENOMINATOR_MISMATCH")
    if sum(
        row.get("source_bytes", -1) if isinstance(row, dict) else -1
        for row in inventory
    ) != CORPUS_SOURCE_BYTES:
        raise ReplayIntegrityError("CORPUS_SOURCE_BYTES_MISMATCH")
    inventory_raw = b"".join(
        (
            f"Downloads/{row.get('source_identity')}\t{row.get('source_bytes')}\t"
            f"{row.get('source_sha256')}\n"
        ).encode("utf-8")
        for row in sorted(inventory, key=lambda item: item.get("source_identity", ""))
    )
    denominator = corpus.get("discovery_denominator", {})
    if (
        hashlib.sha256(inventory_raw).hexdigest() != CORPUS_INVENTORY_SHA256
        or denominator.get("inventory_record_sha256") != CORPUS_INVENTORY_SHA256
    ):
        raise ReplayIntegrityError("CORPUS_INVENTORY_DIGEST_MISMATCH")
    for row in inventory:
        identity = row.get("source_identity")
        publication = row.get("publication", {})
        portable = publication.get("portable_path")
        if not isinstance(identity, str) or not isinstance(portable, str):
            continue
        if identity in by_identity or portable in by_path:
            raise ReplayIntegrityError("CORPUS_SOURCE_IDENTITY_OR_PATH_DUPLICATE")
        by_identity[identity] = row
        by_path[portable] = row
    return by_path, by_identity


def _verify_public_ref(
    root: Path, relative: str, corpus_by_path: dict[str, Any]
) -> dict[str, Any]:
    row = corpus_by_path.get(relative)
    if row is None:
        raise ReplayIntegrityError(f"PUBLIC_REF_NOT_GOVERNED:{relative}")
    publication = row["publication"]
    expected = publication.get("portable_sha256")
    expected_bytes = publication.get("portable_bytes")
    mode = publication.get("mode")
    if mode not in PUBLICATION_MODES:
        raise ReplayIntegrityError(f"PUBLIC_REF_MODE_INVALID:{relative}")
    if not isinstance(expected, str) or len(expected) != 64:
        raise ReplayIntegrityError(f"PUBLIC_REF_DIGEST_INVALID:{relative}")
    if type(expected_bytes) is not int or expected_bytes < 0:
        raise ReplayIntegrityError(f"PUBLIC_REF_SIZE_INVALID:{relative}")
    if (
        publication.get("port_ref") != relative
        or publication.get("port_sha256") != expected
        or publication.get("port_bytes") != expected_bytes
    ):
        raise ReplayIntegrityError(f"PUBLIC_REF_PORT_ALIAS_MISMATCH:{relative}")
    path = _safe_path(root, relative)
    if not path.is_file() or path.is_symlink():
        raise ReplayIntegrityError(f"PUBLIC_REF_MISSING:{relative}")
    raw = path.read_bytes()
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        raise ReplayIntegrityError(f"PUBLIC_REF_HASH_MISMATCH:{relative}")
    if len(raw) != expected_bytes:
        raise ReplayIntegrityError(f"PUBLIC_REF_SIZE_MISMATCH:{relative}")
    if mode == "EXACT" and (
        row.get("source_sha256") != actual
        or row.get("source_bytes") != len(raw)
        or publication.get("transformation") != "exact"
    ):
        raise ReplayIntegrityError(f"EXACT_PUBLIC_REF_BINDING_MISMATCH:{relative}")
    if mode != "EXACT" and publication.get("transformation") != "sanitized":
        raise ReplayIntegrityError(f"SANITIZED_PUBLIC_REF_BINDING_MISMATCH:{relative}")
    return {
        "path": relative,
        "sha256": actual,
        "bytes": len(raw),
        "publication_mode": mode,
    }


def _validator_string_literals(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
    except (OSError, SyntaxError, UnicodeError) as exc:
        raise ReplayIntegrityError(
            f"VALIDATOR_SOURCE_PARSE_FAILED:{path.name}"
        ) from exc
    return {
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }


def _contains_mapping(value: Any, expected: dict[str, Any]) -> bool:
    if isinstance(value, dict):
        if all(value.get(key) == item for key, item in expected.items()):
            return True
        return any(_contains_mapping(item, expected) for item in value.values())
    if isinstance(value, list):
        return any(_contains_mapping(item, expected) for item in value)
    return False


def evaluate(root: Path) -> dict[str, Any]:
    root = root.resolve()
    manifest_path = _safe_path(root, REPLAY_MANIFEST.as_posix())
    manifest = _json(manifest_path)
    if manifest.get("schema") != "plamen.continuation.model-routing-portable-replay.v1":
        raise ReplayIntegrityError("REPLAY_MANIFEST_SCHEMA_MISMATCH")
    policy = manifest.get("claim_policy")
    if policy != {
        "sanitized_is_not_raw": True,
        "semantic_evidence_is_not_archival_pass": True,
        "private_search_is_forbidden": True,
        "declared_nonpublic_requirements_block_execution": True,
    }:
        raise ReplayIntegrityError("REPLAY_CLAIM_POLICY_MISMATCH")

    corpus_ref = manifest.get("corpus_manifest_ref")
    if not isinstance(corpus_ref, str):
        raise ReplayIntegrityError("CORPUS_MANIFEST_REF_INVALID")
    corpus = _json(_safe_path(root, corpus_ref))
    corpus_by_path, corpus_by_identity = _corpus_index(corpus)
    public_corpus_integrity = [
        _verify_public_ref(root, relative, corpus_by_path)
        for relative in sorted(corpus_by_path)
    ]
    if len(public_corpus_integrity) != 127:
        raise ReplayIntegrityError("PUBLIC_CORPUS_PORT_DENOMINATOR_MISMATCH")

    requirements = manifest.get("requirements")
    validators = manifest.get("validators")
    if not isinstance(requirements, dict) or not isinstance(validators, list):
        raise ReplayIntegrityError("REPLAY_MANIFEST_SHAPE_INVALID")

    requirement_observations: dict[str, dict[str, Any]] = {}
    for requirement_id, requirement in requirements.items():
        if not isinstance(requirement_id, str) or not isinstance(requirement, dict):
            raise ReplayIntegrityError("REQUIREMENT_SHAPE_INVALID")
        kind = requirement.get("kind")
        if kind not in VALID_REQUIREMENT_KINDS:
            raise ReplayIntegrityError(f"REQUIREMENT_KIND_INVALID:{requirement_id}")
        evidence_refs = requirement.get("public_evidence_refs")
        if not isinstance(evidence_refs, list) or not evidence_refs:
            raise ReplayIntegrityError(f"REQUIREMENT_PUBLIC_EVIDENCE_MISSING:{requirement_id}")
        evidence = [
            _verify_public_ref(root, ref, corpus_by_path)
            for ref in evidence_refs
            if isinstance(ref, str)
        ]
        if len(evidence) != len(evidence_refs):
            raise ReplayIntegrityError(f"REQUIREMENT_PUBLIC_EVIDENCE_INVALID:{requirement_id}")

        expected_raw = requirement.get("expected_raw_sha256")
        identity = requirement.get("source_identity")
        if kind != "frozen_environment":
            if not isinstance(expected_raw, str) or len(expected_raw) != 64:
                raise ReplayIntegrityError(f"REQUIREMENT_RAW_DIGEST_INVALID:{requirement_id}")
            if any(item["sha256"] == expected_raw for item in evidence):
                raise ReplayIntegrityError(f"SANITIZED_OR_SEMANTIC_REF_EQUALS_RAW:{requirement_id}")
        if kind == "raw_source_with_sanitized_port":
            row = corpus_by_identity.get(identity)
            if row is None or row.get("source_sha256") != expected_raw:
                raise ReplayIntegrityError(f"RAW_SOURCE_CORPUS_BINDING_MISMATCH:{requirement_id}")
            if row["publication"].get("portable_path") not in evidence_refs:
                raise ReplayIntegrityError(
                    f"RAW_SOURCE_SEMANTIC_PORT_MISMATCH:{requirement_id}"
                )
        if kind == "frozen_environment":
            repository_identity = requirement.get("expected_repository_identity")
            if not isinstance(repository_identity, dict) or set(repository_identity) != {
                "branch", "head",
            }:
                raise ReplayIntegrityError(
                    f"FROZEN_REPOSITORY_IDENTITY_INVALID:{requirement_id}"
                )
            structured_evidence = []
            for ref in evidence_refs:
                path = _safe_path(root, ref)
                if path.suffix.lower() == ".json":
                    structured_evidence.append(_json(path))
            if not any(
                _contains_mapping(item, repository_identity)
                for item in structured_evidence
            ):
                raise ReplayIntegrityError(
                    f"FROZEN_REPOSITORY_EVIDENCE_MISMATCH:{requirement_id}"
                )

        requirement_observations[requirement_id] = {
            "id": requirement_id,
            "kind": kind,
            "source_identity": identity,
            "expected_raw_sha256": expected_raw,
            "status": "NONPUBLIC_EXACT_PREREQUISITE",
            "reason": requirement.get("reason"),
            "public_semantic_evidence": evidence,
        }
        if kind == "frozen_environment":
            requirement_observations[requirement_id]["expected_repository_identity"] = (
                requirement.get("expected_repository_identity")
            )
        required_by = requirement.get("required_by_validator_id")
        if not isinstance(required_by, str) or not required_by:
            raise ReplayIntegrityError(
                f"REQUIREMENT_VALIDATOR_ASSIGNMENT_INVALID:{requirement_id}"
            )

    declared_ids: list[str] = []
    validator_by_id: dict[str, dict[str, Any]] = {}
    for spec in validators:
        if not isinstance(spec, dict) or not isinstance(spec.get("id"), str):
            raise ReplayIntegrityError("VALIDATOR_SPEC_INVALID")
        validator_id = spec["id"]
        if validator_id in validator_by_id:
            raise ReplayIntegrityError(f"VALIDATOR_ID_DUPLICATE:{validator_id}")
        validator_by_id[validator_id] = spec
        declared_ids.append(validator_id)

    actual_validator_refs = {
        path.relative_to(root).as_posix()
        for path in (root / "docs" / "continuation" / "research").glob(VALIDATOR_GLOB)
    }
    declared_validator_refs = {spec.get("validator_ref") for spec in validators}
    if actual_validator_refs != declared_validator_refs:
        raise ReplayIntegrityError("VALIDATOR_DENOMINATOR_MISMATCH")

    results: list[dict[str, Any]] = []
    status_by_id: dict[str, str] = {}
    referenced_requirement_ids: set[str] = set()
    validator_names = {
        item: PurePosixPath(spec["validator_ref"]).name
        for item, spec in validator_by_id.items()
    }
    for spec in validators:
        validator_id = spec["id"]
        validator_ref = spec.get("validator_ref")
        package_refs = spec.get("package_refs")
        predecessor_ids = spec.get("predecessor_ids")
        direct_requirement_ids = spec.get("nonpublic_requirement_ids")
        if (
            not isinstance(validator_ref, str)
            or not isinstance(package_refs, list)
            or not isinstance(predecessor_ids, list)
            or not isinstance(direct_requirement_ids, list)
        ):
            raise ReplayIntegrityError(f"VALIDATOR_SPEC_SHAPE_INVALID:{validator_id}")
        if any(item not in status_by_id for item in predecessor_ids):
            raise ReplayIntegrityError(f"VALIDATOR_PREDECESSOR_ORDER_INVALID:{validator_id}")
        if any(item not in requirements for item in direct_requirement_ids):
            raise ReplayIntegrityError(f"VALIDATOR_REQUIREMENT_UNKNOWN:{validator_id}")
        if len(set(predecessor_ids)) != len(predecessor_ids):
            raise ReplayIntegrityError(f"VALIDATOR_PREDECESSOR_DUPLICATE:{validator_id}")
        if len(set(direct_requirement_ids)) != len(direct_requirement_ids):
            raise ReplayIntegrityError(f"VALIDATOR_REQUIREMENT_DUPLICATE:{validator_id}")
        referenced_requirement_ids.update(direct_requirement_ids)

        validator_integrity = _verify_public_ref(root, validator_ref, corpus_by_path)
        if validator_integrity["publication_mode"] != "EXACT":
            raise ReplayIntegrityError(f"VALIDATOR_NOT_EXACT:{validator_id}")
        validator_path = _safe_path(root, validator_ref)
        string_literals = _validator_string_literals(validator_path)
        observed_predecessors = {
            item
            for item, filename in validator_names.items()
            if item != validator_id and filename in string_literals
        }
        if observed_predecessors != set(predecessor_ids):
            raise ReplayIntegrityError(
                f"VALIDATOR_PREDECESSOR_BINDING_MISMATCH:{validator_id}"
            )
        for requirement_id in direct_requirement_ids:
            requirement = requirements[requirement_id]
            if requirement["required_by_validator_id"] != validator_id:
                raise ReplayIntegrityError(
                    f"REQUIREMENT_VALIDATOR_ASSIGNMENT_MISMATCH:{requirement_id}"
                )
            if requirement["kind"] == "frozen_environment":
                binding_literal = requirement.get("validator_binding_literal")
                if (
                    not isinstance(binding_literal, str)
                    or binding_literal not in string_literals
                ):
                    raise ReplayIntegrityError(
                        f"FROZEN_VALIDATOR_BINDING_MISMATCH:{requirement_id}"
                    )
                continue
            expected_raw = requirement["expected_raw_sha256"]
            source_identity = requirement["source_identity"]
            review_hash_unbound = (
                requirement["kind"] == "omitted_private_review_witness"
                and expected_raw not in string_literals
            )
            source_hash_or_name_unbound = (
                requirement["kind"] == "raw_source_with_sanitized_port"
                and expected_raw not in string_literals
                and source_identity not in string_literals
            )
            if review_hash_unbound or source_hash_or_name_unbound:
                raise ReplayIntegrityError(
                    f"VALIDATOR_REQUIREMENT_BINDING_MISMATCH:{validator_id}:{requirement_id}"
                )
        package_integrity = [
            _verify_public_ref(root, ref, corpus_by_path)
            for ref in package_refs
            if isinstance(ref, str)
        ]
        if len(package_integrity) != len(package_refs):
            raise ReplayIntegrityError(f"VALIDATOR_PACKAGE_REF_INVALID:{validator_id}")

        predecessor_blocks = [
            item
            for item in predecessor_ids
            if status_by_id[item] != "EXACT_ARCHIVAL_PASS"
        ]
        blocked = bool(direct_requirement_ids or predecessor_blocks)
        if not blocked and any(
            item["publication_mode"] != "EXACT"
            for item in package_integrity
        ):
            raise ReplayIntegrityError(
                f"RUNNABLE_VALIDATOR_PACKAGE_NOT_EXACT:{validator_id}"
            )
        result: dict[str, Any] = {
            "id": validator_id,
            "validator": validator_integrity,
            "package_integrity": package_integrity,
            "predecessor_ids": predecessor_ids,
            "direct_nonpublic_requirements": [
                requirement_observations[item] for item in direct_requirement_ids
            ],
            "blocked_predecessor_ids": predecessor_blocks,
        }
        if blocked:
            result["status"] = "BLOCKED_NONPUBLIC_PREREQUISITE"
            status_by_id[validator_id] = result["status"]
            results.append(result)
            continue

        completed = subprocess.run(
            [sys.executable, "-I", str(_safe_path(root, validator_ref))],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        result["returncode"] = completed.returncode
        if completed.returncode == 0:
            result["status"] = "EXACT_ARCHIVAL_PASS"
            result["stdout_lines"] = [
                line for line in completed.stdout.splitlines() if line
            ]
        else:
            result["status"] = "EXACT_ARCHIVAL_FAIL"
            result["stdout_sha256"] = hashlib.sha256(
                completed.stdout.encode("utf-8")
            ).hexdigest()
            result["stderr_sha256"] = hashlib.sha256(
                completed.stderr.encode("utf-8")
            ).hexdigest()
            result["stdout_line_count"] = len(completed.stdout.splitlines())
            result["stderr_line_count"] = len(completed.stderr.splitlines())
        status_by_id[validator_id] = result["status"]
        results.append(result)

    if referenced_requirement_ids != set(requirements):
        raise ReplayIntegrityError("REQUIREMENT_DENOMINATOR_MISMATCH")

    summary = {
        "validator_count": len(results),
        "public_corpus_port_count": len(public_corpus_integrity),
        "exact_archival_pass": sum(
            item["status"] == "EXACT_ARCHIVAL_PASS" for item in results
        ),
        "exact_archival_fail": sum(
            item["status"] == "EXACT_ARCHIVAL_FAIL" for item in results
        ),
        "blocked_nonpublic_prerequisite": sum(
            item["status"] == "BLOCKED_NONPUBLIC_PREREQUISITE" for item in results
        ),
        "public_evidence_integrity": "PASS",
        "archival_complete": all(
            item["status"] == "EXACT_ARCHIVAL_PASS" for item in results
        ),
    }
    expected = manifest.get("expected_summary", {})
    if (
        expected.get("validator_count") != summary["validator_count"]
        or expected.get("public_corpus_port_count")
        != summary["public_corpus_port_count"]
        or expected.get("public_exact_runnable")
        != summary["exact_archival_pass"] + summary["exact_archival_fail"]
        or expected.get("declared_blocked")
        != summary["blocked_nonpublic_prerequisite"]
    ):
        raise ReplayIntegrityError("REPLAY_EXPECTED_SUMMARY_MISMATCH")

    return {
        "schema": "plamen.continuation.model-routing-portable-replay-result.v1",
        "claim": "PUBLIC_SAFE_REPLAY_WITH_EXPLICIT_ARCHIVAL_BLOCKS",
        "summary": summary,
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Public checkout root (defaults to the checkout containing this script).",
    )
    parser.add_argument(
        "--accept-declared-blocks",
        action="store_true",
        help="Return zero when every runnable validator passes and all other rows are declared blocks.",
    )
    args = parser.parse_args()
    try:
        report = evaluate(args.root)
    except ReplayIntegrityError as exc:
        report = {
            "schema": "plamen.continuation.model-routing-portable-replay-result.v1",
            "claim": "INTEGRITY_FAILURE",
            "error": str(exc),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    except (OSError, ValueError, json.JSONDecodeError):
        report = {
            "schema": "plamen.continuation.model-routing-portable-replay-result.v1",
            "claim": "INTEGRITY_FAILURE",
            "error": "PUBLIC_REPLAY_IO_OR_PARSE_FAILURE",
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    summary = report["summary"]
    if summary["exact_archival_fail"]:
        return 1
    if summary["blocked_nonpublic_prerequisite"] and not args.accept_declared_blocks:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
