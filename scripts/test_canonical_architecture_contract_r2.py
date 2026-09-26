"""Executable OWN-v2 migration, identity, and no-scope-loss contract.

The v2 registry is not an independently authored summary.  It is the exact
read-old/write-new projection required by section 2.4 of the Program Facts
runtime specification: all 146 v1 rows survive in order, twenty PFR rows are
appended, and graph moves remain explicit redirects.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import unicodedata

import pytest


ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = Path("architecture/canonical-requirement-ownership.v2.json")
PREDECESSOR_PATH = Path("architecture/canonical-requirement-ownership.v1.json")
PROGRAM_FACTS_PATH = Path("architecture/program-facts-runtime-cutover-spec.md")
GRAPH_SUCCESSOR_PATH = Path("architecture/ecosystem-graph-provider-contract.v2.md")

SCHEMA = "plamen.canonical_requirement_ownership.v2"
PREDECESSOR_SCHEMA = "plamen.canonical_requirement_ownership.v1"
HEX64 = re.compile(r"[0-9a-f]{64}")
IDENTIFIER_V3 = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}")
OWNER_KEYS = (
    "evaluation",
    "graph",
    "method_catalog",
    "program_facts_runtime",
    "rfc",
    "scheduler",
)
PFR_ANCHORS = (
    "1-authority-boundary-and-hard-preconditions",
    "2-required-public-contract-amendment",
    "3-deterministic-primitives",
    "4-exact-schemas-and-artifact-paths",
    "5-acyclic-identity-construction",
    "6-sub-stages-and-exact-ownership",
    "7-crash-safe-generation-indirected-publication",
    "8-deterministic-runner-and-replay",
    "9-ecosystem-host-toolchain-and-package-decisions",
    "10-failure-taxonomy",
    "11-cache-concurrency-migration-and-rollback",
    "12-independent-oracle-and-exact-acceptance-denominator",
    "13-security-and-no-self-certification",
    "14-governance-freeze-and-independent-review-workflow",
    "15-mandatory-gate-3-order",
    "16-current-blockers-and-exact-non-cutover-consequences",
    "17-source-and-decision-provenance",
    "18-eight-residual-implementation-readiness-repair-map",
    "19-explicit-invariants-and-assumptions",
    "20-non-goals-and-authority-ceiling",
)


class OwnershipV2Error(ValueError):
    """OWN-v2 is malformed, stale, or not the exact accepted migration."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OwnershipV2Error(message)


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OwnershipV2Error(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_json(raw: bytes, label: str) -> object:
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(
            text,
            object_pairs_hook=_strict_object,
            parse_constant=lambda value: (_ for _ in ()).throw(
                OwnershipV2Error(f"{label}: invalid JSON constant {value}")
            ),
        )
    except OwnershipV2Error:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise OwnershipV2Error(f"{label}: invalid strict JSON: {exc}") from exc


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OwnershipV2Error(f"value is not canonical JSON: {exc}") from exc


def _body_sha256(registry: dict[str, object]) -> str:
    body = {key: value for key, value in registry.items()
            if key != "registry_body_sha256"}
    return hashlib.sha256(_canonical_json(body)).hexdigest()


def _safe_path(value: object) -> Path:
    _require(isinstance(value, str) and bool(value), "nonempty path required")
    assert isinstance(value, str)
    _require("\\" not in value, "backslash path rejected")
    _require(
        re.fullmatch(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", value)
        is not None,
        "non-portable path rejected",
    )
    path = Path(value)
    _require(
        not path.is_absolute()
        and not path.anchor
        and not path.drive
        and not path.root
        and "." not in path.parts
        and ".." not in path.parts,
        "escaping path rejected",
    )
    return path


def _read_inside(root: Path, relative: Path) -> bytes:
    resolved_root = root.resolve()
    resolved = (root / relative).resolve()
    _require(resolved.is_relative_to(resolved_root), "path escaped source root")
    try:
        first = resolved.read_bytes()
        second = resolved.read_bytes()
    except OSError as exc:
        raise OwnershipV2Error(f"cannot read {relative.as_posix()}: {exc}") from exc
    _require(first == second, f"unstable read: {relative.as_posix()}")
    return first


def _file_identity(root: Path, relative: Path) -> dict[str, object]:
    raw = _read_inside(root, relative)
    return {
        "path": relative.as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
    }


def _normalized_sha256(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise OwnershipV2Error(f"owner is not strict UTF-8: {exc}") from exc
    normalized = unicodedata.normalize(
        "NFC", text.replace("\r\n", "\n").replace("\r", "\n")
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _identifier(value: object, label: str) -> str:
    _require(isinstance(value, str), f"{label}: string required")
    assert isinstance(value, str)
    _require(IDENTIFIER_V3.fullmatch(value) is not None, f"{label}: invalid IdentifierV3")
    return value


def _legacy_heading_token(value: str) -> str:
    value = re.sub(r"^[0-9]+(?:\.[0-9]+)*\.?[ ]+", "", value.strip())
    output: list[str] = []
    for character in value:
        if "A" <= character <= "Z":
            character = character.lower()
        if character == " ":
            output.append("-")
        elif (
            "a" <= character <= "z"
            or "0" <= character <= "9"
            or character in "-_"
        ):
            output.append(character)
    return "".join(output)


def _heading_ordinals(raw: bytes) -> dict[str, list[int]]:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise OwnershipV2Error(f"Markdown owner is not UTF-8: {exc}") from exc
    result: dict[str, list[int]] = {}
    ordinal = 0
    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        match = re.fullmatch(r"[ \t]{0,3}#{1,6}[ \t]+(.+?)[ \t]*", line)
        if match is None:
            continue
        ordinal += 1
        heading = re.sub(r"[ \t]+#+[ \t]*$", "", match.group(1)).strip()
        result.setdefault(_legacy_heading_token(heading), []).append(ordinal)
    return result


def _pointer_resolves(document: object, pointer: str) -> bool:
    if pointer == "":
        return True
    if not pointer.startswith("/"):
        return False
    current = document
    for raw_token in pointer[1:].split("/"):
        if re.fullmatch(r"(?:[^~]|~[01])*", raw_token) is None:
            return False
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif (
            isinstance(current, list)
            and re.fullmatch(r"(?:0|[1-9][0-9]*)", token) is not None
            and int(token) < len(current)
        ):
            current = current[int(token)]
        else:
            return False
    return True


def _expected_legacy_requirement(
    row: object,
    ordinal: int,
    *,
    owner_raw: dict[str, bytes],
    owner_format: dict[str, str],
) -> dict[str, object]:
    _require(isinstance(row, dict), "v1 requirement row must be an object")
    assert isinstance(row, dict)
    _require(set(row) == {"anchor", "id", "owner", "status"}, "v1 row is not closed")
    owner_key = _identifier(row["owner"], "v1 owner")
    requirement_id = _identifier(row["id"], "v1 requirement id")
    status = row["status"]
    _require(
        status in {"REPRESENTED_WITH_RESIDUAL", "REPRESENTED_WITH_EXTERNAL_RESIDUAL"},
        "v1 status is not migratable",
    )
    anchor = row["anchor"]
    _require(isinstance(anchor, str), "v1 anchor must be a string")
    assert isinstance(anchor, str)
    if anchor.startswith("/"):
        _require(owner_format[owner_key] == "json", "JSON Pointer used for non-JSON owner")
        document = _strict_json(owner_raw[owner_key], owner_key)
        _require(_pointer_resolves(document, anchor), "v1 JSON Pointer does not resolve")
        anchor_ref = {"kind": "JSON_POINTER", "value": anchor}
        section_ordinal: int | None = None
    else:
        _identifier(anchor, "v1 Markdown anchor")
        _require(owner_format[owner_key] == "markdown", "Markdown anchor used for non-Markdown owner")
        matches = _heading_ordinals(owner_raw[owner_key]).get(anchor, [])
        _require(len(matches) == 1, "v1 Markdown anchor is missing or ambiguous")
        anchor_ref = {"kind": "MARKDOWN_ANCHOR", "value": anchor}
        section_ordinal = matches[0]
    return {
        "anchor": anchor_ref,
        "owner_key": owner_key,
        "registry_ordinal": ordinal,
        "requirement_id": requirement_id,
        "section_ordinal_or_null": section_ordinal,
        "status": status,
    }


def validate_registry_payload(registry: object, *, root: Path = ROOT) -> dict[str, int]:
    """Validate the exact closed v1-to-v2 projection against current bytes."""

    _require(isinstance(registry, dict), "OWN-v2 must be an object")
    assert isinstance(registry, dict)
    _require(
        set(registry)
        == {"owners", "predecessor", "redirects", "registry_body_sha256",
            "requirements", "schema_version"},
        "OWN-v2 top level is not closed",
    )
    _require(registry["schema_version"] == SCHEMA, "OWN-v2 schema mismatch")
    _require(
        isinstance(registry["registry_body_sha256"], str)
        and HEX64.fullmatch(registry["registry_body_sha256"]) is not None,
        "OWN-v2 body digest is malformed",
    )
    _require(registry["registry_body_sha256"] == _body_sha256(registry),
             "OWN-v2 body digest mismatch")

    predecessor = registry["predecessor"]
    _require(isinstance(predecessor, dict), "predecessor identity required")
    _require(set(predecessor) == {"path", "sha256", "size_bytes"},
             "predecessor identity is not closed")
    assert isinstance(predecessor, dict)
    _require(predecessor == _file_identity(root, PREDECESSOR_PATH),
             "predecessor identity mismatch")
    predecessor_raw = _read_inside(root, PREDECESSOR_PATH)
    predecessor_value = _strict_json(predecessor_raw, PREDECESSOR_PATH.as_posix())
    _require(isinstance(predecessor_value, dict), "OWN-v1 must be an object")
    assert isinstance(predecessor_value, dict)
    _require(set(predecessor_value) == {"owners", "requirements", "schema_version"},
             "OWN-v1 top level is not closed")
    _require(predecessor_value["schema_version"] == PREDECESSOR_SCHEMA,
             "OWN-v1 schema mismatch")
    v1_owners = predecessor_value["owners"]
    v1_requirements = predecessor_value["requirements"]
    _require(isinstance(v1_owners, dict) and len(v1_owners) == 5,
             "OWN-v1 must contain five owners")
    _require(isinstance(v1_requirements, list) and len(v1_requirements) == 146,
             "OWN-v1 must contain 146 requirements")
    assert isinstance(v1_owners, dict) and isinstance(v1_requirements, list)

    owners = registry["owners"]
    _require(isinstance(owners, list) and len(owners) == 6,
             "OWN-v2 must contain six owners")
    assert isinstance(owners, list)
    owner_keys = [row.get("owner_key") if isinstance(row, dict) else None for row in owners]
    _require(tuple(owner_keys) == OWNER_KEYS, "OWN-v2 owner order/denominator mismatch")
    owner_raw: dict[str, bytes] = {}
    owner_format: dict[str, str] = {}
    for row in owners:
        _require(isinstance(row, dict), "owner row must be an object")
        assert isinstance(row, dict)
        _require(
            set(row) == {"legacy_normalization_or_null", "normalized_owner_sha256",
                         "normative_document", "owner_key", "status"},
            "owner row is not closed",
        )
        owner_key = _identifier(row["owner_key"], "owner key")
        document = row["normative_document"]
        _require(isinstance(document, dict), "normative document identity required")
        assert isinstance(document, dict)
        _require(set(document) == {"path", "sha256", "size_bytes"},
                 "normative document identity is not closed")
        relative = _safe_path(document["path"])
        _require(document == _file_identity(root, relative),
                 f"stale normative document identity: {owner_key}")
        raw = _read_inside(root, relative)
        normalized_sha256 = _normalized_sha256(raw)
        _require(row["normalized_owner_sha256"] == normalized_sha256,
                 f"stale normalized owner digest: {owner_key}")
        owner_raw[owner_key] = raw
        if owner_key == "program_facts_runtime":
            _require(relative == PROGRAM_FACTS_PATH, "Program Facts owner path mismatch")
            _require(row["legacy_normalization_or_null"] is None,
                     "new Program Facts owner cannot claim v1 lineage")
            _require(row["status"] == "CONTRACT_ONLY_PENDING_IMPLEMENTATION",
                     "Program Facts owner status mismatch")
            owner_format[owner_key] = "markdown"
            continue
        v1 = v1_owners.get(owner_key)
        _require(isinstance(v1, dict), f"missing inherited v1 owner: {owner_key}")
        assert isinstance(v1, dict)
        _require(set(v1) == {"content_sha256_lf_nfc", "format", "path"},
                 "v1 owner row is not closed")
        _require(v1["format"] in {"json", "markdown", "yaml"},
                 "v1 owner format invalid")
        _require(
            row["legacy_normalization_or_null"]
            == {"content_sha256_lf_nfc": v1["content_sha256_lf_nfc"],
                "format": v1["format"]},
            f"v1 normalization lineage mismatch: {owner_key}",
        )
        _require(relative == _safe_path(v1["path"]), f"v1 owner path changed: {owner_key}")
        _require(v1["content_sha256_lf_nfc"] == normalized_sha256,
                 f"v1 owner digest is stale: {owner_key}")
        _require(row["normalized_owner_sha256"] == v1["content_sha256_lf_nfc"],
                 f"inherited normalized digest changed: {owner_key}")
        _require(row["status"] == "INHERITED_V1", f"inherited owner status changed: {owner_key}")
        owner_format[owner_key] = str(v1["format"])
    _require(set(v1_owners) == set(OWNER_KEYS) - {"program_facts_runtime"},
             "unexpected v1 owner denominator")

    expected_requirements = [
        _expected_legacy_requirement(
            row, ordinal, owner_raw=owner_raw, owner_format=owner_format,
        )
        for ordinal, row in enumerate(v1_requirements)
    ]
    expected_requirements.extend(
        {
            "anchor": {"kind": "MARKDOWN_ANCHOR", "value": anchor},
            "owner_key": "program_facts_runtime",
            "registry_ordinal": 146 + index,
            "requirement_id": f"PFR-{index + 1:02d}",
            "section_ordinal_or_null": index + 1,
            "status": "CONTRACT_ONLY_PENDING_IMPLEMENTATION",
        }
        for index, anchor in enumerate(PFR_ANCHORS)
    )
    requirements = registry["requirements"]
    _require(isinstance(requirements, list), "requirements array required")
    _require(requirements == expected_requirements,
             "OWN-v2 requirements are not the exact no-scope-loss migration")
    requirement_ids = [row["requirement_id"] for row in expected_requirements]
    _require(len(requirement_ids) == len(set(requirement_ids)) == 166,
             "requirement identifiers are not unique and total")

    successor_identity = _file_identity(root, GRAPH_SUCCESSOR_PATH)
    expected_redirects = [
        {
            "predecessor_owner_key": "graph",
            "predecessor_requirement_id": f"GP-{index:02d}",
            "reason": "public-v3-shadow-contract-successor",
            "successor_document": successor_identity,
            "successor_owner_key": "graph",
        }
        for index in range(1, 19)
    ]
    redirects = registry["redirects"]
    _require(isinstance(redirects, list) and redirects == expected_redirects,
             "graph redirect denominator/order/identity mismatch")

    return {
        "owner_count": len(owners),
        "requirement_count": len(expected_requirements),
        "redirect_count": len(expected_redirects),
    }


def load_and_validate_registry(*, root: Path = ROOT) -> dict[str, int]:
    raw = _read_inside(root, REGISTRY_PATH)
    return validate_registry_payload(
        _strict_json(raw, REGISTRY_PATH.as_posix()), root=root,
    )


def _load_registry() -> dict[str, object]:
    value = _strict_json(_read_inside(ROOT, REGISTRY_PATH), REGISTRY_PATH.as_posix())
    assert isinstance(value, dict)
    return value


def _reseal(registry: dict[str, object]) -> None:
    registry["registry_body_sha256"] = _body_sha256(registry)


def test_current_ownership_v2_is_exact_six_owner_166_row_migration() -> None:
    assert load_and_validate_registry() == {
        "owner_count": 6,
        "redirect_count": 18,
        "requirement_count": 166,
    }
    requirements = _load_registry()["requirements"]
    assert isinstance(requirements, list)
    assert [
        (requirements[index]["registry_ordinal"], requirements[index]["requirement_id"])
        for index in (0, 145, 146, 165)
    ] == [(0, "MA-01"), (145, "PD-22"), (146, "PFR-01"), (165, "PFR-20")]


def test_v1_conversion_vectors_cover_statuses_cross_owner_anchors_and_pointers() -> None:
    owner_raw = {
        "first": b"# 1. Shared heading\n",
        "second": b"# 9 Shared heading\n",
        "catalog": b'{"schema_version":1,"a/b":{"~":"resolved"}}',
    }
    owner_format = {"first": "markdown", "second": "markdown", "catalog": "json"}
    first = _expected_legacy_requirement(
        {
            "anchor": "shared-heading",
            "id": "FIRST-01",
            "owner": "first",
            "status": "REPRESENTED_WITH_RESIDUAL",
        },
        0,
        owner_raw=owner_raw,
        owner_format=owner_format,
    )
    second = _expected_legacy_requirement(
        {
            "anchor": "shared-heading",
            "id": "SECOND-01",
            "owner": "second",
            "status": "REPRESENTED_WITH_EXTERNAL_RESIDUAL",
        },
        1,
        owner_raw=owner_raw,
        owner_format=owner_format,
    )
    pointer = _expected_legacy_requirement(
        {
            "anchor": "/schema_version",
            "id": "CATALOG-01",
            "owner": "catalog",
            "status": "REPRESENTED_WITH_RESIDUAL",
        },
        2,
        owner_raw=owner_raw,
        owner_format=owner_format,
    )
    assert first["section_ordinal_or_null"] == 1
    assert second["section_ordinal_or_null"] == 1
    assert first["status"] != second["status"]
    assert pointer["anchor"] == {"kind": "JSON_POINTER", "value": "/schema_version"}
    assert pointer["section_ordinal_or_null"] is None
    document = _strict_json(owner_raw["catalog"], "catalog")
    assert _pointer_resolves(document, "/a~1b/~0")
    assert not _pointer_resolves(document, "/a~2b")


@pytest.mark.parametrize("markdown", (b"# Different\n", b"# Target\n# Target\n"))
def test_v1_conversion_rejects_missing_or_ambiguous_markdown_anchor(
    markdown: bytes,
) -> None:
    with pytest.raises(OwnershipV2Error, match="missing or ambiguous"):
        _expected_legacy_requirement(
            {
                "anchor": "target",
                "id": "VECTOR-01",
                "owner": "vector",
                "status": "REPRESENTED_WITH_RESIDUAL",
            },
            0,
            owner_raw={"vector": markdown},
            owner_format={"vector": "markdown"},
        )


@pytest.mark.parametrize(
    "mutation",
    (
        "extra_top_level",
        "predecessor_digest",
        "owner_order",
        "owner_duplicate",
        "owner_path_escape",
        "owner_raw_identity",
        "owner_extra_field",
        "legacy_lineage",
        "pfr_claims_v1_lineage",
        "requirement_missing",
        "requirement_reordered",
        "requirement_extra_field",
        "requirement_owner",
        "requirement_status",
        "json_pointer_retagged",
        "section_ordinal",
        "pfr_ordinal",
        "redirect_missing",
        "redirect_reordered",
        "redirect_extra_field",
        "redirect_successor_identity",
    ),
)
def test_v2_rejects_resealed_scope_identity_and_order_mutations(mutation: str) -> None:
    registry = copy.deepcopy(_load_registry())
    owners = registry["owners"]
    requirements = registry["requirements"]
    redirects = registry["redirects"]
    assert isinstance(owners, list)
    assert isinstance(requirements, list)
    assert isinstance(redirects, list)
    if mutation == "extra_top_level":
        registry["shadow_authority"] = True
    elif mutation == "predecessor_digest":
        registry["predecessor"]["sha256"] = "0" * 64
    elif mutation == "owner_order":
        owners[0], owners[1] = owners[1], owners[0]
    elif mutation == "owner_duplicate":
        owners[-1] = copy.deepcopy(owners[0])
    elif mutation == "owner_path_escape":
        owners[0]["normative_document"]["path"] = "../outside.md"
    elif mutation == "owner_raw_identity":
        owners[0]["normative_document"]["sha256"] = "0" * 64
    elif mutation == "owner_extra_field":
        owners[0]["shadow_authority"] = True
    elif mutation == "legacy_lineage":
        owners[0]["legacy_normalization_or_null"]["content_sha256_lf_nfc"] = "0" * 64
    elif mutation == "pfr_claims_v1_lineage":
        owners[3]["legacy_normalization_or_null"] = {
            "content_sha256_lf_nfc": owners[3]["normalized_owner_sha256"],
            "format": "markdown",
        }
    elif mutation == "requirement_missing":
        requirements.pop(0)
    elif mutation == "requirement_reordered":
        requirements[0], requirements[1] = requirements[1], requirements[0]
    elif mutation == "requirement_extra_field":
        requirements[0]["shadow_authority"] = True
    elif mutation == "requirement_owner":
        requirements[0]["owner_key"] = "graph"
    elif mutation == "requirement_status":
        requirements[0]["status"] = "CONTRACT_ONLY_PENDING_IMPLEMENTATION"
    elif mutation == "json_pointer_retagged":
        row = next(row for row in requirements if row["requirement_id"] == "MC-01")
        row["anchor"]["kind"] = "MARKDOWN_ANCHOR"
    elif mutation == "section_ordinal":
        requirements[0]["section_ordinal_or_null"] += 1
    elif mutation == "pfr_ordinal":
        requirements[-1]["registry_ordinal"] = 166
    elif mutation == "redirect_missing":
        redirects.pop()
    elif mutation == "redirect_reordered":
        redirects[0], redirects[1] = redirects[1], redirects[0]
    elif mutation == "redirect_extra_field":
        redirects[0]["shadow_authority"] = True
    else:
        redirects[0]["successor_document"]["sha256"] = "0" * 64
    _reseal(registry)
    with pytest.raises(OwnershipV2Error):
        validate_registry_payload(registry)


def test_v2_rejects_body_mutation_without_reseal() -> None:
    registry = _load_registry()
    requirements = registry["requirements"]
    assert isinstance(requirements, list)
    requirements[0]["owner_key"] = "graph"
    with pytest.raises(OwnershipV2Error, match="body digest mismatch"):
        validate_registry_payload(registry)


def test_v2_json_loader_rejects_duplicate_keys() -> None:
    with pytest.raises(OwnershipV2Error, match="duplicate JSON key"):
        _strict_json(b'{"schema_version":"one","schema_version":"two"}', "fixture")
