"""Canonical architecture ownership, redirect, and duplication lint."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import unicodedata

import pytest

from method_card_catalog import (
    load_method_card_catalog,
    render_bound_prompt_fragment,
)


ROOT = Path(__file__).resolve().parents[1]
RFC = ROOT / "architecture" / "method-application-rfc.md"
GRAPH = ROOT / "architecture" / "ecosystem-graph-provider-contract.md"
SCHEDULER = ROOT / "architecture" / "work-unit-scheduler.md"
EVALUATION = ROOT / "benchmarks" / "application-coverage-evaluation-plan.md"
CATALOG = ROOT / "methodology" / "method-cards-v1.yaml"
KERNEL = ROOT / "prompts" / "shared" / "v2" / "breadth-semantic-operator-kernel.md"
FL_REDIRECT = ROOT / "architecture" / "finding-ledger-migration.md"
PD_REDIRECT = ROOT / "architecture" / "premise-and-disposition-policy.md"
OWNERSHIP_REGISTRY = (
    ROOT / "architecture" / "canonical-requirement-ownership.v1.json"
)
OWNERSHIP_SCHEMA = "plamen.canonical_requirement_ownership.v1"
OWNERSHIP_STATUSES = {
    "REPRESENTED_WITH_EXTERNAL_RESIDUAL",
    "REPRESENTED_WITH_RESIDUAL",
}
EXPECTED_OWNER_BY_FAMILY = {
    "EV": "evaluation",
    "FL": "rfc",
    "GP": "graph",
    "MA": "rfc",
    "MC": "method_catalog",
    "PD": "rfc",
    "WS": "scheduler",
}

REQUIRED_HEADINGS = {
    RFC: {
        "Premises",
        "Disposition policy",
        "Terminal negatives",
        "R10 migration",
        "Typed authority storage and migration",
        "Rollback/parser retirement",
    },
    GRAPH: {
        "Capability, precision, coverage, and execution vocabulary",
        "Provider conformance matrix",
    },
    SCHEDULER: {
        "Follow-up trigger contract",
        "Multi-output projection recovery",
    },
    EVALUATION: {
        "Lifecycle localization",
        "Typed-authority ablations",
        "Pashov adapter",
    },
}

EXPECTED_FL_REDIRECT = """# Finding-ledger migration — retired physical design

Status: non-normative compatibility redirect

The 2026-07-15 SQLite-first, universal-event-ledger, and global dual-write
design is retired. It is not Plamen semantic authority and must not be
reintroduced without a new reviewed supersession.

See [Typed authority storage and migration](method-application-rfc.md#typed-authority-storage-and-migration)
and [Rollback/parser retirement](method-application-rfc.md#rollbackparser-retirement).
"""

EXPECTED_PD_REDIRECT = """# Premise and disposition policy — relocated

Status: non-normative compatibility redirect

The normative policy is in [Premises](method-application-rfc.md#premises),
[Disposition policy](method-application-rfc.md#disposition-policy),
[Terminal negatives](method-application-rfc.md#terminal-negatives), and
[R10 migration](method-application-rfc.md#r10-migration).
No policy is defined at this historical path.
"""


def _headings(path: Path) -> set[str]:
    return _headings_from_text(path.read_text(encoding="utf-8"))


def _headings_from_text(text: str) -> set[str]:
    return {
        re.sub(
            r"^\d+(?:\.\d+)*\.?\s+",
            "",
            match.group(1).strip(),
        )
        for line in text.splitlines()
        if (match := re.fullmatch(r"#{1,6}\s+(.+?)\s*", line))
    }


def _slug(value: str) -> str:
    value = value.strip().casefold()
    value = re.sub(r"[^\w\s-]", "", value)
    return re.sub(r"\s+", "-", value).strip("-")


def _canonical_lf_nfc(raw: bytes) -> tuple[str, bytes]:
    text = raw.decode("utf-8")
    text = unicodedata.normalize(
        "NFC", text.replace("\r\n", "\n").replace("\r", "\n")
    )
    return text, text.encode("utf-8")


def _strict_json(text: str) -> object:
    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise AssertionError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(text, object_pairs_hook=reject_duplicates)


def _safe_owner_path(value: object) -> Path:
    assert isinstance(value, str) and value
    assert "\\" not in value
    assert re.fullmatch(
        r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*", value
    )
    path = Path(value)
    assert not path.is_absolute()
    assert not path.anchor and not path.drive and not path.root
    assert "." not in path.parts and ".." not in path.parts
    return path


def _json_pointer_resolves(document: object, pointer: str) -> bool:
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
        ):
            index = int(token)
            if index >= len(current):
                return False
            current = current[index]
        else:
            return False
    return True


def _expected_requirement_ids() -> set[str]:
    return {
        *(f"MA-{index:02d}" for index in range(1, 34)),
        *(f"GP-{index:02d}" for index in range(1, 19)),
        *(f"MC-{index:02d}" for index in range(1, 15)),
        *(f"FL-{index:02d}" for index in range(1, 17)),
        *(f"EV-{index:02d}" for index in range(1, 20)),
        *(f"WS-{index:02d}" for index in range(1, 25)),
        *(f"PD-{index:02d}" for index in range(1, 23)),
    }


def _validate_ownership_registry(
    registry: object,
    *,
    owner_bytes: dict[str, bytes],
) -> None:
    assert isinstance(registry, dict)
    assert set(registry) == {"owners", "requirements", "schema_version"}
    assert registry["schema_version"] == OWNERSHIP_SCHEMA
    owners = registry["owners"]
    requirements = registry["requirements"]
    assert isinstance(owners, dict) and owners
    assert isinstance(requirements, list)

    owner_documents: dict[str, tuple[str, object]] = {}
    for owner_id, owner in owners.items():
        assert isinstance(owner_id, str) and owner_id
        assert isinstance(owner, dict)
        assert set(owner) == {
            "content_sha256_lf_nfc",
            "format",
            "path",
        }
        _safe_owner_path(owner["path"])
        assert owner["format"] in {"json", "markdown"}
        raw = owner_bytes[owner_id]
        text, canonical = _canonical_lf_nfc(raw)
        assert hashlib.sha256(canonical).hexdigest() == (
            owner["content_sha256_lf_nfc"]
        )
        if owner["format"] == "markdown":
            parsed: object = {_slug(value) for value in _headings_from_text(text)}
        else:
            parsed = _strict_json(text)
        owner_documents[owner_id] = (owner["format"], parsed)

    ids: list[str] = []
    referenced_owners: set[str] = set()
    for row in requirements:
        assert isinstance(row, dict)
        assert set(row) == {"anchor", "id", "owner", "status"}
        requirement_id = row["id"]
        assert isinstance(requirement_id, str)
        assert re.fullmatch(r"(?:MA|GP|MC|FL|EV|WS|PD)-\d{2}", requirement_id)
        assert row["status"] in OWNERSHIP_STATUSES
        owner_id = row["owner"]
        assert owner_id in owner_documents
        family = requirement_id.split("-", 1)[0]
        assert owner_id == EXPECTED_OWNER_BY_FAMILY[family]
        if family == "EV":
            assert row["status"] == "REPRESENTED_WITH_EXTERNAL_RESIDUAL"
        else:
            assert row["status"] == "REPRESENTED_WITH_RESIDUAL"
        referenced_owners.add(owner_id)
        owner_format, document = owner_documents[owner_id]
        anchor = row["anchor"]
        assert isinstance(anchor, str) and anchor
        if owner_format == "markdown":
            assert anchor in document
        else:
            assert _json_pointer_resolves(document, anchor)
        ids.append(requirement_id)

    assert len(ids) == 146
    assert len(ids) == len(set(ids))
    assert set(ids) == _expected_requirement_ids()
    assert referenced_owners == set(owners)


def _load_ownership_inputs() -> tuple[dict[str, object], dict[str, bytes]]:
    registry = _strict_json(OWNERSHIP_REGISTRY.read_text(encoding="utf-8"))
    assert isinstance(registry, dict)
    assert isinstance(registry.get("owners"), dict)
    owner_bytes: dict[str, bytes] = {}
    for owner_id, owner in registry["owners"].items():
        assert isinstance(owner, dict)
        path = _safe_owner_path(owner["path"])
        resolved = (ROOT / path).resolve()
        assert resolved.is_relative_to(ROOT.resolve())
        owner_bytes[owner_id] = resolved.read_bytes()
    return registry, owner_bytes


def test_all_146_requirements_have_exactly_one_normative_owner() -> None:
    registry, owner_bytes = _load_ownership_inputs()
    _validate_ownership_registry(registry, owner_bytes=owner_bytes)


def test_requirement_ownership_rejects_empty_or_drifted_owner_content() -> None:
    registry, owner_bytes = _load_ownership_inputs()
    mutated = dict(owner_bytes)
    mutated["rfc"] = b"# empty owner\n"
    with pytest.raises(AssertionError):
        _validate_ownership_registry(registry, owner_bytes=mutated)


@pytest.mark.parametrize(
    "mutation",
    (
        "missing",
        "duplicate",
        "owner",
        "foreign_owner",
        "anchor",
        "json_pointer",
        "status",
        "foreign_status",
        "owner_path",
        "windows_root",
        "owner_digest",
    ),
)
def test_requirement_ownership_rejects_invalid_per_id_rows(
    mutation: str,
) -> None:
    registry, owner_bytes = _load_ownership_inputs()
    mutated = copy.deepcopy(registry)
    if mutation == "missing":
        mutated["requirements"].pop()
    elif mutation == "duplicate":
        mutated["requirements"].append(copy.deepcopy(mutated["requirements"][0]))
    elif mutation == "owner":
        mutated["requirements"][0]["owner"] = "absent-owner"
    elif mutation == "foreign_owner":
        mutated["requirements"][0].update(
            {
                "anchor": "provider-conformance-matrix",
                "owner": "graph",
            }
        )
    elif mutation == "anchor":
        mutated["requirements"][0]["anchor"] = "absent-owner-anchor"
    elif mutation == "json_pointer":
        next(
            row for row in mutated["requirements"] if row["id"] == "MC-01"
        )["anchor"] = "/methods/00/method_id"
    elif mutation == "status":
        mutated["requirements"][0]["status"] = "UNREVIEWED"
    elif mutation == "foreign_status":
        next(
            row for row in mutated["requirements"] if row["id"] == "EV-01"
        )["status"] = "REPRESENTED_WITH_RESIDUAL"
    elif mutation == "owner_path":
        mutated["owners"]["rfc"]["path"] = "../outside.md"
    elif mutation == "windows_root":
        mutated["owners"]["rfc"]["path"] = "\\outside.md"
    else:
        mutated["owners"]["rfc"]["content_sha256_lf_nfc"] = "0" * 64
    with pytest.raises(AssertionError):
        _validate_ownership_registry(mutated, owner_bytes=owner_bytes)


def test_required_normative_sections_and_redirect_anchors_resolve() -> None:
    for path, expected in REQUIRED_HEADINGS.items():
        assert expected <= _headings(path)

    rfc_slugs = {_slug(value) for value in _headings(RFC)}
    for redirect in (FL_REDIRECT, PD_REDIRECT):
        for anchor in re.findall(
            r"\]\(method-application-rfc\.md#([a-z0-9-]+)\)",
            redirect.read_text(encoding="utf-8"),
        ):
            assert anchor in rfc_slugs


def test_retired_paths_are_exact_non_normative_redirects() -> None:
    assert FL_REDIRECT.read_text(encoding="utf-8") == EXPECTED_FL_REDIRECT
    assert PD_REDIRECT.read_text(encoding="utf-8") == EXPECTED_PD_REDIRECT


def test_methodcards_are_sole_editable_method_content_source() -> None:
    catalog = load_method_card_catalog(CATALOG, repo_root=ROOT)
    kernel = KERNEL.read_bytes()
    assert render_bound_prompt_fragment(catalog) == kernel
    assert b"<!-- GENERATED PROJECTION:" in kernel

    scan_roots = (
        ROOT / "architecture",
        ROOT / "rules",
        ROOT / "verification_policy",
        ROOT / "prompts",
        ROOT / "agents",
    )
    for card in catalog.cards:
        copies = []
        needle = card.operator_instruction
        for base in scan_roots:
            for path in base.rglob("*"):
                if (
                    path.is_file()
                    and path.suffix.lower() in {".md", ".json", ".yaml", ".yml"}
                    and needle in path.read_text(encoding="utf-8")
                ):
                    copies.append(path.relative_to(ROOT).as_posix())
        assert copies == [
            "prompts/shared/v2/breadth-semantic-operator-kernel.md"
        ]


def test_cross_document_authority_statements_are_not_reversed() -> None:
    rfc = RFC.read_text(encoding="utf-8")
    assert "sole normative source for method" in rfc
    assert "Phase-5\nconsumer profile" in rfc
    assert "canonical catalog for verification operators" not in rfc
    assert "MethodCard compatibility artifact" not in rfc

    graph = GRAPH.read_text(encoding="utf-8")
    assert "`EXACT`, `MAY`, `HEURISTIC`, `SYNTACTIC`" in graph
    assert "Provider conformance matrix" in graph

    scheduler = SCHEDULER.read_text(encoding="utf-8")
    assert "`PENDING`, `STAGED`, `INCORPORATED`, and\n`RECEIPTED`" in scheduler

    evaluation = EVALUATION.read_text(encoding="utf-8")
    assert "METHOD_CONTENT" in evaluation
    assert "VALID_APPLICATION_RECEIPT" in evaluation
    assert "LIFECYCLE_REPORT_SURVIVAL" in evaluation


def test_catalog_remains_canonical_json_subset_yaml() -> None:
    raw = CATALOG.read_bytes()
    assert raw.endswith(b"\n")
    assert json.loads(raw.decode("utf-8"))["schema_version"] == (
        "plamen.method_card_catalog.v1"
    )
