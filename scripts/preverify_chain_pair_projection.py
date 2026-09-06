"""Atomic immutable projection of the final SC chain hypothesis/mapping pair.

``hypotheses.md`` and ``finding_mapping.md`` are mutable chain-phase roots.
This provider never assigns those roots new ownership.  It imports their live
bytes only when the artifact ledger proves one common exact current-run
PhaseIO producer: either ``chain/model`` or the journaled paired
``chain/final_pair_auto_map_apply.<digest>`` successor.

The authorized pair is staged together and made visible with one directory
rename.  Invalid, partial, foreign-run, or interrupted input produces a
content-addressed diagnostic debt receipt with an empty logical mapping; the
mutable candidate roots are never deleted, rewritten, or treated as proof.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
from typing import Any, Callable, Mapping
import uuid

from artifact_ledger import (
    ArtifactLedgerError,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    semantic_import_authority,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
)
from bounded_artifact_io import read_bounded_regular_bytes
from phase_io_contracts import (
    ArtifactSpec,
    LaunchSpec,
    PhaseIOContract,
    canonical_work_unit_key,
)


SCHEMA = "plamen.preverify_chain_pair_projection.v1"
RECEIPT_SCHEMA = "plamen.preverify_chain_pair_projection_receipt.v2"
DEBT_SCHEMA = "plamen.preverify_chain_pair_projection_debt.v1"
RELATION_SCHEMA = "plamen.preverify_chain_pair_relation_validation.v1"
PAIR_DERIVATION_ALGORITHM = "plamen.preverify.chain_pair.v2"
PAIR_DERIVATION_CONFORMANCE_SHA256 = (
    "59888d668a55076c91c4543fffc6aacbe6e4e26fd37fc618c2a4cc6dbc47860b"
)
ROOT = "_preverify_chain_pair"
HYPOTHESES_LOGICAL = "hypotheses.md"
MAPPING_LOGICAL = "finding_mapping.md"
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_RELATION_ROWS = 100_000
MAX_RELATION_TABLES = 64
MAX_RELATION_ISSUES = 128
_RELATION_COUNT_MARKER_RE = re.compile(
    r"<!--\s*PLAMEN_CHAIN_RELATION_COUNT:\s*(\d+)\s*-->",
    re.IGNORECASE,
)


class PreverifyChainPairProjectionError(ValueError):
    """The final chain-pair projection could not be authorized or committed."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    try:
        return (
            json.dumps(
                value,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise PreverifyChainPairProjectionError(
            f"chain-pair value is not canonical JSON: {exc}"
        ) from exc


def _digest(value: Mapping[str, Any]) -> str:
    return _sha(_canonical_bytes(value))


def _binding(raw: bytes) -> dict[str, Any]:
    return {"sha256": _sha(raw), "size": len(raw)}


def _normalized_header(value: str) -> str:
    text = re.sub(r"[*_`]", "", value or "").strip().casefold()
    return re.sub(r"[^a-z0-9]+", "_", text).strip("_")


def _markdown_cells(line: str) -> list[str]:
    """Split one bounded Markdown row without treating escaped pipes as cells."""

    text = str(line or "").strip()
    if text.startswith("|"):
        text = text[1:]
    if text.endswith("|") and not text.endswith(r"\|"):
        text = text[:-1]
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    cells.append("".join(current).strip())
    return cells


def _separator_row(line: str) -> bool:
    cells = _markdown_cells(line)
    return bool(cells) and all(
        re.fullmatch(r":?-{3,}:?", cell.strip()) is not None
        for cell in cells
    )


def _role_index(
    headers: list[str],
    aliases: set[str],
) -> int | None:
    indices = [
        index for index, header in enumerate(headers)
        if header in aliases
    ]
    return indices[0] if len(indices) == 1 else None


_HYPOTHESIS_HEADERS = {
    "hypothesis",
    "hypothesis_id",
    "hypothesis_id_s",
    "internal_hypothesis",
    "internal_hypothesis_id",
    "mapped_hypothesis",
    "mapped_hypothesis_id",
}
_HYPOTHESIS_SOURCE_HEADERS = {
    "constituent",
    "constituents",
    "constituent_finding",
    "constituent_findings",
    "constituent_finding_id",
    "constituent_finding_ids",
    "source",
    "source_finding",
    "source_findings",
    "source_finding_id",
    "source_finding_ids",
}
_MAPPING_SOURCE_HEADERS = {
    "finding",
    "finding_id",
    "source",
    "source_id",
    "source_finding",
    "source_finding_id",
    "source_findings",
    "source_finding_ids",
    "constituent",
    "constituent_id",
    "constituent_finding",
    "constituent_finding_id",
}


def _clean_id_token(value: str) -> str:
    token = str(value or "").strip().strip("`*_ ")
    if len(token) >= 2 and token[0] == "[" and token[-1] == "]":
        token = token[1:-1].strip()
    return token


def _hypothesis_ids(value: str) -> tuple[str, ...]:
    try:
        from plamen_parsers import normalize_hypothesis_id_token
    except (ImportError, AttributeError):
        return ()
    tokens = re.split(
        r"\s*(?:[,;+]|\band\b)\s*",
        _clean_id_token(value),
        flags=re.IGNORECASE,
    )
    result: list[str] = []
    for token in tokens:
        identity = normalize_hypothesis_id_token(_clean_id_token(token))
        if not identity:
            return ()
        if identity not in result:
            result.append(identity)
    return tuple(result)


def _source_ids(value: str) -> tuple[str, ...]:
    try:
        from plamen_parsers import _INTERNAL_FINDING_ID_RE
    except (ImportError, AttributeError):
        return ()
    tokens = re.split(
        r"\s*(?:[,;+]|\band\b)\s*",
        _clean_id_token(value),
        flags=re.IGNORECASE,
    )
    result: list[str] = []
    for token in tokens:
        identity = _clean_id_token(token).upper()
        if (
            not identity
            or _INTERNAL_FINDING_ID_RE.fullmatch(identity) is None
        ):
            return ()
        if identity not in result:
            result.append(identity)
    return tuple(result)


def _typed_relation_rows(
    text: str,
    *,
    hypothesis_document: bool,
) -> dict[str, Any]:
    """Parse only typed Markdown relation tables and retain parse ambiguity."""

    lines = text.splitlines()
    edges: set[tuple[str, str]] = set()
    hypothesis_ids: set[str] = set()
    issues: list[str] = []
    recognized_tables = 0
    candidate_rows = 0
    parsed_rows = 0
    row_limit_hit = False
    table_limit_hit = False
    declared_counts = [
        int(match.group(1))
        for match in _RELATION_COUNT_MARKER_RE.finditer(text)
    ]
    declared_count = declared_counts[0] if len(declared_counts) == 1 else None
    count_consistent = True
    if len(declared_counts) > 1:
        issues.append("typed relation count marker is duplicated")
        count_consistent = False
    index = 0
    while index + 1 < len(lines):
        header_line = lines[index].strip()
        separator_line = lines[index + 1].strip()
        if (
            not header_line.startswith("|")
            or not _separator_row(separator_line)
        ):
            index += 1
            continue
        headers = [
            _normalized_header(cell)
            for cell in _markdown_cells(header_line)
        ]
        hypothesis_index = _role_index(headers, _HYPOTHESIS_HEADERS)
        source_index = _role_index(
            headers,
            (
                _HYPOTHESIS_SOURCE_HEADERS
                if hypothesis_document
                else _MAPPING_SOURCE_HEADERS
            ),
        )
        if (
            hypothesis_index is None
            or source_index is None
            or hypothesis_index == source_index
        ):
            index += 2
            continue
        recognized_tables += 1
        if recognized_tables > MAX_RELATION_TABLES:
            table_limit_hit = True
            break
        cursor = index + 2
        while cursor < len(lines):
            row_line = lines[cursor].strip()
            if not row_line.startswith("|"):
                break
            if (
                cursor + 1 < len(lines)
                and _separator_row(lines[cursor + 1].strip())
            ):
                break
            if _separator_row(row_line):
                cursor += 1
                continue
            candidate_rows += 1
            if candidate_rows > MAX_RELATION_ROWS:
                row_limit_hit = True
                break
            cells = _markdown_cells(row_line)
            if max(hypothesis_index, source_index) >= len(cells):
                issues.append(
                    f"typed row {candidate_rows} has fewer cells than its header"
                )
                cursor += 1
                continue
            hypotheses = _hypothesis_ids(cells[hypothesis_index])
            sources = _source_ids(cells[source_index])
            if not hypotheses or not sources:
                issues.append(
                    f"typed row {candidate_rows} has an unparseable identity cell"
                )
                cursor += 1
                continue
            parsed_rows += 1
            hypothesis_ids.update(hypotheses)
            edges.update(
                (hypothesis, source)
                for hypothesis in hypotheses
                for source in sources
            )
            cursor += 1
        if row_limit_hit:
            break
        index = max(cursor, index + 2)
    if table_limit_hit:
        issues.append(
            f"typed relation exceeded the {MAX_RELATION_TABLES}-table bound"
        )
    if row_limit_hit:
        issues.append(
            f"typed relation exceeded the {MAX_RELATION_ROWS}-row bound"
        )
    if declared_count is not None and declared_count != candidate_rows:
        issues.append(
            "typed relation count marker does not match candidate rows "
            f"({declared_count} declared, {candidate_rows} parsed as rows)"
        )
        count_consistent = False
    explicit_empty = declared_count == 0 and candidate_rows == 0
    if recognized_tables == 0:
        issues.append("no typed relation table was recognized")
    elif candidate_rows == 0 and not explicit_empty:
        issues.append("typed relation table has no candidate rows")
    elif parsed_rows != candidate_rows:
        issues.append(
            f"{candidate_rows - parsed_rows} typed relation row(s) were ambiguous"
        )
    return {
        "recognized_tables": min(recognized_tables, MAX_RELATION_TABLES),
        "candidate_rows": min(candidate_rows, MAX_RELATION_ROWS),
        "parsed_rows": parsed_rows,
        "edges": edges,
        "hypothesis_ids": hypothesis_ids,
        "issues": list(dict.fromkeys(issues))[:MAX_RELATION_ISSUES],
        "complete": (
            recognized_tables > 0
            and (candidate_rows > 0 or explicit_empty)
            and parsed_rows == candidate_rows
            and not table_limit_hit
            and not row_limit_hit
            and count_consistent
        ),
    }


def _relation_validation(
    hypotheses_raw: bytes,
    mapping_raw: bytes,
) -> dict[str, Any]:
    decode_issues: list[str] = []
    decoded: dict[str, str] = {}
    for logical, raw in (
        (HYPOTHESES_LOGICAL, hypotheses_raw),
        (MAPPING_LOGICAL, mapping_raw),
    ):
        try:
            decoded[logical] = raw.decode("utf-8", errors="strict")
        except UnicodeError:
            decoded[logical] = raw.decode("utf-8", errors="replace")
            decode_issues.append(
                f"{logical} is not strict UTF-8; relation is ambiguous"
            )

    def _parse_or_ambiguous(
        logical: str,
        *,
        hypothesis_document: bool,
    ) -> dict[str, Any]:
        try:
            return _typed_relation_rows(
                decoded[logical],
                hypothesis_document=hypothesis_document,
            )
        except Exception as exc:
            # Relation diagnostics must never become a candidate filter.  An
            # implementation/parser failure is visible ambiguity while the
            # exact source pair remains projected byte-for-byte.
            return {
                "recognized_tables": 0,
                "candidate_rows": 0,
                "parsed_rows": 0,
                "edges": set(),
                "hypothesis_ids": set(),
                "issues": [
                    "relation parser failed safely: "
                    f"{type(exc).__name__}: {exc}"
                ],
                "complete": False,
            }

    hypotheses = _parse_or_ambiguous(
        HYPOTHESES_LOGICAL,
        hypothesis_document=True,
    )
    mapping = _parse_or_ambiguous(
        MAPPING_LOGICAL,
        hypothesis_document=False,
    )
    hypothesis_edges = set(hypotheses["edges"])
    mapping_edges = set(mapping["edges"])
    hypotheses_only_edges = sorted(hypothesis_edges - mapping_edges)
    mapping_only_edges = sorted(mapping_edges - hypothesis_edges)
    declared_ids = set(hypotheses["hypothesis_ids"])
    mapped_ids = set(mapping["hypothesis_ids"])
    hypotheses_only_ids = sorted(declared_ids - mapped_ids)
    mapping_only_ids = sorted(mapped_ids - declared_ids)

    parse_issues = [
        *decode_issues,
        *(
            f"{HYPOTHESES_LOGICAL}: {issue}"
            for issue in hypotheses["issues"]
        ),
        *(
            f"{MAPPING_LOGICAL}: {issue}"
            for issue in mapping["issues"]
        ),
    ]
    complete = (
        not decode_issues
        and hypotheses["complete"]
        and mapping["complete"]
    )
    contradictions = (
        hypotheses_only_edges
        or mapping_only_edges
        or hypotheses_only_ids
        or mapping_only_ids
    )
    if not complete:
        state = "AMBIGUOUS"
        reason_code = "CHAIN_PAIR_RELATION_AMBIGUOUS"
        issues = parse_issues
    elif contradictions:
        state = "CONTRADICTED"
        reason_code = "CHAIN_PAIR_RELATION_CONTRADICTION"
        issues = [
            *(
                ["mapping references undeclared hypotheses: "
                 + ", ".join(mapping_only_ids)]
                if mapping_only_ids else []
            ),
            *(
                ["hypotheses lack mapping rows: "
                 + ", ".join(hypotheses_only_ids)]
                if hypotheses_only_ids else []
            ),
            *(
                [
                    f"{len(mapping_only_edges)} mapping edge(s) are absent "
                    "from the hypothesis constituent table"
                ]
                if mapping_only_edges else []
            ),
            *(
                [
                    f"{len(hypotheses_only_edges)} hypothesis constituent "
                    "edge(s) are absent from the mapping table"
                ]
                if hypotheses_only_edges else []
            ),
        ]
    else:
        state = "EXACT"
        reason_code = None
        issues = []

    def _edge_preview(edges: list[tuple[str, str]]) -> list[dict[str, str]]:
        return [
            {"hypothesis_id": hypothesis, "source_finding_id": source}
            for hypothesis, source in edges[:MAX_RELATION_ISSUES]
        ]

    return {
        "schema_version": RELATION_SCHEMA,
        "state": state,
        "reason_code": reason_code,
        "issues": list(dict.fromkeys(issues))[:MAX_RELATION_ISSUES],
        "hypotheses_parser": {
            key: hypotheses[key]
            for key in (
                "recognized_tables",
                "candidate_rows",
                "parsed_rows",
                "complete",
            )
        },
        "mapping_parser": {
            key: mapping[key]
            for key in (
                "recognized_tables",
                "candidate_rows",
                "parsed_rows",
                "complete",
            )
        },
        "hypotheses_only_hypothesis_ids": (
            hypotheses_only_ids[:MAX_RELATION_ISSUES]
        ),
        "mapping_only_hypothesis_ids": (
            mapping_only_ids[:MAX_RELATION_ISSUES]
        ),
        "hypotheses_only_edge_count": len(hypotheses_only_edges),
        "mapping_only_edge_count": len(mapping_only_edges),
        "hypotheses_only_edges": _edge_preview(hypotheses_only_edges),
        "mapping_only_edges": _edge_preview(mapping_only_edges),
        "relation_edge_count": len(hypothesis_edges | mapping_edges),
        "relation_edge_digest": _sha(_canonical_bytes({
            "hypotheses": sorted(hypothesis_edges),
            "mapping": sorted(mapping_edges),
        })),
        "candidate_disposition": "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION",
        "candidate_records_removed": 0,
        "proof_authority": "NONE",
    }


def derive_preverify_chain_pair_relation(
    hypotheses_raw: bytes,
    mapping_raw: bytes,
) -> dict[str, Any]:
    """Replay the declared v1 chain-pair relation derivation."""

    return _relation_validation(bytes(hypotheses_raw), bytes(mapping_raw))


_PAIR_RELATION_DERIVER = derive_preverify_chain_pair_relation


def derive_preverify_chain_pair_derivation_conformance_sha256() -> str:
    """Return the chain-pair v1 golden-vector digest."""

    exact_hypotheses = (
        b"# Hypotheses\n\n"
        b"| Hypothesis | Constituents | Severity |\n"
        b"|---|---|---|\n"
        b"| H-1 | INV-1 | Medium |\n"
    )
    exact_mapping = (
        b"# Finding Mapping\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"|---|---|\n"
        b"| H-1 | INV-1 |\n"
    )
    ambiguous_mapping = (
        b"# Finding Mapping\r\n\r\n"
        b"| Hypothesis | Source Findings |\r\n"
        b"|---|---|\r\n"
        b"| H-1 | not-an-inventory-id |\r\n"
    )
    escaped_hypotheses = (
        b"# Hypotheses\n\n"
        b"| Hypothesis | Constituents | Note |\n"
        b"|---|---|---|\n"
        b"| H-2 | INV-2 | escaped \\\\| pipe |\n"
    )
    escaped_mapping = (
        b"# Finding Mapping\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"|---|---|\n"
        b"| H-2 | INV-2 |\n"
    )
    explicit_empty_hypotheses = (
        b"# Hypotheses\n\n"
        b"<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
        b"| Hypothesis | Constituents |\n"
        b"|---|---|\n"
    )
    explicit_empty_mapping = (
        b"# Finding Mapping\n\n"
        b"<!-- PLAMEN_CHAIN_RELATION_COUNT: 0 -->\n\n"
        b"| Hypothesis | Source Findings |\n"
        b"|---|---|\n"
    )
    vector = {
        "algorithm": PAIR_DERIVATION_ALGORITHM,
        "exact": derive_preverify_chain_pair_relation(
            exact_hypotheses,
            exact_mapping,
        ),
        "ambiguous": derive_preverify_chain_pair_relation(
            exact_hypotheses,
            ambiguous_mapping,
        ),
        "escaped_pipe": derive_preverify_chain_pair_relation(
            escaped_hypotheses,
            escaped_mapping,
        ),
        "explicit_empty": derive_preverify_chain_pair_relation(
            explicit_empty_hypotheses,
            explicit_empty_mapping,
        ),
        "invalid_utf8": derive_preverify_chain_pair_relation(
            exact_hypotheses + b"\xff",
            exact_mapping,
        ),
    }
    return _sha(_canonical_bytes(vector))


def validate_preverify_chain_pair_derivation_conformance() -> None:
    """Reject executable drift hidden behind the pair v1 algorithm ID."""

    actual = derive_preverify_chain_pair_derivation_conformance_sha256()
    if actual != PAIR_DERIVATION_CONFORMANCE_SHA256:
        probe = (
            _PAIR_RELATION_DERIVER(
                (
                    b"| Hypothesis | Constituents |\n"
                    b"|---|---|\n"
                    b"| H-1 | INV-1 |\n"
                ),
                (
                    b"| Hypothesis | Source Findings |\n"
                    b"|---|---|\n"
                    b"| H-1 | INV-1 |\n"
                ),
            )
            if derive_preverify_chain_pair_relation
            is _PAIR_RELATION_DERIVER
            else {}
        )
        if (
            probe.get("state") == "AMBIGUOUS"
            and any(
                "relation parser failed safely" in str(issue)
                for issue in probe.get("issues", [])
            )
        ):
            # The relation projection is advisory and recall-preserving.  A
            # parser outage must retain the exact pair with visible ambiguity
            # debt; replacing the public deriver itself remains a hard
            # conformance failure.
            return
        raise PreverifyChainPairProjectionError(
            "chain-pair derivation v1 conformance digest differs; allocate "
            "a new algorithm identifier "
            f"(expected {PAIR_DERIVATION_CONFORMANCE_SHA256}, got {actual})"
        )


def _safe_relative(value: object, *, label: str) -> str:
    text = str(value or "")
    path = PurePosixPath(text)
    if (
        not text
        or "\\" in text
        or path.is_absolute()
        or text != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise PreverifyChainPairProjectionError(
            f"{label} is not a canonical relative POSIX path"
        )
    return text


def _source_authority(
    root: Path,
    project: Path,
    relative: str,
    *,
    run_id: str,
) -> dict[str, Any]:
    authority = semantic_import_authority(
        root,
        project,
        "scratchpad:" + relative,
        run_id=run_id,
    )
    if authority.get("authority_kind") != "EXACT_PHASE_IO_PRODUCER":
        raise PreverifyChainPairProjectionError(
            f"{relative}: source is not an exact PhaseIO producer"
        )
    return authority


def _derive_authorized(
    *,
    root: Path,
    project: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
) -> dict[str, Any]:
    validate_preverify_chain_pair_derivation_conformance()
    source_bytes: dict[str, bytes] = {}
    authorities: dict[str, dict[str, Any]] = {}
    for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL):
        try:
            raw = read_bounded_regular_bytes(
                root / relative,
                MAX_SOURCE_BYTES,
            )
        except OSError as exc:
            raise PreverifyChainPairProjectionError(
                f"final chain pair is partial; {relative} is unavailable"
            ) from exc
        if not raw:
            raise PreverifyChainPairProjectionError(
                f"final chain pair is partial; {relative} is empty"
            )
        try:
            authority = _source_authority(
                root,
                project,
                relative,
                run_id=run_id,
            )
        except (
            ArtifactLedgerError,
            OSError,
            TypeError,
            ValueError,
        ) as exc:
            raise PreverifyChainPairProjectionError(
                f"{relative} lacks an exact current-run producer or contiguous "
                "same-run semantic-mutation lineage: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if (
            authority.get("identity") != "scratchpad:" + relative
            or authority.get("run_id") != run_id
            or authority.get("source_sha256") != _sha(raw)
            or authority.get("source_size") != len(raw)
        ):
            raise PreverifyChainPairProjectionError(
                f"{relative} import authority does not bind the live bytes"
            )
        source_bytes[relative] = raw
        authorities[relative] = authority

    owner_keys = {
        str(authorities[relative].get("producer_work_unit_key") or "")
        for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    }
    contract_digests = {
        str(authorities[relative].get("producer_contract_digest") or "")
        for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    }
    if len(owner_keys) != 1 or len(contract_digests) != 1:
        raise PreverifyChainPairProjectionError(
            "final chain pair does not share one exact producer generation"
        )
    owner_key = next(iter(owner_keys))
    owner_relative = "/".join(owner_key.split("/")[4:])
    if (
        owner_relative != "chain/model"
        and re.fullmatch(
            r"chain/final_pair_auto_map_apply\.[0-9a-f]{64}",
            owner_relative,
        ) is None
    ):
        raise PreverifyChainPairProjectionError(
            "final chain pair producer is not a registered chain/model or "
            "journaled paired-repair unit"
        )

    relation_validation = derive_preverify_chain_pair_relation(
        source_bytes[HYPOTHESES_LOGICAL],
        source_bytes[MAPPING_LOGICAL],
    )
    relation_debt = (
        []
        if relation_validation["state"] == "EXACT"
        else [{
            "reason_code": relation_validation["reason_code"],
            "issues": relation_validation["issues"],
            "candidate_disposition": (
                "PRESERVE_BOTH_ROOTS_FOR_VERIFICATION"
            ),
            "proof_authority": "NONE",
        }]
    )
    generation_core = {
        "schema_version": SCHEMA,
        "pipeline": pipeline,
        "mode": mode,
        "ecosystem": ecosystem,
        "backend": backend,
        "phase_name": phase_name,
        "run_id": run_id,
        "sources": {
            relative: _binding(source_bytes[relative])
            for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
        },
        "source_authorities": {
            relative: authorities[relative]
            for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
        },
        "relation_validation": relation_validation,
        "derivation_algorithm": PAIR_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            PAIR_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    generation_digest = _digest(generation_core)
    generation_root = f"{ROOT}/generation_{generation_digest}"
    logical_to_physical = {
        relative: f"{generation_root}/{relative}"
        for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL)
    }
    receipt_path = f"{generation_root}/receipt.json"
    required_paths = sorted({
        *logical_to_physical.values(),
        receipt_path,
    })
    unsigned_receipt = {
        **generation_core,
        "schema_version": RECEIPT_SCHEMA,
        "generation_digest": generation_digest,
        "logical_to_physical": logical_to_physical,
        "required_paths": required_paths,
        "debt": relation_debt,
        "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
        "proof_authority": "NONE",
        "publication_atomicity": "PAIRED_DIRECTORY_RENAME",
    }
    receipt = {
        **unsigned_receipt,
        "receipt_digest": _digest(unsigned_receipt),
    }
    outputs = {
        logical_to_physical[HYPOTHESES_LOGICAL]:
            source_bytes[HYPOTHESES_LOGICAL],
        logical_to_physical[MAPPING_LOGICAL]:
            source_bytes[MAPPING_LOGICAL],
        receipt_path: _canonical_bytes(receipt),
    }
    return {
        "generation_digest": generation_digest,
        "generation_root": generation_root,
        "logical_to_physical": logical_to_physical,
        "receipt_path": receipt_path,
        "required_paths": tuple(required_paths),
        "source_authorities": authorities,
        "outputs": outputs,
        "receipt": receipt,
        "debt": tuple(relation_debt),
    }


def _contract_and_launch(
    *,
    derived: Mapping[str, Any],
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
) -> tuple[PhaseIOContract, LaunchSpec]:
    generation = str(derived["generation_digest"])
    owner = canonical_work_unit_key(
        pipeline,
        mode,
        ecosystem,
        backend,
        phase_name,
        f"preverify_chain_pair_projection.{generation}",
    )
    authority_rows = derived.get("source_authorities")
    if not isinstance(authority_rows, Mapping):
        raise PreverifyChainPairProjectionError(
            "chain-pair source authority denominator is malformed"
        )
    exact_inputs = {
        str(row["identity"])
        for row in authority_rows.values()
        if isinstance(row, Mapping)
    }
    outputs = derived.get("outputs")
    if not isinstance(outputs, Mapping):
        raise PreverifyChainPairProjectionError(
            "chain-pair output denominator is malformed"
        )
    contract = PhaseIOContract(
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        phase=phase_name,
        work_unit_id=f"preverify_chain_pair_projection.{generation}",
        outputs=tuple(
            ArtifactSpec(
                root="scratchpad",
                path=_safe_relative(path, label="chain-pair output"),
                owner_key=owner,
                artifact_class="DRIVER_GENERATED",
                writer="DRIVER",
                write_mode="CREATE",
                schema_version=(
                    RECEIPT_SCHEMA
                    if str(path).endswith("/receipt.json")
                    else "unstructured.v1"
                ),
                minimum_gate="CONTENT_ADDRESSED_ATOMIC_CHAIN_PAIR",
                consumers=(f"{phase_name}/t0.live_upstream_authority",),
            )
            for path in sorted(outputs)
        ),
        immutable_inputs=tuple(sorted(exact_inputs)),
        bounded_lookup_inputs=(),
        model_invoked=False,
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=pipeline,
        mode=mode,
        ecosystem=ecosystem,
        backend=backend,
        model="driver",
        timeout_s=120,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _write_new_file(path: Path, raw: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_BINARY", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    """Persist directory metadata where the host exposes directory fsync."""

    if os.name == "nt":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_debt_receipt_atomically(
    path: Path,
    raw: bytes,
    *,
    failpoint: Callable[[str], None] | None,
) -> None:
    """Replace one diagnostic receipt without exposing streamed destination bytes.

    A historical direct ``O_EXCL`` destination write could leave a truncated
    content-addressed receipt after process loss.  A diagnostic receipt grants
    no proof authority, so an exact deterministic postimage may safely repair
    such a legacy partial file.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        if read_bounded_regular_bytes(path, MAX_SOURCE_BYTES) == raw:
            return
    except (OSError, ValueError):
        pass
    temporary = path.with_name(
        f".{path.stem}.{uuid.uuid4().hex}.tmp"
    )
    try:
        _write_new_file(temporary, raw)
        if failpoint is not None:
            failpoint("after_chain_pair_debt_stage")
        os.replace(temporary, path)
        if failpoint is not None:
            failpoint("after_chain_pair_debt_replace")
        _fsync_directory(path.parent)
        if read_bounded_regular_bytes(path, MAX_SOURCE_BYTES) != raw:
            raise PreverifyChainPairProjectionError(
                "atomic chain-pair debt receipt differs after publication"
            )
    finally:
        temporary.unlink(missing_ok=True)


def _validate_generation_bytes(
    root: Path,
    derived: Mapping[str, Any],
) -> None:
    outputs = derived.get("outputs")
    if not isinstance(outputs, Mapping):
        raise PreverifyChainPairProjectionError(
            "chain-pair generation outputs are malformed"
        )
    for relative, expected in outputs.items():
        path = root.joinpath(*PurePosixPath(str(relative)).parts)
        try:
            actual = read_bounded_regular_bytes(path, MAX_SOURCE_BYTES)
        except OSError as exc:
            raise PreverifyChainPairProjectionError(
                "atomic chain-pair generation is partial"
            ) from exc
        if actual != bytes(expected):
            raise PreverifyChainPairProjectionError(
                f"content-addressed chain-pair output has foreign bytes: {path}"
            )


def _publish_generation_atomically(
    root: Path,
    derived: Mapping[str, Any],
    *,
    failpoint: Callable[[str], None] | None,
) -> None:
    generation_relative = _safe_relative(
        derived.get("generation_root"),
        label="chain-pair generation root",
    )
    final = root.joinpath(*PurePosixPath(generation_relative).parts)
    if final.is_dir():
        _validate_generation_bytes(root, derived)
        return
    if final.exists():
        raise PreverifyChainPairProjectionError(
            "chain-pair generation path exists but is not a directory"
        )
    final.parent.mkdir(parents=True, exist_ok=True)
    # Keep the temporary basename short enough for Windows' legacy MAX_PATH
    # environments even when pytest/audit roots are already deeply nested.
    staging = final.parent / (
        f".s_{str(derived['generation_digest'])[:12]}_"
        f"{uuid.uuid4().hex[:12]}"
    )
    staging.mkdir()
    try:
        outputs = derived["outputs"]
        assert isinstance(outputs, Mapping)
        for logical in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL):
            relative = str(derived["logical_to_physical"][logical])
            raw = bytes(outputs[relative])
            _write_new_file(staging / logical, raw)
            if failpoint is not None:
                failpoint(f"after_stage_{logical}")
        receipt_relative = str(derived["receipt_path"])
        _write_new_file(staging / "receipt.json", bytes(outputs[receipt_relative]))
        if failpoint is not None:
            failpoint("before_chain_pair_publish")
        try:
            os.replace(staging, final)
        except OSError:
            if not final.is_dir():
                raise
            _validate_generation_bytes(root, derived)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    _validate_generation_bytes(root, derived)


def _validate_receipt(root: Path, derived: Mapping[str, Any]) -> None:
    receipt_path = _safe_relative(
        derived.get("receipt_path"),
        label="chain-pair receipt",
    )
    try:
        receipt = json.loads(
            read_bounded_regular_bytes(
                root.joinpath(*PurePosixPath(receipt_path).parts),
                MAX_SOURCE_BYTES,
            ).decode("utf-8", errors="strict")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise PreverifyChainPairProjectionError(
            "chain-pair receipt is unavailable or malformed"
        ) from exc
    unsigned = {
        key: value for key, value in receipt.items()
        if key != "receipt_digest"
    }
    if (
        receipt.get("schema_version") != RECEIPT_SCHEMA
        or receipt.get("generation_digest")
        != derived.get("generation_digest")
        or receipt.get("receipt_digest") != _digest(unsigned)
        or receipt != derived.get("receipt")
    ):
        raise PreverifyChainPairProjectionError(
            "chain-pair receipt differs from the authorized derivation"
        )


def _observed_roots(root: Path) -> dict[str, Any]:
    observations: dict[str, Any] = {}
    for relative in (HYPOTHESES_LOGICAL, MAPPING_LOGICAL):
        try:
            raw = read_bounded_regular_bytes(
                root / relative,
                MAX_SOURCE_BYTES,
            )
        except OSError:
            observations[relative] = {"status": "ABSENT"}
        except ValueError:
            observations[relative] = {
                "status": "PRESENT_UNSAFE_OR_UNSTABLE"
            }
        else:
            observations[relative] = {
                "status": "PRESENT_NOT_PROJECTED",
                **_binding(raw),
            }
    return observations


def _degraded(
    *,
    root: Path,
    dimensions: Mapping[str, str],
    reason_code: str,
    issues: list[str],
    failpoint: Callable[[str], None] | None,
) -> dict[str, Any]:
    unsigned = {
        "schema_version": DEBT_SCHEMA,
        **dict(dimensions),
        "state": "DEGRADED_INPUT_AUTHORITY",
        "reason_code": reason_code,
        "issues": list(dict.fromkeys(str(issue) for issue in issues if issue)),
        "observed_roots": _observed_roots(root),
        "logical_to_physical": {},
        "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
        "proof_authority": "NONE",
        "phase_io_authority": "NONE_DIAGNOSTIC_ONLY",
        "mutable_roots_rewritten": False,
        "derivation_algorithm": PAIR_DERIVATION_ALGORITHM,
        "derivation_conformance_sha256": (
            PAIR_DERIVATION_CONFORMANCE_SHA256
        ),
    }
    receipt = {
        **unsigned,
        "receipt_digest": _digest(unsigned),
    }
    receipt_path = f"{ROOT}/debt_{receipt['receipt_digest']}.json"
    path = root.joinpath(*PurePosixPath(receipt_path).parts)
    raw = _canonical_bytes(receipt)
    persisted = False
    persistence_issue = ""
    try:
        _publish_debt_receipt_atomically(
            path,
            raw,
            failpoint=failpoint,
        )
        persisted = True
    except Exception as exc:
        # A failpoint or host error after the atomic replace can report failure
        # even though the complete postimage is already visible.  Reconcile the
        # exact final bytes before falling back to inline haltless debt.
        try:
            persisted = (
                read_bounded_regular_bytes(path, MAX_SOURCE_BYTES) == raw
            )
        except (OSError, ValueError):
            persisted = False
        if persisted:
            persistence_issue = (
                "DEBT_RECEIPT_DURABILITY_UNCERTAIN: complete receipt is "
                "visible but post-publication durability did not complete: "
                f"{type(exc).__name__}: {exc}"
            )
        else:
            persistence_issue = (
                "DEBT_RECEIPT_PERSISTENCE_INTERRUPTED: "
                f"{type(exc).__name__}: {exc}"
            )
    result_issues = list(receipt["issues"])
    if persistence_issue:
        result_issues.append(persistence_issue)
    return {
        "schema_version": SCHEMA,
        "state": "DEGRADED_INPUT_AUTHORITY",
        "safe_to_consume": False,
        "run_id": dimensions["run_id"],
        "generation_digest": None,
        "work_unit_key": None,
        "receipt_path": receipt_path if persisted else None,
        "logical_to_physical": {},
        "required_paths": [receipt_path] if persisted else [],
        "debt": [{
            "reason_code": reason_code,
            "issues": result_issues,
            "candidate_disposition": "PRESERVE_ALL_FOR_VERIFICATION",
            "proof_authority": "NONE",
        }],
        "proof_authority": "NONE",
    }


def prepare_preverify_chain_pair_projection(
    *,
    scratchpad: Path,
    project_root: Path,
    pipeline: str,
    mode: str,
    ecosystem: str,
    backend: str,
    phase_name: str,
    run_id: str,
    failpoint: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Publish or replay the final immutable SC hypothesis/mapping pair."""

    root = Path(scratchpad)
    project = Path(project_root)
    dimensions = {
        "pipeline": str(pipeline or "").strip().lower(),
        "mode": str(mode or "").strip().lower(),
        "ecosystem": str(ecosystem or "").strip().lower(),
        "backend": str(backend or "").strip().lower(),
        "phase_name": str(phase_name or "").strip().lower(),
        "run_id": str(run_id or "").strip(),
    }
    if (
        dimensions["pipeline"] != "sc"
        or dimensions["backend"] not in {"claude", "codex"}
        or not dimensions["mode"]
        or not dimensions["ecosystem"]
        or dimensions["phase_name"] != "sc_verify_queue"
        or not dimensions["run_id"]
    ):
        raise PreverifyChainPairProjectionError(
            "chain-pair projection run tuple is invalid"
        )
    try:
        derived = _derive_authorized(
            root=root,
            project=project,
            **dimensions,
        )
    except (
        ArtifactLedgerError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        return _degraded(
            root=root,
            dimensions=dimensions,
            reason_code="FINAL_CHAIN_PAIR_AUTHORITY_UNAVAILABLE",
            issues=[f"{type(exc).__name__}: {exc}"],
            failpoint=failpoint,
        )

    try:
        contract, launch = _contract_and_launch(
            derived=derived,
            pipeline=dimensions["pipeline"],
            mode=dimensions["mode"],
            ecosystem=dimensions["ecosystem"],
            backend=dimensions["backend"],
            phase_name=dimensions["phase_name"],
        )
        prior_input_issues = validate_work_unit_inputs(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
        )
        prior_output_issues = validate_work_unit_artifacts(
            root,
            project,
            contract,
            launch,
            run_id=dimensions["run_id"],
            actor="DRIVER",
        )
        if not prior_input_issues and not prior_output_issues:
            _validate_generation_bytes(root, derived)
            _validate_receipt(root, derived)
        else:
            record_work_unit_inputs(
                root,
                project,
                contract,
                launch,
                run_id=dimensions["run_id"],
            )
            input_issues = validate_work_unit_inputs(
                root,
                project,
                contract,
                launch,
                run_id=dimensions["run_id"],
            )
            if input_issues:
                raise PreverifyChainPairProjectionError(
                    "chain-pair PhaseIO input arm failed: "
                    + "; ".join(input_issues)
                )
            after_arm = _derive_authorized(
                root=root,
                project=project,
                **dimensions,
            )
            if (
                after_arm["generation_digest"]
                != derived["generation_digest"]
                or after_arm["outputs"] != derived["outputs"]
            ):
                raise PreverifyChainPairProjectionError(
                    "chain-pair source denominator drifted after PhaseIO arm"
                )
            _publish_generation_atomically(
                root,
                derived,
                failpoint=failpoint,
            )
            record_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=dimensions["run_id"],
                actor="DRIVER",
            )
            output_issues = validate_work_unit_artifacts(
                root,
                project,
                contract,
                launch,
                run_id=dimensions["run_id"],
                actor="DRIVER",
            )
            if output_issues:
                raise PreverifyChainPairProjectionError(
                    "chain-pair PhaseIO output commit failed: "
                    + "; ".join(output_issues)
                )
            _validate_receipt(root, derived)
    except (
        ArtifactLedgerError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
    ) as exc:
        return _degraded(
            root=root,
            dimensions=dimensions,
            reason_code="FINAL_CHAIN_PAIR_ATOMIC_PUBLICATION_FAILED",
            issues=[f"{type(exc).__name__}: {exc}"],
            failpoint=failpoint,
        )

    return {
        "schema_version": SCHEMA,
        "state": "OUTPUT_COMMITTED",
        "safe_to_consume": True,
        "run_id": dimensions["run_id"],
        "generation_digest": derived["generation_digest"],
        "work_unit_key": contract.key,
        "receipt_path": derived["receipt_path"],
        "logical_to_physical": dict(derived["logical_to_physical"]),
        "required_paths": list(derived["required_paths"]),
        "debt": list(derived["debt"]),
        "proof_authority": "NONE",
    }


__all__ = [
    "HYPOTHESES_LOGICAL",
    "MAPPING_LOGICAL",
    "PAIR_DERIVATION_ALGORITHM",
    "PAIR_DERIVATION_CONFORMANCE_SHA256",
    "PreverifyChainPairProjectionError",
    "RECEIPT_SCHEMA",
    "ROOT",
    "SCHEMA",
    "derive_preverify_chain_pair_derivation_conformance_sha256",
    "derive_preverify_chain_pair_relation",
    "prepare_preverify_chain_pair_projection",
    "validate_preverify_chain_pair_derivation_conformance",
]
