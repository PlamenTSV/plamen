"""Exact report heading presentation and read-only index authority replay.

Display status is index authority, not an inference from a verifier verdict.
Only the authenticated loader issues projections accepted by pure delivery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Mapping
from weakref import WeakValueDictionary, finalize
from artifact_surface import (
    HEADING, IGNORE_ROLE_VALUE, normalize_cell, normalize_label,
    read_tables, surface,
)
from plamen_types import EVIDENCE_TAGS_ALL, EVIDENCE_TAGS_PROD


class ReportHeadingError(ValueError):
    pass


_STATUS_RE = re.compile(
    r"(?<![A-Z0-9_])(UNVERIFIED|VERIFIED|CONFIRMED|CONTESTED|UNRESOLVED)(?![A-Z0-9_])",
    re.IGNORECASE,
)
_ISSUED_PROJECTIONS: WeakValueDictionary = WeakValueDictionary()
_ISSUED_CONTENT: dict[object, tuple[Any, ...]] = {}


_HEADING_INDEX_ROLES = {
    "report_id": ("report id", "report identifier", "id"),
    "title": ("title", "finding title", "report title"),
    "verification": ("verification", "verification status", "verdict"),
}
# STATIC-TRACE is already a supported structured evidence annotation in typed
# report fixtures. These annotations never supply or upgrade display status.
_HEADING_EVIDENCE_ANNOTATIONS = EVIDENCE_TAGS_ALL | EVIDENCE_TAGS_PROD | {"[STATIC-TRACE]"}


def _heading_index_identity(value):
    value = normalize_cell(value).upper()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1].strip()
    if re.fullmatch(r"[CHMLI]-[0-9]+", value):
        return value
    if re.fullmatch(r"[0-9]+[.)]?", value):
        # The caller verifies this came from the generic ID header, not an
        # authoritative Report ID/Report Identifier column.
        return IGNORE_ROLE_VALUE
    return None


def _heading_index_status(value):
    value = normalize_cell(value).upper()
    # Canonical projection preserves ancillary evidence and can produce
    # `[CODE-TRACE]; CONFIRMED`, as well as `CONFIRMED [CODE-TRACE]`.
    # Tokenize the complete cell; never substring-mine a positive assertion
    # from `NOT VERIFIED`, `UNVERIFIED`, an evidence tag or unknown prose.
    assertions = set()
    for token in re.findall(r"\[[^\[\]]*\]|[^\s;,/]+", value):
        bare = token[1:-1].strip() if token.startswith("[") and token.endswith("]") else token
        if _STATUS_RE.fullmatch(bare):
            assertions.add(bare)
        elif f"[{bare}]" not in _HEADING_EVIDENCE_ANNOTATIONS or not token.startswith("["):
            return None
    return next(iter(assertions)) if len(assertions) == 1 else None


def _heading_index_live(line):
    return not (line.blockquote_depth or line.in_fence or line.in_comment)


def _heading_index_resolved(table, row, role, normalizer):
    result = table.resolve_role(
        row, role, normalizer=normalizer,
        property_name=f"report_heading.index.{role}",
    )
    nonordinal_ignore = any(
        assertion.state == "IGNORED" and normalize_label(assertion.header) != "id"
        for assertion in result.assertions
    )
    if result.state != "RESOLVED" or nonordinal_ignore:
        state = "UNKNOWN" if nonordinal_ignore else result.state
        observed = [(a.header, a.raw, a.state) for a in result.assertions]
        raise ReportHeadingError(
            f"report_heading.index.{role}.{state.lower()} at line "
            f"{row.physical_line}: {observed!r}; expected one unambiguous {role}"
        )
    return result.value


def _index_rows(text: str) -> dict[str, tuple[str, str]]:
    """Read exact heading claims by checked semantic roles, not pipe positions.

    This is only a representation reader. Producer replay, exact index bytes,
    bundle denominator and substantive title agreement remain loader duties.
    """
    parsed = surface(text)
    if parsed.truncated or any(d.property_violated.startswith("encoding.") for d in parsed.defects):
        raise ReportHeadingError("report_heading.index.incomplete_surface: truncated or unreadable input")
    if any(d.property_violated in {
        "format.unterminated_fence", "format.unterminated_html_comment",
    } for d in parsed.defects):
        # The recall-oriented shared surface deliberately recovers malformed
        # quotations as prose. Such recovered mentions cannot authorize a
        # heading projection until their assertion boundary is unambiguous.
        raise ReportHeadingError("report_heading.index.ambiguous_quotation: unterminated example boundary")

    # Use original LogicalLine objects: reserializing line.text destroys the
    # escaped/inline-code pipe protection already captured in line.cells.
    # Quoted/example headings must neither open nor close an authority section.
    in_scope = set()
    master_depth = None
    for line in parsed.lines:
        if not _heading_index_live(line):
            continue
        if line.kind == HEADING:
            if normalize_label(line.heading_text) == "master finding index":
                master_depth = line.heading_level
                continue
            if master_depth is not None and line.heading_level <= master_depth:
                master_depth = None
        if master_depth is not None:
            in_scope.add(line.index)

    rows: dict[str, tuple[str, str]] = {}
    origins = {}
    for table in read_tables(parsed, roles=_HEADING_INDEX_ROLES):
        if table.header is None or table.header.index not in in_scope or not _heading_index_live(table.header):
            continue
        # Unrelated ancillary tables make no heading claim. Once any required
        # role is asserted, missing companion roles are explicit semantic debt
        # that cannot authorize a partial heading map.
        if not any(table.role_indices(role) for role in _HEADING_INDEX_ROLES):
            continue
        for row in table.rows:
            if row.line.index not in in_scope or not _heading_index_live(row.line):
                continue
            if any(cell.strip() for cell in row.cells[len(table.headers):]):
                raise ReportHeadingError(
                    f"report_heading.index.unmapped_cells at line {row.physical_line}: "
                    "nonempty cells have no declared column role"
                )
            rid = _heading_index_resolved(table, row, "report_id", _heading_index_identity)
            title = _heading_index_resolved(table, row, "title", normalize_cell)
            status = _heading_index_resolved(table, row, "verification", _heading_index_status)
            value = (title, status)
            if rid in rows and rows[rid] != value:
                raise ReportHeadingError(
                    f"report_heading.index.duplicate_row.conflict for {rid} at lines "
                    f"{origins[rid]} and {row.physical_line}: {rows[rid]!r} != {value!r}"
                )
            rows[rid] = value
            origins.setdefault(rid, row.physical_line)
    return rows


def index_status_map(text: str) -> dict[str, str]:
    """Use exact bounded tokens; UNVERIFIED must never match VERIFIED."""
    return {rid: status for rid, (_title, status) in _index_rows(text).items()}


def public_heading_title(title: str, status: str = "") -> str:
    from plamen_parsers import _sanitize_client_title

    if status and not _STATUS_RE.fullmatch(status):
        raise ReportHeadingError("report heading status is not exact")
    public = _sanitize_client_title(title)
    return public + (f" [{status.upper()}]" if status else "")


@dataclass(frozen=True)
class AuthenticatedHeadingProjection:
    bundle_digest: str
    index_sha256: str
    producer_receipt_digest: str
    run_id: str
    titles: tuple[tuple[str, str], ...]
    _issuer: object = field(repr=False, compare=False)


def _projection_content(projection: AuthenticatedHeadingProjection) -> tuple[Any, ...]:
    return (projection.bundle_digest, projection.index_sha256,
            projection.producer_receipt_digest, projection.run_id, projection.titles)


def projected_titles(projection: AuthenticatedHeadingProjection,
                     bundle: Mapping[str, Any]) -> dict[str, str]:
    if (type(projection) is not AuthenticatedHeadingProjection
            or _ISSUED_PROJECTIONS.get(projection._issuer) is not projection
            or _ISSUED_CONTENT.get(projection._issuer) != _projection_content(projection)
            or projection.bundle_digest != bundle.get("bundle_digest")):
        raise ReportHeadingError("report heading projection is unbound or belongs to another bundle")
    titles = dict(projection.titles)
    if set(titles) != set(bundle["expected_report_ids"]):
        raise ReportHeadingError("report heading projection denominator differs")
    return titles


def load_authenticated_heading_projection(
    scratchpad: Path, *, project_root: Path, run_id: str,
    bundle: Mapping[str, Any],
) -> AuthenticatedHeadingProjection:
    """Read and replay existing producers without creating any authority."""
    import artifact_ledger as AL
    import report_capture_phaseio_authority as capture
    from report_evidence_authority import validate_report_evidence_bundle

    root, project = Path(scratchpad), Path(project_root)
    if not isinstance(run_id, str) or not run_id.strip():
        raise ReportHeadingError("report heading replay needs an explicit run identity")
    canonical = validate_report_evidence_bundle(bundle)
    index_identity = "scratchpad:report_index.md"
    identities = (index_identity, "scratchpad:report_evidence_records.json")
    try:
        with AL._artifact_validation_epoch(root, project) as epoch:
            issues = AL.semantic_input_prebind_producer_authority_issues(
                root, project, identities, run_id=run_id, _validation_context=epoch,
            )
            if issues:
                raise ReportHeadingError("; ".join(issues))
            ledger = epoch.ledger
            binding = ledger["artifact_bindings"][index_identity]
            owner = binding["owner_key"]
            policy = capture._FIXED_REPORT_SOURCE_POLICIES["report_index.md"]
            if not capture._policy_owner_allowed(
                policy, owner_suffix="/" + "/".join(owner.split("/")[4:]),
                writer=binding["writer"], schema_version=binding["schema_version"],
            ):
                raise ReportHeadingError("report heading index producer is not registered")
            unit = ledger["work_units"][owner]
            contract = capture._registered_producer_contract_from_committed_manifest(
                unit, expected_work_unit=owner,
            )
            launch = capture._launch_from_committed_manifest(unit, contract)
            capture._validate_policy_launch(
                policy, contract=contract, launch=launch, writer=binding["writer"],
            )
            issues = AL.stored_committed_work_unit_authority_issues(
                ledger, work_unit_key=owner, run_id=run_id,
            )
            if issues:
                raise ReportHeadingError("; ".join(issues))
            raw = (root / "report_index.md").read_bytes()
            bundle_raw = (root / "report_evidence_records.json").read_bytes()
            for identity, content in ((index_identity, raw), (identities[1], bundle_raw)):
                observed = ledger["artifact_bindings"][identity]
                if (len(content) != observed["size"]
                        or hashlib.sha256(content).hexdigest() != observed["sha256"]):
                    raise ReportHeadingError("report heading authority bytes changed during replay")
            if json.loads(bundle_raw) != canonical:
                raise ReportHeadingError("report heading bundle differs from its committed source")
            rows = _index_rows(raw.decode("utf-8", errors="strict"))
            titles = []
            for record in canonical["records"]:
                rid = record["report_id"]
                if rid not in rows:
                    raise ReportHeadingError(f"{rid}: report heading index row is missing")
                source_title, status = rows[rid]
                # Privacy normalization is shared, but never accept an arbitrary
                # substituted substantive claim as the expected display title.
                if public_heading_title(source_title) != public_heading_title(record["title"]):
                    raise ReportHeadingError(f"{rid}: typed and index heading titles disagree")
                titles.append((rid, public_heading_title(record["title"], status)))
            projection = AuthenticatedHeadingProjection(
                canonical["bundle_digest"], hashlib.sha256(raw).hexdigest(),
                unit["commit_authority"]["receipt_digest"], run_id,
                tuple(sorted(titles)), object(),
            )
        _ISSUED_PROJECTIONS[projection._issuer] = projection
        _ISSUED_CONTENT[projection._issuer] = _projection_content(projection)
        finalize(projection, _ISSUED_CONTENT.pop, projection._issuer, None)
        return projection
    except (AL.ArtifactLedgerError, KeyError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportHeadingError(f"report heading authority replay failed: {exc}") from exc
