"""Typed publication plan for driver-generated depth self-exclusion re-emits.

The renderer and the artifact-ledger publisher intentionally remain outside
this module.  This substrate binds already-rendered bytes to the exact,
ordered source denominator so the driver can publish the artifact through a
recoverable DRIVER output vector instead of writing an unowned file.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping, Sequence


SCHEMA = "plamen.depth_self_exclusion_publication.v1"
OUTPUT_NAME = "depth_selfexcl_reemit_findings.md"

_HEX_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_SOURCE_RE = re.compile(r"^[A-Za-z0-9_.-]+$", re.ASCII)
_MAX_OUTPUT_BYTES = 32 * 1024 * 1024
_MAX_SOURCE_BYTES = 64 * 1024 * 1024


class DepthSelfExclusionPublicationError(ValueError):
    """The proposed DRIVER publication is not exactly source-bound."""


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _direct_source_name(value: object) -> str:
    name = str(value or "").strip()
    parsed = PurePosixPath(name)
    if (
        not name
        or parsed.name != name
        or name in {".", ".."}
        or _SOURCE_RE.fullmatch(name) is None
    ):
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion source is not a direct artifact"
        )
    return name


def _source_denominator(
    recovered: Sequence[Mapping[str, Any]],
) -> tuple[str, ...]:
    if not recovered:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion publication has no recovered rows"
        )
    by_folded: dict[str, str] = {}
    for index, row in enumerate(recovered):
        if not isinstance(row, Mapping):
            raise DepthSelfExclusionPublicationError(
                f"depth self-exclusion row {index} is malformed"
            )
        name = _direct_source_name(row.get("source"))
        folded = name.casefold()
        prior = by_folded.get(folded)
        if prior is not None and prior != name:
            raise DepthSelfExclusionPublicationError(
                "depth self-exclusion source names collide case-insensitively"
            )
        by_folded[folded] = name
    return tuple(
        by_folded[key]
        for key in sorted(by_folded, key=lambda key: (key, by_folded[key]))
    )


def _source_records(
    names: Sequence[str], source_bytes: Mapping[str, bytes],
) -> tuple[dict[str, Any], ...]:
    if set(source_bytes) != set(names) or len(source_bytes) != len(names):
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion source-byte denominator is not exact"
        )
    records: list[dict[str, Any]] = []
    for name in names:
        raw = source_bytes.get(name)
        if not isinstance(raw, bytes):
            raise DepthSelfExclusionPublicationError(
                f"depth self-exclusion source bytes are invalid: {name}"
            )
        if len(raw) > _MAX_SOURCE_BYTES:
            raise DepthSelfExclusionPublicationError(
                f"depth self-exclusion source exceeds byte cap: {name}"
            )
        records.append({
            "artifact": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        })
    return tuple(records)


@dataclass(frozen=True)
class DepthSelfExclusionPublication:
    """Immutable plan consumed by the driver's recoverable output vector."""

    exact_source_names: tuple[str, ...]
    source_records: tuple[dict[str, Any], ...]
    output_bytes: bytes
    output_sha256: str
    output_size_bytes: int
    publication_digest: str

    @property
    def exact_outputs(self) -> tuple[str, ...]:
        return (OUTPUT_NAME,)

    @property
    def output_vector(self) -> dict[str, bytes]:
        return {OUTPUT_NAME: self.output_bytes}

    @property
    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA,
            "output_artifact": OUTPUT_NAME,
            "exact_source_names": list(self.exact_source_names),
            "source_records": [dict(row) for row in self.source_records],
            "output_sha256": self.output_sha256,
            "output_size_bytes": self.output_size_bytes,
            "publication_digest": self.publication_digest,
        }

    def validate_preimages(self, source_bytes: Mapping[str, bytes]) -> None:
        records = _source_records(self.exact_source_names, source_bytes)
        if records != self.source_records:
            raise DepthSelfExclusionPublicationError(
                "depth self-exclusion source bytes changed after planning"
            )


def build_depth_self_exclusion_publication(
    *,
    recovered: Sequence[Mapping[str, Any]],
    rendered_bytes: bytes,
    source_bytes: Mapping[str, bytes],
) -> DepthSelfExclusionPublication:
    """Bind rendered output bytes to all and only their recovered sources."""

    if not isinstance(rendered_bytes, bytes):
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output must be bytes"
        )
    if not rendered_bytes or len(rendered_bytes) > _MAX_OUTPUT_BYTES:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output byte denominator is invalid"
        )
    try:
        text = rendered_bytes.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output is not UTF-8"
        ) from exc
    if text.count("<!-- PLAMEN_STATUS: COMPLETE -->") != 1:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output lacks one exact completion marker"
        )
    names = _source_denominator(recovered)
    records = _source_records(names, source_bytes)
    output_sha = hashlib.sha256(rendered_bytes).hexdigest()
    unsigned = {
        "schema_version": SCHEMA,
        "output_artifact": OUTPUT_NAME,
        "exact_source_names": list(names),
        "source_records": [dict(row) for row in records],
        "output_sha256": output_sha,
        "output_size_bytes": len(rendered_bytes),
    }
    return DepthSelfExclusionPublication(
        exact_source_names=names,
        source_records=records,
        output_bytes=rendered_bytes,
        output_sha256=output_sha,
        output_size_bytes=len(rendered_bytes),
        publication_digest=_digest(unsigned),
    )


def render_depth_self_exclusion_reemit(
    recovered: Sequence[Mapping[str, Any]],
) -> bytes:
    """Render recovered rows without inventing content for empty records."""

    lines = [
        "# Depth Self-Exclusion Re-Emit", "",
        "Driver-recovered candidates that a depth agent parked under a",
        "Non-Reportable / Absorbed / self-dropped section WITHOUT citing an",
        "in-scope refutation (a real finding ID or file:line), or that rested on",
        "an unverified EXTERNAL assumption. Re-emitted so verification, rather",
        "than the generating agent, adjudicates every content-bearing candidate.",
        "",
    ]
    for ordinal, candidate in enumerate(recovered, start=1):
        title = str(candidate.get("title") or "").strip() or (
            "Self-excluded depth candidate without in-scope referent"
        )
        source = str(candidate.get("source") or "").strip()
        own_id = str(candidate.get("own_id") or "").strip()
        source_identity = (
            f"{source}:{own_id}" if source and own_id
            else source or own_id or f"recovered-row-{ordinal}"
        )
        external = bool(candidate.get("external_assumption"))
        basis = "an unverified external assumption" if external else (
            "no in-scope referent"
        )
        if not bool(candidate.get("content_bearing")):
            # This is the original single-record exclusion: retain the row as
            # methodology debt, but never manufacture a vulnerability from it.
            lines.extend([
                f"### Review Disposition [DXRE-{ordinal}]: {title}", "",
                f"**Source Action ID**: DXRE-{ordinal}",
                f"**Source Identity**: {source_identity}",
                "**Disposition**: CONTENT_LESS_HUMAN_REVIEW",
                "**Reason**: The recovered source row was self-dropped on "
                f"{basis} but carries no concrete location or harm. It is "
                "retained as methodology debt and MUST NOT be fabricated into "
                "a vulnerability finding.",
                "**Source Text**: "
                + str(candidate.get("line_text") or "").strip(), "",
            ])
            continue
        location = str(candidate.get("location") or "").strip() or (
            "unspecified (in-scope referent missing)"
        )
        severity = str(candidate.get("severity") or "").strip() or "Medium"
        description = (
            "This candidate was self-dropped by a depth agent based on "
            f"{basis}, so the drop's basis is unverified. It carries its own "
            "concrete location and mechanism, so dedup it against existing "
            "findings or resolve it into a concrete finding "
            "[RE-EMITTED: depth self-exclusion without in-scope referent]."
        )
        evidence = (
            (f"original entry in {source}" if source else "see source")
            + (f" (agent id {own_id})" if own_id else "")
            + ": " + str(candidate.get("line_text") or "").strip()
        )
        lines.extend([
            f"### Finding [DXRE-{ordinal}]: {title}", "",
            "**Verdict**: CONTESTED", f"**Severity**: {severity}",
            "**Confidence**: LOW", f"**Location**: {location}",
            f"**Source Action ID**: DXRE-{ordinal}",
            f"**Source Identity**: {source_identity}",
            f"**Description**: {description}",
            "**Impact**: If the underlying bug is real, suppressing it via a "
            "belief-based self-exclusion would cause a true positive to be missed.",
            f"**Evidence**: {evidence}", "",
        ])
    lines.extend(("<!-- PLAMEN_STATUS: COMPLETE -->", ""))
    return "\n".join(lines).encode("utf-8")


def validate_depth_self_exclusion_publication(
    publication: DepthSelfExclusionPublication,
    *,
    source_bytes: Mapping[str, bytes],
) -> None:
    """Replay the complete plan without consulting mutable ambient state."""

    if not isinstance(publication, DepthSelfExclusionPublication):
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion publication type is invalid"
        )
    publication.validate_preimages(source_bytes)
    if hashlib.sha256(publication.output_bytes).hexdigest() != publication.output_sha256:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output bytes changed after planning"
        )
    unsigned = {
        key: value
        for key, value in publication.payload.items()
        if key != "publication_digest"
    }
    if _digest(unsigned) != publication.publication_digest:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion publication digest mismatch"
        )
    if _HEX_RE.fullmatch(publication.output_sha256) is None:
        raise DepthSelfExclusionPublicationError(
            "depth self-exclusion output digest is malformed"
        )
