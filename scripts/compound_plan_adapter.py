"""Strict ``chain_hypotheses.md`` to typed compound-work-plan adapter.

The adapter is intentionally filesystem- and driver-neutral.  It accepts only
bounded ``Chain Hypothesis CH-*`` sections and the generic chain contract's
explicit fields.  Missing or ambiguous fields become digest-bound adapter debt;
they are never inferred from summary tables or surrounding prose.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Iterable, Mapping, Sequence

from compound_verification import (
    CompoundCandidate,
    CompoundWorkPlan,
    compile_compound_work_plan,
)


COMPOUND_CANDIDATES_SCHEMA_VERSION = "plamen.compound_candidates.v1"
COMPOUND_ADAPTER_WORK_PLAN_SCHEMA_VERSION = "plamen.compound_adapter_work_plan.v1"

_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
_CHAIN_HEADING_RE = re.compile(
    r"^(?P<marks>#{2,6})[ \t]+Chain Hypothesis[ \t]+"
    r"(?P<chain_id>CH-\d{1,6})(?:[ \t]+.*)?$",
    re.ASCII,
)
_ANY_HEADING_RE = re.compile(r"^(?P<marks>#{1,6})[ \t]+.+$")
_CHAIN_MENTION_RE = re.compile(r"\bChain Hypothesis[ \t]+(CH-\d{1,6})\b", re.ASCII)
_IDENTITY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:-[A-Z0-9_]+)+$", re.ASCII)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", re.ASCII)
_SEVERITY_RE = re.compile(
    r"(?:\*\*)?(?:Proposed Chain Severity|Chain Severity)(?:\*\*)?"
    r"\s*:\s*(?:\*\*)?"
    r"(Critical|High|Medium|Low|Informational)(?:\*\*)?(?:\s+.*)?$"
)
_MACHINE_LINE_RE = re.compile(
    r"^Constituents:\s*(?P<constituents>[^|]+?)"
    r"\s+\|\s+Severity-Upgrade-Justified:\s*(?P<justified>YES|NO)"
    r"\s+\|\s+Combined-Impact:\s*(?P<impact>.*)$",
    re.ASCII,
)
_SEQUENCE_RE = re.compile(
    r"^\s*(?P<number>\d+)\.\s+\["
    r"(?P<role>B|Step from B|A|Step from A|Impact)\]"
    r"\s*:?[ \t]*(?P<step>\S.*)$"
)

_MARKERS = {
    "blocked": "Blocked Finding (A)",
    "enabler": "Enabler Finding (B)",
    "sequence": "Combined Attack Sequence",
    "severity": "Severity Reassessment",
}


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_text(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("chain_hypotheses input must be text")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _token(value: str, field: str) -> str:
    if not isinstance(value, str) or not _TOKEN_RE.fullmatch(value):
        raise ValueError(f"{field} must be a non-empty token")
    return value


def _identity(value: str) -> str:
    normalized = str(value or "").strip().strip("`*[]()").upper()
    if not _IDENTITY_RE.fullmatch(normalized):
        raise ValueError(f"invalid finding identity: {value!r}")
    return normalized


def _strip_bullet_and_outer_bold(line: str) -> str:
    value = line.strip()
    if value.startswith("- "):
        value = value[2:].strip()
    if value.startswith("**") and value.endswith("**") and len(value) >= 4:
        value = value[2:-2].strip()
    return value


def _marker_name(line: str) -> str | None:
    value = line.strip()
    if value.startswith("**") and value.endswith("**"):
        value = value[2:-2].strip()
    else:
        heading = re.fullmatch(r"#{2,6}[ \t]+(.+?)\s*", value)
        if heading:
            value = heading.group(1).strip()
    for key, label in _MARKERS.items():
        if value == label:
            return key
    return None


def _field_values(lines: Sequence[str], label: str) -> list[str]:
    pattern = re.compile(
        r"(?:\*\*)?" + re.escape(label) + r"(?:\*\*)?\s*:\s*"
        r"(?P<value>.*?)(?=,\s*(?:\*\*)?(?:Title|Type)(?:\*\*)?\s*:|$)"
    )
    values: list[str] = []
    for line in lines:
        for match in pattern.finditer(line):
            value = match.group("value").strip().strip("* ")
            if value.endswith("."):
                value = value[:-1].rstrip()
            if value:
                values.append(value)
    return values


@dataclass(frozen=True, slots=True)
class CompoundAdapterIssue:
    """One explicit parser/adapter debt tied to its immutable source section."""

    code: str
    subject_id: str
    detail: str
    start_line: int
    end_line: int
    section_digest: str
    blocking: bool = True

    def __post_init__(self) -> None:
        _token(self.code, "adapter issue code")
        _token(self.subject_id, "adapter issue subject_id")
        if not isinstance(self.detail, str) or not self.detail.strip():
            raise ValueError("adapter issue detail must not be empty")
        if isinstance(self.start_line, bool) or not isinstance(self.start_line, int):
            raise TypeError("adapter issue start_line must be an integer")
        if isinstance(self.end_line, bool) or not isinstance(self.end_line, int):
            raise TypeError("adapter issue end_line must be an integer")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("adapter issue line range is invalid")
        if not _HEX_DIGEST_RE.fullmatch(self.section_digest):
            raise ValueError("adapter issue section_digest must be SHA-256")
        if not isinstance(self.blocking, bool):
            raise TypeError("adapter issue blocking must be boolean")

    def to_record(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "subject_id": self.subject_id,
            "detail": self.detail,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "section_digest": self.section_digest,
            "blocking": self.blocking,
        }


@dataclass(frozen=True, slots=True)
class CompoundAdapterParseResult:
    source_artifact: str
    source_digest: str
    candidates: tuple[CompoundCandidate, ...]
    issues: tuple[CompoundAdapterIssue, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.source_artifact, str) or not self.source_artifact:
            raise ValueError("source_artifact must not be empty")
        if not _HEX_DIGEST_RE.fullmatch(self.source_digest):
            raise ValueError("source_digest must be SHA-256")
        if not all(isinstance(item, CompoundCandidate) for item in self.candidates):
            raise TypeError("candidates must contain CompoundCandidate records")
        if not all(isinstance(item, CompoundAdapterIssue) for item in self.issues):
            raise TypeError("issues must contain CompoundAdapterIssue records")

    def candidates_payload_unsigned(self) -> dict[str, Any]:
        return {
            "schema_version": COMPOUND_CANDIDATES_SCHEMA_VERSION,
            "source_artifact": self.source_artifact,
            "source_digest": self.source_digest,
            "candidate_count": len(self.candidates),
            "issue_count": len(self.issues),
            "candidates": [
                {**candidate.to_record(), "candidate_digest": candidate.digest}
                for candidate in self.candidates
            ],
            "adapter_issues": [issue.to_record() for issue in self.issues],
        }

    @property
    def candidates_digest(self) -> str:
        return _digest(self.candidates_payload_unsigned())

    def candidates_payload(self) -> dict[str, Any]:
        return {
            **self.candidates_payload_unsigned(),
            "payload_digest": self.candidates_digest,
        }


@dataclass(frozen=True, slots=True)
class CompoundAdapterBundle:
    parse_result: CompoundAdapterParseResult
    active_queue_identities: tuple[str, ...]
    active_queue_identity_digest: str
    work_plan: CompoundWorkPlan

    def __post_init__(self) -> None:
        if not isinstance(self.parse_result, CompoundAdapterParseResult):
            raise TypeError("parse_result must be a CompoundAdapterParseResult")
        if not all(_IDENTITY_RE.fullmatch(item) for item in self.active_queue_identities):
            raise ValueError("active_queue_identities contain an invalid identity")
        if tuple(sorted(set(self.active_queue_identities))) != self.active_queue_identities:
            raise ValueError("active_queue_identities must be unique and sorted")
        if not _HEX_DIGEST_RE.fullmatch(self.active_queue_identity_digest):
            raise ValueError("active_queue_identity_digest must be SHA-256")
        if self.active_queue_identity_digest != _digest(
            list(self.active_queue_identities)
        ):
            raise ValueError("active_queue_identity_digest mismatch")
        if not isinstance(self.work_plan, CompoundWorkPlan):
            raise TypeError("work_plan must be a CompoundWorkPlan")

    @property
    def candidates_digest(self) -> str:
        return self.parse_result.candidates_digest

    @property
    def compound_candidates_json(self) -> str:
        return _canonical_json(self.parse_result.candidates_payload())

    def work_plan_payload_unsigned(self) -> dict[str, Any]:
        return {
            "schema_version": COMPOUND_ADAPTER_WORK_PLAN_SCHEMA_VERSION,
            "compound_candidates_digest": self.candidates_digest,
            "active_queue_identities": list(self.active_queue_identities),
            "active_queue_identity_digest": self.active_queue_identity_digest,
            "compound_work_plan": self.work_plan.to_record(),
            "compound_work_plan_digest": self.work_plan.digest,
            "adapter_issues": [
                issue.to_record() for issue in self.parse_result.issues
            ],
        }

    @property
    def work_plan_payload_digest(self) -> str:
        return _digest(self.work_plan_payload_unsigned())

    def work_plan_payload(self) -> dict[str, Any]:
        return {
            **self.work_plan_payload_unsigned(),
            "payload_digest": self.work_plan_payload_digest,
        }

    @property
    def compound_work_plan_json(self) -> str:
        return _canonical_json(self.work_plan_payload())


def _issue(
    issues: list[CompoundAdapterIssue],
    *,
    code: str,
    subject_id: str,
    detail: str,
    start_line: int,
    end_line: int,
    section_digest: str,
    blocking: bool = True,
) -> None:
    issues.append(
        CompoundAdapterIssue(
            code=code,
            subject_id=subject_id,
            detail=detail,
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
            blocking=blocking,
        )
    )


def _single_required_value(
    *,
    lines: Sequence[str],
    label: str,
    missing_code: str,
    ambiguous_code: str,
    subject_id: str,
    start_line: int,
    end_line: int,
    section_digest: str,
    issues: list[CompoundAdapterIssue],
) -> str | None:
    values = _field_values(lines, label)
    if not values:
        _issue(
            issues,
            code=missing_code,
            subject_id=subject_id,
            detail=f"required {label!r} field is absent or empty",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
        return None
    if len(values) != 1:
        _issue(
            issues,
            code=ambiguous_code,
            subject_id=subject_id,
            detail=f"required {label!r} field occurs {len(values)} times",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
        return None
    return values[0]


def _section_segments(section_lines: Sequence[str]) -> dict[str, Sequence[str]]:
    positions: dict[str, list[int]] = {key: [] for key in _MARKERS}
    for index, line in enumerate(section_lines[1:], start=1):
        marker = _marker_name(line)
        if marker:
            positions[marker].append(index)
    all_positions = sorted(
        index for marker_positions in positions.values() for index in marker_positions
    )
    segments: dict[str, Sequence[str]] = {}
    for key, marker_positions in positions.items():
        if len(marker_positions) != 1:
            segments[key] = ()
            continue
        start = marker_positions[0] + 1
        end = next((index for index in all_positions if index >= start), len(section_lines))
        segments[key] = section_lines[start:end]
    return segments


def _parse_section(
    section_lines: Sequence[str],
    *,
    chain_id: str,
    start_line: int,
    end_line: int,
    source_artifact: str,
    pipeline: str,
    mode: str,
) -> tuple[CompoundCandidate | None, tuple[CompoundAdapterIssue, ...]]:
    section_text = "\n".join(section_lines) + "\n"
    section_digest = _text_digest(section_text)
    issues: list[CompoundAdapterIssue] = []
    segments = _section_segments(section_lines)

    marker_counts = {key: 0 for key in _MARKERS}
    for line in section_lines[1:]:
        marker = _marker_name(line)
        if marker:
            marker_counts[marker] += 1
    for key, label in _MARKERS.items():
        count = marker_counts[key]
        if count == 0:
            _issue(
                issues,
                code=f"MISSING_{key.upper()}_SECTION",
                subject_id=chain_id,
                detail=f"required {label!r} section is absent",
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
        elif count > 1:
            _issue(
                issues,
                code=f"AMBIGUOUS_{key.upper()}_SECTION",
                subject_id=chain_id,
                detail=f"required {label!r} section occurs {count} times",
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )

    precondition = _single_required_value(
        lines=segments.get("blocked", ()),
        label="Missing Precondition",
        missing_code="MISSING_BLOCKED_PRECONDITION",
        ambiguous_code="AMBIGUOUS_BLOCKED_PRECONDITION",
        subject_id=chain_id,
        start_line=start_line,
        end_line=end_line,
        section_digest=section_digest,
        issues=issues,
    )
    postcondition = _single_required_value(
        lines=segments.get("enabler", ()),
        label="Postcondition Created",
        missing_code="MISSING_ENABLER_POSTCONDITION",
        ambiguous_code="AMBIGUOUS_ENABLER_POSTCONDITION",
        subject_id=chain_id,
        start_line=start_line,
        end_line=end_line,
        section_digest=section_digest,
        issues=issues,
    )
    blocked_identity_raw = _single_required_value(
        lines=segments.get("blocked", ()),
        label="ID",
        missing_code="MISSING_BLOCKED_IDENTITY",
        ambiguous_code="AMBIGUOUS_BLOCKED_IDENTITY",
        subject_id=chain_id,
        start_line=start_line,
        end_line=end_line,
        section_digest=section_digest,
        issues=issues,
    )
    enabler_identity_raw = _single_required_value(
        lines=segments.get("enabler", ()),
        label="ID",
        missing_code="MISSING_ENABLER_IDENTITY",
        ambiguous_code="AMBIGUOUS_ENABLER_IDENTITY",
        subject_id=chain_id,
        start_line=start_line,
        end_line=end_line,
        section_digest=section_digest,
        issues=issues,
    )
    blocked_identity: str | None = None
    enabler_identity: str | None = None
    for role, raw_identity in (
        ("BLOCKED", blocked_identity_raw),
        ("ENABLER", enabler_identity_raw),
    ):
        if raw_identity is None:
            continue
        try:
            normalized_identity = _identity(raw_identity)
        except ValueError as exc:
            _issue(
                issues,
                code=f"INVALID_{role}_IDENTITY",
                subject_id=chain_id,
                detail=str(exc),
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
            continue
        if role == "BLOCKED":
            blocked_identity = normalized_identity
        else:
            enabler_identity = normalized_identity

    machine_matches: list[re.Match[str]] = []
    malformed_machine_line = False
    for line in section_lines:
        normalized = _strip_bullet_and_outer_bold(line)
        match = _MACHINE_LINE_RE.fullmatch(normalized)
        if match:
            machine_matches.append(match)
        elif "Constituents:" in normalized:
            malformed_machine_line = True
    constituents: tuple[str, ...] | None = None
    justified: bool | None = None
    combined_impact: str | None = None
    if not machine_matches:
        _issue(
            issues,
            code="MALFORMED_MACHINE_LINE" if malformed_machine_line else "MISSING_MACHINE_LINE",
            subject_id=chain_id,
            detail="exact required Constituents/Severity-Upgrade-Justified/Combined-Impact line is absent",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
    elif len(machine_matches) > 1:
        _issue(
            issues,
            code="AMBIGUOUS_MACHINE_LINE",
            subject_id=chain_id,
            detail=f"required machine line occurs {len(machine_matches)} times",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
    else:
        machine = machine_matches[0]
        try:
            constituents = tuple(
                _identity(item)
                for item in machine.group("constituents").split(",")
                if item.strip()
            )
            if len(constituents) < 2 or len(set(constituents)) != len(constituents):
                raise ValueError("constituents must contain at least two unique IDs")
        except ValueError as exc:
            _issue(
                issues,
                code="INVALID_CONSTITUENTS",
                subject_id=chain_id,
                detail=str(exc),
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
            constituents = None
        if (
            constituents is not None
            and blocked_identity is not None
            and enabler_identity is not None
            and constituents != (blocked_identity, enabler_identity)
        ):
            _issue(
                issues,
                code="CONSTITUENT_ROLE_MISMATCH",
                subject_id=chain_id,
                detail=(
                    "machine constituents must be ordered as the explicit "
                    f"blocked/enabler IDs {(blocked_identity, enabler_identity)!r}"
                ),
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
        justified = machine.group("justified") == "YES"
        combined_impact = machine.group("impact").strip().strip("* ")
        if not combined_impact:
            _issue(
                issues,
                code="MISSING_COMBINED_IMPACT",
                subject_id=chain_id,
                detail="Combined-Impact is empty",
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
        elif justified and combined_impact.upper() == "NONE":
            _issue(
                issues,
                code="JUSTIFIED_WITHOUT_COMBINED_IMPACT",
                subject_id=chain_id,
                detail="YES upgrade cannot use Combined-Impact: NONE",
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
        elif not justified and combined_impact.upper() != "NONE":
            _issue(
                issues,
                code="NONJUSTIFIED_COMBINED_IMPACT_NOT_NONE",
                subject_id=chain_id,
                detail="NO upgrade should project Combined-Impact: NONE; retained as restatement debt",
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
                blocking=False,
            )

    sequence_rows: list[tuple[int, str, str]] = []
    for line in segments.get("sequence", ()):
        match = _SEQUENCE_RE.fullmatch(line)
        if match:
            role = match.group("role")
            role = "B" if role == "Step from B" else "A" if role == "Step from A" else role
            sequence_rows.append(
                (int(match.group("number")), role, match.group("step").strip())
            )
    numbers = [row[0] for row in sequence_rows]
    b_positions = [row[0] for row in sequence_rows if row[1] == "B"]
    a_positions = [row[0] for row in sequence_rows if row[1] == "A"]
    impact_positions = [row[0] for row in sequence_rows if row[1] == "Impact"]
    sequence_valid = bool(
        numbers
        and numbers == list(range(1, len(numbers) + 1))
        and b_positions
        and a_positions
        and impact_positions
        and max(b_positions) < min(a_positions)
        and max(a_positions) < min(impact_positions)
    )
    if not sequence_valid:
        _issue(
            issues,
            code="INVALID_SEQUENCE_ORDERING",
            subject_id=chain_id,
            detail="numbered sequence must contain contiguous B-before-A-before-Impact steps",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )

    severities: list[str] = []
    for line in segments.get("severity", ()):
        match = _SEVERITY_RE.search(line.strip())
        if match:
            severities.append(match.group(1))
    proposed_severity: str | None = None
    if not severities:
        _issue(
            issues,
            code="MISSING_PROPOSED_CHAIN_SEVERITY",
            subject_id=chain_id,
            detail="exact Proposed Chain Severity or Chain Severity field is absent",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
    elif len(severities) > 1:
        _issue(
            issues,
            code="AMBIGUOUS_PROPOSED_CHAIN_SEVERITY",
            subject_id=chain_id,
            detail=f"proposed chain severity occurs {len(severities)} times",
            start_line=start_line,
            end_line=end_line,
            section_digest=section_digest,
        )
    else:
        proposed_severity = severities[0]

    candidate: CompoundCandidate | None = None
    if not any(issue.blocking for issue in issues):
        assert constituents is not None
        assert justified is not None
        assert combined_impact is not None
        assert precondition is not None
        assert postcondition is not None
        assert blocked_identity is not None
        assert enabler_identity is not None
        assert proposed_severity is not None
        try:
            candidate = CompoundCandidate.create(
                chain_id=chain_id,
                constituents=constituents,
                severity_upgrade_justified=justified,
                ordering_edges=((enabler_identity, blocked_identity, "precedes"),),
                preconditions=(precondition,),
                postconditions=(postcondition,),
                combined_impact_claim=combined_impact,
                proposed_severity=proposed_severity,
                source_lineage=(
                    f"{source_artifact}:L{start_line}-L{end_line}:sha256={section_digest}",
                ),
                coverage_lineage=tuple(
                    f"chain-machine-line:{chain_id}:{identity}"
                    for identity in constituents
                ),
                pipeline=pipeline,
                mode=mode,
            )
        except (TypeError, ValueError) as exc:
            _issue(
                issues,
                code="INVALID_COMPOUND_CANDIDATE",
                subject_id=chain_id,
                detail=str(exc),
                start_line=start_line,
                end_line=end_line,
                section_digest=section_digest,
            )
    return candidate, tuple(issues)


def parse_chain_hypotheses(
    text: str,
    *,
    pipeline: str,
    mode: str,
    source_artifact: str = "chain_hypotheses.md",
) -> CompoundAdapterParseResult:
    """Parse only strict CH sections; return all malformed sections as debt."""

    normalized = _normalize_text(text)
    lines = normalized.splitlines()
    headings: list[tuple[int, int, str]] = []
    issues: list[CompoundAdapterIssue] = []
    for index, line in enumerate(lines):
        match = _CHAIN_HEADING_RE.fullmatch(line)
        if match:
            headings.append((index, len(match.group("marks")), match.group("chain_id")))
            continue
        mention = _CHAIN_MENTION_RE.search(line)
        if mention:
            line_digest = _text_digest(line + "\n")
            _issue(
                issues,
                code="MALFORMED_CHAIN_HEADING",
                subject_id=mention.group(1),
                detail="chain mention is not a level-2-to-level-6 Chain Hypothesis heading",
                start_line=index + 1,
                end_line=index + 1,
                section_digest=line_digest,
            )

    candidates: list[CompoundCandidate] = []
    for position, (start, level, chain_id) in enumerate(headings):
        end = len(lines)
        next_chain_start = headings[position + 1][0] if position + 1 < len(headings) else None
        for index in range(start + 1, len(lines)):
            if next_chain_start is not None and index == next_chain_start:
                end = index
                break
            generic_heading = _ANY_HEADING_RE.fullmatch(lines[index])
            if generic_heading and len(generic_heading.group("marks")) <= level:
                end = index
                break
        candidate, section_issues = _parse_section(
            lines[start:end],
            chain_id=chain_id,
            start_line=start + 1,
            end_line=max(start + 1, end),
            source_artifact=source_artifact,
            pipeline=pipeline,
            mode=mode,
        )
        issues.extend(section_issues)
        if candidate is not None:
            candidates.append(candidate)

    candidates.sort(key=lambda item: (item.chain_id, item.digest))
    issues.sort(
        key=lambda item: (
            item.start_line,
            item.subject_id,
            item.code,
            item.section_digest,
        )
    )
    return CompoundAdapterParseResult(
        source_artifact=source_artifact,
        source_digest=_text_digest(normalized),
        candidates=tuple(candidates),
        issues=tuple(issues),
    )


def adapt_chain_hypotheses(
    text: str,
    known_active_queue_identities: Iterable[str],
    *,
    pipeline: str,
    mode: str,
    source_artifact: str = "chain_hypotheses.md",
) -> CompoundAdapterBundle:
    """Parse, compile, and serialize one deterministic compound work plan."""

    parsed = parse_chain_hypotheses(
        text,
        pipeline=pipeline,
        mode=mode,
        source_artifact=source_artifact,
    )
    active_ids = tuple(
        sorted({_identity(identity) for identity in known_active_queue_identities})
    )
    work_plan = compile_compound_work_plan(parsed.candidates, active_ids)
    return CompoundAdapterBundle(
        parse_result=parsed,
        active_queue_identities=active_ids,
        active_queue_identity_digest=_digest(list(active_ids)),
        work_plan=work_plan,
    )


def adapt_chain_composition_candidates(
    payload: Mapping[str, Any],
    known_active_queue_identities: Iterable[str],
    known_severities: Mapping[str, str],
    *,
    pipeline: str,
    mode: str,
    source_artifact: str = "chain_composition_verification_candidates.json",
) -> CompoundAdapterBundle:
    """Compile the chain-tail typed authority without reparsing Markdown.

    The sidecar supplies candidate identity, constituents, evidence, and its
    explicit ordinary-verification route.  It grants no proof.  Missing or
    malformed typed fields fail closed instead of falling back to heading
    spelling in ``chain_hypotheses.md``.
    """

    if not isinstance(payload, Mapping):
        raise TypeError("chain composition candidate authority must be an object")
    required = {
        "schema_version", "manifest_sha256", "ledger_sha256",
        "proof_authority", "candidates", "candidate_digest",
    }
    if set(payload) != required:
        raise ValueError("chain composition candidate authority schema mismatch")
    if payload["schema_version"] != "plamen.chain_composition_candidates.v1":
        raise ValueError("chain composition candidate authority version mismatch")
    if payload["proof_authority"] != "NONE":
        raise ValueError("chain composition candidate authority granted proof")
    unsigned = {key: value for key, value in payload.items() if key != "candidate_digest"}
    authority_digest = hashlib.sha256(
        json.dumps(
            unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
    ).hexdigest()
    if payload["candidate_digest"] != authority_digest:
        raise ValueError("chain composition candidate authority digest mismatch")
    if not isinstance(payload["candidates"], list):
        raise TypeError("chain composition candidates must be an array")

    severity_order = {
        "Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4,
    }
    active_ids = tuple(
        sorted({_identity(identity) for identity in known_active_queue_identities})
    )
    candidates: list[CompoundCandidate] = []
    for index, value in enumerate(payload["candidates"]):
        if not isinstance(value, Mapping):
            raise TypeError(f"chain composition candidate {index} must be an object")
        common_fields = {
            "pair_id", "pair_ids", "chain_id", "constituent_finding_ids",
            "evidence", "proof_authority", "route",
        }
        route = str(value.get("route") or "")
        expected_fields = (
            common_fields | {"reason"}
            if route == "HUMAN_REVIEW"
            else common_fields
        )
        if set(value) != expected_fields:
            raise ValueError(f"chain composition candidate {index} schema mismatch")
        if value["proof_authority"] != "NONE":
            raise ValueError(f"chain composition candidate {index} authority mismatch")
        if route == "HUMAN_REVIEW":
            # Lossless orphan proposals remain visible assurance debt but do
            # not masquerade as an ordinary executable verification item.
            if not str(value.get("reason") or "").strip():
                raise ValueError(
                    f"chain composition candidate {index} lacks review reason"
                )
            continue
        if route != "ORDINARY_VERIFICATION":
            raise ValueError(f"chain composition candidate {index} authority mismatch")
        chain_id = str(value["chain_id"] or "").strip().upper()
        constituents_raw = value["constituent_finding_ids"]
        if not isinstance(constituents_raw, list) or len(constituents_raw) < 2:
            raise ValueError(f"chain composition candidate {index} lacks constituents")
        constituents = tuple(_identity(item) for item in constituents_raw)
        severity = max(
            (
                str(known_severities.get(identity) or "Medium").strip().title()
                for identity in constituents
            ),
            key=lambda item: severity_order.get(item, severity_order["Medium"]),
        )
        if severity not in severity_order:
            severity = "Medium"
        pair_ids_raw = value["pair_ids"]
        if not isinstance(pair_ids_raw, list) or not pair_ids_raw:
            raise ValueError(f"chain composition candidate {index} lacks pair roster")
        pair_ids = tuple(
            _token(str(pair_id or ""), "pair_id")
            for pair_id in pair_ids_raw
        )
        if len(set(pair_ids)) != len(pair_ids):
            raise ValueError(
                f"chain composition candidate {index} repeats pair identity"
            )
        pair_id = _token(str(value["pair_id"] or ""), "pair_id")
        if pair_id != pair_ids[0]:
            raise ValueError(
                f"chain composition candidate {index} primary pair mismatch"
            )
        evidence = re.sub(r"\s+", " ", str(value["evidence"] or "")).strip()
        if not evidence:
            raise ValueError(f"chain composition candidate {index} lacks evidence")
        candidates.append(CompoundCandidate.create(
            chain_id=chain_id,
            constituents=constituents,
            # In this adapter the flag means the typed discovery is a distinct
            # compound claim requiring work, not that its severity is proven.
            severity_upgrade_justified=True,
            ordering_edges=(),
            preconditions=(
                "Typed pair roster "
                + ",".join(pair_ids)
                + " composition premise is unverified.",
            ),
            postconditions=("The composed state transition requires independent execution.",),
            combined_impact_claim=evidence,
            proposed_severity=severity,
            source_lineage=(
                f"{source_artifact}:candidate={chain_id}:sha256={payload['candidate_digest']}",
            ),
            coverage_lineage=(*pair_ids, *constituents),
            pipeline=pipeline,
            mode=mode,
        ))
    candidates.sort(key=lambda item: (item.chain_id, item.digest))
    parsed = CompoundAdapterParseResult(
        source_artifact=source_artifact,
        source_digest=str(payload["candidate_digest"]),
        candidates=tuple(candidates),
        issues=(),
    )
    return CompoundAdapterBundle(
        parse_result=parsed,
        active_queue_identities=active_ids,
        active_queue_identity_digest=_digest(list(active_ids)),
        work_plan=compile_compound_work_plan(candidates, active_ids),
    )


__all__ = [
    "COMPOUND_ADAPTER_WORK_PLAN_SCHEMA_VERSION",
    "COMPOUND_CANDIDATES_SCHEMA_VERSION",
    "CompoundAdapterBundle",
    "CompoundAdapterIssue",
    "CompoundAdapterParseResult",
    "adapt_chain_composition_candidates",
    "adapt_chain_hypotheses",
    "parse_chain_hypotheses",
]
