"""Source-citation authority for methodology-application evidence only.

This module normalizes resolvable ``source.ext:line`` and
``source.ext:Lline`` citations to one project-relative ``source.ext:Lline``
location.  It certifies only that an application attestation names an
existing in-scope source locus.  It is not finding validity, severity,
verification, or disposition authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
from typing import Iterable


_SOURCE_EXTENSIONS = (
    "rs",
    "go",
    "sol",
    "vy",
    "move",
    "daml",
    "cairo",
    "py",
    "c",
    "cc",
    "cpp",
    "h",
    "hpp",
    "java",
    "ts",
    "js",
)
_EXTENSION_PATTERN = "|".join(_SOURCE_EXTENSIONS)
_EXACT_CITATION_RE = re.compile(
    rf"^(?P<path>.+\.(?:{_EXTENSION_PATTERN})):(?P<line>L?[0-9]+)$",
    re.IGNORECASE,
)
_QUOTED_CANDIDATE_RE = re.compile(
    r"(?P<quote>[`'\"])(?P<value>[^\r\n]*?)(?P=quote)"
)
_BARE_CANDIDATE_RE = re.compile(
    rf"(?<![A-Za-z0-9_./\\:-])"
    rf"(?P<value>(?:[A-Za-z]:[\\/])?[A-Za-z0-9_@+.,~%:/\\-]+"
    rf"\.(?:{_EXTENSION_PATTERN}):L?[0-9]+)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ResolvedMethodologyCitation:
    """One mechanically resolved application-evidence source location."""

    raw: str
    relative_path: str
    line: int

    @property
    def canonical(self) -> str:
        return f"{self.relative_path}:L{self.line}"


@dataclass(frozen=True)
class RejectedMethodologyCitation:
    """A citation-shaped token that cannot become application evidence."""

    raw: str
    reason: str


@dataclass(frozen=True)
class MethodologyCitationResolution:
    citations: tuple[ResolvedMethodologyCitation, ...]
    rejections: tuple[RejectedMethodologyCitation, ...]

    @property
    def has_valid_citation(self) -> bool:
        return bool(self.citations)


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


class MethodologyCitationResolver:
    """Resolve source citations under one audited project root.

    Direct project-relative and in-root absolute paths are accepted.  A short
    path is accepted only when it uniquely suffix-matches one source file.
    Raw traversal, symlink escape, scratchpad sources, line zero, and lines
    beyond EOF are rejected.
    """

    def __init__(self, project_root: Path, *, scratchpad: Path | None = None) -> None:
        self.project_root = Path(project_root).resolve()
        default_scratchpad = self.project_root / ".scratchpad"
        self.scratchpad = Path(scratchpad or default_scratchpad).resolve()
        self._source_index: tuple[tuple[str, Path], ...] | None = None
        self._line_counts: dict[Path, int] = {}

    def resolve_evidence(self, evidence: str) -> MethodologyCitationResolution:
        citations: dict[str, ResolvedMethodologyCitation] = {}
        rejections: list[RejectedMethodologyCitation] = []
        for raw in self._candidate_tokens(str(evidence or "")):
            resolved, reason = self._resolve_token(raw)
            if resolved is None:
                rejections.append(
                    RejectedMethodologyCitation(raw=raw, reason=reason or "MALFORMED")
                )
                continue
            citations.setdefault(resolved.canonical.casefold(), resolved)
        ordered = tuple(citations[key] for key in sorted(citations))
        return MethodologyCitationResolution(ordered, tuple(rejections))

    def has_resolvable_citation(self, evidence: str) -> bool:
        return self.resolve_evidence(evidence).has_valid_citation

    @staticmethod
    def _candidate_tokens(evidence: str) -> Iterable[str]:
        quoted_spans: list[tuple[int, int]] = []
        for match in _QUOTED_CANDIDATE_RE.finditer(evidence):
            quoted_spans.append(match.span())
            value = match.group("value").strip()
            if _EXACT_CITATION_RE.fullmatch(value):
                yield value
        for match in _BARE_CANDIDATE_RE.finditer(evidence):
            start, end = match.span()
            if any(q_start <= start and end <= q_end for q_start, q_end in quoted_spans):
                continue
            yield match.group("value")

    def _resolve_token(
        self, raw: str
    ) -> tuple[ResolvedMethodologyCitation | None, str]:
        match = _EXACT_CITATION_RE.fullmatch(raw.strip())
        if match is None:
            return None, "MALFORMED"
        raw_path = match.group("path").strip()
        line_token = match.group("line")
        line_digits = (
            line_token[1:] if line_token[:1].casefold() == "l" else line_token
        )
        # Bound adversarial numeric tokens before integer conversion.  No
        # project source can have a trillion physical lines, and Python also
        # rejects pathologically long decimal conversions by default.
        if len(line_digits) > 12:
            return None, "MALFORMED"
        try:
            line_number = int(line_digits)
        except ValueError:
            return None, "MALFORMED"
        if line_number == 0:
            return None, "LINE_ZERO"

        portable = raw_path.replace("\\", "/")
        path_without_drive = re.sub(r"^[A-Za-z]:/", "", portable)
        if any(part == ".." for part in path_without_drive.split("/")):
            return None, "TRAVERSAL"

        candidate, issue = self._direct_candidate(portable)
        if issue:
            return None, issue
        if candidate is None:
            candidates = self._suffix_candidates(portable)
            if not candidates:
                return None, "NONEXISTENT"
            if len(candidates) != 1:
                return None, "AMBIGUOUS"
            candidate = candidates[0]

        exclusion = self._scope_issue(candidate)
        if exclusion:
            return None, exclusion
        line_count = self._line_count(candidate)
        if line_count is None:
            return None, "UNREADABLE"
        if line_number > line_count:
            return None, "LINE_BEYOND_EOF"
        relative = candidate.relative_to(self.project_root).as_posix()
        return (
            ResolvedMethodologyCitation(
                raw=raw,
                relative_path=relative,
                line=line_number,
            ),
            "",
        )

    def _direct_candidate(self, portable: str) -> tuple[Path | None, str]:
        windows_absolute = bool(re.match(r"^[A-Za-z]:/", portable))
        posix_absolute = portable.startswith("/")
        if windows_absolute:
            if os.name != "nt":
                return None, "OUT_OF_ROOT"
            candidate = Path(portable.replace("/", os.sep))
        elif posix_absolute:
            if os.name == "nt":
                return None, "OUT_OF_ROOT"
            candidate = Path(portable)
        else:
            candidate = self.project_root / Path(portable.replace("/", os.sep))
        try:
            resolved = candidate.resolve()
        except (OSError, ValueError):
            return None, "MALFORMED"
        if not _is_relative_to(resolved, self.project_root):
            return None, "OUT_OF_ROOT"
        if resolved.is_file():
            return resolved, ""
        if windows_absolute or posix_absolute:
            return None, "NONEXISTENT"
        return None, ""

    def _suffix_candidates(self, portable: str) -> tuple[Path, ...]:
        suffix = portable.casefold()
        while suffix.startswith("./"):
            suffix = suffix[2:]
        suffix_with_slash = "/" + suffix
        matches = [
            path
            for relative, path in self._source_files()
            if relative == suffix or relative.endswith(suffix_with_slash)
        ]
        return tuple(matches)

    def _source_files(self) -> tuple[tuple[str, Path], ...]:
        if self._source_index is not None:
            return self._source_index
        rows: list[tuple[str, Path]] = []
        seen: set[Path] = set()
        try:
            paths = self.project_root.rglob("*")
            for path in paths:
                try:
                    resolved = path.resolve()
                    if not resolved.is_file() or self._scope_issue(resolved):
                        continue
                    if resolved.suffix.casefold().lstrip(".") not in _SOURCE_EXTENSIONS:
                        continue
                    if resolved in seen:
                        continue
                    seen.add(resolved)
                    relative = resolved.relative_to(self.project_root).as_posix().casefold()
                    rows.append((relative, resolved))
                except (OSError, ValueError):
                    continue
        except OSError:
            rows = []
        rows.sort(key=lambda row: row[0])
        self._source_index = tuple(rows)
        return self._source_index

    def _scope_issue(self, resolved: Path) -> str:
        if not _is_relative_to(resolved, self.project_root):
            return "OUT_OF_ROOT"
        relative = resolved.relative_to(self.project_root)
        if any(part.casefold() == ".scratchpad" for part in relative.parts):
            return "SCRATCHPAD_EXCLUDED"
        if _is_relative_to(resolved, self.scratchpad):
            return "SCRATCHPAD_EXCLUDED"
        return ""

    def _line_count(self, path: Path) -> int | None:
        if path in self._line_counts:
            return self._line_counts[path]
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                count = sum(1 for _ in handle)
        except OSError:
            return None
        self._line_counts[path] = count
        return count


def methodology_evidence_has_citation(
    evidence: str,
    project_root: Path,
    *,
    scratchpad: Path | None = None,
) -> bool:
    """Compatibility boolean for application-evidence consumers."""

    return MethodologyCitationResolver(
        project_root, scratchpad=scratchpad
    ).has_resolvable_citation(evidence)


__all__ = [
    "MethodologyCitationResolution",
    "MethodologyCitationResolver",
    "RejectedMethodologyCitation",
    "ResolvedMethodologyCitation",
    "methodology_evidence_has_citation",
]
