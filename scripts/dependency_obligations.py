"""Deterministic external-dependency obligation inventory for recon wave B.

The provider enumerates direct, non-local dependencies that production source
actually references.  It does not decide whether a dependency is dangerous;
it creates a bounded research obligation so an unavailable fetch is visible
instead of becoming an empty ledger.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import tomllib
from typing import Any, Iterable

SCHEMA = "plamen.external-dependency-obligations.v1"
MAX_OBLIGATIONS = 100
_SOURCE_SUFFIXES = (".sol", ".vy", ".rs", ".go", ".move", ".daml")
_SKIP_DIRS = {
    ".git", ".scratchpad", "artifacts", "cache", "dist", "node_modules",
    "out", "target", "vendor", "build", "coverage", "test", "tests",
}


def _production_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    from recon_prepass import _is_production_source_path

    wanted = {suffix.casefold() for suffix in suffixes}
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.casefold() not in wanted:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if any(part.casefold() in _SKIP_DIRS for part in relative.parts[:-1]):
            continue
        if _is_production_source_path(path, root):
            out.append(path)
    return sorted(out)


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _relative_locus(root: Path, path: Path, line: int) -> str:
    return f"{path.relative_to(root).as_posix()}:L{line}"


def _stable_id(kind: str, name: str, locus: str) -> str:
    digest = hashlib.sha256(
        f"{kind}\0{name.casefold()}\0{locus.casefold()}".encode("utf-8")
    ).hexdigest()[:12].upper()
    return f"DEP-{digest}"


def _row(kind: str, name: str, locus: str, evidence: str) -> dict[str, str]:
    return {
        "obligation_id": _stable_id(kind, name, locus),
        "dependency": name,
        "kind": kind,
        "source_location": locus,
        "declaration_evidence": " ".join(evidence.split())[:500],
        "research_question": (
            "Determine the externally defined semantics, temporal guarantees, "
            "failure behavior, and integration assumptions relied on at this locus."
        ),
    }


def _solidity_rows(root: Path, files: Iterable[Path]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    import_re = re.compile(
        r"(?m)^\s*import\s+(?:[^;]*?\sfrom\s+)?[\"'](?P<path>[^\"']+)[\"']\s*;"
    )
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in import_re.finditer(text):
            imported = match.group("path")
            if imported.startswith((".", "/")):
                continue
            parts = imported.split("/")
            name = "/".join(parts[:2]) if imported.startswith("@") else parts[0]
            locus = _relative_locus(root, path, _line_for(text, match.start()))
            rows.append(_row("source-import", name, locus, match.group(0)))
    # Preserve the existing structural interface-without-implementation signal.
    try:
        from recon_prepass import _detect_external_dependency_markers

        for name, locus in _detect_external_dependency_markers(root):
            rows.append(_row("external-interface", name, locus, name))
    except Exception:
        pass
    return rows


def _cargo_rows(root: Path, rust_files: list[Path]) -> list[dict[str, str]]:
    referenced = "\n".join(
        path.read_text(encoding="utf-8", errors="replace") for path in rust_files
    )
    rows: list[dict[str, str]] = []
    for manifest in sorted(root.rglob("Cargo.toml")):
        if any(part.casefold() in _SKIP_DIRS for part in manifest.relative_to(root).parts[:-1]):
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        tables = [data.get("dependencies", {})]
        workspace = data.get("workspace", {})
        if isinstance(workspace, dict):
            tables.append(workspace.get("dependencies", {}))
        for table in tables:
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                if isinstance(spec, dict) and ("path" in spec or spec.get("workspace") is True):
                    continue
                source_name = str(name).replace("-", "_")
                match = re.search(
                    rf"(?m)^\s*(?:use\s+)?{re.escape(source_name)}(?:::|\b)", referenced
                )
                if not match:
                    continue
                locus = f"{manifest.relative_to(root).as_posix()}:L1"
                rows.append(_row("cargo-direct", str(name), locus, repr(spec)))
    return rows


def _go_rows(root: Path, go_files: list[Path]) -> list[dict[str, str]]:
    imported: set[str] = set()
    import_re = re.compile(r'(?m)^\s*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"([^"\n]+)"')
    for path in go_files:
        text = path.read_text(encoding="utf-8", errors="replace")
        imported.update(import_re.findall(text))
    rows: list[dict[str, str]] = []
    for manifest in sorted(root.rglob("go.mod")):
        if any(part.casefold() in _SKIP_DIRS for part in manifest.relative_to(root).parts[:-1]):
            continue
        text = manifest.read_text(encoding="utf-8", errors="replace")
        in_require = False
        for line_no, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            match = re.match(r"(?:require\s+)?([^\s]+)\s+v[^\s]+", line)
            if not match or (not in_require and not line.startswith("require ")):
                continue
            name = match.group(1)
            if not any(path == name or path.startswith(name + "/") for path in imported):
                continue
            locus = f"{manifest.relative_to(root).as_posix()}:L{line_no}"
            rows.append(_row("go-direct", name, locus, raw))
    return rows


def _move_rows(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for manifest in sorted(root.rglob("Move.toml")):
        if any(part.casefold() in _SKIP_DIRS for part in manifest.relative_to(root).parts[:-1]):
            continue
        try:
            data = tomllib.loads(manifest.read_text(encoding="utf-8"))
        except Exception:
            continue
        for table_name in ("dependencies", "dev-dependencies"):
            table = data.get(table_name, {})
            if not isinstance(table, dict):
                continue
            for name, spec in table.items():
                if isinstance(spec, dict) and "local" in spec:
                    continue
                locus = f"{manifest.relative_to(root).as_posix()}:L1"
                rows.append(_row("move-direct", str(name), locus, repr(spec)))
    return rows


def _daml_rows(root: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for manifest in sorted(root.rglob("daml.yaml")):
        text = manifest.read_text(encoding="utf-8", errors="replace")
        in_dependencies = False
        for line_no, raw in enumerate(text.splitlines(), 1):
            if re.match(r"^dependencies\s*:", raw):
                in_dependencies = True
                continue
            if in_dependencies and raw and not raw.startswith((" ", "\t", "-")):
                in_dependencies = False
            if not in_dependencies:
                continue
            match = re.match(r"\s*-\s*(\S+)", raw)
            if match:
                locus = f"{manifest.relative_to(root).as_posix()}:L{line_no}"
                rows.append(_row("daml-direct", match.group(1), locus, raw))
    return rows


def enumerate_dependency_obligations(
    project_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    if not root.is_dir():
        raise ValueError("project_root must be an existing directory")
    files = _production_files(root, _SOURCE_SUFFIXES)
    by_suffix: dict[str, list[Path]] = {}
    for path in files:
        by_suffix.setdefault(path.suffix.casefold(), []).append(path)
    rows: list[dict[str, str]] = []
    rows.extend(_solidity_rows(root, by_suffix.get(".sol", [])))
    rows.extend(_cargo_rows(root, by_suffix.get(".rs", [])))
    rows.extend(_go_rows(root, by_suffix.get(".go", [])))
    if by_suffix.get(".move") or str(config.get("language", "")).lower() in {"aptos", "sui"}:
        rows.extend(_move_rows(root))
    if by_suffix.get(".daml"):
        rows.extend(_daml_rows(root))
    deduped = {
        row["obligation_id"]: row
        for row in rows
    }
    ordered = [deduped[key] for key in sorted(deduped)]
    retained = ordered[:MAX_OBLIGATIONS]
    return {
        "schema": SCHEMA,
        "provider": "deterministic-direct-nonlocal-referenced-v1",
        "obligations": retained,
        "observed_count": len(ordered),
        "retained_count": len(retained),
        "truncated": len(ordered) > len(retained),
        "overflow_ids": [row["obligation_id"] for row in ordered[MAX_OBLIGATIONS:]],
    }


def write_dependency_obligations(
    scratchpad: Path, project_root: Path, config: dict[str, Any]
) -> dict[str, Any]:
    result = enumerate_dependency_obligations(project_root, config)
    path = Path(scratchpad) / "external_dependency_obligations.json"
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


_LEDGER_COLUMNS = (
    "Obligation ID",
    "Dependency",
    "Integration Surface",
    "Assumed Behavior",
    "Real Behavior",
    "Source",
    "Conformance",
    "Fetch Status",
)


def _parse_research_rows(text: str) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    header: list[str] | None = None
    for raw in (text or "").splitlines():
        stripped = raw.strip()
        if not stripped.startswith("|"):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if header is None and "Obligation ID" in cells:
            header = cells
            continue
        if header is None or len(cells) != len(header):
            continue
        if all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells):
            continue
        row = dict(zip(header, cells))
        obligation_id = row.get("Obligation ID", "").upper()
        if re.fullmatch(r"DEP-[A-F0-9]{12}", obligation_id):
            rows[obligation_id] = row
    return rows


def reconcile_dependency_research_ledger(
    scratchpad: Path,
    obligations: dict[str, Any],
    *,
    worker_text: str = "",
) -> dict[str, Any]:
    """Write one canonical row per deterministic obligation, even on failure."""
    scratchpad = Path(scratchpad)
    worker_rows = _parse_research_rows(worker_text)
    lines = [
        "# External Dependency Research Ledger",
        "",
        "> Deterministic obligation parity: every enumerated dependency has a row. "
        "`NEEDS_DEPENDENCY_RESEARCH` and `FETCH_FAILED` are unresolved evidence, "
        "never permission to assume favorable external behavior.",
        "",
        "| " + " | ".join(_LEDGER_COLUMNS) + " |",
        "|" + "|".join("---" for _ in _LEDGER_COLUMNS) + "|",
    ]
    researched = 0
    unresolved = 0
    expected_ids: list[str] = []
    for obligation in obligations.get("obligations", []):
        oid = str(obligation["obligation_id"]).upper()
        expected_ids.append(oid)
        worker = worker_rows.get(oid, {})
        real = worker.get("Real Behavior", "").strip()
        source = worker.get("Source", "").strip()
        raw_status = worker.get("Fetch Status", "").strip().upper()
        source_grounded = bool(source and source != "-" and re.search(r"https?://|[A-Za-z0-9_./-]+:L\d+", source))
        if raw_status == "FETCH_FAILED":
            status = "FETCH_FAILED"
        elif real and real not in {"-", "UNRESOLVED", "UNKNOWN"} and source_grounded:
            status = "RESEARCHED"
        else:
            status = "NEEDS_DEPENDENCY_RESEARCH"
        if status == "RESEARCHED":
            researched += 1
        else:
            unresolved += 1
        values = (
            oid,
            str(obligation["dependency"]),
            worker.get("Integration Surface", "").strip()
            or str(obligation["source_location"]),
            worker.get("Assumed Behavior", "").strip()
            or str(obligation["research_question"]),
            real or "UNRESOLVED",
            source or "-",
            worker.get("Conformance", "").strip() or "UNKNOWN",
            status,
        )
        lines.append("| " + " | ".join(value.replace("|", "\\|") for value in values) + " |")
    if not expected_ids:
        lines.extend(["", "No external dependency obligations were mechanically enumerated."])
    lines.append("")
    ledger = scratchpad / "external_dependency_research.md"
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    overflow = bool(obligations.get("truncated"))
    limitation = scratchpad / "report_semantic_dependency_research.md"
    if unresolved or overflow:
        limitation.write_text(
            "# External Dependency Research Coverage\n\n"
            f"Status: UNKNOWN — {unresolved} unresolved of {len(expected_ids)} "
            "retained obligation(s).\n"
            + (
                f"Enumeration overflow: observed {obligations.get('observed_count')} "
                f"but retained {obligations.get('retained_count')}; human review required.\n"
                if overflow else ""
            ),
            encoding="utf-8",
        )
    else:
        limitation.unlink(missing_ok=True)
    return {
        "expected_ids": expected_ids,
        "researched": researched,
        "unresolved": unresolved,
        "truncated": overflow,
    }


def validate_dependency_ledger_parity(
    obligations: dict[str, Any], ledger_text: str
) -> tuple[bool, list[str]]:
    expected = {
        str(row["obligation_id"]).upper()
        for row in obligations.get("obligations", [])
    }
    actual = set(_parse_research_rows(ledger_text))
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    issues = []
    if missing:
        issues.append("missing obligation rows: " + ", ".join(missing))
    if extra:
        issues.append("unexpected obligation rows: " + ", ".join(extra))
    return not issues, issues
