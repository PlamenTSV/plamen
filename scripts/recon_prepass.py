#!/usr/bin/env python3
"""Plamen v2 Recon Pre-Pass — mechanical artifact writer.

Writes filesystem-walk artifacts (inventory, state vars, function list,
build status, L1 subsystem map) plus stubs for LLM-dependent artifacts
BEFORE the LLM recon phase runs. Stdlib only. Self-contained.

Export: run_recon_prepass(config: dict) -> dict[str, str]
Status: WRITTEN | STUB | FAILED | SKIPPED
"""

from __future__ import annotations

import logging
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import tempfile
import tomllib
from contextlib import contextmanager
from subprocess import TimeoutExpired
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

try:
    # Canonical checkout root, backend-agnostic (PLAMEN_HOME env -> script-relative).
    # Using this instead of a hardcoded ~/.claude makes recon work for Codex-only
    # installs (no ~/.claude) instead of silently failing the SCIP/skill-index reads.
    from plamen_types import plamen_home as _plamen_home
except Exception:  # pragma: no cover - standalone/fallback
    def _plamen_home() -> Path:
        return Path(os.path.expanduser("~/.claude"))

# ITEM H2: fail-closed supply-chain gate. Sibling module, stdlib only — see
# supply_chain_gate.py. Deliberately no try/except fallback: unlike
# plamen_home (which has a documented legacy default), there is no safe
# "pretend the gate passed" fallback for a missing security module. The
# module import (not just the two names) is kept too so tests can reach
# `supply_chain_gate.DEFAULT_IOC_DENYLIST` / `_call_offline_scanner` through
# this module's namespace for monkeypatching.
import supply_chain_gate
import audit_snapshot as _audit_snapshot_authority
import rooted_path_io as _rooted_io
from supply_chain_gate import SupplyChainAbortError, gate_supply_chain
from production_source_scope import (
    PRODUCTION_SOURCE_SKIP_NAME_RE,
    PRODUCTION_SOURCE_SKIP_PARTS,
    is_production_source_path,
)
from tool_coverage_ledger import (
    PRECISE_GRAPH_ARTIFACTS,
    ToolOutcome,
    ToolOutcomeState,
    ToolCoverageLedgerError,
    bind_succeeded_tool_outcome,
    build_context_bound_tool_outcome_envelope,
    build_tool_execution_context,
    load_toolchain_governance,
    record_tool_outcome,
)
from owned_process_runner import (
    OwnedProcessRunnerError,
    run_owned_process as _run_owned_process_direct,
    run_owned_process_isolated as _run_owned_process_isolated,
)
# The disposable host is currently Windows-only.  On Windows it keeps the
# low-integrity lease and provider Job out of the long-lived audit driver, so a
# containment quarantine dies with the executor.  Other supported platforms
# retain the native direct runner until they have an equally strong host.
run_owned_process = (
    _run_owned_process_isolated
    if os.name == "nt"
    else _run_owned_process_direct
)
from audit_snapshot import (
    build_production_source_path_authority as _build_source_path_authority,
    capture_command_provider_authority as _capture_command_provider_authority,
    capture_python_provider_authority as _capture_python_provider_authority,
    provider_authority_replays as _provider_authority_replays,
)
from artifact_ledger import (
    ArtifactLedgerError,
    ArtifactLedgerCASMismatch,
    artifact_ledger_digest,
    compare_and_swap_artifact_ledger,
    read_artifact_ledger,
    record_work_unit_artifacts,
    record_work_unit_inputs,
    validate_work_unit_artifacts,
    validate_work_unit_inputs,
    write_artifact_ledger,
)
from phase_io_contracts import LaunchSpec, resolve_phase_io_contract

# Module logger. `_scip_to_graph_artifacts` emits a log.warning on the
# large-index (>callee-node-cap) PARTIAL path; without this module-level logger
# that call raised `NameError: name 'log' is not defined` on big repos
# (cosmos-sdk), which surfaced as the SCIP bake FAILED and fell back to grep.
log = logging.getLogger("plamen.recon_prepass")

# Filesystem helpers
SKIP_DIR_NAMES = {
    "node_modules", ".git", "target", "build", "out", "artifacts", "cache",
    "dist", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode",
    "forge-cache", ".foundry", ".anchor", ".aptos", ".sui",
}


def _prune_walk_dirs(
    walk_root: Path,
    dirpath: str | Path,
    dirnames: List[str],
    *,
    skip_dir_names=SKIP_DIR_NAMES,
    dependency_roots: Iterable[Path] = (),
) -> List[str]:
    frozen_dependency_roots = {
        Path(path).resolve() for path in dependency_roots
    }
    return [
        name
        for name in dirnames
        if name not in skip_dir_names
        and not name.startswith(".")
        and (Path(dirpath) / name).resolve() not in frozen_dependency_roots
    ]

# Dirs that never hold source a WHOLE-PROJECT compiler will build (build
# output / VCS / tooling caches). Deliberately does NOT skip dependency dirs
# (`lib/`, `node_modules/`): a whole-project `forge build` / `hardhat compile`
# compiles imported library sources, so they MUST be counted when sizing a
# build-timeout ceiling. Sizing off `_production_source_files` (which skips
# the configured Foundry dependency roots) can undercount the compiler's real
# load by roughly 10x on
# dependency-heavy repos and caused cold-cache builds to time out (a 652s
# budget sized from 13 in-scope files for a real 188-file compile). Over-
# counting is safe: the hardened runner returns as soon as the build finishes,
# so the scaled value is only a CEILING, never a fixed wait.
COMPILE_UNIT_SKIP_DIR_NAMES = {
    ".git", "out", "artifacts", "cache", "forge-cache", "target", "build",
    "dist", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode",
    ".foundry", ".anchor", ".aptos", ".sui",
}

def _read_toml(path: Path) -> dict:
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _read_toml_strict(path: Path, label: str) -> dict:
    """Read a build-authority TOML file without hiding parse failures."""
    try:
        with path.open("rb") as stream:
            value = tomllib.load(stream)
    except Exception as exc:
        raise BuildContextResolutionError(
            f"{label} is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise BuildContextResolutionError(f"{label} is unreadable: root is not a table")
    return value


def _nearest_upward_file(start: Path, name: str, max_ancestors: int = 12) -> Optional[Path]:
    cur = start.resolve()
    for _ in range(max_ancestors + 1):
        candidate = cur / name
        if candidate.is_file():
            return candidate
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return None


def _foundry_dependency_roots(scope: Path) -> Tuple[Path, ...]:
    """Return configured Foundry library roots, relative to the manifest owner.

    A directory named ``lib`` only denotes dependencies when the effective
    Foundry configuration says so.  This keeps ``repo/contracts/lib`` in scope
    when ``repo/foundry.toml`` owns ``repo/lib``, and it respects projects that
    deliberately configure a different ``libs`` directory.
    """
    manifest = _nearest_upward_file(scope, "foundry.toml")
    if manifest is None:
        # Bare-source EVM scopes are scaffolded with Foundry's conventional
        # `libs = ["lib"]` before binding.  Mirror that deterministic future
        # configuration during pre-scaffold enumeration.
        return ((scope.resolve() / "lib").resolve(),)
    data = _read_toml(manifest)
    configured: list[str] = []
    profile = data.get("profile")
    if isinstance(profile, dict):
        # Any selectable profile may be used by recon/verification.  Binding
        # the union is conservative; excluding only one profile's libs is not.
        for value in profile.values():
            if not isinstance(value, dict):
                continue
            libs = value.get("libs")
            if isinstance(libs, str):
                configured.append(libs)
            elif isinstance(libs, list):
                configured.extend(str(item) for item in libs if isinstance(item, str))
    top_level = data.get("libs")
    if isinstance(top_level, str):
        configured.append(top_level)
    elif isinstance(top_level, list):
        configured.extend(str(item) for item in top_level if isinstance(item, str))
    if not configured:
        configured = ["lib"]
    roots = []
    for value in configured:
        candidate = (manifest.parent / value).resolve()
        roots.append(candidate)
    return tuple(sorted(set(roots), key=lambda path: str(path).casefold()))


def _iter_files(
    root: Path,
    suffixes: Tuple[str, ...],
    *,
    dependency_roots: Iterable[Path] = (),
) -> List[Path]:
    out: List[Path] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = _prune_walk_dirs(
            root, dirpath, dirnames, dependency_roots=dependency_roots
        )
        for name in filenames:
            if name.endswith(suffixes):
                out.append(Path(dirpath) / name)
    return out

def _is_production_source_path(path: Path, root: Path) -> bool:
    """Compatibility alias for the canonical production-source predicate."""
    return is_production_source_path(path, root)

def _production_source_files(root: Path, suffixes: Tuple[str, ...]) -> List[Path]:
    dependency_roots: Tuple[Path, ...] = ()
    if any(suffix.lower() in {".sol", ".vy"} for suffix in suffixes):
        dependency_roots = _foundry_dependency_roots(root)
    return [
        p for p in _iter_files(root, suffixes, dependency_roots=dependency_roots)
        if _is_production_source_path(p, root)
    ]

def _compile_unit_files(root: Path, suffixes: Tuple[str, ...]) -> List[Path]:
    """Source files a WHOLE-PROJECT compiler actually builds under `root`,
    INCLUDING dependency dirs (`lib/`, `node_modules/`) that `forge build` /
    `hardhat compile` compile via imports. Only build-output / VCS / tooling-
    cache dirs are skipped (COMPILE_UNIT_SKIP_DIR_NAMES).

    Distinct from `_production_source_files`, which skips `lib/` and every
    test/mock/script dir — correct for "what to audit", but a large undercount
    of "what the compiler builds". Use ONLY to size whole-project build
    timeouts. Never raises; over-counting is safe (the value is a ceiling)."""
    out: List[Path] = []
    try:
        root = root.resolve()
    except Exception:
        return out
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in COMPILE_UNIT_SKIP_DIR_NAMES and not d.startswith(".")
        ]
        for name in filenames:
            if name.endswith(suffixes):
                out.append(Path(dirpath) / name)
    return out

def _lines_and_bytes(p: Path) -> Tuple[int, int]:
    try:
        data = p.read_bytes()
        ln = data.count(b"\n") + (0 if data.endswith(b"\n") else 1 if data else 0)
        return (ln, len(data))
    except Exception:
        return (0, 0)

def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.relative_to(root)).replace("\\", "/")
    except Exception:
        return str(p).replace("\\", "/")

def _read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return ""

def _line_of(text: str, idx: int) -> int:
    return text.count("\n", 0, idx) + 1

# Provenance marker planted at the top of every pre-pass artifact. If the
# file still starts with this on a re-run, it means no LLM phase has rewritten
# it since — safe to overwrite. If the marker is absent, the file was
# enriched (or hand-edited) and must be preserved.
#
# Why a marker instead of a size heuristic: the prior 1.5x rule had two
# silent failure modes — (1) enriched files only slightly larger than the
# stub got clobbered on resume, (2) stale over-large artifacts from a bad
# prior run were preserved forever. A provenance marker is binary: either
# the file is our untouched mechanical output, or it is not.
_PREPASS_MARKER = "<!-- plamen-prepass v1: mechanical pre-pass output; safe to overwrite while marker is present -->"


def _write_text(p: Path, content: str) -> bool:
    """Write `content` to `p`, but preserve LLM-enriched content on resume.

    Overwrite rule (marker-based):
      - File does not exist → write.
      - File exists AND first line matches `_PREPASS_MARKER` → our own
        untouched output, overwrite with fresh content (keeps pre-pass
        idempotent across re-runs).
      - File exists AND first line does NOT match the marker → an LLM
        phase (or the user) has rewritten this file. Preserve it verbatim,
        even if the incoming pre-pass content is larger.

    The marker is prepended to every pre-pass write, so re-runs can
    recognize their own prior output without relying on file size.
    """
    try:
        stamped = _PREPASS_MARKER + "\n" + content
        if p.exists():
            try:
                head = p.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0]
            except Exception:
                head = ""
            if head != _PREPASS_MARKER:
                # File was enriched (or hand-edited) since our last write.
                # Do not clobber.
                return True
        p.write_text(stamped, encoding="utf-8")
        return True
    except Exception:
        return False

# Regex patterns
_EVM_STATE_RE = re.compile(
    r"^\s*(mapping\s*\([^)]+\)(?:\s*\[\s*\])?|uint\d*|int\d*|address(?:\s+payable)?|bytes\d*|bool|string)"
    r"\s+(?:public|private|internal)?\s*(?:immutable|constant)?\s*(\w+)\s*[;=]",
    re.MULTILINE,
)
_EVM_FN_RE = re.compile(
    r"^\s*function\s+(\w+)\s*\([^)]*\)\s*((?:\w+\s+)*)",
    re.MULTILINE,
)
_RUST_STRUCT_RE = re.compile(
    r"#\[\s*account\s*(?:\([^)]*\))?\s*\]\s*(?:pub\s+)?struct\s+\w+\s*\{([^}]*)\}",
    re.DOTALL,
)
_RUST_FIELD_RE = re.compile(r"^\s*(?:pub\s+)?(\w+)\s*:\s*([^,\n]+),?\s*$", re.MULTILINE)
_RUST_FN_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+fn\s+(\w+)", re.MULTILINE)
_MOVE_STRUCT_RE = re.compile(
    r"struct\s+(\w+)[^\{]*has\s+[\w\s,]*\b(?:key|store)\b[^\{]*\{([^}]*)\}",
    re.DOTALL,
)
_MOVE_FIELD_RE = re.compile(r"^\s*(\w+)\s*:\s*([^,\n]+),?\s*$", re.MULTILINE)
_MOVE_FN_RE = re.compile(r"^\s*(?:public(?:\([^)]*\))?\s+|entry\s+)+fun\s+(\w+)", re.MULTILINE)

_CONTRACT_MARKERS = ("#[program]", "#[contract]", "#[contractimpl]", "contractimpl!")


# Language dispatch — per-lang regex adapters; see LANG_DISPATCH below.

def _evm_state_rows(text, f, proj):
    return [
        f"| `{_rel(f, proj)}` | `{m.group(2)}` | `{m.group(1).strip()}` | {_line_of(text, m.start())} |"
        for m in _EVM_STATE_RE.finditer(text)
    ]

def _evm_fn_rows(text, f, proj):
    out = []
    for m in _EVM_FN_RE.finditer(text):
        mods = (m.group(2) or "").strip()
        vis = next((v for v in ("public", "private", "internal", "external")
                    if re.search(rf"\b{v}\b", mods)), "external")
        out.append(f"| `{_rel(f, proj)}` | `{m.group(1)}` | {vis} | {_line_of(text, m.start())} |")
    return out

def _struct_field_rows(text, f, proj, struct_re, field_re, body_group):
    out = []
    for sm in struct_re.finditer(text):
        base = _line_of(text, sm.start())
        body = sm.group(body_group)
        for fm in field_re.finditer(body):
            rel_line = base + body.count("\n", 0, fm.start())
            out.append(f"| `{_rel(f, proj)}` | `{fm.group(1)}` | `{fm.group(2).strip()}` | {rel_line} |")
    return out

def _rust_state_rows(text, f, proj):
    return _struct_field_rows(text, f, proj, _RUST_STRUCT_RE, _RUST_FIELD_RE, 1)

def _move_state_rows(text, f, proj):
    return _struct_field_rows(text, f, proj, _MOVE_STRUCT_RE, _MOVE_FIELD_RE, 2)

def _simple_fn_rows(text, f, proj, fn_re, vis_label):
    return [
        f"| `{_rel(f, proj)}` | `{m.group(1)}` | {vis_label} | {_line_of(text, m.start())} |"
        for m in fn_re.finditer(text)
    ]

def _rust_fn_rows(text, f, proj):
    return _simple_fn_rows(text, f, proj, _RUST_FN_RE, "pub")

def _move_fn_rows(text, f, proj):
    return _simple_fn_rows(text, f, proj, _MOVE_FN_RE, "public")


LANG_DISPATCH: Dict[str, dict] = {
    "evm":     {"suffix": (".sol",),  "marker": False,
                "state": _evm_state_rows,  "fn": _evm_fn_rows},
    "solana":  {"suffix": (".rs",),   "marker": True,
                "state": _rust_state_rows, "fn": _rust_fn_rows},
    "soroban": {"suffix": (".rs",),   "marker": True,
                "state": _rust_state_rows, "fn": _rust_fn_rows},
    "aptos":   {"suffix": (".move",), "marker": False,
                "state": _move_state_rows, "fn": _move_fn_rows},
    "sui":     {"suffix": (".move",), "marker": False,
                "state": _move_state_rows, "fn": _move_fn_rows},
}

def _gather_files(proj: Path, lang: str) -> List[Path]:
    cfg = LANG_DISPATCH.get(lang)
    if not cfg:
        return []
    # Discovery inventory = the AUDIT SURFACE (production contracts). Use the
    # production filter, NOT a bare `_iter_files`: the latter skips only
    # SKIP_DIR_NAMES + dot-dirs, so it still ingests `test/`, `mock/`, `fuzz/`,
    # `script/` contracts. Those are not audit targets, and — critically — a
    # project's own test/fuzz harnesses (invariant assertions, buggy/fixed
    # reproductions) encode the answers and PRIME discovery. This flows into
    # contract_inventory / function_list / state_variables and, via
    # _materialize_sc_slither_flat_files, into slither/*.md. `.medusa-tests`
    # (a dot-dir) was already skipped; this adds the non-dot harness dirs.
    files = _production_source_files(proj, cfg["suffix"])
    if cfg["marker"]:
        files = [f for f in files if any(m in _read_text(f) for m in _CONTRACT_MARKERS)]
    return files

# SC artifact writers
def _write_contract_inventory_sc(scratch: Path, proj: Path, lang: str) -> str:
    try:
        files = _gather_files(proj, lang)
        lines = ["# Contract Inventory", "",
                 f"Pre-pass: {len(files)} file(s) discovered by filesystem walk.", "",
                 "| File | Path | Lines | Bytes |",
                 "|------|------|-------|-------|"]
        for f in sorted(files, key=lambda p: _rel(p, proj)):
            ln, bt = _lines_and_bytes(f)
            lines.append(f"| {f.name} | `{_rel(f, proj)}` | {ln} | {bt} |")
        if not files:
            lines.append("| _(no source files found)_ | - | - | - |")
        _write_text(scratch / "contract_inventory.md", "\n".join(lines) + "\n")
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / "contract_inventory.md",
                    f"# Contract Inventory\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

# M2 (recall): interface-vs-implementation parity. A contract that `is IFoo` but
# whose external/public function is NOT declared in `IFoo` is an interface-
# completeness gap (e.g. a public `doThing()` on a contract that `is IFoo`
# while `IFoo` never declares `doThing`).
# Inheritance-gated (only flag when the contract explicitly inherits the
# interface) to keep false positives near zero. Mechanical Solidity parse.
_SOL_CONTRACT_IS_RE = re.compile(
    r"\bcontract\s+([A-Za-z_]\w*)\s+is\s+([^{]+)\{", re.MULTILINE)
_SOL_INTERFACE_RE = re.compile(r"\binterface\s+([A-Za-z_]\w*)", re.MULTILINE)
_SOL_NONIFACE_FNS = {"constructor", "receive", "fallback"}

# Standard / inherited external functions that protocol interfaces conventionally
# do NOT declare (they come from OZ / ERC standards / proxy bases / DEX callbacks,
# not the contract's own custom surface). Generic names only — no protocol
# specifics. Filtering these keeps the signal (a genuine custom omission like
# `doThing`) while dropping standard-callback noise.
_STD_EXTERNAL_FN_DENYLIST = {
    "onerc721received", "onerc1155received", "onerc1155batchreceived",
    "onerc777received", "tokensreceived", "ontokensreceived", "onflashloan",
    "supportsinterface",
    "initialize", "upgradeto", "upgradetoandcall", "proxiableuuid", "implementation",
    "owner", "renounceownership", "transferownership", "pendingowner", "acceptownership",
    "hasrole", "grantrole", "revokerole", "renouncerole", "getroleadmin",
    "paused",
    "unlockcallback", "uniswapv3swapcallback", "uniswapv3mintcallback",
    "uniswapv3flashcallback", "beforeswap", "afterswap", "multicall",
}


def _sol_ext_pub_fns(text: str) -> dict:
    """external/public function name -> line, excluding constructor/receive/fallback."""
    out: dict = {}
    for m in _EVM_FN_RE.finditer(text):
        name = m.group(1)
        if name in _SOL_NONIFACE_FNS or name in out:
            continue
        mods = m.group(2) or ""
        vis = next((v for v in ("external", "public", "internal", "private")
                    if re.search(rf"\b{v}\b", mods)), "public")
        if vis in ("external", "public"):
            out[name] = _line_of(text, m.start())
    return out


def _sol_declared_fns(text: str) -> set:
    return {m.group(1) for m in _EVM_FN_RE.finditer(text)
            if m.group(1) not in _SOL_NONIFACE_FNS}


def compute_interface_parity_findings(project_root) -> List[dict]:
    """Mechanically find external/public functions declared in a contract that
    `is IFoo` but missing from `IFoo`. Conservative (inheritance-gated, per-file
    function attribution). Returns Informational finding dicts. Never raises."""
    root = Path(project_root)
    try:
        files = _production_source_files(root, (".sol",))
    except Exception:
        return []
    iface_fns: dict = {}                 # interface name -> declared fn set
    contracts: dict = {}                 # contract name -> (file, {fn:line}, parents)
    for f in files:
        text = _read_text(f)
        if not text:
            continue
        for m in _SOL_INTERFACE_RE.finditer(text):
            iface_fns.setdefault(m.group(1), set()).update(_sol_declared_fns(text))
        for m in _SOL_CONTRACT_IS_RE.finditer(text):
            cname = m.group(1)
            parents = set(re.findall(r"\b([A-Za-z_]\w*)\b", m.group(2)))
            if cname not in contracts:
                contracts[cname] = (f, _sol_ext_pub_fns(text), parents)
    findings: List[dict] = []
    n = 0
    for cname, (cfile, cfns, parents) in sorted(contracts.items()):
        inherited_ifaces = [p for p in parents if p in iface_fns]
        if not inherited_ifaces:
            continue
        declared: set = set()
        for iy in inherited_ifaces:
            declared |= iface_fns[iy]
        for fn, line in sorted(cfns.items(), key=lambda kv: kv[1]):
            if fn in declared or fn.lower() in _STD_EXTERNAL_FN_DENYLIST:
                continue
            n += 1
            iy = inherited_ifaces[0]
            findings.append({
                "id": f"IFACE-{n}",
                "title": f"Interface `{', '.join(inherited_ifaces)}` omits external `{cname}.{fn}`",
                "location": f"{_rel(cfile, root)}:L{line}",
                "severity": "Informational",
                "description": (
                    f"`{cname}` inherits `{', '.join(inherited_ifaces)}` and exposes an "
                    f"external/public `{fn}`, but `{fn}` is not declared in the interface "
                    "— interface/implementation drift. Integrators holding the interface "
                    "type cannot reference the function, and ABI/spec consumers see an "
                    "incomplete surface."),
                "impact": (
                    "Interface consumers cannot call the function via the interface type; "
                    "spec/ABI completeness gap (no direct fund risk)."),
            })
    return findings


def _write_interface_parity_findings(scratch: Path, proj: Path) -> str:
    """Write interface-parity findings to niche_interface_parity_findings.md so the
    existing post-depth niche-promotion path ingests them. Recall-safe / additive."""
    try:
        findings = compute_interface_parity_findings(proj)
    except Exception as e:
        _write_text(scratch / "niche_interface_parity_findings.md",
                    f"# Interface Parity\n\n_skipped: {e}_\n")
        return "SKIP"
    if not findings:
        _write_text(scratch / "niche_interface_parity_findings.md",
                    "# Interface Parity Findings\n\n_None — every inherited interface "
                    "declares its implementation's external surface._\n")
        return "NONE"
    lines = ["# Interface Parity Findings", "",
             "Mechanical interface-vs-implementation completeness check "
             "(inheritance-gated). Promoted via the niche path.", ""]
    for fd in findings:
        lines += [
            f"### Finding [{fd['id']}]: {fd['title']}",
            f"**Severity**: {fd['severity']}",
            f"**Location**: {fd['location']}",
            "**Preferred Tag**: [CODE-TRACE]",
            f"**Description**: {fd['description']}",
            f"**Impact**: {fd['impact']}",
            "",
        ]
    _write_text(scratch / "niche_interface_parity_findings.md", "\n".join(lines) + "\n")
    return "WRITTEN"


# M2 (recall): permissionless-setter detector. External/public functions that
# write contract state but declare no access gate (modifier or body guard) are
# a candidate missing-access-control finding. Mechanical Solidity parse — no
# SCIP dependency, testable in isolation. Favors precision: any recognizable
# access gate (modifier or `require(msg.sender == ...)`-style body guard)
# excludes the function, since an admin-setter false-positive flood is the
# failure mode to avoid for an additive niche detector.
_SOL_ACCESS_MODIFIER_RE = re.compile(
    r"\b(onlyOwner|onlyRole|onlyAdmin|onlyGovernance|auth|restricted)\b"
)
# Body guard checked only near the top of the function body ("first
# statements") — a late-body check does not gate the state write above it.
_SOL_BODY_GUARD_RE = re.compile(
    r"require\s*\(\s*msg\.sender\s*==|_checkOwner\s*\(|_checkRole\s*\(|"
    r"hasRole\s*\(|if\s*\(\s*msg\.sender\s*!=[^)]*\)\s*revert|_onlyOwner\s*\(",
    re.DOTALL,
)
_SOL_INITIALIZER_NAME_RE = re.compile(
    r"(?i)^(re)?initiali[sz]e(_unchained)?$|^__\w*_init(_unchained)?$|^init$"
)
_SOL_CONTRACT_DECL_RE = re.compile(r"\b(?:contract|library)\s+([A-Za-z_]\w*)")


def _sol_find_body(text: str, pos: int) -> Tuple[Optional[int], Optional[int]]:
    """From `pos` (end of a function's name+params match), scan forward at
    paren-depth 0 for the function body's opening `{`, skipping over any
    top-level parens (e.g. modifier args, `returns (...)`). Returns
    (body_start, body_end) char offsets of the `{...}` block (body_end is
    exclusive, just past the matching `}`), or (None, None) if the
    declaration ends in `;` first (abstract/interface/virtual — no body).
    Comment/string-agnostic heuristic, matching this module's regex-based
    style; never raises."""
    depth = 0
    i, n = pos, len(text)
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth = max(0, depth - 1)
        elif depth == 0 and c == "{":
            bdepth, j = 1, i + 1
            while j < n and bdepth > 0:
                if text[j] == "{":
                    bdepth += 1
                elif text[j] == "}":
                    bdepth -= 1
                j += 1
            return i, j
        elif depth == 0 and c == ";":
            return None, None
        i += 1
    return None, None


def _sol_fn_spans(text: str) -> List[Tuple[int, int]]:
    """All function body [start, end) char spans in `text`, any visibility."""
    spans: List[Tuple[int, int]] = []
    for m in _EVM_FN_RE.finditer(text):
        b0, b1 = _sol_find_body(text, m.end())
        if b0 is not None:
            spans.append((b0, b1))
    return spans


def _sol_state_var_names(text: str) -> set:
    """Contract-level state variable names — `_EVM_STATE_RE` matches restricted
    to positions OUTSIDE any function body span, so function-local
    declarations that happen to match the same line-start shape are not
    mistaken for contract state."""
    spans = _sol_fn_spans(text)

    def _in_fn(idx: int) -> bool:
        return any(s <= idx < e for s, e in spans)

    return {m.group(2) for m in _EVM_STATE_RE.finditer(text) if not _in_fn(m.start())}


def _sol_body_writes_state(body: str, state_vars: set) -> bool:
    """True if `body` contains a plain/compound assignment or increment to
    any name in `state_vars` (bare `x = `, indexed `x[..] = `, `+=`/`-=`/etc.,
    `++`/`--`). Comparison operators (`==`, `!=`, `<=`, `>=`) never match."""
    if not state_vars:
        return False
    names = "|".join(re.escape(v) for v in sorted(state_vars, key=len, reverse=True))
    pat = re.compile(
        rf"(?<![.\w])(?:{names})\s*(?:\[[^\]]*\])?\s*(?:\+\+|--|[-+*/%&|^]?=(?!=))"
    )
    return bool(pat.search(body))


def compute_permissionless_setter_findings(project_root) -> List[dict]:
    """Mechanically find external/public functions that write contract state
    with no recognizable access gate (modifier or body guard). Conservative —
    excludes view/pure, constructor, initializers, and anything with a
    plausible gate; favors precision over recall. Returns Low-severity
    finding dicts. Never raises."""
    root = Path(project_root)
    try:
        files = _production_source_files(root, (".sol",))
    except Exception:
        return []
    findings: List[dict] = []
    n = 0
    for f in sorted(files):
        text = _read_text(f)
        if not text:
            continue
        try:
            ext_pub = _sol_ext_pub_fns(text)
            if not ext_pub:
                continue
            state_vars = _sol_state_var_names(text)
            if not state_vars:
                continue
            for m in _EVM_FN_RE.finditer(text):
                name = m.group(1)
                if name not in ext_pub:
                    continue
                line = _line_of(text, m.start())
                if line != ext_pub[name]:
                    continue  # not the occurrence _sol_ext_pub_fns attributed
                if _SOL_INITIALIZER_NAME_RE.match(name):
                    continue
                body_start, body_end = _sol_find_body(text, m.end())
                if body_start is None:
                    continue  # abstract/interface declaration, no body
                header = text[m.start():body_start]
                if re.search(r"\b(view|pure)\b", header):
                    continue
                if _SOL_ACCESS_MODIFIER_RE.search(header):
                    continue
                body = text[body_start:body_end]
                if _SOL_BODY_GUARD_RE.search(body[:400]):
                    continue
                if not _sol_body_writes_state(body, state_vars):
                    continue
                n += 1
                cname = "?"
                for cm in _SOL_CONTRACT_DECL_RE.finditer(text):
                    if cm.start() > m.start():
                        break
                    cname = cm.group(1)
                findings.append({
                    "id": f"PSET-{n}",
                    "title": f"`{cname}.{name}` writes state with no access gate",
                    "location": f"{_rel(f, root)}:L{line}",
                    "severity": "Low",
                    "description": (
                        f"`{cname}.{name}` is external/public and writes to "
                        "contract state, but declares neither a role-gating "
                        "modifier (onlyOwner/onlyRole/onlyAdmin/onlyGovernance/"
                        "auth/restricted) nor an equivalent body guard "
                        "(require(msg.sender == ...), _checkOwner(), "
                        "_checkRole(...), hasRole(...)). Mechanical scan only — "
                        "candidate missing access control; verify intended "
                        "permissionlessness before treating as a real finding."),
                    "impact": (
                        "If access control is genuinely missing, any caller can "
                        "mutate contract state via this function; if the "
                        "function is intentionally permissionless, this is a "
                        "false positive requiring no action."),
                })
        except Exception:
            continue
    return findings


def _write_permissionless_setter_findings(scratch: Path, proj: Path) -> str:
    """Write permissionless-setter findings to
    niche_permissionless_setters_findings.md so the existing post-depth
    niche-promotion path ingests them. Recall-safe / additive."""
    try:
        findings = compute_permissionless_setter_findings(proj)
    except Exception as e:
        _write_text(scratch / "niche_permissionless_setters_findings.md",
                    f"# Permissionless Setters\n\n_skipped: {e}_\n")
        return "SKIP"
    if not findings:
        _write_text(scratch / "niche_permissionless_setters_findings.md",
                    "# Permissionless Setter Findings\n\n_None — every "
                    "state-writing external/public function has a "
                    "recognizable access gate._\n")
        return "NONE"
    lines = ["# Permissionless Setter Findings", "",
             "Mechanical scan for external/public state-writing functions with "
             "no recognizable access gate. Promoted via the niche path.", ""]
    for fd in findings:
        lines += [
            f"### Finding [{fd['id']}]: {fd['title']}",
            f"**Severity**: {fd['severity']}",
            f"**Location**: {fd['location']}",
            "**Preferred Tag**: [CODE-TRACE]",
            f"**Description**: {fd['description']}",
            f"**Impact**: {fd['impact']}",
            "",
        ]
    _write_text(scratch / "niche_permissionless_setters_findings.md", "\n".join(lines) + "\n")
    return "WRITTEN"


def _write_table_artifact(scratch: Path, proj: Path, lang: str, kind: str) -> str:
    """kind: 'state' or 'fn' — dispatches to LANG_DISPATCH row function."""
    filename = {"state": "state_variables.md", "fn": "function_list.md"}[kind]
    title = {"state": "State Variables", "fn": "Function List"}[kind]
    header = {"state": "| File | Variable | Type | Line |",
              "fn":    "| File | Function | Visibility | Line |"}[kind]
    sep = {"state": "|------|----------|------|------|",
           "fn":    "|------|----------|------------|------|"}[kind]

    try:
        cfg = LANG_DISPATCH.get(lang)
        if not cfg:
            _write_text(scratch / filename,
                        f"# {title}\n\n[LLM TO ENRICH] Unknown language: {lang}\n")
            return "STUB"
        rows: List[str] = []
        for f in _gather_files(proj, lang):
            text = _read_text(f)
            if not text:
                continue
            rows.extend(cfg[kind](text, f, proj))

        lines = [f"# {title}", "",
                 f"Pre-pass: {len(rows)} {kind}(s) identified via regex scan.",
                 "Regex-based heuristic — LLM recon may add/correct entries.", "",
                 header, sep]
        lines.extend(rows if rows else ["| _(none found)_ | - | - | - |"])
        _write_text(scratch / filename, "\n".join(lines) + "\n")
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / filename, f"# {title}\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

# Build status
BUILD_SPECS = {
    "evm_forge":    {"cmd": ["forge", "build", "--no-auto-detect"],    "timeout": 120},
    "evm_hardhat":  {"cmd": ["npx", "hardhat", "compile"],             "timeout": 120},
    "solana":       {"cmd": ["cargo", "build", "--release"],           "timeout": 300},
    "soroban":      {"cmd": ["cargo", "build", "--release"],           "timeout": 300},
    "aptos":        {"cmd": ["aptos", "move", "compile"],              "timeout": 120},
    "sui":          {"cmd": ["sui", "move", "build"],                  "timeout": 120},
}

# Size-scaled build timeout. The fixed 120s base was too short for large repos
# (e.g. 176 .sol files + optimizer on a cold cache). Because `_run_hardened`
# can no longer deadlock — it always returns by (timeout + grace) and tree-kills
# the whole process group — a generous, file-count-scaled ceiling is harmless:
# a slow build that finishes inside the window succeeds; one that genuinely
# stalls still returns rc=124 so the caller degrades. Generic across ecosystems
# (.sol / .rs / .move / etc. — the caller passes the relevant file count).
_BUILD_TIMEOUT_PER_FILE_S = 4       # per source-file budget added to the base
# Default ceiling for the file-count-scaled build timeout. 30-min (1800s) was too
# low for a COLD `--via-ir` compile of a dependency-heavy repo: a real large dependency-heavy EVM
# run's whole-project build hit the ceiling and degraded to TIMEOUT, which starves
# Slither (approximate source graph) and caps every PoC at [CODE-TRACE] (the verify
# `forge test` can never compile in its own budget against a cold cache). Raised to
# 90-min and made ops-overridable via PLAMEN_BUILD_TIMEOUT_CEILING_S. Harmless per the
# wrapper contract above — a fast build still returns immediately; only a genuinely-
# heavy build spends the extra time, and a truly stuck one still tree-kills at the
# (higher) bound. Generic across every ecosystem sized via _scale_build_timeout.
_BUILD_TIMEOUT_CEILING_S = 5400     # 90-min default ceiling (env: PLAMEN_BUILD_TIMEOUT_CEILING_S)
# Source suffixes per build key, used purely to size the timeout.
_BUILD_TIMEOUT_SUFFIXES = {
    "evm_forge":   (".sol",),
    "evm_hardhat": (".sol",),
    "solana":      (".rs",),
    "soroban":     (".rs",),
    "aptos":       (".move",),
    "sui":         (".move",),
}


# Rust ecosystems whose recon build runs via cargo. Generic by language/build
# key (no project/crate names). Used to scope CARGO_INCREMENTAL=0 + retry-once
# hardening to cargo-driven compiles only (EVM/foundry is excluded).
_RUST_ECOSYSTEM_BUILD_KEYS = frozenset({"solana", "soroban"})


def _is_rust_ecosystem_build(key: Optional[str], cmd: Optional[List[str]]) -> bool:
    """True for a cargo-driven Rust-ecosystem recon build (solana / soroban /
    any cargo-based rust/L1 build). Generic by ecosystem key AND by command
    head so it stays correct if a branch substitutes another cargo subcommand
    (e.g. `cargo build-sbf`). Never raises; returns False for EVM/Move/etc."""
    try:
        if key in _RUST_ECOSYSTEM_BUILD_KEYS:
            return True
        if cmd:
            head = str(cmd[0]).lower()
            # `cargo`, `cargo-build-sbf`, etc. — any cargo front-end.
            if head == "cargo" or head.startswith("cargo-"):
                return True
    except Exception:
        pass
    return False


def _build_timeout_ceiling() -> int:
    """Active build-timeout ceiling: PLAMEN_BUILD_TIMEOUT_CEILING_S when set (ops
    override for very large/slow cold builds), else the module default. Read
    per-call so operators and tests can retune without a module reload. Never
    raises."""
    try:
        return max(1, int(os.environ.get(
            "PLAMEN_BUILD_TIMEOUT_CEILING_S", _BUILD_TIMEOUT_CEILING_S)))
    except Exception:
        return _BUILD_TIMEOUT_CEILING_S


def _scale_build_timeout(base: int, n_files: int) -> int:
    """base + per-file budget, bounded to [base, ceiling]. Never raises."""
    try:
        scaled = int(base) + _BUILD_TIMEOUT_PER_FILE_S * max(0, int(n_files))
    except Exception:
        return int(base)
    return max(int(base), min(_build_timeout_ceiling(), scaled))


def _graph_implies_compiles(graph_status: Optional[str], lang: str) -> bool:
    """True when the mechanical-graph bake already performed a FULL compile of
    the project for this language — making a separate build-status probe a
    redundant second compile. Currently only the EVM Slither bake compiles
    (source=slither); the approximate source-parse / SCIP tiers do NOT, so they
    never suppress the build probe. Generic seam: extend per language as other
    compile-grade bakes are wired."""
    if not isinstance(graph_status, str):
        return False
    if lang == "evm":
        # `_bake_evm_graph` returns "WRITTEN:slither" only when Slither's solc
        # compile of the whole project succeeded. The approximate fallback is
        # "WRITTEN:evm-source (...)" — that did NOT compile, so do not suppress.
        return graph_status.startswith("WRITTEN:slither")
    return False


def _select_build(proj: Path, lang: str) -> Optional[str]:
    if lang == "evm":
        # Use one canonical resolver for snapshot, build, and Slither.  Audit
        # scopes are often a source dir or umbrella above the actual project.
        root = _resolve_evm_build_root(proj)
        if root is not None and (root / "foundry.toml").is_file() and shutil.which("forge"):
            return "evm_forge"
        if root is not None and list(root.glob("hardhat.config.*")) and shutil.which("npx"):
            return "evm_hardhat"
        return None
    if lang in ("solana", "soroban") and shutil.which("cargo"):
        return lang
    if lang == "aptos" and shutil.which("aptos"):
        return "aptos"
    if lang == "sui" and shutil.which("sui"):
        return "sui"
    return None


# STEP 2C: non-EVM build-root resolution. PROJECT_PATH is frequently a scope dir
# like `.../<crate>/src/` that has no build manifest; running `cargo build` /
# `aptos move compile` there fails spuriously. Walk UP from PROJECT_PATH to the
# nearest manifest and build there instead. Returns None when no manifest is
# found within the ancestor bound.
_BUILD_MANIFESTS = {
    "solana": "Cargo.toml",
    "soroban": "Cargo.toml",
    "aptos": "Move.toml",
    "sui": "Move.toml",
}


def _find_build_root_downward(
    proj: Path, manifest_names: Tuple[str, ...], suffixes: Tuple[str, ...],
    max_depth: int = 5,
) -> Optional[Path]:
    """Walk DOWN from PROJECT_PATH to find the real build project in a SUBDIR.

    The mirror of the walk-up case: the audit scope sometimes points at a
    monorepo / umbrella root that has NO build manifest of its own, while the
    actual project lives below it (e.g. `packages/contracts/foundry.toml`,
    `contracts/Move.toml`, `chain/Cargo.toml`). Walk-up returns None there, so
    forge/Slither/cargo would run from the manifest-less root and fail.

    Disambiguation (monorepos can hold several sub-projects): pick the manifest
    directory that ENCLOSES the most in-scope production sources of this
    ecosystem; ties break to the shallowest path. A manifest dir that contains
    no production sources is never selected (it is not the audit target).

    Vendored/build dirs (`lib/`, `node_modules/`, `target/`, …) are pruned via
    SKIP_DIR_NAMES so a DEPENDENCY's manifest is never mistaken for the project.
    Platform-agnostic (os.walk + Path). Bounded depth; never raises."""
    try:
        proj = proj.resolve()
        base_depth = len(proj.parts)
        candidates: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(proj):
            d = Path(dirpath)
            if len(d.parts) - base_depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = _prune_walk_dirs(proj, dirpath, dirnames)
            if any(m in filenames for m in manifest_names):
                candidates.append(d)
        if not candidates:
            return None

        def _score(d: Path) -> Tuple[int, int]:
            try:
                n = len(_production_source_files(d, suffixes)) if suffixes else 0
            except Exception:
                n = 0
            return (n, -len(d.parts))  # most sources, then shallowest

        candidates.sort(key=_score, reverse=True)
        top = candidates[0]
        # Only accept a downward root that actually encloses production sources;
        # otherwise it is not the audit target (e.g. a tooling sub-package).
        if suffixes and not _production_source_files(top, suffixes):
            return None
        return top
    except Exception:
        return None


def _resolve_build_root(proj: Path, lang: str, max_ancestors: int = 4) -> Optional[Path]:
    manifest = _BUILD_MANIFESTS.get(lang)
    if not manifest:
        return None
    cur = proj.resolve()
    for _ in range(max_ancestors + 1):
        try:
            if (cur / manifest).exists():
                return cur
        except Exception:
            pass
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    # Walk-up failed → monorepo / nested crate: search downward.
    suffixes = (LANG_DISPATCH.get(lang) or {}).get("suffix") or ()
    return _find_build_root_downward(proj, (manifest,), suffixes)


def _resolve_evm_build_root(proj: Path, max_ancestors: int = 4) -> Optional[Path]:
    """Resolve the canonical Foundry or Hardhat root for an EVM audit scope.

    Walk UP first: the scope is frequently a SOURCE subdir (e.g.
    `.../smart-contracts/src`) while `foundry.toml` + `remappings.txt` + `lib/`
    live one or more levels up. Running forge/Slither from the scope dir yields
    EMPTY remappings, so every `@import` fails and the build is a false negative.

    If walk-up finds nothing (the scope points at a monorepo / umbrella root
    with no top-level `foundry.toml`), walk DOWN to the sub-project that holds
    the production `.sol` sources. Returns the Foundry root, or None."""
    cur = proj.resolve()
    for _ in range(max_ancestors + 1):
        try:
            if (cur / "foundry.toml").exists() or list(cur.glob("hardhat.config.*")):
                return cur
        except Exception:
            pass
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    # Walk-up failed → monorepo: search downward for the Foundry sub-project.
    return _find_build_root_downward(
        proj,
        (
            "foundry.toml", "hardhat.config.ts", "hardhat.config.js",
            "hardhat.config.cjs", "hardhat.config.mjs",
        ),
        (".sol", ".vy"),
    )


_SNAPSHOT_BUILD_ROOT_SPECS = {
    ("sc", "evm"): (
        (
            "foundry.toml",
            "hardhat.config.ts",
            "hardhat.config.js",
            "hardhat.config.cjs",
            "hardhat.config.mjs",
        ),
        (".sol", ".vy"),
    ),
    ("sc", "solana"): (("Anchor.toml", "Cargo.toml"), (".rs",)),
    ("sc", "soroban"): (("Cargo.toml",), (".rs",)),
    ("sc", "aptos"): (("Move.toml",), (".move",)),
    ("sc", "sui"): (("Move.toml",), (".move",)),
    ("sc", "daml"): (("daml.yaml", "Daml.toml"), (".daml",)),
    ("l1", "go"): (("go.work", "go.mod"), (".go", ".proto")),
    ("l1", "rust"): (("Cargo.toml",), (".rs", ".proto")),
}


class BuildContextResolutionError(RuntimeError):
    """A declared build input cannot be placed inside the frozen closure."""


_MAX_BUILD_CONTEXT_MANIFESTS = 5000


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _select_js_lock_authority(root: Path) -> tuple[Optional[str], Optional[str]]:
    """Resolve one immutable JavaScript installer without guessing.

    Multiple package-manager locks are common in stale repositories.  Their
    dependency graphs need not agree, so filename priority is not an
    authority.  A valid ``packageManager`` field selects the matching lock;
    otherwise exactly one lock family must be present.
    """
    families: List[str] = []
    if (root / "pnpm-lock.yaml").is_file():
        families.append("pnpm")
    if (root / "yarn.lock").is_file():
        families.append("yarn")
    if (
        (root / "package-lock.json").is_file()
        or (root / "npm-shrinkwrap.json").is_file()
    ):
        families.append("npm")

    declared = ""
    try:
        package = json.loads((root / "package.json").read_text(encoding="utf-8"))
        raw = package.get("packageManager") if isinstance(package, dict) else ""
        if isinstance(raw, str):
            declared = raw.split("@", 1)[0].strip().lower()
    except (OSError, UnicodeError, json.JSONDecodeError):
        declared = ""

    if declared:
        if declared not in {"npm", "pnpm", "yarn"}:
            return None, (
                "UNSUPPORTED_JS_PACKAGE_MANAGER: packageManager declares "
                f"{declared!r}; no deterministic installer is configured"
            )
        if declared not in families:
            return None, (
                "JS_PACKAGE_MANAGER_LOCK_MISMATCH: packageManager declares "
                f"{declared!r} but its immutable lock is absent"
            )
        return declared, None
    if len(families) == 1:
        return families[0], None
    if not families:
        return None, (
            "NO_IMMUTABLE_JS_LOCK: package.json is present without an "
            "immutable lock"
        )
    return None, (
        "AMBIGUOUS_JS_LOCKS: multiple package-manager lock families are "
        f"present ({', '.join(families)}) without a packageManager authority"
    )


def _ancestor_dirs(start: Path, max_ancestors: int = 16) -> List[Path]:
    out: List[Path] = []
    cur = start.resolve()
    for _ in range(max_ancestors + 1):
        out.append(cur)
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return out


def _cargo_path_dependencies(data: dict) -> List[str]:
    paths: List[str] = []

    def visit(value, key: str = "", dependency_context: bool = False) -> None:
        if not isinstance(value, dict):
            return
        dependency_context = dependency_context or key in {
            "dependencies", "dev-dependencies", "build-dependencies",
            "patch", "replace",
        }
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            for dependency in value.values():
                if isinstance(dependency, dict) and isinstance(dependency.get("path"), str):
                    paths.append(dependency["path"])
        elif dependency_context and isinstance(value.get("path"), str):
            paths.append(value["path"])
        for child_key, child in value.items():
            if isinstance(child, dict):
                visit(child, str(child_key), dependency_context)

    visit(data)
    return sorted(set(paths))


def _cargo_workspace_root(proj: Path) -> tuple[Optional[Path], Optional[Path]]:
    """Return ``(workspace_root, nearest_package_manifest)`` for *proj*."""
    nearest = _nearest_upward_file(proj, "Cargo.toml")
    if nearest is None:
        return None, None
    nearest_data = _read_toml(nearest)
    package = nearest_data.get("package")
    explicit = package.get("workspace") if isinstance(package, dict) else None
    if isinstance(explicit, str) and explicit.strip():
        root = (nearest.parent / explicit).resolve()
        manifest = root / "Cargo.toml"
        if not manifest.is_file() or not isinstance(_read_toml(manifest).get("workspace"), dict):
            raise BuildContextResolutionError(
                f"Cargo package.workspace does not resolve to a workspace manifest: {explicit}"
            )
        return root, nearest

    # Cargo selects the nearest enclosing workspace.  Looking past the nearest
    # package manifest is essential for `workspace/crates/app` audit scopes.
    for directory in _ancestor_dirs(nearest.parent):
        manifest = directory / "Cargo.toml"
        data = _read_toml(manifest) if manifest.is_file() else {}
        workspace = data.get("workspace")
        if isinstance(workspace, dict):
            try:
                relative = nearest.parent.relative_to(directory).as_posix()
            except ValueError:
                continue
            excluded = False
            for pattern in workspace.get("exclude", []) or []:
                if not isinstance(pattern, str):
                    continue
                normalized = pattern.replace("\\", "/").rstrip("/")
                if relative == normalized or Path(relative).match(normalized):
                    excluded = True
                    break
            if excluded:
                # Cargo's explicit exclude is an authority boundary: the crate
                # builds as an independent package rather than inheriting the
                # ancestor workspace lock/configuration.
                return nearest.parent.resolve(), nearest
            return directory.resolve(), nearest
    return nearest.parent.resolve(), nearest


def _cargo_workspace_path_excluded(
    workspace_root: Path, candidate: Path, patterns: object
) -> bool:
    """Apply Cargo workspace ``exclude`` patterns before following members.

    A wildcard member such as ``crates/*`` may also match an explicitly
    excluded crate.  Following that crate's path dependencies would freeze and
    later analyze inputs Cargo itself does not compile, while an invalid
    excluded manifest could halt startup.  Keep this parser conservative and
    path-relative; ``cargo metadata`` remains the higher-fidelity authority
    when it is available.
    """
    try:
        relative = candidate.resolve().relative_to(workspace_root.resolve()).as_posix()
    except (OSError, ValueError):
        return False
    if not isinstance(patterns, list):
        return False
    relative_path = Path(relative)
    for raw_pattern in patterns:
        if not isinstance(raw_pattern, str) or not raw_pattern.strip():
            continue
        normalized = raw_pattern.replace("\\", "/").strip().rstrip("/")
        if relative == normalized or relative_path.match(normalized):
            return True
    return False


def _cargo_context(
    proj: Path, *, anchor: bool
) -> tuple[Path, List[Path], List[Path], List[str]]:
    anchor_manifest = _nearest_upward_file(proj, "Anchor.toml") if anchor else None
    cargo_root, nearest_manifest = _cargo_workspace_root(proj)
    if anchor_manifest is not None:
        anchor_root = anchor_manifest.parent.resolve()
        # An Anchor root is a build authority even when it has no root
        # Cargo.toml.  If Cargo found a workspace above/at it, that broader
        # manifest owner remains the effective compiler root.
        if cargo_root is None or not _is_within(anchor_root, cargo_root):
            build_root = anchor_root
        else:
            build_root = cargo_root
    elif cargo_root is not None:
        build_root = cargo_root
    else:
        build_root = proj.resolve()

    manifests: set[Path] = set()
    limitations: List[str] = []
    if nearest_manifest is not None:
        manifests.add(nearest_manifest.resolve())
    if (build_root / "Cargo.toml").is_file():
        manifests.add((build_root / "Cargo.toml").resolve())
    root_manifest = build_root / "Cargo.toml"
    if root_manifest.is_file():
        root_data = _read_toml_strict(root_manifest, "Cargo manifest")
        workspace = root_data.get("workspace")
        if isinstance(workspace, dict):
            excluded_patterns = workspace.get("exclude", []) or []
            for raw_member in workspace.get("members", []) or []:
                if not isinstance(raw_member, str) or not raw_member.strip():
                    continue
                matches = sorted(build_root.glob(raw_member))
                if not matches:
                    raise BuildContextResolutionError(
                        f"Cargo workspace member cannot be bound: {raw_member}"
                    )
                for member in matches:
                    member_root = member if member.is_dir() else member.parent
                    if _cargo_workspace_path_excluded(
                        build_root, member_root, excluded_patterns
                    ):
                        continue
                    manifest = member / "Cargo.toml" if member.is_dir() else member
                    if not manifest.is_file():
                        raise BuildContextResolutionError(
                            f"Cargo workspace member lacks Cargo.toml: {raw_member}"
                        )
                    manifests.add(manifest.resolve())

            if (build_root / "Cargo.lock").is_file() and shutil.which("cargo"):
                rc, output = _run_hardened(
                    [
                        "cargo", "metadata", "--locked", "--offline",
                        "--format-version", "1", "--no-deps",
                    ],
                    build_root,
                    30,
                )
                if rc == 0:
                    try:
                        metadata = json.loads(output)
                        for package in metadata.get("packages", []):
                            raw_manifest = package.get("manifest_path")
                            if isinstance(raw_manifest, str):
                                candidate = Path(raw_manifest).resolve()
                                if candidate.is_file():
                                    manifests.add(candidate)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        limitations.append(
                            "CARGO_METADATA_UNUSABLE: locked/offline metadata was "
                            "malformed; workspace membership is approximated"
                        )
                else:
                    limitations.append(
                        "CARGO_METADATA_UNAVAILABLE: locked/offline cargo metadata "
                        "failed; workspace membership is approximated"
                    )
            else:
                limitations.append(
                    "CARGO_METADATA_UNAVAILABLE: no Cargo.lock/cargo authority; "
                    "workspace membership is approximated"
                )

    if anchor_manifest is not None:
        anchor_workspace = _read_toml(anchor_manifest).get("workspace")
        if isinstance(anchor_workspace, dict):
            for raw_member in anchor_workspace.get("members", []) or []:
                if not isinstance(raw_member, str) or not raw_member.strip():
                    continue
                matches = sorted(anchor_manifest.parent.glob(raw_member))
                if not matches:
                    raise BuildContextResolutionError(
                        f"Anchor workspace member cannot be bound: {raw_member}"
                    )
                for member in matches:
                    manifest = member / "Cargo.toml" if member.is_dir() else member
                    if not manifest.is_file():
                        raise BuildContextResolutionError(
                            f"Anchor workspace member lacks Cargo.toml: {raw_member}"
                        )
                    manifests.add(manifest.resolve())

    context_roots: set[Path] = {build_root.resolve()}
    compiled_roots: set[Path] = set()
    for cargo_config in (
        build_root / ".cargo" / "config.toml",
        build_root / ".cargo" / "config",
    ):
        if not cargo_config.is_file():
            continue
        config_data = _read_toml_strict(cargo_config, "Cargo configuration")
        sources = config_data.get("source")
        if not isinstance(sources, dict):
            continue
        for source in sources.values():
            if not isinstance(source, dict) or not isinstance(source.get("directory"), str):
                continue
            source_root = _local_build_path(build_root, source["directory"])
            if not source_root.is_dir():
                raise BuildContextResolutionError(
                    f"Cargo vendored source directory cannot be bound: {source['directory']}"
                )
            context_roots.add(source_root)
            compiled_roots.add(source_root)
    queue = list(sorted(manifests, key=lambda path: str(path).casefold()))
    visited: set[Path] = set()
    while queue:
        manifest = queue.pop(0).resolve()
        if manifest in visited:
            continue
        visited.add(manifest)
        if len(visited) > _MAX_BUILD_CONTEXT_MANIFESTS:
            raise BuildContextResolutionError(
                "Cargo local-dependency closure exceeds the bounded manifest limit"
            )
        data = _read_toml_strict(manifest, "Cargo manifest")
        if not _is_within(manifest.parent, build_root):
            context_roots.add(manifest.parent.resolve())
        for raw_path in _cargo_path_dependencies(data):
            dependency_root = _local_build_path(manifest.parent, raw_path)
            dependency_manifest = dependency_root / "Cargo.toml"
            if not dependency_root.is_dir() or not dependency_manifest.is_file():
                raise BuildContextResolutionError(
                    "local Cargo dependency cannot be bound: "
                    f"{manifest.name} path={raw_path}"
                )
            context_roots.add(dependency_root)
            compiled_roots.add(dependency_root)
            queue.append(dependency_manifest)
    return (
        build_root.resolve(),
        sorted(context_roots, key=lambda path: str(path).casefold()),
        sorted(compiled_roots, key=lambda path: str(path).casefold()),
        limitations,
    )


_GO_LOCAL_PATH_RE = re.compile(
    r"^(?:\.{1,2}[\\/]|[A-Za-z]:[\\/]|/{1,2}|\\\\)"
)


def _local_build_path(base: Path, raw_path: str) -> Path:
    """Resolve manifest-local paths without corrupting Windows separators."""
    value = str(raw_path or "").strip().strip('"').strip("'")
    value = value.replace("\\", os.sep).replace("/", os.sep)
    candidate = Path(value).expanduser()
    return (candidate if candidate.is_absolute() else base / candidate).resolve()


def _go_block_values(text: str, directive: str) -> List[str]:
    values: List[str] = []
    in_block = False
    for raw_line in text.splitlines():
        line = raw_line.split("//", 1)[0].strip()
        if not line:
            continue
        if in_block:
            if line == ")":
                in_block = False
                continue
            # Preserve quoting until the directive-specific parser tokenizes
            # the value.  Stripping only the outer line's trailing quote turns
            # Windows and UNC paths into malformed, unterminated tokens.
            values.append(line.strip())
            continue
        if line == f"{directive} (":
            in_block = True
            continue
        if line.startswith(directive + " "):
            values.append(line[len(directive):].strip())
    return values


def _go_local_replacements(text: str) -> List[str]:
    targets: List[str] = []
    for value in _go_block_values(text, "replace"):
        if "=>" not in value:
            continue
        try:
            tokens = shlex.split(value.split("=>", 1)[1].strip(), posix=False)
        except ValueError:
            tokens = []
        target = (tokens[0] if tokens else "").strip('"').strip("'")
        if _GO_LOCAL_PATH_RE.match(target):
            targets.append(target)
    # A non-block `replace old => ./new` is already returned by
    # `_go_block_values`; keep the parser intentionally syntax-scoped.
    return targets


def _go_context(proj: Path) -> tuple[Path, List[Path], List[Path], List[str]]:
    configured_work = str(os.environ.get("GOWORK") or "").strip()
    if configured_work.lower() == "off":
        go_work = None
    elif configured_work and configured_work.lower() != "auto":
        candidate = Path(configured_work).expanduser()
        if not candidate.is_absolute():
            candidate = (proj / candidate).resolve()
        go_work = candidate.resolve()
        if not go_work.is_file():
            raise BuildContextResolutionError(
                f"configured GOWORK file cannot be bound: {configured_work}"
            )
    else:
        go_work = _nearest_upward_file(proj, "go.work")
    go_mod = _nearest_upward_file(proj, "go.mod")
    if go_work is not None:
        build_root = go_work.parent.resolve()
        work_text = _read_text(go_work)
        module_roots = []
        for raw_path in _go_block_values(work_text, "use"):
            try:
                tokens = shlex.split(raw_path, posix=True)
            except ValueError:
                tokens = []
            token = tokens[0] if tokens else ""
            module = _local_build_path(build_root, token)
            if not module.is_dir() or not (module / "go.mod").is_file():
                raise BuildContextResolutionError(
                    f"go.work use target cannot be bound: {raw_path}"
                )
            module_roots.append(module)
        replacement_base = build_root
        initial_replacements = _go_local_replacements(work_text)
    elif go_mod is not None:
        build_root = go_mod.parent.resolve()
        module_roots = [build_root]
        replacement_base = build_root
        initial_replacements = []
    else:
        return proj.resolve(), [proj.resolve()]

    context_roots: set[Path] = {build_root}
    queue: List[Path] = list(module_roots)
    for raw_path in initial_replacements:
        queue.append(_local_build_path(replacement_base, raw_path))
    visited: set[Path] = set()
    compiled_roots: set[Path] = set(module_roots)
    while queue:
        module = queue.pop(0).resolve()
        if module in visited:
            continue
        visited.add(module)
        if len(visited) > _MAX_BUILD_CONTEXT_MANIFESTS:
            raise BuildContextResolutionError(
                "Go workspace/local-replace closure exceeds the bounded manifest limit"
            )
        manifest = module / "go.mod"
        if not module.is_dir() or not manifest.is_file():
            raise BuildContextResolutionError(
                f"local Go module cannot be bound: {module.name or module}"
            )
        context_roots.add(module)
        if module != build_root:
            compiled_roots.add(module)
        for raw_path in _go_local_replacements(_read_text(manifest)):
            dependency = _local_build_path(module, raw_path)
            compiled_roots.add(dependency)
            queue.append(dependency)
    vendor = build_root / "vendor"
    if vendor.is_dir():
        context_roots.add(vendor.resolve())
        compiled_roots.add(vendor.resolve())
    return (
        build_root,
        sorted(context_roots, key=lambda path: str(path).casefold()),
        sorted(compiled_roots, key=lambda path: str(path).casefold()),
        [],
    )


def _move_context(proj: Path) -> tuple[Path, List[Path], List[Path], List[str]]:
    manifest = _nearest_upward_file(proj, "Move.toml")
    if manifest is None:
        return proj.resolve(), [proj.resolve()], [], []
    build_root = manifest.parent.resolve()
    roots: set[Path] = {build_root}
    queue = [manifest.resolve()]
    visited: set[Path] = set()
    compiled_roots: set[Path] = set()
    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > _MAX_BUILD_CONTEXT_MANIFESTS:
            raise BuildContextResolutionError(
                "Move local-dependency closure exceeds the bounded manifest limit"
            )
        data = _read_toml_strict(current, "Move manifest")
        for section_name in ("dependencies", "dev-dependencies"):
            section = data.get(section_name)
            if not isinstance(section, dict):
                continue
            for dependency in section.values():
                if not isinstance(dependency, dict):
                    continue
                raw_path = dependency.get("local") or dependency.get("path")
                if not isinstance(raw_path, str):
                    continue
                dependency_root = _local_build_path(current.parent, raw_path)
                dependency_manifest = dependency_root / "Move.toml"
                if not dependency_root.is_dir() or not dependency_manifest.is_file():
                    raise BuildContextResolutionError(
                        f"local Move dependency cannot be bound: {raw_path}"
                    )
                roots.add(dependency_root)
                compiled_roots.add(dependency_root)
                queue.append(dependency_manifest)
    return (
        build_root,
        sorted(roots, key=lambda path: str(path).casefold()),
        sorted(compiled_roots, key=lambda path: str(path).casefold()),
        [],
    )


def _package_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildContextResolutionError(
            f"package.json is unreadable: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(value, dict):
        raise BuildContextResolutionError("package.json is unreadable: root is not an object")
    return value


def _javascript_context(
    root: Path,
) -> tuple[set[Path], set[Path], set[Path], List[str]]:
    """Enumerate local/workspace JS inputs plus the installed dependency tree."""
    contexts: set[Path] = set()
    compiled: set[Path] = set()
    files: set[Path] = set()
    limitations: List[str] = []
    package_manifest = root / "package.json"
    if not package_manifest.is_file():
        return contexts, compiled, files, limitations

    queue: List[Path] = [root.resolve()]
    visited: set[Path] = set()
    while queue:
        package_root = queue.pop(0).resolve()
        if package_root in visited:
            continue
        visited.add(package_root)
        if len(visited) > _MAX_BUILD_CONTEXT_MANIFESTS:
            raise BuildContextResolutionError(
                "JavaScript workspace/local-dependency closure exceeds the bounded limit"
            )
        manifest = package_root / "package.json"
        if not manifest.is_file():
            raise BuildContextResolutionError(
                f"local JavaScript dependency lacks package.json: {package_root.name}"
            )
        package = _package_json(manifest)

        raw_workspaces = package.get("workspaces")
        if isinstance(raw_workspaces, dict):
            raw_workspaces = raw_workspaces.get("packages")
        if isinstance(raw_workspaces, str):
            raw_workspaces = [raw_workspaces]
        if isinstance(raw_workspaces, list):
            for pattern in raw_workspaces:
                if not isinstance(pattern, str) or not pattern.strip():
                    continue
                matches = sorted(package_root.glob(pattern))
                if not matches:
                    limitations.append(
                        f"JS_WORKSPACE_PATTERN_UNMATCHED: {pattern}"
                    )
                for workspace in matches:
                    if workspace.is_dir() and (workspace / "package.json").is_file():
                        contexts.add(workspace.resolve())
                        compiled.add(workspace.resolve())
                        queue.append(workspace.resolve())

        for section_name in (
            "dependencies", "devDependencies", "optionalDependencies",
            "peerDependencies",
        ):
            section = package.get(section_name)
            if not isinstance(section, dict):
                continue
            for declaration in section.values():
                if not isinstance(declaration, str):
                    continue
                lowered = declaration.lower()
                if not lowered.startswith(("file:", "link:")):
                    continue
                raw_path = declaration.split(":", 1)[1]
                target = _local_build_path(package_root, raw_path)
                if not target.exists():
                    raise BuildContextResolutionError(
                        f"local JavaScript dependency cannot be bound: {raw_path}"
                    )
                if target.is_dir():
                    contexts.add(target)
                    compiled.add(target)
                    queue.append(target)
                elif target.is_file():
                    files.add(target)
                else:
                    raise BuildContextResolutionError(
                        f"local JavaScript dependency is not regular input: {raw_path}"
                    )

    installed = root / "node_modules"
    if installed.is_dir() and not _dir_empty(installed):
        contexts.add(installed.resolve())
        compiled.add(installed.resolve())
    return contexts, compiled, files, limitations


def _foundry_declared_context(
    root: Path,
) -> tuple[set[Path], set[Path], set[Path], List[str]]:
    contexts: set[Path] = set()
    compiled: set[Path] = set()
    files: set[Path] = set()
    limitations: List[str] = []
    manifest = root / "foundry.toml"
    remapping_values: List[str] = []
    lib_values: List[str] = []
    explicit_libs = False
    if manifest.is_file():
        data = _read_toml_strict(manifest, "foundry.toml")
        tables: List[dict] = [data]
        profiles = data.get("profile")
        if isinstance(profiles, dict):
            tables.extend(value for value in profiles.values() if isinstance(value, dict))
        for table in tables:
            libs = table.get("libs")
            if isinstance(libs, str):
                explicit_libs = True
                lib_values.append(libs)
            elif isinstance(libs, list):
                explicit_libs = True
                lib_values.extend(item for item in libs if isinstance(item, str))
            remappings = table.get("remappings")
            if isinstance(remappings, str):
                remapping_values.append(remappings)
            elif isinstance(remappings, list):
                remapping_values.extend(item for item in remappings if isinstance(item, str))
        remappings_file = root / "remappings.txt"
        if remappings_file.is_file():
            for raw_line in _read_text(remappings_file).splitlines():
                line = raw_line.split("#", 1)[0].strip()
                if line:
                    remapping_values.append(line)
        if not explicit_libs:
            lib_values.append("lib")

    candidates: List[tuple[str, str]] = [("Foundry library", item) for item in lib_values]
    for item in remapping_values:
        if "=" not in item:
            limitations.append(f"FOUNDRY_REMAPPING_UNPARSED: {item[:120]}")
            continue
        candidates.append(("Foundry remapping", item.split("=", 1)[1].strip()))
    for label, raw_path in candidates:
        if not raw_path or "${" in raw_path:
            limitations.append(f"{label.upper().replace(' ', '_')}_UNRESOLVED: {raw_path[:120]}")
            continue
        target = _local_build_path(root, raw_path)
        if target.is_dir():
            contexts.add(target)
            compiled.add(target)
        elif target.is_file():
            files.add(target)
        elif explicit_libs or label == "Foundry remapping":
            limitations.append(f"{label.upper().replace(' ', '_')}_MISSING: {raw_path[:120]}")
    return contexts, compiled, files, limitations


def _evm_context(
    proj: Path,
) -> tuple[Path, List[Path], List[Path], List[Path], List[Path], List[str]]:
    root = (_resolve_evm_build_root(proj) or proj).resolve()
    contexts: set[Path] = {root}
    compiled: set[Path] = set()
    files: set[Path] = set()
    limitations: List[str] = []
    for resolver in (_foundry_declared_context, _javascript_context):
        extra_contexts, extra_compiled, extra_files, extra_limits = resolver(root)
        contexts.update(extra_contexts)
        compiled.update(extra_compiled)
        files.update(extra_files)
        limitations.extend(extra_limits)
    return (
        root,
        sorted(contexts, key=lambda path: str(path).casefold()),
        sorted(compiled, key=lambda path: str(path).casefold()),
        sorted(files, key=lambda path: str(path).casefold()),
        [],
        limitations,
    )


def _daml_yaml_values(text: str, key: str) -> List[str]:
    """Extract scalar/list local path values from the small daml.yaml surface."""
    values: List[str] = []
    lines = text.splitlines()
    key_indent: Optional[int] = None
    for raw_line in lines:
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if key_indent is not None:
            if indent <= key_indent and not stripped.startswith("-"):
                key_indent = None
            elif stripped.startswith("-"):
                value = stripped[1:].strip().strip('"').strip("'")
                if value:
                    values.append(value)
                continue
        match = re.match(rf"{re.escape(key)}\s*:\s*(.*)$", stripped)
        if match:
            value = match.group(1).strip().strip('"').strip("'")
            if value:
                values.append(value)
            else:
                key_indent = indent
    return values


def _daml_context(
    proj: Path,
) -> tuple[Path, List[Path], List[Path], List[Path], List[Path], List[str]]:
    manifest = _nearest_upward_file(proj, "daml.yaml")
    if manifest is None:
        return proj.resolve(), [proj.resolve()], [], [], [], [
            "DAML_BUILD_MANIFEST_MISSING: build closure is source-only"
        ]
    root = manifest.parent.resolve()
    text = _read_text(manifest)
    if not text.strip():
        raise BuildContextResolutionError("daml.yaml is unreadable or empty")
    contexts: set[Path] = {root}
    compiled: set[Path] = set()
    files: set[Path] = set()
    source_files: set[Path] = set()
    limitations: List[str] = []
    source_values = _daml_yaml_values(text, "source") or ["daml"]
    for raw_path in source_values:
        source_root = _local_build_path(root, raw_path)
        if not source_root.is_dir():
            raise BuildContextResolutionError(
                f"DAML source directory cannot be bound: {raw_path}"
            )
        contexts.add(source_root)
        compiled.add(source_root)
        source_files.update(source_root.rglob("*.daml"))
    for key in ("dependencies", "data-dependencies"):
        for raw_path in _daml_yaml_values(text, key):
            # SDK package identifiers are authorities, but not local files.
            if not (raw_path.lower().endswith(".dar") or raw_path.startswith((".", "/", "\\"))):
                continue
            target = _local_build_path(root, raw_path)
            if not target.is_file():
                raise BuildContextResolutionError(
                    f"DAML local DAR cannot be bound: {raw_path}"
                )
            files.add(target)
    limitations.append(
        "DAML_BUILD_CLOSURE_APPROXIMATED: daml.yaml local source/DAR inputs are "
        "bound, but dynamic package resolution is not hermetically proven"
    )
    return (
        root,
        sorted(contexts, key=lambda path: str(path).casefold()),
        sorted(compiled, key=lambda path: str(path).casefold()),
        sorted(files, key=lambda path: str(path).casefold()),
        sorted(source_files, key=lambda path: str(path).casefold()),
        limitations,
    )


def _resolve_manifest_build_root(
    proj: Path,
    manifest_names: Tuple[str, ...],
    suffixes: Tuple[str, ...],
    max_ancestors: int = 5,
) -> Optional[Path]:
    """Resolve a manifest owner without modifying the target tree."""
    cur = proj.resolve()
    for _ in range(max_ancestors + 1):
        try:
            if any((cur / name).exists() for name in manifest_names):
                return cur
        except OSError:
            pass
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    return _find_build_root_downward(proj, manifest_names, suffixes)


def resolve_snapshot_build_root(config: dict) -> Path:
    """Derive and persist the build context that snapshotting must freeze.

    This resolver is deliberately read-only and is called on every startup,
    including resume.  Dependency materialization remains a separate operation
    restricted to fresh/pre-recon runs, so resolving private derived state can
    never hide user drift by mutating inputs before comparison.
    """
    proj = Path(config["project_root"]).resolve()
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    language = str(config.get("language") or "evm").strip().lower()
    compiled_roots: List[Path] = []
    context_files: List[Path] = []
    build_source_files: List[Path] = []
    limitations: List[str] = []
    if (pipeline, language) in {("sc", "solana"), ("sc", "soroban"), ("l1", "rust")}:
        root, contexts, compiled_roots, ecosystem_limits = _cargo_context(
            proj, anchor=(pipeline == "sc" and language == "solana")
        )
        limitations.extend(ecosystem_limits)
    elif (pipeline, language) == ("l1", "go"):
        root, contexts, compiled_roots, ecosystem_limits = _go_context(proj)
        limitations.extend(ecosystem_limits)
    elif pipeline == "sc" and language in {"aptos", "sui"}:
        root, contexts, compiled_roots, ecosystem_limits = _move_context(proj)
        limitations.extend(ecosystem_limits)
    elif (pipeline, language) == ("sc", "evm"):
        (
            root, contexts, compiled_roots, context_files,
            build_source_files, ecosystem_limits,
        ) = _evm_context(proj)
        limitations.extend(ecosystem_limits)
    elif (pipeline, language) == ("sc", "daml"):
        (
            root, contexts, compiled_roots, context_files,
            build_source_files, ecosystem_limits,
        ) = _daml_context(proj)
        limitations.extend(ecosystem_limits)
    else:
        spec = _SNAPSHOT_BUILD_ROOT_SPECS.get((pipeline, language))
        resolved = (
            _resolve_manifest_build_root(proj, spec[0], spec[1])
            if spec is not None
            else None
        )
        root = (resolved or proj).resolve()
        contexts = [root]

    # A downward resolver necessarily chooses one build authority.  If several
    # source-bearing roots exist, keep running but make the approximation loud.
    spec = _SNAPSHOT_BUILD_ROOT_SPECS.get((pipeline, language))
    if spec is not None and root != proj and _is_within(root, proj):
        candidates: set[Path] = set()
        try:
            for manifest_name in spec[0]:
                for manifest in proj.rglob(manifest_name):
                    if any(part in SKIP_DIR_NAMES for part in manifest.relative_to(proj).parts):
                        continue
                    candidate = manifest.parent.resolve()
                    if _production_source_files(candidate, spec[1]):
                        candidates.add(candidate)
        except OSError:
            candidates = {root}
        if len(candidates) > 1:
            limitations.append(
                "MULTI_BUILD_ROOT_SELECTION_APPROXIMATED: multiple source-bearing "
                f"build roots exist ({len(candidates)}); one canonical root was selected"
            )

    limitations.append(
        "MECHANICALLY_APPROXIMATED_BUILD_CLOSURE: declared local dependencies, "
        "workspace members, configured libraries, and installed trees are bound, "
        "but compiler file-open closure is not hermetically proven"
    )
    config["_resolved_build_root"] = str(root)
    config["_resolved_build_context_roots"] = [
        str(path.resolve()) for path in contexts
    ]
    config["_resolved_compiled_dependency_roots"] = [
        str(path.resolve()) for path in compiled_roots
    ]
    config["_resolved_build_context_files"] = [
        str(path.resolve()) for path in context_files
    ]
    config["_resolved_build_source_files"] = [
        str(path.resolve()) for path in build_source_files
    ]
    if pipeline == "sc" and language == "evm" and (root / "package.json").is_file():
        tool, lock_issue = _select_js_lock_authority(root)
        if lock_issue:
            limitations.append(
                f"{lock_issue}; mutable dependency resolution is disabled and "
                "any pre-existing node_modules tree is not proof-grade"
            )
        elif tool and _dir_empty(root / "node_modules"):
            limitations.append(
                "JS_LOCK_DEPENDENCIES_UNMATERIALIZED: immutable lock dependencies "
                "are absent; compiler/AST/PoC completeness is degraded"
            )
            if not shutil.which(tool):
                limitations.append(
                    "JS_LOCK_TOOL_MISSING: a JavaScript lock is present but its "
                    f"immutable {tool} installer is unavailable"
                )
        elif tool:
            limitations.append(
                "JS_DEPENDENCY_TREE_COMPLETENESS_UNPROVEN: node_modules is "
                "content-bound, but lock-to-tree completeness is not hermetically proven"
            )
    if pipeline == "sc" and language == "evm":
        if (root / ".gitmodules").is_file() and _dir_empty(root / "lib"):
            limitations.append(
                "DECLARED_GIT_DEPENDENCIES_UNMATERIALIZED: .gitmodules exists "
                "but the Foundry lib tree is absent"
            )
        try:
            foundry_text = (root / "foundry.toml").read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            foundry_text = ""
        if (
            ("[dependencies]" in foundry_text or (root / "soldeer.lock").is_file())
            and _dir_empty(root / "dependencies")
        ):
            limitations.append(
                "SOLDEER_DEPENDENCIES_UNMATERIALIZED: declared dependency tree is absent"
            )
    config["_snapshot_build_input_limitations"] = list(dict.fromkeys(limitations))
    return root


def _dir_empty(d: Path) -> bool:
    try:
        return (not d.exists()) or not any(d.iterdir())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hardened subprocess runner — the deadlock cure (cross-platform).
#
# CONFIRMED ROOT CAUSE this replaces: `subprocess.run(capture_output=True,
# timeout=T)` kills only the DIRECT child on TimeoutExpired, then drains the OS
# PIPE. A grandchild (solc spawned by forge, cc/ld spawned by cargo,
# rust-analyzer/scip-go workers, ...) inherits and HOLDS the stdout/stderr pipe
# write-handle, so the parent's drain read NEVER returns EOF → TimeoutExpired
# never completes → the driver wedges FOREVER (observed: CPU pinned, no
# recovery even after the forge child was killed, because solc still held the
# pipe).
#
# The two load-bearing fixes here:
#   1. DRAIN TO A TEMP FILE, NOT A PIPE. With Popen(stdout=<file>) there is no
#      OS pipe at all — the kernel writes child output straight to the file and
#      NOBODY can block on a read. A grandchild holding the inherited file
#      handle cannot wedge the parent: there is no parent-side read to block.
#   2. KILL THE WHOLE TREE. POSIX: a new session (start_new_session=True) gives
#      the child its own process-group; os.killpg(SIGKILL) reaps forge AND its
#      solc grandchildren. Windows: CREATE_NEW_PROCESS_GROUP + `taskkill /T /F`
#      tree-kills forge and every grandchild.
#
# Contract: NEVER raises, NEVER blocks past (timeout + GRACE). On timeout returns
# the sentinel rc 124 so existing callers (which already treat rc!=0 / 124 as a
# graceful degrade) fall back to grep/LLM maps. Total wall time is bounded by
# timeout + _HARDENED_GRACE_S regardless of what the child tree does.
# ---------------------------------------------------------------------------

_HARDENED_GRACE_S = 10  # bounded post-kill reap window after a timeout
# Outside both Windows DWORD process exits and POSIX signal returncodes.  This
# remains an internal tuple sentinel; build_status renders no fabricated tool
# exit code when it is present.
_TOOL_EXECUTION_AUTHORITY_DEBT_RC = -(1 << 63)


def _run_hardened(
    cmd: List[str],
    cwd: Optional[Path] = None,
    timeout: int = 120,
    env: Optional[dict] = None,
    *,
    writable_roots: Sequence[Path] = (),
) -> Tuple[int, str]:
    """Run a bounded command inside the shared exhaustive process scope.

    Recon build/tool commands operate only on the disposable or explicitly
    selected build root. Unsupported OS authority, transport failures, and
    timeouts degrade to the legacy numeric statuses; they never mint a clean
    tool outcome.
    """

    argv = [str(value) for value in cmd]
    if not argv:
        return 1, "hardened: empty command"
    # The working directory is an input location, not implicit write
    # authority.  Treating cwd as writable caused Windows MIC setup to relabel
    # entire audited repositories (including dependency junctions) before a
    # tool had even launched.  Callers that genuinely need output must pass a
    # dedicated disposable root and route the tool's outputs there.
    writable = tuple(Path(item).resolve(strict=True) for item in writable_roots)
    try:
        result = run_owned_process(
            argv,
            cwd=cwd,
            env=env,
            timeout=timeout,
            writable_roots=writable,
        )
        return result.returncode, result.stdout + result.stderr
    except FileNotFoundError:
        return 127, f"binary not found: {argv[0]}"
    except TimeoutExpired as exc:
        output = str(getattr(exc, "output", "") or "")
        stderr = str(getattr(exc, "stderr", "") or "")
        return 124, (
            output
            + stderr
            + f"\n[hardened: timed out after {timeout}s, scope terminated]"
        )
    except OwnedProcessRunnerError as exc:
        return (
            _TOOL_EXECUTION_AUTHORITY_DEBT_RC,
            "hardened: TOOL_EXECUTION_AUTHORITY_DEBT: " + str(exc),
        )
    except Exception as exc:  # pragma: no cover - public never-raise contract
        return 1, f"hardened: exception: {type(exc).__name__}: {exc}"


def _run_cmd(cmd: List[str], cwd: Path, timeout: int) -> int:
    """Run a bounded subprocess, return rc only. Never raises.

    Delegates to the hang-proof `_run_hardened` (temp-file drain + tree-kill)."""
    return _run_hardened(cmd, cwd, timeout)[0]


# A non-default Foundry profile is auto-selected ONLY when it is the single
# profile in the manifest (unambiguous); otherwise forge's `default` is used.
_FOUNDRY_PROFILE_RE = re.compile(r"^\s*\[profile\.([A-Za-z0-9_-]+)\]", re.MULTILINE)


def _resolve_foundry_profile_for_recon(root: Path) -> Optional[str]:
    """Pick the FOUNDRY_PROFILE the recon build/Slither should run under.

    Priority: (1) honor an explicit `FOUNDRY_PROFILE` from the environment
    (user/CI choice); (2) if `foundry.toml` defines NO `default` profile but
    exactly ONE other profile, use it (unambiguous — forge's `default` would be
    empty and the build would fail); (3) otherwise None (let forge use default).
    Auto-GUESSING among multiple profiles is deliberately avoided — picking a
    fuzz/CI profile could change build semantics. Never raises."""
    env = os.environ.get("FOUNDRY_PROFILE")
    if env:
        return env
    try:
        toml = (root / "foundry.toml").read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None
    profiles = _FOUNDRY_PROFILE_RE.findall(toml)
    if "default" in profiles:
        return None
    uniq = sorted(set(profiles))
    return uniq[0] if len(uniq) == 1 else None


def _prepare_evm_build(root: Path) -> str:
    """Best-effort dependency + solc readiness at the resolved Foundry root.
    "Make it real, never mock" — resolve the project's REAL dependencies so
    remappings resolve, never stub them:
      (1) `forge install` when git-submodule deps (`.gitmodules`) are declared
          but `lib/` is absent/empty;
      (2) `forge soldeer install` when the repo uses Soldeer (`[dependencies]`
          in foundry.toml or a `soldeer.lock`) but `dependencies/` is empty;
      (3) immutable `npm ci` / frozen yarn/pnpm install when `package.json`
          and a matching lock are present but `node_modules/` is empty;
          a manifest without a lock degrades without mutable resolution;
      (4) pre-install the pragma-detected solc via `svm` so an offline/stale
          version list does not break the build.
    Bounded, idempotent, never raises for its OWN dependency-prep steps —
    failures there are advisory and the build is still attempted afterward.
    EXCEPTION (ITEM H2): the fail-closed supply-chain gate below CAN raise
    `SupplyChainAbortError` and is called BEFORE any install subprocess and
    OUTSIDE the advisory try/except so it is never accidentally swallowed —
    it is a deliberate, true circuit breaker. Callers must let it propagate
    (do not silently continue installing dependencies after it fires)."""
    gate_supply_chain(root)
    notes: List[str] = []
    try:
        # (1) git-submodule (forge) deps
        if (root / ".gitmodules").exists() and _dir_empty(root / "lib") and shutil.which("git"):
            rc, _out = _run_forge(["install"], root, 300)
            notes.append(
                "forge install ok" if rc == 0 else
                f"[DEGRADED:GIT_DEPENDENCY_INSTALL_FAILED] forge install rc={rc}"
            )
        # (2) Soldeer deps
        try:
            ftoml = (root / "foundry.toml").read_text(encoding="utf-8", errors="replace")
        except Exception:
            ftoml = ""
        uses_soldeer = "[dependencies]" in ftoml or (root / "soldeer.lock").exists()
        if uses_soldeer and _dir_empty(root / "dependencies") and shutil.which("forge"):
            rc, _out = _run_forge(["soldeer", "install"], root, 300)
            notes.append(
                "soldeer install ok" if rc == 0 else
                f"[DEGRADED:SOLDEER_INSTALL_FAILED] soldeer install rc={rc}"
            )
        # (3) npm/yarn/pnpm deps (Hardhat, or Foundry remapping into node_modules)
        if (root / "package.json").exists() and _dir_empty(root / "node_modules"):
            js_tool, js_issue = _select_js_lock_authority(root)
            if js_issue:
                notes.append(f"[DEGRADED:{js_issue}]")
            elif js_tool == "pnpm":
                if shutil.which("pnpm"):
                    rc = _run_cmd(["pnpm", "install", "--frozen-lockfile"], root, 420)
                    notes.append(
                        "pnpm install ok" if rc == 0 else
                        f"[DEGRADED:JS_LOCK_INSTALL_FAILED] pnpm install rc={rc}"
                    )
                else:
                    notes.append("[DEGRADED:JS_LOCK_TOOL_MISSING] pnpm lock present but pnpm unavailable")
            elif js_tool == "yarn":
                if shutil.which("yarn"):
                    rc = _run_cmd(["yarn", "install", "--frozen-lockfile"], root, 420)
                    notes.append(
                        "yarn install ok" if rc == 0 else
                        f"[DEGRADED:JS_LOCK_INSTALL_FAILED] yarn install rc={rc}"
                    )
                else:
                    notes.append("[DEGRADED:JS_LOCK_TOOL_MISSING] yarn lock present but yarn unavailable")
            elif js_tool == "npm":
                if shutil.which("npm"):
                    rc = _run_cmd(["npm", "ci"], root, 420)
                    notes.append(
                        "npm ci ok" if rc == 0 else
                        f"[DEGRADED:JS_LOCK_INSTALL_FAILED] npm ci rc={rc}"
                    )
                else:
                    notes.append("[DEGRADED:JS_LOCK_TOOL_MISSING] npm lock present but npm unavailable")
        # (4) solc toolchain
        srcs = _production_source_files(root, (".sol",))
        solc = _detect_solc_version(srcs) if srcs else None
        if solc and shutil.which("svm"):
            _run_hardened(["svm", "install", solc], root, 180)
            notes.append(f"svm install {solc}")
        # (5) profile visibility
        prof = _resolve_foundry_profile_for_recon(root)
        if prof:
            notes.append(f"FOUNDRY_PROFILE={prof}")
    except Exception as exc:
        notes.append(
            f"[DEGRADED:BUILD_INPUT_PREPARATION_EXCEPTION] {type(exc).__name__}: {exc}"
        )
    return "; ".join(notes) or "deps present / no prep needed"

_MAX_RECON_FORGE_FILES = 120
_MAX_OPENGREP_SOURCE_FILES = 300

def _tail(text: str, n: int = 2048) -> str:
    if not text:
        return ""
    if len(text) <= n:
        return text
    return "... [truncated] ...\n" + text[-n:]


# ---------------------------------------------------------------------------
# EVM Foundry build-env bootstrap (FIX 2)
#
# Slither and PoC verification both need a *compilable* project. When an EVM
# scope ships bare `.sol` files with no `foundry.toml`/`hardhat.config.*`, the
# pre-pass previously fell straight to the grep fallback ("no build env
# detected"), so Slither never ran and later verification phases had no harness.
# This best-effort bootstrap scaffolds a minimal Foundry env and runs `forge
# build`. It deliberately does NOT fetch third-party dependencies when the bare
# source bundle has no lockfile/version authority: installing repository HEAD
# can compile against the wrong API and contaminate analysis. It NEVER raises
# and is idempotent (no-op when a build manifest already exists). On any failure
# the caller falls back to the existing source-parse path.
# ---------------------------------------------------------------------------

_PRAGMA_DIRECTIVE_RE = re.compile(
    r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE
)
_SOLC_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")
_SOLC_EXACT_RE = re.compile(r"^\s*=?\s*(\d+\.\d+\.\d+)\s*$")
_SOLC_CONSTRAINT_RE = re.compile(r"(>=|<=|>|<|\^|~|=)?\s*(\d+\.\d+\.\d+)")


def _strip_solidity_comments_and_strings(text: str) -> str:
    """Blank comments/literals while preserving offsets and line boundaries."""
    out = list(text)
    index = 0
    state = "code"
    quote = ""
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if char == "/" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "line"
                index += 2
                continue
            if char == "/" and nxt == "*":
                out[index] = out[index + 1] = " "
                state = "block"
                index += 2
                continue
            if char in {'"', "'"}:
                out[index] = " "
                quote = char
                state = "string"
                index += 1
                continue
        elif state == "line":
            if char in "\r\n":
                state = "code"
            else:
                out[index] = " "
        elif state == "block":
            if char == "*" and nxt == "/":
                out[index] = out[index + 1] = " "
                state = "code"
                index += 2
                continue
            if char not in "\r\n":
                out[index] = " "
        else:
            if char == "\\" and nxt:
                out[index] = " "
                if nxt not in "\r\n":
                    out[index + 1] = " "
                index += 2
                continue
            if char == quote:
                out[index] = " "
                state = "code"
            elif char not in "\r\n":
                out[index] = " "
        index += 1
    return "".join(out)

# import-prefix -> (forge install spec, remapping target dir). Order matters:
# more specific prefixes first so we do not shadow them with a broader match.
_FORGE_LIB_SPECS: Tuple[Tuple[str, str, str, str], ...] = (
    # (import prefix, lib dir name, forge install spec, remapping target)
    ("@openzeppelin/contracts-upgradeable/", "openzeppelin-contracts-upgradeable",
     "OpenZeppelin/openzeppelin-contracts-upgradeable",
     "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/"),
    ("@openzeppelin/contracts/", "openzeppelin-contracts",
     "OpenZeppelin/openzeppelin-contracts",
     "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"),
    ("@openzeppelin/", "openzeppelin-contracts",
     "OpenZeppelin/openzeppelin-contracts",
     "@openzeppelin/=lib/openzeppelin-contracts/"),
    ("solmate/", "solmate", "transmissions11/solmate",
     "solmate/=lib/solmate/src/"),
    ("@solady/", "solady", "Vectorized/solady",
     "@solady/=lib/solady/src/"),
    ("solady/", "solady", "Vectorized/solady",
     "solady/=lib/solady/src/"),
)


def _solc_version_tuple(value: str) -> Tuple[int, int, int]:
    try:
        major, minor, patch = value.split(".")
        return int(major), int(minor), int(patch)
    except Exception:
        return 0, 0, 0


def _solc_clause_satisfied(version: Tuple[int, int, int], clause: str) -> bool:
    # Solidity uses npm-style conjunctions and supports `||`.  Hyphen ranges
    # are normalized to an inclusive pair before token evaluation.
    hyphen = re.fullmatch(
        r"\s*(\d+\.\d+\.\d+)\s+-\s+(\d+\.\d+\.\d+)\s*", clause
    )
    if hyphen:
        return _solc_version_tuple(hyphen.group(1)) <= version <= _solc_version_tuple(hyphen.group(2))
    matches = list(_SOLC_CONSTRAINT_RE.finditer(clause))
    if not matches:
        return False
    # Refuse to bless syntax we did not understand.  Whitespace is the only
    # legal unparsed separator between conjunctive comparator tokens.
    residue = _SOLC_CONSTRAINT_RE.sub("", clause).strip()
    if residue:
        return False
    for match in matches:
        operator = match.group(1) or "="
        bound = _solc_version_tuple(match.group(2))
        if operator == ">=" and not version >= bound:
            return False
        if operator == ">" and not version > bound:
            return False
        if operator == "<=" and not version <= bound:
            return False
        if operator == "<" and not version < bound:
            return False
        if operator == "=" and not version == bound:
            return False
        if operator == "^":
            if bound[0] > 0:
                upper = (bound[0] + 1, 0, 0)
            elif bound[1] > 0:
                upper = (0, bound[1] + 1, 0)
            else:
                upper = (0, 0, bound[2] + 1)
            if not bound <= version < upper:
                return False
        if operator == "~":
            upper = (bound[0], bound[1] + 1, 0)
            if not bound <= version < upper:
                return False
    return True


def _solc_directive_satisfied(version: str, directive: str) -> bool:
    parsed = _solc_version_tuple(version)
    return any(
        _solc_clause_satisfied(parsed, clause)
        for clause in directive.split("||")
    )


def _installed_solc_versions() -> Tuple[str, ...]:
    """Enumerate locally authoritative compiler candidates, best effort."""
    found: set[str] = set()
    probes: List[List[str]] = []
    if shutil.which("svm"):
        probes.append(["svm", "list"])
    if shutil.which("solc-select"):
        probes.append(["solc-select", "versions"])
    if shutil.which("solc"):
        probes.append(["solc", "--version"])
    for command in probes:
        rc, output = _run_hardened(command, timeout=20)
        if rc != 0:
            continue
        found.update(_SOLC_VERSION_RE.findall(output or ""))
    return tuple(sorted(found, key=_solc_version_tuple))


def _detect_solc_version(
    source_files: List[Path],
    *,
    available_versions: Optional[Iterable[str]] = None,
) -> Optional[str]:
    """Choose a compiler that semantically satisfies every range pragma.

    Exact implementation pins retain priority, but an exact candidate excluded
    by any range is rejected.  Range-only selection considers installed/tool-
    authoritative versions plus comparator boundary versions that themselves
    satisfy the constraint.  Consequently an exclusive upper bound can never
    be mistaken for a valid compiler pin.
    """
    from collections import Counter
    exact: Counter = Counter()
    directives: List[str] = []
    for f in source_files[:200]:  # bounded scan
        text = _strip_solidity_comments_and_strings(_read_text(f))
        if not text:
            continue
        for directive in _PRAGMA_DIRECTIVE_RE.findall(text):
            directive = directive.strip()
            directives.append(directive)
            exact_match = _SOLC_EXACT_RE.fullmatch(directive)
            if exact_match:
                exact[exact_match.group(1)] += 1
    if not directives:
        return None
    range_directives = [
        directive for directive in directives
        if _SOLC_EXACT_RE.fullmatch(directive) is None
    ]
    if exact:
        candidates = sorted(
            exact,
            key=lambda value: (exact[value], _solc_version_tuple(value)),
            reverse=True,
        )
        for candidate in candidates:
            # A repository may contain more than one exact pragma.  The most
            # frequent pin is not a valid compiler authority when another
            # audited source requires a different exact version.  Evaluate
            # every directive, including the other exact pins, and degrade to
            # automatic/per-package compilation when no single version can
            # satisfy the complete source set.
            if all(_solc_directive_satisfied(candidate, item) for item in directives):
                return candidate
        return None

    boundary_candidates: set[str] = set()
    for directive in range_directives:
        boundary_candidates.update(_SOLC_VERSION_RE.findall(directive))
    boundary_valid = [
        candidate for candidate in boundary_candidates
        if all(
            _solc_directive_satisfied(candidate, directive)
            for directive in range_directives
        )
    ]
    # With no caller-supplied tool inventory, a valid constraint boundary is
    # the most reproducible pin (e.g. `^0.8.20` -> 0.8.20).  Probe installed
    # versions only when every mentioned boundary is exclusive/invalid.
    if available_versions is None and boundary_valid:
        return max(boundary_valid, key=_solc_version_tuple)
    authoritative = (
        tuple(available_versions)
        if available_versions is not None
        else _installed_solc_versions()
    )
    candidates = {
        value for value in authoritative
        if _SOLC_EXACT_RE.fullmatch(str(value).strip())
    }
    candidates.update(boundary_candidates)
    valid = [
        str(candidate).strip().lstrip("=")
        for candidate in candidates
        if all(
            _solc_directive_satisfied(str(candidate).strip().lstrip("="), directive)
            for directive in range_directives
        )
    ]
    return max(valid, key=_solc_version_tuple) if valid else None


def _detect_import_libs(source_files: List[Path]) -> List[Tuple[str, str, str, str]]:
    """Return the subset of _FORGE_LIB_SPECS whose import prefix appears in the
    Solidity sources. De-duplicated by lib dir name, preserving order."""
    blob_parts: List[str] = []
    for f in source_files[:200]:  # bounded scan
        t = _read_text(f)
        if t:
            blob_parts.append(t)
    blob = "\n".join(blob_parts)
    matched: List[Tuple[str, str, str, str]] = []
    seen_dirs: set = set()
    for spec in _FORGE_LIB_SPECS:
        prefix = spec[0]
        if prefix in blob and spec[1] not in seen_dirs:
            matched.append(spec)
            seen_dirs.add(spec[1])
    return matched


def _run_forge(args: List[str], cwd: Path, timeout: int) -> Tuple[int, str]:
    """Run a bounded `forge ...` subprocess. Returns (rc, combined_output).
    Never raises. Delegates to the hang-proof `_run_hardened` so a solc
    grandchild holding the build pipe can never deadlock the parent."""
    return _run_hardened(["forge", *args], cwd, timeout)


def _bootstrap_evm_foundry_env(
    proj: Path, source_files: List[Path]
) -> Tuple[bool, str]:
    """Best-effort scaffold of a minimal Foundry build env in `proj`.

    Returns (success, reason). NEVER raises. Idempotent: a no-op (returns
    (False, ...)) when a `foundry.toml` already exists so an existing project
    is never clobbered. Requires `forge` on PATH and at least one `.sol` file.
    """
    try:
        # Never scaffold when a real Foundry root exists AT or ABOVE the scope
        # dir. The audit scope is often a source subdir (`.../smart-contracts/src`)
        # whose real foundry.toml + remappings + lib live one level up; writing a
        # minimal `src = "."` env into the scope dir SHADOWS the real root (the
        # observed pollution on a real repo → flat build with empty remappings →
        # every import fails). Walk up, not just the local dir.
        existing_root = _resolve_evm_build_root(proj)
        if existing_root is not None:
            return False, (f"Foundry root already exists at/above scope "
                           f"({existing_root}); bootstrap skipped (idempotent)")
        if not shutil.which("forge"):
            return False, "forge not on PATH; cannot bootstrap Foundry env"
        if not source_files:
            return False, "no Solidity source files to bootstrap against"

        solc = _detect_solc_version(source_files)
        libs = _detect_import_libs(source_files)

        # 1) Minimal foundry.toml. `src = "."` so flat scope dirs of bare .sol
        #    files compile without restructuring; libs vendored under lib/.
        solc_line = f'solc = "{solc}"\n' if solc else ""
        foundry_toml = (
            "[profile.default]\n"
            'src = "."\n'
            'out = "out"\n'
            'libs = ["lib"]\n'
            f"{solc_line}"
            "auto_detect_remappings = true\n"
        )
        try:
            (proj / "foundry.toml").write_text(foundry_toml, encoding="utf-8")
        except Exception as e:
            return False, f"could not write foundry.toml: {e}"

        steps: List[str] = [f"wrote foundry.toml (solc={solc or 'auto'})"]

        # 2) Never guess dependency versions for a manifest-less source bundle.
        #    A package's latest HEAD may have a different API than the audited
        #    code. Locked/declared dependencies are materialized by
        #    `_prepare_evm_build` before snapshot binding on real project roots.
        detected = ", ".join(sorted({spec[1] for spec in libs})) or "none recognized"
        steps.append(
            "unpinned dependency installation skipped "
            f"(detected import families: {detected})"
        )

        # 3) Build. Size-scale the bootstrap build budget too (large scaffolded
        # scopes compile slowly; the hardened wrapper keeps a long ceiling safe).
        _nf = len(_production_source_files(proj, (".sol",)))
        _bt = _scale_build_timeout(180, _nf)
        log.info("[recon] evm bootstrap build: timeout scaled to %ss for %d "
                 ".sol files", _bt, _nf)
        rc, out = _run_forge(["build"], proj, timeout=_bt)
        if rc == 0:
            steps.append("forge build SUCCESS")
            return True, "; ".join(steps)
        steps.append(f"forge build failed (rc={rc}): {_tail(out, 400)}")
        return False, "; ".join(steps)
    except Exception as e:  # pragma: no cover - defensive top-level guard
        return False, f"bootstrap exception: {e}"


def prepare_snapshot_bound_inputs(config: dict) -> Dict[str, str]:
    """Materialize deterministic build inputs before the audit snapshot binds.

    The EVM bare-source bootstrap writes ``foundry.toml`` and may install
    dependency/remapping inputs under the project root.  Those files influence
    Slither, build probes, and PoC execution, so they belong *inside* the bound
    audit input set.  Running this small ecosystem-gated preparation from the
    driver before :func:`build_audit_snapshot` prevents the recon pre-pass from
    being mistaken for mid-run user-source drift.

    This is intentionally best-effort and idempotent.  Existing Foundry or
    Hardhat projects are never modified, unsupported ecosystems are no-ops, and
    every failure is returned as a status rather than raised.
    """
    def finish(status: str, reason: str) -> Dict[str, str]:
        receipt = {"status": status, "reason": reason}
        # Retain the structured result for the current process and tests.  Any
        # persistent snapshot limitation must be derived read-only by
        # `resolve_snapshot_build_root` on every startup; otherwise a private
        # field present only on the fresh run would create false resume drift.
        config["_snapshot_input_preparation"] = dict(receipt)
        return receipt

    try:
        pipeline = str(config.get("pipeline") or "sc").lower()
        language = str(config.get("language") or "evm").lower()
        if pipeline != "sc" or language != "evm":
            return finish("SKIPPED", "not a bare-source EVM lane")

        proj = Path(config["project_root"]).resolve()
        resolved_root = resolve_snapshot_build_root(config)
        owns_declared_build = (
            (resolved_root / "foundry.toml").exists()
            or bool(list(resolved_root.glob("hardhat.config.*")))
            or (resolved_root / "package.json").exists()
        )
        if owns_declared_build:
            note = _prepare_evm_build(resolved_root)
            # Re-derive the private closure/limitations from disk so a fresh
            # successful or failed materialization has the same snapshot
            # semantics as a later read-only resume.
            resolve_snapshot_build_root(config)
            degraded = "[DEGRADED:" in (note or "")
            return finish(
                "DEGRADED" if degraded else "PREPARED",
                note or "declared dependencies ready",
            )
        if not shutil.which("forge"):
            return finish("SKIPPED", "forge not on PATH")

        sources = sorted(
            _production_source_files(proj, (".sol",)), key=lambda p: _rel(p, proj)
        )
        if not sources:
            return finish("SKIPPED", "no Solidity source files")
        if len(sources) > _MAX_RECON_FORGE_FILES:
            return finish(
                "SKIPPED",
                (
                    f"bare-source scope has {len(sources)} files; bootstrap limit is "
                    f"{_MAX_RECON_FORGE_FILES}"
                ),
            )

        manifest = proj / "foundry.toml"
        existed_before = manifest.exists()
        ok, reason = _bootstrap_evm_foundry_env(proj, sources)
        materialized = not existed_before and manifest.exists()
        return finish(
            "PREPARED" if (ok and materialized) else ("READY" if ok else "DEGRADED"),
            reason,
        )
    except SupplyChainAbortError:
        raise
    except Exception as exc:  # pragma: no cover - defensive startup boundary
        return finish("DEGRADED", f"{type(exc).__name__}: {exc}")


def _write_build_status(scratch: Path, proj: Path, lang: str,
                        graph_status: Optional[str] = None) -> str:
    bootstrap_note = ""
    try:
        key = _select_build(proj, lang)
        # FIX 2: EVM scope with bare .sol files and no build manifest. If forge
        # is available, best-effort bootstrap a minimal Foundry env so Slither
        # and later PoC verification have a compilable harness. Falls through to
        # the existing grep-fallback SKIPPED status on any failure.
        if (
            not key
            and lang == "evm"
            and shutil.which("forge")
            and _resolve_evm_build_root(proj) is None
            and not list(proj.glob("hardhat.config.*"))
        ):
            evm_sources = sorted(
                _production_source_files(proj, (".sol",)), key=lambda p: _rel(p, proj)
            )
            if evm_sources and len(evm_sources) <= _MAX_RECON_FORGE_FILES:
                ok, reason = _bootstrap_evm_foundry_env(proj, evm_sources)
                if ok:
                    key = "evm_forge"
                    bootstrap_note = (
                        "**Build Env Bootstrap**: SUCCESS — scaffolded a minimal "
                        f"Foundry env ({reason}).\n\n"
                    )
                else:
                    _write_text(scratch / "build_status.md",
                                "# Build Status\n\n"
                                "**Tool**: (none detected for lang=evm)\n\n"
                                "**Status**: SKIPPED\n\n"
                                "Build env bootstrap attempted but failed: "
                                f"{reason}; grep fallback used. LLM recon may "
                                "re-attempt with a manually configured build.\n")
                    return "STUB"
        if not key:
            _write_text(scratch / "build_status.md",
                        "# Build Status\n\n"
                        f"**Tool**: (none detected for lang={lang})\n\n"
                        "**Status**: SKIPPED\n\n"
                        "No build tool / manifest detected. LLM recon may re-attempt.\n")
            return "STUB"
        spec = BUILD_SPECS[key]
        cmd = list(spec["cmd"])
        timeout = spec["timeout"]
        build_cwd = proj

        # DEDUPE (no double-compile): the mechanical-graph bake for EVM
        # (`_bake_evm_graph` → Slither) already compiles the WHOLE project with
        # solc to build its type-resolved graph. A separate `forge build` here
        # would compile the same project a second time — the redundant, slow
        # step that triggered the observed wedge on large repos. When that bake
        # compiled (graph source=slither), the project provably builds, so we
        # derive build_status from it and SKIP the standalone build probe. The
        # approximate source-parse / SCIP tiers do NOT compile, so they fall
        # through to a real build probe below (no false SUCCESS).
        if _graph_implies_compiles(graph_status, lang):
            log.info("[recon] build probe skipped — %s mechanical-graph bake "
                     "already compiled the project (graph source=slither); "
                     "deriving build_status=SUCCESS instead of recompiling", key)
            _write_text(scratch / "build_status.md",
                        "# Build Status\n\n"
                        f"{bootstrap_note}"
                        f"**Tool**: {key} (derived from Slither bake)\n\n"
                        "**Status**: SUCCESS\n\n"
                        "Derived from the Slither mechanical-graph bake, which "
                        "compiled the whole project (Slither requires a "
                        "successful solc compile to build its graph). The "
                        "redundant standalone build probe was SKIPPED to avoid "
                        "compiling the project twice.\n")
            return "WRITTEN"

        build_writable_roots: tuple[Path, ...] = ()
        if key == "evm_forge":
            root = _resolve_evm_build_root(proj)
            if root is not None and root != proj.resolve():
                # Real Foundry root found ABOVE the scope dir (audit scope is a
                # source subdir like `.../smart-contracts/src`). Build the WHOLE
                # project from the root so its foundry.toml / remappings.txt /
                # lib resolve every `@import` — running from the scope dir gives
                # empty remappings and every import fails (an observed build
                # failure). Dependency/toolchain materialization is exclusively
                # owned by prepare_audit_inputs_before_snapshot; recon is
                # read-only with respect to bound source inputs.
                # `_bake_evm_slither_graph` resolves the same root downstream.
                bootstrap_note = ("**Build Root**: resolved to Foundry root "
                                  f"`{root}` (scope dir had no foundry.toml).\n\n"
                                  "**Build Prep**: pre-snapshot preparation "
                                  "authority reused; no recon-time dependency "
                                  "materialization attempted.\n\n")
                build_cwd = root
                cmd = ["forge", "build"]
                # Size-scale: whole-project build of a large repo (e.g. ~176
                # .sol + optimizer, cold cache) blows past a fixed budget.
                # Count the FULL compile-unit tree incl `lib/` deps — the
                # production-source count excludes `lib/` and undercounts the
                # solc load ~10x, which timed out cold-cache dep-heavy repos.
                _nf = len(_compile_unit_files(root, (".sol",)))
                timeout = _scale_build_timeout(600, _nf)
                log.info("[recon] evm_forge whole-project build at %s: timeout "
                         "scaled to %ss for %d compile-unit .sol files",
                         root, timeout, _nf)
            else:
                source_files = sorted(_production_source_files(proj, (".sol",)), key=lambda p: _rel(p, proj))
                if not source_files:
                    _write_text(scratch / "build_status.md",
                                "# Build Status\n\n"
                                "**Tool**: evm_forge\n\n"
                                "**Status**: SKIPPED\n\n"
                                "No production Solidity source files found for bounded recon pre-pass.\n")
                    return "WRITTEN"
                if len(source_files) > _MAX_RECON_FORGE_FILES:
                    _write_text(scratch / "build_status.md",
                                "# Build Status\n\n"
                                "**Tool**: evm_forge\n\n"
                                "**Status**: SKIPPED\n\n"
                                f"Found {len(source_files)} production Solidity files; "
                                "skipping recon pre-pass compile to avoid an unbounded compiler fanout. "
                                "Later repair/verification phases must compile explicit affected files.\n")
                    return "WRITTEN"
                cmd = (
                    ["forge", "build"]
                    + [_rel(f, proj) for f in source_files]
                    + ["--threads", "1", "--no-auto-detect"]
                )
                # RECON-6: even within the file-count cap, the per-file argv can
                # exceed the OS command-length limit (notably on Windows), which
                # raises OSError/FileNotFoundError and gets recorded as a spurious
                # build=FAILED. When the argv would be too long, fall back to a
                # scoped whole-project `forge build` rather than mis-signal a broken
                # build to recon/verification.
                if sum(len(a) + 1 for a in cmd) > 7000:
                    cmd = ["forge", "build", "--threads", "1", "--no-auto-detect"]
                    # Argv too long → this is now a WHOLE-PROJECT compile. Size
                    # its timeout on the full compile-unit tree (incl deps), not
                    # the scoped production count, or the dependency compile
                    # blows the budget (same root cause as the foundry-root path
                    # above).
                    _nf = len(_compile_unit_files(proj, (".sol",)))
                    timeout = _scale_build_timeout(600, _nf)
                    log.info("[recon] evm_forge whole-project fallback build: "
                             "timeout scaled to %ss for %d compile-unit .sol "
                             "files", timeout, _nf)
                else:
                    # Size-scale the scoped compile too (still bounded by the
                    # file cap above, but the optimizer makes per-file cost
                    # nonlinear).
                    timeout = _scale_build_timeout(timeout, len(source_files))
                    log.info("[recon] evm_forge scoped build: timeout scaled to "
                             "%ss for %d .sol files", timeout, len(source_files))

            # Source and dependencies remain medium-integrity read-only inputs.
            # Foundry's only build products are redirected to a fresh child of
            # this pre-pass's unpublished staging directory.  The containment
            # layer lowers exactly this disposable root, never PROJECT_ROOT or
            # the scratchpad artifact namespace.
            # Keep this disposable name short. Audit roots are often deep and
            # Forge adds ``out/<source>/<contract>.json``; a compact component
            # keeps third-party consumers below legacy Windows MAX_PATH.
            foundry_output_root = scratch / ".fb"
            foundry_output_root.mkdir(mode=0o700)
            foundry_out = foundry_output_root / "out"
            foundry_cache = foundry_output_root / "cache"
            foundry_build_info = foundry_output_root / "build-info"
            cmd.extend(
                [
                    "--out",
                    str(foundry_out),
                    "--cache-path",
                    str(foundry_cache),
                    "--build-info",
                    "--build-info-path",
                    str(foundry_build_info),
                ]
            )
            build_writable_roots = (foundry_output_root,)

        if key == "evm_hardhat":
            root = _resolve_evm_build_root(proj)
            if root is None or not list(root.glob("hardhat.config.*")):
                _write_text(
                    scratch / "build_status.md",
                    "# Build Status\n\n**Tool**: evm_hardhat\n\n"
                    "**Status**: SKIPPED\n\nCanonical Hardhat root could not be resolved.\n",
                )
                return "WRITTEN"
            build_cwd = root
            cmd = ["npx", "hardhat", "compile"]

        # STEP 2C: non-EVM build parity. Give the non-EVM branches the same
        # guards EVM has: (1) a per-language source-file presence check, and
        # (2) build-root resolution so we never run a compile from a scope dir
        # (e.g. `.../<crate>/src/`) that has no build manifest. All branches
        # remain best-effort and always write build_status.md (no new halt).
        if key in ("solana", "soroban", "aptos", "sui"):
            cfg = LANG_DISPATCH.get(key) or {}
            suffixes = cfg.get("suffix") or ()
            source_files = _production_source_files(proj, suffixes) if suffixes else []
            if not source_files:
                _write_text(scratch / "build_status.md",
                            "# Build Status\n\n"
                            f"**Tool**: {key}\n\n"
                            "**Status**: SKIPPED\n\n"
                            f"No production {'/'.join(suffixes) or 'source'} files found "
                            "under PROJECT_PATH for bounded recon pre-pass. LLM recon may "
                            "re-attempt with a resolved build root.\n")
                return "WRITTEN"
            resolved_root = _resolve_build_root(proj, key)
            if resolved_root is None:
                manifest = _BUILD_MANIFESTS.get(key, "manifest")
                _write_text(scratch / "build_status.md",
                            "# Build Status\n\n"
                            f"**Tool**: {key}\n\n"
                            "**Status**: SKIPPED\n\n"
                            f"No {manifest} found at or above PROJECT_PATH; "
                            "skipping recon pre-pass compile to avoid a spurious "
                            "build failure from a scope dir without a build manifest. "
                            "LLM recon should enrich build status.\n")
                return "WRITTEN"
            build_cwd = resolved_root
            # Solana: a host-target `cargo build --release` of an on-chain
            # program is misleading. Prefer the on-chain build toolchain when
            # available; otherwise skip the compile and let LLM recon enrich.
            if key == "solana":
                if shutil.which("cargo-build-sbf") or shutil.which("cargo"):
                    if shutil.which("anchor") and (resolved_root / "Anchor.toml").exists():
                        cmd = ["anchor", "build"]
                    elif shutil.which("cargo-build-sbf"):
                        cmd = ["cargo", "build-sbf"]
                    else:
                        _write_text(scratch / "build_status.md",
                                    "# Build Status\n\n"
                                    "**Tool**: solana\n\n"
                                    "**Status**: SKIPPED\n\n"
                                    "Neither `anchor` nor `cargo build-sbf` is available; a "
                                    "host-target `cargo build` of an on-chain Solana program "
                                    "is misleading, so the recon pre-pass compile is skipped. "
                                    "LLM recon should enrich build status.\n")
                        return "WRITTEN"
            # Size-scale the non-EVM compile by source-file count (Rust crates
            # and large Move packages compile slowly; the fixed base under-
            # budgets big repos). `source_files` is the per-language production
            # set gathered above.
            timeout = _scale_build_timeout(timeout, len(source_files))
            log.info("[recon] %s build at %s: timeout scaled to %ss for %d "
                     "source files", key, build_cwd, timeout, len(source_files))

        # Thread FOUNDRY_PROFILE for EVM so a project whose remappings/settings
        # live under a single non-default profile compiles. None → inherit env
        # (forge default). Honors an explicit env var first.
        build_env = None
        if key == "evm_forge":
            _prof = _resolve_foundry_profile_for_recon(build_cwd)
            if _prof:
                build_env = {**os.environ, "FOUNDRY_PROFILE": _prof}
        # Rust-ecosystem recon-build hardening (generic by ecosystem key, NOT a
        # project/crate name). A stale/corrupt incremental-compilation cache —
        # left behind by a concurrent or interrupted cargo build — makes a fresh,
        # otherwise-clean compile emit spurious parse errors on valid source
        # (e.g. `error: unexpected closing delimiter: }`). Disabling incremental
        # compilation for the recon probe eliminates that whole error class; the
        # full parent env is still inherited so toolchain/rustup overrides remain
        # intact. EVM (forge) keeps its FOUNDRY_PROFILE env above, untouched.
        if _is_rust_ecosystem_build(key, cmd):
            base_env = build_env if build_env is not None else dict(os.environ)
            build_env = {**base_env, "CARGO_INCREMENTAL": "0"}
        # Hardhat probe: size-scale by .sol count too (no foundry; the EVM
        # dedupe still suppresses this entirely when Slither already compiled).
        if key == "evm_hardhat":
            # `hardhat compile` is a whole-project compile (imports pull in
            # node_modules deps), so size on the full compile-unit tree, not
            # the production-only count.
            _nf = len(_compile_unit_files(build_cwd, (".sol",)))
            timeout = _scale_build_timeout(timeout, _nf)
            log.info("[recon] evm_hardhat build: timeout scaled to %ss for %d "
                     "compile-unit .sol files", timeout, _nf)
        # Hang-proof: temp-file drain + tree-kill (a forge→solc / cargo→cc
        # grandchild holding the build pipe can no longer wedge the driver).
        rc, combined = _run_hardened(
            cmd,
            build_cwd,
            timeout,
            env=build_env,
            writable_roots=build_writable_roots,
        )
        # Retry-once on a transient non-timeout build failure. A first attempt
        # that fails for a transient reason (a flake, or a stale incremental
        # cache the first attempt itself invalidated) frequently succeeds on a
        # clean second run. Scoped to exactly ONE retry, and NOT for:
        #   - timeout (rc=124): a genuine stall — retrying just burns the budget;
        #   - binary-not-found (rc=127): the build tool is missing — deterministic.
        # Generic across all ecosystems (the rc∉{0,124,127} guard makes it
        # ecosystem-agnostic); the CARGO_INCREMENTAL=0 env above already removes
        # the dominant Rust-specific cause, so most second attempts succeed.
        if rc not in (
            0,
            124,
            127,
            _TOOL_EXECUTION_AUTHORITY_DEBT_RC,
        ):
            log.warning("[recon] %s build attempt 1 FAILED (rc=%s) — retrying "
                        "ONCE (transient flake / self-invalidated cache often "
                        "clears on a clean re-run)", key, rc)
            rc2, combined2 = _run_hardened(
                cmd,
                build_cwd,
                timeout,
                env=build_env,
                writable_roots=build_writable_roots,
            )
            if rc2 == 0:
                log.info("[recon] %s build retry SUCCEEDED (attempt 1 rc=%s was "
                         "transient)", key, rc)
            else:
                log.warning("[recon] %s build retry FAILED too (attempt 1 rc=%s, "
                            "attempt 2 rc=%s) — degrading build_status",
                            key, rc, rc2)
            rc, combined = rc2, combined2
        timed_out = rc == 124
        authority_debt = rc == _TOOL_EXECUTION_AUTHORITY_DEBT_RC
        # _run_hardened combines stdout+stderr; keep the diagnostic text in the
        # stdout tail and leave stderr empty (split is purely informational).
        so, se = combined, ""

        status = (
            "SUCCESS"
            if rc == 0
            else (
                "TIMEOUT"
                if timed_out
                else (
                    "DEGRADED_AUTHORITY_DEBT"
                    if authority_debt
                    else "FAILED"
                )
            )
        )
        # Visible degrade logging: the user manually reruns and wants to SEE the
        # build outcome — no silent freeze. The hardened wrapper guarantees we
        # reach this line within (timeout + grace) even on a wedged tree.
        if timed_out:
            log.warning("[recon] %s build timed out after %ss, tree-killed — "
                        "degrading build_status to TIMEOUT (later phases compile "
                        "explicit affected files on demand)", key, timeout)
        elif authority_debt:
            log.warning(
                "[recon] %s tool execution authority failed; not retrying "
                "or attributing the infrastructure debt to the compiler; "
                "build_status=DEGRADED_AUTHORITY_DEBT",
                key,
            )
        elif rc != 0:
            log.warning("[recon] %s build FAILED (rc=%s) — build_status=FAILED; "
                        "recon/verification degrade to grep + on-demand compile",
                        key, rc)
        else:
            log.info("[recon] %s build SUCCESS in cwd %s", key, build_cwd)
        content = (
            "# Build Status\n\n"
            f"{bootstrap_note}"
            f"**Tool**: {key}\n"
            f"**Command**: `{' '.join(cmd)}`\n"
            f"**CWD**: `{build_cwd}`\n"
            f"**Timeout**: {timeout}s\n"
            f"**Exit Code**: "
            f"{'N/A (tool completion authority unavailable)' if authority_debt else rc}\n"
            f"**Status**: {status}\n\n"
            "## stdout (tail)\n```\n" + _tail(so) + "\n```\n\n"
            "## stderr (tail)\n```\n" + _tail(se) + "\n```\n"
        )
        _write_text(scratch / "build_status.md", content)
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / "build_status.md",
                    f"# Build Status\n\n**Status**: FAILED\n\nPre-pass exception: {e}\n")
        return "FAILED"

# L1 artifacts
_L1_SUBSYSTEMS = {
    "consensus": ("consensus", "fork_choice", "beacon", "slashing"),
    "p2p":       ("p2p", "network", "libp2p", "discovery"),
    "mempool":   ("txpool", "mempool", "blob_pool"),
    "rpc":       ("rpc", "engine_api", "api"),
    "state":     ("state", "storage", "pruning", "snapshot"),
    "execution": ("vm", "evm", "revm", "interpreter"),
}
_L1_SOURCE_SUFFIXES = (".go", ".rs", ".ts", ".py")
_L1_FN_GO_RE = re.compile(r"^\s*func\s+(?:\([^)]+\)\s+)?(\w+)\s*\(", re.MULTILINE)
_L1_FN_RUST_RE = re.compile(r"^\s*pub(?:\s*\([^)]*\))?\s+(?:async\s+)?fn\s+(\w+)", re.MULTILINE)

def _dir_stats(d: Path) -> Tuple[int, int]:
    files = 0
    loc = 0
    for root, dns, fns in os.walk(d):
        dns[:] = _prune_walk_dirs(d, root, dns)
        for fn in fns:
            if fn.endswith(_L1_SOURCE_SUFFIXES):
                files += 1
                ln, _ = _lines_and_bytes(Path(root) / fn)
                loc += ln
    return files, loc

def _write_subsystem_map_l1(scratch: Path, proj: Path) -> str:
    try:
        buckets: Dict[str, List[Path]] = {k: [] for k in _L1_SUBSYSTEMS}
        for dirpath, dirnames, _ in os.walk(proj):
            dirnames[:] = _prune_walk_dirs(proj, dirpath, dirnames)
            dn = Path(dirpath).name.lower()
            for sub, kws in _L1_SUBSYSTEMS.items():
                if dn in kws:
                    buckets[sub].append(Path(dirpath))

        rows: List[str] = []
        total_files = 0
        for sub, dirs in buckets.items():
            for d in sorted(dirs):
                files, loc = _dir_stats(d)
                total_files += files
                rows.append(f"| `{_rel(d, proj)}` | {sub} | {loc} | {files} |")

        lines = ["# Subsystem Map", "",
                 f"Pre-pass: {len(rows)} dir matches ({total_files} source files).", "",
                 "| Dir | Subsystem | LOC | Files |",
                 "|-----|-----------|-----|-------|"]
        lines.extend(rows if rows else ["| _(no subsystem dirs detected)_ | - | - | - |"])
        _write_text(scratch / "subsystem_map.md", "\n".join(lines) + "\n")
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / "subsystem_map.md",
                    f"# Subsystem Map\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

def _write_trust_boundaries_l1(scratch: Path, proj: Path) -> str:
    try:
        tops = [
            e for e in sorted(proj.iterdir())
            if e.is_dir()
            and e.name not in SKIP_DIR_NAMES
            and not e.name.startswith(".")
        ]
        ext_kw = ("rpc", "p2p", "network", "api", "engine_api", "libp2p", "discovery")
        lines = ["# Trust Boundaries", "",
                 "Pre-pass stub: top-level dirs classified by name heuristic.",
                 "LLM recon MUST enrich with real trust-boundary analysis.", "",
                 "| Top-Level Dir | Classification | Notes |",
                 "|---------------|---------------|-------|"]
        for d in tops:
            cls = "external" if any(k in d.name.lower() for k in ext_kw) else "internal"
            lines.append(f"| `{d.name}` | {cls} | heuristic |")
        if not tops:
            lines.append("| _(no top-level dirs)_ | - | - |")
        _write_text(scratch / "trust_boundaries.md", "\n".join(lines) + "\n")
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / "trust_boundaries.md",
                    f"# Trust Boundaries\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

def _write_attack_surface_l1(scratch: Path, proj: Path) -> str:
    try:
        surface_kws = set(_L1_SUBSYSTEMS["rpc"] + _L1_SUBSYSTEMS["p2p"])
        surface_dirs: List[Path] = []
        for dirpath, dirnames, _ in os.walk(proj):
            dirnames[:] = _prune_walk_dirs(proj, dirpath, dirnames)
            if Path(dirpath).name.lower() in surface_kws:
                surface_dirs.append(Path(dirpath))

        rows: List[str] = []
        for d in sorted(set(surface_dirs)):
            for root, dns, fns in os.walk(d):
                dns[:] = _prune_walk_dirs(d, root, dns)
                for fn in fns:
                    fp = Path(root) / fn
                    text = _read_text(fp)
                    if not text:
                        continue
                    if fn.endswith(".go"):
                        for m in _L1_FN_GO_RE.finditer(text):
                            rows.append(f"| `{_rel(fp, proj)}` | `{m.group(1)}` | go | {_line_of(text, m.start())} |")
                    elif fn.endswith(".rs"):
                        for m in _L1_FN_RUST_RE.finditer(text):
                            rows.append(f"| `{_rel(fp, proj)}` | `{m.group(1)}` | rust | {_line_of(text, m.start())} |")

        lines = ["# Attack Surface (L1 pre-pass)", "",
                 f"Pre-pass: {len(rows)} exported fn(s) in rpc/ and p2p/ dirs.",
                 "LLM recon MUST enrich with real attack-surface analysis.", "",
                 "| File | Function | Lang | Line |",
                 "|------|----------|------|------|"]
        lines.extend(rows if rows else ["| _(no RPC/P2P entry points found)_ | - | - | - |"])
        _write_text(scratch / "attack_surface.md", "\n".join(lines) + "\n")
        return "WRITTEN"
    except Exception as e:
        _write_text(scratch / "attack_surface.md",
                    f"# Attack Surface\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

# Shared stubs
def _write_design_or_threat_stub(scratch: Path, pipeline: str) -> str:
    try:
        if pipeline == "l1":
            target = scratch / "threat_model.md"
            body = ("# Threat Model\n\n"
                    "[LLM TO ENRICH] Pre-pass stub. LLM recon MUST replace each section.\n\n"
                    "## Node Role / Deployment Context\n[LLM TO ENRICH]\n\n"
                    "## Trust Model\n[LLM TO ENRICH]\n\n"
                    "## Attacker Capabilities\n[LLM TO ENRICH]\n\n"
                    "## Critical Invariants\n[LLM TO ENRICH]\n\n"
                    "## Operational Implications\n[LLM TO ENRICH]\n")
        else:
            target = scratch / "design_context.md"
            body = ("# Design Context\n\n"
                    "[LLM TO ENRICH] Pre-pass stub. LLM recon MUST replace each section.\n\n"
                    "## Protocol Summary\n[LLM TO ENRICH]\n\n"
                    "## Key Invariants\n[LLM TO ENRICH]\n\n"
                    "## Operational Implications\n[LLM TO ENRICH]\n\n"
                    "## Trust Assumptions\n[LLM TO ENRICH]\n\n"
                    "## Fork Ancestry\n[LLM TO ENRICH]\n")
        return "STUB" if _write_text(target, body) else "FAILED"
    except Exception:
        return "FAILED"

def _write_sc_recon_stub(scratch: Path, name: str, body: str) -> str:
    """Write a minimal stub for SC recon artifacts not covered by mechanical extraction."""
    return "STUB" if _write_text(scratch / name, body) else "FAILED"


def _write_recon_summary_stub(scratch: Path, proj: Path, lang: str) -> str:
    body = ("# Recon Summary\n\n"
            "[LLM TO ENRICH] Pre-pass stub.\n\n"
            f"- **Target**: `{proj}`\n"
            f"- **Language**: {lang}\n"
            "- **Themes**: [LLM TO ENRICH]\n"
            "- **Risk Areas**: [LLM TO ENRICH]\n"
            "- **Recommended Lanes**: [LLM TO ENRICH — see template_recommendations.md]\n")
    return "STUB" if _write_text(scratch / "recon_summary.md", body) else "FAILED"

def _write_meta_buffer_stub(scratch: Path) -> str:
    return "STUB" if _write_text(scratch / "meta_buffer.md",
                                   "# RAG Meta Buffer\n(optional)\n") else "FAILED"


def _write_external_dependency_research_stub(scratch: Path) -> str:
    """Guarantee `external_dependency_research.md` exists before recon runs
    (Fix B / Hook 1 prereq). Recon is the only phase with live WebSearch/
    WebFetch/tavily_search AND full attack-surface knowledge; it overwrites
    this stub with one row per EXTERNAL_DEPENDENCY / NAMED_EXTERNAL_PROTOCOL
    dependency (TASK 6 detection, TASK 11 research). depth-phase workers run
    with `--disallowedTools mcp__*` and no live web tools, so they can only
    READ this baked ledger — a missing file (not just an empty one) would
    silently look like "nothing to check" instead of "recon never wrote it".
    Header-only is a valid terminal state when zero dependencies are detected;
    this stub is ALWAYS replaced-or-kept by recon, never read as-is by a
    depth worker without a header. Best-effort; never raises."""
    header = (
        "# External Dependency Research Ledger\n\n"
        "> **Status**: [LLM TO ENRICH] Pre-pass stub — no dependencies enumerated yet.\n"
        "> Recon MUST replace this file: one row per EXTERNAL_DEPENDENCY /\n"
        "> NAMED_EXTERNAL_PROTOCOL dependency flagged in TASK 6, researched via\n"
        "> WebSearch/WebFetch/tavily_search (recon has live tool access; depth-phase\n"
        "> workers do not — they only read this baked ledger). A `FETCH_FAILED` row\n"
        "> is carried forward, never dropped. If zero dependencies are detected, the\n"
        "> header-only table below (no data rows) is the correct terminal state.\n\n"
        "| Dependency | Integration Surface | Assumed Behavior | Real Behavior | "
        "Source | Conformance | Fetch Status |\n"
        "|------------|----------------------|-------------------|-----------------|"
        "--------|-------------|---------------|\n"
    )
    return "STUB" if _write_text(scratch / "external_dependency_research.md", header) else "FAILED"


# DAML is the first SAST-less ecosystem: there is no static-analysis prepass
# (no SCIP indexer, no Scout/Slither, DLint is style-only). Recon is fully
# read-driven — the recon LLM is the sole producer of every artifact via
# `damlc inspect-dar --json` (structural oracle) + disciplined grep over .daml.
# This no-op writes the SC recon artifacts as [LLM TO ENRICH] stubs so the
# driver's prepass-read gates never fail on a missing/zero-byte file, plus a
# marker recording WHY no mechanical extraction ran. The mechanical SC
# extractors (LANG_DISPATCH) are deliberately skipped — they have no .daml
# adapter and would emit empty tables.
def _write_daml_prepass_noop(scratch: Path, proj: Path) -> str:
    marker = (
        "# DAML Recon Pre-Pass: NO-OP (read-driven)\n\n"
        "No mechanical prepass for DAML. DAML has no static-analysis prepass "
        "(no SCIP indexer, no Scout/Slither; DLint is style-only). Recon is "
        "fully read-driven: the recon LLM produces every artifact from "
        "`damlc inspect-dar --json` (structural oracle) and grep over `.daml` "
        "sources. These prepass files are non-empty [LLM TO ENRICH] stubs only "
        "so prepass-read gates do not fail; the recon phase replaces them.\n"
    )
    _write_text(scratch / "daml_prepass_noop.md", marker)
    return "STUB"

# template_recommendations.md — extract from skill-index.md
_LANG_HEADING = {
    "evm":     "## EVM Skills",
    "solana":  "## Solana Skills",
    "aptos":   "## Aptos Skills",
    "sui":     "## Sui Skills",
    "soroban": "## Soroban Skills",
    "daml":    "## DAML Skills",
    "l1":      "## L1 Skills",
}

def _extract_skill_table(text: str, heading: str) -> List[Tuple[str, str]]:
    idx = text.find(heading)
    if idx < 0:
        return []
    end = text.find("\n## ", idx + 1)
    section = text[idx:end if end > 0 else len(text)]
    out: List[Tuple[str, str]] = []
    in_table = False
    for line in section.splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if not in_table and cells and cells[0].lower() in ("skill", "name"):
                in_table = True
                continue
            if in_table and cells and set("".join(cells)) <= set("- :"):
                continue
            if in_table and len(cells) >= 2:
                name = cells[0].strip("`").strip()
                trigger = cells[1]
                if name and not name.startswith("_"):
                    out.append((name, trigger))
        else:
            if in_table and not s:
                in_table = False
    return out

def _write_template_recommendations(scratch: Path, skill_index: Path,
                                    lang: str, pipeline: str) -> str:
    try:
        if not skill_index.exists():
            _write_text(scratch / "template_recommendations.md",
                        "# Template Recommendations\n\n[LLM TO ENRICH] skill-index.md not found.\n")
            return "STUB"
        text = _read_text(skill_index)
        sections: List[Tuple[str, List[Tuple[str, str]]]] = []
        if pipeline == "l1":
            sections.append(("L1 Skills", _extract_skill_table(text, "## L1 Skills")))
        else:
            h = _LANG_HEADING.get(lang)
            if h:
                sections.append((f"{lang.upper()} Skills", _extract_skill_table(text, h)))
            sections.append(("Injectable Skills", _extract_skill_table(text, "## Injectable Skills")))
            sections.append(("Niche Agents", _extract_skill_table(text, "## Niche Agents")))

        lines = [
            "# Template Recommendations", "",
            "[LLM TO ENRICH] Pre-pass stub. Every row below is `Required=NO` by default.",
            "LLM recon MUST flip `Required` to **YES** for skills whose trigger pattern",
            "matches this codebase, and add rationale.", "",
            "## BINDING MANIFEST", "",
        ]
        for name, rows in sections:
            lines += [f"### {name}", "",
                      "| Skill | Trigger | Required | Rationale |",
                      "|-------|---------|----------|-----------|"]
            if not rows:
                lines.append("| _(none extracted)_ | - | - | - |")
            lines.extend(f"| `{sk}` | {trig} | NO | [LLM TO ENRICH] |" for sk, trig in rows)
            lines.append("")
        _write_text(scratch / "template_recommendations.md", "\n".join(lines))
        return "STUB"
    except Exception as e:
        _write_text(scratch / "template_recommendations.md",
                    f"# Template Recommendations\n\n[LLM TO ENRICH] pre-pass failed: {e}\n")
        return "FAILED"

# SCIP bake for Rust-based SC pipelines (v2.5.0 P1)

_RUST_ANALYZER_SCIP_TIMEOUT = 180  # seconds
# Go SCIP indexing (scip-go) type-checks the whole module, so it is slower and
# more memory-heavy than rust-analyzer on a large repo (e.g. cosmos-sdk). Larger
# budget; on timeout the caller falls back to grep (non-fatal).
_SCIP_GO_TIMEOUT = 600  # seconds

_SCIP_GRAPH_ARTIFACT_NAMES = PRECISE_GRAPH_ARTIFACTS
_GRAPH_GENERATION_MANIFEST = "_mechanical_graph_generation.json"
_GRAPH_GENERATION_SCHEMA = "plamen.mechanical_graph_generation.v1"


def _provider_authority_debt(authority: dict) -> str:
    status = str(authority.get("authority_status") or "INVALID")
    reason = re.sub(
        r"\s+",
        " ",
        str(authority.get("reason") or "provider identity is not authoritative"),
    ).strip()
    return f"TOOLCHAIN_AUTHORITY_DEBT:{status}:{reason[:180]}"


def _graph_provider_ref(authority: Optional[dict]) -> str:
    authority = authority if isinstance(authority, dict) else {}
    safe = {
        key: authority[key]
        for key in (
            "tool_id",
            "authority_status",
            "deterministic_provider_authority",
            "authority_digest",
            "toolchain_version_lock_sha256",
            "toolchain_governance_sha256",
            "reason",
        )
        if key in authority
        and isinstance(authority[key], (str, int, float, bool, type(None)))
    }
    return json.dumps(safe, sort_keys=True, separators=(",", ":"))


def _record_precise_graph_outcome(
    scratch: Path,
    *,
    capability_id: str,
    tool: str,
    status: str,
    authority: Optional[dict] = None,
    context: Optional[dict] = None,
    upstream_outcomes: Iterable[dict] = (),
) -> None:
    """Durably record precise-graph success/debt without halting fallback."""
    normalized = str(status or "FAILED:empty provider status")
    provider_ref = _graph_provider_ref(authority)
    completed = normalized == "REUSED" or normalized.startswith("WRITTEN")
    authoritative = (
        isinstance(authority, dict)
        and authority.get("deterministic_provider_authority") is True
    )
    if completed and authoritative:
        try:
            envelope = build_context_bound_tool_outcome_envelope(
                Path(scratch),
                capability_id=capability_id,
                tool=tool,
                authority=authority,
                context=context or {},
                artifacts=_SCIP_GRAPH_ARTIFACT_NAMES,
                upstream_outcomes=upstream_outcomes,
            )
            outcome = ToolOutcome.succeeded(
                capability_id,
                tool,
                0,
                artifacts=_SCIP_GRAPH_ARTIFACT_NAMES,
                provider_ref=json.dumps(
                    envelope,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
            )
        except (OSError, ToolCoverageLedgerError, TypeError, ValueError) as exc:
            normalized = (
                "FAILED:TOOLCHAIN_OUTCOME_AUTHORITY_DEBT:"
                f"{type(exc).__name__}:{exc}"
            )
            outcome = ToolOutcome.debt(
                capability_id,
                tool,
                ToolOutcomeState.FAILED,
                normalized,
                provider_ref=provider_ref,
            )
    else:
        if completed and not authoritative:
            authority_status = str(
                (authority or {}).get("authority_status")
                or "INVALID"
            )
            normalized = (
                "FAILED:TOOLCHAIN_AUTHORITY_DEBT:"
                f"{authority_status}:provider completed without replayed "
                "deterministic authority"
            )
        unavailable = (
            normalized.startswith("SKIPPED")
            and (
                "not found" in normalized
                or "not importable" in normalized
                or "TOOLCHAIN_AUTHORITY_DEBT" in normalized
            )
        )
        state = (
            ToolOutcomeState.UNAVAILABLE
            if unavailable
            else ToolOutcomeState.SKIPPED
            if normalized.startswith("SKIPPED")
            else ToolOutcomeState.FAILED
        )
        outcome = ToolOutcome.debt(
            capability_id,
            tool,
            state,
            normalized,
            provider_ref=provider_ref,
        )
    try:
        record_tool_outcome(Path(scratch), outcome)
    except Exception as exc:
        marker = Path(scratch) / "tool_coverage_ledger_repair_required.md"
        existing = _read_text(marker).rstrip()
        line = (
            f"- `{capability_id}`: graph coverage receipt write failed "
            f"({type(exc).__name__}: {exc})"
        )
        body = (
            existing + "\n" + line + "\n"
            if existing
            else "# Tool Coverage Ledger Repair Required\n\n" + line + "\n"
        )
        _write_text(marker, body)


def _scip_bake_is_fresh(scratch: Path, proj: Path, index_path: Path,
                        suffixes: Tuple[str, ...]) -> bool:
    """L1-8: freshness/reuse guard shared by the Rust and Go SCIP bakers.

    True when a previously-baked SCIP index, the human-readable graph artifacts,
    and the current typed machine graph already
    exist on disk and are at least as new as every in-scope production source
    file. Lets a caller skip the (180s-600s) indexer subprocess entirely when
    nothing changed since the last bake — collapsing the double-bake this
    guards against (Path A pre-breadth hook + Path B bake phase both invoking
    the same baker in one audit run). Bounded scan via `_production_source_files`
    (skips vendor/mock/test/lib dirs) keeps this cheap even on large repos.

    Never raises: any stat()/scan error is treated as "not fresh" so the caller
    falls through to a normal rebuild.
    """
    try:
        if not index_path.exists():
            return False
        index_mtime = index_path.stat().st_mtime
        for name in _SCIP_GRAPH_ARTIFACT_NAMES:
            art = scratch / name
            if not art.exists() or art.stat().st_size == 0:
                return False
            if art.stat().st_mtime < index_mtime:
                return False
        # A pre-migration graph is temporally fresh but semantically stale: it
        # drops SCIP signatures and can collapse overloads.  Do not reuse it as
        # though the new provider contract had run.
        graph_path = scratch / "_mechanical_graph.json"
        if graph_path.stat().st_size > 64 * 1024 * 1024:
            return False
        graph = json.loads(graph_path.read_text(encoding="utf-8", errors="strict"))
        if graph.get("function_signature_schema") != "plamen.function_signature_fact.v1":
            return False
        from enumeration_type_ir import validate_function_signature_fact

        functions = graph.get("functions")
        signatures = graph.get("function_signatures")
        if not isinstance(functions, dict) or not isinstance(signatures, dict):
            return False
        if set(functions) != set(signatures):
            return False
        live_source_digests: dict[str, str] = {}
        for identity, row in functions.items():
            if not isinstance(row, dict):
                return False
            fact = row.get("signature_fact")
            if not isinstance(fact, dict) or fact != signatures.get(identity):
                return False
            if fact.get("schema") != "plamen.function_signature_fact.v1":
                return False
            if validate_function_signature_fact(fact):
                return False
            if str(fact.get("function_identity") or "") != str(identity):
                return False
            expected_ecosystem = (
                "go" if "go" in index_path.name.lower() else "rust"
            )
            if str(fact.get("ecosystem") or "").strip().lower() != expected_ecosystem:
                return False
            if str(fact.get("provider") or "").strip().lower() != f"scip-{expected_ecosystem}":
                return False
            binding = (
                fact.get("source_binding")
                if isinstance(fact.get("source_binding"), dict)
                else {}
            )
            if str(binding.get("status") or "") == "EXACT":
                bound_digest = str(binding.get("source_sha256") or "").lower()
                bound_path = str(binding.get("path") or "")
                if bound_path not in live_source_digests:
                    live_source_digests[bound_path] = _normalized_source_sha256(
                        proj, bound_path
                    )
                live_digest = live_source_digests[bound_path]
                if not live_digest or live_digest != bound_digest:
                    return False
        for f in _production_source_files(proj, suffixes):
            try:
                if f.stat().st_mtime > index_mtime:
                    return False
            except OSError:
                continue
        return True
    except Exception:
        return False


def _bake_rust_scip(
    scratch: Path,
    proj: Path,
    *,
    context: Optional[dict] = None,
) -> str:
    """Run `rust-analyzer scip` on a Rust project and generate graph artifacts.

    Produces caller_map.md, callee_map.md, state_write_map.md, function_summary.md
    from the SCIP index — the same artifacts depth agents expect.

    Returns status string: WRITTEN | REUSED | SKIPPED | FAILED:{reason}
    """
    if not shutil.which("rust-analyzer"):
        return "SKIPPED:rust-analyzer not found"
    cargo_toml = proj / "Cargo.toml"
    if not cargo_toml.exists():
        return "SKIPPED:no Cargo.toml"

    authority = _capture_command_provider_authority(
        "rust-analyzer",
        ("rust-analyzer", "--version"),
        project_root=proj,
    )
    if authority.get("deterministic_provider_authority") is not True:
        return "SKIPPED:" + _provider_authority_debt(authority)
    resolved_provider = str(authority["resolved_executable"])

    index_path = scratch / "scip_rust.index"

    # L1-8: reuse a fresh prior bake instead of re-running the 180s indexer.
    try:
        if _scip_bake_is_fresh(scratch, proj, index_path, (".rs",)):
            return "REUSED"
    except Exception:
        pass

    # Run rust-analyzer scip (hang-proof: temp-file drain + tree-kill — a
    # rust-analyzer worker grandchild can no longer deadlock the parent).
    rc, _out = _run_hardened(
        [
            resolved_provider,
            "scip",
            str(proj),
            "--exclude-vendored-libraries",
        ],
        proj, _RUST_ANALYZER_SCIP_TIMEOUT,
    )
    if rc == 124:
        return f"FAILED:timeout after {_RUST_ANALYZER_SCIP_TIMEOUT}s"
    if rc == 127:
        return "SKIPPED:rust-analyzer not found"
    # rust-analyzer scip writes index.scip in the project root
    ra_index = proj / "index.scip"
    if rc != 0:
        return f"FAILED:rust-analyzer scip exit {rc}"
    if not ra_index.exists() or ra_index.stat().st_size < 100:
        return "FAILED:index.scip not produced or empty"
    try:
        shutil.move(str(ra_index), str(index_path))
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"

    if not _provider_authority_replays(authority, project_root=proj):
        index_path.unlink(missing_ok=True)
        return "FAILED:TOOLCHAIN_AUTHORITY_DEBT:IDENTITY_DRIFT_AFTER_EXECUTION"

    # Convert SCIP index to graph artifacts
    return _scip_to_graph_artifacts(
        scratch,
        index_path,
        proj,
        ecosystem="rust",
        context=context,
    )


def _bake_go_scip(
    scratch: Path,
    proj: Path,
    *,
    context: Optional[dict] = None,
) -> str:
    """Run `scip-go` on a Go module and generate the graph artifacts.

    Mirrors ``_bake_rust_scip``: produces caller_map.md, callee_map.md,
    state_write_map.md, function_summary.md from the SCIP index — the same
    artifacts depth agents expect. SCIP is a language-agnostic protobuf, so
    ``_scip_to_graph_artifacts`` parses a Go index identically to a Rust one.

    Returns status string: WRITTEN | REUSED | SKIPPED | FAILED:{reason}
    """
    if not shutil.which("scip-go"):
        return "SKIPPED:scip-go not found"
    if not shutil.which("go"):
        return "SKIPPED:go toolchain not found"
    go_mod = proj / "go.mod"
    if not go_mod.exists():
        return "SKIPPED:no go.mod"

    authority = _capture_command_provider_authority(
        "scip-go",
        ("scip-go", "--version"),
        project_root=proj,
    )
    if authority.get("deterministic_provider_authority") is not True:
        return "SKIPPED:" + _provider_authority_debt(authority)
    resolved_provider = str(authority["resolved_executable"])
    index_path = scratch / "scip_go.index"

    # L1-8: reuse a fresh prior bake instead of re-running the 600s indexer.
    try:
        if _scip_bake_is_fresh(scratch, proj, index_path, (".go",)):
            return "REUSED"
    except Exception:
        pass

    # scip-go writes the output (default index.scip) into its working dir; pin it
    # explicitly so we never collide with a checked-in index.scip in the repo.
    ra_index = proj / "_plamen_scip_go.index"
    try:
        # Hang-proof: temp-file drain + tree-kill (scip-go spawns `go`
        # subprocesses whose grandchildren can no longer wedge the parent).
        rc, _out = _run_hardened(
            [resolved_provider, "--quiet", "--output", str(ra_index)],
            proj, _SCIP_GO_TIMEOUT,
        )
        if rc == 124:
            return f"FAILED:timeout after {_SCIP_GO_TIMEOUT}s"
        if rc == 127:
            return "SKIPPED:scip-go not found"
        if rc != 0:
            return f"FAILED:scip-go exit {rc}"
        if not ra_index.exists() or ra_index.stat().st_size < 100:
            return "FAILED:scip-go index not produced or empty"
        shutil.move(str(ra_index), str(index_path))
        if not _provider_authority_replays(
            authority, project_root=proj
        ):
            index_path.unlink(missing_ok=True)
            return (
                "FAILED:TOOLCHAIN_AUTHORITY_DEBT:"
                "IDENTITY_DRIFT_AFTER_EXECUTION"
            )
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"
    finally:
        # Clean up a partial index file if the move never happened.
        try:
            if ra_index.exists():
                ra_index.unlink()
        except Exception:
            pass

    # Convert SCIP index to graph artifacts (language-agnostic reader)
    return _scip_to_graph_artifacts(
        scratch,
        index_path,
        proj,
        ecosystem="go",
        context=context,
    )


# F1 (recall): mechanical Solidity reference graph via Slither. EVM is the only
# SC family with NO mechanical graph today (its caller/state maps are LLM-
# transcribed). This bakes a deterministic state_read_map / state_write_map /
# caller_map + a machine `_mechanical_graph.json` (the coverage-gate's
# authoritative, LLM-unclobberable source) from Slither's data-flow analysis —
# mirroring _bake_rust_scip for the SCIP ecosystems. Best-effort: returns
# SKIPPED/FAILED on any problem so the caller falls back to the LLM maps.
_SLITHER_GRAPH_TIMEOUT = 300


def _write_mechanical_graph_json(scratch: Path, source: str,
                                 var_refs: dict, functions: dict) -> bool:
    """Write the UNIFIED `_mechanical_graph.json` every provider emits and the
    coverage gate (G2) reads — ecosystem-agnostic, LLM-unclobberable.

    var_refs:   { "<qualified var>": {"bare": str, "refs": ["<descriptor>", ...],
                                       "declaration_locus": str (optional),
                                       "read_sites": [...], "write_sites": [...] (optional)} }
    functions:  { "<qualified fn>":  {"bare": str, "loc": str, "callers": ["<descriptor>", ...],
                                      "callees": ["<descriptor>", ...] (optional, provider-dependent)} }

    A "descriptor" is a string the agent's finding prose can be matched against
    (a bare function/variable name, optionally with a `(file:line)` suffix). Each
    provider fills these from its native graph (Slither: function names; SCIP:
    locations; Move/DAML: function/choice names)."""
    import json
    try:
        # P0-AB: all providers now project the same typed state-symbol schema.
        # Keep ``var_refs`` unchanged for established enumeration consumers.
        # The typed projection never upgrades weak provider evidence: a SCIP or
        # source-parser row with only generic refs remains REFERENCE_ONLY.
        from state_symbol_authority import GRAPH_SCHEMA, build_typed_state_symbols
        from enumeration_type_ir import (
            FUNCTION_SIGNATURE_SCHEMA,
            build_fallback_signature_fact,
            normalize_source_binding_path,
        )

        ecosystem_by_source = {
            "slither": "sol",
            "evm-source": "sol",
            "scip-rust": "rust",
            "scip-go": "go",
            "rust-source": "rust",
            "go-source": "go",
            "move": "move",
            "move-source": "move",
            "daml": "daml",
        }
        normalized_functions: dict = {}
        for identity, raw_row in (functions or {}).items():
            if not isinstance(raw_row, dict):
                normalized_functions[identity] = raw_row
                continue
            row = dict(raw_row)
            fact = row.get("signature_fact")
            if not isinstance(fact, dict):
                loc = str(row.get("loc") or "")
                match = re.match(r"^(.*?):L?(\d+)$", loc)
                source_path = normalize_source_binding_path(
                    match.group(1) if match else loc
                )
                source_line = int(match.group(2)) if match else 0
                provider_name = str(source or "").lower()
                fact = build_fallback_signature_fact(
                    function_identity=str(identity),
                    bare_name=str(row.get("bare") or str(identity).split(".")[-1]),
                    provider=provider_name,
                    source_path=source_path,
                    source_line=source_line,
                    ecosystem=ecosystem_by_source.get(provider_name, ""),
                )
                row["signature_fact"] = fact
            normalized_functions[identity] = row

        (scratch / "_mechanical_graph.json").write_text(
            json.dumps({
                "schema_version": GRAPH_SCHEMA,
                "function_signature_schema": FUNCTION_SIGNATURE_SCHEMA,
                "source": source,
                "state_symbols": build_typed_state_symbols(source, var_refs),
                "var_refs": var_refs,
                "functions": normalized_functions,
                "function_signatures": {
                    identity: row.get("signature_fact", {})
                    for identity, row in normalized_functions.items()
                    if isinstance(row, dict)
                },
            }, indent=1),
            encoding="utf-8")
        return True
    except Exception as e:
        log.warning("[mechanical_graph] json write failed (%s): %s", source, e)
        return False


def _normalized_source_sha256(project: Path, relative_path: str) -> str:
    """Hash UTF-8 source with universal newline normalization.

    The graph consumer reads text the same way, so an LF and CRLF checkout have
    the same exact binding while a semantic source change still invalidates it.
    Paths escaping the project root fail closed to an empty digest.
    """
    try:
        from enumeration_type_ir import normalize_source_binding_path

        root = Path(project).resolve()
        candidate = (root / Path(normalize_source_binding_path(relative_path))).resolve()
        candidate.relative_to(root)
        text = candidate.read_text(encoding="utf-8", errors="replace")
        return hashlib.sha256(text.encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _slither_fn_loc(f, proj: Path) -> str:
    try:
        sm = f.source_mapping
        short = getattr(getattr(sm, "filename", None), "short", "") or ""
        line = (sm.lines[0] if getattr(sm, "lines", None) else 0)
        return f"{short}:L{line}" if short else f"?:L{line}"
    except Exception:
        return "?:L0"


def _slither_project_relative_path(f, proj: Path, build_root: Path) -> str:
    """Resolve Slither's filename metadata into the audited project namespace."""
    try:
        from enumeration_type_ir import normalize_source_binding_path

        mapping = f.source_mapping
        filename = getattr(mapping, "filename", None)
        short = str(getattr(filename, "short", "") or "")
        absolute = str(getattr(filename, "absolute", "") or "")
        project_root = Path(proj).resolve()
        candidates: list[Path] = []
        if absolute:
            candidates.append(Path(absolute))
        if short:
            candidates.extend((project_root / short, Path(build_root).resolve() / short))
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
                relative = resolved.relative_to(project_root)
                if resolved.is_file():
                    return normalize_source_binding_path(relative.as_posix())
            except Exception:
                continue
        return normalize_source_binding_path(short)
    except Exception:
        return ""


def _slither_item_is_production_source(
    item, proj: Path, build_root: Path, *, fallback_contract=None,
) -> bool:
    """Fail closed unless a Slither item is bound to audited source.

    Slither may compile a wider Foundry/Hardhat build root than ``proj``. Its
    graph must still obey the snapshot/recon production-source boundary, so a
    preserved fuzz harness or dependency cannot prime a fresh audit.
    """
    candidates = [item]
    if fallback_contract is not None and fallback_contract is not item:
        candidates.append(fallback_contract)
    for candidate_item in candidates:
        relative = _slither_project_relative_path(
            candidate_item, proj, build_root
        )
        if not relative:
            continue
        try:
            root = Path(proj).resolve()
            candidate = (root / Path(relative)).resolve()
            candidate.relative_to(root)
            if candidate.is_file() and is_production_source_path(candidate, root):
                return True
        except (OSError, RuntimeError, ValueError):
            continue
    return False


def _slither_contract_is_production_source(
    contract, proj: Path, build_root: Path,
) -> bool:
    """Bind a contract through its own mapping or a declared member mapping."""
    if _slither_item_is_production_source(contract, proj, build_root):
        return True
    members = tuple(getattr(contract, "functions_declared", []) or ()) + tuple(
        getattr(contract, "state_variables_declared", []) or ()
    )
    return any(
        _slither_item_is_production_source(member, proj, build_root)
        for member in members
    )


def _slither_state_var_loc(variable, proj: Path) -> str:
    """Best-effort declaration locus for a Slither state variable."""
    try:
        sm = variable.source_mapping
        short = getattr(getattr(sm, "filename", None), "short", "") or ""
        line = sm.lines[0] if getattr(sm, "lines", None) else 0
        return f"{short}:L{line}" if short else f"?:L{line}"
    except Exception:
        return ""


def _bake_evm_slither_graph(scratch: Path, proj: Path) -> str:
    """Run Slither on a Solidity project and emit MECHANICAL graph artifacts.

    Produces `_mechanical_graph.json` (gate source) + state_read_map.md /
    state_write_map.md / caller_map.md (depth-agent inputs), all stamped
    `Source: slither`. Best-effort: returns WRITTEN | SKIPPED:{r} | FAILED:{r};
    on anything other than WRITTEN the caller keeps the LLM-derived maps.
    """
    import json
    authority = _capture_python_provider_authority(
        "slither", project_root=proj
    )
    if authority.get("deterministic_provider_authority") is not True:
        return "SKIPPED:" + _provider_authority_debt(authority)
    try:
        import slither as slither_module  # type: ignore
        from slither import Slither  # type: ignore
    except Exception as e:
        return f"SKIPPED:slither not importable ({e.__class__.__name__})"
    try:
        if (
            Path(str(slither_module.__file__)).resolve(strict=True)
            != Path(str(authority["module_origin"])).resolve(strict=True)
        ):
            return (
                "SKIPPED:TOOLCHAIN_AUTHORITY_DEBT:"
                "MODULE_ORIGIN_DRIFT"
            )
    except (KeyError, OSError, TypeError, ValueError):
        return "SKIPPED:TOOLCHAIN_AUTHORITY_DEBT:MODULE_ORIGIN_UNBOUND"
    if not any(proj.rglob("*.sol")):
        return "SKIPPED:no .sol sources"

    # Slither/crytic-compile auto-detects foundry.toml / hardhat / single dir,
    # but only at the directory it is pointed at. The audit scope is often a
    # source subdir (`.../smart-contracts/src`) while foundry.toml + remappings
    # + lib live at the Foundry root above it — point Slither at the resolved
    # ROOT so the project's own remappings resolve every @import (otherwise every
    # import fails and the precise graph is lost to the approximate fallback).
    # Compilation can still fail for many reasons (solc version, missing deps) —
    # that is a graceful SKIP to the LLM maps, never a halt.
    slither_target = _resolve_evm_build_root(proj) or proj
    # Honor the same single-non-default FOUNDRY_PROFILE the recon build uses so
    # Slither (crytic-compile reads the env) compiles a profile-gated project.
    # Restore the prior env afterward — never leak into other subprocesses.
    _prof = _resolve_foundry_profile_for_recon(Path(slither_target))
    _prev_prof = os.environ.get("FOUNDRY_PROFILE")
    if _prof:
        os.environ["FOUNDRY_PROFILE"] = _prof
    import io
    import contextlib
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            sl = Slither(str(slither_target))
    except Exception as e:
        return f"FAILED:slither compile ({str(e)[:140].replace(chr(10), ' ')})"
    finally:
        if _prof:
            if _prev_prof is None:
                os.environ.pop("FOUNDRY_PROFILE", None)
            else:
                os.environ["FOUNDRY_PROFILE"] = _prev_prof

    production_contracts = [
        contract
        for contract in sl.contracts
        if _slither_contract_is_production_source(
            contract, proj, Path(slither_target)
        )
    ]

    fn_loc: Dict[str, str] = {}
    var_readers: Dict[str, set] = {}
    var_writers: Dict[str, set] = {}
    var_read_sites: Dict[str, set] = {}
    var_write_sites: Dict[str, set] = {}
    var_declarations: Dict[str, str] = {}
    fn_callees: Dict[str, set] = {}     # qualified fn -> set(qualified callee)
    bare_of: Dict[str, str] = {}        # qualified -> bare name
    fn_signature_facts: Dict[str, dict] = {}
    try:
        from collections import Counter
        from enumeration_type_ir import build_function_signature_fact

        provider_functions = [
            (c, f)
            for c in production_contracts
            if not getattr(c, "is_interface", False)
            for f in (getattr(c, "functions_declared", []) or [])
            if (getattr(f, "name", "") or "")
            and _slither_item_is_production_source(
                f, proj, Path(slither_target), fallback_contract=c
            )
        ]
        base_counts = Counter(
            (str(getattr(c, "name", "")), str(getattr(f, "name", "")))
            for c, f in provider_functions
        )
        fn_key_by_object: Dict[int, str] = {}
        assigned_keys: set[str] = set()
        for contract, function in provider_functions:
            contract_name = str(getattr(contract, "name", ""))
            function_name = str(getattr(function, "name", ""))
            base_key = f"{contract_name}.{function_name}"
            key = base_key
            if base_counts[(contract_name, function_name)] > 1:
                canonical = str(
                    getattr(function, "canonical_name", "")
                    or getattr(function, "full_name", "")
                    or getattr(function, "solidity_signature", "")
                ).strip()
                if canonical and canonical.startswith(f"{contract_name}."):
                    key = canonical
                elif canonical:
                    key = f"{contract_name}.{canonical}"
                else:
                    loc = _slither_fn_loc(function, proj)
                    key = f"{base_key}@{loc}"
            if key in assigned_keys:
                discriminator = hashlib.sha256(
                    (
                        key + "\x1f" + _slither_fn_loc(function, proj)
                        + "\x1f" + str(getattr(function, "solidity_signature", ""))
                    ).encode("utf-8")
                ).hexdigest()[:12]
                key = f"{key}#{discriminator}"
            assigned_keys.add(key)
            fn_key_by_object[id(function)] = key

        def _parameter_declaration(parameter) -> str:
            type_name = str(getattr(parameter, "type", "") or "").strip()
            name = str(getattr(parameter, "name", "") or "").strip()
            return " ".join(part for part in (type_name, name) if part)

        def _function_mutability(function) -> str:
            direct = str(getattr(function, "state_mutability", "") or "").strip()
            if direct:
                return direct
            # These are Slither provider booleans, not source-text guesses.
            if bool(getattr(function, "pure", False)):
                return "pure"
            if bool(getattr(function, "view", False)):
                return "view"
            if bool(getattr(function, "payable", False)):
                return "payable"
            return "nonpayable"

        def _callee_key(callee, default_contract: str) -> str:
            exact = fn_key_by_object.get(id(callee))
            if exact:
                return exact
            name = str(getattr(callee, "name", "") or "")
            contract_name = str(
                getattr(getattr(callee, "contract", None), "name", "")
                or default_contract
            )
            return f"{contract_name}.{name}" if name else ""

        for c in production_contracts:
            if getattr(c, "is_interface", False):
                continue
            # Include declaration-only/constructor-only immutables too.  A
            # state inventory must not depend on a non-constructor reader or
            # writer existing in the current compilation unit.
            for v in getattr(c, "state_variables_declared", []) or []:
                if not _slither_item_is_production_source(
                    v, proj, Path(slither_target), fallback_contract=c
                ):
                    continue
                name = getattr(v, "name", "") or ""
                if not name:
                    continue
                vk = f"{getattr(getattr(v, 'contract', None), 'name', c.name)}.{name}"
                bare_of[vk] = name
                var_declarations.setdefault(vk, _slither_state_var_loc(v, proj))
            for f in getattr(c, "functions_declared", []) or []:
                if not _slither_item_is_production_source(
                    f, proj, Path(slither_target), fallback_contract=c
                ):
                    continue
                fname = getattr(f, "name", "") or ""
                if not fname:
                    continue
                fkey = fn_key_by_object.get(id(f), f"{c.name}.{fname}")
                bare_of[fkey] = fname
                raw_function_loc = _slither_fn_loc(f, proj)
                loc_match = re.match(r"^(.*?):L?(\d+)$", raw_function_loc)
                source_line = int(loc_match.group(2)) if loc_match else 0
                relative_path = _slither_project_relative_path(
                    f, proj, Path(slither_target)
                ) or (loc_match.group(1) if loc_match else raw_function_loc)
                function_loc = f"{relative_path}:L{source_line}"
                fn_loc.setdefault(fkey, function_loc)
                raw_parameters = ", ".join(
                    value for value in (
                        _parameter_declaration(parameter)
                        for parameter in (getattr(f, "parameters", []) or [])
                    ) if value
                )
                raw_returns = ", ".join(
                    value for value in (
                        _parameter_declaration(parameter)
                        for parameter in (getattr(f, "returns", []) or [])
                    ) if value
                )
                raw_signature = str(
                    getattr(f, "canonical_name", "")
                    or getattr(f, "full_name", "")
                    or getattr(f, "solidity_signature", "")
                    or fname
                )
                fn_signature_facts[fkey] = build_function_signature_fact(
                    ecosystem="sol",
                    provider="slither",
                    function_identity=fkey,
                    bare_name=fname,
                    provider_symbol=str(
                        getattr(f, "canonical_name", "")
                        or getattr(f, "full_name", "")
                        or fkey
                    ),
                    raw_signature=raw_signature,
                    raw_parameters=raw_parameters,
                    source_path=relative_path,
                    source_line=source_line,
                    source_sha256=_normalized_source_sha256(proj, relative_path),
                    kind=str(getattr(f, "function_type", "") or "Function"),
                    visibility=str(getattr(f, "visibility", "") or ""),
                    mutability=_function_mutability(f),
                    returns=raw_returns,
                )
                for v in getattr(f, "state_variables_read", []) or []:
                    if not _slither_item_is_production_source(
                        v, proj, Path(slither_target),
                        fallback_contract=getattr(v, "contract", c),
                    ):
                        continue
                    vk = f"{getattr(v.contract, 'name', c.name)}.{v.name}"
                    bare_of[vk] = v.name
                    var_declarations.setdefault(vk, _slither_state_var_loc(v, proj))
                    var_readers.setdefault(vk, set()).add(fkey)
                for v in getattr(f, "state_variables_written", []) or []:
                    if not _slither_item_is_production_source(
                        v, proj, Path(slither_target),
                        fallback_contract=getattr(v, "contract", c),
                    ):
                        continue
                    vk = f"{getattr(v.contract, 'name', c.name)}.{v.name}"
                    bare_of[vk] = v.name
                    var_declarations.setdefault(vk, _slither_state_var_loc(v, proj))
                    var_writers.setdefault(vk, set()).add(fkey)
                # Slither nodes retain the actual access locus.  Use those
                # reference sites for exact P0-AB citation binding; function
                # declarations remain only a compatibility fallback.
                for node in getattr(f, "nodes", []) or []:
                    node_locus = _slither_fn_loc(node, proj)
                    for v in getattr(node, "state_variables_read", []) or []:
                        if not _slither_item_is_production_source(
                            v, proj, Path(slither_target),
                            fallback_contract=getattr(v, "contract", c),
                        ):
                            continue
                        vk = f"{getattr(getattr(v, 'contract', None), 'name', c.name)}.{v.name}"
                        var_read_sites.setdefault(vk, set()).add(node_locus)
                    for v in getattr(node, "state_variables_written", []) or []:
                        if not _slither_item_is_production_source(
                            v, proj, Path(slither_target),
                            fallback_contract=getattr(v, "contract", c),
                        ):
                            continue
                        vk = f"{getattr(getattr(v, 'contract', None), 'name', c.name)}.{v.name}"
                        var_write_sites.setdefault(vk, set()).add(node_locus)
                for ic in (getattr(f, "internal_calls", []) or []):
                    callee = getattr(ic, "function", ic)
                    if not _slither_item_is_production_source(
                        callee, proj, Path(slither_target),
                        fallback_contract=getattr(callee, "contract", None),
                    ):
                        continue
                    callee_key = _callee_key(callee, c.name)
                    if callee_key:
                        fn_callees.setdefault(fkey, set()).add(callee_key)
                for hc in (getattr(f, "high_level_calls", []) or []):
                    # high_level_calls entries are (Contract, Function) tuples or objects
                    callee = None
                    if isinstance(hc, (tuple, list)) and len(hc) >= 2:
                        callee = hc[1]
                    callee = getattr(callee, "function", callee)
                    if callee is not None and not _slither_item_is_production_source(
                        callee, proj, Path(slither_target),
                        fallback_contract=getattr(callee, "contract", None),
                    ):
                        continue
                    callee_key = _callee_key(callee, "") if callee is not None else ""
                    if callee_key:
                        fn_callees.setdefault(fkey, set()).add(callee_key)
    except Exception as e:
        return f"FAILED:slither walk ({e.__class__.__name__})"

    # Invert callees -> direct callers.
    fn_callers: Dict[str, set] = {}
    for caller, callees in fn_callees.items():
        for callee in callees:
            fn_callers.setdefault(callee, set()).add(caller)

    if not fn_loc:
        return "FAILED:no functions extracted"

    def _bare(k: str) -> str:
        return bare_of.get(k, k.split(".")[-1])

    def _desc(keys: set) -> list:
        # descriptor = bare function name (what agents cite) + location
        return sorted(f"{_bare(k)} ({fn_loc.get(k, '?')})" for k in keys)

    def _with_loc(keys: set) -> list:
        return _desc(keys)

    # Unified machine artifact (gate-authoritative; LLM never writes this).
    var_refs = {}
    for vk in set(var_declarations) | set(var_readers) | set(var_writers):
        refs = var_readers.get(vk, set()) | var_writers.get(vk, set())
        precise_reads = sorted(var_read_sites.get(vk, set()))
        precise_writes = sorted(var_write_sites.get(vk, set()))
        has_precise_refs = bool(precise_reads or precise_writes)
        var_refs[vk] = {
            "bare": _bare(vk),
            "declaration_locus": var_declarations.get(vk, ""),
            "read_sites": precise_reads or _desc(var_readers.get(vk, set())),
            "write_sites": precise_writes or _desc(var_writers.get(vk, set())),
            "refs": sorted(set(
                precise_reads + precise_writes + _desc(refs)
            )),
            "confidence": (
                "AST_REFERENCE_SITE" if has_precise_refs
                else "AST_FUNCTION_SCOPE_REFERENCE" if refs
                else "AST_DECLARATION_ONLY"
            ),
        }
    functions = {
        fk: {"bare": _bare(fk), "loc": fn_loc.get(fk, "?"),
             "callers": sorted(_bare(ck) for ck in fn_callers.get(fk, set())),
             "callees": sorted(_bare(ck) for ck in fn_callees.get(fk, set())),
             "signature_fact": fn_signature_facts.get(fk, {})}
        for fk in fn_loc
    }
    if not _provider_authority_replays(authority, project_root=proj):
        return (
            "FAILED:TOOLCHAIN_AUTHORITY_DEBT:"
            "IDENTITY_DRIFT_AFTER_EXECUTION"
        )
    if not _write_mechanical_graph_json(
        scratch,
        "slither",
        var_refs,
        functions,
    ):
        return "FAILED:ARTIFACT_STAGE:mechanical graph JSON write failed"

    # Human-readable maps (depth-agent inputs), stamped mechanical.
    def _emit_var_map(filename: str, title: str, data: Dict[str, set], col: str):
        lines = [f"# {title}", "",
                 f"> **Status**: POPULATED / **Source**: slither (mechanical data-flow).",
                 f"> {len(data)} state variable(s).", "",
                 f"| State Variable | {col} (function @ file:line) |",
                 "|----------------|-------------------------------|"]
        for v in sorted(data):
            lines.append(f"| `{v}` | {', '.join(_with_loc(data[v])) or '_(none)_'} |")
        _write_text(scratch / filename, "\n".join(lines) + "\n")

    _emit_var_map("state_read_map.md", "State Read Map", var_readers, "Readers")
    _emit_var_map("state_write_map.md", "State Write Map", var_writers, "Writers")

    cm = ["# Caller Map", "",
          "> **Status**: POPULATED / **Source**: slither (mechanical call graph).",
          f"> {len(fn_loc)} function(s).", "",
          "| Function | Direct callers (function @ file:line) |",
          "|----------|----------------------------------------|"]
    for fk in sorted(fn_loc):
        cm.append(f"| `{fk}` ({fn_loc[fk]}) | {', '.join(_with_loc(fn_callers.get(fk, set()))) or '_(none)_'} |")
    _write_text(scratch / "caller_map.md", "\n".join(cm) + "\n")

    summary = [
        "> **Status**: POPULATED",
        "> **Source**: Slither compiler/type provider",
        "",
        "# Function Summary",
        "",
        "| Function | File | Line | Kind | Visibility | Mutability | Provider Signature | Signature Authority | Callers | Callees |",
        "|----------|------|------|------|------------|------------|--------------------|---------------------|---------|---------|",
    ]
    for fk in sorted(fn_loc):
        fact = fn_signature_facts.get(fk, {})
        loc_match = re.match(r"^(.*?):L?(\d+)$", fn_loc[fk])
        path = loc_match.group(1) if loc_match else fn_loc[fk]
        line = loc_match.group(2) if loc_match else "0"
        signature = str(
            fact.get("canonical_signature") or "_(unavailable)_"
        ).replace("|", "&#124;").replace("`", "&#96;")
        summary.append(
            f"| `{fk}` | {path} | {line} | {fact.get('kind', 'Function')} "
            f"| {fact.get('visibility') or '-'} | {fact.get('mutability') or '-'} "
            f"| `{signature}` | {fact.get('authority', 'UNKNOWN')} "
            f"| {len(fn_callers.get(fk, set()))} | {len(fn_callees.get(fk, set()))} |"
        )
    _write_text(scratch / "function_summary.md", "\n".join(summary) + "\n")

    return "WRITTEN"


_EVM_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_EVM_CALL_STOP = {"if", "while", "for", "require", "assert", "revert", "return",
                  "emit", "new", "function", "modifier", "mapping", "address",
                  "uint", "int", "bool", "bytes", "string", "memory", "storage",
                  "calldata", "keccak256", "abi", "type", "payable", "this",
                  "super", "delete", "sizeof"}


def _bake_evm_source_graph(scratch: Path, proj: Path) -> str:
    """Compilation-free APPROXIMATE Solidity reference graph: function ->
    {state-var symbols it references, callees}. Mirrors the Move/DAML providers
    (same accepted approximation tier). The coverage gate keys on co-referencers
    of IN-SCOPE state symbols, all of which live in the audited source files —
    so a source parse captures the gate's required set WITHOUT resolving external
    dependencies or compiling. Used as the always-available fallback beneath the
    Slither precision tier (which needs the project to build)."""
    files = _production_source_files(proj, (".sol",))
    if not files:
        return "SKIPPED:no .sol sources"
    fn_loc: Dict[str, str] = {}
    sym_refs: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}
    try:
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            # state variables declared in this file (name -> declaration).
            state_vars = {m.group(2) for m in _EVM_STATE_RE.finditer(text)}
            decls = list(_EVM_FN_RE.finditer(text))
            for i, m in enumerate(decls):
                name = m.group(1)
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                body = text[m.end():end]
                fn_loc.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
                # which in-scope state vars does this function body mention?
                body_idents = set(_EVM_CALL_RE.findall(body)) | set(
                    re.findall(r"\b([A-Za-z_]\w*)\b", body))
                for v in state_vars:
                    if v in body_idents:
                        sym_refs.setdefault(v, set()).add(name)
                for cm in _EVM_CALL_RE.finditer(body):
                    cn = cm.group(1)
                    if cn != name and cn not in _EVM_CALL_STOP:
                        # _finalize keeps only callees that are real functions.
                        fn_callees.setdefault(name, set()).add(cn)
    except Exception as e:
        return f"FAILED:evm source parse ({e.__class__.__name__})"
    return _finalize_source_graph(scratch, "evm-source", fn_loc, sym_refs, fn_callees)


_VIA_IR_WARNED = False


def _foundry_via_ir_root(proj: Path) -> Optional[Path]:
    """Search `proj` and up to 4 parent dirs for a foundry.toml that enables the
    whole-program IR pipeline (`via_ir`/`via-ir = true` in any profile). Returns
    the owning dir, else None. Best-effort; never raises."""
    try:
        d = Path(proj).resolve()
        for cand in [d, *list(d.parents)[:4]]:
            ft = cand / "foundry.toml"
            if ft.is_file():
                txt = ft.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"(?im)^\s*via[_-]ir\s*=\s*true\b", txt):
                    return cand
    except Exception:
        pass
    return None


def _maybe_warn_via_ir_build(proj: Path) -> None:
    """One-time console heads-up before the first EVM compile when the project
    uses `--via-ir`. A COLD via-ir build of a dependency-heavy repo can run for
    tens of minutes producing no output — indistinguishable from a hang — which
    leads operators to kill a healthy run. Warn up front. Best-effort; never
    raises. Generic (no project-specific knowledge)."""
    global _VIA_IR_WARNED
    if _VIA_IR_WARNED or _foundry_via_ir_root(proj) is None:
        return
    _VIA_IR_WARNED = True
    msg = ("via-ir build detected (foundry.toml). The first COLD compile of a "
           "dependency-heavy repo can take TENS OF MINUTES with no output — this "
           "is NOT a hang; subsequent builds are incremental (seconds). Budgets "
           "are ops-overridable via PLAMEN_BUILD_TIMEOUT_CEILING_S (recon) and "
           "PLAMEN_MECH_BUILD_TIMEOUT (verify).")
    log.warning("[recon] %s", msg)
    try:
        print(f"\n[PLAMEN] NOTE: {msg}\n", file=sys.stderr, flush=True)
    except Exception:
        pass


def _bake_evm_graph(
    scratch: Path,
    proj: Path,
    *,
    context: Optional[dict] = None,
) -> str:
    """EVM graph provider with tiered degradation (never mock the compiler):
      1. Slither (PRECISE, type-resolved) when the project builds.
      2. compilation-free source parse (APPROXIMATE) otherwise — same tier the
         Move/DAML providers run at; gives the coverage gate a real (if coarser)
         reference set with zero build dependency.
    Mocking missing dependencies to force a Slither compile is deliberately NOT
    done: type-unsound stubs fabricate data-flow, which would make the gate's
    denominator untrustworthy — strictly worse than the honest approximate tier."""
    # Slither's crytic-compile triggers the first (cold) via-ir compile — warn
    # the operator before the potentially-long silent build so it isn't mistaken
    # for a hang.
    _maybe_warn_via_ir_build(proj)
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=".slither-graph-", dir=scratch)
    )
    try:
        slither = _bake_evm_slither_graph(stage, proj)
        if slither == "WRITTEN":
            publication, _evidence = (
                _validate_and_publish_graph_artifact_set(
                    stage,
                    scratch,
                )
            )
            if publication != "WRITTEN":
                slither = publication
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    slither_authority = _capture_python_provider_authority(
        "slither", project_root=proj
    )
    _record_precise_graph_outcome(
        scratch,
        capability_id="slither.evm-reference-graph",
        tool="slither",
        status=slither,
        authority=slither_authority,
        context=context,
    )
    if slither == "WRITTEN":
        return "WRITTEN:slither"
    discard_issues = _discard_committed_graph_generation(scratch)
    if discard_issues:
        return (
            "FAILED:PRECISE_GRAPH_DISCARD:"
            + ",".join(discard_issues)
        )
    fallback = _bake_evm_source_graph(scratch, proj)
    return (f"WRITTEN:evm-source (slither {slither})"
            if fallback == "WRITTEN" else f"FAILED:slither={slither}; source={fallback}")


# Move (Aptos/Sui) + DAML reference-graph providers. No mechanical indexer is
# wired for these, so these are APPROXIMATE source parsers (function/choice ->
# referenced field/resource symbols + callees). Approximate-but-present feeds the
# coverage gate where a precise graph (Slither/SCIP) is unavailable.
_MOVE_FN_DECL_RE = re.compile(
    r"\b(?:public\s*(?:\([^)]*\))?\s+)?(?:entry\s+)?fun\s+(\w+)\s*[<(]", re.MULTILINE)
_MOVE_FIELD_ACCESS_RE = re.compile(r"\.\s*([a-z_]\w*)\b")
_MOVE_BORROW_RE = re.compile(r"\bborrow_global(?:_mut)?\s*<\s*([A-Za-z_]\w*)")
_MOVE_CALL_RE = re.compile(r"\b([a-z_]\w*)\s*\(")
_MOVE_CALL_STOP = {"if", "while", "for", "assert", "let", "return", "vector",
                   "move_to", "move_from", "exists", "copy", "freeze", "abort"}


def _bake_move_graph(scratch: Path, proj: Path) -> str:
    """Approximate Move reference graph: function -> {field/resource symbols, callees}."""
    files = _production_source_files(proj, (".move",))
    if not files:
        return "SKIPPED:no .move sources"
    fn_loc: Dict[str, str] = {}
    sym_refs: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}
    try:
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            decls = list(_MOVE_FN_DECL_RE.finditer(text))
            for i, m in enumerate(decls):
                name = m.group(1)
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                body = text[m.end():end]
                fn_loc.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
                for fm in _MOVE_FIELD_ACCESS_RE.finditer(body):
                    sym_refs.setdefault(fm.group(1), set()).add(name)
                for bm in _MOVE_BORROW_RE.finditer(body):
                    sym_refs.setdefault(bm.group(1), set()).add(name)
                for cm in _MOVE_CALL_RE.finditer(body):
                    cn = cm.group(1)
                    if cn != name and cn not in _MOVE_CALL_STOP:
                        # _finalize keeps only callees that are real functions.
                        fn_callees.setdefault(name, set()).add(cn)
    except Exception as e:
        return f"FAILED:move parse ({e.__class__.__name__})"
    return _finalize_source_graph(scratch, "move", fn_loc, sym_refs, fn_callees)


_DAML_CHOICE_RE = re.compile(r"\b(?:nonconsuming\s+)?choice\s+(\w+)\b", re.MULTILINE)
_DAML_EXERCISE_RE = re.compile(r"\bexercise(?:Cmd)?\s+\w+\s+(\w+)")
_DAML_IDENT_RE = re.compile(r"\b([a-z_]\w*)\b")


def _bake_daml_graph(scratch: Path, proj: Path) -> str:
    """Approximate DAML reference graph: choice -> {field idents referenced, exercised choices}."""
    files = _production_source_files(proj, (".daml",))
    if not files:
        return "SKIPPED:no .daml sources"
    fn_loc: Dict[str, str] = {}
    sym_refs: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}
    try:
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            decls = list(_DAML_CHOICE_RE.finditer(text))
            for i, m in enumerate(decls):
                name = m.group(1)
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                body = text[m.end():end]
                fn_loc.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
                for em in _DAML_EXERCISE_RE.finditer(body):
                    fn_callees.setdefault(name, set()).add(em.group(1))
                # field/ident references (bare identifiers in the choice body) —
                # approximate: any lowercase identifier the choice mentions.
                for im in _DAML_IDENT_RE.finditer(body):
                    ident = im.group(1)
                    if len(ident) > 3 and ident not in (
                            "with", "controller", "where", "then", "else", "return",
                            "create", "exercise", "fetch", "assert", "pure", "this"):
                        sym_refs.setdefault(ident, set()).add(name)
    except Exception as e:
        return f"FAILED:daml parse ({e.__class__.__name__})"
    return _finalize_source_graph(scratch, "daml", fn_loc, sym_refs, fn_callees)


def _finalize_source_graph(scratch: Path, source: str, fn_loc: Dict[str, str],
                           sym_refs: Dict[str, set], fn_callees: Dict[str, set]) -> str:
    """Shared tail for the approximate source-parse providers (Move/DAML): invert
    callees, build the unified schema, emit `_mechanical_graph.json` + the maps."""
    if not fn_loc:
        return "FAILED:no functions/choices extracted"
    fn_callers: Dict[str, set] = {}
    for caller, callees in fn_callees.items():
        for callee in callees:
            if callee in fn_loc:
                fn_callers.setdefault(callee, set()).add(caller)
    # Drop only symbols referenced by too many functions (noise).  A symbol
    # referenced by exactly one function is still security-relevant and must
    # remain available to relation-scoped consumers; consumers own their own
    # denoising policy rather than receiving a destructively filtered graph.
    var_refs = {
        s: {
            "bare": s,
            "refs": sorted(f"{fn} ({fn_loc.get(fn, '?')})" for fn in fns),
            "confidence": "FUNCTION_SCOPE_APPROXIMATE",
        }
        for s, fns in sym_refs.items() if 0 < len(fns) <= 25
    }
    functions = {
        fn: {
            "bare": fn,
            "loc": loc,
            "callers": sorted(fn_callers.get(fn, set())),
            "callees": sorted(fn_callees.get(fn, set())),
        }
        for fn, loc in fn_loc.items()
    }
    if not _write_mechanical_graph_json(
        scratch,
        source,
        var_refs,
        functions,
    ):
        return "FAILED:ARTIFACT_STAGE:mechanical graph JSON write failed"
    return "WRITTEN"


# Rust (Solana/Soroban/L1) + Go (L1) compilation-free source-parse providers.
# These are the Tier-2 fallback BENEATH the precise SCIP bake: when SCIP is
# unavailable (no rust-analyzer / scip-go on PATH) or fails, the SCIP ecosystems
# previously dropped straight to advisory (no graph → the enumeration gate
# no-ops). These give the gate a real-if-approximate reference graph with zero
# toolchain dependency, exactly as Move/DAML/EVM-source do for their families.
_RUST_FN_DECL_RE = re.compile(
    r"\b(?:pub\s*(?:\([^)]*\)\s*)?)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(\w+)\s*[<(]", re.MULTILINE)
_RUST_FIELD_ACCESS_RE = re.compile(r"\.\s*([a-z_]\w*)\b")
_RUST_CALL_RE = re.compile(r"\b([a-z_]\w*)\s*\(")
_RUST_CALL_STOP = {
    "if", "while", "for", "match", "let", "return", "fn", "loop", "move",
    "vec", "println", "print", "eprintln", "format", "write", "writeln",
    "assert", "assert_eq", "assert_ne", "debug_assert", "panic", "unreachable",
    "unwrap", "expect", "clone", "into", "from", "to_string", "as_ref",
    "as_mut", "iter", "map", "filter", "collect", "len", "is_empty", "push",
    "pop", "insert", "remove", "get", "contains", "some", "none", "ok", "err",
    "box", "rc", "arc", "mutex", "self", "super", "drop", "default", "new",
}

_GO_FN_DECL_RE = re.compile(
    r"\bfunc\s+(?:\([^)]*\)\s*)?(\w+)\s*[<(]", re.MULTILINE)
_GO_FIELD_ACCESS_RE = re.compile(r"\.\s*([A-Za-z_]\w*)\b")
_GO_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_GO_CALL_STOP = {
    "if", "for", "switch", "select", "func", "return", "go", "defer", "range",
    "make", "new", "len", "cap", "append", "copy", "delete", "panic", "recover",
    "print", "println", "close", "var", "const", "type", "struct", "interface",
    "map", "chan", "string", "int", "error", "bool", "byte", "rune", "nil",
}


def _bake_rust_source_graph(scratch: Path, proj: Path) -> str:
    """Compilation-free APPROXIMATE Rust reference graph (Tier-2 SCIP fallback):
    function -> {struct-field/symbol references, callees}. Mirrors the Move
    provider; needs no rust-analyzer/cargo."""
    files = _production_source_files(proj, (".rs",))
    if not files:
        return "SKIPPED:no .rs sources"
    fn_loc: Dict[str, str] = {}
    sym_refs: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}
    try:
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            decls = list(_RUST_FN_DECL_RE.finditer(text))
            for i, m in enumerate(decls):
                name = m.group(1)
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                body = text[m.end():end]
                fn_loc.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
                for fm in _RUST_FIELD_ACCESS_RE.finditer(body):
                    sym_refs.setdefault(fm.group(1), set()).add(name)
                for cm in _RUST_CALL_RE.finditer(body):
                    cn = cm.group(1)
                    if cn != name and cn not in _RUST_CALL_STOP:
                        fn_callees.setdefault(name, set()).add(cn)
    except Exception as e:
        return f"FAILED:rust source parse ({e.__class__.__name__})"
    return _finalize_source_graph(scratch, "rust-source", fn_loc, sym_refs, fn_callees)


def _bake_go_source_graph(scratch: Path, proj: Path) -> str:
    """Compilation-free APPROXIMATE Go reference graph (Tier-2 SCIP fallback):
    function/method -> {struct-field/symbol references, callees}. Needs no
    scip-go/go toolchain."""
    files = _production_source_files(proj, (".go",))
    if not files:
        return "SKIPPED:no .go sources"
    fn_loc: Dict[str, str] = {}
    sym_refs: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}
    try:
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            decls = list(_GO_FN_DECL_RE.finditer(text))
            for i, m in enumerate(decls):
                name = m.group(1)
                end = decls[i + 1].start() if i + 1 < len(decls) else len(text)
                body = text[m.end():end]
                fn_loc.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
                for fm in _GO_FIELD_ACCESS_RE.finditer(body):
                    sym_refs.setdefault(fm.group(1), set()).add(name)
                for cm in _GO_CALL_RE.finditer(body):
                    cn = cm.group(1)
                    if cn != name and cn not in _GO_CALL_STOP:
                        fn_callees.setdefault(name, set()).add(cn)
    except Exception as e:
        return f"FAILED:go source parse ({e.__class__.__name__})"
    return _finalize_source_graph(scratch, "go-source", fn_loc, sym_refs, fn_callees)


def _bake_rust_graph(
    scratch: Path,
    proj: Path,
    *,
    context: Optional[dict] = None,
) -> str:
    """Tiered Rust graph (never mock): precise SCIP when the toolchain is present
    and the index builds, else the compilation-free source parse so the
    enumeration gate still has a graph. Mirrors `_bake_evm_graph`.

    Return contract (callers may see any of): REUSED:scip | WRITTEN:scip |
    WRITTEN:rust-source (scip {status}) | FAILED:scip={status}; source={status}
    """
    scip = (
        _bake_rust_scip(scratch, proj)
        if context is None
        else _bake_rust_scip(scratch, proj, context=context)
    )
    rust_authority = _capture_command_provider_authority(
        "rust-analyzer",
        ("rust-analyzer", "--version"),
        project_root=proj,
    )
    _record_precise_graph_outcome(
        scratch,
        capability_id="scip-rust.reference-graph",
        tool="rust-analyzer",
        status=scip,
        authority=rust_authority,
        context=context,
    )
    if scip == "REUSED":
        return "REUSED:scip"
    if scip.startswith("WRITTEN"):
        return "WRITTEN:scip"
    discard_issues = _discard_committed_graph_generation(scratch)
    if discard_issues:
        return (
            "FAILED:PRECISE_GRAPH_DISCARD:"
            + ",".join(discard_issues)
        )
    src = _bake_rust_source_graph(scratch, proj)
    return (f"WRITTEN:rust-source (scip {scip})"
            if src == "WRITTEN" else f"FAILED:scip={scip}; source={src}")


def _bake_go_graph(
    scratch: Path,
    proj: Path,
    *,
    context: Optional[dict] = None,
) -> str:
    """Tiered Go graph (never mock): precise SCIP when scip-go is present and the
    index builds, else the compilation-free source parse.

    Return contract (callers may see any of): REUSED:scip | WRITTEN:scip |
    WRITTEN:go-source (scip {status}) | FAILED:scip={status}; source={status}
    """
    scip = (
        _bake_go_scip(scratch, proj)
        if context is None
        else _bake_go_scip(scratch, proj, context=context)
    )
    go_authority = _capture_command_provider_authority(
        "scip-go",
        ("scip-go", "--version"),
        project_root=proj,
    )
    _record_precise_graph_outcome(
        scratch,
        capability_id="scip-go.reference-graph",
        tool="scip-go",
        status=scip,
        authority=go_authority,
        context=context,
    )
    if scip == "REUSED":
        return "REUSED:scip"
    if scip.startswith("WRITTEN"):
        return "WRITTEN:scip"
    discard_issues = _discard_committed_graph_generation(scratch)
    if discard_issues:
        return (
            "FAILED:PRECISE_GRAPH_DISCARD:"
            + ",".join(discard_issues)
        )
    src = _bake_go_source_graph(scratch, proj)
    return (f"WRITTEN:go-source (scip {scip})"
            if src == "WRITTEN" else f"FAILED:scip={scip}; source={src}")


def _scip_to_graph_artifacts_impl(
    scratch: Path, index_path: Path, proj: Path, *, ecosystem: str = ""
) -> str:
    """Convert a SCIP index into the 4 graph artifacts depth agents consume."""
    try:
        protobuf_authority = _capture_python_provider_authority(
            "protobuf",
            project_root=proj,
        )
        if (
            protobuf_authority.get("deterministic_provider_authority")
            is not True
        ):
            return "FAILED:" + _provider_authority_debt(
                protobuf_authority
            )
        sys_path_added = False
        scip_reader_dir = _plamen_home()
        if str(scip_reader_dir) not in sys.path:
            sys.path.insert(0, str(scip_reader_dir))
            sys_path_added = True
        try:
            from plamen_l1.scip_reader import ScipReader
        except ImportError:
            return "FAILED:scip_reader not importable (missing protobuf bindings?)"
        finally:
            if sys_path_added and str(scip_reader_dir) in sys.path:
                sys.path.remove(str(scip_reader_dir))

        reader = ScipReader(str(index_path))
        stats = reader.stats()

        if stats["definitions"] < 5:
            return f"FAILED:SCIP index has only {stats['definitions']} definitions"

        # Build caller/callee maps from SCIP references.  Function identities
        # are assigned only after every definition has been collected so two
        # same-name methods/functions cannot clobber each other.
        from collections import Counter
        from enumeration_type_ir import (
            build_function_signature_fact,
            normalize_source_binding_path,
        )

        ecosystem = str(ecosystem or "").strip().lower()
        if ecosystem not in {"rust", "go"}:
            ecosystem = "go" if "go" in index_path.name.lower() else "rust"
        signature_provider = f"scip-{ecosystem}"
        callers: Dict[str, List[str]] = {}  # exact fn identity -> caller locations
        callees: Dict[str, List[str]] = {}  # exact fn identity -> callee identities
        fn_info: Dict[str, dict] = {}       # exact identity -> provider facts
        symbol_to_identity: Dict[str, str] = {}
        pending_functions: List[dict] = []
        state_writers: Dict[str, List[str]] = {}  # var_name -> [writer locations]
        state_declarations: Dict[str, str] = {}   # symbol -> declaration locus

        # Collect all definitions and their references
        for sym, defn_occ in reader._definitions.items():
            name = reader._extract_name_from_symbol(sym)
            # RECON-8: explicit grouping -- skip empty names and short
            # underscore-prefixed private symbols.
            if not name or (name.startswith("_") and len(name) < 3):
                continue
            info = reader._symbol_info.get(sym)
            kind = info.kind if info else ""

            # Function-like symbols
            if kind in ("Function", "Method", "Constructor", "") and "()" in sym:
                path_str = normalize_source_binding_path(defn_occ.relative_path)
                pending_functions.append({
                    "symbol": sym,
                    "name": name,
                    "path": path_str,
                    "line": defn_occ.start_line + 1,
                    "kind": kind or "Function",
                    "signature": (info.signature if info else ""),
                })

            # Field/variable symbols for state_write_map
            elif kind in ("Field", "Property", "Variable", ""):
                if "()" not in sym:
                    state_declarations[name] = (
                        f"{defn_occ.relative_path}:L{defn_occ.start_line + 1}"
                    )
                    refs = reader._references.get(sym, [])
                    writer_locs = [
                        f"{ref.relative_path}:L{ref.start_line + 1}"
                        for ref in refs
                    ]
                    if writer_locs:
                        state_writers[name] = writer_locs

        name_counts = Counter(row["name"] for row in pending_functions)

        for row in sorted(
            pending_functions,
            key=lambda value: (
                str(value["path"]).casefold(), int(value["line"]),
                str(value["name"]).casefold(), str(value["symbol"]),
            ),
        ):
            bare = str(row["name"])
            identity = bare
            if name_counts[bare] > 1:
                discriminator = hashlib.sha256(
                    json.dumps(
                        {
                            "symbol": row["symbol"],
                            "signature": row["signature"],
                            "path": row["path"],
                            "line": row["line"],
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ).encode("utf-8")
                ).hexdigest()[:12]
                identity = (
                    f"{bare}@{row['path']}:L{row['line']}#{discriminator}"
                )
            symbol_to_identity[str(row["symbol"])] = identity
            signature_fact = build_function_signature_fact(
                ecosystem=ecosystem,
                provider=signature_provider,
                function_identity=identity,
                bare_name=bare,
                provider_symbol=str(row["symbol"]),
                raw_signature=str(row["signature"] or ""),
                source_path=str(row["path"]),
                source_line=int(row["line"]),
                source_sha256=_normalized_source_sha256(proj, str(row["path"])),
                kind=str(row["kind"]),
            )
            fn_info[identity] = {
                **row,
                "bare": bare,
                "signature_fact": signature_fact,
            }
            caller_locs = [
                f"{normalize_source_binding_path(ref.relative_path)}:L{ref.start_line + 1}"
                for ref in reader._references.get(str(row["symbol"]), [])
            ]
            if caller_locs:
                callers[identity] = sorted(set(caller_locs))

        # For callee_map: approximate callees by same-file reference
        # co-occurrence. RECON-2b: this was O(F^2 * D) (nested fn_info scan with
        # an inner O(D) symbol lookup) and could run effectively unbounded on a
        # large program during the silent window. Two bounds:
        #   1. Pre-build name -> set(files that reference it) ONCE (O(total refs))
        #      so the inner per-pair work is an O(1) set lookup, not an O(D) scan.
        #   2. A hard node cap: above it, emit a PARTIAL callee_map instead of
        #      grinding (callers/state-writers/function-summary are still emitted).
        _CALLEE_NODE_CAP = 1500
        callee_map_status = "HEURISTIC"  # RECON-3: file co-occurrence, not verified call edges
        name_to_ref_files: Dict[str, set] = {}
        for sym, refs in reader._references.items():
            identity = symbol_to_identity.get(sym)
            if identity in fn_info:
                name_to_ref_files.setdefault(identity, set()).update(
                    normalize_source_binding_path(r.relative_path) for r in refs
                )
        if len(fn_info) > _CALLEE_NODE_CAP:
            callee_map_status = "PARTIAL"
            log.warning(
                "[scip_bake] %d functions exceed callee node cap %d; emitting "
                "PARTIAL callee_map (skipping co-occurrence edges)",
                len(fn_info), _CALLEE_NODE_CAP,
            )
        else:
            for fn_name, fn_data in fn_info.items():
                fn_path = fn_data["path"]
                called = [
                    other_name
                    for other_name in fn_info
                    if other_name != fn_name
                    and fn_path in name_to_ref_files.get(other_name, ())
                ]
                if called:
                    callees[fn_name] = called[:20]

        # The Python protobuf runtime parsed attacker-controlled SCIP bytes.
        # Re-capture its complete authority immediately before any graph
        # artifact becomes observable; drift degrades to source-graph fallback
        # without publishing a mixed-authority partial graph.
        if not _provider_authority_replays(
            protobuf_authority,
            project_root=proj,
        ):
            return (
                "FAILED:TOOLCHAIN_AUTHORITY_DEBT:"
                "IDENTITY_DRIFT_BEFORE_PUBLICATION"
            )

        # Write caller_map.md
        lines = [
            "> **Status**: POPULATED",
            "> **Source**: SCIP index (v2.5.0 P1)",
            "",
            "# Caller Map",
            "",
            "| Function | Callers | Count |",
            "|----------|---------|-------|",
        ]
        for fn_name in sorted(callers.keys()):
            locs = callers[fn_name]
            lines.append(f"| `{fn_name}` | {'; '.join(locs[:10])} | {len(locs)} |")
        _write_text(scratch / "caller_map.md", "\n".join(lines))

        # Write callee_map.md
        # RECON-3: these are file-level co-occurrence approximations, NOT
        # verified call edges (a function appears as a "callee" if it is
        # referenced anywhere in the same file). The status header says so, so
        # depth agents weight it as a hint, not ground truth.
        lines = [
            f"> **Status**: {callee_map_status}",
            "> **Source**: SCIP index (v2.5.0 P1) — file-level "
            "co-occurrence heuristic, not verified call edges",
            "",
            "# Callee Map",
            "",
            "| Function | Callees (same-file references, heuristic) |",
            "|----------|---------|",
        ]
        for fn_name in sorted(callees.keys()):
            clist = callees[fn_name]
            lines.append(f"| `{fn_name}` | {', '.join(clist)} |")
        _write_text(scratch / "callee_map.md", "\n".join(lines))

        # Write state_write_map.md
        lines = [
            "> **Status**: POPULATED",
            "> **Source**: SCIP index (v2.5.0 P1)",
            "",
            "# State Write Map",
            "",
            "| Variable | Writer Locations | Count |",
            "|----------|-----------------|-------|",
        ]
        for var_name in sorted(state_writers.keys()):
            locs = state_writers[var_name]
            lines.append(f"| `{var_name}` | {'; '.join(locs[:10])} | {len(locs)} |")
        _write_text(scratch / "state_write_map.md", "\n".join(lines))

        # Write function_summary.md
        lines = [
            "> **Status**: POPULATED",
            "> **Source**: SCIP index (v2.5.0 P1)",
            "",
            "# Function Summary",
            "",
            "| Function | File | Line | Kind | Provider Signature | Signature Authority | Callers | Callees |",
            "|----------|------|------|------|--------------------|---------------------|---------|---------|",
        ]
        for fn_name in sorted(fn_info.keys()):
            data = fn_info[fn_name]
            n_callers = len(callers.get(fn_name, []))
            n_callees = len(callees.get(fn_name, []))
            signature_fact = data["signature_fact"]
            signature_cell = str(
                signature_fact.get("canonical_signature") or "_(unavailable)_"
            ).replace("|", "&#124;").replace("`", "&#96;")
            lines.append(
                f"| `{fn_name}` | {data['path']} | {data['line']} "
                f"| {data['kind']} | `{signature_cell}` "
                f"| {signature_fact.get('authority', 'UNKNOWN')} "
                f"| {n_callers} | {n_callees} |"
            )
        _write_text(scratch / "function_summary.md", "\n".join(lines))

        # Unified machine artifact for the coverage gate (G2). SCIP descriptors
        # are reference LOCATIONS (it does not resolve reader function names);
        # var_refs are all-references (reads+writes combined). The gate matches a
        # descriptor by bare name OR location against the agent's finding prose.
        var_refs = {
            v: {
                "bare": v,
                "declaration_locus": state_declarations.get(v, ""),
                # SCIP's current adapter exposes references, not read/write
                # access polarity.  Preserve that limitation rather than
                # laundering every reference into a proven write site.
                "reference_sites": sorted(state_writers.get(v, [])),
                "refs": sorted(state_writers.get(v, [])),
                "read_sites": [],
                "write_sites": [],
                "confidence": "REFERENCE_SITE_NO_POLARITY",
            }
            for v in sorted(set(state_declarations) | set(state_writers))
        }
        functions = {
            fn: {"bare": data.get("bare", fn),
                 "loc": f"{data['path']}:L{data['line']}",
                 "callers": sorted(callers.get(fn, [])),
                 "callees": sorted(callees.get(fn, [])),
                 "signature_fact": data["signature_fact"]}
            for fn, data in fn_info.items()
        }
        if not _write_mechanical_graph_json(
            scratch,
            f"scip-{ecosystem}",
            var_refs,
            functions,
        ):
            return "FAILED:ARTIFACT_STAGE:mechanical graph JSON write failed"

        # Record status
        ecosystem_label = ecosystem.upper()
        status_lines = [
            f"- SCIP_{ecosystem_label}_BAKE: COMPLETE",
            f"- SCIP_{ecosystem_label}_INDEX: {index_path}",
            f"- SCIP_DEFINITIONS: {stats['definitions']}",
            f"- SCIP_DOCUMENTS: {stats['documents']}",
            f"- SCIP_GRAPH_ARTIFACTS: caller_map.md, callee_map.md, state_write_map.md, function_summary.md",
        ]
        bs = scratch / "build_status.md"
        if bs.exists():
            try:
                existing = bs.read_text(encoding="utf-8", errors="replace")
                if not any("SCIP_RUST_BAKE" in l for l in existing.splitlines()):
                    bs.write_text(
                        existing.rstrip() + "\n\n## SCIP Bake\n" + "\n".join(status_lines) + "\n",
                        encoding="utf-8",
                    )
            except Exception:
                pass

        return f"WRITTEN:{stats['definitions']} defs, {stats['documents']} docs"

    except Exception as e:
        return f"FAILED:{e.__class__.__name__}:{e}"


def _graph_artifact_evidence(root: Path) -> dict[str, dict[str, object]]:
    from enumeration_type_ir import validate_function_signature_fact

    evidence: dict[str, dict[str, object]] = {}
    for name in _SCIP_GRAPH_ARTIFACT_NAMES:
        path = Path(root) / name
        if not path.is_file():
            raise ValueError(f"graph artifact missing: {name}")
        raw = path.read_bytes()
        if not raw:
            raise ValueError(f"graph artifact empty: {name}")
        evidence[name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    graph = json.loads(
        (Path(root) / "_mechanical_graph.json").read_text(
            encoding="utf-8",
            errors="strict",
        )
    )
    functions = graph.get("functions") if isinstance(graph, dict) else None
    signatures = (
        graph.get("function_signatures")
        if isinstance(graph, dict)
        else None
    )
    if (
        not isinstance(graph, dict)
        or graph.get("schema_version")
        != "plamen.mechanical_graph.v2"
        or graph.get("function_signature_schema")
        != "plamen.function_signature_fact.v1"
        or not str(graph.get("source") or "").strip()
        or not isinstance(graph.get("state_symbols"), list)
        or not isinstance(graph.get("var_refs"), dict)
        or not isinstance(functions, dict)
        or not functions
        or not isinstance(signatures, dict)
        or set(functions) != set(signatures)
    ):
        raise ValueError("mechanical graph JSON schema is incomplete")
    for identity, row in functions.items():
        fact = row.get("signature_fact") if isinstance(row, dict) else None
        if (
            not isinstance(fact, dict)
            or fact != signatures.get(identity)
            or fact.get("schema")
            != "plamen.function_signature_fact.v1"
            or str(fact.get("function_identity") or "")
            != str(identity)
            or validate_function_signature_fact(fact)
        ):
            raise ValueError(
                "mechanical graph function signature authority is incomplete"
            )
    return evidence


def _graph_generation_manifest(
    evidence: dict[str, dict[str, object]],
) -> dict[str, object]:
    ordered = [
        {
            "path": name,
            "sha256": evidence[name]["sha256"],
            "bytes": evidence[name]["bytes"],
        }
        for name in _SCIP_GRAPH_ARTIFACT_NAMES
    ]
    unsigned: dict[str, object] = {
        "schema_version": _GRAPH_GENERATION_SCHEMA,
        "state": "COMMITTED",
        "artifact_denominator": list(_SCIP_GRAPH_ARTIFACT_NAMES),
        "artifacts": ordered,
    }
    return {
        **unsigned,
        "generation_sha256": hashlib.sha256(
            (
                json.dumps(
                    unsigned,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest(),
    }


def _validate_graph_generation_manifest(
    root: Path,
    evidence: dict[str, dict[str, object]],
) -> None:
    path = Path(root) / _GRAPH_GENERATION_MANIFEST
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(
            "graph generation manifest is missing or unreadable"
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError("graph generation manifest is malformed")
    expected = _graph_generation_manifest(evidence)
    if payload != expected:
        raise ValueError("graph generation manifest does not bind the set")


def _discard_committed_graph_generation(root: Path) -> list[str]:
    """Remove a prior precise generation before publishing an approximation."""

    root = Path(root)
    if not (root / _GRAPH_GENERATION_MANIFEST).exists():
        return []
    failures: list[str] = []
    for name in (
        _GRAPH_GENERATION_MANIFEST,
        *_SCIP_GRAPH_ARTIFACT_NAMES,
    ):
        try:
            (root / name).unlink(missing_ok=True)
        except OSError as exc:
            failures.append(f"{name}:{type(exc).__name__}")
    return failures


def _validate_and_publish_graph_artifact_set(
    stage: Path,
    destination: Path,
) -> tuple[str, dict[str, dict[str, object]]]:
    """Validate all five artifacts, then publish or restore the prior set."""

    stage = Path(stage)
    destination = Path(destination)
    try:
        staged_evidence = _graph_artifact_evidence(stage)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        return (
            f"FAILED:ARTIFACT_STAGE:{type(exc).__name__}:{exc}",
            {},
        )
    manifest_payload = (
        json.dumps(
            _graph_generation_manifest(staged_evidence),
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")
    publication_names = (
        *_SCIP_GRAPH_ARTIFACT_NAMES,
        _GRAPH_GENERATION_MANIFEST,
    )
    destination.mkdir(parents=True, exist_ok=True)
    prior: dict[str, bytes | None] = {}
    publish_temps: list[Path] = []
    restore_temps: list[Path] = []
    try:
        for name in publication_names:
            target = destination / name
            prior[name] = target.read_bytes() if target.is_file() else None
            descriptor, raw_tmp = tempfile.mkstemp(
                prefix=f".{name}.",
                suffix=".r5-publish",
                dir=destination,
            )
            os.close(descriptor)
            temp_path = Path(raw_tmp)
            temp_path.write_bytes(
                manifest_payload
                if name == _GRAPH_GENERATION_MANIFEST
                else (stage / name).read_bytes()
            )
            publish_temps.append(temp_path)
        for name, temp_path in zip(
            publication_names,
            publish_temps,
        ):
            os.replace(temp_path, destination / name)
        observed = _graph_artifact_evidence(destination)
        if observed != staged_evidence:
            raise OSError("published graph artifact digest mismatch")
        _validate_graph_generation_manifest(destination, observed)
        return "WRITTEN", observed
    except Exception as exc:
        for name in publication_names:
            target = destination / name
            previous = prior.get(name)
            try:
                if previous is None:
                    target.unlink(missing_ok=True)
                    continue
                if target.is_file() and target.read_bytes() == previous:
                    continue
                descriptor, raw_tmp = tempfile.mkstemp(
                    prefix=f".{name}.",
                    suffix=".r5-restore",
                    dir=destination,
                )
                os.close(descriptor)
                temp_path = Path(raw_tmp)
                restore_temps.append(temp_path)
                temp_path.write_bytes(previous)
                os.replace(temp_path, target)
            except OSError:
                # The caller receives typed publication debt.  Never convert a
                # rollback fault into WRITTEN or a successful ledger receipt.
                pass
        restored = True
        for name in publication_names:
            target = destination / name
            previous = prior.get(name)
            try:
                if previous is None:
                    restored = restored and not target.exists()
                else:
                    restored = (
                        restored
                        and target.is_file()
                        and target.read_bytes() == previous
                    )
            except OSError:
                restored = False
        quarantine = ""
        if not restored:
            # A partial rollback is more dangerous than losing an optional
            # graph: direct consumers could combine old and new maps.  Remove
            # the entire denominator so the pipeline degrades to explicit
            # graph coverage debt.  Delete the machine graph first because it
            # is the primary consumer authority.
            quarantine_failures: list[str] = []
            for name in (
                _GRAPH_GENERATION_MANIFEST,
                "_mechanical_graph.json",
                "caller_map.md",
                "callee_map.md",
                "state_write_map.md",
                "function_summary.md",
            ):
                try:
                    (destination / name).unlink(missing_ok=True)
                except OSError as quarantine_exc:
                    quarantine_failures.append(
                        f"{name}:{type(quarantine_exc).__name__}"
                    )
            quarantine = (
                ":ROLLBACK_QUARANTINED"
                if not quarantine_failures
                else ":ROLLBACK_QUARANTINE_DEBT:"
                + ",".join(quarantine_failures)
            )
        return (
            f"FAILED:ARTIFACT_PUBLICATION:{type(exc).__name__}:{exc}"
            f"{quarantine}",
            {},
        )
    finally:
        for path in (*publish_temps, *restore_temps):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass


def _merge_namespaced_graph_artifacts(
    scratch: Path,
    *,
    ecosystems: tuple[str, ...],
) -> str:
    """Merge disjoint provider outputs without allowing shared-slot loss."""

    root = Path(scratch)
    normalized = tuple(
        str(value).strip().lower() for value in ecosystems
    )
    if (
        not normalized
        or len(set(normalized)) != len(normalized)
        or any(value not in {"go", "rust"} for value in normalized)
    ):
        return "FAILED:GRAPH_MERGE:ecosystem denominator is invalid"
    stage = Path(
        tempfile.mkdtemp(prefix=".mixed-graph-", dir=root)
    )
    try:
        from enumeration_type_ir import build_function_signature_fact

        merged_functions: dict[str, dict] = {}
        merged_signatures: dict[str, dict] = {}
        merged_vars: dict[str, dict] = {}
        merged_symbols: list[dict] = []
        markdown: dict[str, list[str]] = {
            name: [
                f"# Mixed L1 {name}",
                "",
                "Deterministic merge of namespaced provider artifacts.",
                "",
            ]
            for name in _SCIP_GRAPH_ARTIFACT_NAMES[:-1]
        }
        graph_schema = ""
        signature_schema = ""
        for ecosystem in normalized:
            provider_root = root / "_graph_providers" / ecosystem
            _graph_artifact_evidence(provider_root)
            graph = json.loads(
                (provider_root / "_mechanical_graph.json").read_text(
                    encoding="utf-8",
                    errors="strict",
                )
            )
            graph_schema = graph_schema or str(
                graph.get("schema_version") or ""
            )
            signature_schema = signature_schema or str(
                graph.get("function_signature_schema") or ""
            )
            functions = graph.get("functions") or {}
            function_keys = {
                str(identity): f"{ecosystem}::{identity}"
                for identity in functions
            }
            for identity in sorted(functions):
                row = dict(functions[identity])
                namespaced = function_keys[str(identity)]
                row["callers"] = [
                    function_keys.get(str(value), str(value))
                    for value in row.get("callers", [])
                ]
                row["callees"] = [
                    function_keys.get(str(value), str(value))
                    for value in row.get("callees", [])
                ]
                fact = row.get("signature_fact")
                if isinstance(fact, dict):
                    binding = (
                        fact.get("source_binding")
                        if isinstance(fact.get("source_binding"), dict)
                        else {}
                    )
                    rebound = build_function_signature_fact(
                        ecosystem=str(fact.get("ecosystem") or ecosystem),
                        provider=str(fact.get("provider") or ""),
                        function_identity=namespaced,
                        bare_name=str(
                            fact.get("bare_name")
                            or row.get("bare")
                            or identity
                        ),
                        provider_symbol=str(
                            fact.get("provider_symbol") or ""
                        ),
                        raw_signature=str(
                            fact.get("raw_signature") or ""
                        ),
                        source_path=str(binding.get("path") or ""),
                        source_line=int(binding.get("line") or 0),
                        source_sha256=str(
                            binding.get("source_sha256") or ""
                        ),
                        kind=str(fact.get("kind") or ""),
                        raw_parameters=(
                            str(fact.get("raw_parameters") or "")
                            if fact.get("parse_status") == "EXACT"
                            else None
                        ),
                        visibility=str(
                            fact.get("visibility") or ""
                        ),
                        mutability=str(
                            fact.get("mutability") or ""
                        ),
                        receiver=str(fact.get("receiver") or ""),
                        generics=str(fact.get("generics") or ""),
                        returns=str(fact.get("returns") or ""),
                        authority=str(fact.get("authority") or ""),
                    )
                    row["signature_fact"] = rebound
                    merged_signatures[namespaced] = rebound
                merged_functions[namespaced] = row
            for identity, raw in sorted(
                (graph.get("var_refs") or {}).items()
            ):
                merged_vars[f"{ecosystem}::{identity}"] = dict(raw)
            for raw in sorted(
                graph.get("state_symbols") or [],
                key=lambda value: str(
                    value.get("qualified_name")
                    if isinstance(value, dict)
                    else ""
                ),
            ):
                if not isinstance(raw, dict):
                    raise ValueError(
                        "provider state-symbol row is malformed"
                    )
                row = dict(raw)
                identity = str(row.get("qualified_name") or "")
                if not identity:
                    raise ValueError(
                        "provider state-symbol identity is absent"
                    )
                namespaced = f"{ecosystem}::{identity}"
                row["qualified_name"] = namespaced
                row["symbol_id"] = (
                    f"{ecosystem}::{row.get('symbol_id') or identity}"
                )
                if row.get("state_symbol_identity"):
                    row["state_symbol_identity"] = (
                        f"{ecosystem}::"
                        f"{row['state_symbol_identity']}"
                    )
                merged_symbols.append(row)
            for name in _SCIP_GRAPH_ARTIFACT_NAMES[:-1]:
                text = (provider_root / name).read_text(
                    encoding="utf-8",
                    errors="strict",
                ).rstrip()
                markdown[name].extend(
                    [
                        f"## Provider namespace: {ecosystem}",
                        "",
                        text,
                        "",
                    ]
                )
        for name, lines in markdown.items():
            (stage / name).write_text(
                "\n".join(lines).rstrip() + "\n",
                encoding="utf-8",
            )
        graph_payload = {
            "schema_version": graph_schema,
            "function_signature_schema": signature_schema,
            "source": "mixed:go+rust",
            "state_symbols": merged_symbols,
            "var_refs": merged_vars,
            "functions": merged_functions,
            "function_signatures": merged_signatures,
            "provider_namespaces": list(normalized),
        }
        (stage / "_mechanical_graph.json").write_text(
            json.dumps(
                graph_payload,
                indent=1,
                sort_keys=True,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        status, _evidence = _validate_and_publish_graph_artifact_set(
            stage,
            root,
        )
        return "WRITTEN:mixed" if status == "WRITTEN" else status
    except (
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        TypeError,
        ValueError,
    ) as exc:
        return f"FAILED:GRAPH_MERGE:{type(exc).__name__}:{exc}"
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def _record_mixed_graph_outcomes(
    scratch: Path,
    project: Path,
    *,
    statuses: dict[str, str],
    context: Optional[dict],
) -> None:
    """Project lane outcomes onto the exact merged consumer artifacts."""

    merge_status = str(statuses.get("merge") or "FAILED:merge missing")
    protobuf_upstreams: list[dict[str, str]] = []
    for ecosystem, capability_id, tool in (
        ("go", "scip-go.reference-graph", "scip-go"),
        ("rust", "scip-rust.reference-graph", "rust-analyzer"),
    ):
        lane_status = str(
            statuses.get(ecosystem) or "SKIPPED:lane not executed"
        )
        lane_ledger_relative = (
            f"_graph_providers/{ecosystem}/"
            "tool_coverage_ledger.json"
        )
        lane_precise = lane_status in {
            "REUSED:scip",
            "WRITTEN:scip",
        }
        if lane_precise:
            try:
                from tool_coverage_ledger import (
                    load_tool_coverage_ledger,
                )

                lane_outcomes = load_tool_coverage_ledger(
                    Path(scratch)
                    / "_graph_providers"
                    / ecosystem
                )
                lane_outcome = lane_outcomes.get(capability_id)
                lane_precise = (
                    lane_outcome is not None
                    and lane_outcome.state
                    is ToolOutcomeState.SUCCEEDED
                    and lane_outcome.tool == tool
                )
                parser_outcome = lane_outcomes.get(
                    "protobuf.scip-graph-parser"
                )
                if (
                    lane_precise
                    and parser_outcome is not None
                    and parser_outcome.state
                    is ToolOutcomeState.SUCCEEDED
                    and parser_outcome.tool == "protobuf"
                ):
                    protobuf_upstreams.append(
                        {
                            "ledger_path": lane_ledger_relative,
                            "capability_id": (
                                "protobuf.scip-graph-parser"
                            ),
                        }
                    )
            except (OSError, ToolCoverageLedgerError, ValueError):
                lane_precise = False
        outcome_status = (
            "WRITTEN"
            if lane_precise and merge_status == "WRITTEN:mixed"
            else (
                f"FAILED:MIXED_GRAPH_PUBLICATION:{merge_status}"
                if lane_precise
                else f"SKIPPED:PRECISE_PROVIDER_FALLBACK:{lane_status}"
            )
        )
        authority = _capture_command_provider_authority(
            tool,
            (tool, "--version"),
            project_root=project,
        )
        _record_precise_graph_outcome(
            scratch,
            capability_id=capability_id,
            tool=tool,
            status=outcome_status,
            authority=authority,
            # This is the root mixed projection.  Its current-run identity is
            # therefore mixed; the bound upstream lane ledger retains the
            # lane-specific go/rust context.
            context=context,
            upstream_outcomes=(
                (
                    {
                        "ledger_path": lane_ledger_relative,
                        "capability_id": capability_id,
                    },
                )
                if lane_precise
                else ()
            ),
        )
    protobuf = _capture_python_provider_authority(
        "protobuf",
        project_root=project,
    )
    _record_precise_graph_outcome(
        scratch,
        capability_id="protobuf.scip-graph-parser",
        tool="protobuf",
        status=(
            "WRITTEN"
            if protobuf_upstreams and merge_status == "WRITTEN:mixed"
            else f"SKIPPED:MIXED_SCIP_PARSER_NOT_ACCEPTED:{merge_status}"
        ),
        authority=protobuf,
        context=context,
        upstream_outcomes=tuple(protobuf_upstreams),
    )


def _scip_to_graph_artifacts(
    scratch: Path,
    index_path: Path,
    proj: Path,
    *,
    ecosystem: str = "",
    context: Optional[dict] = None,
) -> str:
    """Convert SCIP and durably bind the protobuf parser capability outcome."""
    scratch = Path(scratch)
    scratch.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(
            prefix=f".scip-{ecosystem or 'unknown'}-",
            dir=scratch,
        )
    )
    try:
        status = _scip_to_graph_artifacts_impl(
            stage,
            index_path,
            proj,
            ecosystem=ecosystem,
        )
        if str(status).startswith("WRITTEN"):
            publication, _evidence = (
                _validate_and_publish_graph_artifact_set(
                    stage,
                    scratch,
                )
            )
            if publication != "WRITTEN":
                status = publication
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    protobuf_authority = _capture_python_provider_authority(
        "protobuf",
        project_root=proj,
    )
    _record_precise_graph_outcome(
        scratch,
        capability_id="protobuf.scip-graph-parser",
        tool="protobuf",
        status=status,
        authority=protobuf_authority,
        context=context,
    )
    return status


# OpenGrep cross-ecosystem scanner (v2.5.0 P2)

_OPENGREP_SCAN_TIMEOUT = 300  # seconds
# Test-only override. Production resolution is late-bound to the same
# PLAMEN_HOME authority as prompts, rules, and scripts so a staged runtime
# cannot silently consume scanner rules from an ambient user installation.
_OPENGREP_RULES_BASE: Optional[Path] = None


def _opengrep_rules_base() -> Path:
    override = _OPENGREP_RULES_BASE
    return (
        Path(override)
        if override is not None
        else _plamen_home() / "opengrep-rules"
    )
# The three rule trees are repository gitlinks. The installer initializes
# submodules before any audit; recon only accepts the exact release-bound
# revisions and never materializes or repairs rules while source is bound.
_OPENGREP_RULE_REVISIONS = {
    "aptos-move-rules": "9ee5c476c6161d9eece74fd2f38685eb483b999c",
    "decurity-rules": "2e878a89ac7bba1f8435e8a68e3ecb7700096cd5",
    "opengrep-rules": "f1d2b562b414783763fd02a6ed2736eaed622efa",
}
_OPENGREP_LANG_RULES: Dict[str, List[str]] = {
    "evm": ["opengrep-rules/solidity", "decurity-rules/solidity/security"],
    "solana": ["opengrep-rules/rust", "decurity-rules/rust"],
    "soroban": ["opengrep-rules/rust", "decurity-rules/rust"],
    "aptos": ["aptos-move-rules/rules"],
    "sui": [],
}
_OPENGREP_LANG_EXT: Dict[str, Tuple[str, ...]] = {
    "evm": (".sol",),
    "solana": (".rs",),
    "soroban": (".rs",),
    "aptos": (".move",),
    "sui": (".move",),
}


# Populated by _ensure_opengrep_rules() with per-repo validation failures so
# the caller can surface coverage debt instead of failing silently.
_OPENGREP_RULE_FAILURES: Dict[str, str] = {}


def _ensure_opengrep_rules() -> Dict[str, Path]:
    """Return only populated rule submodules at their release-bound revisions."""
    _OPENGREP_RULE_FAILURES.clear()
    available: Dict[str, Path] = {}
    rules_base = _opengrep_rules_base()
    for name, expected_revision in _OPENGREP_RULE_REVISIONS.items():
        local = rules_base / name
        try:
            populated = local.is_dir() and any(local.iterdir())
        except OSError as exc:
            _OPENGREP_RULE_FAILURES[name] = (
                f"prebound rule submodule is unreadable: {type(exc).__name__}"
            )
            continue
        if not populated:
            _OPENGREP_RULE_FAILURES[name] = (
                "prebound rule submodule is absent or empty; run installer "
                "submodule initialization before the audit"
            )
            continue
        if not (local / ".git").exists():
            _OPENGREP_RULE_FAILURES[name] = (
                "rule tree has no gitlink metadata; revision cannot be verified"
            )
            continue
        rc, output = _run_hardened(
            ["git", "-C", str(local), "rev-parse", "HEAD"], None, 20,
        )
        actual_revision = (output or "").strip().splitlines()
        actual_revision = actual_revision[-1].strip() if actual_revision else ""
        if rc != 0 or actual_revision != expected_revision:
            _OPENGREP_RULE_FAILURES[name] = (
                "rule revision mismatch: "
                f"expected {expected_revision}, got {actual_revision or 'unreadable'}"
            )
            continue
        available[name] = local
    return available


def _record_scanner_outcome(
    scratch: Path,
    outcome: ToolOutcome,
    *,
    context: Optional[dict] = None,
) -> ToolOutcome:
    """Persist scanner coverage debt without turning ledger I/O into a halt."""
    recorded = outcome
    if outcome.state is ToolOutcomeState.SUCCEEDED:
        try:
            recorded = bind_succeeded_tool_outcome(
                scratch,
                outcome,
                context=context or {},
            )
        except (OSError, ToolCoverageLedgerError, TypeError, ValueError) as exc:
            recorded = ToolOutcome.debt(
                outcome.capability_id,
                outcome.tool,
                ToolOutcomeState.FAILED,
                "FAILED:TOOL_SUCCESS_AUTHORITY_DEBT:"
                f"{type(exc).__name__}:{exc}",
                provider_ref=outcome.provider_ref,
            )
    try:
        record_tool_outcome(scratch, recorded)
    except Exception as exc:
        marker = scratch / "tool_coverage_ledger_repair_required.md"
        existing = _read_text(marker).rstrip()
        line = (
            f"- `{recorded.capability_id}`: coverage receipt write failed "
            f"({type(exc).__name__}: {exc})"
        )
        body = (
            existing + "\n" + line + "\n"
            if existing
            else "# Tool Coverage Ledger Repair Required\n\n" + line + "\n"
        )
        _write_text(marker, body)
    return recorded


def _validated_sarif(path: Path) -> dict:
    """Load the minimum SARIF 2.1 schema needed to prove a scan completed."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="strict"))
    except Exception as exc:
        raise ValueError(f"invalid SARIF JSON: {type(exc).__name__}") from exc
    if not isinstance(data, dict):
        raise ValueError("SARIF root must be an object")
    if data.get("version") != "2.1.0":
        raise ValueError("SARIF version must be 2.1.0")
    runs = data.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("SARIF runs must be a non-empty array")
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            raise ValueError(f"SARIF run {run_index} must be an object")
        driver = ((run.get("tool") or {}).get("driver") or {})
        if not isinstance(driver, dict) or not str(driver.get("name") or "").strip():
            raise ValueError(f"SARIF run {run_index} has no tool driver name")
        results = run.get("results", [])
        if not isinstance(results, list):
            raise ValueError(f"SARIF run {run_index} results must be an array")
        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                raise ValueError(
                    f"SARIF result {run_index}:{result_index} must be an object"
                )
            message = result.get("message")
            if not isinstance(message, dict):
                raise ValueError(
                    f"SARIF result {run_index}:{result_index} has no message object"
                )
    return data


def _run_opengrep_scan(
    scratch: Path,
    proj: Path,
    lang: str,
    *,
    context: Optional[dict] = None,
) -> str:
    """Run OpenGrep scan and write results to scratchpad.

    Produces: opengrep_results.sarif (raw), opengrep_findings.md (summary).
    Returns status string: WRITTEN:{n} findings | SKIPPED:{reason} | FAILED:{reason}
    """
    capability_id = "opengrep.static-analysis"

    def finish(outcome: ToolOutcome) -> str:
        return _record_scanner_outcome(
            scratch, outcome, context=context
        ).legacy_status()

    # Windows installs Semgrep as the compatible adapter. Prefer native
    # OpenGrep where present, but accept the same Semgrep binary the installer
    # provisions instead of reporting a false tool absence.
    scanner_binary = shutil.which("opengrep") or shutil.which("semgrep")
    if not scanner_binary:
        return finish(ToolOutcome.debt(
            capability_id, "opengrep/semgrep", ToolOutcomeState.UNAVAILABLE,
            "opengrep-compatible scanner not found",
        ))
    scanner_name = (
        "semgrep"
        if "semgrep" in Path(scanner_binary).name.lower()
        else "opengrep"
    )

    rule_dirs = _OPENGREP_LANG_RULES.get(lang, [])
    if not rule_dirs:
        return finish(ToolOutcome.debt(
            capability_id, scanner_name, ToolOutcomeState.SKIPPED,
            f"no OpenGrep rules for {lang}",
        ))

    # Accept only the release-bound, installer-populated rule submodules.
    available_repos = _ensure_opengrep_rules()

    # Resolve rule paths
    resolved_rules: List[str] = []
    for rule_rel in rule_dirs:
        repo_name = rule_rel.split("/")[0]
        if repo_name not in available_repos:
            continue
        full_path = available_repos[repo_name] / "/".join(rule_rel.split("/")[1:])
        if full_path.exists():
            resolved_rules.append(str(full_path))

    if not resolved_rules:
        if _OPENGREP_RULE_FAILURES:
            detail = "; ".join(
                f"{n}: {r}" for n, r in sorted(_OPENGREP_RULE_FAILURES.items())
            )
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.UNAVAILABLE,
                f"rules unavailable: {detail}",
            ))
        return finish(ToolOutcome.debt(
            capability_id, scanner_name, ToolOutcomeState.UNAVAILABLE,
            "no rule directories available",
        ))

    # Check project has relevant source files
    exts = _OPENGREP_LANG_EXT.get(lang, ())
    source_files = sorted(_production_source_files(proj, exts), key=lambda p: _rel(p, proj))
    if not source_files:
        return finish(ToolOutcome.debt(
            capability_id, scanner_name, ToolOutcomeState.SKIPPED,
            f"no production {'/'.join(exts)} files in project",
        ))
    if len(source_files) > _MAX_OPENGREP_SOURCE_FILES:
        return finish(ToolOutcome.debt(
            capability_id, scanner_name, ToolOutcomeState.SKIPPED,
            (
                f"{len(source_files)} production source files exceeds "
                "bounded OpenGrep prepass limit"
            ),
        ))

    sarif_path = scratch / "opengrep_results.sarif"
    findings_path = scratch / "opengrep_findings.md"
    # A retry must never leave a prior successful generation looking current.
    stale_cleanup_failed = False
    for stale in (sarif_path, findings_path):
        try:
            stale.unlink(missing_ok=True)
        except OSError:
            stale_cleanup_failed = True
        if os.path.lexists(stale):
            stale_cleanup_failed = True
    if stale_cleanup_failed:
        return finish(ToolOutcome.debt(
            capability_id,
            scanner_name,
            ToolOutcomeState.FAILED,
            "stale scanner artifacts could not be cleared",
        ))

    # The live scratchpad contains locks, checkpoints, and artifact authority.
    # Relabeling that whole tree for a low-integrity scanner can fail recovery
    # on Windows and quarantine the global lease for the driver's lifetime.
    # Grant write authority only to one fresh private stage, validate there,
    # then atomically promote the authenticated SARIF bytes.
    stage = Path(tempfile.mkdtemp(prefix=".og-", dir=scratch))
    staged_sarif = stage / "results.sarif"
    scanner_env = dict(os.environ)
    scanner_env.update({
        # The scanner's Python wrapper and native core may both create
        # temporary/cache files.  Route every documented/legacy Semgrep path
        # into the same disposable low-integrity stage rather than granting
        # write access to the user's profile or system temporary directory.
        # Do not precreate medium-integrity children before lease activation.
        # The lease lowers this exact empty root; scanner-created descendants
        # then inherit its low MIC label.
        "TEMP": str(stage),
        "TMP": str(stage),
        "TMPDIR": str(stage),
        "XDG_CACHE_HOME": str(stage),
        "SEMGREP_SETTINGS_FILE": str(stage / "settings.yml"),
        "SEMGREP_VERSION_CACHE_PATH": str(stage / "version"),
        "SEMGREP_LOG_FILE": str(stage / "scanner.log"),
        "OPENGREP_ENABLE_VERSION_CHECK": "0",
    })
    cmd = [scanner_binary, "scan", "--disable-version-check"]
    rule_flag = "--config" if scanner_name == "semgrep" else "-f"
    for rp in resolved_rules:
        cmd.extend([rule_flag, rp])
    cmd.extend(["--sarif-output", str(staged_sarif)])
    cmd.extend([_rel(p, proj) for p in source_files])

    # Hang-proof: temp-file drain + tree-kill. The prior Popen+communicate()
    # drained an OS PIPE — exactly the construct a grandchild holding the handle
    # can wedge forever; _run_hardened removes the pipe entirely.
    # The hardened runner treats ``cwd`` as read-only input authority.  The
    # scanner receives only the fresh stage as explicit write authority.
    try:
        rc, scanner_output = _run_hardened(
            cmd,
            proj,
            _OPENGREP_SCAN_TIMEOUT,
            env=scanner_env,
            writable_roots=(stage,),
        )
        if rc == 124:
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.FAILED,
                f"timeout after {_OPENGREP_SCAN_TIMEOUT}s",
            ))
        if rc == 127:
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.UNAVAILABLE,
                "scanner executable could not be started",
            ))
        if rc != 0:
            detail_lines = [
                line.strip()
                for line in str(scanner_output or "").splitlines()
                if line.strip()
            ]
            detail = " | ".join(detail_lines[-3:])[-800:]
            reason = f"exit {rc}: {detail or 'scanner exited abnormally'}"
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.FAILED, reason,
            ))

        # A return code is transport evidence, not result authority. Clean-zero
        # is accepted only from a fresh, schema-valid SARIF document.
        if not staged_sarif.exists() or staged_sarif.stat().st_size < 10:
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.FAILED,
                f"exit {rc}, no SARIF produced",
            ))
        try:
            sarif_data = _validated_sarif(staged_sarif)
        except ValueError as exc:
            return finish(ToolOutcome.debt(
                capability_id, scanner_name, ToolOutcomeState.FAILED,
                str(exc),
            ))
        os.replace(staged_sarif, sarif_path)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    # Parse SARIF and write human-readable summary
    finding_count = _parse_opengrep_sarif(
        scratch, sarif_path, sarif_data=sarif_data,
    )

    # ``build_status.md`` is a committed canonical-recon output by the time
    # this optional pre-breadth provider runs.  Mutating one member after the
    # canonical merge invalidates the producer's bundle receipt and makes
    # every unchanged recon sibling fail strict downstream input-authority
    # replay.  OpenGrep already publishes its result through the governed
    # SARIF, summary, and tool-outcome artifacts below; keep recon immutable.

    revisions = ",".join(
        f"{name}@{_OPENGREP_RULE_REVISIONS[name]}"
        for name in sorted({
            item.split("/")[0] for item in rule_dirs
            if item.split("/")[0] in available_repos
        })
    )
    return finish(ToolOutcome.succeeded(
        capability_id,
        scanner_name,
        finding_count,
        artifacts=("opengrep_results.sarif", "opengrep_findings.md"),
        provider_ref=revisions,
    ))


def _parse_opengrep_sarif(
    scratch: Path,
    sarif_path: Path,
    *,
    sarif_data: Optional[dict] = None,
) -> int:
    """Parse SARIF output and write opengrep_findings.md summary. Returns finding count."""
    import json as _json

    try:
        data = (
            sarif_data
            if sarif_data is not None
            else _json.loads(
                sarif_path.read_text(encoding="utf-8", errors="replace")
            )
        )
    except Exception:
        _write_text(scratch / "opengrep_findings.md",
                     "# OpenGrep Findings\n\n> SARIF parse failed\n")
        return 0

    findings: List[dict] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")
            locations = result.get("locations", [])
            loc_str = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 0)
                loc_str = f"{art}:L{line}" if art else ""

            findings.append({
                "rule": rule_id,
                "message": message[:200],
                "level": level,
                "location": loc_str,
            })

    # Write summary
    lines = [
        "# OpenGrep Findings",
        "",
        f"> **Total**: {len(findings)} findings",
        f"> **Source**: OpenGrep SARIF scan (v2.5.0 P2)",
        "",
        "| # | Rule | Level | Location | Message |",
        "|---|------|-------|----------|---------|",
    ]
    for i, f in enumerate(findings, 1):
        msg = f["message"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {i} | `{f['rule']}` | {f['level']} | `{f['location']}` | {msg} |")
    _write_text(scratch / "opengrep_findings.md", "\n".join(lines))

    return len(findings)


# Sec3 X-Ray Solana scanner (v2.5.0 P4)

# No mutable image default. A governed capability registry/config must supply
# an immutable reference; absence is explicit coverage debt, not clean-zero.
_SEC3_XRAY_IMAGE = ""
_SEC3_IMAGE_RE = re.compile(r"^ghcr\.io/[^@\s]+@sha256:[0-9a-f]{64}$")
_SEC3_XRAY_TIMEOUT = 600  # seconds — Docker pull + LLVM analysis can be slow
_SEC3_SARIF_FILENAME = "sec3-report.sarif"


def _resolve_sec3_image(image_ref: Optional[str] = None) -> Optional[str]:
    candidate = str(image_ref or _SEC3_XRAY_IMAGE or "").strip()
    return candidate if _SEC3_IMAGE_RE.fullmatch(candidate) else None


def _run_sec3_xray(
    scratch: Path,
    proj: Path,
    image_ref: Optional[str] = None,
    *,
    context: Optional[dict] = None,
) -> str:
    """Run Sec3 X-Ray scanner via Docker and write results to scratchpad.

    Produces: sec3_results.sarif (raw), sec3_findings.md (summary).
    Returns status string: WRITTEN:{n} findings | SKIPPED:{reason} | FAILED:{reason}
    """
    capability_id = "sec3-xray.solana-static-analysis"

    def finish(outcome: ToolOutcome) -> str:
        return _record_scanner_outcome(
            scratch, outcome, context=context
        ).legacy_status()

    image = _resolve_sec3_image(image_ref)
    if image is None:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.UNAVAILABLE,
            "immutable Sec3 image digest is not configured",
        ))
    if not shutil.which("docker"):
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.UNAVAILABLE,
            "docker not found",
            provider_ref=image,
        ))

    # Verify Docker is running (hang-proof probe).
    probe_rc, _probe_out = _run_hardened(["docker", "info"], None, 15)
    if probe_rc in (124, 127):
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.UNAVAILABLE,
            "docker not available",
            provider_ref=image,
        ))
    if probe_rc != 0:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.UNAVAILABLE,
            "docker daemon not running",
            provider_ref=image,
        ))

    # Check project has Rust/Solana source files
    source_files = _iter_files(proj, (".rs",))
    if not source_files:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.SKIPPED,
            "no .rs files in project",
            provider_ref=image,
        ))

    # Source is immutable. X-Ray writes only to a dedicated scratchpad mount;
    # cwd=/output keeps generated SARIF outside the audit snapshot.
    output_dir = scratch / ".sec3-output"
    try:
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            f"cannot prepare isolated output directory: {type(exc).__name__}",
            provider_ref=image,
        ))
    proj_posix = str(proj.resolve()).replace("\\", "/")
    output_posix = str(output_dir.resolve()).replace("\\", "/")
    cmd = [
        "docker", "run", "--rm",
        "--tmpfs", "/tmp:rw,nosuid,size=1g",
        "-e", "CARGO_TARGET_DIR=/tmp/sec3-target",
        "-v", f"{proj_posix}:/workspace:ro",
        "-v", f"{output_posix}:/output:rw",
        "-w", "/output",
        image,
        "/workspace",
    ]

    # Hang-proof: temp-file drain + tree-kill (the X-Ray container / LLVM
    # workers can no longer wedge the parent on a held pipe handle).
    rc, _xray_out = _run_hardened(cmd, None, _SEC3_XRAY_TIMEOUT)
    if rc == 124:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            f"timeout after {_SEC3_XRAY_TIMEOUT}s",
            provider_ref=image,
        ))
    if rc == 127:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.UNAVAILABLE,
            "docker executable could not be started",
            provider_ref=image,
        ))
    if rc != 0:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            f"exit {rc}: scanner exited abnormally",
            provider_ref=image,
        ))

    # X-Ray writes SARIF into the isolated output mount.
    sarif_source = output_dir / _SEC3_SARIF_FILENAME
    sarif_dest = scratch / "sec3_results.sarif"

    if not sarif_source.exists():
        # Some versions write to current dir or use different name
        alt_names = ["x-ray-report.sarif", "report.sarif", "xray.sarif"]
        for alt in alt_names:
            alt_path = output_dir / alt
            if alt_path.exists():
                sarif_source = alt_path
                break

    if not sarif_source.exists() or sarif_source.stat().st_size < 10:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            f"exit {rc}, no SARIF produced",
            provider_ref=image,
        ))

    # Copy SARIF into its stable artifact name; source remains confined to the
    # dedicated output directory and the project tree is never mutated.
    try:
        shutil.copy2(str(sarif_source), str(sarif_dest))
    except Exception as exc:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            f"SARIF copy failed: {type(exc).__name__}",
            provider_ref=image,
        ))

    if not sarif_dest.exists():
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            "SARIF copy failed",
            provider_ref=image,
        ))
    try:
        sarif_data = _validated_sarif(sarif_dest)
    except ValueError as exc:
        return finish(ToolOutcome.debt(
            capability_id, "sec3-xray", ToolOutcomeState.FAILED,
            str(exc),
            provider_ref=image,
        ))

    # Parse SARIF and write human-readable summary
    finding_count = _parse_sec3_sarif(
        scratch, sarif_dest, sarif_data=sarif_data,
    )

    # Record in build_status.md
    bs = scratch / "build_status.md"
    if bs.exists():
        try:
            existing = bs.read_text(encoding="utf-8", errors="replace")
            if "SEC3" not in existing:
                bs.write_text(
                    existing.rstrip() + "\n\n## Sec3 X-Ray\n"
                    f"- SEC3_XRAY_AVAILABLE: true\n"
                    f"- SEC3_FINDINGS: {finding_count}\n",
                    encoding="utf-8",
                )
        except Exception:
            pass

    return finish(ToolOutcome.succeeded(
        capability_id,
        "sec3-xray",
        finding_count,
        artifacts=("sec3_results.sarif", "sec3_findings.md"),
        provider_ref=image,
    ))


def _parse_sec3_sarif(
    scratch: Path,
    sarif_path: Path,
    *,
    sarif_data: Optional[dict] = None,
) -> int:
    """Parse Sec3 X-Ray SARIF output and write sec3_findings.md summary. Returns finding count."""
    import json as _json

    try:
        data = (
            sarif_data
            if sarif_data is not None
            else _json.loads(
                sarif_path.read_text(encoding="utf-8", errors="replace")
            )
        )
    except Exception:
        _write_text(scratch / "sec3_findings.md",
                     "# Sec3 X-Ray Findings\n\n> SARIF parse failed\n")
        return 0

    findings: List[dict] = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            message = result.get("message", {}).get("text", "")
            level = result.get("level", "warning")
            locations = result.get("locations", [])
            loc_str = ""
            if locations:
                phys = locations[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {}).get("uri", "")
                region = phys.get("region", {})
                line = region.get("startLine", 0)
                loc_str = f"{art}:L{line}" if art else ""

            findings.append({
                "rule": rule_id,
                "message": message[:200],
                "level": level,
                "location": loc_str,
            })

    lines = [
        "# Sec3 X-Ray Findings",
        "",
        f"> **Total**: {len(findings)} findings",
        f"> **Source**: Sec3 X-Ray SARIF scan (v2.5.0 P4)",
        "",
        "| # | Rule | Level | Location | Message |",
        "|---|------|-------|----------|---------|",
    ]
    for i, f in enumerate(findings, 1):
        msg = f["message"].replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {i} | `{f['rule']}` | {f['level']} | `{f['location']}` | {msg} |")
    _write_text(scratch / "sec3_findings.md", "\n".join(lines))

    return len(findings)


# ---------------------------------------------------------------------------
# Wave-2 A5: mechanical dependency-vulnerability scan (L1 only)
# ---------------------------------------------------------------------------
#
# govulncheck (Go) / cargo audit (Rust) — a known-CVE dependency-vulnerability
# scan against each toolchain's own advisory database. Structured hits are
# handed to the depth/verify phases via `dependency_audit_findings.md`, same
# "deterministic tool run -> structured hits -> markdown artifact" shape as
# `_run_opengrep_scan` above. This is DISTINCT from `supply_chain_gate.py`'s
# fail-closed IOC gate (typosquat / malicious-package detection at install
# time) -- this is a vulnerability-database lookup against already-declared
# dependencies, not an IOC denylist. Never raises: any toolchain absence or
# tool failure degrades to a `TOOLCHAIN_UNAVAILABLE`/`FAILED` marker written
# to disk so the pipeline continues (haltless-by-design).

_GOVULNCHECK_TIMEOUT = 300  # seconds
_CARGO_AUDIT_TIMEOUT = 180  # seconds


def _parse_govulncheck_ndjson_validated(
    raw: str,
) -> Tuple[List[dict], bool]:
    """Parse `govulncheck -json` NDJSON stream into structured hits.

    Each line is a `Message` with either an `osv` entry (vulnerability
    metadata) or a `finding` (a concrete call-site trace). Only `finding`
    messages are surfaced as hits -- `osv`-only messages describe the wider
    vulnerability DB and are used only to backfill the summary text.

    ``parse_ok`` is true only when every non-empty line is a JSON object and
    at least one protocol message exists. This prevents rc=0 plus a banner,
    truncated stream, or arbitrary text from being promoted to clean-zero.
    """
    import json as _json

    findings: List[dict] = []
    osv_summary: Dict[str, str] = {}
    message_count = 0
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = _json.loads(line)
        except Exception:
            return [], False
        if not isinstance(msg, dict):
            return [], False
        message_count += 1
        osv = msg.get("osv")
        if isinstance(osv, dict) and osv.get("id"):
            osv_summary[osv["id"]] = str(osv.get("summary", ""))
        finding = msg.get("finding")
        if isinstance(finding, dict) and finding.get("osv"):
            trace = finding.get("trace") or []
            top = trace[0] if trace and isinstance(trace[0], dict) else {}
            osv_id = str(finding.get("osv", ""))
            findings.append({
                "id": osv_id,
                "module": str(top.get("module", "")),
                "package": str(top.get("package", "")),
                "version": str(top.get("version", "")),
                "function": str(top.get("function", "")),
                "fixed_version": str(finding.get("fixed_version", "")),
                "summary": osv_summary.get(osv_id, "")[:200],
            })
    return findings, message_count > 0


def _parse_govulncheck_ndjson(raw: str) -> List[dict]:
    """Compatibility projection returning only validated parsed findings."""
    findings, parse_ok = _parse_govulncheck_ndjson_validated(raw)
    return findings if parse_ok else []


def _dependency_outcome_status(outcome: ToolOutcome) -> str:
    if outcome.state is ToolOutcomeState.SUCCEEDED:
        return "WRITTEN"
    return outcome.legacy_status(unavailable_token="TOOLCHAIN_UNAVAILABLE")


_ADVISORY_MANIFEST = "plamen-advisory-source.json"
_ADVISORY_SOURCE_ENV = {
    "rustsec-local": "PLAMEN_RUSTSEC_DB",
    "govulndb-local": "PLAMEN_GOVULNDB",
}
_ADVISORY_SOURCE_SCHEMA = "plamen.advisory_source.v1"
_ADVISORY_MAX_DIRS = 20_000
_ADVISORY_MAX_FILES = 100_000
_ADVISORY_MAX_BYTES = 2 * 1024 * 1024 * 1024


def _parse_advisory_timestamp(value: object) -> datetime:
    text = str(value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def _advisory_content_sha256(root: Path) -> str:
    """Hash a bounded local advisory tree without trusting VCS metadata."""
    if root.is_symlink() or (
        hasattr(root, "is_junction") and root.is_junction()
    ):
        raise ValueError("advisory source root is a link or junction")
    digest = hashlib.sha256()
    count = 0
    total = 0
    directories = 0
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directories += 1
        if directories > _ADVISORY_MAX_DIRS:
            raise ValueError("advisory source exceeds bounded directory limits")
        directory = Path(dirpath)
        retained: list[str] = []
        for name in sorted(dirnames):
            if name == ".git":
                continue
            candidate = directory / name
            if candidate.is_symlink() or (
                hasattr(candidate, "is_junction")
                and candidate.is_junction()
            ):
                raise ValueError(
                    f"advisory source contains directory link: {candidate}"
                )
            retained.append(name)
        dirnames[:] = retained
        for name in sorted(filenames):
            path = directory / name
            if path.relative_to(root).as_posix() != _ADVISORY_MANIFEST:
                files.append(path)
                if len(files) > _ADVISORY_MAX_FILES:
                    raise ValueError(
                        "advisory source exceeds bounded file limits"
                    )
    for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        ):
            raise ValueError(f"advisory source contains symlink: {relative}")
        if not path.is_file():
            continue
        count += 1
        size = path.stat().st_size
        total += size
        if count > _ADVISORY_MAX_FILES or total > _ADVISORY_MAX_BYTES:
            raise ValueError("advisory source exceeds bounded hashing limits")
        digest.update(relative.as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _resolve_advisory_source(
    source_id: str,
) -> tuple[Optional[Path], str, str]:
    """Return (database path, canonical provider reference, issue).

    A successful known-CVE scan is authoritative only when its local advisory
    bytes, as-of time, and expiry are bound by a validated manifest.
    """
    env_name = _ADVISORY_SOURCE_ENV.get(source_id)
    if not env_name:
        return None, "", f"unknown advisory source: {source_id}"
    configured = os.environ.get(env_name, "").strip()
    if not configured:
        return None, "", f"{env_name} is not configured"
    root = Path(configured).expanduser()
    if not root.is_dir():
        return None, "", f"{env_name} is not a directory"
    manifest_path = root / _ADVISORY_MANIFEST
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, "", (
            f"advisory manifest unreadable: {type(exc).__name__}"
        )
    if not isinstance(manifest, dict):
        return None, "", "advisory manifest root is not an object"
    if (
        manifest.get("schema_version") != _ADVISORY_SOURCE_SCHEMA
        or manifest.get("source_id") != source_id
    ):
        return None, "", "advisory manifest schema/source mismatch"
    supplied_digest = str(manifest.get("content_sha256") or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", supplied_digest):
        return None, "", "advisory manifest content_sha256 is invalid"
    try:
        as_of = _parse_advisory_timestamp(manifest.get("as_of"))
        expires_at = _parse_advisory_timestamp(manifest.get("expires_at"))
        registry = load_toolchain_governance()
        policy = next(
            row
            for row in registry["advisory_sources"]
            if row.get("source_id") == source_id
        )
        provider = str(policy["provider"])
        if manifest.get("provider") != provider:
            raise ValueError("advisory provider mismatch")
        freshness_policy = policy["freshness_policy"]
        max_age = int(freshness_policy["max_age_seconds"])
        skew = int(
            freshness_policy.get("future_clock_skew_seconds", 0)
        )
        now = datetime.now(timezone.utc)
        if as_of.timestamp() > now.timestamp() + skew:
            raise ValueError("advisory as_of is in the future")
        if now.timestamp() - as_of.timestamp() > max_age:
            raise ValueError("advisory source is stale")
        if expires_at <= as_of:
            raise ValueError("advisory expiry does not follow as_of")
        if expires_at.timestamp() - as_of.timestamp() > max_age:
            raise ValueError("advisory expiry exceeds governance maximum")
        if now >= expires_at:
            raise ValueError("advisory source is expired")
        observed_digest = _advisory_content_sha256(root)
        if observed_digest != supplied_digest:
            raise ValueError("advisory content digest mismatch")
    except (KeyError, StopIteration, TypeError, ValueError, OSError) as exc:
        return None, "", f"advisory provenance invalid: {exc}"
    provider = {
        "schema_version": _ADVISORY_SOURCE_SCHEMA,
        "source_id": source_id,
        "provider": provider,
        "content_sha256": supplied_digest,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
    }
    return (
        root.resolve(),
        json.dumps(provider, sort_keys=True, separators=(",", ":")),
        "",
    )


def _advisory_source_is_external(root: Path, project: Path) -> bool:
    try:
        root.resolve().relative_to(project.resolve())
    except ValueError:
        return True
    return False


def _govulncheck_outcome(proj: Path) -> Tuple[ToolOutcome, List[dict]]:
    """Run `govulncheck -json ./...` against a Go module.

    Returns a typed outcome plus any schema-validated findings.
    """
    if not shutil.which("govulncheck"):
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.UNAVAILABLE,
            "govulncheck not found on PATH",
        ), []
    if not (proj / "go.mod").exists():
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.SKIPPED,
            "no go.mod",
        ), []

    advisory_root, provider_ref, provenance_issue = _resolve_advisory_source(
        "govulndb-local"
    )
    if advisory_root is None:
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.UNAVAILABLE,
            provenance_issue,
        ), []
    if not _advisory_source_is_external(advisory_root, proj):
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.UNAVAILABLE,
            "advisory database must be outside the untrusted target checkout",
        ), []
    govuln_env = dict(os.environ)
    govuln_env.update({
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOTOOLCHAIN": "local",
    })
    rc, out = _run_hardened(
        [
            "govulncheck",
            "-db",
            advisory_root.as_uri(),
            "-json",
            "./...",
        ],
        proj,
        _GOVULNCHECK_TIMEOUT,
        govuln_env,
    )
    if rc == 127:
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.UNAVAILABLE,
            "govulncheck not found on PATH",
        ), []
    if rc == 124:
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.FAILED,
            f"timeout after {_GOVULNCHECK_TIMEOUT}s",
        ), []

    findings, parse_ok = _parse_govulncheck_ndjson_validated(out)
    if not parse_ok:
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.FAILED,
            f"govulncheck exit {rc}, invalid NDJSON output",
        ), []
    # govulncheck exits 0 (clean) or 3 (vulnerabilities found) on a normal
    # run. A different code is incomplete even if a partial stream parsed.
    if rc not in (0, 3):
        return ToolOutcome.debt(
            "govulncheck.dependency-audit",
            "govulncheck",
            ToolOutcomeState.FAILED,
            f"govulncheck exit {rc}",
        ), findings
    return ToolOutcome.succeeded(
        "govulncheck.dependency-audit",
        "govulncheck",
        len(findings),
        artifacts=("dependency_audit_findings.md",),
        provider_ref=provider_ref,
    ), findings


def _govulncheck_scan(proj: Path) -> Tuple[str, List[dict]]:
    """Compatibility wrapper returning the legacy status-string shape."""
    outcome, findings = _govulncheck_outcome(proj)
    return _dependency_outcome_status(outcome), findings


def _parse_cargo_audit_json(raw: str) -> Tuple[List[dict], bool]:
    """Parse `cargo audit --json` output into structured hits.

    Returns (findings, parse_ok). `parse_ok` is False when the output was not
    valid cargo-audit JSON at all -- this distinguishes a genuine tool/setup
    failure (no Cargo.lock, advisory-db fetch failure) from a clean
    zero-vulnerability run (which also produces valid JSON with an empty list).
    """
    import json as _json

    text = (raw or "").strip()
    # The combined stdout+stderr capture can carry a warning banner ahead of
    # the JSON payload; locate the first '{' rather than assuming column 0.
    brace = text.find("{")
    if brace == -1:
        return [], False
    try:
        data = _json.loads(text[brace:])
    except Exception:
        return [], False
    if not isinstance(data, dict):
        return [], False
    vulnerabilities = data.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        return [], False
    vulns = vulnerabilities.get("list")
    if not isinstance(vulns, list):
        return [], False
    findings: List[dict] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        advisory = v.get("advisory") or {}
        pkg = v.get("package") or {}
        patched = ((v.get("versions") or {}).get("patched")) or []
        cvss = advisory.get("cvss")
        severity = ""
        if isinstance(cvss, dict):
            severity = str(cvss.get("severity") or "")
        if not severity:
            severity = str(advisory.get("severity") or "")
        findings.append({
            "id": str(advisory.get("id", "")),
            "package": str(pkg.get("name", "")),
            "version": str(pkg.get("version", "")),
            "title": str(advisory.get("title", ""))[:200],
            "severity": severity,
            "patched": ", ".join(str(p) for p in patched) if patched else "",
            "url": str(advisory.get("url", "")),
        })
    return findings, True


def _cargo_audit_outcome(proj: Path) -> Tuple[ToolOutcome, List[dict]]:
    """Run `cargo audit --json` against a Rust workspace.

    Returns a typed outcome plus any schema-validated findings.
    """
    cargo_audit_binary = shutil.which("cargo-audit")
    if not cargo_audit_binary:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.UNAVAILABLE,
            "cargo-audit not found on PATH",
        ), []
    if not (proj / "Cargo.toml").exists():
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.SKIPPED,
            "no Cargo.toml",
        ), []

    # Invoke the resolved plugin binary directly. Running `cargo audit` in an
    # untrusted checkout allows target-controlled Cargo aliases to interpose.
    probe_rc, _probe_out = _run_hardened(
        [cargo_audit_binary, "--version"], proj, 30,
    )
    if probe_rc == 127:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.UNAVAILABLE,
            "cargo-audit not found on PATH",
        ), []
    if probe_rc != 0:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.UNAVAILABLE,
            "cargo-audit executable probe failed",
        ), []

    advisory_root, provider_ref, provenance_issue = _resolve_advisory_source(
        "rustsec-local"
    )
    if advisory_root is None:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.UNAVAILABLE,
            provenance_issue,
        ), []
    if not _advisory_source_is_external(advisory_root, proj):
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.UNAVAILABLE,
            "advisory database must be outside the untrusted target checkout",
        ), []
    lockfile = (proj / "Cargo.lock").resolve()
    if not lockfile.is_file():
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.SKIPPED,
            "no Cargo.lock",
        ), []
    # A neutral working directory prevents target-controlled
    # `.cargo/audit.toml` from silently ignoring advisories.
    with tempfile.TemporaryDirectory(prefix="plamen-cargo-audit-") as neutral:
        neutral_path = Path(neutral)
        cargo_home = neutral_path / "cargo-home"
        cargo_home.mkdir()
        audit_env = dict(os.environ)
        audit_env["CARGO_HOME"] = str(cargo_home)
        audit_env["CARGO_NET_OFFLINE"] = "true"
        rc, out = _run_hardened(
            [
                cargo_audit_binary,
                "audit",
                "--json",
                "--no-fetch",
                "--db",
                str(advisory_root),
                "--file",
                str(lockfile),
            ],
            neutral_path,
            _CARGO_AUDIT_TIMEOUT,
            audit_env,
        )
    if rc == 124:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.FAILED,
            f"timeout after {_CARGO_AUDIT_TIMEOUT}s",
        ), []

    findings, parse_ok = _parse_cargo_audit_json(out)
    if not parse_ok:
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.FAILED,
            f"cargo audit exit {rc}, invalid JSON output",
        ), []
    # cargo-audit uses 0 for clean and 1 when advisories are present. Other
    # codes mean setup/database failure; retain parsed partial hits but do not
    # assert complete coverage.
    if rc not in (0, 1):
        return ToolOutcome.debt(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            ToolOutcomeState.FAILED,
            f"cargo audit exit {rc}",
        ), findings
    return ToolOutcome.succeeded(
        "cargo-audit.dependency-audit",
        "cargo-audit",
        len(findings),
        artifacts=("dependency_audit_findings.md",),
        provider_ref=provider_ref,
    ), findings


def _cargo_audit_scan(proj: Path) -> Tuple[str, List[dict]]:
    """Compatibility wrapper returning the legacy status-string shape."""
    outcome, findings = _cargo_audit_outcome(proj)
    return _dependency_outcome_status(outcome), findings


def _write_dependency_audit_md(
    scratch: Path, sections: List[Tuple[str, str, List[dict]]],
) -> int:
    """Write `dependency_audit_findings.md` from one or more ecosystem scan
    sections (Go / Rust). Returns the total finding count across sections."""
    total = 0
    lines = [
        "# Dependency Audit Findings", "",
        "> **Source**: mechanical `govulncheck` (Go) / `cargo audit` (Rust) scan.",
        "> Distinct from the supply-chain IOC gate (typosquat / malicious-package",
        "> detection at install time) -- this is a known-CVE dependency-",
        "> vulnerability lookup against each toolchain's own advisory database.",
        "",
    ]
    for label, status, findings in sections:
        lines.append(f"## {label}")
        lines.append("")
        lines.append(f"**Status**: {status}")
        lines.append("")
        if status.startswith("TOOLCHAIN_UNAVAILABLE"):
            lines.append(
                "TOOLCHAIN_UNAVAILABLE: dependency-vulnerability scan skipped "
                "for this ecosystem; degrading without findings."
            )
            lines.append("")
            continue
        if status.startswith(("SKIPPED", "FAILED")) and not findings:
            lines.append("")
            continue
        if status.startswith("FAILED") and findings:
            lines.append(
                "> Partial schema-valid hits are retained below, but this "
                "capability did not establish complete coverage."
            )
            lines.append("")
        total += len(findings)
        if not findings:
            lines.append("No known-vulnerability dependency findings.")
            lines.append("")
            continue
        if label.startswith("Go"):
            lines += [
                "| # | Advisory | Module | Package | Called Function | Fixed Version | Summary |",
                "|---|----------|--------|---------|------------------|----------------|---------|",
            ]
            for i, f in enumerate(findings, 1):
                summ = str(f.get("summary", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| {i} | `{f.get('id', '')}` | `{f.get('module', '')}` | "
                    f"`{f.get('package', '')}` | `{f.get('function', '')}` | "
                    f"{f.get('fixed_version', '')} | {summ} |"
                )
        else:
            lines += [
                "| # | Advisory | Package | Version | Severity | Patched | Title |",
                "|---|----------|---------|---------|----------|---------|-------|",
            ]
            for i, f in enumerate(findings, 1):
                title = str(f.get("title", "")).replace("|", "\\|").replace("\n", " ")
                lines.append(
                    f"| {i} | `{f.get('id', '')}` | `{f.get('package', '')}` | "
                    f"{f.get('version', '')} | {f.get('severity', '') or '-'} | "
                    f"{f.get('patched', '') or '-'} | {title} |"
                )
        lines.append("")
    _write_text(scratch / "dependency_audit_findings.md", "\n".join(lines))
    return total


def _run_dependency_audit_l1(
    scratch: Path,
    proj: Path,
    language: str,
    *,
    context: Optional[dict] = None,
) -> str:
    """L1 mechanical dependency-vulnerability scan (Wave-2 A5).

    Runs `govulncheck` for a Go module and/or `cargo audit` for a Rust
    workspace (both for `language=mixed`) and writes the structured hits to
    `dependency_audit_findings.md` for the depth/verify phases to consume.
    DISTINCT from `supply_chain_gate.py`'s fail-closed IOC gate -- do not
    conflate the two.

    Never raises: any unexpected failure is caught and degrades to a `FAILED`
    marker written to disk (haltless-by-design), matching the OpenGrep/SCIP
    degrade-continue contract used elsewhere in this module.

    Returns a combined status string, e.g.
    'go=WRITTEN:3; rust=SKIPPED:no Cargo.toml'.
    """
    try:
        lang = (language or "").strip().lower()
        sections: List[Tuple[str, str, List[dict]]] = []
        statuses: List[str] = []
        outcomes: List[ToolOutcome] = []

        def run_capability(
            label: str,
            prefix: str,
            capability_id: str,
            tool: str,
            source_id: str,
            scanner,
        ) -> None:
            try:
                status, findings = scanner(proj)
            except Exception as exc:
                status = f"FAILED:{type(exc).__name__}:{exc}"
                findings = []
            sections.append((label, status, findings))
            statuses.append(
                f"{prefix}={status}:{len(findings)}"
                if status == "WRITTEN"
                else f"{prefix}={status}"
            )
            if status == "WRITTEN":
                _root, provider_ref, issue = _resolve_advisory_source(source_id)
                if provider_ref:
                    outcomes.append(ToolOutcome.succeeded(
                        capability_id,
                        tool,
                        len(findings),
                        artifacts=("dependency_audit_findings.md",),
                        provider_ref=provider_ref,
                    ))
                    return
                status = f"FAILED:{issue}"
            reason = status.partition(":")[2] or status
            if status.startswith("TOOLCHAIN_UNAVAILABLE"):
                state = ToolOutcomeState.UNAVAILABLE
            elif status.startswith("SKIPPED"):
                state = ToolOutcomeState.SKIPPED
            else:
                state = ToolOutcomeState.FAILED
            outcomes.append(ToolOutcome.debt(
                capability_id, tool, state, reason,
            ))

        # Each ecosystem is isolated. A parser/process defect in one scanner
        # cannot suppress the other half of a mixed L1 dependency audit.
        if lang in ("go", "mixed"):
            run_capability(
                "Go (govulncheck)",
                "go",
                "govulncheck.dependency-audit",
                "govulncheck",
                "govulndb-local",
                _govulncheck_scan,
            )
        if lang in ("rust", "mixed"):
            run_capability(
                "Rust (cargo audit)",
                "rust",
                "cargo-audit.dependency-audit",
                "cargo-audit",
                "rustsec-local",
                _cargo_audit_scan,
            )
        if not sections:
            reason = (
                "no govulncheck/cargo-audit route for "
                f"language={lang!r}"
            )
            status = f"TOOLCHAIN_UNAVAILABLE:{reason}"
            sections.append(("Dependency Audit", status, []))
            statuses.append(status)
            outcomes.append(ToolOutcome.debt(
                "dependency-audit.routing",
                "dependency-audit",
                ToolOutcomeState.UNAVAILABLE,
                reason,
            ))
        _write_dependency_audit_md(scratch, sections)
        for outcome in outcomes:
            _record_scanner_outcome(
                scratch, outcome, context=context
            )
        return "; ".join(statuses)
    except Exception as e:
        # Absolute degrade-continue floor -- never let this step raise into
        # the pre-pass/pre-breadth hook. Still leave a marker artifact so
        # downstream gates see a real file rather than a missing one.
        try:
            _write_text(
                scratch / "dependency_audit_findings.md",
                f"# Dependency Audit Findings\n\nFAILED:{e.__class__.__name__}\n",
            )
        except Exception:
            pass
        return f"FAILED:{e.__class__.__name__}"


# ---------------------------------------------------------------------------
# Cosmos-SDK / CometBFT framework detection (L1)
# ---------------------------------------------------------------------------
#
# Framework triggers only (like Foundry/Anchor) — never a named chain's answer.
# When a Cosmos-SDK / CometBFT / Tendermint dependency is found in the manifest,
# mechanically seed the COSMOS_SDK flag (and IBC when ibc-go is present) so the
# COSMOS_SDK_MODULE_SAFETY injectable skill is marked Required=YES. Manifest
# priority: a dependency in go.mod/Cargo.toml is authoritative.

# Dependency-path substrings that identify the Cosmos-SDK / CometBFT framework.
_COSMOS_MARKERS = (
    "cosmossdk.io",
    "github.com/cosmos/cosmos-sdk",
    "github.com/cometbft/cometbft",
    "github.com/tendermint/tendermint",
    "github.com/tendermint/tm-db",
)
# IBC markers (a distinct cross-chain subsystem flag).
_IBC_MARKERS = (
    "github.com/cosmos/ibc-go",
    "cosmossdk.io/ibc",
)
# Cosmos-SDK Rust ecosystem (less common, but cw / cosmwasm chains link these).
_COSMOS_RUST_MARKERS = (
    "cosmwasm-std",
    "cosmrs",
    "cosmos-sdk-proto",
    "tendermint-rpc",
    "tendermint-proto",
)


def _detect_cosmos_markers(proj: Path) -> Tuple[bool, bool]:
    """Scan go.mod and Cargo.toml for Cosmos-SDK / CometBFT / IBC markers.

    Returns (cosmos_sdk_found, ibc_found). Best-effort and non-fatal: any read
    failure yields (False, False) for that manifest. Also checks an `x/<module>`
    tree as a corroborating structural signal for Go app-chains.
    """
    cosmos = False
    ibc = False
    for manifest in ("go.mod", "Cargo.toml"):
        text = _read_text(proj / manifest)
        if not text:
            continue
        low = text.lower()
        if any(m in low for m in _COSMOS_MARKERS):
            cosmos = True
        if manifest == "Cargo.toml" and any(m in low for m in _COSMOS_RUST_MARKERS):
            cosmos = True
        if any(m in low for m in _IBC_MARKERS):
            ibc = True
    # Structural corroboration: a top-level `x/` dir with module subdirs is the
    # canonical Cosmos-SDK module layout. Only used to confirm, never alone —
    # manifest dependency is the authoritative signal above.
    if not cosmos:
        try:
            xdir = proj / "x"
            if xdir.is_dir():
                has_module = any(
                    (sub / "module.go").exists() or (sub / "keeper").is_dir()
                    for sub in xdir.iterdir()
                    if sub.is_dir()
                )
                # Require a manifest hint too, to avoid false positives on
                # unrelated `x/` dirs.
                if has_module and (proj / "go.mod").exists():
                    gm = _read_text(proj / "go.mod").lower()
                    if any(m in gm for m in _COSMOS_MARKERS):
                        cosmos = True
        except OSError:
            pass
    return cosmos, ibc


def _seed_mechanical_flag(
    scratch: Path,
    *,
    rows_to_flip: Dict[str, str],
    flags: List[str],
    detected_patterns_header: str,
    detected_patterns_body: str,
    summary_note: str,
) -> None:
    """Shared mechanical SECOND-CHANNEL skill dispatch (3 steps).

    A deterministic backup to the LLM recon's flag detection: when a caller's
    own mechanical marker scan finds a trigger, this helper (1) flips the
    matching skill row(s) in `template_recommendations.md` to Required=YES,
    (2) emits `flags` into `detected_patterns.md`, and (3) appends a
    subsystem-flags line to `recon_summary.md` — so a skill still fires even
    when the LLM recon pass misses the trigger. Mechanical + manifest-priority:
    only rewrites pre-pass-owned files (those still carrying `_PREPASS_MARKER`);
    enriched files are left untouched.

    `rows_to_flip` maps skill name -> rationale phrase appended to that row's
    Rationale column. `flags` is the ordered list of flag tokens to emit.
    Callers own detection (whether to call this at all) and status-string
    formatting (DETECTED/NOT_DETECTED/FAILED) — this helper unconditionally
    performs the 3 writes.
    """
    # 1) Flip the relevant skill rows in template_recommendations.md to
    #    Required=YES (only if the file is still pre-pass-owned).
    tr = scratch / "template_recommendations.md"
    if tr.exists():
        head = _read_text(tr).split("\n", 1)[0]
        if head == _PREPASS_MARKER:
            body = _read_text_unmarked(tr)
            new_lines = []
            flipped = False
            for line in body.splitlines():
                matched_skill = next(
                    (
                        s
                        for s in rows_to_flip
                        if s in line and line.lstrip().startswith("|")
                    ),
                    None,
                )
                if matched_skill is not None:
                    cols = line.split("|")
                    # Row shape: | | `SKILL` | trigger | Required | Rationale | |
                    # Find the Required column (the cell whose stripped/upper
                    # value is NO or YES) and flip it, set rationale.
                    for ci, cell in enumerate(cols):
                        cval = cell.strip().strip("`").strip("*").upper()
                        if cval in ("NO", "YES"):
                            cols[ci] = " YES "
                            # Rationale is the next non-trailing cell.
                            if ci + 1 < len(cols) and cols[ci + 1].strip() not in ("", "|"):
                                cols[ci + 1] = " " + rows_to_flip[matched_skill]
                            flipped = True
                            break
                    line = "|".join(cols)
                new_lines.append(line)
            if flipped:
                _force_overwrite_prepass(tr, "\n".join(new_lines) + "\n")

    # 2) Emit flags into detected_patterns.md (create it if absent).
    dp = scratch / "detected_patterns.md"
    flag_block = (
        f"\n## Flags (mechanical — {detected_patterns_header})\n"
        + "".join(f"- `{f}`\n" for f in flags)
        + "\n" + detected_patterns_body + "\n"
    )
    if dp.exists() and _read_text(dp).split("\n", 1)[0] == _PREPASS_MARKER:
        _force_overwrite_prepass(dp, _read_text_unmarked(dp) + flag_block)
    elif not dp.exists():
        _write_text(
            dp,
            "# Detected Patterns\n\n[LLM TO ENRICH] Pre-pass stub.\n" + flag_block,
        )

    # 3) Append a subsystem-flags line to recon_summary.md so Phase 2
    #    instantiation sees the flags (mirrors the DATA_AVAILABILITY pattern).
    rs = scratch / "recon_summary.md"
    if rs.exists() and _read_text(rs).split("\n", 1)[0] == _PREPASS_MARKER:
        summary_line = (
            "\n- **Subsystem Flags (mechanical)**: "
            + ", ".join(flags)
            + f" ({summary_note})\n"
        )
        _force_overwrite_prepass(rs, _read_text_unmarked(rs) + summary_line)


def _seed_cosmos_flag(scratch: Path, proj: Path) -> str:
    """If Cosmos-SDK markers are present, mark COSMOS_SDK_MODULE_SAFETY Required=YES
    and emit COSMOS_SDK (and IBC) flags into the recon artifacts.

    Thin caller of `_seed_mechanical_flag` — see that function for the shared
    3-step mechanical dispatch this performs.

    Returns: DETECTED:COSMOS_SDK[,IBC] | NOT_DETECTED | FAILED:{reason}
    """
    try:
        cosmos, ibc = _detect_cosmos_markers(proj)
        if not cosmos:
            return "NOT_DETECTED"

        flags = ["COSMOS_SDK"] + (["IBC"] if ibc else [])

        # Flip COSMOS_SDK_MODULE_SAFETY always; COSMOS_IBC_SECURITY only when
        # the IBC flag is present. skill_name -> rationale phrase.
        rows_to_flip = {
            "COSMOS_SDK_MODULE_SAFETY": (
                "Cosmos-SDK / CometBFT framework detected in manifest "
                "(mechanical). "
            ),
        }
        if ibc:
            rows_to_flip["COSMOS_IBC_SECURITY"] = (
                "IBC / ibc-go cross-chain integration detected in manifest "
                "(mechanical). "
            )

        _seed_mechanical_flag(
            scratch,
            rows_to_flip=rows_to_flip,
            flags=flags,
            detected_patterns_header="Cosmos-SDK framework",
            detected_patterns_body=(
                "Cosmos-SDK / CometBFT / Tendermint dependency detected in the "
                "project manifest. Loads `cosmos-sdk-module-safety` into "
                "depth-consensus-invariant and depth-state-trace."
            ),
            summary_note="Cosmos-SDK / CometBFT framework detected in manifest",
        )

        return "DETECTED:" + ",".join(flags)
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"


# ---------------------------------------------------------------------------
# Cross-chain message-handler marker detection (SC, EVM)
# ---------------------------------------------------------------------------
#
# Pure marker/import grep over production source — a low-false-positive
# structural signal (a receiver/peer-registration function name), never a
# named protocol's answer. When a cross-chain messaging entry point is found,
# mechanically seed the CROSS_CHAIN_MSG flag so the CROSS_CHAIN_MESSAGE_
# INTEGRITY skill is marked Required=YES, backing up the LLM recon's own flag
# detection with a deterministic second channel (see skill-index.md).

# Unique, low-false-positive receiver/registration function names for common
# cross-chain messaging entry points (generic mechanism — illustrative only).
_CROSS_CHAIN_MSG_MARKERS = (
    "lzReceive",
    "ccipReceive",
    "receiveWormholeMessages",
    "setPeer",
    "setTrustedRemote",
)


def _detect_cross_chain_msg_markers(proj: Path) -> bool:
    """Scan production `.sol` source for cross-chain message-handler markers.

    Best-effort and non-fatal: any read failure is skipped, never raises.
    Restricted to production source (test/mock/script/lib dirs excluded via
    `_production_source_files`) to keep the signal low-false-positive.
    """
    try:
        for p in _production_source_files(proj, (".sol",)):
            text = _read_text(p)
            if not text:
                continue
            if any(m in text for m in _CROSS_CHAIN_MSG_MARKERS):
                return True
    except Exception:
        pass
    return False


def _seed_cross_chain_msg_flag(scratch: Path, proj: Path) -> str:
    """If cross-chain message-handler markers are present, mark
    CROSS_CHAIN_MESSAGE_INTEGRITY Required=YES and emit the CROSS_CHAIN_MSG
    flag into the recon artifacts.

    Thin caller of `_seed_mechanical_flag` — see that function for the shared
    3-step mechanical dispatch this performs.

    Returns: DETECTED:CROSS_CHAIN_MSG | NOT_DETECTED | FAILED:{reason}
    """
    try:
        if not _detect_cross_chain_msg_markers(proj):
            return "NOT_DETECTED"

        flags = ["CROSS_CHAIN_MSG"]
        rows_to_flip = {
            "CROSS_CHAIN_MESSAGE_INTEGRITY": (
                "Cross-chain message-handler marker (lzReceive/ccipReceive/"
                "receiveWormholeMessages/setPeer/setTrustedRemote) detected "
                "in production source (mechanical). "
            ),
        }

        _seed_mechanical_flag(
            scratch,
            rows_to_flip=rows_to_flip,
            flags=flags,
            detected_patterns_header="cross-chain message handler",
            detected_patterns_body=(
                "Cross-chain message-handler entry point (receiver or peer/"
                "trusted-remote registration function) detected in production "
                "source. Loads `cross-chain-message-integrity` into breadth "
                "agents and depth-external."
            ),
            summary_note="cross-chain message-handler marker detected in production source",
        )

        return "DETECTED:" + ",".join(flags)
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"


# ---------------------------------------------------------------------------
# Generic (non-brand) external-dependency marker detection (SC, EVM)
#
# Fix B / Hook 1 second channel: `NAMED_EXTERNAL_PROTOCOL` (TASK 6 in the
# recon prompt) is a closed ~15-name brand regex and misses any custom,
# unfamous bridge/messenger/pool. This mechanical backup uses a purely
# STRUCTURAL test — never a protocol/token/contract name (Part-0):
#   (a) an `interface` is declared (imported or local) with NO corresponding
#       in-repo `contract` implementation of the same name (i.e. only an ABI
#       is known, not a vendored function body);
#   (b) the interface name is NOT a recognized ERC/EIP-standard or OZ/
#       solmate/solady-class utility name (a small, generic allowlist of
#       standard interface/utility names — not brands);
#   (c) an instance of that interface is called with the return value
#       consumed (`IFoo(addr).bar(...)` used as an expression, not a bare
#       statement).
# Sets EXTERNAL_DEPENDENCY (alias NAMED_EXTERNAL_PROTOCOL for back-compat)
# so INTEGRATION_HAZARD_RESEARCH still fires even when the LLM recon pass
# misses a custom dependency. Best-effort, non-fatal, bounded.
# ---------------------------------------------------------------------------

_EVM_INTERFACE_DECL_RE = re.compile(r"\binterface\s+([A-Za-z_]\w*)\b")
_EVM_CONTRACT_DECL_RE = re.compile(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)\b")

# Recognized ERC/EIP-standard + OZ/solmate/solady-class utility interface
# names. Generic (standard names, not protocol brands) — mirrors the plan's
# explicit "not a recognized stdlib/OZ/solmate-class utility" exclusion.
_EVM_STDLIB_INTERFACE_NAMES = frozenset({
    "IERC20", "IERC20Metadata", "IERC20Permit", "IERC721", "IERC721Receiver",
    "IERC721Metadata", "IERC721Enumerable", "IERC1155", "IERC1155Receiver",
    "IERC1155MetadataURI", "IERC165", "IERC2612", "IERC2981", "IERC4626",
    "IERC777", "IERC777Recipient", "IERC777Sender", "IWETH", "IWETH9",
    "IMulticall", "IMulticall3", "IOwnable", "IAccessControl", "IPausable",
    "IPermit2", "IUniswapV2ERC20",
})

_MAX_EXTERNAL_DEPENDENCY_MARKERS = 10


def _detect_external_dependency_markers(proj: Path) -> List[Tuple[str, str]]:
    """Scan production `.sol` source for the 3-part structural test above.

    Returns up to `_MAX_EXTERNAL_DEPENDENCY_MARKERS` (interface_name,
    file:line) pairs. Best-effort and non-fatal: any read/regex failure
    yields an empty (or partial) result, never raises.
    """
    out: List[Tuple[str, str]] = []
    try:
        files = _production_source_files(proj, (".sol",))
        if not files:
            return out
        interface_decls: Dict[str, str] = {}
        contract_impls: set = set()
        texts: Dict[Path, str] = {}
        for f in files:
            text = _read_text(f)
            if not text:
                continue
            texts[f] = text
            for m in _EVM_INTERFACE_DECL_RE.finditer(text):
                name = m.group(1)
                interface_decls.setdefault(name, f"{_rel(f, proj)}:L{_line_of(text, m.start())}")
            for m in _EVM_CONTRACT_DECL_RE.finditer(text):
                contract_impls.add(m.group(1))
        for name, loc in sorted(interface_decls.items()):
            if name in _EVM_STDLIB_INTERFACE_NAMES or name in contract_impls:
                continue  # recognized utility, or a real in-repo impl exists
            call_re = re.compile(rf"\b{re.escape(name)}\s*\([^)]*\)\s*\.\s*\w+\s*\(")
            if any(call_re.search(text) for text in texts.values()):
                out.append((name, loc))
            if len(out) >= _MAX_EXTERNAL_DEPENDENCY_MARKERS:
                break
    except Exception:
        return out
    return out


def _seed_external_dependency_flag(scratch: Path, proj: Path) -> str:
    """If a generic (non-brand) external dependency is detected, mark
    INTEGRATION_HAZARD_RESEARCH Required=YES and emit the EXTERNAL_DEPENDENCY
    (alias NAMED_EXTERNAL_PROTOCOL) flag into the recon artifacts.

    Thin caller of `_seed_mechanical_flag` — see that function for the shared
    3-step mechanical dispatch this performs.

    Returns: DETECTED:EXTERNAL_DEPENDENCY,NAMED_EXTERNAL_PROTOCOL | NOT_DETECTED | FAILED:{reason}
    """
    try:
        markers = _detect_external_dependency_markers(proj)
        if not markers:
            return "NOT_DETECTED"

        flags = ["EXTERNAL_DEPENDENCY", "NAMED_EXTERNAL_PROTOCOL"]
        names = ", ".join(f"`{n}` ({loc})" for n, loc in markers)
        rows_to_flip = {
            "INTEGRATION_HAZARD_RESEARCH": (
                "Generic (non-brand, structural) external dependency "
                f"detected (mechanical): {names}. "
            ),
        }

        _seed_mechanical_flag(
            scratch,
            rows_to_flip=rows_to_flip,
            flags=flags,
            detected_patterns_header="generic external dependency",
            detected_patterns_body=(
                "Imported/declared interface(s) with no in-repo implementation "
                "and a consumed return value, not matching a recognized "
                "ERC/EIP-standard or OZ/solmate/solady-class utility name: "
                + names + ". Research obligation routed to "
                "external_dependency_research.md (TASK 11)."
            ),
            summary_note="generic external dependency detected (non-brand, structural)",
        )

        return "DETECTED:" + ",".join(flags)
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"


# ---------------------------------------------------------------------------
# Wave-2 A6: embedded Move-source detection (L1) -- closes the L1<->Move
# skill-lane seam. An L1 (Go/Rust node-client) repo can embed a Move-VM
# execution layer as `.move` sources; those files currently get no Move
# methodology at all. Reuses the SAME `.move` suffix scan already used for
# native Aptos/Sui SC audits (`_production_source_files(proj, (".move",))`,
# see `_bake_move_graph` above and `_OPENGREP_LANG_EXT`) -- the trigger is the
# file extension, never a protocol/chain name (Part-0). ROUTING ONLY: this
# just sets the HAS_MOVE_SOURCES flag; the depth-agent prompt builder in
# plamen_driver.py is what routes the already-vetted aptos/sui core Move
# skills (MOVE_SAFETY_CORE_DIRECTIVES / ABILITY_ANALYSIS / TYPE_SAFETY) into
# depth-state-trace / depth-external when this flag is set.
# ---------------------------------------------------------------------------


def _detect_move_sources_l1(proj: Path) -> bool:
    """True when the L1 repo contains at least one production `.move` source
    file (an embedded Move-VM execution layer). Mechanism-only: reuses the
    existing production-source `.move` suffix scan. Never raises."""
    try:
        return bool(_production_source_files(proj, (".move",)))
    except Exception:
        return False


def _seed_move_sources_flag(scratch: Path, proj: Path) -> str:
    """If the L1 repo embeds `.move` sources, set HAS_MOVE_SOURCES and surface
    a 'Move Skill Routing' section in `template_recommendations.md` so the
    depth-agent prompt builder (plamen_driver.py `_build_depth_worker_prompt`)
    can route the vetted aptos/sui core Move skills into depth-state-trace and
    depth-external. Routing only -- no new methodology text, no new skill
    files (the aptos/sui SKILL.md files are read verbatim).

    Unlike `_seed_cosmos_flag`/`_seed_cross_chain_msg_flag`, the 3 routed
    skill names are NOT rows in the L1 skill-index table (they live in the
    aptos/sui trees), so this writes its own dedicated table section directly
    rather than flipping an existing row via `_seed_mechanical_flag`'s
    `rows_to_flip`. The shared flags-into-`detected_patterns.md` +
    `recon_summary.md` steps are still reused (empty `rows_to_flip`).

    Returns: DETECTED:HAS_MOVE_SOURCES | NOT_DETECTED | FAILED:{reason}
    """
    try:
        if not _detect_move_sources_l1(proj):
            return "NOT_DETECTED"

        move_section = (
            "\n### Move Skill Routing (mechanical — HAS_MOVE_SOURCES)\n\n"
            "| Skill | Trigger | Required | Rationale |\n"
            "|-------|---------|----------|-----------|\n"
            + "".join(
                f"| `{skill}` | `.move` sources embedded in L1 repo | YES | "
                "Embedded Move-VM execution layer detected (mechanical `.move` "
                "suffix scan). Routed into depth-state-trace and "
                "depth-external. |\n"
                for skill in (
                    "MOVE_SAFETY_CORE_DIRECTIVES", "ABILITY_ANALYSIS", "TYPE_SAFETY",
                )
            )
        )
        tr = scratch / "template_recommendations.md"
        if tr.exists() and _read_text(tr).split("\n", 1)[0] == _PREPASS_MARKER:
            _force_overwrite_prepass(tr, _read_text_unmarked(tr) + move_section)
        elif not tr.exists():
            _write_text(
                tr,
                "# Template Recommendations\n\n[LLM TO ENRICH] Pre-pass stub.\n"
                + move_section,
            )

        _seed_mechanical_flag(
            scratch,
            rows_to_flip={},
            flags=["HAS_MOVE_SOURCES"],
            detected_patterns_header="embedded Move sources",
            detected_patterns_body=(
                "`.move` source files detected in this L1 (Go/Rust node-"
                "client) repository -- an embedded Move-VM execution layer. "
                "Routes the vetted aptos/sui core Move skills "
                "(MOVE_SAFETY_CORE_DIRECTIVES, ABILITY_ANALYSIS, TYPE_SAFETY) "
                "into depth-state-trace and depth-external."
            ),
            summary_note="embedded .move sources detected (mechanical)",
        )

        return "DETECTED:HAS_MOVE_SOURCES"
    except Exception as e:
        return f"FAILED:{e.__class__.__name__}"


def _read_text_unmarked(p: Path) -> str:
    """Read a pre-pass file, stripping the leading marker line if present."""
    body = _read_text(p)
    if body.startswith(_PREPASS_MARKER):
        return body.split("\n", 1)[1] if "\n" in body else ""
    return body


def _force_overwrite_prepass(p: Path, content: str) -> bool:
    """Overwrite a pre-pass-owned file, re-stamping the marker.

    Caller MUST have already confirmed the file is pre-pass-owned (marker
    present) or absent. Unlike `_write_text`, this does not re-check the marker,
    because the new content already had its marker stripped by the caller.
    """
    try:
        p.write_text(_PREPASS_MARKER + "\n" + content, encoding="utf-8")
        return True
    except Exception:
        return False


# Main entry point renderer.  The public transaction wrapper is below it.
def _render_recon_prepass(config: dict) -> Dict[str, str]:
    """Write mechanical recon artifacts. Returns {artifact: status} dict."""
    results: Dict[str, str] = {}

    def _safe(name: str, fn):
        try:
            results[name] = fn()
        except Exception as e:
            results[name] = f"FAILED:{e.__class__.__name__}"

    try:
        scratch = Path(config["scratchpad"])
        proj = Path(config["project_root"])
        lang = (config.get("language") or "evm").lower()
        pipeline = (config.get("pipeline") or "sc").lower()
    except Exception as e:
        return {"_init": f"FAILED:{e}"}

    try:
        scratch.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        return {"_mkdir_scratch": f"FAILED:{e}"}

    try:
        tool_context = build_tool_execution_context(
            config,
            phase="recon-prebreadth",
        )
    except (OSError, ToolCoverageLedgerError, TypeError, ValueError):
        # Precise/scanner success will fail closed into typed coverage debt.
        tool_context = None

    skill_index = _plamen_home() / "rules" / "skill-index.md"

    # RECON-1/RECON-2: slow external scanners (SCIP bake, Sec3 X-Ray, OpenGrep)
    # must NOT run in the startup pre-pass by default. At startup the driver has
    # not planted _v2_checkpoint.json or printed the first phase, so a multi-
    # minute scan looks like a dead launch (the chronic 0-byte-stdio class).
    # They run instead in the driver's pre-breadth hook where the TUI heartbeat
    # and disk gate are active. Keep the old startup behavior behind an explicit
    # escape hatch for local debugging.
    run_startup_scanners = (
        os.environ.get("PLAMEN_PREPASS_EXTERNAL_SCANNERS") == "1"
        or bool(config.get("prepass_external_scanners"))
    )

    if pipeline == "l1":
        _safe("subsystem_map.md",    lambda: _write_subsystem_map_l1(scratch, proj))
        _safe("trust_boundaries.md", lambda: _write_trust_boundaries_l1(scratch, proj))
        _safe("attack_surface.md",   lambda: _write_attack_surface_l1(scratch, proj))
        _safe("threat_model.md",     lambda: _write_design_or_threat_stub(scratch, pipeline))
    elif lang == "daml":
        # DAML: no mechanical prepass (read-driven). Write a marker plus
        # [LLM TO ENRICH] stubs for every SC recon artifact so prepass-read
        # gates never fail; the recon LLM replaces them via damlc + grep.
        _safe("daml_prepass_noop.md",  lambda: _write_daml_prepass_noop(scratch, proj))
        # F1 (recall): approximate DAML reference graph for the coverage gate.
        _safe("_mechanical_graph.json", lambda: _bake_daml_graph(scratch, proj))
        _safe("contract_inventory.md", lambda: _write_sc_recon_stub(scratch, "contract_inventory.md",
              "# Contract Inventory\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "| Template | Path | Choices | Signatories | Observers | Has Key | Implements |\n"
              "|----------|------|---------|-------------|-----------|---------|------------|\n"))
        _safe("state_variables.md",    lambda: _write_sc_recon_stub(scratch, "state_variables.md",
              "# State Variables\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "| Template.field | Type | Role | Read/Written By |\n"
              "|----------------|------|------|-----------------|\n"))
        _safe("function_list.md",      lambda: _write_sc_recon_stub(scratch, "function_list.md",
              "# Function List\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "| Template.Choice | Consume-Mode | Controller | Return | Arg-Derived Controller? |\n"
              "|-----------------|--------------|------------|--------|-------------------------|\n"))
        _safe("build_status.md",       lambda: _write_sc_recon_stub(scratch, "build_status.md",
              "# Build Status\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "**Tool**: daml build\n\n**Status**: SKIPPED (recon LLM runs `daml build`)\n\n"
              "**Chosen build root**: [LLM TO ENRICH — dir owning daml.yaml]\n"))
        _safe("design_context.md",     lambda: _write_design_or_threat_stub(scratch, pipeline))
        _safe("attack_surface.md",     lambda: _write_sc_recon_stub(scratch, "attack_surface.md",
              "# Attack Surface\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "## Authorization Matrix\n[LLM TO ENRICH]\n\n"
              "## External Dependencies\n[LLM TO ENRICH]\n"))
        _safe("detected_patterns.md",  lambda: _write_sc_recon_stub(scratch, "detected_patterns.md",
              "# Detected Patterns\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "## Flags\n[LLM TO ENRICH]\n"))
        _safe("setter_list.md",        lambda: _write_sc_recon_stub(scratch, "setter_list.md",
              "# Setter List\n\n[LLM TO ENRICH] No prepass for DAML (read-driven).\n\n"
              "| Template | Choice | Field | Controller |\n"
              "|----------|--------|-------|------------|\n"))
        _safe("emit_list.md",          lambda: _write_sc_recon_stub(scratch, "emit_list.md",
              "# Disclosure List\n\n[LLM TO ENRICH] No prepass for DAML (read-driven). "
              "Repurposed as observable-disclosure list (DAML has no events).\n\n"
              "| Template | Exposed To (observer) | Interface view |\n"
              "|----------|-----------------------|----------------|\n"))
    else:
        _safe("contract_inventory.md", lambda: _write_contract_inventory_sc(scratch, proj, lang))
        _safe("state_variables.md",    lambda: _write_table_artifact(scratch, proj, lang, "state"))
        _safe("function_list.md",      lambda: _write_table_artifact(scratch, proj, lang, "fn"))
        # F1 (recall): mechanical Solidity reference graph. Tiered: Slither
        # (precise, needs a build) → compilation-free source parse (approximate,
        # always available; same tier as Move/DAML). Never mocks the compiler.
        # Rust/Go get theirs from the SCIP bake. On total FAIL the LLM-derived
        # maps remain and the coverage gate no-ops.
        # M2 (recall): interface-vs-implementation parity.
        if lang == "evm":
            _safe("_mechanical_graph.json",
                  lambda: _bake_evm_graph(
                      scratch, proj, context=tool_context
                  ))
            _safe("niche_interface_parity_findings.md",
                  lambda: _write_interface_parity_findings(scratch, proj))
            # M2 (recall): permissionless-setter detector.
            _safe("niche_permissionless_setters_findings.md",
                  lambda: _write_permissionless_setter_findings(scratch, proj))
        # Pass the mechanical-graph bake result so EVM can dedupe the redundant
        # second compile: when Slither already compiled (source=slither), the
        # standalone forge build probe is derived-skipped instead of recompiling.
        _safe("build_status.md",       lambda: _write_build_status(
            scratch, proj, lang, results.get("_mechanical_graph.json")))
        _safe("design_context.md",     lambda: _write_design_or_threat_stub(scratch, pipeline))
        # v2.8.6: stub the 4 artifacts the pre-pass previously skipped.
        # When Codex sub-agents partially fail, these stay at 0 bytes and
        # trip the recon gate.  Non-zero stubs let the pipeline degrade
        # gracefully instead of hard-failing on partial Codex output.
        _safe("attack_surface.md",     lambda: _write_sc_recon_stub(scratch, "attack_surface.md",
              "# Attack Surface\n\n[LLM TO ENRICH] Pre-pass stub.\n\n"
              "## Entry Points\n[LLM TO ENRICH]\n\n"
              "## External Dependencies\n[LLM TO ENRICH]\n"))
        _safe("detected_patterns.md",  lambda: _write_sc_recon_stub(scratch, "detected_patterns.md",
              "# Detected Patterns\n\n[LLM TO ENRICH] Pre-pass stub.\n\n"
              "## Flags\n[LLM TO ENRICH]\n"))
        _safe("setter_list.md",        lambda: _write_sc_recon_stub(scratch, "setter_list.md",
              "# Setter List\n\n[LLM TO ENRICH] Pre-pass stub.\n\n"
              "| Contract | Function | Parameter | Modifier |\n"
              "|----------|----------|-----------|----------|\n"))
        _safe("emit_list.md",          lambda: _write_sc_recon_stub(scratch, "emit_list.md",
              "# Emit List\n\n[LLM TO ENRICH] Pre-pass stub.\n\n"
              "| Contract | Event | Parameters | Emitting Function |\n"
              "|----------|-------|------------|-------------------|\n"))
        # v2.5.0 P1: SCIP bake for Rust-based chains (Solana/Soroban).
        # RECON-2: deferred to the driver pre-breadth hook by default (it has an
        # unbounded Python conversion that can stall the silent startup window).
        if lang in ("solana", "soroban") and run_startup_scanners:
            # Tiered: precise SCIP when available, else compilation-free source
            # parse so the enumeration gate still gets a graph (never advisory-only).
            _safe(
                "scip_bake",
                lambda: _bake_rust_graph(
                    scratch, proj, context=tool_context
                ),
            )
        # F1 (recall): approximate Move reference graph for the coverage gate
        # (Aptos/Sui have no SCIP indexer wired). Best-effort, never halts.
        if lang in ("aptos", "sui"):
            _safe("_mechanical_graph.json", lambda: _bake_move_graph(scratch, proj))

    _safe("template_recommendations.md",
          lambda: _write_template_recommendations(scratch, skill_index, lang, pipeline))
    _safe("recon_summary.md",
          lambda: _write_recon_summary_stub(scratch, proj, lang))
    _safe("meta_buffer.md", lambda: _write_meta_buffer_stub(scratch))
    # Fix B / Hook 1 prereq: guarantee the external-dependency research ledger
    # exists (header-only if empty) before recon runs, on EVERY pipeline/lang
    # (SC + L1 + DAML) — depth-phase workers can only read this baked file.
    _safe("external_dependency_research.md",
          lambda: _write_external_dependency_research_stub(scratch))

    # L1: mechanical Cosmos-SDK / CometBFT framework detection. Runs AFTER
    # template_recommendations.md + recon_summary.md exist so it can flip the
    # COSMOS_SDK_MODULE_SAFETY row to Required=YES and seed COSMOS_SDK / IBC
    # flags. Manifest-priority, non-fatal.
    if pipeline == "l1":
        _safe("cosmos_flag", lambda: _seed_cosmos_flag(scratch, proj))
        # Wave-2 A6: mechanical embedded-.move-source detection. Same
        # manifest-priority, non-fatal dispatch as cosmos_flag above; routes
        # the vetted aptos/sui core Move skills to depth-state-trace/external
        # (see `_build_depth_worker_prompt` in plamen_driver.py).
        _safe("move_sources_flag", lambda: _seed_move_sources_flag(scratch, proj))

    # SC (EVM): mechanical cross-chain message-handler marker detection —
    # second-channel backup to the LLM recon's own CROSS_CHAIN_MSG flag
    # detection. Same manifest-priority 3-step dispatch as cosmos_flag above,
    # via the shared _seed_mechanical_flag helper.
    if pipeline != "l1" and lang == "evm":
        _safe("cross_chain_msg_flag", lambda: _seed_cross_chain_msg_flag(scratch, proj))
        # Fix B / Hook 1: mechanical second-channel backup to the LLM recon's
        # own EXTERNAL_DEPENDENCY/NAMED_EXTERNAL_PROTOCOL detection (TASK 6).
        # Same manifest-priority, non-fatal dispatch as cross_chain_msg_flag.
        _safe("external_dependency_flag",
              lambda: _seed_external_dependency_flag(scratch, proj))

    # v2.5.0 P2: OpenGrep cross-ecosystem scanner (SC pipelines only).
    # Deferred to the driver pre-breadth hook by default (see run_startup_scanners
    # above); the escape hatch keeps the old startup behavior for local debugging.
    if pipeline != "l1" and run_startup_scanners:
        _safe(
            "opengrep_scan",
            lambda: _run_opengrep_scan(
                scratch, proj, lang, context=tool_context
            ),
        )

    # v2.5.0 P4: Sec3 X-Ray for Solana (Docker-based, SC only).
    # RECON-1: deferred to the driver pre-breadth hook by default (a Docker run
    # can take ~10 min and would stall the silent startup window).
    if pipeline != "l1" and lang == "solana" and run_startup_scanners:
        _safe(
            "sec3_xray",
            lambda: _run_sec3_xray(
                scratch,
                proj,
                config.get("sec3_xray_image"),
                context=tool_context,
            ),
        )

    return results


_PREPASS_PUBLICATION_RECEIPT = "recon_prepass_publication_receipt.json"
_PREPASS_TIMEOUT_SECONDS = 30
_PREPASS_PREEXECUTION_AUTHORITY_SCHEMA = (
    "plamen.recon-prepass-preexecution-authority.v1"
)
_SC_PREPASS_PUBLIC_OUTPUTS = (
    "contract_inventory.md",
    "state_variables.md",
    "function_list.md",
    "build_status.md",
    "design_context.md",
    "attack_surface.md",
    "detected_patterns.md",
    "setter_list.md",
    "emit_list.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
_L1_PREPASS_PUBLIC_OUTPUTS = (
    "subsystem_map.md",
    "trust_boundaries.md",
    "attack_surface.md",
    "threat_model.md",
    "template_recommendations.md",
    "recon_summary.md",
    "meta_buffer.md",
    "external_dependency_research.md",
)
_PREPASS_AUXILIARY_OUTPUTS = frozenset({
    *PRECISE_GRAPH_ARTIFACTS,
    "_mechanical_graph_generation.json",
    "state_read_map.md",
    "daml_prepass_noop.md",
    "niche_interface_parity_findings.md",
    "niche_permissionless_setters_findings.md",
    "tool_coverage_ledger.json",
    "tool_coverage_ledger.md",
    "tool_coverage_ledger_repair_required.md",
    "toolchain_coverage_debt.json",
    "report_semantic_toolchain_coverage.md",
    "opengrep_results.sarif",
    "opengrep_findings.md",
    "sec3_results.sarif",
    "sec3_findings.md",
    "dependency_audit_findings.md",
})
_PREPASS_STAGE_MAX_ENTRIES = 128
_PREPASS_STAGE_MAX_FILE_BYTES = 64 * 1024 * 1024
_PREPASS_STAGE_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_PREPASS_PRIVATE_TREE_MAX_ENTRIES = 100_000
_PREPASS_PRIVATE_TREE_MAX_DEPTH = 64


class ReconPrepassAuthorityError(RuntimeError):
    """The public recon prepass could not establish exact DRIVER authority."""


def _prepass_collect_private_tree_manifest(
    root: Path,
    directory: Path,
    *,
    label: str,
    seen: list[int],
) -> tuple[
    list[tuple[Path, int, tuple[int, int, int]]],
    list[tuple[Path, tuple[int, int, int, int, int, int]]],
]:
    """Validate one disposable tree and return an immutable identity manifest."""

    relative = directory.relative_to(root).as_posix()
    target = _rooted_io.safe_descendant(
        root, relative, allow_missing=False, label=label
    )
    first = _rooted_io.lstat(target)
    if not stat.S_ISDIR(first.st_mode) or _rooted_io.is_reparse(target):
        raise ReconPrepassAuthorityError(f"{label} is not a literal directory")
    directories: list[tuple[Path, int, tuple[int, int, int]]] = []
    files: list[tuple[Path, tuple[int, int, int, int, int, int]]] = []
    pending: list[tuple[Path, int]] = [(target, 0)]
    while pending:
        current, depth = pending.pop()
        if depth > _PREPASS_PRIVATE_TREE_MAX_DEPTH:
            raise ReconPrepassAuthorityError(f"{label} depth budget exceeded")
        current_row = _rooted_io.lstat(current)
        if (
            not stat.S_ISDIR(current_row.st_mode)
            or _rooted_io.is_reparse(current)
        ):
            raise ReconPrepassAuthorityError(f"{label} directory changed")
        directories.append((current, depth, (
            int(current_row.st_dev), int(current_row.st_ino),
            stat.S_IFMT(current_row.st_mode),
        )))
        with _rooted_io.scandir(current) as iterator:
            entries = []
            for entry in iterator:
                seen[0] += 1
                if seen[0] > _PREPASS_PRIVATE_TREE_MAX_ENTRIES:
                    raise ReconPrepassAuthorityError(
                        f"{label} entry budget exceeded"
                    )
                entries.append(entry)
        for entry in entries:
            child = current / entry.name
            row = _rooted_io.lstat(child)
            if stat.S_ISLNK(row.st_mode) or _rooted_io.is_reparse(child):
                raise ReconPrepassAuthorityError(f"{label} contains an alias")
            if stat.S_ISDIR(row.st_mode):
                pending.append((child, depth + 1))
            elif stat.S_ISREG(row.st_mode) and int(row.st_nlink) == 1:
                files.append((child, (
                    int(row.st_dev), int(row.st_ino), int(row.st_size),
                    int(row.st_mtime_ns), int(row.st_nlink),
                    stat.S_IFMT(row.st_mode),
                )))
            else:
                raise ReconPrepassAuthorityError(
                    f"{label} contains a non-regular entry"
                )
    return directories, files


def _prepass_delete_private_tree_manifests(
    manifests: Sequence[
        tuple[
            list[tuple[Path, int, tuple[int, int, int]]],
            list[tuple[Path, tuple[int, int, int, int, int, int]]],
        ]
    ],
    *,
    label: str,
) -> None:
    """Delete only after every registered tree and identity validates together."""

    directories = [row for manifest, _files in manifests for row in manifest]
    files = [row for _directories, manifest in manifests for row in manifest]

    # A complete preflight prevents a bad later tree from partially deleting an
    # earlier valid tree.  Each entry is checked again immediately before its
    # destructive operation to retain the per-entry TOCTOU guard.
    for child, expected in files:
        row = _rooted_io.lstat(child)
        observed = (
            int(row.st_dev), int(row.st_ino), int(row.st_size),
            int(row.st_mtime_ns), int(row.st_nlink),
            stat.S_IFMT(row.st_mode),
        )
        if observed != expected or _rooted_io.is_reparse(child):
            raise ReconPrepassAuthorityError(
                f"{label} file identity changed before deletion"
            )
    for current, _depth, expected in directories:
        row = _rooted_io.lstat(current)
        observed = (
            int(row.st_dev), int(row.st_ino), stat.S_IFMT(row.st_mode),
        )
        if observed != expected or _rooted_io.is_reparse(current):
            raise ReconPrepassAuthorityError(
                f"{label} directory identity changed before deletion"
            )
    for child, expected in files:
        row = _rooted_io.lstat(child)
        observed = (
            int(row.st_dev), int(row.st_ino), int(row.st_size),
            int(row.st_mtime_ns), int(row.st_nlink),
            stat.S_IFMT(row.st_mode),
        )
        if observed != expected or _rooted_io.is_reparse(child):
            raise ReconPrepassAuthorityError(
                f"{label} file identity changed before deletion"
            )
        os.unlink(_rooted_io.native_path(child))
    for current, _depth, expected in sorted(
        directories, key=lambda item: item[1], reverse=True
    ):
        row = _rooted_io.lstat(current)
        observed = (
            int(row.st_dev), int(row.st_ino), stat.S_IFMT(row.st_mode),
        )
        if observed != expected or _rooted_io.is_reparse(current):
            raise ReconPrepassAuthorityError(
                f"{label} directory identity changed before deletion"
            )
        os.rmdir(_rooted_io.native_path(current))


def _prepass_private_tree_attestation(
    root: Path,
    name: str,
    manifest: tuple[
        list[tuple[Path, int, tuple[int, int, int]]],
        list[tuple[Path, tuple[int, int, int, int, int, int]]],
    ],
) -> tuple[
    str,
    tuple[tuple[str, int, tuple[int, int, int]], ...],
    tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
]:
    """Seal one private-tree denominator as immutable rooted identities."""

    directories, files = manifest
    return (
        name,
        tuple(sorted(
            (path.relative_to(root).as_posix(), depth, identity)
            for path, depth, identity in directories
        )),
        tuple(sorted(
            (path.relative_to(root).as_posix(), identity)
            for path, identity in files
        )),
    )


def _prepass_remove_private_tree(root: Path, directory: Path, *, label: str) -> None:
    """Remove one rooted disposable tree without following aliases/reparse points."""

    try:
        manifest = _prepass_collect_private_tree_manifest(
            root, directory, label=label, seen=[0]
        )
        _prepass_delete_private_tree_manifests([manifest], label=label)
    except ReconPrepassAuthorityError:
        raise
    except (OSError, ValueError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(f"{label} could not be removed safely") from exc


def _prepass_cleanup_renderer_private_stage(stage: Path) -> tuple[
    tuple[
        str,
        tuple[tuple[str, int, tuple[int, int, int]], ...],
        tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
    ],
    ...,
]:
    """Validate and exclude the complete renderer-private tree denominator.

    Publication preparation deliberately does not delete these trees.  That
    keeps every authority-validation failure zero-mutation, including a late
    concurrent namespace change; the run-private stage is disposed only by the
    outer transaction cleanup.
    """

    try:
        with _rooted_io.scandir(stage) as iterator:
            names = []
            for entry in iterator:
                if len(names) >= _PREPASS_STAGE_MAX_ENTRIES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass renderer-private top-level entry budget exceeded"
                    )
                names.append(entry.name)
    except OSError as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass renderer-private enumeration failed"
        ) from exc
    attestations = []
    seen = [0]
    try:
        for name in names:
            registered = name == ".fb" or any(name.startswith(prefix) for prefix in (
                ".slither-graph-", ".mixed-graph-", ".scip-", ".og-",
            ))
            path = stage / name
            row = _rooted_io.lstat(path)
            if registered:
                if not stat.S_ISDIR(row.st_mode) or _rooted_io.is_reparse(path):
                    raise ReconPrepassAuthorityError(
                        "recon prepass registered renderer-private path is aliased"
                    )
                manifest = _prepass_collect_private_tree_manifest(
                    stage,
                    path,
                    label="recon prepass renderer-private tree",
                    seen=seen,
                )
                attestations.append(_prepass_private_tree_attestation(
                    stage, name, manifest
                ))
    except ReconPrepassAuthorityError:
        raise
    except (OSError, ValueError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass renderer-private trees could not be validated safely"
        ) from exc
    return tuple(sorted(attestations, key=lambda row: row[0]))


def _prepass_commit_ledger_cas(
    scratchpad: Path,
    prestate: Mapping[str, Any],
    replacement: Mapping[str, Any],
) -> None:
    """Commit one exact ledger transition under the cross-process lock."""

    expected_digest = artifact_ledger_digest(prestate)
    try:
        compare_and_swap_artifact_ledger(
            scratchpad,
            expected_digest=expected_digest,
            mutator=lambda current: (
                dict(replacement)
                if artifact_ledger_digest(current) == expected_digest
                else (_ for _ in ()).throw(ArtifactLedgerCASMismatch(
                    "recon prepass ledger prestate changed"
                ))
            ),
        )
    except ArtifactLedgerError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass ledger CAS failed: {exc}"
        ) from exc


def _prepass_stable_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _prepass_dimensions(config: Mapping[str, Any]) -> tuple[str, str, str, str]:
    pipeline = str(config.get("pipeline") or "sc").strip().lower()
    mode = str(config.get("mode") or "core").strip().lower()
    language = str(config.get("language") or "unknown").strip().lower()
    ecosystem = {"solidity": "evm", "ethereum": "evm"}.get(language, language)
    backend = str(config.get("cli_backend") or "claude").strip().lower()
    return pipeline, mode, ecosystem, backend


def _prepass_output_names(pipeline: str) -> tuple[str, ...]:
    selected = (
        _L1_PREPASS_PUBLIC_OUTPUTS
        if pipeline == "l1"
        else _SC_PREPASS_PUBLIC_OUTPUTS
    )
    return (*selected, _PREPASS_PUBLICATION_RECEIPT)


_PREPASS_SOURCE_ROOT_SCHEMA = "plamen.recon-prepass-source-root.v1"
_FILE_ATTRIBUTE_REPARSE_POINT = int(
    getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
)
_FILE_ATTRIBUTE_DIRECTORY = int(
    getattr(stat, "FILE_ATTRIBUTE_DIRECTORY", 0x10)
)
_PREPASS_CAPTURE_MAX_ENTRIES = 100_000
_PREPASS_CAPTURE_MAX_FILES = 50_000
_PREPASS_CAPTURE_MAX_DEPTH = 64
_PREPASS_CAPTURE_MAX_FILE_BYTES = 64 * 1024 * 1024
_PREPASS_CAPTURE_MAX_TOTAL_BYTES = 512 * 1024 * 1024
_PREPASS_SEMANTIC_MAX_ENTRIES = 10_000
_PREPASS_SEMANTIC_MAX_FILES = 256
_PREPASS_SEMANTIC_MAX_FILE_BYTES = 8 * 1024 * 1024
_PREPASS_SEMANTIC_MAX_TOTAL_BYTES = 32 * 1024 * 1024


def _prepass_windows_canonical_device(raw_device: object) -> int:
    """Validate CPython's Windows identity width before low-DWORD binding."""

    if (
        type(raw_device) is not int
        or raw_device < 1
        or raw_device > 0xFFFFFFFFFFFFFFFF
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root physical identity is unavailable"
        )
    canonical_device = raw_device & 0xFFFFFFFF
    if canonical_device < 1:
        raise ReconPrepassAuthorityError(
            "recon prepass source root physical identity is unavailable"
        )
    return canonical_device


def _prepass_source_root_authority(
    source_root: Path,
    *,
    logical_identity: str = "project:src",
) -> dict[str, Any]:
    """Observe ``src`` exactly once without following it.

    This helper is deliberately the first filesystem operation applied to the
    source root.  In particular, callers must not probe ``is_dir``/``exists``
    or enumerate children before this observation.
    """

    try:
        observed = os.lstat(source_root)
    except FileNotFoundError:
        return {
            "schema": _PREPASS_SOURCE_ROOT_SCHEMA,
            "logical_identity": logical_identity,
            "status": "ABSENT",
            "device": None,
            "inode": None,
            "mode_type": None,
            "file_attributes": None,
            "reparse_tag": None,
        }
    except (NotADirectoryError, PermissionError, OSError) as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass source root no-follow inspection failed: {exc}"
        ) from exc

    mode = getattr(observed, "st_mode", 0)
    attributes = getattr(observed, "st_file_attributes", 0)
    reparse_tag = getattr(observed, "st_reparse_tag", 0)
    if (
        type(mode) is not int
        or type(attributes) is not int
        or type(reparse_tag) is not int
        or mode < 0
        or attributes < 0
        or attributes > 0xFFFFFFFF
        or reparse_tag < 0
        or reparse_tag > 0xFFFFFFFF
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root physical identity is unavailable"
        )
    mode_type = stat.S_IFMT(mode)
    if (
        stat.S_ISLNK(mode)
        or not stat.S_ISDIR(mode)
        or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
        or (os.name == "nt" and not bool(
            attributes & _FILE_ATTRIBUTE_DIRECTORY
        ))
        or reparse_tag != 0
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root is an unsafe link/reparse or "
            "non-directory authority"
        )
    device = getattr(observed, "st_dev", None)
    inode = getattr(observed, "st_ino", None)
    if (
        type(device) is not int
        or device < 0
        or type(inode) is not int
        or inode <= 0
        or (os.name == "nt" and inode > 0xFFFFFFFFFFFFFFFF)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root physical identity is unavailable"
        )
    if os.name == "nt":
        # CPython's Windows st_dev is a 64-bit volume identifier while the
        # no-follow BY_HANDLE_FILE_INFORMATION authority exposes the canonical
        # DWORD volume serial in its low 32 bits.
        device = _prepass_windows_canonical_device(device)
    if (
        device < (1 if os.name == "nt" else 0)
        or (os.name == "nt" and device > 0xFFFFFFFF)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root physical identity is unavailable"
        )
    return {
        "schema": _PREPASS_SOURCE_ROOT_SCHEMA,
        "logical_identity": logical_identity,
        "status": "PRESENT",
        "device": device,
        "inode": inode,
        "mode_type": mode_type,
        "file_attributes": attributes,
        "reparse_tag": reparse_tag,
    }


def _prepass_assert_source_root_authority(
    source_root: Path,
    expected: Mapping[str, Any],
) -> None:
    """Require one exact no-follow replay of the approved root identity."""

    try:
        observed = _prepass_source_root_authority(
            source_root,
            logical_identity=str(expected.get("logical_identity") or ""),
        )
    except ReconPrepassAuthorityError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass source root identity drift: {exc}"
        ) from exc
    if observed != dict(expected):
        raise ReconPrepassAuthorityError(
            "recon prepass source root identity drift"
        )


def _prepass_assert_capture_source_root(
    project_root: Path,
    capture: Mapping[str, Any],
) -> None:
    authority = capture.get("source_root_authority")
    if not isinstance(authority, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass capture lacks source-root authority"
        )
    _prepass_assert_source_root_authority(
        project_root, authority
    )


def _prepass_exact_unsigned(
    value: object,
    *,
    bits: int,
    positive: bool = False,
) -> int:
    """Return an exact unsigned native field without coercion."""

    if (
        type(value) is not int
        or value < (1 if positive else 0)
        or value > ((1 << bits) - 1)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root native physical identity mismatch"
        )
    return value


def _prepass_validate_native_source_root_identity(
    information: object,
    authority: Mapping[str, Any],
) -> dict[str, int]:
    """Join exact Windows handle identity to the signed lstat authority."""

    missing = object()
    volume = _prepass_exact_unsigned(
        getattr(information, "dwVolumeSerialNumber", missing),
        bits=32,
        positive=True,
    )
    index_high = _prepass_exact_unsigned(
        getattr(information, "nFileIndexHigh", missing), bits=32
    )
    index_low = _prepass_exact_unsigned(
        getattr(information, "nFileIndexLow", missing), bits=32
    )
    attributes = _prepass_exact_unsigned(
        getattr(information, "dwFileAttributes", missing), bits=32
    )
    file_index = (index_high << 32) | index_low
    if file_index == 0:
        raise ReconPrepassAuthorityError(
            "recon prepass source root native physical identity mismatch"
        )

    signed_device = _prepass_exact_unsigned(
        authority.get("device", missing), bits=32, positive=True
    )
    signed_inode = _prepass_exact_unsigned(
        authority.get("inode", missing), bits=64, positive=True
    )
    signed_attributes = _prepass_exact_unsigned(
        authority.get("file_attributes", missing), bits=32
    )
    signed_mode_type = authority.get("mode_type", missing)
    signed_reparse_tag = _prepass_exact_unsigned(
        authority.get("reparse_tag", missing), bits=32
    )
    if (
        signed_mode_type != stat.S_IFDIR
        or signed_reparse_tag != 0
        or volume != signed_device
        or file_index != signed_inode
        or attributes != signed_attributes
        or not bool(attributes & 0x10)
        or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root native physical identity mismatch"
        )
    return {
        "volume_serial_number": volume,
        "file_index": file_index,
        "file_attributes": attributes,
    }


def _prepass_windows_source_root_native_api() -> tuple[Any, Any, Any, Any]:
    """Resolve the one Windows no-follow handle API used by the root guard."""

    import ctypes
    from ctypes import wintypes

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    )
    get_information.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL
    return _ByHandleFileInformation, create_file, get_information, close_handle


@contextmanager
def _prepass_source_root_guard(
    source_root: Path,
    authority: Mapping[str, Any],
):
    """Retain a no-delete/no-follow Windows directory handle during capture."""

    _prepass_assert_source_root_authority(source_root, authority)
    if authority.get("status") != "PRESENT" or os.name != "nt":
        try:
            yield
            _prepass_assert_source_root_authority(source_root, authority)
        finally:
            pass
        return

    import ctypes
    (
        information_type,
        create_file,
        get_information,
        close_handle,
    ) = _prepass_windows_source_root_native_api()
    handle = create_file(
        str(source_root),
        0x80,  # FILE_READ_ATTRIBUTES
        0x1 | 0x2,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deliberately no DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    if handle in (None, ctypes.c_void_p(-1).value):
        raise ReconPrepassAuthorityError(
            "recon prepass source root no-follow handle open failed: "
            f"winerror={ctypes.get_last_error()}"
        )
    try:
        information = information_type()
        if not get_information(handle, ctypes.byref(information)):
            raise ReconPrepassAuthorityError(
                "recon prepass source root native identity query failed: "
                f"winerror={ctypes.get_last_error()}"
            )
        _prepass_validate_native_source_root_identity(information, authority)
        _prepass_assert_source_root_authority(source_root, authority)
        yield
        _prepass_assert_source_root_authority(source_root, authority)
    finally:
        close_handle(handle)


def _prepass_descendant_metadata(path: Path) -> tuple[int, int, int, int, int, int]:
    try:
        observed = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass source descendant inspection failed: {path}: {exc}"
        ) from exc
    mode = int(getattr(observed, "st_mode", 0) or 0)
    attributes = int(getattr(observed, "st_file_attributes", 0) or 0)
    reparse_tag = int(getattr(observed, "st_reparse_tag", 0) or 0)
    if (
        stat.S_ISLNK(mode)
        or bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)
        or reparse_tag != 0
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source root authority contains a link/reparse "
            f"path: {path}"
        )
    if not stat.S_ISDIR(mode) and not stat.S_ISREG(mode):
        raise ReconPrepassAuthorityError(
            f"recon prepass source authority contains a non-file path: {path}"
        )
    device = getattr(observed, "st_dev", None)
    inode = getattr(observed, "st_ino", None)
    if not isinstance(device, int) or not isinstance(inode, int) or inode <= 0:
        raise ReconPrepassAuthorityError(
            f"recon prepass source descendant identity is unavailable: {path}"
        )
    return (
        device,
        inode,
        stat.S_IFMT(mode),
        attributes,
        reparse_tag,
        int(getattr(observed, "st_size", 0) or 0),
    )


def _prepass_regular_file_present(path: Path, *, label: str) -> bool:
    """Distinguish literal absence from every unsafe named filesystem object."""

    try:
        if not _rooted_io.lexists(path):
            return False
        _rooted_io.checked_file(
            path, label=label, require_single_link=True
        )
    except (OSError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            f"{label} is not a safe single-link regular file: {path}: {exc}"
        ) from exc
    return True


def _prepass_bounded_file_digest(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> tuple[str, int]:
    """Hash one no-follow regular file without allocating its full contents."""

    try:
        checked = _rooted_io.checked_file(
            path, label=label, require_single_link=True
        )
        before = _rooted_io.lstat(checked)
        declared_size = int(getattr(before, "st_size", -1))
        if declared_size < 0 or declared_size > max_bytes:
            raise ReconPrepassAuthorityError(
                f"{label} exceeds the {max_bytes}-byte authority budget: {path}"
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(_rooted_io.native_path(checked), flags)
        try:
            opened = os.fstat(descriptor)
            if (
                int(getattr(before, "st_dev", -1))
                != int(getattr(opened, "st_dev", -2))
                or int(getattr(before, "st_ino", -1))
                != int(getattr(opened, "st_ino", -2))
                or not stat.S_ISREG(opened.st_mode)
                or int(getattr(opened, "st_nlink", 1) or 1) != 1
            ):
                raise ReconPrepassAuthorityError(
                    f"{label} identity changed while opening: {path}"
                )
            digest = hashlib.sha256()
            observed_size = 0
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1))
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > max_bytes:
                    raise ReconPrepassAuthorityError(
                        f"{label} exceeds the {max_bytes}-byte authority budget: "
                        f"{path}"
                    )
                digest.update(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named_after = _rooted_io.lstat(checked)
        before_identity = (
            int(getattr(before, "st_dev", -1)),
            int(getattr(before, "st_ino", -1)),
            int(getattr(before, "st_size", -1)),
            int(getattr(before, "st_mtime_ns", -1)),
        )
        if before_identity != (
            int(getattr(after, "st_dev", -2)),
            int(getattr(after, "st_ino", -2)),
            int(getattr(after, "st_size", -2)),
            int(getattr(after, "st_mtime_ns", -2)),
        ) or before_identity != (
            int(getattr(named_after, "st_dev", -3)),
            int(getattr(named_after, "st_ino", -3)),
            int(getattr(named_after, "st_size", -3)),
            int(getattr(named_after, "st_mtime_ns", -3)),
        ) or observed_size != declared_size:
            raise ReconPrepassAuthorityError(
                f"{label} identity changed while hashing: {path}"
            )
        return digest.hexdigest(), observed_size
    except ReconPrepassAuthorityError:
        raise
    except (OSError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            f"{label} could not be hashed safely: {path}: {exc}"
        ) from exc


def _prepass_bounded_read_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int,
) -> bytes:
    """Read a stable no-follow file with a hard allocation ceiling."""

    try:
        checked = _rooted_io.checked_file(
            path, label=label, require_single_link=True
        )
        before = _rooted_io.lstat(checked)
        declared = int(getattr(before, "st_size", -1))
        if declared < 0 or declared > max_bytes:
            raise ReconPrepassAuthorityError(
                f"{label} exceeds the {max_bytes}-byte read budget"
            )
        descriptor = os.open(
            _rooted_io.native_path(checked),
            os.O_RDONLY | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        chunks: list[bytes] = []
        observed = 0
        try:
            while True:
                chunk = os.read(descriptor, min(1024 * 1024, max_bytes + 1))
                if not chunk:
                    break
                observed += len(chunk)
                if observed > max_bytes:
                    raise ReconPrepassAuthorityError(
                        f"{label} exceeds the {max_bytes}-byte read budget"
                    )
                chunks.append(chunk)
            after = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        named = _rooted_io.lstat(checked)
        identity = lambda row: (
            int(getattr(row, "st_dev", -1)),
            int(getattr(row, "st_ino", -1)),
            int(getattr(row, "st_size", -1)),
            int(getattr(row, "st_mtime_ns", -1)),
        )
        if identity(before) != identity(after) or identity(before) != identity(named):
            raise ReconPrepassAuthorityError(f"{label} changed while reading")
        if observed != declared:
            raise ReconPrepassAuthorityError(f"{label} size changed while reading")
        return b"".join(chunks)
    except ReconPrepassAuthorityError:
        raise
    except (OSError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(f"{label} bounded read failed: {exc}") from exc


def _prepass_durable_replace_from_stage(
    source: Path,
    destination: Path,
    *,
    label: str,
    retire_source: bool = False,
) -> None:
    """Copy a bounded checked source into a durable same-parent replacement."""

    temp: Path | None = None
    try:
        checked = _rooted_io.checked_file(
            source, label=label, require_single_link=True
        )
        before = _rooted_io.lstat(checked)
        declared_size = int(getattr(before, "st_size", -1))
        if declared_size < 0 or declared_size > _PREPASS_STAGE_MAX_FILE_BYTES:
            raise ReconPrepassAuthorityError(
                f"{label} exceeds the publication byte budget"
            )
        source_fd = os.open(
            _rooted_io.native_path(checked),
            os.O_RDONLY | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        temp_fd, temp = _rooted_io.exclusive_temp_file(
            destination.parent, prefix=".recon-publish-"
        )
        observed_size = 0
        try:
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                observed_size += len(chunk)
                if observed_size > _PREPASS_STAGE_MAX_FILE_BYTES:
                    raise ReconPrepassAuthorityError(
                        f"{label} exceeds the publication byte budget"
                    )
                view = memoryview(chunk)
                offset = 0
                while offset < len(view):
                    written = os.write(temp_fd, view[offset:])
                    if written <= 0:
                        raise OSError("short recon prepass publication write")
                    offset += written
            os.fsync(temp_fd)
            after = os.fstat(source_fd)
            if (
                observed_size != declared_size
                or int(getattr(after, "st_dev", -1))
                != int(getattr(before, "st_dev", -2))
                or int(getattr(after, "st_ino", -1))
                != int(getattr(before, "st_ino", -2))
                or int(getattr(after, "st_size", -1)) != declared_size
            ):
                raise ReconPrepassAuthorityError(
                    f"{label} changed during durable publication"
                )
        finally:
            os.close(source_fd)
            os.close(temp_fd)
        _rooted_io.durable_replace(temp, destination)
        if retire_source:
            _rooted_io.durable_unlink(checked)
    except ReconPrepassAuthorityError:
        raise
    except (OSError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            f"{label} durable publication failed: {exc}"
        ) from exc
    finally:
        if temp is not None and _rooted_io.lexists(temp):
            _rooted_io.durable_unlink(temp)


def _prepass_fallback_production_records(
    project_root: Path,
    scratchpad: Path,
    source_root_authority: Mapping[str, Any],
    source_exts: set[str],
) -> dict[str, str]:
    """Bounded iterative fallback used only when no audit snapshot is bound."""

    records: dict[str, str] = {}
    casefolded: set[str] = set()
    entry_count = 0
    file_count = 0
    total_bytes = 0
    pending: list[tuple[Path, int]] = [(project_root, 0)]
    with _prepass_source_root_guard(project_root, source_root_authority):
        while pending:
            directory, depth = pending.pop()
            try:
                with _rooted_io.scandir(directory) as iterator:
                    entries = []
                    for entry in iterator:
                        entry_count += 1
                        if entry_count > _PREPASS_CAPTURE_MAX_ENTRIES:
                            raise ReconPrepassAuthorityError(
                                "recon prepass source entry budget exceeded"
                            )
                        entries.append(entry)
            except ReconPrepassAuthorityError:
                raise
            except OSError as exc:
                raise ReconPrepassAuthorityError(
                    f"recon prepass source enumeration failed: {directory}: {exc}"
                ) from exc
            for entry in sorted(entries, key=lambda item: item.name, reverse=True):
                # rooted_path_io may enumerate with a Windows extended-length
                # spelling; retain the caller's canonical lexical root.
                path = directory / entry.name
                before = _prepass_descendant_metadata(path)
                relative = path.relative_to(project_root).as_posix()
                folded = relative.casefold()
                if folded in casefolded:
                    raise ReconPrepassAuthorityError(
                        "recon prepass source authority contains a case alias: "
                        f"{relative}"
                    )
                casefolded.add(folded)
                if before[2] == stat.S_IFDIR:
                    if (
                        entry.name in SKIP_DIR_NAMES
                        or entry.name.startswith(".")
                        or (depth == 0 and entry.name == scratchpad.name)
                    ):
                        continue
                    if depth + 1 > _PREPASS_CAPTURE_MAX_DEPTH:
                        raise ReconPrepassAuthorityError(
                            "recon prepass source depth budget exceeded"
                        )
                    pending.append((path, depth + 1))
                    continue
                if (
                    path.suffix.lower() not in source_exts
                    or not is_production_source_path(path, project_root)
                ):
                    continue
                file_count += 1
                if file_count > _PREPASS_CAPTURE_MAX_FILES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass source file-count budget exceeded"
                    )
                declared_size = before[5]
                if declared_size > _PREPASS_CAPTURE_MAX_FILE_BYTES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass source per-file byte budget exceeded: "
                        f"{path}"
                    )
                if total_bytes + declared_size > _PREPASS_CAPTURE_MAX_TOTAL_BYTES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass source total-byte budget exceeded"
                    )
                digest, size = _prepass_bounded_file_digest(
                    path,
                    label="recon prepass production source",
                    max_bytes=_PREPASS_CAPTURE_MAX_FILE_BYTES,
                )
                total_bytes += size
                records[relative] = digest
        _prepass_assert_source_root_authority(
            project_root, source_root_authority
        )
    return dict(sorted(records.items()))


def _prepass_capture(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    source_root = project_root
    source_root_authority = _prepass_source_root_authority(
        source_root, logical_identity="project:root"
    )
    try:
        semantic_config = _audit_snapshot_authority._semantic_config(config)
        snapshot = config.get("_audit_snapshot") or config.get(
            "audit_snapshot"
        )
        snapshot_digest = ""
        source_scope_digest = ""
        source_path_authority: dict[str, Any] = {}
        audit_config_authority: dict[str, Any] = {}
        if isinstance(snapshot, Mapping):
            if not _audit_snapshot_authority._valid_snapshot(dict(snapshot)):
                raise ValueError("bound audit snapshot is invalid")
            snapshot_digest = str(snapshot.get("snapshot_digest") or "")
            components = snapshot.get("components")
            source_scope = (
                components.get("source_scope")
                if isinstance(components, Mapping)
                else None
            )
            source_scope_digest = str(
                source_scope.get("digest")
                if isinstance(source_scope, Mapping)
                else ""
            )
            current_config_authority = (
                _audit_snapshot_authority._config_component(config)
            )
            bound_config_authority = (
                components.get("audit_config")
                if isinstance(components, Mapping)
                else None
            )
            if current_config_authority != bound_config_authority:
                raise ValueError(
                    "semantic config differs from bound audit snapshot"
                )
            audit_config_authority = dict(current_config_authority)
            source_path_authority = _build_source_path_authority(
                config, snapshot
            )
        if snapshot_digest and re.fullmatch(
            r"[0-9a-fA-F]{64}", snapshot_digest
        ) is None:
            raise ValueError("snapshot digest is malformed")
        if source_scope_digest and re.fullmatch(
            r"[0-9a-fA-F]{64}", source_scope_digest
        ) is None:
            raise ValueError("source-scope digest is malformed")
        config_digest = _prepass_stable_digest(semantic_config)
    except (TypeError, ValueError) as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass config authority is not canonical JSON: {exc}"
        ) from exc
    semantic_candidates: list[Path] = []
    try:
        with _rooted_io.scandir(scratchpad) as iterator:
            semantic_entry_count = 0
            for entry in iterator:
                semantic_entry_count += 1
                if semantic_entry_count > _PREPASS_SEMANTIC_MAX_ENTRIES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass semantic entry budget exceeded"
                    )
                if re.fullmatch(
                    r"recon_unplanned_semantic.*\.md", entry.name
                ):
                    semantic_candidates.append(scratchpad / entry.name)
                    if len(semantic_candidates) > _PREPASS_SEMANTIC_MAX_FILES:
                        raise ReconPrepassAuthorityError(
                            "recon prepass semantic file-count budget exceeded"
                        )
    except ReconPrepassAuthorityError:
        raise
    except OSError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass semantic enumeration failed: {exc}"
        ) from exc
    semantic_candidates.sort(key=lambda candidate: candidate.name)
    unexpected: dict[str, str] = {}
    semantic_total_bytes = 0
    for path in semantic_candidates:
        digest, size = _prepass_bounded_file_digest(
            path,
            label="recon prepass unplanned semantic authority",
            max_bytes=_PREPASS_SEMANTIC_MAX_FILE_BYTES,
        )
        semantic_total_bytes += size
        if semantic_total_bytes > _PREPASS_SEMANTIC_MAX_TOTAL_BYTES:
            raise ReconPrepassAuthorityError(
                "recon prepass semantic total-byte budget exceeded"
            )
        unexpected[path.name] = digest
    _prepass_assert_source_root_authority(
        source_root, source_root_authority
    )
    source_exts = set(_OPENGREP_LANG_EXT.get(
        str(config.get("language") or "").strip().lower(), ()
    ))
    if not source_exts:
        source_exts = {".sol", ".rs", ".move", ".vy", ".cairo", ".daml"}
    production_records: dict[str, str] = {}
    if not source_path_authority:
        production_records = _prepass_fallback_production_records(
            project_root,
            scratchpad,
            source_root_authority,
            source_exts,
        )
    production_source_capture_digest = _prepass_stable_digest(
        dict(sorted(production_records.items()))
    )
    if source_path_authority:
        production_source_capture_digest = str(
            source_path_authority["authority_digest"]
        )
    source_capture_digest = production_source_capture_digest
    input_set_digest = _prepass_stable_digest({
        "source_capture_digest": source_capture_digest,
        "production_source_capture_digest": production_source_capture_digest,
        "source_root_authority": source_root_authority,
        "config_digest": config_digest,
        "snapshot_digest": snapshot_digest.lower(),
        "source_scope_digest": source_scope_digest.lower(),
        "source_path_authority": source_path_authority,
        "audit_config_authority": audit_config_authority,
        "unexpected_semantic_outputs": unexpected,
    })
    return {
        "source_capture_digest": source_capture_digest,
        "production_source_capture_digest": production_source_capture_digest,
        "source_root_authority": source_root_authority,
        "config_digest": config_digest,
        "snapshot_digest": snapshot_digest.lower(),
        "source_scope_digest": source_scope_digest.lower(),
        "source_path_authority": source_path_authority,
        "audit_config_authority": audit_config_authority,
        "unexpected_semantic_outputs": unexpected,
        "input_set_digest": input_set_digest,
    }


def _prepass_preexecution_authority(
    contract: Any,
    launch: LaunchSpec,
    *,
    run_id: str,
    capture: Mapping[str, Any],
) -> dict[str, Any]:
    unsigned: dict[str, Any] = {
        "schema": _PREPASS_PREEXECUTION_AUTHORITY_SCHEMA,
        "work_unit_key": contract.key,
        "run_id": run_id,
        "contract_digest": contract.digest,
        "launch_digest": launch.digest,
        "pipeline": contract.pipeline,
        "mode": contract.mode,
        "ecosystem": contract.ecosystem,
        "backend": contract.backend,
        "planned_output_roster": [
            item.identity for item in contract.outputs
        ],
        "authority_capture": dict(capture),
    }
    return {
        **unsigned,
        "authority_sha256": _prepass_stable_digest(unsigned),
    }


def _validated_prepass_preexecution_authority(
    value: object,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass durable arm lacks a full authority object"
        )
    expected_fields = {
        "schema",
        "work_unit_key",
        "run_id",
        "contract_digest",
        "launch_digest",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
        "planned_output_roster",
        "authority_capture",
        "authority_sha256",
    }
    if set(value) != expected_fields:
        raise ReconPrepassAuthorityError(
            "recon prepass preexecution authority field denominator drift"
        )
    scalar_fields = (
        "work_unit_key",
        "run_id",
        "contract_digest",
        "launch_digest",
        "pipeline",
        "mode",
        "ecosystem",
        "backend",
    )
    if value.get("schema") != _PREPASS_PREEXECUTION_AUTHORITY_SCHEMA:
        raise ReconPrepassAuthorityError(
            "recon prepass preexecution authority schema mismatch"
        )
    if any(
        not isinstance(value.get(field), str)
        or not str(value[field]).strip()
        for field in scalar_fields
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass preexecution authority scalar is invalid"
        )
    for field in ("contract_digest", "launch_digest"):
        if re.fullmatch(r"[0-9a-f]{64}", str(value[field])) is None:
            raise ReconPrepassAuthorityError(
                f"recon prepass preexecution authority {field} is invalid"
            )
    roster = value.get("planned_output_roster")
    if (
        not isinstance(roster, list)
        or not roster
        or any(not isinstance(item, str) or not item for item in roster)
        or len(roster) != len(set(roster))
        or len(roster) != len({item.casefold() for item in roster})
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass planned output roster is malformed or aliased"
        )
    capture = value.get("authority_capture")
    capture_fields = {
        "source_capture_digest",
        "production_source_capture_digest",
        "source_root_authority",
        "config_digest",
        "snapshot_digest",
        "source_scope_digest",
        "source_path_authority",
        "audit_config_authority",
        "unexpected_semantic_outputs",
        "input_set_digest",
    }
    if not isinstance(capture, dict) or set(capture) != capture_fields:
        raise ReconPrepassAuthorityError(
            "recon prepass arm authority capture denominator mismatch"
        )
    source_root_authority = capture.get("source_root_authority")
    source_root_fields = {
        "schema",
        "logical_identity",
        "status",
        "device",
        "inode",
        "mode_type",
        "file_attributes",
        "reparse_tag",
    }
    if (
        not isinstance(source_root_authority, dict)
        or set(source_root_authority) != source_root_fields
        or source_root_authority.get("schema") != _PREPASS_SOURCE_ROOT_SCHEMA
        or source_root_authority.get("logical_identity") != "project:root"
        or source_root_authority.get("status") not in {"PRESENT", "ABSENT"}
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source-root authority denominator mismatch"
        )
    if source_root_authority["status"] == "ABSENT":
        if any(
            source_root_authority.get(field) is not None
            for field in (
                "device",
                "inode",
                "mode_type",
                "file_attributes",
                "reparse_tag",
            )
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass absent source-root authority is malformed"
            )
    else:
        integer_fields = (
            "device",
            "inode",
            "mode_type",
            "file_attributes",
            "reparse_tag",
        )
        exact_integers = all(
            type(source_root_authority.get(field)) is int
            for field in integer_fields
        )
        if os.name == "nt":
            valid_identity = (
                exact_integers
                and 1 <= source_root_authority["device"] <= 0xFFFFFFFF
                and 1 <= source_root_authority["inode"] <= 0xFFFFFFFFFFFFFFFF
                and source_root_authority["mode_type"] == stat.S_IFDIR
                and 0 <= source_root_authority["file_attributes"] <= 0xFFFFFFFF
                and bool(
                    source_root_authority["file_attributes"]
                    & _FILE_ATTRIBUTE_DIRECTORY
                )
                and not bool(
                    source_root_authority["file_attributes"]
                    & _FILE_ATTRIBUTE_REPARSE_POINT
                )
                and 0 <= source_root_authority["reparse_tag"] <= 0xFFFFFFFF
                and source_root_authority["reparse_tag"] == 0
            )
        else:
            valid_identity = (
                exact_integers
                and source_root_authority["device"] >= 0
                and source_root_authority["inode"] > 0
                and source_root_authority["mode_type"] == stat.S_IFDIR
                and not bool(
                    source_root_authority["file_attributes"]
                    & _FILE_ATTRIBUTE_REPARSE_POINT
                )
                and source_root_authority["reparse_tag"] == 0
            )
        if not valid_identity:
            raise ReconPrepassAuthorityError(
                "recon prepass present source-root authority is malformed"
            )
    unexpected = capture.get("unexpected_semantic_outputs")
    if (
        not isinstance(unexpected, dict)
        or list(unexpected) != sorted(unexpected)
        or len(unexpected) != len({str(key).casefold() for key in unexpected})
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for key, digest in unexpected.items()
        )
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass unexpected semantic authority is malformed"
        )
    for field in ("snapshot_digest", "source_scope_digest"):
        digest_value = capture.get(field)
        if (
            not isinstance(digest_value, str)
            or (
                digest_value
                and re.fullmatch(r"[0-9a-f]{64}", digest_value) is None
            )
        ):
            raise ReconPrepassAuthorityError(
                f"recon prepass arm authority capture {field} is invalid"
            )
    source_path_authority = capture.get("source_path_authority")
    audit_config_authority = capture.get("audit_config_authority")
    if not isinstance(source_path_authority, dict) or not isinstance(
        audit_config_authority, dict
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass snapshot-derived authority is malformed"
        )
    if bool(capture["snapshot_digest"]) != bool(source_path_authority):
        raise ReconPrepassAuthorityError(
            "recon prepass source-path authority presence differs from snapshot"
        )
    if bool(capture["snapshot_digest"]) != bool(audit_config_authority):
        raise ReconPrepassAuthorityError(
            "recon prepass config authority presence differs from snapshot"
        )
    if source_path_authority and (
        source_path_authority.get("snapshot_digest")
        != capture["snapshot_digest"]
        or source_path_authority.get("source_scope_digest")
        != capture["source_scope_digest"]
        or source_path_authority.get("authority_digest")
        != capture["production_source_capture_digest"]
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass source-path authority binding mismatch"
        )
    for field in (
        "source_capture_digest",
        "production_source_capture_digest",
        "config_digest",
        "input_set_digest",
    ):
        if (
            not isinstance(capture.get(field), str)
            or re.fullmatch(r"[0-9a-f]{64}", str(capture[field])) is None
        ):
            raise ReconPrepassAuthorityError(
                f"recon prepass arm authority capture {field} is invalid"
            )
    expected_input_digest = _prepass_stable_digest({
        "source_capture_digest": capture["source_capture_digest"],
        "production_source_capture_digest": capture[
            "production_source_capture_digest"
        ],
        "source_root_authority": source_root_authority,
        "config_digest": capture["config_digest"],
        "snapshot_digest": capture["snapshot_digest"],
        "source_scope_digest": capture["source_scope_digest"],
        "source_path_authority": source_path_authority,
        "audit_config_authority": audit_config_authority,
        "unexpected_semantic_outputs": unexpected,
    })
    if capture["input_set_digest"] != expected_input_digest:
        raise ReconPrepassAuthorityError(
            "recon prepass arm authority input-set digest mismatch"
        )
    unsigned = dict(value)
    stored_digest = unsigned.pop("authority_sha256", None)
    if (
        not isinstance(stored_digest, str)
        or stored_digest != _prepass_stable_digest(unsigned)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass preexecution authority digest mismatch"
        )
    try:
        replayed = json.loads(json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ))
    except (TypeError, ValueError) as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass preexecution authority is not canonical JSON: {exc}"
        ) from exc
    if replayed != value:
        raise ReconPrepassAuthorityError(
            "recon prepass preexecution authority changes under JSON replay"
        )
    return replayed


def _prepass_authority_pair(
    authority: Mapping[str, Any],
) -> tuple[Any, LaunchSpec]:
    key = str(authority.get("work_unit_key") or "")
    key_parts = key.split("/")
    if len(key_parts) != 6:
        raise ReconPrepassAuthorityError(
            "recon prepass stored work-unit key is not six-component"
        )
    work_unit_id = key_parts[-1]
    if (
        work_unit_id != "prepass"
        and re.fullmatch(r"prepass\.attempt-\d{4}", work_unit_id) is None
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass stored work-unit identity is not registered"
        )
    contract = resolve_phase_io_contract(
        pipeline=str(authority["pipeline"]),
        mode=str(authority["mode"]),
        ecosystem=str(authority["ecosystem"]),
        backend=str(authority["backend"]),
        phase="recon",
        work_unit_id=work_unit_id,
    )
    if (
        contract.key != authority.get("work_unit_key")
        or contract.digest != authority.get("contract_digest")
        or [item.identity for item in contract.outputs]
        != authority.get("planned_output_roster")
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass stored contract/roster authority mismatch"
        )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_PREPASS_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    if launch.digest != authority.get("launch_digest"):
        raise ReconPrepassAuthorityError(
            "recon prepass stored launch authority mismatch"
        )
    return contract, launch


def _prepass_receipt(
    stage: Path,
    output_names: tuple[str, ...],
    capture: Mapping[str, Any],
    results: Mapping[str, str],
    auxiliary_output_sha256: Mapping[str, str],
) -> dict[str, Any]:
    selected = output_names[:-1]
    hashes = {
        name: _prepass_bounded_file_digest(
            stage / name,
            label="recon prepass staged selected output",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )[0]
        for name in selected
    }
    payload: dict[str, Any] = {
        "schema": "plamen.recon_prepass_publication.v2",
        "authority_capture": dict(capture),
        "selected_outputs": list(selected),
        "selected_output_sha256": hashes,
        "auxiliary_outputs": sorted(auxiliary_output_sha256),
        "auxiliary_output_sha256": dict(auxiliary_output_sha256),
        "results": dict(results),
    }
    payload["artifact_sha256"] = hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest().upper()
    return payload


def _prepass_auxiliary_output_sha256(
    stage: Path,
    output_names: tuple[str, ...],
    excluded_private_roots: tuple[
        tuple[
            str,
            tuple[tuple[str, int, tuple[int, int, int]], ...],
            tuple[tuple[str, tuple[int, int, int, int, int, int]], ...],
        ],
        ...,
    ] = (),
) -> dict[str, str]:
    """Bind every renderer sidecar omitted from the PhaseIO denominator.

    Graphs, scanner evidence, and the tool-coverage ledger are independent
    machine authorities rather than canonical recon outputs. They still have
    to cross the staging boundary with the selected prepass generation.
    """

    selected = set(output_names)
    rows: dict[str, str] = {}
    total_bytes = 0
    try:
        with _rooted_io.scandir(stage) as iterator:
            entries = []
            for entry in iterator:
                if len(entries) >= _PREPASS_STAGE_MAX_ENTRIES:
                    raise ReconPrepassAuthorityError(
                        "recon prepass staged entry budget exceeded"
                    )
                entries.append(entry.name)
    except ReconPrepassAuthorityError:
        raise
    except OSError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass staged enumeration failed: {exc}"
        ) from exc
    excluded_by_name = {row[0]: row for row in excluded_private_roots}
    if len(excluded_by_name) != len(excluded_private_roots):
        raise ReconPrepassAuthorityError(
            "recon prepass renderer-private attestation is ambiguous"
        )
    replay_seen = [0]
    for name, _directories, _files in excluded_private_roots:
        try:
            replay = _prepass_collect_private_tree_manifest(
                stage,
                stage / name,
                label="recon prepass renderer-private replay",
                seen=replay_seen,
            )
            replay_attestation = _prepass_private_tree_attestation(
                stage, name, replay
            )
        except ReconPrepassAuthorityError as exc:
            raise ReconPrepassAuthorityError(
                "recon prepass renderer-private attestation changed"
            ) from exc
        except (OSError, ValueError, _rooted_io.RootedPathIOError) as exc:
            raise ReconPrepassAuthorityError(
                "recon prepass renderer-private attestation changed"
            ) from exc
        if replay_attestation != excluded_by_name[name]:
            raise ReconPrepassAuthorityError(
                "recon prepass renderer-private attestation changed"
            )
    for relative in sorted(entries):
        path = stage / relative
        if relative in excluded_by_name:
            continue
        if not _prepass_regular_file_present(
            path, label="recon prepass staged artifact"
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass renderer produced a missing staged artifact"
            )
        if relative in selected:
            continue
        if relative not in _PREPASS_AUXILIARY_OUTPUTS:
            raise ReconPrepassAuthorityError(
                "recon prepass renderer produced an unregistered auxiliary "
                f"output: {relative}"
            )
        digest, size = _prepass_bounded_file_digest(
            path,
            label="recon prepass staged auxiliary output",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        total_bytes += size
        if total_bytes > _PREPASS_STAGE_MAX_TOTAL_BYTES:
            raise ReconPrepassAuthorityError(
                "recon prepass staged total-byte budget exceeded"
            )
        rows[relative] = digest
    return rows


def _prepass_auxiliary_path(root: Path, relative: object) -> Path:
    """Resolve one receipt-bound sidecar without accepting path escape."""

    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ReconPrepassAuthorityError(
            "recon prepass auxiliary output path is malformed"
        )
    parts = relative.split("/")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise ReconPrepassAuthorityError(
            "recon prepass auxiliary output path is malformed"
        )
    try:
        return _rooted_io.safe_descendant(
            root,
            "/".join(parts),
            allow_missing=True,
            label="recon prepass auxiliary output",
        )
    except _rooted_io.RootedPathIOError as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass auxiliary output path is unsafe"
        ) from exc


def _prepass_read_receipt(scratchpad: Path) -> Mapping[str, Any] | None:
    try:
        receipt_path = _rooted_io.safe_descendant(
            scratchpad,
            _PREPASS_PUBLICATION_RECEIPT,
            allow_missing=True,
            label="recon prepass publication receipt",
        )
        if not _rooted_io.lexists(receipt_path):
            return None
        payload = json.loads(_prepass_bounded_read_bytes(
            receipt_path,
            label="recon prepass publication receipt",
            max_bytes=8 * 1024 * 1024,
        ))
    except (
        FileNotFoundError,
        OSError,
        TypeError,
        ValueError,
        _rooted_io.RootedPathIOError,
    ):
        return None
    if not isinstance(payload, dict):
        return None
    stored = payload.get("artifact_sha256")
    unsigned = dict(payload)
    unsigned.pop("artifact_sha256", None)
    expected = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest().upper()
    return payload if stored == expected else None


def _prepass_published_records(
    scratchpad: Path,
    output_names: tuple[str, ...],
    capture: Mapping[str, Any],
) -> dict[str, dict[str, Any]] | None:
    receipt = _prepass_read_receipt(scratchpad)
    if receipt is None or receipt.get("authority_capture") != capture:
        return None
    selected = output_names[:-1]
    if tuple(receipt.get("selected_outputs") or ()) != selected:
        return None
    output_hashes = receipt.get("selected_output_sha256")
    if not isinstance(output_hashes, dict) or set(output_hashes) != set(selected):
        return None
    auxiliary = receipt.get("auxiliary_outputs")
    auxiliary_hashes = receipt.get("auxiliary_output_sha256")
    if (
        not isinstance(auxiliary, list)
        or any(not isinstance(item, str) for item in auxiliary)
        or auxiliary != sorted(auxiliary)
        or len(auxiliary) != len(set(auxiliary))
        or not isinstance(auxiliary_hashes, dict)
        or set(auxiliary_hashes) != set(auxiliary)
        or any(item not in _PREPASS_AUXILIARY_OUTPUTS for item in auxiliary)
    ):
        return None
    for relative in auxiliary:
        try:
            path = _prepass_auxiliary_path(scratchpad, relative)
        except ReconPrepassAuthorityError:
            return None
        if not _prepass_regular_file_present(
            path, label="recon prepass published auxiliary output"
        ):
            return None
        digest, _size = _prepass_bounded_file_digest(
            path,
            label="recon prepass published auxiliary output",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if auxiliary_hashes.get(relative) != digest:
            return None
    for relative in _PREPASS_AUXILIARY_OUTPUTS.difference(auxiliary):
        try:
            orphan = _prepass_auxiliary_path(scratchpad, relative)
        except ReconPrepassAuthorityError:
            return None
        if _rooted_io.lexists(orphan):
            return None
    records: dict[str, dict[str, Any]] = {}
    for name in output_names:
        path = scratchpad / name
        if not _prepass_regular_file_present(
            path, label="recon prepass published selected output"
        ):
            return None
        digest, size = _prepass_bounded_file_digest(
            path,
            label="recon prepass published selected output",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if size == 0:
            return None
        if name != _PREPASS_PUBLICATION_RECEIPT:
            if output_hashes.get(name) != digest:
                return None
        records[f"scratchpad:{name}"] = {
            "sha256": digest,
            "size": size,
        }
    return records


def _prepass_bind_publication_intent_ledger(
    scratchpad: Path,
    intent: Mapping[str, Any],
) -> Mapping[str, Any]:
    """CAS-bind one authenticated publication intent into its exact row."""

    ledger = read_artifact_ledger(scratchpad)
    prestate = json.loads(json.dumps(ledger))
    units = ledger.get("work_units")
    key = str(intent.get("successor_work_unit_key") or "")
    authority = _validated_prepass_preexecution_authority(
        intent.get("successor_preexecution_authority")
    )
    row = units.get(key) if isinstance(units, dict) else None
    intent_digest = intent.get("intent_digest")
    authority_digest = authority.get("authority_sha256")
    if (
        not isinstance(row, dict)
        or not isinstance(intent_digest, str)
        or row.get("run_id") != intent.get("run_id")
        or row.get("preexecution_authority") != authority
        or row.get("preexecution_authority_digest") != authority_digest
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass publication intent lacks exact ledger authority"
        )
    bound = row.get("auxiliary_publication_intent_digest")
    if bound not in {None, intent_digest}:
        raise ReconPrepassAuthorityError(
            "recon prepass publication ledger intent collision"
        )
    if bound is None:
        row["auxiliary_publication_intent_digest"] = intent_digest
        row["auxiliary_publication_authority_digest"] = authority_digest
        _prepass_commit_ledger_cas(scratchpad, prestate, ledger)
        row = read_artifact_ledger(scratchpad)["work_units"][key]
    elif row.get("auxiliary_publication_authority_digest") != authority_digest:
        raise ReconPrepassAuthorityError(
            "recon prepass publication ledger authority differs"
        )
    return row


def _prepass_seal_publication_transaction(
    scratchpad: Path,
    stage: Path | None,
    output_names: tuple[str, ...],
    current_auxiliary: Mapping[str, str],
    *,
    run_id: str,
    successor_authority: Mapping[str, Any],
    successor_work_unit_key: str,
    successor_receipt_sha256: str,
) -> tuple[dict[str, Any], Path]:
    """Persist the exact rendered generation and bind its intent in the ledger."""

    authority = _validated_prepass_preexecution_authority(successor_authority)
    authority_digest = str(authority["authority_sha256"])
    if authority.get("work_unit_key") != successor_work_unit_key:
        raise ReconPrepassAuthorityError(
            "recon prepass publication authority work unit differs"
        )
    transaction_root = _prepass_ensure_private_directory(
        scratchpad, scratchpad / "_recon_prepass_auxiliary_transactions"
    )
    intent_path = transaction_root / f"{authority_digest}.intent.json"
    existing = _prepass_read_private_json(scratchpad, intent_path)
    payload_root = transaction_root / "payload" / authority_digest

    if existing is None:
        if stage is None:
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication intent is absent"
            )
        if _rooted_io.lexists(payload_root):
            _prepass_remove_private_tree(
                scratchpad,
                payload_root,
                label="recon prepass unbound publication payload",
            )
        payload_root = _prepass_ensure_private_directory(scratchpad, payload_root)
        members: dict[str, dict[str, Any]] = {}
        for relative in (*output_names, *tuple(sorted(current_auxiliary))):
            source = _prepass_auxiliary_path(stage, relative)
            digest, size = _prepass_bounded_file_digest(
                source,
                label="recon prepass publication payload source",
                max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
            )
            target = _prepass_auxiliary_path(payload_root, relative)
            _prepass_durable_replace_from_stage(
                source,
                target,
                label="recon prepass private publication payload",
            )
            members[relative] = {
                "sha256": digest,
                "size": size,
                "kind": (
                    "AUXILIARY" if relative in current_auxiliary
                    else "RECEIPT" if relative == _PREPASS_PUBLICATION_RECEIPT
                    else "SELECTED"
                ),
            }
        prior = _prepass_read_receipt(scratchpad)
        prior_names = prior.get("auxiliary_outputs") if prior is not None else []
        prior_hashes = prior.get("auxiliary_output_sha256") if prior is not None else {}
        if (
            not isinstance(prior_names, list)
            or not isinstance(prior_hashes, Mapping)
            or set(prior_names) != set(prior_hashes)
            or any(name not in _PREPASS_AUXILIARY_OUTPUTS for name in prior_names)
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass predecessor auxiliary denominator is malformed"
            )
        receipt_digest = str(prior.get("artifact_sha256") or "") if prior else ""
        predecessor_archive = _prepass_ensure_private_directory(
            scratchpad,
            transaction_root / "predecessor" / (receipt_digest or "NONE"),
        )
        predecessor_records: dict[str, dict[str, Any]] = {}
        for relative in prior_names:
            candidates = (
                _prepass_auxiliary_path(scratchpad, relative),
                _prepass_auxiliary_path(predecessor_archive, relative),
            )
            matched: dict[str, Any] | None = None
            for candidate in candidates:
                if not _rooted_io.lexists(candidate):
                    continue
                digest, size = _prepass_bounded_file_digest(
                    candidate,
                    label="recon prepass predecessor publication member",
                    max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
                )
                if digest == prior_hashes[relative]:
                    matched = {"sha256": digest, "size": size}
                    break
            if matched is None:
                raise ReconPrepassAuthorityError(
                    "recon prepass predecessor publication member differs"
                )
            predecessor_records[relative] = matched
        unsigned = {
            "schema": "plamen.recon-prepass-publication-transaction.v2",
            "run_id": run_id,
            "successor_authority_digest": authority_digest,
            "successor_preexecution_authority": authority,
            "successor_work_unit_key": successor_work_unit_key,
            "successor_receipt_sha256": successor_receipt_sha256,
            "predecessor_receipt_sha256": receipt_digest,
            "predecessor_auxiliary": predecessor_records,
            "successor_auxiliary": {
                name: {"sha256": members[name]["sha256"], "size": members[name]["size"]}
                for name in sorted(current_auxiliary)
            },
            "publication_members": members,
        }
        existing = {**unsigned, "intent_digest": _prepass_stable_digest(unsigned)}
        _prepass_write_json_atomic(scratchpad, intent_path, existing)
    intent = dict(existing)
    if (
        intent.get("schema")
        != "plamen.recon-prepass-publication-transaction.v2"
        or intent.get("run_id") != run_id
        or intent.get("successor_authority_digest") != authority_digest
        or intent.get("successor_preexecution_authority") != authority
        or intent.get("successor_work_unit_key") != successor_work_unit_key
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass publication transaction intent collision"
        )
    unsigned = dict(intent)
    stored_digest = unsigned.pop("intent_digest", None)
    if stored_digest != _prepass_stable_digest(unsigned):
        raise ReconPrepassAuthorityError(
            "recon prepass publication transaction digest differs"
        )
    members = intent.get("publication_members")
    if not isinstance(members, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass publication payload denominator is malformed"
        )
    total = 0
    payload_root = _prepass_ensure_private_directory(scratchpad, payload_root)
    for relative, record in members.items():
        if (
            not isinstance(relative, str)
            or not isinstance(record, Mapping)
            or set(record) != {"sha256", "size", "kind"}
            or record.get("kind") not in {"SELECTED", "AUXILIARY", "RECEIPT"}
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass publication payload record is malformed"
            )
        digest, size = _prepass_bounded_file_digest(
            _prepass_auxiliary_path(payload_root, relative),
            label="recon prepass sealed publication payload",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if digest != record.get("sha256") or size != record.get("size"):
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication payload differs"
            )
        total += size
        if total > _PREPASS_STAGE_MAX_TOTAL_BYTES:
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication payload exceeds budget"
            )

    _prepass_bind_publication_intent_ledger(scratchpad, intent)
    return intent, payload_root


def _prepass_prepare_auxiliary_transaction(
    scratchpad: Path,
    current_intent: Mapping[str, Any],
    *,
    successor_authority_digest: str,
    successor_work_unit_key: str,
) -> None:
    """Journal and isolate every auxiliary generation before publication.

    The public receipt is written last.  Consequently a crash can expose only
    a subset of the new sidecars while the old receipt is still authoritative.
    Each intent stores both denominators before any public sidecar changes.  A
    later generation first finishes/retire-replays that exact intent, so old,
    partial-new, and current bytes can never be confused.
    """

    transaction_root = _prepass_ensure_private_directory(
        scratchpad, scratchpad / "_recon_prepass_auxiliary_transactions"
    )

    def _record(path: Path, *, label: str) -> dict[str, Any]:
        digest, size = _prepass_bounded_file_digest(
            path, label=label, max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES
        )
        return {"sha256": digest, "size": size}

    def _validate_intent(value: Mapping[str, Any]) -> dict[str, Any]:
        unsigned = dict(value)
        stored = unsigned.pop("intent_digest", None)
        if (
            value.get("schema")
            != "plamen.recon-prepass-publication-transaction.v2"
            or stored != _prepass_stable_digest(unsigned)
            or not isinstance(value.get("run_id"), str)
            or not isinstance(value.get("successor_authority_digest"), str)
            or not isinstance(value.get("successor_preexecution_authority"), Mapping)
            or not isinstance(value.get("successor_work_unit_key"), str)
            or not isinstance(value.get("successor_receipt_sha256"), str)
            or not isinstance(value.get("publication_members"), Mapping)
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary transaction intent is malformed"
            )
        for field in ("predecessor_auxiliary", "successor_auxiliary"):
            records = value.get(field)
            if (
                not isinstance(records, Mapping)
                or any(name not in _PREPASS_AUXILIARY_OUTPUTS for name in records)
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass auxiliary transaction denominator is malformed"
                )
            for record in records.values():
                if (
                    not isinstance(record, Mapping)
                    or set(record) != {"sha256", "size"}
                    or not isinstance(record.get("sha256"), str)
                    or not isinstance(record.get("size"), int)
                    or record.get("size", -1) < 0
                ):
                    raise ReconPrepassAuthorityError(
                        "recon prepass auxiliary transaction record is malformed"
                    )
        return dict(value)

    def _validate_provenance(
        intent: Mapping[str, Any], *, require_binding: bool
    ) -> Mapping[str, Any]:
        ledger = read_artifact_ledger(scratchpad)
        units = ledger.get("work_units")
        key = str(intent["successor_work_unit_key"])
        row = units.get(key) if isinstance(units, Mapping) else None
        authority = _validated_prepass_preexecution_authority(
            intent.get("successor_preexecution_authority")
        )
        if (
            not isinstance(row, Mapping)
            or row.get("run_id") != intent.get("run_id")
            or authority.get("work_unit_key") != key
            or authority.get("run_id") != intent.get("run_id")
            or authority.get("authority_sha256")
            != intent.get("successor_authority_digest")
            or row.get("preexecution_authority") != authority
            or row.get("preexecution_authority_digest")
            != authority.get("authority_sha256")
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary intent lacks ledger provenance"
            )
        if require_binding and (
            row.get("auxiliary_publication_intent_digest")
            != intent.get("intent_digest")
            or row.get("auxiliary_publication_authority_digest")
            != authority.get("authority_sha256")
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary intent lacks ledger binding"
            )
        prefix = key.split("/")[:5]
        generations = [
            candidate for candidate in units
            if isinstance(candidate, str)
            and candidate.split("/")[:5] == prefix
            and len(candidate.split("/")) == 6
            and (
                candidate.endswith("/prepass")
                or _PREPASS_ATTEMPT_ID_RE.fullmatch(candidate.split("/")[-1])
            )
        ]
        if not generations:
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary intent lineage is absent"
            )
        head = max(generations, key=_prepass_generation_ordinal)
        _prepass_validate_closed_lineage(
            scratchpad,
            units,
            {
                "pipeline": prefix[0], "mode": prefix[1],
                "language": prefix[2], "cli_backend": prefix[3],
            },
            run_id=str(intent["run_id"]),
            head_key=head,
        )
        return row

    def _public_generation_matches(intent: Mapping[str, Any]) -> bool:
        members = intent.get("publication_members")
        if not isinstance(members, Mapping):
            return False
        for relative, expected in members.items():
            path = _prepass_auxiliary_path(scratchpad, relative)
            if not _prepass_regular_file_present(
                path, label="recon prepass terminal publication member"
            ):
                return False
            if _record(
                path, label="recon prepass terminal publication member"
            ) != {
                "sha256": expected.get("sha256"),
                "size": expected.get("size"),
            }:
                return False
        return True

    def _resolution_path(authority_digest: str) -> Path:
        return transaction_root / f"{authority_digest}.resolved.json"

    def _resolve(intent: Mapping[str, Any], status: str) -> None:
        authority_digest = str(intent["successor_authority_digest"])
        path = _resolution_path(authority_digest)
        unsigned = {
            "schema": "plamen.recon-prepass-auxiliary-resolution.v1",
            "intent_digest": intent["intent_digest"],
            "successor_authority_digest": authority_digest,
            "status": status,
            "terminal_receipt_sha256": (
                intent["successor_receipt_sha256"]
                if status == "COMMITTED" else None
            ),
        }
        value = {**unsigned, "resolution_digest": _prepass_stable_digest(unsigned)}
        existing = _prepass_read_private_json(scratchpad, path)
        if existing is None:
            _prepass_write_json_atomic(scratchpad, path, value)
        elif existing != value:
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary resolution collision"
            )

    def _archive_predecessor(intent: Mapping[str, Any]) -> None:
        receipt_digest = str(intent.get("predecessor_receipt_sha256") or "NONE")
        archive_root = _prepass_ensure_private_directory(
            scratchpad, transaction_root / "predecessor" / receipt_digest
        )
        for relative, expected in intent["predecessor_auxiliary"].items():
            source = _prepass_auxiliary_path(scratchpad, relative)
            archived = _prepass_auxiliary_path(archive_root, relative)
            source_exists = _prepass_regular_file_present(
                source, label="recon prepass predecessor auxiliary source"
            )
            archive_exists = _prepass_regular_file_present(
                archived, label="recon prepass predecessor auxiliary archive"
            )
            if source_exists and archive_exists:
                source_digest, source_size = _prepass_bounded_file_digest(
                    source,
                    label="recon prepass predecessor auxiliary source",
                    max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
                )
                # A differing source can only be the already-published
                # successor member; the authenticated predecessor archive is
                # still the sole predecessor evidence in that case.
                if (
                    source_digest == expected["sha256"]
                    and source_size == expected["size"]
                ):
                    source_exists, archive_exists = _prepass_recover_durable_move(
                        source,
                        archived,
                        source_exists=True,
                        archive_exists=True,
                        expected_sha256=expected["sha256"],
                        expected_size=expected["size"],
                        label="recon prepass predecessor auxiliary",
                    )
            if not archive_exists:
                if not source_exists:
                    raise ReconPrepassAuthorityError(
                        "recon prepass predecessor auxiliary disappeared"
                    )
                digest, size = _prepass_bounded_file_digest(
                    source,
                    label="recon prepass predecessor auxiliary source",
                    max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
                )
                if digest != expected["sha256"] or size != expected["size"]:
                    raise ReconPrepassAuthorityError(
                        "recon prepass predecessor auxiliary bytes changed"
                    )
                _prepass_move_private(
                    scratchpad,
                    source,
                    archived,
                    expected_sha256=expected["sha256"],
                    expected_size=expected["size"],
                )
                archive_exists = True
            archived_record = _record(
                archived, label="recon prepass predecessor auxiliary archive"
            )
            if archived_record != expected:
                raise ReconPrepassAuthorityError(
                    "recon prepass predecessor auxiliary archive changed"
                )

    def _retire_partial_successor(intent: Mapping[str, Any]) -> None:
        archive_root = _prepass_ensure_private_directory(
            scratchpad,
            transaction_root / "successor"
            / str(intent["successor_authority_digest"]),
        )
        for relative, expected in intent["successor_auxiliary"].items():
            source = _prepass_auxiliary_path(scratchpad, relative)
            archived = _prepass_auxiliary_path(archive_root, relative)
            source_exists = _prepass_regular_file_present(
                source, label="recon prepass partial auxiliary source"
            )
            archive_exists = _prepass_regular_file_present(
                archived, label="recon prepass partial auxiliary archive"
            )
            source_exists, archive_exists = _prepass_recover_durable_move(
                source,
                archived,
                source_exists=source_exists,
                archive_exists=archive_exists,
                expected_sha256=expected["sha256"],
                expected_size=expected["size"],
                label="recon prepass partial auxiliary",
            )
            if source_exists:
                if _record(
                    source, label="recon prepass partial auxiliary source"
                ) != expected:
                    raise ReconPrepassAuthorityError(
                        "recon prepass partial auxiliary bytes changed"
                    )
                _prepass_move_private(
                    scratchpad,
                    source,
                    archived,
                    expected_sha256=expected["sha256"],
                    expected_size=expected["size"],
                )
            elif archive_exists and _record(
                archived, label="recon prepass partial auxiliary archive"
            ) != expected:
                raise ReconPrepassAuthorityError(
                    "recon prepass partial auxiliary archive changed"
                )
            # Absence is valid: this member may not have crossed the public
            # boundary before the crash.

    # Enumerate a closed, bounded transaction namespace.  Unknown or aliased
    # private entries are authority corruption, never ignorable clutter.
    intents: list[dict[str, Any]] = []
    try:
        with _rooted_io.scandir(transaction_root) as iterator:
            names = []
            for entry in iterator:
                names.append(entry.name)
                if len(names) > (_PREPASS_STAGE_MAX_ENTRIES * 2 + 2):
                    raise ReconPrepassAuthorityError(
                        "recon prepass auxiliary transaction entry budget exceeded"
                    )
    except OSError as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass auxiliary transaction enumeration failed"
        ) from exc
    for name in sorted(names):
        if name in {"predecessor", "successor", "payload"}:
            continue
        if name.endswith(".resolved.json"):
            continue
        if not name.endswith(".intent.json"):
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary transaction namespace is malformed"
            )
        value = _prepass_read_private_json(scratchpad, transaction_root / name)
        if value is None:
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary transaction intent disappeared"
            )
        intent = _validate_intent(value)
        if name != f"{intent['successor_authority_digest']}.intent.json":
            raise ReconPrepassAuthorityError(
                "recon prepass auxiliary transaction filename differs"
            )
        intents.append(intent)
    intents.sort(key=lambda item: _prepass_generation_ordinal(
        item["successor_work_unit_key"]
    ))
    # Authenticate the complete intent denominator before processing even the
    # first member. A forged future/cross-run intent must cause zero public
    # mutation, not fail only after earlier legitimate intents were replayed.
    for intent in intents:
        _validate_provenance(intent, require_binding=True)
    public_receipt = _prepass_read_receipt(scratchpad)
    for intent in intents:
        row = _validate_provenance(intent, require_binding=True)
        resolution = _prepass_read_private_json(
            scratchpad,
            _resolution_path(str(intent["successor_authority_digest"])),
        )
        if resolution is not None:
            unsigned_resolution = dict(resolution)
            stored_resolution_digest = unsigned_resolution.pop(
                "resolution_digest", None
            )
            if (
                set(resolution) != {
                    "schema", "intent_digest", "successor_authority_digest",
                    "status", "terminal_receipt_sha256", "resolution_digest",
                }
                or resolution.get("schema")
                != "plamen.recon-prepass-auxiliary-resolution.v1"
                or resolution.get("intent_digest") != intent["intent_digest"]
                or resolution.get("successor_authority_digest")
                != intent["successor_authority_digest"]
                or resolution.get("status") not in {"COMMITTED", "SUPERSEDED"}
                or (
                    resolution.get("terminal_receipt_sha256")
                    != intent["successor_receipt_sha256"]
                    if resolution.get("status") == "COMMITTED"
                    else resolution.get("terminal_receipt_sha256") is not None
                )
                or stored_resolution_digest
                != _prepass_stable_digest(unsigned_resolution)
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass auxiliary resolution is malformed"
                )
            if (
                resolution.get("status") == "COMMITTED"
                and not isinstance(row.get("commit_authority"), Mapping)
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass committed auxiliary resolution lacks commit authority"
                )
            continue
        if (
            public_receipt is not None
            and public_receipt.get("artifact_sha256")
            == intent["successor_receipt_sha256"]
        ):
            if not _public_generation_matches(intent):
                raise ReconPrepassAuthorityError(
                    "recon prepass terminal publication bytes differ"
                )
            _resolve(intent, "COMMITTED")
            continue
        _archive_predecessor(intent)
        if intent["successor_authority_digest"] != successor_authority_digest:
            _retire_partial_successor(intent)
            _resolve(intent, "SUPERSEDED")

    intent = _validate_intent(current_intent)
    if (
        intent["successor_authority_digest"] != successor_authority_digest
        or intent["successor_work_unit_key"] != successor_work_unit_key
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass auxiliary transaction intent collision"
        )
    _archive_predecessor(intent)
    for relative, expected in intent["successor_auxiliary"].items():
        public = _prepass_auxiliary_path(scratchpad, relative)
        if _rooted_io.lexists(public) and _record(
            public, label="recon prepass current partial auxiliary"
        ) != expected:
            raise ReconPrepassAuthorityError(
                "recon prepass current partial auxiliary bytes differ"
            )
    for relative in _PREPASS_AUXILIARY_OUTPUTS.difference(
        intent["successor_auxiliary"]
    ):
        if _rooted_io.lexists(_prepass_auxiliary_path(scratchpad, relative)):
            raise ReconPrepassAuthorityError(
                "recon prepass predecessor auxiliary was not isolated"
            )


def _prepass_bound_generation_state(
    scratchpad: Path,
    prior: Mapping[str, Any],
    output_names: tuple[str, ...],
) -> str:
    prestates = prior.get("output_prestates")
    if not isinstance(prestates, Mapping):
        return "mixed"
    old = 0
    new = 0
    for name in output_names:
        identity = f"scratchpad:{name}"
        prestate = prestates.get(identity)
        if not isinstance(prestate, Mapping):
            return "mixed"
        path = scratchpad / name
        exists = _prepass_regular_file_present(
            path, label="recon prepass bound selected output"
        )
        existed = prestate.get("existed") is True
        if not exists and not existed:
            old += 1
            continue
        if exists and existed:
            digest, _size = _prepass_bounded_file_digest(
                path,
                label="recon prepass bound selected output",
                max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
            )
            if digest == prestate.get("sha256"):
                old += 1
                continue
        new += 1
    if old == len(output_names):
        return "all_old"
    if new == len(output_names):
        return "all_new"
    return "mixed"


_PREPASS_ATTEMPT_ID_RE = re.compile(r"prepass\.attempt-(\d{4})")
_PREPASS_LEGACY_MIGRATION_RECEIPT = (
    "_recon_prepass_legacy_successor_migration.json"
)


def _prepass_generation_ordinal(work_unit_key: object) -> int:
    key = str(work_unit_key or "")
    parts = key.split("/")
    if len(parts) != 6 or parts[-2] != "recon":
        raise ReconPrepassAuthorityError(
            "recon prepass generation key is not six-component"
        )
    if parts[-1] == "prepass":
        return 1
    matched = _PREPASS_ATTEMPT_ID_RE.fullmatch(parts[-1])
    if matched is None or int(matched.group(1)) < 2:
        raise ReconPrepassAuthorityError(
            "recon prepass generation identity is malformed"
        )
    return int(matched.group(1))


def _prepass_successor_pair(
    predecessor_contract: Any,
    *,
    ordinal: int,
) -> tuple[Any, LaunchSpec]:
    if ordinal < 2 or ordinal != _prepass_generation_ordinal(
        predecessor_contract.key
    ) + 1:
        raise ReconPrepassAuthorityError(
            "recon prepass successor lineage is not contiguous"
        )
    contract = resolve_phase_io_contract(
        pipeline=predecessor_contract.pipeline,
        mode=predecessor_contract.mode,
        ecosystem=predecessor_contract.ecosystem,
        backend=predecessor_contract.backend,
        phase="recon",
        work_unit_id=f"prepass.attempt-{ordinal:04d}",
    )
    launch = LaunchSpec(
        work_unit_key=contract.key,
        pipeline=contract.pipeline,
        mode=contract.mode,
        ecosystem=contract.ecosystem,
        backend=contract.backend,
        model="driver",
        timeout_s=_PREPASS_TIMEOUT_SECONDS,
        exec_mode="python",
        tool_policy=("filesystem",),
    )
    return contract, launch


def _prepass_disposition_key(successor_key: str, ordinal: int) -> str:
    parts = successor_key.split("/")
    if len(parts) != 6:
        raise ReconPrepassAuthorityError(
            "recon prepass successor key is not six-component"
        )
    parts[-1] = f"prepass.disposition-{ordinal:04d}"
    return "/".join(parts)


def _prepass_write_json_atomic(
    scratchpad: Path,
    path: Path,
    value: Mapping[str, Any],
) -> None:
    raw = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    try:
        relative = path.relative_to(scratchpad).as_posix()
        destination = _rooted_io.safe_descendant(
            scratchpad,
            relative,
            allow_missing=True,
            label="recon prepass authority JSON",
        )
        parent = _rooted_io.checked_directory(
            destination.parent,
            label="recon prepass authority JSON parent",
        )
        descriptor, temporary = _rooted_io.exclusive_temp_file(
            parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            _rooted_io.durable_publish_new(temporary, destination)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except (OSError, ValueError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass authority JSON publication failed"
        ) from exc


def _prepass_read_private_json(
    scratchpad: Path,
    path: Path,
) -> Mapping[str, Any] | None:
    try:
        relative = path.relative_to(scratchpad).as_posix()
        candidate = _rooted_io.safe_descendant(
            scratchpad,
            relative,
            allow_missing=True,
            label="recon prepass private authority",
        )
        if not _rooted_io.lexists(candidate):
            return None
        payload = json.loads(_prepass_bounded_read_bytes(
            candidate,
            label="recon prepass private authority",
            max_bytes=8 * 1024 * 1024,
        ))
    except (OSError, TypeError, ValueError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass private authority is unreadable"
        ) from exc
    if not isinstance(payload, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass private authority is malformed"
        )
    return payload


def _prepass_ensure_private_directory(
    scratchpad: Path,
    directory: Path,
) -> Path:
    try:
        relative = directory.relative_to(scratchpad).as_posix()
        candidate = _rooted_io.safe_descendant(
            scratchpad,
            relative,
            allow_missing=True,
            label="recon prepass private directory",
        )
        _rooted_io.ensure_directory(
            candidate,
            parents=True,
            label="recon prepass private directory",
        )
        return _rooted_io.safe_descendant(
            scratchpad,
            relative,
            allow_missing=False,
            label="recon prepass private directory",
        )
    except (OSError, ValueError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass private directory is unsafe"
        ) from exc


def _prepass_move_private(
    scratchpad: Path,
    source: Path,
    archived: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> None:
    try:
        source_relative = source.relative_to(scratchpad).as_posix()
        archive_relative = archived.relative_to(scratchpad).as_posix()
        checked_source = _rooted_io.safe_descendant(
            scratchpad,
            source_relative,
            allow_missing=False,
            label="recon prepass quarantine source",
        )
        checked_archive = _rooted_io.safe_descendant(
            scratchpad,
            archive_relative,
            allow_missing=True,
            label="recon prepass quarantine destination",
        )
        _prepass_ensure_private_directory(scratchpad, checked_archive.parent)
        raw = _prepass_bounded_read_bytes(
            checked_source,
            label="recon prepass quarantine source",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if (
            hashlib.sha256(raw).hexdigest() != expected_sha256
            or len(raw) != expected_size
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass quarantine source bytes changed"
            )
        if _rooted_io.lexists(checked_archive):
            raise ReconPrepassAuthorityError(
                "recon prepass quarantine destination already exists"
            )
        _prepass_durable_replace_from_stage(
            checked_source,
            checked_archive,
            label="recon prepass quarantine artifact",
            retire_source=True,
        )
        archived_raw = _prepass_bounded_read_bytes(
            checked_archive,
            label="recon prepass quarantined artifact",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if archived_raw != raw or _rooted_io.lexists(checked_source):
            raise ReconPrepassAuthorityError(
                "recon prepass quarantine move was not exact"
            )
    except _rooted_io.RootedPathIOError as exc:
        raise ReconPrepassAuthorityError(
            "recon prepass quarantine move escaped rooted authority"
        ) from exc


def _prepass_recover_durable_move(
    source: Path,
    archived: Path,
    *,
    source_exists: bool,
    archive_exists: bool,
    expected_sha256: str,
    expected_size: int,
    label: str,
) -> tuple[bool, bool]:
    """Finish the only valid copy-before-unlink crash poststate.

    Durable cross-directory retirement deliberately publishes the archive before
    unlinking the public name.  A power loss can therefore leave two independent
    regular files.  That state is recoverable only when *both* files still match
    the exact intent-bound digest and size; aliases and links have already been
    rejected by ``_prepass_regular_file_present``.
    """

    if not (source_exists and archive_exists):
        return source_exists, archive_exists
    for path, suffix in ((source, "source"), (archived, "archive")):
        digest, size = _prepass_bounded_file_digest(
            path,
            label=f"{label} {suffix}",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if digest != expected_sha256 or size != expected_size:
            raise ReconPrepassAuthorityError(
                f"{label} duplicated bytes differ from durable intent"
            )
    try:
        _rooted_io.durable_unlink(source)
    except (OSError, _rooted_io.RootedPathIOError) as exc:
        raise ReconPrepassAuthorityError(
            f"{label} could not retire the durable source copy"
        ) from exc
    return False, True


def _prepass_projection_snapshot(
    ledger: Mapping[str, Any],
    roster: Sequence[str],
) -> dict[str, dict[str, Any]]:
    bindings = ledger.get("artifact_bindings")
    legacy = ledger.get("artifacts")
    return {
        identity: {
            "artifact_binding": json.loads(json.dumps(
                bindings.get(identity)
                if isinstance(bindings, Mapping) else None
            )),
            "legacy_artifact": json.loads(json.dumps(
                legacy.get(identity.split(":", 1)[1])
                if isinstance(legacy, Mapping) else None
            )),
        }
        for identity in roster
    }


def _prepass_assert_projection_snapshot(
    ledger: Mapping[str, Any],
    roster: Sequence[str],
    expected: object,
) -> None:
    if (
        not isinstance(expected, Mapping)
        or _prepass_projection_snapshot(ledger, roster) != expected
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass artifact projection CAS changed"
        )


def _prepass_assert_projection_owner(
    snapshot: object,
    roster: Sequence[str],
    *,
    allowed_owner: str,
) -> None:
    """Reject intents that would retire an unrelated projection owner."""

    if not isinstance(snapshot, Mapping) or set(snapshot) != set(roster):
        raise ReconPrepassAuthorityError(
            "recon prepass artifact projection denominator differs"
        )
    for identity in roster:
        pair = snapshot.get(identity)
        if not isinstance(pair, Mapping) or set(pair) != {
            "artifact_binding", "legacy_artifact"
        }:
            raise ReconPrepassAuthorityError(
                "recon prepass artifact projection record is malformed"
            )
        for row in pair.values():
            if row is not None and (
                not isinstance(row, Mapping)
                or row.get("owner_key") != allowed_owner
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass artifact projection has unrelated owner"
                )


def recon_prepass_expected_owner_prefix(config: Mapping[str, Any]) -> str:
    """Return the canonical five-component prepass owner prefix."""

    if not isinstance(config, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass owner-prefix config is malformed"
        )
    return "/".join(_prepass_expected_prefix(config))


def _prepass_legacy_authority(value: object) -> dict[str, Any]:
    """Replay the exact pre-v3 authority without accepting it for execution."""

    if not isinstance(value, dict):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass authority is absent"
        )
    expected = {
        "schema", "work_unit_key", "run_id", "contract_digest",
        "launch_digest", "pipeline", "mode", "ecosystem", "backend",
        "planned_output_roster", "authority_capture", "authority_sha256",
    }
    unsigned = dict(value)
    digest = unsigned.pop("authority_sha256", None)
    capture = value.get("authority_capture")
    if (
        set(value) != expected
        or value.get("schema") != _PREPASS_PREEXECUTION_AUTHORITY_SCHEMA
        or not isinstance(capture, dict)
        or set(capture) != {
            "source_capture_digest", "source_root_authority", "config_digest",
            "unexpected_semantic_outputs", "input_set_digest",
        }
        or digest != _prepass_stable_digest(unsigned)
        or len(str(value.get("work_unit_key") or "").split("/")) != 6
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass authority integrity failure"
        )
    return json.loads(json.dumps(value, sort_keys=True))


def _prepass_expected_prefix(config: Mapping[str, Any]) -> tuple[str, ...]:
    return (*_prepass_dimensions(dict(config)), "recon")


def _prepass_validate_legacy_migration_receipt(
    scratchpad: Path,
    units: Mapping[str, Any],
    *,
    run_id: str,
    predecessor_key: str,
    successor_key: str,
    lineage_head_key: str | None = None,
) -> bool:
    receipt = _prepass_read_private_json(
        scratchpad, scratchpad / _PREPASS_LEGACY_MIGRATION_RECEIPT
    )
    if receipt is None:
        return False
    unsigned = dict(receipt)
    digest = unsigned.pop("migration_digest", None)
    legacy_key = f"{predecessor_key}/attempt-2"
    predecessor = units.get(predecessor_key)
    legacy = units.get(legacy_key)
    successor = units.get(successor_key)
    successor_authority = (
        successor.get("preexecution_authority")
        if isinstance(successor, Mapping) else None
    )
    if (
        receipt.get("schema")
        != "plamen.recon-prepass-legacy-successor-migration.v3"
        or digest != _prepass_stable_digest(unsigned)
        or receipt.get("run_id") != run_id
        or receipt.get("predecessor_work_unit_key") != predecessor_key
        or receipt.get("legacy_evidence_key") != legacy_key
        or receipt.get("successor_work_unit_key") != successor_key
        or not isinstance(predecessor, Mapping)
        or not isinstance(legacy, Mapping)
        or not isinstance(successor_authority, Mapping)
        or receipt.get("successor_preexecution_authority")
        != successor_authority
        or receipt.get("legacy_evidence_digest")
        != _prepass_stable_digest(dict(legacy))
        or receipt.get("successor_preexecution_authority_digest")
        != successor_authority.get("authority_sha256")
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass migration receipt lineage is invalid"
        )
    predecessor_digest = _prepass_stable_digest(dict(predecessor))
    successor_state = (
        successor.get("semantic_status"), successor.get("execution_state")
    )
    allowed_predecessor_digests = {
        receipt.get("quarantined_predecessor_digest"),
        receipt.get("finalized_predecessor_digest"),
    }
    normalized_predecessor_digest = predecessor_digest
    if (
        predecessor_digest not in allowed_predecessor_digests
        and
        lineage_head_key is not None
        and lineage_head_key != successor_key
        and isinstance(predecessor, Mapping)
    ):
        lineage_head_ordinal = _prepass_generation_ordinal(lineage_head_key)
        if (
            predecessor.get("superseded_by_work_unit_key")
            != lineage_head_key
            or predecessor.get("superseded_by_generation_ordinal")
            != lineage_head_ordinal
            or (predecessor.get("semantic_status"),
                predecessor.get("execution_state")) != ("INVALID", "FAILED")
        ):
            raise ReconPrepassAuthorityError(
                "legacy recon prepass predecessor lineage head differs"
            )
        normalized = json.loads(json.dumps(predecessor))
        normalized["superseded_by_work_unit_key"] = successor_key
        normalized["superseded_by_generation_ordinal"] = 2
        normalized_predecessor_digest = _prepass_stable_digest(normalized)
    if (
        predecessor_digest not in allowed_predecessor_digests
        and normalized_predecessor_digest
        != receipt.get("finalized_predecessor_digest")
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass predecessor finalized state differs"
        )
    if (
        successor_state == ("ACTIVE", "OUTPUT_COMMITTED")
        and predecessor_digest == receipt.get("quarantined_predecessor_digest")
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass committed successor did not retire predecessor"
        )
    expected_absent = {
        identity: {"artifact_binding": None, "legacy_artifact": None}
        for identity in receipt.get("artifact_roster") or ()
    }
    ledger = read_artifact_ledger(scratchpad)
    if _prepass_projection_snapshot(
        ledger, tuple(receipt.get("artifact_roster") or ())
    ) != expected_absent:
        raise ReconPrepassAuthorityError(
            "legacy recon prepass finalized projections reappeared"
        )
    return True


def _prepass_validate_closed_lineage(
    scratchpad: Path,
    units: Mapping[str, Any],
    config: Mapping[str, Any],
    *,
    run_id: str,
    head_key: str,
) -> None:
    prefix = _prepass_expected_prefix(config)
    head_parts = head_key.split("/")
    if tuple(head_parts[:5]) != prefix:
        raise ReconPrepassAuthorityError(
            "recon prepass owner dimensions differ from current config"
        )
    head_ordinal = _prepass_generation_ordinal(head_key)
    generation_keys = {
        "/".join((*prefix, "prepass" if ordinal == 1 else
                  f"prepass.attempt-{ordinal:04d}"))
        for ordinal in range(1, head_ordinal + 1)
    }
    disposition_keys = {
        _prepass_disposition_key(
            "/".join((*prefix, f"prepass.attempt-{ordinal:04d}")),
            ordinal,
        )
        for ordinal in range(2, head_ordinal + 1)
    }
    legacy_key = "/".join((*prefix, "prepass", "attempt-2"))
    observed_generations: set[str] = set()
    observed_dispositions: set[str] = set()
    observed_legacy: set[str] = set()
    for key, row in units.items():
        if not isinstance(key, str):
            continue
        parts = key.split("/")
        role = parts[-1] if parts else ""
        relevant = (
            (len(parts) == 6 and parts[-2] == "recon" and (
                role == "prepass"
                or role.startswith("prepass.attempt-")
                or role.startswith("prepass.disposition-")
            ))
            or (len(parts) == 7 and parts[-3:] == [
                "recon", "prepass", "attempt-2"
            ])
        )
        if not relevant:
            continue
        if tuple(parts[:5]) != prefix:
            if isinstance(row, Mapping) and row.get("run_id") in {None, run_id}:
                raise ReconPrepassAuthorityError(
                    "recon prepass ledger contains wrong-dimension authority"
                )
            continue
        if len(parts) == 7:
            observed_legacy.add(key)
        elif role.startswith("prepass.disposition-"):
            observed_dispositions.add(key)
        else:
            _prepass_generation_ordinal(key)
            observed_generations.add(key)
    if observed_generations != generation_keys:
        raise ReconPrepassAuthorityError(
            "recon prepass generation lineage has an orphan, gap, or future row"
        )
    base_key = "/".join((*prefix, "prepass"))
    migrated = False
    if observed_legacy:
        if observed_legacy != {legacy_key} or head_ordinal < 2:
            raise ReconPrepassAuthorityError(
                "recon prepass legacy evidence is outside its exact migration"
            )
        migrated = _prepass_validate_legacy_migration_receipt(
            scratchpad,
            units,
            run_id=run_id,
            predecessor_key=base_key,
            successor_key="/".join((*prefix, "prepass.attempt-0002")),
            lineage_head_key=head_key,
        )
    expected_dispositions = set(disposition_keys)
    if migrated:
        expected_dispositions.discard(_prepass_disposition_key(head_key, 2))
    extra_dispositions = observed_dispositions - expected_dispositions
    if extra_dispositions:
        pending_ordinal = head_ordinal + 1
        pending_key = _prepass_disposition_key(
            "/".join((*prefix, f"prepass.attempt-{pending_ordinal:04d}")),
            pending_ordinal,
        )
        pending_row = units.get(pending_key)
        pending = (
            pending_row.get("durable_disposition")
            if isinstance(pending_row, Mapping) else None
        )
        if (
            extra_dispositions != {pending_key}
            or not isinstance(pending, Mapping)
            or (
                pending_row.get("semantic_status"),
                pending_row.get("execution_state"),
            ) != ("DEBT", "FAILED")
            or pending.get("state") != "FAILED"
            or pending.get("predecessor_work_unit_key") != head_key
            or pending.get("generation_ordinal") != pending_ordinal
            or pending.get("producer_attempt_identity")
            != "/".join((
                *prefix, f"prepass.attempt-{pending_ordinal:04d}"
            ))
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass pending successor disposition is invalid"
            )
        expected_dispositions.add(pending_key)
    if observed_dispositions != expected_dispositions:
        raise ReconPrepassAuthorityError(
            "recon prepass disposition lineage denominator differs"
        )
    for ordinal in range(1, head_ordinal + 1):
        key = "/".join((*prefix, "prepass" if ordinal == 1 else
                        f"prepass.attempt-{ordinal:04d}"))
        row = units.get(key)
        if not isinstance(row, Mapping) or row.get("run_id") != run_id:
            raise ReconPrepassAuthorityError(
                "recon prepass lineage row is absent or cross-run"
            )
        if migrated and ordinal == 1:
            _prepass_legacy_authority(row.get("preexecution_authority"))
        else:
            authority = _validated_prepass_preexecution_authority(
                row.get("preexecution_authority")
            )
            if (
                authority.get("work_unit_key") != key
                or authority.get("run_id") != run_id
                or row.get("preexecution_authority_digest")
                != authority.get("authority_sha256")
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass lineage authority binding differs"
                )
            _prepass_authority_pair(authority)
        if ordinal == 1 or (migrated and ordinal == 2):
            continue
        predecessor_key = "/".join((
            *prefix,
            "prepass" if ordinal == 2 else
            f"prepass.attempt-{ordinal - 1:04d}",
        ))
        disposition_key = _prepass_disposition_key(key, ordinal)
        disposition_row = units.get(disposition_key)
        disposition = (
            disposition_row.get("durable_disposition")
            if isinstance(disposition_row, Mapping) else None
        )
        predecessor = units.get(predecessor_key)
        attempted = row.get("preexecution_authority")
        original = (
            predecessor.get("preexecution_authority")
            if isinstance(predecessor, Mapping) else None
        )
        state = disposition.get("state") if isinstance(disposition, Mapping) else None
        expected_row_state = (
            ("HISTORY", "OUTPUT_COMMITTED")
            if state == "COMMITTED" else ("DEBT", "FAILED")
        )
        if (
            not isinstance(disposition, Mapping)
            or not isinstance(disposition_row, Mapping)
            or not isinstance(attempted, Mapping)
            or not isinstance(original, Mapping)
            or disposition.get("schema")
            != "plamen.recon-mutation-disposition.v1"
            or disposition.get("producer_attempt_identity") != key
            or disposition.get("predecessor_work_unit_key") != predecessor_key
            or disposition.get("generation_ordinal") != ordinal
            or disposition.get("attempted_preexecution_authority") != attempted
            or disposition.get("attempted_preexecution_authority_digest")
            != attempted.get("authority_sha256")
            or disposition.get("original_preexecution_authority") != original
            or disposition.get("original_authority_digest")
            != original.get("authority_sha256")
            or state not in {"FAILED", "COMMITTED"}
            or (
                disposition_row.get("semantic_status"),
                disposition_row.get("execution_state"),
            ) != expected_row_state
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass successor disposition lineage is invalid"
            )


def _migrate_legacy_prepass_terminal(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    *,
    run_id: str,
    failure_injector: Callable[..., None] | None = None,
) -> tuple[Any, LaunchSpec, dict[str, Any], Mapping[str, Any]] | None:
    """Quarantine a legacy failed generation, then arm attempt-0002 fresh."""

    ledger = read_artifact_ledger(scratchpad)
    units = ledger.get("work_units")
    if not isinstance(units, dict):
        return None
    expected_predecessor_key = "/".join((
        *_prepass_expected_prefix(config), "prepass"
    ))
    base_rows = [
        (key, row) for key, row in units.items()
        if isinstance(key, str) and key == expected_predecessor_key
        and isinstance(row, dict)
        and (row.get("semantic_status"), row.get("execution_state"))
        == ("INVALID", "FAILED")
    ]
    if len(base_rows) != 1:
        return None
    predecessor_key, predecessor = base_rows[0]
    if predecessor.get("run_id") != run_id:
        raise ReconPrepassAuthorityError(
            "legacy recon prepass predecessor is cross-run"
        )
    legacy_key = f"{predecessor_key}/attempt-2"
    legacy = units.get(legacy_key)
    disposition = (
        legacy.get("durable_disposition")
        if isinstance(legacy, Mapping)
        else None
    )
    if (
        not isinstance(legacy, Mapping)
        or (legacy.get("semantic_status"), legacy.get("execution_state"))
        != ("DEBT", "FAILED")
        or not isinstance(disposition, Mapping)
        or disposition.get("reason_codes")
        != ["PREPASS_INPUT_AUTHORITY_CHANGED"]
    ):
        return None
    original = _prepass_legacy_authority(
        disposition.get("original_preexecution_authority")
    )
    attempted = _prepass_legacy_authority(
        disposition.get("attempted_preexecution_authority")
    )
    if (
        original.get("work_unit_key") != predecessor_key
        or attempted.get("work_unit_key") != predecessor_key
        or original.get("run_id") != run_id
        or attempted.get("run_id") != run_id
        or predecessor.get("preexecution_authority_digest")
        != original.get("authority_sha256")
        or disposition.get("original_authority_digest")
        != original.get("authority_sha256")
        or disposition.get("attempted_preexecution_authority_digest")
        != attempted.get("authority_sha256")
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass disposition lineage is invalid"
        )
    predecessor_contract, _predecessor_launch = _prepass_authority_pair(
        original
    )
    successor_contract, successor_launch = _prepass_successor_pair(
        predecessor_contract, ordinal=2
    )
    if successor_contract.key in units:
        raise ReconPrepassAuthorityError(
            "legacy recon prepass migration successor collision"
        )
    receipt_path = scratchpad / _PREPASS_LEGACY_MIGRATION_RECEIPT
    existing_receipt = _prepass_read_private_json(scratchpad, receipt_path)
    if existing_receipt is not None:
        stored_unsigned = dict(existing_receipt)
        stored_digest = stored_unsigned.pop("migration_digest", None)
        stored_successor_authority = stored_unsigned.get(
            "successor_preexecution_authority"
        )
        if (
            stored_unsigned.get("schema")
            != "plamen.recon-prepass-legacy-successor-migration.v3"
            or stored_digest != _prepass_stable_digest(stored_unsigned)
        ):
            raise ReconPrepassAuthorityError(
                "legacy recon prepass migration receipt collision"
            )
        successor_authority = _validated_prepass_preexecution_authority(
            stored_successor_authority
        )
        stored_contract, stored_launch = _prepass_authority_pair(
            successor_authority
        )
        if (
            successor_authority.get("work_unit_key") != successor_contract.key
            or successor_authority.get("run_id") != run_id
            or stored_contract != successor_contract
            or stored_launch != successor_launch
        ):
            raise ReconPrepassAuthorityError(
                "legacy recon prepass stored successor authority differs"
            )
    else:
        capture = _prepass_capture(scratchpad, project_root, config)
        successor_authority = _prepass_preexecution_authority(
            successor_contract, successor_launch, run_id=run_id,
            capture=capture,
        )
    artifacts = predecessor.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass artifact denominator is malformed"
        )
    roster = tuple(original.get("planned_output_roster") or ())
    if set(artifacts) != set(roster):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass artifact denominator differs"
        )
    legacy_digest = _prepass_stable_digest(dict(legacy))
    predecessor_digest = _prepass_stable_digest(dict(predecessor))
    provisional_digest = _prepass_stable_digest({
        "run_id": run_id,
        "predecessor_work_unit_key": predecessor_key,
        "legacy_evidence_digest": legacy_digest,
        "successor_work_unit_key": successor_contract.key,
        "successor_preexecution_authority_digest": successor_authority[
            "authority_sha256"
        ],
    })
    provisional_quarantine = (
        scratchpad / "_recon_prepass_legacy_quarantine" / provisional_digest
    )
    _prepass_ensure_private_directory(scratchpad, provisional_quarantine)
    if existing_receipt is not None:
        migration_unsigned = dict(existing_receipt)
        migration_digest = migration_unsigned.pop("migration_digest", None)
        receipt_records = migration_unsigned.get("artifact_records")
        receipt_projections = migration_unsigned.get("projection_records")
        if (
            set(migration_unsigned) != {
                "schema", "run_id", "predecessor_work_unit_key",
                "predecessor_evidence_digest", "legacy_evidence_key",
                "legacy_evidence_digest", "successor_work_unit_key",
                "successor_preexecution_authority",
                "successor_preexecution_authority_digest", "artifact_roster",
                "artifact_records", "projection_records",
                "quarantined_predecessor_digest",
                "finalized_predecessor_digest",
            }
            or migration_unsigned.get("schema")
            != "plamen.recon-prepass-legacy-successor-migration.v3"
            or migration_digest != _prepass_stable_digest(migration_unsigned)
            or migration_unsigned.get("run_id") != run_id
            or migration_unsigned.get("predecessor_work_unit_key")
            != predecessor_key
            or migration_unsigned.get("legacy_evidence_key") != legacy_key
            or migration_unsigned.get("legacy_evidence_digest")
            != legacy_digest
            or migration_unsigned.get("successor_work_unit_key")
            != successor_contract.key
            or migration_unsigned.get(
                "successor_preexecution_authority_digest"
            ) != successor_authority["authority_sha256"]
            or migration_unsigned.get("successor_preexecution_authority")
            != successor_authority
            or migration_unsigned.get("artifact_roster") != list(roster)
            or not isinstance(receipt_records, Mapping)
            or set(receipt_records) != set(roster)
            or not isinstance(receipt_projections, Mapping)
            or set(receipt_projections) != set(roster)
            or predecessor_digest not in {
                migration_unsigned.get("predecessor_evidence_digest"),
                migration_unsigned.get("quarantined_predecessor_digest"),
            }
        ):
            raise ReconPrepassAuthorityError(
                "legacy recon prepass migration receipt collision"
            )
        for identity in roster:
            record = receipt_records.get(identity)
            projection = receipt_projections.get(identity)
            if (
                not isinstance(record, Mapping)
                or set(record) != {
                    "committed_sha256", "committed_size", "observed_status",
                    "observed_sha256", "observed_size",
                }
                or record.get("committed_sha256")
                != artifacts[identity].get("sha256")
                or record.get("committed_size")
                != artifacts[identity].get("size")
                or record.get("observed_status") not in {
                    "PRESENT", "BOTH_ABSENT"
                }
                or not isinstance(record.get("observed_sha256"), str)
                or not isinstance(record.get("observed_size"), int)
                or record.get("observed_size", -1) < 0
                or not isinstance(projection, Mapping)
                or set(projection) != {
                    "artifact_binding", "legacy_artifact"
                }
            ):
                raise ReconPrepassAuthorityError(
                    "legacy recon prepass migration receipt records differ"
                )
        _prepass_assert_projection_owner(
            receipt_projections,
            roster,
            allowed_owner=predecessor_key,
        )
        receipt = dict(existing_receipt)
    else:
        observed_records: dict[str, dict[str, Any]] = {}
        for identity in roster:
            _root, relative = identity.split(":", 1)
            source = _prepass_auxiliary_path(scratchpad, relative)
            archived = _prepass_auxiliary_path(provisional_quarantine, relative)
            source_exists = _prepass_regular_file_present(
                source, label="legacy recon prepass public artifact"
            )
            archived_exists = _prepass_regular_file_present(
                archived, label="legacy recon prepass quarantined artifact"
            )
            if source_exists and archived_exists:
                raise ReconPrepassAuthorityError(
                    "legacy recon prepass migration duplicated an artifact"
                )
            selected = (
                source if source_exists else archived if archived_exists else None
            )
            raw = (
                _prepass_bounded_read_bytes(
                    selected,
                    label="legacy recon prepass migration artifact",
                    max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
                )
                if selected is not None else b""
            )
            observed_records[identity] = {
                "committed_sha256": artifacts[identity].get("sha256"),
                "committed_size": artifacts[identity].get("size"),
                "observed_status": (
                    "PRESENT" if (source_exists or archived_exists)
                    else "BOTH_ABSENT"
                ),
                "observed_sha256": (
                    hashlib.sha256(raw).hexdigest()
                    if selected is not None else ""
                ),
                "observed_size": len(raw),
            }
        migration_unsigned = {
            "schema": "plamen.recon-prepass-legacy-successor-migration.v3",
            "run_id": run_id,
            "predecessor_work_unit_key": predecessor_key,
            "predecessor_evidence_digest": predecessor_digest,
            "legacy_evidence_key": legacy_key,
            "legacy_evidence_digest": legacy_digest,
            "successor_work_unit_key": successor_contract.key,
            "successor_preexecution_authority": successor_authority,
            "successor_preexecution_authority_digest": successor_authority[
                "authority_sha256"
            ],
            "artifact_roster": list(roster),
            "artifact_records": observed_records,
            "projection_records": _prepass_projection_snapshot(ledger, roster),
        }
        _prepass_assert_projection_owner(
            migration_unsigned["projection_records"],
            roster,
            allowed_owner=predecessor_key,
        )
        finalized_predecessor = json.loads(json.dumps(predecessor))
        for finalized_row in finalized_predecessor["artifacts"].values():
            if isinstance(finalized_row, dict):
                finalized_row["status"] = "QUARANTINED"
                finalized_row["authority_level"] = (
                    "HISTORICAL_PREDECESSOR_ONLY"
                )
        migration_unsigned["quarantined_predecessor_digest"] = (
            _prepass_stable_digest(finalized_predecessor)
        )
        finalized_predecessor["superseded_by_work_unit_key"] = (
            successor_contract.key
        )
        finalized_predecessor["superseded_by_generation_ordinal"] = 2
        migration_unsigned["finalized_predecessor_digest"] = (
            _prepass_stable_digest(finalized_predecessor)
        )
        migration_digest = _prepass_stable_digest(migration_unsigned)
        receipt = {**migration_unsigned, "migration_digest": migration_digest}
        _prepass_write_json_atomic(scratchpad, receipt_path, receipt)
    if failure_injector is not None:
        failure_injector("legacy_after_intent")
    quarantine = _prepass_ensure_private_directory(
        scratchpad, provisional_quarantine
    )
    for identity, expected in migration_unsigned["artifact_records"].items():
        root, relative = identity.split(":", 1)
        if root != "scratchpad":
            raise ReconPrepassAuthorityError(
                "legacy recon prepass output escaped scratchpad"
            )
        source = _prepass_auxiliary_path(scratchpad, relative)
        archived = _prepass_auxiliary_path(quarantine, relative)
        source_exists = _prepass_regular_file_present(
            source, label="legacy recon prepass public artifact"
        )
        archived_exists = _prepass_regular_file_present(
            archived, label="legacy recon prepass quarantined artifact"
        )
        source_exists, archived_exists = _prepass_recover_durable_move(
            source,
            archived,
            source_exists=source_exists,
            archive_exists=archived_exists,
            expected_sha256=str(expected.get("observed_sha256") or ""),
            expected_size=int(expected.get("observed_size", -1)),
            label="legacy recon prepass migration",
        )
        selected = source if source_exists else archived if archived_exists else None
        expected_status = expected.get("observed_status")
        if expected_status == "BOTH_ABSENT":
            if selected is not None:
                raise ReconPrepassAuthorityError(
                    "legacy recon prepass absent migration artifact appeared"
                )
            continue
        if expected_status != "PRESENT" or selected is None:
            raise ReconPrepassAuthorityError(
                "legacy recon prepass migration artifact disappeared"
            )
        raw = _prepass_bounded_read_bytes(
            selected,
            label="legacy recon prepass migration artifact",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if (
            hashlib.sha256(raw).hexdigest() != expected["observed_sha256"]
            or len(raw) != expected["observed_size"]
        ):
            raise ReconPrepassAuthorityError(
                "legacy recon prepass migration artifact differs"
            )
        if source_exists:
            _prepass_move_private(
                scratchpad,
                source,
                archived,
                expected_sha256=expected["observed_sha256"],
                expected_size=expected["observed_size"],
            )
    if failure_injector is not None:
        failure_injector("legacy_after_quarantine")
    ledger = read_artifact_ledger(scratchpad)
    ledger_prestate = json.loads(json.dumps(ledger))
    predecessor = ledger["work_units"].get(predecessor_key)
    legacy = ledger["work_units"].get(legacy_key)
    if not isinstance(predecessor, dict) or not isinstance(legacy, dict):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass migration CAS changed"
        )
    current_predecessor_digest = _prepass_stable_digest(predecessor)
    if (
        _prepass_stable_digest(legacy) != legacy_digest
        or current_predecessor_digest not in {
            migration_unsigned["predecessor_evidence_digest"],
            migration_unsigned["quarantined_predecessor_digest"],
        }
    ):
        raise ReconPrepassAuthorityError(
            "legacy recon prepass migration CAS changed"
        )
    bindings = ledger.get("artifact_bindings")
    legacy_projection = ledger.get("artifacts")
    expected_absent = {
        identity: {"artifact_binding": None, "legacy_artifact": None}
        for identity in roster
    }
    if current_predecessor_digest == migration_unsigned[
        "predecessor_evidence_digest"
    ]:
        _prepass_assert_projection_snapshot(
            ledger, roster, migration_unsigned["projection_records"]
        )
        for identity in roster:
            rows = (
                bindings.get(identity) if isinstance(bindings, dict) else None,
                legacy_projection.get(identity.split(":", 1)[1])
                if isinstance(legacy_projection, dict)
                else None,
            )
            for row in rows:
                if (
                    isinstance(row, dict)
                    and row.get("owner_key") == predecessor_key
                ):
                    row["status"] = "QUARANTINED"
                    row["authority_level"] = "HISTORICAL_PREDECESSOR_ONLY"
            if isinstance(bindings, dict):
                bindings.pop(identity, None)
            if isinstance(legacy_projection, dict):
                legacy_projection.pop(identity.split(":", 1)[1], None)
        for row in predecessor["artifacts"].values():
            if isinstance(row, dict):
                row["status"] = "QUARANTINED"
                row["authority_level"] = "HISTORICAL_PREDECESSOR_ONLY"
        if _prepass_stable_digest(predecessor) != migration_unsigned[
            "quarantined_predecessor_digest"
        ]:
            raise ReconPrepassAuthorityError(
                "legacy recon prepass quarantined state differs"
            )
        _prepass_assert_projection_snapshot(ledger, roster, expected_absent)
        _prepass_commit_ledger_cas(scratchpad, ledger_prestate, ledger)
        if failure_injector is not None:
            failure_injector("legacy_after_ledger")
    else:
        _prepass_assert_projection_snapshot(ledger, roster, expected_absent)
    try:
        armed = record_work_unit_inputs(
            scratchpad,
            project_root,
            successor_contract,
            successor_launch,
            run_id=run_id,
            preexecution_authority=successor_authority,
        )
    except ArtifactLedgerError as exc:
        raise ReconPrepassAuthorityError(
            f"legacy recon prepass successor input arm failed: {exc}"
        ) from exc
    return successor_contract, successor_launch, successor_authority, armed


def _record_prepass_drift_debt(
    scratchpad: Path,
    contract_or_key: Any,
    capture: Mapping[str, Any],
    *,
    original_authority: Mapping[str, Any] | None = None,
    attempted_authority: Mapping[str, Any] | None = None,
) -> str:
    ledger = read_artifact_ledger(scratchpad)
    ledger_prestate = json.loads(json.dumps(ledger))
    contract_key = (
        contract_or_key
        if isinstance(contract_or_key, str)
        else contract_or_key.key
    )
    old = ledger.get("work_units", {}).get(contract_key)
    if not isinstance(old, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass drift has no committed predecessor"
        )
    predecessor_ordinal = _prepass_generation_ordinal(contract_key)
    attempt_ordinal = predecessor_ordinal + 1
    if attempted_authority is None:
        raise ReconPrepassAuthorityError(
            "recon prepass successor authority is absent"
        )
    validated_attempted = _validated_prepass_preexecution_authority(
        dict(attempted_authority)
    )
    attempt_identity = str(validated_attempted["work_unit_key"])
    if _prepass_generation_ordinal(attempt_identity) != attempt_ordinal:
        raise ReconPrepassAuthorityError(
            "recon prepass successor authority is not the immediate attempt"
        )
    if attempt_identity.split("/")[:5] != contract_key.split("/")[:5]:
        raise ReconPrepassAuthorityError(
            "recon prepass successor changed a fixed dimension"
        )
    disposition_key = _prepass_disposition_key(
        attempt_identity, attempt_ordinal
    )
    binding = {
        "producer_attempt_identity": attempt_identity,
        "predecessor_work_unit_key": contract_key,
        "generation_ordinal": attempt_ordinal,
        "attempt_ordinal": attempt_ordinal,
        "input_set_digest": capture["input_set_digest"],
        "config_digest": capture["config_digest"],
        "source_capture_digest": capture["source_capture_digest"],
    }
    binding["attempted_authority_digest"] = _prepass_stable_digest(binding)
    disposition = {
        **binding,
        "schema": "plamen.recon-mutation-disposition.v1",
        "state": "FAILED",
        "reason_codes": ["PREPASS_INPUT_AUTHORITY_CHANGED"],
    }
    if original_authority is not None:
        validated_original = _validated_prepass_preexecution_authority(
            dict(original_authority)
        )
        disposition["original_authority_digest"] = validated_original[
            "authority_sha256"
        ]
        disposition["original_preexecution_authority"] = validated_original
    disposition["attempted_preexecution_authority_digest"] = (
        validated_attempted["authority_sha256"]
    )
    disposition["attempted_preexecution_authority"] = validated_attempted
    history_row = {
        **binding,
        "work_unit_key": disposition_key,
        "run_id": old.get("run_id"),
        "semantic_status": "DEBT",
        "execution_state": "FAILED",
        "durable_disposition": disposition,
    }
    existing = ledger["work_units"].get(disposition_key)
    if existing is not None and existing != history_row:
        raise ReconPrepassAuthorityError(
            "recon prepass successor disposition key collision"
        )
    executable_collision = ledger["work_units"].get(attempt_identity)
    if executable_collision is not None:
        stored = (
            executable_collision.get("preexecution_authority")
            if isinstance(executable_collision, Mapping)
            else None
        )
        if stored != validated_attempted:
            raise ReconPrepassAuthorityError(
                "recon prepass successor work-unit key collision"
            )
    ledger["work_units"][disposition_key] = history_row
    _prepass_commit_ledger_cas(scratchpad, ledger_prestate, ledger)
    return disposition_key


def _finalize_prepass_successor(
    scratchpad: Path,
    *,
    predecessor_key: str,
    successor_key: str,
) -> None:
    """Retire only the predecessor after its exact successor committed."""

    ledger = read_artifact_ledger(scratchpad)
    ledger_prestate = json.loads(json.dumps(ledger))
    units = ledger.get("work_units")
    bindings = ledger.get("artifact_bindings")
    if not isinstance(units, dict) or not isinstance(bindings, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass successor finalization ledger is malformed"
        )
    predecessor = units.get(predecessor_key)
    successor = units.get(successor_key)
    if not isinstance(predecessor, dict) or not isinstance(successor, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass successor finalization lineage is absent"
        )
    if (
        _prepass_generation_ordinal(successor_key)
        != _prepass_generation_ordinal(predecessor_key) + 1
        or successor.get("semantic_status") != "ACTIVE"
        or successor.get("execution_state") != "OUTPUT_COMMITTED"
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass successor finalization authority is incomplete"
        )
    successor_artifacts = successor.get("artifacts")
    predecessor_artifacts = predecessor.get("artifacts")
    successor_authority = successor.get("preexecution_authority")
    planned_roster = (
        set(successor_authority.get("planned_output_roster") or ())
        if isinstance(successor_authority, Mapping)
        else set()
    )
    if (
        not isinstance(successor_artifacts, Mapping)
        or set(successor_artifacts) != planned_roster
        or len(planned_roster) not in {
            len(_SC_PREPASS_PUBLIC_OUTPUTS) + 1,
            len(_L1_PREPASS_PUBLIC_OUTPUTS) + 1,
        }
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass successor artifact denominator is malformed"
        )
    for identity, record in successor_artifacts.items():
        binding = bindings.get(identity)
        if (
            not isinstance(record, Mapping)
            or not isinstance(binding, Mapping)
            or binding.get("owner_key") != successor_key
            or binding.get("status") != "ACTIVE"
            or binding.get("sha256") != record.get("sha256")
            or binding.get("size") != record.get("size")
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass successor binding did not commit atomically"
            )
    successor_ordinal = _prepass_generation_ordinal(successor_key)
    for ancestor_key, ancestor in units.items():
        if not isinstance(ancestor_key, str) or not isinstance(ancestor, dict):
            continue
        parts = ancestor_key.split("/")
        if len(parts) != 6 or parts[:5] != successor_key.split("/")[:5]:
            continue
        try:
            ancestor_ordinal = _prepass_generation_ordinal(ancestor_key)
        except ReconPrepassAuthorityError:
            continue
        if ancestor_ordinal >= successor_ordinal:
            continue
        ancestor_artifacts = ancestor.get("artifacts")
        if isinstance(ancestor_artifacts, dict):
            for record in ancestor_artifacts.values():
                if isinstance(record, dict):
                    record["status"] = "QUARANTINED"
                    record["authority_level"] = (
                        "HISTORICAL_PREDECESSOR_ONLY"
                    )
        ancestor["semantic_status"] = "INVALID"
        ancestor["execution_state"] = "FAILED"
        ancestor["superseded_by_work_unit_key"] = successor_key
        ancestor["superseded_by_generation_ordinal"] = successor_ordinal
    disposition_key = _prepass_disposition_key(
        successor_key, _prepass_generation_ordinal(successor_key)
    )
    disposition_row = units.get(disposition_key)
    if isinstance(disposition_row, dict):
        disposition = disposition_row.get("durable_disposition")
        if isinstance(disposition, dict):
            disposition["state"] = "COMMITTED"
            disposition["successor_work_unit_key"] = successor_key
            disposition["successor_commit_receipt_digest"] = str(
                (successor.get("commit_authority") or {}).get(
                    "receipt_digest"
                )
            )
        disposition_row["semantic_status"] = "HISTORY"
        disposition_row["execution_state"] = "OUTPUT_COMMITTED"
    _prepass_commit_ledger_cas(scratchpad, ledger_prestate, ledger)


def _arm_prepass_successor(
    scratchpad: Path,
    project_root: Path,
    predecessor_contract: Any,
    *,
    run_id: str,
    capture: Mapping[str, Any],
    original_authority: Mapping[str, Any],
    failure_injector: Callable[..., None] | None = None,
) -> tuple[Any, LaunchSpec, dict[str, Any], Mapping[str, Any]]:
    successor_contract, successor_launch = _prepass_successor_pair(
        predecessor_contract,
        ordinal=_prepass_generation_ordinal(predecessor_contract.key) + 1,
    )
    ordinal = _prepass_generation_ordinal(successor_contract.key)
    disposition_key = _prepass_disposition_key(successor_contract.key, ordinal)
    existing_disposition_row = read_artifact_ledger(scratchpad).get(
        "work_units", {}
    ).get(disposition_key)
    if isinstance(existing_disposition_row, Mapping):
        disposition = existing_disposition_row.get("durable_disposition")
        attempted = (
            disposition.get("attempted_preexecution_authority")
            if isinstance(disposition, Mapping) else None
        )
        successor_authority = _validated_prepass_preexecution_authority(
            attempted
        )
        replay_contract, replay_launch = _prepass_authority_pair(
            successor_authority
        )
        if (
            replay_contract.key != successor_contract.key
            or replay_launch != successor_launch
            or disposition.get("predecessor_work_unit_key")
            != predecessor_contract.key
            or disposition.get("generation_ordinal") != ordinal
            or disposition.get("original_preexecution_authority")
            != original_authority
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass pending disposition replay differs"
            )
        capture = successor_authority["authority_capture"]
    else:
        successor_authority = _prepass_preexecution_authority(
            successor_contract,
            successor_launch,
            run_id=run_id,
            capture=capture,
        )
        _validated_prepass_preexecution_authority(successor_authority)
        _record_prepass_drift_debt(
            scratchpad,
            predecessor_contract.key,
            capture,
            original_authority=original_authority,
            attempted_authority=successor_authority,
        )
        if failure_injector is not None:
            failure_injector("after_disposition")
    current_ledger = read_artifact_ledger(scratchpad)
    current_units = current_ledger.get("work_units", {})
    predecessor_row = current_units.get(predecessor_contract.key)
    legacy_migrated = False
    if (
        _prepass_generation_ordinal(predecessor_contract.key) == 2
        and isinstance(current_units, Mapping)
    ):
        base_key = "/".join((
            *predecessor_contract.key.split("/")[:5], "prepass"
        ))
        if f"{base_key}/attempt-2" in current_units:
            legacy_migrated = _prepass_validate_legacy_migration_receipt(
                scratchpad,
                current_units,
                run_id=run_id,
                predecessor_key=base_key,
                successor_key=predecessor_contract.key,
                lineage_head_key=predecessor_contract.key,
            )
    uncommitted_quarantined = False
    if (
        isinstance(predecessor_row, Mapping)
        and predecessor_row.get("artifacts") == {}
    ):
        uncommitted_quarantined = _quarantine_prepass_uncommitted_publication(
            scratchpad,
            predecessor_key=predecessor_contract.key,
            successor_key=successor_contract.key,
            original_authority=original_authority,
            successor_authority=successor_authority,
            roster=tuple(item.identity for item in successor_contract.outputs),
        )
    if (
        not uncommitted_quarantined
        and not legacy_migrated
        and
        isinstance(predecessor_row, Mapping)
        and predecessor_row.get("artifacts") == {}
        and _prepass_generation_ordinal(predecessor_contract.key) > 1
    ):
        _quarantine_prepass_committed_ancestors(
            scratchpad,
            predecessor_key=predecessor_contract.key,
            successor_key=successor_contract.key,
            roster=tuple(
                item.identity for item in successor_contract.outputs
            ),
        )
    try:
        armed = record_work_unit_inputs(
            scratchpad,
            project_root,
            successor_contract,
            successor_launch,
            run_id=run_id,
            preexecution_authority=successor_authority,
        )
    except ArtifactLedgerError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass successor input arm failed: {exc}"
        ) from exc
    return successor_contract, successor_launch, successor_authority, armed


def _quarantine_prepass_uncommitted_publication(
    scratchpad: Path,
    *,
    predecessor_key: str,
    successor_key: str,
    original_authority: Mapping[str, Any],
    successor_authority: Mapping[str, Any],
    roster: tuple[str, ...],
) -> bool:
    """Remove crash-published predecessor bytes before arming a successor.

    A predecessor can crash after one or all public replaces but before its
    generic artifact commit.  Those bytes have no committed owner and cannot
    be used as the REPLACE prestate of a fresh authority.  Preserve their
    exact observed bytes under an intent-bound private quarantine, then arm
    the successor only after every public destination is absent.
    """

    identity_unsigned = {
        "schema": "plamen.recon-prepass-uncommitted-quarantine-identity.v1",
        "predecessor_work_unit_key": predecessor_key,
        "successor_work_unit_key": successor_key,
        "original_preexecution_authority_digest": original_authority.get(
            "authority_sha256"
        ),
        "successor_preexecution_authority_digest": successor_authority.get(
            "authority_sha256"
        ),
        "artifact_roster": list(roster),
    }
    intent_id = _prepass_stable_digest(identity_unsigned)
    intent_path = scratchpad / f"_recon_prepass_uncommitted_{intent_id}.json"
    quarantine = (
        scratchpad / "_recon_prepass_uncommitted_quarantine" / intent_id
    )
    intent = _prepass_read_private_json(scratchpad, intent_path)
    if intent is not None:
        unsigned = dict(intent) if isinstance(intent, dict) else {}
        intent_digest = unsigned.pop("intent_digest", None)
        if (
            set(unsigned) != {
                *identity_unsigned,
                "artifact_records",
                "transaction_authority",
            }
            or any(unsigned.get(key) != value for key, value in identity_unsigned.items())
            or intent_digest != _prepass_stable_digest(unsigned)
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted quarantine intent collision"
            )
    else:
        initial_ledger = read_artifact_ledger(scratchpad)
        initial_units = initial_ledger.get("work_units")
        predecessor_row = (
            initial_units.get(predecessor_key)
            if isinstance(initial_units, Mapping) else None
        )
        if not isinstance(predecessor_row, Mapping):
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted predecessor is absent"
            )
        predecessor_ordinal = _prepass_generation_ordinal(predecessor_key)
        committed = [
            (key, row)
            for key, row in initial_units.items()
            if isinstance(key, str)
            and isinstance(row, Mapping)
            and len(key.split("/")) == 6
            and key.split("/")[:5] == predecessor_key.split("/")[:5]
            and (
                key.split("/")[-1] == "prepass"
                or _PREPASS_ATTEMPT_ID_RE.fullmatch(key.split("/")[-1])
                is not None
            )
            and _prepass_generation_ordinal(key) < predecessor_ordinal
            and (row.get("semantic_status"), row.get("execution_state"))
            == ("ACTIVE", "OUTPUT_COMMITTED")
        ]
        if len(committed) > 1:
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted transaction has multiple ancestors"
            )
        ancestor_key = committed[0][0] if committed else ""
        ancestor_row = committed[0][1] if committed else None
        finalized_ancestor_digest = ""
        if isinstance(ancestor_row, Mapping):
            finalized = json.loads(json.dumps(ancestor_row))
            finalized["semantic_status"] = "INVALID"
            finalized["execution_state"] = "FAILED"
            finalized["superseded_by_work_unit_key"] = successor_key
            for record in (finalized.get("artifacts") or {}).values():
                if isinstance(record, dict):
                    record["status"] = "QUARANTINED"
                    record["authority_level"] = (
                        "HISTORICAL_PREDECESSOR_ONLY"
                    )
            finalized_ancestor_digest = _prepass_stable_digest(finalized)
        transaction_authority = {
            "predecessor_evidence_digest": _prepass_stable_digest(
                dict(predecessor_row)
            ),
            "committed_ancestor_work_unit_key": ancestor_key,
            "committed_ancestor_evidence_digest": (
                _prepass_stable_digest(dict(ancestor_row))
                if isinstance(ancestor_row, Mapping) else ""
            ),
            "finalized_ancestor_digest": finalized_ancestor_digest,
            "projection_records": _prepass_projection_snapshot(
                initial_ledger, roster
            ),
        }
        projection_owner = ancestor_key or predecessor_key
        _prepass_assert_projection_owner(
            transaction_authority["projection_records"],
            roster,
            allowed_owner=projection_owner,
        )
        observed: dict[str, dict[str, Any]] = {}
        any_present = False
        for identity in roster:
            root, relative = identity.split(":", 1)
            if root != "scratchpad":
                raise ReconPrepassAuthorityError(
                    "recon prepass uncommitted output escaped scratchpad"
                )
            source = _prepass_auxiliary_path(scratchpad, relative)
            source_present = _prepass_regular_file_present(
                source, label="recon prepass uncommitted output"
            )
            if source_present:
                raw = _prepass_bounded_read_bytes(
                    source,
                    label="recon prepass uncommitted output",
                    max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
                )
                any_present = True
                observed[identity] = {
                    "observed_status": "PRESENT",
                    "observed_sha256": hashlib.sha256(raw).hexdigest(),
                    "observed_size": len(raw),
                }
            else:
                observed[identity] = {
                    "observed_status": "BOTH_ABSENT",
                    "observed_sha256": "",
                    "observed_size": 0,
                }
        if not any_present:
            return False
        unsigned = {
            **identity_unsigned,
            "artifact_records": observed,
            "transaction_authority": transaction_authority,
        }
        intent = {
            **unsigned,
            "intent_digest": _prepass_stable_digest(unsigned),
        }
        _prepass_write_json_atomic(scratchpad, intent_path, intent)

    records = intent.get("artifact_records")
    if not isinstance(records, dict) or set(records) != set(roster):
        raise ReconPrepassAuthorityError(
            "recon prepass uncommitted quarantine denominator differs"
        )
    replay_transaction = intent.get("transaction_authority")
    if not isinstance(replay_transaction, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass uncommitted transaction authority is malformed"
        )
    replay_owner = str(
        replay_transaction.get("committed_ancestor_work_unit_key")
        or predecessor_key
    )
    _prepass_assert_projection_owner(
        replay_transaction.get("projection_records"),
        roster,
        allowed_owner=replay_owner,
    )
    quarantine = _prepass_ensure_private_directory(scratchpad, quarantine)
    for identity, expected in records.items():
        _root, relative = identity.split(":", 1)
        source = _prepass_auxiliary_path(scratchpad, relative)
        archived = _prepass_auxiliary_path(quarantine, relative)
        source_exists = _prepass_regular_file_present(
            source, label="recon prepass uncommitted public artifact"
        )
        archive_exists = _prepass_regular_file_present(
            archived, label="recon prepass uncommitted quarantined artifact"
        )
        source_exists, archive_exists = _prepass_recover_durable_move(
            source,
            archived,
            source_exists=source_exists,
            archive_exists=archive_exists,
            expected_sha256=str(expected.get("observed_sha256") or ""),
            expected_size=int(expected.get("observed_size", -1)),
            label="recon prepass uncommitted quarantine",
        )
        selected = source if source_exists else archived if archive_exists else None
        if expected.get("observed_status") == "BOTH_ABSENT":
            if selected is not None:
                raise ReconPrepassAuthorityError(
                    "recon prepass absent uncommitted output appeared"
                )
            continue
        if expected.get("observed_status") != "PRESENT" or selected is None:
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted output disappeared"
            )
        raw = _prepass_bounded_read_bytes(
            selected,
            label="recon prepass uncommitted quarantine artifact",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if (
            hashlib.sha256(raw).hexdigest() != expected.get("observed_sha256")
            or len(raw) != expected.get("observed_size")
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted output bytes changed"
            )
        if source_exists:
            _prepass_move_private(
                scratchpad,
                source,
                archived,
                expected_sha256=expected["observed_sha256"],
                expected_size=expected["observed_size"],
            )
    ledger = read_artifact_ledger(scratchpad)
    ledger_prestate = json.loads(json.dumps(ledger))
    units = ledger.get("work_units")
    if not isinstance(units, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass uncommitted quarantine ledger is malformed"
        )
    transaction = intent.get("transaction_authority")
    predecessor_row = units.get(predecessor_key)
    if (
        not isinstance(transaction, Mapping)
        or not isinstance(predecessor_row, Mapping)
        or _prepass_stable_digest(dict(predecessor_row))
        != transaction.get("predecessor_evidence_digest")
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass uncommitted predecessor CAS changed"
        )
    ancestor_key = str(transaction.get("committed_ancestor_work_unit_key") or "")
    if not ancestor_key:
        _prepass_assert_projection_snapshot(
            ledger, roster, transaction.get("projection_records")
        )
    if ancestor_key:
        ancestor = units.get(ancestor_key)
        if not isinstance(ancestor, dict):
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted ancestor disappeared"
            )
        ancestor_digest = _prepass_stable_digest(ancestor)
        evidence_digest = transaction.get("committed_ancestor_evidence_digest")
        finalized_digest = transaction.get("finalized_ancestor_digest")
        if ancestor_digest == finalized_digest:
            bindings = ledger.get("artifact_bindings")
            legacy = ledger.get("artifacts")
            if any(
                (
                    isinstance(bindings, Mapping) and identity in bindings
                ) or (
                    isinstance(legacy, Mapping)
                    and identity.split(":", 1)[1] in legacy
                )
                for identity in roster
            ):
                raise ReconPrepassAuthorityError(
                    "recon prepass finalized uncommitted projections reappeared"
                )
            return True
        if ancestor_digest != evidence_digest:
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted ancestor CAS changed"
            )
        _prepass_assert_projection_snapshot(
            ledger, roster, transaction.get("projection_records")
        )
        artifacts = ancestor.get("artifacts")
        if not isinstance(artifacts, dict) or set(artifacts) != set(roster):
            raise ReconPrepassAuthorityError(
                "recon prepass uncommitted ancestor denominator differs"
            )
        ancestor["semantic_status"] = "INVALID"
        ancestor["execution_state"] = "FAILED"
        ancestor["superseded_by_work_unit_key"] = successor_key
        bindings = ledger.get("artifact_bindings")
        legacy = ledger.get("artifacts")
        for identity in roster:
            for row in (
                bindings.get(identity) if isinstance(bindings, dict) else None,
                legacy.get(identity.split(":", 1)[1])
                if isinstance(legacy, dict) else None,
                artifacts.get(identity),
            ):
                if isinstance(row, dict) and row.get("owner_key") == ancestor_key:
                    row["status"] = "QUARANTINED"
                    row["authority_level"] = "HISTORICAL_PREDECESSOR_ONLY"
            if isinstance(bindings, dict):
                bindings.pop(identity, None)
            if isinstance(legacy, dict):
                legacy.pop(identity.split(":", 1)[1], None)
        _prepass_commit_ledger_cas(scratchpad, ledger_prestate, ledger)
    return True


def _quarantine_prepass_committed_ancestors(
    scratchpad: Path,
    *,
    predecessor_key: str,
    successor_key: str,
    roster: tuple[str, ...],
) -> None:
    """Retire exact committed ancestors when an unexecuted arm itself drifts."""

    intent_identity = {
        "schema": "plamen.recon-prepass-drifted-arm-quarantine.v2",
        "predecessor_work_unit_key": predecessor_key,
        "successor_work_unit_key": successor_key,
        "artifact_roster": list(roster),
    }
    intent_id = _prepass_stable_digest(intent_identity)
    intent_path = scratchpad / f"_recon_prepass_drifted_arm_{intent_id}.json"
    intent = _prepass_read_private_json(scratchpad, intent_path)
    if intent is not None:
        unsigned = dict(intent)
        intent_digest = unsigned.pop("intent_digest", None)
        if (
            any(unsigned.get(key) != value for key, value in intent_identity.items())
            or intent_digest != _prepass_stable_digest(unsigned)
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass drifted-arm intent collision"
            )
    else:
        ledger = read_artifact_ledger(scratchpad)
        units = ledger.get("work_units")
        predecessor = units.get(predecessor_key) if isinstance(units, Mapping) else None
        if not isinstance(units, Mapping) or not isinstance(predecessor, Mapping):
            raise ReconPrepassAuthorityError(
                "recon prepass ancestor ledger is malformed"
            )
        predecessor_ordinal = _prepass_generation_ordinal(predecessor_key)
        committed = []
        for key, row in units.items():
            if not isinstance(key, str) or not isinstance(row, Mapping):
                continue
            parts = key.split("/")
            if len(parts) != 6 or parts[:5] != predecessor_key.split("/")[:5]:
                continue
            try:
                ordinal = _prepass_generation_ordinal(key)
            except ReconPrepassAuthorityError:
                continue
            if (
                ordinal < predecessor_ordinal
                and (row.get("semantic_status"), row.get("execution_state"))
                == ("ACTIVE", "OUTPUT_COMMITTED")
            ):
                committed.append((key, row))
        if len(committed) != 1:
            raise ReconPrepassAuthorityError(
                "recon prepass drifted arm lacks one committed ancestor"
            )
        ancestor_key, ancestor = committed[0]
        records = ancestor.get("artifacts")
        if not isinstance(records, Mapping) or set(records) != set(roster):
            raise ReconPrepassAuthorityError(
                "recon prepass committed ancestor denominator differs"
            )
        finalized = json.loads(json.dumps(ancestor))
        finalized["semantic_status"] = "INVALID"
        finalized["execution_state"] = "FAILED"
        finalized["superseded_by_work_unit_key"] = successor_key
        for record in finalized["artifacts"].values():
            if isinstance(record, dict):
                record["status"] = "QUARANTINED"
                record["authority_level"] = "HISTORICAL_PREDECESSOR_ONLY"
        intent_unsigned = {
            **intent_identity,
            "predecessor_evidence_digest": _prepass_stable_digest(
                dict(predecessor)
            ),
            "committed_ancestor_work_unit_key": ancestor_key,
            "committed_ancestor_evidence_digest": _prepass_stable_digest(
                dict(ancestor)
            ),
            "finalized_ancestor_digest": _prepass_stable_digest(finalized),
            "projection_records": _prepass_projection_snapshot(
                ledger, roster
            ),
            "artifact_records": {
                identity: {
                    "sha256": records[identity].get("sha256"),
                    "size": records[identity].get("size"),
                }
                for identity in roster
            },
        }
        _prepass_assert_projection_owner(
            intent_unsigned["projection_records"],
            roster,
            allowed_owner=ancestor_key,
        )
        intent = {
            **intent_unsigned,
            "intent_digest": _prepass_stable_digest(intent_unsigned),
        }
        _prepass_write_json_atomic(scratchpad, intent_path, intent)
    quarantine = scratchpad / "_recon_prepass_drifted_arm_quarantine" / intent_id
    quarantine = _prepass_ensure_private_directory(scratchpad, quarantine)
    artifact_records = intent.get("artifact_records")
    if not isinstance(artifact_records, Mapping) or set(artifact_records) != set(roster):
        raise ReconPrepassAuthorityError(
            "recon prepass drifted-arm intent denominator differs"
        )
    _prepass_assert_projection_owner(
        intent.get("projection_records"),
        roster,
        allowed_owner=str(intent.get("committed_ancestor_work_unit_key") or ""),
    )
    for identity, expected in artifact_records.items():
        relative = identity.split(":", 1)[1]
        source = _prepass_auxiliary_path(scratchpad, relative)
        archived = _prepass_auxiliary_path(quarantine, relative)
        source_exists = _prepass_regular_file_present(
            source, label="recon prepass drifted-arm public artifact"
        )
        archive_exists = _prepass_regular_file_present(
            archived, label="recon prepass drifted-arm quarantined artifact"
        )
        source_exists, archive_exists = _prepass_recover_durable_move(
            source,
            archived,
            source_exists=source_exists,
            archive_exists=archive_exists,
            expected_sha256=str(expected.get("sha256") or ""),
            expected_size=int(expected.get("size", -1)),
            label="recon prepass drifted-arm quarantine",
        )
        selected = source if source_exists else archived if archive_exists else None
        if selected is None:
            raise ReconPrepassAuthorityError(
                "recon prepass drifted-arm ancestor byte is absent"
            )
        raw = _prepass_bounded_read_bytes(
            selected,
            label="recon prepass drifted-arm artifact",
            max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
        )
        if (
            hashlib.sha256(raw).hexdigest() != expected["sha256"]
            or len(raw) != expected["size"]
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass drifted-arm ancestor byte differs"
            )
        if source_exists:
            _prepass_move_private(
                scratchpad,
                source,
                archived,
                expected_sha256=expected["sha256"],
                expected_size=expected["size"],
            )
    ledger = read_artifact_ledger(scratchpad)
    ledger_prestate = json.loads(json.dumps(ledger))
    units = ledger.get("work_units")
    predecessor = units.get(predecessor_key) if isinstance(units, dict) else None
    ancestor_key = str(intent.get("committed_ancestor_work_unit_key") or "")
    ancestor = units.get(ancestor_key) if isinstance(units, dict) else None
    if (
        not isinstance(predecessor, Mapping)
        or _prepass_stable_digest(dict(predecessor))
        != intent.get("predecessor_evidence_digest")
        or not isinstance(ancestor, dict)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass drifted-arm predecessor/ancestor CAS changed"
        )
    ancestor_digest = _prepass_stable_digest(ancestor)
    bindings = ledger.get("artifact_bindings")
    legacy = ledger.get("artifacts")
    if ancestor_digest == intent.get("finalized_ancestor_digest"):
        if any(
            (
                isinstance(bindings, Mapping) and identity in bindings
            ) or (
                isinstance(legacy, Mapping)
                and identity.split(":", 1)[1] in legacy
            )
            for identity in roster
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass drifted-arm finalized projections reappeared"
            )
        return
    if ancestor_digest != intent.get("committed_ancestor_evidence_digest"):
        raise ReconPrepassAuthorityError(
            "recon prepass committed ancestor CAS changed"
        )
    _prepass_assert_projection_snapshot(
        ledger, roster, intent.get("projection_records")
    )
    ancestor["semantic_status"] = "INVALID"
    ancestor["execution_state"] = "FAILED"
    ancestor["superseded_by_work_unit_key"] = successor_key
    for identity in roster:
        for row in (
            bindings.get(identity) if isinstance(bindings, dict) else None,
            legacy.get(identity.split(":", 1)[1])
            if isinstance(legacy, dict) else None,
            ancestor.get("artifacts", {}).get(identity),
        ):
            if isinstance(row, dict) and row.get("owner_key") == ancestor_key:
                row["status"] = "QUARANTINED"
                row["authority_level"] = "HISTORICAL_PREDECESSOR_ONLY"
        if isinstance(bindings, dict):
            bindings.pop(identity, None)
        if isinstance(legacy, dict):
            legacy.pop(identity.split(":", 1)[1], None)
    _prepass_commit_ledger_cas(scratchpad, ledger_prestate, ledger)


def _prepass_resume_sealed_publication(
    scratchpad: Path,
    project_root: Path,
    config: Mapping[str, Any],
    contract: Any,
    launch: LaunchSpec,
    *,
    run_id: str,
    authority: Mapping[str, Any],
    predecessor_owner_key: str | None,
    failure_injector: Callable[..., None] | None,
) -> dict[str, Any] | None:
    """Publish an existing exact sealed transaction without rerendering."""

    authority_digest = str(authority.get("authority_sha256") or "")
    intent_path = (
        scratchpad / "_recon_prepass_auxiliary_transactions"
        / f"{authority_digest}.intent.json"
    )
    if _prepass_read_private_json(scratchpad, intent_path) is None:
        return None
    output_names = tuple(item.path for item in contract.outputs)
    intent, publication_root = _prepass_seal_publication_transaction(
        scratchpad,
        None,
        output_names,
        {},
        run_id=run_id,
        successor_authority=authority,
        successor_work_unit_key=contract.key,
        successor_receipt_sha256="",
    )
    members = intent.get("publication_members")
    auxiliary = intent.get("successor_auxiliary")
    if (
        not isinstance(members, Mapping)
        or not isinstance(auxiliary, Mapping)
        or set(members) != set(output_names).union(auxiliary)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass sealed resume denominator differs"
        )
    receipt = json.loads(_prepass_bounded_read_bytes(
        publication_root / _PREPASS_PUBLICATION_RECEIPT,
        label="recon prepass sealed resume receipt",
        max_bytes=8 * 1024 * 1024,
    ))
    if (
        not isinstance(receipt, Mapping)
        or receipt.get("artifact_sha256")
        != intent.get("successor_receipt_sha256")
        or not isinstance(receipt.get("results"), Mapping)
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass sealed resume receipt differs"
        )
    current_capture = _prepass_capture(scratchpad, project_root, config)
    if _prepass_preexecution_authority(
        contract, launch, run_id=run_id, capture=current_capture
    ) != authority:
        return None
    _prepass_prepare_auxiliary_transaction(
        scratchpad,
        intent,
        successor_authority_digest=authority_digest,
        successor_work_unit_key=contract.key,
    )
    for name in output_names[:-1]:
        _prepass_durable_replace_from_stage(
            publication_root / name,
            scratchpad / name,
            label="recon prepass sealed-resume selected output",
        )
    for relative in sorted(auxiliary):
        _prepass_durable_replace_from_stage(
            _prepass_auxiliary_path(publication_root, relative),
            _prepass_auxiliary_path(scratchpad, relative),
            label="recon prepass sealed-resume auxiliary output",
        )
    _prepass_durable_replace_from_stage(
        publication_root / _PREPASS_PUBLICATION_RECEIPT,
        scratchpad / _PREPASS_PUBLICATION_RECEIPT,
        label="recon prepass sealed-resume receipt",
    )
    if failure_injector is not None:
        failure_injector("after_publish")
    commit_capture = _prepass_capture(scratchpad, project_root, config)
    if _prepass_preexecution_authority(
        contract, launch, run_id=run_id, capture=commit_capture
    ) != authority:
        raise ReconPrepassAuthorityError(
            "recon prepass sealed resume authority changed before commit"
        )
    if failure_injector is not None:
        failure_injector("before_commit")
    expected_records = {
        f"scratchpad:{name}": {
            "sha256": members[name]["sha256"],
            "size": members[name]["size"],
        }
        for name in output_names
    }
    committed = record_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        expected_output_records=expected_records,
    )
    if failure_injector is not None:
        failure_injector("after_artifact_commit_before_publication_rebind")
    committed = _prepass_bind_publication_intent_ledger(scratchpad, intent)
    if (
        committed.get("semantic_status") != "ACTIVE"
        or committed.get("execution_state") != "OUTPUT_COMMITTED"
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass sealed resume did not commit"
        )
    issues = validate_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        preexecution_authority=authority,
    )
    if issues:
        raise ReconPrepassAuthorityError(
            "recon prepass sealed resume replay failed: " + "; ".join(issues)
        )
    if failure_injector is not None:
        failure_injector("after_commit")
    if predecessor_owner_key is not None:
        _finalize_prepass_successor(
            scratchpad,
            predecessor_key=predecessor_owner_key,
            successor_key=contract.key,
        )
    return dict(receipt["results"])


def run_recon_prepass(
    config: dict,
    *,
    failure_injector: Callable[..., None] | None = None,
) -> Dict[str, str]:
    """Publish one exact, replayable DRIVER-owned prepass generation."""

    if not isinstance(config, dict):
        raise ReconPrepassAuthorityError("recon prepass config must be a dict")
    scratchpad_text = str(config.get("scratchpad") or "")
    project_root_text = str(config.get("project_root") or "")
    run_id = str(config.get("_run_id") or config.get("run_id") or "").strip()
    if not run_id or not scratchpad_text.strip() or not project_root_text.strip():
        raise ReconPrepassAuthorityError(
            "recon prepass requires current run_id and project_root"
        )
    scratchpad = Path(scratchpad_text)
    project_root = Path(project_root_text)
    ledger = read_artifact_ledger(scratchpad)
    units = ledger.get("work_units")
    if not isinstance(units, dict):
        raise ReconPrepassAuthorityError(
            "recon prepass ledger work-unit authority is malformed"
        )
    possible_owners: list[tuple[str, Mapping[str, Any]]] = []
    terminal_rows: list[str] = []
    expected_prefix = _prepass_expected_prefix(config)
    for key, row in units.items():
        key_text = str(key)
        key_parts = key_text.split("/")
        role = key_parts[-1] if key_parts else ""
        is_prepass_authority = (
            len(key_parts) == 6
            and key_parts[-2] == "recon"
            and (
                role == "prepass"
                or role.startswith("prepass.attempt-")
                or role.startswith("prepass.disposition-")
            )
        ) or (
            len(key_parts) == 7
            and key_parts[-3:] == ["recon", "prepass", "attempt-2"]
        )
        if (
            is_prepass_authority
            and isinstance(row, Mapping)
            and row.get("run_id") in {None, run_id}
            and tuple(key_parts[:5]) != expected_prefix
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass ledger contains wrong-dimension authority"
            )
        if (
            len(key_parts) != 6
            or key_parts[-2] != "recon"
            or (
                key_parts[-1] != "prepass"
                and _PREPASS_ATTEMPT_ID_RE.fullmatch(key_parts[-1]) is None
            )
        ):
            continue
        if not isinstance(key, str) or not isinstance(row, Mapping):
            raise ReconPrepassAuthorityError(
                "recon prepass owner row is malformed"
            )
        if row.get("run_id") != run_id:
            raise ReconPrepassAuthorityError(
                "recon prepass observed a cross-run bound owner"
            )
        state_pair = (
            row.get("semantic_status"),
            row.get("execution_state"),
        )
        if state_pair in {
            ("INPUTS_BOUND", "INPUTS_BOUND_PREEXECUTION"),
            ("ACTIVE", "OUTPUT_COMMITTED"),
        }:
            possible_owners.append((key, row))
        elif state_pair in {
            ("INVALID", "FAILED"),
            ("DEBT", "FAILED"),
            ("REJECTED", "INPUT_REJECTED"),
            ("QUARANTINED", "OUTPUT_QUARANTINED"),
        }:
            terminal_rows.append(key)
        else:
            raise ReconPrepassAuthorityError(
                f"recon prepass owner {key} has an incompatible state"
            )
    possible_owners.sort(
        key=lambda item: _prepass_generation_ordinal(item[0])
    )
    if possible_owners:
        _prepass_validate_closed_lineage(
            scratchpad,
            units,
            config,
            run_id=run_id,
            head_key=possible_owners[-1][0],
        )
    migrated_legacy = None
    if not possible_owners and terminal_rows:
        migrated_legacy = _migrate_legacy_prepass_terminal(
            scratchpad,
            project_root,
            config,
            run_id=run_id,
            failure_injector=failure_injector,
        )
        if migrated_legacy is None:
            raise ReconPrepassAuthorityError(
                "recon prepass prior authority is terminal and cannot be healed"
            )

    if migrated_legacy is not None:
        contract, launch, stored_arm_authority, armed = migrated_legacy
        output_names = tuple(item.path for item in contract.outputs)
        predecessor_owner_key = "/".join(
            (*contract.key.split("/")[:5], "prepass")
        )
    elif possible_owners:
        owner_key, owner = possible_owners[-1]
        predecessor_owner_key = (
            possible_owners[-2][0]
            if len(possible_owners) > 1
            else None
        )
        stored_authority = _validated_prepass_preexecution_authority(
            owner.get("preexecution_authority")
        )
        if (
            owner.get("preexecution_authority_digest")
            != stored_authority["authority_sha256"]
            or stored_authority["work_unit_key"] != owner_key
            or stored_authority["run_id"] != run_id
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass durable arm authority binding mismatch"
            )
        owner_contract, owner_launch = _prepass_authority_pair(
            stored_authority
        )
        issues = validate_work_unit_inputs(
            scratchpad,
            project_root,
            owner_contract,
            owner_launch,
            run_id=run_id,
            preexecution_authority=stored_authority,
        )
        if issues:
            raise ReconPrepassAuthorityError(
                "recon prepass bound input replay failed: " + "; ".join(issues)
            )
        # Generic replay first authenticates the immutable stored object.  Only
        # then may current source/config/semantic authority be recomputed.
        pipeline, mode, ecosystem, backend = _prepass_dimensions(config)
        current_output_names = _prepass_output_names(pipeline)
        if tuple(item.path for item in owner_contract.outputs) != current_output_names:
            raise ReconPrepassAuthorityError(
                "recon prepass contract output denominator/order drift"
            )
        capture = _prepass_capture(scratchpad, project_root, config)
        current_authority = _prepass_preexecution_authority(
            owner_contract,
            owner_launch,
            run_id=run_id,
            capture=capture,
        )
        _validated_prepass_preexecution_authority(current_authority)
        if failure_injector is not None:
            failure_injector("after_capture")
        if current_authority != stored_authority:
            (
                successor_contract,
                successor_launch,
                successor_authority,
                armed,
            ) = _arm_prepass_successor(
                scratchpad,
                project_root,
                owner_contract,
                run_id=run_id,
                capture=capture,
                original_authority=stored_authority,
                failure_injector=failure_injector,
            )
            predecessor_owner_key = owner_key
            contract, launch = successor_contract, successor_launch
            output_names = tuple(item.path for item in contract.outputs)
            stored_arm_authority = successor_authority
        else:
            contract, launch = owner_contract, owner_launch
            output_names = tuple(item.path for item in contract.outputs)
            if (
                owner.get("semantic_status") == "ACTIVE"
                and owner.get("execution_state") == "OUTPUT_COMMITTED"
            ):
                output_issues = validate_work_unit_artifacts(
                    scratchpad,
                    project_root,
                    contract,
                    launch,
                    run_id=run_id,
                    actor="DRIVER",
                    preexecution_authority=stored_authority,
                )
                receipt = _prepass_read_receipt(scratchpad)
                if (
                    output_issues
                    or not isinstance(receipt, Mapping)
                    or receipt.get("authority_capture") != capture
                    or tuple(receipt.get("selected_outputs") or ())
                    != output_names[:-1]
                ):
                    raise ReconPrepassAuthorityError(
                        "recon prepass committed output authority changed"
                    )
                if predecessor_owner_key is not None:
                    _finalize_prepass_successor(
                        scratchpad,
                        predecessor_key=predecessor_owner_key,
                        successor_key=contract.key,
                    )
                result = receipt.get("results")
                return dict(result) if isinstance(result, Mapping) else {}
            armed = owner
            stored_arm_authority = stored_authority
    else:
        predecessor_owner_key = None
        if not project_root.is_dir():
            raise ReconPrepassAuthorityError(
                "recon prepass requires current run_id and project_root"
            )
        scratchpad.mkdir(parents=True, exist_ok=True)
        pipeline, mode, ecosystem, backend = _prepass_dimensions(config)
        output_names = _prepass_output_names(pipeline)
        contract = resolve_phase_io_contract(
            pipeline=pipeline,
            mode=mode,
            ecosystem=ecosystem,
            backend=backend,
            phase="recon",
            work_unit_id="prepass",
        )
        if tuple(item.path for item in contract.outputs) != output_names:
            raise ReconPrepassAuthorityError(
                "recon prepass contract output denominator/order drift"
            )
        launch = LaunchSpec(
            work_unit_key=contract.key,
            pipeline=contract.pipeline,
            mode=contract.mode,
            ecosystem=contract.ecosystem,
            backend=contract.backend,
            model="driver",
            timeout_s=_PREPASS_TIMEOUT_SECONDS,
            exec_mode="python",
            tool_policy=("filesystem",),
        )
        capture = _prepass_capture(scratchpad, project_root, config)
        current_authority = _prepass_preexecution_authority(
            contract,
            launch,
            run_id=run_id,
            capture=capture,
        )
        _validated_prepass_preexecution_authority(current_authority)
        if failure_injector is not None:
            failure_injector("after_capture")
        prearm_capture = _prepass_capture(scratchpad, project_root, config)
        if prearm_capture != capture:
            raise ReconPrepassAuthorityError(
                "recon prepass source root identity drift before input arm"
            )
        _prepass_assert_capture_source_root(project_root, capture)
        try:
            armed = record_work_unit_inputs(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
                preexecution_authority=current_authority,
            )
        except ArtifactLedgerError as exc:
            raise ReconPrepassAuthorityError(
                f"recon prepass input arm failed: {exc}"
            ) from exc
        stored_arm_authority = current_authority
    if (
        armed.get("semantic_status") != "INPUTS_BOUND"
        or armed.get("execution_state") != "INPUTS_BOUND_PREEXECUTION"
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass did not establish a clean preexecution arm"
        )
    if failure_injector is not None:
        failure_injector("after_arm")

    resumed_capture = _prepass_capture(scratchpad, project_root, config)
    resumed_authority = _prepass_preexecution_authority(
        contract,
        launch,
        run_id=run_id,
        capture=resumed_capture,
    )
    if resumed_authority != stored_arm_authority:
        _arm_prepass_successor(
            scratchpad,
            project_root,
            contract,
            run_id=run_id,
            capture=resumed_capture,
            original_authority=stored_arm_authority,
            failure_injector=failure_injector,
        )
        return run_recon_prepass(config)
    capture = resumed_capture

    state = _prepass_bound_generation_state(scratchpad, armed, output_names)
    # The receipt is the written-last generation marker.  Authenticate it
    # before interpreting output prestates: byte-identical members can look
    # old while changed members look new, and a crash between replaces is a
    # normal recoverable mixed state.  A valid receipt commits immediately;
    # otherwise the exact bound authority deterministically rerenders and
    # republishes the complete denominator below.
    recovered = _prepass_published_records(
        scratchpad, output_names, capture
    )
    if recovered is not None:
        try:
            committed = record_work_unit_artifacts(
                scratchpad,
                project_root,
                contract,
                launch,
                run_id=run_id,
                actor="DRIVER",
                expected_output_records=recovered,
            )
        except ArtifactLedgerError as exc:
            raise ReconPrepassAuthorityError(
                f"recon prepass recovery commit failed: {exc}"
            ) from exc
        if failure_injector is not None:
            failure_injector(
                "after_artifact_commit_before_publication_rebind"
            )
        recovery_intent = _prepass_read_private_json(
            scratchpad,
            scratchpad / "_recon_prepass_auxiliary_transactions"
            / f"{stored_arm_authority['authority_sha256']}.intent.json",
        )
        if recovery_intent is None:
            raise ReconPrepassAuthorityError(
                "recon prepass recovery publication intent is absent"
            )
        committed = _prepass_bind_publication_intent_ledger(
            scratchpad, recovery_intent
        )
        if (
            committed.get("semantic_status") != "ACTIVE"
            or committed.get("execution_state") != "OUTPUT_COMMITTED"
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass recovery was not ACTIVE/OUTPUT_COMMITTED"
            )
        if predecessor_owner_key is not None:
            _finalize_prepass_successor(
                scratchpad,
                predecessor_key=predecessor_owner_key,
                successor_key=contract.key,
            )
        receipt = _prepass_read_receipt(scratchpad)
        result = receipt.get("results") if isinstance(receipt, Mapping) else None
        return dict(result) if isinstance(result, Mapping) else {}

    sealed_resume = _prepass_resume_sealed_publication(
        scratchpad,
        project_root,
        config,
        contract,
        launch,
        run_id=run_id,
        authority=stored_arm_authority,
        predecessor_owner_key=predecessor_owner_key,
        failure_injector=failure_injector,
    )
    if sealed_resume is not None:
        return sealed_resume

    _prepass_assert_capture_source_root(project_root, capture)
    # Durable same-volume replacement is the publication primitive below, so
    # the staging directory must share the destination volume. The system temporary
    # directory is commonly on C: while an audited project/scratchpad is on
    # D: on Windows; publishing from the former raises WinError 17 after the
    # expensive mechanical pre-pass has already completed.  Keep the private
    # stage inside the run-owned scratchpad so every replace is same-volume
    # and remains atomic.
    scratchpad.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(
        prefix=".plamen-recon-prepass-",
        dir=scratchpad,
    ))
    try:
        _prepass_assert_capture_source_root(project_root, capture)
        stage_config = dict(config)
        stage_config["scratchpad"] = str(stage)
        results = _render_recon_prepass(stage_config)
        excluded_private_roots = _prepass_cleanup_renderer_private_stage(stage)
        for name in output_names[:-1]:
            path = stage / name
            if not _prepass_regular_file_present(
                path, label="recon prepass staged selected output"
            ):
                raise ReconPrepassAuthorityError(
                    f"recon prepass renderer omitted selected output: {name}"
                )
            _digest, size = _prepass_bounded_file_digest(
                path,
                label="recon prepass staged selected output",
                max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
            )
            if size == 0:
                raise ReconPrepassAuthorityError(
                    f"recon prepass renderer omitted selected output: {name}"
                )
        auxiliary_output_sha256 = _prepass_auxiliary_output_sha256(
            stage, output_names, excluded_private_roots
        )
        receipt = _prepass_receipt(
            stage,
            output_names,
            capture,
            results,
            auxiliary_output_sha256,
        )
        (stage / _PREPASS_PUBLICATION_RECEIPT).write_text(
            json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        staged_records = {}
        staged_total_bytes = 0
        for name in output_names:
            digest, size = _prepass_bounded_file_digest(
                stage / name,
                label="recon prepass staged committed output",
                max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
            )
            staged_total_bytes += size
            if staged_total_bytes > _PREPASS_STAGE_MAX_TOTAL_BYTES:
                raise ReconPrepassAuthorityError(
                    "recon prepass staged total-byte budget exceeded"
                )
            staged_records[f"scratchpad:{name}"] = {
                "sha256": digest,
                "size": size,
            }
        for relative in auxiliary_output_sha256:
            digest, size = _prepass_bounded_file_digest(
                _prepass_auxiliary_path(stage, relative),
                label="recon prepass staged aggregate auxiliary",
                max_bytes=_PREPASS_STAGE_MAX_FILE_BYTES,
            )
            if digest != auxiliary_output_sha256[relative]:
                raise ReconPrepassAuthorityError(
                    "recon prepass staged auxiliary changed before publication"
                )
            staged_total_bytes += size
            if staged_total_bytes > _PREPASS_STAGE_MAX_TOTAL_BYTES:
                raise ReconPrepassAuthorityError(
                    "recon prepass staged total-byte budget exceeded"
                )
        if failure_injector is not None:
            failure_injector("after_stage")
        publish_capture = _prepass_capture(
            scratchpad, project_root, config
        )
        publish_authority = _prepass_preexecution_authority(
            contract,
            launch,
            run_id=run_id,
            capture=publish_capture,
        )
        if publish_authority != stored_arm_authority:
            _arm_prepass_successor(
                scratchpad,
                project_root,
                contract,
                run_id=run_id,
                capture=publish_capture,
                original_authority=stored_arm_authority,
                failure_injector=failure_injector,
            )
            return run_recon_prepass(config)
        publication_intent, publication_root = (
            _prepass_seal_publication_transaction(
                scratchpad,
                stage,
                output_names,
                auxiliary_output_sha256,
                run_id=run_id,
                successor_authority=stored_arm_authority,
                successor_work_unit_key=contract.key,
                successor_receipt_sha256=str(receipt["artifact_sha256"]),
            )
        )
        publication_members = publication_intent.get("publication_members")
        sealed_auxiliary = publication_intent.get("successor_auxiliary")
        if (
            not isinstance(publication_members, Mapping)
            or not isinstance(sealed_auxiliary, Mapping)
            or set(publication_members)
            != set(output_names).union(sealed_auxiliary)
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication denominator differs"
            )
        sealed_receipt = json.loads(_prepass_bounded_read_bytes(
            publication_root / _PREPASS_PUBLICATION_RECEIPT,
            label="recon prepass sealed publication receipt",
            max_bytes=8 * 1024 * 1024,
        ))
        if (
            not isinstance(sealed_receipt, Mapping)
            or sealed_receipt.get("artifact_sha256")
            != publication_intent.get("successor_receipt_sha256")
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication receipt differs"
            )
        receipt = dict(sealed_receipt)
        sealed_results = receipt.get("results")
        if not isinstance(sealed_results, Mapping):
            raise ReconPrepassAuthorityError(
                "recon prepass sealed publication results are malformed"
            )
        results = dict(sealed_results)
        auxiliary_output_sha256 = {
            name: record["sha256"]
            for name, record in sealed_auxiliary.items()
        }
        staged_records = {
            f"scratchpad:{name}": {
                "sha256": publication_members[name]["sha256"],
                "size": publication_members[name]["size"],
            }
            for name in output_names
        }
        _prepass_prepare_auxiliary_transaction(
            scratchpad,
            publication_intent,
            successor_authority_digest=stored_arm_authority[
                "authority_sha256"
            ],
            successor_work_unit_key=contract.key,
        )
        # Preserve the canonical mixed-generation detector: selected outputs
        # publish first, auxiliary machine authorities second, and the signed
        # receipt remains the written-last commit marker.
        for name in output_names[:-1]:
            _prepass_durable_replace_from_stage(
                publication_root / name,
                scratchpad / name,
                label="recon prepass selected output",
            )
        for relative in sorted(auxiliary_output_sha256):
            source = _prepass_auxiliary_path(publication_root, relative)
            target = _prepass_auxiliary_path(scratchpad, relative)
            _prepass_durable_replace_from_stage(
                source,
                target,
                label="recon prepass auxiliary output",
            )
        _prepass_durable_replace_from_stage(
            publication_root / _PREPASS_PUBLICATION_RECEIPT,
            scratchpad / _PREPASS_PUBLICATION_RECEIPT,
            label="recon prepass publication receipt",
        )
        if failure_injector is not None:
            failure_injector("after_publish")
        commit_capture = _prepass_capture(scratchpad, project_root, config)
        commit_authority = _prepass_preexecution_authority(
            contract,
            launch,
            run_id=run_id,
            capture=commit_capture,
        )
        if commit_authority != stored_arm_authority:
            _arm_prepass_successor(
                scratchpad,
                project_root,
                contract,
                run_id=run_id,
                capture=commit_capture,
                original_authority=stored_arm_authority,
                failure_injector=failure_injector,
            )
            return run_recon_prepass(config)
        if failure_injector is not None:
            failure_injector("before_commit")
        commit_capture = _prepass_capture(scratchpad, project_root, config)
        commit_authority = _prepass_preexecution_authority(
            contract,
            launch,
            run_id=run_id,
            capture=commit_capture,
        )
        if commit_authority != stored_arm_authority:
            _arm_prepass_successor(
                scratchpad,
                project_root,
                contract,
                run_id=run_id,
                capture=commit_capture,
                original_authority=stored_arm_authority,
                failure_injector=failure_injector,
            )
            return run_recon_prepass(config)
        expected_records = staged_records
        committed = record_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            expected_output_records=expected_records,
        )
        if failure_injector is not None:
            failure_injector(
                "after_artifact_commit_before_publication_rebind"
            )
        committed = _prepass_bind_publication_intent_ledger(
            scratchpad, publication_intent
        )
        if (
            committed.get("semantic_status") != "ACTIVE"
            or committed.get("execution_state") != "OUTPUT_COMMITTED"
        ):
            raise ReconPrepassAuthorityError(
                "recon prepass commit was not ACTIVE/OUTPUT_COMMITTED"
            )
        issues = validate_work_unit_artifacts(
            scratchpad,
            project_root,
            contract,
            launch,
            run_id=run_id,
            actor="DRIVER",
            preexecution_authority=stored_arm_authority,
        )
        if issues:
            raise ReconPrepassAuthorityError(
                "recon prepass committed replay failed: " + "; ".join(issues)
            )
        if failure_injector is not None:
            failure_injector("after_commit")
        if predecessor_owner_key is not None:
            _finalize_prepass_successor(
                scratchpad,
                predecessor_key=predecessor_owner_key,
                successor_key=contract.key,
            )
        return results
    except ArtifactLedgerError as exc:
        raise ReconPrepassAuthorityError(
            f"recon prepass transaction failed: {exc}"
        ) from exc
    finally:
        shutil.rmtree(stage, ignore_errors=False)


def assert_recon_prepass_dispatch_authority(config: Mapping[str, Any]) -> str:
    """Prove the sole current prepass generation is safe for phase dispatch."""

    if not isinstance(config, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch config is malformed"
        )
    run_id = str(config.get("_run_id") or config.get("run_id") or "").strip()
    scratchpad = Path(str(config.get("scratchpad") or ""))
    project_root = Path(str(config.get("project_root") or ""))
    if not run_id or not scratchpad.is_dir() or not project_root.is_dir():
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch authority lacks current roots/run"
        )
    ledger = read_artifact_ledger(scratchpad)
    units = ledger.get("work_units")
    if not isinstance(units, Mapping):
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch ledger is malformed"
        )
    prefix = _prepass_expected_prefix(config)
    active: list[tuple[str, Mapping[str, Any]]] = []
    for key, row in units.items():
        if not isinstance(key, str) or not isinstance(row, Mapping):
            continue
        parts = key.split("/")
        role = parts[-1] if parts else ""
        relevant = (
            len(parts) == 6
            and parts[-2] == "recon"
            and (
                role == "prepass"
                or role.startswith("prepass.attempt-")
                or role.startswith("prepass.disposition-")
            )
        ) or (
            len(parts) == 7
            and parts[-3:] == ["recon", "prepass", "attempt-2"]
        )
        if not relevant:
            continue
        if tuple(parts[:5]) != prefix:
            raise ReconPrepassAuthorityError(
                "recon prepass dispatch observed wrong-dimension authority"
            )
        if len(parts) == 7:
            # Preserved legacy evidence is never an owner.  Its exact v2
            # migration receipt is authenticated by the closed-lineage replay
            # below; every other seven-component row is rejected there.
            continue
        if (
            role == "prepass" or _PREPASS_ATTEMPT_ID_RE.fullmatch(role)
        ) and (
            row.get("semantic_status"), row.get("execution_state")
        ) == ("ACTIVE", "OUTPUT_COMMITTED"):
            active.append((key, row))
    if len(active) != 1:
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch requires exactly one committed owner"
        )
    head_key, head = active[0]
    _prepass_validate_closed_lineage(
        scratchpad,
        units,
        config,
        run_id=run_id,
        head_key=head_key,
    )
    pending_ordinal = _prepass_generation_ordinal(head_key) + 1
    pending_key = _prepass_disposition_key(
        "/".join((*prefix, f"prepass.attempt-{pending_ordinal:04d}")),
        pending_ordinal,
    )
    pending_row = units.get(pending_key)
    if isinstance(pending_row, Mapping) and (
        pending_row.get("semantic_status"), pending_row.get("execution_state")
    ) == ("DEBT", "FAILED"):
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch rejects pending successor debt"
        )
    authority = _validated_prepass_preexecution_authority(
        head.get("preexecution_authority")
    )
    if authority.get("authority_capture") != _prepass_capture(
        scratchpad, project_root, config
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch current capture changed"
        )
    contract, launch = _prepass_authority_pair(authority)
    input_issues = validate_work_unit_inputs(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        preexecution_authority=authority,
    )
    artifact_issues = validate_work_unit_artifacts(
        scratchpad,
        project_root,
        contract,
        launch,
        run_id=run_id,
        actor="DRIVER",
        preexecution_authority=authority,
    )
    receipt = _prepass_read_receipt(scratchpad)
    output_names = tuple(item.path for item in contract.outputs)
    if (
        input_issues
        or artifact_issues
        or not isinstance(receipt, Mapping)
        or receipt.get("authority_capture") != authority.get("authority_capture")
        or tuple(receipt.get("selected_outputs") or ()) != output_names[:-1]
        or _prepass_published_records(
            scratchpad,
            output_names,
            authority["authority_capture"],
        ) is None
    ):
        raise ReconPrepassAuthorityError(
            "recon prepass dispatch replay or receipt authority failed"
        )
    return head_key


if __name__ == "__main__":
    import json as _json
    import sys as _sys
    if len(_sys.argv) != 2:
        print("Usage: python recon_prepass.py <config.json>")
        _sys.exit(2)
    cfg = _json.loads(Path(_sys.argv[1]).read_text(encoding="utf-8"))
    print(_json.dumps(run_recon_prepass(cfg), indent=2))
