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
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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
from supply_chain_gate import SupplyChainAbortError, gate_supply_chain
from production_source_scope import (
    PRODUCTION_SOURCE_SKIP_NAME_RE,
    PRODUCTION_SOURCE_SKIP_PARTS,
    is_production_source_path,
)

# Module logger. `_scip_to_graph_artifacts` emits a log.warning on the
# large-index (>callee-node-cap) PARTIAL path; without this module-level logger
# that call raised `NameError: name 'log' is not defined` on big repos
# (cosmos-sdk), which surfaced as the SCIP bake FAILED and fell back to grep.
log = logging.getLogger("plamen.recon_prepass")

# Filesystem helpers
SKIP_DIR_NAMES = {
    "node_modules", ".git", "target", "build", "out", "artifacts", "cache",
    "dist", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode",
    "lib", "forge-cache", ".foundry", ".anchor", ".aptos", ".sui",
}

# Dirs that never hold source a WHOLE-PROJECT compiler will build (build
# output / VCS / tooling caches). Deliberately does NOT skip dependency dirs
# (`lib/`, `node_modules/`): a whole-project `forge build` / `hardhat compile`
# compiles imported library sources, so they MUST be counted when sizing a
# build-timeout ceiling. Sizing off `_production_source_files` (which skips
# `lib/` via SKIP_DIR_NAMES) undercounts the compiler's real load by ~10x on
# dependency-heavy repos and caused cold-cache builds to time out (a 652s
# budget sized from 13 in-scope files for a real 188-file compile). Over-
# counting is safe: the hardened runner returns as soon as the build finishes,
# so the scaled value is only a CEILING, never a fixed wait.
COMPILE_UNIT_SKIP_DIR_NAMES = {
    ".git", "out", "artifacts", "cache", "forge-cache", "target", "build",
    "dist", ".venv", "venv", "__pycache__", ".next", ".idea", ".vscode",
    ".foundry", ".anchor", ".aptos", ".sui",
}

def _iter_files(root: Path, suffixes: Tuple[str, ...]) -> List[Path]:
    out: List[Path] = []
    root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        for name in filenames:
            if name.endswith(suffixes):
                out.append(Path(dirpath) / name)
    return out

def _is_production_source_path(path: Path, root: Path) -> bool:
    """Compatibility alias for the canonical production-source predicate."""
    return is_production_source_path(path, root)

def _production_source_files(root: Path, suffixes: Tuple[str, ...]) -> List[Path]:
    return [
        p for p in _iter_files(root, suffixes)
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
        # foundry.toml AT or ABOVE the scope dir (audit scope is often `src/`
        # while the Foundry root is one or more levels up).
        if shutil.which("forge") and _resolve_evm_build_root(proj) is not None:
            return "evm_forge"
        if list(proj.glob("hardhat.config.*")) and shutil.which("npx"):
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
            dirnames[:] = [x for x in dirnames
                           if x not in SKIP_DIR_NAMES and not x.startswith(".")]
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
    """Resolve the Foundry root for an EVM audit scope.

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
            if (cur / "foundry.toml").exists():
                return cur
        except Exception:
            pass
        parent = cur.parent
        if parent == cur:
            break
        cur = parent
    # Walk-up failed → monorepo: search downward for the Foundry sub-project.
    return _find_build_root_downward(proj, ("foundry.toml",), (".sol",))


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


def _hardened_tree_kill(proc: "subprocess.Popen") -> None:
    """Kill the subprocess AND all its descendants. Never raises.

    POSIX: SIGKILL the child's process-group (it was started in a new session).
    Windows: `taskkill /F /T /PID` walks and force-kills the whole tree. Both
    reap grandchildren (solc/cc/...) that a bare proc.kill() would orphan and
    that keep holding inherited handles."""
    try:
        if os.name == "nt":
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15,
                )
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
    except Exception:
        pass


def _run_hardened(cmd: List[str], cwd: Optional[Path] = None,
                  timeout: int = 120, env: Optional[dict] = None) -> Tuple[int, str]:
    """Hang-proof, cross-platform subprocess runner. Returns (rc, combined_output).

    Drains stdout+stderr to a TEMP FILE (never an OS pipe) so a grandchild that
    inherits the output handle can never deadlock the parent, and tree-kills the
    whole process group on timeout. Never raises; never blocks past
    timeout + _HARDENED_GRACE_S. On timeout returns (124, output + notice) so
    callers degrade. stdin is /dev/null so an interactive prompt cannot block."""
    argv = [str(c) for c in cmd]
    cwd_s = str(cwd) if cwd is not None else None

    tf = None
    tf_name = ""
    try:
        tf = tempfile.NamedTemporaryFile(
            mode="w+", suffix=".plamen_run", prefix="plamen_hardened_",
            delete=False, encoding="utf-8", errors="replace")
        tf_name = tf.name
    except Exception as e:  # pragma: no cover - temp dir unavailable
        return 1, f"hardened: temp file create failed: {e}"

    popen_kwargs: Dict = {}
    if os.name == "nt":
        # New process group so a grandchild does not share the parent's group
        # and the whole tree is addressable by taskkill /T.
        popen_kwargs["creationflags"] = getattr(
            subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    else:
        # New session → own process-group → killpg reaps the whole tree.
        popen_kwargs["start_new_session"] = True

    proc = None
    try:
        try:
            proc = subprocess.Popen(
                argv, cwd=cwd_s, env=env,
                stdin=subprocess.DEVNULL,
                stdout=tf, stderr=subprocess.STDOUT,
                **popen_kwargs,
            )
        except FileNotFoundError:
            return 127, f"binary not found: {argv[0] if argv else '?'}"
        except Exception as e:
            return 1, f"hardened: spawn failed: {e}"

        timed_out = False
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _hardened_tree_kill(proc)
            try:
                proc.wait(timeout=_HARDENED_GRACE_S)
            except Exception:
                # Even if the bounded reap window elapses we do NOT block past
                # it — the tree was already SIGKILL'd/taskkilled; return anyway.
                pass

        # Read the drained output from the temp file (close parent handle first
        # so all buffered writes are flushed to disk).
        try:
            tf.close()
        except Exception:
            pass
        output = ""
        try:
            with open(tf_name, "r", encoding="utf-8", errors="replace") as fh:
                output = fh.read()
        except Exception:
            output = ""

        if timed_out:
            return 124, (output +
                         f"\n[hardened: timed out after {timeout}s, tree-killed]")
        rc = proc.returncode
        return (rc if rc is not None else 1), output
    except Exception as e:  # pragma: no cover - defensive top-level guard
        if proc is not None:
            _hardened_tree_kill(proc)
        return 1, f"hardened: exception: {e}"
    finally:
        try:
            if tf is not None and not tf.closed:
                tf.close()
        except Exception:
            pass
        try:
            if tf_name:
                os.unlink(tf_name)
        except Exception:
            pass


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
      (3) `npm/yarn/pnpm install` when `package.json` is present but
          `node_modules/` is empty (Hardhat, or Foundry remapping into
          node_modules — e.g. `@openzeppelin/contracts`);
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
            notes.append("forge install " + ("ok" if rc == 0 else f"rc={rc}"))
        # (2) Soldeer deps
        try:
            ftoml = (root / "foundry.toml").read_text(encoding="utf-8", errors="replace")
        except Exception:
            ftoml = ""
        uses_soldeer = "[dependencies]" in ftoml or (root / "soldeer.lock").exists()
        if uses_soldeer and _dir_empty(root / "dependencies") and shutil.which("forge"):
            rc, _out = _run_forge(["soldeer", "install"], root, 300)
            notes.append("soldeer install " + ("ok" if rc == 0 else f"rc={rc}"))
        # (3) npm/yarn/pnpm deps (Hardhat, or Foundry remapping into node_modules)
        if (root / "package.json").exists() and _dir_empty(root / "node_modules"):
            if (root / "pnpm-lock.yaml").exists() and shutil.which("pnpm"):
                rc = _run_cmd(["pnpm", "install", "--frozen-lockfile"], root, 420)
                notes.append("pnpm install " + ("ok" if rc == 0 else f"rc={rc}"))
            elif (root / "yarn.lock").exists() and shutil.which("yarn"):
                rc = _run_cmd(["yarn", "install", "--frozen-lockfile"], root, 420)
                notes.append("yarn install " + ("ok" if rc == 0 else f"rc={rc}"))
            elif shutil.which("npm"):
                sub = "ci" if (root / "package-lock.json").exists() else "install"
                rc = _run_cmd(["npm", sub], root, 420)
                notes.append(f"npm {sub} " + ("ok" if rc == 0 else f"rc={rc}"))
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
    except Exception:
        pass
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
# This best-effort bootstrap scaffolds a minimal Foundry env (foundry.toml +
# forge-std + import-prefix remappings + well-known libs) and runs `forge
# build`. It NEVER raises and is idempotent (no-op when a build manifest already
# exists). On any failure the caller falls back to the existing grep path.
# ---------------------------------------------------------------------------

_PRAGMA_RE = re.compile(
    r"pragma\s+solidity\s+[^;]*?(\d+\.\d+\.\d+)", re.IGNORECASE
)

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


def _detect_solc_version(source_files: List[Path]) -> Optional[str]:
    """Return the most common concrete `pragma solidity` version, or None."""
    from collections import Counter
    counter: Counter = Counter()
    for f in source_files[:200]:  # bounded scan
        text = _read_text(f)
        if not text:
            continue
        for m in _PRAGMA_RE.finditer(text):
            counter[m.group(1)] += 1
    if not counter:
        return None
    return counter.most_common(1)[0][0]


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

        # 2) forge-std (test harness). Best-effort; build can still succeed
        #    for non-test sources without it.
        rc, out = _run_forge(
            ["install", "foundry-rs/forge-std", "--no-commit"],
            proj, timeout=90,
        )
        if rc == 0:
            steps.append("installed forge-std")
        else:
            steps.append(f"forge-std install failed (rc={rc}): {_tail(out, 200)}")

        # 3) Detected well-known libraries + remappings.
        remap_lines: List[str] = []
        for prefix, lib_dir, install_spec, remap in libs:
            rc, out = _run_forge(
                ["install", install_spec, "--no-commit"], proj, timeout=120,
            )
            if rc == 0:
                steps.append(f"installed {install_spec}")
                remap_lines.append(remap)
            else:
                steps.append(
                    f"{install_spec} install failed (rc={rc}): {_tail(out, 200)}"
                )
        if remap_lines:
            try:
                (proj / "remappings.txt").write_text(
                    "\n".join(remap_lines) + "\n", encoding="utf-8"
                )
                steps.append(f"wrote remappings.txt ({len(remap_lines)} entries)")
            except Exception as e:
                steps.append(f"could not write remappings.txt: {e}")

        # 4) Build. Size-scale the bootstrap build budget too (large scaffolded
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

        if key == "evm_forge":
            root = _resolve_evm_build_root(proj)
            if root is not None and root != proj.resolve():
                # Real Foundry root found ABOVE the scope dir (audit scope is a
                # source subdir like `.../smart-contracts/src`). Build the WHOLE
                # project from the root so its foundry.toml / remappings.txt /
                # lib resolve every `@import` — running from the scope dir gives
                # empty remappings and every import fails (an observed
                # build failure). Make deps + solc real first (never mock).
                # `_bake_evm_slither_graph` resolves the same root downstream.
                bootstrap_note = ("**Build Root**: resolved to Foundry root "
                                  f"`{root}` (scope dir had no foundry.toml).\n\n"
                                  "**Build Prep**: " + _prepare_evm_build(root) + "\n\n")
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
        rc, combined = _run_hardened(cmd, build_cwd, timeout, env=build_env)
        # Retry-once on a transient non-timeout build failure. A first attempt
        # that fails for a transient reason (a flake, or a stale incremental
        # cache the first attempt itself invalidated) frequently succeeds on a
        # clean second run. Scoped to exactly ONE retry, and NOT for:
        #   - timeout (rc=124): a genuine stall — retrying just burns the budget;
        #   - binary-not-found (rc=127): the build tool is missing — deterministic.
        # Generic across all ecosystems (the rc∉{0,124,127} guard makes it
        # ecosystem-agnostic); the CARGO_INCREMENTAL=0 env above already removes
        # the dominant Rust-specific cause, so most second attempts succeed.
        if rc not in (0, 124, 127):
            log.warning("[recon] %s build attempt 1 FAILED (rc=%s) — retrying "
                        "ONCE (transient flake / self-invalidated cache often "
                        "clears on a clean re-run)", key, rc)
            rc2, combined2 = _run_hardened(cmd, build_cwd, timeout, env=build_env)
            if rc2 == 0:
                log.info("[recon] %s build retry SUCCEEDED (attempt 1 rc=%s was "
                         "transient)", key, rc)
            else:
                log.warning("[recon] %s build retry FAILED too (attempt 1 rc=%s, "
                            "attempt 2 rc=%s) — degrading build_status",
                            key, rc, rc2)
            rc, combined = rc2, combined2
        timed_out = rc == 124
        # _run_hardened combines stdout+stderr; keep the diagnostic text in the
        # stdout tail and leave stderr empty (split is purely informational).
        so, se = combined, ""

        status = "SUCCESS" if rc == 0 else ("TIMEOUT" if timed_out else "FAILED")
        # Visible degrade logging: the user manually reruns and wants to SEE the
        # build outcome — no silent freeze. The hardened wrapper guarantees we
        # reach this line within (timeout + grace) even on a wedged tree.
        if timed_out:
            log.warning("[recon] %s build timed out after %ss, tree-killed — "
                        "degrading build_status to TIMEOUT (later phases compile "
                        "explicit affected files on demand)", key, timeout)
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
            f"**Exit Code**: {rc}\n"
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
        dns[:] = [x for x in dns if x not in SKIP_DIR_NAMES and not x.startswith(".")]
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
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
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
        tops = [e for e in sorted(proj.iterdir())
                if e.is_dir() and e.name not in SKIP_DIR_NAMES and not e.name.startswith(".")]
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
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
            if Path(dirpath).name.lower() in surface_kws:
                surface_dirs.append(Path(dirpath))

        rows: List[str] = []
        for d in sorted(set(surface_dirs)):
            for root, dns, fns in os.walk(d):
                dns[:] = [x for x in dns if x not in SKIP_DIR_NAMES and not x.startswith(".")]
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

_SCIP_GRAPH_ARTIFACT_NAMES = (
    "caller_map.md", "callee_map.md", "state_write_map.md", "function_summary.md",
)


def _scip_bake_is_fresh(scratch: Path, proj: Path, index_path: Path,
                        suffixes: Tuple[str, ...]) -> bool:
    """L1-8: freshness/reuse guard shared by the Rust and Go SCIP bakers.

    True when a previously-baked SCIP index AND all 4 graph artifacts already
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
        for name in _SCIP_GRAPH_ARTIFACT_NAMES:
            art = scratch / name
            if not art.exists() or art.stat().st_size == 0:
                return False
        index_mtime = index_path.stat().st_mtime
        for f in _production_source_files(proj, suffixes):
            try:
                if f.stat().st_mtime > index_mtime:
                    return False
            except OSError:
                continue
        return True
    except Exception:
        return False


def _bake_rust_scip(scratch: Path, proj: Path) -> str:
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
        ["rust-analyzer", "scip", str(proj), "--exclude-vendored-libraries"],
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

    # Convert SCIP index to graph artifacts
    return _scip_to_graph_artifacts(scratch, index_path, proj)


def _bake_go_scip(scratch: Path, proj: Path) -> str:
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
            ["scip-go", "--quiet", "--output", str(ra_index)],
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
    return _scip_to_graph_artifacts(scratch, index_path, proj)


# F1 (recall): mechanical Solidity reference graph via Slither. EVM is the only
# SC family with NO mechanical graph today (its caller/state maps are LLM-
# transcribed). This bakes a deterministic state_read_map / state_write_map /
# caller_map + a machine `_mechanical_graph.json` (the coverage-gate's
# authoritative, LLM-unclobberable source) from Slither's data-flow analysis —
# mirroring _bake_rust_scip for the SCIP ecosystems. Best-effort: returns
# SKIPPED/FAILED on any problem so the caller falls back to the LLM maps.
_SLITHER_GRAPH_TIMEOUT = 300


def _write_mechanical_graph_json(scratch: Path, source: str,
                                 var_refs: dict, functions: dict) -> None:
    """Write the UNIFIED `_mechanical_graph.json` every provider emits and the
    coverage gate (G2) reads — ecosystem-agnostic, LLM-unclobberable.

    var_refs:   { "<qualified var>": {"bare": str, "refs": ["<descriptor>", ...]} }
    functions:  { "<qualified fn>":  {"bare": str, "loc": str, "callers": ["<descriptor>", ...],
                                      "callees": ["<descriptor>", ...] (optional, provider-dependent)} }

    A "descriptor" is a string the agent's finding prose can be matched against
    (a bare function/variable name, optionally with a `(file:line)` suffix). Each
    provider fills these from its native graph (Slither: function names; SCIP:
    locations; Move/DAML: function/choice names)."""
    import json
    try:
        (scratch / "_mechanical_graph.json").write_text(
            json.dumps({"source": source, "var_refs": var_refs, "functions": functions},
                       indent=1),
            encoding="utf-8")
    except Exception as e:
        log.warning("[mechanical_graph] json write failed (%s): %s", source, e)


def _slither_fn_loc(f, proj: Path) -> str:
    try:
        sm = f.source_mapping
        short = getattr(getattr(sm, "filename", None), "short", "") or ""
        line = (sm.lines[0] if getattr(sm, "lines", None) else 0)
        return f"{short}:L{line}" if short else f"?:L{line}"
    except Exception:
        return "?:L0"


def _bake_evm_slither_graph(scratch: Path, proj: Path) -> str:
    """Run Slither on a Solidity project and emit MECHANICAL graph artifacts.

    Produces `_mechanical_graph.json` (gate source) + state_read_map.md /
    state_write_map.md / caller_map.md (depth-agent inputs), all stamped
    `Source: slither`. Best-effort: returns WRITTEN | SKIPPED:{r} | FAILED:{r};
    on anything other than WRITTEN the caller keeps the LLM-derived maps.
    """
    import json
    try:
        from slither import Slither  # type: ignore
    except Exception as e:
        return f"SKIPPED:slither not importable ({e.__class__.__name__})"
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

    fn_loc: Dict[str, str] = {}
    var_readers: Dict[str, set] = {}
    var_writers: Dict[str, set] = {}
    fn_callees: Dict[str, set] = {}     # qualified fn -> set(qualified callee)
    bare_of: Dict[str, str] = {}        # qualified -> bare name
    try:
        for c in sl.contracts:
            if getattr(c, "is_interface", False):
                continue
            for f in getattr(c, "functions_declared", []) or []:
                fname = getattr(f, "name", "") or ""
                if not fname:
                    continue
                fkey = f"{c.name}.{fname}"
                bare_of[fkey] = fname
                fn_loc.setdefault(fkey, _slither_fn_loc(f, proj))
                for v in getattr(f, "state_variables_read", []) or []:
                    vk = f"{getattr(v.contract, 'name', c.name)}.{v.name}"
                    bare_of[vk] = v.name
                    var_readers.setdefault(vk, set()).add(fkey)
                for v in getattr(f, "state_variables_written", []) or []:
                    vk = f"{getattr(v.contract, 'name', c.name)}.{v.name}"
                    bare_of[vk] = v.name
                    var_writers.setdefault(vk, set()).add(fkey)
                for ic in (getattr(f, "internal_calls", []) or []):
                    callee = getattr(ic, "function", ic)
                    cn = getattr(callee, "name", None)
                    cc = getattr(getattr(callee, "contract", None), "name", c.name)
                    if cn:
                        fn_callees.setdefault(fkey, set()).add(f"{cc}.{cn}")
                for hc in (getattr(f, "high_level_calls", []) or []):
                    # high_level_calls entries are (Contract, Function) tuples or objects
                    callee = None
                    if isinstance(hc, (tuple, list)) and len(hc) >= 2:
                        callee = hc[1]
                    callee = getattr(callee, "function", callee)
                    cn = getattr(callee, "name", None)
                    cc = getattr(getattr(callee, "contract", None), "name", "")
                    if cn and cc:
                        fn_callees.setdefault(fkey, set()).add(f"{cc}.{cn}")
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
    for vk in set(var_readers) | set(var_writers):
        refs = var_readers.get(vk, set()) | var_writers.get(vk, set())
        var_refs[vk] = {"bare": _bare(vk), "refs": _desc(refs)}
    functions = {
        fk: {"bare": _bare(fk), "loc": fn_loc.get(fk, "?"),
             "callers": sorted(_bare(ck) for ck in fn_callers.get(fk, set())),
             "callees": sorted(_bare(ck) for ck in fn_callees.get(fk, set()))}
        for fk in fn_loc
    }
    _write_mechanical_graph_json(scratch, "slither", var_refs, functions)

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


def _bake_evm_graph(scratch: Path, proj: Path) -> str:
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
    slither = _bake_evm_slither_graph(scratch, proj)
    if slither == "WRITTEN":
        return "WRITTEN:slither"
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
    # drop symbols referenced by too many functions (noise) for the gate.
    var_refs = {
        s: {"bare": s, "refs": sorted(f"{fn} ({fn_loc.get(fn, '?')})" for fn in fns)}
        for s, fns in sym_refs.items() if 1 < len(fns) <= 25
    }
    functions = {
        fn: {"bare": fn, "loc": loc, "callers": sorted(fn_callers.get(fn, set()))}
        for fn, loc in fn_loc.items()
    }
    _write_mechanical_graph_json(scratch, source, var_refs, functions)
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


def _bake_rust_graph(scratch: Path, proj: Path) -> str:
    """Tiered Rust graph (never mock): precise SCIP when the toolchain is present
    and the index builds, else the compilation-free source parse so the
    enumeration gate still has a graph. Mirrors `_bake_evm_graph`.

    Return contract (callers may see any of): REUSED:scip | WRITTEN:scip |
    WRITTEN:rust-source (scip {status}) | FAILED:scip={status}; source={status}
    """
    scip = _bake_rust_scip(scratch, proj)
    if scip == "REUSED":
        return "REUSED:scip"
    if scip == "WRITTEN":
        return "WRITTEN:scip"
    src = _bake_rust_source_graph(scratch, proj)
    return (f"WRITTEN:rust-source (scip {scip})"
            if src == "WRITTEN" else f"FAILED:scip={scip}; source={src}")


def _bake_go_graph(scratch: Path, proj: Path) -> str:
    """Tiered Go graph (never mock): precise SCIP when scip-go is present and the
    index builds, else the compilation-free source parse.

    Return contract (callers may see any of): REUSED:scip | WRITTEN:scip |
    WRITTEN:go-source (scip {status}) | FAILED:scip={status}; source={status}
    """
    scip = _bake_go_scip(scratch, proj)
    if scip == "REUSED":
        return "REUSED:scip"
    if scip == "WRITTEN":
        return "WRITTEN:scip"
    src = _bake_go_source_graph(scratch, proj)
    return (f"WRITTEN:go-source (scip {scip})"
            if src == "WRITTEN" else f"FAILED:scip={scip}; source={src}")


def _scip_to_graph_artifacts(scratch: Path, index_path: Path, proj: Path) -> str:
    """Convert a SCIP index into the 4 graph artifacts depth agents consume."""
    try:
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

        # Build caller/callee maps from SCIP references
        callers: Dict[str, List[str]] = {}  # fn_name -> [caller locations]
        callees: Dict[str, List[str]] = {}  # fn_name -> [callee locations]
        fn_info: Dict[str, dict] = {}       # fn_name -> {path, line, kind, ...}
        state_writers: Dict[str, List[str]] = {}  # var_name -> [writer locations]

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
                path_str = defn_occ.relative_path
                fn_info[name] = {
                    "path": path_str,
                    "line": defn_occ.start_line + 1,
                    "kind": kind or "Function",
                    "signature": (info.signature if info else ""),
                }

                # Build callers from references
                refs = reader._references.get(sym, [])
                caller_locs = []
                callee_locs = []
                for ref in refs:
                    loc = f"{ref.relative_path}:L{ref.start_line + 1}"
                    caller_locs.append(loc)
                if caller_locs:
                    callers[name] = caller_locs

            # Field/variable symbols for state_write_map
            elif kind in ("Field", "Property", "Variable", ""):
                if "()" not in sym:
                    refs = reader._references.get(sym, [])
                    writer_locs = [
                        f"{ref.relative_path}:L{ref.start_line + 1}"
                        for ref in refs
                    ]
                    if writer_locs:
                        state_writers[name] = writer_locs

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
            nm = reader._extract_name_from_symbol(sym)
            if nm in fn_info:
                name_to_ref_files.setdefault(nm, set()).update(
                    r.relative_path for r in refs
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
            "| Function | File | Line | Kind | Callers | Callees |",
            "|----------|------|------|------|---------|---------|",
        ]
        for fn_name in sorted(fn_info.keys()):
            data = fn_info[fn_name]
            n_callers = len(callers.get(fn_name, []))
            n_callees = len(callees.get(fn_name, []))
            lines.append(
                f"| `{fn_name}` | {data['path']} | {data['line']} "
                f"| {data['kind']} | {n_callers} | {n_callees} |"
            )
        _write_text(scratch / "function_summary.md", "\n".join(lines))

        # Unified machine artifact for the coverage gate (G2). SCIP descriptors
        # are reference LOCATIONS (it does not resolve reader function names);
        # var_refs are all-references (reads+writes combined). The gate matches a
        # descriptor by bare name OR location against the agent's finding prose.
        var_refs = {v: {"bare": v, "refs": sorted(locs)}
                    for v, locs in state_writers.items()}
        functions = {
            fn: {"bare": fn,
                 "loc": f"{data['path']}:L{data['line']}",
                 "callers": sorted(callers.get(fn, [])),
                 "callees": sorted(callees.get(fn, []))}
            for fn, data in fn_info.items()
        }
        _write_mechanical_graph_json(scratch, "scip", var_refs, functions)

        # Record status
        status_lines = [
            f"- SCIP_RUST_BAKE: COMPLETE",
            f"- SCIP_RUST_INDEX: {index_path}",
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


# OpenGrep cross-ecosystem scanner (v2.5.0 P2)

_OPENGREP_SCAN_TIMEOUT = 300  # seconds
_OPENGREP_RULES_BASE = Path(os.path.expanduser("~/.plamen/opengrep-rules"))
_OPENGREP_RULE_REPOS = {
    "opengrep-rules": "https://github.com/opengrep/opengrep-rules.git",
    "decurity-rules": "https://github.com/Decurity/semgrep-smart-contracts.git",
    "aptos-move-rules": "https://github.com/aptos-labs/semgrep-move-rules.git",
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


# Populated by _ensure_opengrep_rules() with per-repo clone/init failure
# reasons so the caller can surface them via its SKIPPED-reason path instead
# of failing silently.
_OPENGREP_RULE_FAILURES: Dict[str, str] = {}


def _ensure_opengrep_rules() -> Dict[str, Path]:
    """Clone rule repos if missing. Returns {name: local_path} for present repos.

    Records any clone/init failures in module-level ``_OPENGREP_RULE_FAILURES``
    keyed by repo name so the caller can report 'rules unavailable: clone
    failed' rather than swallowing the error silently.
    """
    _OPENGREP_RULES_BASE.mkdir(parents=True, exist_ok=True)
    _OPENGREP_RULE_FAILURES.clear()
    available: Dict[str, Path] = {}
    for name, url in _OPENGREP_RULE_REPOS.items():
        local = _OPENGREP_RULES_BASE / name
        if local.exists() and (local / ".git").exists():
            available[name] = local
            continue
        # The rule dir may already exist as an uninitialized/partial git
        # submodule checkout (no .git). `git clone` into a non-empty existing
        # dir fails with 'destination path already exists and is not an empty
        # directory'. Try to initialize the submodule first; if that fails,
        # remove the stale/partial tree so the clone has an empty target.
        if local.exists() and not (local / ".git").exists():
            init_rc, _init_out = _run_hardened(
                ["git", "submodule", "update", "--init", str(local)],
                None, 60,
            )
            if init_rc == 0 and (local / ".git").exists():
                available[name] = local
                continue
            try:
                shutil.rmtree(local)
            except Exception as e:
                _OPENGREP_RULE_FAILURES[name] = (
                    f"stale rule dir could not be removed: "
                    f"{e.__class__.__name__}: {e}"
                )
                continue
        clone_rc, clone_out = _run_hardened(
            ["git", "clone", "--depth", "1", url, str(local)],
            None, 60,
        )
        if local.exists() and (local / ".git").exists():
            available[name] = local
        else:
            detail = (clone_out or "").strip().splitlines()
            reason = detail[-1] if detail else f"git clone exited {clone_rc}"
            _OPENGREP_RULE_FAILURES[name] = f"clone failed: {reason}"
    return available


def _run_opengrep_scan(scratch: Path, proj: Path, lang: str) -> str:
    """Run OpenGrep scan and write results to scratchpad.

    Produces: opengrep_results.sarif (raw), opengrep_findings.md (summary).
    Returns status string: WRITTEN:{n} findings | SKIPPED:{reason} | FAILED:{reason}
    """
    if not shutil.which("opengrep"):
        return "SKIPPED:opengrep not found"

    rule_dirs = _OPENGREP_LANG_RULES.get(lang, [])
    if not rule_dirs:
        return f"SKIPPED:no OpenGrep rules for {lang}"

    # Ensure rule repos are cloned
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
            return f"SKIPPED:rules unavailable: {detail}"
        return "SKIPPED:no rule directories available"

    # Check project has relevant source files
    exts = _OPENGREP_LANG_EXT.get(lang, ())
    source_files = sorted(_production_source_files(proj, exts), key=lambda p: _rel(p, proj))
    if not source_files:
        return f"SKIPPED:no production {'/'.join(exts)} files in project"
    if len(source_files) > _MAX_OPENGREP_SOURCE_FILES:
        return f"SKIPPED:{len(source_files)} production source files exceeds bounded OpenGrep prepass limit"

    sarif_path = scratch / "opengrep_results.sarif"
    cmd = ["opengrep", "scan"]
    for rp in resolved_rules:
        cmd.extend(["-f", rp])
    cmd.extend(["--sarif-output", str(sarif_path)])
    cmd.extend([_rel(p, proj) for p in source_files])

    # Hang-proof: temp-file drain + tree-kill. The prior Popen+communicate()
    # drained an OS PIPE — exactly the construct a grandchild holding the handle
    # can wedge forever; _run_hardened removes the pipe entirely.
    rc, _out = _run_hardened(cmd, proj, _OPENGREP_SCAN_TIMEOUT)
    if rc == 124:
        return f"FAILED:timeout after {_OPENGREP_SCAN_TIMEOUT}s"
    if rc == 127:
        return "SKIPPED:opengrep not found"

    # opengrep returns 0 on success (even with findings), 1 on findings in some modes
    if not sarif_path.exists() or sarif_path.stat().st_size < 10:
        if rc != 0:
            return f"FAILED:exit {rc}, no SARIF produced"
        return "WRITTEN:0 findings"

    # Parse SARIF and write human-readable summary
    finding_count = _parse_opengrep_sarif(scratch, sarif_path)

    # Record in build_status.md
    bs = scratch / "build_status.md"
    if bs.exists():
        try:
            existing = bs.read_text(encoding="utf-8", errors="replace")
            if "OPENGREP" not in existing:
                bs.write_text(
                    existing.rstrip() + "\n\n## OpenGrep\n"
                    f"- OPENGREP_AVAILABLE: true\n"
                    f"- OPENGREP_FINDINGS: {finding_count}\n"
                    f"- OPENGREP_RULES: {', '.join(resolved_rules)}\n",
                    encoding="utf-8",
                )
        except Exception:
            pass

    return f"WRITTEN:{finding_count} findings"


def _parse_opengrep_sarif(scratch: Path, sarif_path: Path) -> int:
    """Parse SARIF output and write opengrep_findings.md summary. Returns finding count."""
    import json as _json

    try:
        data = _json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
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

_SEC3_XRAY_IMAGE = "ghcr.io/sec3-product/x-ray:latest"
_SEC3_XRAY_TIMEOUT = 600  # seconds — Docker pull + LLVM analysis can be slow
_SEC3_SARIF_FILENAME = "sec3-report.sarif"


def _run_sec3_xray(scratch: Path, proj: Path) -> str:
    """Run Sec3 X-Ray scanner via Docker and write results to scratchpad.

    Produces: sec3_results.sarif (raw), sec3_findings.md (summary).
    Returns status string: WRITTEN:{n} findings | SKIPPED:{reason} | FAILED:{reason}
    """
    if not shutil.which("docker"):
        return "SKIPPED:docker not found"

    # Verify Docker is running (hang-proof probe).
    probe_rc, _probe_out = _run_hardened(["docker", "info"], None, 15)
    if probe_rc in (124, 127):
        return "SKIPPED:docker not available"
    if probe_rc != 0:
        return "SKIPPED:docker daemon not running"

    # Check project has Rust/Solana source files
    source_files = _iter_files(proj, (".rs",))
    if not source_files:
        return "SKIPPED:no .rs files in project"

    # X-Ray mounts workspace and writes SARIF to the project root
    proj_posix = str(proj).replace("\\", "/")
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{proj_posix}:/workspace",
        _SEC3_XRAY_IMAGE,
        "/workspace",
    ]

    # Hang-proof: temp-file drain + tree-kill (the X-Ray container / LLVM
    # workers can no longer wedge the parent on a held pipe handle).
    rc, _xray_out = _run_hardened(cmd, None, _SEC3_XRAY_TIMEOUT)
    if rc == 124:
        return f"FAILED:timeout after {_SEC3_XRAY_TIMEOUT}s"
    if rc == 127:
        return "SKIPPED:docker not found"

    # X-Ray writes SARIF into the workspace root
    sarif_source = proj / _SEC3_SARIF_FILENAME
    sarif_dest = scratch / "sec3_results.sarif"

    if not sarif_source.exists():
        # Some versions write to current dir or use different name
        alt_names = ["x-ray-report.sarif", "report.sarif", "xray.sarif"]
        for alt in alt_names:
            alt_path = proj / alt
            if alt_path.exists():
                sarif_source = alt_path
                break

    if not sarif_source.exists() or sarif_source.stat().st_size < 10:
        if rc != 0:
            return f"FAILED:exit {rc}, no SARIF produced"
        return "WRITTEN:0 findings"

    # Move SARIF to scratchpad
    try:
        shutil.copy2(str(sarif_source), str(sarif_dest))
        sarif_source.unlink()
    except Exception:
        pass

    if not sarif_dest.exists():
        # Fallback: if copy failed, try reading from source
        if sarif_source.exists():
            sarif_dest = sarif_source
        else:
            return "FAILED:SARIF copy failed"

    # Parse SARIF and write human-readable summary
    finding_count = _parse_sec3_sarif(scratch, sarif_dest)

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

    return f"WRITTEN:{finding_count} findings"


def _parse_sec3_sarif(scratch: Path, sarif_path: Path) -> int:
    """Parse Sec3 X-Ray SARIF output and write sec3_findings.md summary. Returns finding count."""
    import json as _json

    try:
        data = _json.loads(sarif_path.read_text(encoding="utf-8", errors="replace"))
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


def _parse_govulncheck_ndjson(raw: str) -> List[dict]:
    """Parse `govulncheck -json` NDJSON stream into structured hits.

    Each line is a `Message` with either an `osv` entry (vulnerability
    metadata) or a `finding` (a concrete call-site trace). Only `finding`
    messages are surfaced as hits -- `osv`-only messages describe the wider
    vulnerability DB and are used only to backfill the summary text. Malformed
    or partial lines are skipped rather than aborting the whole parse (the
    stream can be truncated on timeout).
    """
    import json as _json

    findings: List[dict] = []
    osv_summary: Dict[str, str] = {}
    for line in (raw or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            msg = _json.loads(line)
        except Exception:
            continue
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
    return findings


def _govulncheck_scan(proj: Path) -> Tuple[str, List[dict]]:
    """Run `govulncheck -json ./...` against a Go module.

    Returns (status, findings). status is one of:
    WRITTEN | SKIPPED:{reason} | TOOLCHAIN_UNAVAILABLE:{reason} | FAILED:{reason}
    """
    if not shutil.which("govulncheck"):
        return "TOOLCHAIN_UNAVAILABLE:govulncheck not found on PATH", []
    if not (proj / "go.mod").exists():
        return "SKIPPED:no go.mod", []

    rc, out = _run_hardened(
        ["govulncheck", "-json", "./..."], proj, _GOVULNCHECK_TIMEOUT,
    )
    if rc == 127:
        return "TOOLCHAIN_UNAVAILABLE:govulncheck not found on PATH", []
    if rc == 124:
        return f"FAILED:timeout after {_GOVULNCHECK_TIMEOUT}s", []

    findings = _parse_govulncheck_ndjson(out)
    # govulncheck exits 0 (clean) or 3 (vulnerabilities found) on a normal
    # run; any other exit code (1 = setup/analysis error, e.g. unresolved
    # module graph) with zero parsed findings is a genuine tool failure, not
    # a clean scan.
    if not findings and rc not in (0, 3):
        return f"FAILED:govulncheck exit {rc}", []
    return "WRITTEN", findings


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
    vulns = ((data.get("vulnerabilities") or {}).get("list")) or []
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


def _cargo_audit_scan(proj: Path) -> Tuple[str, List[dict]]:
    """Run `cargo audit --json` against a Rust workspace.

    Returns (status, findings). status is one of:
    WRITTEN | SKIPPED:{reason} | TOOLCHAIN_UNAVAILABLE:{reason} | FAILED:{reason}
    """
    if not shutil.which("cargo"):
        return "TOOLCHAIN_UNAVAILABLE:cargo not found on PATH", []
    if not (proj / "Cargo.toml").exists():
        return "SKIPPED:no Cargo.toml", []

    # cargo-audit is a cargo subcommand, not a standalone binary on PATH --
    # probe it explicitly so a missing subcommand degrades to
    # TOOLCHAIN_UNAVAILABLE instead of a confusing FAILED.
    probe_rc, _probe_out = _run_hardened(
        ["cargo", "audit", "--version"], proj, 30,
    )
    if probe_rc == 127:
        return "TOOLCHAIN_UNAVAILABLE:cargo not found on PATH", []
    if probe_rc != 0:
        return "TOOLCHAIN_UNAVAILABLE:cargo-audit subcommand not installed", []

    rc, out = _run_hardened(
        ["cargo", "audit", "--json"], proj, _CARGO_AUDIT_TIMEOUT,
    )
    if rc == 124:
        return f"FAILED:timeout after {_CARGO_AUDIT_TIMEOUT}s", []

    findings, parse_ok = _parse_cargo_audit_json(out)
    if not parse_ok:
        if rc == 0:
            # A clean run legitimately produces an empty vulnerabilities list;
            # tolerate a parse miss on rc==0 as "0 findings" rather than FAILED.
            return "WRITTEN", []
        return f"FAILED:cargo audit exit {rc}, no JSON produced", []
    return "WRITTEN", findings


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
        if status.startswith(("SKIPPED", "FAILED")):
            lines.append("")
            continue
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


def _run_dependency_audit_l1(scratch: Path, proj: Path, language: str) -> str:
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
        if lang in ("go", "mixed"):
            status, findings = _govulncheck_scan(proj)
            sections.append(("Go (govulncheck)", status, findings))
            statuses.append(
                f"go={status}:{len(findings)}" if status == "WRITTEN" else f"go={status}"
            )
        if lang in ("rust", "mixed"):
            status, findings = _cargo_audit_scan(proj)
            sections.append(("Rust (cargo audit)", status, findings))
            statuses.append(
                f"rust={status}:{len(findings)}" if status == "WRITTEN" else f"rust={status}"
            )
        if not sections:
            reason = f"TOOLCHAIN_UNAVAILABLE:no govulncheck/cargo-audit route for language={lang!r}"
            sections.append(("Dependency Audit", reason, []))
            statuses.append(reason)
        _write_dependency_audit_md(scratch, sections)
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


# Main entry point
def run_recon_prepass(config: dict) -> Dict[str, str]:
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
                  lambda: _bake_evm_graph(scratch, proj))
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
            _safe("scip_bake", lambda: _bake_rust_graph(scratch, proj))
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
        _safe("opengrep_scan", lambda: _run_opengrep_scan(scratch, proj, lang))

    # v2.5.0 P4: Sec3 X-Ray for Solana (Docker-based, SC only).
    # RECON-1: deferred to the driver pre-breadth hook by default (a Docker run
    # can take ~10 min and would stall the silent startup window).
    if pipeline != "l1" and lang == "solana" and run_startup_scanners:
        _safe("sec3_xray", lambda: _run_sec3_xray(scratch, proj))

    return results


if __name__ == "__main__":
    import json as _json
    import sys as _sys
    if len(_sys.argv) != 2:
        print("Usage: python recon_prepass.py <config.json>")
        _sys.exit(2)
    cfg = _json.loads(Path(_sys.argv[1]).read_text(encoding="utf-8"))
    print(_json.dumps(run_recon_prepass(cfg), indent=2))
