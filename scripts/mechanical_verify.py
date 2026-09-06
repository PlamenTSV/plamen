"""Phase 5b: Mechanical PoC verification — Python-native phase.

The driver invokes this module instead of trusting LLM-reported test outcomes.
For each `verify_*.md` in the scratchpad:

  1. Parse `Test File:` + `Command:` fields (reuses spike_mechanical_poc.py
     parser — already battle-tested by 21 unit tests).
  2. Look up the language's test runner from
     `~/.plamen/rules/language-toolchain-registry.json`.
  3. Resolve the test path under the project root.
  4. Invoke the test runner with a per-test timeout.
  5. Classify outcome: PASS | FAIL | COMPILE_FAIL | TIMEOUT | NO_TEST_MATCH |
     TOOLCHAIN_UNAVAILABLE | BUILD_FAILED | NO_TEST_FILE | EXEC_ERROR.
  6. Append (never overwrite) the mechanical verdict to the verify file:
       - `Mechanical-Verified: YES — Result: PASS` and update Evidence Tag.
       - `Mechanical-Verified: YES — Result: FAIL` (preserve LLM body for
         the Assertion Retry Protocol next pass).
       - `Mechanical-Verified: NO (reason: ...)` for non-execution outcomes.
  7. Emit `mechanical_verify_manifest.md` summarizing all per-finding outcomes.

The phase is opt-in via `MECHANICAL_VERIFY=true` env or
`config["mechanical_verify"]=True`. Default OFF for first ship.
Failure mode is DEGRADED (warning), never HALT — the LLM tag is preserved
when mechanical execution is unavailable.

Cross-ecosystem support:
  - evm     : forge test                          (registry.evm)
  - solana  : cargo test test_{id} (Anchor or native)
  - aptos   : aptos move test --filter test_{id}
  - sui     : sui move test {test_name}
  - soroban : cargo test --features testutils test_{id}
  - l1_go   : go test -run Test_{id} ./...
  - l1_rust : cargo test test_{id}

L1 entries (l1_go, l1_rust) are added to the registry at first load via
_ensure_l1_registry_entries(); the file on disk is the source of truth
for SC ecosystems and L1 is loaded as overlay.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# ITEM H2: fail-closed supply-chain gate — sibling module, stdlib only. Called
# before the per-finding test loop (which runs the TARGET repo's own
# forge/cargo/... commands) so a poisoned dependency lockfile cannot execute
# an install-time payload via the pre-warm build or the tests themselves. The
# module import (not just the two names) is kept too so tests can reach
# `supply_chain_gate.DEFAULT_IOC_DENYLIST` / `_call_offline_scanner` through
# this module's namespace for monkeypatching.
import supply_chain_gate
from supply_chain_gate import SupplyChainAbortError, gate_supply_chain
import mechanical_successor_receipts as mechanical_successor_authority
from mechanical_successor_receipts import (
    MechanicalSuccessorError,
    apply_mechanical_successor,
)
from owned_process_runner import run_owned_process as _run_owned_process

PLAMEN_RUNTIME_ASSETS = (
    {
        "kind": "runtime-data",
        "mode": "file",
        "path": "rules/language-toolchain-registry.json",
    },
)


# Per-file and per-phase budgets (overridable via env for ops scenarios).
_DEFAULT_PER_TEST_TIMEOUT_S = int(os.environ.get("PLAMEN_MECH_VERIFY_TIMEOUT", "180"))
# A1 (l1_go race-class routing): `go test -race` instruments every memory
# access, costing ~2-20x execution time and ~5-10x memory versus a plain run
# (https://go.dev/doc/articles/race_detector, https://go.dev/blog/race-detector).
# A flat multiplier on the per-test timeout is a conservative middle ground —
# enough headroom to absorb typical single-test-function overhead without
# inflating every race-class row to the pathological 20x case (which would
# blow the whole-phase budget when a queue has several race-class rows).
# Ops-overridable; gated exclusively to l1_go rows whose verification_queue
# Bug Class names a race/concurrency defect (see `_is_race_bug_class`).
_RACE_TIMEOUT_MULTIPLIER = int(
    os.environ.get("PLAMEN_MECH_VERIFY_RACE_TIMEOUT_MULTIPLIER", "3")
)
# One-time pre-warm compile budget (see _prewarm_build). Raised from 300s: a cold
# `--via-ir` dependency-heavy repo cannot compile in the old budget, so the cache
# never warmed and every PoC TIMEOUTed at [CODE-TRACE]. Default matches recon's build
# ceiling (a measured large-repo cold via-ir build runs >34min, so a 40-min budget
# was too tight for the cold-verify path). On a cache already warmed by recon this
# pre-warm is a ~seconds incremental build; the generous budget only bites when verify
# runs against a cold cache. Ops-overridable via PLAMEN_MECH_BUILD_TIMEOUT.
_DEFAULT_BUILD_TIMEOUT_S = int(os.environ.get("PLAMEN_MECH_BUILD_TIMEOUT", "5400"))
_DEFAULT_PHASE_BUDGET_S = int(os.environ.get("PLAMEN_MECH_VERIFY_BUDGET", "1800"))


@dataclass
class ExecResult:
    """One verify_*.md → test-runner execution record."""
    verify_file: str
    finding_id: str
    language: str
    test_file_resolved: Optional[str] = None
    test_function: Optional[str] = None
    test_command_used: Optional[str] = None
    # PASS | FAIL | COMPILE_FAIL | TIMEOUT | NO_TEST_MATCH |
    # TOOLCHAIN_UNAVAILABLE | BUILD_FAILED | NO_TEST_FILE | EXEC_ERROR | SKIPPED
    status: str = "SKIPPED"
    duration_s: float = 0.0
    stdout_tail: str = ""
    # Derived evidence tag the manifest recommends ([POC-PASS] / [POC-FAIL] /
    # preserve-existing). Driver decides whether to write back.
    recommended_tag: str = ""
    # A1: True only for l1_go rows where the verification_queue Bug Class
    # routed this run through `go test -race` with the raised timeout. Always
    # False for every SC language and for non-race l1_go/l1_rust rows.
    race_mode: bool = False


# ---------------------------------------------------------------------------
# Registry loading + L1 overlay
# ---------------------------------------------------------------------------


def _registry_path() -> Path:
    """Resolve language-toolchain-registry.json.

    Prefers the canonical install location (PLAMEN_HOME or ~/.plamen/rules/);
    falls back to the copy shipped beside this module in the repo (rules/, one
    level up from scripts/) when the canonical path is absent -- e.g. CI, or the
    driver run directly from a checkout that isn't symlinked into ~/.plamen.
    """
    home = Path(os.environ.get("PLAMEN_HOME", str(Path.home() / ".plamen")))
    canonical = home / "rules" / "language-toolchain-registry.json"
    if canonical.exists():
        return canonical
    repo = Path(__file__).resolve().parent.parent / "rules" / "language-toolchain-registry.json"
    if repo.exists():
        return repo
    return canonical  # let _load_registry handle the missing-file fallback


def _load_registry(custom_path: Optional[Path] = None) -> dict:
    """Load registry JSON. L1 entries are overlay-injected at load time."""
    path = custom_path or _registry_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"version": 2, "languages": {}}
    _ensure_l1_registry_entries(data)
    return data


def _ensure_l1_registry_entries(reg: dict) -> None:
    """Inject l1_go / l1_rust into the registry if not present.

    L1 entries are kept as runtime overlay (not on-disk) for two reasons:
      1. The SC-only registry file is shared across all 5 SC ecosystems and
         doesn't conceptually own L1 client testing.
      2. L1 mode currently hard-codes commands in `prompts/l1/*` — this
         consolidates them under a single dispatch surface without touching
         the L1 prompts.
    """
    langs = reg.setdefault("languages", {})
    if "l1_go" not in langs:
        langs["l1_go"] = {
            "build_command": "go build ./...",
            "test_command": "go test -run {test_function} -v ./...",
            "test_filter_mode": "go_run_regex",
            "evidence_tags": ["POC-PASS", "POC-FAIL", "CODE-TRACE"],
            # A3: template-registration only. `command`/`output_file` mirror the
            # authoritative Go native-fuzz form documented in
            # prompts/l1/v2/phase5-verification-prompt.md
            # ("go test -fuzz Fuzz_{test_name} -fuzztime 5m ./..."). The fuzz
            # re-run is NOT wired into the mechanical execution loop here —
            # that is a deferred item with its own outcome vocabulary.
            "fuzz_engines": [
                {
                    "name": "go_native_fuzz",
                    "command": "go test -fuzz {test_function} -fuzztime 5m ./...",
                    "template_path": "prompts/l1/phase4b-invariant-fuzz-go.md",
                    "output_file": "go_fuzz_findings.md",
                },
            ],
        }
    if "l1_rust" not in langs:
        langs["l1_rust"] = {
            "build_command": "cargo build --all-targets",
            "test_command": "cargo test {test_function} -- --nocapture",
            "test_filter_mode": "cargo_name_filter",
            "test_prewarm_command": "cargo test --no-run",
            "features": [],
            "evidence_tags": ["POC-PASS", "POC-FAIL", "CODE-TRACE"],
            # A3: template-registration only (see l1_go comment above). Commands
            # mirror prompts/l1/v2/phase5-verification-prompt.md's documented
            # preferred/fallback pair: cargo-fuzz (nightly, requires a target
            # under fuzz/fuzz_targets/) with a proptest fallback on stable.
            "fuzz_engines": [
                {
                    "name": "cargo_fuzz",
                    "command": "cargo +nightly fuzz run fuzz_{test_function}",
                    "template_path": "prompts/l1/phase4b-invariant-fuzz-rust.md",
                    "output_file": "cargo_fuzz_findings.md",
                },
                {
                    "name": "proptest",
                    "command": "cargo test test_prop_{test_function} -- --nocapture",
                    "output_file": "proptest_findings.md",
                },
            ],
        }


def _toolchain_binary_for(language: str) -> str:
    """First command word from the build/test command (used for shutil.which)."""
    table = {
        "evm": "forge",
        "solana": "cargo",
        "aptos": "aptos",
        "sui": "sui",
        "soroban": "cargo",
        "l1_go": "go",
        "l1_rust": "cargo",
    }
    return table.get(language, "")


# ---------------------------------------------------------------------------
# Reuse parser + path resolution from the spike script
# ---------------------------------------------------------------------------


def _spike_module():
    """Lazy-import the spike to reuse parse_verify_file + classify_match."""
    import importlib
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    return importlib.import_module("spike_mechanical_poc")


# ---------------------------------------------------------------------------
# Command-template substitution
# ---------------------------------------------------------------------------


def _inject_cargo_exact(argv: list[str]) -> list[str]:
    """Add libtest `--exact` so a cargo test-name filter matches ONE test.

    Without it `cargo test test_x` is a substring filter that also runs
    `test_x_helper`; a sibling FAIL would mis-attribute to this finding (the
    non-EVM analogue of the EVM VERIF-5 AMBIGUOUS isolation guard).
    `--exact` is a libtest harness flag, so it must follow the `--` separator.
    """
    if "--exact" in argv:
        return argv
    if "--" in argv:
        i = argv.index("--")
        return argv[: i + 1] + ["--exact"] + argv[i + 1:]
    return argv + ["--", "--exact"]


# ---------------------------------------------------------------------------
# A1: l1_go `go test -race` routing (race/concurrency Bug-Class rows only)
# ---------------------------------------------------------------------------

# Mechanism-only vocabulary (Part 0: no protocol/codebase proper nouns) — the
# same generic concurrency-defect terms `classify_poc_testability` in
# plamen_parsers.py already recognizes as its `structural_patterns` race
# family, so this gate rides the pipeline's existing bug-class vocabulary
# instead of inventing a new one.
_RACE_BUG_CLASS_KEYWORDS: tuple[str, ...] = (
    "race", "concurrency", "concurrent", "data race", "goroutine leak",
    "deadlock", "atomicity violation", "toctou",
)


def _is_race_bug_class(bug_class: str) -> bool:
    """True when a verification_queue Bug Class names a race/concurrency defect.

    Pure keyword match, case-insensitive substring — mirrors the tolerance
    style already used for header-alias matching in plamen_parsers.py. Never
    raises: a non-string or empty input simply returns False (safe default —
    the finding runs the plain, already-tested `go test` command).
    """
    bc = (bug_class or "").lower()
    return any(kw in bc for kw in _RACE_BUG_CLASS_KEYWORDS)


def _inject_go_race_flag(argv: list[str]) -> list[str]:
    """Insert `-race` right after the `test` subcommand token, once.

    `go test -race -run ^Fn$ -v ./...` — race is a build/test flag that
    `go help testflag` documents as combinable with `-run`; inserting it
    immediately after the `test` token keeps the rendered command readable
    and matches typical `go test -race` usage in Go docs/examples.
    """
    if "-race" in argv:
        return argv
    try:
        i = argv.index("test")
    except ValueError:
        return argv + ["-race"]
    return argv[: i + 1] + ["-race"] + argv[i + 1:]


def _parsers_module():
    """Lazy-import plamen_parsers (read-only reuse, never modified here).

    Only reached for l1_go's race-class gate (`_load_race_bug_class_map`):
    reuses `parse_verification_queue_rows`, the same canonical reader the
    rest of the pipeline uses for `verification_queue.md` (JSON-sidecar
    preferred, markdown-table fallback). Isolated as its own lazy import
    (mirrors `_spike_module()`) so the SC languages' import graph is
    completely unaffected — this module is only ever touched when
    language == "l1_go".
    """
    import importlib
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    return importlib.import_module("plamen_parsers")


def _load_race_bug_class_map(scratchpad: Path, lang: str) -> dict[str, str]:
    """Best-effort `finding_id -> Bug Class` lookup, gated to l1_go only.

    SC ISOLATION: returns `{}` immediately for every language other than
    `l1_go` — no plamen_parsers import, no verification_queue read, so the
    SC verify path (evm/solana/aptos/sui/soroban/daml) and non-race l1_go/
    l1_rust rows are byte-identical to before this function existed.

    HALTLESS: never raises. A missing scratchpad, missing
    verification_queue.md, or any parser failure degrades to an empty map —
    which simply means no row gets the `-race` treatment (the existing,
    already-tested plain `go test` command runs instead).
    """
    if lang != "l1_go":
        return {}
    try:
        parsers = _parsers_module()
        rows = parsers.parse_verification_queue_rows(Path(scratchpad))
    except Exception:
        return {}
    out: dict[str, str] = {}
    try:
        for row in rows or []:
            fid = str(row.get("finding id", "") or "").strip().upper()
            bc = str(row.get("bug class", "") or "").strip()
            if fid:
                out[fid] = bc
    except Exception:
        return {}
    return out


def _format_test_command(template: str, test_function: str,
                        test_file: Optional[str],
                        language: Optional[str] = None) -> list[str]:
    """Render the registry's test_command into an argv list.

    Substitution tokens:
      {ID}            — finding ID (legacy; rarely needed)
      {id}            — same as {ID}, lowercased
      {test_function} — extracted from verify file's `Test File` or `Command`
      {test_name}     — alias for test_function (sui uses {test_name})
      {test_path}     — relative path to the test file under project root

    v2.8.16 Phase 1 (must-fix #1): apply per-ecosystem EXACT-name isolation so
    a `[POC-PASS]` can only be attributed to the finding's own test:
      - cargo (solana/soroban/l1_rust): append libtest `--exact`
      - go (l1_go): anchor the `-run` regex as `^fn$`
      - aptos `--filter` / sui positional have no exact flag (substring; the
        driver-dictated unique function name is the isolation in practice).
    """
    lang = (language or "").lower().strip()
    # l1_go: anchor the -run regex to the exact function name.
    # Guard against a None test_function: str.replace() rejects a None
    # replacement ("replace() argument 2 must be str, not None"), which on a
    # finding with no dictated test name crashed the whole sc_mechanical_verify
    # phase (observed: 1 degraded phase on DFlow). Falling back to "" localizes
    # the failure to that one finding (empty test name -> its PoC simply can't
    # run) instead of degrading the entire phase. All downstream uses of
    # test_function (fn_lower, the test_{id} substitution, cargo --exact) are
    # already None-guarded.
    fn_sub = test_function or ""
    if lang == "l1_go" and test_function and not (
        test_function.startswith("^") and test_function.endswith("$")
    ):
        fn_sub = f"^{test_function}$"
    cmd = template.replace("{test_function}", fn_sub)
    cmd = cmd.replace("{test_name}", fn_sub)
    # Legacy {ID} / {id}: extract suffix after leading 'test_' if present.
    # Use a leading-prefix strip (NOT global replace) so internal 'test_'
    # substrings — e.g. 'test_a_test_b' — are preserved.
    fn_lower = (test_function or "").lower()
    id_suffix = fn_lower[5:] if fn_lower.startswith("test_") else fn_lower
    cmd = cmd.replace("{ID}", id_suffix.upper())
    # Intercept the literal `test_{id}` token with the dictated function name
    # verbatim BEFORE the {id} substitution, so non-`test_`-prefixed names
    # (e.g. aptos 'overflow_check') filter on the real name rather than
    # 'test_overflow_check'. Guarded on a non-empty test_function.
    if test_function:
        cmd = cmd.replace("test_{id}", test_function)
    cmd = cmd.replace("{id}", id_suffix)
    if test_file:
        norm_file = test_file.replace("\\", "/")
        cmd = cmd.replace("{test_path}", norm_file)
        # DAML: `daml test --files {file}` has no per-test name filter
        # (test_filter_mode == "daml_no_filter"). `daml test` runs every
        # in-scope Script(); isolation is file-scoped, so the {file} token is
        # the per-PoC isolated file path. NEVER attempt --match-test/--filter.
        cmd = cmd.replace("{file}", norm_file)
    # Tokenize on whitespace (registry commands don't contain quoted args)
    argv = cmd.split()
    if lang in ("solana", "soroban", "l1_rust") and test_function:
        argv = _inject_cargo_exact(argv)
    return argv


# ---------------------------------------------------------------------------
# Build-root resolution
#
# The audit's `project_root` is the audit *scope* directory — often a
# subdirectory like `omni-chain-contracts/contracts`. But the build manifest
# (foundry.toml / Cargo.toml / Move.toml / go.mod) and the test directory
# (`test/`, `tests/`) live at the *project* root, which is frequently the
# parent. Resolving test files against the scope dir is what produced
# 142/142 NO_TEST_FILE on a prior audit. _find_build_root walks UP from
# project_root to the directory that actually owns the build.
# ---------------------------------------------------------------------------


_BUILD_MANIFESTS: dict[str, tuple[str, ...]] = {
    "evm": ("foundry.toml", "hardhat.config.ts", "hardhat.config.js"),
    "solana": ("Cargo.toml", "Anchor.toml"),
    "soroban": ("Cargo.toml",),
    "aptos": ("Move.toml",),
    "sui": ("Move.toml",),
    "l1_go": ("go.mod",),
    "l1_rust": ("Cargo.toml",),
    "daml": ("daml.yaml", "Daml.toml"),
}


_BUILD_SCAN_SKIP_DIRS = {
    "node_modules", "target", ".git", "out", "cache", "artifacts",
    "dist", "build", ".venv", "venv", "__pycache__", "lib", ".cargo",
}


_RECON_BUILD_ROOT_RE = re.compile(
    r"(?im)^\s*\**\s*Chosen\s+build\s+root\s*\**\s*:\s*`?\s*([^`\n]+?)\s*`?\s*$"
)


def _read_recon_build_root(scratchpad, language: str) -> Optional[Path]:
    """Honor recon's authoritative chosen build root from build_status.md.

    Recon (phase1 TASK 1) resolves the directory that owns the real build
    manifest — frequently a sibling/ancestor of the source-only audit scope
    dir that the heuristic upward-walk + tight neighbourhood scan cannot
    reach. Recon records it in build_status.md as a line:

        **Chosen build root**: `<absolute path>`

    Returns the resolved path ONLY if it exists AND actually owns a manifest
    for `language` (so a stale/wrong recon line degrades safely to the
    heuristic). Returns None when:
      - scratchpad/build_status.md is missing,
      - no `Chosen build root` line is present,
      - the value is the explicit `(none)` token,
      - the path does not exist or owns no matching manifest.
    """
    if scratchpad is None:
        return None
    try:
        status_path = Path(scratchpad) / "build_status.md"
        if not status_path.exists():
            return None
        text = status_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _RECON_BUILD_ROOT_RE.search(text)
    if not m:
        return None
    raw = (m.group(1) or "").strip().strip("`").strip()
    if not raw or raw.lower() in ("(none)", "none"):
        return None
    _lang = (language or "").lower().strip()
    if _lang == "go":
        _lang = "l1_go"
    elif _lang == "rust":
        _lang = "l1_rust"
    manifests = _BUILD_MANIFESTS.get(_lang, ("foundry.toml",))
    try:
        cand = Path(raw).resolve()
    except OSError:
        return None
    if not cand.is_dir():
        return None
    if any((cand / man).exists() for man in manifests):
        return cand
    return None


def _find_build_root(project_root: Path, language: str) -> Path:
    """Resolve the directory that owns the build manifest.

    Order (v2.8.16 Phase 1, must-fix #6):
      1. Walk UP from project_root (project_root + 5 ancestors).
      2. Bounded sibling/descendant scan (≤2 levels under each ancestor),
         short-circuiting on the first manifest match — the audit scope dir is
         frequently a SIBLING of the build root (e.g. an `interfaces/` scope
         beside a `contracts/` Foundry project), which an upward-only walk can
         never reach.
    Falls back to project_root itself if no manifest is found (degradation,
    not failure — the original behavior).
    """
    _lang = (language or "").lower().strip()
    if _lang == "go":
        _lang = "l1_go"
    elif _lang == "rust":
        _lang = "l1_rust"
    manifests = _BUILD_MANIFESTS.get(_lang, ("foundry.toml",))
    root = Path(project_root).resolve()

    def _has_manifest(d: Path) -> bool:
        return any((d / man).exists() for man in manifests)

    # 1. Upward walk (project_root + 5 ancestors).
    cur = root
    for _ in range(6):
        if _has_manifest(cur):
            return cur
        if cur.parent == cur:
            break
        cur = cur.parent

    # 2. Conservative neighbourhood scan. A *wrong* build root yields a false
    #    verdict (worse than no root → safe degrade), so the scan is deliberately
    #    tight: only project_root's own subtree (scope ABOVE the build root) and
    #    its IMMEDIATE siblings (scope and build root share one parent). Deeper
    #    ancestor scanning is NOT done here — that is the job of the authoritative
    #    recon-emitted build_root, not an unbounded heuristic that could match an
    #    unrelated project. Short-circuits on the first manifest match.
    def _scan(base: Path, depth: int) -> Optional[Path]:
        try:
            children = [c for c in base.iterdir() if c.is_dir()]
        except OSError:
            return None
        for c in children:
            if c.name in _BUILD_SCAN_SKIP_DIRS or c.name.startswith("."):
                continue
            if _has_manifest(c):
                return c
            if depth > 1:
                found = _scan(c, depth - 1)
                if found is not None:
                    return found
        return None

    # 2a. project_root's own subtree (≤2 levels): scope dir sits above build root.
    found = _scan(root, 2)
    if found is not None:
        return found
    # 2b. immediate siblings only (≤1 level): scope and build root share a parent.
    parent = root.parent
    if parent != root:
        try:
            for sib in parent.iterdir():
                if sib == root or not sib.is_dir():
                    continue
                if sib.name in _BUILD_SCAN_SKIP_DIRS or sib.name.startswith("."):
                    continue
                if _has_manifest(sib):
                    return sib
        except OSError:
            pass

    return root


# ---------------------------------------------------------------------------
# Per-finding test runner
# ---------------------------------------------------------------------------


_RGLOB_MAX_DEPTH = 6


def _bounded_rglob_unique(root: Path, name: str,
                         max_depth: int = _RGLOB_MAX_DEPTH) -> Optional[Path]:
    """Search for a uniquely-named file under root, bounded by directory
    depth and result count.

    Prunes common non-source directories (`_BUILD_SCAN_SKIP_DIRS`) DURING the
    walk (not just after) so a huge `target/`/`node_modules/` subtree can't
    blow up traversal cost, and stops descending past `max_depth`. Returns the
    sole match, or None on 0 or >=2 matches (ambiguous — never guess a
    resolution the verifier didn't actually run against) or any OSError.
    """
    try:
        root_resolved = Path(root).resolve()
        if not root_resolved.is_dir():
            return None
    except OSError:
        return None
    base_depth = len(root_resolved.parts)
    matches: list[Path] = []
    try:
        for dirpath, dirnames, filenames in os.walk(str(root_resolved)):
            depth = len(Path(dirpath).parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []  # stop descending further
                continue
            dirnames[:] = [
                d for d in dirnames
                if d not in _BUILD_SCAN_SKIP_DIRS and not d.startswith(".")
            ]
            if name in filenames:
                matches.append(Path(dirpath) / name)
                if len(matches) > 1:
                    return None  # ambiguous, short-circuit
    except OSError:
        return None
    return matches[0] if len(matches) == 1 else None


def _resolve_test_path_for(probe, build_root: Path,
                          project_root: Optional[Path] = None) -> Optional[Path]:
    """Resolve a test file path under the build root, trying multiple anchors.

    Tries the build root first (where `test/` normally lives), then the
    narrower audit scope dir as a fallback. Anchors tried per root, in order:
      1. the raw captured path verbatim (works once the cargo test-path regex
         captures "<crate-dir>/tests/foo.rs" and that literally matches a
         workspace member directory under the root);
      2. the bare basename under common test-dir conventions (`test/`,
         `tests/`, `src/`, `sources/tests/`, `trident-tests/`);
      3. a crate-prefix reconstruction: the raw path with its FIRST segment
         stripped, in case the captured crate-dir prefix doesn't line up 1:1
         with the on-disk member (deeper nesting, differently-named dir);
      4. LAST RESORT (all roots exhausted): a bounded, unique-match-only
         rglob(basename) search — trusted ONLY when it finds exactly one
         file. 0 or >1 matches means "don't guess" -> None (NO_TEST_FILE).
    """
    if not probe.test_file_resolved:
        return None
    raw = probe.test_file_resolved.replace("\\", "/")
    name = Path(raw).name
    roots = [build_root]
    if project_root is not None and Path(project_root).resolve() != Path(build_root).resolve():
        roots.append(Path(project_root))

    parts = Path(raw).parts
    tail = Path(*parts[1:]) if len(parts) > 2 else None

    for root in roots:
        candidates = [
            root / raw,
            root / name,
            root / "test" / name,
            root / "tests" / name,
            root / "src" / name,
            root / "sources" / "tests" / name,
            root / "trident-tests" / name,
        ]
        if tail is not None:
            candidates.append(root / tail)
        for c in candidates:
            try:
                if c.exists() and c.is_file():
                    return c
            except OSError:
                continue

    for root in roots:
        found = _bounded_rglob_unique(root, name)
        if found is not None:
            return found
    return None


_MATCH_TEST_CMD_RE = re.compile(r"--match-test\s+[\"']?([A-Za-z0-9_]+)")
_MATCH_CONTRACT_CMD_RE = re.compile(r"--match-contract\s+[\"']?([A-Za-z0-9_]+)")


def _evm_forge_filter(probe, rel_path: str) -> list[str]:
    """Pick the narrowest forge filter available.

    Prefer --match-test (a single function), then --match-contract (the test
    contract), then --match-path (the whole file — always works once the file
    is resolved, even when the verify file gave no function/contract name).
    """
    cmd = probe.test_command or ""
    m = _MATCH_TEST_CMD_RE.search(cmd)
    if m:
        return ["--match-test", m.group(1)]
    if getattr(probe, "test_function", None):
        return ["--match-test", probe.test_function]
    m = _MATCH_CONTRACT_CMD_RE.search(cmd)
    if m:
        return ["--match-contract", m.group(1)]
    return ["--match-path", rel_path]


_FOUNDRY_PROFILE_CMD_RE = re.compile(r"FOUNDRY_PROFILE\s*=\s*[\"']?([A-Za-z0-9_]+)")
# `[profile.<name>]` ... `test = "<dir>"` (and `src`/`test_dir` aliases).
_TOML_PROFILE_HDR_RE = re.compile(r"(?m)^\s*\[profile\.([A-Za-z0-9_]+)\]\s*$")
_TOML_TEST_DIR_RE = re.compile(
    r"(?m)^\s*(?:test|test_dir)\s*=\s*[\"']([^\"']+)[\"']")


def _resolve_foundry_profile(probe, build_root, resolved) -> Optional[str]:
    """Recover the FOUNDRY_PROFILE the verifier's PoC actually ran under.

    The verifier records its working command (e.g. `FOUNDRY_PROFILE=poc forge
    test ...`) on the probe; the mechanical re-run reconstructs its own argv and
    used to drop that env var, so forge fell back to `[profile.default]` whose
    `test` dir often does NOT contain the PoCs (custom profiles route tests to a
    non-default dir). That silently turned a passing suite into mass
    NO_TEST_FILE/FAIL, cascading into spurious assertion + INFLATED_PROSE
    demotions.

    Resolution order:
      1. `FOUNDRY_PROFILE=<x>` explicitly recorded in the verify file's Command.
      2. foundry.toml auto-detect: the non-default profile whose `test` dir
         actually contains the resolved test file (works even when the verifier
         never recorded the env var).
    Returns the profile name, or None to run under the default profile."""
    cmd = getattr(probe, "test_command", "") or ""
    m = _FOUNDRY_PROFILE_CMD_RE.search(cmd)
    if m:
        return m.group(1)
    try:
        toml = (Path(build_root) / "foundry.toml").read_text(encoding="utf-8")
    except Exception:
        return None
    try:
        rel = str(Path(resolved).resolve().relative_to(Path(build_root).resolve()))
    except Exception:
        rel = str(resolved)
    rel = rel.replace("\\", "/")
    # Walk each [profile.<name>] block; map name -> its test dir.
    hdrs = list(_TOML_PROFILE_HDR_RE.finditer(toml))
    for i, h in enumerate(hdrs):
        name = h.group(1)
        block = toml[h.end():(hdrs[i + 1].start() if i + 1 < len(hdrs) else len(toml))]
        tm = _TOML_TEST_DIR_RE.search(block)
        if not tm:
            continue
        test_dir = tm.group(1).strip("/").replace("\\", "/")
        if name != "default" and (rel.startswith(test_dir + "/") or rel == test_dir):
            return name
    return None


_CARGO_PKG_RE = re.compile(
    r"(?:^|\s)(?:-p|--package)(?:[=\s]+)([A-Za-z0-9_][A-Za-z0-9_-]*)")
# Generic tokens that are NOT real test-function names — typically mis-extracted
# from a file stem (`test.rs`, `lib.rs`) or a module path. A cargo
# `--exact <token>` on any of these matches ZERO tests → false NO_TEST_MATCH/FAIL.
_CARGO_BOGUS_FILTER = frozenset(
    {"test", "tests", "mod", "lib", "main", "src", "it", "unit", "integration"})


def _resolve_cargo_package(probe, resolved: Optional[Path] = None,
                          build_root: Optional[Path] = None) -> Optional[str]:
    """Recover the `-p <package>` the verifier's PoC ran under (mirrors
    `_resolve_foundry_profile` for EVM).

    The registry cargo template carries no package selector, so on a multi-member
    workspace (e.g. `contracts/registry`, `contracts/factory`, …) the mechanical
    re-run executes at the workspace root and cannot resolve a member's test →
    mass NO_TEST_FILE/FAIL, and every `[POC-PASS]` fails to graduate.

    Resolution order:
      1. `-p <pkg>` / `--package <pkg>` explicitly recorded in the verifier's
         Command field (read back verbatim from `probe.test_command`).
      2. `probe.package` — the same Command field, parsed once by the spike
         parser's Command-hint extraction (a fallback for a flag spelling the
         regex above misses, e.g. `--package=foo`).
      3. The workspace-member directory name: the FIRST path segment of the
         RESOLVED test file relative to the build root. Only used when it is
         not a bogus generic directory name (`tests`, `src`, …) — a plain
         `tests/foo.rs` sitting directly at the workspace root has no member
         segment to give.
    Returns the package name, or None."""
    cmd = getattr(probe, "test_command", "") or ""
    m = _CARGO_PKG_RE.search(cmd)
    if m:
        return m.group(1)
    hint = getattr(probe, "package", None)
    if hint:
        return hint
    if resolved is not None and build_root is not None:
        try:
            rel = Path(resolved).resolve().relative_to(Path(build_root).resolve())
        except (ValueError, OSError):
            rel = None
        if rel is not None and len(rel.parts) > 1:
            member = rel.parts[0]
            if member.lower() not in _CARGO_BOGUS_FILTER and member not in _BUILD_SCAN_SKIP_DIRS:
                return member
    return None


# Feature-validity gate: cargo hard-errors ("package X does not contain this
# feature: Y") whenever a `--features Y` names a feature the target package does
# not DECLARE in its own `[features]` table. Soroban contract crates commonly
# declare NO features and obtain testutils APIs via
# `soroban-sdk = { features=["testutils"] }` (available under cfg(test) with no
# crate-level flag) — so blindly unioning the registry-default `testutils` fails
# the whole invocation, including tests that pass without any feature flag. We
# therefore only emit a feature the resolved package actually declares.
_PKG_FEATURES_CACHE: dict = {}
_TOML_SECTION_RE = re.compile(r"(?m)^\s*\[[^\]]+\]\s*$")
_CARGO_FEAT_KEY_RE = re.compile(r"(?m)^\s*([A-Za-z0-9_][A-Za-z0-9_-]*)\s*=")


def _toml_section_block(text: str, header_re: re.Pattern) -> str:
    m = header_re.search(text)
    if not m:
        return ""
    start = m.end()
    nxt = _TOML_SECTION_RE.search(text, start)
    return text[start:(nxt.start() if nxt else len(text))]


def _cargo_toml_package_name(text: str) -> Optional[str]:
    block = _toml_section_block(text, re.compile(r"(?m)^\s*\[package\]\s*$"))
    nm = re.search(r'(?m)^\s*name\s*=\s*"([^"]+)"', block)
    return nm.group(1) if nm else None


def _cargo_toml_declared_features(text: str) -> set:
    block = _toml_section_block(text, re.compile(r"(?m)^\s*\[features\]\s*$"))
    return set(_CARGO_FEAT_KEY_RE.findall(block)) if block else set()


def _workspace_package_features(build_root: Optional[Path]) -> dict:
    """Map every workspace member's package name -> the set of features it
    DECLARES in its own `[features]` table (empty set when it declares none).
    Bounded Cargo.toml scan under build_root, cached per build_root. Never raises.
    """
    if not build_root:
        return {}
    try:
        key = str(Path(build_root).resolve())
    except Exception:
        return {}
    cached = _PKG_FEATURES_CACHE.get(key)
    if cached is not None:
        return cached
    out: dict = {}
    try:
        n = 0
        for ct in Path(build_root).rglob("Cargo.toml"):
            if any(p in _BUILD_SCAN_SKIP_DIRS for p in ct.parts):
                continue
            n += 1
            if n > 800:
                break
            try:
                txt = ct.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            name = _cargo_toml_package_name(txt)
            if name:
                out[name] = _cargo_toml_declared_features(txt)
    except Exception:
        pass
    _PKG_FEATURES_CACHE[key] = out
    return out


def _apply_cargo_workspace_fixups(argv: list, probe, language: Optional[str] = None,
                                 resolved: Optional[Path] = None,
                                 build_root: Optional[Path] = None) -> list:
    """Repair the mechanical-cargo mis-reconstructions that made every
    workspace-member Soroban/Rust PoC read as NO_TEST_FILE/FAIL:
      (1) thread the verifier's `-p <package>` back in (registry template omits
          it, and it is derivable from the resolved test path's workspace-member
          segment even when the verifier's Command didn't record one), so a
          workspace-member test resolves — WITHOUT descending `cwd` into the
          member (stays at the workspace root, per _run_test_for_finding);
      (2) drop a phantom `<generic> -- --exact` filter when the substituted test
          name is a non-test token (e.g. `test` extracted from `test.rs`) — run
          the package suite as the verifier actually did, instead of
          `--exact test` which matches nothing;
      (3) reconcile `--features` as a UNION of the registry template's own
          default feature set, whatever the verifier's recorded Command named,
          and the probe's parsed feature hints — instead of silently STRIPPING
          the registry default (e.g. Soroban's `testutils`) whenever the
          verifier's Command happened not to repeat it, which broke compiling
          any `#[cfg(feature = "testutils")]`-gated test module. `testutils`
          is never emitted for solana/l1_rust (soroban-only feature; those
          registry templates never define it).
    Never raises; returns argv unchanged on any parse issue."""
    try:
        out = list(argv)
        # (2) The registry template appends `-- --exact <fn>` for isolation, but
        # the extracted filter is a BARE function name while Rust tests are
        # module-nested (`mod xxx_tests { #[test] fn poc_… }`). `--exact
        # <bare_fn>` then matches NOTHING (cargo `--exact` needs the full
        # `mod::fn` path) → NO_TEST_MATCH. Cargo's SUBSTRING match on the unique
        # function name isolates to that one test in practice (`N filtered out`),
        # so drop the `-- --exact` tail. If the filter token is itself a bogus
        # generic (mis-extracted from `test.rs`), also drop it → package suite.
        if "--" in out:
            sep = out.index("--")
            filt_idx = None
            for i in range(sep - 1, 0, -1):
                if out[i].startswith("-"):
                    continue
                if i <= 1:  # position 1 is the `test` subcommand, never a filter
                    break
                filt_idx = i
                break
            bogus = (filt_idx is not None
                     and out[filt_idx].lower() in _CARGO_BOGUS_FILTER)
            del out[sep:]              # drop `-- --exact …` (substring is isolation)
            if bogus and filt_idx is not None:
                del out[filt_idx]      # also drop the bogus filter → package suite
        # (3) Union the registry template's own default `--features` (if any),
        # the verifier's recorded Command `--features`, and the probe's parsed
        # feature hints. NEVER let one side's absence erase another side's
        # presence — that is the exact bug that used to strip `testutils`
        # whenever the verifier's Command happened not to repeat it (not every
        # workspace member DEFINES that feature either, so `testutils` is
        # filtered out for solana/l1_rust below).
        lang = (language or "").lower().strip()
        default_feat = None
        if "--features" in out:
            fi = out.index("--features")
            if fi + 1 < len(out):
                default_feat = out[fi + 1]
                del out[fi:fi + 2]
            else:
                del out[fi:fi + 1]
        rec = getattr(probe, "test_command", "") or ""
        rec_feat_m = re.search(r"--features(?:[=\s]+)(\S+)", rec)
        rec_feats = rec_feat_m.group(1).split(",") if rec_feat_m else []
        probe_feats = list(getattr(probe, "features", None) or [])
        union: list = []
        for f in ([default_feat] if default_feat else []) + rec_feats + probe_feats:
            f = (f or "").strip()
            if not f:
                continue
            if lang in ("solana", "l1_rust") and f == "testutils":
                continue  # soroban-only feature; never emit for these ecosystems
            if f not in union:
                union.append(f)
        # (1) resolve the target package FIRST — feature validity is per-package.
        pkg = _resolve_cargo_package(probe, resolved, build_root)
        # Feature-validity gate: keep only features the resolved package actually
        # DECLARES in its own [features] table; drop the rest (incl. the
        # registry-default testutils) rather than emit an invalid `--features`
        # that fails the entire invocation. A crate with no [features] (the common
        # Soroban case) → all dropped → runs exactly as the PASSing PoCs did.
        if union:
            declared = (_workspace_package_features(build_root).get(pkg, set())
                        if (pkg and build_root is not None) else set())
            union = [f for f in union if f in declared]
        if union:
            try:
                ti2 = out.index("test")
                out[ti2 + 1:ti2 + 1] = ["--features", ",".join(union)]
            except ValueError:
                out.extend(["--features", ",".join(union)])
        # inject `-p <pkg>` right after the `test` subcommand if absent.
        has_pkg = any(
            t in ("-p", "--package") or t.startswith("--package=") for t in out)
        if pkg and not has_pkg:
            try:
                ti = out.index("test")
                out[ti + 1:ti + 1] = ["-p", pkg]
            except ValueError:
                out.extend(["-p", pkg])
        return out
    except Exception:
        return argv


def _classify_evm_outcome(rc: int, stdout: str, isolated: bool = True) -> str:
    """Classify `forge test` output.

    VERIF-5: when the run was NOT isolated to the finding's own test (i.e. a
    whole-file `--match-path` fallback because the verify file named no test/
    contract), a result containing BOTH `[PASS]` and `[FAIL]` cannot be
    attributed to this finding -- an unrelated test in the same file may have
    failed. Return AMBIGUOUS so the integrity/demotion layer does NOT treat it
    as a real mechanical FAIL (which could wrongly demote a true positive).
    """
    s = stdout
    if "Compiler run failed" in s or re.search(r"^Error \(", s, re.MULTILINE):
        return "COMPILE_FAIL"
    if "No tests match" in s or "no tests to run" in s.lower():
        return "NO_TEST_MATCH"
    if not isolated and "[PASS]" in s and ("[FAIL" in s or re.search(r"Suite result:\s*FAILED", s)):
        return "AMBIGUOUS"
    if rc == 0 and "[PASS]" in s:
        return "PASS"
    if "[FAIL" in s or re.search(r"Suite result:\s*FAILED", s):
        return "FAIL"
    if rc != 0:
        return "FAIL"
    if "[PASS]" in s:
        return "PASS"
    return "FAIL"


def _run_test_for_finding(verify_path: Path, build_root: Path, language: str,
                          registry: dict, per_test_timeout_s: int,
                          project_root: Optional[Path] = None,
                          bug_class_map: Optional[dict[str, str]] = None) -> ExecResult:
    """Execute one verify file's PoC and classify the outcome."""
    spike = _spike_module()
    probe = spike.parse_verify_file(verify_path, language=language)
    result = ExecResult(
        verify_file=verify_path.name,
        finding_id=probe.finding_id,
        language=language,
        test_file_resolved=probe.test_file_resolved,
        test_function=probe.test_function,
    )

    # Short-circuit: no test file referenced at all → record + skip.
    # NOTE: a missing test_function is NOT a skip — we run by --match-path.
    if not probe.test_file_resolved:
        result.status = "NO_TEST_FILE"
        return result

    # Toolchain availability
    bin_name = _toolchain_binary_for(language)
    if bin_name and shutil.which(bin_name) is None:
        result.status = "TOOLCHAIN_UNAVAILABLE"
        result.stdout_tail = f"{bin_name} not on PATH"
        return result

    # Resolve path against the build root (and scope dir as fallback)
    resolved = _resolve_test_path_for(probe, build_root, project_root)
    if resolved is None:
        result.status = "NO_TEST_FILE"
        result.stdout_tail = (
            f"referenced {probe.test_file_resolved} but not found under "
            f"{build_root}"
        )
        return result

    lang_cfg = (registry.get("languages") or {}).get(language)
    if not lang_cfg or "test_command" not in lang_cfg:
        result.status = "TOOLCHAIN_UNAVAILABLE"
        result.stdout_tail = f"no test_command in registry for language={language!r}"
        return result

    try:
        rel_path = str(resolved.relative_to(build_root)).replace("\\", "/")
    except ValueError:
        rel_path = str(resolved).replace("\\", "/")

    # EVM: run forge directly from the build root. Filter by --match-test when
    # a function is known, else --match-contract, else --match-path (whole
    # file). cwd MUST be the build root (where foundry.toml lives).
    if language == "evm":
        forge_bin = shutil.which("forge") or "forge"
        _filter = _evm_forge_filter(probe, rel_path)
        cmd = [forge_bin, "test", *_filter, "-vv"]
        # VERIF-5: a --match-path run is NOT isolated to the finding's own test;
        # a FAIL could be an unrelated test in the same file. Track isolation so
        # the classifier can return AMBIGUOUS instead of mis-attributing FAIL.
        _isolated = _filter[:1] == ["--match-test"]
        # RC-harness: forge must run under the SAME FOUNDRY_PROFILE the verifier
        # used, or a custom profile's non-default test dir is invisible and the
        # whole suite reads as NO_TEST_FILE/FAIL. Inherit env + propagate the
        # resolved profile (recorded command, else foundry.toml auto-detect).
        env = os.environ.copy()
        profile = _resolve_foundry_profile(probe, build_root, resolved)
        if profile:
            env["FOUNDRY_PROFILE"] = profile
        elif env.get("FOUNDRY_PROFILE"):
            profile = env["FOUNDRY_PROFILE"]  # already set in the parent env
        t0 = time.time()
        try:
            proc = _run_owned_process(
                cmd,
                cwd=str(build_root),
                timeout=per_test_timeout_s,
                encoding="utf-8",
                errors="replace",
                env=env,
            )
            result.duration_s = time.time() - t0
            result.test_command_used = (
                (f"FOUNDRY_PROFILE={profile} " if profile else "") + " ".join(cmd))
            stdout = (proc.stdout or "") + "\n" + (proc.stderr or "")
            result.stdout_tail = stdout[-3000:]
            result.status = _classify_evm_outcome(proc.returncode, stdout, isolated=_isolated)
        except subprocess.TimeoutExpired:
            result.duration_s = float(per_test_timeout_s)
            result.status = "TIMEOUT"
            result.stdout_tail = f"forge test exceeded {per_test_timeout_s}s"
        except Exception as exc:
            result.duration_s = time.time() - t0
            result.status = "EXEC_ERROR"
            result.stdout_tail = f"forge subprocess error: {exc}"
        return result

    # Non-EVM ecosystems — build argv from registry template
    cmd = _format_test_command(
        lang_cfg["test_command"], probe.test_function, rel_path,
        language=language,
    )
    if not cmd:
        result.status = "EXEC_ERROR"
        result.stdout_tail = "empty command after template substitution"
        return result

    # Cargo workspace fixups: thread the verifier's `-p <package>` back in and
    # drop a phantom generic `--exact` filter, so a workspace-member PoC is
    # resolvable (RC-harness, mirrors the EVM FOUNDRY_PROFILE fix).
    if language in ("solana", "soroban", "l1_rust"):
        cmd = _apply_cargo_workspace_fixups(
            cmd, probe, language=language, resolved=resolved, build_root=build_root)

    # A1: l1_go race/concurrency Bug-Class rows get `-race` + a raised
    # per-test timeout. Strictly gated: only fires when language == "l1_go"
    # AND the row's Bug Class (from verification_queue.md) matches the race
    # keyword set. Every other language, and every non-race l1_go/l1_rust
    # row, falls through with `effective_timeout_s == per_test_timeout_s`
    # and `race_env is None` (subprocess inherits the parent env exactly as
    # before this change).
    effective_timeout_s = per_test_timeout_s
    race_env: Optional[dict[str, str]] = None
    if language == "l1_go":
        bug_class = (bug_class_map or {}).get((probe.finding_id or "").strip().upper(), "")
        if _is_race_bug_class(bug_class):
            cmd = _inject_go_race_flag(cmd)
            effective_timeout_s = per_test_timeout_s * _RACE_TIMEOUT_MULTIPLIER
            result.race_mode = True
            # `-race` requires cgo enabled (and a C compiler on non-Darwin
            # hosts) — https://go.dev/doc/articles/race_detector. Force
            # CGO_ENABLED=1 for this one subprocess so a CGO_ENABLED=0
            # host/CI default can't silently turn `-race` into a build
            # failure or a no-op non-race binary.
            race_env = os.environ.copy()
            race_env["CGO_ENABLED"] = "1"

    # Resolve binary path (handles Windows .cmd / .exe shims)
    bin_path = shutil.which(cmd[0])
    if bin_path:
        cmd[0] = bin_path

    t0 = time.time()
    try:
        proc = _run_owned_process(
            cmd,
            cwd=str(build_root),
            encoding="utf-8",
            errors="replace",
            timeout=effective_timeout_s,
            env=race_env,
        )
        result.duration_s = time.time() - t0
        result.test_command_used = " ".join(cmd)
        stdout = (proc.stdout or "") + "\n" + (proc.stderr or "")
        result.stdout_tail = stdout[-3000:]
        result.status = _classify_non_evm_outcome(language, proc.returncode, stdout)
    except subprocess.TimeoutExpired:
        result.duration_s = float(effective_timeout_s)
        result.status = "TIMEOUT"
        result.stdout_tail = f"test execution exceeded {effective_timeout_s}s"
    except Exception as exc:
        result.duration_s = time.time() - t0
        result.status = "EXEC_ERROR"
        result.stdout_tail = f"subprocess error: {exc}"
    return result


def _classify_non_evm_outcome(language: str, rc: int, stdout: str) -> str:
    """Decide PASS / FAIL / COMPILE_FAIL / NO_TEST_MATCH for non-EVM runners."""
    s = stdout
    # Cargo (solana, soroban, l1_rust)
    if language in ("solana", "soroban", "l1_rust"):
        # Evaluate REAL signals FIRST. A cargo run prints a per-target
        # `test result:` line for unittests AND doc-tests; the doc-tests line is
        # almost always `running 0 tests` / `ok. 0 passed`. Checking those zero
        # markers first (the prior order) short-circuited a genuine
        # `test result: ok. 72 passed` unittest section to NO_TEST_MATCH — every
        # passing Soroban/Rust suite was silently discarded.
        if re.search(r"error\[E\d+\]|could not compile|error: linking", s):
            return "COMPILE_FAIL"
        if re.search(r"test result:\s*FAILED", s) or re.search(r"[1-9]\d*\s+failed", s):
            return "FAIL"
        if rc == 0 and re.search(r"test result:\s*ok\.\s*[1-9]\d*\s*passed", s):
            return "PASS"
        # No pass and no failure recorded → genuinely zero tests matched.
        if "running 0 tests" in s or re.search(r"test result:\s*ok\.\s*0\s*passed", s):
            return "NO_TEST_MATCH"
        if rc != 0:
            return "FAIL"
        return "NO_TEST_MATCH"
    # Go testing
    if language == "l1_go":
        # Zero-tests-matched must NOT be read as a pass (the `ok\tpkg` summary
        # is printed even when `-run` matched nothing).
        if "no tests to run" in s or "no test files" in s or "matching no tests" in s:
            return "NO_TEST_MATCH"
        if rc == 0 and (re.search(r"^ok\s+", s, re.MULTILINE) or "--- PASS" in s):
            return "PASS"
        if "build failed" in s or "cannot find package" in s or "syntax error" in s:
            return "COMPILE_FAIL"
        if rc != 0:
            return "FAIL"
        return "PASS"
    # Aptos Move
    if language == "aptos":
        if rc == 0 and re.search(r"Result\s*:\s*PASS|Test result:\s*OK", s):
            return "PASS"
        if "ERROR" in s and ("compile" in s.lower() or "type error" in s.lower()):
            return "COMPILE_FAIL"
        if rc != 0:
            return "FAIL"
        # rc==0 but no PASS/OK marker → zero tests matched, not a real pass.
        return "NO_TEST_MATCH"
    # Sui Move
    if language == "sui":
        if rc == 0 and re.search(r"Test result:\s*OK|PASS\s*$", s, re.MULTILINE):
            return "PASS"
        if "error[E" in s or "FAILURE building" in s:
            return "COMPILE_FAIL"
        if rc != 0:
            return "FAIL"
        # rc==0 but no PASS/OK marker → zero tests matched, not a real pass.
        return "NO_TEST_MATCH"
    # DAML (Canton) — `daml test --files <file>` runs every Script() in scope.
    # No per-test name filter (daml_no_filter); isolation is file-scoped.
    if language == "daml":
        sl = s.lower()
        # Compilation problems surface before any test runs.
        if re.search(r"error:|file does not compile|parse error|"
                     r"type checking|scope error|unknown identifier", sl):
            return "COMPILE_FAIL"
        # No Script() in the file → nothing executed, not a pass.
        if "no scripts" in sl or re.search(r"\b0\s+(?:of\s+\d+\s+)?(?:tests?|scripts?)\b", sl):
            return "NO_TEST_MATCH"
        # Runtime PoC failures map to FAIL (the assertion/precondition fired).
        if rc != 0 or re.search(
            r"failed|preconditionfailed|assertion|unhandled exception|"
            r"abort|errors?:\s*[1-9]", sl
        ):
            return "FAIL"
        # rc==0 plus a positive test-summary marker is a genuine pass.
        if re.search(r"test summary|tests?\s+passed|\bok\b|all scripts? ran", sl):
            return "PASS"
        # rc==0 but no positive marker → treat as zero-matched, not a pass.
        return "NO_TEST_MATCH"
    return "EXEC_ERROR"


def _recommended_tag(status: str) -> str:
    return {
        "PASS": "[POC-PASS]",
        "FAIL": "[POC-FAIL]",
        "COMPILE_FAIL": "[CODE-TRACE]",  # broken LLM test, not a defense
        "TIMEOUT": "[CODE-TRACE]",
        "NO_TEST_MATCH": "[CODE-TRACE]",
        "NO_TEST_FILE": "[CODE-TRACE]",
        "TOOLCHAIN_UNAVAILABLE": "",  # preserve existing tag
        "BUILD_FAILED": "",            # preserve existing tag
        "EXEC_ERROR": "",              # preserve existing tag
        "SKIPPED": "",
    }.get(status, "")


# ---------------------------------------------------------------------------
# Verify-file annotation (append-only)
# ---------------------------------------------------------------------------


_EVIDENCE_TAG_LINE_RE = re.compile(
    r"^(\s*\**Evidence\s+Tag\**\s*:.*)$",
    re.MULTILINE | re.IGNORECASE,
)
_PREFERRED_TAG_LINE_RE = re.compile(
    r"^(\s*\**Preferred\s+Tag\**\s*:.*)$",
    re.MULTILINE | re.IGNORECASE,
)
_MECHANICAL_LINE_RE = re.compile(
    r"^\s*\**Mechanical-Verified\**\s*:.*$",
    re.MULTILINE | re.IGNORECASE,
)


def _annotate_verify_file(verify_path: Path, result: ExecResult) -> bool:
    """Append a Mechanical-Verified line and (when PASS/FAIL) update the tag.

    Append-only semantics: previous Evidence Tag line is preserved as a comment
    so the LLM's original claim is auditable. Returns True if file was modified.
    """
    try:
        text = verify_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return False

    # Idempotency: if a prior Mechanical-Verified line exists for the same
    # status, leave the file alone. (Rerunning the phase shouldn't grow it.)
    # Substring match is bold-marker agnostic (the line may carry `**` or not).
    existing = _MECHANICAL_LINE_RE.search(text)
    if existing:
        line = existing.group(0)
        if result.status in ("PASS", "FAIL"):
            same_status = f"Status: {result.status}" in line
        else:
            same_status = f"({result.status})" in line
        if same_status:
            return False

    rec_tag = _recommended_tag(result.status)
    mod_lines: list[str] = []

    # Strip any prior Mechanical-Verified line so we don't accumulate.
    text = _MECHANICAL_LINE_RE.sub("", text)
    text = re.sub(r"\n{3,}", "\n\n", text)

    new_lines: list[str] = [
        "",
        "<!-- mechanical-verify v1 — driver-stamped, do not hand-edit below -->",
    ]
    if result.status in ("PASS", "FAIL"):
        new_lines.append(
            f"**Mechanical-Verified**: YES — Status: {result.status} "
            f"(duration: {result.duration_s:.1f}s)"
        )
    else:
        new_lines.append(
            f"**Mechanical-Verified**: NO ({result.status}) — "
            f"{(result.stdout_tail or '')[:200]}"
        )
    if result.test_command_used:
        new_lines.append(f"**Mechanical-Command**: `{result.test_command_used}`")
    if rec_tag:
        new_lines.append(f"**Mechanical-Tag**: {rec_tag}")
    new_lines.append("")

    text = text.rstrip() + "\n" + "\n".join(new_lines)

    # Only PASS/FAIL update the canonical Evidence Tag. Anything else
    # preserves the LLM's prior tag (the driver-stamped Mechanical-Tag line
    # above carries the override semantics for the report-writer to read).
    if result.status == "PASS":
        # If a downgrade comment is in the existing tag (e.g. "[CODE-TRACE]
        # (was [POC-PASS], integrity downgrade: ...)"), the regex preserves
        # the line. We don't aggressively rewrite — Mechanical-Tag below
        # is the authoritative override that downstream phases read.
        pass

    try:
        verify_path.write_text(text, encoding="utf-8")
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Manifest writer
# ---------------------------------------------------------------------------


def _result_rows_execution_equivalent(
    prior_rows: object, current_rows: list[dict]
) -> bool:
    """Return true when only non-semantic timing telemetry changed.

    Duration is preserved separately in a content-addressed execution record.
    It must not invalidate an immutable successor proving the same test file,
    function, command, status, output, tag, and race mode.
    """

    if not isinstance(prior_rows, list) or len(prior_rows) != len(current_rows):
        return False

    def stable(row: object) -> object:
        if not isinstance(row, dict):
            return row
        return {key: value for key, value in row.items() if key != "duration_s"}

    return [stable(row) for row in prior_rows] == [
        stable(row) for row in current_rows
    ]


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _authoritative_successor_result(
    manifest_path: Path, executed_result: dict
) -> dict:
    """Resolve the exact row retained by the immutable canonical manifest."""

    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return executed_result
    rows = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(rows, list):
        return executed_result
    matches = [
        row
        for row in rows
        if isinstance(row, dict)
        and row.get("finding_id") == executed_result.get("finding_id")
        and row.get("verify_file") == executed_result.get("verify_file")
    ]
    if len(matches) != 1:
        return executed_result
    prior = matches[0]
    if _result_rows_execution_equivalent([prior], [executed_result]):
        return prior
    return executed_result


def _write_exact_execution_evidence(
    scratchpad: Path,
    *,
    executed_result: dict,
    authoritative_result: dict,
    manifest_path: Path,
    successor_receipt_path: Path,
    run_identity: str,
    driver_identity: str,
) -> Path:
    """Persist the exact rerun without mutating established successor proof."""

    manifest_raw = manifest_path.read_bytes()
    successor_raw = successor_receipt_path.read_bytes()
    unsigned = {
        "schema_version": "plamen.mechanical_execution_evidence.v1",
        "run_identity": run_identity,
        "driver_identity": driver_identity,
        "executor_identity": "sha256:"
        + hashlib.sha256(Path(__file__).resolve().read_bytes()).hexdigest(),
        "successor_identity": "sha256:"
        + hashlib.sha256(
            Path(mechanical_successor_authority.__file__).resolve().read_bytes()
        ).hexdigest(),
        "executed_result": executed_result,
        "authoritative_result_sha256": hashlib.sha256(
            _canonical_json_bytes(authoritative_result)
        ).hexdigest(),
        "mechanical_manifest_file": manifest_path.name,
        "mechanical_manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "successor_receipt_file": successor_receipt_path.name,
        "successor_receipt_sha256": hashlib.sha256(successor_raw).hexdigest(),
    }
    record_digest = hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()
    payload = {**unsigned, "record_digest": record_digest}
    raw = _canonical_json_bytes(payload)
    evidence_dir = Path(scratchpad) / "mechanical_execution_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    path = evidence_dir / f"{record_digest}.json"
    if path.exists():
        if path.read_bytes() != raw:
            raise MechanicalSuccessorError(
                "content-addressed mechanical execution evidence collision"
            )
        return path
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with temp.open("xb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp, path)
        except FileExistsError:
            if path.read_bytes() != raw:
                raise MechanicalSuccessorError(
                    "racing mechanical execution evidence disagrees"
                )
        except OSError as exc:
            raise MechanicalSuccessorError(
                f"atomic mechanical execution evidence creation failed: {exc}"
            ) from exc
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    return path


def _write_manifest(results: list[ExecResult], scratchpad: Path) -> Path:
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    lines = [
        "# Mechanical Verify Manifest",
        "",
        f"**Generated**: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total verify files**: {len(results)}",
        "",
        "## Status Counts",
        "",
        "| Status | Count |",
        "|--------|-------|",
    ]
    for status in (
        "PASS", "FAIL", "COMPILE_FAIL", "TIMEOUT",
        "NO_TEST_MATCH", "NO_TEST_FILE", "AMBIGUOUS",
        "TOOLCHAIN_UNAVAILABLE", "BUILD_FAILED", "EXEC_ERROR", "SKIPPED",
    ):
        lines.append(f"| {status} | {counts.get(status, 0)} |")
    lines.append("")
    lines.append("## Per-Finding Results")
    lines.append("")
    lines.append("| Finding | Status | Duration | Test File | Function | Tag |")
    lines.append("|---------|--------|---------:|-----------|----------|-----|")
    for r in sorted(results, key=lambda x: x.finding_id or x.verify_file):
        tf = r.test_file_resolved or "—"
        if len(tf) > 40:
            tf = "…" + tf[-37:]
        lines.append(
            f"| {r.finding_id or '?'} | {r.status} | {r.duration_s:.1f}s "
            f"| {tf} | {r.test_function or '—'} | {_recommended_tag(r.status) or '—'} |"
        )
    (scratchpad / "mechanical_verify_manifest.md").write_text(
        "\n".join(lines), encoding="utf-8"
    )

    # JSON sidecar for downstream programmatic consumption
    manifest_json = scratchpad / "mechanical_verify_manifest.json"
    result_rows = [asdict(r) for r in results]
    # Successor receipts bind the exact JSON manifest bytes.  Preserve an
    # existing manifest when its evidence rows and counts are unchanged so an
    # exact replay cannot be invalidated solely by a regenerated timestamp.
    preserve_existing = False
    if manifest_json.exists():
        try:
            prior = json.loads(manifest_json.read_text(encoding="utf-8"))
            preserve_existing = (
                isinstance(prior, dict)
                and prior.get("counts") == counts
                and _result_rows_execution_equivalent(
                    prior.get("results"), result_rows
                )
            )
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            preserve_existing = False
    if not preserve_existing:
        next_payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "counts": counts,
            "results": result_rows,
        }
        # Never orphan an already-issued immutable receipt by replacing the
        # exact manifest bytes it binds.  A genuinely different rerun is
        # retained as a content-addressed pending generation and surfaced as
        # DEGRADED when the current successor cannot accept it.
        try:
            established_receipts = [
                entry
                for entry in Path(scratchpad).iterdir()
                if entry.name.casefold().startswith("verify_")
                and entry.name.casefold().endswith(
                    ".mechanical_successor.receipt.json"
                )
            ]
        except OSError:
            established_receipts = []
        if manifest_json.exists() and established_receipts:
            pending_raw = _canonical_json_bytes(next_payload)
            pending_digest = hashlib.sha256(pending_raw).hexdigest()
            pending_path = Path(scratchpad) / (
                f"mechanical_verify_manifest.pending.{pending_digest}.json"
            )
            if pending_path.exists():
                if pending_path.read_bytes() != pending_raw:
                    raise MechanicalSuccessorError(
                        "content-addressed pending manifest collision"
                    )
            else:
                pending_path.write_bytes(pending_raw)
        else:
            manifest_json.write_text(
                json.dumps(next_payload, indent=2),
                encoding="utf-8",
            )

    # v2.0.8 (P3.1): write verdict_manifest.json — the canonical
    # machine-readable evidence-truth record that cross-references the
    # verifier's prose Evidence Tag claim against this mechanical execution.
    _write_verdict_manifest(results, scratchpad)
    return manifest_json


def _mechanical_successor_execution_identity(
    scratchpad: Path,
    *,
    run_identity: Optional[str] = None,
    driver_identity: Optional[str] = None,
) -> tuple[str, str]:
    """Resolve the run and exact driver bytes bound by successor receipts.

    Production runs carry a UUID in ``_v2_checkpoint.json``.  The explicit
    keyword parameters are retained for isolated tests and recovery tooling;
    ordinary driver callers need no signature change.  ``test-unbound`` is a
    loud compatibility identity for isolated legacy callers with no
    checkpoint, never an invented production UUID.
    """
    run = str(run_identity or "").strip()
    if not run:
        checkpoint = Path(scratchpad) / "_v2_checkpoint.json"
        try:
            payload = json.loads(checkpoint.read_text(encoding="utf-8-sig"))
            if isinstance(payload, dict):
                run = str(payload.get("run_id") or "").strip()
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            run = ""
    if not run:
        run = "test-unbound"

    driver = str(driver_identity or "").strip()
    if not driver:
        driver_path = Path(__file__).resolve().with_name("plamen_driver.py")
        try:
            driver_bytes = driver_path.read_bytes()
        except OSError:
            # A packaged executor without the driver beside it is still bound
            # to exact code bytes, but the fallback remains distinguishable
            # from the normal plamen_driver.py authority in its receipt audit.
            driver_bytes = Path(__file__).resolve().read_bytes()
        driver = "sha256:" + hashlib.sha256(driver_bytes).hexdigest()
    return run, driver


def _write_successor_authority_summary(
    scratchpad: Path,
    *,
    run_identity: str,
    driver_identity: str,
    committed: int,
    rejections: list[dict[str, str]],
) -> None:
    """Persist haltless-but-loud authority debt for human review."""
    out = Path(scratchpad) / "mechanical_successor_authority.json"
    payload = {
        "schema_version": "plamen.mechanical_successor_authority_summary.v1",
        "status": "DEGRADED" if rejections else "CLEAN",
        "run_identity": run_identity,
        "driver_identity": driver_identity,
        "committed_count": committed,
        "rejected_count": len(rejections),
        "rejections": rejections,
    }
    temp = out.with_suffix(out.suffix + ".tmp")
    temp.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    temp.replace(out)


# ---------------------------------------------------------------------------
# v2.0.8 (P3.1): verdict manifest — evidence-chain truth layer
# ---------------------------------------------------------------------------

_PROOF_EVIDENCE_TAGS = (
    "[POC-PASS]", "[MEDUSA-PASS]", "[FUZZ-PASS]",
    "[NON-DET-PASS]", "[DIFF-PASS]", "[CONFORMANCE-PASS]",
)

_PROSE_TAG_RE = re.compile(
    r"\[(?:POC-PASS|POC-FAIL|CODE-TRACE|MEDUSA-PASS|"
    r"FUZZ-PASS|NON-DET-PASS|DIFF-PASS|CONFORMANCE-PASS|LSP-TRACE)\]",
    re.IGNORECASE,
)


# v2.8.16 Phase 1: the leading-marker class MUST include `-` and `\t`. Real
# verifier files write the canonical field as a Markdown bullet
# (`- **Evidence Tag**: [POC-PASS]`); the old `[*_`> ]*` prefix did not match a
# `-`, so the verifier's actual claim line was silently skipped. After the
# mechanical phase appends a NON-bullet `**Mechanical-Tag**: [CODE-TRACE]` line,
# that line WAS matched instead — so a fabricated bullet-form `[POC-PASS]` +
# NO_TEST_FILE was misclassified CONSISTENT rather than INFLATED_PROSE, defeating
# the integrity downgrade (and the #3a verdict flip that keys on it). The
# verifier's own claim (Evidence/Preferred Tag) is now read with PRIORITY over
# the driver-stamped Mechanical-Tag, so re-runs cannot shadow the claim either.
_CLAIM_FIELD_RE = re.compile(
    r"(?im)^[-*_`> \t]*(?:Evidence\s+Tags?|Preferred\s+Tag)"
    r"[*_`> \t]*\s*:\s*(.+)$"
)
_MECH_TAG_FIELD_RE = re.compile(
    r"(?im)^[-*_`> \t]*Mechanical-?Tag[*_`> \t]*\s*:\s*(.+)$"
)
_FENCED_CODE_RE = re.compile(r"(?s)```.*?```")


def _extract_verifier_prose_tag(verify_path: Path) -> str:
    """Read the verifier's prose Evidence Tag from a verify_<ID>.md file.

    VERIF-2: anchor to the canonical `Evidence Tag:` / `Preferred Tag:` FIELD
    value (the contract every verifier file must carry), NOT a whole-file
    first-match -- a pasted reference table or an example tag in a fenced code
    block could otherwise poison the result. The verifier's OWN claim is read
    with priority; the driver-stamped `Mechanical-Tag:` line is only a fallback
    so a prior annotation cannot shadow the claim being integrity-checked.
    Falls back to a whole-file search (with fenced code stripped) only when no
    field is present. Returns the evidence-tag token (e.g. '[POC-PASS]') or "".
    """
    if not verify_path.exists():
        return ""
    try:
        text = verify_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    # 1. Verifier's own claim (Evidence/Preferred Tag) — highest priority.
    for fm in _CLAIM_FIELD_RE.finditer(text):
        tm = _PROSE_TAG_RE.search(fm.group(1))
        if tm:
            return tm.group(0).upper()
    # 2. Driver-stamped Mechanical-Tag field (only if no verifier claim found).
    for fm in _MECH_TAG_FIELD_RE.finditer(text):
        tm = _PROSE_TAG_RE.search(fm.group(1))
        if tm:
            return tm.group(0).upper()
    # 3. Fallback: whole-file, but ignore tags inside fenced code blocks.
    stripped = _FENCED_CODE_RE.sub(" ", text)
    m = _PROSE_TAG_RE.search(stripped)
    return m.group(0).upper() if m else ""


# ---------------------------------------------------------------------------
# Harm-assertion detection (v2.8.17)
#
# A NO_TEST_FILE status means the mechanical layer could not re-locate / re-run
# the test file — a harness/file-location failure, NOT proof the exploit is
# false. When the verifier actually wrote a real asserting PoC, that finding
# must not be severity-capped to [CODE-TRACE] on a tooling gap. This detector
# recognizes whether the verify prose contains an explicit harm assertion,
# INCLUDING revert / error-expectation forms that narrow positive-assertion
# vocabularies miss (e.g. `try_foo(..).is_err()`). It is strictly ADDITIVE:
# it can only REDUCE false "no assertion" downgrades, never introduce one.
# ---------------------------------------------------------------------------

_HARM_ASSERTION_RE = re.compile(
    "|".join((
        # Revert / error-expectation forms (Rust / Soroban + generic)
        r"\.is_err\s*\(\s*\)",            # x.is_err() / try_foo(..).is_err()
        r"\.is_ok\s*\(\s*\)",             # x.is_ok() on a call result
        r"\.expect_err\s*\(",             # x.expect_err("...")
        r"\.unwrap_err\s*\(\s*\)",        # x.unwrap_err()
        r"#\[\s*should_panic",            # #[should_panic] / #[should_panic(expected=..)]
        r"\bshould_panic\s*\(",           # should_panic(expected = ...)
        r"\bmatches!\s*\([^)]*\bErr\b",   # matches!(x, Err(..))
        r"==\s*Err\s*\(",                 # x == Err(..)
        # Generic positive assertions (existing recognized forms — kept)
        r"\bassert!\s*\(",                # assert!(..) incl. assert!(x.is_err())
        r"\bassert_eq!\s*\(",             # assert_eq!(x, Err(..))
        r"\bassert_ne!\s*\(",
        r"\bassertEq\b", r"\bassertTrue\b", r"\bassertFalse\b",
        r"\bassertGt\b", r"\bassertLt\b",
        r"\bexpectRevert\b",              # Foundry vm.expectRevert
        r"\bassert\.[A-Za-z]",            # Go testify assert.X
        r"\brequire\.[A-Za-z]",           # Go testify require.X
    ))
)


def _contains_harm_assertion(text: str) -> bool:
    """True if `text` contains an explicit harm/error-expectation assertion.

    Recognizes revert/error-expectation assertions (`.is_err()`,
    `#[should_panic]`, `.expect_err(..)`, `.unwrap_err()`, `matches!(.., Err(..))`,
    `assert_eq!(.., Err(..))`) in addition to positive assertion forms. Scans the
    whole verify prose (fenced code blocks included) — a real PoC snippet may
    live either inside or outside a code fence in a verify_<ID>.md file.
    """
    if not text:
        return False
    return bool(_HARM_ASSERTION_RE.search(text))


def _read_verify_text(verify_path: Path) -> str:
    """Best-effort read of a verify_<ID>.md file; '' on any error/absence."""
    try:
        return verify_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _classify_integrity(prose_tag: str, mechanical_status: str,
                        verify_text: str = "") -> tuple[str, str]:
    """v2.0.8 (P3.1): given the verifier prose tag and the mechanical
    execution status, return (integrity_state, effective_tag).

    States:
      - CONSISTENT: prose tag matches mechanical reality.
      - INFLATED_PROSE: prose claims proof-grade evidence
        ([POC-PASS]/[MEDUSA-PASS]/etc.) but mechanical did NOT confirm
        (NO_TEST_FILE / FAIL / COMPILE_FAIL / TIMEOUT) AND the verify prose
        carries no explicit harm assertion. Effective tag forced to
        [CODE-TRACE] with [INTEGRITY-DOWNGRADE] flag.
      - POC_UNVERIFIED_HARNESS (v2.8.17): prose claims proof-grade evidence,
        the verify prose DOES contain an explicit harm assertion, but the
        mechanical layer hit a NO_TEST_FILE harness/file-location failure.
        This is a tooling gap, not disproof — the effective tag PRESERVES the
        upstream severity (keeps the prose tag) and adds
        `[POC-UNVERIFIED-HARNESS] [NEEDS-BUILD]`. It carries NO
        [INTEGRITY-DOWNGRADE], so the driver's verdict-flip (gated on
        INFLATED_PROSE) leaves CONFIRMED intact.
      - MECHANICAL_UNAVAILABLE: no mechanical record (finding not in
        manifest, or toolchain unavailable). Effective tag = prose tag
        with [MECHANICAL-UNAVAILABLE] flag.

    `verify_text` is the verify_<ID>.md prose (optional for back-compat; when
    empty the harness carve-out cannot fire and behavior is unchanged).
    """
    prose_upper = (prose_tag or "").upper()
    status = (mechanical_status or "").upper()
    prose_is_proof = prose_upper in {t.upper() for t in _PROOF_EVIDENCE_TAGS}

    if status in ("TOOLCHAIN_UNAVAILABLE", "SKIPPED", "AMBIGUOUS"):
        # Mechanical layer was unavailable, or (VERIF-5) AMBIGUOUS = a whole-file
        # run with mixed pass/fail that cannot be attributed to THIS finding.
        # Preserve prose with a flag -- do NOT treat as INFLATED_PROSE, which
        # would wrongly demote a true positive on an unrelated test's failure.
        effective = prose_tag or "[CODE-TRACE]"
        return ("MECHANICAL_UNAVAILABLE",
                f"{effective} [MECHANICAL-UNAVAILABLE]")
    if status == "PASS":
        # Mechanical confirmed PASS. If prose also claimed proof → CONSISTENT.
        if prose_is_proof:
            return ("CONSISTENT", prose_tag)
        # Prose was conservative (e.g., [CODE-TRACE]) but mechanical
        # actually passed. Upgrade effective_tag to [POC-PASS] —
        # mechanical truth wins.
        return ("CONSISTENT", "[POC-PASS]")
    if status in ("FAIL",):
        # Mechanical FAILED; verifier shouldn't have claimed proof-grade.
        if prose_is_proof:
            return ("INFLATED_PROSE",
                    "[CODE-TRACE] [INTEGRITY-DOWNGRADE]")
        return ("CONSISTENT", "[POC-FAIL]")
    # NO_TEST_FILE / NO_TEST_MATCH / COMPILE_FAIL / TIMEOUT / BUILD_FAILED /
    # EXEC_ERROR — mechanical did NOT confirm proof.
    if prose_is_proof:
        # v2.8.17 harness-failure carve-out: NO_TEST_FILE is a file-location /
        # harness failure, NOT evidence the exploit is false. When the verifier
        # DID write a real asserting PoC (a recognized harm assertion — incl.
        # revert/error-expectation forms — is present in the verify prose) and
        # claimed proof-grade evidence, demoting to [CODE-TRACE] wrongly caps
        # severity on a tooling gap. Emit a DISTINCT, non-severity-capping
        # disposition that PRESERVES the upstream severity and routes to a build
        # re-run. It carries no [INTEGRITY-DOWNGRADE], so the driver's verdict
        # flip (gated on INFLATED_PROSE) leaves CONFIRMED intact.
        if status == "NO_TEST_FILE" and _contains_harm_assertion(verify_text):
            return ("POC_UNVERIFIED_HARNESS",
                    f"{prose_tag} [POC-UNVERIFIED-HARNESS] [NEEDS-BUILD]")
        # Codex Point 5: the canonical phantom-[POC-PASS] downgrade case
        # (assertion-less prose, or a genuine mechanical FAIL/COMPILE/TIMEOUT).
        return ("INFLATED_PROSE",
                "[CODE-TRACE] [INTEGRITY-DOWNGRADE]")
    # Prose was honest about not having proof; preserve it.
    return ("CONSISTENT", prose_tag or "[CODE-TRACE]")


_VERDICT_CONFIRMED_FIELD_RE = re.compile(
    r"(?im)^([-*>\s`_]*Verdict[*>\s`_]*:\s*)CONFIRMED\b"
    r"(?!\s*\[INTEGRITY-DOWNGRADE\])"
)


def flip_verdict_on_integrity_downgrade(text: str) -> tuple[str, bool]:
    """v2.8.16 Phase 1 (#3a): flip a verifier's `**Verdict**: CONFIRMED` line to
    `CONTESTED [INTEGRITY-DOWNGRADE]`.

    Demoting the Evidence Tag alone does not reach the report — the report Index
    Agent sets the VERIFIED column from the verifier's `Verdict:` line. When the
    mechanical layer classifies a finding INFLATED_PROSE (prose claimed
    proof-grade evidence the run did not confirm), the driver calls this so a
    mechanically-disproven exploit can never ship as a verified-Critical.

    Only the Verdict FIELD line is rewritten (anchored, multiline) — prose
    mentions of the word "CONFIRMED" elsewhere are left untouched. Idempotent:
    an already-downgraded line is not matched again. Returns (new_text, changed).
    """
    new_text, n = _VERDICT_CONFIRMED_FIELD_RE.subn(
        r"\1CONTESTED [INTEGRITY-DOWNGRADE]", text
    )
    return new_text, (n > 0)


def _write_verdict_manifest(results: list, scratchpad: Path) -> None:
    """v2.0.8 (P3.1): write `verdict_manifest.json` from the mechanical
    verify results + each verify_<ID>.md prose Evidence Tag.

    Schema: `plamen.verdict_manifest.v1`. Downstream consumers (skeptic-
    judge, report_index) MUST read `effective_tag` from this manifest
    rather than the verifier's prose claim, which can be inflated.
    """
    verdicts = []
    for r in results:
        verify_path = scratchpad / r.verify_file
        prose_tag = _extract_verifier_prose_tag(verify_path)
        verify_text = _read_verify_text(verify_path)
        integrity_state, effective_tag = _classify_integrity(
            prose_tag, r.status, verify_text
        )
        verdicts.append({
            "finding_id": r.finding_id or "",
            "verify_file": r.verify_file,
            "mechanical_status": r.status,
            "verifier_prose_tag": prose_tag,
            "integrity_state": integrity_state,
            "effective_tag": effective_tag,
        })
    payload = {
        "schema_version": "plamen.verdict_manifest.v1",
        "mechanical_source": "mechanical_verify_manifest.md",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "row_count": len(verdicts),
        "verdicts": verdicts,
    }
    out = scratchpad / "verdict_manifest.json"
    try:
        tmp = out.with_suffix(out.suffix + ".tmp")
        tmp.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        tmp.replace(out)
    except OSError:
        pass


def read_verdict_manifest(scratchpad: Path) -> list[dict]:
    """v2.0.8 (P3.1): read `verdict_manifest.json` if present and valid.

    Returns the `verdicts` list (or [] on absent / malformed file).
    Skeptic-judge and report_index consume this in preference to the
    verifier's prose Evidence Tag.
    """
    path = scratchpad / "verdict_manifest.json"
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if not isinstance(payload, dict):
        return []
    if payload.get("schema_version") != "plamen.verdict_manifest.v1":
        return []
    verdicts = payload.get("verdicts")
    if not isinstance(verdicts, list):
        return []
    return verdicts


# ---------------------------------------------------------------------------
# Driver entry point
# ---------------------------------------------------------------------------


def _lang_cfg_from_registry(registry: dict, language: str) -> dict:
    """Registry may be the full document (`{"languages": {...}}`, what
    `_load_registry()` returns) or, in unit tests and some callers, a flat
    `{language: {...}}` mapping passed directly. Support both shapes so
    production callers and existing test stubs both resolve correctly —
    the prior direct `registry.get(language)` silently returned `{}` for
    every non-EVM language when handed the real nested document, which made
    the cargo pre-warm step below unreachable in production."""
    if not isinstance(registry, dict):
        return {}
    langs = registry.get("languages")
    if isinstance(langs, dict) and language in langs:
        return langs.get(language) or {}
    return registry.get(language) or {}


def _prewarm_build(build_root: Path, language: str, registry: dict,
                   timeout_s: int) -> tuple[bool, str]:
    """One-time best-effort compile from the build root to WARM the build cache
    before the per-finding test loop.

    Without this, the first `forge test` / `cargo test` on a COLD cache must do
    the whole-project (often `--via-ir`) compile inside its own per-test budget
    and TIMEOUTs on a dependency-heavy repo — capping every finding at
    [CODE-TRACE] instead of [POC-PASS]. A warm cache makes each subsequent test
    an incremental (seconds) build.

    Cargo ecosystems (solana/soroban/l1_rust) ALSO get a second, independent
    `cargo test --no-run` warm pass (see `_prewarm_cargo_test_targets`): the
    primary `build_command` (e.g. `cargo build-sbf`, `stellar contract build`)
    compiles the library/program target only, not the *test* targets, so the
    per-finding loop's first `cargo test` still paid a cold test-compile even
    with a warm library cache.

    Best-effort and NON-FATAL: any failure/timeout just leaves the cache as-is
    and the loop proceeds exactly as before (the per-test build then behaves as
    it did pre-fix). Never raises."""
    env = os.environ.copy()
    try:
        if language == "evm":
            cmd = [shutil.which("forge") or "forge", "build"]
        else:
            lang_cfg = _lang_cfg_from_registry(registry, language)
            build_cmd = str(lang_cfg.get("build_command") or "").strip()
            if not build_cmd:
                return (False, f"no build_command for '{language}' — pre-warm skipped")
            cmd = build_cmd.split()
            resolved = shutil.which(cmd[0])
            if resolved:
                cmd[0] = resolved
        t0 = time.time()
        proc = _run_owned_process(
            cmd,
            cwd=str(build_root),
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_s)),
            env=env,
        )
        dt = time.time() - t0
        if proc.returncode == 0:
            ok, note = True, f"warm ok (rc=0) in {dt:.0f}s"
        else:
            # A non-zero build here is informative but not fatal — the per-test
            # run still tries (a scoped compile can succeed where a
            # whole-project one fails), and the classifier handles COMPILE_FAIL.
            ok, note = False, f"build rc={proc.returncode} in {dt:.0f}s (cache left as-is)"
    except subprocess.TimeoutExpired:
        ok, note = False, f"pre-warm build exceeded {timeout_s}s (cache left as-is)"
    except Exception as exc:  # never let cache-warming break verification
        ok, note = False, f"pre-warm build error: {exc}"

    if language in ("solana", "soroban", "l1_rust"):
        ok2, note2 = _prewarm_cargo_test_targets(build_root, language, registry, timeout_s, env)
        note = f"{note}; {note2}"
        # A failed/absent test-prewarm never overrides a successful primary
        # build — it is a pure best-effort supplement, never fatal.
        ok = ok or ok2

    return (ok, note)


def _prewarm_cargo_test_targets(build_root: Path, language: str, registry: dict,
                                timeout_s: int, env: dict) -> tuple[bool, str]:
    """Best-effort `cargo test --no-run` warm pass (see `_prewarm_build`).

    Uses the registry's `test_prewarm_command` when present, else a plain
    `cargo test --no-run`; `--features testutils` is added for soroban only
    (its test modules are commonly gated behind that feature — solana/l1_rust
    never define it). No `-p <crate>` is threaded here: at this point in the
    phase no finding has been parsed yet, so there is no specific workspace
    member to target — this warms whatever `cargo test --no-run` reaches from
    the workspace root, best-effort. Per-finding `-p` threading happens later
    in `_apply_cargo_workspace_fixups`. Independent of the primary build step
    — attempted even when it failed, since a scoped test-target compile can
    succeed on its own. Never raises."""
    try:
        lang_cfg = _lang_cfg_from_registry(registry, language)
        template = str(lang_cfg.get("test_prewarm_command") or "cargo test --no-run").strip()
        cmd = template.split() or ["cargo", "test", "--no-run"]
        resolved = shutil.which(cmd[0])
        if resolved:
            cmd[0] = resolved
        # No unconditional `--features testutils`: this warm runs at the workspace
        # ROOT with no `-p`, where a crate-level feature the members do not DECLARE
        # (the common Soroban case — testutils arrives via the soroban-sdk dep, not
        # a crate feature) makes cargo hard-error ("does not contain this feature"
        # / "--features not allowed in the root of a virtual workspace"), wasting
        # the whole warm pass. Plain `cargo test --no-run` compiles every member's
        # test target and warms the cache; per-finding feature validity is handled
        # later in `_apply_cargo_workspace_fixups`.
        t0 = time.time()
        proc = _run_owned_process(
            cmd,
            cwd=str(build_root),
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_s)),
            env=env,
        )
        dt = time.time() - t0
        if proc.returncode == 0:
            return (True, f"test-prewarm ok (rc=0) in {dt:.0f}s")
        return (False, f"test-prewarm rc={proc.returncode} in {dt:.0f}s (best-effort, ignored)")
    except subprocess.TimeoutExpired:
        return (False, f"test-prewarm exceeded {timeout_s}s (best-effort, ignored)")
    except Exception as exc:
        return (False, f"test-prewarm error (best-effort, ignored): {exc}")


def run_phase5b_mechanical_verify(scratchpad: Path, project_root: Path,
                                  language: str, *,
                                  per_test_timeout_s: Optional[int] = None,
                                  phase_budget_s: Optional[int] = None,
                                  registry: Optional[dict] = None,
                                  run_identity: Optional[str] = None,
                                  driver_identity: Optional[str] = None) -> dict:
    """Execute mechanical PoC verification for every verify_*.md in scratchpad.

    Returns a summary dict (also written to mechanical_verify_manifest.json):

      {
        "status": "ok" | "no_verify_files" | "toolchain_unavailable",
        "counts": {PASS: N, FAIL: N, ...},
        "files_annotated": N,
        "elapsed_s": float,
      }

    Never raises for its OWN execution logic — phase failure is captured in
    the returned status, and the driver marks the phase DEGRADED (warning)
    rather than HALT. EXCEPTION (ITEM H2): the fail-closed supply-chain gate
    called before the per-finding test loop CAN raise
    `supply_chain_gate.SupplyChainAbortError`. That is deliberate — it is a
    true circuit breaker and must propagate so the per-finding subprocess
    loop (which runs the TARGET repo's own build/test commands) never
    starts. The driver's phase try/except catches it like any other phase
    exception and marks this phase degraded without halting the pipeline.
    """
    per_test_timeout_s = per_test_timeout_s or _DEFAULT_PER_TEST_TIMEOUT_S
    phase_budget_s = phase_budget_s or _DEFAULT_PHASE_BUDGET_S
    registry = registry or _load_registry()
    successor_run_identity, successor_driver_identity = (
        _mechanical_successor_execution_identity(
            Path(scratchpad),
            run_identity=run_identity,
            driver_identity=driver_identity,
        )
    )

    # Resolve actual language (caller may pass empty string when config absent)
    lang = (language or "").lower().strip()
    if not lang:
        lang = "evm"  # back-compat default
    elif lang in ("go", "rust"):
        # v2.8.16 Phase 1 (#0a): L1 config stores the raw language `go`/`rust`,
        # but the toolchain registry + manifest tables key on `l1_go`/`l1_rust`.
        # Without this remap _toolchain_binary_for("rust")="" and the registry
        # lookup misses → every L1 finding returns TOOLCHAIN_UNAVAILABLE and
        # L1 mechanical verify is silently dead. Normalize at the single
        # dispatch surface so every caller benefits.
        lang = "l1_go" if lang == "go" else "l1_rust"

    skip_names = {
        "verify_core.md", "verify_core_full.md", "verify_aggregate.md",
    }
    verify_files = sorted(
        f for f in scratchpad.glob("verify_*.md")
        if f.name not in skip_names
    )
    if not verify_files:
        _write_manifest([], scratchpad)
        return {"status": "no_verify_files", "counts": {}, "files_annotated": 0,
                "elapsed_s": 0.0}

    # Resolve the build root before the toolchain pre-check as well as before
    # execution. P1-E must be able to materialize visible, candidate-bound
    # non-execution debt for TOOLCHAIN_UNAVAILABLE without guessing a source
    # or oracle binding.
    build_root = _read_recon_build_root(scratchpad, lang) or _find_build_root(
        Path(project_root), lang
    )

    # Toolchain pre-check — if the binary is absent, short-circuit gracefully.
    bin_name = _toolchain_binary_for(lang)
    if bin_name and shutil.which(bin_name) is None:
        results = [
            ExecResult(verify_file=f.name, finding_id=f.stem.replace("verify_", ""),
                       language=lang, status="TOOLCHAIN_UNAVAILABLE",
                       stdout_tail=f"{bin_name} not on PATH")
            for f in verify_files
        ]
        _write_manifest(results, scratchpad)
        try:
            from execution_scope_runtime import (
                materialize_execution_scope_assessments,
            )

            p1e_scope = materialize_execution_scope_assessments(
                Path(scratchpad), build_root=build_root
            )
        except Exception as exc:
            p1e_scope = {
                "status": "DEGRADED",
                "materialized": 0,
                "issues": [
                    f"P1E_RUNTIME_DEGRADED:{type(exc).__name__}:{exc}"
                ],
            }
        return {"status": "toolchain_unavailable", "counts": {"TOOLCHAIN_UNAVAILABLE": len(results)},
                "files_annotated": 0, "elapsed_s": 0.0,
                "p1e_execution_scope": p1e_scope}

    # Resolve the build root once — the directory that owns the build
    # manifest (foundry.toml etc.), which is often a PARENT of the audit
    # scope dir. Test files and `test/` live here, not under project_root.
    # Recon's authoritative chosen build root (from build_status.md) wins when
    # present — the heuristic is the fallback for runs where recon emitted no
    # (or a stale) choice.
    # ITEM H2: fail-closed supply-chain gate. Runs ONCE for the whole phase,
    # BEFORE the pre-warm build and BEFORE the per-finding test loop below —
    # both invoke the TARGET repo's own build/test toolchain against its
    # dependency lockfile(s). A true circuit breaker: this call is NOT
    # wrapped in a try/except here, so a raised SupplyChainAbortError
    # propagates out of this function immediately and neither the pre-warm
    # build nor a single per-finding test subprocess runs.
    gate_supply_chain(build_root)

    # Warm the build cache ONCE before the per-finding loop. A cold, dependency-
    # heavy (`--via-ir`) repo cannot compile inside a single per-test budget, so
    # without this every finding TIMEOUTs and caps at [CODE-TRACE]; a warm cache
    # makes each test an incremental build. Best-effort / non-fatal.
    prewarm_ok, prewarm_note = _prewarm_build(
        build_root, lang, registry, _DEFAULT_BUILD_TIMEOUT_S)

    # A1: l1_go-only best-effort Bug-Class lookup for `-race` routing. `{}`
    # for every SC language and for l1_rust — see `_load_race_bug_class_map`.
    race_bug_class_map = _load_race_bug_class_map(scratchpad, lang)

    results: list[ExecResult] = []
    t_start = time.time()
    for vf in verify_files:
        if time.time() - t_start > phase_budget_s:
            results.append(ExecResult(
                verify_file=vf.name,
                finding_id=vf.stem.replace("verify_", ""),
                language=lang,
                status="SKIPPED",
                stdout_tail="phase budget exhausted",
            ))
            continue
        r = _run_test_for_finding(
            vf, build_root, lang, registry, per_test_timeout_s,
            project_root=Path(project_root),
            bug_class_map=race_bug_class_map,
        )
        r.recommended_tag = _recommended_tag(r.status)
        results.append(r)

    # The exact result set must exist before any verifier Markdown mutation:
    # every successor receipt binds the immutable JSON manifest bytes plus its
    # own canonical result row.  This also makes a crash at either successor
    # write boundary deterministically repairable.
    manifest_path = _write_manifest(results, scratchpad)
    annotated = 0
    successor_receipts = 0
    authority_rejections: list[dict[str, str]] = []
    by_file = {r.verify_file: r for r in results}
    for vf in verify_files:
        r = by_file.get(vf.name)
        if r is None:
            continue
        try:
            executed_result = asdict(r)
            authoritative_result = _authoritative_successor_result(
                manifest_path, executed_result
            )
            outcome = apply_mechanical_successor(
                vf,
                authoritative_result,
                manifest_path,
                run_identity=successor_run_identity,
                driver_identity=successor_driver_identity,
            )
            _write_exact_execution_evidence(
                Path(scratchpad),
                executed_result=executed_result,
                authoritative_result=authoritative_result,
                manifest_path=manifest_path,
                successor_receipt_path=outcome.receipt_path,
                run_identity=successor_run_identity,
                driver_identity=successor_driver_identity,
            )
            if outcome.transformed_written:
                annotated += 1
            successor_receipts += 1
        except (MechanicalSuccessorError, OSError, UnicodeError, ValueError) as exc:
            # Haltless / repair-then-degrade: do not discard the mechanical
            # execution result, but never mutate unverifiable source bytes.
            authority_rejections.append(
                {
                    "finding_id": r.finding_id,
                    "verify_file": r.verify_file,
                    "reason": str(exc),
                }
            )
    _write_successor_authority_summary(
        Path(scratchpad),
        run_identity=successor_run_identity,
        driver_identity=successor_driver_identity,
        committed=successor_receipts,
        rejections=authority_rejections,
    )
    try:
        from execution_scope_runtime import materialize_execution_scope_assessments

        p1e_scope = materialize_execution_scope_assessments(
            Path(scratchpad), build_root=build_root
        )
    except Exception as exc:
        # Repair-then-degrade: immutable execution evidence remains available
        # for recovery, but no proof upgrade or negative severity cap may rely
        # on a missing P1-E assessment.
        p1e_scope = {
            "status": "DEGRADED",
            "materialized": 0,
            "issues": [f"P1E_RUNTIME_DEGRADED:{type(exc).__name__}:{exc}"],
        }
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return {
        "status": "degraded" if authority_rejections else "ok",
        "counts": counts,
        "files_annotated": annotated,
        "successor_receipts": successor_receipts,
        "authority_rejections": len(authority_rejections),
        "p1e_execution_scope": p1e_scope,
        "build_root": str(build_root),
        "prewarm_ok": prewarm_ok,
        "prewarm_note": prewarm_note,
        "elapsed_s": time.time() - t_start,
    }


__all__ = [
    "ExecResult",
    "run_phase5b_mechanical_verify",
    "_load_registry",
    "_ensure_l1_registry_entries",
    "_find_build_root",
    "_read_recon_build_root",
    "_format_test_command",
    "_classify_non_evm_outcome",
    "_classify_evm_outcome",
    "_recommended_tag",
    "flip_verdict_on_integrity_downgrade",
    "read_verdict_manifest",
    "_is_race_bug_class",
    "_inject_go_race_flag",
    "_load_race_bug_class_map",
    "_RACE_TIMEOUT_MULTIPLIER",
]
