"""Ecosystem-path fix regression tests (non-EVM language misconfiguration +
recon-prepass build parity).

Covers:
- STEP 2A: language<->source-extension consistency startup gate
  (_validate_language_source_consistency / _dominant_source_suffix).
- STEP 2C: recon-prepass non-EVM build-root resolution (_resolve_build_root).

Run: python -m pytest test_ecosystem_path_fixes.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import plamen_driver as D  # noqa: E402
import recon_prepass as RP  # noqa: E402


def _touch(p: Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// src\n", encoding="utf-8")


# ---- STEP 2A: language consistency gate ----------------------------------


def test_dominant_suffix_picks_rust_over_none(tmp_path: Path):
    proj = tmp_path / "crate" / "src"
    _touch(proj / "lib.rs")
    _touch(proj / "state.rs")
    dominant, counts = D._dominant_source_suffix(proj)
    assert dominant == ".rs"
    assert counts[".rs"] >= 2


def test_language_gate_halts_on_definite_contradiction(tmp_path: Path):
    """language=evm but only .rs files present => fail-fast halt with an
    actionable message naming the candidate language(s)."""
    proj = tmp_path / "crate" / "src"
    _touch(proj / "lib.rs")
    ok, msg = D._validate_language_source_consistency(proj, "evm")
    assert ok is False
    assert "language=evm" in msg
    assert ".rs" in msg
    # Suggests a recognized Rust language.
    assert ("solana" in msg) or ("soroban" in msg)


def test_language_gate_passes_on_match(tmp_path: Path):
    proj = tmp_path / "crate" / "src"
    _touch(proj / "lib.rs")
    ok, msg = D._validate_language_source_consistency(proj, "solana")
    assert ok is True
    assert "OK" in msg


def test_language_gate_continues_when_indeterminate(tmp_path: Path):
    """No recognized source files in PROJECT_PATH or its consulted ancestors
    => WARN + continue (never block on an indeterminate signal)."""
    # Nest deeply so the 2-ancestor fallback also sees only empty dirs (the
    # pytest tmp root may contain sibling-test source files above this).
    proj = tmp_path / "iso_a" / "iso_b" / "iso_c" / "empty"
    proj.mkdir(parents=True)
    (proj / "README.md").write_text("docs\n", encoding="utf-8")
    ok, msg = D._validate_language_source_consistency(proj, "evm")
    assert ok is True
    assert "indeterminate" in msg


def test_source_suffix_scan_stops_at_total_entry_budget(
    tmp_path: Path, monkeypatch,
):
    """Unrecognized files must not make the supposedly bounded walk unbounded."""
    visited = 0

    def fake_walk(_root):
        nonlocal visited
        for idx in range(1_000):
            visited += 1
            yield str(tmp_path / f"d{idx}"), [f"child{idx}"], [f"note{idx}.txt"]

    monkeypatch.setattr(D.os, "walk", fake_walk)
    counts = D._count_source_suffixes_under(
        tmp_path, {".sol"}, file_cap=4_000, entry_cap=8, dir_cap=100,
    )

    assert counts == {".sol": 0}
    assert visited <= 4


def test_manifest_scan_stops_at_total_entry_budget(tmp_path: Path, monkeypatch):
    """A found manifest must not disable the traversal budget for its tree."""
    visited = 0

    def fake_walk(_root):
        nonlocal visited
        for idx in range(1_000):
            visited += 1
            files = ["package.json"] if idx == 0 else [f"note{idx}.txt"]
            yield str(tmp_path / f"d{idx}"), [f"child{idx}"], files

    monkeypatch.setattr(D.os, "walk", fake_walk)
    markers = D._scan_manifests_for_markers(
        tmp_path,
        {"package.json"},
        {"evm": ("hardhat",)},
        max_entries=8,
        max_dirs=100,
    )

    assert markers == {"evm": 0}
    assert visited <= 4


def test_language_gate_finds_solidity_via_ancestor_walk(tmp_path: Path):
    """A scope-dir PROJECT_PATH still sees source files via the ancestor walk
    is not needed here, but the dominant-extension scan must see in-tree .sol."""
    proj = tmp_path / "contracts"
    _touch(proj / "Vault.sol")
    ok, _msg = D._validate_language_source_consistency(proj, "evm")
    assert ok is True


# ---- STEP 2C: recon-prepass build-root resolution ------------------------


def test_resolve_build_root_walks_up_to_cargo_manifest(tmp_path: Path):
    root = tmp_path / "crate"
    (root / "src").mkdir(parents=True)
    (root / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    scope = root / "src"
    resolved = RP._resolve_build_root(scope, "solana")
    assert resolved == root.resolve()


def test_resolve_build_root_none_when_no_manifest(tmp_path: Path):
    scope = tmp_path / "crate" / "src"
    scope.mkdir(parents=True)
    assert RP._resolve_build_root(scope, "solana") is None


def test_resolve_build_root_move_manifest(tmp_path: Path):
    root = tmp_path / "pkg"
    (root / "sources").mkdir(parents=True)
    (root / "Move.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    resolved = RP._resolve_build_root(root / "sources", "aptos")
    assert resolved == root.resolve()


# ---- Mechanical ecosystem detector (_detect_ecosystem) -------------------


def _manifest(p: Path, content: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


def test_detect_evm_from_sol_only(tmp_path: Path):
    proj = tmp_path / "contracts"
    _touch(proj / "Vault.sol")
    _touch(proj / "Token.sol")
    lang, conf, sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("evm", "high")
    assert sig["counts"][".sol"] >= 2


def test_detect_solana_from_anchor_lang_cargo(tmp_path: Path):
    proj = tmp_path / "program"
    _touch(proj / "src" / "lib.rs")
    _manifest(
        proj / "Cargo.toml",
        "[dependencies]\nanchor-lang = \"0.30\"\n",
    )
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("solana", "high")


def test_detect_soroban_from_soroban_sdk_cargo(tmp_path: Path):
    proj = tmp_path / "contract"
    _touch(proj / "src" / "lib.rs")
    _manifest(
        proj / "Cargo.toml",
        "[dependencies]\nsoroban-sdk = \"21\"\n",
    )
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("soroban", "high")


def test_detect_solana_from_anchor_toml_presence(tmp_path: Path):
    proj = tmp_path / "program"
    _touch(proj / "programs" / "p" / "src" / "lib.rs")
    # Anchor.toml present anywhere => solana filename-marker, even with a bare
    # Cargo.toml that carries no rust dependency markers.
    _manifest(proj / "Anchor.toml", "[provider]\ncluster = \"localnet\"\n")
    _manifest(proj / "Cargo.toml", "[workspace]\n")
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("solana", "high")


def test_detect_rust_medium_default_when_no_markers(tmp_path: Path):
    proj = tmp_path / "crate"
    _touch(proj / "src" / "lib.rs")
    _manifest(proj / "Cargo.toml", "[package]\nname = \"x\"\n")
    lang, conf, sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("solana", "medium")
    assert "no manifest" in sig["reason"]


def test_detect_rust_conflict_returns_none(tmp_path: Path):
    """Both anchor-lang AND soroban-sdk present => CONFLICT => keep configured.
    Recall-safety: never pick a winner by magnitude."""
    proj = tmp_path / "crate"
    _touch(proj / "src" / "lib.rs")
    _manifest(
        proj / "Cargo.toml",
        "[dependencies]\nanchor-lang = \"0.30\"\nsoroban-sdk = \"21\"\n",
    )
    lang, conf, sig = D._detect_ecosystem(proj)
    assert (lang, conf) == (None, "none")
    assert "conflict" in sig["reason"].lower()


def test_detect_sui_from_sui_framework(tmp_path: Path):
    proj = tmp_path / "pkg"
    _touch(proj / "sources" / "m.move")
    _manifest(
        proj / "Move.toml",
        "[dependencies]\nSui = { local = \"x\" }\nsui-framework = \"1\"\n",
    )
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("sui", "high")


def test_detect_aptos_from_aptos_framework(tmp_path: Path):
    proj = tmp_path / "pkg"
    _touch(proj / "sources" / "m.move")
    _manifest(
        proj / "Move.toml",
        "[dependencies]\naptos-framework = { git = \"x\" }\n",
    )
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("aptos", "high")


def test_detect_move_conflict_returns_none(tmp_path: Path):
    proj = tmp_path / "pkg"
    _touch(proj / "sources" / "m.move")
    _manifest(
        proj / "Move.toml",
        "[dependencies]\nsui-framework = \"1\"\naptos-framework = \"1\"\n",
    )
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == (None, "none")


def test_detect_none_when_no_sources(tmp_path: Path):
    proj = tmp_path / "iso_a" / "iso_b" / "iso_c" / "empty"
    proj.mkdir(parents=True)
    (proj / "README.md").write_text("docs\n", encoding="utf-8")
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == (None, "none")


def test_detect_move_medium_default_when_no_markers(tmp_path: Path):
    proj = tmp_path / "pkg"
    _touch(proj / "sources" / "m.move")
    _manifest(proj / "Move.toml", "[package]\nname = \"x\"\n")
    lang, conf, _sig = D._detect_ecosystem(proj)
    assert (lang, conf) == ("sui", "medium")


# ---- Startup auto-correct integration ------------------------------------


def _write_config(tmp_path: Path, project_root: Path, language: str) -> Path:
    import json
    cfg = {
        "project_root": str(project_root),
        "scratchpad": str(project_root / ".scratchpad"),
        "language": language,
        "mode": "core",
        "pipeline": "sc",
        "extra_key": "preserved",
    }
    cp = tmp_path / "config.json"
    cp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return cp


def test_autocorrect_overrides_and_persists(tmp_path: Path):
    """config.language='evm' but a Solana source tree => in-memory override to
    'solana', config.json rewritten, other keys preserved, NO sys.exit."""
    import json
    proj = tmp_path / "program"
    _touch(proj / "src" / "lib.rs")
    _manifest(proj / "Cargo.toml", "[dependencies]\nanchor-lang = \"0.30\"\n")
    cp = _write_config(tmp_path, proj, "evm")

    config = json.loads(cp.read_text(encoding="utf-8"))
    detected, conf, _sig = D._detect_ecosystem(config["project_root"])
    assert (detected, conf) == ("solana", "high")
    # Simulate the startup auto-correct flow.
    config["language"] = detected
    persisted = D._persist_corrected_language(cp, config, detected)
    assert persisted is True
    assert config["language"] == "solana"  # in-memory authoritative
    on_disk = json.loads(cp.read_text(encoding="utf-8"))
    assert on_disk["language"] == "solana"
    assert on_disk["extra_key"] == "preserved"  # other keys + order preserved


def test_autocorrect_conflict_keeps_configured(tmp_path: Path):
    """config.language='solana' + conflicting rust markers => detection is
    none, configured value UNCHANGED, no override."""
    proj = tmp_path / "crate"
    _touch(proj / "src" / "lib.rs")
    _manifest(
        proj / "Cargo.toml",
        "[dependencies]\nanchor-lang = \"0.30\"\nsoroban-sdk = \"21\"\n",
    )
    detected, conf, _sig = D._detect_ecosystem(proj)
    assert (detected, conf) == (None, "none")
    # The startup branch only overrides on high/medium; here it keeps configured.
    configured = "solana"
    override = detected is not None and conf in ("high", "medium") \
        and detected != configured
    assert override is False


# ---- L1 guard: SC ecosystem detector must NOT override L1 rust/go language ----

def test_language_correction_l1_keeps_configured_rust():
    """L1 GUARD regression: a Rust L1 codebase has .rs files so the
    SC ecosystem detector returns 'solana'; for pipeline=l1 we MUST keep the
    configured rust/go and never inject Solana-SC skills."""
    import plamen_driver as D
    assert D._language_correction("rust", "solana", "medium", "l1") is None
    assert D._language_correction("rust", "solana", "high", "l1") is None
    assert D._language_correction("go", "evm", "high", "l1") is None


def test_language_correction_high_confidence_overrides():
    """HIGH confidence = manifest-disambiguated (anchor-lang->solana,
    soroban-sdk->soroban, .sol->evm, Move.toml markers). Genuine misconfig
    proof -> override is allowed."""
    import plamen_driver as D
    assert D._language_correction("evm", "solana", "high", "sc") == "solana"
    assert D._language_correction("solana", "soroban", "high", "sc") == "soroban"
    assert D._language_correction("aptos", "sui", "high", "sc") == "sui"


def test_language_correction_medium_does_not_clobber_configured():
    """THE BROADER FIX: MEDIUM = suffix-only fallback that returns the family
    DEFAULT (.rs->solana, .move->one of sui/aptos). It cannot tell apart
    same-suffix families, so it must NEVER override an EXPLICITLY configured
    language. Protects Soroban->Solana, Aptos<->Sui, native-Solana, Rust-L1."""
    import plamen_driver as D
    # Soroban project whose Cargo didn't trip soroban-sdk -> .rs suffix-only
    # -> medium 'solana'. Must KEEP configured soroban.
    assert D._language_correction("soroban", "solana", "medium", "sc") is None
    # Aptos project -> .move suffix-only could default to sui. Must KEEP aptos.
    assert D._language_correction("aptos", "sui", "medium", "sc") is None
    assert D._language_correction("sui", "aptos", "medium", "sc") is None
    # Rust-L1 mislabeled as SC: .rs suffix-only medium solana. Must KEEP rust.
    assert D._language_correction("rust", "solana", "medium", "sc") is None


def test_language_correction_medium_fills_unset_only():
    """MEDIUM may only FILL an unset/empty configured language, never clobber."""
    import plamen_driver as D
    assert D._language_correction("", "solana", "medium", "sc") == "solana"
    assert D._language_correction(None, "aptos", "medium", "sc") == "aptos"


def test_language_correction_sc_noop_cases():
    """No correction when confidence is low/none, signal matches, or absent."""
    import plamen_driver as D
    assert D._language_correction("solana", "solana", "high", "sc") is None   # match
    assert D._language_correction("evm", "solana", "low", "sc") is None       # low conf
    assert D._language_correction("evm", None, "none", "sc") is None          # no detection


def test_detect_solana_pinocchio_high_confidence(tmp_path: Path):
    """A Pinocchio Solana program depends on `pinocchio` and reimplements the
    entrypoint, so it often has NEITHER anchor-lang NOR solana-program. The
    marker vocab must still resolve it to HIGH-confidence solana (not a
    suffix-only medium guess)."""
    crate = tmp_path / "pinocchio_prog"
    _touch(crate / "src" / "lib.rs")
    _touch(crate / "src" / "processor.rs")
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "p"\n\n[dependencies]\n'
        'pinocchio = "0.7"\npinocchio-system = "0.2"\n',
        encoding="utf-8",
    )
    lang, conf, _ = D._detect_ecosystem(crate)
    assert lang == "solana"
    assert conf == "high"


def test_detect_solana_native_sdk_high_confidence(tmp_path: Path):
    """Native Solana via solana-sdk (no anchor) resolves HIGH solana."""
    crate = tmp_path / "native_prog"
    _touch(crate / "src" / "lib.rs")
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "n"\n\n[dependencies]\nsolana-sdk = "2.1"\n',
        encoding="utf-8",
    )
    lang, conf, _ = D._detect_ecosystem(crate)
    assert lang == "solana"
    assert conf == "high"


def test_detect_soroban_not_confused_with_solana(tmp_path: Path):
    """Soroban (soroban-sdk) resolves HIGH soroban; the expanded solana vocab
    must not steal it (soroban-sdk and the solana markers never co-occur)."""
    crate = tmp_path / "soro"
    _touch(crate / "src" / "lib.rs")
    (crate / "Cargo.toml").write_text(
        '[package]\nname = "s"\n\n[dependencies]\nsoroban-sdk = "21"\n',
        encoding="utf-8",
    )
    lang, conf, _ = D._detect_ecosystem(crate)
    assert lang == "soroban"
    assert conf == "high"
