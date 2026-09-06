"""Tests for Rust-ecosystem recon-build hardening in recon_prepass._write_build_status.

Covers (per the hardening spec):
  (a) Rust-ecosystem builds (soroban/solana/cargo) carry CARGO_INCREMENTAL=0;
      EVM (forge) does NOT.
  (b) A first-attempt non-timeout failure triggers exactly ONE retry, and a
      second-attempt success is the recorded outcome.
  (c) A timeout (rc=124) does NOT retry.
  (d) A binary-not-found (rc=127) does NOT retry.
  (e) Final failure (after the single retry) still degrades + surfaces loudly
      (Status FAILED, full error text retained, WARNING logged).

All builds are mocked — no real `cargo build` is ever run. A scripted fake
`_run_hardened` returns pre-set (rc, output) tuples per call and records the
`env` it was handed so we can assert the injected variables.
"""
import importlib
import logging

import recon_prepass as rp


# ---------------------------------------------------------------------------
# Test scaffolding
# ---------------------------------------------------------------------------
class FakeRunHardened:
    """Scripted _run_hardened: returns (rc, output) from `scripted` per call.
    Records the env each call received for assertion."""

    def __init__(self, scripted):
        self.scripted = list(scripted)
        self.calls = 0
        self.envs = []
        self.cmds = []

    def __call__(self, cmd, cwd=None, timeout=None, env=None, **_kwargs):
        self.envs.append(env)
        self.cmds.append(list(cmd))
        idx = min(self.calls, len(self.scripted) - 1)
        rc, out = self.scripted[idx]
        self.calls += 1
        return rc, out


def _setup_build(monkeypatch, tmp_path, *, key, scripted):
    """Patch _write_build_status's dependencies so it reaches _run_hardened
    deterministically for the given build `key`, with a scripted runner.
    Returns the FakeRunHardened instance."""
    monkeypatch.setattr(rp, "_select_build", lambda proj, lang: key)
    # Make graph-derive shortcut inert so we exercise the real build probe.
    monkeypatch.setattr(rp, "_graph_implies_compiles", lambda gs, lang: False)
    # Non-empty production sources + a resolvable build root for non-EVM keys.
    src = tmp_path / "lib.rs"
    src.write_text("fn main() {}\n", encoding="utf-8")
    monkeypatch.setattr(rp, "_production_source_files", lambda proj, suffixes: [src])
    monkeypatch.setattr(rp, "_resolve_build_root", lambda proj, key: tmp_path)
    monkeypatch.setattr(rp, "_resolve_evm_build_root", lambda proj: tmp_path)
    monkeypatch.setattr(rp, "_resolve_foundry_profile_for_recon", lambda cwd: None)
    # cargo / forge / etc. all "present".
    monkeypatch.setattr(rp.shutil, "which", lambda name: "/usr/bin/" + name)
    fake = FakeRunHardened(scripted)
    monkeypatch.setattr(rp, "_run_hardened", fake)
    return fake


def _read_status(scratch):
    return (scratch / "build_status.md").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# (a) env injection: rust gets CARGO_INCREMENTAL=0, EVM does not
# ---------------------------------------------------------------------------
def test_soroban_build_env_carries_cargo_incremental_zero(monkeypatch, tmp_path):
    fake = _setup_build(monkeypatch, tmp_path, key="soroban",
                        scripted=[(0, "Compiling\nFinished")])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "soroban")
    assert fake.calls == 1
    env = fake.envs[0]
    assert env is not None and env.get("CARGO_INCREMENTAL") == "0"
    # Full parent env inherited (sanity: PATH carried through).
    assert "PATH" in env or len(env) > 1


def test_solana_build_env_carries_cargo_incremental_zero(monkeypatch, tmp_path):
    # solana key: the recon branch builds via the on-chain toolchain. With
    # `anchor` absent but `cargo-build-sbf` present, the cmd becomes
    # ["cargo", "build-sbf"] — a cargo front-end, so the rust hardening applies.
    fake = _setup_build(monkeypatch, tmp_path, key="solana",
                        scripted=[(0, "Finished")])
    def _which(name):
        if name == "anchor":
            return None
        return "/usr/bin/" + name
    monkeypatch.setattr(rp.shutil, "which", _which)
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "solana")
    assert fake.calls == 1
    # cmd is the cargo-based sbf build, and env carries the hardening.
    assert fake.cmds[0][0] == "cargo"
    assert fake.envs[0].get("CARGO_INCREMENTAL") == "0"


def test_evm_forge_build_env_has_no_cargo_incremental(monkeypatch, tmp_path):
    fake = _setup_build(monkeypatch, tmp_path, key="evm_forge",
                        scripted=[(0, "Compiler run successful")])
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "evm")
    assert fake.calls == 1
    env = fake.envs[0]
    # EVM path with no FOUNDRY_PROFILE → env stays None (inherit), and in no
    # case is CARGO_INCREMENTAL injected for a non-cargo build.
    if env is not None:
        assert "CARGO_INCREMENTAL" not in env


def test_helper_is_generic_by_key_and_command():
    assert rp._is_rust_ecosystem_build("soroban", ["cargo", "build"]) is True
    assert rp._is_rust_ecosystem_build("solana", ["cargo", "build"]) is True
    # cargo front-ends recognized even under a non-rust key name.
    assert rp._is_rust_ecosystem_build("rust_l1", ["cargo", "build"]) is True
    assert rp._is_rust_ecosystem_build("xx", ["cargo-build-sbf"]) is True
    # EVM / Move / Sui are NOT rust-ecosystem.
    assert rp._is_rust_ecosystem_build("evm_forge", ["forge", "build"]) is False
    assert rp._is_rust_ecosystem_build("aptos", ["aptos", "move", "compile"]) is False
    assert rp._is_rust_ecosystem_build("sui", ["sui", "move", "build"]) is False
    # Never raises on junk.
    assert rp._is_rust_ecosystem_build(None, None) is False


# ---------------------------------------------------------------------------
# (b) first-attempt non-timeout failure → exactly one retry, success used
# ---------------------------------------------------------------------------
def test_nontimeout_failure_retries_once_and_uses_success(monkeypatch, tmp_path):
    fake = _setup_build(
        monkeypatch, tmp_path, key="soroban",
        scripted=[(101, "error: unexpected closing delimiter: }"),
                  (0, "Compiling\nFinished release")],
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "soroban")
    # Exactly two attempts: original + one retry.
    assert fake.calls == 2
    status = _read_status(scratch)
    assert "**Status**: SUCCESS" in status
    assert "**Exit Code**: 0" in status
    # Retry env also carries the hardening.
    assert fake.envs[1].get("CARGO_INCREMENTAL") == "0"


def test_nontimeout_failure_retries_at_most_once(monkeypatch, tmp_path):
    # Both attempts fail → bounded to exactly 2 calls (no infinite retry).
    fake = _setup_build(
        monkeypatch, tmp_path, key="soroban",
        scripted=[(101, "error A"), (101, "error B")],
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "soroban")
    assert fake.calls == 2


# ---------------------------------------------------------------------------
# (c) timeout (124) does NOT retry
# ---------------------------------------------------------------------------
def test_timeout_does_not_retry(monkeypatch, tmp_path):
    fake = _setup_build(
        monkeypatch, tmp_path, key="soroban",
        scripted=[(124, "timed out"), (0, "should-not-be-used")],
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "soroban")
    assert fake.calls == 1
    status = _read_status(scratch)
    assert "**Status**: TIMEOUT" in status


# ---------------------------------------------------------------------------
# (d) binary-not-found (127) does NOT retry
# ---------------------------------------------------------------------------
def test_binary_not_found_does_not_retry(monkeypatch, tmp_path):
    fake = _setup_build(
        monkeypatch, tmp_path, key="soroban",
        scripted=[(127, "cargo: command not found"), (0, "unused")],
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    rp._write_build_status(scratch, tmp_path, "soroban")
    assert fake.calls == 1
    status = _read_status(scratch)
    assert "**Status**: FAILED" in status
    assert "**Exit Code**: 127" in status


# ---------------------------------------------------------------------------
# (e) final failure after retry → loud + degraded, full error retained
# ---------------------------------------------------------------------------
def test_final_failure_degrades_loudly_and_retains_error(monkeypatch, tmp_path, caplog):
    err1 = "error: unexpected closing delimiter: } (attempt1)"
    err2 = "error: unexpected closing delimiter: } (attempt2-distinct-text)"
    fake = _setup_build(
        monkeypatch, tmp_path, key="soroban",
        scripted=[(101, err1), (101, err2)],
    )
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    with caplog.at_level(logging.WARNING, logger=rp.log.name):
        rp._write_build_status(scratch, tmp_path, "soroban")
    assert fake.calls == 2
    status = _read_status(scratch)
    # Degraded (not silent) — status FAILED with the rc surfaced.
    assert "**Status**: FAILED" in status
    assert "**Exit Code**: 101" in status
    # Full cargo error text of the FINAL attempt retained in the report.
    assert "attempt2-distinct-text" in status
    # Loud: both attempts logged + the degrade WARNING with the rc.
    text = caplog.text
    assert "retrying" in text.lower()
    assert "rc=101" in text
    assert "FAILED" in text


if __name__ == "__main__":
    import sys
    importlib.reload(rp)
    sys.exit(__import__("pytest").main([__file__, "-q"]))
