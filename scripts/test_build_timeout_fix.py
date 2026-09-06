"""v2.2.3 build-timeout fix.

Two coordinated changes validated here:

1. recon_prepass._scale_build_timeout — the ceiling is raised (1800 -> 5400) and
   made ops-overridable via PLAMEN_BUILD_TIMEOUT_CEILING_S, read per-call. The old
   1800s hard ceiling clamped ~5.6x below the formula's own estimate for a
   dependency-heavy `--via-ir` repo, so the cold whole-project build TIMEOUTed and
   degraded evidence (Slither -> approximate graph; PoCs -> [CODE-TRACE]).

2. mechanical_verify._prewarm_build — a one-time best-effort compile warms the
   build cache before the per-finding test loop, so a cold repo doesn't have to
   compile inside a single per-test budget (which TIMEOUTs and caps at
   [CODE-TRACE]). Best-effort + non-fatal.

All generic (no protocol names): file-count scaling, env overrides, cache warming.
"""
import subprocess

import recon_prepass as RP
import mechanical_verify as MV


class _FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# --------------------------------------------------------------------------- #
# 1. recon ceiling: raised default + env override, read per-call
# --------------------------------------------------------------------------- #
class TestBuildTimeoutCeiling:
    def test_default_ceiling_raised_from_1800(self):
        # Regression guard: the old 30-min ceiling is gone.
        assert RP._BUILD_TIMEOUT_CEILING_S >= 5400
        assert RP._build_timeout_ceiling() >= 5400

    def test_dep_heavy_repo_clamps_at_default_not_1800(self, monkeypatch):
        monkeypatch.delenv("PLAMEN_BUILD_TIMEOUT_CEILING_S", raising=False)
        # ~1847 .sol compile units (large dependency-heavy repo): formula = 600 + 4*1847 = 7988,
        # which now clamps to the 5400 default, NOT the old 1800.
        got = RP._scale_build_timeout(600, 1847)
        assert got == RP._BUILD_TIMEOUT_CEILING_S == 5400
        assert got > 1800  # the whole point

    def test_env_override_raises_ceiling(self, monkeypatch):
        monkeypatch.setenv("PLAMEN_BUILD_TIMEOUT_CEILING_S", "9000")
        # formula 7988 < 9000 -> returns the true scaled value, unclamped
        assert RP._scale_build_timeout(600, 1847) == 7988
        assert RP._build_timeout_ceiling() == 9000

    def test_env_override_can_lower_ceiling(self, monkeypatch):
        monkeypatch.setenv("PLAMEN_BUILD_TIMEOUT_CEILING_S", "900")
        assert RP._scale_build_timeout(600, 1847) == 900

    def test_env_garbage_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("PLAMEN_BUILD_TIMEOUT_CEILING_S", "not-a-number")
        assert RP._build_timeout_ceiling() == RP._BUILD_TIMEOUT_CEILING_S

    def test_fast_build_still_returns_immediately(self, monkeypatch):
        monkeypatch.delenv("PLAMEN_BUILD_TIMEOUT_CEILING_S", raising=False)
        # A small repo is unaffected by the raised ceiling — the per-file term
        # dominates far below the cap.
        assert RP._scale_build_timeout(600, 10) == 640


# --------------------------------------------------------------------------- #
# 2. verify pre-warm: warms cache, best-effort, never fatal
# --------------------------------------------------------------------------- #
class TestPrewarmBuild:
    def test_evm_prewarm_success(self, monkeypatch, tmp_path):
        seen = {}

        def _fake_run(cmd, **kw):
            seen["cmd"] = cmd
            seen["cwd"] = kw.get("cwd")
            return _FakeProc(returncode=0)

        monkeypatch.setattr(MV, "_run_owned_process", _fake_run)
        ok, note = MV._prewarm_build(tmp_path, "evm", {}, 2400)
        assert ok is True
        assert "warm ok" in note
        assert seen["cmd"][-1] == "build"  # forge build
        assert seen["cwd"] == str(tmp_path)

    def test_timeout_is_non_fatal(self, monkeypatch, tmp_path):
        def _boom(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw.get("timeout", 1))

        monkeypatch.setattr(MV, "_run_owned_process", _boom)
        ok, note = MV._prewarm_build(tmp_path, "evm", {}, 5)
        assert ok is False
        assert "exceeded" in note  # cache left as-is, loop proceeds

    def test_nonzero_build_is_non_fatal(self, monkeypatch, tmp_path):
        monkeypatch.setattr(MV, "_run_owned_process",
                            lambda cmd, **kw: _FakeProc(returncode=1))
        ok, note = MV._prewarm_build(tmp_path, "evm", {}, 60)
        assert ok is False
        assert "rc=1" in note

    def test_non_evm_without_build_command_skips(self, tmp_path):
        # empty registry for the language -> nothing to run, clean skip
        ok, note = MV._prewarm_build(tmp_path, "aptos", {}, 60)
        assert ok is False
        assert "no build_command" in note

    def test_non_evm_uses_registry_build_command(self, monkeypatch, tmp_path):
        seen = {}
        monkeypatch.setattr(MV, "_run_owned_process",
                            lambda cmd, **kw: seen.update(cmd=cmd) or _FakeProc(0))
        reg = {"l1_rust": {"build_command": "cargo build --all-targets"}}
        ok, note = MV._prewarm_build(tmp_path, "l1_rust", reg, 60)
        assert ok is True
        assert seen["cmd"][:1] == ["cargo"] or seen["cmd"][0].endswith("cargo") \
            or "cargo" in seen["cmd"][0]

    def test_arbitrary_exception_never_raises(self, monkeypatch, tmp_path):
        def _explode(cmd, **kw):
            raise ValueError("unexpected")

        monkeypatch.setattr(MV, "_run_owned_process", _explode)
        ok, note = MV._prewarm_build(tmp_path, "evm", {}, 60)
        assert ok is False
        assert "error" in note


# --------------------------------------------------------------------------- #
# 3. pre-warm is wired into the phase and surfaced in the summary
# --------------------------------------------------------------------------- #
class TestPrewarmWiredIntoPhase:
    def test_phase_calls_prewarm_and_reports_it(self, monkeypatch, tmp_path):
        # one synthetic verify file so the phase does not short-circuit
        (tmp_path / "verify_H-01.md").write_text(
            "# verify H-01\n**Location**: `Foo.sol:L1`\n", encoding="utf-8")

        calls = {"prewarm": 0}

        def _fake_prewarm(build_root, lang, registry, timeout_s):
            calls["prewarm"] += 1
            calls["timeout"] = timeout_s
            return (True, "warm ok (rc=0) in 3s")

        monkeypatch.setattr(MV, "_prewarm_build", _fake_prewarm)
        # neutralize toolchain gate + the real test runner + build-root heuristic
        monkeypatch.setattr(MV, "_toolchain_binary_for", lambda lang: "")
        monkeypatch.setattr(MV, "_read_recon_build_root", lambda s, l: tmp_path)
        monkeypatch.setattr(
            MV, "_run_test_for_finding",
            lambda vf, br, lang, reg, tt, project_root=None, **kwargs: MV.ExecResult(
                verify_file=vf.name, finding_id="H-01", language=lang,
                status="PASS"),
        )
        monkeypatch.setattr(MV, "_annotate_verify_file", lambda vf, r: True)

        out = MV.run_phase5b_mechanical_verify(tmp_path, tmp_path, "evm")

        assert calls["prewarm"] == 1                      # warmed exactly once
        assert calls["timeout"] == MV._DEFAULT_BUILD_TIMEOUT_S
        assert out["prewarm_ok"] is True
        assert "warm ok" in out["prewarm_note"]
        assert out["counts"].get("PASS") == 1


# --------------------------------------------------------------------------- #
# 4. via-ir "not a hang" heads-up (UX: cold via-ir build looks like a hang)
# --------------------------------------------------------------------------- #
class TestViaIrWarning:
    def test_detects_via_ir_hyphen(self, tmp_path):
        (tmp_path / "foundry.toml").write_text(
            "[profile.default]\nvia-ir = true\n", encoding="utf-8")
        assert RP._foundry_via_ir_root(tmp_path) == tmp_path.resolve()

    def test_detects_via_ir_underscore(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("via_ir=true\n", encoding="utf-8")
        assert RP._foundry_via_ir_root(tmp_path) is not None

    def test_via_ir_false_not_detected(self, tmp_path):
        (tmp_path / "foundry.toml").write_text("via-ir = false\n", encoding="utf-8")
        assert RP._foundry_via_ir_root(tmp_path) is None

    def test_no_via_ir_setting(self, tmp_path):
        (tmp_path / "foundry.toml").write_text(
            "[profile.default]\nsrc='src'\n", encoding="utf-8")
        assert RP._foundry_via_ir_root(tmp_path) is None

    def test_no_foundry_toml(self, tmp_path):
        assert RP._foundry_via_ir_root(tmp_path) is None

    def test_detects_in_parent_root(self, tmp_path):
        # scope dir is a subdir; foundry root (with via-ir) is a parent
        (tmp_path / "foundry.toml").write_text("via-ir = true\n", encoding="utf-8")
        sub = tmp_path / "contracts" / "src"
        sub.mkdir(parents=True)
        assert RP._foundry_via_ir_root(sub) == tmp_path.resolve()

    def test_warns_once_then_silent(self, monkeypatch, tmp_path, capsys):
        (tmp_path / "foundry.toml").write_text(
            "[profile.default]\nvia-ir = true\n", encoding="utf-8")
        monkeypatch.setattr(RP, "_VIA_IR_WARNED", False)
        RP._maybe_warn_via_ir_build(tmp_path)
        err1 = capsys.readouterr().err
        assert "via-ir build detected" in err1 and "NOT a hang" in err1
        # second call is a no-op (flag set) — no duplicate spam
        RP._maybe_warn_via_ir_build(tmp_path)
        assert capsys.readouterr().err == ""

    def test_no_warn_without_via_ir(self, monkeypatch, tmp_path, capsys):
        (tmp_path / "foundry.toml").write_text("src='src'\n", encoding="utf-8")
        monkeypatch.setattr(RP, "_VIA_IR_WARNED", False)
        RP._maybe_warn_via_ir_build(tmp_path)
        assert capsys.readouterr().err == ""
