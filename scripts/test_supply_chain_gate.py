"""ITEM H2 — supply-chain / fail-closed pre-exec safety gate.

Hermetic tests (no network, no real scanner binaries): every scanner call is
monkeypatched. Covers:

  - gate_supply_chain() unit behavior: denylist hit, install-script/base64
    heuristic hit, CRITICAL scanner hit, scanner-absent hard stop, clean
    happy path, no-lockfile happy path, env skip override.
  - denylist_has_not_shrunk() invariant ("denylist-shrink = corruption").
  - recon_prepass._prepare_evm_build() integration: poisoned lockfile aborts
    BEFORE the install mock is invoked; clean lockfile leaves the install
    mock invocation unchanged (zero happy-path regression).
  - mechanical_verify.run_phase5b_mechanical_verify() integration: poisoned
    build_root aborts before the pre-warm build / per-finding test loop.

Poisoned-lockfile fixtures use a SYNTHETIC package name
(`plamen-test-evil-pkg@0.0.0`) — never a real CVE'd package.
"""
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scg():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("supply_chain_gate")


def _rp():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("recon_prepass")


def _mv():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    return importlib.import_module("mechanical_verify")


def _mk(p: Path, body: str = "{}"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _gate_scanner_payload(
    scg,
    tmp_path: Path,
    monkeypatch,
    *,
    scanner: str,
    lock_name: str,
    payload: dict,
):
    _mk(tmp_path / lock_name)
    monkeypatch.setattr(
        scg.shutil,
        "which",
        lambda name: f"/trusted/{name}" if name == scanner else None,
    )
    monkeypatch.setattr(
        scg,
        "_call_offline_scanner",
        lambda binary, lockfile: scg.OfflineScanResult(
            scg.OfflineScanState.SUCCEEDED,
            output=json.dumps(payload),
            returncode=1,
        ),
    )
    return scg.gate_supply_chain(tmp_path, denylist=[])


# ─────────────────────────────────────────────────────────────────────────
# denylist_has_not_shrunk — "denylist-shrink = corruption" mechanical check
# ─────────────────────────────────────────────────────────────────────────

def test_denylist_shrink_is_detected():
    scg = _scg()
    baseline = frozenset({"evil-pkg-a", "evil-pkg-b", "evil-pkg-c"})
    shrunk = frozenset({"evil-pkg-a", "evil-pkg-b"})  # one entry silently dropped
    assert scg.denylist_has_not_shrunk(baseline, shrunk) is False


def test_denylist_growth_or_stable_is_fine():
    scg = _scg()
    baseline = frozenset({"evil-pkg-a", "evil-pkg-b"})
    same = frozenset({"evil-pkg-a", "evil-pkg-b"})
    grown = frozenset({"evil-pkg-a", "evil-pkg-b", "evil-pkg-c"})
    assert scg.denylist_has_not_shrunk(baseline, same) is True
    assert scg.denylist_has_not_shrunk(baseline, grown) is True


def test_default_denylist_never_shrinks_below_recorded_baseline():
    """Regression guard: whatever DEFAULT_IOC_DENYLIST contains today must
    stay a subset of what it contains later. Ships empty — this test still
    guards against a future accidental replace-instead-of-append edit."""
    scg = _scg()
    recorded_baseline = frozenset()  # DEFAULT_IOC_DENYLIST ships empty
    assert scg.denylist_has_not_shrunk(recorded_baseline, scg.DEFAULT_IOC_DENYLIST)


# ─────────────────────────────────────────────────────────────────────────
# gate_supply_chain — unit behavior
# ─────────────────────────────────────────────────────────────────────────

def test_no_lockfile_is_clean_happy_path(tmp_path):
    scg = _scg()
    # Nothing at all under root — degrades safely, never aborts.
    scg.gate_supply_chain(tmp_path)


def test_plamen_scratchpad_siblings_are_not_dependency_inputs(tmp_path):
    scg = _scg()
    _mk(tmp_path / "package-lock.json")
    _mk(
        tmp_path
        / ".ScRaTcHpAd-rerun-old"
        / "_recon_prepass_auxiliary_transactions"
        / "payload"
        / "package-lock.json"
    )
    _mk(
        tmp_path
        / ".plamen-stale-snapshots-older"
        / "archived"
        / "Cargo.lock"
    )

    assert scg._find_lockfiles(tmp_path) == [tmp_path / "package-lock.json"]


def test_scanner_json_requires_one_exact_value_and_trailing_whitespace_only():
    scg = _scg()
    assert scg._validated_scanner_json(
        "osv-scanner", '  {"results":[]}\r\n'
    )[0] == {"results": []}
    assert scg._validated_scanner_json(
        "osv-scanner", 'progress\n{"results":[]}'
    )[0] is None
    assert scg._validated_scanner_json(
        "osv-scanner", '{"results":[]}\nsecond-value'
    )[0] is None


def test_scanner_stderr_prose_is_not_json_classification_authority(
    tmp_path, monkeypatch
):
    scg = _scg()
    lockfile = tmp_path / "package-lock.json"
    _mk(lockfile)
    monkeypatch.setattr(
        scg,
        "run_owned_process",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout='{"results":[]}',
            stderr="CRITICAL MALICIOUS MAL-2026-701 progress only",
        ),
    )
    result = scg._call_offline_scanner("osv-scanner", lockfile)
    assert result.state is scg.OfflineScanState.SUCCEEDED
    assert json.loads(result.output) == {"results": []}


def test_clean_lockfile_with_available_scanner_passes(tmp_path, monkeypatch):
    scg = _scg()
    _mk(tmp_path / "package-lock.json", '{"dependencies": {"left-pad": "1.0.0"}}')
    monkeypatch.setattr(scg.shutil, "which", lambda b: "/usr/bin/" + b if b == "osv-scanner" else None)
    monkeypatch.setattr(
        scg, "_call_offline_scanner",
        lambda binary, lf: scg.OfflineScanResult(
            scg.OfflineScanState.SUCCEEDED,
            output='{"results":[]}',
        ),
    )
    scg.gate_supply_chain(tmp_path)  # must not raise


def test_denylist_hit_aborts(tmp_path):
    scg = _scg()
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(tmp_path / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)
    with pytest.raises(scg.SupplyChainAbortError):
        scg.gate_supply_chain(tmp_path, denylist=[poisoned_pkg])


def test_denylist_miss_does_not_abort_on_denylist_alone(tmp_path, monkeypatch):
    scg = _scg()
    _mk(tmp_path / "package-lock.json", '{"dependencies": {"left-pad": "1.0.0"}}')
    monkeypatch.setattr(scg.shutil, "which", lambda b: "/usr/bin/" + b if b == "osv-scanner" else None)
    monkeypatch.setattr(
        scg, "_call_offline_scanner",
        lambda binary, lf: scg.OfflineScanResult(
            scg.OfflineScanState.SUCCEEDED,
            output='{"results":[]}',
        ),
    )
    scg.gate_supply_chain(tmp_path, denylist=["plamen-test-evil-pkg"])  # no match, no abort


def test_scanner_typed_mal_advisory_hit_aborts(tmp_path, monkeypatch):
    scg = _scg()
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(tmp_path / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)
    monkeypatch.setattr(scg.shutil, "which", lambda b: "/usr/bin/" + b if b == "osv-scanner" else None)
    monkeypatch.setattr(
        scg, "_call_offline_scanner",
        lambda binary, lf: scg.OfflineScanResult(
            scg.OfflineScanState.SUCCEEDED,
            output=json.dumps({
                "results": [{
                    "packages": [{
                        "vulnerabilities": [{
                            "id": "MAL-2026-701",
                            "summary": f"Malicious code in {poisoned_pkg}",
                        }],
                    }],
                }],
            }),
        ),
    )
    with pytest.raises(scg.SupplyChainAbortError):
        scg.gate_supply_chain(tmp_path, denylist=[])


def test_osv_ordinary_critical_vulnerabilities_do_not_abort(
    tmp_path, monkeypatch, caplog
):
    """The DODO-shaped regression: severity is audit risk, not malware."""
    scg = _scg()
    vulnerabilities = [
        {
            "id": f"GHSA-fixture-{index:04d}",
            "summary": "A malicious user can exploit this vulnerability",
            "database_specific": {"severity": "CRITICAL"},
        }
        for index in range(151)
    ]
    _gate_scanner_payload(
        scg,
        tmp_path,
        monkeypatch,
        scanner="osv-scanner",
        lock_name="package-lock.json",
        payload={
            "results": [{
                "packages": [{"vulnerabilities": vulnerabilities}],
            }],
        },
    )
    assert any(
        "151 ordinary dependency vulnerability" in record.message
        for record in caplog.records
    )


def test_osv_mal_alias_aborts(tmp_path, monkeypatch):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="typed malicious"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="osv-scanner",
            lock_name="package-lock.json",
            payload={
                "results": [{
                    "packages": [{
                        "vulnerabilities": [{
                            "id": "GHSA-fixture-safe-shape",
                            "aliases": ["MAL-2026-11961"],
                        }],
                    }],
                }],
            },
        )


def test_osv_provider_specific_words_and_objects_are_not_untyped_markers(
    tmp_path, monkeypatch
):
    scg = _scg()
    _gate_scanner_payload(
        scg,
        tmp_path,
        monkeypatch,
        scanner="osv-scanner",
        lock_name="package-lock.json",
        payload={
            "results": [{
                "packages": [{
                    "vulnerabilities": [{
                        "id": "GHSA-fixture-not-malware",
                        "summary": "MAL-2026-1 CRITICAL MALICIOUS",
                        "database_specific": {
                            "severity": "CRITICAL",
                            "iocs": {"domains": ["example.invalid"]},
                            "malicious-packages-origins": [{"source": "text"}],
                        },
                    }],
                }],
            }],
        },
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"results": {}},
        {"results": [{}]},
        {"results": [{"packages": [{}]}]},
        {"results": [{"packages": [{"vulnerabilities": [{}]}]}]},
        {"results": [{"packages": [{"vulnerabilities": [{
            "id": "MAL-not-a-governed-id",
        }]}]}]},
        {"results": [{"packages": [{"vulnerabilities": [{
            "id": "GHSA-fixture", "aliases": "MAL-2026-1",
        }]}]}]},
    ],
)
def test_osv_malformed_or_missing_typed_shape_fails_closed(
    tmp_path, monkeypatch, payload
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="malformed|classif"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="osv-scanner",
            lock_name="package-lock.json",
            payload=payload,
        )


def test_npm_critical_and_malicious_prose_is_not_a_malware_marker(
    tmp_path, monkeypatch
):
    scg = _scg()
    _gate_scanner_payload(
        scg,
        tmp_path,
        monkeypatch,
        scanner="npm",
        lock_name="package-lock.json",
        payload={
            "auditReportVersion": 2,
            "vulnerabilities": {
                "fixture": {
                    "severity": "critical",
                    "via": [{
                        "source": 123,
                        "title": "MAL-2026-1: malicious critical payload",
                        "severity": "critical",
                        "cwe": ["CWE-79"],
                    }],
                },
            },
            "metadata": {"vulnerabilities": {
                "info": 0, "low": 0, "moderate": 0,
                "high": 0, "critical": 1, "total": 1,
            }},
        },
    )


def test_npm_exact_embedded_malicious_code_cwe_aborts(
    tmp_path, monkeypatch
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="typed malicious"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="npm",
            lock_name="package-lock.json",
            payload={
                "auditReportVersion": 2,
                "vulnerabilities": {
                    "fixture": {"via": [{"source": 123, "cwe": ["CWE-506"]}]},
                },
                "metadata": {"vulnerabilities": {
                    "info": 0, "low": 0, "moderate": 0,
                    "high": 0, "critical": 1, "total": 1,
                }},
            },
        )


@pytest.mark.parametrize(
    "bad_via",
    [None, {}, [{"title": "missing typed source"}], [{"source": True}]],
)
def test_npm_malformed_advisory_shape_fails_closed(
    tmp_path, monkeypatch, bad_via
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="malformed"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="npm",
            lock_name="package-lock.json",
            payload={
                "auditReportVersion": 2,
                "vulnerabilities": {"fixture": {"via": bad_via}},
                "metadata": {"vulnerabilities": {
                    "info": 0, "low": 0, "moderate": 0,
                    "high": 0, "critical": 1, "total": 1,
                }},
            },
        )


@pytest.mark.parametrize(
    "version, counts",
    [
        (1, {"info": 0, "low": 0, "moderate": 0, "high": 0,
             "critical": 0, "total": 0}),
        (2.0, {"info": 0, "low": 0, "moderate": 0, "high": 0,
               "critical": 0, "total": 0}),
        (True, {"info": 0, "low": 0, "moderate": 0, "high": 0,
                "critical": 0, "total": 0}),
        (2, {"info": 0, "low": 0, "moderate": 0, "high": 0,
             "critical": 0, "total": True}),
        (2, {"info": 0, "low": 0, "moderate": 0, "high": 0,
             "critical": 0, "total": 1}),
    ],
)
def test_npm_version_or_count_inconsistency_fails_closed(
    tmp_path, monkeypatch, version, counts
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="malformed"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="npm",
            lock_name="package-lock.json",
            payload={
                "auditReportVersion": version,
                "vulnerabilities": {},
                "metadata": {"vulnerabilities": counts},
            },
        )


def test_cargo_critical_and_malicious_prose_is_not_a_malware_marker(
    tmp_path, monkeypatch
):
    scg = _scg()
    _gate_scanner_payload(
        scg,
        tmp_path,
        monkeypatch,
        scanner="cargo-audit",
        lock_name="Cargo.lock",
        payload={
            "vulnerabilities": {"found": True, "count": 1, "list": [{
                "advisory": {
                    "id": "RUSTSEC-2026-0001",
                    "title": "A malicious user can trigger critical impact",
                    "categories": ["code-execution"],
                },
            }]},
        },
    )


@pytest.mark.parametrize(
    "advisory",
    [
        {"id": "RUSTSEC-2026-0001", "categories": ["malicious"]},
        {"id": "MAL-2026-701", "categories": []},
        {
            "id": "RUSTSEC-2026-0001",
            "aliases": ["MAL-2026-11961"],
            "categories": [],
        },
    ],
)
def test_cargo_typed_malicious_markers_abort(
    tmp_path, monkeypatch, advisory
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="typed malicious"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="cargo-audit",
            lock_name="Cargo.lock",
            payload={"vulnerabilities": {
                "found": True,
                "count": 1,
                "list": [{"advisory": advisory}],
            }},
        )


@pytest.mark.parametrize(
    "row",
    [{}, {"advisory": {}}, {"advisory": {
        "id": "RUSTSEC-2026-0001", "categories": "malicious",
    }}],
)
def test_cargo_malformed_or_missing_typed_shape_fails_closed(
    tmp_path, monkeypatch, row
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="malformed"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="cargo-audit",
            lock_name="Cargo.lock",
            payload={"vulnerabilities": {
                "found": True,
                "count": 1,
                "list": [row],
            }},
        )


@pytest.mark.parametrize(
    "found, count",
    [(False, 1), (True, 0), (True, True), ("true", 1)],
)
def test_cargo_count_or_found_inconsistency_fails_closed(
    tmp_path, monkeypatch, found, count
):
    scg = _scg()
    with pytest.raises(scg.SupplyChainAbortError, match="malformed"):
        _gate_scanner_payload(
            scg,
            tmp_path,
            monkeypatch,
            scanner="cargo-audit",
            lock_name="Cargo.lock",
            payload={"vulnerabilities": {
                "found": found,
                "count": count,
                "list": [{"advisory": {"id": "RUSTSEC-2026-0001"}}],
            }},
        )


def test_scanner_absent_with_lockfile_present_hard_stops(tmp_path, monkeypatch, caplog):
    scg = _scg()
    _mk(tmp_path / "package-lock.json", '{"dependencies": {"left-pad": "1.0.0"}}')
    monkeypatch.setattr(scg.shutil, "which", lambda b: None)  # no scanner on PATH
    with pytest.raises(scg.SupplyChainAbortError, match="no offline scanner"):
        scg.gate_supply_chain(tmp_path, denylist=[])
    assert any("scanner" in rec.message.lower() for rec in caplog.records), (
        "scanner-absent abort must be LOGGED, not silently swallowed"
    )


def test_scanner_absent_with_no_lockfile_does_not_abort(tmp_path, monkeypatch):
    """Nothing to verify → scanner absence is moot; not a hard stop."""
    scg = _scg()
    monkeypatch.setattr(scg.shutil, "which", lambda b: None)
    scg.gate_supply_chain(tmp_path)  # must not raise


def test_install_script_base64_heuristic_fires(tmp_path):
    scg = _scg()
    _mk(
        tmp_path / "package.json",
        '{"scripts": {"postinstall": "node -e \\"eval(Buffer.from(\''
        'aGVsbG8=\',\'base64\'))\\""}}',
    )
    with pytest.raises(scg.SupplyChainAbortError):
        scg.gate_supply_chain(tmp_path, denylist=[])


def test_install_script_alone_without_base64_does_not_fire(tmp_path, monkeypatch):
    scg = _scg()
    _mk(tmp_path / "package.json", '{"scripts": {"postinstall": "node build.js"}}')
    monkeypatch.setattr(scg.shutil, "which", lambda b: None)
    scg.gate_supply_chain(tmp_path, denylist=[])  # no lockfile either -> clean


def test_env_skip_override_disables_gate_entirely(tmp_path, monkeypatch):
    scg = _scg()
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(tmp_path / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)
    monkeypatch.setenv("PLAMEN_SKIP_SUPPLY_CHAIN_GATE", "1")
    scg.gate_supply_chain(tmp_path, denylist=[poisoned_pkg])  # would abort w/o the env


def test_gate_never_raises_on_unreadable_paths(tmp_path):
    """A nonexistent root must degrade safely, not crash."""
    scg = _scg()
    scg.gate_supply_chain(tmp_path / "does-not-exist")


# ─────────────────────────────────────────────────────────────────────────
# recon_prepass._prepare_evm_build integration
# ─────────────────────────────────────────────────────────────────────────

def test_recon_poisoned_lockfile_aborts_before_install_mock(tmp_path, monkeypatch):
    """Wiring test: when the gate raises, _prepare_evm_build must propagate
    the abort WITHOUT invoking any install step. Gate itself is stubbed here
    (isolation); the companion test below drives the REAL gate."""
    rp = _rp()
    root = tmp_path / "proj"
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(root / "package.json", "{}")
    _mk(root / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)
    _mk(root / "src" / "A.sol", "contract A {}\n")

    install_calls = []

    def _raise_abort(_root, denylist=None):
        raise rp.SupplyChainAbortError(
            f"denylisted dependency IoC {poisoned_pkg!r} found"
        )

    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rp, "_run_forge", lambda args, cwd, t: (install_calls.append(("forge", args)) or (0, "")))
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (install_calls.append(("cmd", cmd)) or 0))
    monkeypatch.setattr(rp, "gate_supply_chain", _raise_abort)

    with pytest.raises(rp.SupplyChainAbortError):
        rp._prepare_evm_build(root)

    assert install_calls == [], (
        "install mock(s) must NOT be invoked when the supply-chain gate aborts"
    )


def test_recon_poisoned_lockfile_via_real_gate_aborts_before_install_mock(tmp_path, monkeypatch):
    """Same as above but drives the REAL gate_supply_chain (denylist-based hit),
    not a monkeypatched stand-in — proves the two modules are actually wired
    together, not just individually correct."""
    rp = _rp()
    root = tmp_path / "proj"
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(root / "package.json", "{}")
    _mk(root / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)
    _mk(root / "src" / "A.sol", "contract A {}\n")

    install_calls = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n)
    monkeypatch.setattr(rp, "_run_forge", lambda args, cwd, t: (install_calls.append(("forge", args)) or (0, "")))
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (install_calls.append(("cmd", cmd)) or 0))
    # Drive the real gate with the synthetic IoC injected via the module-level
    # denylist (append-only in production; test-local override here).
    monkeypatch.setattr(rp.supply_chain_gate, "DEFAULT_IOC_DENYLIST", frozenset({poisoned_pkg}))

    with pytest.raises(rp.SupplyChainAbortError):
        rp._prepare_evm_build(root)

    assert install_calls == []


def test_recon_clean_lockfile_leaves_install_mock_unchanged(tmp_path, monkeypatch):
    """Zero happy-path regression: a clean lockfile still reaches the real
    install mock exactly as before this item shipped."""
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "package.json", "{}")
    _mk(root / "package-lock.json", '{"dependencies": {"left-pad": "1.0.0"}}')
    _mk(root / "src" / "A.sol", "contract A {}\n")

    cmds = []
    monkeypatch.setattr(rp.shutil, "which", lambda n: "/usr/bin/" + n if n == "npm" else None)
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (cmds.append(cmd) or 0))
    monkeypatch.setattr(
        rp.supply_chain_gate,
        "_call_offline_scanner",
        lambda binary, lf: rp.supply_chain_gate.OfflineScanResult(
            rp.supply_chain_gate.OfflineScanState.SUCCEEDED,
            output=json.dumps({
                "auditReportVersion": 2,
                "vulnerabilities": {},
                "metadata": {"vulnerabilities": {
                    "info": 0, "low": 0, "moderate": 0,
                    "high": 0, "critical": 0, "total": 0,
                }},
            }),
        ),
    )

    note = rp._prepare_evm_build(root)
    assert ["npm", "ci"] in cmds
    assert "npm ci ok" in note


def test_recon_scanner_absent_with_lockfile_aborts(tmp_path, monkeypatch, caplog):
    rp = _rp()
    root = tmp_path / "proj"
    _mk(root / "package.json", "{}")
    _mk(root / "package-lock.json", '{"dependencies": {"left-pad": "1.0.0"}}')
    _mk(root / "src" / "A.sol", "contract A {}\n")

    install_calls = []
    # No binaries at all resolve -> scanner absent AND install tools absent;
    # the gate must abort before we ever ask whether npm/forge exist for
    # the install step itself.
    monkeypatch.setattr(rp.shutil, "which", lambda n: None)
    monkeypatch.setattr(rp, "_run_cmd", lambda cmd, cwd, t: (install_calls.append(cmd) or 0))
    monkeypatch.setattr(rp, "_run_forge", lambda args, cwd, t: (install_calls.append(args) or (0, "")))

    with pytest.raises(rp.SupplyChainAbortError):
        rp._prepare_evm_build(root)
    assert install_calls == []


def test_prepare_never_raises_still_holds_for_nonexistent_root(tmp_path):
    """Pre-existing contract from test_evm_dep_prep.py: a nonexistent root
    must not raise. The H2 gate must not break this — no lockfile exists
    under a nonexistent path, so the gate degrades cleanly."""
    rp = _rp()
    assert isinstance(rp._prepare_evm_build(tmp_path / "nope"), str)


# ─────────────────────────────────────────────────────────────────────────
# mechanical_verify.run_phase5b_mechanical_verify integration
# ─────────────────────────────────────────────────────────────────────────

def test_verify_poisoned_build_root_aborts_before_prewarm_and_loop(tmp_path, monkeypatch):
    mv = _mv()
    (tmp_path / "verify_H-1.md").write_text(
        "**Test File**: `test/Foo.t.sol` function `test_h1()`\n"
        "**Command**: `forge test --match-test test_h1`\n",
        encoding="utf-8",
    )
    poisoned_pkg = "plamen-test-evil-pkg"
    _mk(tmp_path / "package-lock.json",
        '{"dependencies": {"%s": "0.0.0"}}' % poisoned_pkg)

    monkeypatch.setattr(mv.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(mv, "_read_recon_build_root", lambda s, l: tmp_path)
    monkeypatch.setattr(mv.supply_chain_gate, "DEFAULT_IOC_DENYLIST",
                        frozenset({poisoned_pkg}))

    prewarm_calls = []
    test_calls = []
    monkeypatch.setattr(
        mv, "_prewarm_build",
        lambda *a, **k: (prewarm_calls.append(1) or (True, "warm")),
    )
    monkeypatch.setattr(
        mv, "_run_test_for_finding",
        lambda *a, **k: (test_calls.append(1) or mv.ExecResult(
            verify_file="verify_H-1.md", finding_id="H-1", language="evm",
            status="PASS")),
    )

    with pytest.raises(mv.SupplyChainAbortError):
        mv.run_phase5b_mechanical_verify(tmp_path, tmp_path, "evm")

    assert prewarm_calls == [], "pre-warm build must NOT run after an abort"
    assert test_calls == [], "per-finding test loop must NOT run after an abort"


def test_verify_clean_build_root_unaffected(tmp_path, monkeypatch):
    """Zero happy-path regression: existing prewarm-wiring test shape still
    works with the gate present."""
    mv = _mv()
    (tmp_path / "verify_H-1.md").write_text(
        "**Test File**: `test/Foo.t.sol` function `test_h1()`\n"
        "**Command**: `forge test --match-test test_h1`\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(mv, "_toolchain_binary_for", lambda lang: "")
    monkeypatch.setattr(mv, "_read_recon_build_root", lambda s, l: tmp_path)
    monkeypatch.setattr(mv, "_prewarm_build", lambda *a, **k: (True, "warm"))
    monkeypatch.setattr(
        mv, "_run_test_for_finding",
        lambda *a, **k: mv.ExecResult(
            verify_file="verify_H-1.md", finding_id="H-1", language="evm",
            status="PASS"),
    )
    monkeypatch.setattr(mv, "_annotate_verify_file", lambda vf, r: True)

    out = mv.run_phase5b_mechanical_verify(tmp_path, tmp_path, "evm")
    assert out["counts"].get("PASS") == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
