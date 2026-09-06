"""Pre-handoff contracts for toolchain provenance and vulnerability freshness.

These fixtures intentionally separate four different claims:

* applicability/necessity -- which capability must run for this audit;
* invocation correctness -- which executable/argv implements it;
* runtime identity -- the exact executable bytes/version that ran; and
* vulnerability freshness -- the advisory dataset was recent and identifiable.

An executable SHA-256 proves identity, not that its advisories are current.
No test in this file performs a network request, installation, or real scan.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import audit_snapshot as SNAP
import recon_prepass as RECON
import supply_chain_gate as SCG
from tool_coverage_ledger import (
    ToolCoverageLedgerError,
    ToolOutcome,
    ToolOutcomeState,
    applicable_tool_capabilities,
    load_tool_coverage_ledger,
    reconcile_expected_tool_capabilities,
    tool_identity_policy_issues,
)


_ROOT = Path(__file__).resolve().parent.parent
_GOVERNANCE = (
    _ROOT / "verification_policy" / "toolchain_governance.v1.json"
)


def test_runtime_identity_binds_resolved_bytes_and_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GREEN baseline: the audit snapshot binds executable identity."""

    executable = tmp_path / "scanner"
    executable.write_bytes(b"synthetic scanner bytes")
    SNAP._TOOL_FINGERPRINT_CACHE.clear()
    monkeypatch.setattr(
        SNAP.shutil,
        "which",
        lambda name: str(executable) if name == "scanner" else None,
    )
    monkeypatch.setattr(
        SNAP,
        "_command_version",
        lambda command: b"rc=0\nscanner 1.2.3",
    )

    payload = json.loads(
        SNAP._runtime_tool_fingerprint(("scanner", "--version"))
    )
    assert payload["executable_sha256"] == hashlib.sha256(
        executable.read_bytes()
    ).hexdigest()
    assert payload["version"] == "rc=0\nscanner 1.2.3"


def test_sec3_provider_requires_an_immutable_image_digest() -> None:
    """GREEN baseline: mutable image tags cannot become scan authority."""

    immutable = "ghcr.io/example/sec3@sha256:" + ("a" * 64)
    assert RECON._resolve_sec3_image(immutable) == immutable
    assert RECON._resolve_sec3_image("ghcr.io/example/sec3:latest") is None


def test_supply_chain_scanner_transport_failure_is_not_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: an installed scanner timing out currently becomes a clean pass."""

    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3}\n', encoding="utf-8"
    )
    monkeypatch.setattr(
        SCG.shutil,
        "which",
        lambda name: "/tool/osv-scanner" if name == "osv-scanner" else None,
    )

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(["osv-scanner"], 1)

    monkeypatch.setattr(SCG, "run_owned_process", timeout)
    with pytest.raises(
        SCG.SupplyChainAbortError,
        match=r"(?i)(scanner|verify|unavailable|failed)",
    ):
        SCG.gate_supply_chain(tmp_path, denylist=[])


@pytest.mark.parametrize(
    "lock_name",
    [
        "go.sum",
        "Move.lock",
        "npm-shrinkwrap.json",
    ],
)
def test_supply_chain_lock_denominator_covers_supported_ecosystems(
    tmp_path: Path,
    lock_name: str,
) -> None:
    """RED: an ecosystem lock must not disappear as 'nothing to verify'."""

    lockfile = tmp_path / lock_name
    lockfile.write_text("synthetic lock\n", encoding="utf-8")
    assert lockfile in SCG._find_lockfiles(tmp_path)


def test_supply_chain_lock_denominator_is_project_wide_and_skips_build_cache(
    tmp_path: Path,
) -> None:
    nested = tmp_path / "packages" / "bridge" / "Cargo.lock"
    nested.parent.mkdir(parents=True)
    nested.write_text("version = 3\n", encoding="utf-8")
    ignored = tmp_path / "node_modules" / "dependency" / "package-lock.json"
    ignored.parent.mkdir(parents=True)
    ignored.write_text('{"lockfileVersion":3}\n', encoding="utf-8")

    assert SCG._find_lockfiles(tmp_path) == [nested]


@pytest.mark.parametrize(
    ("binary", "required_flag"),
    [
        ("npm", "--offline"),
        ("cargo-audit", "--no-fetch"),
    ],
)
def test_offline_supply_chain_fallback_forbids_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    binary: str,
    required_flag: str,
) -> None:
    """RED: a command described as offline must mechanically forbid fetching."""

    lockfile = tmp_path / (
        "package-lock.json" if binary == "npm" else "Cargo.lock"
    )
    lockfile.write_text("", encoding="utf-8")
    commands: list[list[str]] = []

    def capture(command, **_kwargs):
        commands.append(list(command))
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")

    monkeypatch.setattr(SCG, "run_owned_process", capture)
    if binary == "cargo-audit":
        database = tmp_path / "rustsec"
        database.mkdir()
        monkeypatch.setenv("PLAMEN_RUSTSEC_DB", str(database))
    SCG._call_offline_scanner(binary, lockfile)
    assert commands and required_flag in commands[0]


def test_osv_v2_invocation_uses_offline_database_and_supported_go_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    go_sum = tmp_path / "go.sum"
    go_sum.write_text("example.invalid/module v1.0.0 h1:x\n", encoding="utf-8")
    go_mod = tmp_path / "go.mod"
    go_mod.write_text("module example.invalid/test\n", encoding="utf-8")
    commands: list[list[str]] = []

    def capture(command, **_kwargs):
        commands.append(list(command))
        return SimpleNamespace(
            returncode=0,
            stdout='{"results":[]}',
            stderr="",
        )

    monkeypatch.setattr(SCG, "run_owned_process", capture)
    result = SCG._call_offline_scanner("osv-scanner", go_sum)
    assert result.state is SCG.OfflineScanState.SUCCEEDED
    command = commands[0]
    assert command[:4] == [
        "osv-scanner",
        "scan",
        "--offline",
        "--offline-vulnerabilities",
    ]
    assert "-L" in command and str(go_mod) in command


@pytest.mark.parametrize("lock_name", ["Move.lock", "soldeer.lock"])
def test_unsupported_lock_has_explicit_outcome_not_false_clean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lock_name: str,
) -> None:
    (tmp_path / lock_name).write_text(
        "[move]\nversion = 3\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        SCG.shutil,
        "which",
        lambda name: f"/tool/{name}",
    )
    with pytest.raises(
        SCG.SupplyChainAbortError,
        match=r"(?i)(compatible|verify|scanner)",
    ):
        SCG.gate_supply_chain(tmp_path, denylist=[])


def test_supply_chain_uses_compatible_fallback_before_declaring_debt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (tmp_path / "package-lock.json").write_text(
        '{"lockfileVersion":3}\n', encoding="utf-8"
    )
    monkeypatch.setattr(
        SCG.shutil, "which", lambda name: f"/tool/{name}"
    )
    observed: list[str] = []

    def scan(binary: str, _lockfile: Path):
        observed.append(binary)
        if binary == "osv-scanner":
            return SCG.OfflineScanResult(
                SCG.OfflineScanState.FAILED,
                reason="offline DB unavailable",
            )
        return SCG.OfflineScanResult(
            SCG.OfflineScanState.SUCCEEDED,
            output=json.dumps({
                "auditReportVersion": 2,
                "vulnerabilities": {},
                "metadata": {"vulnerabilities": {
                    "info": 0,
                    "low": 0,
                    "moderate": 0,
                    "high": 0,
                    "critical": 0,
                    "total": 0,
                }},
            }),
        )

    monkeypatch.setattr(SCG, "_call_offline_scanner", scan)
    SCG.gate_supply_chain(tmp_path, denylist=[])
    assert observed == ["osv-scanner", "npm"]


@pytest.mark.parametrize(
    ("capability_id", "tool"),
    [
        ("cargo-audit.dependency-audit", "cargo-audit"),
        ("govulncheck.dependency-audit", "govulncheck"),
    ],
)
def test_known_cve_clean_claim_requires_advisory_provenance(
    capability_id: str,
    tool: str,
) -> None:
    """RED: clean known-CVE coverage cannot omit advisory DB identity/freshness."""

    with pytest.raises(ToolCoverageLedgerError, match=r"(?i)provenance"):
        ToolOutcome.succeeded(capability_id, tool, 0)


def test_known_cve_clean_claim_rejects_opaque_provider_label() -> None:
    with pytest.raises(
        ToolCoverageLedgerError,
        match=r"(?i)(schema|malformed)",
    ):
        ToolOutcome.succeeded(
            "cargo-audit.dependency-audit",
            "cargo-audit",
            0,
            provider_ref='{"source_id":"trust-me"}',
        )


def _snapshot_probe_commands(
    monkeypatch: pytest.MonkeyPatch,
) -> dict[str, tuple[str, ...]]:
    observed: dict[str, tuple[str, ...]] = {}

    def capture(command: tuple[str, ...], **_kwargs) -> bytes:
        observed[command[0]] = command
        return json.dumps({
            "command": list(command),
            "resolved_executable": "UNAVAILABLE",
            "version": "UNAVAILABLE",
        }).encode()

    monkeypatch.setattr(SNAP, "_runtime_tool_fingerprint", capture)
    monkeypatch.setattr(
        SNAP,
        "_runtime_python_distribution_fingerprint",
        lambda name, **_kwargs: json.dumps({
            "distribution": name,
            "version": "UNAVAILABLE",
        }).encode(),
    )
    monkeypatch.setattr(SNAP, "_installed_python_packages", lambda: b"[]")
    SNAP._fixed_runtime_tool_entries()
    return observed


def test_cargo_scout_runtime_probe_uses_supported_argv(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: setup says cargo-scout-audit has no --version interface."""

    # Plamen's canonical setup probe documents that this cargo plugin has no
    # --version and must be health-probed with --help.
    observed = _snapshot_probe_commands(monkeypatch)
    assert observed["cargo-scout-audit"] == (
        "cargo-scout-audit",
        "--help",
    )


def test_runtime_snapshot_binds_the_daml_executable_that_is_invoked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: bind `daml`, which owns build/test, rather than only `damlc`."""

    # The verification registry invokes `daml build`/`daml test`; fingerprinting
    # only `damlc` does not bind the executable that actually runs those steps.
    observed = _snapshot_probe_commands(monkeypatch)
    assert observed["daml"] == ("daml", "version")


def test_machine_revocation_policy_blocks_version_or_executable_digest(
    tmp_path: Path,
) -> None:
    registry = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    opengrep = next(
        row for row in registry["tools"] if row["tool_id"] == "opengrep"
    )
    opengrep["revocation_policy"]["blocked_version_substrings"] = [
        "opengrep 9.9.9"
    ]
    opengrep["revocation_policy"]["blocked_executable_sha256"] = [
        "a" * 64
    ]
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps(registry), encoding="utf-8")
    (tmp_path / "toolchain_version_lock.v1.json").write_bytes(
        (
            _ROOT
            / "verification_policy"
            / "toolchain_version_lock.v1.json"
        ).read_bytes()
    )
    fingerprint = json.dumps({
        "command": ["opengrep", "--version"],
        "resolved_executable": "/tool/opengrep",
        "version": "rc=0\nopengrep 9.9.9",
        "executable_sha256": "a" * 64,
    })

    issues = tool_identity_policy_issues(
        "opengrep", fingerprint, registry_path=policy
    )
    assert any("revoked token" in issue for issue in issues)
    assert any("digest is revoked" in issue for issue in issues)


def test_toolchain_governance_registry_covers_the_handoff_denominator() -> None:
    """RED: expected capabilities cannot be inferred from tools that happened to run."""

    assert _GOVERNANCE.is_file(), (
        "missing machine-readable toolchain governance denominator"
    )
    payload = json.loads(_GOVERNANCE.read_text(encoding="utf-8"))
    assert payload.get("schema_version") == "plamen.toolchain_governance.v1"
    for field in ("capabilities", "tools", "advisory_sources"):
        assert isinstance(payload.get(field), list) and payload[field], field

    for row in payload["capabilities"]:
        assert {
            "capability_id",
            "applicability",
            "necessity",
            "invocations",
        } <= set(row)
        applicability = row["applicability"]
        assert {
            "pipelines",
            "ecosystems",
            "platforms",
            "modes",
            "phases",
        } <= set(applicability)

    for row in payload["tools"]:
        assert {
            "tool_id",
            "version_policy",
            "integrity_policy",
            "update_policy",
            "revocation_policy",
        } <= set(row)

    for row in payload["advisory_sources"]:
        assert {
            "source_id",
            "provider",
            "offline_policy",
            "freshness_policy",
            "unavailable_policy",
        } <= set(row)


def _write_advisory_source(
    root: Path,
    source_id: str,
    *,
    age: timedelta = timedelta(hours=1),
) -> None:
    root.mkdir()
    (root / "advisories.json").write_text(
        '{"advisories":[]}\n', encoding="utf-8"
    )
    as_of = datetime.now(timezone.utc) - age
    expires_at = as_of + timedelta(days=7)
    manifest = {
        "schema_version": "plamen.advisory_source.v1",
        "source_id": source_id,
        "provider": {
            "rustsec-local": "https://github.com/RustSec/advisory-db",
            "govulndb-local": "https://vuln.go.dev",
        }[source_id],
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "content_sha256": RECON._advisory_content_sha256(root),
    }
    (root / "plamen-advisory-source.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )


def test_advisory_source_binds_digest_as_of_and_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "rustsec-db"
    _write_advisory_source(database, "rustsec-local")
    monkeypatch.setenv("PLAMEN_RUSTSEC_DB", str(database))

    root, provider_ref, issue = RECON._resolve_advisory_source(
        "rustsec-local"
    )
    assert root == database.resolve()
    assert issue == ""
    provider = json.loads(provider_ref)
    assert provider["source_id"] == "rustsec-local"
    assert provider["content_sha256"] == RECON._advisory_content_sha256(
        database
    )
    assert provider["as_of"] and provider["expires_at"]


def test_advisory_source_rejects_stale_or_mutated_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = tmp_path / "stale-db"
    _write_advisory_source(
        stale, "govulndb-local", age=timedelta(days=8)
    )
    monkeypatch.setenv("PLAMEN_GOVULNDB", str(stale))
    assert RECON._resolve_advisory_source("govulndb-local")[0] is None

    fresh = tmp_path / "fresh-db"
    _write_advisory_source(fresh, "govulndb-local")
    (fresh / "advisories.json").write_text(
        '{"advisories":["mutated"]}\n', encoding="utf-8"
    )
    monkeypatch.setenv("PLAMEN_GOVULNDB", str(fresh))
    root, _provider, issue = RECON._resolve_advisory_source(
        "govulndb-local"
    )
    assert root is None
    assert "digest mismatch" in issue


def test_advisory_source_inside_untrusted_project_is_not_scan_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "go.mod").write_text(
        "module example.invalid/test\n", encoding="utf-8"
    )
    database = project / "target-controlled-govulndb"
    _write_advisory_source(database, "govulndb-local")
    monkeypatch.setenv("PLAMEN_GOVULNDB", str(database))
    monkeypatch.setattr(
        RECON.shutil, "which", lambda name: f"/tool/{name}"
    )

    outcome, findings = RECON._govulncheck_outcome(project)
    assert outcome.state is ToolOutcomeState.UNAVAILABLE
    assert "outside the untrusted target" in outcome.reason
    assert findings == []


def test_govulncheck_clean_receipt_uses_bound_local_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "go-project"
    project.mkdir()
    (project / "go.mod").write_text(
        "module example.invalid/test\n", encoding="utf-8"
    )
    database = tmp_path / "govulndb"
    _write_advisory_source(database, "govulndb-local")
    monkeypatch.setenv("PLAMEN_GOVULNDB", str(database))
    monkeypatch.setattr(
        RECON.shutil, "which", lambda name: f"/tool/{name}"
    )
    commands: list[list[str]] = []
    environments: list[dict[str, str]] = []

    def run(command, *_args):
        commands.append(list(command))
        environments.append(dict(_args[2]))
        return 0, '{"config":{"protocol_version":"v1"}}\n'

    monkeypatch.setattr(RECON, "_run_hardened", run)
    outcome, findings = RECON._govulncheck_outcome(project)
    assert outcome.state is ToolOutcomeState.SUCCEEDED
    assert outcome.finding_count == 0 and findings == []
    assert json.loads(outcome.provider_ref)["source_id"] == "govulndb-local"
    assert "-db" in commands[0]
    assert database.resolve().as_uri() in commands[0]
    assert environments[0]["GOPROXY"] == "off"
    assert environments[0]["GOSUMDB"] == "off"
    assert environments[0]["GOTOOLCHAIN"] == "local"


def test_cargo_audit_clean_receipt_is_no_fetch_and_provenance_bound(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = tmp_path / "rust-project"
    project.mkdir()
    (project / "Cargo.toml").write_text(
        "[package]\nname='fixture'\nversion='0.1.0'\n",
        encoding="utf-8",
    )
    (project / "Cargo.lock").write_text(
        "# synthetic\nversion = 3\n", encoding="utf-8"
    )
    database = tmp_path / "rustsec"
    _write_advisory_source(database, "rustsec-local")
    monkeypatch.setenv("PLAMEN_RUSTSEC_DB", str(database))
    monkeypatch.setattr(
        RECON.shutil, "which", lambda name: f"/tool/{name}"
    )
    commands: list[list[str]] = []
    environments: list[dict[str, str] | None] = []

    def run(command, *_args):
        commands.append(list(command))
        environments.append(
            dict(_args[2]) if len(_args) > 2 else None
        )
        if "--version" in command:
            return 0, "cargo-audit 0.fixture"
        return 0, '{"vulnerabilities":{"list":[]}}'

    monkeypatch.setattr(RECON, "_run_hardened", run)
    outcome, findings = RECON._cargo_audit_outcome(project)
    assert outcome.state is ToolOutcomeState.SUCCEEDED
    assert outcome.finding_count == 0 and findings == []
    assert json.loads(outcome.provider_ref)["source_id"] == "rustsec-local"
    scan_command = commands[-1]
    assert "--no-fetch" in scan_command
    assert "--db" in scan_command
    assert str(database.resolve()) in scan_command
    assert "audit" in scan_command
    assert "--file" in scan_command
    assert str((project / "Cargo.lock").resolve()) in scan_command
    assert environments[-1]["CARGO_NET_OFFLINE"] == "true"
    assert Path(environments[-1]["CARGO_HOME"]).parent != project


def test_expected_capability_reconciliation_materializes_only_missing_debt(
    tmp_path: Path,
) -> None:
    applicability = {
        "pipeline": "sc",
        "ecosystem": "solana",
        "platform_name": "win32",
        "mode": "core",
        "phase": "recon-prebreadth",
    }
    expected = [
        row["capability_id"]
        for row in applicable_tool_capabilities(**applicability)
    ]
    added = reconcile_expected_tool_capabilities(
        tmp_path,
        **applicability,
    )
    assert added == expected
    outcomes = load_tool_coverage_ledger(tmp_path)
    assert outcomes["opengrep.static-analysis"].state is (
        ToolOutcomeState.UNAVAILABLE
    )
    assert outcomes["sec3-xray.solana-static-analysis"].state is (
        ToolOutcomeState.SKIPPED
    )
    for capability_id in (
        "protobuf.scip-graph-parser",
        "scip-rust.reference-graph",
    ):
        assert capability_id in expected
        assert outcomes[capability_id].state is ToolOutcomeState.UNAVAILABLE
        assert "emitted no outcome" in outcomes[capability_id].reason
    assert reconcile_expected_tool_capabilities(
        tmp_path,
        **applicability,
    ) == []
