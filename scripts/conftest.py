"""Shared pytest configuration for the Plamen scripts/ test suite.

Two responsibilities, both zero-risk to test *logic*:

1. ``sys.path`` net — put ``scripts/`` on ``sys.path`` so new test modules can
   ``import enumeration_gate`` etc. without repeating the
   ``sys.path.insert(0, ...)`` boilerplate that 190+ existing files hand-roll.
   Existing files keep their own insert (harmless); new ones need not.

2. Test-selection markers (registered in ../pyproject.toml) applied by FILENAME
   here — the single source of truth for which modules are `integration` / `slow`.
   Marking never removes a test: the full/nightly lane (`pytest` with no `-m`)
   still runs every one. It only lets a fast inner loop skip the heavy files:
       fast:        pytest -m "not integration" -n auto
       integration: pytest -m "integration"            (serial, env-guarded)
   The heavy set is measured, not guessed: real OS-subprocess files + files whose
   real ``time.sleep`` is >= ~1s (heartbeat/timing tests). Sub-second sleepers and
   fully-mocked tests stay in the default (fast) lane.
"""

import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pytest

# (0) Hang-proof self-runs — make ANY `pytest` of this suite non-blocking without
# an exported env var. The driver's halt/purge prompts (wait_halt_choice /
# wait_critical_halt_choice / wait_purge_choice) exit on a non-TTY stdin, but an
# agent/pty shell reports isatty()==True, so integration tests (test_driver_smoke,
# test_halt_ux_e2e, test_signal_and_ratelimit) would block on a keypress there.
# setdefault: only fills it if the caller/CI hasn't chosen a value, so explicit
# overrides still win. Test-scoped — real audit runs never import conftest, so
# this cannot change production halt behavior. This is what lets the agent run
# the full suite unattended (the way it has for months) without it hanging.
os.environ.setdefault("PLAMEN_AUTO_HALT_CHOICE", "exit")

# (1) sys.path net — idempotent; scripts/ dir is this file's parent.
_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)


# (2) Exact, source-bound quarantine authority for the release fast lane.
_FAST_GOVERNANCE_SCHEMA = "plamen.fast-lane-skip-governance.v1"
_FAST_GOVERNANCE_MANIFEST_SHA256 = (
    "1efb0db272499c22bd0a5812b7aae3fac289012aeb64570b296eaa023a520502"
)
_FAST_GOVERNANCE_MANIFEST = Path(__file__).with_name(
    "fast_lane_skip_governance_r10.json"
)
_REPO_ROOT = Path(__file__).resolve().parent.parent
# These sources belong to the explicitly private bounty lane and are ignored by
# the public repository.  The governance roster still pins their identities and
# hashes so a private checkout can verify them.  A public checkout may omit the
# exact set, but partial materialization is rejected.
_FAST_GOVERNANCE_PRIVATE_SOURCE_PATHS = frozenset(
    {
        "scripts/bounty/test_bb_staged_runtime_contract_20260727.py",
        "scripts/bounty/test_bb0_independent_review_blockers_20260728.py",
        "scripts/bounty/test_bb0_provider_receipt_hardening_20260728.py",
        "scripts/bounty/test_bb0_round3_publication_repairs_20260728.py",
        "scripts/bounty/test_bb_deployment_quantifier_20260727.py",
        "scripts/bounty/test_bb_git_executable_authority_20260728.py",
        "scripts/bounty/test_bb_network_sandbox_20260727.py",
        "scripts/bounty/test_bb_repo_acquisition_20260727.py",
        "scripts/bounty/test_bb_toolchain_trust_root_20260727.py",
        "scripts/bounty/test_bb_wrapper_closure_20260727.py",
        "scripts/bounty/test_lease_admin_20260727.py",
        "scripts/bounty/test_runtime_closure_20260727.py",
        "scripts/bounty/test_bb_human_gate_containment_20260727.py",
    }
)
_FAST_GOVERNANCE_MARKERS = frozenset(
    {
        "hardlink",
        "installed_runtime",
        "ntfs_ads_sparse",
        "path_envelope",
        "posix_only",
        "provider_live",
        "reparse_or_junction",
        "symlink",
        "windows_only",
    }
)
_FAST_GOVERNANCE_COUNTS = {
    "expanded_pytest_skip_sites": 132,
    "expanded_skipif_sites": 106,
    "guaranteed_current_nodes": 17,
    "quarantine_nodes": 168,
    "source_files": 92,
    "unresolved_runtime_nodes": 151,
}
_FAST_GOVERNANCE_AUTHORITY = {
    "full_audit_sha256": (
        "e6064596f5e525580e3abecb0f38ac1c4621b9398b3147703aeeda768052ceb0"
    ),
    "r9_independent_review_sha256": (
        "dea03df328e190e2110ae95d0746ffb5a3ff316082b3b5b270dc337df69af660"
    ),
    "source_count_amendment_sha256": (
        "bfaed995b50424fe251d182225d3c6696c059ff56b930e4edfdb592cb9ddb65a"
    ),
}
_FAST_GOVERNANCE_PLATFORM_POLICY = {
    "logical_integration_selector": "integration",
    "posix_integration_selector": "integration",
    "production_selector": "not integration and not fast_quarantine",
    "supported_os_names": ["nt", "posix"],
    "unknown_os_name": "abort_collection",
    "windows_integration_selector": "integration and not posix_only",
}
_FAST_GOVERNANCE_HASHES = {
    "governed_production_nodes_sha256": (
        "76364b33eaea680c8a282f93d87a8406b046a039fb682bcd673dc9947c748ef5"
    ),
    "guaranteed_nodes_sha256": (
        "1d15ca6442a2c751d36275be053a7673facf3b51ea63f36fbaf4b96b4c50126b"
    ),
    "quarantine_nodes_sha256": (
        "29bdd0de57165822ae1472f57de64d272a30617a14c5fb654ac5ffae2158e98b"
    ),
    "quarantine_source_path_roster_sha256": (
        "858dd7735dd18648e7c4574e95ea0b2a3ba137469da99e9419b38ce63e8bd86b"
    ),
    "quarantine_source_roster_sha256": (
        "3f38f164396f56149ca47ac5608dc4e6de25c60684be2beac80ab1e9defa8b80"
    ),
    "r9_default_nodes_sha256": (
        "22bbcf73f724b188768fb532fc832e5e6a85aa9fba1196fa4c0dde7e4db2de1d"
    ),
    "source_path_roster_sha256": (
        "f27577b1f91e246ccb65d3e167399c2cbcc6c4832a6ec4bcd4557966ccc118d4"
    ),
    "source_roster_sha256": (
        "75270fb763a3e49fa4093f5d60d29a4b95992e07339c8967f1435e95f188ec92"
    ),
    "unresolved_nodes_sha256": (
        "3176c06f7446119f92bdd97eb4f2482f620ffff7474558665ded06cf95e7a874"
    ),
}


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _duplicate_rejecting_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise pytest.UsageError(
                f"fast-lane governance duplicate JSON key: {key!r}"
            )
        result[key] = value
    return result


def _decode_fast_governance_json(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
        payload = json.loads(
            text, object_pairs_hook=_duplicate_rejecting_object
        )
    except pytest.UsageError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise pytest.UsageError(
            f"malformed fast-lane governance JSON: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise pytest.UsageError("fast-lane governance payload must be an object")
    return payload


def _canonical_source_roster(sources: list[dict]) -> bytes:
    return "".join(
        f"{row['path']}|{row['sha256']}\n" for row in sources
    ).encode("utf-8")


def _canonical_entry_roster(entries: list[dict]) -> bytes:
    return "".join(
        f"{row['state']}|{','.join(row['markers'])}|{row['nodeid']}|"
        f"{row['reason']}\n"
        for row in entries
    ).encode("utf-8")


def _line_roster_sha256(rows) -> str:
    return _sha256_bytes("".join(f"{row}\n" for row in rows).encode("utf-8"))


def _require_supported_os_name(name: str) -> str:
    if name not in {"nt", "posix"}:
        raise pytest.UsageError(
            f"unsupported os.name for fast-lane governance: {name!r}"
        )
    return name


def _validate_fast_governance_payload(
    payload: dict, *, verify_sources: bool = True
) -> dict:
    expected_top = {
        "authority",
        "counts",
        "entries",
        "hashes",
        "marker_policy",
        "platform_policy",
        "schema",
        "sources",
        "version",
    }
    if set(payload) != expected_top:
        raise pytest.UsageError("malformed fast-lane governance top-level keys")
    if payload["schema"] != _FAST_GOVERNANCE_SCHEMA or payload["version"] != 1:
        raise pytest.UsageError("unsupported fast-lane governance schema")
    if payload["counts"] != _FAST_GOVERNANCE_COUNTS:
        raise pytest.UsageError("malformed fast-lane governance counts")
    if payload["authority"] != _FAST_GOVERNANCE_AUTHORITY:
        raise pytest.UsageError("malformed fast-lane governance authority")
    if payload["platform_policy"] != _FAST_GOVERNANCE_PLATFORM_POLICY:
        raise pytest.UsageError("malformed fast-lane governance platform_policy")
    marker_policy = payload["marker_policy"]
    if (
        not isinstance(marker_policy, dict)
        or set(marker_policy) != _FAST_GOVERNANCE_MARKERS | {"fast_quarantine"}
        or not all(isinstance(value, str) and value for value in marker_policy.values())
    ):
        raise pytest.UsageError("malformed fast-lane governance marker_policy")
    hashes = payload["hashes"]
    if not isinstance(hashes, dict):
        raise pytest.UsageError("malformed fast-lane governance hashes")
    for key, expected in _FAST_GOVERNANCE_HASHES.items():
        if hashes.get(key) != expected:
            raise pytest.UsageError(
                f"fast-lane governance hash pin mismatch: {key}"
            )

    sources = payload["sources"]
    if not isinstance(sources, list) or len(sources) != 92:
        raise pytest.UsageError("malformed fast-lane governance source roster")
    source_paths = []
    for row in sources:
        if not isinstance(row, dict) or set(row) != {"path", "sha256"}:
            raise pytest.UsageError("malformed fast-lane governance source row")
        path = row["path"]
        digest = row["sha256"]
        if (
            not isinstance(path, str)
            or not path.startswith("scripts/")
            or "\\" in path
            or Path(path).is_absolute()
            or ".." in Path(path).parts
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise pytest.UsageError("malformed fast-lane governance source identity")
        source_paths.append(path)
    if len(source_paths) != len(set(source_paths)):
        raise pytest.UsageError("duplicate fast-lane governance source identity")
    if len(source_paths) != len({path.casefold() for path in source_paths}):
        raise pytest.UsageError("fast-lane governance source case-collision")
    if _line_roster_sha256(source_paths) != hashes["source_path_roster_sha256"]:
        raise pytest.UsageError("fast-lane governance source path roster drift")
    if _sha256_bytes(_canonical_source_roster(sources)) != hashes["source_roster_sha256"]:
        raise pytest.UsageError("fast-lane governance source roster drift")
    if verify_sources:
        private_paths = _FAST_GOVERNANCE_PRIVATE_SOURCE_PATHS
        if not private_paths <= set(source_paths):
            raise pytest.UsageError(
                "fast-lane private source policy is not bound to the source roster"
            )
        private_materialized = {
            path
            for path in private_paths
            if (_REPO_ROOT / path).is_file()
        }
        if private_materialized and private_materialized != private_paths:
            raise pytest.UsageError(
                "fast-lane private source materialization is partial"
            )
        private_sources_absent = not private_materialized
        for row in sources:
            if private_sources_absent and row["path"] in private_paths:
                continue
            try:
                observed = _sha256_file(_REPO_ROOT / row["path"])
            except OSError as exc:
                raise pytest.UsageError(
                    "fast-lane governance source is unavailable: "
                    f"{row['path']}"
                ) from exc
            if observed != row["sha256"]:
                raise pytest.UsageError(
                    "fast-lane governance source hash drift: "
                    f"{row['path']} expected {row['sha256']} observed {observed}"
                )

    entries = payload["entries"]
    if not isinstance(entries, list):
        raise pytest.UsageError("malformed fast-lane governance entry roster")
    nodeids = []
    for row in entries:
        if not isinstance(row, dict) or set(row) != {
            "markers",
            "nodeid",
            "reason",
            "state",
        }:
            raise pytest.UsageError("malformed fast-lane governance entry")
        nodeid = row["nodeid"]
        markers = row["markers"]
        if (
            not isinstance(nodeid, str)
            or nodeid.count("::") < 1
            or "\\" in nodeid.split("::", 1)[0]
            or row["state"] not in {"guaranteed_current", "unresolved_runtime"}
            or not isinstance(markers, list)
            or not markers
            or len(markers) != len(set(markers))
            or any(marker not in _FAST_GOVERNANCE_MARKERS for marker in markers)
            or not isinstance(row["reason"], str)
            or not row["reason"]
            or "\n" in row["reason"]
        ):
            raise pytest.UsageError("malformed fast-lane governance entry identity")
        nodeids.append(nodeid)
    if len(nodeids) != len(set(nodeids)):
        raise pytest.UsageError("duplicate fast-lane governance node identity")
    if len(nodeids) != len({nodeid.casefold() for nodeid in nodeids}):
        raise pytest.UsageError("fast-lane governance node case-collision")
    if any(nodeid.split("::", 1)[0] not in source_paths for nodeid in nodeids):
        raise pytest.UsageError("fast-lane governance node source is unbound")
    if len(entries) != 168:
        raise pytest.UsageError("malformed fast-lane governance entry roster")
    states = Counter(row["state"] for row in entries)
    if states != {"guaranteed_current": 17, "unresolved_runtime": 151}:
        raise pytest.UsageError("malformed fast-lane governance state partition")
    guaranteed = [
        row["nodeid"] for row in entries if row["state"] == "guaranteed_current"
    ]
    unresolved = [
        row["nodeid"] for row in entries if row["state"] == "unresolved_runtime"
    ]
    if _line_roster_sha256(nodeids) != hashes["quarantine_nodes_sha256"]:
        raise pytest.UsageError("fast-lane quarantine node roster drift")
    if _line_roster_sha256(guaranteed) != hashes["guaranteed_nodes_sha256"]:
        raise pytest.UsageError("fast-lane guaranteed node roster drift")
    if _line_roster_sha256(unresolved) != hashes["unresolved_nodes_sha256"]:
        raise pytest.UsageError("fast-lane unresolved node roster drift")
    if _sha256_bytes(_canonical_entry_roster(entries)) != hashes.get(
        "entry_roster_sha256"
    ):
        raise pytest.UsageError("fast-lane governance entry roster drift")
    quarantine_sources = []
    for nodeid in nodeids:
        source = nodeid.split("::", 1)[0]
        if source not in quarantine_sources:
            quarantine_sources.append(source)
    if _line_roster_sha256(quarantine_sources) != hashes[
        "quarantine_source_path_roster_sha256"
    ]:
        raise pytest.UsageError("fast-lane quarantine source roster drift")
    source_by_path = {row["path"]: row["sha256"] for row in sources}
    quarantine_source_rows = [
        {"path": path, "sha256": source_by_path[path]}
        for path in quarantine_sources
    ]
    if _sha256_bytes(_canonical_source_roster(quarantine_source_rows)) != hashes[
        "quarantine_source_roster_sha256"
    ]:
        raise pytest.UsageError("fast-lane quarantine source/hash roster drift")
    return payload


def _load_fast_governance_manifest() -> dict:
    try:
        raw = _FAST_GOVERNANCE_MANIFEST.read_bytes()
    except OSError as exc:
        raise pytest.UsageError(
            f"fast-lane governance manifest unavailable: {exc}"
        ) from exc
    observed = _sha256_bytes(raw)
    if observed != _FAST_GOVERNANCE_MANIFEST_SHA256:
        raise pytest.UsageError(
            "fast-lane governance manifest hash drift: "
            f"expected {_FAST_GOVERNANCE_MANIFEST_SHA256} observed {observed}"
        )
    return _validate_fast_governance_payload(
        _decode_fast_governance_json(raw), verify_sources=True
    )


def _is_complete_production_collection(config) -> bool:
    resolved = set()
    for raw in getattr(config, "args", []):
        text = str(raw)
        if "::" in text:
            return False
        path = Path(text)
        if not path.is_absolute():
            path = _REPO_ROOT / path
        try:
            resolved.add(path.resolve())
        except OSError:
            return False
    return resolved == {(_REPO_ROOT / "scripts").resolve(), (_REPO_ROOT / "tests").resolve()}


def _apply_fast_governance(config, items, payload: dict) -> None:
    _require_supported_os_name(os.name)
    entries = {row["nodeid"]: row for row in payload["entries"]}
    collected = [item.nodeid for item in items]
    if len(collected) != len(set(collected)):
        raise pytest.UsageError("duplicate collected pytest node identity")
    seen = set(collected)
    if _is_complete_production_collection(config):
        missing = list(entries.keys() - seen)
        if missing:
            raise pytest.UsageError(
                "missing quarantine identities from complete collection: "
                f"{missing[:20]}"
            )
    for item in items:
        row = entries.get(item.nodeid)
        if row is None:
            continue
        item.add_marker(pytest.mark.fast_quarantine)
        for marker in row["markers"]:
            item.add_marker(getattr(pytest.mark, marker))


# (3) Filename-driven marker application. Stems only (no .py). Keep sorted.
# A file lands in _INTEGRATION_STEMS if it spawns a real OS subprocess / external
# tool, or does a real time.sleep >= ~1s. _SLOW_STEMS is the heavyweight subset
# (real driver phase-loop / mass real import subprocesses).
_INTEGRATION_STEMS = frozenset(
    {
        "test_cross_os_hygiene",
        "test_driver_smoke",
        "test_fuzz_workspace_adversarial_review_p2_a",
        "test_fuzz_workspace_authority_p2_a",
        "test_halt_ux_e2e",
        "test_l1_race_fuzz_registry",
        "test_mechanical_heartbeat",
        "test_negative_closure_broker_live_cutover",
        "test_opengrep",
        "test_p0_judge_table_parser",
        "test_p1_dm_phase_io_packaging",
        "test_phase_containment_regression",
        "test_python_packaging_contracts",
        "test_pty_exec",
        "test_recon_hardened_subprocess",
        "test_recon_heartbeat",
        "test_semantic_dedup_applied_authority_p0_qs",
        "test_severity_shadow_phase_runtime_p0_ag4",
        "test_severity_worker_debt_recovery_p0_ag4",
        "test_signal_and_ratelimit",
        "test_snapshot_startup_rewind_r0_8cd",
        "test_spike_mechanical_poc",
        "test_structural_integrity",
        "test_windows_copy_fallback_install",
        "test_worker_execution_receipts",
        "test_worker_process_tree_adversarial_review",
        "test_worker_stdout_output_and_stream_limits",
    }
)
_SLOW_STEMS = frozenset(
    {
        "test_driver_smoke",
        "test_fuzz_workspace_adversarial_review_p2_a",
        "test_fuzz_workspace_authority_p2_a",
        "test_negative_closure_broker_live_cutover",
        "test_severity_shadow_phase_runtime_p0_ag4",
        "test_severity_worker_debt_recovery_p0_ag4",
        "test_snapshot_startup_rewind_r0_8cd",
        "test_spike_mechanical_poc",
        "test_structural_integrity",
        "test_worker_execution_receipts",
        "test_worker_process_tree_adversarial_review",
        "test_worker_stdout_output_and_stream_limits",
    }
)


_LAST_MARKER_PARTITION = {
    "item_count": 0,
    "unit_count": 0,
    "integration_count": 0,
    "slow_count": 0,
    "invalid": [],
}


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(config, items):
    """Apply and validate the total unit/integration execution-lane partition."""
    fast_governance = _load_fast_governance_manifest()
    _apply_fast_governance(config, items, fast_governance)
    invalid = []
    unit_count = 0
    integration_count = 0
    slow_count = 0
    for item in items:
        stem = Path(str(item.fspath)).stem
        if stem in _INTEGRATION_STEMS:
            item.add_marker(pytest.mark.integration)
        if stem in _SLOW_STEMS:
            item.add_marker(pytest.mark.slow)

        # An explicitly slow item must never leak into the parallel unit lane,
        # even if its module was omitted from the filename allowlist.
        if list(item.iter_markers(name="slow")) and not list(
            item.iter_markers(name="integration")
        ):
            item.add_marker(pytest.mark.integration)

        if not list(item.iter_markers(name="integration")) and not list(
            item.iter_markers(name="unit")
        ):
            item.add_marker(pytest.mark.unit)

        is_unit = bool(list(item.iter_markers(name="unit")))
        is_integration = bool(list(item.iter_markers(name="integration")))
        is_slow = bool(list(item.iter_markers(name="slow")))
        unit_count += int(is_unit)
        integration_count += int(is_integration)
        slow_count += int(is_slow)
        if is_unit == is_integration or (is_slow and not is_integration):
            invalid.append(item.nodeid)

    _LAST_MARKER_PARTITION.update(
        {
            "item_count": len(items),
            "unit_count": unit_count,
            "integration_count": integration_count,
            "slow_count": slow_count,
            "invalid": invalid,
        }
    )
    if invalid:
        raise pytest.UsageError(
            "pytest lane markers must be exactly unit xor integration and "
            f"slow implies integration; invalid items: {invalid[:20]}"
        )


@pytest.fixture(autouse=True)
def fail_on_legacy_check_failures(request):
    """Make legacy check()/FAIL harnesses behave like pytest assertions."""
    module = getattr(request, "module", None)
    if module is None or not hasattr(module, "FAIL"):
        yield
        return

    before = getattr(module, "FAIL", 0)
    yield
    after = getattr(module, "FAIL", 0)
    if after <= before:
        return

    details = []
    for attr in ("FAILURES", "ERRORS"):
        entries = getattr(module, attr, None)
        if entries:
            details.extend(str(entry) for entry in entries[-(after - before):])
    detail_text = "\n".join(details) if details else f"{after - before} legacy check() failure(s)"
    pytest.fail(detail_text)
