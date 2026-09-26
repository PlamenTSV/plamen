"""Executable acceptance ledger for the 47 Native Broker v2 RED gates.

This module deliberately reuses the narrow behavioral harnesses beside each
production translation unit.  A gate is accepted only after the relevant C or
Python production surface has accepted the exact case and rejected its
adversarial variants.  Where the final production path does not exist, the test
executes the nearest non-authoritative behavior and then records a precise
``xfail`` blocker; a TEST_ONLY harness is never promoted into release authority.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys
from types import ModuleType
from typing import Any, Iterator

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if os.fspath(SCRIPTS) not in sys.path:
    sys.path.insert(0, os.fspath(SCRIPTS))

import test_apple_container_provider as provider_tests
import test_apple_supervisor_adapter as adapter_tests
import test_darwin_broker_v2_process as process_tests
import test_darwin_process_custodian as custodian_tests
import test_plamen_native_broker_v2 as broker_tests
import test_plamen_native_supervisor_extension_v2 as extension_tests
import test_posix_audit_supervisor as supervisor_tests
import test_posix_backend_execution_integration as posix_integration_tests
import test_posix_native_authority_adapter as native_adapter_tests
import test_worker_execution_receipts_posix_v2 as wer_posix_tests


CONTRACT = ROOT / "docs" / "continuation" / "NATIVE_BROKER_V2_CONTRACT.md"
BUILDER = SCRIPTS / "build_posix_native_supervisor.py"


@pytest.fixture(scope="module")
def v2_builds(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, dict[str, Any]]]:
    """Build both shapes once; neither build is production authority."""

    results: dict[str, dict[str, Any]] = {}
    roots: list[Path] = []
    try:
        for variant in ("production", "test"):
            root = tmp_path_factory.mktemp(f"acceptance-v2-{variant}").resolve()
            root.chmod(0o700)
            roots.append(root)
            results[variant] = extension_tests._build(root, variant)
        yield results
    finally:
        for root in roots:
            extension_tests._clear_test_tree_immutable_flags(root)


@pytest.fixture(scope="module")
def v2_module(v2_builds: dict[str, dict[str, Any]]) -> ModuleType:
    return extension_tests._load_exact(
        v2_builds["test"]["artifact_path"], extension_tests.TEST_MODULE
    )


@pytest.fixture(scope="module")
def native_peers(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path]:
    return broker_tests.native_peers.__wrapped__(tmp_path_factory)


@pytest.fixture(scope="module")
def native_tools(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path, Path]:
    if sys.platform != "darwin":
        pytest.skip("Apple native acceptance requires Darwin")
    # The acceptance gates use only the process driver and helper.  Do not
    # compile the independently evolving launcher/install transaction here.
    directory = tmp_path_factory.mktemp("acceptance-darwin-process")
    driver = directory / "plamen_broker_v2_process_TEST_ONLY"
    helper = directory / "plamen_process_fixture_TEST_ONLY"
    subprocess.run(
        [
            os.fspath(process_tests.CLANG),
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-DPLAMEN_BROKER_V2_TEST_ONLY=1",
            "-DPLAMEN_BROKER_V2_TEST_DRIVER=1",
            os.fspath(process_tests.SOURCE),
            "-framework",
            "Security",
            "-framework",
            "CoreFoundation",
            "-o",
            os.fspath(driver),
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    process_tests._compile_from_stdin(helper, process_tests.HELPER_SOURCE)
    return driver, directory / "unused-launcher", helper


@pytest.fixture(scope="module")
def custody_harness(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if sys.platform != "darwin":
        pytest.skip("Apple process-custody acceptance requires Darwin")
    return custodian_tests.harness.__wrapped__(tmp_path_factory)


@pytest.fixture(scope="module")
def production_readiness() -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, os.fspath(BUILDER), "--production-readiness"],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
        env={
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        },
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    result = json.loads(completed.stdout)
    assert result["schema"] == "plamen.native-supervisor.production-readiness.v2"
    assert result["authority"] == "DIAGNOSTIC_ONLY_LOADED_PYTHON_NO_BUILD_AUTHORITY"
    return result


def _selftest(native_peers: tuple[Path, Path]) -> None:
    completed = subprocess.run(
        [os.fspath(native_peers[0]), "selftest"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")


def _bad_frames(module: ModuleType, *mutations: str) -> None:
    for mutation in mutations:
        extension_tests.test_bad_header_payload_tag_sequence_and_replay_burn_once(
            module, mutation
        )


def _block(
    gate: str,
    reason: str,
    *,
    readiness: dict[str, Any] | None = None,
    required_diagnostics: tuple[str, ...] = (),
) -> None:
    if readiness is not None:
        blockers = set(readiness["blockers"])
        missing = set(required_diagnostics) - blockers
        assert not missing, (
            f"{gate} blocker diagnostics changed; replace the xfail with a final "
            f"production behavioral proof or update its evidence: {sorted(missing)}"
        )
        assert readiness["production_build_allowed"] is False
    pytest.xfail(f"{gate} BLOCKER: {reason}")


# Protocol and bootstrap ----------------------------------------------------


def test_RED_BROKER_V2_ABI_CONSTANT_EQUALITY(
    v2_module: ModuleType, native_peers: tuple[Path, Path]
) -> None:
    extension_tests.test_red_broker_v2_abi_constant_equality(v2_module)
    broker_tests.test_RED_BROKER_V2_ABI_CONSTANT_EQUALITY(native_peers)


def test_RED_BROKER_V2_AUTHENTICATED_HELLO_ONLY(v2_module: ModuleType) -> None:
    _bad_frames(v2_module, "hello_bad_tag")
    extension_tests.test_scm_rights_count_alias_and_hello_roster_are_exact(
        v2_module, "hello_fd"
    )


def test_RED_BROKER_V2_SESSION_KEY_NEVER_PYTHON_VISIBLE(
    v2_module: ModuleType,
) -> None:
    extension_tests.test_session_key_socket_fd_and_tokens_never_become_python_visible(
        v2_module
    )


def test_RED_BROKER_V2_FORGED_PEER_EXECUTABLE_REJECTED(
    native_tools: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    process_tests.test_path_substitution_is_killed_before_user_code(
        native_tools, tmp_path
    )


def test_RED_BROKER_V2_TRUNCATED_OVERSIZE_TRAILING_FRAME_REJECTED(
    v2_module: ModuleType,
) -> None:
    _bad_frames(v2_module, "bad_payload_size", "truncated", "trailing")


def test_RED_BROKER_V2_HMAC_PAYLOAD_AND_HEADER_FORGERY_REJECTED(
    v2_module: ModuleType,
) -> None:
    _bad_frames(
        v2_module, "bad_magic", "bad_flags", "bad_payload_digest", "bad_tag"
    )


def test_RED_BROKER_V2_SEQUENCE_GAP_ROLLBACK_AND_CHAIN_REPLAY_REJECTED(
    v2_module: ModuleType,
) -> None:
    _bad_frames(
        v2_module, "sequence_gap", "sequence_rollback", "bad_previous", "replay"
    )


def test_RED_BROKER_V2_CROSS_SESSION_ATTEMPT_AND_NONCE_REPLAY_REJECTED(
    v2_module: ModuleType,
) -> None:
    _bad_frames(v2_module, "wrong_session", "cross_nonce")
    extension_tests.test_wrong_binding_burns_before_protocol_io(
        v2_module,
        extension_tests.FINGERPRINT,
        "attempt-broker-v2-002",
        RuntimeError,
    )


# FD and process custody ----------------------------------------------------


def test_RED_BROKER_V2_SCM_RIGHTS_COUNT_ORDER_AND_PURPOSE_EXACT(
    v2_module: ModuleType,
) -> None:
    for mutation in ("fd_missing", "fd_surplus", "hello_fd"):
        extension_tests.test_scm_rights_count_alias_and_hello_roster_are_exact(
            v2_module, mutation
        )


def test_RED_BROKER_V2_FD_ALIAS_ACCESS_MODE_AND_IDENTITY_REJECTED(
    v2_module: ModuleType,
) -> None:
    extension_tests.test_scm_rights_count_alias_and_hello_roster_are_exact(
        v2_module, "fd_alias"
    )
    provider_tests.test_descriptor_identity_alias_and_ancestor_overlap_are_rejected()


def test_RED_BROKER_V2_CLOEXEC_AND_FAILURE_PREFIX_FD_CLOSURE(
    native_tools: tuple[Path, Path, Path], native_peers: tuple[Path, Path]
) -> None:
    process_tests.test_cloexec_default_preserves_only_allowlisted_pass_fd(native_tools)
    _selftest(native_peers)


def test_RED_BROKER_V2_NO_SECRET_ARGV_ENV_REPR_PICKLE_OR_EXCEPTION(
    v2_module: ModuleType,
) -> None:
    extension_tests.test_session_key_socket_fd_and_tokens_never_become_python_visible(
        v2_module
    )
    provider_tests.test_repr_receipts_and_errors_are_redacted()


def test_RED_BROKER_V2_CREATOR_PID_FORK_AND_SUBINTERPRETER_REJECTED(
    v2_module: ModuleType,
) -> None:
    extension_tests.test_wrong_pid_and_actual_fork_burn_child_copy_only(v2_module)
    extension_tests.test_wrong_interpreter_binding_burns_once(v2_module)


def test_RED_BROKER_V2_TWO_THREAD_SINGLE_CONSUME(v2_module: ModuleType) -> None:
    extension_tests.test_two_threads_observe_one_initial_and_member_consumption(
        v2_module
    )


def test_RED_BROKER_V2_PID_BIRTH_REUSE_REJECTED(
    native_peers: tuple[Path, Path],
) -> None:
    _selftest(native_peers)
    _block(
        "RED_BROKER_V2_PID_BIRTH_REUSE_REJECTED",
        "production code binds PID birth identity, but no deterministic native "
        "adversary forces the same PID with a different birth and proves rejection",
    )


# Durable effects and recovery ---------------------------------------------


def test_RED_BROKER_V2_START_PREPARE_BEFORE_EFFECT() -> None:
    provider_tests.test_journal_pending_must_be_durable_before_mutation()


def test_RED_BROKER_V2_START_ACK_LOSS_RECOVERS_WITHOUT_DUPLICATE(
    custody_harness: Path, tmp_path: Path
) -> None:
    for fault in range(1, 5):
        custodian_tests.test_start_fault_boundaries_replay_without_duplicate(
            custody_harness, tmp_path, fault
        )
    provider_tests.test_driver_start_crash_after_arm_recovers_without_duplicate_effect()


def test_RED_BROKER_V2_CROSS_PROCESS_START_RACE_EXACTLY_ONCE(
    custody_harness: Path, native_peers: tuple[Path, Path], tmp_path: Path
) -> None:
    (tmp_path / "claim").mkdir()
    custodian_tests.test_cross_process_claim_has_exactly_one_owner(
        custody_harness, tmp_path / "claim"
    )
    (tmp_path / "journal").mkdir()
    broker_tests.test_RED_BROKER_V2_CROSS_PROCESS_START_RACE_EXACTLY_ONCE(
        native_peers, tmp_path / "journal"
    )


def test_RED_BROKER_V2_WAIT_PREPARE_BEFORE_REAP() -> None:
    provider_tests.test_driver_wait_crash_after_arm_starts_only_one_native_wait()


def test_RED_BROKER_V2_WAIT_ACK_LOSS_RECOVERS_IDENTICAL_EXIT(
    custody_harness: Path, tmp_path: Path
) -> None:
    for fault in range(5, 10):
        custodian_tests.test_terminal_fault_boundaries_recover_identical_bytes(
            custody_harness, tmp_path, fault
        )
    custodian_tests.test_terminal_is_byte_recoverable_after_registry_loss(
        custody_harness, tmp_path / "registry-loss"
    )


def test_RED_BROKER_V2_CROSS_PROCESS_WAIT_RACE_EXACTLY_ONCE(
    custody_harness: Path, tmp_path: Path
) -> None:
    custodian_tests.test_concurrent_start_and_wait_are_exactly_once(
        custody_harness, tmp_path
    )
    _block(
        "RED_BROKER_V2_CROSS_PROCESS_WAIT_RACE_EXACTLY_ONCE",
        "the native harness proves two-thread wait CAS only; it does not run two "
        "independent processes racing the same retained wait claim",
    )


def test_RED_BROKER_V2_CLAIM_LOSER_CANNOT_WAIT_OR_REVOKE(
    custody_harness: Path, tmp_path: Path
) -> None:
    custodian_tests.test_claim_loser_cannot_wait(custody_harness, tmp_path)
    provider_tests.test_wait_claim_loser_executable_cleanup_failure_never_revokes_process()
    provider_tests.test_start_claim_loser_abort_check_precedes_native_revoke()


def test_RED_BROKER_V2_PARENT_DEATH_DURABLE_RECONNECT(
    custody_harness: Path, tmp_path: Path
) -> None:
    custodian_tests.test_client_session_disconnect_keeps_service_owned_live_claim(
        custody_harness, tmp_path / "reconnect"
    )
    custodian_tests.test_terminal_is_byte_recoverable_after_registry_loss(
        custody_harness, tmp_path / "terminal"
    )


def test_RED_BROKER_V2_AMBIGUOUS_PREPARE_NEVER_REPEATS_EFFECT(
    custody_harness: Path, tmp_path: Path
) -> None:
    custodian_tests.test_live_started_record_after_custody_daemon_restart_is_ambiguous_not_replayed(
        custody_harness, tmp_path
    )


def test_RED_BROKER_V2_REVOCATION_PRECEDES_CLEANUP_COMMIT() -> None:
    provider_tests.test_driver_wait_timeout_forces_process_guest_and_egress_extinction()
    for hazard in (
        "provider-egress",
        "terminal-count",
        "predelete-count",
        "guest-roster",
        "artifact",
        "export",
    ):
        adapter_tests.test_delete_translation_hard_stops_on_residual_or_artifact_hazard(
            hazard
        )


# Apple lifecycle -----------------------------------------------------------


def test_RED_BROKER_V2_APPLE_CONTAINER_1_3_1_IDENTITY_EXACT() -> None:
    provider_tests.test_preflight_exact_official_shapes_and_every_call_provenance()
    provider_tests.test_vulnerable_130_and_nonexact_banner_commit_are_rejected()


def test_RED_BROKER_V2_APPLE_CLI_PATH_DESCRIPTOR_SUBSTITUTION_REJECTED(
    native_tools: tuple[Path, Path, Path], tmp_path: Path
) -> None:
    process_tests.test_path_substitution_is_killed_before_user_code(
        native_tools, tmp_path
    )
    provider_tests.test_descriptor_identity_alias_and_ancestor_overlap_are_rejected()


def test_RED_BROKER_V2_START_ATTACH_ARGV_EXACT() -> None:
    provider_tests.test_driver_start_is_exact_attached_nonblocking_and_wait_is_exit_authority()


def test_RED_BROKER_V2_ROSETTA_DODO_ONLY_BINDING_EXACT() -> None:
    provider_tests.test_rosetta_is_request_bound_dodo_only_and_exact_create_flag()
    adapter_tests.test_rosetta_is_bound_to_arm_host_dodo_amd64_lane_only()


def test_RED_BROKER_V2_TEN_MOUNT_PURPOSE_ROSTER_EXACT() -> None:
    provider_tests.test_broker_v2_commitment_and_ten_mount_admission_are_exact()
    adapter_tests.test_create_translation_binds_ten_semantic_mounts_and_run_paths()


def test_RED_BROKER_V2_LOWER_MERGED_RECENSUS_DRIFT_REJECTED() -> None:
    provider_tests.test_native_mounted_identity_must_equal_the_held_lease()
    for drift in ("target", "merged", "component"):
        adapter_tests.test_create_translation_rejects_authority_drift(drift)


def test_RED_BROKER_V2_TIMEOUT_SIGNAL_AND_OUTPUT_OVERFLOW_REVOKE(
    native_tools: tuple[Path, Path, Path]
) -> None:
    process_tests.test_timeout_revokes_and_reaps(native_tools)
    process_tests.test_overflow_revokes_and_bounds_retention(native_tools)
    provider_tests.test_driver_wait_rejects_exit_substitution_and_output_overflow_then_revokes()


def test_RED_BROKER_V2_STREAM_FULL_RETAINED_DIGEST_AND_LENGTH_EXACT(
    custody_harness: Path, tmp_path: Path
) -> None:
    provider_tests.test_complete_retained_stream_digest_is_recomputed()
    provider_tests.test_truncated_driver_output_binds_exact_retained_prefix()
    custodian_tests.test_output_capture_rejects_native_observed_digest_mismatch(
        custody_harness, tmp_path
    )


def test_RED_BROKER_V2_DESCENDANTS_GUEST_AND_EGRESS_EXTINCT_BEFORE_DELETE() -> None:
    provider_tests.test_driver_wait_timeout_forces_process_guest_and_egress_extinction()
    for hazard in ("provider-egress", "terminal-count", "predelete-count", "guest-roster"):
        adapter_tests.test_delete_translation_hard_stops_on_residual_or_artifact_hazard(
            hazard
        )


# Extension, adapter, supervisor, and WER ----------------------------------


def test_RED_NATIVE_CONSUMER_EXTENSION_ORIGIN_AND_STATIC_TYPE_EXACT(
    v2_builds: dict[str, dict[str, Any]], v2_module: ModuleType
) -> None:
    extension_tests.test_production_is_static_and_hardstopped_before_initial_authority(
        v2_builds
    )
    extension_tests.test_constructor_subclass_and_test_only_namespace_are_sealed(
        v2_module
    )


def test_RED_NATIVE_CONSUMER_NO_PRODUCTION_MINT_REGISTRY_OR_FACTORY(
    v2_builds: dict[str, dict[str, Any]]
) -> None:
    extension_tests.test_absent_native_bootstrap_never_mints_on_repeat_module_initialization(
        v2_builds
    )
    extension_tests.test_production_is_static_and_hardstopped_before_initial_authority(
        v2_builds
    )


def test_RED_NATIVE_CONSUMER_WRONG_FINGERPRINT_BURNS_ONCE(
    v2_module: ModuleType,
) -> None:
    extension_tests.test_wrong_binding_burns_before_protocol_io(
        v2_module, "f" * 64, extension_tests.ATTEMPT, RuntimeError
    )


def test_RED_NATIVE_PROCESS_AND_EXIT_CAPABILITY_OBJECT_NEW_REJECTED(
    v2_builds: dict[str, dict[str, Any]], v2_module: ModuleType
) -> None:
    extension_tests.test_production_is_static_and_hardstopped_before_initial_authority(
        v2_builds
    )
    extension_tests.test_constructor_subclass_and_test_only_namespace_are_sealed(
        v2_module
    )


def test_RED_APPLE_ADAPTER_MISSING_EXTRA_DUPLICATE_REORDER_ALIAS_REJECTED(
    production_readiness: dict[str, Any],
) -> None:
    for mutation in ("missing", "extra", "duplicate", "reordered"):
        adapter_tests.test_resolution_roster_is_exact_and_ordered(mutation)
    for overlap in (False, True):
        adapter_tests.test_resolution_paths_reject_alias_and_ancestor_overlap(overlap)
    native_adapter_tests.test_roster_requires_ten_exact_non_subclassed_native_types()
    native_adapter_tests.test_request_binding_and_exact_argument_types_fail_before_native_call()
    _block(
        "RED_APPLE_ADAPTER_MISSING_EXTRA_DUPLICATE_REORDER_ALIAS_REJECTED",
        "the TEST_ONLY translator rejects every roster attack, but the production "
        "C provider hook is unreachable so no exact native capability can reach it",
        readiness=production_readiness,
        required_diagnostics=("PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",),
    )


def test_RED_APPLE_PROVIDER_TEST_ONLY_AUTHORITY_CANNOT_CROSS_PRODUCTION(
    v2_builds: dict[str, dict[str, Any]]
) -> None:
    provider_tests.test_production_provider_is_separate_from_test_only_registries()
    extension_tests.test_test_only_artifact_cannot_cross_production_module(v2_builds)


def test_RED_SUPERVISOR_NATIVE_START_WAIT_RECEIPT_BINDING_EXACT(
    production_readiness: dict[str, Any],
) -> None:
    adapter_tests.test_start_wait_and_delete_bind_distinct_provider_and_supervisor_receipts()
    native_adapter_tests.test_all_role1_methods_use_one_canonical_bound_bytes_call()
    native_adapter_tests.test_wrong_top_level_result_type_and_native_failure_are_bounded()
    for field in ("cli", "provenance", "process", "count"):
        adapter_tests.test_wait_translation_rejects_start_substitution(field)
    _block(
        "RED_SUPERVISOR_NATIVE_START_WAIT_RECEIPT_BINDING_EXACT",
        "test translation is exact, but committed native STARTED/EXITED parsing and "
        "the production provider bridge are not integrated",
        readiness=production_readiness,
        required_diagnostics=("PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",),
    )


def test_RED_SUPERVISOR_CRASH_RECOVERY_NEVER_REPEATS_NATIVE_EFFECT(
    production_readiness: dict[str, Any],
) -> None:
    supervisor_tests.test_crash_during_journal_commit_recovers_applied_start_once()
    _block(
        "RED_SUPERVISOR_CRASH_RECOVERY_NEVER_REPEATS_NATIVE_EFFECT",
        "the supervisor simulator recovers once, but no production provider effect "
        "is reachable through the native bridge",
        readiness=production_readiness,
        required_diagnostics=("PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",),
    )


def test_RED_WER_REJECTS_APPLE_DRIVER_OUTPUT_AS_BACKEND_OUTPUT(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Even an exact forged backend wrapper is rejected before a method or byte is
    # observed; an Apple outer-driver receipt has no route around this stronger gate.
    for entrypoint in ("public", "direct"):
        (tmp_path / entrypoint).mkdir()
        wer_posix_tests.test_real_absence_rejects_forged_execution_before_its_methods(
            tmp_path / entrypoint, monkeypatch, entrypoint
        )


def test_RED_POSIX_BACKEND_EXECUTION_REMAINS_HARDSTOP_UNTIL_LINUX_NATIVE(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for entrypoint in ("public", "direct"):
        for attack in ("subclass-property", "exact-evil-value"):
            posix_integration_tests.test_posix_hardstop_precedes_all_bindings_callbacks_and_mutation(
                tmp_path / f"{entrypoint}-{attack}", entrypoint, attack
            )
    posix_integration_tests.test_production_hardstops_raise_before_temporary_destructors(
        tmp_path / "destructors", monkeypatch
    )


# Ordered release gates -----------------------------------------------------


def test_RED_DODO_CREDENTIAL_FREE_OUTER_DRIVER_SMOKE(
    production_readiness: dict[str, Any],
) -> None:
    _block(
        "RED_DODO_CREDENTIAL_FREE_OUTER_DRIVER_SMOKE",
        "no committed multi-artifact native build/install handoff or reachable "
        "Apple provider lifecycle exists; a live DODO smoke is forbidden",
        readiness=production_readiness,
        required_diagnostics=(
            "PRODUCTION_COMPILE_LINK_CLOSURE_UNOBSERVED",
            "MULTI_ARTIFACT_RETAINED_INSTALL_HANDOFF_ABSENT",
            "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
        ),
    )


def test_RED_DODO_GUEST_NATIVE_BACKEND_STREAM_REPLAY(
    production_readiness: dict[str, Any],
) -> None:
    _block(
        "RED_DODO_GUEST_NATIVE_BACKEND_STREAM_REPLAY",
        "the guest-native backend executor, authenticated output replay, and "
        "credential-free DODO predecessor smoke are absent",
        readiness=production_readiness,
        required_diagnostics=(
            "SERVICE_PROCESS_CUSTODY_NOT_INTEGRATED",
            "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
        ),
    )


def test_RED_DODO_CREDENTIAL_BEARING_END_TO_END(
    production_readiness: dict[str, Any],
) -> None:
    _block(
        "RED_DODO_CREDENTIAL_BEARING_END_TO_END",
        "guest-native credential custody and descendant no-read are unproved, and "
        "both ordered predecessor DODO gates remain blocked",
        readiness=production_readiness,
        required_diagnostics=(
            "SERVICE_PROCESS_CUSTODY_NOT_INTEGRATED",
            "PROVIDER_LIFECYCLE_AUTHORITY_UNREACHABLE",
            "SOURCE_INSTALL_COORDINATOR_TRANSACTION_ABSENT",
        ),
    )


# Import-time denominator check: this does not satisfy a gate; it prevents the
# executable mapping above from silently omitting or inventing a reserved name.
_CONTRACT_GATES = tuple(
    re.findall(r"^- `(RED_[A-Z0-9_]+)`$", CONTRACT.read_text("utf-8"), re.MULTILINE)
)
_EXECUTABLE_GATES = tuple(
    name.removeprefix("test_")
    for name, value in tuple(globals().items())
    if name.startswith("test_RED_") and callable(value)
)
assert len(_CONTRACT_GATES) == 47
assert _EXECUTABLE_GATES == _CONTRACT_GATES
